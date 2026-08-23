//! Scaled authenticated sumcheck reference for the C6.3 sparse relation
//! `u = H * m`.
//!
//! For an output point `r`, the reference forms `q = eq(r)` and
//! `a = H^T q`, then proves
//!
//! ```text
//! <q, u> = <a, m>.
//! ```
//!
//! Each quadratic round sends only `g(0), g(2)`.  Both values are corrected
//! independently on both MAC tapes before the shared challenge is drawn.
//! This is executable algebra and wire-census evidence only: the scaled
//! verifier still receives `m` and `u` to evaluate the terminal product.
//! Production must instead bind the initial/terminal claims to the C6.3
//! roots and four WHIR lanes, preserve privacy, and move the fold to the GPU.

use std::{array, fmt};

use volta_field::{Fp2, P};
use volta_mac::{
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
    RESERVED_DOMAIN_BITS,
};
use volta_proto::mle::{eq_vec, fold_low, lagrange3};

use crate::c63_authenticated_sketch::C63SparseSketchReference;

pub const C63_SPARSE_H_MAGIC: [u8; 8] = *b"C63SHC1\0";
pub const C63_SPARSE_H_VERSION: u16 = 1;
pub const C63_SPARSE_H_TAPES: usize = 2;
pub const C63_SPARSE_H_PRODUCTION_ROUNDS: u64 = 22;
pub const C63_SPARSE_H_PRODUCTION_ROUND_PAYLOAD_BYTES: u64 = 1_408;
pub const C63_SPARSE_H_PRODUCTION_FRAMING_BYTES: u64 = 88;
pub const C63_SPARSE_H_PRODUCTION_FRAMED_BYTES: u64 = 1_496;
pub const C63_SPARSE_H_PRODUCTION_FULL_CORRELATIONS_PER_TAPE: u64 = 44;

const HEADER_BYTES: u64 = 56;
const TERMINAL_TAG_BYTES: u64 = 32;
const ROUND_BYTES: u64 = 64;
const CORRELATION_BASE: u64 = 0x0C68_0000_0000_0000;
const STATEMENT_DOMAIN: &str = "volta-zk/c63/sparse-h-closure-statement/v1";
const HEADER_LABEL: &str = "c63_sparse_h_closure_header";
const ROUND_LABEL: &str = "c63_sparse_h_closure_round_corrections";
const TERMINAL_LABEL: &str = "c63_sparse_h_closure_terminal_tags";

type Result<T> = std::result::Result<T, C63SparseHClosureError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHClosureError(String);

impl C63SparseHClosureError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C63SparseHClosureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C63SparseHClosureError {}

/// External C6.3 binding plus the output evaluation point.
///
/// `binding_digest` is deliberately supplied by the caller.  In production it
/// must bind the typed `H`, `D'` and `A` descriptors; this reference does not
/// invent a replacement commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHClosureStatement {
    binding_digest: [u8; 32],
    output_point: Vec<Fp2>,
}

/// One public systematic row/value pair folded into the sparse-H relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63SystematicSpot {
    pub row: u32,
    pub value: Fp2,
}

impl C63SparseHClosureStatement {
    pub fn new(binding_digest: [u8; 32], output_point: Vec<Fp2>) -> Result<Self> {
        if binding_digest == [0; 32] || output_point.is_empty() {
            return Err(C63SparseHClosureError::new(
                "C6.3 sparse-H statement binding or output point is empty",
            ));
        }
        Ok(Self { binding_digest, output_point })
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    pub fn output_point(&self) -> &[Fp2] {
        &self.output_point
    }
}

/// Dual-tape corrected round messages plus the two independent terminal tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHClosureProof {
    input_log2: u8,
    output_log2: u8,
    statement_digest: [u8; 32],
    round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES],
    terminal_tags: [Fp2; C63_SPARSE_H_TAPES],
}

impl C63SparseHClosureProof {
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn round_count(&self) -> usize {
        usize::from(self.input_log2)
    }

    pub fn encoded_len(&self) -> Result<u64> {
        encoded_len(self.round_count())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut bytes = self.header_bytes()?;
        for round in 0..self.round_count() {
            for tape_corrections in &self.round_corrections {
                for value in tape_corrections[round] {
                    encode_fp2(&mut bytes, value);
                }
            }
        }
        for tag in self.terminal_tags {
            encode_fp2(&mut bytes, tag);
        }
        if bytes.len() as u64 != self.encoded_len()? {
            return Err(C63SparseHClosureError::new("C6.3 sparse-H encoded census differs"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C63_SPARSE_H_MAGIC {
            return Err(C63SparseHClosureError::new("bad C63SHC1 magic"));
        }
        if cursor.u16()? != C63_SPARSE_H_VERSION {
            return Err(C63SparseHClosureError::new("bad C63SHC1 version"));
        }
        let input_log2 = cursor.u8()?;
        let output_log2 = cursor.u8()?;
        let round_count = cursor.u16()? as usize;
        if input_log2 == 0
            || output_log2 == 0
            || round_count != usize::from(input_log2)
            || cursor.u16()? as usize != C63_SPARSE_H_TAPES
        {
            return Err(C63SparseHClosureError::new("C63SHC1 header geometry differs"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest == [0; 32]
            || cursor.u64()? != round_payload_bytes(round_count)?
            || bytes.len() as u64 != encoded_len(round_count)?
        {
            return Err(C63SparseHClosureError::new("C63SHC1 header census differs"));
        }
        let mut round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES] =
            array::from_fn(|_| Vec::with_capacity(round_count));
        for _ in 0..round_count {
            for tape_corrections in &mut round_corrections {
                tape_corrections.push([cursor.fp2()?, cursor.fp2()?]);
            }
        }
        let terminal_tags = [cursor.fp2()?, cursor.fp2()?];
        if !cursor.is_eof() {
            return Err(C63SparseHClosureError::new("trailing C63SHC1 proof bytes"));
        }
        let proof =
            Self { input_log2, output_log2, statement_digest, round_corrections, terminal_tags };
        proof.validate_shape()?;
        Ok(proof)
    }

    fn header_bytes(&self) -> Result<Vec<u8>> {
        header_bytes(self.input_log2, self.output_log2, self.statement_digest)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.input_log2 == 0
            || self.output_log2 == 0
            || self.statement_digest == [0; 32]
            || self.round_corrections.iter().any(|rounds| rounds.len() != self.round_count())
        {
            return Err(C63SparseHClosureError::new("C63SHC1 proof shape differs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHClosureReferenceAudit {
    pub sumcheck_point: Vec<Fp2>,
    pub terminal_a: Fp2,
    pub terminal_m: Fp2,
    pub transcript_digest: [u8; 32],
    pub transcript_bytes: u64,
}

/// Scaled honest prover.  It checks `u = H*m` before producing the reference
/// proof, but that direct check is not part of the verifier algorithm.
pub fn prove_c63_sparse_h_closure_reference(
    h: &C63SparseSketchReference,
    m: &[Fp2],
    u: &[Fp2],
    statement: &C63SparseHClosureStatement,
    streams: &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHClosureProof> {
    prove_c63_sparse_h_closure_with_spots_reference(h, m, u, statement, &[], streams, transcript)
}

/// Reference prover that folds sorted, unique systematic spots into the same
/// sparse-H sumcheck without changing its proof body.
pub fn prove_c63_sparse_h_closure_with_spots_reference(
    h: &C63SparseSketchReference,
    m: &[Fp2],
    u: &[Fp2],
    statement: &C63SparseHClosureStatement,
    spots: &[C63SystematicSpot],
    streams: &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHClosureProof> {
    let (input_log2, output_log2, claim, mut a) = prepare_relation(h, m, u, statement)?;
    validate_systematic_spots(spots, m.len())?;
    if h.apply(m).map_err(C63SparseHClosureError::new)? != u {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H witness does not satisfy u = H*m"));
    }
    if spots.is_empty() && inner_product(&a, m)? != claim {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H witness does not satisfy u = H*m"));
    }
    let mut claim = claim;
    let statement_digest =
        reference_statement_digest(statement, input_log2, output_log2, claim, spots);
    let header = header_bytes(input_log2, output_log2, statement_digest)?;
    transcript.append_message(HEADER_LABEL, &header);
    if !spots.is_empty() {
        fuse_systematic_spots(&mut a, &mut claim, spots, transcript.challenge_fp2());
        if inner_product(&a, m)? != claim {
            return Err(C63SparseHClosureError::new(
                "C6.3 sparse-H witness differs from its systematic spots",
            ));
        }
    }

    let mut folded_m = m.to_vec();
    let mut current = [ProverAuthed::from_public(claim); C63_SPARSE_H_TAPES];
    let mut round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES] =
        array::from_fn(|_| Vec::with_capacity(usize::from(input_log2)));

    for round in 0..usize::from(input_log2) {
        let [g0, g1, g2] = product_round(&a, &folded_m)?;
        let mut corrected = [[Fp2::ZERO; 2]; C63_SPARSE_H_TAPES];
        let mut sent = [[ProverAuthed::ZERO; 2]; C63_SPARSE_H_TAPES];
        for tape in 0..C63_SPARSE_H_TAPES {
            let domain = correlation_domain(tape, round)?;
            let correlations = streams[tape].draw_fulls(domain, 2);
            streams[tape]
                .record_c6_fullfield_plaintexts(domain, &[g0, g2])
                .map_err(C63SparseHClosureError::new)?;
            corrected[tape] = [g0 - correlations[0].x, g2 - correlations[1].x];
            sent[tape] = [correlations[0].authenticate(g0), correlations[1].authenticate(g2)];
            if current[tape].sub(sent[tape][0]).x != g1 {
                return Err(C63SparseHClosureError::new(
                    "C6.3 sparse-H compressed round does not sum to its claim",
                ));
            }
            round_corrections[tape].push(corrected[tape]);
        }
        append_round(transcript, &corrected);
        let challenge = transcript.challenge_fp2();
        let weights = lagrange3(challenge);
        for tape in 0..C63_SPARSE_H_TAPES {
            let one = current[tape].sub(sent[tape][0]);
            current[tape] = sent[tape][0]
                .scale(weights[0])
                .add(one.scale(weights[1]))
                .add(sent[tape][1].scale(weights[2]));
        }
        fold_low(&mut a, challenge);
        fold_low(&mut folded_m, challenge);
    }

    let terminal = a[0] * folded_m[0];
    let mut terminal_tags = [Fp2::ZERO; C63_SPARSE_H_TAPES];
    for tape in 0..C63_SPARSE_H_TAPES {
        let residual = current[tape].sub(ProverAuthed::from_public(terminal));
        if residual.x != Fp2::ZERO {
            return Err(C63SparseHClosureError::new(
                "C6.3 sparse-H prover terminal product differs",
            ));
        }
        terminal_tags[tape] = residual.m;
    }
    transcript.append_fp2s(TERMINAL_LABEL, &terminal_tags);
    if let Some(error) = transcript.interactive_error() {
        return Err(C63SparseHClosureError::new(error));
    }

    Ok(C63SparseHClosureProof {
        input_log2,
        output_log2,
        statement_digest,
        round_corrections,
        terminal_tags,
    })
}

/// Scaled verifier mirror.  It keeps both MAC equations separate and uses the
/// supplied witness tables only to stand in for the future WHIR openings.
pub fn verify_c63_sparse_h_closure_reference(
    h: &C63SparseSketchReference,
    m: &[Fp2],
    u: &[Fp2],
    statement: &C63SparseHClosureStatement,
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHClosureReferenceAudit> {
    verify_c63_sparse_h_closure_with_spots_reference(
        h,
        m,
        u,
        statement,
        &[],
        proof,
        contexts,
        transcript,
    )
}

/// Reference verifier for the fused sparse-H/systematic-spot relation.
pub fn verify_c63_sparse_h_closure_with_spots_reference(
    h: &C63SparseSketchReference,
    m: &[Fp2],
    u: &[Fp2],
    statement: &C63SparseHClosureStatement,
    spots: &[C63SystematicSpot],
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHClosureReferenceAudit> {
    proof.validate_shape()?;
    if contexts[0].delta == contexts[1].delta {
        return Err(C63SparseHClosureError::new(
            "C6.3 sparse-H MAC tape multipliers are not independent",
        ));
    }
    let (input_log2, output_log2, claim, mut a) = prepare_relation(h, m, u, statement)?;
    validate_systematic_spots(spots, m.len())?;
    let mut claim = claim;
    let statement_digest =
        reference_statement_digest(statement, input_log2, output_log2, claim, spots);
    if proof.input_log2 != input_log2
        || proof.output_log2 != output_log2
        || proof.statement_digest != statement_digest
    {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H proof statement differs"));
    }
    transcript.append_message(HEADER_LABEL, &proof.header_bytes()?);
    if !spots.is_empty() {
        fuse_systematic_spots(&mut a, &mut claim, spots, transcript.challenge_fp2());
    }

    let mut folded_m = m.to_vec();
    let mut current: [VerifierKey; C63_SPARSE_H_TAPES] =
        array::from_fn(|tape| VerifierKey::from_public(claim, contexts[tape].delta));
    let mut point = Vec::with_capacity(proof.round_count());
    for round in 0..proof.round_count() {
        let mut corrected = [[Fp2::ZERO; 2]; C63_SPARSE_H_TAPES];
        let mut sent = [[VerifierKey::ZERO; 2]; C63_SPARSE_H_TAPES];
        for tape in 0..C63_SPARSE_H_TAPES {
            corrected[tape] = proof.round_corrections[tape][round];
            let keys = contexts[tape]
                .correct_full_verifier_keys(correlation_domain(tape, round)?, &corrected[tape]);
            sent[tape] = [keys[0], keys[1]];
        }
        append_round(transcript, &corrected);
        let challenge = transcript.challenge_fp2();
        let weights = lagrange3(challenge);
        for tape in 0..C63_SPARSE_H_TAPES {
            let one = current[tape].sub(sent[tape][0]);
            current[tape] = sent[tape][0]
                .scale(weights[0])
                .add(one.scale(weights[1]))
                .add(sent[tape][1].scale(weights[2]));
        }
        fold_low(&mut a, challenge);
        fold_low(&mut folded_m, challenge);
        point.push(challenge);
    }

    transcript.append_fp2s(TERMINAL_LABEL, &proof.terminal_tags);
    // Reference-only: production must bind this same-point `m` terminal to
    // the two D22 Hiding-WHIR limb openings instead of receiving `m` here.
    let terminal = a[0] * folded_m[0];
    for tape in 0..C63_SPARSE_H_TAPES {
        let residual = current[tape].sub(VerifierKey::from_public(terminal, contexts[tape].delta));
        if !zero_open_verify(residual, proof.terminal_tags[tape]) {
            return Err(C63SparseHClosureError::new("C6.3 sparse-H terminal ZeroOpen failed"));
        }
    }
    let transcript_digest =
        transcript.canonical_binding_digest().map_err(C63SparseHClosureError::new)?;
    if transcript.total_bytes() != proof.encoded_len()? {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H transcript census differs"));
    }
    Ok(C63SparseHClosureReferenceAudit {
        sumcheck_point: point,
        terminal_a: a[0],
        terminal_m: folded_m[0],
        transcript_digest,
        transcript_bytes: transcript.total_bytes(),
    })
}

fn prepare_relation(
    h: &C63SparseSketchReference,
    m: &[Fp2],
    u: &[Fp2],
    statement: &C63SparseHClosureStatement,
) -> Result<(u8, u8, Fp2, Vec<Fp2>)> {
    let input_log2 = exact_log2(m.len(), "input")?;
    let output_log2 = exact_log2(u.len(), "output")?;
    if usize::from(output_log2) != statement.output_point.len() {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H output point geometry differs"));
    }
    let q = eq_vec(&statement.output_point);
    if q.len() != u.len() {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H equality table geometry differs"));
    }
    let a = h.transpose_weights(&q).map_err(C63SparseHClosureError::new)?;
    if a.len() != m.len() {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H transpose geometry differs"));
    }
    Ok((input_log2, output_log2, inner_product(&q, u)?, a))
}

fn exact_log2(length: usize, label: &str) -> Result<u8> {
    if length < 2 || !length.is_power_of_two() {
        return Err(C63SparseHClosureError::new(format!(
            "C6.3 sparse-H {label} length is not a nontrivial power of two",
        )));
    }
    u8::try_from(length.trailing_zeros())
        .map_err(|_| C63SparseHClosureError::new("C6.3 sparse-H dimension exceeds u8"))
}

fn inner_product(left: &[Fp2], right: &[Fp2]) -> Result<Fp2> {
    if left.len() != right.len() {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H inner-product geometry differs"));
    }
    Ok(left.iter().zip(right).fold(Fp2::ZERO, |sum, (&lhs, &rhs)| sum + lhs * rhs))
}

fn validate_systematic_spots(spots: &[C63SystematicSpot], input_len: usize) -> Result<()> {
    let mut previous = None;
    for spot in spots {
        let row = spot.row as usize;
        if row >= input_len || previous.is_some_and(|old| old >= spot.row) {
            return Err(C63SparseHClosureError::new(
                "C6.3 systematic spots are not sorted, unique and in range",
            ));
        }
        previous = Some(spot.row);
    }
    Ok(())
}

fn fuse_systematic_spots(a: &mut [Fp2], claim: &mut Fp2, spots: &[C63SystematicSpot], beta: Fp2) {
    let mut weight = beta;
    for spot in spots {
        a[spot.row as usize] += weight;
        *claim += weight * spot.value;
        weight = weight * beta;
    }
}

fn product_round(a: &[Fp2], m: &[Fp2]) -> Result<[Fp2; 3]> {
    if a.len() != m.len() || a.len() < 2 || !a.len().is_power_of_two() {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H round geometry differs"));
    }
    let mut values = [Fp2::ZERO; 3];
    for index in 0..a.len() / 2 {
        let (a0, a1) = (a[2 * index], a[2 * index + 1]);
        let (m0, m1) = (m[2 * index], m[2 * index + 1]);
        let a2 = a1 + a1 - a0;
        let m2 = m1 + m1 - m0;
        values[0] += a0 * m0;
        values[1] += a1 * m1;
        values[2] += a2 * m2;
    }
    Ok(values)
}

fn reference_statement_digest(
    statement: &C63SparseHClosureStatement,
    input_log2: u8,
    output_log2: u8,
    claim: Fp2,
    spots: &[C63SystematicSpot],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(&statement.binding_digest);
    hasher.update(&[input_log2, output_log2]);
    for coordinate in &statement.output_point {
        hasher.update(&coordinate.c0.value().to_le_bytes());
        hasher.update(&coordinate.c1.value().to_le_bytes());
    }
    hasher.update(&claim.c0.value().to_le_bytes());
    hasher.update(&claim.c1.value().to_le_bytes());
    // Preserve the historical zero-spot digest exactly.
    if !spots.is_empty() {
        hasher.update(b"volta-zk/c63/systematic-spots/v1");
        hasher.update(&(spots.len() as u64).to_le_bytes());
        for spot in spots {
            hasher.update(&spot.row.to_le_bytes());
            hasher.update(&spot.value.c0.value().to_le_bytes());
            hasher.update(&spot.value.c1.value().to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn correlation_domain(tape: usize, round: usize) -> Result<u64> {
    if tape >= C63_SPARSE_H_TAPES || round > u16::MAX as usize {
        return Err(C63SparseHClosureError::new(
            "C6.3 sparse-H correlation component is out of range",
        ));
    }
    let domain = CORRELATION_BASE | ((tape as u64) << 24) | round as u64;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(C63SparseHClosureError::new(
            "C6.3 sparse-H correlation domain uses reserved bits",
        ));
    }
    Ok(domain)
}

fn append_round(transcript: &mut Transcript, corrections: &[[Fp2; 2]; C63_SPARSE_H_TAPES]) {
    transcript.append_fp2s(
        ROUND_LABEL,
        &[corrections[0][0], corrections[0][1], corrections[1][0], corrections[1][1]],
    );
}

fn header_bytes(input_log2: u8, output_log2: u8, statement_digest: [u8; 32]) -> Result<Vec<u8>> {
    let rounds = usize::from(input_log2);
    let mut bytes = Vec::with_capacity(HEADER_BYTES as usize);
    bytes.extend_from_slice(&C63_SPARSE_H_MAGIC);
    bytes.extend_from_slice(&C63_SPARSE_H_VERSION.to_le_bytes());
    bytes.push(input_log2);
    bytes.push(output_log2);
    bytes.extend_from_slice(&(input_log2 as u16).to_le_bytes());
    bytes.extend_from_slice(&(C63_SPARSE_H_TAPES as u16).to_le_bytes());
    bytes.extend_from_slice(&statement_digest);
    bytes.extend_from_slice(&round_payload_bytes(rounds)?.to_le_bytes());
    if bytes.len() as u64 != HEADER_BYTES {
        return Err(C63SparseHClosureError::new("C6.3 sparse-H header census differs"));
    }
    Ok(bytes)
}

fn round_payload_bytes(rounds: usize) -> Result<u64> {
    u64::try_from(rounds)
        .ok()
        .and_then(|count| count.checked_mul(ROUND_BYTES))
        .ok_or_else(|| C63SparseHClosureError::new("C6.3 sparse-H round payload overflows"))
}

fn encoded_len(rounds: usize) -> Result<u64> {
    HEADER_BYTES
        .checked_add(round_payload_bytes(rounds)?)
        .and_then(|bytes| bytes.checked_add(TERMINAL_TAG_BYTES))
        .ok_or_else(|| C63SparseHClosureError::new("C6.3 sparse-H encoding length overflows"))
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C63SparseHClosureError::new("C63SHC1 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C63SparseHClosureError::new("truncated C63SHC1 proof"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(C63SparseHClosureError::new("noncanonical C63SHC1 field element"));
        }
        Ok(Fp2::new(volta_field::Fp::new(c0), volta_field::Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;

    use crate::c63_authenticated_sketch::C63SparseSketchEdge;

    const TAPE_SEEDS: [[u8; 32]; 2] = [[0xA1; 32], [0xA2; 32]];
    const DELTAS: [Fp2; 2] =
        [Fp2::new(Fp::new(17), Fp::new(19)), Fp2::new(Fp::new(23), Fp::new(29))];
    const TRANSCRIPT_SEED: [u8; 32] = [0xB1; 32];

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(7 * value + 3))
    }

    fn matrix(coefficient_delta: u64) -> C63SparseSketchReference {
        let edges = (0..8u32)
            .map(|input| C63SparseSketchEdge {
                input,
                socket_ordinal: 0,
                output: input % 4,
                coefficient: Fp::new(
                    2 + u64::from(input) + u64::from(input == 0) * coefficient_delta,
                ),
            })
            .collect();
        C63SparseSketchReference::new(8, 4, edges).unwrap()
    }

    fn fixture() -> (C63SparseSketchReference, Vec<Fp2>, Vec<Fp2>, C63SparseHClosureStatement) {
        let h = matrix(0);
        let m = (0..8).map(|index| fp2(11 + index)).collect::<Vec<_>>();
        let u = h.apply(&m).unwrap();
        let statement =
            C63SparseHClosureStatement::new([0xC1; 32], vec![fp2(31), fp2(37)]).unwrap();
        (h, m, u, statement)
    }

    fn prove(
        h: &C63SparseSketchReference,
        m: &[Fp2],
        u: &[Fp2],
        statement: &C63SparseHClosureStatement,
    ) -> (C63SparseHClosureProof, Transcript, [u64; 2]) {
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let proof =
            prove_c63_sparse_h_closure_reference(h, m, u, statement, &mut streams, &mut transcript)
                .unwrap();
        let correlations = array::from_fn(|tape| streams[tape].counters.full_corrs);
        (proof, transcript, correlations)
    }

    fn prove_with_spots(
        h: &C63SparseSketchReference,
        m: &[Fp2],
        u: &[Fp2],
        statement: &C63SparseHClosureStatement,
        spots: &[C63SystematicSpot],
    ) -> Result<(C63SparseHClosureProof, Transcript, [u64; 2])> {
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let proof = prove_c63_sparse_h_closure_with_spots_reference(
            h,
            m,
            u,
            statement,
            spots,
            &mut streams,
            &mut transcript,
        )?;
        let correlations = array::from_fn(|tape| streams[tape].counters.full_corrs);
        Ok((proof, transcript, correlations))
    }

    fn verify(
        h: &C63SparseSketchReference,
        m: &[Fp2],
        u: &[Fp2],
        statement: &C63SparseHClosureStatement,
        proof: &C63SparseHClosureProof,
        transcript_seed: [u8; 32],
    ) -> Result<C63SparseHClosureReferenceAudit> {
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut transcript = Transcript::new(transcript_seed);
        verify_c63_sparse_h_closure_reference(
            h,
            m,
            u,
            statement,
            proof,
            &mut contexts,
            &mut transcript,
        )
    }

    fn verify_with_spots(
        h: &C63SparseSketchReference,
        m: &[Fp2],
        u: &[Fp2],
        statement: &C63SparseHClosureStatement,
        spots: &[C63SystematicSpot],
        proof: &C63SparseHClosureProof,
    ) -> Result<C63SparseHClosureReferenceAudit> {
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        verify_c63_sparse_h_closure_with_spots_reference(
            h,
            m,
            u,
            statement,
            spots,
            proof,
            &mut contexts,
            &mut transcript,
        )
    }

    #[test]
    fn sparse_h_round_trip_and_production_census_are_exact() {
        assert_eq!(
            C63_SPARSE_H_PRODUCTION_ROUNDS * ROUND_BYTES,
            C63_SPARSE_H_PRODUCTION_ROUND_PAYLOAD_BYTES
        );
        assert_eq!(HEADER_BYTES + TERMINAL_TAG_BYTES, C63_SPARSE_H_PRODUCTION_FRAMING_BYTES);
        assert_eq!(
            C63_SPARSE_H_PRODUCTION_ROUND_PAYLOAD_BYTES + C63_SPARSE_H_PRODUCTION_FRAMING_BYTES,
            C63_SPARSE_H_PRODUCTION_FRAMED_BYTES
        );
        assert_eq!(
            2 * C63_SPARSE_H_PRODUCTION_ROUNDS,
            C63_SPARSE_H_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
        );

        let (h, m, u, statement) = fixture();
        let (proof, prover_tx, correlations) = prove(&h, &m, &u, &statement);
        assert_eq!(correlations, [6, 6]);
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded.len() as u64, 56 + 3 * 64 + 32);
        let decoded = C63SparseHClosureProof::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        let audit = verify(&h, &m, &u, &statement, &decoded, TRANSCRIPT_SEED).unwrap();
        assert_eq!(audit.transcript_bytes, encoded.len() as u64);
        let q = eq_vec(statement.output_point());
        let a = h.transpose_weights(&q).unwrap();
        assert_eq!(audit.terminal_a, volta_proto::mle::eval_mle(&a, &audit.sumcheck_point));
        assert_eq!(audit.terminal_m, volta_proto::mle::eval_mle(&m, &audit.sumcheck_point));
        assert_eq!(audit.transcript_digest, prover_tx.canonical_binding_digest().unwrap());
    }

    #[test]
    fn sparse_h_rejects_relation_round_transcript_and_terminal_mutations() {
        let (h, m, u, statement) = fixture();
        let (proof, _, _) = prove(&h, &m, &u, &statement);

        assert!(verify(&matrix(1), &m, &u, &statement, &proof, TRANSCRIPT_SEED).is_err());

        let mut bad_m = m.clone();
        bad_m[0] += Fp2::ONE;
        assert!(verify(&h, &bad_m, &u, &statement, &proof, TRANSCRIPT_SEED).is_err());

        let mut bad_u = u.clone();
        bad_u[0] += Fp2::ONE;
        assert!(verify(&h, &m, &bad_u, &statement, &proof, TRANSCRIPT_SEED).is_err());

        let mut bad_round = proof.clone();
        bad_round.round_corrections[1][1][0] += Fp2::ONE;
        assert!(verify(&h, &m, &u, &statement, &bad_round, TRANSCRIPT_SEED).is_err());

        assert!(verify(&h, &m, &u, &statement, &proof, [0xB2; 32]).is_err());

        let mut bad_terminal = proof.clone();
        bad_terminal.terminal_tags[0] += Fp2::ONE;
        assert!(verify(&h, &m, &u, &statement, &bad_terminal, TRANSCRIPT_SEED).is_err());
    }

    #[test]
    fn sparse_h_codec_and_tape_separation_fail_closed() {
        let (h, m, u, statement) = fixture();
        let (proof, _, _) = prove(&h, &m, &u, &statement);
        let encoded = proof.encode().unwrap();

        let mut bad_header = encoded.clone();
        bad_header[15] = 1;
        assert!(C63SparseHClosureProof::decode(&bad_header).is_err());
        let mut noncanonical = encoded.clone();
        noncanonical[56..64].copy_from_slice(&P.to_le_bytes());
        assert!(C63SparseHClosureProof::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C63SparseHClosureProof::decode(&trailing).is_err());

        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[0]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        assert!(verify_c63_sparse_h_closure_reference(
            &h,
            &m,
            &u,
            &statement,
            &proof,
            &mut contexts,
            &mut transcript,
        )
        .is_err());
    }

    #[test]
    fn zero_spots_preserve_the_historical_proof_transcript_and_correlations() {
        let (h, m, u, statement) = fixture();
        let (old_proof, old_tx, old_correlations) = prove(&h, &m, &u, &statement);
        let (new_proof, new_tx, new_correlations) =
            prove_with_spots(&h, &m, &u, &statement, &[]).unwrap();

        assert_eq!(new_proof, old_proof);
        assert_eq!(new_proof.encode().unwrap(), old_proof.encode().unwrap());
        assert_eq!(new_correlations, old_correlations);
        assert_eq!(new_tx.total_bytes(), old_tx.total_bytes());
        assert_eq!(new_tx.ledger(), old_tx.ledger());
        assert_eq!(
            new_tx.canonical_binding_digest().unwrap(),
            old_tx.canonical_binding_digest().unwrap()
        );
    }

    #[test]
    fn fused_systematic_spots_pass_honestly_and_fail_closed_on_mutation() {
        let (h, m, u, statement) = fixture();
        let spots =
            [C63SystematicSpot { row: 1, value: m[1] }, C63SystematicSpot { row: 5, value: m[5] }];
        let (plain, _, plain_correlations) = prove(&h, &m, &u, &statement);
        let (proof, _, correlations) = prove_with_spots(&h, &m, &u, &statement, &spots).unwrap();
        assert_eq!(proof.encoded_len().unwrap(), plain.encoded_len().unwrap());
        assert_eq!(correlations, plain_correlations);
        verify_with_spots(&h, &m, &u, &statement, &spots, &proof).unwrap();

        let mut changed_value = spots;
        changed_value[0].value += Fp2::ONE;
        assert!(verify_with_spots(&h, &m, &u, &statement, &changed_value, &proof).is_err());

        let mut changed_row = spots;
        changed_row[0].row = 2;
        assert!(verify_with_spots(&h, &m, &u, &statement, &changed_row, &proof).is_err());

        let reversed = [spots[1], spots[0]];
        assert!(verify_with_spots(&h, &m, &u, &statement, &reversed, &proof).is_err());
        assert!(prove_with_spots(&h, &m, &u, &statement, &reversed).is_err());

        let duplicate = [spots[0], C63SystematicSpot { row: spots[0].row, value: m[1] }];
        assert!(verify_with_spots(&h, &m, &u, &statement, &duplicate, &proof).is_err());
        assert!(prove_with_spots(&h, &m, &u, &statement, &duplicate).is_err());
    }

    #[test]
    fn fused_spot_closes_the_plain_sparse_h_kernel_attack() {
        let (h, x, u, statement) = fixture();
        let mut error = vec![Fp2::ZERO; x.len()];
        error[0] = Fp2::from_base(Fp::new(3));
        error[4] = Fp2::ZERO - Fp2::ONE;
        assert_ne!(error, vec![Fp2::ZERO; x.len()]);
        assert_eq!(h.apply(&error).unwrap(), vec![Fp2::ZERO; u.len()]);

        let m = x.iter().zip(&error).map(|(&value, &delta)| value + delta).collect::<Vec<_>>();
        assert_eq!(h.apply(&m).unwrap(), u);
        let (plain, _, _) = prove(&h, &m, &u, &statement);
        verify(&h, &m, &u, &statement, &plain, TRANSCRIPT_SEED).unwrap();

        let spots = [C63SystematicSpot { row: 0, value: x[0] }];
        assert!(prove_with_spots(&h, &m, &u, &statement, &spots).is_err());
        assert!(verify_with_spots(&h, &m, &u, &statement, &spots, &plain).is_err());

        let (honest, _, _) = prove_with_spots(&h, &x, &u, &statement, &spots).unwrap();
        verify_with_spots(&h, &x, &u, &statement, &spots, &honest).unwrap();
    }
}

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
//! Each quadratic round sends only `g(0), g(2)`. Both values are corrected
//! independently on both MAC tapes before the shared challenge is drawn. The
//! selected seam starts and ends with authenticated WHIR keys; the historical
//! combined-message reference remains only for earlier diagnostics.

use std::{array, fmt};

#[cfg(feature = "cuda")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "cuda")]
use volta_accel::{Backend, DeviceBuffer, DeviceSlice, Fp2Repr};

use volta_field::{Fp2, P};
use volta_mac::{
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
    RESERVED_DOMAIN_BITS,
};
use volta_proto::mle::{eq_vec, fold_low, lagrange3};

use crate::c63_authenticated_sketch::C63SparseSketchReference;

pub const C63_SPARSE_H_MAGIC: [u8; 8] = *b"C63SHC2\0";
pub const C63_SPARSE_H_VERSION: u16 = 2;
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
const STATEMENT_DOMAIN: &str = "volta-zk/c63/sparse-h-closure-statement/v2";
const SOURCE_FUNCTIONAL_PREFIX_DOMAIN: &str = "volta-zk/c63/sparse-h-source-functional-prefix/v1";
const HEADER_LABEL: &str = "c63_sparse_h_closure_header";
const ROUND_LABEL: &str = "c63_sparse_h_closure_round_corrections";
const TERMINAL_LABEL: &str = "c63_sparse_h_closure_terminal_tags";

type Result<T> = std::result::Result<T, C63SparseHClosureError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHClosureError(String);

impl C63SparseHClosureError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
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

/// One queried systematic row with a distinct value for each authentication tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63TapeSystematicSpot {
    pub row: u32,
    pub values: [Fp2; C63_SPARSE_H_TAPES],
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

    /// Bind exactly the header and round corrections that determine the D22
    /// terminal point. Terminal tags are deliberately later in the protocol.
    pub fn source_functional_prefix_digest(&self) -> Result<[u8; 32]> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new_derive_key(SOURCE_FUNCTIONAL_PREFIX_DOMAIN);
        hasher.update(&self.header_bytes()?);
        for round in 0..self.round_count() {
            for tape_corrections in &self.round_corrections {
                for value in tape_corrections[round] {
                    hasher.update(&value.c0.value().to_le_bytes());
                    hasher.update(&value.c1.value().to_le_bytes());
                }
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C63_SPARSE_H_MAGIC {
            return Err(C63SparseHClosureError::new("bad C63SHC2 magic"));
        }
        if cursor.u16()? != C63_SPARSE_H_VERSION {
            return Err(C63SparseHClosureError::new("bad C63SHC2 version"));
        }
        let input_log2 = cursor.u8()?;
        let output_log2 = cursor.u8()?;
        let round_count = cursor.u16()? as usize;
        if input_log2 == 0
            || output_log2 == 0
            || round_count != usize::from(input_log2)
            || cursor.u16()? as usize != C63_SPARSE_H_TAPES
        {
            return Err(C63SparseHClosureError::new("C63SHC2 header geometry differs"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest == [0; 32]
            || cursor.u64()? != round_payload_bytes(round_count)?
            || bytes.len() as u64 != encoded_len(round_count)?
        {
            return Err(C63SparseHClosureError::new("C63SHC2 header census differs"));
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
            return Err(C63SparseHClosureError::new("trailing C63SHC2 proof bytes"));
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
            return Err(C63SparseHClosureError::new("C63SHC2 proof shape differs"));
        }
        Ok(())
    }
}

/// Grammar-only production-size fixture; never accepted as cryptographic evidence.
pub fn c63_sparse_h_closure_production_codec_reference() -> C63SparseHClosureProof {
    C63SparseHClosureProof {
        input_log2: C63_SPARSE_H_PRODUCTION_ROUNDS as u8,
        output_log2: 19,
        statement_digest: [1; 32],
        round_corrections: array::from_fn(|_| {
            vec![[Fp2::ZERO; 2]; C63_SPARSE_H_PRODUCTION_ROUNDS as usize]
        }),
        terminal_tags: [Fp2::ZERO; C63_SPARSE_H_TAPES],
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseHTapeClosureReferenceAudit {
    pub sumcheck_point: Vec<Fp2>,
    pub terminal_a: Fp2,
    pub terminal_m_keys: [VerifierKey; C63_SPARSE_H_TAPES],
    pub transcript_digest: [u8; 32],
    pub transcript_bytes: u64,
}

/// Verifier state after the sparse transcript has fixed its D22 terminal
/// point but before the eight WHIR bodies reveal their authenticated targets.
/// It is local-only and can be completed exactly once with the four keys.
pub struct C63SparseHTapeVerifierPending {
    sumcheck_point: Vec<Fp2>,
    terminal_a: Fp2,
    u_coefficient: Fp2,
    offsets: [VerifierKey; C63_SPARSE_H_TAPES],
    terminal_tags: [Fp2; C63_SPARSE_H_TAPES],
    transcript_digest: [u8; 32],
    transcript_bytes: u64,
}

impl C63SparseHTapeVerifierPending {
    pub fn sumcheck_point(&self) -> &[Fp2] {
        &self.sumcheck_point
    }

    /// Recover the only authenticated `u_l` keys consistent with the fixed
    /// sparse transcript, its terminal tags, and the supplied `m_l` keys.
    /// This breaks the verifier-order cycle: projected WHIR can compare its
    /// derived targets against these keys without receiving clear openings.
    pub fn derive_u_opening_keys(
        &self,
        terminal_m_keys: [VerifierKey; C63_SPARSE_H_TAPES],
    ) -> Result<[VerifierKey; C63_SPARSE_H_TAPES]> {
        if self.u_coefficient == Fp2::ZERO {
            return Err(C63SparseHClosureError::new(
                "C6.3 sparse-H terminal u coefficient is zero",
            ));
        }
        let inverse = self.u_coefficient.inv();
        Ok(std::array::from_fn(|tape| {
            terminal_m_keys[tape]
                .scale(self.terminal_a)
                .sub(self.offsets[tape])
                .add(VerifierKey::new(self.terminal_tags[tape]))
                .scale(inverse)
        }))
    }

    pub fn finish(
        self,
        u_opening_keys: [VerifierKey; C63_SPARSE_H_TAPES],
        terminal_m_keys: [VerifierKey; C63_SPARSE_H_TAPES],
    ) -> Result<C63SparseHTapeClosureReferenceAudit> {
        for tape in 0..C63_SPARSE_H_TAPES {
            let current = u_opening_keys[tape].scale(self.u_coefficient).add(self.offsets[tape]);
            let residual = current.sub(terminal_m_keys[tape].scale(self.terminal_a));
            if !zero_open_verify(residual, self.terminal_tags[tape]) {
                return Err(C63SparseHClosureError::new(
                    "C6.3 tape-separated sparse-H terminal ZeroOpen failed",
                ));
            }
        }
        Ok(C63SparseHTapeClosureReferenceAudit {
            sumcheck_point: self.sumcheck_point,
            terminal_a: self.terminal_a,
            terminal_m_keys,
            transcript_digest: self.transcript_digest,
            transcript_bytes: self.transcript_bytes,
        })
    }
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

/// Selected C6.3 prover: one sparse relation per authentication tape with
/// common challenges and no cross-tape plaintext combination.
pub fn prove_c63_sparse_h_tape_closure_with_spots_reference<F>(
    h: &C63SparseSketchReference,
    m: [&[Fp2]; C63_SPARSE_H_TAPES],
    u: [&[Fp2]; C63_SPARSE_H_TAPES],
    u_claims: [ProverAuthed; C63_SPARSE_H_TAPES],
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    streams: &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
    mut open_m: F,
) -> Result<C63SparseHClosureProof>
where
    F: FnMut(usize, &[Fp2]) -> Result<ProverAuthed>,
{
    let (input_log2, output_log2, mut claims, mut a) = prepare_tape_relation(h, m, u, statement)?;
    validate_tape_systematic_spots(spots, a.len())?;
    for tape in 0..C63_SPARSE_H_TAPES {
        if h.apply(m[tape]).map_err(C63SparseHClosureError::new)? != u[tape] {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated witness does not satisfy u_l = H*m_l",
            ));
        }
        if u_claims[tape].x != claims[tape] {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated authenticated u_l claim differs",
            ));
        }
    }
    let statement_digest =
        reference_tape_statement_digest(statement, input_log2, output_log2, spots);
    transcript
        .append_message(HEADER_LABEL, &header_bytes(input_log2, output_log2, statement_digest)?);
    let mut current = u_claims;
    if !spots.is_empty() {
        let additions = fuse_tape_systematic_spots(&mut a, spots, transcript.challenge_fp2());
        for tape in 0..C63_SPARSE_H_TAPES {
            claims[tape] += additions[tape];
            current[tape] = current[tape].add(ProverAuthed::from_public(additions[tape]));
        }
    }
    for tape in 0..C63_SPARSE_H_TAPES {
        if inner_product(&a, m[tape])? != claims[tape] {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated witness differs from its systematic spots",
            ));
        }
    }

    let mut folded_m = [m[0].to_vec(), m[1].to_vec()];
    let mut point = Vec::with_capacity(usize::from(input_log2));
    let mut round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES] =
        array::from_fn(|_| Vec::with_capacity(usize::from(input_log2)));

    for round in 0..usize::from(input_log2) {
        let mut corrected = [[Fp2::ZERO; 2]; C63_SPARSE_H_TAPES];
        let mut sent = [[ProverAuthed::ZERO; 2]; C63_SPARSE_H_TAPES];
        for tape in 0..C63_SPARSE_H_TAPES {
            let [g0, g1, g2] = product_round(&a, &folded_m[tape])?;
            let domain = correlation_domain(tape, round)?;
            let correlations = streams[tape].draw_fulls(domain, 2);
            streams[tape]
                .record_c6_fullfield_plaintexts(domain, &[g0, g2])
                .map_err(C63SparseHClosureError::new)?;
            corrected[tape] = [g0 - correlations[0].x, g2 - correlations[1].x];
            sent[tape] = [correlations[0].authenticate(g0), correlations[1].authenticate(g2)];
            if current[tape].sub(sent[tape][0]).x != g1 {
                return Err(C63SparseHClosureError::new(
                    "C6.3 tape-separated round does not sum to its claim",
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
            fold_low(&mut folded_m[tape], challenge);
        }
        fold_low(&mut a, challenge);
        point.push(challenge);
    }

    let mut terminal_tags = [Fp2::ZERO; C63_SPARSE_H_TAPES];
    for tape in 0..C63_SPARSE_H_TAPES {
        let terminal_m = open_m(tape, &point)?;
        if terminal_m.x != folded_m[tape][0] {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated authenticated m_l opening differs",
            ));
        }
        let residual = current[tape].sub(terminal_m.scale(a[0]));
        if residual.x != Fp2::ZERO {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated terminal product differs",
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

/// Production prover seam for the sparse relation. The private projected
/// correction message stays resident; only two field elements per round cross
/// to the transcript. Public transpose weights are uploaded once and folded
/// beside it.
#[cfg(feature = "cuda")]
pub fn prove_c63_sparse_h_closure_with_spots_resident(
    backend: Arc<Mutex<Backend>>,
    h: &C63SparseSketchReference,
    m: DeviceBuffer<Fp2Repr>,
    u_opening: Fp2,
    statement: &C63SparseHClosureStatement,
    spots: &[C63SystematicSpot],
    streams: &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHClosureProof> {
    let prepared = (|| {
        let (input_log2, output_log2, a) = prepare_relation_from_output_opening(h, statement)?;
        validate_systematic_spots(spots, a.len())?;
        if m.len() != a.len() {
            return Err(C63SparseHClosureError::new(
                "C6.3 resident sparse-H message geometry differs",
            ));
        }
        let claim = u_opening;
        let statement_digest =
            reference_statement_digest(statement, input_log2, output_log2, claim, spots);
        let header = header_bytes(input_log2, output_log2, statement_digest)?;
        Ok((input_log2, output_log2, a, claim, statement_digest, header))
    })();
    let (input_log2, output_log2, mut a, mut claim, statement_digest, header) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Ok(mut locked) = backend.lock() {
                let _ = locked.free_device(m);
            }
            return Err(error);
        }
    };
    transcript.append_message(HEADER_LABEL, &header);
    if !spots.is_empty() {
        fuse_systematic_spots(&mut a, &mut claim, spots, transcript.challenge_fp2());
    }

    let mut fold = ResidentSparseFold::new(backend, vec![m], &a)?;
    if fold.dots()?[0] != claim {
        return Err(C63SparseHClosureError::new("C6.3 resident sparse-H initial claim differs"));
    }
    let mut current = [ProverAuthed::from_public(claim); C63_SPARSE_H_TAPES];
    let mut round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES] =
        array::from_fn(|_| Vec::with_capacity(usize::from(input_log2)));

    for round in 0..usize::from(input_log2) {
        let [g0, g2] = fold.rounds()?[0];
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
        fold.fold(challenge)?;
    }

    let terminal = fold.dots()?[0];
    let mut terminal_tags = [Fp2::ZERO; C63_SPARSE_H_TAPES];
    for tape in 0..C63_SPARSE_H_TAPES {
        let residual = current[tape].sub(ProverAuthed::from_public(terminal));
        if residual.x != Fp2::ZERO {
            return Err(C63SparseHClosureError::new(
                "C6.3 resident sparse-H terminal product differs",
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

/// Selected resident prover: one private message per authentication tape,
/// one shared public transpose vector and one shared challenge sequence.
#[cfg(feature = "cuda")]
#[allow(clippy::too_many_arguments)]
pub fn prove_c63_sparse_h_tape_closure_with_spots_resident<F>(
    backend: Arc<Mutex<Backend>>,
    h: &C63SparseSketchReference,
    messages: [DeviceBuffer<Fp2Repr>; C63_SPARSE_H_TAPES],
    u_claims: [ProverAuthed; C63_SPARSE_H_TAPES],
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    streams: &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
    mut open_m: F,
) -> Result<(C63SparseHClosureProof, Vec<Fp2>)>
where
    F: FnMut(
        usize,
        &[Fp2],
        [u8; 32],
        &mut [CorrelationStream; C63_SPARSE_H_TAPES],
    ) -> Result<ProverAuthed>,
{
    let prepared = (|| {
        let (input_log2, output_log2, mut a) = prepare_relation_from_output_opening(h, statement)?;
        validate_tape_systematic_spots(spots, a.len())?;
        if messages.iter().any(|message| message.len() != a.len()) {
            return Err(C63SparseHClosureError::new("C6.3 resident tape message geometry differs"));
        }
        let statement_digest =
            reference_tape_statement_digest(statement, input_log2, output_log2, spots);
        let header = header_bytes(input_log2, output_log2, statement_digest)?;
        transcript.append_message(HEADER_LABEL, &header);
        let additions = if spots.is_empty() {
            [Fp2::ZERO; C63_SPARSE_H_TAPES]
        } else {
            fuse_tape_systematic_spots(&mut a, spots, transcript.challenge_fp2())
        };
        Ok((input_log2, output_log2, a, additions, statement_digest))
    })();
    let (input_log2, output_log2, a, additions, statement_digest) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Ok(mut locked) = backend.lock() {
                for message in messages {
                    let _ = locked.free_device(message);
                }
            }
            return Err(error);
        }
    };

    let mut current: [ProverAuthed; C63_SPARSE_H_TAPES] =
        std::array::from_fn(|tape| u_claims[tape].add(ProverAuthed::from_public(additions[tape])));
    let mut fold = ResidentSparseFold::new(backend, Vec::from(messages), &a)?;
    if fold.dots()?.as_slice() != current.map(|claim| claim.x) {
        return Err(C63SparseHClosureError::new("C6.3 resident tape initial claims differ"));
    }
    let mut point = Vec::with_capacity(usize::from(input_log2));
    let mut round_corrections: [Vec<[Fp2; 2]>; C63_SPARSE_H_TAPES] =
        array::from_fn(|_| Vec::with_capacity(usize::from(input_log2)));

    for round in 0..usize::from(input_log2) {
        let products = fold.rounds()?;
        let mut corrected = [[Fp2::ZERO; 2]; C63_SPARSE_H_TAPES];
        let mut sent = [[ProverAuthed::ZERO; 2]; C63_SPARSE_H_TAPES];
        for tape in 0..C63_SPARSE_H_TAPES {
            let [g0, g2] = products[tape];
            let domain = correlation_domain(tape, round)?;
            let correlations = streams[tape].draw_fulls(domain, 2);
            streams[tape]
                .record_c6_fullfield_plaintexts(domain, &[g0, g2])
                .map_err(C63SparseHClosureError::new)?;
            corrected[tape] = [g0 - correlations[0].x, g2 - correlations[1].x];
            sent[tape] = [correlations[0].authenticate(g0), correlations[1].authenticate(g2)];
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
        fold.fold(challenge)?;
        point.push(challenge);
    }

    let terminal_a = fold.terminal_a()?;
    let terminal_messages = fold.terminal_messages()?;
    let source_prefix_digest = C63SparseHClosureProof {
        input_log2,
        output_log2,
        statement_digest,
        round_corrections: round_corrections.clone(),
        terminal_tags: [Fp2::ZERO; C63_SPARSE_H_TAPES],
    }
    .source_functional_prefix_digest()?;
    let mut terminal_tags = [Fp2::ZERO; C63_SPARSE_H_TAPES];
    for tape in 0..C63_SPARSE_H_TAPES {
        let terminal_m = open_m(tape, &point, source_prefix_digest, streams)?;
        if terminal_m.x != terminal_messages[tape] {
            return Err(C63SparseHClosureError::new(
                "C6.3 resident tape authenticated opening differs",
            ));
        }
        let residual = current[tape].sub(terminal_m.scale(terminal_a));
        if residual.x != Fp2::ZERO {
            return Err(C63SparseHClosureError::new("C6.3 resident tape terminal product differs"));
        }
        terminal_tags[tape] = residual.m;
    }
    transcript.append_fp2s(TERMINAL_LABEL, &terminal_tags);
    if let Some(error) = transcript.interactive_error() {
        return Err(C63SparseHClosureError::new(error));
    }
    Ok((
        C63SparseHClosureProof {
            input_log2,
            output_log2,
            statement_digest,
            round_corrections,
            terminal_tags,
        },
        point,
    ))
}

#[cfg(feature = "cuda")]
struct ResidentSparseFold {
    backend: Arc<Mutex<Backend>>,
    a: Option<DeviceBuffer<Fp2Repr>>,
    messages: Vec<Option<DeviceBuffer<Fp2Repr>>>,
    len: usize,
}

#[cfg(feature = "cuda")]
impl ResidentSparseFold {
    fn new(
        backend: Arc<Mutex<Backend>>,
        messages: Vec<DeviceBuffer<Fp2Repr>>,
        a: &[Fp2],
    ) -> Result<Self> {
        if messages.is_empty() || messages.iter().any(|message| message.len() != a.len()) {
            if let Ok(mut locked) = backend.lock() {
                for message in messages {
                    let _ = locked.free_device(message);
                }
            }
            return Err(C63SparseHClosureError::new(
                "C6.3 resident sparse message geometry differs",
            ));
        }
        let raw = a.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let a = {
            let mut locked =
                backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
            match locked.upload_new_device(&raw) {
                Ok(a) => a,
                Err(error) => {
                    for message in messages {
                        let _ = locked.free_device(message);
                    }
                    return Err(C63SparseHClosureError::new(error.to_string()));
                }
            }
        };
        Ok(Self {
            backend,
            a: Some(a),
            messages: messages.into_iter().map(Some).collect(),
            len: raw.len(),
        })
    }

    fn dots(&self) -> Result<Vec<Fp2>> {
        let mut locked =
            self.backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
        self.messages
            .iter()
            .map(|message| {
                locked
                    .fp2_dot_device(
                        DeviceSlice::new(self.a.as_ref().expect("resident sparse a"), 0, self.len)
                            .map_err(|error| C63SparseHClosureError::new(error.to_string()))?,
                        DeviceSlice::new(message.as_ref().expect("resident sparse m"), 0, self.len)
                            .map_err(|error| C63SparseHClosureError::new(error.to_string()))?,
                    )
                    .map_err(|error| C63SparseHClosureError::new(error.to_string()))
            })
            .collect()
    }

    fn rounds(&self) -> Result<Vec<[Fp2; 2]>> {
        let mut locked =
            self.backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
        self.messages
            .iter()
            .map(|message| {
                locked
                    .fp2_product_round_device(
                        DeviceSlice::new(self.a.as_ref().expect("resident sparse a"), 0, self.len)
                            .map_err(|error| C63SparseHClosureError::new(error.to_string()))?,
                        DeviceSlice::new(message.as_ref().expect("resident sparse m"), 0, self.len)
                            .map_err(|error| C63SparseHClosureError::new(error.to_string()))?,
                    )
                    .map_err(|error| C63SparseHClosureError::new(error.to_string()))
            })
            .collect()
    }

    fn fold(&mut self, challenge: Fp2) -> Result<()> {
        let mut locked =
            self.backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
        let next_a = locked
            .fp2_fold_rows_device(
                self.a.as_ref().expect("resident sparse a"),
                0,
                1,
                self.len,
                challenge,
            )
            .map_err(|error| C63SparseHClosureError::new(error.to_string()))?;
        let mut next_messages = Vec::with_capacity(self.messages.len());
        for message in &self.messages {
            match locked.fp2_fold_rows_device(
                message.as_ref().expect("resident sparse m"),
                0,
                1,
                self.len,
                challenge,
            ) {
                Ok(value) => next_messages.push(value),
                Err(error) => {
                    let _ = locked.free_device(next_a);
                    for value in next_messages {
                        let _ = locked.free_device(value);
                    }
                    return Err(C63SparseHClosureError::new(error.to_string()));
                }
            }
        }
        let old_a = self.a.take().expect("resident sparse a");
        let old_messages = self
            .messages
            .iter_mut()
            .map(|message| message.take().expect("resident sparse m"))
            .collect::<Vec<_>>();
        let cleanup = locked.free_device(old_a).and_then(|()| {
            for message in old_messages {
                locked.free_device(message)?;
            }
            Ok(())
        });
        if let Err(error) = cleanup {
            let _ = locked.free_device(next_a);
            for message in next_messages {
                let _ = locked.free_device(message);
            }
            return Err(C63SparseHClosureError::new(error.to_string()));
        }
        self.a = Some(next_a);
        self.messages = next_messages.into_iter().map(Some).collect();
        self.len /= 2;
        Ok(())
    }

    fn terminal_a(&self) -> Result<Fp2> {
        if self.len != 1 {
            return Err(C63SparseHClosureError::new("C6.3 sparse fold is not terminal"));
        }
        let mut locked =
            self.backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
        locked
            .download_device(self.a.as_ref().expect("resident sparse a"), 0, 1)
            .map(|values| Fp2::from(values[0]))
            .map_err(|error| C63SparseHClosureError::new(error.to_string()))
    }

    fn terminal_messages(&self) -> Result<Vec<Fp2>> {
        if self.len != 1 {
            return Err(C63SparseHClosureError::new("C6.3 sparse fold is not terminal"));
        }
        let mut locked =
            self.backend.lock().map_err(|_| C63SparseHClosureError::new("CUDA lock"))?;
        self.messages
            .iter()
            .map(|message| {
                locked
                    .download_device(message.as_ref().expect("resident sparse m"), 0, 1)
                    .map(|values| Fp2::from(values[0]))
                    .map_err(|error| C63SparseHClosureError::new(error.to_string()))
            })
            .collect()
    }
}

#[cfg(feature = "cuda")]
impl Drop for ResidentSparseFold {
    fn drop(&mut self) {
        if let Ok(mut locked) = self.backend.lock() {
            if let Some(a) = self.a.take() {
                let _ = locked.free_device(a);
            }
            for message in &mut self.messages {
                if let Some(message) = message.take() {
                    let _ = locked.free_device(message);
                }
            }
        }
    }
}

/// Scaled verifier mirror. It keeps both MAC equations separate while using
/// the supplied witness tables as a compatibility wrapper around the opening
/// based verifier below.
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
    let (input_log2, output_log2, claim, mut a) = prepare_relation(h, m, u, statement)?;
    verify_c63_sparse_h_closure_prepared(
        input_log2,
        output_log2,
        claim,
        &mut a,
        statement,
        spots,
        proof,
        contexts,
        transcript,
        |point| {
            let mut folded_m = m.to_vec();
            for &challenge in point {
                fold_low(&mut folded_m, challenge);
            }
            folded_m.first().copied().ok_or_else(|| {
                C63SparseHClosureError::new("C6.3 sparse-H empty compatibility opening")
            })
        },
    )
}

/// Verifier seam used by the complete C6.3 chain.
///
/// `u_opening` must be the already verified D19 WHIR opening at
/// `statement.output_point()`. Once the sumcheck challenges determine the D22
/// terminal point, `open_m` verifies the matching WHIR opening and returns its
/// value. No full `m` or `u` witness table crosses this verifier boundary.
pub fn verify_c63_sparse_h_closure_from_whir_openings_reference<F>(
    h: &C63SparseSketchReference,
    u_opening: Fp2,
    statement: &C63SparseHClosureStatement,
    spots: &[C63SystematicSpot],
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
    open_m: F,
) -> Result<C63SparseHClosureReferenceAudit>
where
    F: FnOnce(&[Fp2]) -> std::result::Result<Fp2, C63SparseHClosureError>,
{
    let (input_log2, output_log2, mut a) = prepare_relation_from_output_opening(h, statement)?;
    verify_c63_sparse_h_closure_prepared(
        input_log2,
        output_log2,
        u_opening,
        &mut a,
        statement,
        spots,
        proof,
        contexts,
        transcript,
        open_m,
    )
}

/// Selected verifier seam. Each tape supplies its own hidden WHIR openings;
/// only common challenges and the public transpose weights are shared.
pub fn verify_c63_sparse_h_tape_closure_from_whir_openings_reference<F>(
    h: &C63SparseSketchReference,
    u_opening_keys: [VerifierKey; C63_SPARSE_H_TAPES],
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
    mut open_m: F,
) -> Result<C63SparseHTapeClosureReferenceAudit>
where
    F: FnMut(usize, &[Fp2]) -> std::result::Result<VerifierKey, C63SparseHClosureError>,
{
    let pending = begin_verify_c63_sparse_h_tape_closure_reference(
        h, statement, spots, proof, contexts, transcript,
    )?;
    let terminal_m_keys =
        [open_m(0, pending.sumcheck_point())?, open_m(1, pending.sumcheck_point())?];
    pending.finish(u_opening_keys, terminal_m_keys)
}

/// Replay the sparse proof and derive its D22 point without requiring WHIR
/// target keys prematurely. The returned local state is closed only after all
/// eight WHIR bodies have verified.
pub fn begin_verify_c63_sparse_h_tape_closure_reference(
    h: &C63SparseSketchReference,
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
) -> Result<C63SparseHTapeVerifierPending> {
    proof.validate_shape()?;
    if contexts[0].delta == contexts[1].delta {
        return Err(C63SparseHClosureError::new(
            "C6.3 sparse-H MAC tape multipliers are not independent",
        ));
    }
    let (input_log2, output_log2, mut a) = prepare_relation_from_output_opening(h, statement)?;
    validate_tape_systematic_spots(spots, a.len())?;
    let statement_digest =
        reference_tape_statement_digest(statement, input_log2, output_log2, spots);
    if proof.input_log2 != input_log2
        || proof.output_log2 != output_log2
        || proof.statement_digest != statement_digest
    {
        return Err(C63SparseHClosureError::new("C6.3 tape-separated sparse-H statement differs"));
    }
    transcript.append_message(HEADER_LABEL, &proof.header_bytes()?);
    let mut offsets = [VerifierKey::ZERO; C63_SPARSE_H_TAPES];
    if !spots.is_empty() {
        let additions = fuse_tape_systematic_spots(&mut a, spots, transcript.challenge_fp2());
        for tape in 0..C63_SPARSE_H_TAPES {
            offsets[tape] = VerifierKey::from_public(additions[tape], contexts[tape].delta);
        }
    }

    let mut u_coefficient = Fp2::ONE;
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
            offsets[tape] = offsets[tape]
                .scale(weights[1])
                .add(sent[tape][0].scale(weights[0] - weights[1]))
                .add(sent[tape][1].scale(weights[2]));
        }
        u_coefficient = u_coefficient * weights[1];
        fold_low(&mut a, challenge);
        point.push(challenge);
    }

    transcript.append_fp2s(TERMINAL_LABEL, &proof.terminal_tags);
    let transcript_digest =
        transcript.canonical_binding_digest().map_err(C63SparseHClosureError::new)?;
    if transcript.total_bytes() != proof.encoded_len()? {
        return Err(C63SparseHClosureError::new(
            "C6.3 tape-separated sparse-H transcript census differs",
        ));
    }
    Ok(C63SparseHTapeVerifierPending {
        sumcheck_point: point,
        terminal_a: a[0],
        u_coefficient,
        offsets,
        terminal_tags: proof.terminal_tags,
        transcript_digest,
        transcript_bytes: transcript.total_bytes(),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_c63_sparse_h_closure_prepared<F>(
    input_log2: u8,
    output_log2: u8,
    claim: Fp2,
    a: &mut Vec<Fp2>,
    statement: &C63SparseHClosureStatement,
    spots: &[C63SystematicSpot],
    proof: &C63SparseHClosureProof,
    contexts: &mut [VerifierCtx; C63_SPARSE_H_TAPES],
    transcript: &mut Transcript,
    open_m: F,
) -> Result<C63SparseHClosureReferenceAudit>
where
    F: FnOnce(&[Fp2]) -> std::result::Result<Fp2, C63SparseHClosureError>,
{
    proof.validate_shape()?;
    if contexts[0].delta == contexts[1].delta {
        return Err(C63SparseHClosureError::new(
            "C6.3 sparse-H MAC tape multipliers are not independent",
        ));
    }
    validate_systematic_spots(spots, a.len())?;
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
        fuse_systematic_spots(a, &mut claim, spots, transcript.challenge_fp2());
    }

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
        fold_low(a, challenge);
        point.push(challenge);
    }

    let terminal_m = open_m(&point)?;
    transcript.append_fp2s(TERMINAL_LABEL, &proof.terminal_tags);
    let terminal = a[0] * terminal_m;
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
        terminal_m,
        transcript_digest,
        transcript_bytes: transcript.total_bytes(),
    })
}

fn prepare_relation_from_output_opening(
    h: &C63SparseSketchReference,
    statement: &C63SparseHClosureStatement,
) -> Result<(u8, u8, Vec<Fp2>)> {
    let output_log2 = u8::try_from(statement.output_point.len())
        .map_err(|_| C63SparseHClosureError::new("C6.3 sparse-H dimension exceeds u8"))?;
    let q = eq_vec(&statement.output_point);
    let a = h.transpose_weights(&q).map_err(C63SparseHClosureError::new)?;
    let input_log2 = exact_log2(a.len(), "input")?;
    Ok((input_log2, output_log2, a))
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

fn prepare_tape_relation(
    h: &C63SparseSketchReference,
    m: [&[Fp2]; C63_SPARSE_H_TAPES],
    u: [&[Fp2]; C63_SPARSE_H_TAPES],
    statement: &C63SparseHClosureStatement,
) -> Result<(u8, u8, [Fp2; C63_SPARSE_H_TAPES], Vec<Fp2>)> {
    let (input_log2, output_log2, claim0, a) = prepare_relation(h, m[0], u[0], statement)?;
    if m[1].len() != m[0].len() || u[1].len() != u[0].len() {
        return Err(C63SparseHClosureError::new("C6.3 tape-separated message geometry differs"));
    }
    let q = eq_vec(&statement.output_point);
    Ok((input_log2, output_log2, [claim0, inner_product(&q, u[1])?], a))
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

fn validate_tape_systematic_spots(spots: &[C63TapeSystematicSpot], input_len: usize) -> Result<()> {
    let mut previous = None;
    for spot in spots {
        if spot.row as usize >= input_len || previous.is_some_and(|old| old >= spot.row) {
            return Err(C63SparseHClosureError::new(
                "C6.3 tape-separated spots are not sorted, unique and in range",
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

fn fuse_tape_systematic_spots(
    a: &mut [Fp2],
    spots: &[C63TapeSystematicSpot],
    beta: Fp2,
) -> [Fp2; C63_SPARSE_H_TAPES] {
    let mut additions = [Fp2::ZERO; C63_SPARSE_H_TAPES];
    let mut weight = beta;
    for spot in spots {
        a[spot.row as usize] += weight;
        for tape in 0..C63_SPARSE_H_TAPES {
            additions[tape] += weight * spot.values[tape];
        }
        weight = weight * beta;
    }
    additions
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

fn reference_tape_statement_digest(
    statement: &C63SparseHClosureStatement,
    input_log2: u8,
    output_log2: u8,
    spots: &[C63TapeSystematicSpot],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(b"volta-zk/c63/tape-separated/v1");
    hasher.update(&statement.binding_digest);
    hasher.update(&[input_log2, output_log2]);
    for coordinate in &statement.output_point {
        hasher.update(&coordinate.c0.value().to_le_bytes());
        hasher.update(&coordinate.c1.value().to_le_bytes());
    }
    hasher.update(&(spots.len() as u64).to_le_bytes());
    for spot in spots {
        hasher.update(&spot.row.to_le_bytes());
        for value in spot.values {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
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
            .ok_or_else(|| C63SparseHClosureError::new("C63SHC2 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C63SparseHClosureError::new("truncated C63SHC2 proof"))?;
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
            return Err(C63SparseHClosureError::new("noncanonical C63SHC2 field element"));
        }
        Ok(Fp2::new(volta_field::Fp::new(c0), volta_field::Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;

    #[cfg(feature = "cuda")]
    use std::sync::{Arc, Mutex};

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

    fn opening(table: &[Fp2], point: &[Fp2]) -> Result<Fp2> {
        if table.len() != 1usize << point.len() {
            return Err(C63SparseHClosureError::new("test opening geometry differs"));
        }
        let mut folded = table.to_vec();
        for &challenge in point {
            fold_low(&mut folded, challenge);
        }
        Ok(folded[0])
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

        let u_opening = opening(&u, statement.output_point()).unwrap();
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let opening_audit = verify_c63_sparse_h_closure_from_whir_openings_reference(
            &h,
            u_opening,
            &statement,
            &[],
            &decoded,
            &mut contexts,
            &mut transcript,
            |point| opening(&m, point),
        )
        .unwrap();
        assert_eq!(opening_audit, audit);
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
        assert_ne!(
            bad_round.source_functional_prefix_digest().unwrap(),
            proof.source_functional_prefix_digest().unwrap()
        );
        assert!(verify(&h, &m, &u, &statement, &bad_round, TRANSCRIPT_SEED).is_err());

        assert!(verify(&h, &m, &u, &statement, &proof, [0xB2; 32]).is_err());

        let mut bad_terminal = proof.clone();
        bad_terminal.terminal_tags[0] += Fp2::ONE;
        assert_eq!(
            bad_terminal.source_functional_prefix_digest().unwrap(),
            proof.source_functional_prefix_digest().unwrap()
        );
        assert!(verify(&h, &m, &u, &statement, &bad_terminal, TRANSCRIPT_SEED).is_err());

        let u_opening = opening(&u, statement.output_point()).unwrap();
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        assert!(verify_c63_sparse_h_closure_from_whir_openings_reference(
            &h,
            u_opening,
            &statement,
            &[],
            &proof,
            &mut contexts,
            &mut transcript,
            |point| Ok(opening(&m, point)? + Fp2::ONE),
        )
        .is_err());
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

    #[test]
    fn tape_separated_sparse_h_binds_both_distinct_whir_targets() {
        let (h, m0, _, statement) = fixture();
        let m1 = (0..m0.len()).map(|index| fp2(71 + index as u64)).collect::<Vec<_>>();
        let u0 = h.apply(&m0).unwrap();
        let u1 = h.apply(&m1).unwrap();
        let messages = [m0, m1];
        let sketches = [u0, u1];
        let spots = [
            C63TapeSystematicSpot { row: 1, values: [messages[0][1], messages[1][1]] },
            C63TapeSystematicSpot { row: 5, values: [messages[0][5], messages[1][5]] },
        ];
        let u_values = [
            opening(&sketches[0], statement.output_point()).unwrap(),
            opening(&sketches[1], statement.output_point()).unwrap(),
        ];
        let u_tags = [fp2(211), fp2(223)];
        let m_tags = [fp2(227), fp2(229)];
        let u_claims = array::from_fn(|tape| ProverAuthed::new(u_values[tape], u_tags[tape]));
        let u_opening_keys =
            array::from_fn(|tape| VerifierKey::new(u_tags[tape] + DELTAS[tape] * u_values[tape]));
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED);
        let proof = prove_c63_sparse_h_tape_closure_with_spots_reference(
            &h,
            [&messages[0], &messages[1]],
            [&sketches[0], &sketches[1]],
            u_claims,
            &statement,
            &spots,
            &mut streams,
            &mut prover_transcript,
            |tape, point| Ok(ProverAuthed::new(opening(&messages[tape], point)?, m_tags[tape])),
        )
        .unwrap();
        assert_eq!(proof.encoded_len().unwrap(), 56 + 3 * 64 + 32);
        assert_eq!(streams.map(|stream| stream.counters.full_corrs), [6, 6]);

        let verify = |opening_keys, selected_spots: &[C63TapeSystematicSpot], proof| {
            let mut contexts =
                array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
            let mut transcript = Transcript::new(TRANSCRIPT_SEED);
            verify_c63_sparse_h_tape_closure_from_whir_openings_reference(
                &h,
                opening_keys,
                &statement,
                selected_spots,
                proof,
                &mut contexts,
                &mut transcript,
                |tape, point| {
                    Ok(VerifierKey::new(
                        m_tags[tape] + DELTAS[tape] * opening(&messages[tape], point)?,
                    ))
                },
            )
        };
        let audit = verify(u_opening_keys, &spots, &proof).unwrap();
        assert_eq!(audit.transcript_digest, prover_transcript.canonical_binding_digest().unwrap());
        assert_eq!(
            audit.terminal_m_keys,
            array::from_fn(|tape| VerifierKey::new(
                m_tags[tape]
                    + DELTAS[tape] * opening(&messages[tape], &audit.sumcheck_point).unwrap()
            ))
        );

        assert!(verify([u_opening_keys[1], u_opening_keys[0]], &spots, &proof).is_err());
        let mut changed_spots = spots;
        changed_spots[0].values[1] += Fp2::ONE;
        assert!(verify(u_opening_keys, &changed_spots, &proof).is_err());
        let mut changed_round = proof.clone();
        changed_round.round_corrections[1][0][0] += Fp2::ONE;
        assert!(verify(u_opening_keys, &spots, &changed_round).is_err());

        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        assert!(verify_c63_sparse_h_tape_closure_from_whir_openings_reference(
            &h,
            u_opening_keys,
            &statement,
            &spots,
            &proof,
            &mut contexts,
            &mut transcript,
            |tape, point| {
                let wrong_tape = usize::from(tape == 0);
                Ok(VerifierKey::new(
                    m_tags[tape] + DELTAS[tape] * opening(&messages[wrong_tape], point)?,
                ))
            },
        )
        .is_err());
    }

    #[cfg(feature = "cuda")]
    #[test]
    #[ignore = "requires the production ABI44 CUDA library"]
    fn resident_sparse_h_matches_the_cpu_reference_and_releases_memory() {
        let (h, m, u, statement) = fixture();
        let spots =
            [C63SystematicSpot { row: 1, value: m[1] }, C63SystematicSpot { row: 5, value: m[5] }];
        let (expected, expected_transcript, expected_correlations) =
            prove_with_spots(&h, &m, &u, &statement, &spots).unwrap();
        let u_opening = opening(&u, statement.output_point()).unwrap();

        let backend = Arc::new(Mutex::new(Backend::cuda_resident().unwrap()));
        let resident_before =
            backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes;
        let message = backend
            .lock()
            .unwrap()
            .upload_new_device(&m.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>())
            .unwrap();
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let proof = prove_c63_sparse_h_closure_with_spots_resident(
            Arc::clone(&backend),
            &h,
            message,
            u_opening,
            &statement,
            &spots,
            &mut streams,
            &mut transcript,
        )
        .unwrap();

        assert_eq!(proof, expected);
        assert_eq!(
            array::from_fn::<_, 2, _>(|tape| streams[tape].counters.full_corrs),
            expected_correlations,
        );
        assert_eq!(transcript.ledger(), expected_transcript.ledger());
        assert_eq!(
            transcript.canonical_binding_digest().unwrap(),
            expected_transcript.canonical_binding_digest().unwrap(),
        );
        assert_eq!(
            backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes,
            resident_before,
        );

        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED);
        verify_c63_sparse_h_closure_from_whir_openings_reference(
            &h,
            u_opening,
            &statement,
            &spots,
            &proof,
            &mut contexts,
            &mut verifier_transcript,
            |point| opening(&m, point),
        )
        .unwrap();
    }
}

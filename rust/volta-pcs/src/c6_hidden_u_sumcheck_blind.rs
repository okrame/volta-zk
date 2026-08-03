//! Dual-tape blind C6 hidden-`u` sumcheck and pending-source adapter.
//!
//! `C6HUSC1` remains the clear arithmetic oracle.  This v2 layer sends only
//! corrected `g(0),g(2)` nodes on both MAC tapes, reconstructs `g(1)` from
//! the authenticated live claim, and converts the two terminal `U(r)` values
//! per repetition into opaque pending sources.  A post-transfer challenge
//! batches the two terminal functional equations before one ZeroOpen per
//! tape.  Slots 1..7 of each hidden cohort are public-zero capacity
//! constraints; slot 0 is the actual padded hidden oracle.

use std::{array, fmt};

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_prover, zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey, RESERVED_DOMAIN_BITS,
};
use volta_proto::mle::lagrange3;

use crate::c6_hidden_u::{
    C6HiddenUDigest, C6HiddenUFamily, C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUPrequery,
    C6SealedHiddenUBundle, C6_HIDDEN_U_REPETITIONS,
};
use crate::c6_hidden_u_sumcheck::{
    build_schedules, evaluate_functional, hidden_u_round_count,
    prepare_hidden_u_prover_round_state, validate_layouts, C6HiddenUProverRoundState,
    FamilySchedule,
};

pub const C6_BLIND_HIDDEN_U_MAGIC: [u8; 8] = *b"C6HUB2\0\0";
pub const C6_BLIND_HIDDEN_U_VERSION: u16 = 2;
pub const C6_BLIND_HIDDEN_U_TAPES: usize = 2;
pub const C6_BLIND_HIDDEN_U_FAMILIES: usize = 2;
pub const C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY: u16 = 8;
pub const C6_BLIND_HIDDEN_U_PRODUCTION_ROUND_VALUES_PER_REPETITION: u64 = 2 * (21 + 19);
pub const C6_BLIND_HIDDEN_U_PRODUCTION_FULL_CORRELATIONS_PER_TAPE: u64 =
    2 * C6_BLIND_HIDDEN_U_PRODUCTION_ROUND_VALUES_PER_REPETITION + 4;
pub const C6_BLIND_HIDDEN_U_PRODUCTION_BYTES: u64 = 5_416;

const PROOF_DOMAIN: &str = "volta-zk/c6/hidden-u-sumcheck-proof/v2";
const STATEMENT_DOMAIN: &str = "volta-zk/c6/hidden-u-sumcheck-statement/v2";
const FRAMING_LABEL: &str = "c6_hidden_u_blind_framing";
const ROUND_LABEL: &str = "c6_hidden_u_blind_round_corrections";
const PENDING_LABEL: &str = "c6_hidden_u_blind_pending_corrections";
const FIXED_FRAMING_BYTES: u64 = 104;
const FP2_BYTES: u64 = 16;
const CORRELATION_BASE: u64 = 0x0C62_0000_0000_0000;

type Result<T> = std::result::Result<T, C6BlindHiddenUError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindHiddenUError(String);

impl C6BlindHiddenUError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6BlindHiddenUError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6BlindHiddenUError {}

fn hidden_error(error: impl fmt::Display) -> C6BlindHiddenUError {
    C6BlindHiddenUError::new(error.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindHiddenUFamilyProof {
    family: C6HiddenUFamily,
    round_corrections: [Vec<[Fp2; 2]>; C6_BLIND_HIDDEN_U_TAPES],
    pending_corrections: [Fp2; C6_BLIND_HIDDEN_U_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6BlindHiddenURepetitionProof {
    families: Vec<C6BlindHiddenUFamilyProof>,
    terminal_tags: [Fp2; C6_BLIND_HIDDEN_U_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindHiddenUSumcheckProof {
    statement_digest: C6HiddenUDigest,
    repetitions: Vec<C6BlindHiddenURepetitionProof>,
}

impl C6BlindHiddenUSumcheckProof {
    pub fn statement_digest(&self) -> C6HiddenUDigest {
        self.statement_digest
    }

    pub fn encode(&self, layouts: &[C6HiddenULayout]) -> Result<Vec<u8>> {
        self.validate_shape(layouts)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(blind_hidden_u_sumcheck_encoded_len(layouts)?)
                .map_err(|_| C6BlindHiddenUError::new("C6HUB2 encoded length exceeds usize"))?,
        );
        bytes.extend_from_slice(&C6_BLIND_HIDDEN_U_MAGIC);
        bytes.extend_from_slice(&C6_BLIND_HIDDEN_U_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.repetitions.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(C6_BLIND_HIDDEN_U_TAPES as u16).to_le_bytes());
        bytes.extend_from_slice(&(layouts.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for (repetition_index, repetition) in self.repetitions.iter().enumerate() {
            bytes.push(repetition_index as u8);
            bytes.push(repetition.families.len() as u8);
            bytes.extend_from_slice(&0u16.to_le_bytes());
            for (family, layout) in repetition.families.iter().zip(layouts) {
                bytes.push(family.family as u8);
                bytes.push(layout.padded_entries().ilog2() as u8);
                bytes.extend_from_slice(&0u16.to_le_bytes());
                for round in 0..family.round_corrections[0].len() {
                    for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                        for value in family.round_corrections[tape][round] {
                            encode_fp2(&mut bytes, value);
                        }
                    }
                }
                for correction in family.pending_corrections {
                    encode_fp2(&mut bytes, correction);
                }
            }
            for tag in repetition.terminal_tags {
                encode_fp2(&mut bytes, tag);
            }
        }
        bytes.extend_from_slice(&proof_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(
        layouts: &[C6HiddenULayout],
        expected_statement_digest: C6HiddenUDigest,
        bytes: &[u8],
    ) -> Result<Self> {
        validate_layouts(layouts).map_err(hidden_error)?;
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C6_BLIND_HIDDEN_U_MAGIC {
            return Err(C6BlindHiddenUError::new("bad C6HUB2 magic"));
        }
        if cursor.u16()? != C6_BLIND_HIDDEN_U_VERSION
            || cursor.u16()? as usize != C6_HIDDEN_U_REPETITIONS as usize
            || cursor.u16()? as usize != C6_BLIND_HIDDEN_U_TAPES
            || cursor.u16()? as usize != layouts.len()
        {
            return Err(C6BlindHiddenUError::new("C6HUB2 header census mismatch"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest != expected_statement_digest {
            return Err(C6BlindHiddenUError::new("C6HUB2 statement digest mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_HIDDEN_U_REPETITIONS as usize);
        for repetition_index in 0..C6_HIDDEN_U_REPETITIONS as usize {
            if cursor.u8()? as usize != repetition_index
                || cursor.u8()? as usize != layouts.len()
                || cursor.u16()? != 0
            {
                return Err(C6BlindHiddenUError::new("C6HUB2 repetition header mismatch"));
            }
            let mut families = Vec::with_capacity(layouts.len());
            for layout in layouts {
                let family = decode_family(cursor.u8()?)?;
                let rounds = cursor.u8()? as usize;
                if family != layout.family
                    || rounds != layout.padded_entries().ilog2() as usize
                    || cursor.u16()? != 0
                {
                    return Err(C6BlindHiddenUError::new("C6HUB2 family header mismatch"));
                }
                let mut round_corrections: [Vec<[Fp2; 2]>; C6_BLIND_HIDDEN_U_TAPES] =
                    array::from_fn(|_| Vec::with_capacity(rounds));
                for _ in 0..rounds {
                    for tape_corrections in &mut round_corrections {
                        tape_corrections.push([cursor.fp2()?, cursor.fp2()?]);
                    }
                }
                let pending_corrections = [cursor.fp2()?, cursor.fp2()?];
                families.push(C6BlindHiddenUFamilyProof {
                    family,
                    round_corrections,
                    pending_corrections,
                });
            }
            let terminal_tags = [cursor.fp2()?, cursor.fp2()?];
            repetitions.push(C6BlindHiddenURepetitionProof { families, terminal_tags });
        }
        let digest_offset = cursor.position();
        let encoded_digest = cursor.digest()?;
        if !cursor.is_eof() || encoded_digest != proof_digest(&bytes[..digest_offset]) {
            return Err(C6BlindHiddenUError::new("noncanonical or trailing C6HUB2 bytes"));
        }
        let proof = Self { statement_digest, repetitions };
        proof.validate_shape(layouts)?;
        Ok(proof)
    }

    fn validate_shape(&self, layouts: &[C6HiddenULayout]) -> Result<()> {
        validate_layouts(layouts).map_err(hidden_error)?;
        if self.statement_digest == [0; 32]
            || layouts.len() != C6_BLIND_HIDDEN_U_FAMILIES
            || self.repetitions.len() != C6_HIDDEN_U_REPETITIONS as usize
        {
            return Err(C6BlindHiddenUError::new("C6HUB2 proof shape mismatch"));
        }
        for repetition in &self.repetitions {
            if repetition.families.len() != layouts.len() {
                return Err(C6BlindHiddenUError::new("C6HUB2 family count mismatch"));
            }
            for (family, layout) in repetition.families.iter().zip(layouts) {
                let rounds = layout.padded_entries().ilog2() as usize;
                if family.family != layout.family
                    || family
                        .round_corrections
                        .iter()
                        .any(|corrections| corrections.len() != rounds)
                {
                    return Err(C6BlindHiddenUError::new("C6HUB2 round shape mismatch"));
                }
            }
        }
        Ok(())
    }
}

pub fn blind_hidden_u_sumcheck_encoded_len(layouts: &[C6HiddenULayout]) -> Result<u64> {
    validate_layouts(layouts).map_err(hidden_error)?;
    if layouts.len() != C6_BLIND_HIDDEN_U_FAMILIES {
        return Err(C6BlindHiddenUError::new("C6HUB2 requires two hidden families"));
    }
    let rounds = layouts.iter().try_fold(0u64, |sum, layout| {
        sum.checked_add(u64::from(layout.padded_entries().ilog2()))
            .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 round count overflow"))
    })?;
    let repetitions = C6_HIDDEN_U_REPETITIONS;
    let families = u64::try_from(layouts.len())
        .map_err(|_| C6BlindHiddenUError::new("C6HUB2 family count exceeds u64"))?;
    // Header 48; repetition header 4; family header 4; two corrected nodes
    // on two tapes per round; two terminal corrections per family; two
    // terminal tags per repetition; final digest 32.
    48u64
        .checked_add(
            repetitions
                .checked_mul(4)
                .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 repetition framing overflow"))?,
        )
        .and_then(|bytes| bytes.checked_add(repetitions.checked_mul(families)?.checked_mul(4)?))
        .and_then(|bytes| {
            bytes.checked_add(
                repetitions
                    .checked_mul(rounds)?
                    .checked_mul(C6_BLIND_HIDDEN_U_TAPES as u64)?
                    .checked_mul(2)?
                    .checked_mul(FP2_BYTES)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                repetitions
                    .checked_mul(families)?
                    .checked_mul(C6_BLIND_HIDDEN_U_TAPES as u64)?
                    .checked_mul(FP2_BYTES)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                repetitions.checked_mul(C6_BLIND_HIDDEN_U_TAPES as u64)?.checked_mul(FP2_BYTES)?,
            )
        })
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 encoded length overflow"))
}

pub fn production_c6_blind_hidden_u_sumcheck_encoded_len() -> u64 {
    let layouts = [C6HiddenULayout::production_weights(), C6HiddenULayout::production_embed()];
    blind_hidden_u_sumcheck_encoded_len(&layouts).expect("valid production C6HUB2 geometry")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6BlindHiddenUPendingDescriptor {
    statement_digest: C6HiddenUDigest,
    repetition: u8,
    family: C6HiddenUFamily,
    slot: u16,
    point: Vec<Fp2>,
}

impl C6BlindHiddenUPendingDescriptor {
    pub(crate) fn statement_digest(&self) -> C6HiddenUDigest {
        self.statement_digest
    }

    pub(crate) fn repetition(&self) -> u8 {
        self.repetition
    }

    pub(crate) fn family(&self) -> C6HiddenUFamily {
        self.family
    }

    pub(crate) fn slot(&self) -> u16 {
        self.slot
    }

    pub(crate) fn point(&self) -> &[Fp2] {
        &self.point
    }
}

#[derive(Clone)]
pub(crate) struct PendingProverEntry {
    descriptor: C6BlindHiddenUPendingDescriptor,
    auth: [ProverAuthed; C6_BLIND_HIDDEN_U_TAPES],
}

#[derive(Clone)]
pub(crate) struct PendingVerifierEntry {
    descriptor: C6BlindHiddenUPendingDescriptor,
    keys: [VerifierKey; C6_BLIND_HIDDEN_U_TAPES],
}

pub struct C6BlindHiddenUPendingClaimsProver {
    entries: Vec<PendingProverEntry>,
}

pub struct C6BlindHiddenUPendingClaimsVerifier {
    entries: Vec<PendingVerifierEntry>,
}

impl fmt::Debug for C6BlindHiddenUPendingClaimsProver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BlindHiddenUPendingClaimsProver")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for C6BlindHiddenUPendingClaimsVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BlindHiddenUPendingClaimsVerifier")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl C6BlindHiddenUPendingClaimsProver {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn link_entries(
        &self,
    ) -> impl Iterator<Item = (&C6BlindHiddenUPendingDescriptor, [ProverAuthed; C6_BLIND_HIDDEN_U_TAPES])>
    {
        self.entries.iter().map(|entry| (&entry.descriptor, entry.auth))
    }
}

impl C6BlindHiddenUPendingClaimsVerifier {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn link_entries(
        &self,
    ) -> impl Iterator<Item = (&C6BlindHiddenUPendingDescriptor, [VerifierKey; C6_BLIND_HIDDEN_U_TAPES])>
    {
        self.entries.iter().map(|entry| (&entry.descriptor, entry.keys))
    }
}

pub(crate) struct C6BlindHiddenUProverRoundState {
    repetition: u8,
    layouts: Vec<C6HiddenULayout>,
    schedules: Vec<FamilySchedule>,
    q_cols: Vec<Vec<Vec<Fp2>>>,
    statement_digest: C6HiddenUDigest,
    arithmetic: C6HiddenUProverRoundState,
    current: [[Option<ProverAuthed>; C6_BLIND_HIDDEN_U_TAPES]; C6_BLIND_HIDDEN_U_FAMILIES],
    proof_builders: [[Vec<[Fp2; 2]>; C6_BLIND_HIDDEN_U_TAPES]; C6_BLIND_HIDDEN_U_FAMILIES],
    points: Vec<Vec<Fp2>>,
    pending_nodes:
        Option<[[Option<[ProverAuthed; 3]>; C6_BLIND_HIDDEN_U_TAPES]; C6_BLIND_HIDDEN_U_FAMILIES]>,
}

pub(crate) fn begin_c6_blind_hidden_u_stepwise(
    sealed: &C6SealedHiddenUBundle,
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    transcript: &mut Transcript,
) -> Result<C6HiddenUDigest> {
    let layouts = sealed.validate_prequery_binding(prequery).map_err(hidden_error)?;
    validate_protocol_layouts(&layouts)?;
    if postcommit.prequery_digest != prequery.digest() {
        return Err(C6BlindHiddenUError::new("C6HUB2 prequery mismatch"));
    }
    postcommit.validate(&layouts).map_err(hidden_error)?;
    let statement_digest = statement_digest(&layouts, prequery, postcommit)?;
    transcript.append(FRAMING_LABEL, FIXED_FRAMING_BYTES - 32);
    Ok(statement_digest)
}

pub(crate) fn prepare_c6_blind_hidden_u_prover_round_state(
    sealed: &C6SealedHiddenUBundle,
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    repetition: u8,
) -> Result<C6BlindHiddenUProverRoundState> {
    let layouts = sealed.validate_prequery_binding(prequery).map_err(hidden_error)?;
    validate_protocol_layouts(&layouts)?;
    if postcommit.prequery_digest != prequery.digest() {
        return Err(C6BlindHiddenUError::new("C6HUB2 prequery mismatch"));
    }
    postcommit.validate(&layouts).map_err(hidden_error)?;
    let q_cols =
        sealed.families().iter().map(|family| family.q_cols().to_vec()).collect::<Vec<_>>();
    let schedules =
        build_schedules(&layouts, prequery, postcommit, &q_cols).map_err(hidden_error)?;
    let statement_digest = statement_digest(&layouts, prequery, postcommit)?;
    let arithmetic = prepare_hidden_u_prover_round_state(sealed, prequery, postcommit, repetition)
        .map_err(hidden_error)?;
    let proof_builders = array::from_fn(|family| {
        let rounds = layouts[family].padded_entries().ilog2() as usize;
        array::from_fn(|_| Vec::with_capacity(rounds))
    });
    Ok(C6BlindHiddenUProverRoundState {
        repetition,
        points: vec![Vec::new(); layouts.len()],
        layouts,
        schedules,
        q_cols,
        statement_digest,
        arithmetic,
        current: array::from_fn(|_| array::from_fn(|_| None)),
        proof_builders,
        pending_nodes: None,
    })
}

impl C6BlindHiddenUProverRoundState {
    #[allow(dead_code)]
    pub(crate) fn repetition(&self) -> u8 {
        self.repetition
    }

    pub(crate) fn round_index(&self) -> usize {
        self.arithmetic.round_index()
    }

    pub(crate) fn round_count(&self) -> usize {
        self.arithmetic.round_count()
    }

    pub(crate) fn fix_next_round(
        &mut self,
        streams: &mut [CorrelationStream; C6_BLIND_HIDDEN_U_TAPES],
    ) -> Result<u64> {
        if self.pending_nodes.is_some() || self.arithmetic.is_complete() {
            return Err(C6BlindHiddenUError::new(
                "C6HUB2 step-wise prover is not awaiting a round message",
            ));
        }
        self.arithmetic.fix_next_round().map_err(hidden_error)?;
        let messages = self.arithmetic.fixed_active_messages().map_err(hidden_error)?;
        let active = messages.len();
        let mut nodes: [[Option<[ProverAuthed; 3]>; C6_BLIND_HIDDEN_U_TAPES];
            C6_BLIND_HIDDEN_U_FAMILIES] = array::from_fn(|_| array::from_fn(|_| None));
        for message in messages {
            let family_index = family_index(message.family)?;
            for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                let live = self.current[family_index][tape]
                    .unwrap_or_else(|| ProverAuthed::from_public(message.initial_claim));
                if message.evaluations[0] + message.evaluations[1] != live.x {
                    return Err(C6BlindHiddenUError::new(
                        "C6HUB2 clear arithmetic diverges from authenticated live claim",
                    ));
                }
                let domain = correlation_domain(
                    self.repetition,
                    tape,
                    round_purpose(message.family),
                    message.local_round,
                )?;
                let (corrections, sent) = authenticate_values(
                    &mut streams[tape],
                    domain,
                    &[message.evaluations[0], message.evaluations[2]],
                )?;
                self.proof_builders[family_index][tape].push([corrections[0], corrections[1]]);
                let g1 = live.sub(sent[0]);
                if g1.x != message.evaluations[1] {
                    return Err(C6BlindHiddenUError::new(
                        "C6HUB2 compressed node-one reconstruction mismatch",
                    ));
                }
                nodes[family_index][tape] = Some([sent[0], g1, sent[1]]);
            }
        }
        self.pending_nodes = Some(nodes);
        u64::try_from(active)
            .ok()
            .and_then(|families| families.checked_mul(2 * C6_BLIND_HIDDEN_U_TAPES as u64))
            .and_then(|values| values.checked_mul(FP2_BYTES))
            .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 round byte count overflows"))
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6BlindHiddenUError::new("C6HUB2 prover challenge precedes round message")
        })?;
        self.arithmetic.bind_challenge(challenge).map_err(hidden_error)?;
        let weights = lagrange3(challenge);
        for family_index in 0..self.layouts.len() {
            if nodes[family_index][0].is_none() {
                continue;
            }
            self.points[family_index].push(challenge);
            for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                let round_nodes = nodes[family_index][tape]
                    .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 cross-tape round gap"))?;
                self.current[family_index][tape] = Some(interpolate_prover(round_nodes, weights));
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        streams: &mut [CorrelationStream; C6_BLIND_HIDDEN_U_TAPES],
        transcript: &mut Transcript,
    ) -> Result<(C6BlindHiddenURepetitionProof, Vec<PendingProverEntry>)> {
        if self.pending_nodes.is_some() || !self.arithmetic.is_complete() {
            return Err(C6BlindHiddenUError::new("incomplete C6HUB2 step-wise prover repetition"));
        }
        let (_, clear_claims) = self.arithmetic.finish().map_err(hidden_error)?;
        if clear_claims.len() != self.layouts.len() {
            return Err(C6BlindHiddenUError::new("C6HUB2 terminal family census mismatch"));
        }
        let mut pending_entries = Vec::with_capacity(
            C6_BLIND_HIDDEN_U_FAMILIES * C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY as usize,
        );
        let mut family_proofs = Vec::with_capacity(self.layouts.len());
        let mut terminal_residuals: [[ProverAuthed; C6_BLIND_HIDDEN_U_FAMILIES];
            C6_BLIND_HIDDEN_U_TAPES] =
            array::from_fn(|_| [ProverAuthed::ZERO; C6_BLIND_HIDDEN_U_FAMILIES]);
        for family_index in 0..self.layouts.len() {
            let claim = &clear_claims[family_index];
            if claim.family != self.layouts[family_index].family
                || claim.point != self.points[family_index]
            {
                return Err(C6BlindHiddenUError::new("C6HUB2 terminal point mismatch"));
            }
            let functional = evaluate_functional(
                self.layouts[family_index],
                &self.schedules[family_index],
                usize::from(self.repetition),
                &self.q_cols[family_index],
                &claim.point,
            )
            .map_err(hidden_error)?;
            let mut pending_corrections = [Fp2::ZERO; C6_BLIND_HIDDEN_U_TAPES];
            let mut pending_auth = [ProverAuthed::ZERO; C6_BLIND_HIDDEN_U_TAPES];
            for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                let domain =
                    correlation_domain(self.repetition, tape, pending_purpose(claim.family), 0)?;
                let (corrections, auth) =
                    authenticate_values(&mut streams[tape], domain, &[claim.value])?;
                pending_corrections[tape] = corrections[0];
                pending_auth[tape] = auth[0];
                transcript.append(PENDING_LABEL, FP2_BYTES);
                let live = self.current[family_index][tape].ok_or_else(|| {
                    C6BlindHiddenUError::new("missing C6HUB2 terminal live claim")
                })?;
                terminal_residuals[tape][family_index] = live.sub(auth[0].scale(functional));
                if terminal_residuals[tape][family_index].x != Fp2::ZERO {
                    return Err(C6BlindHiddenUError::new(
                        "C6HUB2 terminal functional residual is nonzero",
                    ));
                }
            }
            append_family_pending_prover_entries(
                &mut pending_entries,
                self.statement_digest,
                self.repetition,
                claim.family,
                claim.point.clone(),
                pending_auth,
            );
            family_proofs.push(C6BlindHiddenUFamilyProof {
                family: claim.family,
                round_corrections: std::mem::take(&mut self.proof_builders[family_index]),
                pending_corrections,
            });
        }
        let eta = transcript.challenge_fp2();
        let terminal_tags = array::from_fn(|tape| {
            let aggregate = terminal_residuals[tape][0].add(terminal_residuals[tape][1].scale(eta));
            zero_open_prover(&aggregate, transcript)
        });
        Ok((
            C6BlindHiddenURepetitionProof { families: family_proofs, terminal_tags },
            pending_entries,
        ))
    }
}

pub(crate) struct C6BlindHiddenUVerifierRoundState {
    repetition: u8,
    layouts: Vec<C6HiddenULayout>,
    schedules: Vec<FamilySchedule>,
    q_cols: Vec<Vec<Vec<Fp2>>>,
    statement_digest: C6HiddenUDigest,
    repetition_proof: C6BlindHiddenURepetitionProof,
    current: [[Option<VerifierKey>; C6_BLIND_HIDDEN_U_TAPES]; C6_BLIND_HIDDEN_U_FAMILIES],
    points: Vec<Vec<Fp2>>,
    max_rounds: usize,
    global_round: usize,
    pending_nodes:
        Option<[[Option<[VerifierKey; 3]>; C6_BLIND_HIDDEN_U_TAPES]; C6_BLIND_HIDDEN_U_FAMILIES]>,
}

pub(crate) fn begin_c6_blind_hidden_u_verifier_stepwise(
    layouts: &[C6HiddenULayout],
    q_cols: &[Vec<Vec<Fp2>>],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    proof: &C6BlindHiddenUSumcheckProof,
    transcript: &mut Transcript,
) -> Result<C6HiddenUDigest> {
    validate_protocol_layouts(layouts)?;
    if postcommit.prequery_digest != prequery.digest() {
        return Err(C6BlindHiddenUError::new("C6HUB2 prequery mismatch"));
    }
    postcommit.validate(layouts).map_err(hidden_error)?;
    build_schedules(layouts, prequery, postcommit, q_cols).map_err(hidden_error)?;
    let expected_statement = statement_digest(layouts, prequery, postcommit)?;
    if proof.statement_digest != expected_statement {
        return Err(C6BlindHiddenUError::new("C6HUB2 proof statement mismatch"));
    }
    proof.validate_shape(layouts)?;
    transcript.append(FRAMING_LABEL, FIXED_FRAMING_BYTES - 32);
    Ok(expected_statement)
}

pub(crate) fn prepare_c6_blind_hidden_u_verifier_round_state(
    layouts: &[C6HiddenULayout],
    q_cols: &[Vec<Vec<Fp2>>],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    proof: &C6BlindHiddenUSumcheckProof,
    repetition: u8,
) -> Result<C6BlindHiddenUVerifierRoundState> {
    validate_protocol_layouts(layouts)?;
    if usize::from(repetition) >= C6_HIDDEN_U_REPETITIONS as usize
        || postcommit.prequery_digest != prequery.digest()
    {
        return Err(C6BlindHiddenUError::new("C6HUB2 verifier repetition or prequery mismatch"));
    }
    postcommit.validate(layouts).map_err(hidden_error)?;
    let schedules = build_schedules(layouts, prequery, postcommit, q_cols).map_err(hidden_error)?;
    let statement_digest = statement_digest(layouts, prequery, postcommit)?;
    if proof.statement_digest != statement_digest {
        return Err(C6BlindHiddenUError::new("C6HUB2 proof statement mismatch"));
    }
    proof.validate_shape(layouts)?;
    Ok(C6BlindHiddenUVerifierRoundState {
        repetition,
        layouts: layouts.to_vec(),
        schedules,
        q_cols: q_cols.to_vec(),
        statement_digest,
        repetition_proof: proof.repetitions[usize::from(repetition)].clone(),
        current: array::from_fn(|_| array::from_fn(|_| None)),
        points: vec![Vec::new(); layouts.len()],
        max_rounds: hidden_u_round_count(layouts).map_err(hidden_error)?,
        global_round: 0,
        pending_nodes: None,
    })
}

impl C6BlindHiddenUVerifierRoundState {
    #[allow(dead_code)]
    pub(crate) fn repetition(&self) -> u8 {
        self.repetition
    }

    pub(crate) fn round_index(&self) -> usize {
        self.global_round
    }

    pub(crate) fn round_count(&self) -> usize {
        self.max_rounds
    }

    pub(crate) fn check_next_round(
        &mut self,
        contexts: &mut [VerifierCtx; C6_BLIND_HIDDEN_U_TAPES],
    ) -> Result<u64> {
        if self.pending_nodes.is_some() || self.global_round >= self.max_rounds {
            return Err(C6BlindHiddenUError::new(
                "C6HUB2 step-wise verifier is not awaiting a round message",
            ));
        }
        let mut nodes: [[Option<[VerifierKey; 3]>; C6_BLIND_HIDDEN_U_TAPES];
            C6_BLIND_HIDDEN_U_FAMILIES] = array::from_fn(|_| array::from_fn(|_| None));
        let mut active = 0u64;
        for family_index in 0..self.layouts.len() {
            let rounds = self.layouts[family_index].padded_entries().ilog2() as usize;
            let start = self.max_rounds - rounds;
            if self.global_round < start {
                continue;
            }
            active += 1;
            let local_round = self.global_round - start;
            for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                let live = self.current[family_index][tape].unwrap_or(VerifierKey::from_public(
                    self.schedules[family_index]
                        .initial_claim(usize::from(self.repetition))
                        .map_err(hidden_error)?,
                    contexts[tape].delta,
                ));
                let corrections = self.repetition_proof.families[family_index].round_corrections
                    [tape][local_round];
                let domain = correlation_domain(
                    self.repetition,
                    tape,
                    round_purpose(self.layouts[family_index].family),
                    local_round,
                )?;
                let sent = contexts[tape].correct_full_verifier_keys(domain, &corrections);
                nodes[family_index][tape] = Some([sent[0], live.sub(sent[0]), sent[1]]);
            }
        }
        self.pending_nodes = Some(nodes);
        active
            .checked_mul(2 * C6_BLIND_HIDDEN_U_TAPES as u64)
            .and_then(|values| values.checked_mul(FP2_BYTES))
            .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 verifier bytes overflow"))
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6BlindHiddenUError::new("C6HUB2 verifier challenge precedes round message")
        })?;
        let weights = lagrange3(challenge);
        for family_index in 0..self.layouts.len() {
            if nodes[family_index][0].is_none() {
                continue;
            }
            self.points[family_index].push(challenge);
            for tape in 0..C6_BLIND_HIDDEN_U_TAPES {
                let round_nodes = nodes[family_index][tape]
                    .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 cross-tape round gap"))?;
                self.current[family_index][tape] = Some(interpolate_verifier(round_nodes, weights));
            }
        }
        self.global_round += 1;
        Ok(())
    }

    pub(crate) fn finish(
        self,
        contexts: &mut [VerifierCtx; C6_BLIND_HIDDEN_U_TAPES],
        transcript: &mut Transcript,
    ) -> Result<Vec<PendingVerifierEntry>> {
        if self.pending_nodes.is_some() || self.global_round != self.max_rounds {
            return Err(C6BlindHiddenUError::new(
                "incomplete C6HUB2 step-wise verifier repetition",
            ));
        }
        let mut pending_entries = Vec::with_capacity(
            C6_BLIND_HIDDEN_U_FAMILIES * C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY as usize,
        );
        let mut terminal_residuals: [[VerifierKey; C6_BLIND_HIDDEN_U_FAMILIES];
            C6_BLIND_HIDDEN_U_TAPES] =
            array::from_fn(|_| [VerifierKey::ZERO; C6_BLIND_HIDDEN_U_FAMILIES]);
        for family_index in 0..self.layouts.len() {
            let family = self.layouts[family_index].family;
            let functional = evaluate_functional(
                self.layouts[family_index],
                &self.schedules[family_index],
                usize::from(self.repetition),
                &self.q_cols[family_index],
                &self.points[family_index],
            )
            .map_err(hidden_error)?;
            let mut pending_keys = [VerifierKey::ZERO; C6_BLIND_HIDDEN_U_TAPES];
            for (tape, residuals) in terminal_residuals.iter_mut().enumerate() {
                let domain = correlation_domain(self.repetition, tape, pending_purpose(family), 0)?;
                pending_keys[tape] = contexts[tape].correct_full_verifier_keys(
                    domain,
                    &[self.repetition_proof.families[family_index].pending_corrections[tape]],
                )[0];
                transcript.append(PENDING_LABEL, FP2_BYTES);
                let live = self.current[family_index][tape]
                    .ok_or_else(|| C6BlindHiddenUError::new("missing C6HUB2 verifier terminal"))?;
                residuals[family_index] = live.sub(pending_keys[tape].scale(functional));
            }
            append_family_pending_verifier_entries(
                &mut pending_entries,
                self.statement_digest,
                self.repetition,
                family,
                self.points[family_index].clone(),
                pending_keys,
            );
        }
        let eta = transcript.challenge_fp2();
        for (tape, residuals) in terminal_residuals.iter().enumerate() {
            let aggregate = residuals[0].add(residuals[1].scale(eta));
            transcript.append("zero_open_tag", FP2_BYTES);
            if !zero_open_verify(aggregate, self.repetition_proof.terminal_tags[tape]) {
                return Err(C6BlindHiddenUError::new("C6HUB2 terminal ZeroOpen failed"));
            }
        }
        Ok(pending_entries)
    }
}

pub fn prove_c6_blind_hidden_u_sumchecks_reference(
    sealed: &C6SealedHiddenUBundle,
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    streams: &mut [CorrelationStream; C6_BLIND_HIDDEN_U_TAPES],
    transcript: &mut Transcript,
) -> Result<(C6BlindHiddenUSumcheckProof, C6BlindHiddenUPendingClaimsProver)> {
    let layouts = sealed.validate_prequery_binding(prequery).map_err(hidden_error)?;
    let statement_digest =
        begin_c6_blind_hidden_u_stepwise(sealed, prequery, postcommit, transcript)?;
    let mut repetitions = Vec::with_capacity(C6_HIDDEN_U_REPETITIONS as usize);
    let mut pending_entries = Vec::with_capacity(
        C6_HIDDEN_U_REPETITIONS as usize
            * C6_BLIND_HIDDEN_U_FAMILIES
            * C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY as usize,
    );
    for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
        let mut state =
            prepare_c6_blind_hidden_u_prover_round_state(sealed, prequery, postcommit, repetition)?;
        while state.round_index() < state.round_count() {
            let bytes = state.fix_next_round(streams)?;
            transcript.append(ROUND_LABEL, bytes);
            let challenge = transcript.challenge_fp2();
            state.bind_challenge(challenge)?;
        }
        let (repetition_proof, repetition_pending) = state.finish(streams, transcript)?;
        repetitions.push(repetition_proof);
        pending_entries.extend(repetition_pending);
    }
    let proof = C6BlindHiddenUSumcheckProof { statement_digest, repetitions };
    proof.validate_shape(&layouts)?;
    Ok((proof, C6BlindHiddenUPendingClaimsProver { entries: pending_entries }))
}

pub fn verify_c6_blind_hidden_u_sumchecks(
    layouts: &[C6HiddenULayout],
    q_cols: &[Vec<Vec<Fp2>>],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    proof: &C6BlindHiddenUSumcheckProof,
    contexts: &mut [VerifierCtx; C6_BLIND_HIDDEN_U_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindHiddenUPendingClaimsVerifier> {
    if contexts[0].delta == contexts[1].delta {
        return Err(C6BlindHiddenUError::new("C6HUB2 MAC tapes are not independent"));
    }
    begin_c6_blind_hidden_u_verifier_stepwise(
        layouts, q_cols, prequery, postcommit, proof, transcript,
    )?;
    let mut pending_entries = Vec::with_capacity(
        C6_HIDDEN_U_REPETITIONS as usize
            * C6_BLIND_HIDDEN_U_FAMILIES
            * C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY as usize,
    );
    for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
        let mut state = prepare_c6_blind_hidden_u_verifier_round_state(
            layouts, q_cols, prequery, postcommit, proof, repetition,
        )?;
        while state.round_index() < state.round_count() {
            let bytes = state.check_next_round(contexts)?;
            transcript.append(ROUND_LABEL, bytes);
            let challenge = transcript.challenge_fp2();
            state.bind_challenge(challenge)?;
        }
        pending_entries.extend(state.finish(contexts, transcript)?);
    }
    Ok(C6BlindHiddenUPendingClaimsVerifier { entries: pending_entries })
}

fn append_family_pending_prover_entries(
    entries: &mut Vec<PendingProverEntry>,
    statement_digest: C6HiddenUDigest,
    repetition: u8,
    family: C6HiddenUFamily,
    point: Vec<Fp2>,
    actual: [ProverAuthed; C6_BLIND_HIDDEN_U_TAPES],
) {
    for slot in 0..C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY {
        entries.push(PendingProverEntry {
            descriptor: C6BlindHiddenUPendingDescriptor {
                statement_digest,
                repetition,
                family,
                slot,
                point: point.clone(),
            },
            auth: if slot == 0 { actual } else { [ProverAuthed::ZERO; C6_BLIND_HIDDEN_U_TAPES] },
        });
    }
}

fn append_family_pending_verifier_entries(
    entries: &mut Vec<PendingVerifierEntry>,
    statement_digest: C6HiddenUDigest,
    repetition: u8,
    family: C6HiddenUFamily,
    point: Vec<Fp2>,
    actual: [VerifierKey; C6_BLIND_HIDDEN_U_TAPES],
) {
    for slot in 0..C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY {
        entries.push(PendingVerifierEntry {
            descriptor: C6BlindHiddenUPendingDescriptor {
                statement_digest,
                repetition,
                family,
                slot,
                point: point.clone(),
            },
            keys: if slot == 0 { actual } else { [VerifierKey::ZERO; C6_BLIND_HIDDEN_U_TAPES] },
        });
    }
}

fn validate_protocol_layouts(layouts: &[C6HiddenULayout]) -> Result<()> {
    validate_layouts(layouts).map_err(hidden_error)?;
    if layouts.len() != C6_BLIND_HIDDEN_U_FAMILIES
        || layouts[0].family != C6HiddenUFamily::Weights
        || layouts[1].family != C6HiddenUFamily::Embed
    {
        return Err(C6BlindHiddenUError::new("C6HUB2 hidden family order mismatch"));
    }
    Ok(())
}

fn statement_digest(
    layouts: &[C6HiddenULayout],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
) -> Result<C6HiddenUDigest> {
    let postcommit_digest = postcommit.digest(layouts).map_err(hidden_error)?;
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(&prequery.digest());
    hasher.update(&postcommit_digest);
    hasher.update(&(layouts.len() as u64).to_le_bytes());
    for layout in layouts {
        hasher.update(&layout.digest());
    }
    hasher.update(&C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY.to_le_bytes());
    hasher.update(&[0]); // actual oracle slot
    hasher.update(&[1, 7]); // inclusive public-zero slot interval
    Ok(*hasher.finalize().as_bytes())
}

fn authenticate_values(
    stream: &mut CorrelationStream,
    domain: u64,
    values: &[Fp2],
) -> Result<(Vec<Fp2>, Vec<ProverAuthed>)> {
    let correlations = stream.draw_fulls(domain, values.len());
    stream.record_c6_fullfield_plaintexts(domain, values).map_err(hidden_error)?;
    let mut corrections = Vec::with_capacity(values.len());
    let mut auth = Vec::with_capacity(values.len());
    for (&value, correlation) in values.iter().zip(correlations) {
        corrections.push(value - correlation.x);
        auth.push(correlation.authenticate(value));
    }
    Ok((corrections, auth))
}

fn interpolate_prover(nodes: [ProverAuthed; 3], weights: [Fp2; 3]) -> ProverAuthed {
    nodes
        .into_iter()
        .zip(weights)
        .fold(ProverAuthed::ZERO, |sum, (node, weight)| sum.add(node.scale(weight)))
}

fn interpolate_verifier(nodes: [VerifierKey; 3], weights: [Fp2; 3]) -> VerifierKey {
    nodes
        .into_iter()
        .zip(weights)
        .fold(VerifierKey::ZERO, |sum, (node, weight)| sum.add(node.scale(weight)))
}

fn family_index(family: C6HiddenUFamily) -> Result<usize> {
    match family {
        C6HiddenUFamily::Weights => Ok(0),
        C6HiddenUFamily::Embed => Ok(1),
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum CorrelationPurpose {
    WeightsRound = 1,
    EmbedRound = 2,
    WeightsPending = 3,
    EmbedPending = 4,
}

fn round_purpose(family: C6HiddenUFamily) -> CorrelationPurpose {
    match family {
        C6HiddenUFamily::Weights => CorrelationPurpose::WeightsRound,
        C6HiddenUFamily::Embed => CorrelationPurpose::EmbedRound,
    }
}

fn pending_purpose(family: C6HiddenUFamily) -> CorrelationPurpose {
    match family {
        C6HiddenUFamily::Weights => CorrelationPurpose::WeightsPending,
        C6HiddenUFamily::Embed => CorrelationPurpose::EmbedPending,
    }
}

fn correlation_domain(
    repetition: u8,
    tape: usize,
    purpose: CorrelationPurpose,
    index: usize,
) -> Result<u64> {
    if usize::from(repetition) >= C6_HIDDEN_U_REPETITIONS as usize
        || tape >= C6_BLIND_HIDDEN_U_TAPES
        || index > u16::MAX as usize
    {
        return Err(C6BlindHiddenUError::new("C6HUB2 correlation component out of range"));
    }
    let domain = CORRELATION_BASE
        | (u64::from(repetition) << 28)
        | ((tape as u64) << 24)
        | ((purpose as u64) << 16)
        | index as u64;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(C6BlindHiddenUError::new("C6HUB2 correlation domain uses reserved bits"));
    }
    Ok(domain)
}

fn proof_digest(prefix: &[u8]) -> C6HiddenUDigest {
    let mut hasher = blake3::Hasher::new_derive_key(PROOF_DOMAIN);
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    *hasher.finalize().as_bytes()
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

fn decode_family(value: u8) -> Result<C6HiddenUFamily> {
    match value {
        1 => Ok(C6HiddenUFamily::Weights),
        2 => Ok(C6HiddenUFamily::Embed),
        _ => Err(C6BlindHiddenUError::new("unknown C6HUB2 family")),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C6BlindHiddenUError::new("C6HUB2 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6BlindHiddenUError::new("truncated C6HUB2 proof"))?;
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

    fn digest(&mut self) -> Result<C6HiddenUDigest> {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let mut c0 = [0; 8];
        let mut c1 = [0; 8];
        c0.copy_from_slice(self.take(8)?);
        c1.copy_from_slice(self.take(8)?);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C6BlindHiddenUError::new("noncanonical C6HUB2 field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c6_hidden_u::{
        encode_fp2_ntt, C6HiddenUBundleWitness, C6HiddenUFamilyPostCommit, C6HiddenUFamilyWitness,
        C6HiddenUQueryClaim,
    };
    use crate::c6_hidden_u_sumcheck::flatten_witness;
    use crate::ligero::LigeroParams;
    use crate::ntt::NttPlan;
    use volta_proto::mle::eval_mle;

    const TAPE_SEEDS: [[u8; 32]; 2] = [[0x91; 32], [0x92; 32]];
    const DELTAS: [Fp2; 2] =
        [Fp2::new(Fp::new(17), Fp::new(19)), Fp2::new(Fp::new(23), Fp::new(29))];

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 13 + 7))
    }

    fn layout(family: C6HiddenUFamily, claims: usize) -> C6HiddenULayout {
        let vector_capacity = if family == C6HiddenUFamily::Weights { 4 } else { 2 };
        C6HiddenULayout {
            family,
            params: LigeroParams { rows: 8, col_bits: 3, pad: 4, code_bits: 4, n_queries: 4 },
            claim_count: claims,
            vector_capacity,
            vector_stride: 16,
        }
    }

    fn family_witness(
        layout: C6HiddenULayout,
        seed: u64,
    ) -> (C6HiddenUFamilyWitness, Vec<Vec<Fp2>>) {
        let vectors = (0..layout.live_vectors())
            .map(|vector| {
                (0..layout.msg_len())
                    .map(|index| fp2(seed + 100 * vector as u64 + index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let q_cols = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.cols())
                    .map(|index| fp2(seed + 1_000 + 100 * claim as u64 + index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let witness = C6HiddenUFamilyWitness::new(
            layout,
            vectors[0].clone(),
            vectors[1..].to_vec(),
            q_cols.clone(),
        )
        .unwrap();
        (witness, q_cols)
    }

    fn fixture(
    ) -> (Vec<C6HiddenULayout>, Vec<Vec<Vec<Fp2>>>, C6SealedHiddenUBundle, C6HiddenUPostCommit)
    {
        let layouts = vec![layout(C6HiddenUFamily::Weights, 2), layout(C6HiddenUFamily::Embed, 1)];
        let (weights, weights_q) = family_witness(layouts[0], 11);
        let (embed, embed_q) = family_witness(layouts[1], 29);
        let sealed = C6HiddenUBundleWitness::new(vec![weights, embed])
            .unwrap()
            .seal(vec![[0x31; 32], [0x32; 32]], [0x33; 32])
            .unwrap();
        let families = layouts
            .iter()
            .zip(sealed.families())
            .map(|(layout, family)| {
                let plan = NttPlan::new(layout.code_len());
                let encoded = family
                    .vectors()
                    .iter()
                    .map(|vector| encode_fp2_ntt(&plan, vector))
                    .collect::<Vec<_>>();
                let queries = [0usize, 3, 7, 15]
                    .into_iter()
                    .map(|index| C6HiddenUQueryClaim {
                        index: index as u32,
                        rhs: encoded.iter().map(|vector| vector[index]).collect(),
                    })
                    .collect();
                C6HiddenUFamilyPostCommit { family: layout.family, queries }
            })
            .collect();
        let postcommit = C6HiddenUPostCommit {
            prequery_digest: sealed.prequery().digest(),
            batching_seed: [0x45; 32],
            families,
        };
        (layouts, vec![weights_q, embed_q], sealed, postcommit)
    }

    #[test]
    fn production_codec_and_correlation_identities_are_exact() {
        assert_eq!(production_c6_blind_hidden_u_sumcheck_encoded_len(), 5_416);
        assert_eq!(
            production_c6_blind_hidden_u_sumcheck_encoded_len(),
            C6_BLIND_HIDDEN_U_PRODUCTION_BYTES
        );
        assert_eq!(C6_BLIND_HIDDEN_U_PRODUCTION_FULL_CORRELATIONS_PER_TAPE, 164);
    }

    #[test]
    fn blind_hidden_stepwise_states_reject_out_of_order_challenges() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut prover = prepare_c6_blind_hidden_u_prover_round_state(
            &sealed,
            sealed.prequery(),
            &postcommit,
            0,
        )
        .unwrap();
        assert!(prover.bind_challenge(Fp2::ONE).is_err());
        assert!(prover.fix_next_round(&mut streams).unwrap() > 0);
        assert!(prover.fix_next_round(&mut streams).is_err());

        let mut transcript = Transcript::new([0x59; 32]);
        let (proof, _) = prove_c6_blind_hidden_u_sumchecks_reference(
            &sealed,
            sealed.prequery(),
            &postcommit,
            &mut TAPE_SEEDS.map(CorrelationStream::new),
            &mut transcript,
        )
        .unwrap();
        let mut verifier = prepare_c6_blind_hidden_u_verifier_round_state(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &proof,
            0,
        )
        .unwrap();
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        assert!(verifier.bind_challenge(Fp2::ONE).is_err());
        assert!(verifier.check_next_round(&mut contexts).unwrap() > 0);
        assert!(verifier.check_next_round(&mut contexts).is_err());
    }

    #[test]
    fn blind_hidden_round_trip_binds_real_and_zero_capacity_slots() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let before: [u64; 2] = array::from_fn(|tape| streams[tape].counters.full_corrs);
        let mut prover_tx = Transcript::new([0x61; 32]);
        let (proof, prover_pending) = prove_c6_blind_hidden_u_sumchecks_reference(
            &sealed,
            sealed.prequery(),
            &postcommit,
            &mut streams,
            &mut prover_tx,
        )
        .unwrap();
        let encoded = proof.encode(&layouts).unwrap();
        assert_eq!(encoded.len() as u64, blind_hidden_u_sumcheck_encoded_len(&layouts).unwrap());
        let decoded =
            C6BlindHiddenUSumcheckProof::decode(&layouts, proof.statement_digest(), &encoded)
                .unwrap();
        assert_eq!(decoded, proof);
        let after: [u64; 2] = array::from_fn(|tape| streams[tape].counters.full_corrs);
        assert_eq!([after[0] - before[0], after[1] - before[1]], [48, 48]);

        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        let mut verifier_tx = Transcript::new([0x61; 32]);
        let verifier_pending = verify_c6_blind_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &decoded,
            &mut contexts,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
        assert_eq!(prover_tx.total_bytes() + 32, encoded.len() as u64);
        assert_eq!(prover_pending.len(), 32);
        assert_eq!(verifier_pending.len(), 32);

        let prover_entries = prover_pending.link_entries().collect::<Vec<_>>();
        let verifier_entries = verifier_pending.link_entries().collect::<Vec<_>>();
        for index in 0..prover_entries.len() {
            let (descriptor, auth) = prover_entries[index];
            let (verifier_descriptor, keys) = verifier_entries[index];
            assert_eq!(descriptor, verifier_descriptor);
            for tape in 0..2 {
                assert_eq!(keys[tape].k, auth[tape].m + DELTAS[tape] * auth[tape].x);
            }
            if descriptor.slot() == 0 {
                let family_index = family_index(descriptor.family()).unwrap();
                let table = flatten_witness(
                    layouts[family_index],
                    sealed.families()[family_index].vectors(),
                )
                .unwrap();
                assert_eq!(auth[0].x, eval_mle(&table, descriptor.point()));
                assert_eq!(auth[0].x, auth[1].x);
                let raw = fp2_bytes(auth[0].x);
                assert!(!encoded.windows(16).any(|window| window == raw));
            } else {
                assert_eq!(auth, [ProverAuthed::ZERO; 2]);
                assert_eq!(keys, [VerifierKey::ZERO; 2]);
            }
        }
    }

    #[test]
    fn blind_hidden_strict_codec_and_tamper_seams_reject() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let mut streams = TAPE_SEEDS.map(CorrelationStream::new);
        let mut tx = Transcript::new([0x71; 32]);
        let (proof, _) = prove_c6_blind_hidden_u_sumchecks_reference(
            &sealed,
            sealed.prequery(),
            &postcommit,
            &mut streams,
            &mut tx,
        )
        .unwrap();
        let encoded = proof.encode(&layouts).unwrap();
        let mut old = encoded.clone();
        old[..8].copy_from_slice(b"C6HUSC1\0");
        assert!(
            C6BlindHiddenUSumcheckProof::decode(&layouts, proof.statement_digest(), &old).is_err()
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6BlindHiddenUSumcheckProof::decode(&layouts, proof.statement_digest(), &trailing)
            .is_err());
        let mut noncanonical = encoded.clone();
        noncanonical[56..64].copy_from_slice(&P.to_le_bytes());
        assert!(C6BlindHiddenUSumcheckProof::decode(
            &layouts,
            proof.statement_digest(),
            &noncanonical
        )
        .is_err());

        let mut bad_round = proof.clone();
        bad_round.repetitions[0].families[0].round_corrections[1][0][0] += Fp2::ONE;
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        assert!(verify_c6_blind_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &bad_round,
            &mut contexts,
            &mut Transcript::new([0x71; 32]),
        )
        .is_err());

        let mut bad_pending = proof.clone();
        bad_pending.repetitions[1].families[1].pending_corrections[0] += Fp2::ONE;
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        assert!(verify_c6_blind_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &bad_pending,
            &mut contexts,
            &mut Transcript::new([0x71; 32]),
        )
        .is_err());

        let mut bad_tag = proof.clone();
        bad_tag.repetitions[0].terminal_tags[0] += Fp2::ONE;
        let mut contexts = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[tape]));
        assert!(verify_c6_blind_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &bad_tag,
            &mut contexts,
            &mut Transcript::new([0x71; 32]),
        )
        .is_err());

        let mut same_delta = array::from_fn(|tape| VerifierCtx::new(TAPE_SEEDS[tape], DELTAS[0]));
        assert!(verify_c6_blind_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &proof,
            &mut same_delta,
            &mut Transcript::new([0x71; 32]),
        )
        .is_err());
    }

    fn fp2_bytes(value: Fp2) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&value.c0.value().to_le_bytes());
        bytes[8..].copy_from_slice(&value.c1.value().to_le_bytes());
        bytes
    }
}

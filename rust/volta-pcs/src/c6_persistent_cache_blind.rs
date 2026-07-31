//! Pointwise-sound dual-tape blind adapter for the C6 persistent cache.
//!
//! The reference path is deliberately scaled: production geometry must use a
//! streaming client compiler and is rejected here.  The transition owner is
//! weighted by `eq(a, x)` at a verifier-owned relation point; the remaining
//! two owners bind predecessor attention and current-slab/output functionals.
//! Four live terminal evaluations and 28 canonical zero claims per repetition
//! remain pending until `C6LNK2` and both packed PCS chains accept. Aggregate
//! source keys are authenticated inputs to this sumcheck, not PCS outputs.

// The complete arithmetic implementation below is a scaled reference gate.
// Ordinary production builds expose only its codec/pending types until the
// separately registered streaming 24-round compiler is connected.
#![allow(dead_code)]

use std::{array, fmt};

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_prover, zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey, RESERVED_DOMAIN_BITS,
};
use volta_proto::mle::{eq_vec, lagrange3};

use crate::c6_wrapper_pcs::{
    C6WrapperDigest, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    C6_WRAPPER_AUXILIARY_COHORT_ID, C6_WRAPPER_REPETITIONS,
};

pub const C6_PERSISTENT_CACHE_BLIND_MAGIC: [u8; 8] = *b"C6PC2\0\0\0";
pub const C6_PERSISTENT_CACHE_BLIND_VERSION: u16 = 2;
pub const C6_PERSISTENT_CACHE_BLIND_TAPES: usize = 2;
pub const C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS: usize = 4;
pub const C6_PERSISTENT_CACHE_BLIND_ZERO_CLAIMS: usize = 28;
pub const C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION: usize = 32;
pub const C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS: usize = 24;
pub const C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES: u64 = 3_506;
pub const C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE: u64 = 104;
pub const C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_MAGIC: [u8; 8] = *b"C6PS1\0\0\0";
pub const C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_VERSION: u16 = 1;
pub const C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES: u64 = 304;
pub const C6_PERSISTENT_CACHE_SOURCE_BOUND_PRODUCTION_BYTES: u64 =
    C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES + C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES;

const REFERENCE_MAX_ROUNDS: usize = 12;
const STATEMENT_DOMAIN: &str = "volta-zk/c6/persistent-cache-blind-statement/v2";
const SCHEDULE_DOMAIN: &str = "volta-zk/c6/persistent-cache-blind-schedule/v2";
const FRAMING_LABEL: &str = "c6_persistent_cache_blind_framing";
const REPETITION_LABEL: &str = "c6_persistent_cache_blind_repetition";
const ROUND_LABEL: &str = "c6_persistent_cache_blind_round_corrections";
const TERMINAL_LABEL: &str = "c6_persistent_cache_blind_terminal_corrections";
const SOURCE_BOOTSTRAP_HEADER_LABEL: &str = "c6_persistent_cache_source_bootstrap_header";
const SOURCE_BOOTSTRAP_FIXED_LABEL: &str = "c6_persistent_cache_source_bootstrap_fixed";
const SOURCE_BOOTSTRAP_TRANSITION_LABEL: &str = "c6_persistent_cache_source_bootstrap_transition";
const HEADER_AND_STATEMENT_BYTES: u64 = 48;
const REPETITION_PREFIX_BYTES: u64 = 33;
const ROUND_BYTES: u64 = 64;
const TERMINAL_BYTES: u64 = 128;
const FP2_BYTES: u64 = 16;
const SOURCE_BOOTSTRAP_HEADER_BYTES: u64 = 48;
const SOURCE_BOOTSTRAP_FIXED_BYTES: u64 = 128;
const SOURCE_BOOTSTRAP_TRANSITION_BYTES: u64 = 64;
const CORRELATION_BASE: u64 = 0x0C66_0000_0000_0000;

const SOURCE_OWNER_COUNT: usize = 3;
const SOURCE_KV_COUNT: usize = 2;

type SourceAggregatesProver =
    [[[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; SOURCE_OWNER_COUNT];
type SourceAggregatesVerifier =
    [[[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; SOURCE_OWNER_COUNT];
type SourceAggregateMasks =
    [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; SOURCE_OWNER_COUNT];

type Result<T> = std::result::Result<T, C6PersistentCacheBlindError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheBlindError(String);

impl C6PersistentCacheBlindError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6PersistentCacheBlindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6PersistentCacheBlindError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum C6PersistentCacheRelationOwner {
    AppendTransition = 0,
    PredecessorAttention = 1,
    CurrentSlabOutput = 2,
}

impl C6PersistentCacheRelationOwner {
    const ALL: [Self; 3] =
        [Self::AppendTransition, Self::PredecessorAttention, Self::CurrentSlabOutput];
}

/// Strict aggregate-correction frame that bootstraps the six C6PC2 source
/// keys without exposing any historical corrected key vector.  The four
/// fold aggregates are response-fixed; the two append aggregates depend on
/// each repetition's verifier-owned equality point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheSourceBootstrapFrame {
    statement_digest: C6WrapperDigest,
    /// predecessor K/V, current-slab K/V; then tape.
    fixed_corrections: [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; 2],
    /// repetition, K/V, tape.
    transition_corrections:
        [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS],
}

impl C6PersistentCacheSourceBootstrapFrame {
    fn new(
        statement_digest: C6WrapperDigest,
        fixed_corrections: [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; 2],
        transition_corrections: [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
            C6_WRAPPER_REPETITIONS],
    ) -> Result<Self> {
        if statement_digest == [0; 32] {
            return Err(C6PersistentCacheBlindError::new(
                "zero C6PS1 source-bootstrap statement digest",
            ));
        }
        Ok(Self { statement_digest, fixed_corrections, transition_corrections })
    }

    pub fn statement_digest(&self) -> C6WrapperDigest {
        self.statement_digest
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES as usize);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_MAGIC);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_VERSION.to_le_bytes());
        bytes.push(C6_WRAPPER_REPETITIONS as u8);
        bytes.push(C6_PERSISTENT_CACHE_BLIND_TAPES as u8);
        bytes.push(4);
        bytes.push(2);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for owner in &self.fixed_corrections {
            for kv in owner {
                for correction in kv {
                    encode_fp2(&mut bytes, *correction);
                }
            }
        }
        for repetition in &self.transition_corrections {
            for kv in repetition {
                for correction in kv {
                    encode_fp2(&mut bytes, *correction);
                }
            }
        }
        if bytes.len() as u64 != C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES {
            return Err(C6PersistentCacheBlindError::new("C6PS1 encoded length changed"));
        }
        Ok(bytes)
    }

    pub fn decode(expected_statement_digest: C6WrapperDigest, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 != C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES {
            return Err(C6PersistentCacheBlindError::new("C6PS1 encoded length mismatch"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_MAGIC
            || cursor.u16()? != C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_VERSION
            || cursor.u8()? as usize != C6_WRAPPER_REPETITIONS
            || cursor.u8()? as usize != C6_PERSISTENT_CACHE_BLIND_TAPES
            || cursor.u8()? != 4
            || cursor.u8()? != 2
            || cursor.u16()? != 0
        {
            return Err(C6PersistentCacheBlindError::new("C6PS1 header census mismatch"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest != expected_statement_digest || statement_digest == [0; 32] {
            return Err(C6PersistentCacheBlindError::new("C6PS1 statement digest mismatch"));
        }
        let mut fixed_corrections =
            [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; 2];
        for owner in &mut fixed_corrections {
            for kv in owner {
                for correction in kv {
                    *correction = cursor.fp2()?;
                }
            }
        }
        let mut transition_corrections = [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
            SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
        for repetition in &mut transition_corrections {
            for kv in repetition {
                for correction in kv {
                    *correction = cursor.fp2()?;
                }
            }
        }
        if !cursor.is_eof() {
            return Err(C6PersistentCacheBlindError::new("trailing C6PS1 bytes"));
        }
        Self::new(statement_digest, fixed_corrections, transition_corrections)
    }

    fn charge_header_and_fixed(&self, transcript: &mut Transcript) {
        transcript.append(SOURCE_BOOTSTRAP_HEADER_LABEL, SOURCE_BOOTSTRAP_HEADER_BYTES);
        transcript.append(SOURCE_BOOTSTRAP_FIXED_LABEL, SOURCE_BOOTSTRAP_FIXED_BYTES);
    }

    fn charge_transition(&self, repetition: usize, transcript: &mut Transcript) -> Result<()> {
        if repetition >= C6_WRAPPER_REPETITIONS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PS1 transition repetition is out of range",
            ));
        }
        transcript.append(SOURCE_BOOTSTRAP_TRANSITION_LABEL, SOURCE_BOOTSTRAP_TRANSITION_BYTES);
        Ok(())
    }

    fn correction(&self, repetition: usize, owner: usize, kv: usize, tape: usize) -> Result<Fp2> {
        if repetition >= C6_WRAPPER_REPETITIONS
            || owner >= SOURCE_OWNER_COUNT
            || kv >= SOURCE_KV_COUNT
            || tape >= C6_PERSISTENT_CACHE_BLIND_TAPES
        {
            return Err(C6PersistentCacheBlindError::new("C6PS1 source index is out of range"));
        }
        Ok(match owner {
            0 => self.transition_corrections[repetition][kv][tape],
            1 | 2 => self.fixed_corrections[owner - 1][kv][tape],
            _ => unreachable!(),
        })
    }

    fn correct_base_keys(
        &self,
        repetition: usize,
        base_keys: &SourceAggregatesVerifier,
        deltas: [Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES],
    ) -> Result<SourceAggregatesVerifier> {
        if repetition >= C6_WRAPPER_REPETITIONS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PS1 base-key repetition is out of range",
            ));
        }
        if deltas[0] == deltas[1] {
            return Err(C6PersistentCacheBlindError::new("C6PS1 MAC tapes are not independent"));
        }
        let mut corrected = *base_keys;
        for owner in 0..SOURCE_OWNER_COUNT {
            for kv in 0..SOURCE_KV_COUNT {
                for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                    let base = base_keys[owner][kv][tape];
                    corrected[owner][kv][tape] = base.with_same_c6_trace(
                        base.k + deltas[tape] * self.correction(repetition, owner, kv, tape)?,
                    );
                }
            }
        }
        Ok(corrected)
    }
}

/// Client-derived scaled relation plan.  Production construction is absent
/// on purpose: accepting 24-round materialized coefficient tables here would
/// violate the registered streaming-memory seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistentCacheRelationPlan {
    rounds: usize,
    old_len: usize,
    append_len: usize,
    root_binding_digest: C6WrapperDigest,
    workload_digest: C6WrapperDigest,
    source_schedule_digest: C6WrapperDigest,
    predecessor_coefficients: [Vec<Fp2>; 2],
    current_coefficients: [Vec<Fp2>; 2],
    auxiliary_target_point: Vec<Fp2>,
    statement_digest: C6WrapperDigest,
}

impl C6PersistentCacheRelationPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_scaled_client_derived(
        rounds: usize,
        old_len: usize,
        append_len: usize,
        root_binding_digest: C6WrapperDigest,
        workload_digest: C6WrapperDigest,
        source_schedule_digest: C6WrapperDigest,
        predecessor_coefficients: [Vec<Fp2>; 2],
        current_coefficients: [Vec<Fp2>; 2],
        auxiliary_target_point: Vec<Fp2>,
    ) -> Result<Self> {
        if rounds == 0 || rounds > REFERENCE_MAX_ROUNDS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 reference compiler rejects production-sized geometry",
            ));
        }
        let len = 1usize
            .checked_shl(rounds as u32)
            .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 relation length overflow"))?;
        if old_len.checked_add(append_len).is_none_or(|new_len| new_len > len)
            || append_len == 0
            || root_binding_digest == [0; 32]
            || workload_digest == [0; 32]
            || source_schedule_digest == [0; 32]
            || predecessor_coefficients.iter().any(|values| values.len() != len)
            || current_coefficients.iter().any(|values| values.len() != len)
            || auxiliary_target_point.is_empty()
            || auxiliary_target_point.last() != Some(&Fp2::ZERO)
        {
            return Err(C6PersistentCacheBlindError::new(
                "invalid client-derived C6PC2 relation plan",
            ));
        }
        let mut plan = Self {
            rounds,
            old_len,
            append_len,
            root_binding_digest,
            workload_digest,
            source_schedule_digest,
            predecessor_coefficients,
            current_coefficients,
            auxiliary_target_point,
            statement_digest: [0; 32],
        };
        plan.statement_digest = plan.compute_statement_digest();
        Ok(plan)
    }

    pub(crate) fn rounds(&self) -> usize {
        self.rounds
    }

    pub(crate) fn statement_digest(&self) -> C6WrapperDigest {
        self.statement_digest
    }

    fn len(&self) -> usize {
        1usize << self.rounds
    }

    fn compute_statement_digest(&self) -> C6WrapperDigest {
        let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
        hasher.update(&[self.rounds as u8]);
        hasher.update(&(self.old_len as u64).to_le_bytes());
        hasher.update(&(self.append_len as u64).to_le_bytes());
        hasher.update(&self.root_binding_digest);
        hasher.update(&self.workload_digest);
        hasher.update(&self.source_schedule_digest);
        for owner in C6PersistentCacheRelationOwner::ALL {
            hasher.update(&[owner as u8]);
        }
        for coefficients in self.predecessor_coefficients.iter().chain(&self.current_coefficients) {
            hash_fp2_slice(&mut hasher, coefficients);
        }
        hash_fp2_slice(&mut hasher, &self.auxiliary_target_point);
        *hasher.finalize().as_bytes()
    }

    fn compile(
        &self,
        repetition: u8,
        relation_point: &[Fp2],
        relation_roots: [Fp2; 3],
        kv_root: Fp2,
    ) -> Result<CompiledRelation> {
        if relation_point.len() != self.rounds {
            return Err(C6PersistentCacheBlindError::new("C6PC2 relation-point width mismatch"));
        }
        let equality = eq_vec(relation_point);
        if equality.len() != self.len() {
            return Err(C6PersistentCacheBlindError::new("C6PC2 equality compiler mismatch"));
        }
        let mut coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| vec![Fp2::ZERO; self.len()]);
        for index in 0..self.len() {
            let transition = equality[index] * relation_roots[0];
            if index < self.old_len {
                coefficients[0][index] = coefficients[0][index] - transition;
                coefficients[1][index] = coefficients[1][index] - transition * kv_root;
            }
            coefficients[2][index] += transition;
            coefficients[3][index] += transition * kv_root;

            coefficients[0][index] += self.predecessor_coefficients[0][index] * relation_roots[1];
            coefficients[1][index] +=
                self.predecessor_coefficients[1][index] * relation_roots[1] * kv_root;
            coefficients[2][index] += self.current_coefficients[0][index] * relation_roots[2];
            coefficients[3][index] +=
                self.current_coefficients[1][index] * relation_roots[2] * kv_root;
        }
        let mut hasher = blake3::Hasher::new_derive_key(SCHEDULE_DOMAIN);
        hasher.update(&self.statement_digest);
        hasher.update(&[repetition]);
        hash_fp2_slice(&mut hasher, relation_point);
        hash_fp2_slice(&mut hasher, &relation_roots);
        hash_fp2_slice(&mut hasher, &[kv_root]);
        for owner in C6PersistentCacheRelationOwner::ALL {
            hasher.update(&[owner as u8]);
        }
        for table in &coefficients {
            hash_fp2_slice(&mut hasher, table);
        }
        Ok(CompiledRelation {
            equality,
            coefficients,
            schedule_digest: *hasher.finalize().as_bytes(),
        })
    }
}

#[derive(Clone, Debug)]
struct CompiledRelation {
    equality: Vec<Fp2>,
    coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    schedule_digest: C6WrapperDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistentCacheBlindWitness {
    /// predecessor K, predecessor V, successor K, successor V
    tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
}

impl C6PersistentCacheBlindWitness {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    ) -> Result<Self> {
        if tables.iter().any(|table| table.len() != plan.len()) {
            return Err(C6PersistentCacheBlindError::new("C6PC2 witness geometry mismatch"));
        }
        Ok(Self { tables })
    }
}

#[derive(Clone)]
pub(crate) struct C6PersistentCacheSourcesProver {
    source_schedule_digest: C6WrapperDigest,
    transition_append: [Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
    predecessor_targets: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    current_targets: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
}

#[derive(Clone)]
pub(crate) struct C6PersistentCacheSourcesVerifier {
    source_schedule_digest: C6WrapperDigest,
    transition_append: [Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
    predecessor_targets: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    current_targets: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
}

/// Provider-side base masks matching every already-authenticated append or
/// fold source. They are folded with the exact same public coefficients as
/// the source values and never cross the wire.
#[derive(Clone)]
pub(crate) struct C6PersistentCacheSourceMasksProver {
    source_schedule_digest: C6WrapperDigest,
    transition_append: [Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
    predecessor_targets: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    current_targets: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
}

impl C6PersistentCacheSourcesProver {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        predecessor_targets: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
        current_targets: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    ) -> Result<Self> {
        let sources = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            predecessor_targets,
            current_targets,
        };
        sources.validate(plan)?;
        Ok(sources)
    }

    fn validate(&self, plan: &C6PersistentCacheRelationPlan) -> Result<()> {
        if self.source_schedule_digest != plan.source_schedule_digest
            || self.transition_append.iter().any(|values| values.len() != plan.append_len)
            || self.transition_append.iter().flatten().any(|value| value[0].x != value[1].x)
            || self.predecessor_targets.iter().any(|value| value[0].x != value[1].x)
            || self.current_targets.iter().any(|value| value[0].x != value[1].x)
        {
            return Err(C6PersistentCacheBlindError::new("C6PC2 prover source binding mismatch"));
        }
        Ok(())
    }

    fn owner_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> SourceAggregatesProver {
        array::from_fn(|owner| {
            array::from_fn(|kv| {
                array::from_fn(|tape| match owner {
                    0 => self.transition_append[kv].iter().enumerate().fold(
                        ProverAuthed::ZERO,
                        |sum, (offset, value)| {
                            sum.add(value[tape].scale(compiled.equality[plan.old_len + offset]))
                        },
                    ),
                    1 => self.predecessor_targets[kv][tape],
                    2 => self.current_targets[kv][tape],
                    _ => unreachable!(),
                })
            })
        })
    }
}

impl C6PersistentCacheSourcesVerifier {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        predecessor_targets: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
        current_targets: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    ) -> Result<Self> {
        let sources = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            predecessor_targets,
            current_targets,
        };
        if sources.source_schedule_digest != plan.source_schedule_digest
            || sources.transition_append.iter().any(|values| values.len() != plan.append_len)
        {
            return Err(C6PersistentCacheBlindError::new("C6PC2 verifier source binding mismatch"));
        }
        Ok(sources)
    }

    fn owner_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> SourceAggregatesVerifier {
        array::from_fn(|owner| {
            array::from_fn(|kv| {
                array::from_fn(|tape| match owner {
                    0 => self.transition_append[kv].iter().enumerate().fold(
                        VerifierKey::ZERO,
                        |sum, (offset, value)| {
                            sum.add(value[tape].scale(compiled.equality[plan.old_len + offset]))
                        },
                    ),
                    1 => self.predecessor_targets[kv][tape],
                    2 => self.current_targets[kv][tape],
                    _ => unreachable!(),
                })
            })
        })
    }
}

impl C6PersistentCacheSourceMasksProver {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        predecessor_targets: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
        current_targets: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; 2],
    ) -> Result<Self> {
        let masks = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            predecessor_targets,
            current_targets,
        };
        if masks.source_schedule_digest != plan.source_schedule_digest
            || masks.transition_append.iter().any(|values| values.len() != plan.append_len)
        {
            return Err(C6PersistentCacheBlindError::new("C6PS1 prover mask binding mismatch"));
        }
        Ok(masks)
    }

    fn owner_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> SourceAggregateMasks {
        array::from_fn(|owner| {
            array::from_fn(|kv| {
                array::from_fn(|tape| match owner {
                    0 => self.transition_append[kv].iter().enumerate().fold(
                        Fp2::ZERO,
                        |sum, (offset, value)| {
                            sum + value[tape] * compiled.equality[plan.old_len + offset]
                        },
                    ),
                    1 => self.predecessor_targets[kv][tape],
                    2 => self.current_targets[kv][tape],
                    _ => unreachable!(),
                })
            })
        })
    }
}

fn combine_source_aggregates_prover(
    sources: &SourceAggregatesProver,
    relation_roots: [Fp2; SOURCE_OWNER_COUNT],
    kv_root: Fp2,
    tape: usize,
) -> ProverAuthed {
    (0..SOURCE_OWNER_COUNT).fold(ProverAuthed::ZERO, |sum, owner| {
        let by_kv = sources[owner][0][tape].add(sources[owner][1][tape].scale(kv_root));
        sum.add(by_kv.scale(relation_roots[owner]))
    })
}

fn combine_source_aggregates_verifier(
    sources: &SourceAggregatesVerifier,
    relation_roots: [Fp2; SOURCE_OWNER_COUNT],
    kv_root: Fp2,
    tape: usize,
) -> VerifierKey {
    (0..SOURCE_OWNER_COUNT).fold(VerifierKey::ZERO, |sum, owner| {
        let by_kv = sources[owner][0][tape].add(sources[owner][1][tape].scale(kv_root));
        sum.add(by_kv.scale(relation_roots[owner]))
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6PersistentCacheBlindRepetitionProof {
    schedule_digest: C6WrapperDigest,
    round_corrections: Vec<[[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
    terminal_corrections:
        [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    terminal_tags: [Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheBlindProof {
    statement_digest: C6WrapperDigest,
    rounds: u8,
    repetitions: Vec<C6PersistentCacheBlindRepetitionProof>,
}

impl C6PersistentCacheBlindProof {
    pub fn statement_digest(&self) -> C6WrapperDigest {
        self.statement_digest
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(self.encoded_len()? as usize);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_BLIND_MAGIC);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_BLIND_VERSION.to_le_bytes());
        bytes.push(C6_WRAPPER_REPETITIONS as u8);
        bytes.push(C6_PERSISTENT_CACHE_BLIND_TAPES as u8);
        bytes.push(self.rounds);
        bytes.push(C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS as u8);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for (repetition, proof) in self.repetitions.iter().enumerate() {
            bytes.push(repetition as u8);
            bytes.extend_from_slice(&proof.schedule_digest);
            for round in &proof.round_corrections {
                for tape in round {
                    for value in tape {
                        encode_fp2(&mut bytes, *value);
                    }
                }
            }
            for terminal in &proof.terminal_corrections {
                for value in terminal {
                    encode_fp2(&mut bytes, *value);
                }
            }
            for tag in proof.terminal_tags {
                encode_fp2(&mut bytes, tag);
            }
        }
        debug_assert_eq!(bytes.len() as u64, self.encoded_len()?);
        Ok(bytes)
    }

    pub fn decode(
        expected_statement_digest: C6WrapperDigest,
        expected_rounds: usize,
        bytes: &[u8],
    ) -> Result<Self> {
        if expected_rounds == 0 || expected_rounds > C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
            return Err(C6PersistentCacheBlindError::new("invalid expected C6PC2 round count"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C6_PERSISTENT_CACHE_BLIND_MAGIC {
            return Err(C6PersistentCacheBlindError::new("bad C6PC2 magic"));
        }
        if cursor.u16()? != C6_PERSISTENT_CACHE_BLIND_VERSION
            || cursor.u8()? as usize != C6_WRAPPER_REPETITIONS
            || cursor.u8()? as usize != C6_PERSISTENT_CACHE_BLIND_TAPES
            || cursor.u8()? as usize != expected_rounds
            || cursor.u8()? as usize != C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS
            || cursor.u16()? != 0
        {
            return Err(C6PersistentCacheBlindError::new("C6PC2 header census mismatch"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest != expected_statement_digest {
            return Err(C6PersistentCacheBlindError::new("C6PC2 statement digest mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            if cursor.u8()? as usize != repetition {
                return Err(C6PersistentCacheBlindError::new("C6PC2 repetition order mismatch"));
            }
            let schedule_digest = cursor.digest()?;
            let mut round_corrections = Vec::with_capacity(expected_rounds);
            for _ in 0..expected_rounds {
                round_corrections
                    .push([[cursor.fp2()?, cursor.fp2()?], [cursor.fp2()?, cursor.fp2()?]]);
            }
            let mut terminal_corrections = [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
                C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
            for terminal in &mut terminal_corrections {
                for value in terminal {
                    *value = cursor.fp2()?;
                }
            }
            let terminal_tags = [cursor.fp2()?, cursor.fp2()?];
            repetitions.push(C6PersistentCacheBlindRepetitionProof {
                schedule_digest,
                round_corrections,
                terminal_corrections,
                terminal_tags,
            });
        }
        if !cursor.is_eof() {
            return Err(C6PersistentCacheBlindError::new("trailing C6PC2 bytes"));
        }
        let proof = Self { statement_digest, rounds: expected_rounds as u8, repetitions };
        proof.validate_shape()?;
        Ok(proof)
    }

    pub fn encoded_len(&self) -> Result<u64> {
        c6_persistent_cache_blind_encoded_len(usize::from(self.rounds))
    }

    fn validate_shape(&self) -> Result<()> {
        let rounds = usize::from(self.rounds);
        if self.statement_digest == [0; 32]
            || rounds == 0
            || rounds > C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
            || self.repetitions.len() != C6_WRAPPER_REPETITIONS
            || self.repetitions.iter().any(|proof| {
                proof.schedule_digest == [0; 32] || proof.round_corrections.len() != rounds
            })
        {
            return Err(C6PersistentCacheBlindError::new("invalid C6PC2 proof shape"));
        }
        Ok(())
    }
}

pub fn c6_persistent_cache_blind_encoded_len(rounds: usize) -> Result<u64> {
    if rounds == 0 || rounds > C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
        return Err(C6PersistentCacheBlindError::new("invalid C6PC2 encoded round count"));
    }
    Ok(HEADER_AND_STATEMENT_BYTES
        + C6_WRAPPER_REPETITIONS as u64
            * (REPETITION_PREFIX_BYTES + rounds as u64 * ROUND_BYTES + TERMINAL_BYTES)
        + C6_WRAPPER_REPETITIONS as u64 * C6_PERSISTENT_CACHE_BLIND_TAPES as u64 * FP2_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistentCachePendingDescriptor {
    statement_digest: C6WrapperDigest,
    repetition: u8,
    cohort_id: u32,
    slot: u16,
    target_point: Vec<Fp2>,
}

impl C6PersistentCachePendingDescriptor {
    pub(crate) fn statement_digest(&self) -> C6WrapperDigest {
        self.statement_digest
    }

    pub(crate) fn repetition(&self) -> u8 {
        self.repetition
    }

    pub(crate) fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    pub(crate) fn slot(&self) -> u16 {
        self.slot
    }

    pub(crate) fn target_point(&self) -> &[Fp2] {
        &self.target_point
    }
}

#[derive(Clone)]
struct PendingProverEntry {
    descriptor: C6PersistentCachePendingDescriptor,
    auth: [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
}

#[derive(Clone)]
struct PendingVerifierEntry {
    descriptor: C6PersistentCachePendingDescriptor,
    keys: [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
}

pub struct C6PersistentCachePendingClaimsProver {
    entries: Vec<PendingProverEntry>,
}

pub struct C6PersistentCachePendingClaimsVerifier {
    entries: Vec<PendingVerifierEntry>,
}

impl C6PersistentCachePendingClaimsProver {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn link_entries(
        &self,
    ) -> impl Iterator<
        Item = (
            &C6PersistentCachePendingDescriptor,
            [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
        ),
    > {
        self.entries.iter().map(|entry| (&entry.descriptor, entry.auth))
    }
}

impl C6PersistentCachePendingClaimsVerifier {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn link_entries(
        &self,
    ) -> impl Iterator<
        Item = (
            &C6PersistentCachePendingDescriptor,
            [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
        ),
    > {
        self.entries.iter().map(|entry| (&entry.descriptor, entry.keys))
    }
}

impl fmt::Debug for C6PersistentCachePendingClaimsProver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6PersistentCachePendingClaimsProver")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for C6PersistentCachePendingClaimsVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6PersistentCachePendingClaimsVerifier")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheBlindMetrics {
    pub rounds_per_repetition: u64,
    pub proof_bytes: u64,
    pub full_correlations_per_tape: u64,
    pub pending_claims: u64,
}

pub(crate) fn prove_c6_persistent_cache_blind_reference(
    plan: &C6PersistentCacheRelationPlan,
    witness: &C6PersistentCacheBlindWitness,
    sources: &C6PersistentCacheSourcesProver,
    source_masks: &C6PersistentCacheSourceMasksProver,
    streams: &mut [CorrelationStream; C6_PERSISTENT_CACHE_BLIND_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6PersistentCacheBlindProof,
    C6PersistentCacheSourceBootstrapFrame,
    C6PersistentCachePendingClaimsProver,
    C6PersistentCacheBlindMetrics,
)> {
    sources.validate(plan)?;
    if source_masks.source_schedule_digest != plan.source_schedule_digest {
        return Err(C6PersistentCacheBlindError::new("C6PS1 prover statement mismatch"));
    }
    if witness.tables.iter().any(|table| table.len() != plan.len()) {
        return Err(C6PersistentCacheBlindError::new("C6PC2 witness geometry changed"));
    }
    // These four corrections are fixed by already-authenticated fold sources
    // before the transcript emits either relation point.  Keeping their
    // construction here, ahead of the framing charge, makes the
    // commit-before-challenge dependency executable rather than documentary.
    let fixed_corrections = array::from_fn(|fixed_owner| {
        array::from_fn(|kv| {
            array::from_fn(|tape| {
                let (source, mask) = match fixed_owner {
                    0 => (
                        sources.predecessor_targets[kv][tape],
                        source_masks.predecessor_targets[kv][tape],
                    ),
                    1 => {
                        (sources.current_targets[kv][tape], source_masks.current_targets[kv][tape])
                    }
                    _ => unreachable!(),
                };
                source.x - mask
            })
        })
    });
    let mut transition_corrections =
        [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
    transcript.append(FRAMING_LABEL, HEADER_AND_STATEMENT_BYTES);
    transcript.append(SOURCE_BOOTSTRAP_HEADER_LABEL, SOURCE_BOOTSTRAP_HEADER_BYTES);
    transcript.append(SOURCE_BOOTSTRAP_FIXED_LABEL, SOURCE_BOOTSTRAP_FIXED_BYTES);
    let before = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
        streams[tape].counters.full_corrs
    });
    let mut repetitions = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut pending_entries = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let relation_point =
            (0..plan.rounds).map(|_| transcript.challenge_fp2()).collect::<Vec<_>>();
        let relation_roots = array::from_fn(|_| transcript.challenge_fp2());
        let kv_root = transcript.challenge_fp2();
        let compiled = plan.compile(repetition, &relation_point, relation_roots, kv_root)?;
        let source_aggregates = sources.owner_values(plan, &compiled);
        let aggregate_masks = source_masks.owner_values(plan, &compiled);
        for kv in 0..SOURCE_KV_COUNT {
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                transition_corrections[usize::from(repetition)][kv][tape] =
                    source_aggregates[0][kv][tape].x - aggregate_masks[0][kv][tape];
            }
        }
        transcript.append(SOURCE_BOOTSTRAP_TRANSITION_LABEL, SOURCE_BOOTSTRAP_TRANSITION_BYTES);
        transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);
        let mut current = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
            combine_source_aggregates_prover(&source_aggregates, relation_roots, kv_root, tape)
        });
        let mut coefficient_tables = compiled.coefficients.clone();
        let mut witness_tables = witness.tables.clone();
        let mut point = Vec::with_capacity(plan.rounds);
        let mut round_corrections = Vec::with_capacity(plan.rounds);
        for round in 0..plan.rounds {
            let evaluations = sumcheck_round_evaluations(&coefficient_tables, &witness_tables)?;
            if evaluations[0] + evaluations[1] != current[0].x
                || evaluations[0] + evaluations[1] != current[1].x
            {
                return Err(C6PersistentCacheBlindError::new(
                    "C6PC2 clear relation diverges from authenticated source",
                ));
            }
            let mut corrections = [[Fp2::ZERO; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES];
            let mut nodes = [[ProverAuthed::ZERO; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES];
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                let sent0 = authenticate_one(
                    &mut streams[tape],
                    correlation_domain(repetition, tape, CorrelationPurpose::Round, round * 2)?,
                    evaluations[0],
                )?;
                let sent2 = authenticate_one(
                    &mut streams[tape],
                    correlation_domain(repetition, tape, CorrelationPurpose::Round, round * 2 + 1)?,
                    evaluations[2],
                )?;
                corrections[tape] = [sent0.0, sent2.0];
                nodes[tape] = [sent0.1, current[tape].sub(sent0.1), sent2.1];
                if nodes[tape][1].x != evaluations[1] {
                    return Err(C6PersistentCacheBlindError::new(
                        "C6PC2 compressed node-one mismatch",
                    ));
                }
            }
            transcript.append(ROUND_LABEL, ROUND_BYTES);
            let challenge = transcript.challenge_fp2();
            point.push(challenge);
            let weights = lagrange3(challenge);
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                current[tape] = interpolate_prover(nodes[tape], weights);
            }
            fold_tables(&mut coefficient_tables, challenge)?;
            fold_tables(&mut witness_tables, challenge)?;
            round_corrections.push(corrections);
        }
        let mut terminal_corrections = [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
            C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
        let mut terminals = [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
            C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
        for (terminal, (terminal_auths, correction_values)) in
            terminals.iter_mut().zip(&mut terminal_corrections).enumerate()
        {
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                let (correction, auth) = authenticate_one(
                    &mut streams[tape],
                    correlation_domain(repetition, tape, CorrelationPurpose::Terminal, terminal)?,
                    witness_tables[terminal][0],
                )?;
                correction_values[tape] = correction;
                terminal_auths[tape] = auth;
            }
        }
        transcript.append(TERMINAL_LABEL, TERMINAL_BYTES);
        let terminal_root = transcript.challenge_fp2();
        let terminal_tags = array::from_fn(|tape| {
            let expected = (0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS).fold(
                ProverAuthed::ZERO,
                |sum, terminal| {
                    sum.add(terminals[terminal][tape].scale(coefficient_tables[terminal][0]))
                },
            );
            let residual = current[tape].sub(expected).scale(terminal_root);
            zero_open_prover(&residual, transcript)
        });
        append_pending_prover(&mut pending_entries, plan, repetition, &point, terminals);
        repetitions.push(C6PersistentCacheBlindRepetitionProof {
            schedule_digest: compiled.schedule_digest,
            round_corrections,
            terminal_corrections,
            terminal_tags,
        });
    }
    let proof = C6PersistentCacheBlindProof {
        statement_digest: plan.statement_digest,
        rounds: plan.rounds as u8,
        repetitions,
    };
    proof.validate_shape()?;
    let source_frame = C6PersistentCacheSourceBootstrapFrame::new(
        plan.statement_digest,
        fixed_corrections,
        transition_corrections,
    )?;
    let full_correlations_per_tape = streams[0].counters.full_corrs - before[0];
    if (1..C6_PERSISTENT_CACHE_BLIND_TAPES)
        .any(|tape| streams[tape].counters.full_corrs - before[tape] != full_correlations_per_tape)
    {
        return Err(C6PersistentCacheBlindError::new("C6PC2 cross-tape correlation mismatch"));
    }
    let metrics = C6PersistentCacheBlindMetrics {
        rounds_per_repetition: plan.rounds as u64,
        proof_bytes: proof
            .encoded_len()?
            .checked_add(C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES)
            .ok_or_else(|| {
            C6PersistentCacheBlindError::new("C6 source-bound bytes overflow")
        })?,
        full_correlations_per_tape,
        pending_claims: pending_entries.len() as u64,
    };
    Ok((
        proof,
        source_frame,
        C6PersistentCachePendingClaimsProver { entries: pending_entries },
        metrics,
    ))
}

pub(crate) fn verify_c6_persistent_cache_blind(
    plan: &C6PersistentCacheRelationPlan,
    source_base_keys: &C6PersistentCacheSourcesVerifier,
    source_frame: &C6PersistentCacheSourceBootstrapFrame,
    proof: &C6PersistentCacheBlindProof,
    contexts: &mut [VerifierCtx; C6_PERSISTENT_CACHE_BLIND_TAPES],
    transcript: &mut Transcript,
) -> Result<C6PersistentCachePendingClaimsVerifier> {
    if proof.statement_digest != plan.statement_digest
        || usize::from(proof.rounds) != plan.rounds
        || source_base_keys.source_schedule_digest != plan.source_schedule_digest
        || source_frame.statement_digest != plan.statement_digest
    {
        return Err(C6PersistentCacheBlindError::new("C6PC2 verifier statement mismatch"));
    }
    if contexts[0].delta == contexts[1].delta {
        return Err(C6PersistentCacheBlindError::new("C6PC2 MAC tapes are not independent"));
    }
    proof.validate_shape()?;
    transcript.append(FRAMING_LABEL, HEADER_AND_STATEMENT_BYTES);
    source_frame.charge_header_and_fixed(transcript);
    let mut pending_entries = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let relation_point =
            (0..plan.rounds).map(|_| transcript.challenge_fp2()).collect::<Vec<_>>();
        let relation_roots = array::from_fn(|_| transcript.challenge_fp2());
        let kv_root = transcript.challenge_fp2();
        let compiled = plan.compile(repetition, &relation_point, relation_roots, kv_root)?;
        source_frame.charge_transition(usize::from(repetition), transcript)?;
        let repetition_proof = &proof.repetitions[usize::from(repetition)];
        if repetition_proof.schedule_digest != compiled.schedule_digest {
            return Err(C6PersistentCacheBlindError::new("C6PC2 compiled schedule mismatch"));
        }
        transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);
        let source_base_aggregates = source_base_keys.owner_values(plan, &compiled);
        let source_aggregates = source_frame.correct_base_keys(
            usize::from(repetition),
            &source_base_aggregates,
            [contexts[0].delta, contexts[1].delta],
        )?;
        let mut current = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
            combine_source_aggregates_verifier(&source_aggregates, relation_roots, kv_root, tape)
        });
        let mut coefficient_tables = compiled.coefficients;
        let mut point = Vec::with_capacity(plan.rounds);
        for round in 0..plan.rounds {
            let mut nodes = [[VerifierKey::ZERO; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES];
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                let corrections = repetition_proof.round_corrections[round][tape];
                let sent0 = contexts[tape].correct_full_verifier_keys(
                    correlation_domain(repetition, tape, CorrelationPurpose::Round, round * 2)?,
                    &[corrections[0]],
                )[0];
                let sent2 = contexts[tape].correct_full_verifier_keys(
                    correlation_domain(repetition, tape, CorrelationPurpose::Round, round * 2 + 1)?,
                    &[corrections[1]],
                )[0];
                nodes[tape] = [sent0, current[tape].sub(sent0), sent2];
            }
            transcript.append(ROUND_LABEL, ROUND_BYTES);
            let challenge = transcript.challenge_fp2();
            point.push(challenge);
            let weights = lagrange3(challenge);
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                current[tape] = interpolate_verifier(nodes[tape], weights);
            }
            fold_tables(&mut coefficient_tables, challenge)?;
        }
        let mut terminals = [[VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
            C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
        for (terminal, terminal_keys) in terminals.iter_mut().enumerate() {
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                terminal_keys[tape] = contexts[tape].correct_full_verifier_keys(
                    correlation_domain(repetition, tape, CorrelationPurpose::Terminal, terminal)?,
                    &[repetition_proof.terminal_corrections[terminal][tape]],
                )[0];
            }
        }
        transcript.append(TERMINAL_LABEL, TERMINAL_BYTES);
        let terminal_root = transcript.challenge_fp2();
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let expected = (0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS).fold(
                VerifierKey::ZERO,
                |sum, terminal| {
                    sum.add(terminals[terminal][tape].scale(coefficient_tables[terminal][0]))
                },
            );
            let residual = current[tape].sub(expected).scale(terminal_root);
            transcript.append("zero_open_tag", FP2_BYTES);
            if !zero_open_verify(residual, repetition_proof.terminal_tags[tape]) {
                return Err(C6PersistentCacheBlindError::new("C6PC2 terminal ZeroOpen failed"));
            }
        }
        append_pending_verifier(&mut pending_entries, plan, repetition, &point, terminals);
    }
    Ok(C6PersistentCachePendingClaimsVerifier { entries: pending_entries })
}

fn append_pending_prover(
    entries: &mut Vec<PendingProverEntry>,
    plan: &C6PersistentCacheRelationPlan,
    repetition: u8,
    point: &[Fp2],
    terminals: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) {
    let mut cache_point = point.to_vec();
    cache_point.push(Fp2::ZERO);
    for (cohort_offset, cohort_id) in
        [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID].into_iter().enumerate()
    {
        for slot in 0..8u16 {
            let terminal = cohort_offset * 2 + usize::from(slot.min(1));
            entries.push(PendingProverEntry {
                descriptor: C6PersistentCachePendingDescriptor {
                    statement_digest: plan.statement_digest,
                    repetition,
                    cohort_id,
                    slot,
                    target_point: cache_point.clone(),
                },
                auth: if slot < 2 {
                    terminals[terminal]
                } else {
                    [ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]
                },
            });
        }
    }
    for slot in 16..32u16 {
        entries.push(PendingProverEntry {
            descriptor: C6PersistentCachePendingDescriptor {
                statement_digest: plan.statement_digest,
                repetition,
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                slot,
                target_point: plan.auxiliary_target_point.clone(),
            },
            auth: [ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
        });
    }
}

fn append_pending_verifier(
    entries: &mut Vec<PendingVerifierEntry>,
    plan: &C6PersistentCacheRelationPlan,
    repetition: u8,
    point: &[Fp2],
    terminals: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) {
    let mut cache_point = point.to_vec();
    cache_point.push(Fp2::ZERO);
    for (cohort_offset, cohort_id) in
        [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID].into_iter().enumerate()
    {
        for slot in 0..8u16 {
            let terminal = cohort_offset * 2 + usize::from(slot.min(1));
            entries.push(PendingVerifierEntry {
                descriptor: C6PersistentCachePendingDescriptor {
                    statement_digest: plan.statement_digest,
                    repetition,
                    cohort_id,
                    slot,
                    target_point: cache_point.clone(),
                },
                keys: if slot < 2 {
                    terminals[terminal]
                } else {
                    [VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]
                },
            });
        }
    }
    for slot in 16..32u16 {
        entries.push(PendingVerifierEntry {
            descriptor: C6PersistentCachePendingDescriptor {
                statement_digest: plan.statement_digest,
                repetition,
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                slot,
                target_point: plan.auxiliary_target_point.clone(),
            },
            keys: [VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
        });
    }
}

fn sumcheck_round_evaluations(
    coefficients: &[Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    witness: &[Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) -> Result<[Fp2; 3]> {
    let len = coefficients[0].len();
    if len < 2
        || !len.is_multiple_of(2)
        || coefficients.iter().any(|table| table.len() != len)
        || witness.iter().any(|table| table.len() != len)
    {
        return Err(C6PersistentCacheBlindError::new("C6PC2 round table geometry mismatch"));
    }
    Ok(array::from_fn(|node| {
        let t = Fp2::from_base(Fp::new(node as u64));
        (0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS).fold(Fp2::ZERO, |sum, table| {
            (0..len).step_by(2).fold(sum, |inner, index| {
                let coefficient = coefficients[table][index]
                    + (coefficients[table][index + 1] - coefficients[table][index]) * t;
                let value =
                    witness[table][index] + (witness[table][index + 1] - witness[table][index]) * t;
                inner + coefficient * value
            })
        })
    }))
}

fn fold_tables<const N: usize>(tables: &mut [Vec<Fp2>; N], challenge: Fp2) -> Result<()> {
    for table in tables {
        if table.len() < 2 || !table.len().is_multiple_of(2) {
            return Err(C6PersistentCacheBlindError::new("C6PC2 invalid fold geometry"));
        }
        let mut folded = Vec::with_capacity(table.len() / 2);
        for index in (0..table.len()).step_by(2) {
            folded.push(table[index] + (table[index + 1] - table[index]) * challenge);
        }
        *table = folded;
    }
    Ok(())
}

fn authenticate_one(
    stream: &mut CorrelationStream,
    domain: u64,
    value: Fp2,
) -> Result<(Fp2, ProverAuthed)> {
    let correlation = stream.draw_fulls(domain, 1)[0];
    stream
        .record_c6_fullfield_plaintexts(domain, &[value])
        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?;
    Ok((value - correlation.x, correlation.authenticate(value)))
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

#[derive(Clone, Copy)]
#[repr(u8)]
enum CorrelationPurpose {
    Round = 1,
    Terminal = 2,
}

fn correlation_domain(
    repetition: u8,
    tape: usize,
    purpose: CorrelationPurpose,
    index: usize,
) -> Result<u64> {
    if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
        || tape >= C6_PERSISTENT_CACHE_BLIND_TAPES
        || index > u16::MAX as usize
    {
        return Err(C6PersistentCacheBlindError::new("C6PC2 correlation component out of range"));
    }
    let domain = CORRELATION_BASE
        | (u64::from(repetition) << 28)
        | ((tape as u64) << 24)
        | ((purpose as u64) << 16)
        | index as u64;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 correlation domain uses reserved bits",
        ));
    }
    Ok(domain)
}

fn hash_fp2_slice(hasher: &mut blake3::Hasher, values: &[Fp2]) {
    hasher.update(&(values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
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

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6PersistentCacheBlindError::new("truncated C6PC2 proof"))?;
        self.offset = end;
        Ok(value)
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn digest(&mut self) -> Result<C6WrapperDigest> {
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
            return Err(C6PersistentCacheBlindError::new("noncanonical C6PC2 field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

const _: () = {
    assert!(
        SOURCE_BOOTSTRAP_HEADER_BYTES
            + SOURCE_BOOTSTRAP_FIXED_BYTES
            + C6_WRAPPER_REPETITIONS as u64 * SOURCE_BOOTSTRAP_TRANSITION_BYTES
            == C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES
    );
    assert!(
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS + C6_PERSISTENT_CACHE_BLIND_ZERO_CLAIMS
            == C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION
    );
    assert!(
        HEADER_AND_STATEMENT_BYTES
            + C6_WRAPPER_REPETITIONS as u64
                * (REPETITION_PREFIX_BYTES
                    + C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS as u64 * ROUND_BYTES
                    + TERMINAL_BYTES)
            + C6_WRAPPER_REPETITIONS as u64 * C6_PERSISTENT_CACHE_BLIND_TAPES as u64 * FP2_BYTES
            == C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES
    );
    assert!(
        C6_WRAPPER_REPETITIONS as u64
            * (2 * C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS as u64
                + C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS as u64)
            == C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const ROUNDS: usize = 4;
    const OLD_LEN: usize = 5;
    const APPEND_LEN: usize = 3;
    const TRANSCRIPT_SEED: [u8; 32] = [0x41; 32];
    const TAPE_SEEDS: [[u8; 32]; 2] = [[0x51; 32], [0x62; 32]];

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(17 * value + 3))
    }

    fn dot(coefficients: &[Fp2], values: &[Fp2]) -> Fp2 {
        coefficients
            .iter()
            .zip(values)
            .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient * value)
    }

    fn fixture() -> (
        C6PersistentCacheRelationPlan,
        C6PersistentCacheBlindWitness,
        C6PersistentCacheSourcesProver,
        C6PersistentCacheSourceMasksProver,
        C6PersistentCacheSourcesVerifier,
    ) {
        let len = 1usize << ROUNDS;
        let predecessor_coefficients = array::from_fn(|kv| {
            (0..len).map(|index| symbol(1_000 + kv as u64 * 100 + index as u64)).collect::<Vec<_>>()
        });
        let current_coefficients = array::from_fn(|kv| {
            (0..len).map(|index| symbol(2_000 + kv as u64 * 100 + index as u64)).collect::<Vec<_>>()
        });
        let plan = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            ROUNDS,
            OLD_LEN,
            APPEND_LEN,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            predecessor_coefficients.clone(),
            current_coefficients.clone(),
            vec![symbol(9), symbol(10), symbol(11), Fp2::ZERO],
        )
        .unwrap();
        let predecessor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..len)
                .map(|index| {
                    if index < OLD_LEN {
                        symbol(10_000 + kv as u64 * 1_000 + index as u64)
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        let append: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..APPEND_LEN).map(|index| symbol(20_000 + kv as u64 * 1_000 + index as u64)).collect()
        });
        let successor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..len)
                .map(|index| {
                    if index < OLD_LEN {
                        predecessor[kv][index]
                    } else if index < OLD_LEN + APPEND_LEN {
                        append[kv][index - OLD_LEN]
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        let witness = C6PersistentCacheBlindWitness::new(
            &plan,
            [
                predecessor[0].clone(),
                predecessor[1].clone(),
                successor[0].clone(),
                successor[1].clone(),
            ],
        )
        .unwrap();
        let transition_prover = array::from_fn(|kv| {
            append[kv]
                .iter()
                .map(|&value| [ProverAuthed::from_public(value); 2])
                .collect::<Vec<_>>()
        });
        let predecessor_values: [Fp2; 2] =
            array::from_fn(|kv| dot(&predecessor_coefficients[kv], &predecessor[kv]));
        let current_values: [Fp2; 2] =
            array::from_fn(|kv| dot(&current_coefficients[kv], &successor[kv]));
        let prover_sources = C6PersistentCacheSourcesProver::new(
            &plan,
            transition_prover,
            array::from_fn(|kv| [ProverAuthed::from_public(predecessor_values[kv]); 2]),
            array::from_fn(|kv| [ProverAuthed::from_public(current_values[kv]); 2]),
        )
        .unwrap();
        let transition_masks = array::from_fn(|kv| {
            (0..APPEND_LEN)
                .map(|index| {
                    array::from_fn(|tape| {
                        symbol(30_000 + kv as u64 * 1_000 + tape as u64 * 100 + index as u64)
                    })
                })
                .collect::<Vec<_>>()
        });
        let predecessor_masks = array::from_fn(|kv| {
            array::from_fn(|tape| symbol(40_000 + kv as u64 * 100 + tape as u64))
        });
        let current_masks = array::from_fn(|kv| {
            array::from_fn(|tape| symbol(50_000 + kv as u64 * 100 + tape as u64))
        });
        let source_masks = C6PersistentCacheSourceMasksProver::new(
            &plan,
            transition_masks.clone(),
            predecessor_masks,
            current_masks,
        )
        .unwrap();
        let deltas = [symbol(0xD1), symbol(0xE2)];
        let transition_verifier = array::from_fn(|kv| {
            transition_masks[kv]
                .iter()
                .map(|masks| array::from_fn(|tape| VerifierKey::new(deltas[tape] * masks[tape])))
                .collect::<Vec<_>>()
        });
        let verifier_sources = C6PersistentCacheSourcesVerifier::new(
            &plan,
            transition_verifier,
            array::from_fn(|kv| {
                array::from_fn(|tape| VerifierKey::new(deltas[tape] * predecessor_masks[kv][tape]))
            }),
            array::from_fn(|kv| {
                array::from_fn(|tape| VerifierKey::new(deltas[tape] * current_masks[kv][tape]))
            }),
        )
        .unwrap();
        (plan, witness, prover_sources, source_masks, verifier_sources)
    }

    fn prove_fixture() -> (
        C6PersistentCacheRelationPlan,
        C6PersistentCacheSourcesVerifier,
        C6PersistentCacheBlindProof,
        C6PersistentCacheSourceBootstrapFrame,
        C6PersistentCachePendingClaimsProver,
        C6PersistentCacheBlindMetrics,
        BTreeSet<u64>,
    ) {
        let (plan, witness, prover_sources, source_masks, verifier_sources) = fixture();
        let mut streams = array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let (proof, source_frame, pending, metrics) = prove_c6_persistent_cache_blind_reference(
            &plan,
            &witness,
            &prover_sources,
            &source_masks,
            &mut streams,
            &mut transcript,
        )
        .unwrap();
        let domains = (0..C6_WRAPPER_REPETITIONS as u8)
            .flat_map(|repetition| {
                (0..2).flat_map(move |tape| {
                    (0..ROUNDS * 2)
                        .map(move |index| {
                            correlation_domain(repetition, tape, CorrelationPurpose::Round, index)
                                .unwrap()
                        })
                        .chain((0..4).map(move |index| {
                            correlation_domain(
                                repetition,
                                tape,
                                CorrelationPurpose::Terminal,
                                index,
                            )
                            .unwrap()
                        }))
                })
            })
            .collect();
        (plan, verifier_sources, proof, source_frame, pending, metrics, domains)
    }

    #[test]
    fn production_codec_correlation_and_domain_censuses_are_exact() {
        assert_eq!(c6_persistent_cache_blind_encoded_len(24).unwrap(), 3_506);
        assert_eq!(C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE, 104);
        assert_eq!(C6_PERSISTENT_CACHE_BLIND_ZERO_CLAIMS, 28);
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let domains = (0..C6_WRAPPER_REPETITIONS as u8)
                .flat_map(|repetition| {
                    (0..2 * C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS)
                        .map(move |index| {
                            correlation_domain(repetition, tape, CorrelationPurpose::Round, index)
                                .unwrap()
                        })
                        .chain((0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS).map(move |index| {
                            correlation_domain(
                                repetition,
                                tape,
                                CorrelationPurpose::Terminal,
                                index,
                            )
                            .unwrap()
                        }))
                })
                .collect::<Vec<_>>();
            assert_eq!(domains.len(), 104);
            assert_eq!(domains.iter().copied().collect::<BTreeSet<_>>().len(), 104);
            assert!(domains.iter().all(|domain| domain & RESERVED_DOMAIN_BITS == 0));
        }
        let (plan, _, proof, source_frame, pending, metrics, domains) = prove_fixture();
        assert_eq!(metrics.proof_bytes, 1_250);
        assert_eq!(metrics.full_correlations_per_tape, 24);
        assert_eq!(metrics.pending_claims, 64);
        assert_eq!(pending.len(), 64);
        assert_eq!(domains.len(), 48);
        assert!(domains.iter().all(|domain| domain & RESERVED_DOMAIN_BITS == 0));
        assert_eq!(proof.encode().unwrap().len(), 946);
        assert_eq!(source_frame.encode().unwrap().len(), 304);
        assert_eq!(C6_PERSISTENT_CACHE_SOURCE_BOUND_PRODUCTION_BYTES, 3_810);
        assert_eq!(C6_PERSISTENT_CACHE_BLIND_ZERO_CLAIMS, 28);
        assert_eq!(
            C6PersistentCacheSourceBootstrapFrame::decode(
                plan.statement_digest(),
                &source_frame.encode().unwrap(),
            )
            .unwrap(),
            source_frame
        );
        assert_eq!(
            C6PersistentCacheBlindProof::decode(
                plan.statement_digest(),
                plan.rounds(),
                &proof.encode().unwrap(),
            )
            .unwrap(),
            proof
        );
        let production = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            24,
            1,
            1,
            [1; 32],
            [2; 32],
            [3; 32],
            [vec![], vec![]],
            [vec![], vec![]],
            vec![Fp2::ZERO],
        );
        assert!(production.is_err());
    }

    #[test]
    fn scaled_pointwise_relation_is_transcript_and_pending_identical() {
        let (plan, verifier_sources, proof, source_frame, prover_pending, metrics, _) =
            prove_fixture();
        let mut contexts = [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
        ];
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        let verifier_pending = verify_c6_persistent_cache_blind(
            &plan,
            &verifier_sources,
            &source_frame,
            &proof,
            &mut contexts,
            &mut transcript,
        )
        .unwrap();
        assert_eq!(prover_pending.len(), verifier_pending.len());
        assert_eq!(metrics.pending_claims as usize, verifier_pending.len());
        let prover_descriptors = prover_pending
            .link_entries()
            .map(|(descriptor, _)| descriptor.clone())
            .collect::<Vec<_>>();
        let verifier_descriptors = verifier_pending
            .link_entries()
            .map(|(descriptor, _)| descriptor.clone())
            .collect::<Vec<_>>();
        assert_eq!(prover_descriptors, verifier_descriptors);
        assert_eq!(transcript.total_bytes(), metrics.proof_bytes);
    }

    #[test]
    fn equality_weighting_rejects_a_canceling_invalid_transition() {
        let (plan, mut witness, prover_sources, source_masks, _) = fixture();
        let delta = symbol(77);
        witness.tables[2][1] += delta;
        witness.tables[2][2] = witness.tables[2][2] - delta;
        let unweighted_residual = delta - delta;
        assert_eq!(unweighted_residual, Fp2::ZERO);
        let mut streams = array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]));
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        assert!(prove_c6_persistent_cache_blind_reference(
            &plan,
            &witness,
            &prover_sources,
            &source_masks,
            &mut streams,
            &mut transcript,
        )
        .is_err());
    }

    #[test]
    fn strict_codec_and_every_binding_seam_fail_closed() {
        let (plan, mut verifier_sources, proof, source_frame, _, _, _) = prove_fixture();
        let encoded = proof.encode().unwrap();
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(C6PersistentCacheBlindProof::decode(plan.statement_digest(), ROUNDS, &wrong_magic)
            .is_err());
        let mut wrong_version = encoded.clone();
        wrong_version[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert!(C6PersistentCacheBlindProof::decode(
            plan.statement_digest(),
            ROUNDS,
            &wrong_version,
        )
        .is_err());
        let mut noncanonical = encoded.clone();
        let first_round = HEADER_AND_STATEMENT_BYTES as usize + REPETITION_PREFIX_BYTES as usize;
        noncanonical[first_round..first_round + 8].copy_from_slice(&P.to_le_bytes());
        assert!(C6PersistentCacheBlindProof::decode(
            plan.statement_digest(),
            ROUNDS,
            &noncanonical,
        )
        .is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6PersistentCacheBlindProof::decode(plan.statement_digest(), ROUNDS, &trailing)
            .is_err());

        let source_encoded = source_frame.encode().unwrap();
        let mut bad_source_magic = source_encoded.clone();
        bad_source_magic[0] ^= 1;
        assert!(C6PersistentCacheSourceBootstrapFrame::decode(
            plan.statement_digest(),
            &bad_source_magic,
        )
        .is_err());
        let mut bad_source_field = source_encoded.clone();
        bad_source_field
            [SOURCE_BOOTSTRAP_HEADER_BYTES as usize..SOURCE_BOOTSTRAP_HEADER_BYTES as usize + 8]
            .copy_from_slice(&P.to_le_bytes());
        assert!(C6PersistentCacheSourceBootstrapFrame::decode(
            plan.statement_digest(),
            &bad_source_field,
        )
        .is_err());
        let mut trailing_source = source_encoded.clone();
        trailing_source.push(0);
        assert!(C6PersistentCacheSourceBootstrapFrame::decode(
            plan.statement_digest(),
            &trailing_source,
        )
        .is_err());

        let mut bad_transition_source = source_frame.clone();
        bad_transition_source.transition_corrections[0][0][1] += Fp2::ONE;
        let mut bad_fixed_source = source_frame.clone();
        bad_fixed_source.fixed_corrections[1][1][0] += Fp2::ONE;
        for bad_source_frame in [bad_transition_source, bad_fixed_source] {
            let mut contexts = [
                VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
                VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
            ];
            let mut transcript = Transcript::new(TRANSCRIPT_SEED);
            assert!(verify_c6_persistent_cache_blind(
                &plan,
                &verifier_sources,
                &bad_source_frame,
                &proof,
                &mut contexts,
                &mut transcript,
            )
            .is_err());
        }

        let mut cases = Vec::new();
        let mut bad_schedule = proof.clone();
        bad_schedule.repetitions[0].schedule_digest[0] ^= 1;
        cases.push(bad_schedule);
        let mut bad_round = proof.clone();
        bad_round.repetitions[0].round_corrections[0][0][0] += Fp2::ONE;
        cases.push(bad_round);
        let mut bad_terminal = proof.clone();
        bad_terminal.repetitions[1].terminal_corrections[3][1] += Fp2::ONE;
        cases.push(bad_terminal);
        let mut bad_tag = proof.clone();
        bad_tag.repetitions[0].terminal_tags[1] += Fp2::ONE;
        cases.push(bad_tag);
        for bad in cases {
            let mut contexts = [
                VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
                VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
            ];
            let mut transcript = Transcript::new(TRANSCRIPT_SEED);
            assert!(verify_c6_persistent_cache_blind(
                &plan,
                &verifier_sources,
                &source_frame,
                &bad,
                &mut contexts,
                &mut transcript,
            )
            .is_err());
        }

        verifier_sources.source_schedule_digest[0] ^= 1;
        let mut contexts = [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
        ];
        let mut transcript = Transcript::new(TRANSCRIPT_SEED);
        assert!(verify_c6_persistent_cache_blind(
            &plan,
            &verifier_sources,
            &source_frame,
            &proof,
            &mut contexts,
            &mut transcript,
        )
        .is_err());

        let (_, _, _, _, valid_sources) = fixture();
        let mut contexts = [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
        ];
        let mut wrong_point_transcript = Transcript::new([0x42; 32]);
        assert!(verify_c6_persistent_cache_blind(
            &plan,
            &valid_sources,
            &source_frame,
            &proof,
            &mut contexts,
            &mut wrong_point_transcript,
        )
        .is_err());

        let mut wrong_owner_coefficients = plan.predecessor_coefficients.clone();
        wrong_owner_coefficients[0][0] += Fp2::ONE;
        let wrong_owner = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            ROUNDS,
            OLD_LEN,
            APPEND_LEN,
            plan.root_binding_digest,
            plan.workload_digest,
            plan.source_schedule_digest,
            wrong_owner_coefficients,
            plan.current_coefficients.clone(),
            plan.auxiliary_target_point.clone(),
        )
        .unwrap();
        assert_ne!(wrong_owner.statement_digest(), plan.statement_digest());
        assert!(C6PersistentCacheBlindProof::decode(
            wrong_owner.statement_digest(),
            ROUNDS,
            &encoded,
        )
        .is_err());
    }
}

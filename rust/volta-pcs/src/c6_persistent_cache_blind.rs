//! Pointwise-sound dual-tape blind adapter for the C6 persistent cache.
//!
//! The reference path is deliberately scaled: production geometry must use a
//! streaming client compiler and is rejected here.  The transition owner is
//! weighted by `eq(a, x)` at a verifier-owned relation point; the remaining
//! predecessor owner is canonical zero and the successor owner binds a
//! verifier-root scalar batch of every model cache functional.
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
#[cfg(feature = "c6-trace")]
use volta_proto::c6_cache_fold::{
    C6CacheFoldKind, C6CacheFoldPairedProverTargets, C6CacheFoldPairedVerifierTargets,
    C6CacheFoldScalarBatchPlan, C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceIdentity,
};
use volta_proto::mle::{eq_vec, lagrange3};

use crate::c6_persistent_cache::{
    C6_PERSISTENT_CACHE_CAPACITY_TOKENS, C6_PERSISTENT_CACHE_FOLD_CAPACITY,
    C6_PERSISTENT_CACHE_LAYERS, C6_PERSISTENT_CACHE_PADDED_LAYERS,
    C6_PERSISTENT_CACHE_PADDED_WIDTH, C6_PERSISTENT_CACHE_SLOT_CAPACITY, C6_PERSISTENT_CACHE_WIDTH,
};
#[cfg(feature = "c6-trace")]
use crate::c6_wrapper_pcs::{production_c6_wrapper_specs, C6WrapperRoundPoint};
use crate::c6_wrapper_pcs::{
    C6WrapperDigest, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    C6_WRAPPER_AUXILIARY_COHORT_ID, C6_WRAPPER_REPETITIONS,
};
#[cfg(feature = "c6-trace")]
use crate::c6_wrapper_persisted::C6PersistedCacheSemanticReader;

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
pub const C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_VERSION: u16 = 2;
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
const SOURCE_BOOTSTRAP_FOLD_LABEL: &str = "c6_persistent_cache_source_bootstrap_fold";
const SOURCE_BOOTSTRAP_APPEND_LABEL: &str = "c6_persistent_cache_source_bootstrap_append";
const HEADER_AND_STATEMENT_BYTES: u64 = 48;
const REPETITION_PREFIX_BYTES: u64 = 33;
const ROUND_BYTES: u64 = 64;
const TERMINAL_BYTES: u64 = 128;
const FP2_BYTES: u64 = 16;
const SOURCE_BOOTSTRAP_HEADER_BYTES: u64 = 48;
const SOURCE_BOOTSTRAP_FOLD_BYTES: u64 = 64;
const SOURCE_BOOTSTRAP_APPEND_BYTES: u64 = 64;
const CORRELATION_BASE: u64 = 0x0C66_0000_0000_0000;
#[cfg(feature = "c6-trace")]
const RUNTIME_FOLD_SOURCE_SCHEDULE_DOMAIN: &str = "volta-zk/c6/runtime-fold-source-schedule/v1";

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
    CanonicalPredecessorZero = 1,
    SuccessorModelFolds = 2,
}

impl C6PersistentCacheRelationOwner {
    const ALL: [Self; 3] =
        [Self::AppendTransition, Self::CanonicalPredecessorZero, Self::SuccessorModelFolds];
}

/// Strict aggregate-correction frame that bootstraps the six C6PC2 source
/// keys without exposing any historical corrected key vector.  Fold
/// corrections are repetition-local and committed only after the successor
/// batching root; append corrections follow the verifier-owned equality
/// point.  The canonical predecessor owner has value and correction zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheSourceBootstrapFrame {
    statement_digest: C6WrapperDigest,
    /// repetition, K/V, tape; sampled after the successor batching root.
    fold_corrections:
        [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS],
    /// repetition, K/V, tape; sampled after the relation point.
    append_corrections:
        [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS],
}

impl C6PersistentCacheSourceBootstrapFrame {
    fn new(
        statement_digest: C6WrapperDigest,
        fold_corrections: [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
            C6_WRAPPER_REPETITIONS],
        append_corrections: [[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
            C6_WRAPPER_REPETITIONS],
    ) -> Result<Self> {
        if statement_digest == [0; 32] {
            return Err(C6PersistentCacheBlindError::new(
                "zero C6PS1 source-bootstrap statement digest",
            ));
        }
        Ok(Self { statement_digest, fold_corrections, append_corrections })
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
        bytes.push(2);
        bytes.push(2);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for repetition in &self.fold_corrections {
            for kv in repetition {
                for correction in kv {
                    encode_fp2(&mut bytes, *correction);
                }
            }
        }
        for repetition in &self.append_corrections {
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
            || cursor.u8()? != 2
            || cursor.u8()? != 2
            || cursor.u16()? != 0
        {
            return Err(C6PersistentCacheBlindError::new("C6PS1 header census mismatch"));
        }
        let statement_digest = cursor.digest()?;
        if statement_digest != expected_statement_digest || statement_digest == [0; 32] {
            return Err(C6PersistentCacheBlindError::new("C6PS1 statement digest mismatch"));
        }
        let mut fold_corrections = [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
            C6_WRAPPER_REPETITIONS];
        for repetition in &mut fold_corrections {
            for kv in repetition {
                for correction in kv {
                    *correction = cursor.fp2()?;
                }
            }
        }
        let mut append_corrections = [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
            SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
        for repetition in &mut append_corrections {
            for kv in repetition {
                for correction in kv {
                    *correction = cursor.fp2()?;
                }
            }
        }
        if !cursor.is_eof() {
            return Err(C6PersistentCacheBlindError::new("trailing C6PS1 bytes"));
        }
        Self::new(statement_digest, fold_corrections, append_corrections)
    }

    fn charge_header(&self, transcript: &mut Transcript) {
        transcript.append(SOURCE_BOOTSTRAP_HEADER_LABEL, SOURCE_BOOTSTRAP_HEADER_BYTES);
    }

    fn charge_fold(&self, repetition: usize, transcript: &mut Transcript) -> Result<()> {
        if repetition >= C6_WRAPPER_REPETITIONS {
            return Err(C6PersistentCacheBlindError::new("C6PS1 fold repetition is out of range"));
        }
        transcript.append(SOURCE_BOOTSTRAP_FOLD_LABEL, SOURCE_BOOTSTRAP_FOLD_BYTES);
        Ok(())
    }

    fn charge_append(&self, repetition: usize, transcript: &mut Transcript) -> Result<()> {
        if repetition >= C6_WRAPPER_REPETITIONS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PS1 append repetition is out of range",
            ));
        }
        transcript.append(SOURCE_BOOTSTRAP_APPEND_LABEL, SOURCE_BOOTSTRAP_APPEND_BYTES);
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
            0 => self.append_corrections[repetition][kv][tape],
            1 => Fp2::ZERO,
            2 => self.fold_corrections[repetition][kv][tape],
            _ => unreachable!(),
        })
    }

    /// The post-root C6PS1 fold has no independent correction authority: it
    /// must be the scalar-power fold of the already fixed C6FT1 slots.
    #[cfg(feature = "c6-trace")]
    pub(crate) fn validate_c6ft1_fold_corrections(
        &self,
        repetition: usize,
        scalar_root: Fp2,
        fixed: &C6CacheFoldTargetFixedCorrections,
    ) -> Result<()> {
        if repetition >= C6_WRAPPER_REPETITIONS
            || self.fold_corrections[repetition] != fixed.fold_corrections(scalar_root)
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PS1 fold corrections are not derived from fixed C6FT1 slots",
            ));
        }
        Ok(())
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
pub(crate) struct C6PersistentCacheScaledFoldFunctional {
    ordinal: u16,
    kv: u8,
    coefficients: Vec<Fp2>,
}

impl C6PersistentCacheScaledFoldFunctional {
    pub(crate) fn new(ordinal: usize, kv: usize, coefficients: Vec<Fp2>) -> Result<Self> {
        let ordinal = u16::try_from(ordinal)
            .map_err(|_| C6PersistentCacheBlindError::new("C6PC2 fold ordinal overflow"))?;
        let kv = u8::try_from(kv)
            .map_err(|_| C6PersistentCacheBlindError::new("C6PC2 fold K/V index overflow"))?;
        Ok(Self { ordinal, kv, coefficients })
    }

    pub(crate) fn kv(&self) -> usize {
        usize::from(self.kv)
    }

    pub(crate) fn coefficients(&self) -> &[Fp2] {
        &self.coefficients
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistentCacheRelationPlan {
    rounds: usize,
    old_len: usize,
    append_len: usize,
    root_binding_digest: C6WrapperDigest,
    workload_digest: C6WrapperDigest,
    source_schedule_digest: C6WrapperDigest,
    successor_fold_functionals: Vec<C6PersistentCacheScaledFoldFunctional>,
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
        successor_fold_functionals: Vec<C6PersistentCacheScaledFoldFunctional>,
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
            || successor_fold_functionals.is_empty()
            || successor_fold_functionals.len() as u64 > C6_PERSISTENT_CACHE_FOLD_CAPACITY
            || successor_fold_functionals.iter().enumerate().any(|(ordinal, functional)| {
                usize::from(functional.ordinal) != ordinal
                    || usize::from(functional.kv) >= SOURCE_KV_COUNT
                    || functional.coefficients.len() != len
            })
            || (0..SOURCE_KV_COUNT).any(|kv| {
                !successor_fold_functionals
                    .iter()
                    .any(|functional| usize::from(functional.kv) == kv)
            })
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
            successor_fold_functionals,
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

    pub(crate) fn fold_count(&self) -> usize {
        self.successor_fold_functionals.len()
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
        hasher.update(&(self.successor_fold_functionals.len() as u64).to_le_bytes());
        for functional in &self.successor_fold_functionals {
            hasher.update(&functional.ordinal.to_le_bytes());
            hasher.update(&[functional.kv]);
            hash_fp2_slice(&mut hasher, &functional.coefficients);
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
        fold_weights: &[Fp2],
    ) -> Result<CompiledRelation> {
        if relation_point.len() != self.rounds {
            return Err(C6PersistentCacheBlindError::new("C6PC2 relation-point width mismatch"));
        }
        if fold_weights != self.fold_weights(relation_roots[2]) {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 successor fold weights do not match verifier root",
            ));
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
        }
        for (functional, &weight) in self.successor_fold_functionals.iter().zip(fold_weights) {
            let kv = usize::from(functional.kv);
            let terminal = 2 + kv;
            let factor = relation_roots[2] * weight * if kv == 0 { Fp2::ONE } else { kv_root };
            for (coefficient, &functional_coefficient) in
                coefficients[terminal].iter_mut().zip(&functional.coefficients)
            {
                *coefficient += functional_coefficient * factor;
            }
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

    fn fold_weights(&self, rho: Fp2) -> Vec<Fp2> {
        let mut power = rho;
        self.successor_fold_functionals
            .iter()
            .map(|_| {
                let weight = power;
                power = power * rho;
                weight
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct CompiledRelation {
    equality: Vec<Fp2>,
    coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    schedule_digest: C6WrapperDigest,
}

#[cfg(feature = "c6-trace")]
const C6PC2_LAYER_LOG2: usize = 20;
#[cfg(feature = "c6-trace")]
const C6PC2_LAYER_LEN: usize = 1 << C6PC2_LAYER_LOG2;

/// One repetition's production coefficient compiler. It retains one `2^20`
/// equality slice plus the factorized runtime batch and can write one cache
/// layer at a time. There is deliberately no `2^24` materialization method.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Debug)]
pub(crate) struct C6PersistentCacheProductionRelationCompiler {
    repetition: u8,
    statement_digest: C6WrapperDigest,
    old_len: u16,
    new_len: u16,
    relation_point: [Fp2; C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS],
    relation_roots: [Fp2; SOURCE_OWNER_COUNT],
    kv_root: Fp2,
    equality_within_layer: Vec<Fp2>,
    scalar_batch: C6CacheFoldScalarBatchPlan,
    schedule_digest: C6WrapperDigest,
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionRelationCompiler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repetition: u8,
        statement_digest: C6WrapperDigest,
        old_len: u16,
        new_len: u16,
        relation_point: [Fp2; C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS],
        relation_roots: [Fp2; SOURCE_OWNER_COUNT],
        kv_root: Fp2,
        scalar_batch: C6CacheFoldScalarBatchPlan,
    ) -> Result<Self> {
        if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
            || statement_digest == [0; 32]
            || old_len > new_len
            || new_len > C6_PERSISTENT_CACHE_CAPACITY_TOKENS
            || scalar_batch.identity.scalar_root != relation_roots[2]
            || scalar_batch.identity.fold_count == 0
            || u64::from(scalar_batch.identity.fold_count) > C6_PERSISTENT_CACHE_FOLD_CAPACITY
        {
            return Err(C6PersistentCacheBlindError::new(
                "invalid production C6PC2 factorized compiler binding",
            ));
        }
        let equality_within_layer = eq_vec(&relation_point[..C6PC2_LAYER_LOG2]);
        if equality_within_layer.len() != C6PC2_LAYER_LEN
            || u64::from(C6_PERSISTENT_CACHE_PADDED_LAYERS)
                * u64::from(C6_PERSISTENT_CACHE_CAPACITY_TOKENS)
                * u64::from(C6_PERSISTENT_CACHE_PADDED_WIDTH)
                != C6_PERSISTENT_CACHE_SLOT_CAPACITY
        {
            return Err(C6PersistentCacheBlindError::new("production C6PC2 geometry changed"));
        }
        let schedule_digest = production_schedule_digest(
            repetition,
            statement_digest,
            old_len,
            new_len,
            &relation_point,
            relation_roots,
            kv_root,
            &scalar_batch,
        );
        Ok(Self {
            repetition,
            statement_digest,
            old_len,
            new_len,
            relation_point,
            relation_roots,
            kv_root,
            equality_within_layer,
            scalar_batch,
            schedule_digest,
        })
    }

    pub(crate) fn schedule_digest(&self) -> C6WrapperDigest {
        self.schedule_digest
    }

    fn append_cell_count(&self) -> Result<usize> {
        production_append_cell_count(self.old_len, self.new_len)
    }

    fn append_coefficient(&self, ordinal: usize) -> Result<Fp2> {
        let (padded_layer, layer_index) =
            production_append_indices(self.old_len, self.new_len, ordinal)?;
        Ok(self.equality_within_layer[layer_index]
            * equality_boolean_index(&self.relation_point[C6PC2_LAYER_LOG2..], padded_layer))
    }

    pub(crate) fn write_layer_coefficients(
        &self,
        padded_layer: u16,
        output: &mut [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    ) -> Result<u64> {
        if padded_layer >= C6_PERSISTENT_CACHE_PADDED_LAYERS
            || output.iter().any(|table| table.len() != C6PC2_LAYER_LEN)
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production layer output geometry mismatch",
            ));
        }
        for table in output.iter_mut() {
            table.fill(Fp2::ZERO);
        }
        let layer_equality = equality_boolean_index(
            &self.relation_point[C6PC2_LAYER_LOG2..],
            usize::from(padded_layer),
        );
        write_production_transition_layer(
            padded_layer,
            self.old_len,
            layer_equality,
            &self.equality_within_layer,
            self.relation_roots[0],
            self.kv_root,
            output,
        )?;
        let mut applications = 0u64;
        if padded_layer < C6_PERSISTENT_CACHE_LAYERS {
            let mut model = vec![Fp2::ZERO; C6PC2_LAYER_LEN];
            applications = applications
                .checked_add(
                    self.scalar_batch
                        .write_padded_layer_coefficients(
                            C6CacheFoldKind::KeyRows,
                            usize::from(padded_layer),
                            &mut model,
                        )
                        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?,
                )
                .ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 factor applications overflow")
                })?;
            for (coefficient, model) in output[2].iter_mut().zip(&model) {
                *coefficient += self.relation_roots[2] * *model;
            }
            applications = applications
                .checked_add(
                    self.scalar_batch
                        .write_padded_layer_coefficients(
                            C6CacheFoldKind::ValueColumns,
                            usize::from(padded_layer),
                            &mut model,
                        )
                        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?,
                )
                .ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 factor applications overflow")
                })?;
            for (coefficient, model) in output[3].iter_mut().zip(&model) {
                *coefficient += self.relation_roots[2] * self.kv_root * *model;
            }
        }
        Ok(applications)
    }
}

#[cfg(feature = "c6-trace")]
fn production_append_cell_count(old_len: u16, new_len: u16) -> Result<usize> {
    if old_len >= new_len || new_len > C6_PERSISTENT_CACHE_CAPACITY_TOKENS {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production append geometry is invalid",
        ));
    }
    usize::from(new_len - old_len)
        .checked_mul(usize::from(C6_PERSISTENT_CACHE_LAYERS))
        .and_then(|cells| cells.checked_mul(usize::from(C6_PERSISTENT_CACHE_WIDTH)))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 append census overflows"))
}

#[cfg(feature = "c6-trace")]
fn production_append_indices(old_len: u16, new_len: u16, ordinal: usize) -> Result<(usize, usize)> {
    let append_positions = usize::from(new_len - old_len);
    let cells_per_layer = append_positions
        .checked_mul(usize::from(C6_PERSISTENT_CACHE_WIDTH))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 append layer overflows"))?;
    if ordinal >= production_append_cell_count(old_len, new_len)? || cells_per_layer == 0 {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 append ordinal is outside production geometry",
        ));
    }
    let padded_layer = ordinal / cells_per_layer;
    let within_layer = ordinal % cells_per_layer;
    let position = usize::from(old_len)
        .checked_add(within_layer / usize::from(C6_PERSISTENT_CACHE_WIDTH))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 append position overflows"))?;
    let channel = within_layer % usize::from(C6_PERSISTENT_CACHE_WIDTH);
    let layer_index = position
        .checked_mul(usize::from(C6_PERSISTENT_CACHE_PADDED_WIDTH))
        .and_then(|base| base.checked_add(channel))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 append index overflows"))?;
    Ok((padded_layer, layer_index))
}

#[cfg(feature = "c6-trace")]
fn validate_production_fold_identity(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    identity: C6CacheFoldTraceIdentity,
) -> Result<()> {
    validate_production_batch_fold_identity(&compiler.scalar_batch, identity)
}

#[cfg(feature = "c6-trace")]
fn validate_production_batch_fold_identity(
    scalar_batch: &C6CacheFoldScalarBatchPlan,
    identity: C6CacheFoldTraceIdentity,
) -> Result<()> {
    let batch = scalar_batch.identity;
    if identity.version != batch.version
        || identity.fold_count != batch.fold_count
        || identity.coefficient_applications != batch.coefficient_applications
        || identity.topology_digest != batch.topology_digest
        || identity.instance_digest != batch.instance_digest
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production fold identity diverges from coefficient compiler",
        ));
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn aggregate_production_append_prover(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    sources: &[Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
) -> Result<[[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    let expected = compiler.append_cell_count()?;
    if sources.iter().any(|values| values.len() != expected)
        || sources.iter().flatten().any(|values| values[0].x != values[1].x)
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover append source binding mismatch",
        ));
    }
    let mut aggregates = [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
    for kv in 0..SOURCE_KV_COUNT {
        for (ordinal, values) in sources[kv].iter().enumerate() {
            let coefficient = compiler.append_coefficient(ordinal)?;
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                aggregates[kv][tape] = aggregates[kv][tape].add(values[tape].scale(coefficient));
            }
        }
    }
    Ok(aggregates)
}

#[cfg(feature = "c6-trace")]
fn aggregate_production_append_masks(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    sources: &[Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
) -> Result<[[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    let expected = compiler.append_cell_count()?;
    if sources.iter().any(|values| values.len() != expected) {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production append mask binding mismatch",
        ));
    }
    let mut aggregates = [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
    for kv in 0..SOURCE_KV_COUNT {
        for (ordinal, values) in sources[kv].iter().enumerate() {
            let coefficient = compiler.append_coefficient(ordinal)?;
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                aggregates[kv][tape] += values[tape] * coefficient;
            }
        }
    }
    Ok(aggregates)
}

#[cfg(feature = "c6-trace")]
fn aggregate_production_append_verifier(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    sources: &[Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
) -> Result<[[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    let expected = compiler.append_cell_count()?;
    if sources.iter().any(|values| values.len() != expected) {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier append source binding mismatch",
        ));
    }
    let mut aggregates = [[VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
    for kv in 0..SOURCE_KV_COUNT {
        for (ordinal, values) in sources[kv].iter().enumerate() {
            let coefficient = compiler.append_coefficient(ordinal)?;
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                aggregates[kv][tape] = aggregates[kv][tape].add(values[tape].scale(coefficient));
            }
        }
    }
    Ok(aggregates)
}

#[cfg(feature = "c6-trace")]
fn aggregate_production_fold_prover(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    targets: &C6CacheFoldPairedProverTargets,
) -> Result<[[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    validate_production_fold_identity(compiler, targets.identity)?;
    aggregate_runtime_fold_prover(
        compiler.relation_roots[2],
        compiler.scalar_batch.identity.fold_count as usize,
        targets,
    )
}

#[cfg(feature = "c6-trace")]
fn aggregate_runtime_fold_prover(
    scalar_root: Fp2,
    expected_count: usize,
    targets: &C6CacheFoldPairedProverTargets,
) -> Result<[[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    let mut aggregates = [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
    let mut weight = scalar_root;
    let mut count = 0usize;
    for (kind, values) in targets.terms() {
        let kv = match kind {
            C6CacheFoldKind::KeyRows => 0,
            C6CacheFoldKind::ValueColumns => 1,
        };
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            aggregates[kv][tape] = aggregates[kv][tape].add(values[tape].scale(weight));
        }
        weight = weight * scalar_root;
        count += 1;
    }
    if count != expected_count {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover fold census mismatch",
        ));
    }
    Ok(aggregates)
}

#[cfg(feature = "c6-trace")]
fn aggregate_production_fold_verifier(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    targets: &C6CacheFoldPairedVerifierTargets,
) -> Result<[[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    validate_production_fold_identity(compiler, targets.identity)?;
    aggregate_runtime_fold_verifier(
        compiler.relation_roots[2],
        compiler.scalar_batch.identity.fold_count as usize,
        targets,
    )
}

#[cfg(feature = "c6-trace")]
fn aggregate_runtime_fold_verifier(
    scalar_root: Fp2,
    expected_count: usize,
    targets: &C6CacheFoldPairedVerifierTargets,
) -> Result<[[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]> {
    let mut aggregates = [[VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
    let mut weight = scalar_root;
    let mut count = 0usize;
    for (kind, values) in targets.terms() {
        let kv = match kind {
            C6CacheFoldKind::KeyRows => 0,
            C6CacheFoldKind::ValueColumns => 1,
        };
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            aggregates[kv][tape] = aggregates[kv][tape].add(values[tape].scale(weight));
        }
        weight = weight * scalar_root;
        count += 1;
    }
    if count != expected_count {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier fold census mismatch",
        ));
    }
    Ok(aggregates)
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFixedFoldProver {
    repetition: u8,
    statement_digest: C6WrapperDigest,
    scalar_root: Fp2,
    identity: C6CacheFoldTraceIdentity,
    values: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    corrections: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFixedFoldVerifier {
    repetition: u8,
    statement_digest: C6WrapperDigest,
    scalar_root: Fp2,
    identity: C6CacheFoldTraceIdentity,
    values: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
}

#[cfg(feature = "c6-trace")]
pub(crate) fn begin_c6_persistent_cache_production(
    statement_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<()> {
    if statement_digest == [0; 32] {
        return Err(C6PersistentCacheBlindError::new("zero C6PC2 production statement digest"));
    }
    transcript.append(FRAMING_LABEL, HEADER_AND_STATEMENT_BYTES);
    transcript.append(SOURCE_BOOTSTRAP_HEADER_LABEL, SOURCE_BOOTSTRAP_HEADER_BYTES);
    Ok(())
}

#[cfg(feature = "c6-trace")]
pub(crate) fn draw_c6_persistent_cache_production_roots(
    repetition: u8,
    transcript: &mut Transcript,
) -> Result<([Fp2; SOURCE_OWNER_COUNT], Fp2)> {
    if usize::from(repetition) >= C6_WRAPPER_REPETITIONS {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production root repetition is out of range",
        ));
    }
    Ok((array::from_fn(|_| transcript.challenge_fp2()), transcript.challenge_fp2()))
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionFixedFoldProver {
    pub(crate) fn draw_relation_point(
        &self,
        transcript: &mut Transcript,
    ) -> [Fp2; C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS] {
        array::from_fn(|_| transcript.challenge_fp2())
    }
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionFixedFoldVerifier {
    pub(crate) fn draw_relation_point(
        &self,
        transcript: &mut Transcript,
    ) -> [Fp2; C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS] {
        array::from_fn(|_| transcript.challenge_fp2())
    }
}

#[cfg(feature = "c6-trace")]
pub(crate) fn fix_c6_persistent_cache_production_fold_prover(
    repetition: u8,
    statement_digest: C6WrapperDigest,
    scalar_batch: &C6CacheFoldScalarBatchPlan,
    targets: &C6CacheFoldPairedProverTargets,
    fixed_targets: &C6CacheFoldTargetFixedCorrections,
    transcript: &mut Transcript,
) -> Result<C6PersistentCacheProductionFixedFoldProver> {
    if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
        || statement_digest == [0; 32]
        || fixed_targets.identity() != targets.identity
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover pre-point fold binding mismatch",
        ));
    }
    validate_production_batch_fold_identity(scalar_batch, targets.identity)?;
    let scalar_root = scalar_batch.identity.scalar_root;
    let values = aggregate_runtime_fold_prover(
        scalar_root,
        scalar_batch.identity.fold_count as usize,
        targets,
    )?;
    let corrections = fixed_targets.fold_corrections(scalar_root);
    transcript.append(SOURCE_BOOTSTRAP_FOLD_LABEL, SOURCE_BOOTSTRAP_FOLD_BYTES);
    Ok(C6PersistentCacheProductionFixedFoldProver {
        repetition,
        statement_digest,
        scalar_root,
        identity: targets.identity,
        values,
        corrections,
    })
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn fix_c6_persistent_cache_production_fold_verifier(
    repetition: u8,
    statement_digest: C6WrapperDigest,
    scalar_batch: &C6CacheFoldScalarBatchPlan,
    targets: &C6CacheFoldPairedVerifierTargets,
    fixed_targets: &C6CacheFoldTargetFixedCorrections,
    source_frame: &C6PersistentCacheSourceBootstrapFrame,
    transcript: &mut Transcript,
) -> Result<C6PersistentCacheProductionFixedFoldVerifier> {
    if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
        || statement_digest == [0; 32]
        || source_frame.statement_digest != statement_digest
        || fixed_targets.identity() != targets.identity
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier pre-point fold binding mismatch",
        ));
    }
    validate_production_batch_fold_identity(scalar_batch, targets.identity)?;
    let scalar_root = scalar_batch.identity.scalar_root;
    source_frame.validate_c6ft1_fold_corrections(
        usize::from(repetition),
        scalar_root,
        fixed_targets,
    )?;
    let values = aggregate_runtime_fold_verifier(
        scalar_root,
        scalar_batch.identity.fold_count as usize,
        targets,
    )?;
    source_frame.charge_fold(usize::from(repetition), transcript)?;
    Ok(C6PersistentCacheProductionFixedFoldVerifier {
        repetition,
        statement_digest,
        scalar_root,
        identity: targets.identity,
        values,
    })
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionPreparedProver<'a> {
    pub(crate) round_state: C6PersistentCacheProductionProverRoundState<'a>,
    statement_digest: C6WrapperDigest,
    schedule_digest: C6WrapperDigest,
    fold_corrections: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    append_corrections: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionPreparedProver<'_> {
    fn corrections(
        &self,
    ) -> (
        [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
        [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    ) {
        (self.fold_corrections, self.append_corrections)
    }
}

/// Fix the exact repetition-local C6PS1 sources and start the streamed C6PC2
/// prover. Fold corrections are derived from the already sealed C6FT1 slots;
/// append corrections are the canonical D24 equality fold of response K/V.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_c6_persistent_cache_production_prover<'a>(
    compiler: &'a C6PersistentCacheProductionRelationCompiler,
    predecessor: &'a C6PersistedCacheSemanticReader,
    successor: &'a C6PersistedCacheSemanticReader,
    append_sources: &[Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
    append_masks: &[Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
    fixed_fold: C6PersistentCacheProductionFixedFoldProver,
    transcript: &mut Transcript,
) -> Result<C6PersistentCacheProductionPreparedProver<'a>> {
    if fixed_fold.repetition != compiler.repetition
        || fixed_fold.statement_digest != compiler.statement_digest
        || fixed_fold.scalar_root != compiler.relation_roots[2]
        || fixed_fold.identity.version != compiler.scalar_batch.identity.version
        || fixed_fold.identity.fold_count != compiler.scalar_batch.identity.fold_count
        || fixed_fold.identity.coefficient_applications
            != compiler.scalar_batch.identity.coefficient_applications
        || fixed_fold.identity.topology_digest != compiler.scalar_batch.identity.topology_digest
        || fixed_fold.identity.instance_digest != compiler.scalar_batch.identity.instance_digest
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover fixed-fold/compiler mismatch",
        ));
    }

    let append_values = aggregate_production_append_prover(compiler, append_sources)?;
    let append_masks = aggregate_production_append_masks(compiler, append_masks)?;
    let append_corrections = array::from_fn(|kv| {
        array::from_fn(|tape| append_values[kv][tape].x - append_masks[kv][tape])
    });
    transcript.append(SOURCE_BOOTSTRAP_APPEND_LABEL, SOURCE_BOOTSTRAP_APPEND_BYTES);
    transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);

    let source_aggregates =
        assemble_source_aggregates(append_values, fixed_fold.values, ProverAuthed::ZERO);
    let current = array::from_fn(|tape| {
        combine_source_aggregates_prover(
            &source_aggregates,
            compiler.relation_roots,
            compiler.kv_root,
            tape,
        )
    });
    let round_state = C6PersistentCacheProductionProverRoundState::new(
        compiler.repetition,
        current,
        compiler,
        predecessor,
        successor,
    )?;
    Ok(C6PersistentCacheProductionPreparedProver {
        round_state,
        statement_digest: compiler.statement_digest,
        schedule_digest: compiler.schedule_digest,
        fold_corrections: fixed_fold.corrections,
        append_corrections,
    })
}

/// Apply the strict C6PS1 frame to verifier-owned append base keys while
/// reusing the C6FT1-corrected fold targets. No historical corrected cache
/// key vector is admitted.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_c6_persistent_cache_production_verifier<'a>(
    compiler: &'a C6PersistentCacheProductionRelationCompiler,
    append_base_keys: &[Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; SOURCE_KV_COUNT],
    fixed_fold: C6PersistentCacheProductionFixedFoldVerifier,
    source_frame: &C6PersistentCacheSourceBootstrapFrame,
    deltas: [Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES],
    transcript: &mut Transcript,
) -> Result<C6PersistentCacheProductionVerifierRoundState<'a>> {
    let repetition = usize::from(compiler.repetition);
    if source_frame.statement_digest != compiler.statement_digest
        || deltas[0] == deltas[1]
        || fixed_fold.repetition != compiler.repetition
        || fixed_fold.statement_digest != compiler.statement_digest
        || fixed_fold.scalar_root != compiler.relation_roots[2]
        || fixed_fold.identity.version != compiler.scalar_batch.identity.version
        || fixed_fold.identity.fold_count != compiler.scalar_batch.identity.fold_count
        || fixed_fold.identity.coefficient_applications
            != compiler.scalar_batch.identity.coefficient_applications
        || fixed_fold.identity.topology_digest != compiler.scalar_batch.identity.topology_digest
        || fixed_fold.identity.instance_digest != compiler.scalar_batch.identity.instance_digest
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier source binding mismatch",
        ));
    }
    let append_base = aggregate_production_append_verifier(compiler, append_base_keys)?;
    let append_values = array::from_fn(|kv| {
        array::from_fn(|tape| {
            let base = append_base[kv][tape];
            base.with_same_c6_trace(
                base.k + deltas[tape] * source_frame.append_corrections[repetition][kv][tape],
            )
        })
    });
    source_frame.charge_append(repetition, transcript)?;
    transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);

    let source_aggregates =
        assemble_source_aggregates(append_values, fixed_fold.values, VerifierKey::ZERO);
    let current = array::from_fn(|tape| {
        combine_source_aggregates_verifier(
            &source_aggregates,
            compiler.relation_roots,
            compiler.kv_root,
            tape,
        )
    });
    C6PersistentCacheProductionVerifierRoundState::new(compiler.repetition, current, compiler)
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
fn write_production_transition_layer(
    padded_layer: u16,
    old_len: u16,
    layer_equality: Fp2,
    equality_within_layer: &[Fp2],
    transition_root: Fp2,
    kv_root: Fp2,
    output: &mut [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) -> Result<()> {
    if padded_layer >= C6_PERSISTENT_CACHE_PADDED_LAYERS
        || old_len > C6_PERSISTENT_CACHE_CAPACITY_TOKENS
        || equality_within_layer.len() != C6PC2_LAYER_LEN
        || output.iter().any(|table| table.len() != C6PC2_LAYER_LEN)
    {
        return Err(C6PersistentCacheBlindError::new("C6PC2 transition layer geometry mismatch"));
    }
    for index in 0..C6PC2_LAYER_LEN {
        let position = index >> 10;
        let channel = index & ((1 << 10) - 1);
        let transition = equality_within_layer[index] * layer_equality * transition_root;
        let is_old_live = padded_layer < C6_PERSISTENT_CACHE_LAYERS
            && position < usize::from(old_len)
            && channel < usize::from(C6_PERSISTENT_CACHE_WIDTH);
        if is_old_live {
            output[0][index] = output[0][index] - transition;
            output[1][index] = output[1][index] - transition * kv_root;
        }
        output[2][index] += transition;
        output[3][index] += transition * kv_root;
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn equality_boolean_index(point: &[Fp2], index: usize) -> Fp2 {
    point.iter().enumerate().fold(Fp2::ONE, |value, (bit, coordinate)| {
        value * if index & (1 << bit) == 0 { Fp2::ONE - *coordinate } else { *coordinate }
    })
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
fn production_schedule_digest(
    repetition: u8,
    statement_digest: C6WrapperDigest,
    old_len: u16,
    new_len: u16,
    relation_point: &[Fp2; C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS],
    relation_roots: [Fp2; SOURCE_OWNER_COUNT],
    kv_root: Fp2,
    scalar_batch: &C6CacheFoldScalarBatchPlan,
) -> C6WrapperDigest {
    let mut hasher = blake3::Hasher::new_derive_key(SCHEDULE_DOMAIN);
    hasher.update(&statement_digest);
    hasher.update(&[repetition]);
    hasher.update(&old_len.to_le_bytes());
    hasher.update(&new_len.to_le_bytes());
    hash_fp2_slice(&mut hasher, relation_point);
    hash_fp2_slice(&mut hasher, &relation_roots);
    hash_fp2_slice(&mut hasher, &[kv_root]);
    hasher.update(&scalar_batch.identity.version.to_le_bytes());
    hasher.update(&scalar_batch.identity.fold_count.to_le_bytes());
    hasher.update(&scalar_batch.identity.factor_values.to_le_bytes());
    hasher.update(&scalar_batch.identity.coefficient_applications.to_le_bytes());
    hasher.update(&scalar_batch.identity.topology_digest);
    hasher.update(&scalar_batch.identity.instance_digest);
    hasher.update(&scalar_batch.identity.batch_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct C6PersistentCacheProductionCompilerMetrics {
    pub semantic_bytes_read: u64,
    pub factor_applications: u64,
    pub peak_layer_source_bytes: u64,
    pub peak_layer_coefficient_bytes: u64,
    pub folded_state_bytes: u64,
    pub full_d24_tables_materialized: u64,
}

/// Algebraic first-round message fixed before the response-global challenge.
/// Binding consumes this value and performs the second semantic scan.
#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFixedFirstRound<'a> {
    compiler: &'a C6PersistentCacheProductionRelationCompiler,
    predecessor: &'a C6PersistedCacheSemanticReader,
    successor: &'a C6PersistedCacheSemanticReader,
    evaluations: [Fp2; 3],
    metrics: C6PersistentCacheProductionCompilerMetrics,
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionFixedFirstRound<'_> {
    pub(crate) fn evaluations(&self) -> [Fp2; 3] {
        self.evaluations
    }

    pub(crate) fn metrics(&self) -> C6PersistentCacheProductionCompilerMetrics {
        self.metrics
    }

    pub(crate) fn bind_challenge(
        self,
        challenge: Fp2,
    ) -> Result<C6PersistentCacheProductionFoldedTables> {
        let mut coefficient_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| Vec::with_capacity(1 << 23));
        let mut witness_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| Vec::with_capacity(1 << 23));
        let mut metrics = self.metrics;
        for padded_layer in 0..C6_PERSISTENT_CACHE_PADDED_LAYERS {
            let (witness, bytes_read) = read_production_semantic_layer(
                self.compiler,
                self.predecessor,
                self.successor,
                padded_layer,
            )?;
            metrics.semantic_bytes_read =
                metrics.semantic_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 semantic-read metric overflows")
                })?;
            let mut coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
                array::from_fn(|_| vec![Fp2::ZERO; C6PC2_LAYER_LEN]);
            metrics.factor_applications = metrics
                .factor_applications
                .checked_add(
                    self.compiler.write_layer_coefficients(padded_layer, &mut coefficients)?,
                )
                .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 factor metric overflows"))?;
            fold_layer_into(&coefficients, challenge, &mut coefficient_tables)?;
            fold_layer_into(&witness, challenge, &mut witness_tables)?;
        }
        if coefficient_tables.iter().any(|table| table.len() != 1 << 23)
            || witness_tables.iter().any(|table| table.len() != 1 << 23)
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 folded production state geometry mismatch",
            ));
        }
        metrics.folded_state_bytes = folded_state_bytes(&coefficient_tables, &witness_tables)?;
        Ok(C6PersistentCacheProductionFoldedTables {
            round: 1,
            coefficient_tables,
            witness_tables,
            metrics,
        })
    }
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFoldedTables {
    round: usize,
    coefficient_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    witness_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    metrics: C6PersistentCacheProductionCompilerMetrics,
}

#[cfg(feature = "c6-trace")]
impl C6PersistentCacheProductionFoldedTables {
    pub(crate) fn round(&self) -> usize {
        self.round
    }

    pub(crate) fn metrics(&self) -> C6PersistentCacheProductionCompilerMetrics {
        self.metrics
    }

    pub(crate) fn fix_next_round(&self) -> Result<[Fp2; 3]> {
        if self.round >= C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production folded state is complete",
            ));
        }
        sumcheck_round_evaluations(&self.coefficient_tables, &self.witness_tables)
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if self.round >= C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production folded challenge exceeds round count",
            ));
        }
        fold_tables(&mut self.coefficient_tables, challenge)?;
        fold_tables(&mut self.witness_tables, challenge)?;
        self.round += 1;
        self.metrics.folded_state_bytes = self
            .metrics
            .folded_state_bytes
            .max(folded_state_bytes(&self.coefficient_tables, &self.witness_tables)?);
        Ok(())
    }

    pub(crate) fn terminal_tables(
        &self,
    ) -> Result<(
        [Fp2; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
        [Fp2; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    )> {
        if self.round != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
            || self.coefficient_tables.iter().any(|table| table.len() != 1)
            || self.witness_tables.iter().any(|table| table.len() != 1)
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production terminal requested before completion",
            ));
        }
        Ok((
            array::from_fn(|index| self.coefficient_tables[index][0]),
            array::from_fn(|index| self.witness_tables[index][0]),
        ))
    }
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionProverRoundState<'a> {
    repetition: u8,
    round: usize,
    current: [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
    first_round: Option<C6PersistentCacheProductionFixedFirstRound<'a>>,
    folded: Option<C6PersistentCacheProductionFoldedTables>,
    point: Vec<Fp2>,
    pending_nodes: Option<[[ProverAuthed; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

#[cfg(feature = "c6-trace")]
impl<'a> C6PersistentCacheProductionProverRoundState<'a> {
    pub(crate) fn new(
        repetition: u8,
        current: [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
        compiler: &'a C6PersistentCacheProductionRelationCompiler,
        predecessor: &'a C6PersistedCacheSemanticReader,
        successor: &'a C6PersistedCacheSemanticReader,
    ) -> Result<Self> {
        if repetition != compiler.repetition {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production prover repetition mismatch",
            ));
        }
        Ok(Self {
            repetition,
            round: 0,
            current,
            first_round: Some(fix_c6_persistent_cache_production_first_round(
                compiler,
                predecessor,
                successor,
            )?),
            folded: None,
            point: Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS),
            pending_nodes: None,
        })
    }

    pub(crate) fn fix_next_round(
        &mut self,
        streams: &mut [CorrelationStream; C6_PERSISTENT_CACHE_BLIND_TAPES],
    ) -> Result<[[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES]> {
        if self.pending_nodes.is_some() || self.round >= C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production prover is not awaiting a round message",
            ));
        }
        let evaluations = if self.round == 0 {
            self.first_round
                .as_ref()
                .ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 first-round owner disappeared")
                })?
                .evaluations()
        } else {
            self.folded
                .as_ref()
                .ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 folded prover owner is absent")
                })?
                .fix_next_round()?
        };
        if evaluations[0] + evaluations[1] != self.current[0].x
            || evaluations[0] + evaluations[1] != self.current[1].x
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production clear relation diverges from authenticated source",
            ));
        }
        let mut corrections = [[Fp2::ZERO; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES];
        let mut nodes = [[ProverAuthed::ZERO; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES];
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let sent0 = authenticate_one(
                &mut streams[tape],
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2,
                )?,
                evaluations[0],
            )?;
            let sent2 = authenticate_one(
                &mut streams[tape],
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2 + 1,
                )?,
                evaluations[2],
            )?;
            corrections[tape] = [sent0.0, sent2.0];
            nodes[tape] = [sent0.1, self.current[tape].sub(sent0.1), sent2.1];
            if nodes[tape][1].x != evaluations[1] {
                return Err(C6PersistentCacheBlindError::new(
                    "C6PC2 production compressed node-one mismatch",
                ));
            }
        }
        self.pending_nodes = Some(nodes);
        Ok(corrections)
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6PersistentCacheBlindError::new(
                "C6PC2 production prover challenge precedes round message",
            )
        })?;
        let weights = lagrange3(challenge);
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            self.current[tape] = interpolate_prover(nodes[tape], weights);
        }
        if self.round == 0 {
            let first = self.first_round.take().ok_or_else(|| {
                C6PersistentCacheBlindError::new("C6PC2 first-round owner disappeared")
            })?;
            self.folded = Some(first.bind_challenge(challenge)?);
        } else {
            self.folded
                .as_mut()
                .ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 folded prover owner is absent")
                })?
                .bind_challenge(challenge)?;
        }
        self.point.push(challenge);
        self.round += 1;
        Ok(())
    }

    pub(crate) fn terminal_state(
        &self,
    ) -> Result<(
        [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
        [Fp2; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
        [Fp2; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
        &[Fp2],
        C6PersistentCacheProductionCompilerMetrics,
    )> {
        if self.pending_nodes.is_some() || self.round != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production prover terminal requested before completion",
            ));
        }
        let folded = self.folded.as_ref().ok_or_else(|| {
            C6PersistentCacheBlindError::new("C6PC2 folded prover owner is absent")
        })?;
        let (coefficients, witness) = folded.terminal_tables()?;
        Ok((self.current, coefficients, witness, &self.point, folded.metrics()))
    }
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionVerifierRoundState<'a> {
    repetition: u8,
    round: usize,
    current: [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
    compiler: &'a C6PersistentCacheProductionRelationCompiler,
    coefficient_tables: Option<[Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS]>,
    point: Vec<Fp2>,
    pending_nodes: Option<[[VerifierKey; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
    metrics: C6PersistentCacheProductionCompilerMetrics,
}

#[cfg(feature = "c6-trace")]
impl<'a> C6PersistentCacheProductionVerifierRoundState<'a> {
    pub(crate) fn new(
        repetition: u8,
        current: [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
        compiler: &'a C6PersistentCacheProductionRelationCompiler,
    ) -> Result<Self> {
        if repetition != compiler.repetition {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production verifier repetition mismatch",
            ));
        }
        Ok(Self {
            repetition,
            round: 0,
            current,
            compiler,
            coefficient_tables: None,
            point: Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS),
            pending_nodes: None,
            metrics: C6PersistentCacheProductionCompilerMetrics::default(),
        })
    }

    pub(crate) fn check_next_round(
        &mut self,
        corrections: [[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES],
        contexts: &mut [VerifierCtx; C6_PERSISTENT_CACHE_BLIND_TAPES],
    ) -> Result<()> {
        if self.pending_nodes.is_some() || self.round >= C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production verifier is not awaiting a round message",
            ));
        }
        let mut nodes = [[VerifierKey::ZERO; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES];
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let sent0 = contexts[tape].correct_full_verifier_keys(
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2,
                )?,
                &[corrections[tape][0]],
            )[0];
            let sent2 = contexts[tape].correct_full_verifier_keys(
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2 + 1,
                )?,
                &[corrections[tape][1]],
            )[0];
            nodes[tape] = [sent0, self.current[tape].sub(sent0), sent2];
        }
        self.pending_nodes = Some(nodes);
        Ok(())
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6PersistentCacheBlindError::new(
                "C6PC2 production verifier challenge precedes round message",
            )
        })?;
        let weights = lagrange3(challenge);
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            self.current[tape] = interpolate_verifier(nodes[tape], weights);
        }
        if self.round == 0 {
            let (coefficients, factor_applications) =
                fold_production_coefficient_first_round(self.compiler, challenge)?;
            self.metrics.factor_applications = factor_applications;
            self.metrics.folded_state_bytes = table_bytes(&coefficients)?;
            self.coefficient_tables = Some(coefficients);
        } else {
            fold_tables(
                self.coefficient_tables.as_mut().ok_or_else(|| {
                    C6PersistentCacheBlindError::new("C6PC2 verifier coefficients are absent")
                })?,
                challenge,
            )?;
        }
        self.point.push(challenge);
        self.round += 1;
        Ok(())
    }

    pub(crate) fn terminal_state(
        &self,
    ) -> Result<(
        [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
        [Fp2; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
        &[Fp2],
        C6PersistentCacheProductionCompilerMetrics,
    )> {
        let coefficients = self.coefficient_tables.as_ref().ok_or_else(|| {
            C6PersistentCacheBlindError::new("C6PC2 verifier coefficients are absent")
        })?;
        if self.pending_nodes.is_some()
            || self.round != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
            || coefficients.iter().any(|table| table.len() != 1)
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production verifier terminal requested before completion",
            ));
        }
        Ok((
            self.current,
            array::from_fn(|index| coefficients[index][0]),
            &self.point,
            self.metrics,
        ))
    }
}

#[cfg(feature = "c6-trace")]
fn fold_production_coefficient_first_round(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    challenge: Fp2,
) -> Result<([Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS], u64)> {
    let mut folded: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
        array::from_fn(|_| Vec::with_capacity(1 << 23));
    let mut factor_applications = 0u64;
    for padded_layer in 0..C6_PERSISTENT_CACHE_PADDED_LAYERS {
        let mut coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| vec![Fp2::ZERO; C6PC2_LAYER_LEN]);
        factor_applications = factor_applications
            .checked_add(compiler.write_layer_coefficients(padded_layer, &mut coefficients)?)
            .ok_or_else(|| {
                C6PersistentCacheBlindError::new("C6PC2 verifier factor metric overflows")
            })?;
        fold_layer_into(&coefficients, challenge, &mut folded)?;
    }
    if folded.iter().any(|table| table.len() != 1 << 23) {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 verifier folded coefficient geometry mismatch",
        ));
    }
    Ok((folded, factor_applications))
}

#[cfg(feature = "c6-trace")]
pub(crate) fn fix_c6_persistent_cache_production_first_round<'a>(
    compiler: &'a C6PersistentCacheProductionRelationCompiler,
    predecessor: &'a C6PersistedCacheSemanticReader,
    successor: &'a C6PersistedCacheSemanticReader,
) -> Result<C6PersistentCacheProductionFixedFirstRound<'a>> {
    validate_production_semantic_bindings(compiler, predecessor, successor)?;
    let layer_bytes = u64::try_from(C6PC2_LAYER_LEN)
        .ok()
        .and_then(|values| values.checked_mul(16))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 layer bytes overflow"))?;
    let peak_layer_bytes = layer_bytes
        .checked_mul(4)
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 layer peak overflows"))?;
    let mut metrics = C6PersistentCacheProductionCompilerMetrics {
        peak_layer_source_bytes: peak_layer_bytes,
        peak_layer_coefficient_bytes: peak_layer_bytes,
        ..C6PersistentCacheProductionCompilerMetrics::default()
    };
    let mut evaluations = [Fp2::ZERO; 3];
    for padded_layer in 0..C6_PERSISTENT_CACHE_PADDED_LAYERS {
        let (witness, bytes_read) =
            read_production_semantic_layer(compiler, predecessor, successor, padded_layer)?;
        metrics.semantic_bytes_read =
            metrics.semantic_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                C6PersistentCacheBlindError::new("C6PC2 semantic-read metric overflows")
            })?;
        let mut coefficients: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| vec![Fp2::ZERO; C6PC2_LAYER_LEN]);
        metrics.factor_applications = metrics
            .factor_applications
            .checked_add(compiler.write_layer_coefficients(padded_layer, &mut coefficients)?)
            .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 factor metric overflows"))?;
        let layer_evaluations = sumcheck_round_evaluations(&coefficients, &witness)?;
        for (total, layer) in evaluations.iter_mut().zip(layer_evaluations) {
            *total += layer;
        }
    }
    Ok(C6PersistentCacheProductionFixedFirstRound {
        compiler,
        predecessor,
        successor,
        evaluations,
        metrics,
    })
}

#[cfg(feature = "c6-trace")]
fn validate_production_semantic_bindings(
    compiler: &C6PersistentCacheProductionRelationCompiler,
    predecessor: &C6PersistedCacheSemanticReader,
    successor: &C6PersistedCacheSemanticReader,
) -> Result<()> {
    let predecessor_binding = predecessor.binding();
    let successor_binding = successor.binding();
    if predecessor.payload_len() != C6_PERSISTENT_CACHE_SLOT_CAPACITY as usize
        || successor.payload_len() != C6_PERSISTENT_CACHE_SLOT_CAPACITY as usize
        || predecessor_binding.0 != compiler.statement_digest
        || successor_binding.0 != compiler.statement_digest
        || predecessor_binding.1 != successor_binding.1
        || predecessor_binding.2 == successor_binding.2
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 semantic owners do not bind the production relation",
        ));
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn read_production_semantic_layer(
    _compiler: &C6PersistentCacheProductionRelationCompiler,
    predecessor: &C6PersistedCacheSemanticReader,
    successor: &C6PersistedCacheSemanticReader,
    padded_layer: u16,
) -> Result<([Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS], u64)> {
    let start = usize::from(padded_layer)
        .checked_mul(C6PC2_LAYER_LEN)
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 semantic layer offset overflows"))?;
    let (predecessor_k, bytes_0) = predecessor
        .read_slot_range(0, start, C6PC2_LAYER_LEN)
        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?;
    let (predecessor_v, bytes_1) = predecessor
        .read_slot_range(1, start, C6PC2_LAYER_LEN)
        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?;
    let (successor_k, bytes_2) = successor
        .read_slot_range(0, start, C6PC2_LAYER_LEN)
        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?;
    let (successor_v, bytes_3) = successor
        .read_slot_range(1, start, C6PC2_LAYER_LEN)
        .map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))?;
    let bytes_read = bytes_0
        .checked_add(bytes_1)
        .and_then(|value| value.checked_add(bytes_2))
        .and_then(|value| value.checked_add(bytes_3))
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 semantic bytes overflow"))?;
    Ok(([predecessor_k, predecessor_v, successor_k, successor_v], bytes_read))
}

#[cfg(feature = "c6-trace")]
fn fold_layer_into<const N: usize>(
    source: &[Vec<Fp2>; N],
    challenge: Fp2,
    output: &mut [Vec<Fp2>; N],
) -> Result<()> {
    if N == 0 {
        return Err(C6PersistentCacheBlindError::new("C6PC2 production layer has no tables"));
    }
    let len = source[0].len();
    if len < 2 || !len.is_multiple_of(2) || source.iter().any(|table| table.len() != len) {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production source layer geometry mismatch",
        ));
    }
    for (source, output) in source.iter().zip(output) {
        output.extend(source.chunks_exact(2).map(|pair| pair[0] + (pair[1] - pair[0]) * challenge));
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn folded_state_bytes<const N: usize>(
    coefficients: &[Vec<Fp2>; N],
    witness: &[Vec<Fp2>; N],
) -> Result<u64> {
    table_bytes_iter(coefficients.iter().chain(witness))
}

#[cfg(feature = "c6-trace")]
fn table_bytes<const N: usize>(tables: &[Vec<Fp2>; N]) -> Result<u64> {
    table_bytes_iter(tables)
}

#[cfg(feature = "c6-trace")]
fn table_bytes_iter<'a>(tables: impl IntoIterator<Item = &'a Vec<Fp2>>) -> Result<u64> {
    tables.into_iter().try_fold(0u64, |bytes, table| {
        bytes
            .checked_add(
                u64::try_from(table.len())
                    .ok()
                    .and_then(|values| values.checked_mul(16))
                    .ok_or_else(|| {
                        C6PersistentCacheBlindError::new("C6PC2 folded bytes overflow")
                    })?,
            )
            .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 folded bytes overflow"))
    })
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
    fold_targets: Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

#[derive(Clone)]
pub(crate) struct C6PersistentCacheSourcesVerifier {
    source_schedule_digest: C6WrapperDigest,
    transition_append: [Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
    fold_targets: Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

/// Provider-side base masks matching every already-authenticated append or
/// fold source. They are folded with the exact same public coefficients as
/// the source values and never cross the wire.
#[derive(Clone)]
pub(crate) struct C6PersistentCacheSourceMasksProver {
    source_schedule_digest: C6WrapperDigest,
    transition_append: [Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
    fold_targets: Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

impl C6PersistentCacheSourcesProver {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        fold_targets: Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
    ) -> Result<Self> {
        let sources = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            fold_targets,
        };
        sources.validate(plan)?;
        Ok(sources)
    }

    #[cfg(feature = "c6-trace")]
    pub(crate) fn new_with_runtime_fold_targets(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        base_source_schedule_digest: C6WrapperDigest,
        runtime: &C6CacheFoldPairedProverTargets,
    ) -> Result<Self> {
        validate_runtime_fold_binding(
            plan,
            base_source_schedule_digest,
            runtime.identity,
            runtime.terms().map(|(kind, _)| kind),
        )?;
        Self::new(plan, transition_append, runtime.terms().map(|(_, targets)| targets).collect())
    }

    fn validate(&self, plan: &C6PersistentCacheRelationPlan) -> Result<()> {
        if self.source_schedule_digest != plan.source_schedule_digest
            || self.transition_append.iter().any(|values| values.len() != plan.append_len)
            || self.transition_append.iter().flatten().any(|value| value[0].x != value[1].x)
            || self.fold_targets.len() != plan.successor_fold_functionals.len()
            || self.fold_targets.iter().any(|value| value[0].x != value[1].x)
        {
            return Err(C6PersistentCacheBlindError::new("C6PC2 prover source binding mismatch"));
        }
        Ok(())
    }

    fn append_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        array::from_fn(|kv| {
            array::from_fn(|tape| {
                self.transition_append[kv].iter().enumerate().fold(
                    ProverAuthed::ZERO,
                    |sum, (offset, value)| {
                        sum.add(value[tape].scale(compiled.equality[plan.old_len + offset]))
                    },
                )
            })
        })
    }

    fn fold_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        fold_weights: &[Fp2],
    ) -> [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        let mut values = [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
        for ((functional, target), &weight) in
            plan.successor_fold_functionals.iter().zip(&self.fold_targets).zip(fold_weights)
        {
            let kv = usize::from(functional.kv);
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                values[kv][tape] = values[kv][tape].add(target[tape].scale(weight));
            }
        }
        values
    }
}

impl C6PersistentCacheSourcesVerifier {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        fold_targets: Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
    ) -> Result<Self> {
        let sources = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            fold_targets,
        };
        if sources.source_schedule_digest != plan.source_schedule_digest
            || sources.transition_append.iter().any(|values| values.len() != plan.append_len)
            || sources.fold_targets.len() != plan.successor_fold_functionals.len()
        {
            return Err(C6PersistentCacheBlindError::new("C6PC2 verifier source binding mismatch"));
        }
        Ok(sources)
    }

    #[cfg(feature = "c6-trace")]
    pub(crate) fn new_with_runtime_fold_targets(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        base_source_schedule_digest: C6WrapperDigest,
        runtime: &C6CacheFoldPairedVerifierTargets,
    ) -> Result<Self> {
        validate_runtime_fold_binding(
            plan,
            base_source_schedule_digest,
            runtime.identity,
            runtime.terms().map(|(kind, _)| kind),
        )?;
        Self::new(plan, transition_append, runtime.terms().map(|(_, targets)| targets).collect())
    }

    fn append_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        array::from_fn(|kv| {
            array::from_fn(|tape| {
                self.transition_append[kv].iter().enumerate().fold(
                    VerifierKey::ZERO,
                    |sum, (offset, value)| {
                        sum.add(value[tape].scale(compiled.equality[plan.old_len + offset]))
                    },
                )
            })
        })
    }

    fn fold_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        fold_weights: &[Fp2],
    ) -> [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        let mut values = [[VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
        for ((functional, target), &weight) in
            plan.successor_fold_functionals.iter().zip(&self.fold_targets).zip(fold_weights)
        {
            let kv = usize::from(functional.kv);
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                values[kv][tape] = values[kv][tape].add(target[tape].scale(weight));
            }
        }
        values
    }
}

#[cfg(feature = "c6-trace")]
pub(crate) fn c6_runtime_fold_source_schedule_digest(
    base_source_schedule_digest: C6WrapperDigest,
    identity: C6CacheFoldTraceIdentity,
) -> Result<C6WrapperDigest> {
    if base_source_schedule_digest == [0; 32]
        || identity.fold_count == 0
        || u64::from(identity.fold_count) > C6_PERSISTENT_CACHE_FOLD_CAPACITY
    {
        return Err(C6PersistentCacheBlindError::new(
            "invalid C6 runtime-fold source-schedule binding",
        ));
    }
    let mut hasher = blake3::Hasher::new_derive_key(RUNTIME_FOLD_SOURCE_SCHEDULE_DOMAIN);
    hasher.update(&base_source_schedule_digest);
    hasher.update(&identity.version.to_le_bytes());
    hasher.update(&identity.fold_count.to_le_bytes());
    hasher.update(&identity.coefficient_applications.to_le_bytes());
    hasher.update(&identity.topology_digest);
    hasher.update(&identity.instance_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(feature = "c6-trace")]
fn validate_runtime_fold_binding(
    plan: &C6PersistentCacheRelationPlan,
    base_source_schedule_digest: C6WrapperDigest,
    identity: C6CacheFoldTraceIdentity,
    kinds: impl Iterator<Item = C6CacheFoldKind>,
) -> Result<()> {
    let expected_schedule =
        c6_runtime_fold_source_schedule_digest(base_source_schedule_digest, identity)?;
    if plan.source_schedule_digest != expected_schedule
        || identity.fold_count as usize != plan.successor_fold_functionals.len()
        || kinds.zip(&plan.successor_fold_functionals).any(|(kind, functional)| {
            usize::from(functional.kv)
                != match kind {
                    C6CacheFoldKind::KeyRows => 0,
                    C6CacheFoldKind::ValueColumns => 1,
                }
        })
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6 runtime fold targets do not match the cache statement",
        ));
    }
    Ok(())
}

impl C6PersistentCacheSourceMasksProver {
    pub(crate) fn new(
        plan: &C6PersistentCacheRelationPlan,
        transition_append: [Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>; 2],
        fold_targets: Vec<[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
    ) -> Result<Self> {
        let masks = Self {
            source_schedule_digest: plan.source_schedule_digest,
            transition_append,
            fold_targets,
        };
        masks.validate(plan)?;
        Ok(masks)
    }

    fn validate(&self, plan: &C6PersistentCacheRelationPlan) -> Result<()> {
        if self.source_schedule_digest != plan.source_schedule_digest
            || self.transition_append.iter().any(|values| values.len() != plan.append_len)
            || self.fold_targets.len() != plan.successor_fold_functionals.len()
        {
            return Err(C6PersistentCacheBlindError::new("C6PS1 prover mask binding mismatch"));
        }
        Ok(())
    }

    fn append_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        compiled: &CompiledRelation,
    ) -> [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        array::from_fn(|kv| {
            array::from_fn(|tape| {
                self.transition_append[kv].iter().enumerate().fold(
                    Fp2::ZERO,
                    |sum, (offset, value)| {
                        sum + value[tape] * compiled.equality[plan.old_len + offset]
                    },
                )
            })
        })
    }

    fn fold_values(
        &self,
        plan: &C6PersistentCacheRelationPlan,
        fold_weights: &[Fp2],
    ) -> [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT] {
        let mut values = [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT];
        for ((functional, target), &weight) in
            plan.successor_fold_functionals.iter().zip(&self.fold_targets).zip(fold_weights)
        {
            let kv = usize::from(functional.kv);
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                values[kv][tape] += target[tape] * weight;
            }
        }
        values
    }
}

fn assemble_source_aggregates<T: Copy>(
    append: [[T; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    fold: [[T; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    zero: T,
) -> [[[T; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; SOURCE_OWNER_COUNT] {
    [append, [[zero; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT], fold]
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

struct C6PersistentCacheProverRoundState {
    repetition: u8,
    round: usize,
    rounds: usize,
    current: [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
    coefficient_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    witness_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    point: Vec<Fp2>,
    pending_nodes: Option<[[ProverAuthed; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

impl C6PersistentCacheProverRoundState {
    fn new(
        repetition: u8,
        current: [ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES],
        compiled: &CompiledRelation,
        witness: &C6PersistentCacheBlindWitness,
        rounds: usize,
    ) -> Self {
        Self {
            repetition,
            round: 0,
            rounds,
            current,
            coefficient_tables: compiled.coefficients.clone(),
            witness_tables: witness.tables.clone(),
            point: Vec::with_capacity(rounds),
            pending_nodes: None,
        }
    }

    fn fix_next_round(
        &mut self,
        streams: &mut [CorrelationStream; C6_PERSISTENT_CACHE_BLIND_TAPES],
    ) -> Result<[[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES]> {
        if self.pending_nodes.is_some() || self.round >= self.rounds {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 prover round state is not awaiting a message",
            ));
        }
        let evaluations =
            sumcheck_round_evaluations(&self.coefficient_tables, &self.witness_tables)?;
        if evaluations[0] + evaluations[1] != self.current[0].x
            || evaluations[0] + evaluations[1] != self.current[1].x
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
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2,
                )?,
                evaluations[0],
            )?;
            let sent2 = authenticate_one(
                &mut streams[tape],
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2 + 1,
                )?,
                evaluations[2],
            )?;
            corrections[tape] = [sent0.0, sent2.0];
            nodes[tape] = [sent0.1, self.current[tape].sub(sent0.1), sent2.1];
            if nodes[tape][1].x != evaluations[1] {
                return Err(C6PersistentCacheBlindError::new("C6PC2 compressed node-one mismatch"));
            }
        }
        self.pending_nodes = Some(nodes);
        Ok(corrections)
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6PersistentCacheBlindError::new("C6PC2 prover challenge precedes round message")
        })?;
        let weights = lagrange3(challenge);
        self.point.push(challenge);
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            self.current[tape] = interpolate_prover(nodes[tape], weights);
        }
        fold_tables(&mut self.coefficient_tables, challenge)?;
        fold_tables(&mut self.witness_tables, challenge)?;
        self.round += 1;
        Ok(())
    }
}

struct C6PersistentCacheVerifierRoundState {
    repetition: u8,
    round: usize,
    rounds: usize,
    current: [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
    coefficient_tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
    point: Vec<Fp2>,
    pending_nodes: Option<[[VerifierKey; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
}

impl C6PersistentCacheVerifierRoundState {
    fn new(
        repetition: u8,
        current: [VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES],
        compiled: CompiledRelation,
        rounds: usize,
    ) -> Self {
        Self {
            repetition,
            round: 0,
            rounds,
            current,
            coefficient_tables: compiled.coefficients,
            point: Vec::with_capacity(rounds),
            pending_nodes: None,
        }
    }

    fn check_next_round(
        &mut self,
        corrections: [[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES],
        contexts: &mut [VerifierCtx; C6_PERSISTENT_CACHE_BLIND_TAPES],
    ) -> Result<()> {
        if self.pending_nodes.is_some() || self.round >= self.rounds {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 verifier round state is not awaiting a message",
            ));
        }
        let mut nodes = [[VerifierKey::ZERO; 3]; C6_PERSISTENT_CACHE_BLIND_TAPES];
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let sent0 = contexts[tape].correct_full_verifier_keys(
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2,
                )?,
                &[corrections[tape][0]],
            )[0];
            let sent2 = contexts[tape].correct_full_verifier_keys(
                correlation_domain(
                    self.repetition,
                    tape,
                    CorrelationPurpose::Round,
                    self.round * 2 + 1,
                )?,
                &[corrections[tape][1]],
            )[0];
            nodes[tape] = [sent0, self.current[tape].sub(sent0), sent2];
        }
        self.pending_nodes = Some(nodes);
        Ok(())
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let nodes = self.pending_nodes.take().ok_or_else(|| {
            C6PersistentCacheBlindError::new("C6PC2 verifier challenge precedes round message")
        })?;
        let weights = lagrange3(challenge);
        self.point.push(challenge);
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            self.current[tape] = interpolate_verifier(nodes[tape], weights);
        }
        fold_tables(&mut self.coefficient_tables, challenge)?;
        self.round += 1;
        Ok(())
    }
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
    source_masks.validate(plan)?;
    if witness.tables.iter().any(|table| table.len() != plan.len()) {
        return Err(C6PersistentCacheBlindError::new("C6PC2 witness geometry changed"));
    }
    let mut fold_corrections =
        [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
    let mut append_corrections =
        [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
    transcript.append(FRAMING_LABEL, HEADER_AND_STATEMENT_BYTES);
    transcript.append(SOURCE_BOOTSTRAP_HEADER_LABEL, SOURCE_BOOTSTRAP_HEADER_BYTES);
    let before = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
        streams[tape].counters.full_corrs
    });
    let mut repetitions = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut pending_entries = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let relation_roots = array::from_fn(|_| transcript.challenge_fp2());
        let kv_root = transcript.challenge_fp2();
        let fold_weights = plan.fold_weights(relation_roots[2]);
        let fold_values = sources.fold_values(plan, &fold_weights);
        let fold_masks = source_masks.fold_values(plan, &fold_weights);
        for kv in 0..SOURCE_KV_COUNT {
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                fold_corrections[usize::from(repetition)][kv][tape] =
                    fold_values[kv][tape].x - fold_masks[kv][tape];
            }
        }
        transcript.append(SOURCE_BOOTSTRAP_FOLD_LABEL, SOURCE_BOOTSTRAP_FOLD_BYTES);
        let relation_point =
            (0..plan.rounds).map(|_| transcript.challenge_fp2()).collect::<Vec<_>>();
        let compiled =
            plan.compile(repetition, &relation_point, relation_roots, kv_root, &fold_weights)?;
        let append_values = sources.append_values(plan, &compiled);
        let append_masks = source_masks.append_values(plan, &compiled);
        for kv in 0..SOURCE_KV_COUNT {
            for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                append_corrections[usize::from(repetition)][kv][tape] =
                    append_values[kv][tape].x - append_masks[kv][tape];
            }
        }
        transcript.append(SOURCE_BOOTSTRAP_APPEND_LABEL, SOURCE_BOOTSTRAP_APPEND_BYTES);
        let source_aggregates =
            assemble_source_aggregates(append_values, fold_values, ProverAuthed::ZERO);
        transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);
        let current = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
            combine_source_aggregates_prover(&source_aggregates, relation_roots, kv_root, tape)
        });
        let mut round_state = C6PersistentCacheProverRoundState::new(
            repetition,
            current,
            &compiled,
            witness,
            plan.rounds,
        );
        let mut round_corrections = Vec::with_capacity(plan.rounds);
        for _ in 0..plan.rounds {
            let corrections = round_state.fix_next_round(streams)?;
            transcript.append(ROUND_LABEL, ROUND_BYTES);
            let challenge = transcript.challenge_fp2();
            round_state.bind_challenge(challenge)?;
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
                    round_state.witness_tables[terminal][0],
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
                    sum.add(
                        terminals[terminal][tape]
                            .scale(round_state.coefficient_tables[terminal][0]),
                    )
                },
            );
            let residual = round_state.current[tape].sub(expected).scale(terminal_root);
            zero_open_prover(&residual, transcript)
        });
        append_pending_prover(
            &mut pending_entries,
            plan,
            repetition,
            &round_state.point,
            terminals,
        );
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
        fold_corrections,
        append_corrections,
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
    source_frame.charge_header(transcript);
    let mut pending_entries = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let relation_roots = array::from_fn(|_| transcript.challenge_fp2());
        let kv_root = transcript.challenge_fp2();
        let fold_weights = plan.fold_weights(relation_roots[2]);
        let fold_values = source_base_keys.fold_values(plan, &fold_weights);
        source_frame.charge_fold(usize::from(repetition), transcript)?;
        let relation_point =
            (0..plan.rounds).map(|_| transcript.challenge_fp2()).collect::<Vec<_>>();
        let compiled =
            plan.compile(repetition, &relation_point, relation_roots, kv_root, &fold_weights)?;
        let append_values = source_base_keys.append_values(plan, &compiled);
        source_frame.charge_append(usize::from(repetition), transcript)?;
        let repetition_proof = &proof.repetitions[usize::from(repetition)];
        if repetition_proof.schedule_digest != compiled.schedule_digest {
            return Err(C6PersistentCacheBlindError::new("C6PC2 compiled schedule mismatch"));
        }
        transcript.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);
        let source_base_aggregates =
            assemble_source_aggregates(append_values, fold_values, VerifierKey::ZERO);
        let source_aggregates = source_frame.correct_base_keys(
            usize::from(repetition),
            &source_base_aggregates,
            [contexts[0].delta, contexts[1].delta],
        )?;
        let current = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_TAPES, _>(|tape| {
            combine_source_aggregates_verifier(&source_aggregates, relation_roots, kv_root, tape)
        });
        let mut round_state =
            C6PersistentCacheVerifierRoundState::new(repetition, current, compiled, plan.rounds);
        for round in 0..plan.rounds {
            round_state.check_next_round(repetition_proof.round_corrections[round], contexts)?;
            transcript.append(ROUND_LABEL, ROUND_BYTES);
            let challenge = transcript.challenge_fp2();
            round_state.bind_challenge(challenge)?;
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
                    sum.add(
                        terminals[terminal][tape]
                            .scale(round_state.coefficient_tables[terminal][0]),
                    )
                },
            );
            let residual = round_state.current[tape].sub(expected).scale(terminal_root);
            transcript.append("zero_open_tag", FP2_BYTES);
            if !zero_open_verify(residual, repetition_proof.terminal_tags[tape]) {
                return Err(C6PersistentCacheBlindError::new("C6PC2 terminal ZeroOpen failed"));
            }
        }
        append_pending_verifier(
            &mut pending_entries,
            plan,
            repetition,
            &round_state.point,
            terminals,
        );
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

#[cfg(feature = "c6-trace")]
fn production_auxiliary_point(point: &C6WrapperRoundPoint) -> Result<Vec<Fp2>> {
    let spec = production_c6_wrapper_specs()
        .into_iter()
        .find(|spec| spec.cohort_id == C6_WRAPPER_AUXILIARY_COHORT_ID)
        .ok_or_else(|| C6PersistentCacheBlindError::new("C6PC2 auxiliary cohort disappeared"))?;
    point.cohort_point(spec).map_err(|error| C6PersistentCacheBlindError::new(error.to_string()))
}

#[cfg(feature = "c6-trace")]
fn append_pending_production_prover(
    entries: &mut Vec<PendingProverEntry>,
    statement_digest: C6WrapperDigest,
    repetition: u8,
    point: &C6WrapperRoundPoint,
    terminals: [[ProverAuthed; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) -> Result<()> {
    if point.repetition() != repetition {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 prover wrapper-point repetition mismatch",
        ));
    }
    let cache_point = point.common_point().to_vec();
    let auxiliary_point = production_auxiliary_point(point)?;
    for (cohort_offset, cohort_id) in
        [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID].into_iter().enumerate()
    {
        for slot in 0..8u16 {
            let terminal = cohort_offset * 2 + usize::from(slot.min(1));
            entries.push(PendingProverEntry {
                descriptor: C6PersistentCachePendingDescriptor {
                    statement_digest,
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
                statement_digest,
                repetition,
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                slot,
                target_point: auxiliary_point.clone(),
            },
            auth: [ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
        });
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn append_pending_production_verifier(
    entries: &mut Vec<PendingVerifierEntry>,
    statement_digest: C6WrapperDigest,
    repetition: u8,
    point: &C6WrapperRoundPoint,
    terminals: [[VerifierKey; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
) -> Result<()> {
    if point.repetition() != repetition {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 verifier wrapper-point repetition mismatch",
        ));
    }
    let cache_point = point.common_point().to_vec();
    let auxiliary_point = production_auxiliary_point(point)?;
    for (cohort_offset, cohort_id) in
        [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID].into_iter().enumerate()
    {
        for slot in 0..8u16 {
            let terminal = cohort_offset * 2 + usize::from(slot.min(1));
            entries.push(PendingVerifierEntry {
                descriptor: C6PersistentCachePendingDescriptor {
                    statement_digest,
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
                statement_digest,
                repetition,
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                slot,
                target_point: auxiliary_point.clone(),
            },
            keys: [VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
        });
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFinishedProver {
    repetition: u8,
    proof: C6PersistentCacheBlindRepetitionProof,
    fold_corrections: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    append_corrections: [[Fp2; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
    pending: Vec<PendingProverEntry>,
    compiler_metrics: C6PersistentCacheProductionCompilerMetrics,
}

#[cfg(feature = "c6-trace")]
pub(crate) fn finish_c6_persistent_cache_production_prover_repetition(
    prepared: C6PersistentCacheProductionPreparedProver<'_>,
    point: &C6WrapperRoundPoint,
    streams: &mut [CorrelationStream; C6_PERSISTENT_CACHE_BLIND_TAPES],
    transcript: &mut Transcript,
    round_corrections: Vec<[[Fp2; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES]>,
) -> Result<C6PersistentCacheProductionFinishedProver> {
    let C6PersistentCacheProductionPreparedProver {
        round_state,
        statement_digest,
        schedule_digest,
        fold_corrections,
        append_corrections,
    } = prepared;
    let repetition = round_state.repetition;
    if point.repetition() != repetition
        || round_corrections.len() != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover terminal schedule mismatch",
        ));
    }
    let (current, coefficients, witness, sumcheck_point, compiler_metrics) =
        round_state.terminal_state()?;
    if sumcheck_point != point.random_point() {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover point diverges from global coordinator",
        ));
    }
    let mut terminal_corrections =
        [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
    let mut terminals = [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
    for terminal in 0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS {
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            let (correction, auth) = authenticate_one(
                &mut streams[tape],
                correlation_domain(repetition, tape, CorrelationPurpose::Terminal, terminal)?,
                witness[terminal],
            )?;
            terminal_corrections[terminal][tape] = correction;
            terminals[terminal][tape] = auth;
        }
    }
    transcript.append(TERMINAL_LABEL, TERMINAL_BYTES);
    let terminal_root = transcript.challenge_fp2();
    let terminal_tags = array::from_fn(|tape| {
        let expected = (0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS)
            .fold(ProverAuthed::ZERO, |sum, terminal| {
                sum.add(terminals[terminal][tape].scale(coefficients[terminal]))
            });
        zero_open_prover(&current[tape].sub(expected).scale(terminal_root), transcript)
    });
    let mut pending = Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION);
    append_pending_production_prover(&mut pending, statement_digest, repetition, point, terminals)?;
    Ok(C6PersistentCacheProductionFinishedProver {
        repetition,
        proof: C6PersistentCacheBlindRepetitionProof {
            schedule_digest,
            round_corrections,
            terminal_corrections,
            terminal_tags,
        },
        fold_corrections,
        append_corrections,
        pending,
        compiler_metrics,
    })
}

#[cfg(feature = "c6-trace")]
pub(crate) struct C6PersistentCacheProductionFinishedVerifier {
    repetition: u8,
    pending: Vec<PendingVerifierEntry>,
    compiler_metrics: C6PersistentCacheProductionCompilerMetrics,
}

#[cfg(feature = "c6-trace")]
pub(crate) fn finish_c6_persistent_cache_production_verifier_repetition(
    round_state: C6PersistentCacheProductionVerifierRoundState<'_>,
    point: &C6WrapperRoundPoint,
    proof: &C6PersistentCacheBlindProof,
    contexts: &mut [VerifierCtx; C6_PERSISTENT_CACHE_BLIND_TAPES],
    transcript: &mut Transcript,
) -> Result<C6PersistentCacheProductionFinishedVerifier> {
    let repetition = round_state.repetition;
    if proof.statement_digest != round_state.compiler.statement_digest
        || usize::from(proof.rounds) != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
        || proof.repetitions.len() != C6_WRAPPER_REPETITIONS
        || point.repetition() != repetition
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier proof binding mismatch",
        ));
    }
    let repetition_proof = &proof.repetitions[usize::from(repetition)];
    if point.repetition() != repetition
        || repetition_proof.schedule_digest != round_state.compiler.schedule_digest
    {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier terminal schedule mismatch",
        ));
    }
    let (current, coefficients, sumcheck_point, compiler_metrics) = round_state.terminal_state()?;
    if sumcheck_point != point.random_point() {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier point diverges from global coordinator",
        ));
    }
    let mut terminals = [[VerifierKey::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS];
    for terminal in 0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS {
        for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
            terminals[terminal][tape] = contexts[tape].correct_full_verifier_keys(
                correlation_domain(repetition, tape, CorrelationPurpose::Terminal, terminal)?,
                &[repetition_proof.terminal_corrections[terminal][tape]],
            )[0];
        }
    }
    transcript.append(TERMINAL_LABEL, TERMINAL_BYTES);
    let terminal_root = transcript.challenge_fp2();
    for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
        let expected = (0..C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS)
            .fold(VerifierKey::ZERO, |sum, terminal| {
                sum.add(terminals[terminal][tape].scale(coefficients[terminal]))
            });
        let residual = current[tape].sub(expected).scale(terminal_root);
        transcript.append("zero_open_tag", FP2_BYTES);
        if !zero_open_verify(residual, repetition_proof.terminal_tags[tape]) {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production terminal ZeroOpen failed",
            ));
        }
    }
    let mut pending = Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION);
    append_pending_production_verifier(
        &mut pending,
        round_state.compiler.statement_digest,
        repetition,
        point,
        terminals,
    )?;
    Ok(C6PersistentCacheProductionFinishedVerifier { repetition, pending, compiler_metrics })
}

#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistentCacheProductionMetrics {
    pub protocol: C6PersistentCacheBlindMetrics,
    pub compiler: [C6PersistentCacheProductionCompilerMetrics; C6_WRAPPER_REPETITIONS],
}

#[cfg(feature = "c6-trace")]
pub(crate) fn assemble_c6_persistent_cache_production_proof(
    statement_digest: C6WrapperDigest,
    repetitions: Vec<C6PersistentCacheProductionFinishedProver>,
) -> Result<(
    C6PersistentCacheBlindProof,
    C6PersistentCacheSourceBootstrapFrame,
    C6PersistentCachePendingClaimsProver,
    C6PersistentCacheProductionMetrics,
)> {
    if statement_digest == [0; 32] || repetitions.len() != C6_WRAPPER_REPETITIONS {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production prover repetition census mismatch",
        ));
    }
    let mut proofs = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut pending = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    let mut fold_corrections =
        [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
    let mut append_corrections =
        [[[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT]; C6_WRAPPER_REPETITIONS];
    let mut compiler =
        [C6PersistentCacheProductionCompilerMetrics::default(); C6_WRAPPER_REPETITIONS];
    for (expected, repetition) in repetitions.into_iter().enumerate() {
        if usize::from(repetition.repetition) != expected
            || repetition.pending.len() != C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production prover repetition order mismatch",
            ));
        }
        fold_corrections[expected] = repetition.fold_corrections;
        append_corrections[expected] = repetition.append_corrections;
        compiler[expected] = repetition.compiler_metrics;
        proofs.push(repetition.proof);
        pending.extend(repetition.pending);
    }
    let proof = C6PersistentCacheBlindProof {
        statement_digest,
        rounds: C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS as u8,
        repetitions: proofs,
    };
    proof.validate_shape()?;
    if proof.encoded_len()? != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production proof byte formula changed",
        ));
    }
    let source_frame = C6PersistentCacheSourceBootstrapFrame::new(
        statement_digest,
        fold_corrections,
        append_corrections,
    )?;
    let protocol = C6PersistentCacheBlindMetrics {
        rounds_per_repetition: C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS as u64,
        proof_bytes: C6_PERSISTENT_CACHE_SOURCE_BOUND_PRODUCTION_BYTES,
        full_correlations_per_tape: C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE,
        pending_claims: pending.len() as u64,
    };
    Ok((
        proof,
        source_frame,
        C6PersistentCachePendingClaimsProver { entries: pending },
        C6PersistentCacheProductionMetrics { protocol, compiler },
    ))
}

#[cfg(feature = "c6-trace")]
pub(crate) fn assemble_c6_persistent_cache_production_verifier_pending(
    repetitions: Vec<C6PersistentCacheProductionFinishedVerifier>,
) -> Result<(
    C6PersistentCachePendingClaimsVerifier,
    [C6PersistentCacheProductionCompilerMetrics; C6_WRAPPER_REPETITIONS],
)> {
    if repetitions.len() != C6_WRAPPER_REPETITIONS {
        return Err(C6PersistentCacheBlindError::new(
            "C6PC2 production verifier repetition census mismatch",
        ));
    }
    let mut pending = Vec::with_capacity(
        C6_WRAPPER_REPETITIONS * C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION,
    );
    let mut compiler =
        [C6PersistentCacheProductionCompilerMetrics::default(); C6_WRAPPER_REPETITIONS];
    for (expected, repetition) in repetitions.into_iter().enumerate() {
        if usize::from(repetition.repetition) != expected
            || repetition.pending.len() != C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION
        {
            return Err(C6PersistentCacheBlindError::new(
                "C6PC2 production verifier repetition order mismatch",
            ));
        }
        compiler[expected] = repetition.compiler_metrics;
        pending.extend(repetition.pending);
    }
    Ok((C6PersistentCachePendingClaimsVerifier { entries: pending }, compiler))
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
            + C6_WRAPPER_REPETITIONS as u64
                * (SOURCE_BOOTSTRAP_FOLD_BYTES + SOURCE_BOOTSTRAP_APPEND_BYTES)
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

    #[cfg(feature = "c6-trace")]
    #[test]
    fn production_transition_layer_enforces_prefix_tail_and_padding_without_d24_table() {
        let equality = vec![Fp2::ONE; C6PC2_LAYER_LEN];
        let mut output: [Vec<Fp2>; C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS] =
            array::from_fn(|_| vec![Fp2::ZERO; C6PC2_LAYER_LEN]);
        let transition_root = Fp2::from_base(Fp::new(3));
        let kv_root = Fp2::from_base(Fp::new(5));
        write_production_transition_layer(
            0,
            2,
            Fp2::from_base(Fp::new(2)),
            &equality,
            transition_root,
            kv_root,
            &mut output,
        )
        .unwrap();
        let transition = Fp2::from_base(Fp::new(6));
        assert_eq!(output[0][0], Fp2::ZERO - transition);
        assert_eq!(output[1][0], Fp2::ZERO - transition * kv_root);
        assert_eq!(output[2][0], transition);
        assert_eq!(output[3][0], transition * kv_root);
        assert_eq!(output[0][2 << 10], Fp2::ZERO);
        assert_eq!(output[1][2 << 10], Fp2::ZERO);
        assert_eq!(output[2][2 << 10], transition);
        assert_eq!(output[0][768], Fp2::ZERO);
        assert_eq!(output[1][768], Fp2::ZERO);
        assert_eq!(output[2][768], transition);

        for table in &mut output {
            table.fill(Fp2::ZERO);
        }
        write_production_transition_layer(
            C6_PERSISTENT_CACHE_LAYERS,
            2,
            Fp2::ONE,
            &equality,
            transition_root,
            kv_root,
            &mut output,
        )
        .unwrap();
        assert_eq!(output[0][0], Fp2::ZERO);
        assert_eq!(output[1][0], Fp2::ZERO);
        assert_eq!(output[2][0], transition_root);
        assert_eq!(output[3][0], transition_root * kv_root);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn production_layer_fold_matches_resident_fold_without_full_domain_state() {
        let source: [Vec<Fp2>; 4] = array::from_fn(|table| {
            (0..8).map(|index| symbol((100 * table + index + 1) as u64)).collect()
        });
        let challenge = symbol(17);
        let mut output: [Vec<Fp2>; 4] = array::from_fn(|_| Vec::new());
        fold_layer_into(&source, challenge, &mut output).unwrap();
        let mut expected = source.clone();
        fold_tables(&mut expected, challenge).unwrap();
        assert_eq!(output, expected);
        assert_eq!(folded_state_bytes(&output, &expected).unwrap(), 512);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn production_append_ordinals_match_canonical_d24_equality_indices() {
        let point = array::from_fn::<_, C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS, _>(|index| {
            symbol(100 + index as u64)
        });
        let equality_within_layer = eq_vec(&point[..C6PC2_LAYER_LOG2]);
        let old_len = 17;
        let new_len = 19;
        let cells_per_layer =
            usize::from(new_len - old_len) * usize::from(C6_PERSISTENT_CACHE_WIDTH);
        let count = production_append_cell_count(old_len, new_len).unwrap();
        assert_eq!(count, cells_per_layer * usize::from(C6_PERSISTENT_CACHE_LAYERS));
        for ordinal in [0, 767, 768, cells_per_layer, count - 1] {
            let (layer, layer_index) =
                production_append_indices(old_len, new_len, ordinal).unwrap();
            let coefficient = equality_within_layer[layer_index]
                * equality_boolean_index(&point[C6PC2_LAYER_LOG2..], layer);
            let global_index = layer * C6PC2_LAYER_LEN + layer_index;
            assert_eq!(coefficient, equality_boolean_index(&point, global_index));
        }
        assert!(production_append_indices(old_len, new_len, count).is_err());
        assert!(production_append_cell_count(new_len, old_len).is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn production_prover_round_state_rejects_challenge_before_message() {
        let mut state = C6PersistentCacheProductionProverRoundState {
            repetition: 0,
            round: 0,
            current: [ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
            first_round: None,
            folded: None,
            point: Vec::new(),
            pending_nodes: None,
        };
        assert!(state.bind_challenge(symbol(17)).is_err());
        assert_eq!(state.round, 0);
        assert!(state.point.is_empty());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn production_pending_and_strict_frames_assemble_at_exact_census() {
        use crate::c6_wrapper_pcs::{
            fix_test_c6_wrapper_commitments, C6WrapperCohortSpec, C6WrapperCommitment,
            C6WrapperOracleKind, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
        };

        let statement = [0xC6; 32];
        let spec = C6WrapperCohortSpec {
            cohort_id: 99,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 2,
            slot_count: 2,
        };
        let commitment = C6WrapperCommitment::from_root(statement, spec, [0x51; 32]).unwrap();
        let mut root_transcript = Transcript::new([0x61; 32]);
        let fixed = fix_test_c6_wrapper_commitments(statement, &[commitment], &mut root_transcript)
            .unwrap();
        let mut finished = Vec::new();
        for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
            let mut transcript = Transcript::new([0x70 + repetition; 32]);
            let mut coordinator = C6WrapperRoundCoordinator::new_test(
                &fixed,
                repetition,
                C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS,
                2,
                3,
            )
            .unwrap();
            while coordinator.round_index() < C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
                let ids = coordinator.expected_participant_ids().unwrap();
                let receipts = ids
                    .iter()
                    .map(|&participant_id| C6WrapperRoundMessageReceipt {
                        participant_id,
                        message_bytes: 1,
                    })
                    .collect::<Vec<_>>();
                coordinator.fix_messages_and_release_challenge(&receipts, &mut transcript).unwrap();
                coordinator.confirm_participants_bound(&ids).unwrap();
            }
            let point = coordinator.finish().unwrap();
            let mut pending = Vec::new();
            append_pending_production_prover(
                &mut pending,
                statement,
                repetition,
                &point,
                [[ProverAuthed::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
                    C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
            )
            .unwrap();
            assert_eq!(pending.len(), C6_PERSISTENT_CACHE_BLIND_PENDING_PER_REPETITION);
            assert!(pending[..16].iter().all(|entry| entry.descriptor.target_point.len() == 25));
            assert!(pending[16..].iter().all(|entry| entry.descriptor.target_point.len() == 16));
            finished.push(C6PersistentCacheProductionFinishedProver {
                repetition,
                proof: C6PersistentCacheBlindRepetitionProof {
                    schedule_digest: [repetition + 1; 32],
                    round_corrections: vec![
                        [[Fp2::ZERO; 2]; C6_PERSISTENT_CACHE_BLIND_TAPES];
                        C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS
                    ],
                    terminal_corrections: [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES];
                        C6_PERSISTENT_CACHE_BLIND_LIVE_TERMINALS],
                    terminal_tags: [Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES],
                },
                fold_corrections: [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
                append_corrections: [[Fp2::ZERO; C6_PERSISTENT_CACHE_BLIND_TAPES]; SOURCE_KV_COUNT],
                pending,
                compiler_metrics: C6PersistentCacheProductionCompilerMetrics::default(),
            });
        }
        let (proof, frame, pending, metrics) =
            assemble_c6_persistent_cache_production_proof(statement, finished).unwrap();
        assert_eq!(
            proof.encode().unwrap().len() as u64,
            C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES
        );
        assert_eq!(
            frame.encode().unwrap().len() as u64,
            C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES
        );
        assert_eq!(pending.len(), 64);
        assert_eq!(metrics.protocol.proof_bytes, C6_PERSISTENT_CACHE_SOURCE_BOUND_PRODUCTION_BYTES);
        assert_eq!(metrics.protocol.full_correlations_per_tape, 104);
    }

    fn fixture() -> (
        C6PersistentCacheRelationPlan,
        C6PersistentCacheBlindWitness,
        C6PersistentCacheSourcesProver,
        C6PersistentCacheSourceMasksProver,
        C6PersistentCacheSourcesVerifier,
    ) {
        let len = 1usize << ROUNDS;
        let fold_functionals = (0..4)
            .map(|ordinal| {
                let kv = ordinal / 2;
                C6PersistentCacheScaledFoldFunctional::new(
                    ordinal,
                    kv,
                    (0..len)
                        .map(|index| symbol(1_000 + ordinal as u64 * 100 + index as u64))
                        .collect(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let plan = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            ROUNDS,
            OLD_LEN,
            APPEND_LEN,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            fold_functionals,
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
        let fold_values = plan
            .successor_fold_functionals
            .iter()
            .map(|functional| dot(&functional.coefficients, &successor[usize::from(functional.kv)]))
            .collect::<Vec<_>>();
        let prover_sources = C6PersistentCacheSourcesProver::new(
            &plan,
            transition_prover,
            fold_values.iter().map(|&value| [ProverAuthed::from_public(value); 2]).collect(),
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
        let fold_masks = (0..plan.successor_fold_functionals.len())
            .map(|ordinal| {
                array::from_fn(|tape| symbol(40_000 + ordinal as u64 * 100 + tape as u64))
            })
            .collect::<Vec<_>>();
        let source_masks = C6PersistentCacheSourceMasksProver::new(
            &plan,
            transition_masks.clone(),
            fold_masks.clone(),
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
            fold_masks
                .iter()
                .map(|masks| array::from_fn(|tape| VerifierKey::new(deltas[tape] * masks[tape])))
                .collect(),
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
            vec![],
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
        assert_eq!(transcript.bytes_for(SOURCE_BOOTSTRAP_HEADER_LABEL), 48);
        assert_eq!(transcript.bytes_for(SOURCE_BOOTSTRAP_FOLD_LABEL), 128);
        assert_eq!(transcript.bytes_for(SOURCE_BOOTSTRAP_APPEND_LABEL), 128);
        assert_eq!(transcript.bytes_for("c6_persistent_cache_source_bootstrap_fixed"), 0);
        assert_eq!(transcript.bytes_for("c6_persistent_cache_source_bootstrap_transition"), 0);
    }

    #[test]
    fn post_rho_fold_batch_and_post_point_append_corrections_are_exact_and_separate() {
        let (plan, witness, sources, masks, _) = fixture();
        let mut streams = array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]));
        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED);
        let (_, frame, _, _) = prove_c6_persistent_cache_blind_reference(
            &plan,
            &witness,
            &sources,
            &masks,
            &mut streams,
            &mut prover_transcript,
        )
        .unwrap();

        let mut oracle = Transcript::new(TRANSCRIPT_SEED);
        for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
            let relation_roots = array::from_fn(|_| oracle.challenge_fp2());
            let kv_root = oracle.challenge_fp2();
            let fold_weights = plan.fold_weights(relation_roots[2]);
            assert_eq!(fold_weights[0], relation_roots[2]);
            assert_eq!(fold_weights[1], relation_roots[2] * relation_roots[2]);
            let fold_values = sources.fold_values(&plan, &fold_weights);
            let fold_masks = masks.fold_values(&plan, &fold_weights);
            for kv in 0..SOURCE_KV_COUNT {
                for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                    assert_eq!(
                        frame.fold_corrections[usize::from(repetition)][kv][tape],
                        fold_values[kv][tape].x - fold_masks[kv][tape]
                    );
                    assert_eq!(
                        frame.correction(usize::from(repetition), 1, kv, tape).unwrap(),
                        Fp2::ZERO
                    );
                }
            }
            oracle.append(SOURCE_BOOTSTRAP_FOLD_LABEL, SOURCE_BOOTSTRAP_FOLD_BYTES);
            let relation_point =
                (0..plan.rounds).map(|_| oracle.challenge_fp2()).collect::<Vec<_>>();
            let compiled = plan
                .compile(repetition, &relation_point, relation_roots, kv_root, &fold_weights)
                .unwrap();
            let append_values = sources.append_values(&plan, &compiled);
            let append_masks = masks.append_values(&plan, &compiled);
            for kv in 0..SOURCE_KV_COUNT {
                for tape in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                    assert_eq!(
                        frame.append_corrections[usize::from(repetition)][kv][tape],
                        append_values[kv][tape].x - append_masks[kv][tape]
                    );
                }
            }
            oracle.append(SOURCE_BOOTSTRAP_APPEND_LABEL, SOURCE_BOOTSTRAP_APPEND_BYTES);
            oracle.append(REPETITION_LABEL, REPETITION_PREFIX_BYTES);
            for _ in 0..plan.rounds {
                oracle.append(ROUND_LABEL, ROUND_BYTES);
                let _ = oracle.challenge_fp2();
            }
            oracle.append(TERMINAL_LABEL, TERMINAL_BYTES);
            let _ = oracle.challenge_fp2();
            for _ in 0..C6_PERSISTENT_CACHE_BLIND_TAPES {
                oracle.append("zero_open_tag", FP2_BYTES);
            }
        }
        assert_ne!(frame.fold_corrections[0], frame.fold_corrections[1]);
    }

    #[test]
    fn stepwise_cache_state_binds_only_challenges_released_by_global_coordinator() {
        use crate::c6_wrapper_pcs::{
            fix_test_c6_wrapper_commitments, C6WrapperCohortSpec, C6WrapperCommitment,
            C6WrapperOracleKind, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
            C6_CACHE_ROUND_PARTICIPANT_ID,
        };

        let (plan, witness, sources, _, _) = fixture();
        let relation_roots = [symbol(501), symbol(502), symbol(503)];
        let kv_root = symbol(504);
        let relation_point =
            (0..ROUNDS).map(|index| symbol(510 + index as u64)).collect::<Vec<_>>();
        let fold_weights = plan.fold_weights(relation_roots[2]);
        let compiled =
            plan.compile(0, &relation_point, relation_roots, kv_root, &fold_weights).unwrap();
        let aggregates = assemble_source_aggregates(
            sources.append_values(&plan, &compiled),
            sources.fold_values(&plan, &fold_weights),
            ProverAuthed::ZERO,
        );
        let current = array::from_fn(|tape| {
            combine_source_aggregates_prover(&aggregates, relation_roots, kv_root, tape)
        });
        let mut state =
            C6PersistentCacheProverRoundState::new(0, current, &compiled, &witness, ROUNDS);
        assert!(state.bind_challenge(symbol(599)).is_err());

        let specs = [
            C6WrapperCohortSpec {
                cohort_id: 11,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 3,
                slot_count: 2,
            },
            C6WrapperCohortSpec {
                cohort_id: 12,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 2,
                slot_count: 2,
            },
            C6WrapperCohortSpec {
                cohort_id: 13,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: 2,
                slot_count: 4,
            },
        ];
        let statement = [0xA5; 32];
        let commitments = specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                C6WrapperCommitment::from_root(statement, spec, [(index + 1) as u8; 32]).unwrap()
            })
            .collect::<Vec<_>>();
        let mut transcript = Transcript::new([0xB6; 32]);
        let fixed =
            fix_test_c6_wrapper_commitments(statement, &commitments, &mut transcript).unwrap();
        let mut coordinator = C6WrapperRoundCoordinator::new_test(&fixed, 0, ROUNDS, 2, 3).unwrap();
        let mut streams = array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]));
        let mut corrections = Vec::with_capacity(ROUNDS);
        while coordinator.round_index() < ROUNDS {
            let round_corrections = state.fix_next_round(&mut streams).unwrap();
            assert!(state.fix_next_round(&mut streams).is_err());
            let ids = coordinator.expected_participant_ids().unwrap();
            assert_eq!(ids[0], C6_CACHE_ROUND_PARTICIPANT_ID);
            let receipts = ids
                .iter()
                .map(|&participant_id| C6WrapperRoundMessageReceipt {
                    participant_id,
                    message_bytes: if participant_id == C6_CACHE_ROUND_PARTICIPANT_ID {
                        ROUND_BYTES
                    } else {
                        1
                    },
                })
                .collect::<Vec<_>>();
            let challenge =
                coordinator.fix_messages_and_release_challenge(&receipts, &mut transcript).unwrap();
            state.bind_challenge(challenge).unwrap();
            coordinator.confirm_participants_bound(&ids).unwrap();
            corrections.push(round_corrections);
        }
        let point = coordinator.finish().unwrap();
        assert_eq!(state.point, point.random_point());
        let mut expected_cache_point = state.point.clone();
        expected_cache_point.push(Fp2::ZERO);
        assert_eq!(expected_cache_point, point.common_point());
        assert_eq!(corrections.len(), ROUNDS);
        assert_eq!(
            transcript.bytes_for("c6_wrapper_global_sumcheck_round"),
            ROUNDS as u64 * ROUND_BYTES + 3
        );
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
        let mut legacy_source_version = source_encoded.clone();
        legacy_source_version[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert!(C6PersistentCacheSourceBootstrapFrame::decode(
            plan.statement_digest(),
            &legacy_source_version,
        )
        .is_err());
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

        let mut bad_append_source = source_frame.clone();
        bad_append_source.append_corrections[0][0][1] += Fp2::ONE;
        let mut bad_fold_source = source_frame.clone();
        bad_fold_source.fold_corrections[1][1][0] += Fp2::ONE;
        for bad_source_frame in [bad_append_source, bad_fold_source] {
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

        let mut wrong_fold_functionals = plan.successor_fold_functionals.clone();
        wrong_fold_functionals[0].coefficients[0] += Fp2::ONE;
        let wrong_owner = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            ROUNDS,
            OLD_LEN,
            APPEND_LEN,
            plan.root_binding_digest,
            plan.workload_digest,
            plan.source_schedule_digest,
            wrong_fold_functionals,
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

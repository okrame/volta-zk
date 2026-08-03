//! C6 packed authenticated-output link.
//!
//! This is the in-memory, scaled/reference byte oracle for the persistent-cache
//! C6LNK2
//! construction.  It deliberately refuses production-fixed roots: production
//! acceptance remains gated on the separately preregistered fused backend.
//! Pending MAC values stay opaque and the old target evaluations never enter
//! the proof.  The prover receives its bound view only after constructing the
//! complete PCS and terminal tags; the verifier's sole Pending-to-Bound
//! transition occurs after both packed chains and all four ZeroOpen checks
//! succeed.

use std::array;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_prover, zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey, RESERVED_DOMAIN_BITS,
};
use volta_proto::mle::{eq_points, eq_vec, fold_low, lagrange3};

use crate::c6_hidden_u::C6HiddenUFamily;
use crate::c6_hidden_u_sumcheck_blind::{
    C6BlindHiddenUPendingClaimsProver, C6BlindHiddenUPendingClaimsVerifier,
};
use crate::c6_persistent_cache_blind::{
    C6PersistentCachePendingClaimsProver, C6PersistentCachePendingClaimsVerifier,
};
use crate::c6_residual_sumcheck::C6ResidualSumcheckFamily;
use crate::c6_residual_sumcheck_blind::{
    C6BlindResidualPendingClaimsProver, C6BlindResidualPendingClaimsVerifier,
    C6BlindResidualPendingDescriptor,
};
use crate::c6_wrapper_pcs::{
    prove_c6_wrapper_pcs_assembled, seal_authenticated_link_c6_wrapper_claims,
    verify_c6_wrapper_pcs_assembled, C6CommittedWrapperCohort, C6FixedWrapperCommitments,
    C6WrapperDigest, C6WrapperOpeningClaim, C6WrapperOracleKind, C6WrapperPcsError,
    C6WrapperPcsProof, C6_DELTA_RESIDUAL_COHORT_ID, C6_HIDDEN_U_EMBED_COHORT_ID,
    C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    C6_WRAPPER_ACTIVE_SLOTS, C6_WRAPPER_AUXILIARY_COHORT_ID, C6_WRAPPER_REPETITIONS,
    C6_WRAPPER_TWO_CHAIN_BYTES,
};
use crate::c6_wrapper_persisted::{
    C6PersistedCoefficientSlotReader, C6PersistedLinkFoldMetrics, C6PersistedLinkFoldOwner,
};
use crate::x4::ntt::evaluate_multilinear_table;

pub const C6_AUTHENTICATED_OUTPUT_LINK_MAGIC: [u8; 8] = *b"C6LNK2\0\0";
pub const C6_AUTHENTICATED_OUTPUT_LINK_VERSION: u16 = 2;
pub const C6_AUTHENTICATED_OUTPUT_LINK_TAPES: usize = 2;
pub const C6_AUTHENTICATED_OUTPUT_LINK_COHORTS: usize = 6;
pub const C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_RELATIONS: usize = 72;
pub const C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_ROUNDS: usize = 25;
pub const C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_CORRELATIONS_PER_TAPE: u64 = 100;
pub const C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_OVERHEAD_BYTES: u64 = 3_570;
pub const C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_BYTES: u64 = 3_883_036;

const LINK_PROOF_CONTEXT: &str = "volta-zk/c6/authenticated-output-link-proof/v2";
const LINK_SCHEDULE_CONTEXT: &str = "volta-zk/c6/authenticated-output-link-schedule/v2";
const LINK_PREFIX_LABEL: &str = "c6_authenticated_output_link_prefix";
const LINK_ROUND_LABEL: &str = "c6_authenticated_output_link_round_corrections";
const LINK_AGGREGATES_LABEL: &str = "c6_authenticated_output_link_aggregates";
const LINK_DIGEST_LABEL: &str = "c6_authenticated_output_link_digest";
const LINK_HEADER_BYTES: u64 = 16;
const LINK_REPETITION_PREFIX_BYTES: u64 = 33;
const LINK_ROUND_BYTES: u64 = 64;
const LINK_AGGREGATE_BYTES: u64 = 96;
const LINK_TERMINAL_TAG_BYTES: u64 = 64;
const LINK_DIGEST_BYTES: u64 = 32;
const LINK_CORRELATION_BASE: u64 = 0x0C64_0000_0000_0000;

type Result<T> = std::result::Result<T, C6AuthenticatedOutputLinkError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6AuthenticatedOutputLinkError(String);

impl C6AuthenticatedOutputLinkError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6AuthenticatedOutputLinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6AuthenticatedOutputLinkError {}

impl From<C6WrapperPcsError> for C6AuthenticatedOutputLinkError {
    fn from(value: C6WrapperPcsError) -> Self {
        Self(format!("C6 wrapper PCS: {value}"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PendingSlotDescriptor {
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    source_statement_digest: C6WrapperDigest,
    repetition: u8,
    cohort_id: u32,
    slot: u16,
    target_point: Vec<Fp2>,
}

impl C6PendingSlotDescriptor {
    pub fn wrapper_statement_digest(&self) -> C6WrapperDigest {
        self.wrapper_statement_digest
    }

    pub fn fixed_roots_digest(&self) -> C6WrapperDigest {
        self.fixed_roots_digest
    }

    pub fn source_statement_digest(&self) -> C6WrapperDigest {
        self.source_statement_digest
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    pub fn slot(&self) -> u16 {
        self.slot
    }

    pub fn target_point(&self) -> &[Fp2] {
        &self.target_point
    }

    fn key(&self) -> SlotKey {
        SlotKey { repetition: self.repetition, cohort_id: self.cohort_id, slot: self.slot }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SlotKey {
    repetition: u8,
    cohort_id: u32,
    slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingProverEntry {
    descriptor: C6PendingSlotDescriptor,
    auth: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingVerifierEntry {
    descriptor: C6PendingSlotDescriptor,
    keys: [VerifierKey; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
}

pub struct C6PendingSlotRegistryProver {
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    entries: Vec<PendingProverEntry>,
}

pub struct C6PendingSlotRegistryVerifier {
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    entries: Vec<PendingVerifierEntry>,
}

impl C6PendingSlotRegistryProver {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6PendingSlotDescriptor> {
        self.entries.get(index).map(|entry| &entry.descriptor)
    }
}

impl fmt::Debug for C6PendingSlotRegistryProver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6PendingSlotRegistryProver")
            .field("wrapper_statement_digest", &self.wrapper_statement_digest)
            .field("fixed_roots_digest", &self.fixed_roots_digest)
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl C6PendingSlotRegistryVerifier {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6PendingSlotDescriptor> {
        self.entries.get(index).map(|entry| &entry.descriptor)
    }
}

impl fmt::Debug for C6PendingSlotRegistryVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6PendingSlotRegistryVerifier")
            .field("wrapper_statement_digest", &self.wrapper_statement_digest)
            .field("fixed_roots_digest", &self.fixed_roots_digest)
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct BoundProverEntry {
    descriptor: C6PendingSlotDescriptor,
    _auth: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
}

#[derive(Debug)]
struct BoundVerifierEntry {
    descriptor: C6PendingSlotDescriptor,
    _keys: [VerifierKey; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
}

/// Opaque slot registry whose origin has passed both packed PCS chains.
pub struct C6BoundSlotRegistryProver {
    entries: Vec<BoundProverEntry>,
}

/// Verifier companion to [`C6BoundSlotRegistryProver`].
pub struct C6BoundSlotRegistryVerifier {
    entries: Vec<BoundVerifierEntry>,
}

impl C6BoundSlotRegistryProver {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6PendingSlotDescriptor> {
        self.entries.get(index).map(|entry| &entry.descriptor)
    }
}

impl fmt::Debug for C6BoundSlotRegistryProver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BoundSlotRegistryProver")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl C6BoundSlotRegistryVerifier {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6PendingSlotDescriptor> {
        self.entries.get(index).map(|entry| &entry.descriptor)
    }
}

impl fmt::Debug for C6BoundSlotRegistryVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BoundSlotRegistryVerifier")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct C6PendingSlotRegistryProverBuilder {
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    dimensions: BTreeMap<SlotKey, usize>,
    entries: BTreeMap<SlotKey, PendingProverEntry>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct C6PendingSlotRegistryVerifierBuilder {
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    dimensions: BTreeMap<SlotKey, usize>,
    entries: BTreeMap<SlotKey, PendingVerifierEntry>,
}

#[allow(dead_code)]
impl C6PendingSlotRegistryProverBuilder {
    pub(crate) fn new(fixed: &C6FixedWrapperCommitments) -> Result<Self> {
        let dimensions = expected_slot_dimensions(fixed)?;
        Ok(Self {
            wrapper_statement_digest: fixed.statement_digest(),
            fixed_roots_digest: fixed.binding_digest(),
            dimensions,
            entries: BTreeMap::new(),
        })
    }

    pub(crate) fn absorb_residual(
        &mut self,
        pending: &C6BlindResidualPendingClaimsProver,
    ) -> Result<()> {
        for (descriptor, auth) in pending.link_entries() {
            let slot_descriptor = self.residual_descriptor(&descriptor)?;
            self.insert_entry(slot_descriptor, auth)?;
        }
        Ok(())
    }

    pub(crate) fn absorb_hidden_u(
        &mut self,
        pending: &C6BlindHiddenUPendingClaimsProver,
    ) -> Result<()> {
        for (descriptor, auth) in pending.link_entries() {
            let cohort_id = hidden_u_cohort_id(descriptor.family());
            let mut target_point = descriptor.point().to_vec();
            target_point.push(Fp2::ZERO);
            self.insert_source(
                descriptor.repetition(),
                cohort_id,
                descriptor.slot(),
                descriptor.statement_digest(),
                target_point,
                auth,
            )?;
        }
        Ok(())
    }

    pub(crate) fn absorb_persistent_cache(
        &mut self,
        pending: &C6PersistentCachePendingClaimsProver,
    ) -> Result<()> {
        for (descriptor, auth) in pending.link_entries() {
            validate_cache_pending_owner(
                descriptor.cohort_id(),
                descriptor.slot(),
                descriptor.target_point(),
            )?;
            self.insert_source(
                descriptor.repetition(),
                descriptor.cohort_id(),
                descriptor.slot(),
                descriptor.statement_digest(),
                descriptor.target_point().to_vec(),
                auth,
            )?;
        }
        Ok(())
    }

    pub(crate) fn insert_source(
        &mut self,
        repetition: u8,
        cohort_id: u32,
        slot: u16,
        source_statement_digest: C6WrapperDigest,
        target_point: Vec<Fp2>,
        auth: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) -> Result<()> {
        let descriptor = self.source_descriptor(
            repetition,
            cohort_id,
            slot,
            source_statement_digest,
            target_point,
        );
        self.insert_entry(descriptor, auth)
    }

    fn insert_entry(
        &mut self,
        descriptor: C6PendingSlotDescriptor,
        auth: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) -> Result<()> {
        validate_pending_descriptor(
            self.wrapper_statement_digest,
            self.fixed_roots_digest,
            &self.dimensions,
            &descriptor,
        )?;
        if auth[0].x != auth[1].x {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link pending plaintext differs across tapes",
            ));
        }
        let key = descriptor.key();
        if self.entries.insert(key, PendingProverEntry { descriptor, auth }).is_some() {
            return Err(C6AuthenticatedOutputLinkError::new(
                "duplicate C6 link pending prover slot",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<C6PendingSlotRegistryProver> {
        if self.entries.len() != self.dimensions.len()
            || self.entries.keys().ne(self.dimensions.keys())
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "incomplete C6 link pending prover registry",
            ));
        }
        Ok(C6PendingSlotRegistryProver {
            wrapper_statement_digest: self.wrapper_statement_digest,
            fixed_roots_digest: self.fixed_roots_digest,
            entries: self.entries.into_values().collect(),
        })
    }

    fn residual_descriptor(
        &self,
        residual: &C6BlindResidualPendingDescriptor,
    ) -> Result<C6PendingSlotDescriptor> {
        let mut target_point = residual.point().to_vec();
        target_point.push(Fp2::ZERO);
        let table = residual.table();
        let correct_owner = match residual.family() {
            C6ResidualSumcheckFamily::LeafRaw => table.cohort_id == C6_DELTA_RESIDUAL_COHORT_ID,
            C6ResidualSumcheckFamily::Auxiliary => {
                table.cohort_id == C6_WRAPPER_AUXILIARY_COHORT_ID
            }
        };
        if !correct_owner {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 residual pending owner does not match its family",
            ));
        }
        Ok(self.source_descriptor(
            residual.repetition(),
            table.cohort_id,
            table.slot,
            residual.statement_digest(),
            target_point,
        ))
    }

    fn source_descriptor(
        &self,
        repetition: u8,
        cohort_id: u32,
        slot: u16,
        source_statement_digest: C6WrapperDigest,
        target_point: Vec<Fp2>,
    ) -> C6PendingSlotDescriptor {
        C6PendingSlotDescriptor {
            wrapper_statement_digest: self.wrapper_statement_digest,
            fixed_roots_digest: self.fixed_roots_digest,
            source_statement_digest,
            repetition,
            cohort_id,
            slot,
            target_point,
        }
    }
}

#[allow(dead_code)]
impl C6PendingSlotRegistryVerifierBuilder {
    pub(crate) fn new(fixed: &C6FixedWrapperCommitments) -> Result<Self> {
        let dimensions = expected_slot_dimensions(fixed)?;
        Ok(Self {
            wrapper_statement_digest: fixed.statement_digest(),
            fixed_roots_digest: fixed.binding_digest(),
            dimensions,
            entries: BTreeMap::new(),
        })
    }

    pub(crate) fn absorb_residual(
        &mut self,
        pending: &C6BlindResidualPendingClaimsVerifier,
    ) -> Result<()> {
        for (descriptor, keys) in pending.link_entries() {
            let mut target_point = descriptor.point().to_vec();
            target_point.push(Fp2::ZERO);
            let table = descriptor.table();
            let correct_owner = match descriptor.family() {
                C6ResidualSumcheckFamily::LeafRaw => table.cohort_id == C6_DELTA_RESIDUAL_COHORT_ID,
                C6ResidualSumcheckFamily::Auxiliary => {
                    table.cohort_id == C6_WRAPPER_AUXILIARY_COHORT_ID
                }
            };
            if !correct_owner {
                return Err(C6AuthenticatedOutputLinkError::new(
                    "C6 residual verifier owner does not match its family",
                ));
            }
            self.insert_source(
                descriptor.repetition(),
                table.cohort_id,
                table.slot,
                descriptor.statement_digest(),
                target_point,
                keys,
            )?;
        }
        Ok(())
    }

    pub(crate) fn absorb_hidden_u(
        &mut self,
        pending: &C6BlindHiddenUPendingClaimsVerifier,
    ) -> Result<()> {
        for (descriptor, keys) in pending.link_entries() {
            let cohort_id = hidden_u_cohort_id(descriptor.family());
            let mut target_point = descriptor.point().to_vec();
            target_point.push(Fp2::ZERO);
            self.insert_source(
                descriptor.repetition(),
                cohort_id,
                descriptor.slot(),
                descriptor.statement_digest(),
                target_point,
                keys,
            )?;
        }
        Ok(())
    }

    pub(crate) fn absorb_persistent_cache(
        &mut self,
        pending: &C6PersistentCachePendingClaimsVerifier,
    ) -> Result<()> {
        for (descriptor, keys) in pending.link_entries() {
            validate_cache_pending_owner(
                descriptor.cohort_id(),
                descriptor.slot(),
                descriptor.target_point(),
            )?;
            self.insert_source(
                descriptor.repetition(),
                descriptor.cohort_id(),
                descriptor.slot(),
                descriptor.statement_digest(),
                descriptor.target_point().to_vec(),
                keys,
            )?;
        }
        Ok(())
    }

    pub(crate) fn insert_source(
        &mut self,
        repetition: u8,
        cohort_id: u32,
        slot: u16,
        source_statement_digest: C6WrapperDigest,
        target_point: Vec<Fp2>,
        keys: [VerifierKey; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) -> Result<()> {
        let descriptor = C6PendingSlotDescriptor {
            wrapper_statement_digest: self.wrapper_statement_digest,
            fixed_roots_digest: self.fixed_roots_digest,
            source_statement_digest,
            repetition,
            cohort_id,
            slot,
            target_point,
        };
        validate_pending_descriptor(
            self.wrapper_statement_digest,
            self.fixed_roots_digest,
            &self.dimensions,
            &descriptor,
        )?;
        let key = descriptor.key();
        if self.entries.insert(key, PendingVerifierEntry { descriptor, keys }).is_some() {
            return Err(C6AuthenticatedOutputLinkError::new(
                "duplicate C6 link pending verifier slot",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<C6PendingSlotRegistryVerifier> {
        if self.entries.len() != self.dimensions.len()
            || self.entries.keys().ne(self.dimensions.keys())
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "incomplete C6 link pending verifier registry",
            ));
        }
        Ok(C6PendingSlotRegistryVerifier {
            wrapper_statement_digest: self.wrapper_statement_digest,
            fixed_roots_digest: self.fixed_roots_digest,
            entries: self.entries.into_values().collect(),
        })
    }
}

fn hidden_u_cohort_id(family: C6HiddenUFamily) -> u32 {
    match family {
        C6HiddenUFamily::Weights => C6_HIDDEN_U_WEIGHTS_COHORT_ID,
        C6HiddenUFamily::Embed => C6_HIDDEN_U_EMBED_COHORT_ID,
    }
}

fn validate_cache_pending_owner(cohort_id: u32, slot: u16, point: &[Fp2]) -> Result<()> {
    let owner_matches = match cohort_id {
        C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID => slot < 8,
        C6_WRAPPER_AUXILIARY_COHORT_ID => (16..32).contains(&slot),
        _ => false,
    };
    if !owner_matches || point.is_empty() || point.last() != Some(&Fp2::ZERO) {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 persistent-cache pending owner mismatch",
        ));
    }
    Ok(())
}

fn expected_slot_dimensions(fixed: &C6FixedWrapperCommitments) -> Result<BTreeMap<SlotKey, usize>> {
    let (relations, _, cohorts) = link_geometry(fixed)?;
    if relations != C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_RELATIONS
        || cohorts != C6_AUTHENTICATED_OUTPUT_LINK_COHORTS
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link requires the exact six-cohort 72-slot census",
        ));
    }
    let mut dimensions = BTreeMap::new();
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        for commitment in fixed.commitments() {
            let dimension = usize::from(commitment.spec.coefficient_log2()?);
            for slot in 0..commitment.spec.slot_count {
                dimensions.insert(
                    SlotKey {
                        repetition: repetition as u8,
                        cohort_id: commitment.spec.cohort_id,
                        slot,
                    },
                    dimension,
                );
            }
        }
    }
    Ok(dimensions)
}

fn validate_pending_descriptor(
    wrapper_statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    dimensions: &BTreeMap<SlotKey, usize>,
    descriptor: &C6PendingSlotDescriptor,
) -> Result<()> {
    let expected_dimension = dimensions
        .get(&descriptor.key())
        .ok_or_else(|| C6AuthenticatedOutputLinkError::new("unknown C6 link pending slot"))?;
    if descriptor.wrapper_statement_digest != wrapper_statement_digest
        || descriptor.fixed_roots_digest != fixed_roots_digest
        || descriptor.source_statement_digest == [0; 32]
        || descriptor.target_point.len() != *expected_dimension
        || descriptor.target_point.last() != Some(&Fp2::ZERO)
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link pending descriptor binding mismatch",
        ));
    }
    Ok(())
}

/// Boolean-hypercube table for one committed slot.  Witness tables include
/// their independent upper ZK half.
#[derive(Clone, Copy, Debug)]
pub struct C6LinkSlotPolynomial<'a> {
    pub repetition: u8,
    pub cohort_id: u32,
    pub slot: u16,
    pub evaluations: &'a [Fp2],
}

#[derive(Clone)]
struct DelayedTerm {
    coefficient: Fp2,
    evaluations: Vec<Fp2>,
    equality: Vec<Fp2>,
    leading_virtual_rounds: usize,
    virtual_factor: Fp2,
}

impl DelayedTerm {
    fn new(
        coefficient: Fp2,
        evaluations: &[Fp2],
        target_point: &[Fp2],
        global_rounds: usize,
    ) -> Result<Self> {
        if target_point.is_empty()
            || target_point.len() > global_rounds
            || evaluations.len()
                != 1usize.checked_shl(target_point.len() as u32).unwrap_or_default()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link polynomial table geometry mismatch",
            ));
        }
        Ok(Self {
            coefficient,
            evaluations: evaluations.to_vec(),
            equality: eq_vec(target_point),
            leading_virtual_rounds: global_rounds - target_point.len(),
            virtual_factor: Fp2::ONE,
        })
    }

    fn active_sum(&self) -> Fp2 {
        self.evaluations.iter().zip(&self.equality).fold(Fp2::ZERO, |sum, (value, eq)| {
            sum + self.coefficient * *value * *eq * self.virtual_factor
        })
    }

    fn round_values(&self) -> Result<(Fp2, Fp2)> {
        if self.evaluations.len() != self.equality.len() || self.evaluations.is_empty() {
            return Err(C6AuthenticatedOutputLinkError::new("invalid C6 link delayed-term state"));
        }
        if self.leading_virtual_rounds > 0 {
            let at_zero = self.active_sum();
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        if self.evaluations.len() == 1 {
            let at_zero =
                self.coefficient * self.evaluations[0] * self.equality[0] * self.virtual_factor;
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        let mut at_zero = Fp2::ZERO;
        let mut at_two = Fp2::ZERO;
        for (values, equality) in
            self.evaluations.chunks_exact(2).zip(self.equality.chunks_exact(2))
        {
            let value_two = values[0] + (values[1] - values[0]) * Fp2::from_base(Fp::new(2));
            let equality_two =
                equality[0] + (equality[1] - equality[0]) * Fp2::from_base(Fp::new(2));
            at_zero += self.coefficient * values[0] * equality[0] * self.virtual_factor;
            at_two += self.coefficient * value_two * equality_two * self.virtual_factor;
        }
        Ok((at_zero, at_two))
    }

    fn bind(&mut self, challenge: Fp2) {
        if self.leading_virtual_rounds > 0 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
            self.leading_virtual_rounds -= 1;
        } else if self.evaluations.len() == 1 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
        } else {
            fold_low(&mut self.evaluations, challenge);
            fold_low(&mut self.equality, challenge);
        }
    }

    fn terminal(&self) -> Result<Fp2> {
        if self.leading_virtual_rounds != 0
            || self.evaluations.len() != 1
            || self.equality.len() != 1
        {
            return Err(C6AuthenticatedOutputLinkError::new("invalid C6 link terminal term state"));
        }
        Ok(self.coefficient * self.evaluations[0] * self.equality[0] * self.virtual_factor)
    }
}

/// Coefficient-domain form used by the persisted production link.  It never
/// reconstructs the Boolean evaluation table or an equality vector.  The
/// resident `Vec` here is the scaled differential state; production replaces
/// it with the create-new folded coefficient owner.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct C6CoefficientDelayedTerm {
    coefficient: Fp2,
    coefficients: Vec<Fp2>,
    target_point: Vec<Fp2>,
    leading_virtual_rounds: usize,
    virtual_factor: Fp2,
}

#[allow(dead_code)]
impl C6CoefficientDelayedTerm {
    pub(crate) fn new(
        coefficient: Fp2,
        coefficients: Vec<Fp2>,
        target_point: &[Fp2],
        global_rounds: usize,
    ) -> Result<Self> {
        if target_point.is_empty()
            || target_point.len() > global_rounds
            || coefficients.len()
                != 1usize.checked_shl(target_point.len() as u32).unwrap_or_default()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 coefficient link term geometry mismatch",
            ));
        }
        Ok(Self {
            coefficient,
            coefficients,
            target_point: target_point.to_vec(),
            leading_virtual_rounds: global_rounds - target_point.len(),
            virtual_factor: Fp2::ONE,
        })
    }

    pub(crate) fn round_values(&self) -> Result<(Fp2, Fp2)> {
        if self.coefficients.is_empty()
            || self.coefficients.len()
                != 1usize.checked_shl(self.target_point.len() as u32).unwrap_or_default()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "invalid C6 coefficient link term state",
            ));
        }
        if self.leading_virtual_rounds > 0 {
            let value = evaluate_coefficients_streaming(&self.coefficients, &self.target_point)?;
            let at_zero = self.coefficient * value * self.virtual_factor;
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        if self.coefficients.len() == 1 {
            let at_zero = self.coefficient * self.coefficients[0] * self.virtual_factor;
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        let target = self.target_point[0];
        let (value_zero, value_two) =
            evaluate_coefficient_round_endpoints(&self.coefficients, &self.target_point[1..])?;
        let equality_zero = Fp2::ONE - target;
        let equality_two = target + target - equality_zero;
        Ok((
            self.coefficient * value_zero * equality_zero * self.virtual_factor,
            self.coefficient * value_two * equality_two * self.virtual_factor,
        ))
    }

    pub(crate) fn bind(&mut self, challenge: Fp2) {
        if self.leading_virtual_rounds > 0 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
            self.leading_virtual_rounds -= 1;
            return;
        }
        if self.coefficients.len() == 1 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
            return;
        }
        self.virtual_factor =
            self.virtual_factor * eq_points(&[challenge], &[self.target_point[0]]);
        let half = self.coefficients.len() / 2;
        for index in 0..half {
            self.coefficients[index] =
                self.coefficients[2 * index] + challenge * self.coefficients[2 * index + 1];
        }
        self.coefficients.truncate(half);
        self.target_point.remove(0);
    }

    pub(crate) fn terminal(&self) -> Result<Fp2> {
        if self.leading_virtual_rounds != 0
            || self.coefficients.len() != 1
            || self.target_point.len() != 0
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "invalid C6 coefficient link terminal state",
            ));
        }
        Ok(self.coefficient * self.coefficients[0] * self.virtual_factor)
    }
}

#[allow(dead_code)]
const C6_LINK_EVALUATION_CHUNK_SYMBOLS: usize = 16 * 1024;
#[allow(dead_code)]
const C6_LINK_LOW_WEIGHT_BITS: usize = 12;
#[allow(dead_code)]
const C6_LINK_TERM_BINDING_DOMAIN: &str = "volta-zk/c6/link-persisted-term/v1";

#[allow(dead_code)]
struct C6PersistedCoefficientDelayedTerm {
    coefficient: Fp2,
    owner: Option<C6PersistedLinkFoldOwner>,
    target_point: Vec<Fp2>,
    leading_virtual_rounds: usize,
    virtual_factor: Fp2,
    global_round: u16,
    target_value: Option<Fp2>,
}

#[allow(dead_code)]
impl C6PersistedCoefficientDelayedTerm {
    #[allow(clippy::too_many_arguments)]
    fn new(
        coefficient: Fp2,
        descriptor: &C6PendingSlotDescriptor,
        source: &C6PersistedCoefficientSlotReader,
        spill_root: &Path,
        global_rounds: usize,
        metrics: &mut C6PersistedLinkFoldMetrics,
    ) -> Result<Self> {
        if descriptor.target_point.is_empty()
            || descriptor.target_point.len() > global_rounds
            || source.coefficient_len()
                != 1usize.checked_shl(descriptor.target_point.len() as u32).unwrap_or_default()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 persisted coefficient link term geometry mismatch",
            ));
        }
        let (statement_digest, _, root) = source.binding();
        if descriptor.wrapper_statement_digest != statement_digest {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 persisted coefficient link statement mismatch",
            ));
        }
        let target_digest = persisted_link_term_digest(descriptor, coefficient);
        let (owner, initial_metrics) = source.open_link_fold_owner(
            spill_root,
            descriptor.repetition,
            descriptor.cohort_id,
            descriptor.slot,
            target_digest,
        )?;
        if owner.binding().root != root {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 persisted coefficient link root mismatch",
            ));
        }
        metrics.absorb_nonlive(initial_metrics)?;
        Ok(Self {
            coefficient,
            owner: Some(owner),
            target_point: descriptor.target_point.clone(),
            leading_virtual_rounds: global_rounds - descriptor.target_point.len(),
            virtual_factor: Fp2::ONE,
            global_round: 0,
            target_value: None,
        })
    }

    fn initial_value(&mut self, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<Fp2> {
        if self.target_value.is_none() {
            self.target_value =
                Some(evaluate_persisted_coefficients(self.owner()?, &self.target_point, metrics)?);
        }
        Ok(self.coefficient * self.target_value.unwrap())
    }

    fn round_values(&self, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<(Fp2, Fp2)> {
        let owner = self.owner()?;
        if owner.binding().round != self.global_round
            || owner.coefficient_len()
                != 1usize.checked_shl(self.target_point.len() as u32).unwrap_or_default()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "invalid C6 persisted coefficient link term state",
            ));
        }
        if self.leading_virtual_rounds > 0 {
            let value = self.target_value.ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new(
                    "C6 persisted link virtual value was not initialized",
                )
            })?;
            let at_zero = self.coefficient * value * self.virtual_factor;
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        if owner.coefficient_len() < 2 || self.target_point.is_empty() {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 persisted link has no active round",
            ));
        }
        let target = self.target_point[0];
        let (value_zero, value_two) =
            evaluate_persisted_round_endpoints(owner, &self.target_point[1..], metrics)?;
        let equality_zero = Fp2::ONE - target;
        let equality_two = target + target - equality_zero;
        Ok((
            self.coefficient * value_zero * equality_zero * self.virtual_factor,
            self.coefficient * value_two * equality_two * self.virtual_factor,
        ))
    }

    fn bind(&mut self, challenge: Fp2, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<()> {
        let next_round = self.global_round.checked_add(1).ok_or_else(|| {
            C6AuthenticatedOutputLinkError::new("C6 persisted link round overflow")
        })?;
        let owner = self.owner.take().ok_or_else(|| {
            C6AuthenticatedOutputLinkError::new("C6 persisted link owner already consumed")
        })?;
        let successor = if self.leading_virtual_rounds > 0 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
            self.leading_virtual_rounds -= 1;
            owner.advance_virtual_create_new(challenge, next_round, metrics)?
        } else {
            let target = *self.target_point.first().ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("C6 persisted link target exhausted")
            })?;
            self.virtual_factor = self.virtual_factor * eq_points(&[challenge], &[target]);
            self.target_point.remove(0);
            owner.bind_create_new(challenge, next_round, metrics)?
        };
        self.owner = Some(successor);
        self.global_round = next_round;
        Ok(())
    }

    fn terminal(&self, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<Fp2> {
        let owner = self.owner()?;
        if self.leading_virtual_rounds != 0
            || !self.target_point.is_empty()
            || owner.coefficient_len() != 1
            || owner.binding().round != self.global_round
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "invalid C6 persisted coefficient link terminal state",
            ));
        }
        let (coefficient, bytes_read) = owner.read_range(0, 1)?;
        metrics.coefficient_bytes_read =
            metrics.coefficient_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("C6 persisted link read metric overflow")
            })?;
        Ok(self.coefficient * coefficient[0] * self.virtual_factor)
    }

    fn release(mut self, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<()> {
        self.owner
            .take()
            .ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("C6 persisted link owner already released")
            })?
            .release(metrics)?;
        Ok(())
    }

    fn owner(&self) -> Result<&C6PersistedLinkFoldOwner> {
        self.owner
            .as_ref()
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 persisted link owner missing"))
    }
}

#[allow(dead_code)]
fn persisted_link_term_digest(
    descriptor: &C6PendingSlotDescriptor,
    coefficient: Fp2,
) -> C6WrapperDigest {
    let mut hasher = blake3::Hasher::new_derive_key(C6_LINK_TERM_BINDING_DOMAIN);
    hasher.update(&descriptor.wrapper_statement_digest);
    hasher.update(&descriptor.fixed_roots_digest);
    hasher.update(&descriptor.source_statement_digest);
    hasher.update(&[descriptor.repetition]);
    hasher.update(&descriptor.cohort_id.to_le_bytes());
    hasher.update(&descriptor.slot.to_le_bytes());
    hasher.update(&[descriptor.target_point.len() as u8]);
    for coordinate in &descriptor.target_point {
        hash_fp2(&mut hasher, *coordinate);
    }
    hash_fp2(&mut hasher, coefficient);
    *hasher.finalize().as_bytes()
}

#[allow(dead_code)]
fn evaluate_persisted_coefficients(
    owner: &C6PersistedLinkFoldOwner,
    point: &[Fp2],
    metrics: &mut C6PersistedLinkFoldMetrics,
) -> Result<Fp2> {
    if owner.coefficient_len() != 1usize.checked_shl(point.len() as u32).unwrap_or_default() {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 persisted coefficient evaluation geometry mismatch",
        ));
    }
    let low_weights = low_monomial_weights(point);
    let low_bits = C6_LINK_LOW_WEIGHT_BITS.min(point.len());
    let low_mask = low_weights.len() - 1;
    let mut sum = Fp2::ZERO;
    let mut start = 0usize;
    while start < owner.coefficient_len() {
        let count = (owner.coefficient_len() - start).min(C6_LINK_EVALUATION_CHUNK_SYMBOLS);
        let (coefficients, bytes_read) = owner.read_range(start, count)?;
        metrics.coefficient_bytes_read =
            metrics.coefficient_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("C6 persisted link read metric overflow")
            })?;
        let mut high_index = usize::MAX;
        let mut high_weight = Fp2::ZERO;
        for (offset, coefficient) in coefficients.into_iter().enumerate() {
            let index = start + offset;
            let next_high_index = index >> low_bits;
            if next_high_index != high_index {
                high_index = next_high_index;
                high_weight = coefficient_monomial_weight(high_index, &point[low_bits..]);
            }
            sum += coefficient * low_weights[index & low_mask] * high_weight;
        }
        start += count;
    }
    Ok(sum)
}

#[allow(dead_code)]
fn evaluate_persisted_round_endpoints(
    owner: &C6PersistedLinkFoldOwner,
    suffix_point: &[Fp2],
    metrics: &mut C6PersistedLinkFoldMetrics,
) -> Result<(Fp2, Fp2)> {
    if owner.coefficient_len() != 2usize.checked_shl(suffix_point.len() as u32).unwrap_or_default()
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 persisted coefficient endpoint geometry mismatch",
        ));
    }
    let low_weights = low_monomial_weights(suffix_point);
    let low_bits = C6_LINK_LOW_WEIGHT_BITS.min(suffix_point.len());
    let low_mask = low_weights.len() - 1;
    let two = Fp2::from_base(Fp::new(2));
    let mut zero = Fp2::ZERO;
    let mut endpoint_two = Fp2::ZERO;
    let mut start = 0usize;
    while start < owner.coefficient_len() {
        let mut count = (owner.coefficient_len() - start).min(C6_LINK_EVALUATION_CHUNK_SYMBOLS);
        count -= count % 2;
        let (coefficients, bytes_read) = owner.read_range(start, count)?;
        metrics.coefficient_bytes_read =
            metrics.coefficient_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("C6 persisted link read metric overflow")
            })?;
        let pair_start = start / 2;
        let mut high_index = usize::MAX;
        let mut high_weight = Fp2::ZERO;
        for (offset, pair) in coefficients.chunks_exact(2).enumerate() {
            let index = pair_start + offset;
            let next_high_index = index >> low_bits;
            if next_high_index != high_index {
                high_index = next_high_index;
                high_weight = coefficient_monomial_weight(high_index, &suffix_point[low_bits..]);
            }
            let weight = low_weights[index & low_mask] * high_weight;
            zero += pair[0] * weight;
            endpoint_two += (pair[0] + two * pair[1]) * weight;
        }
        start += count;
    }
    Ok((zero, endpoint_two))
}

#[allow(dead_code)]
fn low_monomial_weights(point: &[Fp2]) -> Vec<Fp2> {
    let low_bits = C6_LINK_LOW_WEIGHT_BITS.min(point.len());
    let mut weights = Vec::with_capacity(1usize << low_bits);
    weights.push(Fp2::ONE);
    for coordinate in point.iter().take(low_bits) {
        let prior = weights.len();
        for index in 0..prior {
            weights.push(weights[index] * *coordinate);
        }
    }
    weights
}

fn evaluate_coefficient_round_endpoints(
    coefficients: &[Fp2],
    suffix_point: &[Fp2],
) -> Result<(Fp2, Fp2)> {
    if coefficients.len() != 2usize.checked_shl(suffix_point.len() as u32).unwrap_or_default() {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 coefficient endpoint geometry mismatch",
        ));
    }
    let mut zero = Fp2::ZERO;
    let mut two = Fp2::ZERO;
    for (index, pair) in coefficients.chunks_exact(2).enumerate() {
        let weight = coefficient_monomial_weight(index, suffix_point);
        zero += pair[0] * weight;
        two += (pair[0] + Fp2::from_base(Fp::new(2)) * pair[1]) * weight;
    }
    Ok((zero, two))
}

fn evaluate_coefficients_streaming(coefficients: &[Fp2], point: &[Fp2]) -> Result<Fp2> {
    if coefficients.len() != 1usize.checked_shl(point.len() as u32).unwrap_or_default() {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 streaming coefficient evaluation geometry mismatch",
        ));
    }
    Ok(coefficients.iter().enumerate().fold(Fp2::ZERO, |sum, (index, value)| {
        sum + *value * coefficient_monomial_weight(index, point)
    }))
}

fn coefficient_monomial_weight(index: usize, point: &[Fp2]) -> Fp2 {
    point.iter().enumerate().fold(Fp2::ONE, |weight, (bit, coordinate)| {
        if index & (1usize << bit) == 0 {
            weight
        } else {
            weight * *coordinate
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6LinkRepetitionProof {
    repetition: u8,
    schedule_digest: C6WrapperDigest,
    /// Round-major, tape-major, endpoint `(0,2)`.
    corrections: Vec<[[Fp2; 2]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]>,
    aggregates: [Fp2; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6AuthenticatedOutputLinkProof {
    repetitions: Vec<C6LinkRepetitionProof>,
    wrapper_pcs: C6WrapperPcsProof,
    terminal_tags: [[Fp2; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]; C6_WRAPPER_REPETITIONS],
}

impl C6AuthenticatedOutputLinkProof {
    pub fn wrapper_pcs(&self) -> &C6WrapperPcsProof {
        &self.wrapper_pcs
    }

    pub fn encoded_len(&self, fixed: &C6FixedWrapperCommitments) -> Result<u64> {
        u64::try_from(self.canonical_bytes(fixed)?.len())
            .map_err(|_| C6AuthenticatedOutputLinkError::new("C6 link proof length exceeds u64"))
    }

    pub fn canonical_bytes(&self, fixed: &C6FixedWrapperCommitments) -> Result<Vec<u8>> {
        let (relations, rounds, cohorts) = link_geometry(fixed)?;
        validate_proof_shape(self, relations, rounds, cohorts)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&C6_AUTHENTICATED_OUTPUT_LINK_MAGIC);
        bytes.extend_from_slice(&C6_AUTHENTICATED_OUTPUT_LINK_VERSION.to_le_bytes());
        bytes.push(C6_WRAPPER_REPETITIONS as u8);
        bytes.push(C6_AUTHENTICATED_OUTPUT_LINK_TAPES as u8);
        bytes.extend_from_slice(
            &u16::try_from(relations)
                .map_err(|_| C6AuthenticatedOutputLinkError::new("C6 link relation overflow"))?
                .to_le_bytes(),
        );
        bytes.push(
            u8::try_from(rounds)
                .map_err(|_| C6AuthenticatedOutputLinkError::new("C6 link round overflow"))?,
        );
        bytes.push(
            u8::try_from(cohorts)
                .map_err(|_| C6AuthenticatedOutputLinkError::new("C6 link cohort overflow"))?,
        );
        for repetition in &self.repetitions {
            bytes.push(repetition.repetition);
            bytes.extend_from_slice(&repetition.schedule_digest);
            for round in &repetition.corrections {
                for tape in round {
                    encode_fp2(&mut bytes, tape[0]);
                    encode_fp2(&mut bytes, tape[1]);
                }
            }
            for aggregate in repetition.aggregates {
                encode_fp2(&mut bytes, aggregate);
            }
        }
        bytes.extend_from_slice(&self.wrapper_pcs.canonical_bytes()?);
        for repetition in self.terminal_tags {
            for tag in repetition {
                encode_fp2(&mut bytes, tag);
            }
        }
        let digest = proof_digest(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub fn decode(fixed: &C6FixedWrapperCommitments, bytes: &[u8]) -> Result<Self> {
        let (relations, rounds, cohorts) = link_geometry(fixed)?;
        let minimum = usize::try_from(
            LINK_HEADER_BYTES
                + C6_WRAPPER_REPETITIONS as u64
                    * (LINK_REPETITION_PREFIX_BYTES
                        + rounds as u64 * LINK_ROUND_BYTES
                        + LINK_AGGREGATE_BYTES)
                + LINK_TERMINAL_TAG_BYTES
                + LINK_DIGEST_BYTES,
        )
        .map_err(|_| C6AuthenticatedOutputLinkError::new("C6 link minimum length overflow"))?;
        if bytes.len() <= minimum {
            return Err(C6AuthenticatedOutputLinkError::new("truncated C6 link proof"));
        }
        let digest_offset = bytes.len() - LINK_DIGEST_BYTES as usize;
        let expected_digest = proof_digest(&bytes[..digest_offset]);
        if bytes[digest_offset..] != expected_digest {
            return Err(C6AuthenticatedOutputLinkError::new("C6 link proof digest mismatch"));
        }
        let mut cursor = Cursor::new(&bytes[..digest_offset]);
        if cursor.take(8)? != C6_AUTHENTICATED_OUTPUT_LINK_MAGIC {
            return Err(C6AuthenticatedOutputLinkError::new("wrong C6 link magic"));
        }
        if cursor.u16()? != C6_AUTHENTICATED_OUTPUT_LINK_VERSION
            || cursor.u8()? != C6_WRAPPER_REPETITIONS as u8
            || cursor.u8()? != C6_AUTHENTICATED_OUTPUT_LINK_TAPES as u8
            || usize::from(cursor.u16()?) != relations
            || usize::from(cursor.u8()?) != rounds
            || usize::from(cursor.u8()?) != cohorts
        {
            return Err(C6AuthenticatedOutputLinkError::new("C6 link header geometry mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            let encoded_repetition = cursor.u8()?;
            if usize::from(encoded_repetition) != repetition {
                return Err(C6AuthenticatedOutputLinkError::new(
                    "C6 link repetition order mismatch",
                ));
            }
            let mut schedule_digest = [0u8; 32];
            schedule_digest.copy_from_slice(cursor.take(32)?);
            let mut corrections = Vec::with_capacity(rounds);
            for _ in 0..rounds {
                let mut round = [[Fp2::ZERO; 2]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
                for tape in &mut round {
                    tape[0] = cursor.fp2()?;
                    tape[1] = cursor.fp2()?;
                }
                corrections.push(round);
            }
            let mut aggregates = [Fp2::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS];
            for aggregate in &mut aggregates {
                *aggregate = cursor.fp2()?;
            }
            repetitions.push(C6LinkRepetitionProof {
                repetition: encoded_repetition,
                schedule_digest,
                corrections,
                aggregates,
            });
        }
        let pcs_end = cursor
            .bytes
            .len()
            .checked_sub(LINK_TERMINAL_TAG_BYTES as usize)
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("truncated C6 link tags"))?;
        if cursor.position() >= pcs_end {
            return Err(C6AuthenticatedOutputLinkError::new("empty C6 link PCS section"));
        }
        let wrapper_pcs = C6WrapperPcsProof::decode(
            fixed.commitments(),
            &cursor.bytes[cursor.position()..pcs_end],
        )?;
        cursor.offset = pcs_end;
        let mut terminal_tags =
            [[Fp2::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]; C6_WRAPPER_REPETITIONS];
        for repetition in &mut terminal_tags {
            for tag in repetition {
                *tag = cursor.fp2()?;
            }
        }
        if !cursor.is_eof() {
            return Err(C6AuthenticatedOutputLinkError::new("trailing C6 link proof bytes"));
        }
        let proof = Self { repetitions, wrapper_pcs, terminal_tags };
        if proof.canonical_bytes(fixed)?.as_slice() != bytes {
            return Err(C6AuthenticatedOutputLinkError::new("noncanonical C6 link proof bytes"));
        }
        Ok(proof)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6AuthenticatedOutputLinkMetrics {
    pub relations_per_repetition: u64,
    pub rounds_per_repetition: u64,
    pub full_correlations_per_tape: u64,
    pub link_overhead_bytes: u64,
    pub combined_proof_bytes: u64,
}

struct ProverRoundOutput {
    point: Vec<Fp2>,
    final_claims: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    corrections: Vec<[[Fp2; 2]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]>,
}

/// Scaled/reference prover.  It is intentionally not a production backend.
pub fn prove_c6_authenticated_output_link_reference(
    fixed: &C6FixedWrapperCommitments,
    cohorts: &[C6CommittedWrapperCohort],
    pending: C6PendingSlotRegistryProver,
    polynomials: &[C6LinkSlotPolynomial<'_>],
    streams: &mut [CorrelationStream; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6AuthenticatedOutputLinkProof,
    C6BoundSlotRegistryProver,
    C6AuthenticatedOutputLinkMetrics,
)> {
    refuse_production_reference(fixed)?;
    let (relations, rounds, _) = link_geometry(fixed)?;
    validate_prover_registry(fixed, &pending)?;
    validate_prover_cohorts(fixed, cohorts)?;
    let polynomial_registry = validate_polynomials(fixed, polynomials)?;
    let mut schedule_digests = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        schedule_digests.push(schedule_digest(
            fixed,
            repetition as u8,
            &pending
                .entries
                .iter()
                .filter(|entry| usize::from(entry.descriptor.repetition) == repetition)
                .map(|entry| &entry.descriptor)
                .collect::<Vec<_>>(),
            rounds,
        )?);
    }
    let schedule_digests: [C6WrapperDigest; C6_WRAPPER_REPETITIONS] =
        schedule_digests.try_into().map_err(|_| {
            C6AuthenticatedOutputLinkError::new("C6 link schedule repetition mismatch")
        })?;
    transcript.append(
        LINK_PREFIX_LABEL,
        LINK_HEADER_BYTES + C6_WRAPPER_REPETITIONS as u64 * LINK_REPETITION_PREFIX_BYTES,
    );

    let mut repetition_proofs = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut assembled_claims = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut final_claims =
        [[ProverAuthed::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]; C6_WRAPPER_REPETITIONS];
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let beta = transcript.challenge_fp2();
        let entries = pending_entries_for_repetition(&pending.entries, repetition as u8);
        let rhos = scalar_power_weights(beta, entries.len());
        let initial_claims = array::from_fn(|tape| {
            entries
                .iter()
                .zip(&rhos)
                .fold(ProverAuthed::ZERO, |sum, (entry, rho)| sum.add(entry.auth[tape].scale(*rho)))
        });
        let mut terms = Vec::with_capacity(entries.len());
        for (entry, rho) in entries.iter().zip(&rhos) {
            let polynomial = polynomial_registry
                .get(&entry.descriptor.key())
                .ok_or_else(|| C6AuthenticatedOutputLinkError::new("missing C6 link polynomial"))?;
            let target_value = evaluate_multilinear_table(
                polynomial,
                &entry.descriptor.target_point,
            )
            .map_err(|error| {
                C6AuthenticatedOutputLinkError::new(format!("C6 link target evaluation: {error:?}"))
            })?;
            if target_value != entry.auth[0].x {
                return Err(C6AuthenticatedOutputLinkError::new(
                    "C6 link polynomial does not match pending old-point value",
                ));
            }
            terms.push(DelayedTerm::new(*rho, polynomial, &entry.descriptor.target_point, rounds)?);
        }
        if terms.iter().fold(Fp2::ZERO, |sum, term| sum + term.active_sum()) != initial_claims[0].x
        {
            return Err(C6AuthenticatedOutputLinkError::new("false C6 link initial claim"));
        }
        let round_output = prove_dual_tape_rounds(
            terms,
            initial_claims,
            repetition as u8,
            streams,
            transcript,
            rounds,
        )?;
        ensure_nonzero_fresh_zk_coordinate(&round_output.point)?;
        let (claims, aggregates) = assemble_new_point_claims(
            fixed,
            repetition as u8,
            &entries,
            &rhos,
            &round_output.point,
            Some(&polynomial_registry),
            None,
        )?;
        let aggregate_sum = aggregates.iter().copied().fold(Fp2::ZERO, |sum, value| sum + value);
        if round_output.final_claims.iter().any(|claim| claim.x != aggregate_sum) {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link terminal does not match new-point aggregates",
            ));
        }
        transcript.append(LINK_AGGREGATES_LABEL, LINK_AGGREGATE_BYTES);
        final_claims[repetition] = round_output.final_claims;
        assembled_claims.push(claims);
        repetition_proofs.push(C6LinkRepetitionProof {
            repetition: repetition as u8,
            schedule_digest: schedule_digests[repetition],
            corrections: round_output.corrections,
            aggregates,
        });
    }

    let assembled = seal_authenticated_link_c6_wrapper_claims(fixed, assembled_claims)?;
    let wrapper_pcs =
        prove_c6_wrapper_pcs_assembled(fixed.statement_digest(), cohorts, &assembled, transcript)?;
    let mut terminal_tags =
        [[Fp2::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]; C6_WRAPPER_REPETITIONS];
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let opened = repetition_proofs[repetition]
            .aggregates
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let residual = final_claims[repetition][tape].sub(ProverAuthed::from_public(opened));
            if residual.x != Fp2::ZERO {
                return Err(C6AuthenticatedOutputLinkError::new(
                    "nonzero C6 link terminal residual",
                ));
            }
            terminal_tags[repetition][tape] = zero_open_prover(&residual, transcript);
        }
    }
    let proof = C6AuthenticatedOutputLinkProof {
        repetitions: repetition_proofs,
        wrapper_pcs,
        terminal_tags,
    };
    let combined_proof_bytes = proof.encoded_len(fixed)?;
    transcript.append(LINK_DIGEST_LABEL, LINK_DIGEST_BYTES);
    let pcs_bytes = proof.wrapper_pcs.encoded_len()?;
    let link_overhead_bytes = combined_proof_bytes
        .checked_sub(pcs_bytes)
        .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link overhead underflow"))?;
    let metrics = C6AuthenticatedOutputLinkMetrics {
        relations_per_repetition: relations as u64,
        rounds_per_repetition: rounds as u64,
        full_correlations_per_tape: (C6_WRAPPER_REPETITIONS * 2 * rounds) as u64,
        link_overhead_bytes,
        combined_proof_bytes,
    };
    let bound = C6BoundSlotRegistryProver {
        entries: pending
            .entries
            .into_iter()
            .map(|entry| BoundProverEntry { descriptor: entry.descriptor, _auth: entry.auth })
            .collect(),
    };
    Ok((proof, bound, metrics))
}

/// Scaled/reference verifier companion.  Bound typestate is returned only
/// after the PCS and all four terminal MAC checks accept.
pub fn verify_c6_authenticated_output_link_reference(
    fixed: &C6FixedWrapperCommitments,
    pending: C6PendingSlotRegistryVerifier,
    proof: &C6AuthenticatedOutputLinkProof,
    contexts: &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BoundSlotRegistryVerifier> {
    refuse_production_reference(fixed)?;
    verify_c6_authenticated_output_link_inner(fixed, pending, proof, contexts, transcript)
}

/// Production verifier for a link proof whose packed PCS was created from
/// the persisted/CUDA owners. Verification remains witness-free and uses the
/// same strict proof grammar and transcript as the scaled reference path.
pub fn verify_c6_authenticated_output_link_production(
    fixed: &C6FixedWrapperCommitments,
    pending: C6PendingSlotRegistryVerifier,
    proof: &C6AuthenticatedOutputLinkProof,
    contexts: &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BoundSlotRegistryVerifier> {
    if !fixed.is_production_profile() {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 production link verifier requires production-fixed roots",
        ));
    }
    verify_c6_authenticated_output_link_inner(fixed, pending, proof, contexts, transcript)
}

fn verify_c6_authenticated_output_link_inner(
    fixed: &C6FixedWrapperCommitments,
    pending: C6PendingSlotRegistryVerifier,
    proof: &C6AuthenticatedOutputLinkProof,
    contexts: &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BoundSlotRegistryVerifier> {
    let (relations, rounds, cohorts) = link_geometry(fixed)?;
    validate_verifier_registry(fixed, &pending)?;
    validate_proof_shape(proof, relations, rounds, cohorts)?;
    let mut expected_schedule_digests = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        expected_schedule_digests.push(schedule_digest(
            fixed,
            repetition as u8,
            &pending
                .entries
                .iter()
                .filter(|entry| usize::from(entry.descriptor.repetition) == repetition)
                .map(|entry| &entry.descriptor)
                .collect::<Vec<_>>(),
            rounds,
        )?);
    }
    let expected_schedule_digests: [C6WrapperDigest; C6_WRAPPER_REPETITIONS] =
        expected_schedule_digests.try_into().map_err(|_| {
            C6AuthenticatedOutputLinkError::new("C6 link schedule repetition mismatch")
        })?;
    if proof
        .repetitions
        .iter()
        .zip(expected_schedule_digests)
        .any(|(proof, expected)| proof.schedule_digest != expected)
    {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link schedule digest mismatch"));
    }
    transcript.append(
        LINK_PREFIX_LABEL,
        LINK_HEADER_BYTES + C6_WRAPPER_REPETITIONS as u64 * LINK_REPETITION_PREFIX_BYTES,
    );
    let mut final_keys =
        [[VerifierKey::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]; C6_WRAPPER_REPETITIONS];
    let mut assembled_claims = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for (repetition, (repetition_proof, final_key_slot)) in
        proof.repetitions.iter().zip(&mut final_keys).enumerate()
    {
        let beta = transcript.challenge_fp2();
        let entries = pending_verifier_entries_for_repetition(&pending.entries, repetition as u8);
        let rhos = scalar_power_weights(beta, entries.len());
        let initial_keys = array::from_fn(|tape| {
            entries
                .iter()
                .zip(&rhos)
                .fold(VerifierKey::ZERO, |sum, (entry, rho)| sum.add(entry.keys[tape].scale(*rho)))
        });
        let (point, keys) = verify_dual_tape_rounds(
            initial_keys,
            repetition as u8,
            &repetition_proof.corrections,
            contexts,
            transcript,
            rounds,
        )?;
        ensure_nonzero_fresh_zk_coordinate(&point)?;
        let descriptors = entries.iter().map(|entry| &entry.descriptor).collect::<Vec<_>>();
        let (claims, _) = assemble_new_point_claims(
            fixed,
            repetition as u8,
            &descriptors,
            &rhos,
            &point,
            None,
            Some(repetition_proof.aggregates),
        )?;
        transcript.append(LINK_AGGREGATES_LABEL, LINK_AGGREGATE_BYTES);
        assembled_claims.push(claims);
        *final_key_slot = keys;
    }
    let assembled = seal_authenticated_link_c6_wrapper_claims(fixed, assembled_claims)?;
    verify_c6_wrapper_pcs_assembled(
        fixed.statement_digest(),
        fixed.commitments(),
        &assembled,
        &proof.wrapper_pcs,
        transcript,
    )?;
    for ((repetition_proof, keys), tags) in
        proof.repetitions.iter().zip(&final_keys).zip(&proof.terminal_tags)
    {
        let opened =
            repetition_proof.aggregates.iter().copied().fold(Fp2::ZERO, |sum, value| sum + value);
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let residual = keys[tape].sub(VerifierKey::from_public(opened, contexts[tape].delta));
            if !zero_open_verify(residual, tags[tape]) {
                return Err(C6AuthenticatedOutputLinkError::new(
                    "C6 link terminal ZeroOpen rejected",
                ));
            }
            transcript.append("zero_open_tag", 16);
        }
    }
    transcript.append(LINK_DIGEST_LABEL, LINK_DIGEST_BYTES);
    Ok(C6BoundSlotRegistryVerifier {
        entries: pending
            .entries
            .into_iter()
            .map(|entry| BoundVerifierEntry { descriptor: entry.descriptor, _keys: entry.keys })
            .collect(),
    })
}

fn refuse_production_reference(fixed: &C6FixedWrapperCommitments) -> Result<()> {
    if fixed.is_production_profile() {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 reference link refuses production-fixed roots",
        ));
    }
    Ok(())
}

fn validate_prover_cohorts(
    fixed: &C6FixedWrapperCommitments,
    cohorts: &[C6CommittedWrapperCohort],
) -> Result<()> {
    if cohorts.len() != fixed.commitments().len()
        || cohorts
            .iter()
            .zip(fixed.commitments())
            .any(|(cohort, commitment)| cohort.commitment() != commitment)
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link prover cohorts do not match fixed roots",
        ));
    }
    Ok(())
}

fn validate_prover_registry(
    fixed: &C6FixedWrapperCommitments,
    pending: &C6PendingSlotRegistryProver,
) -> Result<()> {
    let dimensions = expected_slot_dimensions(fixed)?;
    if pending.wrapper_statement_digest != fixed.statement_digest()
        || pending.fixed_roots_digest != fixed.binding_digest()
        || pending.entries.len() != dimensions.len()
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link prover registry root binding mismatch",
        ));
    }
    for ((expected_key, _), entry) in dimensions.iter().zip(&pending.entries) {
        if *expected_key != entry.descriptor.key() {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link prover registry is not canonical",
            ));
        }
        validate_pending_descriptor(
            fixed.statement_digest(),
            fixed.binding_digest(),
            &dimensions,
            &entry.descriptor,
        )?;
        if entry.auth[0].x != entry.auth[1].x {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link prover registry tape plaintext mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_verifier_registry(
    fixed: &C6FixedWrapperCommitments,
    pending: &C6PendingSlotRegistryVerifier,
) -> Result<()> {
    let dimensions = expected_slot_dimensions(fixed)?;
    if pending.wrapper_statement_digest != fixed.statement_digest()
        || pending.fixed_roots_digest != fixed.binding_digest()
        || pending.entries.len() != dimensions.len()
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link verifier registry root binding mismatch",
        ));
    }
    for ((expected_key, _), entry) in dimensions.iter().zip(&pending.entries) {
        if *expected_key != entry.descriptor.key() {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link verifier registry is not canonical",
            ));
        }
        validate_pending_descriptor(
            fixed.statement_digest(),
            fixed.binding_digest(),
            &dimensions,
            &entry.descriptor,
        )?;
    }
    Ok(())
}

fn validate_polynomials<'a>(
    fixed: &C6FixedWrapperCommitments,
    polynomials: &'a [C6LinkSlotPolynomial<'a>],
) -> Result<BTreeMap<SlotKey, &'a [Fp2]>> {
    let dimensions = expected_slot_dimensions(fixed)?;
    if polynomials.len() != dimensions.len() {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link polynomial census mismatch"));
    }
    let mut registry = BTreeMap::new();
    for polynomial in polynomials {
        let key = SlotKey {
            repetition: polynomial.repetition,
            cohort_id: polynomial.cohort_id,
            slot: polynomial.slot,
        };
        let dimension = dimensions
            .get(&key)
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("unknown C6 link polynomial"))?;
        if polynomial.evaluations.len() != 1usize << dimension
            || registry.insert(key, polynomial.evaluations).is_some()
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "duplicate or malformed C6 link polynomial",
            ));
        }
    }
    if registry.keys().ne(dimensions.keys()) {
        return Err(C6AuthenticatedOutputLinkError::new("incomplete C6 link polynomial registry"));
    }
    Ok(registry)
}

fn pending_entries_for_repetition(
    entries: &[PendingProverEntry],
    repetition: u8,
) -> Vec<&PendingProverEntry> {
    entries.iter().filter(|entry| entry.descriptor.repetition == repetition).collect()
}

fn pending_verifier_entries_for_repetition(
    entries: &[PendingVerifierEntry],
    repetition: u8,
) -> Vec<&PendingVerifierEntry> {
    entries.iter().filter(|entry| entry.descriptor.repetition == repetition).collect()
}

fn scalar_power_weights(beta: Fp2, count: usize) -> Vec<Fp2> {
    let mut power = beta;
    (0..count)
        .map(|_| {
            let output = power;
            power = power * beta;
            output
        })
        .collect()
}

fn prove_dual_tape_rounds(
    mut terms: Vec<DelayedTerm>,
    mut claims: [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    repetition: u8,
    streams: &mut [CorrelationStream; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
    rounds: usize,
) -> Result<ProverRoundOutput> {
    let mut point = Vec::with_capacity(rounds);
    let mut corrections = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let (at_zero, at_two) =
            terms.iter().try_fold((Fp2::ZERO, Fp2::ZERO), |(zero, two), term| {
                let (term_zero, term_two) = term.round_values()?;
                Ok::<_, C6AuthenticatedOutputLinkError>((zero + term_zero, two + term_two))
            })?;
        let mut round_corrections = [[Fp2::ZERO; 2]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        let mut auth_zero = [ProverAuthed::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        let mut auth_two = [ProverAuthed::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let mask_zero = streams[tape]
                .draw_fulls(link_correlation_domain(repetition, tape, round, 0)?, 1)[0];
            let mask_two = streams[tape]
                .draw_fulls(link_correlation_domain(repetition, tape, round, 1)?, 1)[0];
            round_corrections[tape] = [at_zero - mask_zero.x, at_two - mask_two.x];
            auth_zero[tape] = mask_zero.authenticate(at_zero);
            auth_two[tape] = mask_two.authenticate(at_two);
        }
        transcript.append(LINK_ROUND_LABEL, LINK_ROUND_BYTES);
        let challenge = transcript.challenge_fp2();
        let weights = lagrange3(challenge);
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let auth_one = claims[tape].sub(auth_zero[tape]);
            claims[tape] = auth_zero[tape]
                .scale(weights[0])
                .add(auth_one.scale(weights[1]))
                .add(auth_two[tape].scale(weights[2]));
        }
        for term in &mut terms {
            term.bind(challenge);
        }
        point.push(challenge);
        corrections.push(round_corrections);
    }
    let terminal = terms.iter().try_fold(Fp2::ZERO, |sum, term| {
        Ok::<_, C6AuthenticatedOutputLinkError>(sum + term.terminal()?)
    })?;
    if claims.iter().any(|claim| claim.x != terminal) {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link sumcheck terminal mismatch"));
    }
    Ok(ProverRoundOutput { point, final_claims: claims, corrections })
}

fn verify_dual_tape_rounds(
    mut claims: [VerifierKey; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    repetition: u8,
    corrections: &[[[Fp2; 2]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES]],
    contexts: &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    transcript: &mut Transcript,
    rounds: usize,
) -> Result<(Vec<Fp2>, [VerifierKey; C6_AUTHENTICATED_OUTPUT_LINK_TAPES])> {
    if corrections.len() != rounds {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link verifier correction-round mismatch",
        ));
    }
    let mut point = Vec::with_capacity(rounds);
    for (round, round_corrections) in corrections.iter().enumerate() {
        let mut key_zero = [VerifierKey::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        let mut key_two = [VerifierKey::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            key_zero[tape] = contexts[tape].correct_full_verifier_keys(
                link_correlation_domain(repetition, tape, round, 0)?,
                &[round_corrections[tape][0]],
            )[0];
            key_two[tape] = contexts[tape].correct_full_verifier_keys(
                link_correlation_domain(repetition, tape, round, 1)?,
                &[round_corrections[tape][1]],
            )[0];
        }
        transcript.append(LINK_ROUND_LABEL, LINK_ROUND_BYTES);
        let challenge = transcript.challenge_fp2();
        let weights = lagrange3(challenge);
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let key_one = claims[tape].sub(key_zero[tape]);
            claims[tape] = key_zero[tape]
                .scale(weights[0])
                .add(key_one.scale(weights[1]))
                .add(key_two[tape].scale(weights[2]));
        }
        point.push(challenge);
    }
    Ok((point, claims))
}

fn ensure_nonzero_fresh_zk_coordinate(point: &[Fp2]) -> Result<()> {
    if point.is_empty() || point.last() == Some(&Fp2::ZERO) {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link fresh ZK coordinate is zero"));
    }
    Ok(())
}

trait DescriptorView {
    fn descriptor(&self) -> &C6PendingSlotDescriptor;
}

impl DescriptorView for &PendingProverEntry {
    fn descriptor(&self) -> &C6PendingSlotDescriptor {
        &self.descriptor
    }
}

impl DescriptorView for &C6PendingSlotDescriptor {
    fn descriptor(&self) -> &C6PendingSlotDescriptor {
        self
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_new_point_claims<D: DescriptorView>(
    fixed: &C6FixedWrapperCommitments,
    repetition: u8,
    entries: &[D],
    rhos: &[Fp2],
    point: &[Fp2],
    polynomial_registry: Option<&BTreeMap<SlotKey, &[Fp2]>>,
    supplied_aggregates: Option<[Fp2; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS]>,
) -> Result<(Vec<C6WrapperOpeningClaim>, [Fp2; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS])> {
    if entries.len() != rhos.len() {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link entry/weight census mismatch"));
    }
    let mut weights = BTreeMap::new();
    for (entry, rho) in entries.iter().zip(rhos) {
        let descriptor = entry.descriptor();
        let dimension = descriptor.target_point.len();
        let leading = point
            .len()
            .checked_sub(dimension)
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link point suffix underflow"))?;
        let virtual_factor =
            point[..leading].iter().fold(Fp2::ONE, |product, z| product * (Fp2::ONE - *z));
        let weight = *rho * eq_points(&point[leading..], &descriptor.target_point) * virtual_factor;
        weights.insert(descriptor.key(), weight);
    }
    let mut computed_aggregates = [Fp2::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS];
    let mut claims = Vec::with_capacity(fixed.commitments().len());
    for (cohort_index, commitment) in fixed.commitments().iter().enumerate() {
        let dimension = usize::from(commitment.spec.coefficient_log2()?);
        let cohort_point = point
            .get(
                point.len().checked_sub(dimension).ok_or_else(|| {
                    C6AuthenticatedOutputLinkError::new("C6 link cohort point underflow")
                })?..,
            )
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link cohort point missing"))?
            .to_vec();
        let mut slot_weights = Vec::with_capacity(usize::from(commitment.spec.slot_count));
        let mut aggregate = Fp2::ZERO;
        for slot in 0..commitment.spec.slot_count {
            let key = SlotKey { repetition, cohort_id: commitment.spec.cohort_id, slot };
            let weight = *weights.get(&key).ok_or_else(|| {
                C6AuthenticatedOutputLinkError::new("missing C6 link slot weight")
            })?;
            slot_weights.push(weight);
            if let Some(polynomials) = polynomial_registry {
                let evaluations = polynomials.get(&key).ok_or_else(|| {
                    C6AuthenticatedOutputLinkError::new("missing C6 aggregate polynomial")
                })?;
                aggregate += weight
                    * evaluate_multilinear_table(evaluations, &cohort_point).map_err(|error| {
                        C6AuthenticatedOutputLinkError::new(format!(
                            "C6 link new-point evaluation: {error:?}"
                        ))
                    })?;
            }
        }
        if let Some(supplied) = supplied_aggregates {
            aggregate = supplied[cohort_index];
        }
        computed_aggregates[cohort_index] = aggregate;
        claims.push(C6WrapperOpeningClaim {
            repetition,
            cohort_id: commitment.spec.cohort_id,
            point: cohort_point,
            slot_weights,
            value: aggregate,
        });
    }
    Ok((claims, computed_aggregates))
}

fn link_geometry(fixed: &C6FixedWrapperCommitments) -> Result<(usize, usize, usize)> {
    let commitments = fixed.commitments();
    if commitments.len() != C6_AUTHENTICATED_OUTPUT_LINK_COHORTS {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link cohort census mismatch"));
    }
    for commitment in commitments {
        commitment.validate()?;
    }
    let expected_cohorts = [
        (C6_PREDECESSOR_CACHE_COHORT_ID, C6WrapperOracleKind::Witness, 8u16),
        (C6_SUCCESSOR_CACHE_COHORT_ID, C6WrapperOracleKind::Witness, 8u16),
        (C6_DELTA_RESIDUAL_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_HIDDEN_U_EMBED_COHORT_ID, C6WrapperOracleKind::Witness, 8),
        (C6_WRAPPER_AUXILIARY_COHORT_ID, C6WrapperOracleKind::Auxiliary, 32),
    ];
    if commitments.iter().zip(expected_cohorts).any(|(commitment, expected)| {
        (commitment.spec.cohort_id, commitment.spec.oracle_kind, commitment.spec.slot_count)
            != expected
    }) {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link cohort owner/order mismatch"));
    }
    let relations = commitments.iter().try_fold(0usize, |sum, commitment| {
        sum.checked_add(usize::from(commitment.spec.slot_count))
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link relation overflow"))
    })?;
    if relations != C6_WRAPPER_ACTIVE_SLOTS {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link relation census mismatch"));
    }
    let rounds = usize::from(commitments[0].spec.coefficient_log2()?);
    if rounds == 0
        || rounds > 30
        || commitments
            .iter()
            .any(|commitment| usize::from(commitment.spec.coefficient_log2().unwrap_or(0)) > rounds)
    {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link global-round geometry mismatch"));
    }
    Ok((relations, rounds, commitments.len()))
}

fn validate_proof_shape(
    proof: &C6AuthenticatedOutputLinkProof,
    relations: usize,
    rounds: usize,
    cohorts: usize,
) -> Result<()> {
    if relations != C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_RELATIONS
        || cohorts != C6_AUTHENTICATED_OUTPUT_LINK_COHORTS
        || proof.repetitions.len() != C6_WRAPPER_REPETITIONS
        || proof.wrapper_pcs.chains.len() != C6_WRAPPER_REPETITIONS
    {
        return Err(C6AuthenticatedOutputLinkError::new("C6 link proof census mismatch"));
    }
    for (repetition, proof) in proof.repetitions.iter().enumerate() {
        if usize::from(proof.repetition) != repetition
            || proof.schedule_digest == [0; 32]
            || proof.corrections.len() != rounds
        {
            return Err(C6AuthenticatedOutputLinkError::new(
                "C6 link repetition proof shape mismatch",
            ));
        }
    }
    Ok(())
}

fn link_correlation_domain(
    repetition: u8,
    tape: usize,
    round: usize,
    endpoint: usize,
) -> Result<u64> {
    if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
        || tape >= C6_AUTHENTICATED_OUTPUT_LINK_TAPES
        || round >= C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_ROUNDS
        || endpoint >= 2
    {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link correlation component out of range",
        ));
    }
    let index = round
        .checked_mul(2)
        .and_then(|value| value.checked_add(endpoint))
        .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link domain index overflow"))?;
    let domain = LINK_CORRELATION_BASE
        | (u64::from(repetition) << 28)
        | ((tape as u64) << 24)
        | 0x0001_0000
        | index as u64;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(C6AuthenticatedOutputLinkError::new(
            "C6 link correlation domain uses reserved bits",
        ));
    }
    Ok(domain)
}

fn schedule_digest(
    fixed: &C6FixedWrapperCommitments,
    repetition: u8,
    descriptors: &[&C6PendingSlotDescriptor],
    rounds: usize,
) -> Result<C6WrapperDigest> {
    let mut hasher = blake3::Hasher::new_derive_key(LINK_SCHEDULE_CONTEXT);
    hasher.update(&fixed.statement_digest());
    hasher.update(&fixed.binding_digest());
    hasher.update(&[repetition]);
    hasher.update(&(descriptors.len() as u16).to_le_bytes());
    hasher.update(&[rounds as u8]);
    for descriptor in descriptors {
        hasher.update(&descriptor.wrapper_statement_digest);
        hasher.update(&descriptor.fixed_roots_digest);
        hasher.update(&descriptor.source_statement_digest);
        hasher.update(&[descriptor.repetition]);
        hasher.update(&descriptor.cohort_id.to_le_bytes());
        hasher.update(&descriptor.slot.to_le_bytes());
        hasher.update(&[descriptor.target_point.len() as u8]);
        for coordinate in &descriptor.target_point {
            hash_fp2(&mut hasher, *coordinate);
        }
    }
    for round in 0..rounds {
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            for endpoint in 0..2 {
                let domain = link_correlation_domain(repetition, tape, round, endpoint)?;
                hasher.update(&domain.to_le_bytes());
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn proof_digest(prefix: &[u8]) -> C6WrapperDigest {
    let mut hasher = blake3::Hasher::new_derive_key(LINK_PROOF_CONTEXT);
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    *hasher.finalize().as_bytes()
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
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
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("C6 link decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6AuthenticatedOutputLinkError::new("truncated C6 link proof"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let mut c0 = [0u8; 8];
        let mut c1 = [0u8; 8];
        c0.copy_from_slice(self.take(8)?);
        c1.copy_from_slice(self.take(8)?);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C6AuthenticatedOutputLinkError::new("noncanonical C6 link field symbol"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

const _: () = {
    assert!(
        LINK_HEADER_BYTES
            + C6_WRAPPER_REPETITIONS as u64
                * (LINK_REPETITION_PREFIX_BYTES
                    + C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_ROUNDS as u64 * LINK_ROUND_BYTES
                    + LINK_AGGREGATE_BYTES)
            + LINK_TERMINAL_TAG_BYTES
            + LINK_DIGEST_BYTES
            == C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_OVERHEAD_BYTES
    );
    assert!(
        C6_WRAPPER_TWO_CHAIN_BYTES + C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_OVERHEAD_BYTES
            == C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_BYTES
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::c6_hidden_u::{
        encode_fp2_ntt, C6HiddenUBundleWitness, C6HiddenUFamilyPostCommit, C6HiddenUFamilyWitness,
        C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUQueryClaim, C6SealedHiddenUBundle,
    };
    use crate::c6_hidden_u_sumcheck::flatten_witness;
    use crate::c6_hidden_u_sumcheck_blind::{
        prove_c6_blind_hidden_u_sumchecks_reference, verify_c6_blind_hidden_u_sumchecks,
        C6BlindHiddenUSumcheckProof,
    };
    use crate::c6_persistent_cache_blind::{
        prove_c6_persistent_cache_blind_reference, verify_c6_persistent_cache_blind,
        C6PersistentCacheBlindProof, C6PersistentCacheBlindWitness, C6PersistentCacheRelationPlan,
        C6PersistentCacheScaledFoldFunctional, C6PersistentCacheSourceBootstrapFrame,
        C6PersistentCacheSourceMasksProver, C6PersistentCacheSourcesProver,
        C6PersistentCacheSourcesVerifier,
    };
    use crate::c6_residual_sumcheck::{
        C6ResidualSumcheckStatement, C6ResidualSumcheckTerm, C6ResidualSumcheckWitness,
        C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION, C6_RESIDUAL_LEAF_TABLES_PER_REPETITION,
    };
    use crate::c6_residual_sumcheck_blind::{
        prepare_c6_blind_residual_statement, prove_c6_blind_residual_sumchecks_reference,
        verify_c6_blind_residual_sumchecks, C6BlindResidualPendingTransferFrame,
        C6BlindResidualStatement, C6BlindResidualSumcheckProof,
    };
    #[cfg(feature = "c6-trace")]
    use crate::c6_residual_sumcheck_blind::{
        prove_c6_blind_residual_sumchecks_fused_scaled,
        verify_c6_blind_residual_sumchecks_fused_scaled, C6BlindResidualFusedCompilerContext,
    };
    use crate::c6_wrapper_pcs::{
        commit_c6_cache_state_cohort, commit_c6_wrapper_cohort, fix_test_c6_wrapper_commitments,
        C6CacheStateDescriptors, C6WrapperCohortSpec, C6WrapperCommitment, C6WrapperOracleKind,
        C6WrapperSlotWitness, C6_HIDDEN_U_EMBED_COHORT_ID, C6_HIDDEN_U_WEIGHTS_COHORT_ID,
        C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    };
    use crate::c6_wrapper_persisted::persist_scaled_c6_wrapper_cohort_reference;
    use crate::ligero::LigeroParams;
    use crate::ntt::NttPlan;
    #[cfg(feature = "c6-trace")]
    use volta_proto::{
        build_c6_residual_fused_scaled_fixture, C6ResidualFusedCoefficientArena,
        C6ResidualFusedScaledFixture,
    };
    use volta_proto::{
        C6ResponseProofEnvelope, C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS,
        C6_RESPONSE_CACHE_FOLD_TARGET_BYTES, C6_RESPONSE_PROOF_ENVELOPE_MAX_BYTES,
        C6_RESPONSE_RESIDUAL_PENDING_BYTES, C6_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
    };

    const LEAF_ROUNDS: usize = 5;
    const AUXILIARY_ROUNDS: usize = 3;
    const GLOBAL_ROUNDS: usize = 7;
    const CHALLENGE_SEED: [u8; 32] = [0x71; 32];
    const TAPE_SEEDS: [[u8; 32]; C6_AUTHENTICATED_OUTPUT_LINK_TAPES] = [[0x31; 32], [0x52; 32]];
    const CACHE_SOURCE_CORRELATION_BASE: u64 = 0x0C67_0000_0000_0000;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(19 * value + 7))
    }

    fn table(rounds: usize, base: u64) -> Vec<Fp2> {
        (0..(1usize << rounds)).map(|index| symbol(base + index as u64 + 1)).collect()
    }

    #[test]
    fn coefficient_delayed_term_matches_resident_evaluation_term_round_by_round() {
        let evaluations = table(5, 9_000);
        let coefficients = crate::x4::ntt::multilinear_coefficients(&evaluations).unwrap();
        let target = (0..5).map(|index| symbol(10_000 + index)).collect::<Vec<_>>();
        let mut resident = DelayedTerm::new(symbol(77), &evaluations, &target, 7).unwrap();
        let mut persisted =
            C6CoefficientDelayedTerm::new(symbol(77), coefficients, &target, 7).unwrap();
        for round in 0..7 {
            assert_eq!(
                persisted.round_values().unwrap(),
                resident.round_values().unwrap(),
                "round {round}",
            );
            let challenge = symbol(11_000 + round as u64);
            resident.bind(challenge);
            persisted.bind(challenge);
        }
        assert_eq!(persisted.terminal().unwrap(), resident.terminal().unwrap());
    }

    #[test]
    fn persisted_coefficient_term_matches_resident_and_accounts_create_new_lifecycle() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-link-term-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let cohort_root = root.join("cohorts");
        let spill_root = root.join("link");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&cohort_root).unwrap();
        std::fs::create_dir(&spill_root).unwrap();
        let statement_digest = [0x61; 32];
        let spec = C6WrapperCohortSpec {
            cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Auxiliary,
            payload_log2: 5,
            slot_count: 32,
        };
        let evaluations = table(5, 9_500);
        let slots = (0..usize::from(spec.slot_count))
            .map(|slot| C6WrapperSlotWitness::Auxiliary {
                evaluations: if slot == 0 {
                    evaluations.clone()
                } else {
                    table(5, 20_000 + slot as u64 * 100)
                },
            })
            .collect::<Vec<_>>();
        let cohort = commit_c6_wrapper_cohort(statement_digest, spec, slots).unwrap();
        let persisted =
            persist_scaled_c6_wrapper_cohort_reference(cohort, &cohort_root, [0x62; 32], 0)
                .unwrap();
        let source = persisted.open_coefficient_slots().unwrap();
        let target = (0..5).map(|index| symbol(10_500 + index)).collect::<Vec<_>>();
        let descriptor = C6PendingSlotDescriptor {
            wrapper_statement_digest: statement_digest,
            fixed_roots_digest: [0x63; 32],
            source_statement_digest: [0x64; 32],
            repetition: 1,
            cohort_id: spec.cohort_id,
            slot: 0,
            target_point: target.clone(),
        };
        let coefficient = symbol(81);
        let mut resident = DelayedTerm::new(coefficient, &evaluations, &target, 7).unwrap();
        let mut metrics = C6PersistedLinkFoldMetrics::default();
        let mut persisted_term = C6PersistedCoefficientDelayedTerm::new(
            coefficient,
            &descriptor,
            &source,
            &spill_root,
            7,
            &mut metrics,
        )
        .unwrap();
        assert_eq!(persisted_term.initial_value(&mut metrics).unwrap(), resident.active_sum());
        for round in 0..7 {
            assert_eq!(
                persisted_term.round_values(&mut metrics).unwrap(),
                resident.round_values().unwrap(),
                "round {round}",
            );
            let challenge = symbol(11_500 + round as u64);
            resident.bind(challenge);
            persisted_term.bind(challenge, &mut metrics).unwrap();
        }
        assert_eq!(persisted_term.terminal(&mut metrics).unwrap(), resident.terminal().unwrap());
        persisted_term.release(&mut metrics).unwrap();
        assert_eq!(metrics.coefficient_bytes_read, 2_512);
        assert_eq!(metrics.coefficient_bytes_written, 496);
        assert_eq!(metrics.manifest_bytes_written, 1_792);
        assert_eq!(metrics.files_created, 12);
        assert_eq!(metrics.files_deleted_after_successor_durable, 12);
        assert_eq!(metrics.directories_created, 1);
        assert_eq!(metrics.fsync_count, 27);
        assert_eq!(metrics.current_live_spill_bytes, 0);
        assert_eq!(metrics.peak_live_spill_bytes, 896);
        drop(source);
        drop(persisted);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn expression_sum(terms: &[C6ResidualSumcheckTerm], tables: &[Vec<Fp2>]) -> Fp2 {
        terms.iter().fold(Fp2::ZERO, |total, term| match term {
            C6ResidualSumcheckTerm::Linear { table, coefficients } => {
                total
                    + coefficients
                        .iter()
                        .zip(&tables[usize::from(*table)])
                        .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient * value)
            }
            C6ResidualSumcheckTerm::Quadratic { lhs, rhs, coefficients } => {
                total
                    + coefficients
                        .iter()
                        .zip(tables[usize::from(*lhs)].iter().zip(&tables[usize::from(*rhs)]))
                        .fold(Fp2::ZERO, |sum, (&coefficient, (&left, &right))| {
                            sum + coefficient * left * right
                        })
            }
        })
    }

    fn scaled_specs() -> [C6WrapperCohortSpec; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS] {
        [
            C6WrapperCohortSpec {
                cohort_id: C6_PREDECESSOR_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 6,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_SUCCESSOR_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 6,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_DELTA_RESIDUAL_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 5,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_WEIGHTS_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 4,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_EMBED_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 4,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: 4,
                slot_count: 32,
            },
        ]
    }

    #[cfg(feature = "c6-trace")]
    fn installed_residual_scaled_specs(
    ) -> [C6WrapperCohortSpec; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS] {
        let mut specs = scaled_specs();
        specs[0].payload_log2 = 7;
        specs[1].payload_log2 = 7;
        specs[2].payload_log2 = 7;
        specs[5].payload_log2 = 3;
        specs
    }

    fn scaled_cache_descriptors() -> C6CacheStateDescriptors {
        C6CacheStateDescriptors::from_slots(array::from_fn(|slot| [(slot + 1) as u8; 32])).unwrap()
    }

    struct ScaledInputs {
        specs: [C6WrapperCohortSpec; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS],
        statements: Vec<C6BlindResidualStatement>,
        witnesses: Vec<C6ResidualSumcheckWitness>,
        hidden_layouts: Vec<C6HiddenULayout>,
        hidden_q_cols: Vec<Vec<Vec<Fp2>>>,
        hidden_sealed: C6SealedHiddenUBundle,
        hidden_postcommit: C6HiddenUPostCommit,
        cohorts: Vec<C6CommittedWrapperCohort>,
        commitments: Vec<C6WrapperCommitment>,
        tables: BTreeMap<(u32, u16), Vec<Fp2>>,
        cache_rounds: usize,
        cache_old_len: usize,
        cache_append_len: usize,
        cache_auxiliary_target: Vec<Fp2>,
        cache_witness: C6PersistentCacheBlindWitness,
        cache_fold_functionals: Vec<C6PersistentCacheScaledFoldFunctional>,
        cache_append_values: [Vec<Fp2>; 2],
        cache_fold_targets: Vec<Fp2>,
    }

    fn scaled_hidden_inputs(
    ) -> (Vec<C6HiddenULayout>, Vec<Vec<Vec<Fp2>>>, C6SealedHiddenUBundle, C6HiddenUPostCommit)
    {
        let layouts = vec![
            C6HiddenULayout {
                family: C6HiddenUFamily::Weights,
                params: LigeroParams { rows: 8, col_bits: 2, pad: 2, code_bits: 3, n_queries: 2 },
                claim_count: 1,
                vector_capacity: 2,
                vector_stride: 8,
            },
            C6HiddenULayout {
                family: C6HiddenUFamily::Embed,
                params: LigeroParams { rows: 8, col_bits: 2, pad: 2, code_bits: 3, n_queries: 2 },
                claim_count: 1,
                vector_capacity: 2,
                vector_stride: 8,
            },
        ];
        let mut q_cols = Vec::with_capacity(layouts.len());
        let mut family_witnesses = Vec::with_capacity(layouts.len());
        for (family_index, layout) in layouts.iter().enumerate() {
            let seed = 310_000 + family_index as u64 * 10_000;
            let vectors = (0..layout.live_vectors())
                .map(|vector| {
                    (0..layout.msg_len())
                        .map(|index| symbol(seed + vector as u64 * 100 + index as u64))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let family_q_cols = vec![(0..layout.cols())
                .map(|index| symbol(seed + 1_000 + index as u64))
                .collect::<Vec<_>>()];
            family_witnesses.push(
                C6HiddenUFamilyWitness::new(
                    *layout,
                    vectors[0].clone(),
                    vectors[1..].to_vec(),
                    family_q_cols.clone(),
                )
                .unwrap(),
            );
            q_cols.push(family_q_cols);
        }
        let sealed = C6HiddenUBundleWitness::new(family_witnesses)
            .unwrap()
            .seal(vec![[0xB1; 32], [0xB2; 32]], [0xB3; 32])
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
                let queries = [0usize, 7]
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
            batching_seed: [0xB4; 32],
            families,
        };
        (layouts, q_cols, sealed, postcommit)
    }

    fn scaled_inputs() -> ScaledInputs {
        let leaf_tables = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION as u64)
            .map(|slot| table(LEAF_ROUNDS, 10_000 + 100 * slot))
            .collect::<Vec<_>>();
        let auxiliary_tables = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION as u64)
            .map(|slot| table(AUXILIARY_ROUNDS, 20_000 + 100 * slot))
            .collect::<Vec<_>>();
        let leaf_terms = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION)
            .map(|slot| {
                C6ResidualSumcheckTerm::linear(
                    slot as u8,
                    table(LEAF_ROUNDS, 30_000 + 100 * slot as u64),
                )
            })
            .collect::<Vec<_>>();
        let mut auxiliary_terms = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION)
            .map(|slot| {
                C6ResidualSumcheckTerm::linear(
                    slot as u8,
                    table(AUXILIARY_ROUNDS, 40_000 + 100 * slot as u64),
                )
            })
            .collect::<Vec<_>>();
        auxiliary_terms.extend(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.iter().enumerate().map(
            |(index, (lhs, rhs))| {
                C6ResidualSumcheckTerm::quadratic(
                    *lhs,
                    *rhs,
                    table(AUXILIARY_ROUNDS, 50_000 + 100 * index as u64),
                )
                .unwrap()
            },
        ));
        let target = expression_sum(&leaf_terms, &leaf_tables)
            + expression_sum(&auxiliary_terms, &auxiliary_tables);
        let mut statements = Vec::new();
        let mut witnesses = Vec::new();
        for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
            let reference = C6ResidualSumcheckStatement::new_test(
                repetition,
                target,
                LEAF_ROUNDS,
                AUXILIARY_ROUNDS,
                leaf_terms.clone(),
                auxiliary_terms.clone(),
            )
            .unwrap();
            witnesses.push(
                C6ResidualSumcheckWitness::new(
                    &reference,
                    leaf_tables.clone(),
                    auxiliary_tables.clone(),
                )
                .unwrap(),
            );
            statements.push(
                prepare_c6_blind_residual_statement(reference, [0xA0 + repetition; 32]).unwrap(),
            );
        }

        let (hidden_layouts, hidden_q_cols, hidden_sealed, hidden_postcommit) =
            scaled_hidden_inputs();
        let mut tables = BTreeMap::new();
        for (slot, lower) in leaf_tables.into_iter().enumerate() {
            let mut evaluations = lower;
            evaluations.extend(table(LEAF_ROUNDS, 60_000 + 100 * slot as u64));
            tables.insert((C6_DELTA_RESIDUAL_COHORT_ID, slot as u16), evaluations);
        }
        for (slot, lower) in auxiliary_tables.into_iter().enumerate() {
            let mut evaluations = lower;
            evaluations.extend(table(AUXILIARY_ROUNDS, 70_000 + 100 * slot as u64));
            tables.insert((C6_WRAPPER_AUXILIARY_COHORT_ID, slot as u16), evaluations);
        }
        for (family_index, cohort_id) in
            [C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6_HIDDEN_U_EMBED_COHORT_ID].into_iter().enumerate()
        {
            let lower = flatten_witness(
                hidden_layouts[family_index],
                hidden_sealed.families()[family_index].vectors(),
            )
            .unwrap();
            let mut actual = lower;
            actual.extend(table(
                hidden_layouts[family_index].padded_entries().ilog2() as usize,
                330_000 + family_index as u64 * 10_000,
            ));
            tables.insert((cohort_id, 0), actual);
            for slot in 1..8u16 {
                let mut zero = vec![Fp2::ZERO; hidden_layouts[family_index].padded_entries()];
                zero.extend(table(
                    hidden_layouts[family_index].padded_entries().ilog2() as usize,
                    340_000 + family_index as u64 * 10_000 + u64::from(slot) * 100,
                ));
                tables.insert((cohort_id, slot), zero);
            }
        }

        const CACHE_ROUNDS: usize = 6;
        const CACHE_OLD_LEN: usize = 12;
        const CACHE_APPEND_LEN: usize = 4;
        let cache_len = 1usize << CACHE_ROUNDS;
        let cache_predecessor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..cache_len)
                .map(|index| {
                    if index < CACHE_OLD_LEN {
                        symbol(400_000 + kv as u64 * 10_000 + index as u64)
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        let cache_append_values: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..CACHE_APPEND_LEN)
                .map(|index| symbol(430_000 + kv as u64 * 10_000 + index as u64))
                .collect()
        });
        let cache_successor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..cache_len)
                .map(|index| {
                    if index < CACHE_OLD_LEN {
                        cache_predecessor[kv][index]
                    } else if index < CACHE_OLD_LEN + CACHE_APPEND_LEN {
                        cache_append_values[kv][index - CACHE_OLD_LEN]
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        let cache_fold_functionals = (0..4)
            .map(|ordinal| {
                C6PersistentCacheScaledFoldFunctional::new(
                    ordinal,
                    ordinal / 2,
                    table(CACHE_ROUNDS, 460_000 + ordinal as u64 * 10_000),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let cache_fold_targets = cache_fold_functionals
            .iter()
            .map(|functional| {
                functional
                    .coefficients()
                    .iter()
                    .zip(&cache_successor[functional.kv()])
                    .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient * value)
            })
            .collect::<Vec<_>>();
        for kv in 0..2 {
            let mut predecessor = cache_predecessor[kv].clone();
            predecessor.extend(table(CACHE_ROUNDS, 500_000 + kv as u64 * 10_000));
            tables.insert((C6_PREDECESSOR_CACHE_COHORT_ID, kv as u16), predecessor);
            let mut successor = cache_successor[kv].clone();
            successor.extend(table(CACHE_ROUNDS, 520_000 + kv as u64 * 10_000));
            tables.insert((C6_SUCCESSOR_CACHE_COHORT_ID, kv as u16), successor);
        }
        for cohort_id in [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID] {
            for slot in 2..8u16 {
                let mut zero = vec![Fp2::ZERO; cache_len];
                zero.extend(table(
                    CACHE_ROUNDS,
                    540_000 + u64::from(cohort_id & 0xff) * 10_000 + u64::from(slot) * 100,
                ));
                tables.insert((cohort_id, slot), zero);
            }
        }
        for slot in 16..32u16 {
            tables.insert((C6_WRAPPER_AUXILIARY_COHORT_ID, slot), vec![Fp2::ZERO; 1 << 4]);
        }
        let placeholder_cache_plan = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            CACHE_ROUNDS,
            CACHE_OLD_LEN,
            CACHE_APPEND_LEN,
            [0xC1; 32],
            [0xC2; 32],
            [0xC3; 32],
            cache_fold_functionals.clone(),
            vec![symbol(490_001), symbol(490_002), symbol(490_003), Fp2::ZERO],
        )
        .unwrap();
        let cache_witness = C6PersistentCacheBlindWitness::new(
            &placeholder_cache_plan,
            [
                cache_predecessor[0].clone(),
                cache_predecessor[1].clone(),
                cache_successor[0].clone(),
                cache_successor[1].clone(),
            ],
        )
        .unwrap();
        let specs = scaled_specs();
        for spec in specs {
            for slot in 0..spec.slot_count {
                if tables.contains_key(&(spec.cohort_id, slot)) {
                    continue;
                }
                let dimension = usize::from(spec.coefficient_log2().unwrap());
                tables.insert(
                    (spec.cohort_id, slot),
                    table(
                        dimension,
                        100_000
                            + u64::from(spec.cohort_id & 0xffff) * 10_000
                            + u64::from(slot) * 200,
                    ),
                );
            }
        }
        let cohorts = commit_scaled_cohorts(&specs, &tables);
        let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect();
        ScaledInputs {
            specs,
            statements,
            witnesses,
            hidden_layouts,
            hidden_q_cols,
            hidden_sealed,
            hidden_postcommit,
            cohorts,
            commitments,
            tables,
            cache_rounds: CACHE_ROUNDS,
            cache_old_len: CACHE_OLD_LEN,
            cache_append_len: CACHE_APPEND_LEN,
            cache_auxiliary_target: vec![
                symbol(490_001),
                symbol(490_002),
                symbol(490_003),
                Fp2::ZERO,
            ],
            cache_witness,
            cache_fold_functionals,
            cache_append_values,
            cache_fold_targets,
        }
    }

    fn commit_scaled_cohorts(
        specs: &[C6WrapperCohortSpec; C6_AUTHENTICATED_OUTPUT_LINK_COHORTS],
        tables: &BTreeMap<(u32, u16), Vec<Fp2>>,
    ) -> Vec<C6CommittedWrapperCohort> {
        specs
            .iter()
            .copied()
            .map(|spec| {
                let slots = (0..spec.slot_count)
                    .map(|slot| {
                        let evaluations = tables[&(spec.cohort_id, slot)].clone();
                        match spec.oracle_kind {
                            C6WrapperOracleKind::Witness => {
                                let half = evaluations.len() / 2;
                                C6WrapperSlotWitness::Witness {
                                    witness: evaluations[..half].to_vec(),
                                    zk_mask: evaluations[half..].to_vec(),
                                }
                            }
                            C6WrapperOracleKind::Auxiliary => {
                                C6WrapperSlotWitness::Auxiliary { evaluations }
                            }
                        }
                    })
                    .collect();
                if matches!(
                    spec.cohort_id,
                    C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID
                ) {
                    commit_c6_cache_state_cohort(
                        [0xC6; 32],
                        spec,
                        slots,
                        &scaled_cache_descriptors(),
                    )
                    .unwrap()
                } else {
                    commit_c6_wrapper_cohort([0xC6; 32], spec, slots).unwrap()
                }
            })
            .collect()
    }

    #[cfg(feature = "c6-trace")]
    fn installed_residual_scaled_inputs() -> (ScaledInputs, C6ResidualFusedScaledFixture) {
        let fused = build_c6_residual_fused_scaled_fixture().unwrap();
        assert!(fused.uses_installed_terminal_witness());
        let mut inputs = scaled_inputs();
        inputs.specs = installed_residual_scaled_specs();
        inputs.statements.clear();
        inputs.witnesses.clear();
        for atomic in fused.compilation().statements() {
            let reference =
                C6ResidualSumcheckStatement::from_atomic_relation_reference(atomic).unwrap();
            inputs.witnesses.push(
                C6ResidualSumcheckWitness::new(
                    &reference,
                    fused.reference().leaf_tables().to_vec(),
                    fused.reference().auxiliary_tables().to_vec(),
                )
                .unwrap(),
            );
            let semantic = fused.semantic_compiler_digest(atomic.proof_repetition()).unwrap();
            inputs
                .statements
                .push(prepare_c6_blind_residual_statement(reference, semantic).unwrap());
        }

        for (slot, lower) in fused.reference().leaf_tables().iter().enumerate() {
            let mut evaluations = lower.clone();
            evaluations.extend(table(7, 610_000 + 100 * slot as u64));
            inputs.tables.insert((C6_DELTA_RESIDUAL_COHORT_ID, slot as u16), evaluations);
        }
        for (slot, lower) in fused.reference().auxiliary_tables().iter().enumerate() {
            let mut evaluations = lower.clone();
            evaluations.extend(table(2, 620_000 + 100 * slot as u64));
            inputs.tables.insert((C6_WRAPPER_AUXILIARY_COHORT_ID, slot as u16), evaluations);
        }
        for slot in 16..32u16 {
            inputs.tables.insert((C6_WRAPPER_AUXILIARY_COHORT_ID, slot), vec![Fp2::ZERO; 1 << 3]);
        }

        const CACHE_ROUNDS: usize = 7;
        const CACHE_OLD_LEN: usize = 12;
        const CACHE_APPEND_LEN: usize = 4;
        let cache_len = 1usize << CACHE_ROUNDS;
        let cache_predecessor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..cache_len)
                .map(|index| {
                    if index < CACHE_OLD_LEN {
                        symbol(400_000 + kv as u64 * 10_000 + index as u64)
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        inputs.cache_append_values = array::from_fn(|kv| {
            (0..CACHE_APPEND_LEN)
                .map(|index| symbol(430_000 + kv as u64 * 10_000 + index as u64))
                .collect()
        });
        let cache_successor: [Vec<Fp2>; 2] = array::from_fn(|kv| {
            (0..cache_len)
                .map(|index| {
                    if index < CACHE_OLD_LEN {
                        cache_predecessor[kv][index]
                    } else if index < CACHE_OLD_LEN + CACHE_APPEND_LEN {
                        inputs.cache_append_values[kv][index - CACHE_OLD_LEN]
                    } else {
                        Fp2::ZERO
                    }
                })
                .collect()
        });
        inputs.cache_fold_functionals = (0..4)
            .map(|ordinal| {
                C6PersistentCacheScaledFoldFunctional::new(
                    ordinal,
                    ordinal / 2,
                    table(CACHE_ROUNDS, 460_000 + ordinal as u64 * 10_000),
                )
                .unwrap()
            })
            .collect();
        inputs.cache_fold_targets = inputs
            .cache_fold_functionals
            .iter()
            .map(|functional| {
                functional
                    .coefficients()
                    .iter()
                    .zip(&cache_successor[functional.kv()])
                    .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient * value)
            })
            .collect();
        inputs.cache_auxiliary_target = vec![symbol(490_001), symbol(490_002), Fp2::ZERO];
        let placeholder_cache_plan = C6PersistentCacheRelationPlan::new_scaled_client_derived(
            CACHE_ROUNDS,
            CACHE_OLD_LEN,
            CACHE_APPEND_LEN,
            [0xC1; 32],
            [0xC2; 32],
            [0xC3; 32],
            inputs.cache_fold_functionals.clone(),
            inputs.cache_auxiliary_target.clone(),
        )
        .unwrap();
        inputs.cache_witness = C6PersistentCacheBlindWitness::new(
            &placeholder_cache_plan,
            [
                cache_predecessor[0].clone(),
                cache_predecessor[1].clone(),
                cache_successor[0].clone(),
                cache_successor[1].clone(),
            ],
        )
        .unwrap();
        inputs.cache_rounds = CACHE_ROUNDS;
        inputs.cache_old_len = CACHE_OLD_LEN;
        inputs.cache_append_len = CACHE_APPEND_LEN;
        for kv in 0..2 {
            let mut predecessor = cache_predecessor[kv].clone();
            predecessor.extend(table(CACHE_ROUNDS, 500_000 + kv as u64 * 10_000));
            inputs.tables.insert((C6_PREDECESSOR_CACHE_COHORT_ID, kv as u16), predecessor);
            let mut successor = cache_successor[kv].clone();
            successor.extend(table(CACHE_ROUNDS, 520_000 + kv as u64 * 10_000));
            inputs.tables.insert((C6_SUCCESSOR_CACHE_COHORT_ID, kv as u16), successor);
        }
        for cohort_id in [C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID] {
            for slot in 2..8u16 {
                let mut zero = vec![Fp2::ZERO; cache_len];
                zero.extend(table(
                    CACHE_ROUNDS,
                    540_000 + u64::from(cohort_id & 0xff) * 10_000 + u64::from(slot) * 100,
                ));
                inputs.tables.insert((cohort_id, slot), zero);
            }
        }
        inputs.cohorts = commit_scaled_cohorts(&inputs.specs, &inputs.tables);
        inputs.commitments =
            inputs.cohorts.iter().map(|cohort| cohort.commitment().clone()).collect();
        (inputs, fused)
    }

    fn polynomial_views<'a>(inputs: &'a ScaledInputs) -> Vec<C6LinkSlotPolynomial<'a>> {
        let mut polynomials = Vec::with_capacity(C6_WRAPPER_REPETITIONS * C6_WRAPPER_ACTIVE_SLOTS);
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            for spec in inputs.specs {
                for slot in 0..spec.slot_count {
                    polynomials.push(C6LinkSlotPolynomial {
                        repetition: repetition as u8,
                        cohort_id: spec.cohort_id,
                        slot,
                        evaluations: &inputs.tables[&(spec.cohort_id, slot)],
                    });
                }
            }
        }
        polynomials
    }

    fn source_target(repetition: u8, cohort_id: u32, slot: u16, dimension: usize) -> Vec<Fp2> {
        let mut point = (0..dimension - 1)
            .map(|index| {
                symbol(
                    800_000
                        + u64::from(repetition) * 10_000
                        + u64::from(cohort_id & 0xff) * 100
                        + u64::from(slot) * 10
                        + index as u64,
                )
            })
            .collect::<Vec<_>>();
        point.push(Fp2::ZERO);
        point
    }

    fn cache_relation_plan(
        fixed: &C6FixedWrapperCommitments,
        inputs: &ScaledInputs,
    ) -> C6PersistentCacheRelationPlan {
        C6PersistentCacheRelationPlan::new_scaled_client_derived(
            inputs.cache_rounds,
            inputs.cache_old_len,
            inputs.cache_append_len,
            fixed.binding_digest(),
            [0xC2; 32],
            [0xC3; 32],
            inputs.cache_fold_functionals.clone(),
            inputs.cache_auxiliary_target.clone(),
        )
        .unwrap()
    }

    fn cache_source_domain(tape: usize, ordinal: usize) -> u64 {
        let domain = CACHE_SOURCE_CORRELATION_BASE | ((tape as u64) << 24) | ordinal as u64;
        assert_eq!(domain & RESERVED_DOMAIN_BITS, 0);
        domain
    }

    fn authenticate_cache_source(
        streams: &mut [CorrelationStream; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
        ordinal: usize,
        value: Fp2,
    ) -> (
        [ProverAuthed; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
        [Fp2; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) {
        let mut auth = [ProverAuthed::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        let mut masks = [Fp2::ZERO; C6_AUTHENTICATED_OUTPUT_LINK_TAPES];
        for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
            let domain = cache_source_domain(tape, ordinal);
            let correlation = streams[tape].draw_fulls(domain, 1)[0];
            streams[tape].record_c6_fullfield_plaintexts(domain, &[value]).unwrap();
            masks[tape] = correlation.x;
            auth[tape] = correlation.authenticate(value);
        }
        (auth, masks)
    }

    fn cache_sources_prover(
        plan: &C6PersistentCacheRelationPlan,
        inputs: &ScaledInputs,
        streams: &mut [CorrelationStream; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) -> (C6PersistentCacheSourcesProver, C6PersistentCacheSourceMasksProver) {
        let mut ordinal = 0usize;
        let mut transition_auth: [Vec<[ProverAuthed; 2]>; 2] = array::from_fn(|_| Vec::new());
        let mut transition_masks: [Vec<[Fp2; 2]>; 2] = array::from_fn(|_| Vec::new());
        for kv in 0..2 {
            for &value in &inputs.cache_append_values[kv] {
                let (auth, masks) = authenticate_cache_source(streams, ordinal, value);
                transition_auth[kv].push(auth);
                transition_masks[kv].push(masks);
                ordinal += 1;
            }
        }
        let mut fold_auth = Vec::with_capacity(inputs.cache_fold_targets.len());
        let mut fold_masks = Vec::with_capacity(inputs.cache_fold_targets.len());
        for &target in &inputs.cache_fold_targets {
            let (auth, masks) = authenticate_cache_source(streams, ordinal, target);
            fold_auth.push(auth);
            fold_masks.push(masks);
            ordinal += 1;
        }
        assert_eq!(ordinal, 12);
        (
            C6PersistentCacheSourcesProver::new(plan, transition_auth, fold_auth).unwrap(),
            C6PersistentCacheSourceMasksProver::new(plan, transition_masks, fold_masks).unwrap(),
        )
    }

    fn cache_sources_verifier(
        plan: &C6PersistentCacheRelationPlan,
        contexts: &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) -> C6PersistentCacheSourcesVerifier {
        let mut ordinal = 0usize;
        let mut transition_keys: [Vec<[VerifierKey; 2]>; 2] = array::from_fn(|_| Vec::new());
        for keys in &mut transition_keys {
            for _ in 0..4 {
                keys.push(array::from_fn(|tape| {
                    contexts[tape].expand_full_verifier_keys(cache_source_domain(tape, ordinal), 1)
                        [0]
                }));
                ordinal += 1;
            }
        }
        let mut fold_keys = Vec::with_capacity(plan.fold_count());
        for _ in 0..plan.fold_count() {
            fold_keys.push(array::from_fn(|tape| {
                contexts[tape].expand_full_verifier_keys(cache_source_domain(tape, ordinal), 1)[0]
            }));
            ordinal += 1;
        }
        assert_eq!(ordinal, 12);
        C6PersistentCacheSourcesVerifier::new(plan, transition_keys, fold_keys).unwrap()
    }

    struct IntegratedFixture {
        inputs: ScaledInputs,
        residual_proof: C6BlindResidualSumcheckProof,
        residual_frame: C6BlindResidualPendingTransferFrame,
        hidden_proof: C6BlindHiddenUSumcheckProof,
        cache_proof: C6PersistentCacheBlindProof,
        cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
        cache_proof_bytes: u64,
        cache_correlations_per_tape: u64,
        cache_pending_claims: u64,
        fixed: C6FixedWrapperCommitments,
        proof: C6AuthenticatedOutputLinkProof,
        encoded: Vec<u8>,
        response_envelope: Vec<u8>,
        metrics: C6AuthenticatedOutputLinkMetrics,
        old_values: Vec<Fp2>,
        prover_ledger: BTreeMap<&'static str, u64>,
        prover_total: u64,
        prover_link_counter_delta: [u64; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    }

    fn prove_integrated_fixture() -> IntegratedFixture {
        let inputs = scaled_inputs();
        prove_integrated_fixture_with(inputs, |inputs, streams, transcript| {
            prove_c6_blind_residual_sumchecks_reference(
                &inputs.statements,
                &inputs.witnesses,
                streams,
                transcript,
            )
            .unwrap()
        })
    }

    #[cfg(feature = "c6-trace")]
    fn prove_installed_residual_integrated_fixture(
    ) -> (IntegratedFixture, C6ResidualFusedScaledFixture) {
        let (inputs, fused) = installed_residual_scaled_inputs();
        let compiler = C6BlindResidualFusedCompilerContext::new(
            fused.operation_plan(),
            fused.extraction(),
            fused.runtime(),
            fused.linear(),
            fused.relation(),
        );
        let arena = C6ResidualFusedCoefficientArena::new(fused.manifest());
        let integrated = prove_integrated_fixture_with(inputs, |inputs, streams, transcript| {
            prove_c6_blind_residual_sumchecks_fused_scaled(
                &inputs.statements,
                &inputs.witnesses,
                compiler,
                fused.witness_view().unwrap(),
                &arena,
                streams,
                transcript,
            )
            .unwrap()
        });
        assert_eq!(arena.active_repetition(), None);
        assert_eq!(arena.active_elements(), 0);
        assert!(!arena.is_faulted());
        (integrated, fused)
    }

    fn prove_integrated_fixture_with(
        inputs: ScaledInputs,
        prove_residual: impl FnOnce(
            &ScaledInputs,
            &mut [CorrelationStream; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
            &mut Transcript,
        ) -> (
            C6BlindResidualSumcheckProof,
            C6BlindResidualPendingTransferFrame,
            C6BlindResidualPendingClaimsProver,
        ),
    ) -> IntegratedFixture {
        let mut streams = array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]));
        let mut transcript = Transcript::new(CHALLENGE_SEED);
        let fixed =
            fix_test_c6_wrapper_commitments([0xC6; 32], &inputs.commitments, &mut transcript)
                .unwrap();
        let (residual_proof, residual_frame, residual_pending) =
            prove_residual(&inputs, &mut streams, &mut transcript);
        let (hidden_proof, hidden_pending) = prove_c6_blind_hidden_u_sumchecks_reference(
            &inputs.hidden_sealed,
            inputs.hidden_sealed.prequery(),
            &inputs.hidden_postcommit,
            &mut streams,
            &mut transcript,
        )
        .unwrap();
        let cache_plan = cache_relation_plan(&fixed, &inputs);
        let (cache_sources, cache_source_masks) =
            cache_sources_prover(&cache_plan, &inputs, &mut streams);
        let (cache_proof, cache_source_frame, cache_pending, cache_metrics) =
            prove_c6_persistent_cache_blind_reference(
                &cache_plan,
                &inputs.cache_witness,
                &cache_sources,
                &cache_source_masks,
                &mut streams,
                &mut transcript,
            )
            .unwrap();
        let mut builder = C6PendingSlotRegistryProverBuilder::new(&fixed).unwrap();
        builder.absorb_residual(&residual_pending).unwrap();
        builder.absorb_hidden_u(&hidden_pending).unwrap();
        builder.absorb_persistent_cache(&cache_pending).unwrap();
        let pending = builder.finish().unwrap();
        let old_values = pending.entries.iter().map(|entry| entry.auth[0].x).collect::<Vec<_>>();
        let before: [u64; C6_AUTHENTICATED_OUTPUT_LINK_TAPES] =
            array::from_fn(|tape| streams[tape].counters.full_corrs);
        let (proof, bound, metrics) = prove_c6_authenticated_output_link_reference(
            &fixed,
            &inputs.cohorts,
            pending,
            &polynomial_views(&inputs),
            &mut streams,
            &mut transcript,
        )
        .unwrap();
        assert_eq!(bound.len(), 2 * C6_WRAPPER_ACTIVE_SLOTS);
        let prover_link_counter_delta =
            array::from_fn(|tape| streams[tape].counters.full_corrs - before[tape]);
        let encoded = proof.canonical_bytes(&fixed).unwrap();
        // C6FT1 is produced by the response/model crate and is independently
        // strict-codec tested there. This cross-crate fixture reserves its
        // exact closed component while installing every PCS-owned component
        // from the live proof objects above.
        let response_envelope = C6ResponseProofEnvelope::new(
            residual_proof.encode(&inputs.statements).unwrap(),
            residual_frame.encode().unwrap(),
            hidden_proof.encode(&inputs.hidden_layouts).unwrap(),
            cache_source_frame.encode().unwrap(),
            cache_proof.encode().unwrap(),
            vec![0; C6_RESPONSE_CACHE_FOLD_TARGET_BYTES as usize],
            encoded.clone(),
        )
        .unwrap()
        .encode()
        .unwrap();
        IntegratedFixture {
            inputs,
            residual_proof,
            residual_frame,
            hidden_proof,
            cache_proof,
            cache_source_frame,
            cache_proof_bytes: cache_metrics.proof_bytes,
            cache_correlations_per_tape: cache_metrics.full_correlations_per_tape,
            cache_pending_claims: cache_metrics.pending_claims,
            fixed,
            proof,
            encoded,
            response_envelope,
            metrics,
            old_values,
            prover_ledger: transcript.ledger().clone(),
            prover_total: transcript.total_bytes(),
            prover_link_counter_delta,
        }
    }

    fn verifier_prefix(
        fixture: &IntegratedFixture,
    ) -> (
        C6FixedWrapperCommitments,
        C6PendingSlotRegistryVerifier,
        [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
        Transcript,
        [u64; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) {
        verifier_prefix_with(fixture, |fixture, contexts, transcript| {
            verify_c6_blind_residual_sumchecks(
                &fixture.inputs.statements,
                &fixture.residual_proof,
                &fixture.residual_frame,
                contexts,
                transcript,
            )
            .unwrap()
        })
    }

    #[cfg(feature = "c6-trace")]
    fn verifier_prefix_installed(
        fixture: &IntegratedFixture,
        fused: &C6ResidualFusedScaledFixture,
    ) -> (
        C6FixedWrapperCommitments,
        C6PendingSlotRegistryVerifier,
        [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
        Transcript,
        [u64; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) {
        let compiler = C6BlindResidualFusedCompilerContext::new(
            fused.operation_plan(),
            fused.extraction(),
            fused.runtime(),
            fused.linear(),
            fused.relation(),
        );
        verifier_prefix_with(fixture, |fixture, contexts, transcript| {
            verify_c6_blind_residual_sumchecks_fused_scaled(
                &fixture.inputs.statements,
                &fixture.residual_proof,
                &fixture.residual_frame,
                compiler,
                contexts,
                transcript,
            )
            .unwrap()
        })
    }

    fn verifier_prefix_with(
        fixture: &IntegratedFixture,
        verify_residual: impl FnOnce(
            &IntegratedFixture,
            &mut [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
            &mut Transcript,
        ) -> C6BlindResidualPendingClaimsVerifier,
    ) -> (
        C6FixedWrapperCommitments,
        C6PendingSlotRegistryVerifier,
        [VerifierCtx; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
        Transcript,
        [u64; C6_AUTHENTICATED_OUTPUT_LINK_TAPES],
    ) {
        let mut contexts = [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
        ];
        let mut transcript = Transcript::new(CHALLENGE_SEED);
        let fixed = fix_test_c6_wrapper_commitments(
            [0xC6; 32],
            &fixture.inputs.commitments,
            &mut transcript,
        )
        .unwrap();
        let residual_pending = verify_residual(fixture, &mut contexts, &mut transcript);
        let hidden_pending = verify_c6_blind_hidden_u_sumchecks(
            &fixture.inputs.hidden_layouts,
            &fixture.inputs.hidden_q_cols,
            fixture.inputs.hidden_sealed.prequery(),
            &fixture.inputs.hidden_postcommit,
            &fixture.hidden_proof,
            &mut contexts,
            &mut transcript,
        )
        .unwrap();
        let cache_plan = cache_relation_plan(&fixed, &fixture.inputs);
        let cache_sources = cache_sources_verifier(&cache_plan, &mut contexts);
        let cache_pending = verify_c6_persistent_cache_blind(
            &cache_plan,
            &cache_sources,
            &fixture.cache_source_frame,
            &fixture.cache_proof,
            &mut contexts,
            &mut transcript,
        )
        .unwrap();
        let mut builder = C6PendingSlotRegistryVerifierBuilder::new(&fixed).unwrap();
        builder.absorb_residual(&residual_pending).unwrap();
        builder.absorb_hidden_u(&hidden_pending).unwrap();
        builder.absorb_persistent_cache(&cache_pending).unwrap();
        let pending = builder.finish().unwrap();
        let counters = array::from_fn(|tape| contexts[tape].counters.full_corrs);
        (fixed, pending, contexts, transcript, counters)
    }

    fn rewrite_digest(bytes: &mut [u8]) {
        let offset = bytes.len() - LINK_DIGEST_BYTES as usize;
        let digest = proof_digest(&bytes[..offset]);
        bytes[offset..].copy_from_slice(&digest);
    }

    #[test]
    fn production_constants_and_domain_census_are_exact() {
        assert_eq!(C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_CORRELATIONS_PER_TAPE, 100);
        assert_eq!(C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_OVERHEAD_BYTES, 3_570);
        assert_eq!(C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_BYTES, 3_883_036);
        assert_eq!(
            volta_proto::C6_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
            crate::C6_RESIDUAL_BLIND_PROOF_BYTES
        );
        assert_eq!(
            volta_proto::C6_RESPONSE_RESIDUAL_PENDING_BYTES,
            crate::C6_RESIDUAL_BLIND_PENDING_BYTES
        );
        assert_eq!(
            volta_proto::C6_RESPONSE_HIDDEN_U_MAX_BYTES,
            crate::C6_BLIND_HIDDEN_U_PRODUCTION_BYTES
        );
        assert_eq!(
            volta_proto::C6_RESPONSE_CACHE_SOURCE_BYTES,
            crate::c6_persistent_cache_blind::C6_PERSISTENT_CACHE_SOURCE_BOOTSTRAP_BYTES
        );
        assert_eq!(
            volta_proto::C6_RESPONSE_CACHE_BLIND_MAX_BYTES,
            crate::c6_persistent_cache_blind::C6_PERSISTENT_CACHE_BLIND_PRODUCTION_BYTES
        );
        assert_eq!(
            volta_proto::C6_RESPONSE_AUTHENTICATED_LINK_MAX_BYTES,
            C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_BYTES
        );
        for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
            for tape in 0..C6_AUTHENTICATED_OUTPUT_LINK_TAPES {
                let domains = (0..C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_ROUNDS)
                    .flat_map(|round| {
                        [0, 1].map(|endpoint| {
                            link_correlation_domain(repetition, tape, round, endpoint).unwrap()
                        })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(domains.len(), 50);
                assert_eq!(domains.iter().copied().collect::<BTreeSet<_>>().len(), 50);
                assert!(domains.iter().all(|domain| domain & RESERVED_DOMAIN_BITS == 0));
            }
        }
    }

    #[test]
    fn actual_residual_hidden_and_cache_pending_values_close_through_packed_link_and_pcs() {
        let fixture = prove_integrated_fixture();
        let response_envelope =
            C6ResponseProofEnvelope::decode(&fixture.response_envelope).unwrap();
        assert!(fixture.response_envelope.len() as u64 <= C6_RESPONSE_PROOF_ENVELOPE_MAX_BYTES);
        assert!(
            response_envelope.residual_sumcheck().len() as u64
                <= C6_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
        );
        assert_eq!(
            response_envelope.residual_pending_corrections().len() as u64,
            C6_RESPONSE_RESIDUAL_PENDING_BYTES
        );
        assert_eq!(
            C6BlindResidualSumcheckProof::decode(
                &fixture.inputs.statements,
                response_envelope.residual_sumcheck(),
            )
            .unwrap(),
            fixture.residual_proof
        );
        assert_eq!(
            C6BlindResidualPendingTransferFrame::decode(
                response_envelope.residual_pending_corrections()
            )
            .unwrap(),
            fixture.residual_frame
        );
        assert_eq!(
            C6BlindHiddenUSumcheckProof::decode(
                &fixture.inputs.hidden_layouts,
                fixture.hidden_proof.statement_digest(),
                response_envelope.hidden_u(),
            )
            .unwrap(),
            fixture.hidden_proof
        );
        assert_eq!(
            C6PersistentCacheSourceBootstrapFrame::decode(
                fixture.cache_source_frame.statement_digest(),
                response_envelope.cache_source_bootstrap(),
            )
            .unwrap(),
            fixture.cache_source_frame
        );
        assert_eq!(
            C6PersistentCacheBlindProof::decode(
                fixture.cache_proof.statement_digest(),
                fixture.inputs.cache_rounds,
                response_envelope.cache_blind(),
            )
            .unwrap(),
            fixture.cache_proof
        );
        assert_eq!(response_envelope.authenticated_output_link(), fixture.encoded);
        assert_eq!(
            C6AuthenticatedOutputLinkProof::decode(
                &fixture.fixed,
                response_envelope.authenticated_output_link(),
            )
            .unwrap(),
            fixture.proof
        );
        assert_eq!(fixture.cache_proof_bytes, 1_506);
        assert_eq!(fixture.cache_source_frame.encode().unwrap().len(), 304);
        assert_eq!(fixture.cache_correlations_per_tape, 32);
        assert_eq!(fixture.cache_pending_claims, 64);
        assert_eq!(
            fixture.hidden_proof.encode(&fixture.inputs.hidden_layouts).unwrap().len(),
            1_320
        );
        assert_eq!(fixture.metrics.relations_per_repetition, 72);
        assert_eq!(fixture.metrics.rounds_per_repetition, GLOBAL_ROUNDS as u64);
        assert_eq!(fixture.metrics.full_correlations_per_tape, 28);
        assert_eq!(fixture.prover_link_counter_delta, [28, 28]);
        assert_eq!(
            fixture.metrics.link_overhead_bytes,
            LINK_HEADER_BYTES
                + 2 * (LINK_REPETITION_PREFIX_BYTES
                    + GLOBAL_ROUNDS as u64 * LINK_ROUND_BYTES
                    + LINK_AGGREGATE_BYTES)
                + LINK_TERMINAL_TAG_BYTES
                + LINK_DIGEST_BYTES
        );
        assert_eq!(fixture.metrics.combined_proof_bytes, fixture.encoded.len() as u64);
        assert_eq!(
            C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &fixture.encoded).unwrap(),
            fixture.proof
        );
        assert_eq!(fixture.proof.canonical_bytes(&fixture.fixed).unwrap(), fixture.encoded);
        for value in &fixture.old_values {
            if *value == Fp2::ZERO {
                continue;
            }
            let mut encoded_value = Vec::new();
            encode_fp2(&mut encoded_value, *value);
            assert!(
                !fixture.encoded.windows(encoded_value.len()).any(|window| window == encoded_value),
                "old target value leaked into combined proof"
            );
        }

        let (fixed, pending, mut contexts, mut transcript, before) = verifier_prefix(&fixture);
        let verifier_descriptors = (0..pending.len())
            .map(|index| pending.descriptor(index).unwrap().clone())
            .collect::<Vec<_>>();
        let bound = verify_c6_authenticated_output_link_reference(
            &fixed,
            pending,
            &fixture.proof,
            &mut contexts,
            &mut transcript,
        )
        .unwrap();
        assert_eq!(bound.len(), 2 * C6_WRAPPER_ACTIVE_SLOTS);
        assert_eq!(
            verifier_descriptors,
            (0..bound.len())
                .map(|index| bound.descriptor(index).unwrap().clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            array::from_fn::<_, C6_AUTHENTICATED_OUTPUT_LINK_TAPES, _>(|tape| {
                contexts[tape].counters.full_corrs - before[tape]
            }),
            [28, 28]
        );
        assert_eq!(fixture.prover_ledger, *transcript.ledger());
        assert_eq!(fixture.prover_total, transcript.total_bytes());
        assert_eq!(
            transcript.bytes_for(LINK_PREFIX_LABEL),
            LINK_HEADER_BYTES + 2 * LINK_REPETITION_PREFIX_BYTES
        );
        assert_eq!(transcript.bytes_for(LINK_ROUND_LABEL), 2 * 7 * 64);
        assert_eq!(transcript.bytes_for(LINK_AGGREGATES_LABEL), 192);
        // C6RSC3 contributes 64 B, blind hidden-u and blind cache contribute
        // 64 B each, and the packed link contributes the final four tags.
        assert_eq!(transcript.bytes_for("zero_open_tag"), 256);
        assert_eq!(transcript.bytes_for(LINK_DIGEST_LABEL), 32);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn installed_residual_fused_prover_and_verifier_close_through_packed_link_and_pcs() {
        let (fixture, fused) = prove_installed_residual_integrated_fixture();
        assert!(fused.uses_installed_terminal_witness());
        assert_eq!(fixture.metrics.relations_per_repetition, 72);
        assert_eq!(fixture.metrics.rounds_per_repetition, 8);
        assert_eq!(fixture.metrics.full_correlations_per_tape, 32);
        assert_eq!(fixture.metrics.link_overhead_bytes, 1_394);
        assert_eq!(fixture.metrics.combined_proof_bytes, 418_708);
        assert_eq!(fixture.encoded.len(), 418_708);
        assert_eq!(fixture.prover_link_counter_delta, [32, 32]);

        let (fixed, pending, mut contexts, mut transcript, before) =
            verifier_prefix_installed(&fixture, &fused);
        assert_eq!(pending.len(), 2 * C6_WRAPPER_ACTIVE_SLOTS);
        let bound = verify_c6_authenticated_output_link_reference(
            &fixed,
            pending,
            &fixture.proof,
            &mut contexts,
            &mut transcript,
        )
        .unwrap();
        assert_eq!(bound.len(), 2 * C6_WRAPPER_ACTIVE_SLOTS);
        assert_eq!(
            array::from_fn::<_, C6_AUTHENTICATED_OUTPUT_LINK_TAPES, _>(|tape| {
                contexts[tape].counters.full_corrs - before[tape]
            }),
            [32, 32]
        );
        assert_eq!(fixture.prover_ledger, *transcript.ledger());
        assert_eq!(fixture.prover_total, transcript.total_bytes());
        assert_eq!(transcript.bytes_for(LINK_ROUND_LABEL), 2 * 8 * 64);
    }

    #[test]
    fn strict_codec_rejects_old_noncanonical_corrupt_and_trailing_bytes() {
        let fixture = prove_integrated_fixture();

        let mut wrong_magic = fixture.encoded.clone();
        wrong_magic[0] ^= 1;
        rewrite_digest(&mut wrong_magic);
        assert!(C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &wrong_magic).is_err());

        let mut wrong_version = fixture.encoded.clone();
        wrong_version[8..10].copy_from_slice(&1u16.to_le_bytes());
        rewrite_digest(&mut wrong_version);
        assert!(C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &wrong_version).is_err());

        let mut noncanonical = fixture.encoded.clone();
        let first_correction = LINK_HEADER_BYTES as usize + LINK_REPETITION_PREFIX_BYTES as usize;
        noncanonical[first_correction..first_correction + 8].copy_from_slice(&P.to_le_bytes());
        rewrite_digest(&mut noncanonical);
        assert!(C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &noncanonical).is_err());

        let mut corrupt_digest = fixture.encoded.clone();
        *corrupt_digest.last_mut().unwrap() ^= 1;
        assert!(C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &corrupt_digest).is_err());

        let mut trailing = fixture.encoded.clone();
        trailing.push(0);
        assert!(C6AuthenticatedOutputLinkProof::decode(&fixture.fixed, &trailing).is_err());
    }

    #[test]
    fn verifier_rejects_each_link_pcs_and_terminal_boundary() {
        let fixture = prove_integrated_fixture();

        let mut cases = Vec::new();
        let mut bad_schedule = fixture.proof.clone();
        bad_schedule.repetitions[0].schedule_digest[0] ^= 1;
        cases.push(bad_schedule);

        let mut bad_first_tape = fixture.proof.clone();
        bad_first_tape.repetitions[0].corrections[0][0][0] += Fp2::ONE;
        cases.push(bad_first_tape);

        let mut bad_second_tape = fixture.proof.clone();
        bad_second_tape.repetitions[1].corrections[3][1][1] += Fp2::ONE;
        cases.push(bad_second_tape);

        let mut bad_aggregate = fixture.proof.clone();
        bad_aggregate.repetitions[0].aggregates[2] += Fp2::ONE;
        cases.push(bad_aggregate);

        let mut bad_pcs = fixture.proof.clone();
        bad_pcs.wrapper_pcs.chains[0].fold_frames[0].root_digest[0] ^= 1;
        cases.push(bad_pcs);

        let mut bad_tag = fixture.proof.clone();
        bad_tag.terminal_tags[1][1] += Fp2::ONE;
        cases.push(bad_tag);

        for proof in cases {
            let (fixed, pending, mut contexts, mut transcript, _) = verifier_prefix(&fixture);
            assert!(verify_c6_authenticated_output_link_reference(
                &fixed,
                pending,
                &proof,
                &mut contexts,
                &mut transcript,
            )
            .is_err());
        }
    }

    #[test]
    fn registry_and_fresh_point_fail_closed_before_link_authority() {
        let inputs = scaled_inputs();
        let mut transcript = Transcript::new([0x44; 32]);
        let fixed =
            fix_test_c6_wrapper_commitments([0xC6; 32], &inputs.commitments, &mut transcript)
                .unwrap();
        let mut builder = C6PendingSlotRegistryProverBuilder::new(&fixed).unwrap();
        let auth = [ProverAuthed::from_public(Fp2::ONE); 2];
        let spec = scaled_specs()[0];
        let target = source_target(0, spec.cohort_id, 0, GLOBAL_ROUNDS);

        assert!(builder
            .insert_source(2, spec.cohort_id, 0, [1; 32], target.clone(), auth)
            .is_err());
        assert!(builder.insert_source(0, 0xDEAD_BEEF, 0, [1; 32], target.clone(), auth).is_err());
        assert!(builder
            .insert_source(0, spec.cohort_id, 99, [1; 32], target.clone(), auth)
            .is_err());
        assert!(builder
            .insert_source(0, spec.cohort_id, 0, [0; 32], target.clone(), auth)
            .is_err());
        let mut wrong_target = target.clone();
        wrong_target.pop();
        assert!(builder.insert_source(0, spec.cohort_id, 0, [1; 32], wrong_target, auth).is_err());
        let mismatched = [
            ProverAuthed::from_public(Fp2::ONE),
            ProverAuthed::from_public(Fp2::from_base(Fp::new(2))),
        ];
        assert!(builder
            .insert_source(0, spec.cohort_id, 0, [1; 32], target.clone(), mismatched,)
            .is_err());
        builder.insert_source(0, spec.cohort_id, 0, [1; 32], target.clone(), auth).unwrap();
        assert!(builder.insert_source(0, spec.cohort_id, 0, [1; 32], target, auth).is_err());
        assert!(builder.finish().is_err());
        assert!(ensure_nonzero_fresh_zk_coordinate(&[Fp2::ONE, Fp2::ZERO]).is_err());
    }
}

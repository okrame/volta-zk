//! Strict-codec CPU differential for the C6.1 claimless-affine WHIR fork.
//!
//! This feature-gated module connects the reviewed fork boundary to C6AWH1
//! without implementing a production backend.  The opening target is
//! authenticated before the native proof, never serialized, propagated as a
//! public affine form by both roles, and closed by one designated ZeroOpen.
//! The verifier consumes only the strict C6AWP1 payload, never a shared
//! in-memory proof object.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::unix::fs::FileExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir_c61::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir_c61::pcs::zk::{
    BaseCaseClaimlessClosure, BaseCaseZkProof, BlindedMask, HidingWhirProver, HidingWhirVerifier,
    MaskOpeningPair, ZkParameters, ZkRoundProof, ZkWhirConfig, ZkWhirProof,
};
use p3_whir_c61::{ClaimlessAffineClaim, ClaimlessZkSumcheckData};
use rand::rngs::OsRng;
use rand::RngCore as Rand08RngCore;
use rand_010::rngs::StdRng;
use rand_010::{RngExt, SeedableRng};
use volta_accel::{Backend, BackendKind};
use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_verify, C6CanonicalTargetProfile, C6InstalledOperationPlan,
    C6OperationPlanTerminalMetadata, C6OperationPlanTopologyIdentity, C6TraceSourceManifest,
    CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::c6::{
    C6CacheHead, C6ClientAttempt, C6ClientState, C6CorrelationRange, C6PairedCorrelationRanges,
    C6Workload,
};

use crate::c61_authenticated_whir::{
    finish_c61_authenticated_whir_base, finish_c61_authenticated_whir_base_with_zero_rows,
    finish_c61_joint_native_bridge, prepare_c61_authenticated_whir_mask,
    prepare_c61_joint_native_bridge_prover, prepare_c61_joint_native_bridge_verifier,
    simulate_c61_authenticated_whir_base_view, verify_c61_authenticated_whir_base,
    verify_c61_authenticated_whir_base_with_zero_rows_residual, verify_c61_joint_native_bridge,
    C61AuthenticatedWhirAffineClaim, C61AuthenticatedWhirBaseProof, C61AuthenticatedWhirMaskRange,
    C61AuthenticatedWhirProverFinishInput, C61AuthenticatedWhirVerifierInput,
    C61JointNativeBridgeFrame, C61JointNativeProverBridgePending, C61JointNativeProverTerm,
    C61JointNativeVerifierBridgePending, C61JointNativeVerifierTerm,
    C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
};
use crate::c61_interactive_driver::{
    create_c61_durable_checkpoint_prefix, open_c61_durable_checkpoint,
    spawn_c61_durable_private_entropy_broker, spawn_c61_private_entropy_broker, C61DurableJournal,
    C61InteractiveCheckpoint, C61InteractiveTape, C61PrivateEntropyBrokerOutput,
    C61PrivateEntropyEndpoint, C61PrivateEntropyProverChallenger,
    C61PrivateEntropyReplayChallenger, C61PrivateEntropyTranscriptReplayEndpoint,
};
use crate::c61_joint_native_bridge::{
    C61JointNativeBodyBinding, C61JointNativeBodyScheduleBuilder, C61JointNativeChallenge,
};
use crate::c61_persisted_mmcs::{
    C61MmcsResourceMetrics, C61PersistedMmcs, C61PersistedMmcsMetrics,
};
use crate::c61_public_compression::{
    c61_joint_public_statement_digest, C61ArithmeticFrame, C61JointPublicArgument,
    C61NativeChainId, C61NativeComponent, C61PublicArgument, C61_ARITHMETIC_FRAME_BYTES,
    C61_NATIVE_CHAIN_COUNT, C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES,
};
use crate::c61_shared_round_challenger::c61_shared_round_pair;
use crate::c61_terminal_functional::{
    authenticate_c61_sparse_response_targets_prover,
    authenticate_c61_sparse_response_targets_verifier,
    build_c61_production_model_embedding_public_statement, C61NativeCommitmentDescriptor,
    C61NativeProverChainStatement, C61NativeVerifierChainStatement,
    C61SparseRationalBlindArithmeticProof, C61SparseRationalCompilerOracles,
    C61TerminalFunctionalCompilerBinding, C61TerminalFunctionalCompilerStatement,
    C61TypedNativeChainPublicStatement, C61TypedNativeRelationStatement,
    C61_EMBEDDING_POLYNOMIAL_LOG2, C61_MODEL_POLYNOMIAL_LOG2,
};
use crate::c61_whir_reference::{
    c61_max_pruned_binary_siblings, c61_p3_fp2_from_volta, c61_reference_mmcs,
    c61_volta_fp2_from_p3, C61Commitment, C61InteractiveChallenger, C61Mmcs, C61MultiProof,
    C61P3Fp2, C61Reader, C61SizingChallenger, C61WhirInteractionStats, C61WhirReferenceError,
    C61Writer, ReferenceResult, C61_WHIRA1_DIGEST_BYTES, C61_WHIRA1_ELL_ZK, C61_WHIRA1_FP2_BYTES,
    C61_WHIRA1_FP_BYTES, C61_WHIRA1_INITIAL_FOLD, C61_WHIRA1_LATER_FOLD,
    C61_WHIRA1_MASK_LOG_INV_RATE, C61_WHIRA1_MULTIPROOF_COUNT_BYTES,
    C61_WHIRA1_STARTING_LOG_INV_RATE,
};

/// Fresh provider-private randomness for one production hiding-WHIR lane.
///
/// The returned seed is consumed immediately by the CSPRNG and is never part
/// of the statement, certificate, verifier challenge tape or replay state.
/// Production attempts are burn-on-interruption, so no RNG checkpoint exists.
fn c61_production_private_zk_rng() -> Result<StdRng, String> {
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|error| format!("C6ICT2 provider entropy unavailable: {error}"))?;
    Ok(StdRng::from_seed(seed))
}
use crate::{C6Nbr2ProvedLink, C6Nbr2VerifiedLink, C61_NATIVE_CHAIN_MAX_BYTES};

pub const C61_AUTHENTICATED_P3_SECURITY_BITS: usize = 75;
pub const C61_AUTHENTICATED_P3_REVISION: &str =
    "66e290615de1858f2f2f6a804158064c406cda1c+c61-claimless-affine-multi-v2";
pub const C61_AUTHENTICATED_P3_MAGIC: [u8; 8] = *b"C6AWP1\0\0";
pub const C61_AUTHENTICATED_P3_VERSION: u16 = 1;
pub const C61_JOINT_AUTHENTICATED_P3_MAGIC: [u8; 8] = *b"C6AWP2\0\0";
pub const C61_JOINT_AUTHENTICATED_P3_VERSION: u16 = 2;
pub const C61_AUTHENTICATED_P3_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4;
pub const C61_SHARED_MULTI_ORACLE_MAGIC: [u8; 8] = *b"C6SMO1\0\0";
pub const C61_SHARED_MULTI_ORACLE_VERSION: u16 = 1;
pub const C61_SHARED_MULTI_ORACLE_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4;
pub const C61_SHARED_MULTI_ORACLE_MAX_BYTES: usize = 2_500_000;
const C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS: usize = 12;
const C61_EXACT_PLAN_FOLD_SEMANTIC_OPENINGS: usize = 2;
const C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS: usize = 2 * C61_EXACT_PLAN_FOLD_SEMANTIC_OPENINGS;
const C61_EXACT_PHYSICAL_RESPONSE_OPENINGS: usize =
    C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS + C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS;
/// Frozen C6.1 coefficient-plus-witness component cap.  This is deliberately
/// not a cap on total process RSS or GPU memory; those must be measured
/// separately by the production executor.
pub const C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES: u64 = 2_293_198_848;
/// Admission floor for the explicit host-monolithic A100 baseline.  This is
/// not a protocol cap: it leaves room above the 35.43-GB initial-oracle lower
/// bound for materialized relation vectors, later WHIR rounds and allocator
/// overhead.  The production record must still measure actual RSS.
pub const C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

type C61AuthenticatedP3Proof = ZkWhirProof<Goldilocks, C61P3Fp2, C61Mmcs>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedP3StructuralBudget {
    pub num_variables: usize,
    pub rounds: usize,
    pub mask_queries: usize,
    /// Largest number of private OOD answers in one code-switch round.
    pub max_ood_samples: usize,
    /// Numerator `sum_r t_r(t_r+1)/2` of the composed OOD privacy bad-event
    /// bound over the quadratic-extension field.
    pub ood_privacy_bad_event_numerator: usize,
    pub round_opening_bytes: usize,
    pub base_mask_opening_bytes: usize,
    pub blinded_mask_bytes: usize,
    pub base_case_bytes: usize,
    pub strict_chain_bytes: usize,
}

#[derive(Debug)]
pub struct C61AuthenticatedP3Diagnostic {
    pub num_variables: usize,
    pub provider_affine: C61AuthenticatedWhirAffineClaim,
    pub verifier_affine: C61AuthenticatedWhirAffineClaim,
    pub provider_transcript_bytes: u64,
    pub verifier_transcript_bytes: u64,
    pub provider_ledger: BTreeMap<&'static str, u64>,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub proof_has_clear_evaluation_field: bool,
    pub full_correlations: u64,
}

/// Scaled ordered multi-opening report used by the model/embedding relation
/// adapter.  Opening points and target keys stay in the enclosing statement;
/// the strict provider artifact remains claim-count independent.
#[derive(Debug)]
pub struct C61AuthenticatedP3MultiOpenDiagnostic {
    pub num_variables: usize,
    pub claim_count: usize,
    pub strict_payload_bytes: usize,
    /// Claim-count-independent maximum for this WHIR geometry.  Concrete
    /// payloads may be smaller when sampled Merkle queries share siblings.
    pub strict_payload_max_bytes: usize,
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub batching_weights_identical: bool,
    pub point_mutation_rejected: bool,
    pub full_correlations: u64,
}

/// Scaled physical response/plan compiler opening under one shared-round
/// transcript and one aggregated designated ZeroOpen.  The response carries
/// the two base-field limbs at Dn while the plan remains at D(n-1).
#[derive(Debug)]
pub struct C61AuthenticatedP3SharedMultiOracleDiagnostic {
    pub production_geometry: bool,
    /// True only for the explicitly admitted host-monolithic A100 baseline.
    /// It is never GPU performance credit.
    pub monolithic_host_baseline: bool,
    pub persisted_executor: bool,
    pub gpu_performance_credit: bool,
    pub admitted_available_host_bytes: u64,
    pub admitted_available_spill_bytes: u64,
    pub monolithic_retained_lower_bound_bytes: u64,
    pub pooled_pcg: bool,
    pub response_num_variables: usize,
    pub plan_num_variables: usize,
    pub response_claim_count: usize,
    pub plan_claim_count: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub strict_payload_max_bytes: usize,
    /// C6SBA1 bytes for the scaled executable relation fixture.
    pub arithmetic_payload_bytes: usize,
    /// Scaled C6SBA1 plus the strict two-oracle C6SMO1 artifact.
    pub total_provider_payload_bytes: usize,
    pub response_target_correction_bytes: u64,
    /// QuickSilver triples in the scaled executable relation fixture.
    pub arithmetic_product_triples: usize,
    /// Arithmetic rows folded into the one existing WHIR ZeroOpen.
    pub folded_zero_rows: usize,
    /// Wire ledger, including C6SBA1 bodies but excluding its framing.
    pub provider_transcript_bytes: u64,
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub native_challenges_shared: bool,
    pub postproof_batching_challenge_identical: bool,
    pub plan_reserved_tag_is_zero: bool,
    pub codec_mutations_rejected: bool,
    pub arithmetic_payload_mutation_rejected: bool,
    pub joint_tag_mutation_rejected: bool,
    pub role_separated_compact_verifier_checked: bool,
    pub subfield_correlations: u64,
    pub full_correlations: u64,
    pub response_spill: C61PersistedMmcsMetrics,
    pub plan_spill: C61PersistedMmcsMetrics,
}

pub const C61_PRODUCTION_COMPILER_PROOF_MAGIC: [u8; 8] = *b"C6CPX2\0\0";
pub const C61_PRODUCTION_COMPILER_PROOF_VERSION: u16 = 2;
pub const C61_JOINT_COMPILER_PROOF_MAGIC: [u8; 8] = *b"C6CPX3\0\0";
pub const C61_JOINT_COMPILER_PROOF_VERSION: u16 = 3;
const C61_PRODUCTION_COMPILER_PROOF_HEADER_BYTES: usize = 148;
const C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES: usize = 32;
pub const C61_COMPILER_VERIFIER_SETUP_CAP_BYTES: u64 = 8_000_000;

/// Response-independent compiler verifier state retained by the client.
/// It deliberately contains neither the installed operation plan nor the
/// physical D27 plan oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61CompilerVerifierProfile {
    operation_plan_digest: [u8; 32],
    topology: C6OperationPlanTopologyIdentity,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    base_domain_log2: u8,
    response_parameter_digest: [u8; 32],
    plan_parameter_digest: [u8; 32],
    encoded_setup_bytes: u64,
    digest: [u8; 32],
}

impl C61CompilerVerifierProfile {
    pub fn new(terminal_metadata: C6OperationPlanTerminalMetadata) -> Result<Self, String> {
        let topology = terminal_metadata.topology();
        let operation_plan_digest = terminal_metadata.operation_plan_artifact_digest();
        let base_domain_log2 =
            volta_proto::c6_residual::c6_sparse_rational_base_domain_log2_compact(topology)
                .map_err(|error| error.to_string())?;
        if base_domain_log2 != 25 {
            return Err(
                "C6SPR11 production compiler profile must use the canonical D25 base".to_owned()
            );
        }
        let response_parameter_digest = c61_authenticated_p3_parameter_digest(28)?;
        let plan_parameter_digest = c61_authenticated_p3_parameter_digest(27)?;
        // Strict persisted bytes: the canonical terminal projection plus the
        // fixed profile header/digests.  This excludes the separately counted
        // extraction map but includes every byte owned by this profile.
        let encoded_setup_bytes = terminal_metadata
            .encoded_len()
            .map_err(|error| error.to_string())?
            .checked_add(8 + 2 + 2 + 32 * 4 + 1 + 7)
            .ok_or_else(|| "C6SPR11 compact setup census overflows".to_owned())?;
        if encoded_setup_bytes > C61_COMPILER_VERIFIER_SETUP_CAP_BYTES {
            return Err("C6SPR11 compact compiler profile exceeds the 8-MB allocation".to_owned());
        }
        let mut profile = Self {
            operation_plan_digest,
            topology,
            terminal_metadata,
            base_domain_log2,
            response_parameter_digest,
            plan_parameter_digest,
            encoded_setup_bytes,
            digest: [0; 32],
        };
        profile.digest = profile.recompute_digest();
        profile.validate()?;
        Ok(profile)
    }

    pub fn operation_plan_digest(&self) -> [u8; 32] {
        self.operation_plan_digest
    }

    pub fn topology(&self) -> C6OperationPlanTopologyIdentity {
        self.topology
    }

    pub fn terminal_metadata(&self) -> &C6OperationPlanTerminalMetadata {
        &self.terminal_metadata
    }

    pub fn base_domain_log2(&self) -> u8 {
        self.base_domain_log2
    }

    pub fn response_parameter_digest(&self) -> [u8; 32] {
        self.response_parameter_digest
    }

    pub fn plan_parameter_digest(&self) -> [u8; 32] {
        self.plan_parameter_digest
    }

    pub fn encoded_setup_bytes(&self) -> u64 {
        self.encoded_setup_bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.1/compiler-verifier-profile/v1");
        hasher.update(&self.operation_plan_digest);
        hasher.update(&self.topology.topology_digest);
        hasher.update(&self.terminal_metadata.digest());
        hasher.update(&[self.base_domain_log2]);
        hasher.update(&self.response_parameter_digest);
        hasher.update(&self.plan_parameter_digest);
        hasher.update(&self.encoded_setup_bytes.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn validate(&self) -> Result<(), String> {
        if self.operation_plan_digest == [0; 32]
            || self.operation_plan_digest != self.terminal_metadata.operation_plan_artifact_digest()
            || self.topology != self.terminal_metadata.topology()
            || self.base_domain_log2 != 25
            || self.response_parameter_digest != c61_authenticated_p3_parameter_digest(28)?
            || self.plan_parameter_digest != c61_authenticated_p3_parameter_digest(27)?
            || self.encoded_setup_bytes > C61_COMPILER_VERIFIER_SETUP_CAP_BYTES
            || self.digest == [0; 32]
            || self.digest != self.recompute_digest()
        {
            return Err("C6SPR11 compiler verifier profile is noncanonical".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionCompilerChainProof {
    terminal_binding_digest: [u8; 32],
    plan_folds: [Fp2; 2],
    physical_plan_fold_values: [Fp2; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS],
    arithmetic_payload: Vec<u8>,
    shared_payload: Vec<u8>,
}

impl C61ProductionCompilerChainProof {
    pub fn terminal_binding_digest(&self) -> [u8; 32] {
        self.terminal_binding_digest
    }

    pub fn plan_folds(&self) -> [Fp2; 2] {
        self.plan_folds
    }

    pub fn physical_plan_fold_values(&self) -> [Fp2; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS] {
        self.physical_plan_fold_values
    }

    pub fn arithmetic_payload(&self) -> &[u8] {
        &self.arithmetic_payload
    }

    pub fn shared_payload(&self) -> &[u8] {
        &self.shared_payload
    }

    pub fn encoded_len(&self) -> usize {
        C61_PRODUCTION_COMPILER_PROOF_HEADER_BYTES
            + self.arithmetic_payload.len()
            + self.shared_payload.len()
            + C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.terminal_binding_digest == [0; 32]
            || self.arithmetic_payload.is_empty()
            || self.shared_payload.is_empty()
            || self.arithmetic_payload.len() > 500_000
            || self.shared_payload.len() > C61_SHARED_MULTI_ORACLE_MAX_BYTES
        {
            return Err("C6CPX2 proof shape is noncanonical".to_owned());
        }
        let arithmetic_len = u32::try_from(self.arithmetic_payload.len())
            .map_err(|_| "C6CPX2 arithmetic payload exceeds u32".to_owned())?;
        let shared_len = u32::try_from(self.shared_payload.len())
            .map_err(|_| "C6CPX2 shared payload exceeds u32".to_owned())?;
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&C61_PRODUCTION_COMPILER_PROOF_MAGIC);
        bytes.extend_from_slice(&C61_PRODUCTION_COMPILER_PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.terminal_binding_digest);
        for value in self.plan_folds {
            bytes.extend_from_slice(&value.c0.value().to_le_bytes());
            bytes.extend_from_slice(&value.c1.value().to_le_bytes());
        }
        for value in self.physical_plan_fold_values {
            bytes.extend_from_slice(&value.c0.value().to_le_bytes());
            bytes.extend_from_slice(&value.c1.value().to_le_bytes());
        }
        bytes.extend_from_slice(&arithmetic_len.to_le_bytes());
        bytes.extend_from_slice(&shared_len.to_le_bytes());
        bytes.extend_from_slice(&self.arithmetic_payload);
        bytes.extend_from_slice(&self.shared_payload);
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        debug_assert_eq!(bytes.len(), self.encoded_len());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len()
            < C61_PRODUCTION_COMPILER_PROOF_HEADER_BYTES
                + C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES
        {
            return Err("truncated C6CPX2 proof".to_owned());
        }
        let payload_end = bytes.len() - C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES;
        if blake3::hash(&bytes[..payload_end]).as_bytes() != &bytes[payload_end..] {
            return Err("C6CPX2 proof digest mismatch".to_owned());
        }
        let mut offset = 0usize;
        let mut take = |count: usize| -> Result<&[u8], String> {
            let end = offset
                .checked_add(count)
                .filter(|end| *end <= payload_end)
                .ok_or_else(|| "truncated C6CPX2 field".to_owned())?;
            let field = &bytes[offset..end];
            offset = end;
            Ok(field)
        };
        if take(8)? != C61_PRODUCTION_COMPILER_PROOF_MAGIC
            || u16::from_le_bytes(take(2)?.try_into().expect("fixed C6CPX2 version"))
                != C61_PRODUCTION_COMPILER_PROOF_VERSION
            || u16::from_le_bytes(take(2)?.try_into().expect("fixed C6CPX2 reserved")) != 0
        {
            return Err("C6CPX2 header mismatch".to_owned());
        }
        let terminal_binding_digest = take(32)?.try_into().expect("fixed C6CPX2 digest");
        let mut plan_folds = [Fp2::ZERO; 2];
        for value in &mut plan_folds {
            let c0 = u64::from_le_bytes(take(8)?.try_into().expect("fixed C6CPX2 c0"));
            let c1 = u64::from_le_bytes(take(8)?.try_into().expect("fixed C6CPX2 c1"));
            if c0 >= P || c1 >= P {
                return Err("noncanonical C6CPX2 field element".to_owned());
            }
            *value = Fp2::new(Fp::new(c0), Fp::new(c1));
        }
        let mut physical_plan_fold_values = [Fp2::ZERO; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS];
        for value in &mut physical_plan_fold_values {
            let c0 = u64::from_le_bytes(take(8)?.try_into().expect("fixed C6CPX2 c0"));
            let c1 = u64::from_le_bytes(take(8)?.try_into().expect("fixed C6CPX2 c1"));
            if c0 >= P || c1 >= P {
                return Err("noncanonical C6CPX2 physical field element".to_owned());
            }
            *value = Fp2::new(Fp::new(c0), Fp::new(c1));
        }
        let arithmetic_len =
            u32::from_le_bytes(take(4)?.try_into().expect("fixed C6CPX2 arithmetic length"))
                as usize;
        let shared_len =
            u32::from_le_bytes(take(4)?.try_into().expect("fixed C6CPX2 shared length")) as usize;
        if arithmetic_len == 0
            || arithmetic_len > 500_000
            || shared_len == 0
            || shared_len > C61_SHARED_MULTI_ORACLE_MAX_BYTES
            || C61_PRODUCTION_COMPILER_PROOF_HEADER_BYTES + arithmetic_len + shared_len
                != payload_end
        {
            return Err("C6CPX2 payload lengths are noncanonical".to_owned());
        }
        let arithmetic_payload = take(arithmetic_len)?.to_vec();
        let shared_payload = take(shared_len)?.to_vec();
        let proof = Self {
            terminal_binding_digest,
            plan_folds,
            physical_plan_fold_values,
            arithmetic_payload,
            shared_payload,
        };
        if proof.encode()? != bytes {
            return Err("noncanonical C6CPX2 encoding".to_owned());
        }
        Ok(proof)
    }
}

/// Wire-neutral compiler semantic version bound to the post-body native
/// schedule and exact compiled target functional. The two digests live in the
/// C6PA2 statement and are verifier inputs, not duplicated provider bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointCompilerChainProof {
    inner: C61ProductionCompilerChainProof,
    body_schedule_digest: [u8; 32],
    functional_digest: [u8; 32],
}

impl C61ProductionJointCompilerChainProof {
    pub fn new(
        inner: C61ProductionCompilerChainProof,
        body_schedule_digest: [u8; 32],
        functional_digest: [u8; 32],
    ) -> Result<Self, String> {
        if body_schedule_digest == [0; 32] || functional_digest == [0; 32] {
            return Err("C6CPX3 compiler binding contains a zero digest".to_owned());
        }
        Ok(Self { inner, body_schedule_digest, functional_digest })
    }

    pub fn inner(&self) -> &C61ProductionCompilerChainProof {
        &self.inner
    }

    pub fn body_schedule_digest(&self) -> [u8; 32] {
        self.body_schedule_digest
    }

    pub fn functional_digest(&self) -> [u8; 32] {
        self.functional_digest
    }

    pub fn encoded_len(&self) -> usize {
        self.inner.encoded_len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bytes = self.inner.encode()?;
        let digest_offset = bytes.len() - C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES;
        bytes[..8].copy_from_slice(&C61_JOINT_COMPILER_PROOF_MAGIC);
        bytes[8..10].copy_from_slice(&C61_JOINT_COMPILER_PROOF_VERSION.to_le_bytes());
        let digest = blake3::hash(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        body_schedule_digest: [u8; 32],
        functional_digest: [u8; 32],
    ) -> Result<Self, String> {
        if bytes.len()
            < C61_PRODUCTION_COMPILER_PROOF_HEADER_BYTES
                + C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES
            || bytes[..8] != C61_JOINT_COMPILER_PROOF_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed C6CPX3 version"))
                != C61_JOINT_COMPILER_PROOF_VERSION
        {
            return Err("C6CPX3 header/version mismatch".to_owned());
        }
        let digest_offset = bytes.len() - C61_PRODUCTION_COMPILER_PROOF_DIGEST_BYTES;
        if blake3::hash(&bytes[..digest_offset]).as_bytes() != &bytes[digest_offset..] {
            return Err("C6CPX3 proof digest mismatch".to_owned());
        }
        let mut ordinary = bytes.to_vec();
        ordinary[..8].copy_from_slice(&C61_PRODUCTION_COMPILER_PROOF_MAGIC);
        ordinary[8..10].copy_from_slice(&C61_PRODUCTION_COMPILER_PROOF_VERSION.to_le_bytes());
        let digest = blake3::hash(&ordinary[..digest_offset]);
        ordinary[digest_offset..].copy_from_slice(digest.as_bytes());
        let proof = Self::new(
            C61ProductionCompilerChainProof::decode(&ordinary)?,
            body_schedule_digest,
            functional_digest,
        )?;
        if proof.encode()? != bytes {
            return Err("noncanonical C6CPX3 proof".to_owned());
        }
        Ok(proof)
    }
}

pub struct C61ProductionCompilerChainExecution {
    public: Option<C61TypedNativeChainPublicStatement>,
    pub proof: C61ProductionCompilerChainProof,
    pub report: C61AuthenticatedP3SharedMultiOracleDiagnostic,
}

impl C61ProductionCompilerChainExecution {
    /// Production executions always retain their exact typed public
    /// statement. Scaled diagnostics deliberately have no production
    /// statement because their D14/D13 commitments cannot be reinterpreted
    /// as the registered D28/D27 relation.
    pub fn public(&self) -> Result<&C61TypedNativeChainPublicStatement, String> {
        self.public.as_ref().ok_or_else(|| {
            "scaled compiler execution has no production public statement".to_owned()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionCompilerChainVerification {
    pub id: C61NativeChainId,
    pub response_num_variables: usize,
    pub plan_num_variables: usize,
    pub response_claim_count: usize,
    pub plan_claim_count: usize,
    pub strict_payload_bytes: usize,
    pub arithmetic_payload_bytes: usize,
    pub verifier_interaction: C61WhirInteractionStats,
    pub verifier_transcript_bytes: u64,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub compact_profile_digest: [u8; 32],
    pub compact_profile_setup_bytes: u64,
    pub client_setup_allocation_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C61ProductionNativeChainProof {
    Committed(C61ProductionCommittedChainProof),
    Compiler(C61ProductionCompilerChainProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionNativeChainArtifact {
    id: C61NativeChainId,
    proof: C61ProductionNativeChainProof,
}

impl C61ProductionNativeChainArtifact {
    pub fn committed(
        id: C61NativeChainId,
        proof: C61ProductionCommittedChainProof,
    ) -> Result<Self, String> {
        if id.component == C61NativeComponent::Compiler || id.repetition >= 2 {
            return Err("C6SPR11 committed artifact has a non-model/embed identity".to_owned());
        }
        Ok(Self { id, proof: C61ProductionNativeChainProof::Committed(proof) })
    }

    pub fn compiler(
        id: C61NativeChainId,
        proof: C61ProductionCompilerChainProof,
    ) -> Result<Self, String> {
        if id.component != C61NativeComponent::Compiler || id.repetition >= 2 {
            return Err("C6SPR11 compiler artifact has a non-compiler identity".to_owned());
        }
        Ok(Self { id, proof: C61ProductionNativeChainProof::Compiler(proof) })
    }

    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    fn payload(&self) -> Result<Vec<u8>, String> {
        match &self.proof {
            C61ProductionNativeChainProof::Committed(proof) => Ok(proof.payload.clone()),
            C61ProductionNativeChainProof::Compiler(proof) => proof.encode(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionPublicArgumentAssembly {
    argument: C61PublicArgument,
    encoded: Vec<u8>,
    native_payload_bytes: [usize; C61_NATIVE_CHAIN_COUNT],
}

impl C61ProductionPublicArgumentAssembly {
    pub fn argument(&self) -> &C61PublicArgument {
        &self.argument
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub fn native_payload_bytes(&self) -> [usize; C61_NATIVE_CHAIN_COUNT] {
        self.native_payload_bytes
    }

    pub fn outer_framing_bytes(&self) -> usize {
        C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
    }

    pub fn arithmetic_frame_bytes(&self) -> usize {
        C61_ARITHMETIC_FRAME_BYTES
    }
}

/// Assemble the exact ordered production C6PA1 object from four committed
/// model/embed chains, two compiler C6CPX2 chains and one C6RSC4 frame.
pub fn assemble_c61_production_public_argument(
    statement_digest: [u8; 32],
    chains: [C61ProductionNativeChainArtifact; C61_NATIVE_CHAIN_COUNT],
    arithmetic: C61ArithmeticFrame,
) -> Result<C61ProductionPublicArgumentAssembly, String> {
    if statement_digest == [0; 32] || arithmetic.statement_digest != statement_digest {
        return Err("C6SPR11 C6PA1/C6RSC4 statement digest mismatch".to_owned());
    }
    let arithmetic = arithmetic.encode();
    let mut payloads: [Vec<u8>; C61_NATIVE_CHAIN_COUNT] = std::array::from_fn(|_| Vec::new());
    for (index, (expected, artifact)) in
        C61NativeChainId::ordered().into_iter().zip(chains).enumerate()
    {
        if artifact.id != expected {
            return Err("C6SPR11 production native chains are not in canonical order".to_owned());
        }
        payloads[index] = artifact.payload()?;
    }
    let native_payload_bytes = std::array::from_fn(|index| payloads[index].len());
    let argument = C61PublicArgument::new(statement_digest, payloads, arithmetic)
        .map_err(|error| error.to_string())?;
    let encoded = argument.encode().map_err(|error| error.to_string())?;
    let decoded = C61PublicArgument::decode(&encoded).map_err(|error| error.to_string())?;
    if decoded != argument {
        return Err("C6SPR11 decoded C6PA1 differs from its exact assembly".to_owned());
    }
    Ok(C61ProductionPublicArgumentAssembly { argument, encoded, native_payload_bytes })
}

/// Strictly decode every nested production chain against its typed public
/// statement.  The caller subsequently runs the role-specific verifiers on
/// these exact proof objects; parsing alone never grants proof acceptance.
pub fn decode_c61_production_public_argument(
    bytes: &[u8],
    public: &[C61TypedNativeChainPublicStatement; C61_NATIVE_CHAIN_COUNT],
) -> Result<
    (
        C61PublicArgument,
        [C61ProductionNativeChainArtifact; C61_NATIVE_CHAIN_COUNT],
        C61ArithmeticFrame,
    ),
    String,
> {
    let argument = C61PublicArgument::decode(bytes).map_err(|error| error.to_string())?;
    let mut artifacts = Vec::with_capacity(C61_NATIVE_CHAIN_COUNT);
    for (index, id) in C61NativeChainId::ordered().into_iter().enumerate() {
        if public[index].id() != id {
            return Err("C6SPR11 typed native statements are not in canonical order".to_owned());
        }
        let rebuilt = C61TypedNativeChainPublicStatement::new(id, public[index].relation().clone())
            .map_err(|error| error.to_string())?;
        if rebuilt != public[index] {
            return Err("C6SPR11 typed native statement is noncanonical".to_owned());
        }
        let payload = &argument.native_chains()[index];
        let artifact = if id.component == C61NativeComponent::Compiler {
            C61ProductionNativeChainArtifact::compiler(
                id,
                C61ProductionCompilerChainProof::decode(payload)?,
            )?
        } else {
            C61ProductionNativeChainArtifact::committed(
                id,
                C61ProductionCommittedChainProof::decode(payload, &public[index])?,
            )?
        };
        artifacts.push(artifact);
    }
    let artifacts: [C61ProductionNativeChainArtifact; C61_NATIVE_CHAIN_COUNT] = artifacts
        .try_into()
        .map_err(|_| "C6SPR11 decoded native-chain census mismatch".to_owned())?;
    let arithmetic =
        C61ArithmeticFrame::decode(argument.arithmetic()).map_err(|error| error.to_string())?;
    if arithmetic.statement_digest != argument.statement_digest() {
        return Err("C6SPR11 decoded C6RSC4 differs from C6PA1 statement".to_owned());
    }
    for statement in &public[4..] {
        let compiler = match statement.relation() {
            C61TypedNativeRelationStatement::Compiler(statement) => statement,
            _ => {
                return Err("C6SPR11 final native statements are not compiler relations".to_owned())
            }
        };
        if compiler.terminal_claims != arithmetic.terminal_claims {
            return Err("C6SPR11 C6RSC4 terminal values differ from compiler statements".to_owned());
        }
    }
    Ok((argument, artifacts, arithmetic))
}

/// Exact C6PA2 component kinds. Primary model/embed chains retain C6AWP1;
/// secondary chains use C6AWP2 and compiler chains use C6CPX3. Keeping this
/// separate from the historical C6PA1 enum prevents semantic-version
/// confusion even though every replacement is wire-neutral.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C61ProductionJointNativeChainProof {
    CommittedPrimary(C61ProductionCommittedChainProof),
    CommittedSecondary(C61ProductionJointCommittedChainProof),
    Compiler(C61ProductionJointCompilerChainProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointNativeChainArtifact {
    id: C61NativeChainId,
    proof: C61ProductionJointNativeChainProof,
}

impl C61ProductionJointNativeChainArtifact {
    pub fn committed_primary(
        id: C61NativeChainId,
        proof: C61ProductionCommittedChainProof,
    ) -> Result<Self, String> {
        if id.component == C61NativeComponent::Compiler || id.repetition != 0 {
            return Err("C6PA2 primary artifact has a non-primary identity".to_owned());
        }
        Ok(Self { id, proof: C61ProductionJointNativeChainProof::CommittedPrimary(proof) })
    }

    pub fn committed_secondary(
        id: C61NativeChainId,
        proof: C61ProductionJointCommittedChainProof,
    ) -> Result<Self, String> {
        if id.component == C61NativeComponent::Compiler || id.repetition != 1 {
            return Err("C6PA2 secondary artifact has a non-secondary identity".to_owned());
        }
        Ok(Self { id, proof: C61ProductionJointNativeChainProof::CommittedSecondary(proof) })
    }

    pub fn compiler(
        id: C61NativeChainId,
        proof: C61ProductionJointCompilerChainProof,
    ) -> Result<Self, String> {
        if id.component != C61NativeComponent::Compiler || id.repetition >= 2 {
            return Err("C6PA2 compiler artifact has a non-compiler identity".to_owned());
        }
        Ok(Self { id, proof: C61ProductionJointNativeChainProof::Compiler(proof) })
    }

    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    pub fn proof(&self) -> &C61ProductionJointNativeChainProof {
        &self.proof
    }

    pub fn into_proof(self) -> C61ProductionJointNativeChainProof {
        self.proof
    }

    fn payload(&self) -> Result<Vec<u8>, String> {
        match &self.proof {
            C61ProductionJointNativeChainProof::CommittedPrimary(proof) => {
                Ok(proof.payload.clone())
            }
            C61ProductionJointNativeChainProof::CommittedSecondary(proof) => {
                Ok(proof.payload.clone())
            }
            C61ProductionJointNativeChainProof::Compiler(proof) => proof.encode(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointPublicArgumentAssembly {
    argument: C61JointPublicArgument,
    encoded: Vec<u8>,
    native_payload_bytes: [usize; C61_NATIVE_CHAIN_COUNT],
}

impl C61ProductionJointPublicArgumentAssembly {
    pub fn argument(&self) -> &C61JointPublicArgument {
        &self.argument
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub fn native_payload_bytes(&self) -> [usize; C61_NATIVE_CHAIN_COUNT] {
        self.native_payload_bytes
    }
}

fn c61_joint_tail_role_for_component(
    profile: &C6CanonicalTargetProfile,
    component: C61NativeComponent,
) -> Result<C61JointNativeTailRole, String> {
    let mut matches = profile
        .cohorts
        .iter()
        .enumerate()
        .filter(|(_, cohort)| cohort.chain_slot == component as u16);
    let (index, _) = matches
        .next()
        .ok_or_else(|| "C6PA2 target profile omits a secondary native component".to_owned())?;
    if matches.next().is_some() {
        return Err("C6PA2 target profile duplicates a secondary native component".to_owned());
    }
    Ok(match index {
        0 => C61JointNativeTailRole::Correction,
        1 => C61JointNativeTailRole::ZeroOpenTag,
        _ => C61JointNativeTailRole::Reserved,
    })
}

/// Assemble the exact ordered production C6PA2 object. The generic target
/// profile, rather than a GPT-2 claim census, assigns the secondary carrier
/// roles. C6PA1 components are rejected even where their byte lengths match.
pub fn assemble_c61_production_joint_public_argument(
    statement_digest: [u8; 32],
    profile: &C6CanonicalTargetProfile,
    chains: [C61ProductionJointNativeChainArtifact; C61_NATIVE_CHAIN_COUNT],
    arithmetic: C61ArithmeticFrame,
) -> Result<C61ProductionJointPublicArgumentAssembly, String> {
    if statement_digest == [0; 32] || arithmetic.statement_digest != statement_digest {
        return Err("C6PA2/C6RSC4 statement digest mismatch".to_owned());
    }
    let arithmetic = arithmetic.encode();
    let mut payloads: [Vec<u8>; C61_NATIVE_CHAIN_COUNT] = std::array::from_fn(|_| Vec::new());
    for (index, (expected, artifact)) in
        C61NativeChainId::ordered().into_iter().zip(chains).enumerate()
    {
        if artifact.id != expected {
            return Err("C6PA2 native chains are not in canonical order".to_owned());
        }
        match (&artifact.proof, expected.component, expected.repetition) {
            (C61ProductionJointNativeChainProof::CommittedPrimary(_), component, 0)
                if component != C61NativeComponent::Compiler => {}
            (C61ProductionJointNativeChainProof::CommittedSecondary(proof), component, 1)
                if component != C61NativeComponent::Compiler
                    && proof.tail_role()
                        == c61_joint_tail_role_for_component(profile, component)? => {}
            (C61ProductionJointNativeChainProof::Compiler(_), C61NativeComponent::Compiler, _) => {}
            _ => {
                return Err("C6PA2 native chain semantic version or carrier role differs".to_owned())
            }
        }
        payloads[index] = artifact.payload()?;
    }
    let native_payload_bytes = std::array::from_fn(|index| payloads[index].len());
    let argument = C61JointPublicArgument::new(statement_digest, payloads, arithmetic)
        .map_err(|error| error.to_string())?;
    let encoded = argument.encode().map_err(|error| error.to_string())?;
    let decoded = C61JointPublicArgument::decode(&encoded).map_err(|error| error.to_string())?;
    if decoded != argument {
        return Err("decoded C6PA2 differs from its exact assembly".to_owned());
    }
    Ok(C61ProductionJointPublicArgumentAssembly { argument, encoded, native_payload_bytes })
}

/// Consume the actual production executions into one canonical C6PA2 wire
/// object. The statement digest is derived here from the base statement,
/// installed C6NTO1 artifact, post-body schedule and compiler functional;
/// callers cannot attach those executions to an arbitrary outer digest.
#[allow(clippy::too_many_arguments)]
pub fn assemble_c61_production_joint_public_argument_from_executions(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    profile: &C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    secondary: C61ProductionJointNativeProverExecution,
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: C61ArithmeticFrame,
) -> Result<C61ProductionJointPublicArgumentAssembly, String> {
    let schedule_digest = secondary.challenge.schedule_digest;
    if secondary.proofs.len() != profile.cohorts.len() {
        return Err("C6PA2 secondary proof/profile census mismatch".to_owned());
    }
    if functional_digest == [0; 32] {
        return Err("C6PA2 compiler functional binding is zero".to_owned());
    }
    let statement_digest = c61_joint_public_statement_digest(
        base_statement_digest,
        native_profile_digest,
        schedule_digest,
        functional_digest,
    )
    .map_err(|error| error.to_string())?;
    if arithmetic.statement_digest != statement_digest {
        return Err("C6PA2 execution assembly received a different C6RSC4 statement".to_owned());
    }

    for (repetition, execution) in compiler.iter().enumerate() {
        let public = execution.public()?;
        let expected = C61NativeChainId {
            component: C61NativeComponent::Compiler,
            repetition: repetition as u8,
        };
        let compiler_statement = match public.relation() {
            C61TypedNativeRelationStatement::Compiler(statement) if public.id() == expected => {
                statement.as_ref()
            }
            _ => return Err("C6PA2 compiler execution has a noncanonical typed role".to_owned()),
        };
        if compiler_statement.terminal_claims != arithmetic.terminal_claims
            || compiler_statement.relation_root != arithmetic.adjoint_root
            || compiler_statement.functional_fold != arithmetic.source_boundary
        {
            return Err("C6PA2 compiler statement differs from the exact C6RSC4 relation"
                .to_owned());
        }
    }
    if compiler[0].public()?.relation() != compiler[1].public()?.relation() {
        return Err("C6PA2 compiler repetitions prove different public relations".to_owned());
    }

    let [model_primary, embedding_primary] = primary;
    let expected_primary = [
        C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
        C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 0 },
    ];
    if [model_primary.report.id, embedding_primary.report.id] != expected_primary {
        return Err("C6PA2 primary executions are not model0/embed0".to_owned());
    }

    let mut model_secondary = None;
    let mut embedding_secondary = None;
    for (index, (cohort, proof)) in profile.cohorts.iter().zip(secondary.proofs).enumerate() {
        if proof.tail_role() != c61_joint_native_carrier_tail(secondary.frame, index).0 {
            return Err("C6PA2 secondary execution carrier role differs from its cohort".to_owned());
        }
        match cohort.chain_slot {
            slot if slot == C61NativeComponent::Model as u16 && model_secondary.is_none() => {
                model_secondary = Some(proof)
            }
            slot if slot == C61NativeComponent::Embedding as u16
                && embedding_secondary.is_none() =>
            {
                embedding_secondary = Some(proof)
            }
            _ => {
                return Err(
                    "C6PA2 secondary execution has an unsupported or duplicate slot".to_owned()
                )
            }
        }
    }
    let model_secondary = model_secondary
        .ok_or_else(|| "C6PA2 secondary execution omits the model cohort".to_owned())?;
    let embedding_secondary = embedding_secondary
        .ok_or_else(|| "C6PA2 secondary execution omits the embedding cohort".to_owned())?;
    let [compiler0, compiler1] = compiler;
    let chains = [
        C61ProductionJointNativeChainArtifact::committed_primary(
            expected_primary[0],
            model_primary.proof,
        )?,
        C61ProductionJointNativeChainArtifact::committed_secondary(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            model_secondary,
        )?,
        C61ProductionJointNativeChainArtifact::committed_primary(
            expected_primary[1],
            embedding_primary.proof,
        )?,
        C61ProductionJointNativeChainArtifact::committed_secondary(
            C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
            embedding_secondary,
        )?,
        C61ProductionJointNativeChainArtifact::compiler(
            C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
            C61ProductionJointCompilerChainProof::new(
                compiler0.proof,
                schedule_digest,
                functional_digest,
            )?,
        )?,
        C61ProductionJointNativeChainArtifact::compiler(
            C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 },
            C61ProductionJointCompilerChainProof::new(
                compiler1.proof,
                schedule_digest,
                functional_digest,
            )?,
        )?,
    ];
    assemble_c61_production_joint_public_argument(statement_digest, profile, chains, arithmetic)
}

/// Decode all C6PA2 children under their typed statements and the two
/// statement-resident C6CPX3 bindings. Parsing remains distinct from native,
/// compiler, C6NBR2 and joint-ZeroOpen acceptance.
#[allow(clippy::type_complexity)]
pub fn decode_c61_production_joint_public_argument(
    bytes: &[u8],
    public: &[C61TypedNativeChainPublicStatement; C61_NATIVE_CHAIN_COUNT],
    profile: &C6CanonicalTargetProfile,
    body_schedule_digest: [u8; 32],
    functional_digest: [u8; 32],
) -> Result<
    (
        C61JointPublicArgument,
        [C61ProductionJointNativeChainArtifact; C61_NATIVE_CHAIN_COUNT],
        C61ArithmeticFrame,
    ),
    String,
> {
    if body_schedule_digest == [0; 32] || functional_digest == [0; 32] {
        return Err("C6PA2 compiler statement binding is empty".to_owned());
    }
    let argument = C61JointPublicArgument::decode(bytes).map_err(|error| error.to_string())?;
    let mut artifacts = Vec::with_capacity(C61_NATIVE_CHAIN_COUNT);
    for (index, id) in C61NativeChainId::ordered().into_iter().enumerate() {
        if public[index].id() != id {
            return Err("C6PA2 typed native statements are not in canonical order".to_owned());
        }
        let rebuilt = C61TypedNativeChainPublicStatement::new(id, public[index].relation().clone())
            .map_err(|error| error.to_string())?;
        if rebuilt != public[index] {
            return Err("C6PA2 typed native statement is noncanonical".to_owned());
        }
        let payload = &argument.native_chains()[index];
        let artifact = match (id.component, id.repetition) {
            (C61NativeComponent::Compiler, _) => C61ProductionJointNativeChainArtifact::compiler(
                id,
                C61ProductionJointCompilerChainProof::decode(
                    payload,
                    body_schedule_digest,
                    functional_digest,
                )?,
            )?,
            (_, 0) => C61ProductionJointNativeChainArtifact::committed_primary(
                id,
                C61ProductionCommittedChainProof::decode(payload, &public[index])?,
            )?,
            (component, 1) => {
                let role = c61_joint_tail_role_for_component(profile, component)?;
                C61ProductionJointNativeChainArtifact::committed_secondary(
                    id,
                    C61ProductionJointCommittedChainProof::decode(payload, &public[index], role)?,
                )?
            }
            _ => return Err("C6PA2 native identity is outside the six-chain profile".to_owned()),
        };
        artifacts.push(artifact);
    }
    let artifacts: [C61ProductionJointNativeChainArtifact; C61_NATIVE_CHAIN_COUNT] = artifacts
        .try_into()
        .map_err(|_| "decoded C6PA2 native-chain census mismatch".to_owned())?;
    let arithmetic =
        C61ArithmeticFrame::decode(argument.arithmetic()).map_err(|error| error.to_string())?;
    if arithmetic.statement_digest != argument.statement_digest() {
        return Err("decoded C6RSC4 differs from C6PA2 statement".to_owned());
    }
    for statement in &public[4..] {
        let compiler = match statement.relation() {
            C61TypedNativeRelationStatement::Compiler(statement) => statement,
            _ => return Err("C6PA2 final native statements are not compiler relations".to_owned()),
        };
        if compiler.terminal_claims != arithmetic.terminal_claims {
            return Err("C6PA2 terminal values differ from compiler statements".to_owned());
        }
    }
    Ok((argument, artifacts, arithmetic))
}

/// Strict production model/embedding proof boundary.  `payload` is exactly
/// one canonical C6AWP1 chain; this wrapper contributes no additional wire
/// bytes when nested in C6PA1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionCommittedChainProof {
    payload: Vec<u8>,
}

impl C61ProductionCommittedChainProof {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn decode(
        payload: &[u8],
        public: &C61TypedNativeChainPublicStatement,
    ) -> Result<Self, String> {
        let openings = c61_model_embedding_openings(public)?;
        let num_variables = usize::from(openings.commitment.polynomial_domain_log2);
        let (commitment, proof, base_proof) =
            decode_c61_authenticated_p3_artifact_inner(payload, num_variables, true)
                .map_err(|error| error.to_string())?;
        c61_validate_committed_chain_root(public, &commitment)?;
        let canonical = encode_c61_authenticated_p3_artifact_inner(
            num_variables,
            &commitment,
            &proof,
            base_proof,
            true,
        )
        .map_err(|error| error.to_string())?;
        if canonical != payload {
            return Err("noncanonical production C6AWP1 chain".to_owned());
        }
        Ok(Self { payload: payload.to_vec() })
    }
}

/// The fixed semantic use of one 16-byte secondary-chain tail in C6AWP2.
/// Carrier assignment is supplied by the ordered generic cohort profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C61JointNativeTailRole {
    Correction,
    ZeroOpenTag,
    Reserved,
}

pub fn c61_joint_native_carrier_tail(
    frame: C61JointNativeBridgeFrame,
    cohort_index: usize,
) -> (C61JointNativeTailRole, [u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]) {
    let encoded = frame.encode();
    match cohort_index {
        0 => {
            let mut tail = [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES];
            tail.copy_from_slice(&encoded[..C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
            (C61JointNativeTailRole::Correction, tail)
        }
        1 => {
            let mut tail = [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES];
            tail.copy_from_slice(&encoded[C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES..]);
            (C61JointNativeTailRole::ZeroOpenTag, tail)
        }
        _ => (C61JointNativeTailRole::Reserved, [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]),
    }
}

/// A strict C6AWP2 secondary chain. Its WHIR body is byte-for-byte the C6AWP1
/// body under a new semantic header; its tail is accepted only as one part of
/// the outer joint relation and is never an ordinary per-chain proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointCommittedChainProof {
    payload: Vec<u8>,
    tail_role: C61JointNativeTailRole,
}

impl C61ProductionJointCommittedChainProof {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn tagless_payload(&self) -> &[u8] {
        &self.payload[..self.payload.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]
    }

    pub fn tail(&self) -> &[u8] {
        &self.payload[self.payload.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES..]
    }

    pub fn tail_role(&self) -> C61JointNativeTailRole {
        self.tail_role
    }

    pub fn decode(
        payload: &[u8],
        public: &C61TypedNativeChainPublicStatement,
        tail_role: C61JointNativeTailRole,
    ) -> Result<Self, String> {
        if public.id().repetition != 1 {
            return Err("C6AWP2 requires a complete secondary native chain".to_owned());
        }
        let mut ordinary = c61_validate_joint_payload_shape(payload, tail_role)?;
        let tail_start = ordinary.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
        ordinary[tail_start..].fill(0);
        C61ProductionCommittedChainProof::decode(&ordinary, public)?;
        Ok(Self { payload: payload.to_vec(), tail_role })
    }

    pub fn from_parts(
        tagless_payload: &[u8],
        tail: &[u8],
        public: &C61TypedNativeChainPublicStatement,
        tail_role: C61JointNativeTailRole,
    ) -> Result<Self, String> {
        if tail.len() != C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES {
            return Err("C6AWP2 tail has noncanonical length".to_owned());
        }
        let mut payload = tagless_payload.to_vec();
        payload.extend_from_slice(tail);
        Self::decode(&payload, public, tail_role)
    }
}

fn c61_validate_joint_payload_shape(
    payload: &[u8],
    tail_role: C61JointNativeTailRole,
) -> Result<Vec<u8>, String> {
    if payload.len()
        < C61_AUTHENTICATED_P3_HEADER_BYTES + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES
    {
        return Err("C6AWP2 requires a complete secondary native chain".to_owned());
    }
    let tail_start = payload.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
    let tail = &payload[tail_start..];
    C61AuthenticatedWhirBaseProof::decode(tail).map_err(|error| error.to_string())?;
    if tail_role == C61JointNativeTailRole::Reserved && tail.iter().any(|byte| *byte != 0) {
        return Err("C6AWP2 reserved secondary tail is nonzero".to_owned());
    }
    c61_awp1_payload_from_joint(payload)
}

fn c61_joint_tagless_from_awp1(tagless: &[u8]) -> Result<Vec<u8>, String> {
    if tagless.len() < C61_AUTHENTICATED_P3_HEADER_BYTES
        || tagless[..8] != C61_AUTHENTICATED_P3_MAGIC
        || u16::from_le_bytes(tagless[8..10].try_into().expect("fixed C6AWP1 version"))
            != C61_AUTHENTICATED_P3_VERSION
    {
        return Err("C6AWP2 source is not a canonical C6AWP1 tagless body".to_owned());
    }
    let body_len = u32::from_le_bytes(tagless[12..16].try_into().expect("fixed C6AWP1 length"));
    if body_len as usize
        != tagless.len() - C61_AUTHENTICATED_P3_HEADER_BYTES
            + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES
    {
        return Err("C6AWP2 source body length is inconsistent".to_owned());
    }
    let mut joint = tagless.to_vec();
    joint[..8].copy_from_slice(&C61_JOINT_AUTHENTICATED_P3_MAGIC);
    joint[8..10].copy_from_slice(&C61_JOINT_AUTHENTICATED_P3_VERSION.to_le_bytes());
    Ok(joint)
}

fn c61_awp1_payload_from_joint(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len()
        < C61_AUTHENTICATED_P3_HEADER_BYTES + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES
        || payload[..8] != C61_JOINT_AUTHENTICATED_P3_MAGIC
        || u16::from_le_bytes(payload[8..10].try_into().expect("fixed C6AWP2 version"))
            != C61_JOINT_AUTHENTICATED_P3_VERSION
    {
        return Err("C6AWP2 header mismatch".to_owned());
    }
    let body_len = u32::from_le_bytes(payload[12..16].try_into().expect("fixed C6AWP2 length"));
    if body_len as usize != payload.len() - C61_AUTHENTICATED_P3_HEADER_BYTES {
        return Err("C6AWP2 body length mismatch".to_owned());
    }
    let mut ordinary = payload.to_vec();
    ordinary[..8].copy_from_slice(&C61_AUTHENTICATED_P3_MAGIC);
    ordinary[8..10].copy_from_slice(&C61_AUTHENTICATED_P3_VERSION.to_le_bytes());
    Ok(ordinary)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionCommittedChainReport {
    pub id: C61NativeChainId,
    pub num_variables: usize,
    pub claim_count: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub strict_payload_max_bytes: usize,
    pub pooled_pcg: bool,
    pub persisted_executor: bool,
    pub cuda_resident_admission: bool,
    pub gpu_performance_credit: bool,
    pub provider_interaction: C61WhirInteractionStats,
    pub provider_transcript_bytes: u64,
    pub provider_ledger: BTreeMap<&'static str, u64>,
    pub spill: C61PersistedMmcsMetrics,
}

#[derive(Debug)]
pub struct C61ProductionCommittedChainExecution {
    pub statement: C61NativeProverChainStatement,
    pub proof: C61ProductionCommittedChainProof,
    pub report: C61ProductionCommittedChainReport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProviderSessionBinding {
    digest: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProviderJointSessionBinding {
    digest: [u8; 32],
    profile_digest: [u8; 32],
}

fn c61_canonical_target_profile_digest(
    profile: &C6CanonicalTargetProfile,
) -> Result<[u8; 32], String> {
    C61JointNativeBodyScheduleBuilder::new(profile)?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/canonical-target-profile/v1");
    hasher.update(&profile.inference_profile_digest);
    hasher.update(&profile.topology_digest);
    hasher.update(&profile.source_schedule_digest);
    hasher.update(
        &u32::try_from(profile.cohorts.len())
            .map_err(|_| "C6ICT2 target cohort census exceeds u32".to_owned())?
            .to_le_bytes(),
    );
    for cohort in &profile.cohorts {
        hasher.update(&cohort.cohort_id.to_le_bytes());
        hasher.update(&cohort.chain_slot.to_le_bytes());
        hasher.update(&[cohort.polynomial_log2]);
        hasher.update(&cohort.claim_layout_digest);
        hasher.update(
            &u32::try_from(cohort.canonical_nodes.len())
                .map_err(|_| "C6ICT2 target-node census exceeds u32".to_owned())?
                .to_le_bytes(),
        );
        for node in &cohort.canonical_nodes {
            hasher.update(&node.to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

impl C61ProviderJointSessionBinding {
    pub fn from_reserved_attempt(
        attempt: C6ClientAttempt,
        profile: &C6CanonicalTargetProfile,
    ) -> Result<Self, String> {
        attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
        attempt.workload.validate().map_err(|error| error.to_string())?;
        if attempt.setup_manifest_digest == [0; 32]
            || attempt.nonce == [0; 32]
            || attempt.old_head_digest == [0; 32]
        {
            return Err("C6ICT2 joint provider session binding is noncanonical".to_owned());
        }
        let profile_digest = c61_canonical_target_profile_digest(profile)?;
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/provider-joint-session/v1");
        hasher.update(&attempt.slot.to_le_bytes());
        hasher.update(&attempt.nonce);
        hasher.update(&attempt.setup_manifest_digest);
        hasher.update(&attempt.old_head_digest);
        hasher.update(&attempt.predecessor_certificate_digest);
        for range in attempt.correlation_ranges.coordinates {
            hasher.update(&range.stage.to_le_bytes());
            hasher.update(&range.start.to_le_bytes());
            hasher.update(&range.count.to_le_bytes());
        }
        hasher.update(&attempt.workload.digest());
        hasher.update(&profile_digest);
        Ok(Self { digest: *hasher.finalize().as_bytes(), profile_digest })
    }

    fn validate_for(self, profile: &C6CanonicalTargetProfile) -> Result<(), String> {
        if self.profile_digest != c61_canonical_target_profile_digest(profile)? {
            return Err("C6ICT2 joint provider binding uses another target profile".to_owned());
        }
        Ok(())
    }

    pub fn context_digest(self) -> [u8; 32] {
        self.digest
    }
}

impl C61ProviderSessionBinding {
    pub fn from_reserved_attempt(
        attempt: C6ClientAttempt,
        id: C61NativeChainId,
        mask_range: C61AuthenticatedWhirMaskRange,
    ) -> Result<Self, String> {
        attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
        attempt.workload.validate().map_err(|error| error.to_string())?;
        if attempt.setup_manifest_digest == [0; 32]
            || attempt.nonce == [0; 32]
            || attempt.old_head_digest == [0; 32]
            || id.repetition >= 2
        {
            return Err("C6ICT2 provider session binding is noncanonical".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/provider-session/v1");
        hasher.update(&attempt.slot.to_le_bytes());
        hasher.update(&attempt.nonce);
        hasher.update(&attempt.setup_manifest_digest);
        hasher.update(&attempt.old_head_digest);
        hasher.update(&attempt.predecessor_certificate_digest);
        for range in attempt.correlation_ranges.coordinates {
            hasher.update(&range.stage.to_le_bytes());
            hasher.update(&range.start.to_le_bytes());
            hasher.update(&range.count.to_le_bytes());
        }
        hasher.update(&attempt.workload.digest());
        hasher.update(&(id.component as u16).to_le_bytes());
        hasher.update(&[id.repetition, mask_range.stage]);
        hasher.update(&mask_range.slot.to_le_bytes());
        hasher.update(&mask_range.range_start.to_le_bytes());
        Ok(Self { digest: *hasher.finalize().as_bytes(), id, mask_range })
    }

    pub fn context_digest(self) -> [u8; 32] {
        self.digest
    }

    fn validate_for(
        self,
        id: C61NativeChainId,
        mask_range: C61AuthenticatedWhirMaskRange,
    ) -> Result<(), String> {
        if self.id != id || self.mask_range != mask_range {
            return Err("C6ICT2 provider session binding is assigned to another chain".to_owned());
        }
        Ok(())
    }
}

/// Linear provider state after the canonical claimless-WHIR body is fixed
/// and before its 16-byte authenticated tail is emitted. The state is not
/// clonable or serializable; an ordinary or joint closure must consume it.
pub struct C61ProductionCommittedChainProverBody {
    statement: C61NativeProverChainStatement,
    id: C61NativeChainId,
    num_variables: usize,
    claim_count: usize,
    tagless_payload: Vec<u8>,
    tagless_digest: [u8; 32],
    claim_weights: Vec<Fp2>,
    prepared: crate::c61_authenticated_whir::C61AuthenticatedWhirPreparedMask,
    affine: C61AuthenticatedWhirAffineClaim,
    finish_input: C61AuthenticatedWhirProverFinishInput,
    transcript: Transcript,
    provider_interaction: C61WhirInteractionStats,
    strict_payload_max_bytes: usize,
    spill: C61PersistedMmcsMetrics,
}

impl C61ProductionCommittedChainProverBody {
    pub fn statement(&self) -> &C61NativeProverChainStatement {
        &self.statement
    }

    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    pub fn claim_weights(&self) -> &[Fp2] {
        &self.claim_weights
    }

    pub fn tagless_payload(&self) -> &[u8] {
        &self.tagless_payload
    }

    pub fn tagless_digest(&self) -> [u8; 32] {
        self.tagless_digest
    }

    pub fn joint_tagless_payload(&self) -> Result<Vec<u8>, String> {
        if self.id.repetition != 1 {
            return Err("C6AWP2 tagless body requires a secondary chain".to_owned());
        }
        c61_joint_tagless_from_awp1(&self.tagless_payload)
    }

    pub fn joint_tagless_digest(&self) -> Result<[u8; 32], String> {
        Ok(*blake3::hash(&self.joint_tagless_payload()?).as_bytes())
    }

    /// Consume a secondary body into the model-independent joint relation.
    /// The returned term contains no profile-specific target census or name.
    pub fn into_joint_term(
        mut self,
        cohort_weight: Fp2,
    ) -> Result<C61JointNativeProverTerm, String> {
        if self.id.repetition != 1 {
            return Err("C6NBR1 joint prover admits only secondary native bodies".to_owned());
        }
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&self.tagless_payload)?;
        }
        Ok(C61JointNativeProverTerm {
            prepared: self.prepared,
            combined: self.finish_input.combined,
            shifted_masked_claim: self.finish_input.shifted_masked_claim,
            gamma: self.finish_input.gamma,
            affine: self.affine,
            cohort_weight,
        })
    }

    pub fn finish_ordinary(mut self) -> Result<C61ProductionCommittedChainExecution, String> {
        let closure = finish_c61_authenticated_whir_base(
            self.prepared,
            self.finish_input,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        let mut payload = self.tagless_payload;
        payload.extend_from_slice(&closure.proof.encode());
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&payload)?;
        }
        let proof = C61ProductionCommittedChainProof::decode(&payload, self.statement.public())?;
        let report = C61ProductionCommittedChainReport {
            id: self.id,
            num_variables: self.num_variables,
            claim_count: self.claim_count,
            strict_payload_bytes: payload.len(),
            strict_payload_blake3: *blake3::hash(&payload).as_bytes(),
            strict_payload_max_bytes: self.strict_payload_max_bytes,
            pooled_pcg: true,
            persisted_executor: true,
            cuda_resident_admission: true,
            gpu_performance_credit: false,
            provider_interaction: self.provider_interaction,
            provider_transcript_bytes: self.transcript.total_bytes(),
            provider_ledger: self.transcript.ledger().clone(),
            spill: self.spill,
        };
        Ok(C61ProductionCommittedChainExecution { statement: self.statement, proof, report })
    }
}

/// Linear verifier state after replaying and accepting the canonical tagless
/// body. It carries no target plaintext and consumes the verifier PCG only
/// when an ordinary or joint authenticated tail is checked.
pub struct C61ProductionCommittedChainVerifierBody {
    id: C61NativeChainId,
    num_variables: usize,
    claim_count: usize,
    tagless_payload_len: usize,
    tagless_payload: Vec<u8>,
    tagless_digest: [u8; 32],
    claim_weights: Vec<Fp2>,
    aggregate_key: Option<VerifierKey>,
    affine: C61AuthenticatedWhirAffineClaim,
    base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    mask_range: C61AuthenticatedWhirMaskRange,
    transcript: Transcript,
    verifier_interaction: C61WhirInteractionStats,
}

impl C61ProductionCommittedChainVerifierBody {
    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    pub fn claim_weights(&self) -> &[Fp2] {
        &self.claim_weights
    }

    pub fn tagless_digest(&self) -> [u8; 32] {
        self.tagless_digest
    }

    /// Consume a secondary verifier body without target keys. The native mask
    /// key is expanded from verifier-owned pooled PCG state exactly once.
    pub fn into_joint_term(
        mut self,
        cohort_weight: Fp2,
        context: &mut VerifierCtx,
    ) -> Result<C61JointNativeVerifierTerm, String> {
        if self.id.repetition != 1 {
            return Err("C6NBR1 joint verifier admits only secondary native bodies".to_owned());
        }
        if self.aggregate_key.is_some() {
            return Err("C6NBR1 joint verifier body unexpectedly contains target keys".to_owned());
        }
        if !context.uses_pooled_pcg() {
            return Err("C6NBR1 production verifier forbids mock PCG state".to_owned());
        }
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&self.tagless_payload)?;
        }
        let mask_domain =
            self.mask_range.correlation_domain(self.id).map_err(|error| error.to_string())?;
        let mask_key = context
            .expand_full_verifier_keys(mask_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| "C6NBR1 missing verifier mask key".to_owned())?;
        Ok(C61JointNativeVerifierTerm {
            mask_key,
            combined: c61_volta_fp2_from_p3(self.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(self.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(self.base_case.gamma),
            affine: self.affine,
            cohort_weight,
        })
    }

    pub fn finish_ordinary(
        mut self,
        tail: &[u8],
        context: &mut VerifierCtx,
    ) -> Result<C61ProductionCommittedChainVerification, String> {
        if !context.uses_pooled_pcg() {
            return Err("C6SPR13 production verifier tail forbids mock PCG state".to_owned());
        }
        let base_proof =
            C61AuthenticatedWhirBaseProof::decode(tail).map_err(|error| error.to_string())?;
        let aggregate_key = self.aggregate_key.ok_or_else(|| {
            "C6SPR13 ordinary verifier body is missing authenticated target keys".to_owned()
        })?;
        let final_key = self.affine.derive_verifier_key(aggregate_key, context.delta);
        verify_c61_authenticated_whir_base(
            C61AuthenticatedWhirVerifierInput {
                id: self.id,
                mask_range: self.mask_range,
                combined: c61_volta_fp2_from_p3(self.base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(self.base_case.shifted_masked_claim),
                gamma: c61_volta_fp2_from_p3(self.base_case.gamma),
                target: final_key,
            },
            base_proof,
            context,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        if self.transcript.is_interactive() {
            let mut payload = self.tagless_payload;
            payload.extend_from_slice(tail);
            self.transcript.finish_interactive(&payload)?;
        }
        Ok(C61ProductionCommittedChainVerification {
            id: self.id,
            num_variables: self.num_variables,
            claim_count: self.claim_count,
            strict_payload_bytes: self
                .tagless_payload_len
                .checked_add(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
                .ok_or_else(|| "C6SPR13 native-chain payload length overflows".to_owned())?,
            verifier_interaction: self.verifier_interaction,
            verifier_transcript_bytes: self.transcript.total_bytes(),
            verifier_ledger: self.transcript.ledger().clone(),
        })
    }
}

pub struct C61ProductionJointNativeProverBodiesFixed {
    bodies: Vec<C61ProductionCommittedChainProverBody>,
    joint_tagless_payloads: Vec<Vec<u8>>,
    challenge: C61JointNativeChallenge,
    transcript: Transcript,
}

/// C6PA2 prover state after the 16-byte correction is fixed and before the
/// final joint ZeroOpen tail is created. Only a completed C6NBR2 link receipt
/// can advance it.
pub struct C61ProductionJointNativeProverLinkPending {
    statements: Vec<C61TypedNativeChainPublicStatement>,
    joint_tagless_payloads: Vec<Vec<u8>>,
    challenge: C61JointNativeChallenge,
    transcript: Transcript,
    bridge: C61JointNativeProverBridgePending,
    nbr2_statement_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointNativeProverExecution {
    pub proofs: Vec<C61ProductionJointCommittedChainProof>,
    pub frame: C61JointNativeBridgeFrame,
    pub challenge: C61JointNativeChallenge,
    pub transcript_bytes: u64,
    pub transcript_ledger: BTreeMap<&'static str, u64>,
}

impl C61ProductionJointNativeProverBodiesFixed {
    pub fn challenge(&self) -> &C61JointNativeChallenge {
        &self.challenge
    }

    /// Ordered post-body weights for compiling the exact generic functional
    /// before the correction and link statement are fixed.
    pub fn claim_weights(&self) -> Vec<&[Fp2]> {
        self.bodies.iter().map(|body| body.claim_weights.as_slice()).collect()
    }

    pub fn finish(
        mut self,
        compiler_base_fold: ProverAuthed,
        compiler_correction: Fp2,
    ) -> Result<C61ProductionJointNativeProverExecution, String> {
        let statements =
            self.bodies.iter().map(|body| body.statement.public().clone()).collect::<Vec<_>>();
        let terms = self
            .bodies
            .into_iter()
            .zip(self.challenge.cohort_weights.iter().copied())
            .map(|(body, weight)| body.into_joint_term(weight))
            .collect::<Result<Vec<_>, _>>()?;
        let frame = finish_c61_joint_native_bridge(
            terms,
            compiler_base_fold,
            compiler_correction,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        let proofs = self
            .joint_tagless_payloads
            .iter()
            .zip(&statements)
            .enumerate()
            .map(|(index, (tagless, public))| {
                let (role, tail) = c61_joint_native_carrier_tail(frame, index);
                C61ProductionJointCommittedChainProof::from_parts(tagless, &tail, public, role)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&c61_joint_native_tape_payload(&proofs)?)?;
        }
        Ok(C61ProductionJointNativeProverExecution {
            proofs,
            frame,
            challenge: self.challenge,
            transcript_bytes: self.transcript.total_bytes(),
            transcript_ledger: self.transcript.ledger().clone(),
        })
    }

    /// Pause the native tail after fixing its correction. The returned state
    /// contains no serializable proof yet and cannot emit the joint tag until
    /// the amended output link has completed.
    pub fn prepare_nbr2_link(
        mut self,
        compiler_base_fold: ProverAuthed,
        compiler_correction: Fp2,
        nbr2_statement_digest: [u8; 32],
    ) -> Result<C61ProductionJointNativeProverLinkPending, String> {
        if nbr2_statement_digest == [0; 32] {
            return Err("C6PA2 C6NBR2 statement digest is zero".to_owned());
        }
        let statements =
            self.bodies.iter().map(|body| body.statement.public().clone()).collect::<Vec<_>>();
        let terms = self
            .bodies
            .into_iter()
            .zip(self.challenge.cohort_weights.iter().copied())
            .map(|(body, weight)| body.into_joint_term(weight))
            .collect::<Result<Vec<_>, _>>()?;
        let bridge = prepare_c61_joint_native_bridge_prover(
            terms,
            compiler_base_fold,
            compiler_correction,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        Ok(C61ProductionJointNativeProverLinkPending {
            statements,
            joint_tagless_payloads: self.joint_tagless_payloads,
            challenge: self.challenge,
            transcript: self.transcript,
            bridge,
            nbr2_statement_digest,
        })
    }
}

impl C61ProductionJointNativeProverLinkPending {
    pub fn challenge(&self) -> &C61JointNativeChallenge {
        &self.challenge
    }

    pub fn finish_after_nbr2_link(
        mut self,
        receipt: C6Nbr2ProvedLink,
    ) -> Result<C61ProductionJointNativeProverExecution, String> {
        if receipt.statement_digest() != self.nbr2_statement_digest {
            return Err("C6PA2 prover received a different C6NBR2 link receipt".to_owned());
        }
        let frame = self.bridge.finish(&mut self.transcript).map_err(|error| error.to_string())?;
        let proofs = self
            .joint_tagless_payloads
            .iter()
            .zip(&self.statements)
            .enumerate()
            .map(|(index, (tagless, public))| {
                let (role, tail) = c61_joint_native_carrier_tail(frame, index);
                C61ProductionJointCommittedChainProof::from_parts(tagless, &tail, public, role)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&c61_joint_native_tape_payload(&proofs)?)?;
        }
        Ok(C61ProductionJointNativeProverExecution {
            proofs,
            frame,
            challenge: self.challenge,
            transcript_bytes: self.transcript.total_bytes(),
            transcript_ledger: self.transcript.ledger().clone(),
        })
    }
}

pub fn prepare_c61_production_joint_native_prover_bodies(
    profile: &C6CanonicalTargetProfile,
    bodies: Vec<C61ProductionCommittedChainProverBody>,
    mut transcript: Transcript,
) -> Result<C61ProductionJointNativeProverBodiesFixed, String> {
    if bodies.len() != profile.cohorts.len() {
        return Err("C6NBR1 prover body/profile census mismatch".to_owned());
    }
    let mut schedule = C61JointNativeBodyScheduleBuilder::new(profile)?;
    let mut joint_tagless_payloads = Vec::with_capacity(bodies.len());
    for (cohort, body) in profile.cohorts.iter().zip(&bodies) {
        if body.id.repetition != 1
            || cohort.chain_slot != body.id.component as u16
            || usize::from(cohort.polynomial_log2) != body.num_variables
        {
            return Err("C6NBR1 prover body is in the wrong generic cohort slot".to_owned());
        }
        let joint_tagless = body.joint_tagless_payload()?;
        schedule.bind_next(C61JointNativeBodyBinding {
            cohort_id: cohort.cohort_id,
            chain_slot: cohort.chain_slot,
            claim_count: u32::try_from(body.claim_weights.len())
                .map_err(|_| "C6NBR1 prover claim census exceeds u32".to_owned())?,
            typed_statement_digest: body.statement.public().digest(),
            tagless_body_digest: *blake3::hash(&joint_tagless).as_bytes(),
        })?;
        joint_tagless_payloads.push(joint_tagless);
    }
    let challenge = schedule.finish()?.draw_zeta(&mut transcript);
    Ok(C61ProductionJointNativeProverBodiesFixed {
        bodies,
        joint_tagless_payloads,
        challenge,
        transcript,
    })
}

pub fn prepare_c61_production_joint_native_prover_bodies_private_entropy(
    profile: &C6CanonicalTargetProfile,
    bodies: Vec<C61ProductionCommittedChainProverBody>,
    provider_session_binding: C61ProviderJointSessionBinding,
    endpoint: C61PrivateEntropyEndpoint,
) -> Result<C61ProductionJointNativeProverBodiesFixed, String> {
    provider_session_binding.validate_for(profile)?;
    prepare_c61_production_joint_native_prover_bodies(
        profile,
        bodies,
        Transcript::new_interactive(Box::new(endpoint)),
    )
}

pub struct C61ProductionJointNativeVerifierBodiesFixed {
    bodies: Vec<C61ProductionCommittedChainVerifierBody>,
    frame: C61JointNativeBridgeFrame,
    joint_payload: Vec<u8>,
    challenge: C61JointNativeChallenge,
    transcript: Transcript,
}

fn c61_joint_native_tape_payload(
    proofs: &[C61ProductionJointCommittedChainProof],
) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"C6IJNT2\0");
    payload.extend_from_slice(
        &u32::try_from(proofs.len())
            .map_err(|_| "C6ICT2 joint proof census exceeds u32".to_owned())?
            .to_le_bytes(),
    );
    for proof in proofs {
        payload.extend_from_slice(
            &u32::try_from(proof.payload().len())
                .map_err(|_| "C6ICT2 joint proof length exceeds u32".to_owned())?
                .to_le_bytes(),
        );
        payload.extend_from_slice(proof.payload());
    }
    Ok(payload)
}

/// Verifier state after independent compiler/correction reconstruction. The
/// stored tag is decoded but deliberately unchecked until C6LNK2 accepts.
pub struct C61ProductionJointNativeVerifierLinkPending {
    cohort_count: usize,
    joint_payload: Vec<u8>,
    challenge: C61JointNativeChallenge,
    transcript: Transcript,
    bridge: C61JointNativeVerifierBridgePending,
    nbr2_statement_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionJointNativeVerification {
    pub cohort_count: usize,
    pub challenge: C61JointNativeChallenge,
    pub transcript_bytes: u64,
    pub transcript_ledger: BTreeMap<&'static str, u64>,
}

impl C61ProductionJointNativeVerifierBodiesFixed {
    pub fn challenge(&self) -> &C61JointNativeChallenge {
        &self.challenge
    }

    /// Ordered weights recovered while replaying the fixed tagless bodies.
    /// This borrow is available only after `zeta` exists, so callers cannot
    /// compile the joint functional against a partial native schedule.
    pub fn claim_weights(&self) -> Vec<&[Fp2]> {
        self.bodies.iter().map(|body| body.claim_weights.as_slice()).collect()
    }

    /// Provider-carried correction parsed from the first two reassigned
    /// tails. It is only a pending public claim here; C6NBR2 must authenticate
    /// it before [`Self::prepare_nbr2_link`] can be finalized.
    pub fn pending_correction(&self) -> Fp2 {
        self.frame.correction()
    }

    pub fn finish(
        mut self,
        compiler_base_key: VerifierKey,
        expected_compiler_correction: Fp2,
        context: &mut VerifierCtx,
    ) -> Result<C61ProductionJointNativeVerification, String> {
        let terms = self
            .bodies
            .into_iter()
            .zip(self.challenge.cohort_weights.iter().copied())
            .map(|(body, weight)| body.into_joint_term(weight, context))
            .collect::<Result<Vec<_>, _>>()?;
        verify_c61_joint_native_bridge(
            &terms,
            compiler_base_key,
            expected_compiler_correction,
            context.delta,
            self.frame,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&self.joint_payload)?;
        }
        Ok(C61ProductionJointNativeVerification {
            cohort_count: terms.len(),
            challenge: self.challenge,
            transcript_bytes: self.transcript.total_bytes(),
            transcript_ledger: self.transcript.ledger().clone(),
        })
    }

    pub fn prepare_nbr2_link(
        mut self,
        compiler_base_key: VerifierKey,
        expected_compiler_correction: Fp2,
        nbr2_statement_digest: [u8; 32],
        context: &mut VerifierCtx,
    ) -> Result<C61ProductionJointNativeVerifierLinkPending, String> {
        if nbr2_statement_digest == [0; 32] {
            return Err("C6PA2 C6NBR2 statement digest is zero".to_owned());
        }
        let terms = self
            .bodies
            .into_iter()
            .zip(self.challenge.cohort_weights.iter().copied())
            .map(|(body, weight)| body.into_joint_term(weight, context))
            .collect::<Result<Vec<_>, _>>()?;
        let bridge = prepare_c61_joint_native_bridge_verifier(
            &terms,
            compiler_base_key,
            expected_compiler_correction,
            context.delta,
            self.frame,
            &mut self.transcript,
        )
        .map_err(|error| error.to_string())?;
        Ok(C61ProductionJointNativeVerifierLinkPending {
            cohort_count: terms.len(),
            joint_payload: self.joint_payload,
            challenge: self.challenge,
            transcript: self.transcript,
            bridge,
            nbr2_statement_digest,
        })
    }
}

impl C61ProductionJointNativeVerifierLinkPending {
    pub fn challenge(&self) -> &C61JointNativeChallenge {
        &self.challenge
    }

    pub fn finish_after_nbr2_link(
        mut self,
        receipt: C6Nbr2VerifiedLink,
    ) -> Result<C61ProductionJointNativeVerification, String> {
        if receipt.statement_digest() != self.nbr2_statement_digest {
            return Err("C6PA2 verifier received a different C6NBR2 link receipt".to_owned());
        }
        self.bridge.finish(&mut self.transcript).map_err(|error| error.to_string())?;
        if self.transcript.is_interactive() {
            self.transcript.finish_interactive(&self.joint_payload)?;
        }
        Ok(C61ProductionJointNativeVerification {
            cohort_count: self.cohort_count,
            challenge: self.challenge,
            transcript_bytes: self.transcript.total_bytes(),
            transcript_ledger: self.transcript.ledger().clone(),
        })
    }
}

/// Recompile and validate the exact generic target functional from verifier
/// inputs after every secondary native body and `zeta` are fixed.  Retaining
/// the canonical installed plan in response-independent setup is deliberate:
/// neither topology nor a provider functional digest contains its operands.
#[allow(clippy::too_many_arguments)]
pub fn verify_c61_joint_native_compiler_functional(
    fixed: &C61ProductionJointNativeVerifierBodiesFixed,
    operation_plan: &C6InstalledOperationPlan,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    profile: &C6CanonicalTargetProfile,
    expected_schedule_digest: [u8; 32],
    expected_functional_digest: [u8; 32],
) -> Result<volta_proto::c6_residual::C6CompiledNativeTargetFunctional, String> {
    if fixed.challenge.schedule_digest != expected_schedule_digest {
        return Err(
            "C6PA2 body schedule differs before compiler-functional verification".to_owned()
        );
    }
    let claim_weights = fixed.claim_weights().into_iter().map(<[Fp2]>::to_vec).collect::<Vec<_>>();
    let functional = volta_proto::c6_residual::C6CompiledNativeTargetFunctional::compile(
        operation_plan,
        extraction,
        runtime,
        profile,
        &claim_weights,
        &fixed.challenge.cohort_weights,
    )
    .map_err(|error| error.to_string())?;
    if functional.functional_digest() != expected_functional_digest {
        return Err("C6PA2 locally compiled functional differs from C6CPX3 binding".to_owned());
    }
    Ok(functional)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_production_joint_native_verifier_bodies(
    profile: &C6CanonicalTargetProfile,
    public: &[C61TypedNativeChainPublicStatement],
    proofs: &[C61ProductionJointCommittedChainProof],
    verifier_seeds: &[[u8; 32]],
    mask_ranges: &[C61AuthenticatedWhirMaskRange],
    transcript: Transcript,
) -> Result<C61ProductionJointNativeVerifierBodiesFixed, String> {
    prepare_c61_production_joint_native_verifier_bodies_with_transcripts(
        profile,
        public,
        proofs,
        verifier_seeds.iter().copied().map(Transcript::new).collect(),
        mask_ranges,
        transcript,
    )
}

fn prepare_c61_production_joint_native_verifier_bodies_with_transcripts(
    profile: &C6CanonicalTargetProfile,
    public: &[C61TypedNativeChainPublicStatement],
    proofs: &[C61ProductionJointCommittedChainProof],
    transcripts: Vec<Transcript>,
    mask_ranges: &[C61AuthenticatedWhirMaskRange],
    mut transcript: Transcript,
) -> Result<C61ProductionJointNativeVerifierBodiesFixed, String> {
    let count = profile.cohorts.len();
    if public.len() != count
        || proofs.len() != count
        || transcripts.len() != count
        || mask_ranges.len() != count
    {
        return Err("C6NBR1 verifier body/profile census mismatch".to_owned());
    }
    let mut schedule = C61JointNativeBodyScheduleBuilder::new(profile)?;
    let mut bodies = Vec::with_capacity(count);
    let mut transcripts = transcripts.into_iter();
    let mut frame_bytes = [0u8; 32];
    for index in 0..count {
        let cohort = &profile.cohorts[index];
        let expected_role = match index {
            0 => C61JointNativeTailRole::Correction,
            1 => C61JointNativeTailRole::ZeroOpenTag,
            _ => C61JointNativeTailRole::Reserved,
        };
        let proof = C61ProductionJointCommittedChainProof::decode(
            proofs[index].payload(),
            &public[index],
            expected_role,
        )?;
        if proof != proofs[index]
            || public[index].id().repetition != 1
            || cohort.chain_slot != public[index].id().component as u16
        {
            return Err("C6NBR1 verifier body is in the wrong generic cohort slot".to_owned());
        }
        if index < 2 {
            let start = index * C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
            frame_bytes[start..start + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]
                .copy_from_slice(proof.tail());
        }
        let body = prepare_c61_authenticated_whir_p3_production_joint_chain_public_verifier_body_with_transcript(
            &public[index],
            proof.tagless_payload(),
            transcripts.next().expect("C6ICT2 verifier transcript census"),
            mask_ranges[index],
        )?;
        if usize::from(cohort.polynomial_log2) != body.num_variables {
            return Err("C6NBR1 verifier polynomial dimension mismatch".to_owned());
        }
        schedule.bind_next(C61JointNativeBodyBinding {
            cohort_id: cohort.cohort_id,
            chain_slot: cohort.chain_slot,
            claim_count: u32::try_from(body.claim_weights.len())
                .map_err(|_| "C6NBR1 verifier claim census exceeds u32".to_owned())?,
            typed_statement_digest: public[index].digest(),
            tagless_body_digest: body.tagless_digest(),
        })?;
        bodies.push(body);
    }
    let frame =
        C61JointNativeBridgeFrame::decode(&frame_bytes).map_err(|error| error.to_string())?;
    let joint_payload = c61_joint_native_tape_payload(proofs)?;
    let challenge = schedule.finish()?.draw_zeta(&mut transcript);
    Ok(C61ProductionJointNativeVerifierBodiesFixed {
        bodies,
        frame,
        joint_payload,
        challenge,
        transcript,
    })
}

pub fn prepare_c61_production_joint_native_verifier_bodies_private_entropy(
    profile: &C6CanonicalTargetProfile,
    public: &[C61TypedNativeChainPublicStatement],
    proofs: &[C61ProductionJointCommittedChainProof],
    tapes: Vec<C61InteractiveTape>,
    provider_session_bindings: &[C61ProviderSessionBinding],
    mask_ranges: &[C61AuthenticatedWhirMaskRange],
    joint_tape: C61InteractiveTape,
    joint_provider_session_binding: C61ProviderJointSessionBinding,
) -> Result<C61ProductionJointNativeVerifierBodiesFixed, String> {
    if public.len() != tapes.len()
        || public.len() != provider_session_bindings.len()
        || public.len() != mask_ranges.len()
    {
        return Err("C6ICT2 joint verifier private-lane census mismatch".to_owned());
    }
    let mut transcripts = Vec::with_capacity(tapes.len());
    for (((public, tape), binding), mask_range) in
        public.iter().zip(tapes).zip(provider_session_bindings).zip(mask_ranges)
    {
        binding.validate_for(public.id(), *mask_range)?;
        let endpoint = C61PrivateEntropyTranscriptReplayEndpoint::new(
            tape,
            usize::from(match public.relation() {
                C61TypedNativeRelationStatement::Model(statement)
                | C61TypedNativeRelationStatement::Embedding(statement) => {
                    statement.commitment.polynomial_domain_log2
                }
                _ => return Err("C6ICT2 joint verifier received a compiler lane".to_owned()),
            }),
            binding.context_digest(),
        )
        .map_err(|error| error.to_string())?;
        transcripts.push(Transcript::new_interactive(Box::new(endpoint)));
    }
    joint_provider_session_binding.validate_for(profile)?;
    let joint_endpoint = C61PrivateEntropyTranscriptReplayEndpoint::new(
        joint_tape,
        0,
        joint_provider_session_binding.context_digest(),
    )
    .map_err(|error| error.to_string())?;
    prepare_c61_production_joint_native_verifier_bodies_with_transcripts(
        profile,
        public,
        proofs,
        transcripts,
        mask_ranges,
        Transcript::new_interactive(Box::new(joint_endpoint)),
    )
}

#[derive(Debug)]
pub struct C61ProductionCommittedFourChainExecution {
    pub chains: [C61ProductionCommittedChainExecution; 4],
    pub model_coefficient_digest: [u8; 32],
    pub embedding_coefficient_digest: [u8; 32],
    pub peak_loaded_coefficient_bytes: u64,
}

struct C61ProductionCommittedFourChainBodies {
    bodies: [C61ProductionCommittedChainProverBody; 4],
    model_coefficient_digest: [u8; 32],
    embedding_coefficient_digest: [u8; 32],
    peak_loaded_coefficient_bytes: u64,
}

/// Exact C6PA2 split of the four production model/embed chains. The primary
/// chains are complete C6AWP1 proofs; both secondary bodies remain linear and
/// are jointly challenge-bound before either reassigned tail can be emitted.
pub struct C61ProductionJointCommittedFourChainPrepared {
    pub primary: [C61ProductionCommittedChainExecution; 2],
    pub joint: C61ProductionJointNativeProverBodiesFixed,
    pub model_coefficient_digest: [u8; 32],
    pub embedding_coefficient_digest: [u8; 32],
    pub peak_loaded_coefficient_bytes: u64,
}

const C61_COEFFICIENT_OWNER_MAGIC: [u8; 8] = *b"C6PCO1\0\0";
const C61_COEFFICIENT_OWNER_VERSION: u32 = 1;
const C61_COEFFICIENT_OWNER_MANIFEST_BYTES: usize = 128;

/// One row-strided signed source placement into a production D28/D27 native
/// polynomial.  Gaps and the suffix are canonical zero coefficients in the
/// create-new sparse file; overlapping placements are rejected.
pub struct C61SignedCoefficientPlacement<'a> {
    values: &'a [i16],
    rows: usize,
    cols: usize,
    destination_offset: usize,
    destination_stride: usize,
    destination_end: usize,
}

impl<'a> C61SignedCoefficientPlacement<'a> {
    pub fn new(
        values: &'a [i16],
        rows: usize,
        cols: usize,
        destination_offset: usize,
        destination_stride: usize,
    ) -> Result<Self, String> {
        if rows == 0
            || cols == 0
            || cols > destination_stride
            || values.len() != rows.checked_mul(cols).unwrap_or(usize::MAX)
        {
            return Err("C6SPR12 signed coefficient placement geometry mismatch".to_owned());
        }
        let destination_end = destination_offset
            .checked_add(
                rows.checked_sub(1)
                    .and_then(|rows| rows.checked_mul(destination_stride))
                    .and_then(|span| span.checked_add(cols))
                    .ok_or_else(|| "C6SPR12 signed coefficient placement overflows".to_owned())?,
            )
            .ok_or_else(|| "C6SPR12 signed coefficient placement end overflows".to_owned())?;
        Ok(Self { values, rows, cols, destination_offset, destination_stride, destination_end })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C61ProductionCoefficientOwnerMetrics {
    pub logical_coefficient_bytes: u64,
    pub placed_coefficient_bytes_written: u64,
    pub manifest_bytes_written: u64,
    pub coefficient_files_created: u64,
    pub manifest_files_created: u64,
    pub fsync_calls: u64,
}

/// Durable create-new D28/D27 coefficient source.  Loading validates the
/// complete canonical file and content digest before returning a vector to a
/// native chain; repetitions therefore cannot silently switch polynomials.
pub struct C61ProductionCoefficientOwner {
    component: C61NativeComponent,
    session_digest: [u8; 32],
    coefficient_digest: [u8; 32],
    manifest_digest: [u8; 32],
    root: std::path::PathBuf,
    metrics: C61ProductionCoefficientOwnerMetrics,
}

impl C61ProductionCoefficientOwner {
    pub fn component(&self) -> C61NativeComponent {
        self.component
    }

    pub fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }

    pub fn coefficient_digest(&self) -> [u8; 32] {
        self.coefficient_digest
    }

    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn metrics(&self) -> C61ProductionCoefficientOwnerMetrics {
        self.metrics
    }

    pub fn load_for(
        &self,
        component: C61NativeComponent,
        repetition: u8,
    ) -> Result<Vec<Goldilocks>, String> {
        if component != self.component || repetition >= 2 {
            return Err("C6SPR12 coefficient owner component/repetition mismatch".to_owned());
        }
        let expected = c61_production_coefficient_count(component)?;
        self.validate_manifest(expected)?;
        let file = File::open(self.root.join("coefficients.bin"))
            .map_err(|error| format!("open C6SPR12 coefficient owner: {error}"))?;
        if file
            .metadata()
            .map_err(|error| format!("stat C6SPR12 coefficient owner: {error}"))?
            .len()
            != (expected as u64) * 8
        {
            return Err("C6SPR12 coefficient owner file length changed".to_owned());
        }
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(expected)
            .map_err(|_| "C6SPR12 coefficient reload allocation failed".to_owned())?;
        let mut hasher = c61_coefficient_digest_hasher(component, expected);
        let mut bytes = [0u8; 8];
        for _ in 0..expected {
            reader
                .read_exact(&mut bytes)
                .map_err(|error| format!("read C6SPR12 coefficient owner: {error}"))?;
            let value = u64::from_le_bytes(bytes);
            if value >= P {
                return Err(
                    "C6SPR12 coefficient owner contains a noncanonical field value".to_owned()
                );
            }
            hasher.update(&bytes);
            coefficients.push(Goldilocks::from_u64(value));
        }
        let mut trailing = [0u8; 1];
        if reader
            .read(&mut trailing)
            .map_err(|error| format!("finish C6SPR12 coefficient owner read: {error}"))?
            != 0
            || *hasher.finalize().as_bytes() != self.coefficient_digest
        {
            return Err("C6SPR12 coefficient owner content digest changed".to_owned());
        }
        Ok(coefficients)
    }

    fn validate_manifest(&self, expected: usize) -> Result<(), String> {
        let bytes = fs::read(self.root.join("manifest.bin"))
            .map_err(|error| format!("read C6SPR12 coefficient manifest: {error}"))?;
        let expected_dimension = match self.component {
            C61NativeComponent::Model => C61_MODEL_POLYNOMIAL_LOG2,
            C61NativeComponent::Embedding => C61_EMBEDDING_POLYNOMIAL_LOG2,
            C61NativeComponent::Compiler => {
                return Err("C6SPR12 coefficient manifest has compiler component".to_owned())
            }
        };
        if bytes.len() != C61_COEFFICIENT_OWNER_MANIFEST_BYTES
            || bytes[..8] != C61_COEFFICIENT_OWNER_MAGIC
            || u32::from_le_bytes(bytes[8..12].try_into().expect("four manifest bytes"))
                != C61_COEFFICIENT_OWNER_VERSION
            || u16::from_le_bytes(bytes[12..14].try_into().expect("two manifest bytes"))
                != self.component as u16
            || bytes[14] != expected_dimension
            || bytes[15] != 0
            || u64::from_le_bytes(bytes[16..24].try_into().expect("eight manifest bytes"))
                != expected as u64
            || u64::from_le_bytes(bytes[24..32].try_into().expect("eight manifest bytes"))
                != (expected as u64) * 8
            || bytes[32..64] != self.session_digest
            || bytes[64..96] != self.coefficient_digest
            || bytes[96..128] != self.manifest_digest
            || *blake3::hash(&bytes[..96]).as_bytes() != self.manifest_digest
        {
            return Err("C6SPR12 coefficient owner manifest changed or is noncanonical".to_owned());
        }
        Ok(())
    }
}

fn c61_production_coefficient_count(component: C61NativeComponent) -> Result<usize, String> {
    match component {
        C61NativeComponent::Model => Ok(1usize << C61_MODEL_POLYNOMIAL_LOG2),
        C61NativeComponent::Embedding => Ok(1usize << C61_EMBEDDING_POLYNOMIAL_LOG2),
        C61NativeComponent::Compiler => {
            Err("C6SPR12 coefficient owner rejects compiler polynomials".to_owned())
        }
    }
}

fn c61_coefficient_digest_hasher(component: C61NativeComponent, count: usize) -> blake3::Hasher {
    let mut hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/production-coefficient-owner/v1");
    hasher.update(&(component as u16).to_le_bytes());
    hasher.update(&(count as u64).to_le_bytes());
    hasher
}

pub fn c61_production_coefficient_digest(
    component: C61NativeComponent,
    coefficients: &[Goldilocks],
) -> Result<[u8; 32], String> {
    let expected = c61_production_coefficient_count(component)?;
    if coefficients.len() != expected {
        return Err("C6SPR11 coefficient owner has the wrong production geometry".to_owned());
    }
    let mut hasher = c61_coefficient_digest_hasher(component, coefficients.len());
    for coefficient in coefficients {
        hasher.update(&coefficient.as_canonical_u64().to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Create and durably seal one sparse-on-disk production coefficient owner.
/// Only explicitly placed tensor rows allocate data blocks; holes are read as
/// canonical zero coefficients and are included in the complete digest.
pub fn create_c61_production_coefficient_owner(
    root: &Path,
    component: C61NativeComponent,
    session_digest: [u8; 32],
    placements: &[C61SignedCoefficientPlacement<'_>],
) -> Result<C61ProductionCoefficientOwner, String> {
    let count = c61_production_coefficient_count(component)?;
    if session_digest == [0; 32] || placements.is_empty() || root.exists() {
        return Err("C6SPR12 coefficient owner preflight or create-new gate failed".to_owned());
    }
    let mut ranges = placements
        .iter()
        .map(|placement| (placement.destination_offset, placement.destination_end))
        .collect::<Vec<_>>();
    if ranges.iter().any(|(_, end)| *end > count) {
        return Err("C6SPR12 coefficient placement exceeds its native polynomial".to_owned());
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err("C6SPR12 coefficient placements overlap".to_owned());
    }
    let parent = root
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| "C6SPR12 coefficient owner parent is absent".to_owned())?;
    fs::create_dir(root).map_err(|error| format!("create C6SPR12 coefficient owner: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6SPR12 coefficient owner parent: {error}"))?;

    let coefficient_path = root.join("coefficients.bin");
    let coefficient_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&coefficient_path)
        .map_err(|error| format!("create C6SPR12 coefficient file: {error}"))?;
    let logical_bytes = (count as u64)
        .checked_mul(8)
        .ok_or_else(|| "C6SPR12 coefficient byte length overflows".to_owned())?;
    coefficient_file
        .set_len(logical_bytes)
        .map_err(|error| format!("size C6SPR12 coefficient file: {error}"))?;
    let mut placed_values = 0u64;
    let mut row_bytes = Vec::new();
    for placement in placements {
        row_bytes.clear();
        row_bytes
            .try_reserve_exact(placement.cols * 8)
            .map_err(|_| "C6SPR12 coefficient row buffer allocation failed".to_owned())?;
        for row in 0..placement.rows {
            row_bytes.clear();
            let start = row * placement.cols;
            for value in &placement.values[start..start + placement.cols] {
                row_bytes.extend_from_slice(&Fp::from_i64(i64::from(*value)).value().to_le_bytes());
            }
            let destination = placement
                .destination_offset
                .checked_add(row * placement.destination_stride)
                .and_then(|value| value.checked_mul(8))
                .ok_or_else(|| "C6SPR12 coefficient write offset overflows".to_owned())?;
            coefficient_file
                .write_all_at(&row_bytes, destination as u64)
                .map_err(|error| format!("write C6SPR12 coefficient row: {error}"))?;
            placed_values = placed_values
                .checked_add(placement.cols as u64)
                .ok_or_else(|| "C6SPR12 placed coefficient census overflows".to_owned())?;
        }
    }
    coefficient_file
        .sync_all()
        .map_err(|error| format!("fsync C6SPR12 coefficient file: {error}"))?;

    let digest = {
        let mut reader = BufReader::with_capacity(
            8 * 1024 * 1024,
            File::open(&coefficient_path)
                .map_err(|error| format!("reopen C6SPR12 coefficient file: {error}"))?,
        );
        let mut hasher = c61_coefficient_digest_hasher(component, count);
        let mut buffer = vec![0u8; 8 * 1024 * 1024];
        let mut remaining = logical_bytes;
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| "C6SPR12 coefficient digest chunk exceeds usize".to_owned())?;
            reader
                .read_exact(&mut buffer[..take])
                .map_err(|error| format!("read C6SPR12 coefficient digest: {error}"))?;
            for bytes in buffer[..take].chunks_exact(8) {
                if u64::from_le_bytes(bytes.try_into().expect("eight-byte coefficient")) >= P {
                    return Err(
                        "C6SPR12 coefficient writer produced a noncanonical field value".to_owned()
                    );
                }
            }
            hasher.update(&buffer[..take]);
            remaining -= take as u64;
        }
        *hasher.finalize().as_bytes()
    };

    let dimension = match component {
        C61NativeComponent::Model => C61_MODEL_POLYNOMIAL_LOG2,
        C61NativeComponent::Embedding => C61_EMBEDDING_POLYNOMIAL_LOG2,
        C61NativeComponent::Compiler => unreachable!("compiler rejected above"),
    };
    let mut manifest = Vec::with_capacity(C61_COEFFICIENT_OWNER_MANIFEST_BYTES);
    manifest.extend_from_slice(&C61_COEFFICIENT_OWNER_MAGIC);
    manifest.extend_from_slice(&C61_COEFFICIENT_OWNER_VERSION.to_le_bytes());
    manifest.extend_from_slice(&(component as u16).to_le_bytes());
    manifest.push(dimension);
    manifest.push(0);
    manifest.extend_from_slice(&(count as u64).to_le_bytes());
    manifest.extend_from_slice(&logical_bytes.to_le_bytes());
    manifest.extend_from_slice(&session_digest);
    manifest.extend_from_slice(&digest);
    manifest.resize(C61_COEFFICIENT_OWNER_MANIFEST_BYTES - 32, 0);
    let manifest_digest = *blake3::hash(&manifest).as_bytes();
    manifest.extend_from_slice(&manifest_digest);
    let manifest_path = root.join("manifest.bin");
    let manifest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .map_err(|error| format!("create C6SPR12 coefficient manifest: {error}"))?;
    manifest_file
        .write_all_at(&manifest, 0)
        .map_err(|error| format!("write C6SPR12 coefficient manifest: {error}"))?;
    manifest_file
        .sync_all()
        .map_err(|error| format!("fsync C6SPR12 coefficient manifest: {error}"))?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6SPR12 coefficient owner directory: {error}"))?;

    Ok(C61ProductionCoefficientOwner {
        component,
        session_digest,
        coefficient_digest: digest,
        manifest_digest,
        root: root.to_path_buf(),
        metrics: C61ProductionCoefficientOwnerMetrics {
            logical_coefficient_bytes: logical_bytes,
            placed_coefficient_bytes_written: placed_values * 8,
            manifest_bytes_written: manifest.len() as u64,
            coefficient_files_created: 1,
            manifest_files_created: 1,
            fsync_calls: 4,
        },
    })
}

/// Produce model0/model1/embed0/embed1 sequentially from a reloadable durable
/// source.  Only one coefficient vector is live at a time; the preregistered
/// digest guarantees both repetitions use the same exact polynomial.
#[allow(clippy::too_many_arguments)]
pub fn prove_c61_authenticated_whir_p3_production_four_committed_chains_in_attempt(
    load_coefficients: impl FnMut(C61NativeComponent, u8) -> Result<Vec<Goldilocks>, String>,
    expected_model_coefficient_digest: [u8; 32],
    expected_embedding_coefficient_digest: [u8; 32],
    model_claims: [&[crate::batch::BlockClaim]; 2],
    embedding_claims: [&[crate::batch::BlockClaim]; 2],
    model_targets: [Vec<ProverAuthed>; 2],
    embedding_targets: [Vec<ProverAuthed>; 2],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut [CorrelationStream; 2],
    verifier_seeds: [[u8; 32]; 4],
    mask_ranges: [C61AuthenticatedWhirMaskRange; 4],
) -> Result<C61ProductionCommittedFourChainExecution, String> {
    let prepared = prepare_c61_authenticated_whir_p3_production_four_committed_chain_bodies(
        load_coefficients,
        expected_model_coefficient_digest,
        expected_embedding_coefficient_digest,
        model_claims,
        embedding_claims,
        model_targets,
        embedding_targets,
        spill_root,
        admission,
        backend,
        correlations,
        verifier_seeds.map(Transcript::new),
        verifier_seeds,
        mask_ranges,
    )?;
    let chains = prepared
        .bodies
        .into_iter()
        .map(C61ProductionCommittedChainProverBody::finish_ordinary)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "C6SPR11 four-chain execution census mismatch".to_owned())?;
    Ok(C61ProductionCommittedFourChainExecution {
        chains,
        model_coefficient_digest: prepared.model_coefficient_digest,
        embedding_coefficient_digest: prepared.embedding_coefficient_digest,
        peak_loaded_coefficient_bytes: prepared.peak_loaded_coefficient_bytes,
    })
}

/// Prepare the exact C6PA2 split without replaying a coefficient owner or
/// native claim. Primary repetitions close as C6AWP1; secondary repetitions
/// enter the generic post-body challenge schedule and remain linear until the
/// later C6NBR2 receipt.
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_authenticated_whir_p3_production_joint_four_chains_in_attempt(
    load_coefficients: impl FnMut(C61NativeComponent, u8) -> Result<Vec<Goldilocks>, String>,
    expected_model_coefficient_digest: [u8; 32],
    expected_embedding_coefficient_digest: [u8; 32],
    model_claims: [&[crate::batch::BlockClaim]; 2],
    embedding_claims: [&[crate::batch::BlockClaim]; 2],
    model_targets: [Vec<ProverAuthed>; 2],
    embedding_targets: [Vec<ProverAuthed>; 2],
    profile: &C6CanonicalTargetProfile,
    joint_transcript: Transcript,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut [CorrelationStream; 2],
    verifier_seeds: [[u8; 32]; 4],
    mask_ranges: [C61AuthenticatedWhirMaskRange; 4],
) -> Result<C61ProductionJointCommittedFourChainPrepared, String> {
    let prepared = prepare_c61_authenticated_whir_p3_production_four_committed_chain_bodies(
        load_coefficients,
        expected_model_coefficient_digest,
        expected_embedding_coefficient_digest,
        model_claims,
        embedding_claims,
        model_targets,
        embedding_targets,
        spill_root,
        admission,
        backend,
        correlations,
        verifier_seeds.map(Transcript::new),
        verifier_seeds,
        mask_ranges,
    )?;
    let [model_primary, model_secondary, embedding_primary, embedding_secondary] = prepared.bodies;
    let primary = [model_primary.finish_ordinary()?, embedding_primary.finish_ordinary()?];
    let joint = prepare_c61_production_joint_native_prover_bodies(
        profile,
        vec![model_secondary, embedding_secondary],
        joint_transcript,
    )?;
    Ok(C61ProductionJointCommittedFourChainPrepared {
        primary,
        joint,
        model_coefficient_digest: prepared.model_coefficient_digest,
        embedding_coefficient_digest: prepared.embedding_coefficient_digest,
        peak_loaded_coefficient_bytes: prepared.peak_loaded_coefficient_bytes,
    })
}

/// Provider-only C6ICT2 four-chain boundary. All five challenge transports
/// (four WHIR lanes plus the post-body joint bridge) are opaque endpoints;
/// verifier seeds, replay tapes and checkpoints cannot enter this call.
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt(
    load_coefficients: impl FnMut(C61NativeComponent, u8) -> Result<Vec<Goldilocks>, String>,
    expected_model_coefficient_digest: [u8; 32],
    expected_embedding_coefficient_digest: [u8; 32],
    model_claims: [&[crate::batch::BlockClaim]; 2],
    embedding_claims: [&[crate::batch::BlockClaim]; 2],
    model_targets: [Vec<ProverAuthed>; 2],
    embedding_targets: [Vec<ProverAuthed>; 2],
    profile: &C6CanonicalTargetProfile,
    provider_session_bindings: [C61ProviderSessionBinding; 4],
    endpoints: [C61PrivateEntropyEndpoint; 4],
    joint_provider_session_binding: C61ProviderJointSessionBinding,
    joint_endpoint: C61PrivateEntropyEndpoint,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut [CorrelationStream; 2],
    mask_ranges: [C61AuthenticatedWhirMaskRange; 4],
) -> Result<C61ProductionJointCommittedFourChainPrepared, String> {
    let schedule = [
        C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
        C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
        C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 0 },
        C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
    ];
    for ((binding, id), mask_range) in
        provider_session_bindings.iter().zip(schedule).zip(mask_ranges)
    {
        binding.validate_for(id, mask_range)?;
    }
    joint_provider_session_binding.validate_for(profile)?;
    let transcripts = endpoints.map(|endpoint| Transcript::new_interactive(Box::new(endpoint)));
    let binding_digests = provider_session_bindings.map(C61ProviderSessionBinding::context_digest);
    let prepared = prepare_c61_authenticated_whir_p3_production_four_committed_chain_bodies(
        load_coefficients,
        expected_model_coefficient_digest,
        expected_embedding_coefficient_digest,
        model_claims,
        embedding_claims,
        model_targets,
        embedding_targets,
        spill_root,
        admission,
        backend,
        correlations,
        transcripts,
        binding_digests,
        mask_ranges,
    )?;
    let [model_primary, model_secondary, embedding_primary, embedding_secondary] = prepared.bodies;
    let primary = [model_primary.finish_ordinary()?, embedding_primary.finish_ordinary()?];
    let joint = prepare_c61_production_joint_native_prover_bodies_private_entropy(
        profile,
        vec![model_secondary, embedding_secondary],
        joint_provider_session_binding,
        joint_endpoint,
    )?;
    Ok(C61ProductionJointCommittedFourChainPrepared {
        primary,
        joint,
        model_coefficient_digest: prepared.model_coefficient_digest,
        embedding_coefficient_digest: prepared.embedding_coefficient_digest,
        peak_loaded_coefficient_bytes: prepared.peak_loaded_coefficient_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_c61_authenticated_whir_p3_production_four_committed_chain_bodies(
    mut load_coefficients: impl FnMut(C61NativeComponent, u8) -> Result<Vec<Goldilocks>, String>,
    expected_model_coefficient_digest: [u8; 32],
    expected_embedding_coefficient_digest: [u8; 32],
    model_claims: [&[crate::batch::BlockClaim]; 2],
    embedding_claims: [&[crate::batch::BlockClaim]; 2],
    model_targets: [Vec<ProverAuthed>; 2],
    embedding_targets: [Vec<ProverAuthed>; 2],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut [CorrelationStream; 2],
    transcripts: [Transcript; 4],
    provider_session_bindings: [[u8; 32]; 4],
    mask_ranges: [C61AuthenticatedWhirMaskRange; 4],
) -> Result<C61ProductionCommittedFourChainBodies, String> {
    if expected_model_coefficient_digest == [0; 32]
        || expected_embedding_coefficient_digest == [0; 32]
        || backend.kind() != BackendKind::CudaResident
        || !admission.allow_persisted_executor
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES
        || admission.available_spill_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES
        || correlations.iter().any(|stream| !stream.uses_pooled_pcg())
        || model_claims.iter().any(|claims| claims.len() != 96)
        || embedding_claims.iter().any(|claims| claims.len() != 6)
        || model_targets.iter().any(|targets| targets.len() != 96)
        || embedding_targets.iter().any(|targets| targets.len() != 6)
        || !spill_root.is_dir()
    {
        return Err(
            "C6SPR11 four-chain persisted/CUDA preflight failed before source load".to_owned()
        );
    }
    let schedule = [
        (C61NativeComponent::Model, 0u8),
        (C61NativeComponent::Model, 1u8),
        (C61NativeComponent::Embedding, 0u8),
        (C61NativeComponent::Embedding, 1u8),
    ];
    if schedule.iter().any(|(component, repetition)| {
        spill_root.join(format!("{:?}-{repetition}", component).to_ascii_lowercase()).exists()
    }) {
        return Err("C6SPR11 four-chain spill children must all be create-new".to_owned());
    }
    let mut model_targets = model_targets.into_iter();
    let mut embedding_targets = embedding_targets.into_iter();
    let mut transcripts = transcripts.into_iter();
    let mut provider_session_bindings = provider_session_bindings.into_iter();
    let mut bodies = Vec::with_capacity(4);
    let mut peak_loaded_coefficient_bytes = 0u64;
    for (ordinal, (component, repetition)) in schedule.into_iter().enumerate() {
        let coefficients = load_coefficients(component, repetition)?;
        let digest = c61_production_coefficient_digest(component, &coefficients)?;
        let expected_digest = match component {
            C61NativeComponent::Model => expected_model_coefficient_digest,
            C61NativeComponent::Embedding => expected_embedding_coefficient_digest,
            C61NativeComponent::Compiler => unreachable!("compiler absent from schedule"),
        };
        if digest != expected_digest {
            return Err(
                "C6SPR11 reloaded coefficient polynomial differs from its owner digest".to_owned()
            );
        }
        peak_loaded_coefficient_bytes = peak_loaded_coefficient_bytes.max(
            (coefficients.len() as u64)
                .checked_mul(std::mem::size_of::<Goldilocks>() as u64)
                .ok_or_else(|| "C6SPR11 coefficient byte census overflows".to_owned())?,
        );
        let (claims, targets, parameter_digest) = match component {
            C61NativeComponent::Model => (
                model_claims[usize::from(repetition)],
                model_targets.next().expect("two model target owners"),
                c61_authenticated_p3_parameter_digest(28)?,
            ),
            C61NativeComponent::Embedding => (
                embedding_claims[usize::from(repetition)],
                embedding_targets.next().expect("two embedding target owners"),
                c61_authenticated_p3_parameter_digest(27)?,
            ),
            C61NativeComponent::Compiler => unreachable!("compiler absent from schedule"),
        };
        let id = C61NativeChainId { component, repetition };
        let child = spill_root.join(format!("{:?}-{repetition}", component).to_ascii_lowercase());
        bodies.push(prepare_c61_authenticated_whir_p3_production_committed_chain_with_transcript(
            coefficients,
            claims,
            targets,
            parameter_digest,
            &child,
            admission,
            backend,
            &mut correlations[usize::from(repetition)],
            transcripts.next().expect("four C6ICT2 chain transcripts"),
            provider_session_bindings.next().expect("four C6ICT2 provider session bindings"),
            id,
            mask_ranges[ordinal],
        )?);
    }
    let bodies =
        bodies.try_into().map_err(|_| "C6SPR11 four-chain body census mismatch".to_owned())?;
    Ok(C61ProductionCommittedFourChainBodies {
        bodies,
        model_coefficient_digest: expected_model_coefficient_digest,
        embedding_coefficient_digest: expected_embedding_coefficient_digest,
        peak_loaded_coefficient_bytes,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ProductionCommittedChainVerification {
    pub id: C61NativeChainId,
    pub num_variables: usize,
    pub claim_count: usize,
    pub strict_payload_bytes: usize,
    pub verifier_interaction: C61WhirInteractionStats,
    pub verifier_transcript_bytes: u64,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionMonolithicResourceAdmission {
    /// Available host memory sampled immediately before entering the runner,
    /// not installed RAM.
    pub available_host_bytes: u64,
    /// Informative A100 device capacity.  The monolithic P3 baseline does not
    /// consume it and receives no GPU performance credit.
    pub gpu_total_bytes: u64,
    pub a100_present: bool,
    /// Must be set explicitly by the owner-authorized campaign runner.
    pub allow_host_monolithic_baseline: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionPersistedResourceAdmission {
    pub available_host_bytes: u64,
    pub available_spill_bytes: u64,
    pub gpu_total_bytes: u64,
    pub a100_present: bool,
    pub allow_persisted_executor: bool,
}

/// Production total-memory census for the selected monolithic P3 prover data
/// layout.
///
/// `HidingWhirProverData` retains the Boolean message and the encoded initial
/// oracle, while `MerkleTreeMmcs` retains every digest layer.  Both response
/// and plan roots must be fixed before the relation challenges, so the two
/// prover-data objects coexist.  These are strict retained lower bounds: ZK
/// randomness, later round oracles, GKR state and allocator overhead are not
/// included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionMonolithicMemoryCensus {
    pub response_num_variables: usize,
    pub plan_num_variables: usize,
    pub response_message_bytes: u64,
    pub response_encoded_bytes: u64,
    pub response_merkle_bytes: u64,
    pub response_retained_lower_bound_bytes: u64,
    pub plan_message_bytes: u64,
    pub plan_encoded_bytes: u64,
    pub plan_merkle_bytes: u64,
    pub plan_retained_lower_bound_bytes: u64,
    pub concurrent_retained_lower_bound_bytes: u64,
    /// Informative comparison only.  The owner-frozen component cap excludes
    /// encoded PCS oracles and Merkle prover data.
    pub coefficient_witness_cap_bytes: u64,
    pub retained_minus_component_cap_bytes: u64,
}

/// Reference-only designated-verifier view simulation report.
///
/// The simulator receives the target MAC key but never the real opening
/// plaintext, its provider tag, the real witness, or provider correlation
/// state.  It samples a surrogate witness only to materialize concrete
/// Merkle trees in this executable differential; the security argument uses
/// the pinned HVZK query simulators for those oracle views.
#[derive(Debug)]
pub struct C61AuthenticatedP3PrivacyDiagnostic {
    pub num_variables: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub simulator_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub simulator_transcript_bytes: u64,
    pub verifier_transcript_bytes: u64,
    pub simulator_ledger: BTreeMap<&'static str, u64>,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub received_real_target_plaintext: bool,
    pub received_provider_target_tag: bool,
    pub received_provider_correlation_state: bool,
    pub verifier_full_key_draws: u64,
}

/// Reference-only two-party transport and replay-to-frontier report.
#[derive(Debug)]
pub struct C61PrivateEntropyDriverDiagnostic {
    pub num_variables: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub challenge_count: usize,
    pub checkpoint_frontier: usize,
    pub checkpoint_bytes: usize,
    pub replayed_challenges: usize,
    pub resumed_artifact_identical: bool,
    pub resumed_tape_identical: bool,
    pub mutated_checkpoint_rejected: bool,
    pub checkpoint_codec_mutations_rejected: bool,
    pub durable_journal_bytes: usize,
    pub durable_replayed_challenges: usize,
    pub durable_replayed_mask_events: usize,
    pub durable_mask_frontier: u32,
    pub durable_record_count: u32,
    pub durable_resume_artifact_identical: bool,
    pub durable_resume_tape_identical: bool,
    pub durable_wrong_binding_rejected: bool,
    pub durable_torn_journal_rejected: bool,
    pub durable_corrupt_journal_rejected: bool,
    pub provider_received_verifier_seed: bool,
    pub provider_received_checkpoint: bool,
    pub full_correlations: u64,
}

#[derive(Clone)]
struct C61AuthenticatedP3Artifact {
    payload: Vec<u8>,
}

#[derive(Clone)]
struct C61SharedMultiOracleArtifact {
    payload: Vec<u8>,
}

struct C61PrivateEntropyFixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    broker: C61PrivateEntropyBrokerOutput,
    full_correlations: u64,
}

struct C61PrivateEntropyProviderFixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    full_correlations: u64,
}

#[derive(Clone)]
struct C61AuthenticatedP3Fixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    provider_interaction: C61WhirInteractionStats,
    provider_transcript_bytes: u64,
    provider_ledger: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Copy)]
struct C61AuthenticatedP3VerifierInput<'a> {
    point: &'a Point<C61P3Fp2>,
    target_key: VerifierKey,
    verifier_seed: [u8; 32],
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
}

fn c61_authenticated_config<Challenger>(
    num_variables: usize,
) -> Result<ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>, String>
where
    Challenger: FieldChallenger<Goldilocks> + GrindingChallenger<Witness = Goldilocks>,
{
    ZkWhirConfig::new(
        num_variables,
        ProtocolParameters {
            security_level: C61_AUTHENTICATED_P3_SECURITY_BITS,
            pow_bits: 0,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::ConstantFromSecondRound(
                C61_WHIRA1_INITIAL_FOLD,
                C61_WHIRA1_LATER_FOLD,
            ),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: C61_WHIRA1_STARTING_LOG_INV_RATE,
        },
        ZkParameters { ell_zk: C61_WHIRA1_ELL_ZK, mask_log_inv_rate: C61_WHIRA1_MASK_LOG_INV_RATE },
    )
    .map_err(|error| error.to_string())
}

fn affine_from_p3(claim: ClaimlessAffineClaim<C61P3Fp2>) -> C61AuthenticatedWhirAffineClaim {
    C61AuthenticatedWhirAffineClaim {
        coefficient: c61_volta_fp2_from_p3(claim.coefficient),
        constant: c61_volta_fp2_from_p3(claim.constant),
    }
}

fn aggregate_prover_targets(
    targets: &[ProverAuthed],
    claim_weights: &[C61P3Fp2],
) -> Result<ProverAuthed, String> {
    if targets.is_empty() || targets.len() != claim_weights.len() || targets.len() > 128 {
        return Err("C6AWP1 provider target batch census mismatch".to_owned());
    }
    Ok(targets.iter().zip(claim_weights).fold(ProverAuthed::ZERO, |sum, (target, weight)| {
        sum.add(target.scale(c61_volta_fp2_from_p3(*weight)))
    }))
}

fn aggregate_verifier_targets(
    targets: &[VerifierKey],
    claim_weights: &[C61P3Fp2],
) -> Result<VerifierKey, String> {
    if targets.is_empty() || targets.len() != claim_weights.len() || targets.len() > 128 {
        return Err("C6AWP1 verifier target batch census mismatch".to_owned());
    }
    Ok(targets.iter().zip(claim_weights).fold(VerifierKey::ZERO, |sum, (target, weight)| {
        sum.add(target.scale(c61_volta_fp2_from_p3(*weight)))
    }))
}

fn c61_model_embedding_openings(
    public: &C61TypedNativeChainPublicStatement,
) -> Result<&crate::c61_terminal_functional::C61CommittedOpeningStatement, String> {
    let rebuilt = C61TypedNativeChainPublicStatement::new(public.id(), public.relation().clone())
        .map_err(|error| error.to_string())?;
    if &rebuilt != public {
        return Err("C6SPR11 typed native public statement is noncanonical".to_owned());
    }
    match public.relation() {
        C61TypedNativeRelationStatement::Model(openings)
        | C61TypedNativeRelationStatement::Embedding(openings) => Ok(openings),
        C61TypedNativeRelationStatement::Compiler(_) => {
            Err("C6SPR11 committed-chain boundary rejects compiler statements".to_owned())
        }
    }
}

/// Canonical digest of the selected authenticated WHIR production profile.
/// It is setup metadata, not a response field.
pub fn c61_authenticated_p3_parameter_digest(num_variables: usize) -> Result<[u8; 32], String> {
    let budget = c61_authenticated_structural_budget_inner(num_variables, true)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/authenticated-whir-parameters/v1");
    hasher.update(C61_AUTHENTICATED_P3_REVISION.as_bytes());
    hasher.update(&(num_variables as u64).to_le_bytes());
    hasher.update(&(C61_AUTHENTICATED_P3_SECURITY_BITS as u64).to_le_bytes());
    hasher.update(&(budget.rounds as u64).to_le_bytes());
    hasher.update(&(budget.mask_queries as u64).to_le_bytes());
    hasher.update(&(budget.strict_chain_bytes as u64).to_le_bytes());
    hasher.update(&(C61_WHIRA1_INITIAL_FOLD as u64).to_le_bytes());
    hasher.update(&(C61_WHIRA1_LATER_FOLD as u64).to_le_bytes());
    hasher.update(&(C61_WHIRA1_STARTING_LOG_INV_RATE as u64).to_le_bytes());
    hasher.update(&(C61_WHIRA1_MASK_LOG_INV_RATE as u64).to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn c61_validate_committed_chain_root(
    public: &C61TypedNativeChainPublicStatement,
    commitment: &C61Commitment,
) -> Result<(), String> {
    let openings = c61_model_embedding_openings(public)?;
    let num_variables = usize::from(openings.commitment.polynomial_domain_log2);
    let expected_dimension = match public.id().component {
        C61NativeComponent::Model => usize::from(C61_MODEL_POLYNOMIAL_LOG2),
        C61NativeComponent::Embedding => usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2),
        C61NativeComponent::Compiler => unreachable!("compiler rejected above"),
    };
    if num_variables != expected_dimension
        || openings.commitment.parameter_digest
            != c61_authenticated_p3_parameter_digest(num_variables)?
        || commitment.num_roots() != 1
        || commitment.roots()[0] != openings.commitment.commitment_root
    {
        return Err(
            "C6SPR11 native commitment differs from its typed production statement".to_owned()
        );
    }
    Ok(())
}

fn c61_model_embedding_points(
    public: &C61TypedNativeChainPublicStatement,
) -> Result<Vec<Point<C61P3Fp2>>, String> {
    let openings = c61_model_embedding_openings(public)?;
    let num_variables = usize::from(openings.commitment.polynomial_domain_log2);
    let points = openings
        .ordered_points
        .iter()
        .map(|point| {
            let mut point = point.clone();
            point.reverse();
            Point::new(point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect::<Vec<_>>();
    if points.is_empty()
        || points.len() != public.target_count()
        || points.iter().any(|point| point.num_variables() != num_variables)
    {
        return Err("C6SPR11 typed production opening points are malformed".to_owned());
    }
    Ok(points)
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), String> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| "C6AWP1 structural byte count overflow".to_owned())?;
    Ok(())
}

fn opening_bytes(
    leaves: usize,
    queries: usize,
    row_width: usize,
    element_bytes: usize,
) -> Result<usize, String> {
    let rows = queries
        .checked_mul(row_width)
        .and_then(|value| value.checked_mul(element_bytes))
        .ok_or_else(|| "C6AWP1 opening row byte count overflow".to_owned())?;
    let siblings = c61_max_pruned_binary_siblings(leaves, queries)
        .checked_mul(C61_WHIRA1_DIGEST_BYTES)
        .ok_or_else(|| "C6AWP1 Merkle frontier byte count overflow".to_owned())?;
    C61_WHIRA1_MULTIPROOF_COUNT_BYTES
        .checked_add(rows)
        .and_then(|value| value.checked_add(siblings))
        .ok_or_else(|| "C6AWP1 opening byte count overflow".to_owned())
}

fn c61_authenticated_structural_budget_inner(
    num_variables: usize,
    production_dimensions_only: bool,
) -> Result<C61AuthenticatedP3StructuralBudget, String> {
    if production_dimensions_only && !matches!(num_variables, 27 | 28) {
        return Err("C6AWP1 production profile admits only D27 or D28".to_owned());
    }
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWP1 dimension must be in 4..=28".to_owned());
    }
    let config = c61_authenticated_config::<C61SizingChallenger>(num_variables)?;
    if config.params.pow_bits != 0
        || config.starting_folding_pow_bits != 0
        || config.final_pow_bits != 0
        || config.final_folding_pow_bits != 0
        || config
            .round_parameters
            .iter()
            .any(|round| round.pow_bits != 0 || round.folding_pow_bits != 0)
    {
        return Err("C6AWP1 forbids every proof-of-work transcript field".to_owned());
    }

    let mut round_opening_bytes = 0usize;
    let mut rounds_bytes = 0usize;
    let mut max_ood_samples = 0usize;
    let mut ood_privacy_bad_event_numerator = 0usize;
    for (index, round) in config.round_parameters.iter().enumerate() {
        let switch_mask = config
            .switch_masks
            .get(index)
            .ok_or_else(|| "C6AWP1 missing code-switch privacy mask".to_owned())?;
        let pad_slots =
            switch_mask.message_len.checked_sub(config.oracle_randomness[index]).ok_or_else(
                || "C6AWP1 code-switch mask is shorter than source randomness".to_owned(),
            )?;
        if pad_slots != round.ood_samples {
            return Err("C6AWP1 does not have one fresh pad slot per OOD answer".to_owned());
        }
        max_ood_samples = max_ood_samples.max(round.ood_samples);
        let round_bad_numerator = round
            .ood_samples
            .checked_add(1)
            .and_then(|successor| round.ood_samples.checked_mul(successor))
            .and_then(|value| value.checked_div(2))
            .ok_or_else(|| "C6AWP1 OOD privacy numerator overflow".to_owned())?;
        checked_add(&mut ood_privacy_bad_event_numerator, round_bad_numerator)?;
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let element_bytes = if index == 0 { C61_WHIRA1_FP_BYTES } else { C61_WHIRA1_FP2_BYTES };
        let opening = opening_bytes(leaves, round.num_queries, 1usize << fold, element_bytes)?;
        checked_add(&mut round_opening_bytes, opening)?;
        checked_add(
            &mut rounds_bytes,
            2 * C61_WHIRA1_DIGEST_BYTES + round.ood_samples * C61_WHIRA1_FP2_BYTES + opening,
        )?;
    }

    let groups = config.mask_groups();
    let flat_mask_count: usize = groups.iter().map(|group| group.width).sum();
    let mut base_mask_opening_bytes = 0usize;
    let mut blinded_mask_bytes = 0usize;
    for group in &groups {
        let one = opening_bytes(
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            C61_WHIRA1_FP2_BYTES,
        )?;
        checked_add(&mut base_mask_opening_bytes, 2 * one)?;
        let one_mask = group
            .shape
            .message_len
            .checked_add(group.shape.randomness_len)
            .and_then(|elements| elements.checked_mul(C61_WHIRA1_FP2_BYTES))
            .ok_or_else(|| "C6AWP1 blinded-mask byte count overflow".to_owned())?;
        checked_add(&mut blinded_mask_bytes, group.width * one_mask)?;
    }

    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;
    let source_opening = opening_bytes(
        final_domain,
        config.final_queries,
        1usize << final_round.folding_factor,
        C61_WHIRA1_FP2_BYTES,
    )?;
    let fresh_main_opening =
        opening_bytes(final_domain, config.final_queries, 1, C61_WHIRA1_FP2_BYTES)?;
    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];

    let mut base_case_bytes = 0usize;
    checked_add(&mut base_case_bytes, (1 + groups.len()) * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut base_case_bytes, C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, final_message_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, final_randomness_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, blinded_mask_bytes)?;
    checked_add(&mut base_case_bytes, source_opening)?;
    checked_add(&mut base_case_bytes, fresh_main_opening)?;
    checked_add(&mut base_case_bytes, base_mask_opening_bytes)?;

    let sumcheck_batches = config.n_rounds() + 1;
    let sumcheck_rounds: usize =
        (0..sumcheck_batches).map(|batch| config.round_folding_factor(batch)).sum();
    let sumcheck_bytes =
        (sumcheck_batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES;

    let mut strict_chain_bytes = C61_AUTHENTICATED_P3_HEADER_BYTES;
    checked_add(&mut strict_chain_bytes, C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut strict_chain_bytes, sumcheck_bytes)?;
    checked_add(&mut strict_chain_bytes, sumcheck_batches * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut strict_chain_bytes, rounds_bytes)?;
    checked_add(&mut strict_chain_bytes, base_case_bytes)?;
    checked_add(&mut strict_chain_bytes, C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)?;

    if flat_mask_count != config.folding_schedule.iter().sum::<usize>() + config.n_rounds() {
        return Err("C6AWP1 mask-group census mismatch".to_owned());
    }
    if strict_chain_bytes > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(format!(
            "C6AWP1 D{num_variables} structural maximum {strict_chain_bytes} exceeds the native-chain cap"
        ));
    }

    Ok(C61AuthenticatedP3StructuralBudget {
        num_variables,
        rounds: config.n_rounds(),
        mask_queries: config.mask_queries,
        max_ood_samples,
        ood_privacy_bad_event_numerator,
        round_opening_bytes,
        base_mask_opening_bytes,
        blinded_mask_bytes,
        base_case_bytes,
        strict_chain_bytes,
    })
}

/// Exact structural maximum for the registered 75-bit C6AWP1 D27/D28
/// profile.  It includes the final 16-byte designated ZeroOpen tag and no
/// clear opening evaluation.
pub fn c61_authenticated_p3_structural_budget(
    num_variables: usize,
) -> Result<C61AuthenticatedP3StructuralBudget, String> {
    c61_authenticated_structural_budget_inner(num_variables, true)
}

fn c61_monolithic_initial_oracle_retained_lower_bound(
    num_variables: usize,
) -> Result<(u64, u64, u64, u64), String> {
    if !matches!(num_variables, 27 | 28) {
        return Err("C6SPR4 production admission admits only D27 or D28".to_owned());
    }
    let n = u32::try_from(num_variables)
        .map_err(|_| "C6SPR4 production dimension exceeds u32".to_owned())?;
    let field_bytes = u64::try_from(std::mem::size_of::<Goldilocks>())
        .map_err(|_| "C6SPR4 field width exceeds u64".to_owned())?;
    if field_bytes != C61_WHIRA1_FP_BYTES as u64 {
        return Err("C6SPR4 Goldilocks storage width changed".to_owned());
    }

    // The initial fold is one bit.  `zk_padded_matrix` therefore has 2^n
    // rows and width two, while the retained Boolean message has 2^n base
    // elements.  The binary MMCS stores digest layers of lengths
    // 2^n, 2^(n-1), ..., 1.
    let message_elements =
        1u64.checked_shl(n).ok_or_else(|| "C6SPR4 message geometry overflows".to_owned())?;
    let encoded_elements = message_elements
        .checked_mul(2)
        .ok_or_else(|| "C6SPR4 encoded geometry overflows".to_owned())?;
    let merkle_digests = encoded_elements
        .checked_sub(1)
        .ok_or_else(|| "C6SPR4 Merkle geometry underflows".to_owned())?;
    let message_bytes = message_elements
        .checked_mul(field_bytes)
        .ok_or_else(|| "C6SPR4 message bytes overflow".to_owned())?;
    let encoded_bytes = encoded_elements
        .checked_mul(field_bytes)
        .ok_or_else(|| "C6SPR4 encoded bytes overflow".to_owned())?;
    let merkle_bytes = merkle_digests
        .checked_mul(C61_WHIRA1_DIGEST_BYTES as u64)
        .ok_or_else(|| "C6SPR4 Merkle bytes overflow".to_owned())?;
    let retained = message_bytes
        .checked_add(encoded_bytes)
        .and_then(|bytes| bytes.checked_add(merkle_bytes))
        .ok_or_else(|| "C6SPR4 retained bytes overflow".to_owned())?;
    Ok((message_bytes, encoded_bytes, merkle_bytes, retained))
}

/// Compute the exact total-memory lower bound retained by the generic P3
/// prover at the registered D28/D27 geometry.
///
/// The generic diagnostic rejects D28 rather than attempting this allocation
/// without resource instrumentation.  This report does not compare total
/// memory against the narrower coefficient-plus-witness protocol cap.
pub fn c61_production_monolithic_memory_census(
) -> Result<C61ProductionMonolithicMemoryCensus, String> {
    let response_num_variables = 28;
    let plan_num_variables = 27;
    let (
        response_message_bytes,
        response_encoded_bytes,
        response_merkle_bytes,
        response_retained_lower_bound_bytes,
    ) = c61_monolithic_initial_oracle_retained_lower_bound(response_num_variables)?;
    let (
        plan_message_bytes,
        plan_encoded_bytes,
        plan_merkle_bytes,
        plan_retained_lower_bound_bytes,
    ) = c61_monolithic_initial_oracle_retained_lower_bound(plan_num_variables)?;
    let concurrent_retained_lower_bound_bytes = response_retained_lower_bound_bytes
        .checked_add(plan_retained_lower_bound_bytes)
        .ok_or_else(|| "C6SPR4 concurrent retained bytes overflow".to_owned())?;
    let retained_minus_component_cap_bytes = concurrent_retained_lower_bound_bytes
        .checked_sub(C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES)
        .ok_or_else(|| "C6SPR4 retained total is below its informative comparison".to_owned())?;
    Ok(C61ProductionMonolithicMemoryCensus {
        response_num_variables,
        plan_num_variables,
        response_message_bytes,
        response_encoded_bytes,
        response_merkle_bytes,
        response_retained_lower_bound_bytes,
        plan_message_bytes,
        plan_encoded_bytes,
        plan_merkle_bytes,
        plan_retained_lower_bound_bytes,
        concurrent_retained_lower_bound_bytes,
        coefficient_witness_cap_bytes: C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES,
        retained_minus_component_cap_bytes,
    })
}

fn reject_monolithic_production_backend() -> Result<(), String> {
    let census = c61_production_monolithic_memory_census()?;
    Err(format!(
        "C6SPR4 generic diagnostic is not a resource-instrumented production executor: its concurrent D28/D27 P3 prover data retains at least {} B; use an explicit persisted/recomputable or GPU-resident executor and measure total RSS/GPU memory separately",
        census.concurrent_retained_lower_bound_bytes,
    ))
}

fn encode_fp_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<Goldilocks, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<()> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err(C61WhirReferenceError::new("C6AWP1 base-field opening shape mismatch"));
    }
    for row in &opening.rows {
        for value in row {
            writer.fp(*value);
        }
    }
    writer.multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
}

fn encode_fp2_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<C61P3Fp2, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<()> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err(C61WhirReferenceError::new("C6AWP1 extension opening shape mismatch"));
    }
    for row in &opening.rows {
        for value in row {
            writer.fp2(*value);
        }
    }
    writer.multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
}

fn decode_fp_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<SharedProofOpening<Goldilocks, C61MultiProof>> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp()?);
        }
        rows.push(row);
    }
    let proof = reader.multiproof(c61_max_pruned_binary_siblings(leaves, queries))?;
    Ok(SharedProofOpening { rows, proof })
}

fn decode_fp2_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<SharedProofOpening<C61P3Fp2, C61MultiProof>> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp2()?);
        }
        rows.push(row);
    }
    let proof = reader.multiproof(c61_max_pruned_binary_siblings(leaves, queries))?;
    Ok(SharedProofOpening { rows, proof })
}

fn encode_c61_authenticated_p3_artifact_inner<MT>(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
    base_proof: C61AuthenticatedWhirBaseProof,
    production_dimensions_only: bool,
) -> ReferenceResult<Vec<u8>>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>,
{
    let budget =
        c61_authenticated_structural_budget_inner(num_variables, production_dimensions_only)
            .map_err(C61WhirReferenceError::new)?;
    let config = c61_authenticated_config::<C61SizingChallenger>(num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut body = C61Writer::default();
    body.commitment(commitment)?;
    if proof.sumchecks.len() != batches || proof.sumcheck_mask_commitments.len() != batches {
        return Err(C61WhirReferenceError::new("C6AWP1 sumcheck batch count mismatch"));
    }
    for (batch, sumcheck) in proof.sumchecks.iter().enumerate() {
        let rounds = config.round_folding_factor(batch);
        if sumcheck.ell_zk != C61_WHIRA1_ELL_ZK
            || sumcheck.round_coefficients.len() != rounds
            || sumcheck
                .round_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != C61_WHIRA1_ELL_ZK - 1)
            || !sumcheck.pow_witnesses.is_empty()
        {
            return Err(C61WhirReferenceError::new("C6AWP1 sumcheck shape mismatch"));
        }
        body.fp2(sumcheck.mu_tilde);
        for coefficients in &sumcheck.round_coefficients {
            for coefficient in coefficients {
                body.fp2(*coefficient);
            }
        }
    }
    for root in &proof.sumcheck_mask_commitments {
        body.commitment(root)?;
    }

    if proof.rounds.len() != config.n_rounds() {
        return Err(C61WhirReferenceError::new("C6AWP1 round count mismatch"));
    }
    for (index, (round_proof, round)) in
        proof.rounds.iter().zip(&config.round_parameters).enumerate()
    {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        body.commitment(&round_proof.commitment)?;
        body.commitment(&round_proof.mask_commitment)?;
        if round_proof.ood_answers.len() != round.ood_samples
            || round_proof.pow_witness != Goldilocks::ZERO
        {
            return Err(C61WhirReferenceError::new("C6AWP1 round scalar shape mismatch"));
        }
        for answer in &round_proof.ood_answers {
            body.fp2(*answer);
        }
        match (&round_proof.openings, index) {
            (QueryOpenings::Base(opening), 0) => {
                encode_fp_opening(&mut body, opening, round.num_queries, 1usize << fold, leaves)?;
            }
            (QueryOpenings::Extension(opening), index) if index > 0 => {
                encode_fp2_opening(&mut body, opening, round.num_queries, 1usize << fold, leaves)?;
            }
            _ => {
                return Err(C61WhirReferenceError::new("C6AWP1 round opening field tag mismatch"));
            }
        }
    }

    let base = &proof.base_case;
    body.commitment(&base.fresh_main_commitment)?;
    if base.fresh_mask_commitments.len() != groups.len() {
        return Err(C61WhirReferenceError::new("C6AWP1 fresh-mask commitment count mismatch"));
    }
    for commitment in &base.fresh_mask_commitments {
        body.commitment(commitment)?;
    }
    body.fp2(base.masked_claim);

    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];
    if base.blinded_message.len() != final_message_elements
        || base.blinded_randomness.len() != final_randomness_elements
    {
        return Err(C61WhirReferenceError::new("C6AWP1 base source reveal shape mismatch"));
    }
    for value in &base.blinded_message {
        body.fp2(*value);
    }
    for value in &base.blinded_randomness {
        body.fp2(*value);
    }

    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    if base.blinded_masks.len() != flat_masks {
        return Err(C61WhirReferenceError::new("C6AWP1 blinded-mask count mismatch"));
    }
    let mut mask_index = 0usize;
    for group in &groups {
        for _ in 0..group.width {
            let mask = &base.blinded_masks[mask_index];
            mask_index += 1;
            if mask.message.len() != group.shape.message_len
                || mask.randomness.len() != group.shape.randomness_len
            {
                return Err(C61WhirReferenceError::new("C6AWP1 blinded-mask shape mismatch"));
            }
            for value in &mask.message {
                body.fp2(*value);
            }
            for value in &mask.randomness {
                body.fp2(*value);
            }
        }
    }
    if base.pow_witness != Goldilocks::ZERO {
        return Err(C61WhirReferenceError::new("C6AWP1 forbids a base-case PoW witness"));
    }
    match &base.source_openings {
        QueryOpenings::Extension(opening) => encode_fp2_opening(
            &mut body,
            opening,
            config.final_queries,
            1usize << final_round.folding_factor,
            final_domain,
        )?,
        QueryOpenings::Base(_) => {
            return Err(C61WhirReferenceError::new("C6AWP1 final source opening must use Fp2"));
        }
    }
    encode_fp2_opening(
        &mut body,
        &base.fresh_main_openings,
        config.final_queries,
        1,
        final_domain,
    )?;
    if base.mask_openings.len() != groups.len() {
        return Err(C61WhirReferenceError::new("C6AWP1 mask-opening group count mismatch"));
    }
    for (opening, group) in base.mask_openings.iter().zip(&groups) {
        encode_fp2_opening(
            &mut body,
            &opening.carried,
            config.mask_queries,
            group.width,
            group.shape.domain_size,
        )?;
        encode_fp2_opening(
            &mut body,
            &opening.fresh,
            config.mask_queries,
            group.width,
            group.shape.domain_size,
        )?;
    }
    body.bytes.extend_from_slice(&base_proof.encode());

    let total = C61_AUTHENTICATED_P3_HEADER_BYTES
        .checked_add(body.bytes.len())
        .ok_or_else(|| C61WhirReferenceError::new("C6AWP1 total length overflow"))?;
    if total > budget.strict_chain_bytes || total > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds its structural cap"));
    }
    let mut writer = C61Writer::default();
    writer.bytes.extend_from_slice(&C61_AUTHENTICATED_P3_MAGIC);
    writer.u16(C61_AUTHENTICATED_P3_VERSION);
    writer.u8(u8::try_from(num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6AWP1 dimension exceeds u8"))?);
    writer.u8(0);
    writer.u32(body.bytes.len())?;
    writer.bytes.extend_from_slice(&body.bytes);
    Ok(writer.bytes)
}

fn decode_c61_authenticated_p3_artifact_inner(
    bytes: &[u8],
    expected_num_variables: usize,
    production_dimensions_only: bool,
) -> ReferenceResult<(C61Commitment, C61AuthenticatedP3Proof, C61AuthenticatedWhirBaseProof)> {
    if bytes.len() > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds native-chain cap"));
    }
    let budget = c61_authenticated_structural_budget_inner(
        expected_num_variables,
        production_dimensions_only,
    )
    .map_err(C61WhirReferenceError::new)?;
    if bytes.len() > budget.strict_chain_bytes {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds its structural cap"));
    }
    let config = c61_authenticated_config::<C61SizingChallenger>(expected_num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut reader = C61Reader::new(bytes);
    if reader.take(8)? != C61_AUTHENTICATED_P3_MAGIC {
        return Err(C61WhirReferenceError::new("C6AWP1 magic mismatch"));
    }
    if reader.u16()? != C61_AUTHENTICATED_P3_VERSION {
        return Err(C61WhirReferenceError::new("C6AWP1 version mismatch"));
    }
    if reader.u8()? as usize != expected_num_variables {
        return Err(C61WhirReferenceError::new("C6AWP1 dimension mismatch"));
    }
    if reader.u8()? != 0 {
        return Err(C61WhirReferenceError::new("C6AWP1 reserved byte is nonzero"));
    }
    let body_len = reader.u32()?;
    if body_len != bytes.len().saturating_sub(C61_AUTHENTICATED_P3_HEADER_BYTES) {
        return Err(C61WhirReferenceError::new("C6AWP1 body length mismatch"));
    }

    let commitment = reader.commitment()?;
    let mut sumchecks = Vec::with_capacity(batches);
    for batch in 0..batches {
        let rounds = config.round_folding_factor(batch);
        let mu_tilde = reader.fp2()?;
        let mut round_coefficients = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let mut coefficients = Vec::with_capacity(C61_WHIRA1_ELL_ZK - 1);
            for _ in 0..C61_WHIRA1_ELL_ZK - 1 {
                coefficients.push(reader.fp2()?);
            }
            round_coefficients.push(coefficients);
        }
        sumchecks.push(ClaimlessZkSumcheckData {
            mu_tilde,
            ell_zk: C61_WHIRA1_ELL_ZK,
            round_coefficients,
            pow_witnesses: Vec::new(),
        });
    }
    let mut sumcheck_mask_commitments = Vec::with_capacity(batches);
    for _ in 0..batches {
        sumcheck_mask_commitments.push(reader.commitment()?);
    }

    let mut rounds = Vec::with_capacity(config.n_rounds());
    for (index, round) in config.round_parameters.iter().enumerate() {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let commitment = reader.commitment()?;
        let mask_commitment = reader.commitment()?;
        let mut ood_answers = Vec::with_capacity(round.ood_samples);
        for _ in 0..round.ood_samples {
            ood_answers.push(reader.fp2()?);
        }
        let openings = if index == 0 {
            QueryOpenings::Base(decode_fp_opening(
                &mut reader,
                round.num_queries,
                1usize << fold,
                leaves,
            )?)
        } else {
            QueryOpenings::Extension(decode_fp2_opening(
                &mut reader,
                round.num_queries,
                1usize << fold,
                leaves,
            )?)
        };
        rounds.push(ZkRoundProof {
            commitment,
            mask_commitment,
            ood_answers,
            pow_witness: Goldilocks::ZERO,
            openings,
        });
    }

    let fresh_main_commitment = reader.commitment()?;
    let mut fresh_mask_commitments = Vec::with_capacity(groups.len());
    for _ in 0..groups.len() {
        fresh_mask_commitments.push(reader.commitment()?);
    }
    let masked_claim = reader.fp2()?;
    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];
    let mut blinded_message = Vec::with_capacity(final_message_elements);
    for _ in 0..final_message_elements {
        blinded_message.push(reader.fp2()?);
    }
    let mut blinded_randomness = Vec::with_capacity(final_randomness_elements);
    for _ in 0..final_randomness_elements {
        blinded_randomness.push(reader.fp2()?);
    }
    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    let mut blinded_masks = Vec::with_capacity(flat_masks);
    for group in &groups {
        for _ in 0..group.width {
            let mut message = Vec::with_capacity(group.shape.message_len);
            for _ in 0..group.shape.message_len {
                message.push(reader.fp2()?);
            }
            let mut randomness = Vec::with_capacity(group.shape.randomness_len);
            for _ in 0..group.shape.randomness_len {
                randomness.push(reader.fp2()?);
            }
            blinded_masks.push(BlindedMask { message, randomness });
        }
    }
    let source_openings = QueryOpenings::Extension(decode_fp2_opening(
        &mut reader,
        config.final_queries,
        1usize << final_round.folding_factor,
        final_domain,
    )?);
    let fresh_main_openings =
        decode_fp2_opening(&mut reader, config.final_queries, 1, final_domain)?;
    let mut mask_openings = Vec::with_capacity(groups.len());
    for group in &groups {
        mask_openings.push(MaskOpeningPair {
            carried: decode_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
            fresh: decode_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
        });
    }
    let base_proof = C61AuthenticatedWhirBaseProof::decode(
        reader.take(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)?,
    )
    .map_err(|error| C61WhirReferenceError::new(error.to_string()))?;
    reader.finish()?;

    let base_case = BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness: Goldilocks::ZERO,
        source_openings,
        fresh_main_openings,
        mask_openings,
    };
    Ok((
        commitment,
        ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case },
        base_proof,
    ))
}

fn encode_c61_shared_multi_oracle_artifact(
    response_num_variables: usize,
    plan_num_variables: usize,
    response_payload: &[u8],
    plan_payload: &[u8],
) -> ReferenceResult<C61SharedMultiOracleArtifact> {
    let (_, _, _) = decode_c61_authenticated_p3_artifact_inner(
        response_payload,
        response_num_variables,
        false,
    )?;
    let (_, _, plan_reserved_tag) =
        decode_c61_authenticated_p3_artifact_inner(plan_payload, plan_num_variables, false)?;
    if plan_reserved_tag.tag() != Fp2::ZERO {
        return Err(C61WhirReferenceError::new(
            "C6SMO1 plan payload must carry the canonical zero reserved tag",
        ));
    }
    let body_len = response_payload
        .len()
        .checked_add(plan_payload.len())
        .ok_or_else(|| C61WhirReferenceError::new("C6SMO1 body length overflow"))?;
    let total_len = C61_SHARED_MULTI_ORACLE_HEADER_BYTES
        .checked_add(body_len)
        .ok_or_else(|| C61WhirReferenceError::new("C6SMO1 total length overflow"))?;
    if total_len > C61_SHARED_MULTI_ORACLE_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6SMO1 payload exceeds compiler-chain cap"));
    }
    let mut writer = C61Writer::default();
    writer.bytes.extend_from_slice(&C61_SHARED_MULTI_ORACLE_MAGIC);
    writer.u16(C61_SHARED_MULTI_ORACLE_VERSION);
    writer.u8(u8::try_from(response_num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6SMO1 response dimension exceeds u8"))?);
    writer.u8(u8::try_from(plan_num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6SMO1 plan dimension exceeds u8"))?);
    writer.u32(response_payload.len())?;
    writer.bytes.extend_from_slice(response_payload);
    writer.bytes.extend_from_slice(plan_payload);
    Ok(C61SharedMultiOracleArtifact { payload: writer.bytes })
}

fn decode_c61_shared_multi_oracle_artifact(
    artifact: &C61SharedMultiOracleArtifact,
    expected_response_num_variables: usize,
    expected_plan_num_variables: usize,
) -> ReferenceResult<(
    (C61Commitment, C61AuthenticatedP3Proof),
    (C61Commitment, C61AuthenticatedP3Proof),
    C61AuthenticatedWhirBaseProof,
)> {
    if artifact.payload.len() > C61_SHARED_MULTI_ORACLE_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6SMO1 payload exceeds compiler-chain cap"));
    }
    let mut reader = C61Reader::new(&artifact.payload);
    if reader.take(8)? != C61_SHARED_MULTI_ORACLE_MAGIC {
        return Err(C61WhirReferenceError::new("C6SMO1 magic mismatch"));
    }
    if reader.u16()? != C61_SHARED_MULTI_ORACLE_VERSION {
        return Err(C61WhirReferenceError::new("C6SMO1 version mismatch"));
    }
    if reader.u8()? as usize != expected_response_num_variables {
        return Err(C61WhirReferenceError::new("C6SMO1 response dimension mismatch"));
    }
    if reader.u8()? as usize != expected_plan_num_variables {
        return Err(C61WhirReferenceError::new("C6SMO1 plan dimension mismatch"));
    }
    let response_len = reader.u32()?;
    if response_len == 0
        || response_len
            > artifact.payload.len().saturating_sub(C61_SHARED_MULTI_ORACLE_HEADER_BYTES)
    {
        return Err(C61WhirReferenceError::new("C6SMO1 response length is noncanonical"));
    }
    let response_payload = reader.take(response_len)?;
    let plan_payload = reader.take(
        artifact
            .payload
            .len()
            .saturating_sub(C61_SHARED_MULTI_ORACLE_HEADER_BYTES)
            .saturating_sub(response_len),
    )?;
    reader.finish()?;
    if plan_payload.is_empty() {
        return Err(C61WhirReferenceError::new("C6SMO1 plan payload is empty"));
    }
    let (response_commitment, response_proof, joint_tag) =
        decode_c61_authenticated_p3_artifact_inner(
            response_payload,
            expected_response_num_variables,
            false,
        )?;
    let (plan_commitment, plan_proof, plan_reserved_tag) =
        decode_c61_authenticated_p3_artifact_inner(
            plan_payload,
            expected_plan_num_variables,
            false,
        )?;
    if plan_reserved_tag.tag() != Fp2::ZERO {
        return Err(C61WhirReferenceError::new("C6SMO1 plan reserved tag is nonzero"));
    }
    Ok(((response_commitment, response_proof), (plan_commitment, plan_proof), joint_tag))
}

#[allow(clippy::too_many_arguments)]
fn prove_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedP3Fixture, u64), String> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err("C6AWH1-P3 witness/point dimension mismatch".to_owned());
    }
    let evaluation_p3 = witness.eval_base(&point);
    let evaluation = c61_volta_fp2_from_p3(evaluation_p3);
    let target = ProverAuthed::new(evaluation, target_tag);
    let target_key = VerifierKey::new(target_tag + delta * evaluation);

    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = StdRng::seed_from_u64(prover_rng_seed);
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);

    // The low-level fork deliberately has no target-revealing PCS adapter.
    // Reproduce its load-bearing statement order explicitly: root first,
    // then the verifier-owned opening point, then the first native challenge.
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    let mut correlations = CorrelationStream::new(pcg_seed);
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
        .map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), evaluation_p3)],
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;

    // Account for every serialized WHIR byte before the final ZeroOpen move.
    // Challenge-bearing fields were already observed in interactive order;
    // the tag itself is the final 16-byte move appended by C6AWH1.
    let placeholder_base_proof =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        placeholder_base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let provider_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&[target], &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 ZeroOpen tag changed the strict payload length".to_owned());
    }

    Ok((
        C61AuthenticatedP3Fixture {
            artifact: C61AuthenticatedP3Artifact { payload },
            point,
            target_key,
            provider_affine,
            provider_base_case: output.base_case,
            provider_interaction,
            provider_transcript_bytes: transcript.total_bytes(),
            provider_ledger: transcript.ledger().clone(),
        },
        correlations.counters.full_corrs,
    ))
}

fn c61_private_entropy_context_digest(
    point: &Point<C61P3Fp2>,
    target_key: VerifierKey,
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"C6ICT1-private-entropy-context-v1");
    hasher.update(&(point.num_variables() as u64).to_le_bytes());
    for coordinate in point.as_slice() {
        let coefficients: &[Goldilocks] =
            <C61P3Fp2 as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(coordinate);
        for coefficient in coefficients {
            hasher.update(&coefficient.as_canonical_u64().to_le_bytes());
        }
    }
    hasher.update(&target_key.k.c0.value().to_le_bytes());
    hasher.update(&target_key.k.c1.value().to_le_bytes());
    hasher.update(&delta.c0.value().to_le_bytes());
    hasher.update(&delta.c1.value().to_le_bytes());
    hasher.update(&[match id.component {
        C61NativeComponent::Model => 0,
        C61NativeComponent::Embedding => 1,
        C61NativeComponent::Compiler => 2,
    }]);
    hasher.update(&[id.repetition]);
    hasher.update(&[mask_range.stage]);
    hasher.update(&mask_range.slot.to_le_bytes());
    hasher.update(&mask_range.range_start.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[allow(clippy::too_many_arguments)]
fn prove_private_entropy_provider_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    mut challenger: C61PrivateEntropyProverChallenger,
) -> Result<C61PrivateEntropyProviderFixture, String> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err("C6ICT1 witness/point dimension mismatch".to_owned());
    }
    let evaluation_p3 = witness.eval_base(&point);
    let evaluation = c61_volta_fp2_from_p3(evaluation_p3);
    let target = ProverAuthed::new(evaluation, target_tag);
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let config = c61_authenticated_config::<C61PrivateEntropyProverChallenger>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = StdRng::seed_from_u64(prover_rng_seed);
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    let mut correlations = CorrelationStream::new(pcg_seed);
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
        .map_err(|error| error.to_string())?;
    challenger.note_mask_frontier(1).map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), evaluation_p3)],
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );

    // This transcript is provider-side accounting for the terminal ZeroOpen
    // only.  Its dummy seed is never used to draw a challenge; all native
    // challenges came through the endpoint-only transport challenger.
    let mut zero_open_transcript = Transcript::new([0u8; 32]);
    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&[target], &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut zero_open_transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let finish_result = challenger.finish(&payload[..whir_payload_bytes]);
    drop(challenger);
    finish_result.map_err(|error| error.to_string())?;

    Ok(C61PrivateEntropyProviderFixture {
        artifact: C61AuthenticatedP3Artifact { payload },
        point,
        target_key,
        provider_affine,
        provider_base_case: output.base_case,
        full_correlations: correlations.counters.full_corrs,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_private_entropy_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    checkpoint: C61InteractiveCheckpoint,
    durable: Option<C61DurableJournal>,
) -> Result<C61PrivateEntropyFixture, String> {
    let num_variables = witness.num_variables();
    let evaluation = c61_volta_fp2_from_p3(witness.eval_base(&point));
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let context_digest =
        c61_private_entropy_context_digest(&point, target_key, delta, id, mask_range);
    let (challenger, broker_handle) = match durable {
        Some(journal) => spawn_c61_durable_private_entropy_broker(
            verifier_seed,
            num_variables,
            context_digest,
            journal,
        ),
        None => spawn_c61_private_entropy_broker(
            verifier_seed,
            num_variables,
            context_digest,
            checkpoint,
        ),
    }
    .map_err(|error| error.to_string())?;
    let provider = prove_private_entropy_provider_diagnostic(
        witness,
        point,
        prover_rng_seed,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        challenger,
    );
    let broker = broker_handle
        .join()
        .map_err(|_| "C6ICT1 verifier broker panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    let provider = provider?;
    let whir_payload_bytes = provider
        .artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    if broker.transcript_bytes != whir_payload_bytes as u64 {
        return Err("C6ICT1 broker payload accounting mismatch".to_owned());
    }
    Ok(C61PrivateEntropyFixture {
        artifact: provider.artifact,
        point: provider.point,
        target_key: provider.target_key,
        provider_affine: provider.provider_affine,
        provider_base_case: provider.provider_base_case,
        broker,
        full_correlations: provider.full_correlations,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_private_entropy_diagnostic(
    artifact: &C61AuthenticatedP3Artifact,
    point: &Point<C61P3Fp2>,
    target_key: VerifierKey,
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    tape: C61InteractiveTape,
) -> Result<
    (C61AuthenticatedWhirAffineClaim, BaseCaseClaimlessClosure<C61P3Fp2>, C61WhirInteractionStats),
    String,
> {
    let num_variables = point.num_variables();
    let context_digest =
        c61_private_entropy_context_digest(point, target_key, delta, id, mask_range);
    let (commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&artifact.payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut challenger =
        C61PrivateEntropyReplayChallenger::new(tape, num_variables, context_digest)
            .map_err(|error| error.to_string())?;
    let config = c61_authenticated_config::<C61PrivateEntropyReplayChallenger>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(commitment.clone());
    challenger.observe_public_point(point).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(&proof, &commitment, std::slice::from_ref(point), &mut challenger)
    }))
    .map_err(|_| "C6ICT1 fork verifier panicked".to_owned())?
    .map_err(|error| format!("C6ICT1 verification failed: {error}"))?;
    let whir_payload_bytes = artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let verifier_interaction = challenger
        .finish(&artifact.payload[..whir_payload_bytes])
        .map_err(|error| error.to_string())?;
    drop(challenger);

    let verifier_affine = affine_from_p3(result.target);
    let aggregate_target = aggregate_verifier_targets(&[target_key], &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_target, delta);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let mut zero_open_transcript = Transcript::new([0u8; 32]);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut zero_open_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok((verifier_affine, result.base_case, verifier_interaction))
}

/// Produce an accepting designated-verifier view without the real witness or
/// target plaintext.  This is deliberately separate from `prove_diagnostic`:
/// it has no target-plaintext/tag argument and never constructs a provider
/// correlation stream.
#[allow(clippy::too_many_arguments)]
fn simulate_view_diagnostic(
    num_variables: usize,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    verifier_seed: [u8; 32],
    simulator_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedP3Fixture, u64), String> {
    if point.num_variables() != num_variables {
        return Err("C6AWP1 simulator point dimension mismatch".to_owned());
    }

    // A simulator may generate internal dummy values; it must not receive the
    // real relation witness.  A uniform surrogate makes the executable path
    // exercise the full commitment/opening machinery without coupling it to
    // the real target hidden behind `target_key`.
    let mut rng = StdRng::seed_from_u64(simulator_rng_seed);
    let surrogate = Poly::new((0..(1usize << num_variables)).map(|_| rng.random()).collect());
    let surrogate_evaluation = surrogate.eval_base(&point);

    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let (commitment, data) = prover.commit(surrogate, &mut challenger, &mut rng);
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    // In a real execution this shift is the plaintext half of the fresh
    // C6AWH1 correlation.  Conditioned on the verifier's mask key it remains
    // uniform, so the simulator samples it directly and later derives the
    // only correlated observable (the final tag) from verifier state.
    let simulated_base_shift: C61P3Fp2 = rng.random();
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), surrogate_evaluation)],
        simulated_base_shift,
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;

    let placeholder_base_proof =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        placeholder_base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 simulator payload is shorter than its ZeroOpen tag".to_owned())?;
    let simulator_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_verifier_targets(&[target_key], &output.claim_weights)?;
    let final_key = affine.derive_verifier_key(aggregate_target, delta);
    let mut simulator_context = VerifierCtx::new(pcg_seed, delta);
    let base_proof = simulate_c61_authenticated_whir_base_view(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_key,
        },
        &mut simulator_context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 simulator tag changed the strict payload length".to_owned());
    }

    Ok((
        C61AuthenticatedP3Fixture {
            artifact: C61AuthenticatedP3Artifact { payload },
            point,
            target_key,
            provider_affine: affine,
            provider_base_case: output.base_case,
            provider_interaction: simulator_interaction,
            provider_transcript_bytes: transcript.total_bytes(),
            provider_ledger: transcript.ledger().clone(),
        },
        simulator_context.counters.full_corrs,
    ))
}

fn verify_diagnostic(
    artifact: &C61AuthenticatedP3Artifact,
    input: C61AuthenticatedP3VerifierInput<'_>,
) -> Result<
    (
        C61AuthenticatedWhirAffineClaim,
        BaseCaseClaimlessClosure<C61P3Fp2>,
        Transcript,
        C61WhirInteractionStats,
    ),
    String,
> {
    let num_variables = input.point.num_variables();
    let (commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&artifact.payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut transcript = Transcript::new(input.verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(commitment.clone());
    challenger.observe_public_point(input.point).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(
            &proof,
            &commitment,
            std::slice::from_ref(input.point),
            &mut challenger,
        )
    }))
    .map_err(|_| "C6AWH1-P3 fork verifier panicked".to_owned())?
    .map_err(|error| format!("C6AWH1-P3 verification failed: {error}"))?;
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
    let whir_payload_bytes = artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let verifier_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let verifier_affine = affine_from_p3(result.target);
    let aggregate_target = aggregate_verifier_targets(&[input.target_key], &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_target, input.delta);
    let mut context = VerifierCtx::new(input.pcg_seed, input.delta);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id: input.id,
            mask_range: input.mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok((verifier_affine, result.base_case, transcript, verifier_interaction))
}

/// Run one reference-only end-to-end differential.  Small dimensions are
/// diagnostic; D27/D28 remain the only production-profile shapes.
pub fn run_c61_authenticated_whir_p3_diagnostic(
    num_variables: usize,
) -> Result<C61AuthenticatedP3Diagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWH1-P3 diagnostic dimension must be in 4..=28".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(17).wrapping_add(3)))
            .collect(),
    );
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(19).wrapping_add(5)))
            .collect(),
    );
    let verifier_seed = [0x61; 32];
    let pcg_seed = [0xA7; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 17), volta_field::Fp::new(0x1234_5678));
    let target_tag = Fp2::new(volta_field::Fp::new(41), volta_field::Fp::new(43));
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 1, range_start: 40_000 };
    let (fixture, full_correlations) = prove_diagnostic(
        witness,
        point,
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
    )?;
    let (verifier_affine, verifier_base_case, verifier_transcript, verifier_interaction) =
        verify_diagnostic(
            &fixture.artifact,
            C61AuthenticatedP3VerifierInput {
                point: &fixture.point,
                target_key: fixture.target_key,
                verifier_seed,
                pcg_seed,
                delta,
                id,
                mask_range,
            },
        )?;
    if fixture.provider_affine != verifier_affine {
        return Err("C6AWH1-P3 provider/verifier affine replay mismatch".to_owned());
    }
    if fixture.provider_base_case != verifier_base_case {
        return Err("C6AWH1-P3 provider/verifier base closure mismatch".to_owned());
    }
    if fixture.provider_interaction != verifier_interaction {
        return Err("C6AWP1 provider/verifier interaction accounting mismatch".to_owned());
    }
    if fixture.provider_ledger != *verifier_transcript.ledger() {
        return Err("C6AWH1-P3 provider/verifier transcript ledger mismatch".to_owned());
    }
    Ok(C61AuthenticatedP3Diagnostic {
        num_variables,
        provider_affine: fixture.provider_affine,
        verifier_affine,
        provider_transcript_bytes: fixture.provider_transcript_bytes,
        verifier_transcript_bytes: verifier_transcript.total_bytes(),
        provider_ledger: fixture.provider_ledger,
        verifier_ledger: verifier_transcript.ledger().clone(),
        strict_payload_bytes: fixture.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&fixture.artifact.payload).as_bytes(),
        provider_interaction: fixture.provider_interaction,
        verifier_interaction,
        proof_has_clear_evaluation_field: false,
        full_correlations,
    })
}

/// Exercise the exact ordered multi-opening reduction needed by the future
/// model/embedding adapter.  This remains a scaled feature-only diagnostic:
/// it proves openings of one committed polynomial, not yet the complete C6
/// compiler relation.
pub fn run_c61_authenticated_whir_p3_multi_open_diagnostic(
    num_variables: usize,
    claim_count: usize,
) -> Result<C61AuthenticatedP3MultiOpenDiagnostic, String> {
    if !(4..=20).contains(&num_variables) || !(2..=128).contains(&claim_count) {
        return Err("C6AWP1 multi-open diagnostic geometry is out of range".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(31).wrapping_add(7)))
            .collect(),
    );
    let points: Vec<_> = (0..claim_count)
        .map(|claim| {
            Point::new(
                (0..num_variables)
                    .map(|coordinate| {
                        C61P3Fp2::from_u64(
                            (claim as u64 + 3)
                                .wrapping_mul(37)
                                .wrapping_add((coordinate as u64 + 5).wrapping_mul(41)),
                        )
                    })
                    .collect(),
            )
        })
        .collect();
    let evaluations: Vec<_> = points.iter().map(|point| witness.eval_base(point)).collect();
    let delta = Fp2::new(volta_field::Fp::new(P - 59), volta_field::Fp::new(0xC6_6101));
    let targets: Vec<_> = evaluations
        .iter()
        .enumerate()
        .map(|(index, evaluation)| {
            let value = c61_volta_fp2_from_p3(*evaluation);
            let tag = Fp2::new(
                volta_field::Fp::new(101 + index as u64 * 2),
                volta_field::Fp::new(103 + index as u64 * 2),
            );
            ProverAuthed::new(value, tag)
        })
        .collect();
    let target_keys: Vec<_> =
        targets.iter().map(|target| VerifierKey::new(target.m + delta * target.x)).collect();
    let claims: Vec<_> = points.iter().cloned().zip(evaluations.iter().copied()).collect();
    let verifier_seed = [0xB7; 32];
    let pcg_seed = [0xD9; 32];
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 21, range_start: 90_000 };

    let mut provider_transcript = Transcript::new(verifier_seed);
    let mut correlations = CorrelationStream::new(pcg_seed);
    let (
        commitment,
        output,
        prepared,
        placeholder_payload,
        whir_payload_bytes,
        provider_interaction,
    ) = {
        let mut provider_challenger =
            C61InteractiveChallenger::new_claimless(&mut provider_transcript, num_variables);
        let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
        let mmcs = c61_reference_mmcs();
        let dft = Radix2DFTSmallBatch::default();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);
        let mut rng = StdRng::seed_from_u64(0xC6_6101);
        let (commitment, data) = prover.commit(witness, &mut provider_challenger, &mut rng);
        provider_challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
        let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
            .map_err(|error| error.to_string())?;
        let output = prover.prove_claimless(
            data,
            &claims,
            c61_p3_fp2_from_volta(prepared.value()),
            &mut provider_challenger,
            &mut rng,
        );
        provider_challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
        let placeholder = C61AuthenticatedWhirBaseProof::decode(
            &[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES],
        )
        .map_err(|error| error.to_string())?;
        let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
            num_variables,
            &commitment,
            &output.proof,
            placeholder,
            false,
        )
        .map_err(|error| error.to_string())?;
        let whir_payload_bytes = placeholder_payload
            .len()
            .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
            .ok_or_else(|| "C6AWP1 multi-open payload is shorter than its tag".to_owned())?;
        let provider_interaction =
            provider_challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
        (
            commitment,
            output,
            prepared,
            placeholder_payload,
            whir_payload_bytes,
            provider_interaction,
        )
    };
    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&targets, &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 multi-open tag changed the strict payload length".to_owned());
    }

    let (decoded_commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut verifier_transcript = Transcript::new(verifier_seed);
    let (result, verifier_interaction) = {
        let mut verifier_challenger =
            C61InteractiveChallenger::new_claimless(&mut verifier_transcript, num_variables);
        let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
        let mmcs = c61_reference_mmcs();
        verifier_challenger.observe(decoded_commitment.clone());
        verifier_challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
        let verifier = HidingWhirVerifier::new(&config, &mmcs);
        let result = catch_unwind(AssertUnwindSafe(|| {
            verifier.verify_claimless(
                &proof,
                &decoded_commitment,
                &points,
                &mut verifier_challenger,
            )
        }))
        .map_err(|_| "C6AWP1 multi-open verifier panicked".to_owned())?
        .map_err(|error| format!("C6AWP1 multi-open verification failed: {error}"))?;
        let verifier_interaction =
            verifier_challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
        (result, verifier_interaction)
    };
    let verifier_affine = affine_from_p3(result.target);
    let aggregate_key = aggregate_verifier_targets(&target_keys, &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_key, delta);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    if provider_affine != verifier_affine
        || provider_interaction != verifier_interaction
        || provider_transcript.ledger() != verifier_transcript.ledger()
    {
        return Err("C6AWP1 multi-open role differential mismatch".to_owned());
    }

    let mut changed_points = points.clone();
    let mut changed_coordinates = changed_points[0].as_slice().to_vec();
    changed_coordinates[0] += C61P3Fp2::ONE;
    changed_points[0] = Point::new(changed_coordinates);
    let mut changed_transcript = Transcript::new(verifier_seed);
    let mut changed_challenger =
        C61InteractiveChallenger::new_claimless(&mut changed_transcript, num_variables);
    let changed_config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let changed_mmcs = c61_reference_mmcs();
    let changed_verifier = HidingWhirVerifier::new(&changed_config, &changed_mmcs);
    changed_challenger.observe(decoded_commitment.clone());
    changed_challenger.observe_public_points(&changed_points).map_err(|error| error.to_string())?;
    let changed_result = catch_unwind(AssertUnwindSafe(|| {
        changed_verifier.verify_claimless(
            &proof,
            &decoded_commitment,
            &changed_points,
            &mut changed_challenger,
        )
    }));
    let point_mutation_rejected = match changed_result {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(changed_closure)) => {
            let finish = changed_challenger.finish(whir_payload_bytes);
            let aggregate_key =
                aggregate_verifier_targets(&target_keys, &changed_closure.claim_weights);
            let (_, _, changed_base_proof) =
                decode_c61_authenticated_p3_artifact_inner(&payload, num_variables, false)
                    .map_err(|error| error.to_string())?;
            match (finish, aggregate_key) {
                (Ok(_), Ok(aggregate_key)) => {
                    let changed_affine = affine_from_p3(changed_closure.target);
                    let changed_final_key =
                        changed_affine.derive_verifier_key(aggregate_key, delta);
                    let mut changed_context = VerifierCtx::new(pcg_seed, delta);
                    verify_c61_authenticated_whir_base(
                        C61AuthenticatedWhirVerifierInput {
                            id,
                            mask_range,
                            combined: c61_volta_fp2_from_p3(changed_closure.base_case.combined),
                            shifted_masked_claim: c61_volta_fp2_from_p3(
                                changed_closure.base_case.shifted_masked_claim,
                            ),
                            gamma: c61_volta_fp2_from_p3(changed_closure.base_case.gamma),
                            target: changed_final_key,
                        },
                        changed_base_proof,
                        &mut changed_context,
                        &mut changed_transcript,
                    )
                    .is_err()
                }
                _ => true,
            }
        }
    };

    Ok(C61AuthenticatedP3MultiOpenDiagnostic {
        num_variables,
        claim_count,
        strict_payload_bytes: payload.len(),
        strict_payload_max_bytes: c61_authenticated_structural_budget_inner(num_variables, false)?
            .strict_chain_bytes,
        provider_interaction,
        verifier_interaction,
        batching_weights_identical: output.claim_weights == result.claim_weights,
        point_mutation_rejected,
        full_correlations: correlations.counters.full_corrs,
    })
}

/// Produce one exact model or embedding chain from the retained global
/// coefficient polynomial and its ordered 96/6 authenticated claims.  The
/// C6SPX1 owner is create-new, the caller's coefficient vector is moved into
/// the prover, and CPU/hybrid or mock-PCG entry fails before filesystem I/O.
#[allow(clippy::too_many_arguments)]
pub fn prove_c61_authenticated_whir_p3_production_committed_chain_persisted_cuda_in_attempt(
    coefficients: Vec<Goldilocks>,
    claims: &[crate::batch::BlockClaim],
    targets: Vec<ProverAuthed>,
    parameter_digest: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut CorrelationStream,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainExecution, String> {
    prepare_c61_authenticated_whir_p3_production_committed_chain_persisted_cuda_in_attempt(
        coefficients,
        claims,
        targets,
        parameter_digest,
        spill_root,
        admission,
        backend,
        correlations,
        verifier_seed,
        id,
        mask_range,
    )?
    .finish_ordinary()
}

/// Stop the same production chain after its canonical claimless body and
/// batching weights are fixed but before the authenticated tail is emitted.
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_authenticated_whir_p3_production_committed_chain_persisted_cuda_in_attempt(
    coefficients: Vec<Goldilocks>,
    claims: &[crate::batch::BlockClaim],
    targets: Vec<ProverAuthed>,
    parameter_digest: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut CorrelationStream,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainProverBody, String> {
    prepare_c61_authenticated_whir_p3_production_committed_chain_with_transcript(
        coefficients,
        claims,
        targets,
        parameter_digest,
        spill_root,
        admission,
        backend,
        correlations,
        Transcript::new(verifier_seed),
        verifier_seed,
        id,
        mask_range,
    )
}

/// Provider-only C6ICT2 entry. The opaque endpoint owns transport but no
/// verifier seed, replay checkpoint, verifier transcript, key or Delta.
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_authenticated_whir_p3_production_committed_chain_private_entropy(
    coefficients: Vec<Goldilocks>,
    claims: &[crate::batch::BlockClaim],
    targets: Vec<ProverAuthed>,
    parameter_digest: [u8; 32],
    provider_session_binding: C61ProviderSessionBinding,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut CorrelationStream,
    endpoint: C61PrivateEntropyEndpoint,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainProverBody, String> {
    provider_session_binding.validate_for(id, mask_range)?;
    prepare_c61_authenticated_whir_p3_production_committed_chain_with_transcript(
        coefficients,
        claims,
        targets,
        parameter_digest,
        spill_root,
        admission,
        backend,
        correlations,
        Transcript::new_interactive(Box::new(endpoint)),
        provider_session_binding.context_digest(),
        id,
        mask_range,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_c61_authenticated_whir_p3_production_committed_chain_with_transcript(
    coefficients: Vec<Goldilocks>,
    claims: &[crate::batch::BlockClaim],
    targets: Vec<ProverAuthed>,
    parameter_digest: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    correlations: &mut CorrelationStream,
    mut transcript: Transcript,
    provider_session_binding: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainProverBody, String> {
    let num_variables = match id.component {
        C61NativeComponent::Model => usize::from(C61_MODEL_POLYNOMIAL_LOG2),
        C61NativeComponent::Embedding => usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2),
        C61NativeComponent::Compiler => {
            return Err("C6SPR11 committed-chain prover rejects compiler chains".to_owned());
        }
    };
    let expected_claims = match id.component {
        C61NativeComponent::Model => 96,
        C61NativeComponent::Embedding => 6,
        C61NativeComponent::Compiler => unreachable!("compiler rejected above"),
    };
    if id.repetition >= 2
        || backend.kind() != BackendKind::CudaResident
        || !admission.allow_persisted_executor
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES
        || admission.available_spill_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES
    {
        return Err(format!(
            "C6SPR11 persisted/CUDA admission failed: component={:?}, repetition={}, backend={:?}, available_host={} B, available_spill={} B, gpu={} B, a100={}, owner_persisted={}",
            id.component,
            id.repetition,
            backend.kind(),
            admission.available_host_bytes,
            admission.available_spill_bytes,
            admission.gpu_total_bytes,
            admission.a100_present,
            admission.allow_persisted_executor,
        ));
    }
    if !correlations.uses_pooled_pcg() {
        return Err("C6SPR11 production committed-chain prover forbids mock PCG state".to_owned());
    }
    if parameter_digest != c61_authenticated_p3_parameter_digest(num_variables)?
        || coefficients.len() != (1usize << num_variables)
        || claims.len() != expected_claims
        || targets.len() != expected_claims
    {
        return Err("C6SPR11 production coefficient/claim/profile geometry mismatch".to_owned());
    }
    if spill_root.exists() {
        return Err("C6SPR11 production committed-chain spill owner must be create-new".to_owned());
    }
    let parent = spill_root
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| "C6SPR11 production committed-chain spill parent is absent".to_owned())?;
    fs::create_dir(spill_root)
        .map_err(|error| format!("create C6SPR11 committed-chain spill root: {error}"))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6SPR11 committed-chain spill parent: {error}"))?;

    let mut session_hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/committed-chain-c6spx1-session/v1");
    session_hasher.update(&provider_session_binding);
    session_hasher.update(&parameter_digest);
    session_hasher.update(&(id.component as u16).to_le_bytes());
    session_hasher.update(&[id.repetition, mask_range.stage]);
    session_hasher.update(&mask_range.slot.to_le_bytes());
    session_hasher.update(&mask_range.range_start.to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    let lane = match id.component {
        C61NativeComponent::Model => *b"modelpcs",
        C61NativeComponent::Embedding => *b"embedpcs",
        C61NativeComponent::Compiler => unreachable!("compiler rejected above"),
    };
    let mmcs = C61PersistedMmcs::new(
        c61_reference_mmcs(),
        spill_root.join("oracle"),
        session_digest,
        lane,
    )?;
    let witness = Poly::new(coefficients);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = c61_production_private_zk_rng()?;
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);
    if commitment.num_roots() != 1 {
        return Err("C6SPR11 production committed chain has a noncanonical root cap".to_owned());
    }
    let public = build_c61_production_model_embedding_public_statement(
        id,
        C61NativeCommitmentDescriptor {
            parameter_digest,
            commitment_root: commitment.roots()[0],
            polynomial_domain_log2: num_variables as u8,
        },
        claims,
    )
    .map_err(|error| error.to_string())?;
    let statement =
        C61NativeProverChainStatement::new(public, targets).map_err(|error| error.to_string())?;
    let points = c61_model_embedding_points(statement.public())?;
    let evaluations = points.iter().map(|point| data.message.eval_base(point)).collect::<Vec<_>>();
    if evaluations
        .iter()
        .zip(statement.targets())
        .any(|(evaluation, target)| c61_volta_fp2_from_p3(*evaluation) != target.x)
    {
        return Err(
            "C6SPR11 retained authenticated target differs from its committed polynomial opening"
                .to_owned(),
        );
    }
    let native_claims = points.iter().cloned().zip(evaluations).collect::<Vec<_>>();
    challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, correlations)
        .map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &native_claims,
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
    let placeholder =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        placeholder,
        true,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6SPR11 production C6AWP1 payload is shorter than its tag".to_owned())?;
    let provider_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let aggregate_target = aggregate_prover_targets(statement.targets(), &output.claim_weights)?;
    let affine = affine_from_p3(output.target);
    let final_target = affine.authenticate_prover(aggregate_target);
    let claim_weights = output.claim_weights.iter().copied().map(c61_volta_fp2_from_p3).collect();
    let finish_input = C61AuthenticatedWhirProverFinishInput {
        combined: c61_volta_fp2_from_p3(output.base_case.combined),
        shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
        gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
        target: final_target,
    };
    let tagless_payload = placeholder_payload[..whir_payload_bytes].to_vec();
    let tagless_digest = *blake3::hash(&tagless_payload).as_bytes();
    let strict_payload_max_bytes =
        c61_authenticated_structural_budget_inner(num_variables, true)?.strict_chain_bytes;
    Ok(C61ProductionCommittedChainProverBody {
        statement,
        id,
        num_variables,
        claim_count: points.len(),
        tagless_payload,
        tagless_digest,
        claim_weights,
        prepared,
        affine,
        finish_input,
        transcript,
        provider_interaction,
        strict_payload_max_bytes,
        spill: mmcs.metrics(),
    })
}

/// Verify one decoded production model/embedding C6AWP1 chain using only the
/// typed verifier statement, verifier PCG state and strict provider bytes.
/// No witness, provider target share or resident prover object crosses this
/// boundary.
pub fn verify_c61_authenticated_whir_p3_production_committed_chain_in_attempt(
    statement: &C61NativeVerifierChainStatement,
    proof: &C61ProductionCommittedChainProof,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerification, String> {
    let tail_start = proof
        .payload()
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6SPR13 production native chain is shorter than its tail".to_owned())?;
    prepare_c61_authenticated_whir_p3_production_committed_chain_verifier_body(
        statement,
        &proof.payload()[..tail_start],
        verifier_seed,
        mask_range,
    )?
    .finish_ordinary(&proof.payload()[tail_start..], context)
}

pub fn verify_c61_authenticated_whir_p3_production_committed_chain_private_entropy_in_attempt(
    statement: &C61NativeVerifierChainStatement,
    proof: &C61ProductionCommittedChainProof,
    context: &mut VerifierCtx,
    tape: C61InteractiveTape,
    provider_session_binding: C61ProviderSessionBinding,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerification, String> {
    let validated = C61NativeVerifierChainStatement::new(
        statement.public().clone(),
        statement.target_keys().to_vec(),
    )
    .map_err(|error| error.to_string())?;
    if &validated != statement {
        return Err("C6ICT2 production verifier requires a canonical statement".to_owned());
    }
    let id = statement.public().id();
    provider_session_binding.validate_for(id, mask_range)?;
    let tail_start = proof
        .payload()
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT2 production native chain is shorter than its tail".to_owned())?;
    let endpoint = C61PrivateEntropyTranscriptReplayEndpoint::new(
        tape,
        match id.component {
            C61NativeComponent::Model => usize::from(C61_MODEL_POLYNOMIAL_LOG2),
            C61NativeComponent::Embedding => usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2),
            C61NativeComponent::Compiler => {
                return Err("C6ICT2 committed verifier rejects compiler chains".to_owned())
            }
        },
        provider_session_binding.context_digest(),
    )
    .map_err(|error| error.to_string())?;
    let mut body =
        prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body_with_transcript(
            statement.public(),
            &proof.payload()[..tail_start],
            Transcript::new_interactive(Box::new(endpoint)),
            mask_range,
        )?;
    body.aggregate_key = Some(aggregate_verifier_targets(
        statement.target_keys(),
        &body.claim_weights.iter().copied().map(c61_p3_fp2_from_volta).collect::<Vec<_>>(),
    )?);
    body.finish_ordinary(&proof.payload()[tail_start..], context)
}

/// Replay and accept a canonical production body without consuming its
/// authenticated tail or the verifier's PCG allocation.
pub fn prepare_c61_authenticated_whir_p3_production_committed_chain_verifier_body(
    statement: &C61NativeVerifierChainStatement,
    tagless_payload: &[u8],
    verifier_seed: [u8; 32],
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerifierBody, String> {
    let public = statement.public();
    let validated =
        C61NativeVerifierChainStatement::new(public.clone(), statement.target_keys().to_vec())
            .map_err(|error| error.to_string())?;
    if &validated != statement {
        return Err("C6SPR13 production verifier body requires a canonical statement".to_owned());
    }
    let mut body =
        prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body(
            public,
            tagless_payload,
            verifier_seed,
            mask_range,
        )?;
    body.aggregate_key = Some(aggregate_verifier_targets(
        statement.target_keys(),
        &body.claim_weights.iter().copied().map(c61_p3_fp2_from_volta).collect::<Vec<_>>(),
    )?);
    Ok(body)
}

/// Replay a canonical model/embedding body from its typed public statement
/// alone. This is the only admitted verifier constructor for a secondary
/// joint cohort: it cannot receive, reconstruct or synthesize target keys.
pub fn prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body(
    public: &C61TypedNativeChainPublicStatement,
    tagless_payload: &[u8],
    verifier_seed: [u8; 32],
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerifierBody, String> {
    prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body_with_transcript(
        public,
        tagless_payload,
        Transcript::new(verifier_seed),
        mask_range,
    )
}

fn prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body_with_transcript(
    public: &C61TypedNativeChainPublicStatement,
    tagless_payload: &[u8],
    mut transcript: Transcript,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerifierBody, String> {
    let mut placeholder_payload = tagless_payload.to_vec();
    placeholder_payload.extend_from_slice(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
    C61ProductionCommittedChainProof::decode(&placeholder_payload, public)?;
    let openings = c61_model_embedding_openings(public)?;
    let num_variables = usize::from(openings.commitment.polynomial_domain_log2);
    let points = c61_model_embedding_points(public)?;
    let (commitment, native_proof, _) =
        decode_c61_authenticated_p3_artifact_inner(&placeholder_payload, num_variables, true)
            .map_err(|error| error.to_string())?;

    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(commitment.clone());
    challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(&native_proof, &commitment, &points, &mut challenger)
    }))
    .map_err(|_| "C6SPR11 production committed-chain verifier panicked".to_owned())?
    .map_err(|error| format!("C6SPR11 production committed-chain verification failed: {error}"))?;
    let verifier_interaction =
        challenger.finish(tagless_payload.len()).map_err(|error| error.to_string())?;
    drop(challenger);

    let claim_weights = result.claim_weights.iter().copied().map(c61_volta_fp2_from_p3).collect();
    Ok(C61ProductionCommittedChainVerifierBody {
        id: public.id(),
        num_variables,
        claim_count: points.len(),
        tagless_payload_len: tagless_payload.len(),
        tagless_payload: tagless_payload.to_vec(),
        tagless_digest: *blake3::hash(tagless_payload).as_bytes(),
        claim_weights,
        aggregate_key: None,
        affine: affine_from_p3(result.target),
        base_case: result.base_case,
        mask_range,
        transcript,
        verifier_interaction,
    })
}

/// C6AWP2 counterpart of the public-only verifier constructor. The semantic
/// header is checked before it is translated to the byte-identical WHIR-v1
/// parser; the retained digest continues to bind the original C6AWP2 bytes.
pub fn prepare_c61_authenticated_whir_p3_production_joint_chain_public_verifier_body(
    public: &C61TypedNativeChainPublicStatement,
    joint_tagless_payload: &[u8],
    verifier_seed: [u8; 32],
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerifierBody, String> {
    prepare_c61_authenticated_whir_p3_production_joint_chain_public_verifier_body_with_transcript(
        public,
        joint_tagless_payload,
        Transcript::new(verifier_seed),
        mask_range,
    )
}

fn prepare_c61_authenticated_whir_p3_production_joint_chain_public_verifier_body_with_transcript(
    public: &C61TypedNativeChainPublicStatement,
    joint_tagless_payload: &[u8],
    transcript: Transcript,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCommittedChainVerifierBody, String> {
    if public.id().repetition != 1 {
        return Err("C6AWP2 verifier requires a secondary native statement".to_owned());
    }
    let mut complete = joint_tagless_payload.to_vec();
    complete.extend_from_slice(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
    let ordinary = c61_awp1_payload_from_joint(&complete)?;
    let ordinary_tagless = &ordinary[..ordinary.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES];
    let mut body =
        prepare_c61_authenticated_whir_p3_production_committed_chain_public_verifier_body_with_transcript(
            public,
            ordinary_tagless,
            transcript,
            mask_range,
        )?;
    body.tagless_payload = joint_tagless_payload.to_vec();
    body.tagless_digest = *blake3::hash(joint_tagless_payload).as_bytes();
    Ok(body)
}

fn c61_shared_statement_digest(
    response: &C61Commitment,
    plan: &C61Commitment,
    response_points: &[Point<C61P3Fp2>],
    plan_points: &[Point<C61P3Fp2>],
) -> Result<[u8; 32], String> {
    if response.num_roots() != 1 || plan.num_roots() != 1 {
        return Err("C6SMO1 statement requires one root per oracle".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/shared-multi-oracle/v1");
    hasher.update(&response.roots()[0]);
    hasher.update(&plan.roots()[0]);
    for (role, points) in [(0u8, response_points), (1u8, plan_points)] {
        hasher.update(&[role]);
        hasher.update(&(points.len() as u64).to_le_bytes());
        for point in points {
            hasher.update(&(point.num_variables() as u64).to_le_bytes());
            for coordinate in point.as_slice() {
                let limbs: &[Goldilocks] = coordinate.as_basis_coefficients_slice();
                for limb in limbs {
                    hasher.update(&limb.as_canonical_u64().to_le_bytes());
                }
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn c61_sparse_shared_statement_digest(
    response: &C61Commitment,
    plan: &C61Commitment,
    response_points: &[Point<C61P3Fp2>],
    plan_points: &[Point<C61P3Fp2>],
    relation_digest: [u8; 32],
    arithmetic_payload: &[u8],
    plan_values: &[Fp2; 3],
    terminal_binding: &C61ExactTerminalFoldBinding,
) -> Result<[u8; 32], String> {
    terminal_binding.validate()?;
    let base = c61_shared_statement_digest(response, plan, response_points, plan_points)?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/sparse-shared-statement/v1");
    hasher.update(&base);
    hasher.update(&relation_digest);
    hasher.update(blake3::hash(arithmetic_payload).as_bytes());
    for value in plan_values {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
    hasher.update(&terminal_binding.digest);
    Ok(*hasher.finalize().as_bytes())
}

enum C61SparseCompilerSource<'a> {
    Scaled(volta_proto::c6_residual::C6ResidualFusedScaledFixture),
    Production {
        operation_plan: &'a C6InstalledOperationPlan,
        extraction: &'a volta_mac::C6DecodedInstanceExtractionPlan,
        runtime: &'a volta_mac::C6RuntimeInstanceValues,
        relation: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    },
}

struct C61SparseCompilerPhysicalFixture<'a> {
    source: C61SparseCompilerSource<'a>,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    lanes: [volta_proto::c6_residual::C6ResidualFoldedTerminalAdjointLaneReference; 2],
    packed: volta_proto::c6_residual::C6SparseRationalPackedOracleReference,
    output_beta: Fp2,
    terminal_binding: C61ExactTerminalFoldBinding,
    terminal_relation_root: Option<[u8; 32]>,
    production: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C61ExactTerminalFoldBinding {
    leaf_points: [Vec<Fp2>; 2],
    auxiliary_points: [Vec<Fp2>; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    functional_fold: Fp2,
    direct_fold: Fp2,
    plan_folds: [Fp2; 2],
    digest: [u8; 32],
}

impl C61ExactTerminalFoldBinding {
    fn new(
        terminal_metadata: &C6OperationPlanTerminalMetadata,
        relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
        leaf_points: [&[Fp2]; 2],
        auxiliary_points: [&[Fp2]; 2],
        terminal_functionals: [Fp2; 64],
        output_beta: Fp2,
        plan_folds: [Fp2; 2],
    ) -> Result<Self, String> {
        let direct = volta_proto::c6_residual::reduce_c6_residual_folded_terminal_direct(
            terminal_metadata,
            relation,
            leaf_points,
            auxiliary_points,
            output_beta,
        )
        .map_err(|error| error.to_string())?;
        let functional_fold = crate::fold_terminal_claims(&terminal_functionals, output_beta);
        if plan_folds[0] + plan_folds[1] + direct.fold() != functional_fold {
            return Err("C6SPR10 exact terminal fold differs from direct reducer plus plan lanes"
                .to_owned());
        }
        let mut binding = Self {
            leaf_points: [leaf_points[0].to_vec(), leaf_points[1].to_vec()],
            auxiliary_points: [auxiliary_points[0].to_vec(), auxiliary_points[1].to_vec()],
            terminal_functionals,
            output_beta,
            functional_fold,
            direct_fold: direct.fold(),
            plan_folds,
            digest: [0; 32],
        };
        binding.digest = binding.recompute_digest();
        Ok(binding)
    }

    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.1/exact-terminal-fold-binding/v1");
        for (repetition, (leaf, auxiliary)) in
            self.leaf_points.iter().zip(&self.auxiliary_points).enumerate()
        {
            hasher.update(&(repetition as u64).to_le_bytes());
            for point in [leaf, auxiliary] {
                hasher.update(&(point.len() as u64).to_le_bytes());
                for &coordinate in point {
                    hasher.update(&coordinate.c0.value().to_le_bytes());
                    hasher.update(&coordinate.c1.value().to_le_bytes());
                }
            }
        }
        for value in self.terminal_functionals {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
        for value in [self.output_beta, self.functional_fold, self.direct_fold]
            .into_iter()
            .chain(self.plan_folds)
        {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn validate(&self) -> Result<(), String> {
        if self.digest == [0; 32]
            || self.digest != self.recompute_digest()
            || crate::fold_terminal_claims(&self.terminal_functionals, self.output_beta)
                != self.functional_fold
            || self.plan_folds[0] + self.plan_folds[1] + self.direct_fold != self.functional_fold
        {
            return Err("C6SPR10 exact terminal fold binding is noncanonical".to_owned());
        }
        Ok(())
    }

    fn validate_physical_plan_fold_values(
        &self,
        base_domain_log2: u8,
        values: &[Fp2; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS],
    ) -> Result<(), String> {
        self.validate()?;
        let source_dimension = usize::from(base_domain_log2)
            .checked_sub(2)
            .ok_or_else(|| "C6CPX2 compact source dimension underflows".to_owned())?;
        for repetition in 0..2usize {
            let leaf = &self.leaf_points[repetition];
            if leaf.len() < source_dimension {
                return Err(
                    "C6CPX2 terminal leaf point is shorter than its source block".to_owned()
                );
            }
            let value =
                values[2 * repetition] + Fp2::new(Fp::ZERO, Fp::ONE) * values[2 * repetition + 1];
            let padding = leaf[source_dimension..]
                .iter()
                .fold(Fp2::ONE, |factor, coordinate| factor * (Fp2::ONE - *coordinate));
            if value * padding != self.plan_folds[repetition] {
                return Err(
                    "C6CPX2 physical plan-fold targets do not reconstruct the semantic fold"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }
}

/// Public-only view handed to the verifier phase.  In particular this type
/// has no extraction map, runtime values, adjoint lanes, response
/// coefficients, or combined relation vectors.
struct C61SparseCompilerVerifierFixture<'a> {
    operation_plan_digest: [u8; 32],
    topology: C6OperationPlanTopologyIdentity,
    terminal_metadata: &'a C6OperationPlanTerminalMetadata,
    relation_challenges: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    output_beta: Fp2,
    base_domain_log2: u8,
    response_digest: [u8; 32],
    plan_digest: [u8; 32],
    terminal_binding: C61ExactTerminalFoldBinding,
}

impl C61SparseCompilerPhysicalFixture<'_> {
    fn operation_plan(&self) -> &C6InstalledOperationPlan {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.operation_plan(),
            C61SparseCompilerSource::Production { operation_plan, .. } => operation_plan,
        }
    }

    fn extraction(&self) -> &volta_mac::C6DecodedInstanceExtractionPlan {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.extraction(),
            C61SparseCompilerSource::Production { extraction, .. } => extraction,
        }
    }

    fn runtime(&self) -> &volta_mac::C6RuntimeInstanceValues {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.runtime(),
            C61SparseCompilerSource::Production { runtime, .. } => runtime,
        }
    }

    fn relation(&self) -> &volta_proto::c6_residual::C6ResidualRelationChallenges {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.relation(),
            C61SparseCompilerSource::Production { relation, .. } => relation,
        }
    }

    fn verifier_fixture(&self) -> Result<C61SparseCompilerVerifierFixture<'_>, String> {
        Ok(C61SparseCompilerVerifierFixture {
            operation_plan_digest: self.operation_plan().artifact_digest(),
            topology: self.operation_plan().topology(),
            terminal_metadata: &self.terminal_metadata,
            relation_challenges: self.relation(),
            output_beta: self.output_beta,
            base_domain_log2: self.packed.base_domain_log2(),
            response_digest: self.packed.response_digest(),
            plan_digest: self.packed.plan_digest(),
            terminal_binding: self.terminal_binding.clone(),
        })
    }
}

fn c61_production_compiler_public_statement(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    id: C61NativeChainId,
    response_root: [u8; 32],
    plan_root: [u8; 32],
) -> Result<C61TypedNativeChainPublicStatement, String> {
    if !fixture.production || id.component != C61NativeComponent::Compiler || id.repetition >= 2 {
        return Err("C6SPR11 compiler statement builder requires one production chain".to_owned());
    }
    let terminal_relation_root = fixture
        .terminal_relation_root
        .ok_or_else(|| "C6SPR11 compiler statement omitted the exact C6TFR1 root".to_owned())?;
    let response = C61NativeCommitmentDescriptor {
        parameter_digest: c61_authenticated_p3_parameter_digest(28)?,
        commitment_root: response_root,
        polynomial_domain_log2: 28,
    };
    let plan = C61NativeCommitmentDescriptor {
        parameter_digest: c61_authenticated_p3_parameter_digest(27)?,
        commitment_root: plan_root,
        polynomial_domain_log2: 27,
    };
    let binding = C61TerminalFunctionalCompilerBinding {
        operation_plan_digest: fixture.operation_plan().artifact_digest(),
        operation_topology_digest: fixture.operation_plan().topology().topology_digest,
        terminal_metadata_digest: fixture.terminal_metadata.digest(),
        extraction_map_digest: fixture.extraction().census().map_digest,
        runtime_root: fixture.runtime().instance_identity().instance_digest,
        residual_manifest_digest: fixture.relation().manifest().digest(),
        residual_public_claims_digest: fixture.relation().claims().digest(),
        relation_challenges_digest: fixture.relation().digest(),
        sparse_oracles: C61SparseRationalCompilerOracles::new(response, plan)
            .map_err(|error| error.to_string())?,
        leaf_points: fixture.terminal_binding.leaf_points.clone(),
        auxiliary_points: fixture.terminal_binding.auxiliary_points.clone(),
        terminal_claims: fixture.terminal_binding.terminal_functionals,
        output_beta: fixture.output_beta,
        relation_root: terminal_relation_root,
    };
    let relation =
        C61TerminalFunctionalCompilerStatement::new(binding).map_err(|error| error.to_string())?;
    if relation.functional_fold != fixture.terminal_binding.functional_fold {
        return Err(
            "C6SPR11 compiler statement fold differs from the exact terminal owner".to_owned()
        );
    }
    C61TypedNativeChainPublicStatement::new(
        id,
        C61TypedNativeRelationStatement::Compiler(Box::new(relation)),
    )
    .map_err(|error| error.to_string())
}

fn c61_exact_plan_fold_physical_openings(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
) -> Result<(Vec<Point<C61P3Fp2>>, Vec<Fp2>), String> {
    fixture.terminal_binding.validate()?;
    if fixture.terminal_binding.output_beta != fixture.output_beta {
        return Err("C6SPR10 terminal fold beta differs from the sparse relation".to_owned());
    }
    let points = c61_exact_plan_fold_physical_points(
        &fixture.terminal_binding,
        fixture.packed.base_domain_log2(),
        response_num_variables,
    )?;
    let physical_coefficients = fixture
        .packed
        .physical_response_values()
        .into_iter()
        .map(Fp2::from_base)
        .collect::<Vec<_>>();
    let values = points
        .iter()
        .map(|point| {
            let native_point = point
                .as_slice()
                .iter()
                .rev()
                .take(usize::from(fixture.packed.base_domain_log2()) + 3)
                .map(|coordinate| c61_volta_fp2_from_p3(*coordinate))
                .collect::<Vec<_>>();
            volta_proto::mle::eval_mle(&physical_coefficients, &native_point)
        })
        .collect::<Vec<_>>();
    fixture.terminal_binding.validate_physical_plan_fold_values(
        fixture.packed.base_domain_log2(),
        &values
            .as_slice()
            .try_into()
            .map_err(|_| "C6SPR10 physical plan-fold value census mismatch".to_owned())?,
    )?;
    Ok((points, values))
}

fn c61_exact_plan_fold_physical_points(
    binding: &C61ExactTerminalFoldBinding,
    base_domain_log2: u8,
    response_num_variables: usize,
) -> Result<Vec<Point<C61P3Fp2>>, String> {
    binding.validate()?;
    let base_dimension = usize::from(base_domain_log2);
    let source_dimension = base_dimension
        .checked_sub(2)
        .ok_or_else(|| "C6SPR10 source opening dimension underflows".to_owned())?;
    let native_physical_dimension = base_dimension + 3;
    if response_num_variables < native_physical_dimension {
        return Err("C6SPR10 response padding is below the native oracle".to_owned());
    }
    let mut points = Vec::with_capacity(C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS);
    for repetition in 0..2usize {
        let leaf = &binding.leaf_points[repetition];
        if leaf.len() < source_dimension {
            return Err("C6SPR10 terminal leaf point is shorter than the source block".to_owned());
        }
        let mut semantic = leaf[..source_dimension].to_vec();
        semantic.extend_from_slice(&[
            Fp2::from_base(Fp::new(repetition as u64)),
            Fp2::ONE,
            Fp2::ZERO,
            Fp2::ONE,
        ]);
        if semantic.len() + 1 != native_physical_dimension {
            return Err("C6SPR10 packed plan-fold point has the wrong dimension".to_owned());
        }
        for limb in [Fp2::ZERO, Fp2::ONE] {
            let mut native_point = semantic.clone();
            native_point.push(limb);
            native_point.resize(response_num_variables, Fp2::ZERO);
            native_point.reverse();
            points.push(Point::new(native_point.into_iter().map(c61_p3_fp2_from_volta).collect()));
        }
    }
    Ok(points)
}

struct C61SparseCompilerProviderPhase {
    public_relation: volta_proto::c6_residual::C6ResidualSparseRationalPublicRelation,
    physical_points: volta_proto::c6_residual::C6SparseRationalPhysicalOpeningPoints,
    response_values: [Fp2; 12],
    plan_values: [Fp2; 3],
    response_targets: [ProverAuthed; 12],
    zero_rows: Vec<ProverAuthed>,
    arithmetic_payload: Vec<u8>,
    product_triples: usize,
}

struct C61SparseCompilerVerifierPhase {
    public_relation: volta_proto::c6_residual::C6ResidualSparseRationalPublicRelation,
    physical_points: volta_proto::c6_residual::C6SparseRationalPhysicalOpeningPoints,
    response_keys: [VerifierKey; 12],
    plan_values: [Fp2; 3],
    zero_rows: Vec<VerifierKey>,
    product_triples: usize,
}

fn c61_sparse_compiler_physical_fixture(
) -> Result<C61SparseCompilerPhysicalFixture<'static>, String> {
    use volta_proto::c6_residual::*;

    let direct =
        build_c6_residual_direct_fused_scaled_fixture().map_err(|error| error.to_string())?;
    let topology = direct.operation_plan().topology();
    let source_manifest = C6TraceSourceManifest::new(
        topology.source_count,
        topology.source_schedule_digest,
        direct.manifest().product_mask_sources().to_vec(),
    )
    .map_err(|error| error.to_string())?;
    let terminal_metadata =
        C6OperationPlanTerminalMetadata::from_installed(direct.operation_plan(), &source_manifest)
            .map_err(|error| error.to_string())?;
    let leaf_point = [
        Fp2::from_base(Fp::new(2)),
        Fp2::from_base(Fp::new(3)),
        Fp2::from_base(Fp::new(5)),
        Fp2::from_base(Fp::new(7)),
        Fp2::from_base(Fp::new(11)),
        Fp2::from_base(Fp::new(13)),
        Fp2::from_base(Fp::new(17)),
    ];
    let auxiliary_point = [Fp2::from_base(Fp::new(23)), Fp2::from_base(Fp::new(29))];
    let output_beta = Fp2::new(Fp::new(191), Fp::new(17));
    let lanes = std::array::from_fn(|repetition| {
        compile_c6_residual_folded_terminal_adjoint_lane_reference(
            direct.operation_plan(),
            &terminal_metadata,
            direct.extraction(),
            direct.runtime(),
            direct.relation(),
            repetition as u8,
            &leaf_point,
            output_beta,
        )
        .expect("scaled C6SPR3 adjoint lane fixture")
    });
    let packed = compile_c6_sparse_rational_packed_oracle_reference(
        direct.operation_plan(),
        direct.extraction(),
        direct.runtime(),
        [&lanes[0], &lanes[1]],
    )
    .map_err(|error| error.to_string())?;
    let terminal = compile_c6_residual_terminal_functional_relation_reference(
        direct.operation_plan(),
        direct.extraction(),
        direct.runtime(),
        direct.linear(),
        direct.relation(),
        [&leaf_point, &leaf_point],
        [&auxiliary_point, &auxiliary_point],
        output_beta,
    )
    .map_err(|error| error.to_string())?;
    let terminal_binding = C61ExactTerminalFoldBinding::new(
        &terminal_metadata,
        direct.relation(),
        [&leaf_point, &leaf_point],
        [&auxiliary_point, &auxiliary_point],
        *terminal.terminal_functionals(),
        output_beta,
        [lanes[0].plan_fold(), lanes[1].plan_fold()],
    )?;
    Ok(C61SparseCompilerPhysicalFixture {
        source: C61SparseCompilerSource::Scaled(direct),
        terminal_metadata,
        lanes,
        packed,
        output_beta,
        terminal_binding,
        terminal_relation_root: None,
        production: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn c61_sparse_compiler_production_fixture<'a>(
    operation_plan: &'a C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &'a volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &'a volta_mac::C6RuntimeInstanceValues,
    relation: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
) -> Result<C61SparseCompilerPhysicalFixture<'a>, String> {
    use volta_proto::c6_residual::{
        compile_c6_residual_folded_terminal_adjoint_lane_reference,
        compile_c6_sparse_rational_packed_oracle_production,
    };

    if !relation.manifest().is_production_geometry() {
        return Err("C6SPR5 production fixture requires the frozen C6RLM1 geometry".to_owned());
    }
    if terminal_relation_root == [0; 32] {
        return Err("C6SPR5 production fixture requires the exact C6TFR1 root".to_owned());
    }
    let lanes: [volta_proto::c6_residual::C6ResidualFoldedTerminalAdjointLaneReference; 2] = (0
        ..2usize)
        .map(|repetition| {
            compile_c6_residual_folded_terminal_adjoint_lane_reference(
                operation_plan,
                &terminal_metadata,
                extraction,
                runtime,
                relation,
                repetition as u8,
                leaf_points[repetition],
                output_beta,
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "C6SPR5 production adjoint-lane census differs from two".to_owned())?;
    let packed = compile_c6_sparse_rational_packed_oracle_production(
        operation_plan,
        extraction,
        runtime,
        [&lanes[0], &lanes[1]],
    )
    .map_err(|error| error.to_string())?;
    if packed.physical_response_domain_log2() != 28 || packed.plan_domain_log2() != 27 {
        return Err("C6SPR5 production packing is not physical D28/D27".to_owned());
    }
    let terminal_binding = C61ExactTerminalFoldBinding::new(
        &terminal_metadata,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        [lanes[0].plan_fold(), lanes[1].plan_fold()],
    )?;
    Ok(C61SparseCompilerPhysicalFixture {
        source: C61SparseCompilerSource::Production {
            operation_plan,
            extraction,
            runtime,
            relation,
        },
        terminal_metadata,
        lanes,
        packed,
        output_beta,
        terminal_binding,
        terminal_relation_root: Some(terminal_relation_root),
        production: true,
    })
}

/// Execute one exact compiler chain with the pinned host-monolithic P3
/// prover on an owner-authorized A100 node.
///
/// This is a resource-instrumented production-geometry baseline, not the
/// persisted/GPU-resident C6SPR5 solution and not GPU performance credit.
/// It fails closed unless the caller reports an A100, at least 64 GiB of
/// immediately available host memory, and real pooled PCG state for both
/// roles.  The caller remains responsible for measuring RSS and GPU memory
/// around this call and for using append-only clean records.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_monolithic_baseline(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
    admission: C61ProductionMonolithicResourceAdmission,
    mut correlations: CorrelationStream,
    mut context: VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    let census = c61_production_monolithic_memory_census()?;
    if !admission.allow_host_monolithic_baseline
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES
        || admission.available_host_bytes < census.concurrent_retained_lower_bound_bytes
    {
        return Err(format!(
            "C6SPR5 monolithic A100 baseline admission failed: available_host={} B, minimum={} B, retained_lower_bound={} B, gpu={} B, a100={}, owner_baseline={}",
            admission.available_host_bytes,
            C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES,
            census.concurrent_retained_lower_bound_bytes,
            admission.gpu_total_bytes,
            admission.a100_present,
            admission.allow_host_monolithic_baseline,
        ));
    }
    if id.component != C61NativeComponent::Compiler {
        return Err("C6SPR5 production runner admits only compiler chains".to_owned());
    }
    if !correlations.uses_pooled_pcg() || !context.uses_pooled_pcg() {
        return Err("C6SPR5 production runner forbids mock PCG state".to_owned());
    }
    let fixture = c61_sparse_compiler_production_fixture(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        terminal_relation_root,
    )?;
    run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
        &fixture,
        28,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        admission.available_host_bytes,
    )
}

/// Execute one exact production compiler chain with the C6SPX1 persisted
/// prover-data lifecycle.  This is the only host executor admitted for the
/// C6SPR5 campaign; it never falls back to the resident MMCS and earns no GPU
/// performance credit.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_persisted(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    mut correlations: CorrelationStream,
    mut context: VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    run_c61_authenticated_whir_p3_production_persisted_in_attempt(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        terminal_relation_root,
        spill_root,
        admission,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
    )
}

/// Same production executor, borrowing the connection-owned PCG states so
/// an exact response runner can continue the indivisible paired attempt.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_persisted_in_attempt(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    Ok(run_c61_authenticated_whir_p3_production_persisted_execution_in_attempt(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        terminal_relation_root,
        spill_root,
        admission,
        correlations,
        context,
        verifier_seed,
        id,
        mask_range,
    )?
    .report)
}

/// Exact persisted compiler-chain execution retaining its strict provider
/// proof bytes for the enclosing response certificate.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_persisted_execution_in_attempt(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainExecution, String> {
    validate_c61_production_compiler_persisted_admission(
        admission,
        correlations,
        Some(context),
        id,
    )?;
    let fixture = c61_sparse_compiler_production_fixture(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        terminal_relation_root,
    )?;
    let mut session_hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/c6spx1-session/v1");
    session_hasher.update(&verifier_seed);
    session_hasher.update(&operation_plan.artifact_digest());
    session_hasher.update(&(id.component as u16).to_le_bytes());
    session_hasher.update(&[id.repetition, mask_range.stage]);
    session_hasher.update(&mask_range.slot.to_le_bytes());
    session_hasher.update(&mask_range.range_start.to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    run_c61_authenticated_whir_p3_production_persisted_with_transcript(
        &fixture,
        spill_root,
        admission,
        correlations,
        Some(context),
        Some(verifier_seed),
        Transcript::new(verifier_seed),
        session_digest,
        id,
        mask_range,
    )
}

/// Provider-only persisted compiler entry. The endpoint and public durable
/// binding expose no verifier seed, checkpoint, transcript, key or Delta.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    terminal_functionals: [Fp2; 64],
    output_beta: Fp2,
    terminal_relation_root: [u8; 32],
    provider_session_binding: C61ProviderSessionBinding,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &mut CorrelationStream,
    endpoint: C61PrivateEntropyEndpoint,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainExecution, String> {
    validate_c61_production_compiler_persisted_admission(admission, correlations, None, id)?;
    provider_session_binding.validate_for(id, mask_range)?;
    let fixture = c61_sparse_compiler_production_fixture(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        auxiliary_points,
        terminal_functionals,
        output_beta,
        terminal_relation_root,
    )?;
    let mut session_hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/c6ict2-compiler-session/v1");
    session_hasher.update(&provider_session_binding.context_digest());
    session_hasher.update(&operation_plan.artifact_digest());
    session_hasher.update(&(id.component as u16).to_le_bytes());
    session_hasher.update(&[id.repetition, mask_range.stage]);
    session_hasher.update(&mask_range.slot.to_le_bytes());
    session_hasher.update(&mask_range.range_start.to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    run_c61_authenticated_whir_p3_production_persisted_with_transcript(
        &fixture,
        spill_root,
        admission,
        correlations,
        None,
        None,
        Transcript::new_interactive(Box::new(endpoint)),
        session_digest,
        id,
        mask_range,
    )
}

fn validate_c61_production_compiler_persisted_admission(
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &CorrelationStream,
    verifier_context: Option<&VerifierCtx>,
    id: C61NativeChainId,
) -> Result<(), String> {
    if !admission.allow_persisted_executor
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES
        || admission.available_spill_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES
    {
        return Err(format!(
            "C6SPR5 persisted A100 admission failed: available_host={} B, minimum_host={} B, available_spill={} B, minimum_spill={} B, gpu={} B, a100={}, owner_persisted={}",
            admission.available_host_bytes,
            C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
            admission.available_spill_bytes,
            C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
            admission.gpu_total_bytes,
            admission.a100_present,
            admission.allow_persisted_executor,
        ));
    }
    if id.component != C61NativeComponent::Compiler || id.repetition >= 2 {
        return Err("C6SPR5 persisted runner admits only compiler chains".to_owned());
    }
    if !correlations.uses_pooled_pcg()
        || verifier_context.is_some_and(|context| !context.uses_pooled_pcg())
    {
        return Err("C6SPR5 persisted runner forbids mock PCG state".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_c61_authenticated_whir_p3_production_persisted_with_transcript(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &mut CorrelationStream,
    verifier_context: Option<&mut VerifierCtx>,
    verifier_seed: Option<[u8; 32]>,
    provider_transcript: Transcript,
    session_digest: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainExecution, String> {
    let commit_gate = Arc::new(Mutex::new(()));
    let response_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("response"),
        session_digest,
        *b"response",
        Arc::clone(&commit_gate),
    )?;
    let plan_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("plan"),
        session_digest,
        *b"planlane",
        commit_gate,
    )?;
    let execution = run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_transcript(
        fixture,
        28,
        correlations,
        verifier_context,
        verifier_seed,
        provider_transcript,
        id,
        mask_range,
        admission.available_host_bytes,
        admission.available_spill_bytes,
        response_mmcs,
        plan_mmcs,
    )?;
    if !execution.report.production_geometry
        || !execution.report.persisted_executor
        || execution.report.monolithic_host_baseline
    {
        return Err("C6SPR5 persisted runner returned a non-persisted production report".to_owned());
    }
    Ok(execution)
}

fn sample_c61_sparse_relation_challenges(
    operation_plan: &C6InstalledOperationPlan,
    transcript: &mut Transcript,
) -> Result<volta_proto::c6_residual::C6ResidualSparseRationalChallenges, String> {
    sample_c61_sparse_relation_challenges_compact(operation_plan.topology(), transcript)
}

fn sample_c61_sparse_relation_challenges_compact(
    topology: C6OperationPlanTopologyIdentity,
    transcript: &mut Transcript,
) -> Result<volta_proto::c6_residual::C6ResidualSparseRationalChallenges, String> {
    volta_proto::c6_residual::C6ResidualSparseRationalChallenges::new(
        topology,
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
    )
    .map_err(|error| error.to_string())
}

fn prove_c61_sparse_compiler_relation_phase(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    stream: &mut CorrelationStream,
    doms: &mut volta_proto::logup::Doms,
    transcript: &mut Transcript,
) -> Result<C61SparseCompilerProviderPhase, String> {
    use volta_proto::c6_residual::*;
    use volta_proto::prod_check::prod_batch_prover;

    let sparse_challenges =
        sample_c61_sparse_relation_challenges(fixture.operation_plan(), transcript)?;
    let relation = if fixture.production {
        compile_c6_residual_sparse_rational_relation_production(
            fixture.operation_plan(),
            &fixture.terminal_metadata,
            fixture.extraction(),
            fixture.runtime(),
            fixture.relation(),
            [&fixture.lanes[0], &fixture.lanes[1]],
            sparse_challenges,
            fixture.output_beta,
        )
    } else {
        compile_c6_residual_sparse_rational_relation_reference(
            fixture.operation_plan(),
            &fixture.terminal_metadata,
            fixture.extraction(),
            fixture.runtime(),
            fixture.relation(),
            [&fixture.lanes[0], &fixture.lanes[1]],
            sparse_challenges,
            fixture.output_beta,
        )
    }
    .map_err(|error| error.to_string())?;
    let public_relation = C6ResidualSparseRationalPublicRelation::new(
        fixture.operation_plan(),
        &fixture.terminal_metadata,
        fixture.relation(),
        sparse_challenges,
        fixture.output_beta,
    )
    .map_err(|error| error.to_string())?;
    fixture.packed.validate_relation(&relation).map_err(|error| error.to_string())?;

    let mut products = Vec::new();
    let mut zero_rows = Vec::new();
    let (gkr, leaf_claims) = prove_c6_residual_sparse_rational_gkr_blind_reference(
        fixture.operation_plan(),
        fixture.extraction(),
        fixture.runtime(),
        &relation,
        &public_relation,
        stream,
        doms,
        transcript,
        &mut volta_proto::logup::Counters::default(),
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let (joint, terminal) = prove_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
        fixture.operation_plan(),
        &relation,
        &public_relation,
        &fixture.packed,
        &leaf_claims,
        stream,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let physical_points = fixture
        .packed
        .physical_opening_points(terminal.points().input_point())
        .map_err(|error| error.to_string())?;
    let response_values = fixture
        .packed
        .evaluate_physical_response_openings(&physical_points)
        .map_err(|error| error.to_string())?;
    let plan_values = fixture
        .packed
        .evaluate_physical_plan_openings(&physical_points)
        .map_err(|error| error.to_string())?;
    let (response_target_proof, response_targets) =
        authenticate_c61_sparse_response_targets_prover(&response_values, stream, doms, transcript)
            .map_err(|error| error.to_string())?;
    let plan_targets = plan_values.map(ProverAuthed::from_public);
    let terminal_proof = crate::finish_c61_sparse_rational_blind_physical_terminal_prover(
        terminal,
        &response_targets,
        &plan_targets,
        stream,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let product_triples = products.len();
    let chi = transcript.challenge_fp2();
    let product_domain = doms.take(1);
    let product_mask = stream.draw_product_mask(product_domain, product_triples);
    let product_proof = prod_batch_prover(&products, chi, product_mask, transcript);
    let arithmetic = C61SparseRationalBlindArithmeticProof::new(
        fixture.operation_plan(),
        public_relation.digest(),
        response_target_proof,
        gkr,
        joint,
        terminal_proof,
        product_proof,
    )
    .map_err(|error| error.to_string())?;
    let arithmetic_payload = arithmetic
        .encode(fixture.operation_plan(), public_relation.digest())
        .map_err(|error| error.to_string())?;
    Ok(C61SparseCompilerProviderPhase {
        public_relation,
        physical_points,
        response_values,
        plan_values,
        response_targets,
        zero_rows,
        arithmetic_payload,
        product_triples,
    })
}

fn verify_c61_sparse_compiler_relation_phase(
    fixture: &C61SparseCompilerVerifierFixture<'_>,
    arithmetic_payload: &[u8],
    context: &mut VerifierCtx,
    doms: &mut volta_proto::logup::Doms,
    transcript: &mut Transcript,
) -> Result<C61SparseCompilerVerifierPhase, String> {
    use volta_proto::c6_residual::*;
    use volta_proto::prod_check::prod_batch_verify;

    let sparse_challenges =
        sample_c61_sparse_relation_challenges_compact(fixture.topology, transcript)?;
    let public_relation = C6ResidualSparseRationalPublicRelation::new_compact(
        fixture.operation_plan_digest,
        fixture.topology,
        fixture.terminal_metadata,
        fixture.relation_challenges,
        sparse_challenges,
        fixture.output_beta,
    )
    .map_err(|error| error.to_string())?;
    let arithmetic = C61SparseRationalBlindArithmeticProof::decode_compact(
        fixture.topology,
        public_relation.digest(),
        arithmetic_payload,
    )
    .map_err(|error| error.to_string())?;
    let (response_target_proof, gkr, joint, terminal_proof, product_proof) =
        arithmetic.into_parts();
    let mut products = Vec::new();
    let mut zero_rows = Vec::new();
    let leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_compact(
        fixture.operation_plan_digest,
        fixture.topology,
        fixture.terminal_metadata,
        fixture.relation_challenges,
        &public_relation,
        &gkr,
        context,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "C6SPR3 blind GKR verifier rejected".to_owned())?;
    let terminal = verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_compact(
        fixture.operation_plan_digest,
        fixture.topology,
        fixture.terminal_metadata,
        fixture.relation_challenges,
        &public_relation,
        fixture.base_domain_log2,
        fixture.response_digest,
        fixture.plan_digest,
        &leaf_keys,
        &joint,
        context,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "C6SPR3 blind joint verifier rejected".to_owned())?;
    let physical_points = C6SparseRationalPhysicalOpeningPoints::new(
        fixture.base_domain_log2,
        fixture.response_digest,
        fixture.plan_digest,
        terminal.points().input_point(),
    )
    .map_err(|error| error.to_string())?;
    let plan_values = *terminal.clear_plan_values();
    let response_keys = authenticate_c61_sparse_response_targets_verifier(
        response_target_proof,
        context,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let plan_keys = plan_values.map(|value| VerifierKey::from_public(value, context.delta));
    crate::finish_c61_sparse_rational_blind_physical_terminal_verifier(
        terminal,
        &response_keys,
        &plan_keys,
        &terminal_proof,
        context,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let product_triples = products.len();
    let chi = transcript.challenge_fp2();
    let product_domain = doms.take(1);
    let product_key = context.expand_product_mask_verifier_key(product_domain, product_triples);
    transcript.append_fp2s("prod_check_m0_m1", &[product_proof.m0, product_proof.m1]);
    if !prod_batch_verify(&products, product_key, context.delta, chi, &product_proof) {
        return Err("C6SPR3 global QuickSilver product verification failed".to_owned());
    }
    Ok(C61SparseCompilerVerifierPhase {
        public_relation,
        physical_points,
        response_keys,
        plan_values,
        zero_rows,
        product_triples,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_c61_authenticated_whir_p3_compiler_chain_compact(
    fixture: &C61SparseCompilerVerifierFixture<'_>,
    expected_response_root: [u8; 32],
    expected_plan_root: [u8; 32],
    response_num_variables: usize,
    proof: &C61ProductionCompilerChainProof,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    compact_profile_digest: [u8; 32],
    compact_profile_setup_bytes: u64,
    client_setup_allocation_bytes: u64,
) -> Result<C61ProductionCompilerChainVerification, String> {
    verify_c61_authenticated_whir_p3_compiler_chain_compact_with_transcript(
        fixture,
        expected_response_root,
        expected_plan_root,
        response_num_variables,
        proof,
        context,
        Transcript::new(verifier_seed),
        id,
        mask_range,
        compact_profile_digest,
        compact_profile_setup_bytes,
        client_setup_allocation_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_c61_authenticated_whir_p3_compiler_chain_compact_with_transcript(
    fixture: &C61SparseCompilerVerifierFixture<'_>,
    expected_response_root: [u8; 32],
    expected_plan_root: [u8; 32],
    response_num_variables: usize,
    proof: &C61ProductionCompilerChainProof,
    context: &mut VerifierCtx,
    mut transcript: Transcript,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    compact_profile_digest: [u8; 32],
    compact_profile_setup_bytes: u64,
    client_setup_allocation_bytes: u64,
) -> Result<C61ProductionCompilerChainVerification, String> {
    if id.component != C61NativeComponent::Compiler || id.repetition >= 2 {
        return Err("C6SPR11 compact verifier requires one canonical compiler chain".to_owned());
    }
    fixture.terminal_binding.validate()?;
    if proof.terminal_binding_digest != fixture.terminal_binding.digest
        || proof.plan_folds != fixture.terminal_binding.plan_folds
    {
        return Err("C6SPR11 C6CPX2 terminal binding differs from the public relation".to_owned());
    }
    fixture.terminal_binding.validate_physical_plan_fold_values(
        fixture.base_domain_log2,
        &proof.physical_plan_fold_values,
    )?;
    let native_response_num_variables = usize::from(fixture.base_domain_log2) + 3;
    if response_num_variables < native_response_num_variables || response_num_variables > 28 {
        return Err("C6SPR11 compact response dimension is noncanonical".to_owned());
    }
    let plan_num_variables = response_num_variables
        .checked_sub(1)
        .ok_or_else(|| "C6SPR11 compact plan dimension underflows".to_owned())?;
    let artifact = C61SharedMultiOracleArtifact { payload: proof.shared_payload.clone() };
    let ((response_commitment, response_proof), (plan_commitment, plan_proof), joint_tag) =
        decode_c61_shared_multi_oracle_artifact(
            &artifact,
            response_num_variables,
            plan_num_variables,
        )
        .map_err(|error| error.to_string())?;
    if response_commitment.num_roots() != 1
        || plan_commitment.num_roots() != 1
        || response_commitment.roots()[0] != expected_response_root
        || plan_commitment.roots()[0] != expected_plan_root
    {
        return Err(
            "C6SPR11 decoded compiler commitments differ from the typed statement".to_owned()
        );
    }

    let (mut response_challenger, mut plan_challenger, coordinator) =
        c61_shared_round_pair(&mut transcript, [response_num_variables, plan_num_variables]);
    let response_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(response_num_variables)?;
    let plan_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(plan_num_variables)?;
    let response_mmcs = c61_reference_mmcs();
    let plan_mmcs = c61_reference_mmcs();
    response_challenger.observe(response_commitment.clone());
    plan_challenger.observe(plan_commitment.clone());
    let mut doms = volta_proto::logup::Doms::new(50_000);
    let phase = coordinator.with_pre_statement_transcript(|transcript| {
        verify_c61_sparse_compiler_relation_phase(
            fixture,
            proof.arithmetic_payload(),
            context,
            &mut doms,
            transcript,
        )
    })?;

    let mut response_points: Vec<_> = phase
        .physical_points
        .response()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(response_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    response_points.extend(c61_exact_plan_fold_physical_points(
        &fixture.terminal_binding,
        fixture.base_domain_log2,
        response_num_variables,
    )?);
    let plan_points: Vec<_> = phase
        .physical_points
        .plan()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(plan_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    if response_points.len() != C61_EXACT_PHYSICAL_RESPONSE_OPENINGS
        || plan_points.len() != 3
        || response_points.iter().any(|point| point.num_variables() != response_num_variables)
        || plan_points.iter().any(|point| point.num_variables() != plan_num_variables)
    {
        return Err("C6SPR11 compact compiler opening point shape mismatch".to_owned());
    }
    let statement_digest = c61_sparse_shared_statement_digest(
        &response_commitment,
        &plan_commitment,
        &response_points,
        &plan_points,
        phase.public_relation.digest(),
        proof.arithmetic_payload(),
        &phase.plan_values,
        &fixture.terminal_binding,
    )?;
    response_challenger
        .observe_public_points(statement_digest, &response_points)
        .map_err(|error| error.to_string())?;
    plan_challenger
        .observe_public_points(statement_digest, &plan_points)
        .map_err(|error| error.to_string())?;
    let response_verifier = HidingWhirVerifier::new(&response_config, &response_mmcs);
    let plan_verifier = HidingWhirVerifier::new(&plan_config, &plan_mmcs);
    let (response_result, plan_result) = thread::scope(|scope| {
        let response_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                response_verifier.verify_claimless(
                    &response_proof,
                    &response_commitment,
                    &response_points,
                    &mut response_challenger,
                )
            }));
            (result, response_challenger.finish_lane())
        });
        let plan_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                plan_verifier.verify_claimless(
                    &plan_proof,
                    &plan_commitment,
                    &plan_points,
                    &mut plan_challenger,
                )
            }));
            (result, plan_challenger.finish_lane())
        });
        (response_thread.join(), plan_thread.join())
    });
    let (response_result, response_finish) =
        response_result.map_err(|_| "C6SPR11 response verifier thread panicked")?;
    response_finish?;
    let response_result = response_result
        .map_err(|_| "C6SPR11 response verifier panicked")?
        .map_err(|error| format!("C6SPR11 response verification failed: {error}"))?;
    let (plan_result, plan_finish) =
        plan_result.map_err(|_| "C6SPR11 plan verifier thread panicked")?;
    plan_finish?;
    let plan_result = plan_result
        .map_err(|_| "C6SPR11 plan verifier panicked")?
        .map_err(|error| format!("C6SPR11 plan verification failed: {error}"))?;
    let eta = coordinator.sample_postproof_fp2()?;
    let whir_payload_bytes = proof
        .shared_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6SPR11 shared payload is shorter than its joint tag".to_owned())?;
    let verifier_interaction = coordinator.finish(&proof.shared_payload[..whir_payload_bytes])?;
    drop(coordinator);

    let delta = context.delta;
    let mut response_keys = phase.response_keys.to_vec();
    response_keys.extend(
        proof
            .physical_plan_fold_values
            .iter()
            .copied()
            .map(|value| VerifierKey::from_public(value, delta)),
    );
    let response_key = affine_from_p3(response_result.target).derive_verifier_key(
        aggregate_verifier_targets(&response_keys, &response_result.claim_weights)?,
        delta,
    );
    let plan_keys = phase.plan_values.map(|value| VerifierKey::from_public(value, delta));
    let plan_key = affine_from_p3(plan_result.target).derive_verifier_key(
        aggregate_verifier_targets(&plan_keys, &plan_result.claim_weights)?,
        delta,
    );
    let response_gamma = c61_volta_fp2_from_p3(response_result.base_case.gamma);
    let plan_gamma = c61_volta_fp2_from_p3(plan_result.base_case.gamma);
    let joint_key = response_key.scale(response_gamma).add(plan_key.scale(eta * plan_gamma));
    let joint_combined = c61_volta_fp2_from_p3(response_result.base_case.combined)
        - c61_volta_fp2_from_p3(response_result.base_case.shifted_masked_claim)
        + eta
            * (c61_volta_fp2_from_p3(plan_result.base_case.combined)
                - c61_volta_fp2_from_p3(plan_result.base_case.shifted_masked_claim));
    let _residual = verify_c61_authenticated_whir_base_with_zero_rows_residual(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: joint_combined,
            shifted_masked_claim: Fp2::ZERO,
            gamma: Fp2::ONE,
            target: joint_key,
        },
        &phase.zero_rows,
        joint_tag,
        context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    if transcript.is_interactive() {
        transcript.finish_interactive(&proof.encode()?)?;
    }
    Ok(C61ProductionCompilerChainVerification {
        id,
        response_num_variables,
        plan_num_variables,
        response_claim_count: C61_EXACT_PHYSICAL_RESPONSE_OPENINGS,
        plan_claim_count: 3,
        strict_payload_bytes: proof.shared_payload.len(),
        arithmetic_payload_bytes: proof.arithmetic_payload.len(),
        verifier_interaction,
        verifier_transcript_bytes: transcript.total_bytes(),
        verifier_ledger: transcript.ledger().clone(),
        compact_profile_digest,
        compact_profile_setup_bytes,
        client_setup_allocation_bytes,
    })
}

/// Verify one production compiler chain from strict wire bytes and compact
/// client setup.  This boundary has no provider correlations, installed
/// operation plan, extraction map contents, response witness, or D27 vector.
#[allow(clippy::too_many_arguments)]
pub fn verify_c61_authenticated_whir_p3_production_compiler_chain_in_attempt(
    profile: &C61CompilerVerifierProfile,
    extraction_map_setup_bytes: u64,
    public: &C61TypedNativeChainPublicStatement,
    relation_challenges: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    proof_bytes: &[u8],
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainVerification, String> {
    verify_c61_authenticated_whir_p3_production_compiler_chain_with_transcript(
        profile,
        extraction_map_setup_bytes,
        public,
        relation_challenges,
        proof_bytes,
        context,
        Transcript::new(verifier_seed),
        id,
        mask_range,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_c61_authenticated_whir_p3_production_compiler_chain_with_transcript(
    profile: &C61CompilerVerifierProfile,
    extraction_map_setup_bytes: u64,
    public: &C61TypedNativeChainPublicStatement,
    relation_challenges: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    proof_bytes: &[u8],
    context: &mut VerifierCtx,
    transcript: Transcript,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainVerification, String> {
    profile.validate()?;
    if !context.uses_pooled_pcg() {
        return Err("C6SPR11 production compiler verifier forbids mock PCG state".to_owned());
    }
    let rebuilt = C61TypedNativeChainPublicStatement::new(id, public.relation().clone())
        .map_err(|error| error.to_string())?;
    if &rebuilt != public || public.id() != id || id.component != C61NativeComponent::Compiler {
        return Err(
            "C6SPR11 compiler public statement or chain identity is noncanonical".to_owned()
        );
    }
    let compiler = match public.relation() {
        C61TypedNativeRelationStatement::Compiler(statement) => statement.as_ref(),
        _ => return Err("C6SPR11 compiler verifier rejects a non-compiler statement".to_owned()),
    };
    if compiler.operation_plan_digest != profile.operation_plan_digest
        || compiler.operation_topology_digest != profile.topology.topology_digest
        || compiler.terminal_metadata_digest != profile.terminal_metadata.digest()
        || compiler.relation_challenges_digest != relation_challenges.digest()
        || compiler.sparse_oracles.response.polynomial_domain_log2 != 28
        || compiler.sparse_oracles.plan.polynomial_domain_log2 != 27
        || compiler.sparse_oracles.response.parameter_digest != profile.response_parameter_digest
        || compiler.sparse_oracles.plan.parameter_digest != profile.plan_parameter_digest
    {
        return Err(
            "C6SPR11 compiler statement differs from compact setup or response relation".to_owned()
        );
    }
    let client_setup_allocation_bytes = extraction_map_setup_bytes
        .checked_add(profile.encoded_setup_bytes)
        .ok_or_else(|| "C6SPR11 client setup allocation overflows".to_owned())?;
    if client_setup_allocation_bytes > C61_COMPILER_VERIFIER_SETUP_CAP_BYTES {
        return Err("C6SPR11 extraction map plus compact profile exceeds 8 MB".to_owned());
    }
    let proof = C61ProductionCompilerChainProof::decode(proof_bytes)?;
    let terminal_binding = C61ExactTerminalFoldBinding::new(
        &profile.terminal_metadata,
        relation_challenges,
        [&compiler.leaf_points[0], &compiler.leaf_points[1]],
        [&compiler.auxiliary_points[0], &compiler.auxiliary_points[1]],
        compiler.terminal_claims,
        compiler.output_beta,
        proof.plan_folds,
    )?;
    if terminal_binding.digest != proof.terminal_binding_digest {
        return Err(
            "C6SPR11 decoded C6CPX2 terminal digest differs from the typed statement".to_owned()
        );
    }
    // The packed-oracle content digests do not alter physical coordinates;
    // the verifier binds their identity to the already decoded commitment
    // roots, avoiding an additional response field.
    let fixture = C61SparseCompilerVerifierFixture {
        operation_plan_digest: profile.operation_plan_digest,
        topology: profile.topology,
        terminal_metadata: &profile.terminal_metadata,
        relation_challenges,
        output_beta: compiler.output_beta,
        base_domain_log2: profile.base_domain_log2,
        response_digest: compiler.sparse_oracles.response.commitment_root,
        plan_digest: compiler.sparse_oracles.plan.commitment_root,
        terminal_binding,
    };
    verify_c61_authenticated_whir_p3_compiler_chain_compact_with_transcript(
        &fixture,
        compiler.sparse_oracles.response.commitment_root,
        compiler.sparse_oracles.plan.commitment_root,
        28,
        &proof,
        context,
        transcript,
        id,
        mask_range,
        profile.digest,
        profile.encoded_setup_bytes,
        client_setup_allocation_bytes,
    )
}

/// Disk-verifier replay for one seedless compiler chain. The tape is
/// client-private and bound to the public durable attempt before verification.
#[allow(clippy::too_many_arguments)]
pub fn verify_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(
    profile: &C61CompilerVerifierProfile,
    extraction_map_setup_bytes: u64,
    public: &C61TypedNativeChainPublicStatement,
    relation_challenges: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    proof_bytes: &[u8],
    context: &mut VerifierCtx,
    tape: C61InteractiveTape,
    provider_session_binding: C61ProviderSessionBinding,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61ProductionCompilerChainVerification, String> {
    provider_session_binding.validate_for(id, mask_range)?;
    let endpoint = C61PrivateEntropyTranscriptReplayEndpoint::new(
        tape,
        28,
        provider_session_binding.context_digest(),
    )
    .map_err(|error| error.to_string())?;
    verify_c61_authenticated_whir_p3_production_compiler_chain_with_transcript(
        profile,
        extraction_map_setup_bytes,
        public,
        relation_challenges,
        proof_bytes,
        context,
        Transcript::new_interactive(Box::new(endpoint)),
        id,
        mask_range,
    )
}

/// Exercise the C6SPR3 physical response/plan opening as Dn and D(n-1)
/// commitments sharing every common native verifier challenge, the exact
/// response-only tail, and one final authenticated residual.  At production
/// this geometry is D28/D27; the executable differential uses D14/D13.
pub fn run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(
    response_num_variables: usize,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    if response_num_variables == 28 {
        reject_monolithic_production_backend()?;
        return Err("C6SPR4 production admission returned without a production backend".to_owned());
    }
    let fixture = c61_sparse_compiler_physical_fixture()?;
    let verifier_seed = [0xC2; 32];
    let pcg_seed = [0xD3; 32];
    let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
    let mut correlations = CorrelationStream::new(pcg_seed);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 };
    run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
        &fixture,
        response_num_variables,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        0,
    )
}

/// Execute the scaled shared-chain differential through the C6SPX1 persisted
/// prover-data lifecycle.  The unchanged resident MMCS is still used by the
/// verifier after strict decoding.
pub fn run_c61_authenticated_whir_p3_shared_multi_oracle_persisted_diagnostic(
    response_num_variables: usize,
    spill_root: &Path,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    if response_num_variables == 28 {
        return Err("C6SPX1 diagnostic does not admit production geometry".to_owned());
    }
    let fixture = c61_sparse_compiler_physical_fixture()?;
    let verifier_seed = [0xC2; 32];
    let pcg_seed = [0xD3; 32];
    let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
    let mut correlations = CorrelationStream::new(pcg_seed);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 };
    let mut session_hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/c6spx1-session/v1");
    session_hasher.update(&verifier_seed);
    session_hasher.update(&(response_num_variables as u64).to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    let commit_gate = Arc::new(Mutex::new(()));
    let response_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("response"),
        session_digest,
        *b"response",
        Arc::clone(&commit_gate),
    )?;
    let plan_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("plan"),
        session_digest,
        *b"planlane",
        commit_gate,
    )?;
    run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs(
        &fixture,
        response_num_variables,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        0,
        0,
        response_mmcs,
        plan_mmcs,
    )
    .map(|execution| execution.report)
}

fn run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    admitted_available_host_bytes: u64,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs(
        fixture,
        response_num_variables,
        correlations,
        context,
        verifier_seed,
        id,
        mask_range,
        admitted_available_host_bytes,
        0,
        c61_reference_mmcs(),
        c61_reference_mmcs(),
    )
    .map(|execution| execution.report)
}

#[allow(clippy::too_many_arguments)]
fn run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs<RM, PM>(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    admitted_available_host_bytes: u64,
    admitted_available_spill_bytes: u64,
    response_mmcs: RM,
    plan_mmcs: PM,
) -> Result<C61ProductionCompilerChainExecution, String>
where
    RM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    PM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    RM::ProverData<DenseMatrix<Goldilocks>>: Send,
    PM::ProverData<DenseMatrix<Goldilocks>>: Send,
{
    run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_transcript(
        fixture,
        response_num_variables,
        correlations,
        Some(context),
        Some(verifier_seed),
        Transcript::new(verifier_seed),
        id,
        mask_range,
        admitted_available_host_bytes,
        admitted_available_spill_bytes,
        response_mmcs,
        plan_mmcs,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_transcript<RM, PM>(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
    correlations: &mut CorrelationStream,
    mut verifier_context: Option<&mut VerifierCtx>,
    verifier_seed: Option<[u8; 32]>,
    mut provider_transcript: Transcript,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    admitted_available_host_bytes: u64,
    admitted_available_spill_bytes: u64,
    response_mmcs: RM,
    plan_mmcs: PM,
) -> Result<C61ProductionCompilerChainExecution, String>
where
    RM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    PM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    RM::ProverData<DenseMatrix<Goldilocks>>: Send,
    PM::ProverData<DenseMatrix<Goldilocks>>: Send,
{
    let verifier_fixture = fixture.verifier_fixture()?;
    let native_response_num_variables = usize::from(fixture.packed.physical_response_domain_log2());
    let native_plan_num_variables = usize::from(fixture.packed.plan_domain_log2());
    if fixture.production
        && (native_response_num_variables != 28
            || native_plan_num_variables != 27
            || response_num_variables != 28)
    {
        return Err("C6SPR5 production materialization must be exact D28/D27".to_owned());
    }
    if !fixture.production
        && !(native_response_num_variables..=20).contains(&response_num_variables)
    {
        return Err(format!(
            "C6SPR3 scaled response geometry must be in D{native_response_num_variables}..=D20; production uses the separate fail-closed D28 admission"
        ));
    }
    let plan_num_variables = response_num_variables - 1;
    if plan_num_variables < native_plan_num_variables {
        return Err("C6SPR3 plan padding dimension is below its native layout".to_owned());
    }
    let mut response_coefficients = fixture
        .packed
        .physical_response_values()
        .into_iter()
        .map(|value| Goldilocks::from_u64(value.value()))
        .collect::<Vec<_>>();
    response_coefficients.resize(1usize << response_num_variables, Goldilocks::ZERO);
    let response_witness = Poly::new(response_coefficients);
    let mut plan_coefficients = fixture
        .packed
        .physical_plan_values()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|value| Goldilocks::from_u64(value.value()))
        .collect::<Vec<_>>();
    plan_coefficients.resize(1usize << plan_num_variables, Goldilocks::ZERO);
    let plan_witness = Poly::new(plan_coefficients);
    let pooled_pcg = correlations.uses_pooled_pcg()
        && verifier_context.as_ref().is_none_or(|context| context.uses_pooled_pcg());
    if fixture.production && !pooled_pcg {
        return Err("C6SPR5 production executor requires real pooled PCG correlations".to_owned());
    }
    let mut provider_doms = volta_proto::logup::Doms::new(50_000);

    let (mut response_challenger, mut plan_challenger, provider_coordinator) =
        c61_shared_round_pair(
            &mut provider_transcript,
            [response_num_variables, plan_num_variables],
        );
    let response_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(response_num_variables)?;
    let plan_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(plan_num_variables)?;
    let response_dft = Radix2DFTSmallBatch::default();
    let plan_dft = Radix2DFTSmallBatch::default();
    let response_prover = HidingWhirProver::new(&response_config, &response_dft, &response_mmcs);
    let plan_prover = HidingWhirProver::new(&plan_config, &plan_dft, &plan_mmcs);
    let (mut response_rng, mut plan_rng) = if fixture.production {
        (c61_production_private_zk_rng()?, c61_production_private_zk_rng()?)
    } else {
        (StdRng::seed_from_u64(0xC6_5202), StdRng::seed_from_u64(0xC6_5203))
    };
    let (response_commitment, response_data) =
        response_prover.commit(response_witness, &mut response_challenger, &mut response_rng);
    let (plan_commitment, plan_data) =
        plan_prover.commit(plan_witness, &mut plan_challenger, &mut plan_rng);
    let provider_phase = provider_coordinator.with_pre_statement_transcript(|transcript| {
        prove_c61_sparse_compiler_relation_phase(
            &fixture,
            correlations,
            &mut provider_doms,
            transcript,
        )
    })?;
    let arithmetic_payload_mutation_rejected =
        if let (Some(context), Some(verifier_seed)) = (verifier_context.as_ref(), verifier_seed) {
            let mut changed_payload = provider_phase.arithmetic_payload.clone();
            let changed_index = changed_payload.len() / 2;
            changed_payload[changed_index] ^= 1;
            let mut changed_context = VerifierCtx::new([0xD3; 32], context.delta);
            let mut changed_doms = volta_proto::logup::Doms::new(50_000);
            let mut changed_transcript = Transcript::new(verifier_seed);
            verify_c61_sparse_compiler_relation_phase(
                &verifier_fixture,
                &changed_payload,
                &mut changed_context,
                &mut changed_doms,
                &mut changed_transcript,
            )
            .is_err()
        } else {
            false
        };
    let mut response_points: Vec<_> = provider_phase
        .physical_points
        .response()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(response_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    let (exact_plan_fold_points, exact_plan_fold_values) =
        c61_exact_plan_fold_physical_openings(fixture, response_num_variables)?;
    response_points.extend(exact_plan_fold_points);
    let mut response_values = provider_phase.response_values.to_vec();
    response_values.extend(exact_plan_fold_values);
    let plan_points: Vec<_> = provider_phase
        .physical_points
        .plan()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(plan_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    if response_points.len() != C61_EXACT_PHYSICAL_RESPONSE_OPENINGS
        || response_values.len() != C61_EXACT_PHYSICAL_RESPONSE_OPENINGS
        || plan_points.len() != 3
        || response_points.iter().any(|point| point.num_variables() != response_num_variables)
        || plan_points.iter().any(|point| point.num_variables() != plan_num_variables)
    {
        return Err("C6SPR3 exact physical opening point shape mismatch".to_owned());
    }
    let response_claim_count = response_points.len();
    if response_points[..C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS]
        .iter()
        .zip(provider_phase.response_values)
        .any(|(point, expected)| {
            c61_volta_fp2_from_p3(response_data.message.eval_base(point)) != expected
        })
        || response_points[C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS..]
            .iter()
            .zip(&response_values[C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS..])
            .any(|(point, expected)| {
                c61_volta_fp2_from_p3(response_data.message.eval_base(point)) != *expected
            })
        || plan_points.iter().zip(provider_phase.plan_values).any(|(point, expected)| {
            c61_volta_fp2_from_p3(plan_data.message.eval_base(point)) != expected
        })
    {
        return Err("C6SPR3 Volta-LSB/P3-MSB physical evaluation adapter mismatch".to_owned());
    }
    let response_claims: Vec<_> = response_points
        .iter()
        .cloned()
        .zip(response_values.iter().copied().map(c61_p3_fp2_from_volta))
        .collect();
    let plan_claims: Vec<_> = plan_points
        .iter()
        .cloned()
        .zip(provider_phase.plan_values.map(c61_p3_fp2_from_volta))
        .collect();
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, correlations)
        .map_err(|error| error.to_string())?;
    let response_base_shift = c61_p3_fp2_from_volta(prepared.value());
    let statement_digest = c61_sparse_shared_statement_digest(
        &response_commitment,
        &plan_commitment,
        &response_points,
        &plan_points,
        provider_phase.public_relation.digest(),
        &provider_phase.arithmetic_payload,
        &provider_phase.plan_values,
        &fixture.terminal_binding,
    )?;
    response_challenger
        .observe_public_points(statement_digest, &response_points)
        .map_err(|error| error.to_string())?;
    plan_challenger
        .observe_public_points(statement_digest, &plan_points)
        .map_err(|error| error.to_string())?;

    let (response_output, plan_output) = thread::scope(|scope| {
        let response_thread = scope.spawn(move || {
            let output = response_prover.prove_claimless(
                response_data,
                &response_claims,
                response_base_shift,
                &mut response_challenger,
                &mut response_rng,
            );
            response_challenger.finish_lane().map(|()| output)
        });
        let plan_thread = scope.spawn(move || {
            let output = plan_prover.prove_claimless(
                plan_data,
                &plan_claims,
                C61P3Fp2::ZERO,
                &mut plan_challenger,
                &mut plan_rng,
            );
            plan_challenger.finish_lane().map(|()| output)
        });
        (response_thread.join(), plan_thread.join())
    });
    let response_output = response_output.map_err(|_| "C6SMO1 response prover panicked")??;
    let plan_output = plan_output.map_err(|_| "C6SMO1 plan prover panicked")??;
    let provider_eta = provider_coordinator.sample_postproof_fp2()?;
    let placeholder =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let response_placeholder = encode_c61_authenticated_p3_artifact_inner(
        response_num_variables,
        &response_commitment,
        &response_output.proof,
        placeholder,
        false,
    )
    .map_err(|error| error.to_string())?;
    let plan_payload = encode_c61_authenticated_p3_artifact_inner(
        plan_num_variables,
        &plan_commitment,
        &plan_output.proof,
        placeholder,
        false,
    )
    .map_err(|error| error.to_string())?;
    let placeholder_artifact = encode_c61_shared_multi_oracle_artifact(
        response_num_variables,
        plan_num_variables,
        &response_placeholder,
        &plan_payload,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6SMO1 payload is shorter than its joint tag".to_owned())?;
    let provider_interaction =
        provider_coordinator.finish(&placeholder_artifact.payload[..whir_payload_bytes])?;
    drop(provider_coordinator);

    let response_affine = affine_from_p3(response_output.target);
    let plan_affine = affine_from_p3(plan_output.target);
    let mut response_targets = provider_phase.response_targets.to_vec();
    response_targets.extend(
        response_values[C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS..]
            .iter()
            .copied()
            .map(ProverAuthed::from_public),
    );
    let response_target = response_affine.authenticate_prover(aggregate_prover_targets(
        &response_targets,
        &response_output.claim_weights,
    )?);
    let plan_targets = provider_phase.plan_values.map(ProverAuthed::from_public);
    let plan_target = plan_affine
        .authenticate_prover(aggregate_prover_targets(&plan_targets, &plan_output.claim_weights)?);
    let response_gamma = c61_volta_fp2_from_p3(response_output.base_case.gamma);
    let plan_gamma = c61_volta_fp2_from_p3(plan_output.base_case.gamma);
    let joint_target =
        response_target.scale(response_gamma).add(plan_target.scale(provider_eta * plan_gamma));
    let joint_combined = c61_volta_fp2_from_p3(response_output.base_case.combined)
        - c61_volta_fp2_from_p3(response_output.base_case.shifted_masked_claim)
        + provider_eta
            * (c61_volta_fp2_from_p3(plan_output.base_case.combined)
                - c61_volta_fp2_from_p3(plan_output.base_case.shifted_masked_claim));
    let joint_closure = finish_c61_authenticated_whir_base_with_zero_rows(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: joint_combined,
            shifted_masked_claim: Fp2::ZERO,
            gamma: Fp2::ONE,
            target: joint_target,
        },
        &provider_phase.zero_rows,
        &mut provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let response_payload = encode_c61_authenticated_p3_artifact_inner(
        response_num_variables,
        &response_commitment,
        &response_output.proof,
        joint_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let artifact = encode_c61_shared_multi_oracle_artifact(
        response_num_variables,
        plan_num_variables,
        &response_payload,
        &plan_payload,
    )
    .map_err(|error| error.to_string())?;
    if artifact.payload.len() != placeholder_artifact.payload.len() {
        return Err("C6SMO1 joint tag changed strict payload length".to_owned());
    }
    let codec_mutations_rejected = {
        let rejects = |payload: Vec<u8>| {
            decode_c61_shared_multi_oracle_artifact(
                &C61SharedMultiOracleArtifact { payload },
                response_num_variables,
                plan_num_variables,
            )
            .is_err()
        };
        let mut bad_magic = artifact.payload.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = artifact.payload.clone();
        bad_version[8] ^= 1;
        let mut bad_response_dimension = artifact.payload.clone();
        bad_response_dimension[10] ^= 1;
        let mut bad_plan_dimension = artifact.payload.clone();
        bad_plan_dimension[11] ^= 1;
        let mut bad_response_len = artifact.payload.clone();
        bad_response_len[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut bad_plan_reserved_tag = artifact.payload.clone();
        *bad_plan_reserved_tag.last_mut().expect("C6SMO1 artifact is nonempty") ^= 1;
        let mut trailing = artifact.payload.clone();
        trailing.push(0);
        let mut truncated = artifact.payload.clone();
        truncated.pop();
        [
            bad_magic,
            bad_version,
            bad_response_dimension,
            bad_plan_dimension,
            bad_response_len,
            bad_plan_reserved_tag,
            trailing,
            truncated,
        ]
        .into_iter()
        .all(rejects)
    };

    let strict_response = c61_authenticated_structural_budget_inner(response_num_variables, false)?
        .strict_chain_bytes;
    let strict_plan =
        c61_authenticated_structural_budget_inner(plan_num_variables, false)?.strict_chain_bytes;
    let response_spill = response_mmcs.c61_persisted_metrics();
    let plan_spill = plan_mmcs.c61_persisted_metrics();
    let persisted_executor = response_spill.is_some() && plan_spill.is_some();
    let physical_plan_fold_values: [Fp2; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS] = response_values
        [C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS..]
        .try_into()
        .map_err(|_| "C6CPX2 physical plan-fold target census mismatch".to_owned())?;
    fixture.terminal_binding.validate_physical_plan_fold_values(
        fixture.packed.base_domain_log2(),
        &physical_plan_fold_values,
    )?;
    let proof = C61ProductionCompilerChainProof {
        terminal_binding_digest: fixture.terminal_binding.digest,
        plan_folds: fixture.terminal_binding.plan_folds,
        physical_plan_fold_values,
        arithmetic_payload: provider_phase.arithmetic_payload.clone(),
        shared_payload: artifact.payload.clone(),
    };
    let proof_bytes = proof.encode()?;
    let proof = C61ProductionCompilerChainProof::decode(&proof_bytes)?;
    let public = if fixture.production {
        Some(c61_production_compiler_public_statement(
            fixture,
            id,
            response_commitment.roots()[0],
            plan_commitment.roots()[0],
        )?)
    } else {
        None
    };
    if provider_transcript.is_interactive() {
        provider_transcript.finish_interactive(&proof_bytes)?;
    }

    let build_report = |verifier_interaction: C61WhirInteractionStats,
                        postproof_batching_challenge_identical: bool,
                        joint_tag_mutation_rejected: bool,
                        role_separated_compact_verifier_checked: bool|
     -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
        Ok(C61AuthenticatedP3SharedMultiOracleDiagnostic {
            production_geometry: fixture.production,
            monolithic_host_baseline: fixture.production && !persisted_executor,
            persisted_executor,
            gpu_performance_credit: false,
            admitted_available_host_bytes,
            admitted_available_spill_bytes,
            monolithic_retained_lower_bound_bytes: if fixture.production {
                c61_production_monolithic_memory_census()?.concurrent_retained_lower_bound_bytes
            } else {
                0
            },
            pooled_pcg,
            response_num_variables,
            plan_num_variables,
            response_claim_count,
            plan_claim_count: provider_phase.plan_values.len(),
            strict_payload_bytes: artifact.payload.len(),
            strict_payload_blake3: *blake3::hash(&artifact.payload).as_bytes(),
            strict_payload_max_bytes: C61_SHARED_MULTI_ORACLE_HEADER_BYTES
                + strict_response
                + strict_plan,
            arithmetic_payload_bytes: provider_phase.arithmetic_payload.len(),
            total_provider_payload_bytes: provider_phase
                .arithmetic_payload
                .len()
                .checked_add(artifact.payload.len())
                .ok_or_else(|| "C6SPR3 complete provider byte count overflow".to_owned())?,
            response_target_correction_bytes: provider_transcript
                .bytes_for("c6_sparse_response_target_corrections"),
            arithmetic_product_triples: provider_phase.product_triples,
            folded_zero_rows: provider_phase.zero_rows.len(),
            provider_transcript_bytes: provider_transcript.total_bytes(),
            provider_interaction,
            verifier_interaction,
            native_challenges_shared: response_output.claim_weights
                [..plan_output.claim_weights.len()]
                == plan_output.claim_weights,
            postproof_batching_challenge_identical,
            plan_reserved_tag_is_zero: true,
            codec_mutations_rejected,
            arithmetic_payload_mutation_rejected,
            joint_tag_mutation_rejected,
            role_separated_compact_verifier_checked,
            subfield_correlations: correlations.counters.sub_corrs,
            full_correlations: correlations.counters.full_corrs,
            response_spill: response_spill.unwrap_or_default(),
            plan_spill: plan_spill.unwrap_or_default(),
        })
    };

    if verifier_context.is_none() {
        let report = build_report(C61WhirInteractionStats::default(), false, false, false)?;
        return Ok(C61ProductionCompilerChainExecution { public, proof, report });
    }
    let context = verifier_context
        .take()
        .ok_or_else(|| "C6ICT2 compiler verifier context disappeared".to_owned())?;
    let verifier_seed = verifier_seed
        .ok_or_else(|| "C6ICT2 compiler verifier seed/context pairing mismatch".to_owned())?;
    let delta = context.delta;

    let ((response_commitment, response_proof), (plan_commitment, plan_proof), joint_tag) =
        decode_c61_shared_multi_oracle_artifact(
            &artifact,
            response_num_variables,
            plan_num_variables,
        )
        .map_err(|error| error.to_string())?;
    let mut verifier_transcript = Transcript::new(verifier_seed);
    let (mut response_challenger, mut plan_challenger, verifier_coordinator) =
        c61_shared_round_pair(
            &mut verifier_transcript,
            [response_num_variables, plan_num_variables],
        );
    let response_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(response_num_variables)?;
    let plan_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(plan_num_variables)?;
    let verifier_response_mmcs = c61_reference_mmcs();
    let verifier_plan_mmcs = c61_reference_mmcs();
    response_challenger.observe(response_commitment.clone());
    plan_challenger.observe(plan_commitment.clone());
    let mut verifier_doms = volta_proto::logup::Doms::new(50_000);
    let verifier_phase = verifier_coordinator.with_pre_statement_transcript(|transcript| {
        verify_c61_sparse_compiler_relation_phase(
            &verifier_fixture,
            &provider_phase.arithmetic_payload,
            context,
            &mut verifier_doms,
            transcript,
        )
    })?;
    if verifier_phase.public_relation.digest() != provider_phase.public_relation.digest()
        || verifier_phase.physical_points != provider_phase.physical_points
        || verifier_phase.plan_values != provider_phase.plan_values
        || verifier_phase.product_triples != provider_phase.product_triples
        || verifier_phase.zero_rows.len() != provider_phase.zero_rows.len()
    {
        return Err("C6SPR3 provider/verifier pre-statement relation mismatch".to_owned());
    }
    let verifier_statement_digest = c61_sparse_shared_statement_digest(
        &response_commitment,
        &plan_commitment,
        &response_points,
        &plan_points,
        verifier_phase.public_relation.digest(),
        &provider_phase.arithmetic_payload,
        &verifier_phase.plan_values,
        &verifier_fixture.terminal_binding,
    )?;
    response_challenger
        .observe_public_points(verifier_statement_digest, &response_points)
        .map_err(|error| error.to_string())?;
    plan_challenger
        .observe_public_points(verifier_statement_digest, &plan_points)
        .map_err(|error| error.to_string())?;
    let response_verifier = HidingWhirVerifier::new(&response_config, &verifier_response_mmcs);
    let plan_verifier = HidingWhirVerifier::new(&plan_config, &verifier_plan_mmcs);
    let (response_result, plan_result) = thread::scope(|scope| {
        let response_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                response_verifier.verify_claimless(
                    &response_proof,
                    &response_commitment,
                    &response_points,
                    &mut response_challenger,
                )
            }));
            (result, response_challenger.finish_lane())
        });
        let plan_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                plan_verifier.verify_claimless(
                    &plan_proof,
                    &plan_commitment,
                    &plan_points,
                    &mut plan_challenger,
                )
            }));
            (result, plan_challenger.finish_lane())
        });
        (response_thread.join(), plan_thread.join())
    });
    let (response_result, response_finish) =
        response_result.map_err(|_| "C6SMO1 response verifier thread panicked")?;
    response_finish?;
    let response_result = response_result
        .map_err(|_| "C6SMO1 response verifier panicked")?
        .map_err(|error| format!("C6SMO1 response verification failed: {error}"))?;
    let (plan_result, plan_finish) =
        plan_result.map_err(|_| "C6SMO1 plan verifier thread panicked")?;
    plan_finish?;
    let plan_result = plan_result
        .map_err(|_| "C6SMO1 plan verifier panicked")?
        .map_err(|error| format!("C6SMO1 plan verification failed: {error}"))?;
    let verifier_eta = verifier_coordinator.sample_postproof_fp2()?;
    let verifier_interaction =
        verifier_coordinator.finish(&artifact.payload[..whir_payload_bytes])?;
    drop(verifier_coordinator);

    let mut response_keys = verifier_phase.response_keys.to_vec();
    response_keys.extend(
        response_values[C61_SPARSE_ARITHMETIC_PHYSICAL_RESPONSE_OPENINGS..]
            .iter()
            .copied()
            .map(|value| VerifierKey::from_public(value, delta)),
    );
    let response_key = affine_from_p3(response_result.target).derive_verifier_key(
        aggregate_verifier_targets(&response_keys, &response_result.claim_weights)?,
        delta,
    );
    let plan_keys = verifier_phase.plan_values.map(|value| VerifierKey::from_public(value, delta));
    let plan_key = affine_from_p3(plan_result.target).derive_verifier_key(
        aggregate_verifier_targets(&plan_keys, &plan_result.claim_weights)?,
        delta,
    );
    let response_gamma = c61_volta_fp2_from_p3(response_result.base_case.gamma);
    let plan_gamma = c61_volta_fp2_from_p3(plan_result.base_case.gamma);
    let joint_key =
        response_key.scale(response_gamma).add(plan_key.scale(verifier_eta * plan_gamma));
    let joint_combined = c61_volta_fp2_from_p3(response_result.base_case.combined)
        - c61_volta_fp2_from_p3(response_result.base_case.shifted_masked_claim)
        + verifier_eta
            * (c61_volta_fp2_from_p3(plan_result.base_case.combined)
                - c61_volta_fp2_from_p3(plan_result.base_case.shifted_masked_claim));
    let joint_verifier_input = C61AuthenticatedWhirVerifierInput {
        id,
        mask_range,
        combined: joint_combined,
        shifted_masked_claim: Fp2::ZERO,
        gamma: Fp2::ONE,
        target: joint_key,
    };
    let joint_residual = verify_c61_authenticated_whir_base_with_zero_rows_residual(
        joint_verifier_input,
        &verifier_phase.zero_rows,
        joint_tag,
        context,
        &mut verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    let joint_tag_mutation_rejected = {
        let mut bytes = joint_tag.encode();
        bytes[0] ^= 1;
        let changed_tag =
            C61AuthenticatedWhirBaseProof::decode(&bytes).map_err(|error| error.to_string())?;
        !zero_open_verify(joint_residual, changed_tag.tag())
    };
    if provider_interaction != verifier_interaction {
        return Err(format!(
            "C6SMO1 provider/verifier shared interaction mismatch: provider={provider_interaction:?}, verifier={verifier_interaction:?}"
        ));
    }
    if provider_transcript.ledger() != verifier_transcript.ledger() {
        return Err(format!(
            "C6SMO1 provider/verifier transcript ledger mismatch: provider={:?}, verifier={:?}",
            provider_transcript.ledger(),
            verifier_transcript.ledger()
        ));
    }
    if statement_digest != verifier_statement_digest {
        return Err("C6SMO1 provider/verifier statement digest mismatch".to_owned());
    }

    let role_separated_compact_verifier_checked = if fixture.production {
        false
    } else {
        let ((response_commitment, _), (plan_commitment, _), _) =
            decode_c61_shared_multi_oracle_artifact(
                &C61SharedMultiOracleArtifact { payload: proof.shared_payload.clone() },
                response_num_variables,
                plan_num_variables,
            )
            .map_err(|error| error.to_string())?;
        let compact_fixture = C61SparseCompilerVerifierFixture {
            operation_plan_digest: verifier_fixture.operation_plan_digest,
            topology: verifier_fixture.topology,
            terminal_metadata: verifier_fixture.terminal_metadata,
            relation_challenges: verifier_fixture.relation_challenges,
            output_beta: verifier_fixture.output_beta,
            base_domain_log2: verifier_fixture.base_domain_log2,
            response_digest: response_commitment.roots()[0],
            plan_digest: plan_commitment.roots()[0],
            terminal_binding: verifier_fixture.terminal_binding.clone(),
        };
        let mut compact_context = VerifierCtx::new([0xD3; 32], delta);
        let compact = verify_c61_authenticated_whir_p3_compiler_chain_compact(
            &compact_fixture,
            response_commitment.roots()[0],
            plan_commitment.roots()[0],
            response_num_variables,
            &proof,
            &mut compact_context,
            verifier_seed,
            id,
            mask_range,
            [0; 32],
            0,
            0,
        )?;
        if compact.verifier_interaction != verifier_interaction
            || compact.verifier_transcript_bytes != verifier_transcript.total_bytes()
            || compact.verifier_ledger != *verifier_transcript.ledger()
        {
            return Err(
                "C6SPR11 role-separated compact verifier differs from inline verifier".to_owned()
            );
        }
        true
    };
    let report = build_report(
        verifier_interaction,
        provider_eta == verifier_eta,
        joint_tag_mutation_rejected,
        role_separated_compact_verifier_checked,
    )?;
    Ok(C61ProductionCompilerChainExecution { public, proof, report })
}

/// Execute the target-plaintext-free designated-verifier view simulator and
/// feed its strict artifact to the ordinary verifier.
pub fn run_c61_authenticated_whir_p3_privacy_diagnostic(
    num_variables: usize,
) -> Result<C61AuthenticatedP3PrivacyDiagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWP1 privacy diagnostic dimension must be in 4..=28".to_owned());
    }
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(29).wrapping_add(7)))
            .collect(),
    );
    let verifier_seed = [0x93; 32];
    let pcg_seed = [0xD5; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 37), volta_field::Fp::new(0xC6_1001));
    // This is verifier state, not a `(target, provider_tag)` pair.  The
    // simulator API has no way to receive either missing provider value.
    let target_key =
        VerifierKey::new(Fp2::new(volta_field::Fp::new(0x1234_5678), volta_field::Fp::new(P - 41)));
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 12, range_start: 60_000 };
    let (fixture, verifier_full_key_draws) = simulate_view_diagnostic(
        num_variables,
        point,
        target_key,
        verifier_seed,
        0xC6_3003,
        pcg_seed,
        delta,
        id,
        mask_range,
    )?;
    let (_, verifier_base_case, verifier_transcript, verifier_interaction) = verify_diagnostic(
        &fixture.artifact,
        C61AuthenticatedP3VerifierInput {
            point: &fixture.point,
            target_key,
            verifier_seed,
            pcg_seed,
            delta,
            id,
            mask_range,
        },
    )?;
    if fixture.provider_base_case != verifier_base_case {
        return Err("C6AWP1 simulator/verifier base closure mismatch".to_owned());
    }
    if fixture.provider_interaction != verifier_interaction {
        return Err("C6AWP1 simulator/verifier interaction accounting mismatch".to_owned());
    }
    if fixture.provider_ledger != *verifier_transcript.ledger() {
        return Err("C6AWP1 simulator/verifier transcript ledger mismatch".to_owned());
    }

    Ok(C61AuthenticatedP3PrivacyDiagnostic {
        num_variables,
        strict_payload_bytes: fixture.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&fixture.artifact.payload).as_bytes(),
        simulator_interaction: fixture.provider_interaction,
        verifier_interaction,
        simulator_transcript_bytes: fixture.provider_transcript_bytes,
        verifier_transcript_bytes: verifier_transcript.total_bytes(),
        simulator_ledger: fixture.provider_ledger,
        verifier_ledger: verifier_transcript.ledger().clone(),
        received_real_target_plaintext: false,
        received_provider_target_tag: false,
        received_provider_correlation_state: false,
        verifier_full_key_draws,
    })
}

/// Exercise the endpoint-only interactive driver, strict verifier-local
/// checkpoint codec, and deterministic replay to a mid-proof frontier.
pub fn run_c61_private_entropy_driver_diagnostic(
    num_variables: usize,
) -> Result<C61PrivateEntropyDriverDiagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6ICT1 diagnostic dimension must be in 4..=28".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(17).wrapping_add(3)))
            .collect(),
    );
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(19).wrapping_add(5)))
            .collect(),
    );
    let verifier_seed = [0x61; 32];
    let pcg_seed = [0xA7; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 17), volta_field::Fp::new(0x1234_5678));
    let target_tag = Fp2::new(volta_field::Fp::new(41), volta_field::Fp::new(43));
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 1, range_start: 40_000 };
    let evaluation = c61_volta_fp2_from_p3(witness.eval_base(&point));
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let context_digest =
        c61_private_entropy_context_digest(&point, target_key, delta, id, mask_range);
    let empty_checkpoint = C61InteractiveCheckpoint::empty(num_variables, context_digest)
        .map_err(|error| error.to_string())?;
    let first = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        empty_checkpoint,
        None,
    )?;
    if first.broker.ledger.values().sum::<u64>() != first.broker.transcript_bytes {
        return Err("C6ICT1 broker transcript ledger mismatch".to_owned());
    }
    let (verifier_affine, verifier_base_case, verifier_interaction) =
        verify_private_entropy_diagnostic(
            &first.artifact,
            &first.point,
            first.target_key,
            pcg_seed,
            delta,
            id,
            mask_range,
            first.broker.tape.clone(),
        )?;
    if first.provider_affine != verifier_affine
        || first.provider_base_case != verifier_base_case
        || first.broker.interaction != verifier_interaction
    {
        return Err("C6ICT1 provider/verifier differential mismatch".to_owned());
    }
    let checkpoint_frontier = first.broker.tape.challenge_count() / 2;
    let checkpoint_bytes = first
        .broker
        .tape
        .checkpoint_bytes(checkpoint_frontier)
        .map_err(|error| error.to_string())?;
    let checkpoint =
        C61InteractiveCheckpoint::decode(&checkpoint_bytes).map_err(|error| error.to_string())?;
    if checkpoint.challenge_count() != checkpoint_frontier {
        return Err("C6ICT1 checkpoint round-trip changed its frontier".to_owned());
    }
    let checkpoint_codec_mutations_rejected = {
        let mut wrong_magic = checkpoint_bytes.clone();
        wrong_magic[0] ^= 1;
        let mut wrong_version = checkpoint_bytes.clone();
        wrong_version[8] ^= 1;
        let mut wrong_reserved = checkpoint_bytes.clone();
        wrong_reserved[11] = 1;
        let mut wrong_record_tag = checkpoint_bytes.clone();
        wrong_record_tag[48] = 0xff;
        let mut wrong_record_reserved = checkpoint_bytes.clone();
        wrong_record_reserved[50] = 1;
        let mut trailing = checkpoint_bytes.clone();
        trailing.push(0);
        C61InteractiveCheckpoint::decode(&wrong_magic).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_version).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_reserved).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_record_tag).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_record_reserved).is_err()
            && C61InteractiveCheckpoint::decode(&checkpoint_bytes[..checkpoint_bytes.len() - 1])
                .is_err()
            && C61InteractiveCheckpoint::decode(&trailing).is_err()
    };

    let durable_root = std::env::temp_dir().join(format!(
        "volta-c61-durable-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock predates UNIX epoch".to_owned())?
            .as_nanos()
    ));
    std::fs::create_dir_all(&durable_root)
        .map_err(|error| format!("cannot create C6ICJ1 diagnostic directory: {error}"))?;
    let journal_path = durable_root.join("interaction.c6icj1");
    let head = C6CacheHead {
        epoch: 0,
        cache_len: 0,
        cache_root: [0x31; 32],
        producer_transition_digest: [0; 32],
    };
    let attempt = C6ClientAttempt {
        slot: 0,
        nonce: [0x32; 32],
        setup_manifest_digest: [0x33; 32],
        old_head_digest: head.digest(),
        predecessor_certificate_digest: [0; 32],
        correlation_ranges: C6PairedCorrelationRanges {
            coordinates: [
                C6CorrelationRange { stage: 1, start: 40_000, count: 100 },
                C6CorrelationRange { stage: 1, start: 40_000, count: 100 },
            ],
        },
        workload: C6Workload { prompt_tokens: 1, decode_tokens: 0, old_context: 0, new_context: 1 },
    };
    let durable_state = C6ClientState {
        protocol_digest: [0x34; 32],
        model_digest: [0x35; 32],
        params_digest: [0x36; 32],
        setup_manifest_digest: attempt.setup_manifest_digest,
        connection_id: [0x37; 32],
        head,
        accepted_certificate_digest: [0; 32],
        next_slot: 1,
        raw_high_water: [40_100, 40_100],
        pending_attempt: Some(attempt),
    };
    durable_state.validate().map_err(|error| error.to_string())?;
    let checkpoint_mask_events: Vec<(usize, u32, [u8; 32])> = first
        .broker
        .mask_events
        .iter()
        .copied()
        .filter(|(index, _, _)| *index <= checkpoint_frontier)
        .collect();
    let durable_journal = create_c61_durable_checkpoint_prefix(
        &journal_path,
        durable_state,
        attempt,
        checkpoint.clone(),
        &checkpoint_mask_events,
    )
    .map_err(|error| error.to_string())?;
    drop(durable_journal);
    let durable_journal = open_c61_durable_checkpoint(
        &journal_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .map_err(|error| error.to_string())?;
    let durable_resumed = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        checkpoint.clone(),
        Some(durable_journal),
    )?;
    let durable_resume_artifact_identical =
        durable_resumed.artifact.payload == first.artifact.payload;
    let durable_resume_tape_identical = durable_resumed.broker.tape == first.broker.tape;
    let durable_journal_bytes = usize::try_from(
        std::fs::metadata(&journal_path)
            .map_err(|error| format!("cannot stat C6ICJ1 journal: {error}"))?
            .len(),
    )
    .map_err(|_| "C6ICJ1 journal length exceeds usize".to_owned())?;
    let durable_bytes = std::fs::read(&journal_path)
        .map_err(|error| format!("cannot read C6ICJ1 diagnostic journal: {error}"))?;
    let wrong_binding_state = C6ClientState { connection_id: [0x38; 32], ..durable_state };
    let durable_wrong_binding_rejected = open_c61_durable_checkpoint(
        &journal_path,
        wrong_binding_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();
    let torn_path = durable_root.join("torn.c6icj1");
    std::fs::write(&torn_path, &durable_bytes[..durable_bytes.len() - 1])
        .map_err(|error| format!("cannot write torn C6ICJ1 journal: {error}"))?;
    let durable_torn_journal_rejected = open_c61_durable_checkpoint(
        &torn_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();
    let corrupt_path = durable_root.join("corrupt.c6icj1");
    let mut corrupt_bytes = durable_bytes;
    let corrupt_index = corrupt_bytes.len() / 2;
    corrupt_bytes[corrupt_index] ^= 1;
    std::fs::write(&corrupt_path, &corrupt_bytes)
        .map_err(|error| format!("cannot write corrupt C6ICJ1 journal: {error}"))?;
    let durable_corrupt_journal_rejected = open_c61_durable_checkpoint(
        &corrupt_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();

    let resumed = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        checkpoint.clone(),
        None,
    )?;
    let resumed_artifact_identical = resumed.artifact.payload == first.artifact.payload;
    let resumed_tape_identical = resumed.broker.tape == first.broker.tape;

    let mut mutated_checkpoint = checkpoint;
    mutated_checkpoint.mutate_first_move_for_test();
    let mutated_checkpoint_rejected = catch_unwind(AssertUnwindSafe(|| {
        prove_private_entropy_diagnostic(
            witness,
            point,
            verifier_seed,
            0xC6_1001,
            pcg_seed,
            delta,
            target_tag,
            id,
            mask_range,
            mutated_checkpoint,
            None,
        )
    }))
    .map_or(true, |result| result.is_err());

    std::fs::remove_dir_all(&durable_root)
        .map_err(|error| format!("cannot remove C6ICJ1 diagnostic directory: {error}"))?;

    Ok(C61PrivateEntropyDriverDiagnostic {
        num_variables,
        strict_payload_bytes: first.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&first.artifact.payload).as_bytes(),
        provider_interaction: first.broker.interaction,
        verifier_interaction,
        challenge_count: first.broker.tape.challenge_count(),
        checkpoint_frontier,
        checkpoint_bytes: checkpoint_bytes.len(),
        replayed_challenges: resumed.broker.replayed_challenges,
        resumed_artifact_identical,
        resumed_tape_identical,
        mutated_checkpoint_rejected,
        checkpoint_codec_mutations_rejected,
        durable_journal_bytes,
        durable_replayed_challenges: durable_resumed.broker.replayed_challenges,
        durable_replayed_mask_events: durable_resumed.broker.replayed_mask_events,
        durable_mask_frontier: durable_resumed.broker.mask_frontier,
        durable_record_count: durable_resumed.broker.durable_record_count,
        durable_resume_artifact_identical,
        durable_resume_tape_identical,
        durable_wrong_binding_rejected,
        durable_torn_journal_rejected,
        durable_corrupt_journal_rejected,
        provider_received_verifier_seed: false,
        provider_received_checkpoint: false,
        full_correlations: first.full_correlations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_claimless_affine_whir_closes_through_designated_mac() {
        let report = run_c61_authenticated_whir_p3_diagnostic(14).unwrap();
        assert_eq!(report.provider_affine, report.verifier_affine);
        assert_eq!(report.provider_ledger, report.verifier_ledger);
        assert_eq!(report.provider_transcript_bytes, report.verifier_transcript_bytes);
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(
            report.provider_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert_eq!(report.strict_payload_bytes, 378_496);
        assert_eq!(report.provider_interaction.provider_messages, 26);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 52_608);
        assert_eq!(report.provider_interaction.provider_payload_bytes, 378_480);
        assert_eq!(report.provider_interaction.client_fp_challenges, 52);
        assert_eq!(report.provider_interaction.client_query_challenges, 2_536);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 10_560);
        assert_eq!(
            report.strict_payload_blake3,
            [
                0x9d, 0xba, 0xa6, 0x63, 0x36, 0xf8, 0x83, 0x3b, 0x0a, 0x0e, 0x3a, 0x32, 0xf7, 0x02,
                0x3f, 0x5c, 0x25, 0xf2, 0x16, 0x6e, 0x6e, 0x84, 0x31, 0x24, 0x4a, 0x06, 0xb4, 0x1d,
                0x70, 0x79, 0x58, 0xbb,
            ],
        );
        assert!(!report.proof_has_clear_evaluation_field);
        assert_eq!(report.full_correlations, 1);

        let d27 = c61_authenticated_p3_structural_budget(27).unwrap();
        let d28 = c61_authenticated_p3_structural_budget(28).unwrap();
        assert_eq!(d27.rounds, 10);
        assert_eq!(d28.rounds, 11);
        assert_eq!(d27.mask_queries, 187);
        assert_eq!(d28.mask_queries, 187);
        assert_eq!(d27.max_ood_samples, 1);
        assert_eq!(d28.max_ood_samples, 1);
        assert_eq!(d27.ood_privacy_bad_event_numerator, 10);
        assert_eq!(d28.ood_privacy_bad_event_numerator, 11);
        assert_eq!(d27.strict_chain_bytes, 1_085_464);
        assert_eq!(d28.strict_chain_bytes, 1_172_652);
        assert!(d28.strict_chain_bytes < C61_NATIVE_CHAIN_MAX_BYTES);
        assert!(c61_authenticated_p3_structural_budget(26).is_err());
        assert!(c61_authenticated_structural_budget_inner(14, true).is_err());
    }

    #[test]
    fn ordered_multi_open_aggregates_authenticated_targets_without_wire_growth() {
        let embedding = run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 6).unwrap();
        let model = run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 96).unwrap();
        assert_eq!(embedding.claim_count, 6);
        assert_eq!(model.claim_count, 96);
        assert!(embedding.strict_payload_bytes <= embedding.strict_payload_max_bytes);
        assert!(model.strict_payload_bytes <= model.strict_payload_max_bytes);
        assert_eq!(
            embedding.strict_payload_max_bytes,
            c61_authenticated_structural_budget_inner(14, false).unwrap().strict_chain_bytes
        );
        assert_eq!(embedding.strict_payload_max_bytes, model.strict_payload_max_bytes);
        assert_eq!(embedding.provider_interaction, embedding.verifier_interaction);
        assert_eq!(model.provider_interaction, model.verifier_interaction);
        assert_eq!(
            embedding.provider_interaction.provider_payload_bytes as usize + 16,
            embedding.strict_payload_bytes
        );
        assert_eq!(
            model.provider_interaction.provider_payload_bytes as usize + 16,
            model.strict_payload_bytes
        );
        assert!(embedding.batching_weights_identical);
        assert!(model.batching_weights_identical);
        assert!(embedding.point_mutation_rejected);
        assert!(model.point_mutation_rejected);
        assert_eq!(embedding.full_correlations, 1);
        assert_eq!(model.full_correlations, 1);
        assert!(run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 129).is_err());
    }

    #[test]
    fn physical_response_and_plan_share_common_rounds_and_one_authenticated_residual() {
        let report = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(14).unwrap();
        assert!(!report.production_geometry);
        assert!(!report.monolithic_host_baseline);
        assert!(!report.persisted_executor);
        assert!(!report.gpu_performance_credit);
        assert_eq!(report.admitted_available_host_bytes, 0);
        assert_eq!(report.admitted_available_spill_bytes, 0);
        assert_eq!(report.monolithic_retained_lower_bound_bytes, 0);
        assert!(!report.pooled_pcg);
        assert_eq!(report.response_num_variables, 14);
        assert_eq!(report.plan_num_variables, 13);
        assert_eq!(report.response_claim_count, C61_EXACT_PHYSICAL_RESPONSE_OPENINGS);
        assert_eq!(report.plan_claim_count, 3);
        assert_eq!(report.strict_payload_bytes, 677_532);
        assert_eq!(report.strict_payload_max_bytes, 770_748);
        assert_eq!(report.arithmetic_payload_bytes, 5_212);
        assert_eq!(report.total_provider_payload_bytes, 682_744);
        assert_eq!(report.response_target_correction_bytes, 192);
        assert_eq!(report.arithmetic_product_triples, 87);
        assert_eq!(report.folded_zero_rows, 31);
        assert_eq!(report.provider_transcript_bytes, 682_652);
        assert_eq!(
            report.total_provider_payload_bytes as u64 - report.provider_transcript_bytes,
            crate::C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES,
        );
        assert!(report.strict_payload_bytes <= report.strict_payload_max_bytes);
        assert!(report.strict_payload_max_bytes < C61_SHARED_MULTI_ORACLE_MAX_BYTES);
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(report.provider_interaction.provider_messages, 36);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 94_752);
        assert_eq!(report.provider_interaction.client_fp_challenges, 75);
        assert_eq!(report.provider_interaction.client_query_challenges, 4_193);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 17_372);
        assert_eq!(
            report.provider_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert!(report.native_challenges_shared);
        assert!(report.postproof_batching_challenge_identical);
        assert!(report.plan_reserved_tag_is_zero);
        assert!(report.codec_mutations_rejected);
        assert!(report.arithmetic_payload_mutation_rejected);
        assert!(report.joint_tag_mutation_rejected);
        assert!(report.role_separated_compact_verifier_checked);
        assert_eq!(report.subfield_correlations, 24);
        assert_eq!(report.full_correlations, 305);
        assert_eq!(report.response_spill, C61PersistedMmcsMetrics::default());
        assert_eq!(report.plan_spill, C61PersistedMmcsMetrics::default());
    }

    #[test]
    fn exact_terminal_fold_and_compiler_frame_reject_mutations() {
        let fixture = c61_sparse_compiler_physical_fixture().unwrap();
        fixture.terminal_binding.validate().unwrap();
        let (_, physical_values) = c61_exact_plan_fold_physical_openings(&fixture, 14).unwrap();
        let physical_values: [Fp2; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS] =
            physical_values.try_into().unwrap();
        fixture
            .terminal_binding
            .validate_physical_plan_fold_values(fixture.packed.base_domain_log2(), &physical_values)
            .unwrap();
        let mut changed_physical = physical_values;
        changed_physical[0] += Fp2::ONE;
        assert!(fixture
            .terminal_binding
            .validate_physical_plan_fold_values(
                fixture.packed.base_domain_log2(),
                &changed_physical
            )
            .is_err());

        let mut changed_fold = fixture.terminal_binding.clone();
        changed_fold.plan_folds[0] += Fp2::ONE;
        changed_fold.digest = changed_fold.recompute_digest();
        assert!(changed_fold.validate().is_err());

        let proof = C61ProductionCompilerChainProof {
            terminal_binding_digest: fixture.terminal_binding.digest,
            plan_folds: fixture.terminal_binding.plan_folds,
            physical_plan_fold_values: [Fp2::new(Fp::new(7), Fp::new(11)); 4],
            arithmetic_payload: vec![0xA5; 97],
            shared_payload: vec![0x5A; 193],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded.len(), 180 + 97 + 193);
        assert_eq!(C61ProductionCompilerChainProof::decode(&encoded).unwrap(), proof);
        let joint =
            C61ProductionJointCompilerChainProof::new(proof.clone(), [0xC3; 32], [0xC4; 32])
                .unwrap();
        let joint_encoded = joint.encode().unwrap();
        assert_eq!(joint_encoded.len(), encoded.len());
        assert_eq!(
            C61ProductionJointCompilerChainProof::decode(&joint_encoded, [0xC3; 32], [0xC4; 32],)
                .unwrap(),
            joint,
        );
        assert!(C61ProductionCompilerChainProof::decode(&joint_encoded).is_err());
        let mut changed_joint = joint_encoded;
        changed_joint[8] ^= 1;
        assert!(C61ProductionJointCompilerChainProof::decode(
            &changed_joint,
            [0xC3; 32],
            [0xC4; 32],
        )
        .is_err());
        assert!(C61ProductionJointCompilerChainProof::new(proof.clone(), [0; 32], [1; 32]).is_err());
        for index in [0, 12, 51, encoded.len() / 2, encoded.len() - 1] {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(C61ProductionCompilerChainProof::decode(&changed).is_err());
        }
        assert!(C61ProductionCompilerChainProof::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(C61ProductionCompilerChainProof::decode(&trailing).is_err());
    }

    #[test]
    fn production_public_argument_assembles_six_typed_artifacts_and_one_rsc4_frame() {
        let statement_digest = [0x61; 32];
        let committed = |marker| C61ProductionCommittedChainProof { payload: vec![marker; 17] };
        let compiler = |marker| C61ProductionCompilerChainProof {
            terminal_binding_digest: [marker; 32],
            plan_folds: [Fp2::ZERO; 2],
            physical_plan_fold_values: [Fp2::ZERO; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS],
            arithmetic_payload: vec![marker; 19],
            shared_payload: vec![marker.wrapping_add(1); 23],
        };
        let chains = [
            C61ProductionNativeChainArtifact::committed(
                C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
                committed(1),
            )
            .unwrap(),
            C61ProductionNativeChainArtifact::committed(
                C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
                committed(2),
            )
            .unwrap(),
            C61ProductionNativeChainArtifact::committed(
                C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 0 },
                committed(3),
            )
            .unwrap(),
            C61ProductionNativeChainArtifact::committed(
                C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
                committed(4),
            )
            .unwrap(),
            C61ProductionNativeChainArtifact::compiler(
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                compiler(5),
            )
            .unwrap(),
            C61ProductionNativeChainArtifact::compiler(
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 },
                compiler(6),
            )
            .unwrap(),
        ];
        let arithmetic = C61ArithmeticFrame {
            statement_digest,
            challenge_digest: [0x62; 32],
            adjoint_root: [0x63; 32],
            terminal_claims: [Fp2::ZERO; 64],
            runtime_evaluations: [Fp2::ZERO; 2],
            source_boundary: Fp2::ZERO,
        };
        let assembly =
            assemble_c61_production_public_argument(statement_digest, chains.clone(), arithmetic)
                .unwrap();
        assert_eq!(
            assembly.encoded().len(),
            C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
                + C61_ARITHMETIC_FRAME_BYTES
                + assembly.native_payload_bytes().into_iter().sum::<usize>()
        );
        assert_eq!(C61PublicArgument::decode(assembly.encoded()).unwrap(), *assembly.argument());
        let mut wrong_order = chains.clone();
        wrong_order.swap(0, 1);
        assert!(assemble_c61_production_public_argument(
            statement_digest,
            wrong_order,
            C61ArithmeticFrame::decode(assembly.argument().arithmetic()).unwrap(),
        )
        .is_err());
        let mut wrong_frame = C61ArithmeticFrame::decode(assembly.argument().arithmetic()).unwrap();
        wrong_frame.statement_digest[0] ^= 1;
        assert!(assemble_c61_production_public_argument(statement_digest, chains, wrong_frame,)
            .is_err());
    }

    #[test]
    fn joint_public_argument_assembles_only_profile_assigned_c6pa2_children() {
        let statement_digest = [0x71; 32];
        let topology = volta_proto::c6_residual::build_c6_residual_direct_fused_scaled_fixture()
            .unwrap()
            .operation_plan()
            .topology();
        let profile = C6CanonicalTargetProfile {
            inference_profile_digest: [0x72; 32],
            topology_digest: topology.topology_digest,
            source_schedule_digest: topology.source_schedule_digest,
            cohorts: vec![
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 7,
                    chain_slot: C61NativeComponent::Model as u16,
                    polynomial_log2: 12,
                    claim_layout_digest: [0x73; 32],
                    canonical_nodes: vec![topology.canonical_node_count - 2],
                },
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 9,
                    chain_slot: C61NativeComponent::Embedding as u16,
                    polynomial_log2: 11,
                    claim_layout_digest: [0x74; 32],
                    canonical_nodes: vec![topology.canonical_node_count - 1],
                },
            ],
        };
        let primary = |marker| C61ProductionCommittedChainProof { payload: vec![marker; 17] };
        let secondary = |marker, tail_role| C61ProductionJointCommittedChainProof {
            payload: vec![marker; 17],
            tail_role,
        };
        let compiler = |marker| {
            C61ProductionJointCompilerChainProof::new(
                C61ProductionCompilerChainProof {
                    terminal_binding_digest: [marker; 32],
                    plan_folds: [Fp2::ZERO; 2],
                    physical_plan_fold_values: [Fp2::ZERO; C61_EXACT_PLAN_FOLD_PHYSICAL_OPENINGS],
                    arithmetic_payload: vec![marker; 19],
                    shared_payload: vec![marker.wrapping_add(1); 23],
                },
                [0x75; 32],
                [0x76; 32],
            )
            .unwrap()
        };
        let chains = [
            C61ProductionJointNativeChainArtifact::committed_primary(
                C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
                primary(1),
            )
            .unwrap(),
            C61ProductionJointNativeChainArtifact::committed_secondary(
                C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
                secondary(2, C61JointNativeTailRole::Correction),
            )
            .unwrap(),
            C61ProductionJointNativeChainArtifact::committed_primary(
                C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 0 },
                primary(3),
            )
            .unwrap(),
            C61ProductionJointNativeChainArtifact::committed_secondary(
                C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
                secondary(4, C61JointNativeTailRole::ZeroOpenTag),
            )
            .unwrap(),
            C61ProductionJointNativeChainArtifact::compiler(
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                compiler(5),
            )
            .unwrap(),
            C61ProductionJointNativeChainArtifact::compiler(
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 },
                compiler(6),
            )
            .unwrap(),
        ];
        let arithmetic = C61ArithmeticFrame {
            statement_digest,
            challenge_digest: [0x77; 32],
            adjoint_root: [0x78; 32],
            terminal_claims: [Fp2::ZERO; 64],
            runtime_evaluations: [Fp2::ZERO; 2],
            source_boundary: Fp2::ZERO,
        };
        let assembly = assemble_c61_production_joint_public_argument(
            statement_digest,
            &profile,
            chains.clone(),
            arithmetic,
        )
        .unwrap();
        assert_eq!(
            assembly.encoded().len(),
            C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
                + C61_ARITHMETIC_FRAME_BYTES
                + assembly.native_payload_bytes().into_iter().sum::<usize>()
        );
        assert_eq!(
            C61JointPublicArgument::decode(assembly.encoded()).unwrap(),
            *assembly.argument()
        );

        let mut wrong_role = chains;
        wrong_role[1] = C61ProductionJointNativeChainArtifact::committed_secondary(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            secondary(2, C61JointNativeTailRole::ZeroOpenTag),
        )
        .unwrap();
        assert!(assemble_c61_production_joint_public_argument(
            statement_digest,
            &profile,
            wrong_role,
            C61ArithmeticFrame::decode(assembly.argument().arithmetic()).unwrap(),
        )
        .is_err());
        assert!(C61ProductionJointNativeChainArtifact::committed_primary(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            primary(9),
        )
        .is_err());
    }

    #[test]
    fn persisted_shared_flow_is_byte_identical_to_resident_reference() {
        let resident = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(14).unwrap();
        let spill_root = std::env::temp_dir().join(format!(
            "volta-c61-shared-spill-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let persisted =
            run_c61_authenticated_whir_p3_shared_multi_oracle_persisted_diagnostic(14, &spill_root)
                .unwrap();
        assert!(persisted.persisted_executor);
        assert!(!persisted.monolithic_host_baseline);
        assert!(!persisted.gpu_performance_credit);
        assert_eq!(persisted.strict_payload_blake3, resident.strict_payload_blake3);
        assert_eq!(persisted.strict_payload_bytes, resident.strict_payload_bytes);
        assert_eq!(persisted.arithmetic_payload_bytes, resident.arithmetic_payload_bytes);
        assert_eq!(persisted.total_provider_payload_bytes, resident.total_provider_payload_bytes);
        assert_eq!(persisted.provider_interaction, resident.provider_interaction);
        assert_eq!(persisted.verifier_interaction, resident.verifier_interaction);
        assert_eq!(persisted.subfield_correlations, resident.subfield_correlations);
        assert_eq!(persisted.full_correlations, resident.full_correlations);
        for metrics in [persisted.response_spill, persisted.plan_spill] {
            assert!(metrics.spill_files > 1);
            assert!(metrics.logical_spill_bytes > 0);
            assert!(metrics.host_bytes_written >= metrics.logical_spill_bytes);
            assert!(metrics.host_bytes_read > 0);
            assert!(metrics.host_bytes_read < metrics.logical_spill_bytes);
            assert_eq!(metrics.fsync_calls, metrics.spill_files);
        }
        std::fs::remove_dir_all(spill_root).unwrap();
    }

    #[test]
    fn production_d28_d27_censuses_monolithic_memory_before_allocation() {
        let census = c61_production_monolithic_memory_census().unwrap();
        assert_eq!(census.response_num_variables, 28);
        assert_eq!(census.plan_num_variables, 27);
        assert_eq!(census.response_message_bytes, 2_147_483_648);
        assert_eq!(census.response_encoded_bytes, 4_294_967_296);
        assert_eq!(census.response_merkle_bytes, 17_179_869_152);
        assert_eq!(census.response_retained_lower_bound_bytes, 23_622_320_096);
        assert_eq!(census.plan_message_bytes, 1_073_741_824);
        assert_eq!(census.plan_encoded_bytes, 2_147_483_648);
        assert_eq!(census.plan_merkle_bytes, 8_589_934_560);
        assert_eq!(census.plan_retained_lower_bound_bytes, 11_811_160_032);
        assert_eq!(census.concurrent_retained_lower_bound_bytes, 35_433_480_128);
        assert_eq!(census.coefficient_witness_cap_bytes, 2_293_198_848);
        assert_eq!(census.retained_minus_component_cap_bytes, 33_140_281_280);

        let error = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(28)
            .expect_err("D28 must reject before materializing the scaled fixture or witness");
        assert!(error.contains("persisted/recomputable or GPU-resident executor"));
        assert!(error.contains("35433480128 B"));
        assert!(!error.contains("provider-state gate"));
    }

    #[test]
    fn production_monolithic_entry_requires_owner_resources_and_real_pcg() {
        use volta_proto::c6_residual::*;

        let direct = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let topology = direct.operation_plan().topology();
        let source_manifest = C6TraceSourceManifest::new(
            topology.source_count,
            topology.source_schedule_digest,
            direct.manifest().product_mask_sources().to_vec(),
        )
        .unwrap();
        let terminal_metadata = C6OperationPlanTerminalMetadata::from_installed(
            direct.operation_plan(),
            &source_manifest,
        )
        .unwrap();
        let leaf_point = [Fp2::ZERO; 7];
        let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
        let invoke = |admission| {
            run_c61_authenticated_whir_p3_production_monolithic_baseline(
                direct.operation_plan(),
                terminal_metadata.clone(),
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                [&leaf_point, &leaf_point],
                [&[Fp2::ZERO; 2], &[Fp2::ZERO; 2]],
                [Fp2::ZERO; 64],
                Fp2::new(Fp::new(191), Fp::new(17)),
                [0xC1; 32],
                admission,
                CorrelationStream::new([0xD3; 32]),
                VerifierCtx::new([0xD3; 32], delta),
                [0xC2; 32],
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 },
            )
            .unwrap_err()
        };
        let resource_error = invoke(C61ProductionMonolithicResourceAdmission {
            available_host_bytes: 11 * 1024 * 1024 * 1024,
            gpu_total_bytes: 0,
            a100_present: false,
            allow_host_monolithic_baseline: false,
        });
        assert!(resource_error.contains("baseline admission failed"));
        let pcg_error = invoke(C61ProductionMonolithicResourceAdmission {
            available_host_bytes: C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES,
            gpu_total_bytes: 80 * 1024 * 1024 * 1024,
            a100_present: true,
            allow_host_monolithic_baseline: true,
        });
        assert!(pcg_error.contains("forbids mock PCG state"));

        let persisted_invoke = |admission| {
            run_c61_authenticated_whir_p3_production_persisted(
                direct.operation_plan(),
                terminal_metadata.clone(),
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                [&leaf_point, &leaf_point],
                [&[Fp2::ZERO; 2], &[Fp2::ZERO; 2]],
                [Fp2::ZERO; 64],
                Fp2::new(Fp::new(191), Fp::new(17)),
                [0xC1; 32],
                Path::new("/tmp/volta-c61-persisted-admission-unused"),
                admission,
                CorrelationStream::new([0xD3; 32]),
                VerifierCtx::new([0xD3; 32], delta),
                [0xC2; 32],
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 },
            )
            .unwrap_err()
        };
        let resource_error = persisted_invoke(C61ProductionPersistedResourceAdmission {
            available_host_bytes: 11 * 1024 * 1024 * 1024,
            available_spill_bytes: 64 * 1024 * 1024 * 1024,
            gpu_total_bytes: 0,
            a100_present: false,
            allow_persisted_executor: false,
        });
        assert!(resource_error.contains("persisted A100 admission failed"));
        let pcg_error = persisted_invoke(C61ProductionPersistedResourceAdmission {
            available_host_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
            available_spill_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
            gpu_total_bytes: 80 * 1024 * 1024 * 1024,
            a100_present: true,
            allow_persisted_executor: true,
        });
        assert!(pcg_error.contains("persisted runner forbids mock PCG state"));
    }

    #[test]
    fn production_committed_chain_binds_profile_root_and_rejects_before_io() {
        let model_parameters = c61_authenticated_p3_parameter_digest(28).unwrap();
        let embedding_parameters = c61_authenticated_p3_parameter_digest(27).unwrap();
        assert_ne!(model_parameters, embedding_parameters);
        assert!(c61_authenticated_p3_parameter_digest(26).is_err());

        let claims = (0..96)
            .map(|index| crate::batch::BlockClaim {
                offset: index * 2,
                point: vec![Fp2::new(Fp::new(index as u64 + 2), Fp::new(3))],
            })
            .collect::<Vec<_>>();
        let root = [0x51; 32];
        let public = build_c61_production_model_embedding_public_statement(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
            C61NativeCommitmentDescriptor {
                parameter_digest: model_parameters,
                commitment_root: root,
                polynomial_domain_log2: 28,
            },
            &claims,
        )
        .unwrap();
        c61_validate_committed_chain_root(&public, &C61Commitment::new(vec![root])).unwrap();
        assert!(c61_validate_committed_chain_root(&public, &C61Commitment::new(vec![[0x52; 32]]))
            .is_err());

        let spill_root = std::env::temp_dir().join(format!(
            "volta-c61-committed-admission-unused-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut backend = Backend::cpu();
        let mut correlations = CorrelationStream::new([0x91; 32]);
        let error =
            prove_c61_authenticated_whir_p3_production_committed_chain_persisted_cuda_in_attempt(
                Vec::new(),
                &[],
                Vec::new(),
                model_parameters,
                &spill_root,
                C61ProductionPersistedResourceAdmission {
                    available_host_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
                    available_spill_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
                    gpu_total_bytes: 80 * 1024 * 1024 * 1024,
                    a100_present: true,
                    allow_persisted_executor: true,
                },
                &mut backend,
                &mut correlations,
                [0x92; 32],
                C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 31, range_start: 130_000 },
            )
            .unwrap_err();
        assert!(error.contains("persisted/CUDA admission failed"));
        assert!(!spill_root.exists());
    }

    #[test]
    fn four_committed_chain_driver_rejects_before_loading_any_coefficient_owner() {
        let mut backend = Backend::cpu();
        let mut correlations =
            [CorrelationStream::new([0xA1; 32]), CorrelationStream::new([0xA2; 32])];
        let claims: [&[crate::batch::BlockClaim]; 2] = [&[], &[]];
        let loaded = std::cell::Cell::new(false);
        let error = prove_c61_authenticated_whir_p3_production_four_committed_chains_in_attempt(
            |_, _| {
                loaded.set(true);
                Ok(Vec::new())
            },
            [1; 32],
            [2; 32],
            claims,
            claims,
            [Vec::new(), Vec::new()],
            [Vec::new(), Vec::new()],
            Path::new("/definitely/not/a/c61/attempt"),
            C61ProductionPersistedResourceAdmission {
                available_host_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
                available_spill_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
                gpu_total_bytes: 80 * 1024 * 1024 * 1024,
                a100_present: true,
                allow_persisted_executor: true,
            },
            &mut backend,
            &mut correlations,
            [[0xB1; 32], [0xB2; 32], [0xB3; 32], [0xB4; 32]],
            [
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 41, range_start: 140_000 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 42, range_start: 141_000 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 43, range_start: 142_000 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 44, range_start: 143_000 },
            ],
        )
        .unwrap_err();
        assert!(error.contains("preflight failed before source load"));
        assert!(!loaded.get());

        let joint_error =
            prepare_c61_authenticated_whir_p3_production_joint_four_chains_in_attempt(
                |_, _| {
                    loaded.set(true);
                    Ok(Vec::new())
                },
                [1; 32],
                [2; 32],
                claims,
                claims,
                [Vec::new(), Vec::new()],
                [Vec::new(), Vec::new()],
                &C6CanonicalTargetProfile {
                    inference_profile_digest: [3; 32],
                    topology_digest: [4; 32],
                    source_schedule_digest: [5; 32],
                    cohorts: Vec::new(),
                },
                Transcript::new([0xB5; 32]),
                Path::new("/definitely/not/a/c61/attempt"),
                C61ProductionPersistedResourceAdmission {
                    available_host_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
                    available_spill_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
                    gpu_total_bytes: 80 * 1024 * 1024 * 1024,
                    a100_present: true,
                    allow_persisted_executor: true,
                },
                &mut backend,
                &mut correlations,
                [[0xB1; 32], [0xB2; 32], [0xB3; 32], [0xB4; 32]],
                [
                    C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 41, range_start: 140_000 },
                    C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 42, range_start: 141_000 },
                    C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 43, range_start: 142_000 },
                    C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 44, range_start: 143_000 },
                ],
            )
            .err()
            .expect("joint four-chain preflight must reject CPU/mock state");
        assert!(joint_error.contains("preflight failed before source load"));
        assert!(!loaded.get());
    }

    #[test]
    fn fork_source_guard_has_no_eval_field_or_clear_claim_replay() {
        let proof = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/proof.rs");
        let prover = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs");
        let verifier = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/verifier/mod.rs");
        let sumcheck = include_str!("../../third_party/p3-sumcheck-c61/src/zk/prover/residual.rs");
        let prover_data = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/data.rs");
        let adapter = include_str!("c61_authenticated_whir_p3.rs");
        let production_adapter = adapter.split("#[cfg(test)]").next().unwrap();
        let sparse_verifier = production_adapter
            .split("fn verify_c61_sparse_compiler_relation_phase(")
            .nth(1)
            .unwrap()
            .split("fn verify_c61_authenticated_whir_p3_compiler_chain_compact(")
            .next()
            .unwrap();
        assert!(!proof.contains("pub evals:"));
        assert_eq!(prover.matches("into_zk_sumcheck_claimless(").count(), 2);
        assert!(prover.contains("claims.len() <= 128"));
        assert!(!prover.contains("claims[0]"));
        assert!(verifier.contains("verify_affine_claim"));
        assert!(verifier.contains("points.len() > 128"));
        assert!(!verifier.contains("points[0]"));
        assert!(sumcheck.contains("into_zk_sumcheck_claimless"));
        assert!(sumcheck.contains("aux_claim,\n            false,"));
        assert!(prover_data.contains("pub message: Poly<F>"));
        assert!(prover_data.contains("pub merkle: MT::ProverData<DenseMatrix<F>>"));
        assert_eq!(
            production_adapter.matches("C61InteractiveChallenger::new_claimless(").count(),
            8
        );
        assert_eq!(production_adapter.matches(".observe_public_point(").count(), 5);
        assert_eq!(production_adapter.matches(".observe_public_points(").count(), 11);
        assert_eq!(production_adapter.matches(".ensure_public_statement_bound()").count(), 5);
        assert_eq!(production_adapter.matches("challenger.finish(").count(), 9);
        assert_eq!(production_adapter.matches("c61_shared_round_pair(").count(), 3);
        assert!(!sparse_verifier.contains(".direct"));
        assert!(!sparse_verifier.contains(".packed"));
        assert!(!sparse_verifier.contains("extraction"));
        assert!(!sparse_verifier.contains("runtime"));
        assert_eq!(production_adapter.matches(".sample_postproof_fp2()").count(), 3);
        assert!(production_adapter
            .contains("C61_SHARED_MULTI_ORACLE_MAGIC: [u8; 8] = *b\"C6SMO1\\0\\0\""));
        assert!(!production_adapter.contains("proof.evals"));
        let verifier_adapter = production_adapter
            .split("fn verify_diagnostic(")
            .nth(1)
            .unwrap()
            .split("/// Run one reference-only")
            .next()
            .unwrap();
        assert!(!verifier_adapter.contains("artifact.provider_"));
        assert!(!verifier_adapter.contains("artifact.point"));
        assert!(!verifier_adapter.contains("artifact.target_key"));

        let simulator_adapter = production_adapter
            .split("fn simulate_view_diagnostic(")
            .nth(1)
            .unwrap()
            .split("fn verify_diagnostic(")
            .next()
            .unwrap();
        assert!(simulator_adapter.contains("target_key: VerifierKey"));
        assert!(!simulator_adapter.contains("target_tag"));
        assert!(!simulator_adapter.contains("ProverAuthed"));
        assert!(!simulator_adapter.contains("CorrelationStream"));
        assert!(simulator_adapter.contains("simulate_c61_authenticated_whir_base_view("));

        let mut transcript = Transcript::new([0x31; 32]);
        let challenger = C61InteractiveChallenger::new_claimless(&mut transcript, 4);
        assert!(challenger.ensure_public_statement_bound().is_err());
    }

    #[test]
    fn designated_view_simulator_accepts_without_real_target_or_provider_state() {
        let report = run_c61_authenticated_whir_p3_privacy_diagnostic(14).unwrap();
        assert_eq!(report.simulator_ledger, report.verifier_ledger);
        assert_eq!(report.simulator_transcript_bytes, report.verifier_transcript_bytes);
        assert_eq!(report.simulator_interaction, report.verifier_interaction);
        assert_eq!(
            report.simulator_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert!(
            report.strict_payload_bytes
                <= c61_authenticated_structural_budget_inner(14, false).unwrap().strict_chain_bytes,
        );
        assert!(!report.received_real_target_plaintext);
        assert!(!report.received_provider_target_tag);
        assert!(!report.received_provider_correlation_state);
        assert_eq!(report.verifier_full_key_draws, 1);
    }

    #[test]
    fn private_entropy_driver_replays_to_frontier_without_seed_or_checkpoint_leak() {
        let report = run_c61_private_entropy_driver_diagnostic(14).unwrap();
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(report.strict_payload_bytes, 378_496);
        assert_eq!(report.provider_interaction.provider_messages, 26);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 52_608);
        assert_eq!(report.provider_interaction.provider_payload_bytes, 378_480);
        assert_eq!(report.provider_interaction.client_fp_challenges, 52);
        assert_eq!(report.provider_interaction.client_query_challenges, 2_536);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 10_560);
        assert_eq!(report.challenge_count, 2_588);
        assert_eq!(report.checkpoint_frontier, 1_294);
        assert_eq!(report.replayed_challenges, report.checkpoint_frontier);
        assert_eq!(report.checkpoint_bytes, 73_360);
        assert!(report.resumed_artifact_identical);
        assert!(report.resumed_tape_identical);
        assert!(report.mutated_checkpoint_rejected);
        assert!(report.checkpoint_codec_mutations_rejected);
        assert_eq!(report.durable_journal_bytes, 208_204);
        assert_eq!(report.durable_replayed_challenges, report.checkpoint_frontier);
        assert_eq!(report.durable_replayed_mask_events, 1);
        assert_eq!(report.durable_mask_frontier, 1);
        assert_eq!(report.durable_record_count, 2_590);
        assert!(report.durable_resume_artifact_identical);
        assert!(report.durable_resume_tape_identical);
        assert!(report.durable_wrong_binding_rejected);
        assert!(report.durable_torn_journal_rejected);
        assert!(report.durable_corrupt_journal_rejected);
        assert!(!report.provider_received_verifier_seed);
        assert!(!report.provider_received_checkpoint);
        assert_eq!(report.full_correlations, 1);

        let driver_source = include_str!("c61_interactive_driver.rs");
        let endpoint = driver_source
            .split("struct C61ProviderEndpoint")
            .nth(1)
            .unwrap()
            .split("/// Seedless exact-move endpoint")
            .next()
            .unwrap();
        assert!(endpoint.contains("SyncSender<C61BrokerRequest>"));
        assert!(!endpoint.contains("verifier_seed"));
        assert!(!endpoint.contains("checkpoint"));
        assert!(!endpoint.contains("Transcript"));

        let provider = include_str!("c61_authenticated_whir_p3.rs")
            .split("fn prove_private_entropy_provider_diagnostic(")
            .nth(1)
            .unwrap()
            .split("fn prove_private_entropy_diagnostic(")
            .next()
            .unwrap();
        assert!(provider.contains("C61PrivateEntropyProverChallenger"));
        assert!(!provider.contains("verifier_seed"));
        assert!(!provider.contains("checkpoint"));
    }

    #[test]
    fn production_hiding_rng_is_provider_private_and_not_reproducible() {
        let source = include_str!("c61_authenticated_whir_p3.rs");
        let helper = source
            .split("fn c61_production_private_zk_rng()")
            .nth(1)
            .unwrap()
            .split("const C61_AUTHENTICATED_P3_MAGIC")
            .next()
            .unwrap();
        assert!(helper.contains("OsRng"));
        assert!(helper.contains("try_fill_bytes"));
        assert!(!helper.contains("seed_from_u64"));

        let native = source
            .split(
                "pub fn prepare_c61_authenticated_whir_p3_production_committed_chain_persisted_cuda_in_attempt(",
            )
            .nth(1)
            .unwrap()
            .split("pub fn verify_c61_authenticated_whir_p3_production_committed_chain_in_attempt(")
            .next()
            .unwrap();
        assert!(native.contains("c61_production_private_zk_rng()?"));
        assert!(!native.contains("seed_from_u64"));

        let compiler = source
            .split("fn run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_transcript<")
            .nth(1)
            .unwrap()
            .split("pub fn run_c61_private_entropy_driver_diagnostic(")
            .next()
            .unwrap();
        assert!(compiler.contains("if fixture.production"));
        assert_eq!(compiler.matches("c61_production_private_zk_rng()?").count(), 2);
    }

    #[test]
    fn production_private_entropy_api_exposes_only_typed_provider_inputs() {
        let source = include_str!("c61_authenticated_whir_p3.rs");
        let signature = source
            .split(
                "fn prepare_c61_authenticated_whir_p3_production_committed_chain_private_entropy(",
            )
            .nth(1)
            .unwrap()
            .split(") -> Result<C61ProductionCommittedChainProverBody, String>")
            .next()
            .unwrap();
        assert!(signature.contains("C61ProviderSessionBinding"));
        assert!(signature.contains("C61PrivateEntropyEndpoint"));
        assert!(!signature.contains("verifier_seed"));
        assert!(!signature.contains("checkpoint"));
        assert!(!signature.contains("VerifierCtx"));
        assert!(!signature.contains("VerifierKey"));
        assert!(!signature.contains("Delta"));
        assert!(!signature.contains("Transcript"));

        let compiler_signature = source
            .split(
                "fn run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(",
            )
            .nth(1)
            .unwrap()
            .split(") -> Result<C61ProductionCompilerChainExecution, String>")
            .next()
            .unwrap();
        assert!(compiler_signature.contains("C61ProviderSessionBinding"));
        assert!(compiler_signature.contains("C61PrivateEntropyEndpoint"));
        assert!(!compiler_signature.contains("verifier_seed"));
        assert!(!compiler_signature.contains("checkpoint"));
        assert!(!compiler_signature.contains("VerifierCtx"));
        assert!(!compiler_signature.contains("VerifierKey"));
        assert!(!compiler_signature.contains("Delta"));
        assert!(!compiler_signature.contains("Transcript"));

        let four_chain_signature = source
            .split(
                "fn prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt(",
            )
            .nth(1)
            .unwrap()
            .split(
                ") -> Result<C61ProductionJointCommittedFourChainPrepared, String>",
            )
            .next()
            .unwrap();
        assert!(four_chain_signature.contains("[C61ProviderSessionBinding; 4]"));
        assert!(four_chain_signature.contains("[C61PrivateEntropyEndpoint; 4]"));
        assert!(four_chain_signature.contains("C61ProviderJointSessionBinding"));
        assert!(four_chain_signature.contains("joint_endpoint: C61PrivateEntropyEndpoint"));
        assert!(!four_chain_signature.contains("verifier_seed"));
        assert!(!four_chain_signature.contains("checkpoint"));
        assert!(!four_chain_signature.contains("VerifierCtx"));
        assert!(!four_chain_signature.contains("VerifierKey"));
        assert!(!four_chain_signature.contains("Delta"));
        assert!(!four_chain_signature.contains("Transcript"));

        let driver = include_str!("c61_interactive_driver.rs");
        let endpoint = driver
            .split("struct C61PrivateEntropyEndpoint")
            .nth(1)
            .unwrap()
            .split("impl TranscriptChallengeChannel")
            .next()
            .unwrap();
        assert!(endpoint.contains("C61ProviderEndpoint"));
        assert!(!endpoint.contains("verifier_seed"));
        assert!(!endpoint.contains("checkpoint"));
        assert!(!endpoint.contains("VerifierCtx"));
        assert!(!endpoint.contains("VerifierKey"));
        assert!(!endpoint.contains("Delta"));
        assert!(!endpoint.contains("Transcript"));
    }

    #[test]
    #[ignore = "C6ICT2 D14/D13 release differential; run on the admitted high-memory host"]
    fn compiler_private_entropy_scaled_provider_and_disk_replay_match_exactly() {
        let response_num_variables = 14;
        let verifier_seed = [0xC2; 32];
        let pcg_seed = [0xD3; 32];
        let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
        let context_digest = [0xA7; 32];
        let fixture = c61_sparse_compiler_physical_fixture().unwrap();
        let verifier_fixture = fixture.verifier_fixture().unwrap();
        let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
        let mask_range =
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 };
        let (endpoint, broker_handle) =
            crate::c61_interactive_driver::spawn_c61_private_entropy_transcript_broker(
                verifier_seed,
                response_num_variables,
                context_digest,
            )
            .unwrap();
        let mut correlations = CorrelationStream::new(pcg_seed);
        let execution = run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_transcript(
            &fixture,
            response_num_variables,
            &mut correlations,
            None,
            None,
            Transcript::new_interactive(Box::new(endpoint)),
            id,
            mask_range,
            0,
            0,
            c61_reference_mmcs(),
            c61_reference_mmcs(),
        )
        .unwrap();
        let broker = broker_handle.finish_output().unwrap();
        assert!(broker.tape.challenge_count() > 100);

        let ((response_commitment, _), (plan_commitment, _), _) =
            decode_c61_shared_multi_oracle_artifact(
                &C61SharedMultiOracleArtifact { payload: execution.proof.shared_payload.clone() },
                response_num_variables,
                response_num_variables - 1,
            )
            .unwrap();
        let compact_fixture = C61SparseCompilerVerifierFixture {
            operation_plan_digest: verifier_fixture.operation_plan_digest,
            topology: verifier_fixture.topology,
            terminal_metadata: verifier_fixture.terminal_metadata,
            relation_challenges: verifier_fixture.relation_challenges,
            output_beta: verifier_fixture.output_beta,
            base_domain_log2: verifier_fixture.base_domain_log2,
            response_digest: response_commitment.roots()[0],
            plan_digest: plan_commitment.roots()[0],
            terminal_binding: verifier_fixture.terminal_binding.clone(),
        };
        let replay = C61PrivateEntropyTranscriptReplayEndpoint::new(
            broker.tape.clone(),
            response_num_variables,
            context_digest,
        )
        .unwrap();
        let mut context = VerifierCtx::new(pcg_seed, delta);
        let verification = verify_c61_authenticated_whir_p3_compiler_chain_compact_with_transcript(
            &compact_fixture,
            response_commitment.roots()[0],
            plan_commitment.roots()[0],
            response_num_variables,
            &execution.proof,
            &mut context,
            Transcript::new_interactive(Box::new(replay)),
            id,
            mask_range,
            [0; 32],
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            execution.report.provider_transcript_bytes,
            verification.verifier_transcript_bytes
        );
        assert_eq!(execution.report.provider_interaction, verification.verifier_interaction);
    }

    fn mutation_fixture() -> (
        C61AuthenticatedP3Fixture,
        [u8; 32],
        [u8; 32],
        Fp2,
        C61NativeChainId,
        C61AuthenticatedWhirMaskRange,
    ) {
        let num_variables = 14;
        let witness = Poly::new(
            (0..(1usize << num_variables))
                .map(|index| Goldilocks::from_u64((index as u64) * 13 + 7))
                .collect(),
        );
        let point = Point::new(
            (0..num_variables).map(|index| C61P3Fp2::from_u64(index as u64 * 23 + 11)).collect(),
        );
        let verifier_seed = [0x72; 32];
        let pcg_seed = [0xB8; 32];
        let delta = Fp2::new(volta_field::Fp::new(P - 29), volta_field::Fp::new(991));
        let id = C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 };
        let mask_range =
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 9, range_start: 50_000 };
        let (fixture, _) = prove_diagnostic(
            witness,
            point,
            verifier_seed,
            0xC6_2002,
            pcg_seed,
            delta,
            Fp2::new(volta_field::Fp::new(47), volta_field::Fp::new(53)),
            id,
            mask_range,
        )
        .unwrap();
        (fixture, verifier_seed, pcg_seed, delta, id, mask_range)
    }

    #[test]
    fn target_key_transcript_point_and_base_mutations_fail_closed() {
        let (fixture, verifier_seed, pcg_seed, delta, id, mask_range) = mutation_fixture();
        let artifact = &fixture.artifact;
        let verifier_input = C61AuthenticatedP3VerifierInput {
            point: &fixture.point,
            target_key: fixture.target_key,
            verifier_seed,
            pcg_seed,
            delta,
            id,
            mask_range,
        };

        let (commitment, proof, base_proof) =
            decode_c61_authenticated_p3_artifact_inner(&artifact.payload, 14, false).unwrap();
        assert_eq!(
            encode_c61_authenticated_p3_artifact_inner(14, &commitment, &proof, base_proof, false,)
                .unwrap(),
            artifact.payload,
        );

        let mut bad_key = fixture.target_key;
        bad_key.k += Fp2::ONE;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { target_key: bad_key, ..verifier_input },
        )
        .is_err());

        let mut bad_base = artifact.clone();
        let (commitment, mut proof, base_proof) =
            decode_c61_authenticated_p3_artifact_inner(&bad_base.payload, 14, false).unwrap();
        proof.base_case.masked_claim += C61P3Fp2::ONE;
        bad_base.payload =
            encode_c61_authenticated_p3_artifact_inner(14, &commitment, &proof, base_proof, false)
                .unwrap();
        assert!(verify_diagnostic(&bad_base, verifier_input,).is_err());

        let mut bad_tag = artifact.clone();
        let last = bad_tag.payload.len() - 1;
        bad_tag.payload[last] ^= 1;
        assert!(verify_diagnostic(&bad_tag, verifier_input,).is_err());

        let mut coordinates = fixture.point.as_slice().to_vec();
        coordinates[0] += C61P3Fp2::ONE;
        let bad_point = Point::new(coordinates);
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { point: &bad_point, ..verifier_input },
        )
        .is_err());

        let mut wrong_seed = verifier_seed;
        wrong_seed[0] ^= 1;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { verifier_seed: wrong_seed, ..verifier_input },
        )
        .is_err());

        let mut wrong_range = mask_range;
        wrong_range.range_start += 3;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { mask_range: wrong_range, ..verifier_input },
        )
        .is_err());

        let mut bad_magic = artifact.payload.clone();
        bad_magic[0] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_magic, 14, false).is_err());

        let mut bad_version = artifact.payload.clone();
        bad_version[8] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_version, 14, false).is_err());

        let mut bad_dimension = artifact.payload.clone();
        bad_dimension[10] = 13;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_dimension, 14, false).is_err());

        let mut bad_reserved = artifact.payload.clone();
        bad_reserved[11] = 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_reserved, 14, false).is_err());

        let mut bad_body_len = artifact.payload.clone();
        bad_body_len[12] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_body_len, 14, false).is_err());

        let mut noncanonical_tag = artifact.payload.clone();
        let tag_offset = noncanonical_tag.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
        noncanonical_tag[tag_offset..tag_offset + 8].copy_from_slice(&P.to_le_bytes());
        assert!(decode_c61_authenticated_p3_artifact_inner(&noncanonical_tag, 14, false).is_err());

        let mut trailing = artifact.payload.clone();
        trailing.push(0);
        assert!(decode_c61_authenticated_p3_artifact_inner(&trailing, 14, false).is_err());
        assert!(decode_c61_authenticated_p3_artifact_inner(
            &artifact.payload[..artifact.payload.len() - 1],
            14,
            false,
        )
        .is_err());

        let config = c61_authenticated_config::<C61SizingChallenger>(14).unwrap();
        let batches = config.n_rounds() + 1;
        let sumcheck_rounds: usize =
            (0..batches).map(|batch| config.round_folding_factor(batch)).sum();
        let first_round = &config.round_parameters[0];
        let first_fold = config.round_folding_factor(0);
        let first_multiproof_count = C61_AUTHENTICATED_P3_HEADER_BYTES
            + C61_WHIRA1_DIGEST_BYTES
            + (batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES
            + batches * C61_WHIRA1_DIGEST_BYTES
            + 2 * C61_WHIRA1_DIGEST_BYTES
            + first_round.ood_samples * C61_WHIRA1_FP2_BYTES
            + first_round.num_queries * (1usize << first_fold) * C61_WHIRA1_FP_BYTES;
        let mut excessive_frontier = artifact.payload.clone();
        excessive_frontier[first_multiproof_count..first_multiproof_count + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_c61_authenticated_p3_artifact_inner(&excessive_frontier, 14, false).is_err());
    }

    #[test]
    fn joint_awp2_header_preserves_the_exact_tagless_whir_body() {
        let (fixture, _, _, _, _, _) = mutation_fixture();
        let tail_start =
            fixture.artifact.payload.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
        let ordinary_tagless = &fixture.artifact.payload[..tail_start];
        let joint_tagless = c61_joint_tagless_from_awp1(ordinary_tagless).unwrap();
        assert_eq!(joint_tagless.len(), ordinary_tagless.len());
        assert_eq!(joint_tagless[..8], C61_JOINT_AUTHENTICATED_P3_MAGIC);
        assert_eq!(
            u16::from_le_bytes(joint_tagless[8..10].try_into().unwrap()),
            C61_JOINT_AUTHENTICATED_P3_VERSION,
        );
        assert_eq!(joint_tagless[10..], ordinary_tagless[10..]);

        let mut joint_payload = joint_tagless.clone();
        joint_payload.extend_from_slice(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
        assert!(c61_validate_joint_payload_shape(
            &joint_payload,
            C61JointNativeTailRole::Correction,
        )
        .is_ok());
        assert!(c61_validate_joint_payload_shape(
            &joint_payload,
            C61JointNativeTailRole::ZeroOpenTag,
        )
        .is_ok());
        let ordinary_payload = c61_awp1_payload_from_joint(&joint_payload).unwrap();
        let (_, _, tail) =
            decode_c61_authenticated_p3_artifact_inner(&ordinary_payload, 14, false).unwrap();
        assert_eq!(tail.encode(), [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);

        let mut bad_magic = joint_payload.clone();
        bad_magic[0] ^= 1;
        assert!(c61_awp1_payload_from_joint(&bad_magic).is_err());
        let mut bad_version = joint_payload.clone();
        bad_version[8] ^= 1;
        assert!(c61_awp1_payload_from_joint(&bad_version).is_err());
        let mut bad_length = joint_payload;
        bad_length[12] ^= 1;
        assert!(c61_awp1_payload_from_joint(&bad_length).is_err());
        assert!(c61_joint_tagless_from_awp1(&joint_tagless).is_err());

        let mut nonzero_reserved = joint_tagless.clone();
        nonzero_reserved.extend_from_slice(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
        let last = nonzero_reserved.len() - 1;
        nonzero_reserved[last] = 1;
        assert!(c61_validate_joint_payload_shape(
            &nonzero_reserved,
            C61JointNativeTailRole::Reserved,
        )
        .is_err());
        let tail_start = nonzero_reserved.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
        nonzero_reserved[tail_start..tail_start + 8].copy_from_slice(&P.to_le_bytes());
        assert!(c61_validate_joint_payload_shape(
            &nonzero_reserved,
            C61JointNativeTailRole::Correction,
        )
        .is_err());

        let mut frame_bytes = [0u8; 32];
        frame_bytes[..8].copy_from_slice(&17u64.to_le_bytes());
        frame_bytes[8..16].copy_from_slice(&19u64.to_le_bytes());
        frame_bytes[16..24].copy_from_slice(&23u64.to_le_bytes());
        frame_bytes[24..].copy_from_slice(&29u64.to_le_bytes());
        let frame = C61JointNativeBridgeFrame::decode(&frame_bytes).unwrap();
        let (role0, tail0) = c61_joint_native_carrier_tail(frame, 0);
        let (role1, tail1) = c61_joint_native_carrier_tail(frame, 1);
        let (role2, tail2) = c61_joint_native_carrier_tail(frame, 2);
        assert_eq!(role0, C61JointNativeTailRole::Correction);
        assert_eq!(role1, C61JointNativeTailRole::ZeroOpenTag);
        assert_eq!(role2, C61JointNativeTailRole::Reserved);
        assert_eq!([tail0, tail1].concat(), frame_bytes);
        assert_eq!(tail2, [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES]);
    }

    #[test]
    fn joint_role_verifier_closes_without_secondary_target_keys() {
        let delta = Fp2::new(Fp::new(1_801), Fp::new(1_803));
        let pool = volta_pcg::expand_phase_a(
            [0xD8; 32],
            delta,
            0,
            2,
            volta_pcg::PhaseAParams::tiny_for_test(4),
        );
        let mut prover_correlations = CorrelationStream::from_pcg_pool(pool.prover);
        let mut verifier_context = VerifierCtx::from_pcg_pool(delta, pool.verifier);
        let ids = [
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
        ];
        let ranges = [
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 31, range_start: 70_000 },
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 31, range_start: 70_100 },
        ];
        let gamma =
            [Fp2::new(Fp::new(1_807), Fp::new(1_811)), Fp2::new(Fp::new(1_813), Fp::new(1_817))];
        let targets =
            [Fp2::new(Fp::new(1_819), Fp::new(1_821)), Fp2::new(Fp::new(1_823), Fp::new(1_827))];
        let zeta = Fp2::new(Fp::new(1_829), Fp::new(1_831));
        let weights = [Fp2::ONE, zeta];
        let mut prover_terms = Vec::new();
        let mut verifier_bodies = Vec::new();
        for index in 0..2 {
            let prepared = prepare_c61_authenticated_whir_mask(
                ids[index],
                ranges[index],
                &mut prover_correlations,
            )
            .unwrap();
            let masked_claim = Fp2::new(Fp::new(1_900 + index as u64), Fp::new(1_910));
            let shifted_masked_claim = prepared.shifted_masked_claim(masked_claim);
            let combined = masked_claim + gamma[index] * targets[index];
            prover_terms.push(C61JointNativeProverTerm {
                prepared,
                combined,
                shifted_masked_claim,
                gamma: gamma[index],
                affine: C61AuthenticatedWhirAffineClaim::identity(),
                cohort_weight: weights[index],
            });
            verifier_bodies.push(C61ProductionCommittedChainVerifierBody {
                id: ids[index],
                num_variables: 12 - index,
                claim_count: 1,
                tagless_payload_len: 0,
                tagless_payload: Vec::new(),
                tagless_digest: [0xD9 + index as u8; 32],
                claim_weights: vec![Fp2::ONE],
                aggregate_key: None,
                affine: C61AuthenticatedWhirAffineClaim::identity(),
                base_case: BaseCaseClaimlessClosure {
                    combined: c61_p3_fp2_from_volta(combined),
                    shifted_masked_claim: c61_p3_fp2_from_volta(shifted_masked_claim),
                    gamma: c61_p3_fp2_from_volta(gamma[index]),
                },
                mask_range: ranges[index],
                transcript: Transcript::new([0xDA + index as u8; 32]),
                verifier_interaction: C61WhirInteractionStats::default(),
            });
        }
        let corrected_plaintext = targets[0] + zeta * targets[1];
        let compiler_correction = Fp2::new(Fp::new(1_837), Fp::new(1_841));
        let compiler_base = ProverAuthed::new(
            corrected_plaintext - compiler_correction,
            Fp2::new(Fp::new(1_843), Fp::new(1_849)),
        );
        let compiler_base_key = VerifierKey::new(compiler_base.m + delta * compiler_base.x);
        let challenge = C61JointNativeChallenge {
            schedule_digest: [0xDB; 32],
            zeta,
            cohort_weights: weights.to_vec(),
        };
        let transcript = Transcript::new([0xDC; 32]);
        let frame = finish_c61_joint_native_bridge(
            prover_terms,
            compiler_base,
            compiler_correction,
            &mut Transcript::new([0xDC; 32]),
        )
        .unwrap();
        let fixed = C61ProductionJointNativeVerifierBodiesFixed {
            bodies: verifier_bodies,
            frame,
            joint_payload: Vec::new(),
            challenge: challenge.clone(),
            transcript,
        };
        let direct =
            volta_proto::c6_residual::build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let topology = direct.operation_plan().topology();
        let profile = C6CanonicalTargetProfile {
            inference_profile_digest: [0xDD; 32],
            topology_digest: topology.topology_digest,
            source_schedule_digest: topology.source_schedule_digest,
            cohorts: vec![
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 7,
                    chain_slot: C61NativeComponent::Model as u16,
                    polynomial_log2: 12,
                    claim_layout_digest: [0xDE; 32],
                    canonical_nodes: vec![topology.canonical_node_count - 2],
                },
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 9,
                    chain_slot: C61NativeComponent::Embedding as u16,
                    polynomial_log2: 11,
                    claim_layout_digest: [0xDF; 32],
                    canonical_nodes: vec![topology.canonical_node_count - 1],
                },
            ],
        };
        let compiled = volta_proto::c6_residual::C6CompiledNativeTargetFunctional::compile(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &profile,
            &[vec![Fp2::ONE], vec![Fp2::ONE]],
            &weights,
        )
        .unwrap();
        assert_eq!(
            verify_c61_joint_native_compiler_functional(
                &fixed,
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                &profile,
                challenge.schedule_digest,
                compiled.functional_digest(),
            )
            .unwrap()
            .functional_digest(),
            compiled.functional_digest(),
        );
        assert!(verify_c61_joint_native_compiler_functional(
            &fixed,
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &profile,
            [0; 32],
            compiled.functional_digest(),
        )
        .is_err());
        assert!(verify_c61_joint_native_compiler_functional(
            &fixed,
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &profile,
            challenge.schedule_digest,
            [0; 32],
        )
        .is_err());
        let nbr2_statement_digest = [0xE1; 32];
        assert_eq!(fixed.pending_correction(), compiler_correction);
        let pending = fixed
            .prepare_nbr2_link(
                compiler_base_key,
                compiler_correction,
                nbr2_statement_digest,
                &mut verifier_context,
            )
            .unwrap();
        assert_eq!(pending.transcript.ledger().get("c6_joint_native_corrections"), Some(&16));
        assert_eq!(pending.transcript.ledger().get("zero_open_tag"), None);
        let verified = pending
            .finish_after_nbr2_link(C6Nbr2VerifiedLink::for_test(nbr2_statement_digest))
            .unwrap();
        assert_eq!(verified.cohort_count, 2);
        assert_eq!(verified.challenge, challenge);
        assert_eq!(verified.transcript_bytes, 32);
        assert_eq!(verified.transcript_ledger.get("c6_joint_native_corrections"), Some(&16));
        assert_eq!(verified.transcript_ledger.get("zero_open_tag"), Some(&16));
    }

    #[test]
    fn production_coefficient_owner_rejects_bad_placements_before_filesystem_effects() {
        assert!(C61SignedCoefficientPlacement::new(&[1], 0, 1, 0, 1).is_err());
        assert!(C61SignedCoefficientPlacement::new(&[1, 2], 1, 2, 0, 1).is_err());
        let count = 1usize << C61_MODEL_POLYNOMIAL_LOG2;
        let placement = C61SignedCoefficientPlacement::new(&[1], 1, 1, count, 1).unwrap();
        let root = std::env::temp_dir().join(format!(
            "c61-coefficient-owner-reject-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        assert!(!root.exists());
        let result = create_c61_production_coefficient_owner(
            &root,
            C61NativeComponent::Model,
            [0xA5; 32],
            &[placement],
        );
        assert!(matches!(result, Err(error) if error.contains("exceeds")));
        assert!(!root.exists());
    }
}

//! P3: blind sumcheck (M3 schema), Thaler matmul reduction, batched
//! QuickSilver product check (M7/M8), and the end-to-end blind GEMM proof
//! built on `volta-mac`'s authenticated values and mock-PCG correlations.
//! P4 adds `logup` (Gruen fraction-GKR, superseding the volta-bench spike).

pub mod block_proof;
pub(crate) mod boundary_thinning;
pub mod c6;
pub mod c61_certificate;
pub mod c61_public_instance;
pub mod c61_response_envelope;
pub mod c62_certificate;
pub mod c62_response_envelope;
pub mod c63_certificate;
pub mod c63_response_envelope;
#[cfg(feature = "c6-trace")]
pub mod c6_cache_fold;
pub mod c6_census;
pub mod c6_production_pcg;
pub mod c6_residual;
pub mod c6_response_envelope;
#[cfg(feature = "c6-trace")]
pub mod c6_response_fixture;
pub mod c6_source;
pub mod c6_subfield;
pub(crate) mod ffn_schedule;
pub mod gemm_proof;
pub mod hadamard;
pub mod logup;
pub mod mle;
pub mod model_proof;
pub mod model_proof_codec;
pub(crate) mod private_argmax;
pub mod prod_check;
pub mod schedule;
pub mod sumcheck_blind;
pub mod sumcheck_clear;
pub mod thaler;
pub mod wires;
pub mod x1_routing;
pub mod x2_moe;
pub mod x2_proof;
pub mod x3_ops;
pub mod x3_proof;

pub use block_proof::{
    build_attn_wires, cattn_permuted, layer_content_keys, layer_dom_base, prove_layer_phase1,
    prove_layer_phase1_with_wires, prove_layer_phase2, verify_layer_phase1, verify_layer_phase2,
    AttnBlockProof, AttnWires, BlockCtxP, BlockCtxV, FfnBlockProof, InstanceLookups, LayerBytes,
    LayerOut, LayerOutV, LayerProof, LnChainProof, TableBankP, TableBankV, TableCloseProof,
};
pub use c6::{
    C6CacheHead, C6ClientAttempt, C6ClientState, C6ClientStore, C6CorrelationRange,
    C6DeltaResidual, C6Digest, C6Error, C6FinalCertificate, C6MacTapeManifest,
    C6PairedCorrelationRanges, C6PairedDeltaResidual, C6ProposedCacheHead, C6SetupManifest,
    C6SlotHandle, C6SlotReservation, C6SlotStatus, C6SlotStore, C6Workload, C6WrapperCommitments,
    C6_ABORT_RETRY_CREDITS, C6_ACCEPTANCE_CREDITS, C6_BASELINE_RAW_CORRELATIONS,
    C6_CERTIFICATE_NEW_PAYLOAD_FRAMING_BYTES, C6_CERTIFICATE_VERSION, C6_CLIENT_STATE_VERSION,
    C6_FASE_D_SETUP_BYTES, C6_FINAL_PROOF_CAP_BYTES, C6_LIGERO_QUERIES, C6_MAC_COORDINATES,
    C6_MAX_CONTEXT, C6_NEW_PAYLOAD_BUDGET_BYTES, C6_PAIRED_PCG_SETUP_BYTES, C6_PI_FINAL_CAP_BYTES,
    C6_RESPONSE_CAP_BYTES, C6_RETAINED_Q121_BASELINE_BYTES, C6_ROOFLINE_PI_FINAL_MAX_BYTES,
    C6_SETUP_CAP_BYTES, C6_SLOT_JOURNAL_VERSION, C6_STRICT_PI_FINAL_MAX_BYTES,
    C6_STRICT_RESPONSE_MAX_BYTES, C6_TERMINAL_ONE_RAW_CAPACITY,
};
pub use c61_certificate::{
    C61CertificateError, C61NativeFinalCertificate, C61NativeWrapperCommitments,
    C61RetainedResponseBinding, C61_CERTIFICATE_STRICT_MAX_BYTES,
    C61_NATIVE_CERTIFICATE_FRAMING_BYTES, C61_NATIVE_CERTIFICATE_VERSION,
    C61_NATIVE_STRICT_PI_FINAL_MAX_BYTES, C61_NATIVE_WRAPPER_QUERIES,
    C61_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES, C61_RETAINED_NON_PCS_RESPONSE_BYTES,
};
pub use c61_public_instance::{
    C61PublicInstanceError, C61PublicWorkloadInstance, C61PublicWorkloadPreimage,
};
pub use c61_response_envelope::{
    C61NativeResponseProofEnvelope, C61NativeResponseProofEnvelopeError,
    C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES, C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES,
    C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES, C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES,
    C61_NATIVE_RESPONSE_PROOF_COMPONENTS, C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAGIC,
    C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES,
    C61_NATIVE_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES, C61_NATIVE_RESPONSE_PROOF_ENVELOPE_VERSION,
    C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES, C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
};
pub use c62_certificate::{
    C62CertificateError, C62NativeFinalCertificate, C62NativeWrapperCommitments,
    C62_CERTIFICATE_STRICT_MAX_BYTES, C62_NATIVE_CERTIFICATE_FRAMING_BYTES,
    C62_NATIVE_CERTIFICATE_VERSION, C62_NATIVE_STRICT_PI_FINAL_MAX_BYTES,
    C62_NATIVE_WRAPPER_QUERIES, C62_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES,
    C62_RETAINED_NON_PCS_RESPONSE_BYTES,
};
pub use c62_response_envelope::{
    C62ResponseProofEnvelope, C62ResponseProofEnvelopeError, C62_RESPONSE_AUTHENTICATED_LINK_BYTES,
    C62_RESPONSE_CACHE_BLIND_MAX_BYTES, C62_RESPONSE_CACHE_FOLD_TARGET_BYTES,
    C62_RESPONSE_CACHE_SOURCE_BYTES, C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES,
    C62_RESPONSE_PROOF_COMPONENTS, C62_RESPONSE_PROOF_ENVELOPE_MAGIC,
    C62_RESPONSE_PROOF_ENVELOPE_MAX_BYTES, C62_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
    C62_RESPONSE_PROOF_ENVELOPE_VERSION, C62_RESPONSE_RESIDUAL_PENDING_BYTES,
    C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
};
pub use c63_certificate::{
    C63CertificateError, C63NativeFinalCertificate, C63NativeWrapperCommitments,
    C63_CERTIFICATE_CODEC_MAX_BYTES, C63_INHERITED_PUBLIC_ARGUMENT_BYTES,
    C63_NATIVE_CERTIFICATE_FRAMING_BYTES, C63_NATIVE_CERTIFICATE_VERSION,
    C63_NATIVE_STRICT_PI_FINAL_MAX_BYTES, C63_NATIVE_WRAPPER_QUERIES,
    C63_RETAINED_NON_PCS_RESPONSE_BYTES, C63_SKETCH_PUBLIC_ARGUMENT_MAX_BYTES,
};
pub use c63_response_envelope::{
    C63ResponseProofEnvelope, C63ResponseProofEnvelopeError,
    C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES, C63_RESPONSE_AUTHENTICATED_SKETCH_LINK_BYTES,
    C63_RESPONSE_PROOF_COMPONENTS, C63_RESPONSE_PROOF_ENVELOPE_MAGIC,
    C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES, C63_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
    C63_RESPONSE_PROOF_ENVELOPE_VERSION, C63_RESPONSE_SPARSE_H_CLOSURE_BYTES,
    C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES,
};
pub use c6_census::{
    audit_c6_t1_source_census, c6_t1_trace_source_manifest, C6CensusDigest, C6CensusError,
    C6CensusLeafRole, C6ResidualCapacityCensus, C6T1CensusInput, C6T1SourceCensus,
    C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES, C6_RESIDUAL_LEAF_ALIGNED_SLOTS, C6_RESIDUAL_SLOT_COUNT,
    C6_RESIDUAL_SLOT_ENTRIES, C6_RESIDUAL_SLOT_LOG2, C6_T1_COMPLETE_ALLOCATION_SCHEDULE_DIGEST_HEX,
    C6_T1_CORRECTION_SCHEDULE_DIGEST_HEX, C6_T1_FINAL_PRODUCT_TRIPLES, C6_T1_FULL_CORRECTION_BYTES,
    C6_T1_MAC_CLOSURE_BYTES, C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX,
    C6_T1_MODEL_FULL_CORRELATIONS, C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES,
    C6_T1_MODEL_LOCAL_PRODUCT_TRIPLES, C6_T1_MODEL_PRODUCT_MESSAGE_BYTES,
    C6_T1_MODEL_SUB_CORRELATIONS, C6_T1_MODEL_TRANSCRIPT_BYTES, C6_T1_OLD_PCS_FULL_CORRELATIONS,
    C6_T1_OTHER_MODEL_TRANSCRIPT_BYTES, C6_T1_RESERVED_RAW_CORRELATIONS,
    C6_T1_SOURCE_SCHEDULE_DIGEST_HEX, C6_T1_SUB_CORRECTION_BYTES, C6_T1_TOTAL_PRODUCT_CLOSURES,
    C6_T1_TOTAL_PRODUCT_TRIPLES, C6_T1_ZERO_CLOSURES,
};
pub use c6_production_pcg::{
    C6BoundProductionVerifierReplay, C6ProductionPairedPcgAttempt, C6ProductionPairedSourceWitness,
    C6ProductionVerifierReplayOwner, C61_PRODUCTION_FULL_CORRELATIONS,
    C61_PRODUCTION_SUB_CORRELATIONS, C61_VERIFIER_REPLAY_STATE_BYTES,
    C62_CONTINUATION_256_FULL_CORRELATIONS, C62_CONTINUATION_256_RAW_CORRELATIONS,
    C62_CONTINUATION_256_SUB_CORRELATIONS, C62_CONTINUATION_512_FULL_CORRELATIONS,
    C62_CONTINUATION_512_RAW_CORRELATIONS, C62_CONTINUATION_512_SUB_CORRELATIONS,
    C62_CONTINUATION_1024_FULL_CORRELATIONS, C62_CONTINUATION_1024_RAW_CORRELATIONS,
    C62_CONTINUATION_1024_SUB_CORRELATIONS,
    C62_CONTINUATION_1024_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_1024_RESPONSE_SUB_CORRELATIONS,
    C62_CONTINUATION_256_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_256_RESPONSE_SUB_CORRELATIONS,
    C62_CONTINUATION_512_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_512_RESPONSE_SUB_CORRELATIONS,
    C62_GENESIS_FULL_CORRELATIONS,
    C62_GENESIS_RESPONSE_FULL_CORRELATIONS, C62_GENESIS_RESPONSE_SUB_CORRELATIONS,
    C62_GENESIS_RAW_CORRELATIONS, C62_GENESIS_SUB_CORRELATIONS,
    C62_PRODUCTION_SUFFIX_FULL_CORRELATIONS, C62_PRODUCTION_SUFFIX_SUB_CORRELATIONS,
    C63_CONTINUATION_1024_FULL_CORRELATIONS,
    C63_CONTINUATION_1024_RAW_CORRELATIONS, C63_CONTINUATION_1024_SUB_CORRELATIONS,
    C63_CONTINUATION_256_FULL_CORRELATIONS, C63_CONTINUATION_256_RAW_CORRELATIONS,
    C63_CONTINUATION_256_SUB_CORRELATIONS, C63_CONTINUATION_512_FULL_CORRELATIONS,
    C63_CONTINUATION_512_RAW_CORRELATIONS, C63_CONTINUATION_512_SUB_CORRELATIONS,
    C63_GENESIS_FULL_CORRELATIONS, C63_GENESIS_RAW_CORRELATIONS,
    C63_GENESIS_SUB_CORRELATIONS, C63_PRODUCTION_SUFFIX_FULL_CORRELATIONS,
    C63_PRODUCTION_SUFFIX_SUB_CORRELATIONS,
};
#[cfg(feature = "c6-trace")]
pub use c6_residual::{
    build_c6_residual_direct_fused_scaled_fixture, build_c6_residual_fused_scaled_fixture,
    C6ResidualFusedScaledFixture,
};
pub use c6_residual::{
    c6_residual_equality_affine_range_sum, c6_residual_fused_coefficient_memory_census,
    compile_c6_residual_atomic_relation_reference,
    compile_c6_residual_folded_terminal_adjoint_reference, compile_c6_residual_fused_first_round,
    compile_c6_residual_fused_folded_coefficients, compile_c6_residual_fused_terminal_coefficients,
    compile_c6_residual_terminal_functional_relation_reference,
    evaluate_c6_nbr2_coefficient_prefix_at_two_points, reduce_c6_residual_folded_terminal_direct,
    replay_c6_residual_atomic_events, C6CommittedResidualProgram, C6CompiledBaseKeyRlc,
    C6CompiledLinearResidual, C6CompiledLinearResidualMemoryCensus, C6CompiledPairedBaseKeyRlc,
    C6CompiledPairedResidualPlan, C6CompiledResidualBinding, C6CompiledResidualPlan,
    C6CompiledTerminalLinearForm, C6LeafId, C6LeafKind, C6LeafRole, C6Nbr2TwoPointEvaluationPlan,
    C6PairedNativeTargetValues, C6PairedResidualAuxiliaryWitness, C6PairedResidualClosureWitness,
    C6PairedResidualLeafWitness, C6ProductPostCommit, C6ResidualAtomicCoefficientEvent,
    C6ResidualAtomicCoefficientTarget, C6ResidualAtomicEventAuditSink, C6ResidualAtomicEventSink,
    C6ResidualAtomicFamily, C6ResidualAtomicOutputEvent, C6ResidualAtomicReferenceCompilation,
    C6ResidualAtomicRelationStatement, C6ResidualAtomicReplaySummary,
    C6ResidualAtomicWeightSchedule, C6ResidualAuxiliaryLane, C6ResidualAuxiliaryWitnessCensus,
    C6ResidualBaseShareContext, C6ResidualBuilder, C6ResidualCensus, C6ResidualClaimsBoundContext,
    C6ResidualClosureWitnessCensus, C6ResidualDigest, C6ResidualDirectAlphaPoints,
    C6ResidualDirectEqualityPoints, C6ResidualDirectPostClaimPoints,
    C6ResidualDirectScheduleDimensions, C6ResidualEqualityAffineRangeSum, C6ResidualError,
    C6ResidualFoldedTerminalAdjointReference, C6ResidualFoldedTerminalDirectReduction,
    C6ResidualFusedCoefficientAllocationTracker, C6ResidualFusedCoefficientArena,
    C6ResidualFusedCoefficientFamily, C6ResidualFusedCoefficientMemoryCensus,
    C6ResidualFusedFirstRound, C6ResidualFusedFoldedCoefficients,
    C6ResidualFusedTerminalCoefficients, C6ResidualFusedWitnessView, C6ResidualLeafColumn,
    C6ResidualPlan, C6ResidualPostCommit, C6ResidualPostRootChallenges,
    C6ResidualProductClaimCoordinate, C6ResidualProductPublicClaim, C6ResidualPublicClaimsFrame,
    C6ResidualRelationChallenges, C6ResidualRelationManifest, C6ResidualRelationReferenceWitness,
    C6ResidualRelationRootBound, C6ResidualRetainedChallenges, C6ResidualTerminalFormKind,
    C6ResidualTerminalFunctionalRelation, C6ResidualTerminalWeightSchedule, C6SourceWitness,
    C6ValueId, C6ValueOperation, C6_RESIDUAL_AUXILIARY_LANES, C6_RESIDUAL_AUXILIARY_PRODUCT_LANES,
    C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS, C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES,
    C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2, C6_RESIDUAL_AUXILIARY_ZERO_LANES,
    C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_BYTES,
    C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS, C6_RESIDUAL_MAC_COORDINATES,
    C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS, C6_RESIDUAL_PRODUCT_CLAIMS_COORDINATE_ONE_LABEL,
    C6_RESIDUAL_PROOF_REPETITIONS, C6_RESIDUAL_RELATION_LEAF_TABLES,
    C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE, C6_RESIDUAL_TERMINAL_FORM_KINDS,
    C6_RESIDUAL_TERMINAL_FUNCTIONALS, C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION,
    C6_RESIDUAL_TERMINAL_FUNCTIONAL_DOMAIN_LOG2,
};
pub use c6_response_envelope::{
    C6ResponseProofEnvelope, C6ResponseProofEnvelopeError,
    C6_RESPONSE_AUTHENTICATED_LINK_MAX_BYTES, C6_RESPONSE_CACHE_BLIND_MAX_BYTES,
    C6_RESPONSE_CACHE_FOLD_TARGET_BYTES, C6_RESPONSE_CACHE_SOURCE_BYTES,
    C6_RESPONSE_HIDDEN_U_MAX_BYTES, C6_RESPONSE_PROOF_COMPONENTS, C6_RESPONSE_PROOF_ENVELOPE_MAGIC,
    C6_RESPONSE_PROOF_ENVELOPE_MAX_BYTES, C6_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
    C6_RESPONSE_PROOF_ENVELOPE_VERSION, C6_RESPONSE_RESIDUAL_PENDING_BYTES,
    C6_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
};
#[cfg(feature = "c6-trace")]
pub use c6_response_fixture::{
    build_c6_response_residual_fixture, build_c6_response_residual_fixture_production_geometry,
    build_c6_t1_production_response_owner, build_c62_continuation_production_response_owner,
    c6_gpt2_native_target_profile,
    prepare_c6_t1_disk_residual_owner, prepare_c6_t1_production_residual_owner,
    prove_c6_t1_production_response_provider,
    prove_c62_continuation_production_response_provider,
    replay_c6_t1_production_response_verifier,
    replay_c62_continuation_production_response_verifier,
    C6ResponseResidualCensus, C6ResponseResidualFixture, C6ResponseResidualProviderInputs,
    C6ResponseResidualTiming, C6ResponseResidualVerifierInputs, C6T1DiskResidualBoundOwner,
    C6T1DiskResidualClaimsOwner, C6T1DiskResidualOwner, C6T1InstalledRoleOwner,
    C6T1ProductionResidualBoundOwner, C6T1ProductionResidualClaimsOwner,
    C6T1ProductionResidualOwner, C6T1ProductionResponseOwner,
    C6T1ProductionResponseProviderPending, C6T1ProductionResponseVerifierReplay,
};
pub use c6_source::{
    replay_c6_source_coordinate, C6PairedSourceWitness, C6SourceCoordinate, C6SourceDigest,
    C6SourceError,
};
pub use c6_subfield::{
    replay_c6_subfield_coordinate, C6PairedSubfieldWitness, C6SubfieldDigest, C6SubfieldError,
};
pub use gemm_proof::{
    auth_phase, prove_gemm_blind, prove_gemm_blind_committed, verify_gemm_blind,
    verify_gemm_blind_committed, GemmBlindProof, ProveTimings, WeightClaimP,
};
pub use gemm_proof::{
    auth_phase_at, prove_gemm_act_chained, prove_gemm_blind_at, prove_gemm_blind_committed_at,
    prove_gemm_committed_chained, verify_gemm_act_chained, verify_gemm_blind_at,
    verify_gemm_blind_committed_at, verify_gemm_committed_chained, ChainDoms, ChainedGemmProof,
    GemmDomains, WireKey, WireOut,
};
pub use hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
pub use model_proof::{
    prove_model, prove_model_with_backend, prove_response, prove_response_private_logits,
    prove_response_private_logits_with_backend, prove_response_resident,
    prove_response_resident_private_logits, prove_response_with_backend, verify_model,
    verify_response, verify_response_private_logits, ChunkPub, ChunkRef, EmbedProof, FinalLnProof,
    ModelOut, ModelOutV, ModelProof, PrivateChunkPub, ResidentChunkRef, SeamProof,
};
#[cfg(feature = "c6-trace")]
pub use model_proof::{
    prove_response_private_logits_c6_cache_inline, verify_response_private_logits_c6_cache_inline,
    verify_response_private_logits_c6_cache_inline_from_profile, C6GrandResidualProverRoots,
    C6GrandResidualVerifierRoots,
};
pub use model_proof_codec::{
    decode_model_proof_canonical, encode_model_proof_canonical, C6RetainedResponseProof,
    c62_retained_response_byte_census, C62RetainedResponseByteCensus, ModelProofCodecError,
    C62_RETAINED_RESPONSE_BYTES, C6_RETAINED_RESPONSE_BYTES,
};
pub use prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
pub use schedule::{
    CorrelationScope, CorrelationSegment, RoundFamily, SchedulePlan, ScheduleSite, SiteCorrPlan,
    SiteId, StagedEpoch, StagedEpochSite,
};
pub use sumcheck_blind::{blind_prove, blind_prove_with_finals, blind_verify, BlindSumcheckProof};
pub use sumcheck_clear::{prove_clear, verify_clear, ClearProof};
pub use x1_routing::{
    build_x1_routing_fixture, encode_x1_golden, native_top_k_d1, prove_x1_routing,
    verify_x1_routing, x1_content_keys, x1_model_config, X1LayerWitness, X1RoutingFixture,
    X1RoutingProof, X1RoutingProverOut, X1RoutingVerifierOut, X1_D, X1_EXPERTS, X1_LAYERS, X1_T,
    X1_TOP_K,
};
pub use x2_moe::{
    build_x2_moe_fixture, encode_x2_golden, eval_i16_matrix, x2_lookup_counts, x2_model_config,
    x2_native_operation_counts, x2_native_top2_d1, x2_public_routes, X2ExpertWeights,
    X2ExpertWitness, X2LayerWeights, X2LayerWitness, X2MoeFixture, X2RouterWitness, X2_D, X2_DFF,
    X2_EXPERTS, X2_HEAD_DIM, X2_KV_HEADS, X2_LAYERS, X2_LOGICAL_LOOKUPS, X2_LOOKUP_SITES,
    X2_NATIVE_MACS, X2_PADDED_LOOKUPS, X2_QKV, X2_Q_HEADS, X2_SHIFT, X2_T, X2_TOP_K, X2_VOCAB,
};
pub use x2_proof::{
    prove_x2_moe, verify_x2_moe, x2_content_keys, X2MoeProof, X2MoeProverOut, X2MoeVerifierOut,
};
pub use x3_ops::{
    build_x3_ops_fixture, encode_x3_golden, x3_model_config, x3_native_operation_counts,
    x3_public_routes, x3_rope_coefficients, X3AttentionWitness, X3ClampProbe, X3ExpertWeights,
    X3ExpertWitness, X3FinalWitness, X3LayerWeights, X3LayerWitness, X3OpsFixture, X3PadMode,
    X3RmsWitness, X3_CLAMP_MAX, X3_CLAMP_MIN, X3_D, X3_DFF, X3_DFF_PAD, X3_D_PAD, X3_EXPERTS,
    X3_GQA_GROUP, X3_HEAD_DIM, X3_KV_HEADS, X3_LAYERS, X3_QKV, X3_Q_HEADS, X3_ROPE_FRAC,
    X3_SCORE_SHIFT, X3_SHIFT, X3_SILU_SHIFT, X3_SINKS, X3_T, X3_TOP_K, X3_T_PAD, X3_VOCAB,
    X3_VOCAB_PAD,
};
pub use x3_proof::{
    prove_x3_ops, verify_x3_ops, x3_content_keys, X3GemmProof, X3HadamardProof, X3OpsProof,
    X3OpsProverOut, X3OpsVerifierOut, X3PairProof, X3RangeProof,
};

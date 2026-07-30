//! Authenticated values (`k = m + Δ·x`), Π_Auth, Π_ZeroOpen/ZeroBatch, and
//! mock-PCG correlation streams with domain-separated one-time indices.
//!
//! P2 milestone — implementation mirrors the Lean theorems: M1 (`Authed`,
//! `Valid` and linearity), M2 (ZeroOpen/ZeroBatch with fresh full-field
//! mask), M4/M6 (one-time domain-separated correlation indices, every
//! consumption counted), M5 (subfield `F_p` corrections, 8 B each).

pub mod auth;
pub mod authed;
pub mod c6_trace;
pub mod corr;
pub mod open;
pub mod transcript;

pub use auth::{
    auth_prover, auth_verifier, auth_verifier_from_epilogue, prover_tags_from_epilogue,
};
pub use authed::{ProverAuthed, ProverSubAuthed, VerifierKey};
#[doc(hidden)]
pub use c6_trace::begin_c6_runtime_instance_capture_diagnostic;
pub use c6_trace::{
    begin_c6_prover_trace, begin_c6_runtime_instance_capture, begin_c6_verifier_trace,
    compile_c6_operation_trace, compile_c6_operation_trace_for_role, finish_c6_prover_trace,
    finish_c6_verifier_trace, normalize_c6_operation_trace,
    normalize_c6_operation_trace_debug_block, record_c6_product_closure, record_c6_zero_roots,
    C6CanonicalNodeDebug, C6CanonicalNodeDebugKind, C6CanonicalNodeKindCensus,
    C6CanonicalOperationPlan, C6CanonicalTerminalDebug, C6CompiledOperationPlan,
    C6DecodedInstanceExtractionPlan, C6DecodedOperationPlan, C6InstanceExtractionArtifact,
    C6InstanceExtractionCensus, C6InstanceExtractionRole, C6OperationPlanArtifact,
    C6OperationPlanDiagnostics, C6OperationPlanEncodingCensus, C6OperationPlanIdentity,
    C6OperationPlanInstanceIdentity, C6OperationPlanSpecializedEncodingCensus,
    C6OperationPlanTopologyIdentity, C6ProverTraceSnapshot, C6RuntimeInstanceCaptureGuard,
    C6RuntimeInstanceValues, C6TraceError, C6TraceNode, C6TraceProductClosure,
    C6TraceSourceManifest, C6TraceToken, C6VerifierTraceSnapshot, C6_OPERATION_PLAN_VERSION,
};
pub use corr::{
    C6FullfieldWitnessAudit, C6FullfieldWitnessDraw, C6SubfieldWitnessAudit, C6SubfieldWitnessDraw,
    ConnectionCorrelationScope, CorrCounters, CorrIndex, CorrReservationError, CorrScheduleAudit,
    CorrScheduleDraw, CorrScheduleKind, CorrScheduleRole, CorrelationStream, FullCorr,
    FullCorrBatchReservation, FullCorrRange, FullKeyBatchReservation, ProductMaskCorr, SubCorr,
    SubMaskRowsReservation, VerifierCtx, FULL_BIT, LEDGER_SHADOW_BIT, RESERVED_DOMAIN_BITS,
    TAG_BIT,
};
pub use open::{
    fresh_zero_mask, zero_batch_exchange, zero_batch_prover, zero_batch_verify, zero_mask_key,
    zero_open_prover, zero_open_verify,
};
pub use transcript::Transcript;

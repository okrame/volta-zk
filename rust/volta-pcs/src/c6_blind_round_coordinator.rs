#![allow(dead_code)]

use std::path::Path;

#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c61_authenticated_whir_p3::{
    assemble_c61_production_joint_public_argument_from_executions,
    C61ProductionCommittedChainExecution, C61ProductionCompilerChainExecution,
    C61ProductionJointNativeProverExecution, C61ProductionJointNativeProverLinkPending,
    C61ProductionJointNativeVerification, C61ProductionJointNativeVerifierLinkPending,
    C61ProductionJointPublicArgumentAssembly,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c6_authenticated_output_link::verify_c6_authenticated_output_link_production_nbr2_strict;
use crate::c6_authenticated_output_link::{
    prove_c6_authenticated_output_link_persisted_cuda,
    prove_c6_authenticated_output_link_persisted_cuda_nbr2_strict,
    verify_c6_authenticated_output_link_production, C6AuthenticatedOutputLinkProof,
    C6Nbr2CorrectionFunctional, C6Nbr2ProvedLink, C6PendingSlotRegistryProverBuilder,
    C6PendingSlotRegistryVerifier, C6PendingSlotRegistryVerifierBuilder,
    C6ProductionAuthenticatedOutputLinkMetrics,
};
use crate::c6_hidden_u::{
    C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUPrequery, C6SealedHiddenUBundle,
};
use crate::c6_hidden_u_sumcheck_blind::{
    assemble_c6_blind_hidden_u_prover_stepwise, assemble_c6_blind_hidden_u_verifier_stepwise,
    begin_c6_blind_hidden_u_stepwise, begin_c6_blind_hidden_u_verifier_stepwise,
    c6_blind_hidden_u_statement_digest,
    prepare_c6_blind_hidden_u_prover_round_state, prepare_c6_blind_hidden_u_verifier_round_state,
    C6BlindHiddenUPendingClaimsProver, C6BlindHiddenUProverRoundState, C6BlindHiddenUSumcheckProof,
    C6BlindHiddenUVerifierRoundState,
};
use crate::c6_persistent_cache_blind::{
    assemble_c6_persistent_cache_production_proof,
    assemble_c6_persistent_cache_production_verifier_pending, begin_c6_persistent_cache_production,
    draw_c6_persistent_cache_production_roots,
    finish_c6_persistent_cache_production_prover_repetition,
    finish_c6_persistent_cache_production_verifier_repetition,
    fix_c6_persistent_cache_production_fold_prover,
    fix_c6_persistent_cache_production_fold_verifier,
    prepare_c6_persistent_cache_production_verifier, C6PersistentCacheBlindProof,
    C6PersistentCachePendingClaimsProver, C6PersistentCacheProductionMetrics,
    C6PersistentCacheProductionPreparedProver, C6PersistentCacheProductionRelationCompiler,
    C6PersistentCacheProductionVerifierRoundState, C6PersistentCacheSourceBootstrapFrame,
    C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS, C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
};
use crate::c6_residual_sumcheck_blind::{
    assemble_c6_blind_residual_prover_stepwise, assemble_c6_blind_residual_verifier_stepwise,
    begin_c6_blind_residual_prover_stepwise, begin_c6_blind_residual_verifier_stepwise,
    finish_c6_blind_residual_verifier_round_state_direct_claims,
    prepare_c6_blind_residual_prover_round_state_fused,
    prepare_c6_blind_residual_verifier_round_state, C6BlindResidualDirectTerminalFold,
    C6BlindResidualDirectTerminalOutputs, C6BlindResidualFusedCompilerContext,
    C6BlindResidualPendingClaimsProver, C6BlindResidualPendingTransferFrame,
    C6BlindResidualProverRoundState, C6BlindResidualStatement, C6BlindResidualSumcheckProof,
    C6BlindResidualVerifierRoundState,
};
use crate::c6_wrapper_pcs::{
    C6FixedWrapperCommitments, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
    C6WrapperRoundPoint, C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ACTIVATION_ROUND,
    C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
    C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND, C6_WRAPPER_RANDOM_POINT_LEN, C6_WRAPPER_REPETITIONS,
};
use volta_field::Fp2;
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx};
use volta_proto::c6_cache_fold::{
    compile_c6_cache_fold_scalar_batch, C6CacheFoldPairedProverTargets,
    C6CacheFoldPairedVerifierTargets, C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceSnapshot,
};
use volta_proto::{C6ResidualFusedCoefficientArena, C6ResidualFusedWitnessView};
use volta_proto::C6ResponseProofEnvelope;

use crate::c6_live_wrapper::{C6PersistedLiveWrapperRootBinding, C6VerifierLiveWrapperRootBinding};
use crate::c6_wrapper_persisted::C6PersistedCacheSemanticReader;
use volta_accel::Backend;

const TAPES: usize = 2;

fn text_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub struct C6ProductionBlindProverOutput {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_pending: C6BlindResidualPendingClaimsProver,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) hidden_proof: C6BlindHiddenUSumcheckProof,
    pub(crate) hidden_pending: C6BlindHiddenUPendingClaimsProver,
    pub(crate) cache_proof: C6PersistentCacheBlindProof,
    pub(crate) cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    pub(crate) cache_pending: C6PersistentCachePendingClaimsProver,
    pub(crate) cache_metrics: C6PersistentCacheProductionMetrics,
}

pub(crate) struct C6ExactProductionProverProof {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) residual_terminal_fold: C6BlindResidualDirectTerminalFold,
    pub(crate) hidden_proof: C6BlindHiddenUSumcheckProof,
    pub(crate) cache_proof: C6PersistentCacheBlindProof,
    pub(crate) cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    pub(crate) cache_metrics: C6PersistentCacheProductionMetrics,
    pub(crate) authenticated_link: C6AuthenticatedOutputLinkProof,
    pub(crate) authenticated_link_metrics: C6ProductionAuthenticatedOutputLinkMetrics,
}

#[derive(Clone, Copy)]
struct C6ExactProductionVerifierProof<'a> {
    residual_proof: &'a C6BlindResidualSumcheckProof,
    residual_frame: &'a C6BlindResidualPendingTransferFrame,
    terminal_functionals: &'a [Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    expected_terminal_fold: Option<C6BlindResidualDirectTerminalFold>,
    hidden_proof: &'a C6BlindHiddenUSumcheckProof,
    cache_proof: &'a C6PersistentCacheBlindProof,
    cache_source_frame: &'a C6PersistentCacheSourceBootstrapFrame,
}

impl<'a> C6ExactProductionVerifierProof<'a> {
    fn from_local(proof: &'a C6ExactProductionProverProof) -> Self {
        Self {
            residual_proof: &proof.residual_proof,
            residual_frame: &proof.residual_frame,
            terminal_functionals: proof.residual_terminal_outputs.terminal_functionals(),
            expected_terminal_fold: Some(proof.residual_terminal_fold),
            hidden_proof: &proof.hidden_proof,
            cache_proof: &proof.cache_proof,
            cache_source_frame: &proof.cache_source_frame,
        }
    }
}

/// Same-attempt C6PA2/C6NBR2 output. The native proof cannot be emitted until
/// the embedded global link has authenticated the exact correction claim.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C6ExactProductionNbr2ProverProof {
    pub(crate) blind: C6ExactProductionProverProof,
    pub(crate) joint_native: C61ProductionJointNativeProverExecution,
    nbr2_statement_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C6ExactProductionVerifierOutput {
    pub(crate) bound_slots: u64,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C6ExactProductionNbr2VerifierOutput {
    blind: C6ExactProductionVerifierOutput,
    joint_native: C61ProductionJointNativeVerification,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C6ExactProductionNbr2VerifierOutput {
    pub fn bound_slots(&self) -> u64 {
        self.blind.bound_slots
    }

    pub fn joint_native(&self) -> &C61ProductionJointNativeVerification {
        &self.joint_native
    }
}

/// Final provider-owned exact certificate components. `public_argument` is
/// the strict C6PA2 object; `blind` contains the global blind proofs and the
/// same C6LNK2 proof whose local receipt released its secondary native tail.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C6ExactProductionNbr2Certificate {
    blind: C6ExactProductionProverProof,
    public_argument: C61ProductionJointPublicArgumentAssembly,
    proof_envelope: Vec<u8>,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C6ExactProductionNbr2Certificate {
    pub fn public_argument(&self) -> &C61ProductionJointPublicArgumentAssembly {
        &self.public_argument
    }

    pub fn encoded_public_argument(&self) -> &[u8] {
        self.public_argument.encoded()
    }

    pub fn encoded_proof_envelope(&self) -> &[u8] {
        &self.proof_envelope
    }
}

/// Strict blind proof decoded from C6PIF1 without any retained prover
/// typestate. C6FT1 remains as canonical bytes until response verification
/// derives its expected trace identity.
pub struct C6DecodedExactProductionBlindProof {
    residual_proof: C6BlindResidualSumcheckProof,
    residual_frame: C6BlindResidualPendingTransferFrame,
    hidden_proof: C6BlindHiddenUSumcheckProof,
    cache_proof: C6PersistentCacheBlindProof,
    cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    cache_fold_target_frame: Vec<u8>,
    authenticated_link: C6AuthenticatedOutputLinkProof,
}

impl C6DecodedExactProductionBlindProof {
    pub fn cache_fold_target_frame(&self) -> &[u8] {
        &self.cache_fold_target_frame
    }

    fn verifier_view<'a>(
        &'a self,
        terminal_functionals: &'a [Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    ) -> C6ExactProductionVerifierProof<'a> {
        C6ExactProductionVerifierProof {
            residual_proof: &self.residual_proof,
            residual_frame: &self.residual_frame,
            terminal_functionals,
            expected_terminal_fold: None,
            hidden_proof: &self.hidden_proof,
            cache_proof: &self.cache_proof,
            cache_source_frame: &self.cache_source_frame,
        }
    }
}

pub fn decode_c6_exact_production_blind_envelope(
    envelope: &C6ResponseProofEnvelope,
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    cache_statement_digest: [u8; 32],
    fixed: &C6FixedWrapperCommitments,
) -> Result<C6DecodedExactProductionBlindProof, String> {
    let hidden_statement =
        c6_blind_hidden_u_statement_digest(hidden_layouts, hidden_prequery, hidden_postcommit)
            .map_err(text_error)?;
    Ok(C6DecodedExactProductionBlindProof {
        residual_proof: C6BlindResidualSumcheckProof::decode(
            statements,
            envelope.residual_sumcheck(),
        )
        .map_err(text_error)?,
        residual_frame: C6BlindResidualPendingTransferFrame::decode(
            envelope.residual_pending_corrections(),
        )
        .map_err(text_error)?,
        hidden_proof: C6BlindHiddenUSumcheckProof::decode(
            hidden_layouts,
            hidden_statement,
            envelope.hidden_u(),
        )
        .map_err(text_error)?,
        cache_source_frame: C6PersistentCacheSourceBootstrapFrame::decode(
            cache_statement_digest,
            envelope.cache_source_bootstrap(),
        )
        .map_err(text_error)?,
        cache_proof: C6PersistentCacheBlindProof::decode(
            cache_statement_digest,
            C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS,
            envelope.cache_blind(),
        )
        .map_err(text_error)?,
        cache_fold_target_frame: envelope.cache_fold_targets().to_vec(),
        authenticated_link: C6AuthenticatedOutputLinkProof::decode(
            fixed,
            envelope.authenticated_output_link(),
        )
        .map_err(text_error)?,
    })
}

/// Consume all opaque pending values exactly once into the production
/// 72-slot relation and its persisted/CUDA PCS.  There is no constructor from
/// terminal scalar values or caller-authored slot descriptors.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_c6_production_blind_with_persisted_link(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C6ProductionBlindProverOutput,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionProverProof, String> {
    let (proof, receipt) = finish_c6_production_blind_with_persisted_link_inner(
        roots,
        blind,
        None,
        streams,
        backend,
        spill_root,
        session_digest,
        transcript,
    )?;
    if receipt.is_some() {
        return Err("C6 exact legacy runner unexpectedly produced a C6NBR2 receipt".to_owned());
    }
    Ok(proof)
}

/// Complete the amended global link and only then release the native joint
/// ZeroOpen tail. This is the sole production join between C6NBR2 and the
/// C6PA2 native typestate; both consume the same statement digest receipt.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c6_production_blind_with_persisted_nbr2_link(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C6ProductionBlindProverOutput,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeProverLinkPending,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2ProverProof, String> {
    let (blind, receipt) = finish_c6_production_blind_with_persisted_link_inner(
        roots,
        blind,
        Some(nbr2),
        streams,
        backend,
        spill_root,
        session_digest,
        transcript,
    )?;
    let receipt = receipt
        .ok_or_else(|| "C6 exact NBR2 runner omitted its authenticated-link receipt".to_owned())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C6ExactProductionNbr2ProverProof {
        blind,
        joint_native,
        nbr2_statement_digest: nbr2.digest(),
        outer_statement_digest: nbr2.outer_statement_digest(),
    })
}

/// Consume all remaining same-attempt provider owners into the exact C6PA2
/// plus global-blind certificate boundary. This function accepts no detached
/// secondary proof: that proof must come from the receipt-gated output above.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn assemble_c6_exact_production_nbr2_certificate(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    profile: &volta_mac::C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: crate::c61_public_compression::C61ArithmeticFrame,
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    cache_fold_target_frame: &[u8],
    fixed: &C6FixedWrapperCommitments,
    proof: C6ExactProductionNbr2ProverProof,
) -> Result<C6ExactProductionNbr2Certificate, String> {
    let outer_statement_digest = proof.outer_statement_digest;
    let public_argument = assemble_c61_production_joint_public_argument_from_executions(
        base_statement_digest,
        native_profile_digest,
        functional_digest,
        profile,
        primary,
        proof.joint_native,
        compiler,
        arithmetic,
    )?;
    if public_argument.argument().statement_digest() != outer_statement_digest {
        return Err("exact C6PA2 statement differs from the proved C6NBR2 outer binding".to_owned());
    }
    let proof_envelope = C6ResponseProofEnvelope::new(
        proof.blind.residual_proof.encode(statements).map_err(text_error)?,
        proof.blind.residual_frame.encode().map_err(text_error)?,
        proof.blind.hidden_proof.encode(hidden_layouts).map_err(text_error)?,
        proof.blind.cache_source_frame.encode().map_err(text_error)?,
        proof.blind.cache_proof.encode().map_err(text_error)?,
        cache_fold_target_frame.to_vec(),
        proof.blind.authenticated_link.canonical_bytes(fixed).map_err(text_error)?,
    )
    .map_err(text_error)?
    .encode()
    .map_err(text_error)?;
    Ok(C6ExactProductionNbr2Certificate { blind: proof.blind, public_argument, proof_envelope })
}

#[allow(clippy::too_many_arguments)]
fn finish_c6_production_blind_with_persisted_link_inner(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C6ProductionBlindProverOutput,
    nbr2: Option<&C6Nbr2CorrectionFunctional<'_>>,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<(C6ExactProductionProverProof, Option<C6Nbr2ProvedLink>), String> {
    validate_production_streams(streams)?;
    if roots.session_digest() != session_digest {
        return Err("C6 exact runner root/session mismatch".to_owned());
    }
    let output_beta = transcript.challenge_fp2();
    let residual_terminal_fold =
        blind.residual_terminal_outputs.clone().bind_output_beta(output_beta);
    let mut pending = C6PendingSlotRegistryProverBuilder::new(roots.fixed()).map_err(text_error)?;
    pending.absorb_residual(&blind.residual_pending).map_err(text_error)?;
    pending.absorb_hidden_u(&blind.hidden_pending).map_err(text_error)?;
    pending.absorb_persistent_cache(&blind.cache_pending).map_err(text_error)?;
    let pending = pending.finish().map_err(text_error)?;
    let (authenticated_link, bound, authenticated_link_metrics, receipt) = match nbr2 {
        Some(nbr2) => {
            let (proof, bound, metrics, receipt) =
                prove_c6_authenticated_output_link_persisted_cuda_nbr2_strict(
                    roots.fixed(),
                    roots.cohorts(),
                    pending,
                    nbr2,
                    streams,
                    backend,
                    spill_root,
                    session_digest,
                    transcript,
                )
                .map_err(text_error)?;
            (proof, bound, metrics, Some(receipt))
        }
        None => {
            let (proof, bound, metrics) = prove_c6_authenticated_output_link_persisted_cuda(
                roots.fixed(),
                roots.cohorts(),
                pending,
                streams,
                backend,
                spill_root,
                session_digest,
                transcript,
            )
            .map_err(text_error)?;
            (proof, bound, metrics, None)
        }
    };
    if bound.len() != 2 * crate::c6_wrapper_pcs::C6_WRAPPER_ACTIVE_SLOTS {
        return Err("C6 exact runner bound-slot census mismatch".to_owned());
    }
    Ok((
        C6ExactProductionProverProof {
            residual_proof: blind.residual_proof,
            residual_frame: blind.residual_frame,
            residual_terminal_outputs: blind.residual_terminal_outputs,
            residual_terminal_fold,
            hidden_proof: blind.hidden_proof,
            cache_proof: blind.cache_proof,
            cache_source_frame: blind.cache_source_frame,
            cache_metrics: blind.cache_metrics,
            authenticated_link,
            authenticated_link_metrics,
        },
        receipt,
    ))
}

/// Complete prover-side join for the three real blind participants.  Cache
/// preparation remains a callback because its relation roots and point are
/// drawn from this same transcript immediately before each repetition.
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_production_blind_components<'a>(
    fixed: &C6FixedWrapperCommitments,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedProverTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    predecessor_cache: &C6PersistedCacheSemanticReader,
    successor_cache: &C6PersistedCacheSemanticReader,
    old_len: u16,
    new_len: u16,
    append_sources: &[Vec<[ProverAuthed; TAPES]>; 2],
    append_masks: &[Vec<[Fp2; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    residual_compiler: C6BlindResidualFusedCompilerContext<'a>,
    residual_witness: C6ResidualFusedWitnessView<'a>,
    residual_arena: &'a C6ResidualFusedCoefficientArena,
    hidden: &C6SealedHiddenUBundle,
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ProductionBlindProverOutput, String> {
    validate_production_streams(streams)?;
    begin_c6_persistent_cache_production(cache_statement_digest, transcript).map_err(text_error)?;
    begin_c6_blind_residual_prover_stepwise(statements, residual_arena, transcript)
        .map_err(text_error)?;
    let hidden_statement =
        begin_c6_blind_hidden_u_stepwise(hidden, hidden_prequery, hidden_postcommit, transcript)
            .map_err(text_error)?;
    let hidden_layouts = hidden.validate_prequery_binding(hidden_prequery).map_err(text_error)?;

    let mut cache_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut residual_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut hidden_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let (relation_roots, kv_root) =
            draw_c6_persistent_cache_production_roots(repetition, transcript)
                .map_err(text_error)?;
        let scalar_batch = compile_c6_cache_fold_scalar_batch(cache_snapshot, relation_roots[2])
            .map_err(text_error)?;
        let fixed_fold = fix_c6_persistent_cache_production_fold_prover(
            repetition,
            cache_statement_digest,
            &scalar_batch,
            cache_targets,
            cache_fixed_targets,
            transcript,
        )
        .map_err(text_error)?;
        let relation_point = fixed_fold.draw_relation_point(transcript);
        let compiler = C6PersistentCacheProductionRelationCompiler::new(
            repetition,
            cache_statement_digest,
            old_len,
            new_len,
            relation_point,
            relation_roots,
            kv_root,
            scalar_batch,
        )
        .map_err(text_error)?;
        let mut cache =
            crate::c6_persistent_cache_blind::prepare_c6_persistent_cache_production_prover(
                &compiler,
                predecessor_cache,
                successor_cache,
                append_sources,
                append_masks,
                fixed_fold,
                transcript,
            )
            .map_err(text_error)?;
        let mut residual = prepare_c6_blind_residual_prover_round_state_fused(
            &statements[usize::from(repetition)],
            residual_compiler,
            residual_witness,
            residual_arena,
            None,
        )
        .map_err(text_error)?;
        let mut hidden_state = prepare_c6_blind_hidden_u_prover_round_state(
            hidden,
            hidden_prequery,
            hidden_postcommit,
            repetition,
        )
        .map_err(text_error)?;
        let (point, cache_corrections) = drive_c6_production_blind_prover_rounds(
            fixed,
            &mut cache,
            &mut residual,
            &mut hidden_state,
            streams,
            transcript,
        )?;
        cache_finished.push(
            finish_c6_persistent_cache_production_prover_repetition(
                cache,
                &point,
                streams,
                transcript,
                cache_corrections,
            )
            .map_err(text_error)?,
        );
        residual_finished.push(residual.finish(streams, transcript).map_err(text_error)?);
        hidden_finished.push(hidden_state.finish(streams, transcript).map_err(text_error)?);
    }

    let (residual_proof, residual_frame, residual_pending, terminal_outputs) =
        assemble_c6_blind_residual_prover_stepwise(
            statements,
            residual_compiler,
            residual_arena,
            residual_finished,
            transcript,
        )
        .map_err(text_error)?;
    let residual_terminal_outputs = terminal_outputs
        .ok_or_else(|| "C6 exact blind join omitted direct terminal outputs".to_owned())?;
    let (hidden_proof, hidden_pending) = assemble_c6_blind_hidden_u_prover_stepwise(
        hidden_statement,
        &hidden_layouts,
        hidden_finished,
    )
    .map_err(text_error)?;
    let (cache_proof, cache_source_frame, cache_pending, cache_metrics) =
        assemble_c6_persistent_cache_production_proof(cache_statement_digest, cache_finished)
            .map_err(text_error)?;
    Ok(C6ProductionBlindProverOutput {
        residual_proof,
        residual_frame,
        residual_pending,
        residual_terminal_outputs,
        hidden_proof,
        hidden_pending,
        cache_proof,
        cache_source_frame,
        cache_pending,
        cache_metrics,
    })
}

/// Witness-free mirror of the complete blind coordinator and production
/// C6LNK2 verifier.  The residual terminal values come from the strict proof
/// object fixed before the next transcript challenge; no verifier compiler
/// replay or fixed-DAG-node substitute is admitted here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c6_exact_production_proof(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_q_cols: &[Vec<Vec<Fp2>>],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    proof: &C6ExactProductionProverProof,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionVerifierOutput, String> {
    let pending = verify_c6_exact_production_blind_pending(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        append_base_keys,
        statements,
        hidden_layouts,
        hidden_q_cols,
        hidden_prequery,
        hidden_postcommit,
        C6ExactProductionVerifierProof::from_local(proof),
        contexts,
        transcript,
    )?;
    let bound = verify_c6_authenticated_output_link_production(
        roots.fixed(),
        pending,
        &proof.authenticated_link,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    c6_exact_bound_slot_output(bound.len())
}

/// Witness-free verifier join for the exact amended flow. The native
/// ZeroOpen tag remains pending until the same decoded C6LNK2 proof verifies
/// the exact C6NBR2 statement and returns its local-only receipt.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c6_exact_production_nbr2_proof(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_q_cols: &[Vec<Vec<Fp2>>],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    proof: &C6ExactProductionNbr2ProverProof,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2VerifierOutput, String> {
    if proof.outer_statement_digest != nbr2.outer_statement_digest()
        || proof.nbr2_statement_digest != nbr2.digest()
    {
        return Err("exact prover output differs from the verifier C6NBR2 binding".to_owned());
    }
    let pending = verify_c6_exact_production_blind_pending(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        append_base_keys,
        statements,
        hidden_layouts,
        hidden_q_cols,
        hidden_prequery,
        hidden_postcommit,
        C6ExactProductionVerifierProof::from_local(&proof.blind),
        contexts,
        transcript,
    )?;
    let (bound, receipt) = verify_c6_authenticated_output_link_production_nbr2_strict(
        roots.fixed(),
        pending,
        &proof.blind.authenticated_link,
        nbr2,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    let blind = c6_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C6ExactProductionNbr2VerifierOutput { blind, joint_native })
}

/// Verify the global blind/C6NBR2 portion of a decoded exact certificate.
/// C6PA2 decoding and native-body/compiler preparation intentionally occur
/// first and supply the linear `native` state consumed here.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c6_exact_production_nbr2_certificate(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_q_cols: &[Vec<Vec<Fp2>>],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    certificate: &C6ExactProductionNbr2Certificate,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2VerifierOutput, String> {
    if certificate.public_argument.argument().statement_digest()
        != nbr2.outer_statement_digest()
    {
        return Err("decoded C6PA2 statement differs from the verifier C6NBR2 binding".to_owned());
    }
    let pending = verify_c6_exact_production_blind_pending(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        append_base_keys,
        statements,
        hidden_layouts,
        hidden_q_cols,
        hidden_prequery,
        hidden_postcommit,
        C6ExactProductionVerifierProof::from_local(&certificate.blind),
        contexts,
        transcript,
    )?;
    let (bound, receipt) = verify_c6_authenticated_output_link_production_nbr2_strict(
        roots.fixed(),
        pending,
        &certificate.blind.authenticated_link,
        nbr2,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    let blind = c6_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C6ExactProductionNbr2VerifierOutput { blind, joint_native })
}

/// Disk-artifact verifier for the decoded C6PIF1 portion. The 64 functional
/// values and outer statement digest must come from the strict decoded
/// C6PA2/C6RSC4 object; no local prover terminal owner is accepted.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c6_decoded_exact_production_nbr2_certificate(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_q_cols: &[Vec<Vec<Fp2>>],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    proof: &C6DecodedExactProductionBlindProof,
    public_argument_statement_digest: [u8; 32],
    terminal_functionals: &[Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2VerifierOutput, String> {
    if public_argument_statement_digest != nbr2.outer_statement_digest() {
        return Err("decoded C6PA2 statement differs from the verifier C6NBR2 binding".to_owned());
    }
    let pending = verify_c6_exact_production_blind_pending(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        append_base_keys,
        statements,
        hidden_layouts,
        hidden_q_cols,
        hidden_prequery,
        hidden_postcommit,
        proof.verifier_view(terminal_functionals),
        contexts,
        transcript,
    )?;
    let (bound, receipt) = verify_c6_authenticated_output_link_production_nbr2_strict(
        roots.fixed(),
        pending,
        &proof.authenticated_link,
        nbr2,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    let blind = c6_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C6ExactProductionNbr2VerifierOutput { blind, joint_native })
}

#[allow(clippy::too_many_arguments)]
fn verify_c6_exact_production_blind_pending(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    hidden_layouts: &[C6HiddenULayout],
    hidden_q_cols: &[Vec<Vec<Fp2>>],
    hidden_prequery: &C6HiddenUPrequery,
    hidden_postcommit: &C6HiddenUPostCommit,
    proof: C6ExactProductionVerifierProof<'_>,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6PendingSlotRegistryVerifier, String> {
    validate_production_contexts(contexts)?;
    begin_c6_persistent_cache_production(cache_statement_digest, transcript).map_err(text_error)?;
    begin_c6_blind_residual_verifier_stepwise(
        statements,
        proof.residual_proof,
        proof.residual_frame,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    begin_c6_blind_hidden_u_verifier_stepwise(
        hidden_layouts,
        hidden_q_cols,
        hidden_prequery,
        hidden_postcommit,
        proof.hidden_proof,
        transcript,
    )
    .map_err(text_error)?;

    let mut cache_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut residual_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut hidden_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS as u8 {
        let (relation_roots, kv_root) =
            draw_c6_persistent_cache_production_roots(repetition, transcript)
                .map_err(text_error)?;
        let scalar_batch = compile_c6_cache_fold_scalar_batch(cache_snapshot, relation_roots[2])
            .map_err(text_error)?;
        let fixed_fold = fix_c6_persistent_cache_production_fold_verifier(
            repetition,
            cache_statement_digest,
            &scalar_batch,
            cache_targets,
            cache_fixed_targets,
            proof.cache_source_frame,
            transcript,
        )
        .map_err(text_error)?;
        let relation_point = fixed_fold.draw_relation_point(transcript);
        let compiler = C6PersistentCacheProductionRelationCompiler::new(
            repetition,
            cache_statement_digest,
            old_len,
            new_len,
            relation_point,
            relation_roots,
            kv_root,
            scalar_batch,
        )
        .map_err(text_error)?;
        let mut cache = prepare_c6_persistent_cache_production_verifier(
            &compiler,
            append_base_keys,
            fixed_fold,
            proof.cache_source_frame,
            [contexts[0].delta, contexts[1].delta],
            transcript,
        )
        .map_err(text_error)?;
        let mut residual = prepare_c6_blind_residual_verifier_round_state(
            &statements[usize::from(repetition)],
            &proof.residual_proof,
        )
        .map_err(text_error)?;
        let mut hidden = prepare_c6_blind_hidden_u_verifier_round_state(
            hidden_layouts,
            hidden_q_cols,
            hidden_prequery,
            hidden_postcommit,
            &proof.hidden_proof,
            repetition,
        )
        .map_err(text_error)?;
        let cache_corrections = proof
            .cache_proof
            .production_round_corrections(usize::from(repetition))
            .map_err(text_error)?;
        let point = drive_c6_production_blind_verifier_rounds(
            roots.fixed(),
            &mut cache,
            cache_corrections,
            &mut residual,
            &mut hidden,
            contexts,
            transcript,
        )?;
        cache_finished.push(
            finish_c6_persistent_cache_production_verifier_repetition(
                cache,
                &point,
                proof.cache_proof,
                contexts,
                transcript,
            )
            .map_err(text_error)?,
        );
        residual_finished.push(
            finish_c6_blind_residual_verifier_round_state_direct_claims(
                residual,
                proof.residual_frame,
                proof.terminal_functionals,
                contexts,
                transcript,
            )
            .map_err(text_error)?,
        );
        hidden_finished.push(hidden.finish(contexts, transcript).map_err(text_error)?);
    }

    let (cache_pending, _) =
        assemble_c6_persistent_cache_production_verifier_pending(cache_finished)
            .map_err(text_error)?;
    let residual_pending =
        assemble_c6_blind_residual_verifier_stepwise(residual_finished, transcript)
            .map_err(text_error)?;
    let hidden_pending =
        assemble_c6_blind_hidden_u_verifier_stepwise(hidden_finished).map_err(text_error)?;
    let output_beta = transcript.challenge_fp2();
    let functional_fold = proof
        .terminal_functionals
        .iter()
        .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), value| {
            (sum + power * *value, power * output_beta)
        })
        .0;
    if proof.expected_terminal_fold.is_some_and(|expected| {
        expected.beta() != output_beta || expected.functional_fold() != functional_fold
    }) {
        return Err("C6 exact verifier terminal output-fold mismatch".to_owned());
    }
    let mut pending =
        C6PendingSlotRegistryVerifierBuilder::new(roots.fixed()).map_err(text_error)?;
    pending.absorb_residual(&residual_pending).map_err(text_error)?;
    pending.absorb_hidden_u(&hidden_pending).map_err(text_error)?;
    pending.absorb_persistent_cache(&cache_pending).map_err(text_error)?;
    pending.finish().map_err(text_error)
}

fn c6_exact_bound_slot_output(
    bound_slots: usize,
) -> Result<C6ExactProductionVerifierOutput, String> {
    let bound_slots = bound_slots as u64;
    if bound_slots != 2 * crate::c6_wrapper_pcs::C6_WRAPPER_ACTIVE_SLOTS as u64 {
        return Err("C6 exact verifier bound-slot census mismatch".to_owned());
    }
    Ok(C6ExactProductionVerifierOutput { bound_slots })
}

fn validate_production_streams(streams: &[CorrelationStream; TAPES]) -> Result<(), String> {
    if streams.iter().any(|stream| !stream.uses_pooled_pcg()) {
        return Err("C6 exact blind join requires paired pooled PCG streams".to_owned());
    }
    Ok(())
}

fn validate_production_contexts(contexts: &[VerifierCtx; TAPES]) -> Result<(), String> {
    if contexts.iter().any(|context| !context.uses_pooled_pcg()) {
        return Err("C6 exact verifier requires paired pooled PCG contexts".to_owned());
    }
    if contexts[0].delta == contexts[1].delta {
        return Err("C6 exact verifier requires independent MAC coordinates".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_schedule(
    repetition: u8,
    cache_repetition: u8,
    cache_round: usize,
    residual_repetition: u8,
    residual_round: usize,
    residual_rounds: usize,
    hidden_repetition: u8,
    hidden_round: usize,
    hidden_rounds: usize,
) -> Result<(), String> {
    if cache_repetition != repetition
        || residual_repetition != repetition
        || hidden_repetition != repetition
        || cache_round != 0
        || residual_round != 0
        || hidden_round != 0
        || residual_rounds != C6_WRAPPER_RANDOM_POINT_LEN - C6_DELTA_RESIDUAL_ACTIVATION_ROUND
        || hidden_rounds != C6_WRAPPER_RANDOM_POINT_LEN - C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND
    {
        return Err("C6 production blind coordinator participant schedule mismatch".to_owned());
    }
    Ok(())
}

fn receipts(
    ids: &[u32],
    residual_bytes: Option<u64>,
    hidden_bytes: Option<u64>,
) -> Result<Vec<C6WrapperRoundMessageReceipt>, String> {
    ids.iter()
        .map(|&participant_id| {
            let message_bytes = match participant_id {
                C6_CACHE_ROUND_PARTICIPANT_ID => C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
                C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID => residual_bytes
                    .ok_or_else(|| "missing active C6RSC3 blind message".to_owned())?,
                C6_HIDDEN_U_ROUND_PARTICIPANT_ID => {
                    hidden_bytes.ok_or_else(|| "missing active C6HUB2 blind message".to_owned())?
                }
                _ => return Err("unknown C6 blind-round participant".to_owned()),
            };
            Ok(C6WrapperRoundMessageReceipt { participant_id, message_bytes })
        })
        .collect()
}

/// Drive one prover repetition through the sole production 24-round challenge
/// owner. Every active component fixes its real blind correction message
/// before the coordinator releases the shared challenge.
pub(crate) fn drive_c6_production_blind_prover_rounds(
    fixed: &C6FixedWrapperCommitments,
    cache: &mut C6PersistentCacheProductionPreparedProver<'_>,
    residual: &mut C6BlindResidualProverRoundState<'_>,
    hidden: &mut C6BlindHiddenUProverRoundState,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<(C6WrapperRoundPoint, Vec<[[Fp2; 2]; TAPES]>), String> {
    let repetition = cache.round_state.repetition();
    validate_schedule(
        repetition,
        repetition,
        cache.round_state.round_index(),
        residual.repetition(),
        residual.round_index(),
        residual.round_count(),
        hidden.repetition(),
        hidden.round_index(),
        hidden.round_count(),
    )?;
    let mut coordinator = C6WrapperRoundCoordinator::new(fixed, repetition).map_err(text_error)?;
    let mut cache_corrections = Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS);

    while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
        let global_round = coordinator.round_index();
        validate_live_rounds(
            global_round,
            cache.round_state.round_index(),
            residual.round_index(),
            hidden.round_index(),
        )?;
        let cache_message = cache.round_state.fix_next_round(streams).map_err(text_error)?;
        let residual_message = if global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND {
            Some(residual.fix_next_round(streams).map_err(text_error)?)
        } else {
            None
        };
        let hidden_bytes = if global_round >= C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND {
            Some(hidden.fix_next_round(streams).map_err(text_error)?)
        } else {
            None
        };
        let ids = coordinator.expected_participant_ids().map_err(text_error)?;
        let receipts =
            receipts(&ids, residual_message.map(|message| message.message_bytes), hidden_bytes)?;
        let challenge = coordinator
            .fix_messages_and_release_challenge(&receipts, transcript)
            .map_err(text_error)?;
        cache.round_state.bind_challenge(challenge).map_err(text_error)?;
        if residual_message.is_some() {
            residual.bind_challenge(challenge).map_err(text_error)?;
        }
        if hidden_bytes.is_some() {
            hidden.bind_challenge(challenge).map_err(text_error)?;
        }
        coordinator.confirm_participants_bound(&ids).map_err(text_error)?;
        cache_corrections.push(cache_message);
    }
    let point = coordinator.finish().map_err(text_error)?;
    if cache_corrections.len() != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
        return Err("C6 production blind prover cache round census mismatch".to_owned());
    }
    Ok((point, cache_corrections))
}

/// Replay the same global schedule on verifier-owned keys and proof bytes.
/// The verifier draws no component-private round challenge.
pub(crate) fn drive_c6_production_blind_verifier_rounds(
    fixed: &C6FixedWrapperCommitments,
    cache: &mut C6PersistentCacheProductionVerifierRoundState<'_>,
    cache_corrections: &[[[Fp2; 2]; TAPES]],
    residual: &mut C6BlindResidualVerifierRoundState<'_>,
    hidden: &mut C6BlindHiddenUVerifierRoundState,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6WrapperRoundPoint, String> {
    let repetition = cache.repetition();
    validate_schedule(
        repetition,
        repetition,
        cache.round_index(),
        residual.repetition(),
        residual.round_index(),
        residual.round_count(),
        hidden.repetition(),
        hidden.round_index(),
        hidden.round_count(),
    )?;
    if cache_corrections.len() != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
        return Err("C6 production blind verifier cache round census mismatch".to_owned());
    }
    let mut coordinator = C6WrapperRoundCoordinator::new(fixed, repetition).map_err(text_error)?;

    while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
        let global_round = coordinator.round_index();
        validate_live_rounds(
            global_round,
            cache.round_index(),
            residual.round_index(),
            hidden.round_index(),
        )?;
        cache.check_next_round(cache_corrections[global_round], contexts).map_err(text_error)?;
        let residual_message = if global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND {
            Some(residual.check_next_round(contexts).map_err(text_error)?)
        } else {
            None
        };
        let hidden_bytes = if global_round >= C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND {
            Some(hidden.check_next_round(contexts).map_err(text_error)?)
        } else {
            None
        };
        let ids = coordinator.expected_participant_ids().map_err(text_error)?;
        let receipts =
            receipts(&ids, residual_message.map(|message| message.message_bytes), hidden_bytes)?;
        let challenge = coordinator
            .fix_messages_and_release_challenge(&receipts, transcript)
            .map_err(text_error)?;
        cache.bind_challenge(challenge).map_err(text_error)?;
        if residual_message.is_some() {
            residual.bind_challenge(challenge).map_err(text_error)?;
        }
        if hidden_bytes.is_some() {
            hidden.bind_challenge(challenge).map_err(text_error)?;
        }
        coordinator.confirm_participants_bound(&ids).map_err(text_error)?;
    }
    coordinator.finish().map_err(text_error)
}

fn validate_live_rounds(
    global_round: usize,
    cache_round: usize,
    residual_round: usize,
    hidden_round: usize,
) -> Result<(), String> {
    if cache_round != global_round
        || (global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND
            && residual_round != global_round - C6_DELTA_RESIDUAL_ACTIVATION_ROUND)
        || (global_round >= C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND
            && hidden_round != global_round - C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND)
    {
        return Err("C6 production blind participant round drift".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_join_rejects_mock_streams_before_protocol_work() {
        let streams = [CorrelationStream::new([0x41; 32]), CorrelationStream::new([0x42; 32])];
        assert_eq!(
            validate_production_streams(&streams).unwrap_err(),
            "C6 exact blind join requires paired pooled PCG streams"
        );
        assert!(streams.iter().all(|stream| stream.counters.sub_corrs == 0
            && stream.counters.full_corrs == 0
            && stream.counters.domains == 0));

        let contexts = [
            VerifierCtx::new([0x41; 32], Fp2::from_base(volta_field::Fp::new(17))),
            VerifierCtx::new([0x42; 32], Fp2::from_base(volta_field::Fp::new(19))),
        ];
        assert_eq!(
            validate_production_contexts(&contexts).unwrap_err(),
            "C6 exact verifier requires paired pooled PCG contexts"
        );
    }

    #[test]
    fn production_schedule_and_receipt_order_are_exact() {
        validate_schedule(1, 1, 0, 1, 0, 23, 1, 0, 21).unwrap();
        assert!(validate_schedule(1, 1, 0, 1, 0, 22, 1, 0, 21).is_err());
        assert!(validate_live_rounds(3, 3, 2, 0).is_ok());
        assert!(validate_live_rounds(3, 3, 1, 0).is_err());
        let receipts = receipts(
            &[
                C6_CACHE_ROUND_PARTICIPANT_ID,
                C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
                C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
            ],
            Some(96),
            Some(64),
        )
        .unwrap();
        assert_eq!(
            receipts,
            vec![
                C6WrapperRoundMessageReceipt {
                    participant_id: C6_CACHE_ROUND_PARTICIPANT_ID,
                    message_bytes: 64,
                },
                C6WrapperRoundMessageReceipt {
                    participant_id: C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
                    message_bytes: 96,
                },
                C6WrapperRoundMessageReceipt {
                    participant_id: C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
                    message_bytes: 64,
                },
            ]
        );
    }

    #[test]
    fn exact_nbr2_runner_keeps_receipt_and_outer_binding_in_order() {
        let source = include_str!("c6_blind_round_coordinator.rs");
        let prover = source
            .split("pub fn finish_c6_production_blind_with_persisted_nbr2_link(")
            .nth(1)
            .unwrap()
            .split("fn finish_c6_production_blind_with_persisted_link_inner(")
            .next()
            .unwrap();
        assert!(
            prover.find("finish_c6_production_blind_with_persisted_link_inner(").unwrap()
                < prover.find("native.finish_after_nbr2_link(receipt)").unwrap()
        );
        let assembly = source
            .split("pub fn assemble_c6_exact_production_nbr2_certificate(")
            .nth(1)
            .unwrap()
            .split("fn finish_c6_production_blind_with_persisted_link_inner(")
            .next()
            .unwrap();
        assert!(assembly.contains("assemble_c61_production_joint_public_argument_from_executions"));
        assert!(assembly.contains("!= outer_statement_digest"));
        assert!(assembly.contains("C6ResponseProofEnvelope::new("));
        assert!(assembly.contains("cache_fold_target_frame.to_vec()"));
        assert!(source.contains("pub fn decode_c6_exact_production_blind_envelope("));
        assert!(source.contains("pub fn verify_c6_decoded_exact_production_nbr2_certificate("));
        let verifier = source
            .split("pub fn verify_c6_exact_production_nbr2_certificate(")
            .nth(1)
            .unwrap()
            .split("fn verify_c6_exact_production_blind_pending(")
            .next()
            .unwrap();
        assert!(
            verifier
                .find("statement_digest()\n        != nbr2.outer_statement_digest()")
                .unwrap()
                < verifier.find("verify_c6_exact_production_blind_pending(").unwrap()
        );
        assert!(
            verifier
                .find("verify_c6_authenticated_output_link_production_nbr2_strict(")
                .unwrap()
                < verifier.find("native.finish_after_nbr2_link(receipt)").unwrap()
        );
    }
}

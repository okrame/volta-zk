#![allow(dead_code)]

use std::path::Path;
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use std::sync::Arc;

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c61_authenticated_whir::{
    finish_c63_authenticated_whir_limb_pair, prepare_c63_authenticated_whir_limb_pair,
    C63AuthenticatedWhirLane, C63AuthenticatedWhirPreparedLimbPair,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c61_authenticated_whir::{C61AuthenticatedWhirBaseProof, C63AuthenticatedWhirMaskRange};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c61_authenticated_whir_p3::{
    assemble_c61_production_joint_public_argument_from_executions,
    assemble_c62_production_public_argument_from_executions, C61ProductionCommittedChainExecution,
    C61ProductionCompilerChainExecution, C61ProductionJointNativeProverExecution,
    C61ProductionJointNativeProverLinkPending, C61ProductionJointNativeVerification,
    C61ProductionJointNativeVerifierLinkPending, C61ProductionJointPublicArgumentAssembly,
    C62ProductionJointNativeProverExecution, C62ProductionJointNativeProverLinkPending,
    C62ProductionJointNativeVerification, C62ProductionJointNativeVerifierLinkPending,
    C62ProductionPublicArgumentAssembly,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c61_public_compression::{
    C61EqualityDrawn, C61OutputChallengeDrawn, C61ReadyPublicProof,
};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c62_gpu_whir::{
    C62GpuMmcs, C62ProviderCacheKey, C62_GPU_WHIR_EXECUTOR_VERSION, C62_GPU_WHIR_FIELD_TAG,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c63_preencoded_whir::{begin_verify_c63_sketch_suffix, C63SketchSuffixVerifierPending};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c63_preencoded_whir::{
    c63_challenger, c63_sample_systematic_query_rows, c63_whir_config,
    prepare_c63_resident_projected_limb, prepare_c63_resident_systematic_limb,
    C63EncodedSketchAtoYContext, C63ResidentProjectedPrepared, C63ResidentSystematicPrepared,
    C63TranscriptBinding,
};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c63_public_argument::C63PublicArgument;
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c63_public_argument::C63VerifierSketchState;
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c63_sparse_h_closure::{
    prove_c63_sparse_h_tape_closure_with_spots_resident, C63SparseHClosureError,
    C63SparseHClosureStatement, C63TapeSystematicSpot,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c63_sparse_h_closure::{C63SparseHClosureProof, C63SparseHTapeClosureReferenceAudit};
use crate::c6_authenticated_output_link::{
    authenticate_c63_residual_source_functionals,
    prove_c63_authenticated_output_link_persisted_cuda_nbr2_strict,
    prove_c6_authenticated_output_link_persisted_cuda,
    prove_c6_authenticated_output_link_persisted_cuda_nbr2_strict,
    verify_c6_authenticated_output_link_production, C61NativePendingSlotRegistryProverBuilder,
    C61NativePendingSlotRegistryVerifierBuilder,
    C63AuthenticatedSketchPendingSlotRegistryProverBuilder,
    C63AuthenticatedSketchPendingSlotRegistryVerifierBuilder, C63ResidualSourceFunctionalFrame,
    C63ResidualSourceFunctionalProverClaims, C63ResidualSourceFunctionals,
    C6AuthenticatedOutputLinkProof, C6Nbr2CorrectionFunctional, C6Nbr2ProvedLink,
    C6PendingSlotRegistryProverBuilder, C6PendingSlotRegistryVerifier,
    C6PendingSlotRegistryVerifierBuilder, C6ProductionAuthenticatedOutputLinkMetrics,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::c6_authenticated_output_link::{
    verify_c63_authenticated_output_link_production_nbr2_strict,
    verify_c63_residual_source_functionals,
    verify_c6_authenticated_output_link_production_nbr2_strict,
    C63ResidualSourceFunctionalVerifierClaims, C63ResidualSourceFunctionalsVerifiedLink,
};
use crate::c6_hidden_u::{
    C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUPrequery, C6SealedHiddenUBundle,
};
use crate::c6_hidden_u_sumcheck_blind::{
    assemble_c6_blind_hidden_u_prover_stepwise, assemble_c6_blind_hidden_u_verifier_stepwise,
    begin_c6_blind_hidden_u_stepwise, begin_c6_blind_hidden_u_verifier_stepwise,
    c6_blind_hidden_u_statement_digest, prepare_c6_blind_hidden_u_prover_round_state,
    prepare_c6_blind_hidden_u_verifier_round_state, C6BlindHiddenUPendingClaimsProver,
    C6BlindHiddenUProverRoundState, C6BlindHiddenUSumcheckProof, C6BlindHiddenUVerifierRoundState,
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
    C6PersistentCachePendingClaimsProver, C6PersistentCachePendingClaimsVerifier,
    C6PersistentCacheProductionMetrics, C6PersistentCacheProductionPreparedProver,
    C6PersistentCacheProductionRelationCompiler, C6PersistentCacheProductionVerifierRoundState,
    C6PersistentCacheSourceBootstrapFrame, C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS,
    C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
};
#[cfg(feature = "c6-trace")]
use crate::c6_residual_sumcheck_blind::prove_c6_blind_residual_sumchecks_fused_direct;
#[cfg(feature = "c6-trace")]
use crate::c6_residual_sumcheck_blind::verify_c6_blind_residual_sumchecks_direct_claims_with_points;
use crate::c6_residual_sumcheck_blind::{
    assemble_c6_blind_residual_prover_stepwise, assemble_c6_blind_residual_verifier_stepwise,
    begin_c6_blind_residual_prover_stepwise, begin_c6_blind_residual_verifier_stepwise,
    finish_c6_blind_residual_verifier_round_state_direct_claims,
    prepare_c6_blind_residual_prover_round_state_fused,
    prepare_c6_blind_residual_verifier_round_state, C6BlindResidualDirectTerminalFold,
    C6BlindResidualDirectTerminalOutputs, C6BlindResidualFusedCompilerContext,
    C6BlindResidualPendingClaimsProver, C6BlindResidualPendingClaimsVerifier,
    C6BlindResidualPendingTransferFrame, C6BlindResidualProverRoundState, C6BlindResidualStatement,
    C6BlindResidualSumcheckProof, C6BlindResidualVerifierRoundState,
};
use crate::c6_wrapper_pcs::{
    C61NativeWrapperRoundCoordinator, C6FixedWrapperCommitments, C6WrapperRoundCoordinator,
    C6WrapperRoundMessageReceipt, C6WrapperRoundPoint, C61_NATIVE_WRAPPER_ACTIVE_SLOTS,
    C63_AUTHENTICATED_SKETCH_WRAPPER_ACTIVE_SLOTS, C6_CACHE_ROUND_PARTICIPANT_ID,
    C6_DELTA_RESIDUAL_ACTIVATION_ROUND, C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
    C6_HIDDEN_U_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND,
    C6_WRAPPER_RANDOM_POINT_LEN, C6_WRAPPER_REPETITIONS,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use crate::C63SparseSketchReference;
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::{
    c63_verify_correction_rows_by_tape_reference, C63GpuStateOwner, C63_SYSTEMATIC_SPOT_QUERIES,
};
use volta_field::Fp2;
use volta_mac::{CorrScheduleAudit, CorrelationStream, ProverAuthed, Transcript, VerifierCtx};
use volta_proto::c6_cache_fold::{
    compile_c6_cache_fold_scalar_batch, C6CacheFoldAppendSourcePlan, C6CacheFoldKind,
    C6CacheFoldPairedProverTargets, C6CacheFoldPairedVerifierTargets,
    C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceSnapshot,
};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use volta_proto::C6SetupManifest;
use volta_proto::{
    C61NativeResponseProofEnvelope, C62ResponseProofEnvelope, C6ClientAttempt,
    C6ProductionPairedSourceWitness, C6ResponseProofEnvelope,
};
use volta_proto::{C6ResidualFusedCoefficientArena, C6ResidualFusedWitnessView};

use crate::c6_live_wrapper::{C6PersistedLiveWrapperRootBinding, C6VerifierLiveWrapperRootBinding};
use crate::c6_wrapper_persisted::C6PersistedCacheSemanticReader;
use volta_accel::Backend;

const TAPES: usize = 2;

/// Provider-only replay of the already consumed response cache sources. The
/// owner contains no fresh correlation and is never serialized.
pub struct C61NativeCacheAppendOwner {
    sources: [Vec<[ProverAuthed; TAPES]>; 2],
    masks: [Vec<[Fp2; TAPES]>; 2],
    semantic_bytes_read: u64,
}

/// Verifier-only replay of the same appended source coordinates. It carries
/// keys but no plaintext, provider tag, mask or Delta and is never serialized.
pub struct C61NativeCacheAppendVerifierOwner {
    base_keys: [Vec<[volta_mac::VerifierKey; TAPES]>; 2],
}

impl C61NativeCacheAppendVerifierOwner {
    pub fn source_cells(&self) -> usize {
        self.base_keys[0].len() + self.base_keys[1].len()
    }
}

impl C61NativeCacheAppendOwner {
    pub fn source_cells(&self) -> usize {
        self.sources[0].len() + self.sources[1].len()
    }

    pub fn semantic_bytes_read(&self) -> u64 {
        self.semantic_bytes_read
    }
}

/// Authenticate the two C6.3 openings from the inference-owned paired source
/// witness. This path never materializes or rereads the historical dense
/// cache: it consumes the already recorded one-time corrections `D=X-R`.
pub fn authenticate_c63_resident_source_functionals(
    old_len: u16,
    new_len: u16,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source: &C6ProductionPairedSourceWitness,
    statement: C63ResidualSourceFunctionals,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C63ResidentSourceFunctionalClaims, String> {
    let values = crate::c63_evaluate_residual_source_functionals(
        old_len,
        new_len,
        statement.source_schedule_digest(),
        plan,
        schedule,
        source,
        [
            statement.coefficients(0).map_err(text_error)?,
            statement.coefficients(1).map_err(text_error)?,
        ],
    )?;
    let (claims, frame) =
        authenticate_c63_residual_source_functionals(statement, values, streams, transcript)
            .map_err(text_error)?;
    Ok(C63ResidentSourceFunctionalClaims { claims, frame })
}

/// Compile the exact tape-separated D22 terminal functionals after the sparse
/// rounds have fixed their point, then authenticate them from the live
/// inference source. The owned statement keeps the coefficient vectors alive
/// through the later output-link join without copying them again.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_c63_resident_source_functionals_at_point(
    fixed: &C6FixedWrapperCommitments,
    outer_statement_digest: [u8; 32],
    source_binding_digest: [u8; 32],
    functional_context_digest: [u8; 32],
    old_len: u16,
    new_len: u16,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source: &C6ProductionPairedSourceWitness,
    rho: &[Fp2; crate::C63_BOLT_COLUMNS],
    row_point: &[Fp2],
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C63ResidentSourceFunctionalClaims, String> {
    if source.source().subfield_leaf_count() as u64 != schedule.counters.sub_corrs {
        return Err("C6.3 resident source count differs from its schedule".to_owned());
    }
    let source_count = u32::try_from(schedule.counters.sub_corrs)
        .map_err(|_| "C6.3 resident source count exceeds u32".to_owned())?;
    let coefficients = crate::c63_compile_residual_source_functionals(
        old_len,
        new_len,
        source_count,
        schedule.digest,
        plan,
        schedule,
        rho,
        row_point,
    )?;
    let statement = C63ResidualSourceFunctionals::new_owned(
        fixed,
        outer_statement_digest,
        source_binding_digest,
        schedule.digest,
        functional_context_digest,
        coefficients,
    )
    .map_err(text_error)?;
    authenticate_c63_resident_source_functionals(
        old_len, new_len, plan, schedule, source, statement, streams, transcript,
    )
}

/// Verifier mirror of the resident source compiler. The sparse proof has
/// already fixed `rho`, the terminal point and their transcript context, so
/// the provider cannot choose any coefficient here.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c63_resident_source_functionals_at_pending(
    fixed: &C6FixedWrapperCommitments,
    source_binding_digest: [u8; 32],
    old_len: u16,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    suffix: &C63SketchSuffixVerifierPending,
    frame: &C63ResidualSourceFunctionalFrame,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C63ResidualSourceFunctionalVerifierClaims, String> {
    let source_count = u32::try_from(schedule.counters.sub_corrs)
        .map_err(|_| "C6.3 verifier source count exceeds u32".to_owned())?;
    let coefficients = crate::c63_compile_residual_source_functionals(
        old_len,
        suffix.accepted_len(),
        source_count,
        schedule.digest,
        plan,
        schedule,
        suffix.rho(),
        suffix.sumcheck_point(),
    )?;
    let statement = C63ResidualSourceFunctionals::new_owned(
        fixed,
        suffix.statement_digest(),
        source_binding_digest,
        schedule.digest,
        suffix.source_functional_context_digest(),
        coefficients,
    )
    .map_err(text_error)?;
    verify_c63_residual_source_functionals(statement, frame, contexts, transcript)
        .map_err(text_error)
}

/// Serialized resident C6.3 suffix. No dense correction table is returned.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C63ResidentSketchSuffixProverOutput {
    sketch_public_argument: Vec<u8>,
    sparse_h_closure: C63SparseHClosureProof,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
impl C63ResidentSketchSuffixProverOutput {
    pub fn into_parts(
        self,
    ) -> (Vec<u8>, C63SparseHClosureProof, [C61AuthenticatedWhirBaseProof; 4]) {
        (self.sketch_public_argument, self.sparse_h_closure, self.terminal_proofs)
    }
}

/// Resident commitments held while the existing authenticated output link
/// consumes its correlations. The exact source claim is returned separately
/// and must be consumed by that link before this state can be finished.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C63ResidentSketchSuffixPrepared {
    binding: C63TranscriptBinding,
    query_seed: [u8; 32],
    outer_statement_digest: [u8; 32],
    profile_digest: [u8; 32],
    predecessor_correction_root: [u8; 32],
    predecessor_encoded_sketch_root: [u8; 32],
    correction_root: [u8; 32],
    encoded_sketch_root: [u8; 32],
    epoch: u64,
    old_len: u16,
    new_len: u16,
    spot_rows: Vec<u32>,
    correction_artifact: Vec<u8>,
    output_point: Vec<Fp2>,
    m_point: Vec<Fp2>,
    systematic: [[Option<C63ResidentSystematicPrepared>; 2]; TAPES],
    projected: [[Option<C63ResidentProjectedPrepared>; 2]; TAPES],
    u_limb_values: [[Fp2; 2]; TAPES],
    m_claims: [ProverAuthed; TAPES],
    u_claims: [ProverAuthed; TAPES],
    source_functional_statement_digest: [u8; 32],
    sparse_h_closure: C63SparseHClosureProof,
}

/// Commit the eight initial roots and close the resident sparse relation. The
/// exact `D=X-R` source is authenticated only after its terminal point is
/// fixed; WHIR masks remain undrawn for the intervening output-link phase.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c63_resident_sketch_suffix<R: rand_010::Rng>(
    mmcs: C62GpuMmcs,
    h: &C63SparseSketchReference,
    attempt: C6ClientAttempt,
    setup_manifest: &C6SetupManifest,
    fixed: &C6FixedWrapperCommitments,
    outer_statement_digest: [u8; 32],
    profile_digest: [u8; 32],
    source_binding_digest: [u8; 32],
    predecessor_state: &C63VerifierSketchState,
    predecessor: Option<Arc<C63GpuStateOwner>>,
    successor: Arc<C63GpuStateOwner>,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source: &C6ProductionPairedSourceWitness,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<(C63ResidentSketchSuffixPrepared, C63ResidentSourceFunctionalClaims), String> {
    let backend = mmcs.backend();
    let mut sparse_messages = std::array::from_fn::<_, TAPES, _>(|_| None);
    let result = (|| {
        let old_len = predecessor_state.accepted_len();
        let new_len = successor.accepted_len();
        if successor.append_start() != old_len
            || successor.epoch()
                != predecessor_state
                    .epoch()
                    .checked_add(1)
                    .ok_or_else(|| "C6.3 resident predecessor epoch overflows".to_owned())?
            || old_len >= new_len
            || predecessor_state.correction_root() == [0; 32]
            || predecessor_state.encoded_sketch_root() == [0; 32]
            || successor.correction_root() == [0; 32]
            || successor.encoded_sketch_root() == [0; 32]
        {
            return Err("C6.3 resident suffix state transition differs".to_owned());
        }
        match predecessor.as_deref() {
            Some(owner)
                if owner.epoch() != predecessor_state.epoch()
                    || owner.accepted_len() != old_len
                    || owner.correction_root() != predecessor_state.correction_root()
                    || owner.encoded_sketch_root() != predecessor_state.encoded_sketch_root() =>
            {
                return Err("C6.3 resident predecessor owner differs".to_owned())
            }
            None if old_len != 0 || predecessor_state.epoch() != 0 => {
                return Err("C6.3 resident predecessor owner is absent".to_owned())
            }
            _ => {}
        }

        let binding = C63TranscriptBinding::new(
            attempt,
            outer_statement_digest,
            profile_digest,
            predecessor_state.correction_root(),
            predecessor_state.encoded_sketch_root(),
            successor.correction_root(),
            successor.encoded_sketch_root(),
            successor.epoch(),
            old_len,
            new_len,
        )?;
        setup_manifest.validate().map_err(|error| error.to_string())?;
        if setup_manifest.digest().map_err(|error| error.to_string())?
            != attempt.setup_manifest_digest
        {
            return Err("C6.3 resident suffix setup differs from its attempt".to_owned());
        }
        let output_point = binding.output_point();
        let mut rho_challenger = c63_challenger(binding.rho_seed())?;
        let (rho, projected_contexts) = C63EncodedSketchAtoYContext::sample_tape_limb_after_roots(
            crate::c61_whir_reference::C61Commitment::new(
                vec![predecessor_state.correction_root()],
            ),
            crate::c61_whir_reference::C61Commitment::new(vec![
                predecessor_state.encoded_sketch_root()
            ]),
            crate::c61_whir_reference::C61Commitment::new(vec![successor.correction_root()]),
            crate::c61_whir_reference::C61Commitment::new(vec![successor.encoded_sketch_root()]),
            old_len,
            1usize << 19,
            &mut rho_challenger,
        )?;
        let input_config = c63_whir_config(22)?;
        let output_config = c63_whir_config(19)?;
        let mut systematic: [[Option<C63ResidentSystematicPrepared>; 2]; TAPES] =
            std::array::from_fn(|_| std::array::from_fn(|_| None));
        let mut projected: [[Option<C63ResidentProjectedPrepared>; 2]; TAPES] =
            std::array::from_fn(|_| std::array::from_fn(|_| None));
        let mut initial_roots = [[0u8; 32]; 8];
        let mut u_limb_values = [[Fp2::ZERO; 2]; TAPES];

        for tape in 0..TAPES {
            let mut messages = successor
                .project_tape_messages(predecessor.as_deref(), rho, tape)
                .map_err(|error| error.to_string())?;
            sparse_messages[tape] =
                Some(messages.combined_systematic().map_err(|error| error.to_string())?);
            for limb in 0..2 {
                let systematic_lane = prepare_c63_resident_systematic_limb(
                    mmcs.clone(),
                    &input_config,
                    messages.take_systematic(limb).map_err(|error| error.to_string())?,
                    binding.lane_seed(&rho, C63AuthenticatedWhirLane::Systematic, tape, limb)?,
                    rng,
                )?;
                initial_roots[tape * 2 + limb] = systematic_lane.root();
                systematic[tape][limb] = Some(systematic_lane);

                let projected_lane = prepare_c63_resident_projected_limb(
                    mmcs.clone(),
                    &output_config,
                    c63_projected_cache_key(
                        setup_manifest,
                        binding,
                        &rho,
                        tape,
                        limb,
                        &output_config,
                    )?,
                    messages.take_sketch(limb).map_err(|error| error.to_string())?,
                    messages.take_encoded_sketch(limb).map_err(|error| error.to_string())?,
                    projected_contexts[tape][limb].clone(),
                    predecessor.clone(),
                    Arc::clone(&successor),
                    binding.lane_seed(&rho, C63AuthenticatedWhirLane::Sketch, tape, limb)?,
                    rng,
                )?;
                initial_roots[4 + tape * 2 + limb] = projected_lane.root();
                u_limb_values[tape][limb] = projected_lane.evaluate(&output_point)?;
                projected[tape][limb] = Some(projected_lane);
            }
        }

        let query_seed = binding.query_seed(&rho, &initial_roots)?;
        let mut spot_challenger = c63_challenger(binding.spot_seed(query_seed)?)?;
        let spot_rows = c63_sample_systematic_query_rows(
            &mut spot_challenger,
            22,
            C63_SYSTEMATIC_SPOT_QUERIES,
        )?;
        let correction_opening =
            successor.open_correction_rows(&spot_rows).map_err(|error| error.to_string())?;
        let correction_artifact = correction_opening.encode(old_len, new_len, &spot_rows)?;
        let (spots, _) = c63_verify_correction_rows_by_tape_reference(
            predecessor_state.correction_root(),
            successor.correction_root(),
            predecessor_state.correction_frontier(),
            profile_digest,
            successor.epoch(),
            old_len,
            new_len,
            &spot_rows,
            &rho,
            &correction_opening,
        )?;
        let spots = spots
            .into_iter()
            .map(|(row, values)| C63TapeSystematicSpot { row, values })
            .collect::<Vec<_>>();
        let statement =
            C63SparseHClosureStatement::new(successor.correction_root(), output_point.clone())
                .map_err(|error| error.to_string())?;
        let basis = Fp2::new(volta_field::Fp::ZERO, volta_field::Fp::ONE);
        let u_claims = std::array::from_fn(|tape| {
            ProverAuthed::from_public(u_limb_values[tape][0] + u_limb_values[tape][1] * basis)
        });
        let mut source_claims = None;
        let mut sparse_transcript = Transcript::new(binding.sparse_seed(query_seed)?);
        let (sparse_h_closure, m_point) = prove_c63_sparse_h_tape_closure_with_spots_resident(
            Arc::clone(&backend),
            h,
            sparse_messages.each_mut().map(|message| {
                message.take().expect("both resident sparse messages were prepared")
            }),
            u_claims,
            &statement,
            &spots,
            streams,
            &mut sparse_transcript,
            |tape, point, prefix_digest, streams| {
                if source_claims.is_none() {
                    let functional_context = binding
                        .source_functional_context(query_seed, prefix_digest)
                        .map_err(C63SparseHClosureError::new)?;
                    source_claims = Some(
                        authenticate_c63_resident_source_functionals_at_point(
                            fixed,
                            outer_statement_digest,
                            source_binding_digest,
                            functional_context,
                            old_len,
                            new_len,
                            plan,
                            schedule,
                            source,
                            &rho,
                            point,
                            streams,
                            transcript,
                        )
                        .map_err(C63SparseHClosureError::new)?,
                    );
                }
                Ok(source_claims
                    .as_ref()
                    .expect("C6.3 source claims were created")
                    .terminal_m_claims()[tape])
            },
        )
        .map_err(|error| error.to_string())?;
        let source_claims =
            source_claims.ok_or_else(|| "C6.3 resident source claims are absent".to_owned())?;
        let m_claims = source_claims.terminal_m_claims();
        let source_functional_statement_digest = source_claims.claims.statement().digest();

        Ok((
            C63ResidentSketchSuffixPrepared {
                binding,
                query_seed,
                outer_statement_digest,
                profile_digest,
                predecessor_correction_root: predecessor_state.correction_root(),
                predecessor_encoded_sketch_root: predecessor_state.encoded_sketch_root(),
                correction_root: successor.correction_root(),
                encoded_sketch_root: successor.encoded_sketch_root(),
                epoch: successor.epoch(),
                old_len,
                new_len,
                spot_rows,
                correction_artifact,
                output_point,
                m_point,
                systematic,
                projected,
                u_limb_values,
                m_claims,
                u_claims,
                source_functional_statement_digest,
                sparse_h_closure,
            },
            source_claims,
        ))
    })();
    if result.is_err() {
        if let Ok(mut locked) = backend.lock() {
            for message in sparse_messages.into_iter().flatten() {
                let _ = locked.free_device(message);
            }
        }
    }
    result
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn c63_projected_cache_key(
    setup: &C6SetupManifest,
    binding: C63TranscriptBinding,
    rho: &[Fp2; crate::C63_BOLT_COLUMNS],
    tape: usize,
    limb: usize,
    config: &crate::c63_preencoded_whir::C63WhirConfig,
) -> Result<C62ProviderCacheKey, String> {
    let folding = config.round_folding_factor(0);
    let height = (1usize << (config.num_variables - folding)) << config.starting_log_inv_rate;
    let key = C62ProviderCacheKey {
        model_digest: setup.model_digest,
        protocol_digest: setup.protocol_digest,
        parameter_digest: setup.params_digest,
        content_digest: binding.projected_cache_content_digest(rho, tape, limb)?,
        field_tag: C62_GPU_WHIR_FIELD_TAG,
        encoder_version: C62_GPU_WHIR_EXECUTOR_VERSION,
        num_variables: config.num_variables as u8,
        folding: folding as u8,
        height: height as u64,
    };
    key.validate().map_err(|error| error.to_string())?;
    Ok(key)
}

/// Draw the WHIR masks only after the existing global output link has
/// consumed its correlations, then serialize the eight bodies and four final
/// tags.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub fn finish_c63_resident_sketch_suffix<R: rand_010::Rng>(
    prepared: C63ResidentSketchSuffixPrepared,
    linked: &C63ExactProductionProverProof,
    mask_range: C63AuthenticatedWhirMaskRange,
    streams: &mut [CorrelationStream; TAPES],
    rng: &mut R,
) -> Result<C63ResidentSketchSuffixProverOutput, String> {
    finish_c63_resident_sketch_suffix_inner(
        prepared,
        linked.source_functional_statement_digest,
        linked.outer_statement_digest,
        mask_range,
        streams,
        rng,
    )
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub fn finish_c64_resident_sketch_suffix<R: rand_010::Rng>(
    prepared: C63ResidentSketchSuffixPrepared,
    linked: &C64ExactProductionProverProof,
    mask_range: C63AuthenticatedWhirMaskRange,
    streams: &mut [CorrelationStream; TAPES],
    rng: &mut R,
) -> Result<C63ResidentSketchSuffixProverOutput, String> {
    finish_c63_resident_sketch_suffix_inner(
        prepared,
        linked.source_functional_statement_digest,
        linked.outer_statement_digest,
        mask_range,
        streams,
        rng,
    )
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn finish_c63_resident_sketch_suffix_inner<R: rand_010::Rng>(
    prepared: C63ResidentSketchSuffixPrepared,
    linked_source_functional_statement_digest: [u8; 32],
    linked_outer_statement_digest: [u8; 32],
    mask_range: C63AuthenticatedWhirMaskRange,
    streams: &mut [CorrelationStream; TAPES],
    rng: &mut R,
) -> Result<C63ResidentSketchSuffixProverOutput, String> {
    let C63ResidentSketchSuffixPrepared {
        binding,
        query_seed,
        outer_statement_digest,
        profile_digest,
        predecessor_correction_root,
        predecessor_encoded_sketch_root,
        correction_root,
        encoded_sketch_root,
        epoch,
        old_len,
        new_len,
        spot_rows,
        correction_artifact,
        output_point,
        m_point,
        mut systematic,
        mut projected,
        u_limb_values,
        m_claims,
        u_claims,
        source_functional_statement_digest,
        sparse_h_closure,
    } = prepared;
    if linked_source_functional_statement_digest != source_functional_statement_digest
        || linked_outer_statement_digest != outer_statement_digest
    {
        return Err("C6.3 resident suffix was not released by its output link".to_owned());
    }
    let mut systematic_masks = Vec::with_capacity(TAPES);
    let mut projected_masks = Vec::with_capacity(TAPES);
    for stream in streams.iter_mut() {
        systematic_masks.push(
            prepare_c63_authenticated_whir_limb_pair(
                C63AuthenticatedWhirLane::Systematic,
                mask_range,
                stream,
            )
            .map_err(|error| error.to_string())?,
        );
        projected_masks.push(
            prepare_c63_authenticated_whir_limb_pair(
                C63AuthenticatedWhirLane::Sketch,
                mask_range,
                stream,
            )
            .map_err(|error| error.to_string())?,
        );
    }
    let systematic_masks: [C63AuthenticatedWhirPreparedLimbPair; TAPES] = systematic_masks
        .try_into()
        .map_err(|_| "C6.3 systematic mask census differs".to_owned())?;
    let mut systematic_masks = systematic_masks.map(Some);
    let projected_masks: [C63AuthenticatedWhirPreparedLimbPair; TAPES] =
        projected_masks.try_into().map_err(|_| "C6.3 projected mask census differs".to_owned())?;
    let mut projected_masks = projected_masks.map(Some);
    let mut m_artifacts: [[Vec<u8>; 2]; TAPES] =
        std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
    let mut u_artifacts: [[Vec<u8>; 2]; TAPES] =
        std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
    let mut m_normalized = [[None; 2]; TAPES];
    let mut u_normalized = [[None; 2]; TAPES];
    for tape in 0..TAPES {
        let m_mask_values = systematic_masks[tape]
            .as_ref()
            .ok_or_else(|| "C6.3 systematic masks are absent".to_owned())?
            .values();
        let u_mask_values = projected_masks[tape]
            .as_ref()
            .ok_or_else(|| "C6.3 projected masks are absent".to_owned())?
            .values();
        for limb in 0..2 {
            let lane = systematic[tape][limb]
                .take()
                .ok_or_else(|| "C6.3 systematic lane is absent".to_owned())?;
            let evaluation = lane.evaluate(&m_point)?;
            let proof = lane.finish(&m_point, evaluation, m_mask_values[limb], rng)?;
            m_artifacts[tape][limb] = proof.artifact;
            m_normalized[tape][limb] = Some(proof.normalized);

            let lane = projected[tape][limb]
                .take()
                .ok_or_else(|| "C6.3 projected lane is absent".to_owned())?;
            let proof =
                lane.finish(&output_point, u_limb_values[tape][limb], u_mask_values[limb], rng)?;
            u_artifacts[tape][limb] = proof.artifact;
            u_normalized[tape][limb] = Some(proof.normalized);
        }
    }

    let public_argument = C63PublicArgument::new(
        outer_statement_digest,
        profile_digest,
        predecessor_correction_root,
        predecessor_encoded_sketch_root,
        correction_root,
        encoded_sketch_root,
        epoch,
        old_len,
        new_len,
        &spot_rows,
        correction_artifact,
        m_artifacts,
        u_artifacts,
    )?;
    let sketch_public_argument = public_argument.encode()?;
    let sparse_bytes = sparse_h_closure.encode().map_err(|error| error.to_string())?;
    let terminal_contexts =
        binding.terminal_contexts(query_seed, &sketch_public_argument, &sparse_bytes)?;
    let mut terminal_proofs = Vec::with_capacity(4);
    for tape in 0..TAPES {
        let mut terminal_transcript = Transcript::new_fiat_shamir(terminal_contexts[0][tape])?;
        terminal_proofs.push(
            finish_c63_authenticated_whir_limb_pair(
                systematic_masks[tape]
                    .take()
                    .ok_or_else(|| "C6.3 systematic terminal mask is absent".to_owned())?,
                [
                    m_normalized[tape][0]
                        .ok_or_else(|| "C6.3 systematic limb zero is absent".to_owned())?,
                    m_normalized[tape][1]
                        .ok_or_else(|| "C6.3 systematic limb one is absent".to_owned())?,
                ],
                m_claims[tape],
                &mut terminal_transcript,
            )
            .map_err(|error| error.to_string())?
            .proof,
        );
    }
    for tape in 0..TAPES {
        let mut terminal_transcript = Transcript::new_fiat_shamir(terminal_contexts[1][tape])?;
        terminal_proofs.push(
            finish_c63_authenticated_whir_limb_pair(
                projected_masks[tape]
                    .take()
                    .ok_or_else(|| "C6.3 projected terminal mask is absent".to_owned())?,
                [
                    u_normalized[tape][0]
                        .ok_or_else(|| "C6.3 projected limb zero is absent".to_owned())?,
                    u_normalized[tape][1]
                        .ok_or_else(|| "C6.3 projected limb one is absent".to_owned())?,
                ],
                u_claims[tape],
                &mut terminal_transcript,
            )
            .map_err(|error| error.to_string())?
            .proof,
        );
    }
    let terminal_proofs =
        terminal_proofs.try_into().map_err(|_| "C6.3 terminal-proof census differs".to_owned())?;
    Ok(C63ResidentSketchSuffixProverOutput {
        sketch_public_argument,
        sparse_h_closure,
        terminal_proofs,
    })
}

/// Recover the exact K/V append cells from the committed successor cache and
/// attach their original response-tape tags and masks. Replays are required
/// to leave correlation counters and the public schedule unchanged.
pub fn materialize_c61_native_cache_append_owner(
    plan: &C6CacheFoldAppendSourcePlan,
    successor: &C6PersistedCacheSemanticReader,
    old_len: u16,
    new_len: u16,
    streams: &mut [CorrelationStream; TAPES],
) -> Result<C61NativeCacheAppendOwner, String> {
    if old_len >= new_len
        || new_len > crate::c6_persistent_cache::C6_PERSISTENT_CACHE_CAPACITY_TOKENS
        || plan.layers().len()
            != usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_LAYERS)
        || successor.payload_len()
            != crate::c6_persistent_cache::C6_PERSISTENT_CACHE_SLOT_CAPACITY as usize
        || streams.iter().any(|stream| !stream.uses_pooled_pcg())
    {
        return Err("C6.1 cache append owner geometry/backend mismatch".to_owned());
    }
    let before_counters = [streams[0].counters, streams[1].counters];
    let before_schedules = [streams[0].schedule_audit(), streams[1].schedule_audit()];
    let append_rows = usize::from(new_len - old_len);
    let width = usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_WIDTH);
    let padded_width = usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_PADDED_WIDTH);
    let layer_len = usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_CAPACITY_TOKENS)
        .checked_mul(padded_width)
        .ok_or_else(|| "C6.1 cache append layer length overflows".to_owned())?;
    let per_kind = append_rows
        .checked_mul(width)
        .and_then(|count| count.checked_mul(plan.layers().len()))
        .ok_or_else(|| "C6.1 cache append source census overflows".to_owned())?;
    let mut sources: [Vec<[ProverAuthed; TAPES]>; 2] =
        std::array::from_fn(|_| Vec::with_capacity(per_kind));
    let mut masks: [Vec<[Fp2; TAPES]>; 2] = std::array::from_fn(|_| Vec::with_capacity(per_kind));
    let mut semantic_bytes_read = 0u64;

    for (layer_ordinal, layer) in plan.layers().iter().enumerate() {
        if usize::from(layer.model_layer()) != layer_ordinal
            || layer.first_row() != usize::from(old_len)
            || layer.row_count().map_err(text_error)? != append_rows
        {
            return Err(
                "C6.1 cache append source plan does not cover the exact response".to_owned()
            );
        }
        for (kv, kind) in
            [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns].into_iter().enumerate()
        {
            let start = layer_ordinal
                .checked_mul(layer_len)
                .and_then(|base| {
                    usize::from(old_len)
                        .checked_mul(padded_width)
                        .and_then(|offset| base.checked_add(offset))
                })
                .ok_or_else(|| "C6.1 cache append semantic offset overflows".to_owned())?;
            let count = append_rows
                .checked_mul(padded_width)
                .ok_or_else(|| "C6.1 cache append semantic range overflows".to_owned())?;
            let (values, bytes_read) =
                successor.read_slot_range(kv as u8, start, count).map_err(text_error)?;
            semantic_bytes_read = semantic_bytes_read
                .checked_add(bytes_read)
                .ok_or_else(|| "C6.1 cache append semantic byte count overflows".to_owned())?;
            for row_offset in 0..append_rows {
                let row = usize::from(old_len) + row_offset;
                let domain = layer.source_domain(kind, row).map_err(text_error)?;
                let replayed_masks = [
                    streams[0].replay_consumed_sub_masks(domain, width),
                    streams[1].replay_consumed_sub_masks(domain, width),
                ];
                let tags = [
                    streams[0].draw_sub_tags(domain, width),
                    streams[1].draw_sub_tags(domain, width),
                ];
                for channel in 0..width {
                    let value = values[row_offset * padded_width + channel];
                    if value.c1 != volta_field::Fp::ZERO {
                        return Err("C6.1 cache append source is not a base-field value".to_owned());
                    }
                    let authenticated = std::array::from_fn(|tape| {
                        streams[tape].authenticate_subfield_sparse_linear(
                            domain,
                            width,
                            &[(channel, Fp2::ONE)],
                            value,
                            tags[tape][channel],
                        )
                    });
                    sources[kv].push(authenticated);
                    masks[kv].push(std::array::from_fn(|tape| {
                        Fp2::from_base(replayed_masks[tape][channel])
                    }));
                }
            }
        }
    }
    if sources.iter().any(|values| values.len() != per_kind)
        || masks.iter().any(|values| values.len() != per_kind)
        || [streams[0].counters, streams[1].counters] != before_counters
        || [streams[0].schedule_audit(), streams[1].schedule_audit()] != before_schedules
    {
        return Err("C6.1 cache append replay changed census or correlation state".to_owned());
    }
    Ok(C61NativeCacheAppendOwner { sources, masks, semantic_bytes_read })
}

/// Reconstruct the verifier keys for the exact append-domain map emitted by
/// the independent response replay. No provider map or wire field is used.
pub fn materialize_c61_native_cache_append_verifier_owner(
    plan: &C6CacheFoldAppendSourcePlan,
    old_len: u16,
    new_len: u16,
    contexts: &mut [VerifierCtx; TAPES],
) -> Result<C61NativeCacheAppendVerifierOwner, String> {
    if old_len >= new_len
        || new_len > crate::c6_persistent_cache::C6_PERSISTENT_CACHE_CAPACITY_TOKENS
        || plan.layers().len()
            != usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_LAYERS)
        || contexts.iter().any(|context| !context.uses_pooled_pcg())
        || contexts[0].delta == contexts[1].delta
    {
        return Err("C6.1 verifier cache append owner geometry/backend mismatch".to_owned());
    }
    let before_counters = [contexts[0].counters, contexts[1].counters];
    let before_schedules = [contexts[0].schedule_audit(), contexts[1].schedule_audit()];
    let append_rows = usize::from(new_len - old_len);
    let width = usize::from(crate::c6_persistent_cache::C6_PERSISTENT_CACHE_WIDTH);
    let per_kind = append_rows
        .checked_mul(width)
        .and_then(|count| count.checked_mul(plan.layers().len()))
        .ok_or_else(|| "C6.1 verifier cache append census overflows".to_owned())?;
    let mut base_keys: [Vec<[volta_mac::VerifierKey; TAPES]>; 2] =
        std::array::from_fn(|_| Vec::with_capacity(per_kind));
    for (layer_ordinal, layer) in plan.layers().iter().enumerate() {
        if usize::from(layer.model_layer()) != layer_ordinal
            || layer.first_row() != usize::from(old_len)
            || layer.row_count().map_err(text_error)? != append_rows
        {
            return Err(
                "C6.1 verifier cache append plan does not cover the exact response".to_owned()
            );
        }
        for (kv, kind) in
            [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns].into_iter().enumerate()
        {
            for row in usize::from(old_len)..usize::from(new_len) {
                let domain = layer.source_domain(kind, row).map_err(text_error)?;
                let keys = [
                    contexts[0].replay_consumed_sub_verifier_keys(domain, width),
                    contexts[1].replay_consumed_sub_verifier_keys(domain, width),
                ];
                for channel in 0..width {
                    base_keys[kv].push([keys[0][channel], keys[1][channel]]);
                }
            }
        }
    }
    if base_keys.iter().any(|values| values.len() != per_kind)
        || [contexts[0].counters, contexts[1].counters] != before_counters
        || [contexts[0].schedule_audit(), contexts[1].schedule_audit()] != before_schedules
    {
        return Err("C6.1 verifier cache append replay changed census or state".to_owned());
    }
    Ok(C61NativeCacheAppendVerifierOwner { base_keys })
}

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

/// C6.1 native blind output. Hidden-u is absent from its ownership graph.
pub struct C61NativeProductionBlindProverOutput {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_pending: C6BlindResidualPendingClaimsProver,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) cache_proof: C6PersistentCacheBlindProof,
    pub(crate) cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    pub(crate) cache_pending: C6PersistentCachePendingClaimsProver,
    pub(crate) cache_metrics: C6PersistentCacheProductionMetrics,
}

/// C6.3 blind prefix. Cache and hidden owners are absent: the authenticated
/// sketch replaces the cache proof and only the residual relation remains.
pub struct C63ProductionBlindProverOutput {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_pending: C6BlindResidualPendingClaimsProver,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C64ProductionBlindProverOutput {
    blind: C63ProductionBlindProverOutput,
    precommit: crate::c64_projected_residual_suffix::C64ProjectedResidualPrecommit,
}

/// The fresh authentication and its wire correction are created together and
/// consumed together, preventing a frame from another response from being
/// paired with the resident `D=X-R` values.
pub struct C63ResidentSourceFunctionalClaims {
    claims: C63ResidualSourceFunctionalProverClaims,
    frame: C63ResidualSourceFunctionalFrame,
}

impl C63ResidentSourceFunctionalClaims {
    pub fn terminal_m_claims(&self) -> [ProverAuthed; TAPES] {
        [self.claims.claims()[0][0], self.claims.claims()[1][1]]
    }

    fn into_parts(
        self,
    ) -> (C63ResidualSourceFunctionalProverClaims, C63ResidualSourceFunctionalFrame) {
        (self.claims, self.frame)
    }
}

/// Linear public-compression continuation derived from the exact native blind
/// output. Compiler inputs, arithmetic typestate and the later C6NBR2 join
/// therefore cannot be assembled from detached terminal claims.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61NativeTerminalCompilerPrepared {
    public_output: C61OutputChallengeDrawn,
    ready: C61ReadyPublicProof,
    inputs: C6ExactTerminalCompilerInputs,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C61NativeTerminalCompilerPrepared {
    pub fn ready(&self) -> &C61ReadyPublicProof {
        &self.ready
    }

    pub fn inputs(&self) -> &C6ExactTerminalCompilerInputs {
        &self.inputs
    }
}

pub(crate) struct C61NativeExactProductionProverProof {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) residual_terminal_fold: C6BlindResidualDirectTerminalFold,
    pub(crate) cache_proof: C6PersistentCacheBlindProof,
    pub(crate) cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    pub(crate) cache_metrics: C6PersistentCacheProductionMetrics,
    pub(crate) authenticated_link: C6AuthenticatedOutputLinkProof,
    pub(crate) authenticated_link_metrics: C6ProductionAuthenticatedOutputLinkMetrics,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61NativeExactProductionNbr2ProverProof {
    pub(crate) blind: C61NativeExactProductionProverProof,
    pub(crate) joint_native: C61ProductionJointNativeProverExecution,
    nbr2_statement_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C62NativeExactProductionNbr2ProverProof {
    pub(crate) blind: C61NativeExactProductionProverProof,
    pub(crate) joint_native: C62ProductionJointNativeProverExecution,
    nbr2_statement_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C63ExactProductionProverProof {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) residual_terminal_fold: C6BlindResidualDirectTerminalFold,
    pub(crate) source_functional_frame: C63ResidualSourceFunctionalFrame,
    pub(crate) authenticated_link: C6AuthenticatedOutputLinkProof,
    pub(crate) authenticated_link_metrics: C6ProductionAuthenticatedOutputLinkMetrics,
    pub(crate) joint_native: C62ProductionJointNativeProverExecution,
    nbr2_statement_digest: [u8; 32],
    source_functional_statement_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C64ExactProductionProverProof {
    pub(crate) residual_proof: C6BlindResidualSumcheckProof,
    pub(crate) residual_frame: C6BlindResidualPendingTransferFrame,
    pub(crate) residual_terminal_outputs: C6BlindResidualDirectTerminalOutputs,
    pub(crate) residual_terminal_fold: C6BlindResidualDirectTerminalFold,
    pub(crate) source_functional_frame: C63ResidualSourceFunctionalFrame,
    pub(crate) projected: crate::c64_projected_residual_codec::C64ProjectedResidualFrame,
    pub(crate) joint_native: C62ProductionJointNativeProverExecution,
    nbr2_statement_digest: [u8; 32],
    source_functional_statement_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
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

#[derive(Clone, Copy)]
struct C61NativeExactProductionVerifierProof<'a> {
    residual_proof: &'a C6BlindResidualSumcheckProof,
    residual_frame: &'a C6BlindResidualPendingTransferFrame,
    terminal_functionals: &'a [Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    expected_terminal_fold: Option<C6BlindResidualDirectTerminalFold>,
    cache_proof: &'a C6PersistentCacheBlindProof,
    cache_source_frame: &'a C6PersistentCacheSourceBootstrapFrame,
}

impl<'a> C61NativeExactProductionVerifierProof<'a> {
    fn from_local(proof: &'a C61NativeExactProductionProverProof) -> Self {
        Self {
            residual_proof: &proof.residual_proof,
            residual_frame: &proof.residual_frame,
            terminal_functionals: proof.residual_terminal_outputs.terminal_functionals(),
            expected_terminal_fold: Some(proof.residual_terminal_fold),
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

/// Canonical public inputs fixed by the global blind relation before the two
/// persisted compiler chains are started.  This is a read-only projection of
/// linear prover typestate: it contains no witness table, MAC share or key.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ExactTerminalCompilerInputs {
    relation_challenges_digest: [u8; 32],
    leaf_points: [Vec<Fp2>; 2],
    auxiliary_points: [Vec<Fp2>; 2],
    terminal_functionals: [Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    output_beta: Fp2,
    relation_root: [u8; 32],
    functional_fold: Fp2,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C6ExactTerminalCompilerInputs {
    pub fn relation_challenges_digest(&self) -> [u8; 32] {
        self.relation_challenges_digest
    }

    pub fn leaf_points(&self) -> [&[Fp2]; 2] {
        [&self.leaf_points[0], &self.leaf_points[1]]
    }

    pub fn auxiliary_points(&self) -> [&[Fp2]; 2] {
        [&self.auxiliary_points[0], &self.auxiliary_points[1]]
    }

    pub fn terminal_functionals(&self) -> &[Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS] {
        &self.terminal_functionals
    }

    pub fn output_beta(&self) -> Fp2 {
        self.output_beta
    }

    pub fn relation_root(&self) -> [u8; 32] {
        self.relation_root
    }

    pub fn functional_fold(&self) -> Fp2 {
        self.functional_fold
    }
}

#[cfg(feature = "c61-p3-authenticated-reference")]
fn terminal_compiler_inputs(
    outputs: &C6BlindResidualDirectTerminalOutputs,
    output_beta: Fp2,
) -> Result<C6ExactTerminalCompilerInputs, String> {
    if outputs.relation_challenges_digest() == [0; 32] || outputs.digest() == [0; 32] {
        return Err("C6.1 compiler inputs have a noncanonical terminal binding".to_owned());
    }
    let terminal_functionals = *outputs.terminal_functionals();
    Ok(C6ExactTerminalCompilerInputs {
        relation_challenges_digest: outputs.relation_challenges_digest(),
        leaf_points: [
            outputs.leaf_point(0).map_err(text_error)?.to_vec(),
            outputs.leaf_point(1).map_err(text_error)?.to_vec(),
        ],
        auxiliary_points: [
            outputs.auxiliary_point(0).map_err(text_error)?.to_vec(),
            outputs.auxiliary_point(1).map_err(text_error)?.to_vec(),
        ],
        terminal_functionals,
        output_beta,
        relation_root: outputs.digest(),
        functional_fold: crate::fold_terminal_claims(&terminal_functionals, output_beta),
    })
}

/// Fix the exact 64 C6RSC3 outputs, draw beta, bind their canonical C6TFR1
/// root and only then release runtime challenges. No caller supplies a root,
/// point, terminal value or fold.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn prepare_c61_native_terminal_compiler(
    blind: &C61NativeProductionBlindProverOutput,
    equality: C61EqualityDrawn,
    transcript: &mut Transcript,
) -> Result<C61NativeTerminalCompilerPrepared, String> {
    prepare_native_terminal_compiler(&blind.residual_terminal_outputs, equality, transcript)
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn prepare_c63_terminal_compiler(
    blind: &C63ProductionBlindProverOutput,
    equality: C61EqualityDrawn,
    transcript: &mut Transcript,
) -> Result<C61NativeTerminalCompilerPrepared, String> {
    prepare_native_terminal_compiler(&blind.residual_terminal_outputs, equality, transcript)
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub fn prepare_c64_terminal_compiler(
    blind: &C64ProductionBlindProverOutput,
    equality: C61EqualityDrawn,
    transcript: &mut Transcript,
) -> Result<C61NativeTerminalCompilerPrepared, String> {
    prepare_c63_terminal_compiler(&blind.blind, equality, transcript)
}

#[cfg(feature = "c61-p3-authenticated-reference")]
fn prepare_native_terminal_compiler(
    outputs: &C6BlindResidualDirectTerminalOutputs,
    equality: C61EqualityDrawn,
    transcript: &mut Transcript,
) -> Result<C61NativeTerminalCompilerPrepared, String> {
    let public_output = equality
        .fix_terminal_claims(*outputs.terminal_functionals(), transcript)
        .draw_output_challenge(transcript);
    let inputs = terminal_compiler_inputs(outputs, public_output.output_beta())?;
    let ready = public_output
        .clone()
        .fix_adjoint_root(inputs.relation_root(), transcript)
        .map_err(text_error)?
        .draw_runtime_challenges(transcript);
    if ready.terminal_claims() != inputs.terminal_functionals()
        || ready.adjoint_root() != inputs.relation_root()
    {
        return Err("native compiler typestate differs from exact blind outputs".to_owned());
    }
    Ok(C61NativeTerminalCompilerPrepared { public_output, ready, inputs })
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C6ExactProductionNbr2ProverProof {
    pub fn terminal_compiler_inputs(&self) -> Result<C6ExactTerminalCompilerInputs, String> {
        let outputs = &self.blind.residual_terminal_outputs;
        if outputs.relation_challenges_digest() == [0; 32]
            || outputs.digest() == [0; 32]
            || self.blind.residual_terminal_fold.terminal_outputs_digest() != outputs.digest()
        {
            return Err("C6 exact compiler inputs have a noncanonical terminal binding".to_owned());
        }
        Ok(C6ExactTerminalCompilerInputs {
            relation_challenges_digest: outputs.relation_challenges_digest(),
            leaf_points: [
                outputs.leaf_point(0).map_err(text_error)?.to_vec(),
                outputs.leaf_point(1).map_err(text_error)?.to_vec(),
            ],
            auxiliary_points: [
                outputs.auxiliary_point(0).map_err(text_error)?.to_vec(),
                outputs.auxiliary_point(1).map_err(text_error)?.to_vec(),
            ],
            terminal_functionals: *outputs.terminal_functionals(),
            output_beta: self.blind.residual_terminal_fold.beta(),
            relation_root: outputs.digest(),
            functional_fold: self.blind.residual_terminal_fold.functional_fold(),
        })
    }
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C61NativeExactProductionNbr2ProverProof {
    pub fn terminal_compiler_inputs(&self) -> Result<C6ExactTerminalCompilerInputs, String> {
        let outputs = &self.blind.residual_terminal_outputs;
        if self.blind.residual_terminal_fold.terminal_outputs_digest() != outputs.digest() {
            return Err(
                "C6.1 native compiler inputs have a noncanonical terminal binding".to_owned()
            );
        }
        terminal_compiler_inputs(outputs, self.blind.residual_terminal_fold.beta())
    }
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
pub struct C62ExactProductionNbr2VerifierOutput {
    blind: C6ExactProductionVerifierOutput,
    joint_native: C62ProductionJointNativeVerification,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C63ExactProductionVerifierOutput {
    inherited: C62ExactProductionNbr2VerifierOutput,
    source_link: C63ResidualSourceFunctionalsVerifiedLink,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C63CompleteProductionVerifierOutput {
    inherited: C63ExactProductionVerifierOutput,
    sparse_audit: C63SparseHTapeClosureReferenceAudit,
    successor_state: C63VerifierSketchState,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C64CompleteProductionVerifierOutput {
    joint_native: C62ProductionJointNativeVerification,
    projected_audit: crate::c63_sparse_h_closure::C63SparseHTapeClosureReferenceAudit,
    sparse_audit: C63SparseHTapeClosureReferenceAudit,
    successor_state: C63VerifierSketchState,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C64CompleteProductionVerifierOutput {
    pub fn joint_native(&self) -> &C62ProductionJointNativeVerification {
        &self.joint_native
    }

    pub fn successor_state(&self) -> &C63VerifierSketchState {
        &self.successor_state
    }

    pub fn into_successor_state(self) -> C63VerifierSketchState {
        self.successor_state
    }
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C63ExactProductionVerifierOutput {
    pub fn inherited(&self) -> &C62ExactProductionNbr2VerifierOutput {
        &self.inherited
    }

    pub fn source_link(&self) -> C63ResidualSourceFunctionalsVerifiedLink {
        self.source_link
    }
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C63CompleteProductionVerifierOutput {
    pub fn inherited(&self) -> &C63ExactProductionVerifierOutput {
        &self.inherited
    }

    pub fn sparse_audit(&self) -> &C63SparseHTapeClosureReferenceAudit {
        &self.sparse_audit
    }

    pub fn successor_state(&self) -> &C63VerifierSketchState {
        &self.successor_state
    }

    pub fn into_successor_state(self) -> C63VerifierSketchState {
        self.successor_state
    }
}

/// Release the successor only after the inherited verifier and the complete
/// authenticated-sketch suffix have both accepted.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn finish_c63_complete_verifier(
    inherited: C63ExactProductionVerifierOutput,
    suffix: C63SketchSuffixVerifierPending,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    verifier_contexts: &mut [VerifierCtx; TAPES],
) -> Result<C63CompleteProductionVerifierOutput, String> {
    let (sparse_audit, successor_state) =
        suffix.finish(inherited.source_link(), terminal_proofs, mask_range, verifier_contexts)?;
    Ok(C63CompleteProductionVerifierOutput { inherited, sparse_audit, successor_state })
}

/// One CPU-verifier entry point for the complete C6.3 suffix and its inherited
/// authenticated output link. It preserves the real correlation order:
/// sparse rounds, exact source corrections, global link, then WHIR masks.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c63_complete_decoded_response(
    roots: &C6VerifierLiveWrapperRootBinding,
    blind: C6ResidualDecodedBlindVerifierPending,
    authenticated_link: &C6AuthenticatedOutputLinkProof,
    inherited_public_argument_statement_digest: [u8; 32],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    source_binding_digest: [u8; 32],
    old_len: u16,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source_frame: &C63ResidualSourceFunctionalFrame,
    native: C62ProductionJointNativeVerifierLinkPending,
    sketch_public_argument: &[u8],
    attempt: C6ClientAttempt,
    h: &C63SparseSketchReference,
    sparse_h_closure: &C63SparseHClosureProof,
    predecessor_state: &C63VerifierSketchState,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C63CompleteProductionVerifierOutput, String> {
    let suffix = begin_verify_c63_sketch_suffix(
        sketch_public_argument,
        attempt,
        h,
        sparse_h_closure,
        predecessor_state,
        contexts,
    )?;
    if suffix.statement_digest() != inherited_public_argument_statement_digest
        || suffix.accepted_len() <= old_len
    {
        return Err("C6.3 inherited and sketch statements differ".to_owned());
    }
    let source_functionals = verify_c63_resident_source_functionals_at_pending(
        roots.fixed(),
        source_binding_digest,
        old_len,
        plan,
        schedule,
        &suffix,
        source_frame,
        contexts,
        transcript,
    )?;
    let inherited = finish_c63_decoded_verifier(
        roots,
        blind,
        authenticated_link,
        inherited_public_argument_statement_digest,
        nbr2,
        &source_functionals,
        native,
        contexts,
        transcript,
    )?;
    finish_c63_complete_verifier(inherited, suffix, terminal_proofs, mask_range, contexts)
}

#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c64_complete_decoded_response(
    roots: &C6VerifierLiveWrapperRootBinding,
    blind: C6ResidualDecodedBlindVerifierPending,
    inherited_public_argument_statement_digest: [u8; 32],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    source_binding_digest: [u8; 32],
    old_len: u16,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source_frame: &C63ResidualSourceFunctionalFrame,
    native: C62ProductionJointNativeVerifierLinkPending,
    sketch_public_argument: &[u8],
    attempt: C6ClientAttempt,
    h: &C63SparseSketchReference,
    sparse_h_closure: &C63SparseHClosureProof,
    predecessor_state: &C63VerifierSketchState,
    cache_terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    cache_mask_range: C63AuthenticatedWhirMaskRange,
    projected_frame: &crate::c64_projected_residual_codec::C64ProjectedResidualFrame,
    precommit_binding_digest: [u8; 32],
    projected_weights: crate::c64_projected_residual_suffix::C64ProjectedResidualWeights,
    projected_mask_range: crate::c61_authenticated_whir::C64AuthenticatedWhirMaskRange,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C64CompleteProductionVerifierOutput, String> {
    let suffix = begin_verify_c63_sketch_suffix(
        sketch_public_argument,
        attempt,
        h,
        sparse_h_closure,
        predecessor_state,
        contexts,
    )?;
    if suffix.statement_digest() != inherited_public_argument_statement_digest
        || suffix.accepted_len() <= old_len
        || inherited_public_argument_statement_digest != nbr2.outer_statement_digest()
    {
        return Err("C6.4 inherited and sketch statements differ".to_owned());
    }
    let source_functionals = verify_c63_resident_source_functionals_at_pending(
        roots.fixed(),
        source_binding_digest,
        old_len,
        plan,
        schedule,
        &suffix,
        source_frame,
        contexts,
        transcript,
    )?;
    let residual_pending = blind
        .residual_pending
        .as_ref()
        .ok_or_else(|| "C6.4 residual pending claims are absent".to_owned())?;
    let pending_digest =
        crate::c64_joint_residual_sketch::c64_projected_pending_digest_verifier(residual_pending)?;
    let (correction_beta, batch_alphas) =
        crate::c64_projected_residual_suffix::draw_c64_projected_residual_postclaim_challenges(
            projected_frame.roots,
            pending_digest,
            source_functionals.statement().digest(),
            transcript,
        )?;
    let projected = crate::c64_projected_residual_suffix::verify_c64_projected_residual(
        projected_frame,
        precommit_binding_digest,
        roots.fixed().binding_digest(),
        nbr2.digest(),
        projected_weights,
        residual_pending,
        blind.inputs.leaf_points(),
        blind.inputs.auxiliary_points(),
        &source_functionals,
        correction_beta,
        batch_alphas,
        projected_mask_range,
        contexts,
        transcript,
    )?;
    let (receipt, source_link) =
        crate::c6_authenticated_output_link::c64_projected_residual_verified_links(
            &projected,
            nbr2.digest(),
            &source_functionals,
        )
        .map_err(text_error)?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    let (sparse_audit, successor_state) =
        suffix.finish(source_link, cache_terminal_proofs, cache_mask_range, contexts)?;
    Ok(C64CompleteProductionVerifierOutput {
        joint_native,
        projected_audit: projected.correction_audit,
        sparse_audit,
        successor_state,
    })
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C62ExactProductionNbr2VerifierOutput {
    pub fn bound_slots(&self) -> u64 {
        self.blind.bound_slots
    }

    pub fn joint_native(&self) -> &C62ProductionJointNativeVerification {
        &self.joint_native
    }
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

/// Hidden-free same-attempt C6.1 certificate components. The encoded proof
/// bytes are necessarily C61PIF2; no historical envelope is accepted.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61NativeExactProductionNbr2Certificate {
    blind: C61NativeExactProductionProverProof,
    public_argument: C61ProductionJointPublicArgumentAssembly,
    proof_envelope: Vec<u8>,
}

/// C6.2 certificate components with an independent C62PA1 public argument
/// and C62PIF1 blind-proof envelope.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C62NativeExactProductionNbr2Certificate {
    blind: C61NativeExactProductionProverProof,
    public_argument: C62ProductionPublicArgumentAssembly,
    proof_envelope: Vec<u8>,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C61NativeExactProductionNbr2Certificate {
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

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C62NativeExactProductionNbr2Certificate {
    pub fn public_argument(&self) -> &C62ProductionPublicArgumentAssembly {
        &self.public_argument
    }

    pub fn encoded_public_argument(&self) -> &[u8] {
        self.public_argument.encoded()
    }

    pub fn encoded_proof_envelope(&self) -> &[u8] {
        &self.proof_envelope
    }
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

/// Strict hidden-free blind proof decoded from C61PIF2.
pub struct C61NativeDecodedExactProductionBlindProof {
    residual_proof: C6BlindResidualSumcheckProof,
    residual_frame: C6BlindResidualPendingTransferFrame,
    cache_proof: C6PersistentCacheBlindProof,
    cache_source_frame: C6PersistentCacheSourceBootstrapFrame,
    cache_fold_target_frame: Vec<u8>,
    authenticated_link: C6AuthenticatedOutputLinkProof,
}

impl C61NativeDecodedExactProductionBlindProof {
    pub fn cache_fold_target_frame(&self) -> &[u8] {
        &self.cache_fold_target_frame
    }

    fn verifier_view<'a>(
        &'a self,
        terminal_functionals: &'a [Fp2; volta_proto::C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    ) -> C61NativeExactProductionVerifierProof<'a> {
        C61NativeExactProductionVerifierProof {
            residual_proof: &self.residual_proof,
            residual_frame: &self.residual_frame,
            terminal_functionals,
            expected_terminal_fold: None,
            cache_proof: &self.cache_proof,
            cache_source_frame: &self.cache_source_frame,
        }
    }
}

pub fn decode_c61_native_exact_production_blind_envelope(
    envelope: &C61NativeResponseProofEnvelope,
    statements: &[C6BlindResidualStatement],
    cache_statement_digest: [u8; 32],
    fixed: &C6FixedWrapperCommitments,
) -> Result<C61NativeDecodedExactProductionBlindProof, String> {
    Ok(C61NativeDecodedExactProductionBlindProof {
        residual_proof: C6BlindResidualSumcheckProof::decode(
            statements,
            envelope.residual_sumcheck(),
        )
        .map_err(text_error)?,
        residual_frame: C6BlindResidualPendingTransferFrame::decode(
            envelope.residual_pending_corrections(),
        )
        .map_err(text_error)?,
        cache_proof: C6PersistentCacheBlindProof::decode(
            cache_statement_digest,
            C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS,
            envelope.cache_blind(),
        )
        .map_err(text_error)?,
        cache_source_frame: C6PersistentCacheSourceBootstrapFrame::decode(
            cache_statement_digest,
            envelope.cache_source_bootstrap(),
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

pub fn decode_c62_native_exact_production_blind_envelope(
    envelope: &C62ResponseProofEnvelope,
    statements: &[C6BlindResidualStatement],
    cache_statement_digest: [u8; 32],
    fixed: &C6FixedWrapperCommitments,
) -> Result<C61NativeDecodedExactProductionBlindProof, String> {
    Ok(C61NativeDecodedExactProductionBlindProof {
        residual_proof: C6BlindResidualSumcheckProof::decode(
            statements,
            envelope.residual_sumcheck(),
        )
        .map_err(text_error)?,
        residual_frame: C6BlindResidualPendingTransferFrame::decode(
            envelope.residual_pending_corrections(),
        )
        .map_err(text_error)?,
        cache_proof: C6PersistentCacheBlindProof::decode(
            cache_statement_digest,
            C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS,
            envelope.cache_blind(),
        )
        .map_err(text_error)?,
        cache_source_frame: C6PersistentCacheSourceBootstrapFrame::decode(
            cache_statement_digest,
            envelope.cache_source_bootstrap(),
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

/// Disk-only continuation after the blind residual proof has been checked and
/// the exact terminal/compiler challenge order has been replayed.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C6ResidualDecodedBlindVerifierPending {
    pending: C6PendingSlotRegistryVerifier,
    residual_pending:
        Option<crate::c6_residual_sumcheck_blind::C6BlindResidualPendingClaimsVerifier>,
    ready: C61ReadyPublicProof,
    inputs: C6ExactTerminalCompilerInputs,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub type C61NativeDecodedBlindVerifierPending = C6ResidualDecodedBlindVerifierPending;

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C6ResidualDecodedBlindVerifierPending {
    pub fn ready(&self) -> &C61ReadyPublicProof {
        &self.ready
    }

    pub fn inputs(&self) -> &C6ExactTerminalCompilerInputs {
        &self.inputs
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compiler_public_statement(
        &self,
        operation_plan: &volta_mac::C6InstalledOperationPlan,
        terminal_metadata: &volta_mac::C6OperationPlanTerminalMetadata,
        extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
        runtime: &volta_mac::C6RuntimeInstanceValues,
        relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
        commitments: [crate::C61NativeCommitmentDescriptor; 2],
        id: crate::C61NativeChainId,
    ) -> Result<crate::C61TypedNativeChainPublicStatement, String> {
        if id.component != crate::C61NativeComponent::Compiler || id.repetition >= 2 {
            return Err("C6ICT5 disk compiler statement has a noncanonical role".to_owned());
        }
        let leaf = self.inputs.leaf_points();
        let auxiliary = self.inputs.auxiliary_points();
        let binding = crate::C61TerminalFunctionalCompilerBinding {
            operation_plan_digest: operation_plan.artifact_digest(),
            operation_topology_digest: operation_plan.topology().topology_digest,
            terminal_metadata_digest: terminal_metadata.digest(),
            extraction_map_digest: extraction.census().map_digest,
            runtime_root: runtime.instance_identity().instance_digest,
            residual_manifest_digest: relation.manifest().digest(),
            residual_public_claims_digest: relation.claims().digest(),
            relation_challenges_digest: relation.digest(),
            sparse_oracles: crate::C61SparseRationalCompilerOracles::new(
                commitments[0],
                commitments[1],
            )
            .map_err(text_error)?,
            leaf_points: [leaf[0].to_vec(), leaf[1].to_vec()],
            auxiliary_points: [auxiliary[0].to_vec(), auxiliary[1].to_vec()],
            terminal_claims: *self.inputs.terminal_functionals(),
            output_beta: self.inputs.output_beta(),
            relation_root: self.inputs.relation_root(),
        };
        let compiler =
            crate::C61TerminalFunctionalCompilerStatement::new(binding).map_err(text_error)?;
        if compiler.functional_fold != self.inputs.functional_fold() {
            return Err("C6ICT5 disk compiler statement terminal fold differs".to_owned());
        }
        crate::C61TypedNativeChainPublicStatement::new(
            id,
            crate::C61TypedNativeRelationStatement::Compiler(Box::new(compiler)),
        )
        .map_err(text_error)
    }
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
    public_output: &C61OutputChallengeDrawn,
    native: C61ProductionJointNativeProverLinkPending,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2ProverProof, String> {
    if public_output.terminal_claims() != blind.residual_terminal_outputs.terminal_functionals() {
        return Err("C6 exact public typestate differs from the fixed C6RSC3 outputs".to_owned());
    }
    let (blind, receipt) = finish_c6_production_blind_with_persisted_link_inner(
        roots,
        blind,
        Some(nbr2),
        Some(public_output.output_beta()),
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

/// C6.1-native join: only residual and cache pending owners enter the 56-slot
/// registry, and C6NBR2 is mandatory before the joint native tail is released.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c61_native_production_blind_with_persisted_nbr2_link(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C61NativeProductionBlindProverOutput,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    terminal: &C61NativeTerminalCompilerPrepared,
    native: C61ProductionJointNativeProverLinkPending,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C61NativeExactProductionNbr2ProverProof, String> {
    validate_production_streams(streams)?;
    if roots.session_digest() != session_digest {
        return Err("C6.1 native exact runner root/session mismatch".to_owned());
    }
    if terminal.public_output.terminal_claims()
        != blind.residual_terminal_outputs.terminal_functionals()
        || terminal.inputs.relation_root() != blind.residual_terminal_outputs.digest()
    {
        return Err("C6.1 native public typestate differs from residual outputs".to_owned());
    }
    let residual_terminal_fold = blind
        .residual_terminal_outputs
        .clone()
        .bind_output_beta(terminal.public_output.output_beta());
    let mut pending =
        C61NativePendingSlotRegistryProverBuilder::new(roots.fixed()).map_err(text_error)?;
    pending.absorb_residual(&blind.residual_pending).map_err(text_error)?;
    pending.absorb_persistent_cache(&blind.cache_pending).map_err(text_error)?;
    let pending = pending.finish().map_err(text_error)?;
    let (authenticated_link, bound, authenticated_link_metrics, receipt) =
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
    if bound.len() != 2 * C61_NATIVE_WRAPPER_ACTIVE_SLOTS {
        return Err("C6.1 native exact runner bound-slot census mismatch".to_owned());
    }
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C61NativeExactProductionNbr2ProverProof {
        blind: C61NativeExactProductionProverProof {
            residual_proof: blind.residual_proof,
            residual_frame: blind.residual_frame,
            residual_terminal_outputs: blind.residual_terminal_outputs,
            residual_terminal_fold,
            cache_proof: blind.cache_proof,
            cache_source_frame: blind.cache_source_frame,
            cache_metrics: blind.cache_metrics,
            authenticated_link,
            authenticated_link_metrics,
        },
        joint_native,
        nbr2_statement_digest: nbr2.digest(),
        outer_statement_digest: nbr2.outer_statement_digest(),
    })
}

/// C6.2 join for the hidden-free blind proof and the receipt-gated C62JVR1
/// secondary tail. The C6NBR2 receipt and C62JVR1 relation are from one
/// public statement.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c62_native_production_blind_with_persisted_nbr2_link(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C61NativeProductionBlindProverOutput,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    terminal: &C61NativeTerminalCompilerPrepared,
    native: C62ProductionJointNativeProverLinkPending,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C62NativeExactProductionNbr2ProverProof, String> {
    validate_production_streams(streams)?;
    if roots.session_digest() != session_digest {
        return Err("C6.2 native exact runner root/session mismatch".to_owned());
    }
    if terminal.public_output.terminal_claims()
        != blind.residual_terminal_outputs.terminal_functionals()
        || terminal.inputs.relation_root() != blind.residual_terminal_outputs.digest()
    {
        return Err("C6.2 native public typestate differs from residual outputs".to_owned());
    }
    let residual_terminal_fold = blind
        .residual_terminal_outputs
        .clone()
        .bind_output_beta(terminal.public_output.output_beta());
    let mut pending =
        C61NativePendingSlotRegistryProverBuilder::new(roots.fixed()).map_err(text_error)?;
    pending.absorb_residual(&blind.residual_pending).map_err(text_error)?;
    pending.absorb_persistent_cache(&blind.cache_pending).map_err(text_error)?;
    let pending = pending.finish().map_err(text_error)?;
    let (authenticated_link, bound, authenticated_link_metrics, receipt) =
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
    if bound.len() != 2 * C61_NATIVE_WRAPPER_ACTIVE_SLOTS {
        return Err("C6.2 native exact runner bound-slot census mismatch".to_owned());
    }
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C62NativeExactProductionNbr2ProverProof {
        blind: C61NativeExactProductionProverProof {
            residual_proof: blind.residual_proof,
            residual_frame: blind.residual_frame,
            residual_terminal_outputs: blind.residual_terminal_outputs,
            residual_terminal_fold,
            cache_proof: blind.cache_proof,
            cache_source_frame: blind.cache_source_frame,
            cache_metrics: blind.cache_metrics,
            authenticated_link,
            authenticated_link_metrics,
        },
        joint_native,
        nbr2_statement_digest: nbr2.digest(),
        outer_statement_digest: nbr2.outer_statement_digest(),
    })
}

/// Close the residual-only C6.3 prefix, its two resident correction
/// functionals and the inherited C6.2 native tail in one typed operation.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c63_production_blind_with_persisted_link(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C63ProductionBlindProverOutput,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    source: C63ResidentSourceFunctionalClaims,
    terminal: &C61NativeTerminalCompilerPrepared,
    native: C62ProductionJointNativeProverLinkPending,
    streams: &mut [CorrelationStream; TAPES],
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C63ExactProductionProverProof, String> {
    validate_production_streams(streams)?;
    if roots.session_digest() != session_digest
        || terminal.public_output.terminal_claims()
            != blind.residual_terminal_outputs.terminal_functionals()
        || terminal.inputs.relation_root() != blind.residual_terminal_outputs.digest()
        || nbr2.outer_statement_digest() != source.claims.statement().outer_statement_digest()
    {
        return Err("C6.3 exact runner statement or terminal binding differs".to_owned());
    }
    let residual_terminal_fold = blind
        .residual_terminal_outputs
        .clone()
        .bind_output_beta(terminal.public_output.output_beta());
    let mut pending = C63AuthenticatedSketchPendingSlotRegistryProverBuilder::new(roots.fixed())
        .map_err(text_error)?;
    pending.absorb_residual(&blind.residual_pending).map_err(text_error)?;
    let pending = pending.finish().map_err(text_error)?;
    let C63ResidentSourceFunctionalClaims { claims, frame } = source;
    let source_functional_statement_digest = claims.statement().digest();
    let (authenticated_link, bound, authenticated_link_metrics, receipt, source_receipt) =
        prove_c63_authenticated_output_link_persisted_cuda_nbr2_strict(
            roots.fixed(),
            roots.cohorts(),
            pending,
            nbr2,
            &claims,
            streams,
            backend,
            spill_root,
            session_digest,
            transcript,
        )
        .map_err(text_error)?;
    if bound.len() != 2 * C63_AUTHENTICATED_SKETCH_WRAPPER_ACTIVE_SLOTS
        || source_receipt.statement_digest() != source_functional_statement_digest
    {
        return Err("C6.3 exact runner link census or source receipt differs".to_owned());
    }
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C63ExactProductionProverProof {
        residual_proof: blind.residual_proof,
        residual_frame: blind.residual_frame,
        residual_terminal_outputs: blind.residual_terminal_outputs,
        residual_terminal_fold,
        source_functional_frame: frame,
        authenticated_link,
        authenticated_link_metrics,
        joint_native,
        nbr2_statement_digest: nbr2.digest(),
        source_functional_statement_digest,
        outer_statement_digest: nbr2.outer_statement_digest(),
    })
}

/// Close the C6.4 residual prefix with the pre-challenge projected PCS. The
/// old residual wrapper/output-link is absent; its two cache functionals are
/// linked directly to the committed correction polynomial.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn finish_c64_production_blind_with_projected_residual<R: rand_010::Rng>(
    roots: &C6PersistedLiveWrapperRootBinding,
    mut blind: C64ProductionBlindProverOutput,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    source: C63ResidentSourceFunctionalClaims,
    terminal: &C61NativeTerminalCompilerPrepared,
    native: C62ProductionJointNativeProverLinkPending,
    mask_range: crate::c61_authenticated_whir::C64AuthenticatedWhirMaskRange,
    streams: &mut [CorrelationStream; TAPES],
    session_digest: [u8; 32],
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<C64ExactProductionProverProof, String> {
    validate_production_streams(streams)?;
    if roots.session_digest() != session_digest
        || terminal.public_output.terminal_claims()
            != blind.blind.residual_terminal_outputs.terminal_functionals()
        || terminal.inputs.relation_root() != blind.blind.residual_terminal_outputs.digest()
    {
        return Err("C6.4 exact runner statement or terminal binding differs".to_owned());
    }
    let residual_terminal_fold = blind
        .blind
        .residual_terminal_outputs
        .clone()
        .bind_output_beta(terminal.public_output.output_beta());
    let (source_claims, source_functional_frame) = source.into_parts();
    if nbr2.outer_statement_digest() != source_claims.statement().outer_statement_digest() {
        return Err("C6.4 source functional outer statement differs".to_owned());
    }
    let pending_digest = crate::c64_joint_residual_sketch::c64_projected_pending_digest(
        &blind.blind.residual_pending,
    )?;
    let source_statement_digest = source_claims.statement().digest();
    let (correction_beta, batch_alphas) =
        crate::c64_projected_residual_suffix::draw_c64_projected_residual_postclaim_challenges(
            blind.precommit.roots,
            pending_digest,
            source_statement_digest,
            transcript,
        )?;
    let coefficients = [
        source_claims.statement().coefficients(0).map_err(text_error)?,
        source_claims.statement().coefficients(1).map_err(text_error)?,
    ];
    let coefficient_digest = crate::c63_sparse_h_closure::c64_correction_link_coefficient_digest(
        coefficients,
        correction_beta,
        1 << 23,
    )
    .map_err(text_error)?;
    let mut binding = blake3::Hasher::new_derive_key("volta-zk/c64/correction-link-binding/v1");
    binding.update(&roots.fixed().binding_digest());
    binding.update(&nbr2.digest());
    binding.update(&source_statement_digest);
    for root in blind.precommit.roots {
        binding.update(&root);
    }
    let correction_binding_digest = *binding.finalize().as_bytes();
    let statement = crate::c63_sparse_h_closure::C64TerminalLinkStatement::new(
        correction_binding_digest,
        coefficient_digest,
        pending_digest,
        24,
    )
    .map_err(text_error)?;
    let initial_claims = std::array::from_fn(|tape| {
        source_claims.claims()[0][tape].add(source_claims.claims()[1][tape].scale(correction_beta))
    });
    let correction_message = blind
        .precommit
        .correction_message
        .take()
        .ok_or_else(|| "C6.4 correction message is absent".to_owned())?;
    let (correction_link, correction_link_point, correction_link_targets) =
        crate::c63_sparse_h_closure::prove_c64_correction_link_resident(
            std::sync::Arc::clone(&blind.precommit.backend),
            coefficients,
            correction_beta,
            correction_message,
            initial_claims,
            &statement,
            streams,
            transcript,
        )
        .map_err(text_error)?;
    let projected_pending = crate::c64_joint_residual_sketch::fold_c64_projected_pending_prover(
        &blind.blind.residual_pending,
        blind.precommit.weights.leaf(),
        blind.precommit.weights.auxiliary(),
    )?;
    let correction_pending = crate::c64_joint_residual_sketch::c64_correction_pending_prover(
        &blind.blind.residual_pending,
    )?;
    let projected_roots = blind.precommit.roots;
    let projected_output =
        crate::c64_projected_residual_suffix::finish_c64_projected_residual_precommit(
            blind.precommit,
            projected_pending,
            correction_pending,
            [
                blind.blind.residual_terminal_outputs.leaf_point(0).map_err(text_error)?,
                blind.blind.residual_terminal_outputs.leaf_point(1).map_err(text_error)?,
            ],
            [
                blind.blind.residual_terminal_outputs.auxiliary_point(0).map_err(text_error)?,
                blind.blind.residual_terminal_outputs.auxiliary_point(1).map_err(text_error)?,
            ],
            &correction_link_point,
            correction_link_targets,
            correction_link,
            batch_alphas,
            mask_range,
            streams,
            rng,
        )?;
    let projected = crate::c64_projected_residual_codec::C64ProjectedResidualFrame::from_output(
        correction_binding_digest,
        projected_roots,
        projected_output,
    )?;
    let (receipt, source_receipt) =
        crate::c6_authenticated_output_link::c64_projected_residual_proved_links(
            &projected,
            nbr2.digest(),
            source_statement_digest,
        )
        .map_err(text_error)?;
    if source_receipt.statement_digest() != source_statement_digest {
        return Err("C6.4 source receipt differs".to_owned());
    }
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C64ExactProductionProverProof {
        residual_proof: blind.blind.residual_proof,
        residual_frame: blind.blind.residual_frame,
        residual_terminal_outputs: blind.blind.residual_terminal_outputs,
        residual_terminal_fold,
        source_functional_frame,
        projected,
        joint_native,
        nbr2_statement_digest: nbr2.digest(),
        source_functional_statement_digest: source_statement_digest,
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

/// Consume the hidden-free native owners into C6PA2 plus the strict C61PIF2
/// six-component envelope. Historical proof bytes are not an input.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn assemble_c61_native_exact_production_nbr2_certificate(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    profile: &volta_mac::C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: crate::c61_public_compression::C61ArithmeticFrame,
    statements: &[C6BlindResidualStatement],
    cache_fold_target_frame: &[u8],
    fixed: &C6FixedWrapperCommitments,
    proof: C61NativeExactProductionNbr2ProverProof,
) -> Result<C61NativeExactProductionNbr2Certificate, String> {
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
        return Err(
            "native C6PA2 statement differs from the proved C6NBR2 outer binding".to_owned()
        );
    }
    let proof_envelope = C61NativeResponseProofEnvelope::new(
        proof.blind.residual_proof.encode(statements).map_err(text_error)?,
        proof.blind.residual_frame.encode().map_err(text_error)?,
        proof.blind.cache_source_frame.encode().map_err(text_error)?,
        proof.blind.cache_proof.encode().map_err(text_error)?,
        cache_fold_target_frame.to_vec(),
        proof.blind.authenticated_link.canonical_bytes(fixed).map_err(text_error)?,
    )
    .map_err(text_error)?
    .encode()
    .map_err(text_error)?;
    Ok(C61NativeExactProductionNbr2Certificate {
        blind: proof.blind,
        public_argument,
        proof_envelope,
    })
}

/// Consume the C6.2 native owners into C62PA1 and C62PIF1. C6.1 wire
/// objects are not accepted by either codec.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn assemble_c62_native_exact_production_nbr2_certificate(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    response_binding_digest: [u8; 32],
    root_binding_digest: [u8; 32],
    profile: &volta_mac::C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: crate::c61_public_compression::C61ArithmeticFrame,
    product_coordinate_one: &[u8],
    statements: &[C6BlindResidualStatement],
    cache_fold_target_frame: &[u8],
    fixed: &C6FixedWrapperCommitments,
    proof: C62NativeExactProductionNbr2ProverProof,
) -> Result<C62NativeExactProductionNbr2Certificate, String> {
    if proof.nbr2_statement_digest == [0; 32] {
        return Err("C6.2 exact assembly has an empty C6NBR2 statement".to_owned());
    }
    let outer_statement_digest = proof.outer_statement_digest;
    let public_argument = assemble_c62_production_public_argument_from_executions(
        base_statement_digest,
        native_profile_digest,
        functional_digest,
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        proof.joint_native,
        compiler,
        arithmetic,
    )?;
    if public_argument.argument().statement_digest() != outer_statement_digest {
        return Err("C62PA1 statement differs from the proved C6NBR2 outer binding".to_owned());
    }
    let proof_envelope = C62ResponseProofEnvelope::new(
        proof.blind.residual_proof.encode(statements).map_err(text_error)?,
        product_coordinate_one.to_vec(),
        proof.blind.residual_frame.encode().map_err(text_error)?,
        proof.blind.cache_source_frame.encode().map_err(text_error)?,
        proof.blind.cache_proof.encode().map_err(text_error)?,
        cache_fold_target_frame.to_vec(),
        proof.blind.authenticated_link.canonical_bytes(fixed).map_err(text_error)?,
    )
    .map_err(text_error)?
    .encode()
    .map_err(text_error)?;
    Ok(C62NativeExactProductionNbr2Certificate {
        blind: proof.blind,
        public_argument,
        proof_envelope,
    })
}

/// Assemble the two C6.3 certificate payloads from the exact joined proof.
/// Final session metadata remains with the campaign boundary; no historical
/// cache-proof component is accepted here.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn assemble_c63_exact_production_components(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    response_binding_digest: [u8; 32],
    root_binding_digest: [u8; 32],
    profile: &volta_mac::C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: crate::c61_public_compression::C61ArithmeticFrame,
    product_coordinate_one: &[u8],
    response_cache_fold_targets: &[u8],
    statements: &[C6BlindResidualStatement],
    fixed: &C6FixedWrapperCommitments,
    proof: C63ExactProductionProverProof,
    sparse_h_closure: &crate::c63_sparse_h_closure::C63SparseHClosureProof,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
) -> Result<(C62ProductionPublicArgumentAssembly, Vec<u8>), String> {
    if proof.nbr2_statement_digest == [0; 32]
        || proof.source_functional_statement_digest == [0; 32]
        || proof.residual_terminal_fold.terminal_outputs_digest()
            != proof.residual_terminal_outputs.digest()
        || arithmetic.terminal_claims != *proof.residual_terminal_outputs.terminal_functionals()
    {
        return Err("C6.3 exact assembly has a noncanonical terminal binding".to_owned());
    }
    let public_argument = assemble_c62_production_public_argument_from_executions(
        base_statement_digest,
        native_profile_digest,
        functional_digest,
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        proof.joint_native,
        compiler,
        arithmetic,
    )?;
    if public_argument.argument().statement_digest() != proof.outer_statement_digest {
        return Err("C6.3 inherited public argument differs from the exact link".to_owned());
    }
    let response_tail = crate::assemble_c63_response_tail(
        fixed,
        proof.residual_proof.encode(statements).map_err(text_error)?,
        product_coordinate_one.to_vec(),
        proof.residual_frame.encode().map_err(text_error)?,
        response_cache_fold_targets.to_vec(),
        proof.source_functional_frame,
        &proof.authenticated_link,
        sparse_h_closure,
        terminal_proofs,
    )?;
    Ok((public_argument, response_tail))
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn assemble_c64_exact_production_components(
    base_statement_digest: [u8; 32],
    native_profile_digest: [u8; 32],
    functional_digest: [u8; 32],
    response_binding_digest: [u8; 32],
    root_binding_digest: [u8; 32],
    profile: &volta_mac::C6CanonicalTargetProfile,
    primary: [C61ProductionCommittedChainExecution; 2],
    compiler: [C61ProductionCompilerChainExecution; 2],
    arithmetic: crate::c61_public_compression::C61ArithmeticFrame,
    product_coordinate_one: &[u8],
    response_cache_fold_targets: &[u8],
    statements: &[C6BlindResidualStatement],
    proof: C64ExactProductionProverProof,
    sparse_h_closure: C63SparseHClosureProof,
    cache_terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
) -> Result<(C62ProductionPublicArgumentAssembly, Vec<u8>), String> {
    if proof.nbr2_statement_digest == [0; 32]
        || proof.source_functional_statement_digest == [0; 32]
        || proof.residual_terminal_fold.terminal_outputs_digest()
            != proof.residual_terminal_outputs.digest()
        || arithmetic.terminal_claims != *proof.residual_terminal_outputs.terminal_functionals()
    {
        return Err("C6.4 exact assembly has a noncanonical terminal binding".to_owned());
    }
    let public_argument = assemble_c62_production_public_argument_from_executions(
        base_statement_digest,
        native_profile_digest,
        functional_digest,
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        proof.joint_native,
        compiler,
        arithmetic,
    )?;
    if public_argument.argument().statement_digest() != proof.outer_statement_digest {
        return Err("C6.4 inherited public argument differs from the projected link".to_owned());
    }
    let response_tail = crate::c64_response_tail::C64DecodedResponseTail {
        residual_sumcheck: proof.residual_proof.encode(statements).map_err(text_error)?,
        product_coordinate_one: product_coordinate_one.to_vec(),
        residual_pending_corrections: proof.residual_frame.encode().map_err(text_error)?,
        response_cache_fold_targets: response_cache_fold_targets.to_vec(),
        source_functional_corrections: proof.source_functional_frame,
        sparse_h_closure,
        cache_whir_terminal_tags: cache_terminal_proofs,
        projected_residual: proof.projected,
    }
    .encode()?;
    Ok((public_argument, response_tail))
}

#[allow(clippy::too_many_arguments)]
fn finish_c6_production_blind_with_persisted_link_inner(
    roots: &C6PersistedLiveWrapperRootBinding,
    blind: C6ProductionBlindProverOutput,
    nbr2: Option<&C6Nbr2CorrectionFunctional<'_>>,
    fixed_output_beta: Option<Fp2>,
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
    let output_beta = fixed_output_beta.unwrap_or_else(|| transcript.challenge_fp2());
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

/// Produce the C6.1 blind components under the two-participant native
/// coordinator. Hidden-u is absent rather than represented by an empty proof.
#[allow(clippy::too_many_arguments)]
pub fn prove_c61_native_production_blind_components<'a>(
    fixed: &C6FixedWrapperCommitments,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedProverTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    predecessor_cache: &C6PersistedCacheSemanticReader,
    successor_cache: &C6PersistedCacheSemanticReader,
    old_len: u16,
    new_len: u16,
    append: &C61NativeCacheAppendOwner,
    statements: &[C6BlindResidualStatement],
    residual_compiler: C6BlindResidualFusedCompilerContext<'a>,
    residual_witness: C6ResidualFusedWitnessView<'a>,
    residual_arena: &'a C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C61NativeProductionBlindProverOutput, String> {
    validate_production_streams(streams)?;
    begin_c6_persistent_cache_production(cache_statement_digest, transcript).map_err(text_error)?;
    begin_c6_blind_residual_prover_stepwise(statements, residual_arena, transcript)
        .map_err(text_error)?;

    let mut cache_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut residual_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
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
                &append.sources,
                &append.masks,
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
        let (point, cache_corrections) = drive_c61_native_blind_prover_rounds(
            fixed,
            &mut cache,
            &mut residual,
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
        .ok_or_else(|| "C6.1 native blind join omitted direct terminal outputs".to_owned())?;
    let (cache_proof, cache_source_frame, cache_pending, cache_metrics) =
        assemble_c6_persistent_cache_production_proof(cache_statement_digest, cache_finished)
            .map_err(text_error)?;
    Ok(C61NativeProductionBlindProverOutput {
        residual_proof,
        residual_frame,
        residual_pending,
        residual_terminal_outputs,
        cache_proof,
        cache_source_frame,
        cache_pending,
        cache_metrics,
    })
}

/// Produce the C6.3 residual-only blind prefix with the existing fused
/// arithmetic. No cache participant, dense cache encoding or hidden owner is
/// admitted to this path.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prove_c63_production_blind_components<'a>(
    statements: &[C6BlindResidualStatement],
    residual_compiler: C6BlindResidualFusedCompilerContext<'a>,
    residual_witness: C6ResidualFusedWitnessView<'a>,
    residual_arena: &'a C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C63ProductionBlindProverOutput, String> {
    validate_production_streams(streams)?;
    let (residual_proof, residual_frame, residual_pending, residual_terminal_outputs) =
        prove_c6_blind_residual_sumchecks_fused_direct(
            statements,
            residual_compiler,
            residual_witness,
            residual_arena,
            streams,
            transcript,
        )
        .map_err(text_error)?;
    Ok(C63ProductionBlindProverOutput {
        residual_proof,
        residual_frame,
        residual_pending,
        residual_terminal_outputs,
    })
}

#[cfg(all(feature = "cuda", feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prove_c64_production_blind_components<'a>(
    precommit: crate::c64_projected_residual_suffix::C64ProjectedResidualPrecommit,
    statements: &[C6BlindResidualStatement],
    residual_compiler: C6BlindResidualFusedCompilerContext<'a>,
    residual_witness: C6ResidualFusedWitnessView<'a>,
    residual_arena: &'a C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<C64ProductionBlindProverOutput, String> {
    let blind = prove_c63_production_blind_components(
        statements,
        residual_compiler,
        residual_witness,
        residual_arena,
        streams,
        transcript,
    )?;
    Ok(C64ProductionBlindProverOutput { blind, precommit })
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

/// Verify the C6.1-native global blind proof and mandatory C6NBR2 link.  The
/// verifier replays only residual and cache participants under the four-root
/// profile; there is no hidden-u proof input or compatibility path.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn verify_c61_native_exact_production_nbr2_proof(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append: &C61NativeCacheAppendVerifierOwner,
    statements: &[C6BlindResidualStatement],
    proof: &C61NativeExactProductionNbr2ProverProof,
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2VerifierOutput, String> {
    if proof.outer_statement_digest != nbr2.outer_statement_digest()
        || proof.nbr2_statement_digest != nbr2.digest()
    {
        return Err("C6.1 native prover output differs from the verifier C6NBR2 binding".to_owned());
    }
    let pending = verify_c61_native_production_blind_pending(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        &append.base_keys,
        statements,
        C61NativeExactProductionVerifierProof::from_local(&proof.blind),
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
    let blind = c61_native_exact_bound_slot_output(bound.len())?;
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
    if certificate.public_argument.argument().statement_digest() != nbr2.outer_statement_digest() {
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

/// Replay the strict disk blind prefix and then reproduce the provider's
/// terminal order: claims, beta, C6TFR1 root, and runtime challenges. The
/// compiler/link verifier receives only this continuation.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_native_decoded_blind_verifier(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append: &C61NativeCacheAppendVerifierOwner,
    statements: &[C6BlindResidualStatement],
    proof: &C61NativeDecodedExactProductionBlindProof,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    equality: C61EqualityDrawn,
    arithmetic: &crate::c61_public_compression::C61ArithmeticFrame,
    canonical_runtime: &[Fp2],
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C61NativeDecodedBlindVerifierPending, String> {
    let (pending, leaf_points, auxiliary_points) =
        verify_c61_native_production_blind_pending_with_terminal_points(
            roots,
            cache_statement_digest,
            cache_snapshot,
            cache_targets,
            cache_fixed_targets,
            old_len,
            new_len,
            &append.base_keys,
            statements,
            proof.verifier_view(&arithmetic.terminal_claims),
            contexts,
            transcript,
        )?;
    let outputs = C6BlindResidualDirectTerminalOutputs::from_verifier_claims(
        statements,
        relation,
        leaf_points,
        auxiliary_points,
        arithmetic.terminal_claims,
    )
    .map_err(text_error)?;
    let public_output = equality
        .fix_terminal_claims(arithmetic.terminal_claims, transcript)
        .draw_output_challenge(transcript);
    let inputs = terminal_compiler_inputs(&outputs, public_output.output_beta())?;
    let ready = public_output
        .fix_adjoint_root(inputs.relation_root(), transcript)
        .map_err(text_error)?
        .draw_runtime_challenges(transcript);
    crate::verify_c61_production_arithmetic_frame(
        &ready,
        arithmetic.statement_digest,
        canonical_runtime,
        arithmetic,
    )
    .map_err(text_error)?;
    if inputs.relation_challenges_digest() != relation.digest()
        || inputs.functional_fold() != arithmetic.source_boundary
    {
        return Err("decoded C6RSC4 differs from the replayed terminal relation".to_owned());
    }
    Ok(C6ResidualDecodedBlindVerifierPending { pending, residual_pending: None, ready, inputs })
}

/// Replay the C6.3 residual-only blind prefix. Cache state has moved to the
/// authenticated sketch, so no cache or hidden participant is accepted here.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c63_decoded_blind_verifier(
    roots: &C6VerifierLiveWrapperRootBinding,
    statements: &[C6BlindResidualStatement],
    residual_proof: &C6BlindResidualSumcheckProof,
    residual_frame: &C6BlindResidualPendingTransferFrame,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    equality: C61EqualityDrawn,
    arithmetic: &crate::c61_public_compression::C61ArithmeticFrame,
    canonical_runtime: &[Fp2],
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ResidualDecodedBlindVerifierPending, String> {
    validate_production_contexts(contexts)?;
    let (residual_pending, leaf_points, auxiliary_points) =
        verify_c6_blind_residual_sumchecks_direct_claims_with_points(
            statements,
            residual_proof,
            residual_frame,
            &arithmetic.terminal_claims,
            contexts,
            transcript,
        )
        .map_err(text_error)?;
    let mut pending = C63AuthenticatedSketchPendingSlotRegistryVerifierBuilder::new(roots.fixed())
        .map_err(text_error)?;
    pending.absorb_residual(&residual_pending).map_err(text_error)?;
    let pending = pending.finish().map_err(text_error)?;
    let outputs = C6BlindResidualDirectTerminalOutputs::from_verifier_claims(
        statements,
        relation,
        leaf_points,
        auxiliary_points,
        arithmetic.terminal_claims,
    )
    .map_err(text_error)?;
    let public_output = equality
        .fix_terminal_claims(arithmetic.terminal_claims, transcript)
        .draw_output_challenge(transcript);
    let inputs = terminal_compiler_inputs(&outputs, public_output.output_beta())?;
    let ready = public_output
        .fix_adjoint_root(inputs.relation_root(), transcript)
        .map_err(text_error)?
        .draw_runtime_challenges(transcript);
    crate::verify_c61_production_arithmetic_frame(
        &ready,
        arithmetic.statement_digest,
        canonical_runtime,
        arithmetic,
    )
    .map_err(text_error)?;
    if inputs.relation_challenges_digest() != relation.digest()
        || inputs.functional_fold() != arithmetic.source_boundary
    {
        return Err("decoded C6.3 residual differs from the terminal relation".to_owned());
    }
    Ok(C6ResidualDecodedBlindVerifierPending {
        pending,
        residual_pending: Some(residual_pending),
        ready,
        inputs,
    })
}

/// Consume the exact disk blind continuation only after compiler/native
/// verification has prepared the matching C6NBR2-gated joint tail.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c61_native_decoded_nbr2_verifier(
    roots: &C6VerifierLiveWrapperRootBinding,
    blind: C61NativeDecodedBlindVerifierPending,
    proof: &C61NativeDecodedExactProductionBlindProof,
    public_argument_statement_digest: [u8; 32],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C61ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6ExactProductionNbr2VerifierOutput, String> {
    if public_argument_statement_digest != nbr2.outer_statement_digest() {
        return Err("decoded native C6PA2 statement differs from the C6NBR2 binding".to_owned());
    }
    let (bound, receipt) = verify_c6_authenticated_output_link_production_nbr2_strict(
        roots.fixed(),
        blind.pending,
        &proof.authenticated_link,
        nbr2,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    let blind = c61_native_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C6ExactProductionNbr2VerifierOutput { blind, joint_native })
}

/// Complete the decoded C6.2 blind verifier and release C62JVR1 only after
/// the matching C6NBR2 proof verifies.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c62_native_decoded_nbr2_verifier(
    roots: &C6VerifierLiveWrapperRootBinding,
    blind: C61NativeDecodedBlindVerifierPending,
    proof: &C61NativeDecodedExactProductionBlindProof,
    public_argument_statement_digest: [u8; 32],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    native: C62ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C62ExactProductionNbr2VerifierOutput, String> {
    if public_argument_statement_digest != nbr2.outer_statement_digest() {
        return Err("decoded C62PA1 statement differs from the C6NBR2 binding".to_owned());
    }
    let (bound, receipt) = verify_c6_authenticated_output_link_production_nbr2_strict(
        roots.fixed(),
        blind.pending,
        &proof.authenticated_link,
        nbr2,
        contexts,
        transcript,
    )
    .map_err(text_error)?;
    let blind = c61_native_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C62ExactProductionNbr2VerifierOutput { blind, joint_native })
}

/// Close the C6.3 residual-only link and retain the authenticated systematic
/// opening receipt for the subsequent sparse/WHIR suffix.
#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub fn finish_c63_decoded_verifier(
    roots: &C6VerifierLiveWrapperRootBinding,
    blind: C6ResidualDecodedBlindVerifierPending,
    authenticated_link: &C6AuthenticatedOutputLinkProof,
    public_argument_statement_digest: [u8; 32],
    nbr2: &C6Nbr2CorrectionFunctional<'_>,
    source_functionals: &C63ResidualSourceFunctionalVerifierClaims,
    native: C62ProductionJointNativeVerifierLinkPending,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C63ExactProductionVerifierOutput, String> {
    if public_argument_statement_digest != nbr2.outer_statement_digest()
        || public_argument_statement_digest
            != source_functionals.statement().outer_statement_digest()
    {
        return Err("decoded C6.3 public argument differs from the link statements".to_owned());
    }
    let (bound, receipt, source_link) =
        verify_c63_authenticated_output_link_production_nbr2_strict(
            roots.fixed(),
            blind.pending,
            authenticated_link,
            nbr2,
            source_functionals,
            contexts,
            transcript,
        )
        .map_err(text_error)?;
    let blind = c63_exact_bound_slot_output(bound.len())?;
    let joint_native = native.finish_after_nbr2_link(receipt)?;
    Ok(C63ExactProductionVerifierOutput {
        inherited: C62ExactProductionNbr2VerifierOutput { blind, joint_native },
        source_link,
    })
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

#[allow(clippy::too_many_arguments)]
fn verify_c61_native_production_blind_pending_with_terminal_points(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    proof: C61NativeExactProductionVerifierProof<'_>,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<
    (
        C6PendingSlotRegistryVerifier,
        [Vec<Fp2>; C6_WRAPPER_REPETITIONS],
        [Vec<Fp2>; C6_WRAPPER_REPETITIONS],
    ),
    String,
> {
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

    let mut cache_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut residual_finished = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut leaf_points = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut auxiliary_points = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
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
            proof.residual_proof,
        )
        .map_err(text_error)?;
        let cache_corrections = proof
            .cache_proof
            .production_round_corrections(usize::from(repetition))
            .map_err(text_error)?;
        let point = drive_c61_native_blind_verifier_rounds(
            roots.fixed(),
            &mut cache,
            cache_corrections,
            &mut residual,
            contexts,
            transcript,
        )?;
        let (leaf_point, auxiliary_point) = residual.terminal_points().map_err(text_error)?;
        leaf_points.push(leaf_point);
        auxiliary_points.push(auxiliary_point);
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
    }

    let (cache_pending, _) =
        assemble_c6_persistent_cache_production_verifier_pending(cache_finished)
            .map_err(text_error)?;
    let residual_pending =
        assemble_c6_blind_residual_verifier_stepwise(residual_finished, transcript)
            .map_err(text_error)?;
    let pending = finish_c61_native_pending_registry_verifier(
        roots.fixed(),
        &residual_pending,
        &cache_pending,
    )?;
    Ok((
        pending,
        leaf_points.try_into().map_err(|_| "C6.1 native verifier leaf-point census differs")?,
        auxiliary_points
            .try_into()
            .map_err(|_| "C6.1 native verifier auxiliary-point census differs")?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_c61_native_production_blind_pending(
    roots: &C6VerifierLiveWrapperRootBinding,
    cache_statement_digest: [u8; 32],
    cache_snapshot: &C6CacheFoldTraceSnapshot,
    cache_targets: &C6CacheFoldPairedVerifierTargets,
    cache_fixed_targets: &C6CacheFoldTargetFixedCorrections,
    old_len: u16,
    new_len: u16,
    append_base_keys: &[Vec<[volta_mac::VerifierKey; TAPES]>; 2],
    statements: &[C6BlindResidualStatement],
    proof: C61NativeExactProductionVerifierProof<'_>,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6PendingSlotRegistryVerifier, String> {
    let (pending, _, _) = verify_c61_native_production_blind_pending_with_terminal_points(
        roots,
        cache_statement_digest,
        cache_snapshot,
        cache_targets,
        cache_fixed_targets,
        old_len,
        new_len,
        append_base_keys,
        statements,
        proof,
        contexts,
        transcript,
    )?;
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
        return Err("C6.1 native verifier terminal output-fold mismatch".to_owned());
    }
    Ok(pending)
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

fn c61_native_exact_bound_slot_output(
    bound_slots: usize,
) -> Result<C6ExactProductionVerifierOutput, String> {
    let bound_slots = bound_slots as u64;
    if bound_slots != 2 * C61_NATIVE_WRAPPER_ACTIVE_SLOTS as u64 {
        return Err("C6.1 native verifier bound-slot census mismatch".to_owned());
    }
    Ok(C6ExactProductionVerifierOutput { bound_slots })
}

fn c63_exact_bound_slot_output(
    bound_slots: usize,
) -> Result<C6ExactProductionVerifierOutput, String> {
    let bound_slots = bound_slots as u64;
    if bound_slots
        != 2 * crate::c6_wrapper_pcs::C63_AUTHENTICATED_SKETCH_WRAPPER_ACTIVE_SLOTS as u64
    {
        return Err("C6.3 verifier bound-slot census mismatch".to_owned());
    }
    Ok(C6ExactProductionVerifierOutput { bound_slots })
}

fn finish_c61_native_pending_registry_verifier(
    fixed: &C6FixedWrapperCommitments,
    residual: &C6BlindResidualPendingClaimsVerifier,
    cache: &C6PersistentCachePendingClaimsVerifier,
) -> Result<C6PendingSlotRegistryVerifier, String> {
    let mut pending =
        C61NativePendingSlotRegistryVerifierBuilder::new(fixed).map_err(text_error)?;
    pending.absorb_residual(residual).map_err(text_error)?;
    pending.absorb_persistent_cache(cache).map_err(text_error)?;
    pending.finish().map_err(text_error)
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

fn c61_native_receipts(
    ids: &[u32],
    residual_bytes: Option<u64>,
) -> Result<Vec<C6WrapperRoundMessageReceipt>, String> {
    ids.iter()
        .map(|&participant_id| {
            let message_bytes = match participant_id {
                C6_CACHE_ROUND_PARTICIPANT_ID => C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
                C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID => residual_bytes
                    .ok_or_else(|| "missing active C6.1 residual message".to_owned())?,
                _ => return Err("unknown C6.1 native blind-round participant".to_owned()),
            };
            Ok(C6WrapperRoundMessageReceipt { participant_id, message_bytes })
        })
        .collect()
}

fn validate_c61_native_schedule(
    repetition: u8,
    cache_repetition: u8,
    cache_round: usize,
    residual_repetition: u8,
    residual_round: usize,
    residual_rounds: usize,
) -> Result<(), String> {
    if cache_repetition != repetition
        || residual_repetition != repetition
        || cache_round != 0
        || residual_round != 0
        || residual_rounds != C6_WRAPPER_RANDOM_POINT_LEN - C6_DELTA_RESIDUAL_ACTIVATION_ROUND
    {
        return Err("C6.1 native blind coordinator participant schedule mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn drive_c61_native_blind_prover_rounds(
    fixed: &C6FixedWrapperCommitments,
    cache: &mut C6PersistentCacheProductionPreparedProver<'_>,
    residual: &mut C6BlindResidualProverRoundState<'_>,
    streams: &mut [CorrelationStream; TAPES],
    transcript: &mut Transcript,
) -> Result<(C6WrapperRoundPoint, Vec<[[Fp2; 2]; TAPES]>), String> {
    let repetition = cache.round_state.repetition();
    validate_c61_native_schedule(
        repetition,
        repetition,
        cache.round_state.round_index(),
        residual.repetition(),
        residual.round_index(),
        residual.round_count(),
    )?;
    let mut coordinator =
        C61NativeWrapperRoundCoordinator::new(fixed, repetition).map_err(text_error)?;
    let mut cache_corrections = Vec::with_capacity(C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS);
    while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
        let global_round = coordinator.round_index();
        if cache.round_state.round_index() != global_round
            || (global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND
                && residual.round_index() != global_round - C6_DELTA_RESIDUAL_ACTIVATION_ROUND)
        {
            return Err("C6.1 native blind prover participant round drift".to_owned());
        }
        let cache_message = cache.round_state.fix_next_round(streams).map_err(text_error)?;
        let residual_message = if global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND {
            Some(residual.fix_next_round(streams).map_err(text_error)?)
        } else {
            None
        };
        let ids = coordinator.expected_participant_ids().map_err(text_error)?;
        let receipts =
            c61_native_receipts(&ids, residual_message.map(|message| message.message_bytes))?;
        let challenge = coordinator
            .fix_messages_and_release_challenge(&receipts, transcript)
            .map_err(text_error)?;
        cache.round_state.bind_challenge(challenge).map_err(text_error)?;
        if residual_message.is_some() {
            residual.bind_challenge(challenge).map_err(text_error)?;
        }
        coordinator.confirm_participants_bound(&ids).map_err(text_error)?;
        cache_corrections.push(cache_message);
    }
    let point = coordinator.finish().map_err(text_error)?;
    if cache_corrections.len() != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
        return Err("C6.1 native prover cache round census mismatch".to_owned());
    }
    Ok((point, cache_corrections))
}

pub(crate) fn drive_c61_native_blind_verifier_rounds(
    fixed: &C6FixedWrapperCommitments,
    cache: &mut C6PersistentCacheProductionVerifierRoundState<'_>,
    cache_corrections: &[[[Fp2; 2]; TAPES]],
    residual: &mut C6BlindResidualVerifierRoundState<'_>,
    contexts: &mut [VerifierCtx; TAPES],
    transcript: &mut Transcript,
) -> Result<C6WrapperRoundPoint, String> {
    let repetition = cache.repetition();
    validate_c61_native_schedule(
        repetition,
        repetition,
        cache.round_index(),
        residual.repetition(),
        residual.round_index(),
        residual.round_count(),
    )?;
    if cache_corrections.len() != C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS {
        return Err("C6.1 native verifier cache round census mismatch".to_owned());
    }
    let mut coordinator =
        C61NativeWrapperRoundCoordinator::new(fixed, repetition).map_err(text_error)?;
    while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
        let global_round = coordinator.round_index();
        if cache.round_index() != global_round
            || (global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND
                && residual.round_index() != global_round - C6_DELTA_RESIDUAL_ACTIVATION_ROUND)
        {
            return Err("C6.1 native blind verifier participant round drift".to_owned());
        }
        cache.check_next_round(cache_corrections[global_round], contexts).map_err(text_error)?;
        let residual_message = if global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND {
            Some(residual.check_next_round(contexts).map_err(text_error)?)
        } else {
            None
        };
        let ids = coordinator.expected_participant_ids().map_err(text_error)?;
        let receipts =
            c61_native_receipts(&ids, residual_message.map(|message| message.message_bytes))?;
        let challenge = coordinator
            .fix_messages_and_release_challenge(&receipts, transcript)
            .map_err(text_error)?;
        cache.bind_challenge(challenge).map_err(text_error)?;
        if residual_message.is_some() {
            residual.bind_challenge(challenge).map_err(text_error)?;
        }
        coordinator.confirm_participants_bound(&ids).map_err(text_error)?;
    }
    coordinator.finish().map_err(text_error)
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
            verifier.find("statement_digest() != nbr2.outer_statement_digest()").unwrap()
                < verifier.find("verify_c6_exact_production_blind_pending(").unwrap()
        );
        assert!(
            verifier.find("verify_c6_authenticated_output_link_production_nbr2_strict(").unwrap()
                < verifier.find("native.finish_after_nbr2_link(receipt)").unwrap()
        );
    }

    #[test]
    fn c63_resident_driver_and_complete_verifier_keep_the_link_order() {
        let source = include_str!("c6_blind_round_coordinator.rs");
        let prepare = source
            .split("pub fn prepare_c63_resident_sketch_suffix")
            .nth(1)
            .unwrap()
            .split("pub fn finish_c63_resident_sketch_suffix")
            .next()
            .unwrap();
        assert!(prepare.contains("prove_c63_sparse_h_tape_closure_with_spots_resident("));
        assert!(prepare.contains("authenticate_c63_resident_source_functionals_at_point("));
        assert!(!prepare.contains("prepare_c63_authenticated_whir_limb_pair("));

        let finish = source
            .split("pub fn finish_c63_resident_sketch_suffix")
            .nth(1)
            .unwrap()
            .split("/// Recover the exact K/V append cells")
            .next()
            .unwrap();
        assert!(finish.contains("linked: &C63ExactProductionProverProof"));
        assert!(
            finish.find("source_functional_statement_digest !=").unwrap()
                < finish.find("prepare_c63_authenticated_whir_limb_pair(").unwrap()
        );

        let verifier = source
            .split("pub fn verify_c63_complete_decoded_response")
            .nth(1)
            .unwrap()
            .split("impl C62ExactProductionNbr2VerifierOutput")
            .next()
            .unwrap();
        let sparse = verifier.find("begin_verify_c63_sketch_suffix(").unwrap();
        let source_functional =
            verifier.find("verify_c63_resident_source_functionals_at_pending(").unwrap();
        let link = verifier.find("finish_c63_decoded_verifier(").unwrap();
        let whir = verifier.find("finish_c63_complete_verifier(").unwrap();
        assert!(sparse < source_functional && source_functional < link && link < whir);
    }

    #[test]
    fn c61_native_join_has_no_hidden_owner_and_receipt_gates_native_tail() {
        let source = include_str!("c6_blind_round_coordinator.rs");
        validate_c61_native_schedule(1, 1, 0, 1, 0, 23).unwrap();
        assert!(validate_c61_native_schedule(1, 1, 0, 1, 0, 22).is_err());
        assert!(c61_native_receipts(
            &[C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,],
            Some(96),
        )
        .is_ok());
        assert!(c61_native_receipts(&[C6_HIDDEN_U_ROUND_PARTICIPANT_ID], Some(96)).is_err());

        let blind_prover = source
            .split("pub fn prove_c61_native_production_blind_components<'a>(")
            .nth(1)
            .unwrap()
            .split("/// Witness-free mirror")
            .next()
            .unwrap();
        assert!(blind_prover.contains("drive_c61_native_blind_prover_rounds("));
        assert!(blind_prover.contains("C61NativeProductionBlindProverOutput"));
        assert!(blind_prover.contains("append: &C61NativeCacheAppendOwner"));
        assert!(blind_prover.contains("&append.sources"));
        assert!(blind_prover.contains("&append.masks"));
        assert!(!blind_prover.contains("append_sources:"));
        assert!(!blind_prover.contains("append_masks:"));

        let terminal = source
            .split("pub fn prepare_c61_native_terminal_compiler(")
            .nth(1)
            .unwrap()
            .split("impl C6ExactProductionNbr2ProverProof")
            .next()
            .unwrap();
        assert!(
            terminal.find(".fix_terminal_claims(").unwrap()
                < terminal.find(".draw_output_challenge(").unwrap()
        );
        assert!(
            terminal.find(".fix_adjoint_root(").unwrap()
                < terminal.find(".draw_runtime_challenges(").unwrap()
        );
        for forbidden in ["terminal_claims:", "relation_root:", "functional_fold:"] {
            assert!(!terminal.contains(forbidden));
        }

        let append_materializer = source
            .split("pub fn materialize_c61_native_cache_append_owner(")
            .nth(1)
            .unwrap()
            .split("fn text_error(")
            .next()
            .unwrap();
        for required in [
            "read_slot_range",
            "replay_consumed_sub_masks",
            "draw_sub_tags",
            "authenticate_subfield_sparse_linear",
            "before_counters",
            "before_schedules",
        ] {
            assert!(append_materializer.contains(required));
        }
        let verifier_append_materializer = source
            .split("pub fn materialize_c61_native_cache_append_verifier_owner(")
            .nth(1)
            .unwrap()
            .split("fn text_error(")
            .next()
            .unwrap();
        for required in ["replay_consumed_sub_verifier_keys", "before_counters", "before_schedules"]
        {
            assert!(verifier_append_materializer.contains(required));
        }

        let prover = source
            .split("pub fn finish_c61_native_production_blind_with_persisted_nbr2_link(")
            .nth(1)
            .unwrap()
            .split("/// Consume all remaining same-attempt")
            .next()
            .unwrap();
        assert!(prover.contains("terminal: &C61NativeTerminalCompilerPrepared"));
        assert!(!prover.contains("public_output: &C61OutputChallengeDrawn"));
        assert!(prover.contains("C61NativePendingSlotRegistryProverBuilder::new"));
        assert!(prover.contains("2 * C61_NATIVE_WRAPPER_ACTIVE_SLOTS"));
        assert!(
            prover.find("prove_c6_authenticated_output_link_persisted_cuda_nbr2_strict(").unwrap()
                < prover.find("native.finish_after_nbr2_link(receipt)").unwrap()
        );
        for forbidden in [
            "C6HiddenU",
            "hidden_pending",
            "hidden_proof",
            "absorb_hidden_u",
            "C6PendingSlotRegistryProverBuilder::new",
        ] {
            assert!(!prover.contains(forbidden));
        }

        let production_verifier = source
            .split("pub fn verify_c61_native_exact_production_nbr2_proof(")
            .nth(1)
            .unwrap()
            .split("/// Verify the global blind")
            .next()
            .unwrap();
        assert!(production_verifier.contains("verify_c61_native_production_blind_pending("));
        assert!(production_verifier.contains("append: &C61NativeCacheAppendVerifierOwner"));
        assert!(production_verifier.contains("&append.base_keys"));
        assert!(production_verifier.contains("c61_native_exact_bound_slot_output(bound.len())"));
        assert!(
            production_verifier
                .find("verify_c6_authenticated_output_link_production_nbr2_strict(")
                .unwrap()
                < production_verifier.find("native.finish_after_nbr2_link(receipt)").unwrap()
        );
        for forbidden in ["C6HiddenU", "hidden_", "verify_c6_exact_production_blind_pending("] {
            assert!(!production_verifier.contains(forbidden));
        }

        let blind_verifier = source
            .split("fn verify_c61_native_production_blind_pending_with_terminal_points(")
            .nth(1)
            .unwrap()
            .split("fn verify_c61_native_production_blind_pending(")
            .next()
            .unwrap();
        assert!(blind_verifier.contains("drive_c61_native_blind_verifier_rounds("));
        assert!(blind_verifier.contains("finish_c61_native_pending_registry_verifier("));
        assert!(blind_verifier.contains("residual.terminal_points()"));
        for forbidden in ["C6HiddenU", "hidden_", "absorb_hidden_u"] {
            assert!(!blind_verifier.contains(forbidden));
        }

        let disk_terminal = source
            .split("pub fn prepare_c61_native_decoded_blind_verifier(")
            .nth(1)
            .unwrap()
            .split("pub fn finish_c61_native_decoded_nbr2_verifier(")
            .next()
            .unwrap();
        let blind = disk_terminal
            .find("verify_c61_native_production_blind_pending_with_terminal_points(")
            .unwrap();
        let claims = disk_terminal.find(".fix_terminal_claims(").unwrap();
        let beta = disk_terminal.find(".draw_output_challenge(").unwrap();
        let root = disk_terminal.find(".fix_adjoint_root(").unwrap();
        let runtime = disk_terminal.find(".draw_runtime_challenges(").unwrap();
        assert!(blind < claims && claims < beta && beta < root && root < runtime);

        let assembly = source
            .split("pub fn assemble_c61_native_exact_production_nbr2_certificate(")
            .nth(1)
            .unwrap()
            .split("fn finish_c6_production_blind_with_persisted_link_inner(")
            .next()
            .unwrap();
        assert!(assembly.contains("C61NativeResponseProofEnvelope::new("));
        assert!(assembly.contains("cache_fold_target_frame.to_vec()"));
        for forbidden in ["C6ResponseProofEnvelope::new(", "hidden_", "C6HiddenU"] {
            assert!(!assembly.contains(forbidden));
        }

        let decoder = source
            .split("pub fn decode_c61_native_exact_production_blind_envelope(")
            .nth(1)
            .unwrap()
            .split("impl C6DecodedExactProductionBlindProof")
            .next()
            .unwrap();
        assert!(decoder.contains("C61NativeDecodedExactProductionBlindProof"));
        for forbidden in ["hidden_", "C6HiddenU", ".hidden_u()"] {
            assert!(!decoder.contains(forbidden));
        }

        let verifier = source
            .split("fn finish_c61_native_pending_registry_verifier(")
            .nth(1)
            .unwrap()
            .split("fn validate_production_streams")
            .next()
            .unwrap();
        assert!(verifier.contains("C61NativePendingSlotRegistryVerifierBuilder::new"));
        assert!(!verifier.contains("absorb_hidden_u"));
        assert!(!verifier.contains("C6HiddenU"));
    }
}

#![allow(dead_code)]

use crate::c6_hidden_u::{C6HiddenUPostCommit, C6HiddenUPrequery, C6SealedHiddenUBundle};
use crate::c6_hidden_u_sumcheck_blind::{
    assemble_c6_blind_hidden_u_prover_stepwise, begin_c6_blind_hidden_u_stepwise,
    prepare_c6_blind_hidden_u_prover_round_state, C6BlindHiddenUPendingClaimsProver,
    C6BlindHiddenUProverRoundState, C6BlindHiddenUSumcheckProof, C6BlindHiddenUVerifierRoundState,
};
use crate::c6_persistent_cache_blind::{
    assemble_c6_persistent_cache_production_proof, begin_c6_persistent_cache_production,
    draw_c6_persistent_cache_production_roots,
    finish_c6_persistent_cache_production_prover_repetition,
    fix_c6_persistent_cache_production_fold_prover, C6PersistentCacheBlindProof,
    C6PersistentCachePendingClaimsProver, C6PersistentCacheProductionMetrics,
    C6PersistentCacheProductionPreparedProver, C6PersistentCacheProductionRelationCompiler,
    C6PersistentCacheProductionVerifierRoundState, C6PersistentCacheSourceBootstrapFrame,
    C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS, C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
};
use crate::c6_residual_sumcheck_blind::{
    assemble_c6_blind_residual_prover_stepwise, begin_c6_blind_residual_prover_stepwise,
    prepare_c6_blind_residual_prover_round_state_fused, C6BlindResidualDirectTerminalOutputs,
    C6BlindResidualFusedCompilerContext, C6BlindResidualPendingClaimsProver,
    C6BlindResidualPendingTransferFrame, C6BlindResidualProverRoundState, C6BlindResidualStatement,
    C6BlindResidualSumcheckProof, C6BlindResidualVerifierRoundState,
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
    C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceSnapshot,
};
use volta_proto::{C6ResidualFusedCoefficientArena, C6ResidualFusedWitnessView};

use crate::c6_wrapper_persisted::C6PersistedCacheSemanticReader;

const TAPES: usize = 2;

fn text_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(crate) struct C6ProductionBlindProverOutput {
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

/// Complete prover-side join for the three real blind participants.  Cache
/// preparation remains a callback because its relation roots and point are
/// drawn from this same transcript immediately before each repetition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c6_production_blind_components<'a>(
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

fn validate_production_streams(streams: &[CorrelationStream; TAPES]) -> Result<(), String> {
    if streams.iter().any(|stream| !stream.uses_pooled_pcg()) {
        return Err("C6 exact blind join requires paired pooled PCG streams".to_owned());
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
}

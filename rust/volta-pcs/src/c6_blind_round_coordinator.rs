#![allow(dead_code)]

use crate::c6_hidden_u_sumcheck_blind::{
    C6BlindHiddenUProverRoundState, C6BlindHiddenUVerifierRoundState,
};
use crate::c6_persistent_cache_blind::{
    C6PersistentCacheProductionPreparedProver, C6PersistentCacheProductionVerifierRoundState,
    C6_PERSISTENT_CACHE_BLIND_PRODUCTION_ROUNDS, C6_PERSISTENT_CACHE_BLIND_ROUND_BYTES,
};
use crate::c6_residual_sumcheck_blind::{
    C6BlindResidualProverRoundState, C6BlindResidualVerifierRoundState,
};
use crate::c6_wrapper_pcs::{
    C6FixedWrapperCommitments, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
    C6WrapperRoundPoint, C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ACTIVATION_ROUND,
    C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
    C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND, C6_WRAPPER_RANDOM_POINT_LEN,
};
use volta_field::Fp2;
use volta_mac::{CorrelationStream, Transcript, VerifierCtx};

const TAPES: usize = 2;

fn text_error(error: impl std::fmt::Display) -> String {
    error.to_string()
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

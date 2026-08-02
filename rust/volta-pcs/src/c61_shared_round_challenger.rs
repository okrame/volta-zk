//! Lockstep interactive challenger for the two C6SPR2 compiler oracles.
//!
//! Response and plan remain independently committed D27 polynomials, but
//! every native challenge is released only after both lanes reach the same
//! transcript boundary.  This is reference-only coordination for the
//! feature-gated claimless backend; it is not a production transport.

#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::point::Point;
use volta_field::Fp2;
use volta_mac::Transcript;

use crate::c61_whir_reference::{
    C61Commitment, C61P3Fp2, C61WhirInteractionStats, C61_WHIRA1_DIGEST_BYTES, C61_WHIRA1_FP_BYTES,
};

const SHARED_MESSAGE_LABEL: &str = "c61.shared.native.interactive_message";
const SHARED_FINAL_PAYLOAD_LABEL: &str = "c61.shared.native.final_payload";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengeRequest {
    Field,
    Bits(usize),
}

struct SharedState<'a> {
    transcript: &'a mut Transcript,
    num_variables: usize,
    initial_root_seen: [bool; 2],
    public_statement_bound: [bool; 2],
    public_statement_digest: Option<[u8; 32]>,
    pending_provider_bytes: u64,
    stats: C61WhirInteractionStats,
    generation: u64,
    arrivals: usize,
    request: Option<ChallengeRequest>,
    last_response: u64,
}

struct SharedSync<'a> {
    state: Mutex<SharedState<'a>>,
    ready: Condvar,
}

/// One of the two symmetric provider/verifier lanes.  Cloning preserves the
/// lane identity, as required by generic challenger adapters.
pub(crate) struct C61SharedRoundChallenger<'a> {
    lane: usize,
    shared: Arc<SharedSync<'a>>,
}

impl Clone for C61SharedRoundChallenger<'_> {
    fn clone(&self) -> Self {
        Self { lane: self.lane, shared: Arc::clone(&self.shared) }
    }
}

/// Owner of the one transcript shared by both lanes.
pub(crate) struct C61SharedRoundCoordinator<'a> {
    shared: Arc<SharedSync<'a>>,
}

pub(crate) fn c61_shared_round_pair(
    transcript: &mut Transcript,
    num_variables: usize,
) -> (C61SharedRoundChallenger<'_>, C61SharedRoundChallenger<'_>, C61SharedRoundCoordinator<'_>) {
    let shared = Arc::new(SharedSync {
        state: Mutex::new(SharedState {
            transcript,
            num_variables,
            initial_root_seen: [false; 2],
            public_statement_bound: [false; 2],
            public_statement_digest: None,
            pending_provider_bytes: 0,
            stats: C61WhirInteractionStats::default(),
            generation: 0,
            arrivals: 0,
            request: None,
            last_response: 0,
        }),
        ready: Condvar::new(),
    });
    (
        C61SharedRoundChallenger { lane: 0, shared: Arc::clone(&shared) },
        C61SharedRoundChallenger { lane: 1, shared: Arc::clone(&shared) },
        C61SharedRoundCoordinator { shared },
    )
}

impl<'a> C61SharedRoundChallenger<'a> {
    pub(crate) fn observe_public_points(
        &mut self,
        statement_digest: [u8; 32],
        points: &[Point<C61P3Fp2>],
    ) -> Result<(), String> {
        let mut state = self.lock();
        if !state.initial_root_seen[self.lane]
            || state.public_statement_bound[self.lane]
            || points.is_empty()
            || points.len() > 128
            || points.iter().any(|point| point.num_variables() != state.num_variables)
        {
            return Err("C6SPR2 shared-round public statement shape mismatch".to_owned());
        }
        match state.public_statement_digest {
            Some(bound) if bound != statement_digest => {
                return Err("C6SPR2 shared-round lanes bind different statements".to_owned());
            }
            None => state.public_statement_digest = Some(statement_digest),
            Some(_) => {}
        }
        state.public_statement_bound[self.lane] = true;
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, SharedState<'a>> {
        self.shared.state.lock().expect("C6SPR2 shared challenger mutex poisoned")
    }

    fn shared_challenge(&self, request: ChallengeRequest) -> u64 {
        let mut state = self.lock();
        assert!(state.public_statement_bound[self.lane], "C6SPR2 challenge preceded statement");
        let generation = state.generation;
        match state.request {
            Some(bound) => {
                assert_eq!(bound, request, "C6SPR2 lanes requested different challenges")
            }
            None => state.request = Some(request),
        }
        state.arrivals += 1;
        assert!(state.arrivals <= 2, "C6SPR2 shared challenge received duplicate arrival");
        if state.arrivals == 2 {
            flush_pending(&mut state);
            state.last_response = match request {
                ChallengeRequest::Field => {
                    state.stats.client_fp_challenges += 1;
                    state.stats.client_challenge_payload_bytes += C61_WHIRA1_FP_BYTES as u64;
                    state.transcript.challenge_fp().value()
                }
                ChallengeRequest::Bits(bits) => {
                    assert!((1..=32).contains(&bits), "C6SPR2 query width must fit u32");
                    state.stats.client_query_challenges += 1;
                    state.stats.client_challenge_payload_bytes += 4;
                    u64::from(state.transcript.challenge_bits(bits as u8))
                }
            };
            state.arrivals = 0;
            state.request = None;
            state.generation += 1;
            self.shared.ready.notify_all();
            return state.last_response;
        }
        while state.generation == generation {
            state = self
                .shared
                .ready
                .wait(state)
                .expect("C6SPR2 shared challenger mutex poisoned while waiting");
        }
        state.last_response
    }
}

impl C61SharedRoundCoordinator<'_> {
    /// Fresh post-proof scalar used to aggregate both affine base residuals
    /// before the compiler chain's single designated ZeroOpen.
    pub(crate) fn sample_postproof_fp2(&self) -> Result<Fp2, String> {
        let mut state = self.shared.state.lock().map_err(|_| {
            "C6SPR2 shared challenger mutex poisoned before residual batching".to_owned()
        })?;
        if state.arrivals != 0
            || state.request.is_some()
            || state.public_statement_bound != [true; 2]
        {
            return Err("C6SPR2 lanes did not reach the common post-proof boundary".to_owned());
        }
        flush_pending(&mut state);
        state.stats.client_fp_challenges += 2;
        state.stats.client_challenge_payload_bytes += 16;
        Ok(state.transcript.challenge_fp2())
    }

    pub(crate) fn finish(&self, payload_bytes: usize) -> Result<C61WhirInteractionStats, String> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "C6SPR2 shared challenger mutex poisoned at finish".to_owned())?;
        if state.arrivals != 0
            || state.request.is_some()
            || state.public_statement_bound != [true; 2]
        {
            return Err("C6SPR2 shared challenger finished off the common boundary".to_owned());
        }
        flush_pending(&mut state);
        let payload_bytes = u64::try_from(payload_bytes)
            .map_err(|_| "C6SPR2 shared payload length exceeds u64".to_owned())?;
        if state.stats.provider_semantic_bytes > payload_bytes {
            return Err("C6SPR2 shared semantic bytes exceed strict payload".to_owned());
        }
        let residual = payload_bytes - state.stats.provider_semantic_bytes;
        if residual != 0 {
            state.transcript.append(SHARED_FINAL_PAYLOAD_LABEL, residual);
            state.stats.provider_messages += 1;
        }
        state.stats.provider_payload_bytes = payload_bytes;
        Ok(state.stats)
    }
}

fn flush_pending(state: &mut SharedState<'_>) {
    if state.pending_provider_bytes != 0 {
        state.transcript.append(SHARED_MESSAGE_LABEL, state.pending_provider_bytes);
        state.stats.provider_messages += 1;
        state.pending_provider_bytes = 0;
    }
}

impl CanObserve<Goldilocks> for C61SharedRoundChallenger<'_> {
    fn observe(&mut self, _value: Goldilocks) {
        let mut state = self.lock();
        state.pending_provider_bytes += C61_WHIRA1_FP_BYTES as u64;
        state.stats.provider_semantic_bytes += C61_WHIRA1_FP_BYTES as u64;
    }
}

impl CanObserve<C61Commitment> for C61SharedRoundChallenger<'_> {
    fn observe(&mut self, value: C61Commitment) {
        assert_eq!(value.num_roots(), 1, "C6SPR2 requires cap height zero");
        let mut state = self.lock();
        state.initial_root_seen[self.lane] = true;
        state.pending_provider_bytes += C61_WHIRA1_DIGEST_BYTES as u64;
        state.stats.provider_semantic_bytes += C61_WHIRA1_DIGEST_BYTES as u64;
    }
}

impl CanSample<Goldilocks> for C61SharedRoundChallenger<'_> {
    fn sample(&mut self) -> Goldilocks {
        Goldilocks::new(self.shared_challenge(ChallengeRequest::Field))
    }
}

impl CanSampleBits<usize> for C61SharedRoundChallenger<'_> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.shared_challenge(ChallengeRequest::Bits(bits)) as usize
    }
}

impl CanSampleUniformBits<Goldilocks> for C61SharedRoundChallenger<'_> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61SharedRoundChallenger<'_> {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6SPR2 proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61SharedRoundChallenger<'_> {}

#[cfg(test)]
mod tests {
    use std::thread;

    use p3_challenger::{CanSample, CanSampleBits};

    use super::*;

    #[test]
    fn both_lanes_wait_for_one_shared_challenge_and_one_postproof_batch() {
        let mut transcript = Transcript::new([0x61; 32]);
        let (mut response, mut plan, coordinator) = c61_shared_round_pair(&mut transcript, 4);
        let point = Point::new(vec![C61P3Fp2::ONE; 4]);
        let root = C61Commitment::from(vec![[0x11; 32]]);
        response.observe(root.clone());
        plan.observe(root);
        response.observe_public_points([0xA1; 32], std::slice::from_ref(&point)).unwrap();
        plan.observe_public_points([0xA1; 32], std::slice::from_ref(&point)).unwrap();

        let (response_values, plan_values) = thread::scope(|scope| {
            let response_thread = scope.spawn(move || {
                response.observe(Goldilocks::new(7));
                (response.sample(), response.sample_bits(13))
            });
            let plan_thread = scope.spawn(move || {
                plan.observe(Goldilocks::new(9));
                (plan.sample(), plan.sample_bits(13))
            });
            (response_thread.join().unwrap(), plan_thread.join().unwrap())
        });
        assert_eq!(response_values, plan_values);
        assert_ne!(coordinator.sample_postproof_fp2().unwrap(), Fp2::ZERO);
        let stats = coordinator.finish(80).unwrap();
        assert_eq!(stats.provider_semantic_bytes, 80);
        assert_eq!(stats.provider_payload_bytes, 80);
        assert_eq!(stats.client_fp_challenges, 3);
        assert_eq!(stats.client_query_challenges, 1);
    }
}

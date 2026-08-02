//! Lockstep interactive challenger for the two C6SPR2 compiler oracles.
//!
//! Response and plan remain independently committed polynomials. Challenges
//! at common transcript boundaries are released only after both lanes arrive;
//! once the shorter lane finishes, the longer lane may consume its exact
//! terminal tail from the same transcript. This is reference-only
//! coordination for the feature-gated claimless backend.

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
    lane_dimensions: [usize; 2],
    initial_root_seen: [bool; 2],
    public_statement_bound: [bool; 2],
    public_statement_digest: Option<[u8; 32]>,
    pre_statement_transaction_complete: bool,
    pending_provider_bytes: u64,
    stats: C61WhirInteractionStats,
    generations: [u64; 2],
    arrived: [bool; 2],
    completed: [bool; 2],
    requests: [Option<ChallengeRequest>; 2],
    last_responses: [u64; 2],
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
    lane_dimensions: [usize; 2],
) -> (C61SharedRoundChallenger<'_>, C61SharedRoundChallenger<'_>, C61SharedRoundCoordinator<'_>) {
    let shared = Arc::new(SharedSync {
        state: Mutex::new(SharedState {
            transcript,
            lane_dimensions,
            initial_root_seen: [false; 2],
            public_statement_bound: [false; 2],
            public_statement_digest: None,
            pre_statement_transaction_complete: false,
            pending_provider_bytes: 0,
            stats: C61WhirInteractionStats::default(),
            generations: [0; 2],
            arrived: [false; 2],
            completed: [false; 2],
            requests: [None; 2],
            last_responses: [0; 2],
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
            || points.iter().any(|point| point.num_variables() != state.lane_dimensions[self.lane])
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
        assert!(!state.completed[self.lane], "C6SPR3 completed lane requested a challenge");
        let generation = state.generations[self.lane];
        assert!(!state.arrived[self.lane], "C6SPR2 shared challenge received duplicate arrival");
        assert!(state.requests[self.lane].is_none(), "C6SPR3 lane retained a stale request");
        state.requests[self.lane] = Some(request);
        state.arrived[self.lane] = true;
        if state.arrived == [true; 2] || state.completed[1 - self.lane] {
            release_ready_challenges(&mut state);
            self.shared.ready.notify_all();
            if state.generations[self.lane] != generation {
                return state.last_responses[self.lane];
            }
        }
        while state.generations[self.lane] == generation {
            state = self
                .shared
                .ready
                .wait(state)
                .expect("C6SPR2 shared challenger mutex poisoned while waiting");
        }
        state.last_responses[self.lane]
    }

    pub(crate) fn finish_lane(&self) -> Result<(), String> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "C6SPR3 shared challenger mutex poisoned at lane finish".to_owned())?;
        if !state.public_statement_bound[self.lane]
            || state.completed[self.lane]
            || state.arrived[self.lane]
        {
            return Err("C6SPR3 lane finished from a noncanonical boundary".to_owned());
        }
        state.completed[self.lane] = true;
        let other = 1 - self.lane;
        if state.arrived[other] {
            if state.requests[other].is_none() {
                return Err("C6SPR3 waiting tail challenge has no request".to_owned());
            }
            release_ready_challenges(&mut state);
            self.shared.ready.notify_all();
        }
        Ok(())
    }
}

impl C61SharedRoundCoordinator<'_> {
    /// Run the challenge-dependent compiler relation after both commitment
    /// roots are fixed and before either lane binds its derived opening
    /// points.  This is a one-shot transcript transaction: it cannot be
    /// reopened after success or interleaved with a native WHIR challenge.
    pub(crate) fn with_pre_statement_transcript<T>(
        &self,
        action: impl FnOnce(&mut Transcript) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.shared.state.lock().map_err(|_| {
            "C6SPR3 shared challenger mutex poisoned before pre-statement relation".to_owned()
        })?;
        if state.initial_root_seen != [true; 2]
            || state.public_statement_bound != [false; 2]
            || state.public_statement_digest.is_some()
            || state.pre_statement_transaction_complete
            || state.arrived != [false; 2]
            || state.requests != [None; 2]
            || state.completed != [false; 2]
            || state.generations != [0; 2]
        {
            return Err(
                "C6SPR3 pre-statement relation did not start at the post-root boundary".to_owned()
            );
        }
        flush_pending(&mut state);
        let output = action(state.transcript)?;
        state.pre_statement_transaction_complete = true;
        Ok(output)
    }

    /// Fresh post-proof scalar used to aggregate both affine base residuals
    /// before the compiler chain's single designated ZeroOpen.
    pub(crate) fn sample_postproof_fp2(&self) -> Result<Fp2, String> {
        let mut state = self.shared.state.lock().map_err(|_| {
            "C6SPR2 shared challenger mutex poisoned before residual batching".to_owned()
        })?;
        if state.arrived != [false; 2]
            || state.requests != [None; 2]
            || state.public_statement_bound != [true; 2]
            || state.completed != [true; 2]
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
        if state.arrived != [false; 2]
            || state.requests != [None; 2]
            || state.public_statement_bound != [true; 2]
            || state.completed != [true; 2]
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

fn release_ready_challenges(state: &mut SharedState<'_>) {
    flush_pending(state);
    let active = state
        .requests
        .iter()
        .enumerate()
        .filter_map(|(lane, request)| request.map(|request| (lane, request)))
        .collect::<Vec<_>>();
    assert!(!active.is_empty(), "C6SPR3 challenge release has no active lane");
    match active.as_slice() {
        [(lane, request)] => release_one_challenge(state, *lane, *request),
        [(_, ChallengeRequest::Field), (_, ChallengeRequest::Field)] => {
            state.stats.client_fp_challenges += 1;
            state.stats.client_challenge_payload_bytes += C61_WHIRA1_FP_BYTES as u64;
            let response = state.transcript.challenge_fp().value();
            state.last_responses = [response; 2];
            release_lanes(state, &[0, 1]);
        }
        [(_, ChallengeRequest::Bits(left)), (_, ChallengeRequest::Bits(right))] => {
            let max_bits = (*left).max(*right);
            assert!((1..=32).contains(&max_bits), "C6SPR2 query width must fit u32");
            state.stats.client_query_challenges += 1;
            state.stats.client_challenge_payload_bytes += 4;
            let response = u64::from(state.transcript.challenge_bits(max_bits as u8));
            let project = |bits: usize| {
                if bits == 64 {
                    response
                } else {
                    response & ((1u64 << bits) - 1)
                }
            };
            state.last_responses = [project(*left), project(*right)];
            release_lanes(state, &[0, 1]);
        }
        [(_, _), (_, _)] => {
            assert_ne!(
                state.lane_dimensions[0], state.lane_dimensions[1],
                "C6SPR3 equal-dimension lanes requested different challenge kinds"
            );
            let longer = usize::from(state.lane_dimensions[1] > state.lane_dimensions[0]);
            let request = state.requests[longer]
                .expect("C6SPR3 longer lane has no request at asymmetric boundary");
            release_one_challenge(state, longer, request);
        }
        _ => unreachable!("C6SPR3 active challenge census is impossible"),
    }
}

fn release_one_challenge(state: &mut SharedState<'_>, lane: usize, request: ChallengeRequest) {
    state.last_responses[lane] = match request {
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
    release_lanes(state, &[lane]);
}

fn release_lanes(state: &mut SharedState<'_>, lanes: &[usize]) {
    for &lane in lanes {
        state.arrived[lane] = false;
        state.requests[lane] = None;
        state.generations[lane] += 1;
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
        let (mut response, mut plan, coordinator) = c61_shared_round_pair(&mut transcript, [4, 4]);
        let point = Point::new(vec![C61P3Fp2::ONE; 4]);
        let root = C61Commitment::from(vec![[0x11; 32]]);
        response.observe(root.clone());
        plan.observe(root);
        response.observe_public_points([0xA1; 32], std::slice::from_ref(&point)).unwrap();
        plan.observe_public_points([0xA1; 32], std::slice::from_ref(&point)).unwrap();

        let ((response_values, response), (plan_values, plan)) = thread::scope(|scope| {
            let response_thread = scope.spawn(move || {
                response.observe(Goldilocks::new(7));
                ((response.sample(), response.sample_bits(13)), response)
            });
            let plan_thread = scope.spawn(move || {
                plan.observe(Goldilocks::new(9));
                ((plan.sample(), plan.sample_bits(13)), plan)
            });
            (response_thread.join().unwrap(), plan_thread.join().unwrap())
        });
        assert_eq!(response_values, plan_values);
        response.finish_lane().unwrap();
        plan.finish_lane().unwrap();
        assert_ne!(coordinator.sample_postproof_fp2().unwrap(), Fp2::ZERO);
        let stats = coordinator.finish(80).unwrap();
        assert_eq!(stats.provider_semantic_bytes, 80);
        assert_eq!(stats.provider_payload_bytes, 80);
        assert_eq!(stats.client_fp_challenges, 3);
        assert_eq!(stats.client_query_challenges, 1);
    }

    #[test]
    fn pre_statement_transaction_is_post_root_pre_point_and_one_shot() {
        let mut transcript = Transcript::new([0x63; 32]);
        let (mut response, mut plan, coordinator) = c61_shared_round_pair(&mut transcript, [4, 4]);
        let point = Point::new(vec![C61P3Fp2::ONE; 4]);
        let root = C61Commitment::from(vec![[0x13; 32]]);
        response.observe(root.clone());
        assert!(coordinator.with_pre_statement_transcript(|_| Ok::<_, String>(())).is_err());
        plan.observe(root);
        let relation_challenge = coordinator
            .with_pre_statement_transcript(|transcript| Ok(transcript.challenge_fp2()))
            .unwrap();
        assert_ne!(relation_challenge, Fp2::ZERO);
        assert!(coordinator.with_pre_statement_transcript(|_| Ok::<_, String>(())).is_err());
        response.observe_public_points([0xA3; 32], std::slice::from_ref(&point)).unwrap();
        plan.observe_public_points([0xA3; 32], std::slice::from_ref(&point)).unwrap();
        assert!(coordinator.with_pre_statement_transcript(|_| Ok::<_, String>(())).is_err());
    }

    #[test]
    fn shorter_lane_releases_only_the_longer_terminal_tail() {
        let mut transcript = Transcript::new([0x62; 32]);
        let (mut response, mut plan, coordinator) = c61_shared_round_pair(&mut transcript, [5, 4]);
        let response_point = Point::new(vec![C61P3Fp2::ONE; 5]);
        let plan_point = Point::new(vec![C61P3Fp2::ONE; 4]);
        let root = C61Commitment::from(vec![[0x12; 32]]);
        response.observe(root.clone());
        plan.observe(root);
        response.observe_public_points([0xA2; 32], std::slice::from_ref(&response_point)).unwrap();
        plan.observe_public_points([0xA2; 32], std::slice::from_ref(&plan_point)).unwrap();

        thread::scope(|scope| {
            let response_thread = scope.spawn(|| response.sample());
            let plan_thread = scope.spawn(|| plan.sample());
            assert_eq!(response_thread.join().unwrap(), plan_thread.join().unwrap());
        });
        let (response_query, plan_query) = thread::scope(|scope| {
            let response_thread = scope.spawn(|| {
                assert_ne!(response.sample(), Goldilocks::ZERO);
                response.sample_bits(5)
            });
            let plan_thread = scope.spawn(|| plan.sample_bits(4));
            (response_thread.join().unwrap(), plan_thread.join().unwrap())
        });
        assert_eq!(response_query & 0xf, plan_query);
        plan.finish_lane().unwrap();
        let tail = response.sample();
        assert_ne!(tail, Goldilocks::ZERO);
        response.finish_lane().unwrap();
        assert_ne!(coordinator.sample_postproof_fp2().unwrap(), Fp2::ZERO);
        let stats = coordinator.finish(64).unwrap();
        assert_eq!(stats.client_fp_challenges, 5);
        assert_eq!(stats.client_query_challenges, 1);
    }
}

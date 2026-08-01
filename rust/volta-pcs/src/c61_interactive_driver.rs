//! Reference-only private-entropy transport for C6AWP1.
//!
//! The provider endpoint owns only a synchronous channel.  Verifier entropy,
//! its transcript state, and any replay checkpoint stay in the broker thread.
//! A disconnected attempt can be replayed deterministically to a recorded
//! frontier: every provider move must match byte-for-byte before its old
//! challenge is released, after which the broker continues with fresh draws.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::point::Point;
use p3_symmetric::MerkleCap;
use volta_field::P;
use volta_mac::Transcript;

use crate::c61_whir_reference::{
    C61Commitment, C61P3Fp2, C61WhirInteractionStats, C61WhirReferenceError, ReferenceResult,
    C61_WHIRA1_DIGEST_BYTES, C61_WHIRA1_FP_BYTES,
};

const C61_PRIVATE_MESSAGE_LABEL: &str = "c61.native.interactive_message";
const C61_PRIVATE_FINAL_LABEL: &str = "c61.native.final_payload";
const C61_INTERACTIVE_CHECKPOINT_MAGIC: [u8; 8] = *b"C6ICT1\0\0";
const C61_INTERACTIVE_CHECKPOINT_VERSION: u16 = 1;
const C61_INTERACTIVE_CHECKPOINT_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4 + 32;
const C61_INTERACTIVE_CHECKPOINT_MAX_BYTES: usize = 1_000_000;
const C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS: usize = 100_000;
const C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
enum C61ChallengeKind {
    Fp,
    Query { bits: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum C61ChallengeValue {
    Fp(u64),
    Query(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C61ChallengeRecord {
    provider_move: Vec<u8>,
    kind: C61ChallengeKind,
    value: C61ChallengeValue,
}

/// Verifier-local resumable prefix.  It contains already released public
/// challenges and exact provider moves, but never the verifier entropy seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C61InteractiveCheckpoint {
    num_variables: u8,
    context_digest: [u8; 32],
    records: Vec<C61ChallengeRecord>,
}

impl C61InteractiveCheckpoint {
    pub(crate) fn empty(num_variables: usize, context_digest: [u8; 32]) -> ReferenceResult<Self> {
        let num_variables = u8::try_from(num_variables)
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 dimension exceeds u8"))?;
        Ok(Self { num_variables, context_digest, records: Vec::new() })
    }

    pub(crate) fn challenge_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn encode(&self) -> ReferenceResult<Vec<u8>> {
        if self.records.len() > C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS {
            return Err(C61WhirReferenceError::new("C6ICT1 record count exceeds cap"));
        }
        let mut bytes = Vec::with_capacity(C61_INTERACTIVE_CHECKPOINT_HEADER_BYTES);
        bytes.extend_from_slice(&C61_INTERACTIVE_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&C61_INTERACTIVE_CHECKPOINT_VERSION.to_le_bytes());
        bytes.push(self.num_variables);
        bytes.push(0);
        bytes.extend_from_slice(
            &u32::try_from(self.records.len())
                .map_err(|_| C61WhirReferenceError::new("C6ICT1 record count exceeds u32"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.context_digest);
        for record in &self.records {
            let (kind, bits, value) = match (&record.kind, &record.value) {
                (C61ChallengeKind::Fp, C61ChallengeValue::Fp(value)) => (0u8, 0u8, *value),
                (C61ChallengeKind::Query { bits }, C61ChallengeValue::Query(value)) => {
                    (1u8, *bits, u64::from(*value))
                }
                _ => return Err(C61WhirReferenceError::new("C6ICT1 challenge tag mismatch")),
            };
            if record.provider_move.len() > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES {
                return Err(C61WhirReferenceError::new("C6ICT1 provider move exceeds cap"));
            }
            bytes.push(kind);
            bytes.push(bits);
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(record.provider_move.len())
                    .map_err(|_| C61WhirReferenceError::new("C6ICT1 move length exceeds u32"))?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&record.provider_move);
            if bytes.len() > C61_INTERACTIVE_CHECKPOINT_MAX_BYTES {
                return Err(C61WhirReferenceError::new("C6ICT1 payload exceeds cap"));
            }
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> ReferenceResult<Self> {
        if bytes.len() > C61_INTERACTIVE_CHECKPOINT_MAX_BYTES {
            return Err(C61WhirReferenceError::new("C6ICT1 payload exceeds cap"));
        }
        let mut reader = C61CheckpointReader::new(bytes);
        if reader.take(8)? != C61_INTERACTIVE_CHECKPOINT_MAGIC {
            return Err(C61WhirReferenceError::new("C6ICT1 magic mismatch"));
        }
        if reader.u16()? != C61_INTERACTIVE_CHECKPOINT_VERSION {
            return Err(C61WhirReferenceError::new("C6ICT1 version mismatch"));
        }
        let num_variables = reader.u8()?;
        if reader.u8()? != 0 {
            return Err(C61WhirReferenceError::new("C6ICT1 reserved byte is nonzero"));
        }
        let count = reader.u32()?;
        if count > C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS {
            return Err(C61WhirReferenceError::new("C6ICT1 record count exceeds cap"));
        }
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(reader.take(32)?);
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let kind_tag = reader.u8()?;
            let bits = reader.u8()?;
            if reader.u16()? != 0 {
                return Err(C61WhirReferenceError::new("C6ICT1 record reserved field is nonzero"));
            }
            let move_len = reader.u32()?;
            if move_len > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES {
                return Err(C61WhirReferenceError::new("C6ICT1 provider move exceeds cap"));
            }
            let raw_value = reader.u64()?;
            let (kind, value) = match kind_tag {
                0 if bits == 0 && raw_value < P => {
                    (C61ChallengeKind::Fp, C61ChallengeValue::Fp(raw_value))
                }
                1 if (1..=32).contains(&bits) && raw_value < (1u64 << bits) => (
                    C61ChallengeKind::Query { bits },
                    C61ChallengeValue::Query(
                        u32::try_from(raw_value)
                            .map_err(|_| C61WhirReferenceError::new("C6ICT1 query exceeds u32"))?,
                    ),
                ),
                _ => return Err(C61WhirReferenceError::new("C6ICT1 noncanonical challenge")),
            };
            let provider_move = reader.take(move_len)?.to_vec();
            records.push(C61ChallengeRecord { provider_move, kind, value });
        }
        reader.finish()?;
        Ok(Self { num_variables, context_digest, records })
    }

    pub(crate) fn mutate_first_move_for_test(&mut self) {
        if let Some(byte) =
            self.records.first_mut().and_then(|record| record.provider_move.first_mut())
        {
            *byte ^= 1;
        }
    }
}

struct C61CheckpointReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> C61CheckpointReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> ReferenceResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C61WhirReferenceError::new("C6ICT1 cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(C61WhirReferenceError::new("truncated C6ICT1 payload"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> ReferenceResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> ReferenceResult<u16> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> ReferenceResult<usize> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw) as usize)
    }

    fn u64(&mut self) -> ReferenceResult<u64> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn finish(self) -> ReferenceResult<()> {
        if self.offset != self.bytes.len() {
            return Err(C61WhirReferenceError::new("trailing bytes in C6ICT1 payload"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C61InteractiveTape {
    checkpoint: C61InteractiveCheckpoint,
    final_payload_bytes: usize,
    final_payload_blake3: [u8; 32],
}

impl C61InteractiveTape {
    pub(crate) fn challenge_count(&self) -> usize {
        self.checkpoint.records.len()
    }

    pub(crate) fn checkpoint(&self, count: usize) -> ReferenceResult<C61InteractiveCheckpoint> {
        if count > self.checkpoint.records.len() {
            return Err(C61WhirReferenceError::new("C6ICT1 checkpoint frontier exceeds tape"));
        }
        Ok(C61InteractiveCheckpoint {
            num_variables: self.checkpoint.num_variables,
            context_digest: self.checkpoint.context_digest,
            records: self.checkpoint.records[..count].to_vec(),
        })
    }

    pub(crate) fn checkpoint_bytes(&self, count: usize) -> ReferenceResult<Vec<u8>> {
        self.checkpoint(count)?.encode()
    }
}

#[derive(Debug)]
pub(crate) struct C61PrivateEntropyBrokerOutput {
    pub(crate) tape: C61InteractiveTape,
    pub(crate) interaction: C61WhirInteractionStats,
    pub(crate) transcript_bytes: u64,
    pub(crate) ledger: BTreeMap<&'static str, u64>,
    pub(crate) replayed_challenges: usize,
}

enum C61BrokerResponse {
    Fp(u64),
    Query(u32),
    Ack,
}

enum C61BrokerRequest {
    Challenge {
        provider_move: Vec<u8>,
        kind: C61ChallengeKind,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
    Finish {
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
}

/// The only object crossing into the provider role.  Its fields contain no
/// entropy seed, verifier transcript, or resumable checkpoint.
#[derive(Clone)]
struct C61ProviderEndpoint {
    sender: mpsc::SyncSender<C61BrokerRequest>,
}

struct C61ProviderState {
    endpoint: C61ProviderEndpoint,
    initial_root_seen: bool,
    public_statement_bound: bool,
    num_variables: usize,
    pending_provider_move: Vec<u8>,
    semantic_bytes: usize,
    failure: Option<C61WhirReferenceError>,
    fallback_query: u32,
}

/// Provider-side challenger backed only by the typed synchronous endpoint.
pub(crate) struct C61PrivateEntropyProverChallenger {
    state: Arc<Mutex<C61ProviderState>>,
}

impl Clone for C61PrivateEntropyProverChallenger {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

impl C61PrivateEntropyProverChallenger {
    fn new(endpoint: C61ProviderEndpoint, num_variables: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(C61ProviderState {
                endpoint,
                initial_root_seen: false,
                public_statement_bound: false,
                num_variables,
                pending_provider_move: Vec::new(),
                semantic_bytes: 0,
                failure: None,
                fallback_query: 0,
            })),
        }
    }

    pub(crate) fn observe_public_point(&mut self, point: &Point<C61P3Fp2>) -> ReferenceResult<()> {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        if !state.initial_root_seen || state.public_statement_bound {
            return Err(C61WhirReferenceError::new("C6ICT1 public-point order mismatch"));
        }
        if point.num_variables() != state.num_variables {
            return Err(C61WhirReferenceError::new("C6ICT1 public-point arity mismatch"));
        }
        state.public_statement_bound = true;
        Ok(())
    }

    fn request(&self, kind: C61ChallengeKind) -> ReferenceResult<C61BrokerResponse> {
        let (endpoint, provider_move) = {
            let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            if !state.public_statement_bound {
                return Err(C61WhirReferenceError::new(
                    "C6ICT1 challenge requested before public statement",
                ));
            }
            (state.endpoint.clone(), std::mem::take(&mut state.pending_provider_move))
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        endpoint
            .sender
            .send(C61BrokerRequest::Challenge { provider_move, kind, response: response_sender })
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier broker disconnected"))?;
        let result = response_receiver
            .recv()
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier response disconnected"))?;
        if let Err(error) = &result {
            self.state.lock().expect("C6ICT1 provider mutex poisoned").failure =
                Some(error.clone());
        }
        result
    }

    fn record_failure(&self, message: &'static str) {
        self.state.lock().expect("C6ICT1 provider mutex poisoned").failure =
            Some(C61WhirReferenceError::new(message));
    }

    fn next_fallback_query(&self, bits: u8) -> usize {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        let mask = if bits == 32 { u32::MAX } else { (1u32 << bits) - 1 };
        let value = state.fallback_query & mask;
        state.fallback_query = state.fallback_query.wrapping_add(1);
        value as usize
    }

    pub(crate) fn finish(&self, payload: &[u8]) -> ReferenceResult<()> {
        let (endpoint, semantic_bytes, pending_empty) = {
            let state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            (state.endpoint.clone(), state.semantic_bytes, state.pending_provider_move.is_empty())
        };
        if !pending_empty {
            return Err(C61WhirReferenceError::new(
                "C6ICT1 final provider move lacks a challenge boundary",
            ));
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        endpoint
            .sender
            .send(C61BrokerRequest::Finish {
                payload_bytes: payload.len(),
                payload_blake3: *blake3::hash(payload).as_bytes(),
                semantic_bytes,
                response: response_sender,
            })
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier broker disconnected"))?;
        match response_receiver
            .recv()
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier response disconnected"))??
        {
            C61BrokerResponse::Ack => Ok(()),
            _ => Err(C61WhirReferenceError::new("C6ICT1 finish response tag mismatch")),
        }
    }
}

impl CanObserve<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn observe(&mut self, value: Goldilocks) {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        state.pending_provider_move.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        state.semantic_bytes += C61_WHIRA1_FP_BYTES;
    }
}

impl CanObserve<C61Commitment> for C61PrivateEntropyProverChallenger {
    fn observe(&mut self, value: C61Commitment) {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        assert_eq!(value.num_roots(), 1, "C6ICT1 requires cap height zero");
        state.initial_root_seen = true;
        state.pending_provider_move.extend_from_slice(&value.roots()[0]);
        state.semantic_bytes += C61_WHIRA1_DIGEST_BYTES;
    }
}

impl CanSample<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn sample(&mut self) -> Goldilocks {
        match self.request(C61ChallengeKind::Fp) {
            Err(_) => Goldilocks::ONE,
            Ok(C61BrokerResponse::Fp(value)) => Goldilocks::new(value),
            Ok(_) => {
                self.record_failure("C6ICT1 field response tag mismatch");
                Goldilocks::ONE
            }
        }
    }
}

impl CanSampleBits<usize> for C61PrivateEntropyProverChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C6ICT1 query width must fit u32");
        let bits = u8::try_from(bits).expect("validated C6ICT1 query width");
        match self.request(C61ChallengeKind::Query { bits }) {
            Ok(C61BrokerResponse::Query(value)) => value as usize,
            Err(_) => self.next_fallback_query(bits),
            Ok(_) => {
                self.record_failure("C6ICT1 query response tag mismatch");
                self.next_fallback_query(bits)
            }
        }
    }
}

impl CanSampleUniformBits<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61PrivateEntropyProverChallenger {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6ICT1 proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61PrivateEntropyProverChallenger {}

fn derive_challenge(transcript: &mut Transcript, kind: &C61ChallengeKind) -> C61ChallengeValue {
    match kind {
        C61ChallengeKind::Fp => C61ChallengeValue::Fp(transcript.challenge_fp().value()),
        C61ChallengeKind::Query { bits } => {
            C61ChallengeValue::Query(transcript.challenge_bits(*bits) as u32)
        }
    }
}

fn broker_loop(
    receiver: mpsc::Receiver<C61BrokerRequest>,
    verifier_seed: [u8; 32],
    checkpoint: C61InteractiveCheckpoint,
) -> ReferenceResult<C61PrivateEntropyBrokerOutput> {
    let mut transcript = Transcript::new(verifier_seed);
    let mut records = Vec::new();
    let mut interaction = C61WhirInteractionStats::default();
    let mut replayed_challenges = 0usize;

    while let Ok(request) = receiver.recv() {
        match request {
            C61BrokerRequest::Challenge { provider_move, kind, response } => {
                if !provider_move.is_empty() {
                    transcript.append(
                        C61_PRIVATE_MESSAGE_LABEL,
                        u64::try_from(provider_move.len()).map_err(|_| {
                            C61WhirReferenceError::new("C6ICT1 provider move exceeds u64")
                        })?,
                    );
                    interaction.provider_messages += 1;
                    interaction.provider_semantic_bytes += provider_move.len() as u64;
                }
                let value = derive_challenge(&mut transcript, &kind);
                let record = C61ChallengeRecord { provider_move, kind, value };
                let result = if records.len() < checkpoint.records.len() {
                    if record != checkpoint.records[records.len()] {
                        Err(C61WhirReferenceError::new(
                            "C6ICT1 replay diverged before the recorded frontier",
                        ))
                    } else {
                        replayed_challenges += 1;
                        Ok(())
                    }
                } else {
                    Ok(())
                };
                if let Err(error) = result {
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                interaction.client_challenge_payload_bytes += match record.kind {
                    C61ChallengeKind::Fp => {
                        interaction.client_fp_challenges += 1;
                        C61_WHIRA1_FP_BYTES as u64
                    }
                    C61ChallengeKind::Query { .. } => {
                        interaction.client_query_challenges += 1;
                        4
                    }
                };
                let broker_response = match record.value {
                    C61ChallengeValue::Fp(value) => C61BrokerResponse::Fp(value),
                    C61ChallengeValue::Query(value) => C61BrokerResponse::Query(value),
                };
                records.push(record);
                if response.send(Ok(broker_response)).is_err() {
                    return Err(C61WhirReferenceError::new(
                        "C6ICT1 provider dropped a challenge response",
                    ));
                }
            }
            C61BrokerRequest::Finish {
                payload_bytes,
                payload_blake3,
                semantic_bytes,
                response,
            } => {
                if records.len() < checkpoint.records.len() {
                    let error = C61WhirReferenceError::new(
                        "C6ICT1 provider finished before the replay frontier",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if semantic_bytes != interaction.provider_semantic_bytes as usize
                    || semantic_bytes > payload_bytes
                {
                    let error = C61WhirReferenceError::new("C6ICT1 semantic-byte census mismatch");
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                let residual = payload_bytes - semantic_bytes;
                if residual > 0 {
                    transcript.append(C61_PRIVATE_FINAL_LABEL, residual as u64);
                    interaction.provider_messages += 1;
                }
                interaction.provider_payload_bytes = payload_bytes as u64;
                let tape = C61InteractiveTape {
                    checkpoint: C61InteractiveCheckpoint {
                        num_variables: checkpoint.num_variables,
                        context_digest: checkpoint.context_digest,
                        records,
                    },
                    final_payload_bytes: payload_bytes,
                    final_payload_blake3: payload_blake3,
                };
                response
                    .send(Ok(C61BrokerResponse::Ack))
                    .map_err(|_| C61WhirReferenceError::new("C6ICT1 finish ACK disconnected"))?;
                return Ok(C61PrivateEntropyBrokerOutput {
                    tape,
                    interaction,
                    transcript_bytes: transcript.total_bytes(),
                    ledger: transcript.ledger().clone(),
                    replayed_challenges,
                });
            }
        }
    }
    Err(C61WhirReferenceError::new("C6ICT1 provider disconnected before finish"))
}

pub(crate) fn spawn_c61_private_entropy_broker(
    verifier_seed: [u8; 32],
    num_variables: usize,
    context_digest: [u8; 32],
    checkpoint: C61InteractiveCheckpoint,
) -> ReferenceResult<(
    C61PrivateEntropyProverChallenger,
    JoinHandle<ReferenceResult<C61PrivateEntropyBrokerOutput>>,
)> {
    if checkpoint.num_variables as usize != num_variables
        || checkpoint.context_digest != context_digest
    {
        return Err(C61WhirReferenceError::new("C6ICT1 checkpoint context mismatch"));
    }
    let (sender, receiver) = mpsc::sync_channel(0);
    let endpoint = C61ProviderEndpoint { sender };
    let challenger = C61PrivateEntropyProverChallenger::new(endpoint, num_variables);
    let handle = thread::spawn(move || broker_loop(receiver, verifier_seed, checkpoint));
    Ok((challenger, handle))
}

struct C61ReplayState {
    tape: C61InteractiveTape,
    next_record: usize,
    initial_root_seen: bool,
    public_statement_bound: bool,
    num_variables: usize,
    pending_provider_move: Vec<u8>,
    interaction: C61WhirInteractionStats,
}

/// Verifier challenger that consumes the broker's typed tape.  It has no seed
/// and rejects any proof observation or challenge-kind divergence.
pub(crate) struct C61PrivateEntropyReplayChallenger {
    state: Arc<Mutex<C61ReplayState>>,
}

impl Clone for C61PrivateEntropyReplayChallenger {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

impl C61PrivateEntropyReplayChallenger {
    pub(crate) fn new(
        tape: C61InteractiveTape,
        num_variables: usize,
        context_digest: [u8; 32],
    ) -> ReferenceResult<Self> {
        if tape.checkpoint.num_variables as usize != num_variables
            || tape.checkpoint.context_digest != context_digest
        {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier tape context mismatch"));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(C61ReplayState {
                tape,
                next_record: 0,
                initial_root_seen: false,
                public_statement_bound: false,
                num_variables,
                pending_provider_move: Vec::new(),
                interaction: C61WhirInteractionStats::default(),
            })),
        })
    }

    pub(crate) fn observe_public_point(&mut self, point: &Point<C61P3Fp2>) -> ReferenceResult<()> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.initial_root_seen || state.public_statement_bound {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier public-point order mismatch"));
        }
        if point.num_variables() != state.num_variables {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier public-point arity mismatch"));
        }
        state.public_statement_bound = true;
        Ok(())
    }

    fn replay(&self, kind: C61ChallengeKind) -> ReferenceResult<C61ChallengeValue> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.public_statement_bound {
            return Err(C61WhirReferenceError::new(
                "C6ICT1 verifier challenge before public statement",
            ));
        }
        let index = state.next_record;
        let provider_move = std::mem::take(&mut state.pending_provider_move);
        let record = state
            .tape
            .checkpoint
            .records
            .get(index)
            .ok_or_else(|| C61WhirReferenceError::new("C6ICT1 verifier exhausted challenge tape"))?
            .clone();
        if record.provider_move != provider_move || record.kind != kind {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier tape divergence"));
        }
        if !record.provider_move.is_empty() {
            state.interaction.provider_messages += 1;
            state.interaction.provider_semantic_bytes += record.provider_move.len() as u64;
        }
        state.next_record += 1;
        state.interaction.client_challenge_payload_bytes += match record.kind {
            C61ChallengeKind::Fp => {
                state.interaction.client_fp_challenges += 1;
                C61_WHIRA1_FP_BYTES as u64
            }
            C61ChallengeKind::Query { .. } => {
                state.interaction.client_query_challenges += 1;
                4
            }
        };
        Ok(record.value)
    }

    pub(crate) fn finish(&self, payload: &[u8]) -> ReferenceResult<C61WhirInteractionStats> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.pending_provider_move.is_empty()
            || state.next_record != state.tape.checkpoint.records.len()
        {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier did not consume exact tape"));
        }
        if payload.len() != state.tape.final_payload_bytes
            || *blake3::hash(payload).as_bytes() != state.tape.final_payload_blake3
            || state.interaction.provider_semantic_bytes as usize > payload.len()
        {
            return Err(C61WhirReferenceError::new("C6ICT1 final artifact seal mismatch"));
        }
        if state.interaction.provider_semantic_bytes < payload.len() as u64 {
            state.interaction.provider_messages += 1;
        }
        state.interaction.provider_payload_bytes = payload.len() as u64;
        Ok(state.interaction)
    }
}

impl CanObserve<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn observe(&mut self, value: Goldilocks) {
        self.state
            .lock()
            .expect("C6ICT1 replay mutex poisoned")
            .pending_provider_move
            .extend_from_slice(&value.as_canonical_u64().to_le_bytes());
    }
}

impl CanObserve<MerkleCap<Goldilocks, [u8; 32]>> for C61PrivateEntropyReplayChallenger {
    fn observe(&mut self, value: MerkleCap<Goldilocks, [u8; 32]>) {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        assert_eq!(value.num_roots(), 1, "C6ICT1 replay requires cap height zero");
        state.initial_root_seen = true;
        state.pending_provider_move.extend_from_slice(&value.roots()[0]);
    }
}

impl CanSample<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn sample(&mut self) -> Goldilocks {
        match self.replay(C61ChallengeKind::Fp).unwrap_or_else(|error| panic!("{error}")) {
            C61ChallengeValue::Fp(value) => Goldilocks::new(value),
            _ => panic!("C6ICT1 replay field tag mismatch"),
        }
    }
}

impl CanSampleBits<usize> for C61PrivateEntropyReplayChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C6ICT1 replay query width must fit u32");
        match self
            .replay(C61ChallengeKind::Query { bits: bits as u8 })
            .unwrap_or_else(|error| panic!("{error}"))
        {
            C61ChallengeValue::Query(value) => value as usize,
            _ => panic!("C6ICT1 replay query tag mismatch"),
        }
    }
}

impl CanSampleUniformBits<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61PrivateEntropyReplayChallenger {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6ICT1 replay proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61PrivateEntropyReplayChallenger {}

impl fmt::Debug for C61PrivateEntropyProverChallenger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("C61PrivateEntropyProverChallenger(endpoint-only)")
    }
}

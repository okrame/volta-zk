//! Transcript accounting and verifier challenge derivation.
//!
//! Every protocol message is charged to a labelled byte ledger (the P2 gate
//! compares totals against the analytic budget). Challenges are drawn from a
//! verifier-side ChaCha stream — this mocks the *interactive* DV exchange
//! (declared shortcut: in the deployed protocol challenges come fresh from V
//! after each prover message; they are NOT Fiat–Shamir hashes and must not be
//! derivable by the prover from public data alone).

use std::collections::BTreeMap;
use volta_field::{Fp, Fp2, FpStream, P};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptChallengeRequest {
    Fp,
    Fp2,
    Bits(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptChallengeResponse {
    Fp(u64),
    Fp2([u64; 2]),
    Bits(u64),
}

/// Seedless provider endpoint for an interactive verifier-owned transcript.
/// Implementations own transport only; verifier entropy and replay state stay
/// behind the endpoint.
pub trait TranscriptChallengeChannel: Send {
    fn challenge(
        &mut self,
        provider_move: Vec<u8>,
        provider_semantic_bytes: usize,
        request: TranscriptChallengeRequest,
    ) -> Result<TranscriptChallengeResponse, String>;

    fn finish(
        &mut self,
        _pending_provider_move: Vec<u8>,
        _payload_bytes: usize,
        _payload_blake3: [u8; 32],
        _semantic_bytes: usize,
    ) -> Result<(), String> {
        Ok(())
    }
}

enum TranscriptChallenges {
    Private(FpStream),
    Interactive(Box<dyn TranscriptChallengeChannel>),
}

pub struct Transcript {
    challenges: TranscriptChallenges,
    bytes: BTreeMap<&'static str, u64>,
    n_messages: u64,
    canonical_moves: blake3::Hasher,
    noncanonical_events: u64,
    #[cfg(debug_assertions)]
    canonical_event_debug: Vec<(&'static str, [u8; 32])>,
    pending_provider_move: Vec<u8>,
    pending_semantic_bytes: usize,
    unbound_provider_bytes: u64,
    interactive_error: Option<String>,
}

impl Transcript {
    /// `seed` is the verifier's challenge seed (independent of the PCG seed).
    pub fn new(seed: [u8; 32]) -> Transcript {
        Transcript {
            challenges: TranscriptChallenges::Private(FpStream::domain_separated(seed, u64::MAX)),
            bytes: BTreeMap::new(),
            n_messages: 0,
            canonical_moves: blake3::Hasher::new_derive_key(
                "volta-zk/transcript/canonical-moves/v1",
            ),
            noncanonical_events: 0,
            #[cfg(debug_assertions)]
            canonical_event_debug: Vec::new(),
            pending_provider_move: Vec::new(),
            pending_semantic_bytes: 0,
            unbound_provider_bytes: 0,
            interactive_error: None,
        }
    }

    /// Construct a provider-side transcript that owns no verifier entropy.
    pub fn new_interactive(channel: Box<dyn TranscriptChallengeChannel>) -> Transcript {
        Transcript {
            challenges: TranscriptChallenges::Interactive(channel),
            bytes: BTreeMap::new(),
            n_messages: 0,
            canonical_moves: blake3::Hasher::new_derive_key(
                "volta-zk/transcript/canonical-moves/v1",
            ),
            noncanonical_events: 0,
            #[cfg(debug_assertions)]
            canonical_event_debug: Vec::new(),
            pending_provider_move: Vec::new(),
            pending_semantic_bytes: 0,
            unbound_provider_bytes: 0,
            interactive_error: None,
        }
    }

    fn account(&mut self, label: &'static str, n: u64) {
        *self.bytes.entry(label).or_insert(0) += n;
        self.n_messages += 1;
    }

    /// Charge `n` bytes of prover→verifier message under `label`.
    pub fn append(&mut self, label: &'static str, n: u64) {
        self.account(label, n);
        self.noncanonical_events = self.noncanonical_events.saturating_add(1);
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.unbound_provider_bytes = self.unbound_provider_bytes.saturating_add(n);
        }
    }

    /// Charge and bind one exact canonical provider message. Interactive
    /// challenge release consumes this encoding; private seeded transcripts
    /// retain the historical accounting behavior.
    pub fn append_message(&mut self, label: &'static str, message: &[u8]) {
        self.account(label, message.len() as u64);
        let label_len = u16::try_from(label.len()).expect("transcript label exceeds u16");
        let mut event = Vec::with_capacity(2 + label.len() + 8 + message.len());
        event.extend_from_slice(&label_len.to_le_bytes());
        event.extend_from_slice(label.as_bytes());
        event.extend_from_slice(&(message.len() as u64).to_le_bytes());
        event.extend_from_slice(message);
        self.canonical_moves.update(&[1]);
        self.canonical_moves.update(&event);
        #[cfg(debug_assertions)]
        self.canonical_event_debug.push((label, *blake3::hash(&event).as_bytes()));
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.pending_semantic_bytes = self.pending_semantic_bytes.saturating_add(message.len());
            self.pending_provider_move.extend_from_slice(&event);
        }
    }

    pub fn append_fps(&mut self, label: &'static str, values: &[Fp]) {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for value in values {
            bytes.extend_from_slice(&value.value().to_le_bytes());
        }
        self.append_message(label, &bytes);
    }

    pub fn append_fp2s(&mut self, label: &'static str, values: &[Fp2]) {
        let mut bytes = Vec::with_capacity(values.len() * 16);
        for value in values {
            bytes.extend_from_slice(&value.c0.value().to_le_bytes());
            bytes.extend_from_slice(&value.c1.value().to_le_bytes());
        }
        self.append_message(label, &bytes);
    }

    /// Bind canonical base-field wire values without materializing a second
    /// copy of a potentially large correction vector. The exact byte length
    /// remains in the accounting ledger while the interactive move carries a
    /// collision-resistant digest that the strict verifier recomputes.
    pub fn append_fp_values_digest(&mut self, label: &'static str, values: &[u64]) {
        self.append_fp_value_slices_digest(label, &[values]);
    }

    pub fn append_fp_value_slices_digest(&mut self, label: &'static str, slices: &[&[u64]]) {
        assert!(
            slices.iter().flat_map(|values| values.iter()).all(|value| *value < P),
            "noncanonical transcript Fp value"
        );
        let mut hasher = blake3::Hasher::new();
        let mut value_count = 0u64;
        for values in slices {
            value_count = value_count
                .checked_add(values.len() as u64)
                .expect("transcript Fp value count overflow");
            for value in *values {
                hasher.update(&value.to_le_bytes());
            }
        }
        self.append_message_digest(
            label,
            value_count.checked_mul(8).expect("transcript Fp byte count overflow"),
            *hasher.finalize().as_bytes(),
        );
    }

    /// Bind canonical zero padding by length and digest. Padding is public and
    /// independently reconstructible, so carrying the full zero string in a
    /// private challenge tape would add state without adding security.
    pub fn append_zero_message(&mut self, label: &'static str, logical_bytes: u64) {
        let mut hasher = blake3::Hasher::new();
        let zeroes = [0u8; 4096];
        let mut remaining = logical_bytes;
        while remaining != 0 {
            let take = remaining.min(zeroes.len() as u64) as usize;
            hasher.update(&zeroes[..take]);
            remaining -= take as u64;
        }
        self.append_message_digest(label, logical_bytes, *hasher.finalize().as_bytes());
    }

    /// Bind a large canonical provider message by length and BLAKE3 digest.
    /// The verifier replay recomputes the digest from the strict proof bytes.
    pub fn append_message_digest(
        &mut self,
        label: &'static str,
        logical_bytes: u64,
        digest: [u8; 32],
    ) {
        self.account(label, logical_bytes);
        let label_len = u16::try_from(label.len()).expect("transcript label exceeds u16");
        let mut event = Vec::with_capacity(2 + label.len() + 8 + digest.len());
        event.extend_from_slice(&label_len.to_le_bytes());
        event.extend_from_slice(label.as_bytes());
        event.extend_from_slice(&logical_bytes.to_le_bytes());
        event.extend_from_slice(&digest);
        self.canonical_moves.update(&[2]);
        self.canonical_moves.update(&event);
        #[cfg(debug_assertions)]
        self.canonical_event_debug.push((label, *blake3::hash(&event).as_bytes()));
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.pending_semantic_bytes = self
                .pending_semantic_bytes
                .saturating_add(usize::try_from(logical_bytes).unwrap_or(usize::MAX));
            self.pending_provider_move.extend_from_slice(&event);
        }
    }

    fn record_challenge_request(&mut self, request: TranscriptChallengeRequest) {
        self.canonical_moves.update(&[3]);
        let (_label, request_bytes): (&'static str, &[u8]) = match request {
            TranscriptChallengeRequest::Fp => ("challenge_fp", &[1]),
            TranscriptChallengeRequest::Fp2 => ("challenge_fp2", &[2]),
            TranscriptChallengeRequest::Bits(width) => {
                self.canonical_moves.update(&[3, width]);
                #[cfg(debug_assertions)]
                self.canonical_event_debug
                    .push(("challenge_bits", *blake3::hash(&[3, width]).as_bytes()));
                return;
            }
        };
        self.canonical_moves.update(request_bytes);
        #[cfg(debug_assertions)]
        self.canonical_event_debug.push((_label, *blake3::hash(request_bytes).as_bytes()));
    }

    fn interactive_challenge(
        &mut self,
        request: TranscriptChallengeRequest,
    ) -> Option<TranscriptChallengeResponse> {
        let TranscriptChallenges::Interactive(channel) = &mut self.challenges else {
            return None;
        };
        if self.interactive_error.is_some() {
            return Some(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
            });
        }
        if self.unbound_provider_bytes != 0 || self.noncanonical_events != 0 {
            self.interactive_error = Some(format!(
                "interactive challenge follows {} unbound provider bytes in {} noncanonical events",
                self.unbound_provider_bytes, self.noncanonical_events
            ));
            return Some(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
            });
        }
        let provider_move = std::mem::take(&mut self.pending_provider_move);
        let provider_semantic_bytes = std::mem::take(&mut self.pending_semantic_bytes);
        Some(match channel.challenge(provider_move, provider_semantic_bytes, request) {
            Ok(response) => response,
            Err(error) => {
                self.interactive_error = Some(error);
                match request {
                    TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                    TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                    TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
                }
            }
        })
    }

    /// Fresh verifier challenge in `E` (only sound after the prover's
    /// corresponding message has been appended — callers keep that order).
    pub fn challenge_fp2(&mut self) -> Fp2 {
        self.record_challenge_request(TranscriptChallengeRequest::Fp2);
        match self.interactive_challenge(TranscriptChallengeRequest::Fp2) {
            Some(TranscriptChallengeResponse::Fp2([a, b])) if a < P && b < P => {
                Fp2::new(Fp::new(a), Fp::new(b))
            }
            Some(_) => {
                self.interactive_error
                    .get_or_insert_with(|| "interactive Fp2 challenge tag is noncanonical".into());
                Fp2::ONE
            }
            None => match &mut self.challenges {
                TranscriptChallenges::Private(challenges) => challenges.next_fp2(),
                TranscriptChallenges::Interactive(_) => unreachable!(),
            },
        }
    }

    /// Fresh verifier challenge in the Goldilocks base field.
    ///
    /// Native C6.1 protocols use this for base-field transcript moves.  As
    /// with [`Self::challenge_fp2`], callers must first append the prover
    /// message on which the challenge depends.
    pub fn challenge_fp(&mut self) -> Fp {
        self.record_challenge_request(TranscriptChallengeRequest::Fp);
        match self.interactive_challenge(TranscriptChallengeRequest::Fp) {
            Some(TranscriptChallengeResponse::Fp(value)) if value < P => Fp::new(value),
            Some(_) => {
                self.interactive_error
                    .get_or_insert_with(|| "interactive Fp challenge tag is noncanonical".into());
                Fp::ONE
            }
            None => match &mut self.challenges {
                TranscriptChallenges::Private(challenges) => challenges.next_fp(),
                TranscriptChallenges::Interactive(_) => unreachable!(),
            },
        }
    }

    /// Fresh exact-bit verifier challenge for a power-of-two query domain.
    pub fn challenge_bits(&mut self, width: u8) -> u64 {
        assert!((1..=64).contains(&width), "transcript bit width must be in 1..=64");
        self.record_challenge_request(TranscriptChallengeRequest::Bits(width));
        match self.interactive_challenge(TranscriptChallengeRequest::Bits(width)) {
            Some(TranscriptChallengeResponse::Bits(value))
                if width == 64 || value < (1u64 << width) =>
            {
                value
            }
            Some(_) => {
                self.interactive_error
                    .get_or_insert_with(|| "interactive bit challenge tag is noncanonical".into());
                0
            }
            None => match &mut self.challenges {
                TranscriptChallenges::Private(challenges) => challenges.next_bits(width),
                TranscriptChallenges::Interactive(_) => unreachable!(),
            },
        }
    }

    pub fn interactive_error(&self) -> Option<&str> {
        self.interactive_error.as_deref()
    }

    pub fn is_interactive(&self) -> bool {
        matches!(self.challenges, TranscriptChallenges::Interactive(_))
    }

    /// Exact canonical provider-move and challenge-order identity. Seeded
    /// prover/verifier executions use this as a deterministic parity check;
    /// any legacy length-only event makes the identity unavailable.
    pub fn canonical_binding_digest(&self) -> Result<[u8; 32], String> {
        if self.noncanonical_events != 0 {
            return Err(format!(
                "transcript contains {} noncanonical length-only events",
                self.noncanonical_events
            ));
        }
        Ok(*self.canonical_moves.clone().finalize().as_bytes())
    }

    #[cfg(debug_assertions)]
    pub fn debug_first_canonical_divergence(&self, other: &Self) -> Option<String> {
        let shared = self.canonical_event_debug.len().min(other.canonical_event_debug.len());
        for index in 0..shared {
            if self.canonical_event_debug[index] != other.canonical_event_debug[index] {
                return Some(format!(
                    "event {index}: provider {:?}, verifier {:?}",
                    self.canonical_event_debug[index], other.canonical_event_debug[index]
                ));
            }
        }
        (self.canonical_event_debug.len() != other.canonical_event_debug.len()).then(|| {
            format!(
                "event census: provider {}, verifier {}",
                self.canonical_event_debug.len(),
                other.canonical_event_debug.len()
            )
        })
    }

    /// Seal one complete strict provider artifact and terminate its seedless
    /// challenge channel. Length-only terminal framing is permitted here
    /// because the complete canonical payload digest binds it.
    pub fn finish_interactive(&mut self, payload: &[u8]) -> Result<(), String> {
        if let Some(error) = &self.interactive_error {
            return Err(error.clone());
        }
        let semantic_bytes = usize::try_from(self.total_bytes())
            .map_err(|_| "interactive transcript byte count exceeds usize".to_owned())?;
        let pending_provider_move = std::mem::take(&mut self.pending_provider_move);
        let TranscriptChallenges::Interactive(channel) = &mut self.challenges else {
            return Err("cannot finish a private seeded transcript as interactive".to_owned());
        };
        channel.finish(
            pending_provider_move,
            payload.len(),
            *blake3::hash(payload).as_bytes(),
            semantic_bytes,
        )
    }

    pub fn bytes_for(&self, label: &str) -> u64 {
        self.bytes.get(label).copied().unwrap_or(0)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.values().sum()
    }

    pub fn ledger(&self) -> &BTreeMap<&'static str, u64> {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    struct ScriptedChannel {
        moves: Arc<Mutex<Vec<(Vec<u8>, TranscriptChallengeRequest)>>>,
    }

    impl TranscriptChallengeChannel for ScriptedChannel {
        fn challenge(
            &mut self,
            provider_move: Vec<u8>,
            _provider_semantic_bytes: usize,
            request: TranscriptChallengeRequest,
        ) -> Result<TranscriptChallengeResponse, String> {
            self.moves.lock().unwrap().push((provider_move, request));
            Ok(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(7),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([11, 13]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(5),
            })
        }
    }

    #[test]
    fn interactive_transcript_releases_only_after_exact_move() {
        let moves = Arc::new(Mutex::new(Vec::new()));
        let channel = ScriptedChannel { moves: Arc::clone(&moves) };
        let mut transcript = Transcript::new_interactive(Box::new(channel));
        transcript.append_message("round", &[1, 2, 3]);
        assert_eq!(transcript.challenge_fp().value(), 7);
        transcript.append_message_digest("large", 4096, [0xA5; 32]);
        assert_eq!(transcript.challenge_fp2(), Fp2::new(Fp::new(11), Fp::new(13)));
        assert_eq!(transcript.challenge_bits(8), 5);
        assert!(transcript.interactive_error().is_none());

        let moves = moves.lock().unwrap();
        assert_eq!(moves.len(), 3);
        assert_eq!(moves[0].1, TranscriptChallengeRequest::Fp);
        assert!(moves[0].0.ends_with(&[1, 2, 3]));
        assert_eq!(moves[1].1, TranscriptChallengeRequest::Fp2);
        assert!(moves[1].0.ends_with(&[0xA5; 32]));
        assert_eq!(moves[2], (Vec::new(), TranscriptChallengeRequest::Bits(8)));
    }

    #[test]
    fn interactive_transcript_rejects_length_only_move_before_challenge() {
        let moves = Arc::new(Mutex::new(Vec::new()));
        let channel = ScriptedChannel { moves: Arc::clone(&moves) };
        let mut transcript = Transcript::new_interactive(Box::new(channel));
        transcript.append("unbound", 16);
        assert_eq!(transcript.challenge_fp(), Fp::ONE);
        assert!(transcript.interactive_error().unwrap().contains("unbound provider bytes"));
        assert!(moves.lock().unwrap().is_empty());
    }

    #[test]
    fn canonical_binding_is_order_and_value_exact() {
        let mut first = Transcript::new([0x31; 32]);
        first.append_fp2s("correction", &[Fp2::new(Fp::new(7), Fp::new(9))]);
        let _ = first.challenge_fp2();
        first.append_message_digest("large", 4096, [0xA5; 32]);
        let _ = first.challenge_bits(12);

        let mut same = Transcript::new([0x31; 32]);
        same.append_fp2s("correction", &[Fp2::new(Fp::new(7), Fp::new(9))]);
        let _ = same.challenge_fp2();
        same.append_message_digest("large", 4096, [0xA5; 32]);
        let _ = same.challenge_bits(12);
        assert_eq!(
            first.canonical_binding_digest().unwrap(),
            same.canonical_binding_digest().unwrap()
        );

        let mut changed = Transcript::new([0x31; 32]);
        changed.append_fp2s("correction", &[Fp2::new(Fp::new(7), Fp::new(10))]);
        let _ = changed.challenge_fp2();
        changed.append_message_digest("large", 4096, [0xA5; 32]);
        let _ = changed.challenge_bits(12);
        assert_ne!(
            first.canonical_binding_digest().unwrap(),
            changed.canonical_binding_digest().unwrap()
        );

        let mut legacy = Transcript::new([0x31; 32]);
        legacy.append("zero_length_marker", 0);
        assert!(legacy.canonical_binding_digest().is_err());
    }
}

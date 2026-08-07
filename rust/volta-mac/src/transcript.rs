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
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.unbound_provider_bytes = self.unbound_provider_bytes.saturating_add(n);
        }
    }

    /// Charge and bind one exact canonical provider message. Interactive
    /// challenge release consumes this encoding; private seeded transcripts
    /// retain the historical accounting behavior.
    pub fn append_message(&mut self, label: &'static str, message: &[u8]) {
        self.account(label, message.len() as u64);
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.pending_semantic_bytes = self.pending_semantic_bytes.saturating_add(message.len());
            let label_len = u16::try_from(label.len()).expect("transcript label exceeds u16");
            self.pending_provider_move.extend_from_slice(&label_len.to_le_bytes());
            self.pending_provider_move.extend_from_slice(label.as_bytes());
            self.pending_provider_move.extend_from_slice(&(message.len() as u64).to_le_bytes());
            self.pending_provider_move.extend_from_slice(message);
        }
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
        if matches!(self.challenges, TranscriptChallenges::Interactive(_)) {
            self.pending_semantic_bytes = self
                .pending_semantic_bytes
                .saturating_add(usize::try_from(logical_bytes).unwrap_or(usize::MAX));
            let label_len = u16::try_from(label.len()).expect("transcript label exceeds u16");
            self.pending_provider_move.extend_from_slice(&label_len.to_le_bytes());
            self.pending_provider_move.extend_from_slice(label.as_bytes());
            self.pending_provider_move.extend_from_slice(&logical_bytes.to_le_bytes());
            self.pending_provider_move.extend_from_slice(&digest);
        }
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
        if self.unbound_provider_bytes != 0 {
            self.interactive_error = Some(format!(
                "interactive challenge follows {} unbound provider bytes",
                self.unbound_provider_bytes
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
}

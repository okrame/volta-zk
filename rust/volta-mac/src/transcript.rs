//! Transcript accounting and verifier challenge derivation.
//!
//! Every protocol message is charged to a labelled byte ledger (the P2 gate
//! compares totals against the analytic budget). Challenges are drawn from a
//! verifier-side ChaCha stream — this mocks the *interactive* DV exchange
//! (declared shortcut: in the deployed protocol challenges come fresh from V
//! after each prover message; they are NOT Fiat–Shamir hashes and must not be
//! derivable by the prover from public data alone).

use std::collections::{BTreeMap, HashMap, HashSet};
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
    FiatShamir(FiatShamirState),
}

#[derive(Clone, Copy)]
enum FiatShamirProfile {
    C41,
    C62,
}

impl FiatShamirProfile {
    fn name(self) -> &'static str {
        match self {
            Self::C41 => "C41FS1",
            Self::C62 => "C62FS1",
        }
    }

    fn challenge_domain(self) -> &'static str {
        match self {
            Self::C41 => "volta-zk/c4.1/fiat-shamir/challenge/v1",
            Self::C62 => "volta-zk/c6.2/fiat-shamir/challenge/v1",
        }
    }

    fn max_challenges(self) -> u64 {
        match self {
            Self::C41 => C41_FIAT_SHAMIR_MAX_CHALLENGES,
            Self::C62 => C62_FIAT_SHAMIR_MAX_CHALLENGES,
        }
    }

    fn max_rejection_draws_per_limb(self) -> u32 {
        match self {
            Self::C41 => C41_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB,
            Self::C62 => C62_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB,
        }
    }

    fn response_debug_label(self) -> &'static str {
        match self {
            Self::C41 => "c41_fiat_shamir_response",
            Self::C62 => "c62_fiat_shamir_response",
        }
    }
}

struct FiatShamirState {
    profile: FiatShamirProfile,
    context_digest: [u8; 32],
    challenge_index: u64,
}

pub const C41_FIAT_SHAMIR_MAX_CHALLENGES: u64 = 131_072;
pub const C41_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB: u32 = 4;
pub const C41_FIAT_SHAMIR_MAX_RANDOM_ORACLE_QUERIES: u64 =
    C41_FIAT_SHAMIR_MAX_CHALLENGES * 2 * C41_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB as u64;
pub const C62_FIAT_SHAMIR_MAX_CHALLENGES: u64 = 131_072;
pub const C62_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB: u32 = 4;
pub const C62_FIAT_SHAMIR_MAX_RANDOM_ORACLE_QUERIES: u64 =
    C62_FIAT_SHAMIR_MAX_CHALLENGES * 2 * C62_FIAT_SHAMIR_MAX_REJECTION_DRAWS_PER_LIMB as u64;

pub struct Transcript {
    challenges: TranscriptChallenges,
    bytes: BTreeMap<&'static str, u64>,
    n_messages: u64,
    canonical_moves: blake3::Hasher,
    noncanonical_events: u64,
    first_noncanonical_label: Option<&'static str>,
    #[cfg(debug_assertions)]
    canonical_event_debug: Vec<(&'static str, [u8; 32])>,
    pending_provider_move: Vec<u8>,
    pending_semantic_bytes: usize,
    unbound_provider_bytes: u64,
    interactive_error: Option<String>,
    c62_subfield_digest_overrides: Option<HashMap<(usize, usize), [u8; 32]>>,
    c62_subfield_digest_uses: HashSet<(usize, usize)>,
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
            first_noncanonical_label: None,
            #[cfg(debug_assertions)]
            canonical_event_debug: Vec::new(),
            pending_provider_move: Vec::new(),
            pending_semantic_bytes: 0,
            unbound_provider_bytes: 0,
            interactive_error: None,
            c62_subfield_digest_overrides: None,
            c62_subfield_digest_uses: HashSet::new(),
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
            first_noncanonical_label: None,
            #[cfg(debug_assertions)]
            canonical_event_debug: Vec::new(),
            pending_provider_move: Vec::new(),
            pending_semantic_bytes: 0,
            unbound_provider_bytes: 0,
            interactive_error: None,
            c62_subfield_digest_overrides: None,
            c62_subfield_digest_uses: HashSet::new(),
        }
    }

    /// Construct the public C6.2 Fiat--Shamir transcript. The context digest
    /// must bind the complete public attempt and the typed lane identity.
    /// Provider moves remain canonical byte events and no verifier secret is
    /// used for challenge derivation.
    pub fn new_fiat_shamir(context_digest: [u8; 32]) -> Result<Transcript, String> {
        Self::new_fiat_shamir_profile(context_digest, FiatShamirProfile::C62)
    }

    /// Construct the public C4.1 Fiat--Shamir transcript. Verifier-private
    /// VOLE keys and `Delta` remain outside this public challenge state.
    pub fn new_c41_fiat_shamir(context_digest: [u8; 32]) -> Result<Transcript, String> {
        Self::new_fiat_shamir_profile(context_digest, FiatShamirProfile::C41)
    }

    fn new_fiat_shamir_profile(
        context_digest: [u8; 32],
        profile: FiatShamirProfile,
    ) -> Result<Transcript, String> {
        if context_digest == [0; 32] {
            return Err(format!("{} context digest is zero", profile.name()));
        }
        Ok(Transcript {
            challenges: TranscriptChallenges::FiatShamir(FiatShamirState {
                profile,
                context_digest,
                challenge_index: 0,
            }),
            bytes: BTreeMap::new(),
            n_messages: 0,
            canonical_moves: blake3::Hasher::new_derive_key(
                "volta-zk/transcript/canonical-moves/v1",
            ),
            noncanonical_events: 0,
            first_noncanonical_label: None,
            #[cfg(debug_assertions)]
            canonical_event_debug: Vec::new(),
            pending_provider_move: Vec::new(),
            pending_semantic_bytes: 0,
            unbound_provider_bytes: 0,
            interactive_error: None,
            c62_subfield_digest_overrides: None,
            c62_subfield_digest_uses: HashSet::new(),
        })
    }

    /// Install the strict C6.2 compact-response digests for decoded zero
    /// placeholders. Keys are the stable backing address and logical length
    /// of each retained `Vec<u64>` in the decoded proof object.
    pub fn install_c62_subfield_digest_overrides(
        &mut self,
        overrides: Vec<(*const u64, usize, [u8; 32])>,
    ) -> Result<(), String> {
        if self.c62_subfield_digest_overrides.is_some() || !self.c62_subfield_digest_uses.is_empty()
        {
            return Err("C6.2 subfield digest replay is already installed".to_owned());
        }
        let mut map = HashMap::with_capacity(overrides.len());
        for (pointer, len, digest) in overrides {
            if len == 0
                || digest == [0; 32]
                || map.insert((pointer as usize, len), digest).is_some()
            {
                return Err("C6.2 subfield digest replay manifest is noncanonical".to_owned());
            }
        }
        if map.is_empty() {
            return Err("C6.2 subfield digest replay manifest is empty".to_owned());
        }
        self.c62_subfield_digest_overrides = Some(map);
        Ok(())
    }

    pub fn finish_c62_subfield_digest_overrides(&mut self) -> Result<(), String> {
        let overrides = self
            .c62_subfield_digest_overrides
            .take()
            .ok_or_else(|| "C6.2 subfield digest replay is absent".to_owned())?;
        if overrides.len() != self.c62_subfield_digest_uses.len()
            || overrides.keys().any(|key| !self.c62_subfield_digest_uses.contains(key))
        {
            return Err("C6.2 subfield digest replay census differs".to_owned());
        }
        self.c62_subfield_digest_uses.clear();
        Ok(())
    }

    fn account(&mut self, label: &'static str, n: u64) {
        *self.bytes.entry(label).or_insert(0) += n;
        self.n_messages += 1;
    }

    /// Charge `n` bytes of prover→verifier message under `label`.
    pub fn append(&mut self, label: &'static str, n: u64) {
        self.account(label, n);
        self.noncanonical_events = self.noncanonical_events.saturating_add(1);
        self.first_noncanonical_label.get_or_insert(label);
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

    /// Bind public bytes that both roles reconstruct independently. These
    /// bytes affect Fiat--Shamir challenges but do not count as provider wire.
    pub fn absorb_public_message(&mut self, label: &'static str, message: &[u8]) {
        self.account(label, 0);
        let label_len = u16::try_from(label.len()).expect("transcript label exceeds u16");
        let mut event = Vec::with_capacity(2 + label.len() + 8 + message.len());
        event.extend_from_slice(&label_len.to_le_bytes());
        event.extend_from_slice(label.as_bytes());
        event.extend_from_slice(&(message.len() as u64).to_le_bytes());
        event.extend_from_slice(message);
        self.canonical_moves.update(&[5]);
        self.canonical_moves.update(&event);
        #[cfg(debug_assertions)]
        self.canonical_event_debug.push((label, *blake3::hash(&event).as_bytes()));
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

    /// Bind canonical extension-field wire values without materializing a
    /// second copy of large PCS vectors.
    pub fn append_fp2_value_slices_digest(&mut self, label: &'static str, slices: &[&[Fp2]]) {
        let mut hasher = blake3::Hasher::new();
        let mut value_count = 0u64;
        for values in slices {
            value_count = value_count
                .checked_add(values.len() as u64)
                .expect("transcript Fp2 value count overflow");
            for value in *values {
                hasher.update(&value.c0.value().to_le_bytes());
                hasher.update(&value.c1.value().to_le_bytes());
            }
        }
        self.append_message_digest(
            label,
            value_count.checked_mul(16).expect("transcript Fp2 byte count overflow"),
            *hasher.finalize().as_bytes(),
        );
    }

    /// Bind canonical base-field wire values without materializing a second
    /// copy of a potentially large correction vector. The exact byte length
    /// remains in the accounting ledger while the interactive move carries a
    /// collision-resistant digest that the strict verifier recomputes.
    pub fn append_fp_values_digest(&mut self, label: &'static str, values: &[u64]) {
        self.append_fp_value_slices_digest(label, &[values]);
    }

    pub fn append_fp_value_slices_digest(&mut self, label: &'static str, slices: &[&[u64]]) {
        if let (Some(overrides), [values]) = (&self.c62_subfield_digest_overrides, slices) {
            let key = (values.as_ptr() as usize, values.len());
            if let Some(&digest) = overrides.get(&key) {
                assert!(
                    values.iter().all(|value| *value == 0),
                    "C6.2 compact subfield placeholder is nonzero"
                );
                assert!(
                    self.c62_subfield_digest_uses.insert(key),
                    "C6.2 compact subfield digest was replayed twice"
                );
                self.append_message_digest(
                    label,
                    (values.len() as u64)
                        .checked_mul(8)
                        .expect("transcript Fp byte count overflow"),
                    digest,
                );
                return;
            }
        }
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

    fn fs_sample_u64(
        profile: FiatShamirProfile,
        context_digest: [u8; 32],
        transcript_digest: [u8; 32],
        challenge_index: u64,
        request: TranscriptChallengeRequest,
        limb: u8,
        retry: u32,
    ) -> u64 {
        let mut hasher = blake3::Hasher::new_derive_key(profile.challenge_domain());
        hasher.update(&context_digest);
        hasher.update(&transcript_digest);
        hasher.update(&challenge_index.to_le_bytes());
        match request {
            TranscriptChallengeRequest::Fp => hasher.update(&[1, 0]),
            TranscriptChallengeRequest::Fp2 => hasher.update(&[2, limb]),
            TranscriptChallengeRequest::Bits(width) => hasher.update(&[3, width]),
        };
        hasher.update(&retry.to_le_bytes());
        let output = hasher.finalize();
        u64::from_le_bytes(output.as_bytes()[..8].try_into().expect("eight-byte BLAKE3 prefix"))
    }

    fn record_fs_response(
        &mut self,
        profile: FiatShamirProfile,
        response: TranscriptChallengeResponse,
    ) {
        self.canonical_moves.update(&[4]);
        let mut encoded = [0u8; 17];
        let length = match response {
            TranscriptChallengeResponse::Fp(value) => {
                encoded[0] = 1;
                encoded[1..9].copy_from_slice(&value.to_le_bytes());
                9
            }
            TranscriptChallengeResponse::Fp2([c0, c1]) => {
                encoded[0] = 2;
                encoded[1..9].copy_from_slice(&c0.to_le_bytes());
                encoded[9..17].copy_from_slice(&c1.to_le_bytes());
                17
            }
            TranscriptChallengeResponse::Bits(value) => {
                encoded[0] = 3;
                encoded[1..9].copy_from_slice(&value.to_le_bytes());
                9
            }
        };
        self.canonical_moves.update(&encoded[..length]);
        #[cfg(debug_assertions)]
        self.canonical_event_debug
            .push((profile.response_debug_label(), *blake3::hash(&encoded[..length]).as_bytes()));
    }

    fn fiat_shamir_challenge(
        &mut self,
        request: TranscriptChallengeRequest,
    ) -> Option<TranscriptChallengeResponse> {
        let TranscriptChallenges::FiatShamir(state) = &mut self.challenges else {
            return None;
        };
        if self.noncanonical_events != 0 {
            self.interactive_error.get_or_insert_with(|| {
                format!(
                    "{} challenge follows {} noncanonical length-only events",
                    state.profile.name(),
                    self.noncanonical_events
                )
            });
            return Some(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
            });
        }
        if self.interactive_error.is_some() {
            return Some(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
            });
        }
        let transcript_digest = *self.canonical_moves.clone().finalize().as_bytes();
        let profile = state.profile;
        let context_digest = state.context_digest;
        let challenge_index = state.challenge_index;
        if challenge_index >= profile.max_challenges() {
            self.interactive_error =
                Some(format!("{} challenge census exceeds its proof bound", profile.name()));
            return Some(match request {
                TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
            });
        }
        state.challenge_index = match state.challenge_index.checked_add(1) {
            Some(next) => next,
            None => {
                self.interactive_error =
                    Some(format!("{} challenge index overflow", profile.name()));
                return Some(match request {
                    TranscriptChallengeRequest::Fp => TranscriptChallengeResponse::Fp(1),
                    TranscriptChallengeRequest::Fp2 => TranscriptChallengeResponse::Fp2([1, 0]),
                    TranscriptChallengeRequest::Bits(_) => TranscriptChallengeResponse::Bits(0),
                });
            }
        };
        let sample_fp = |limb| {
            (0..profile.max_rejection_draws_per_limb()).find_map(|retry| {
                let value = Self::fs_sample_u64(
                    profile,
                    context_digest,
                    transcript_digest,
                    challenge_index,
                    request,
                    limb,
                    retry,
                );
                (value < P).then_some(value)
            })
        };
        let response = match request {
            TranscriptChallengeRequest::Fp => {
                let Some(value) = sample_fp(0) else {
                    self.interactive_error =
                        Some(format!("{} Fp rejection sampling exhausted", profile.name()));
                    return Some(TranscriptChallengeResponse::Fp(1));
                };
                TranscriptChallengeResponse::Fp(value)
            }
            TranscriptChallengeRequest::Fp2 => {
                let (Some(c0), Some(c1)) = (sample_fp(0), sample_fp(1)) else {
                    self.interactive_error =
                        Some(format!("{} Fp2 rejection sampling exhausted", profile.name()));
                    return Some(TranscriptChallengeResponse::Fp2([1, 0]));
                };
                TranscriptChallengeResponse::Fp2([c0, c1])
            }
            TranscriptChallengeRequest::Bits(width) => {
                let value = Self::fs_sample_u64(
                    profile,
                    context_digest,
                    transcript_digest,
                    challenge_index,
                    request,
                    0,
                    0,
                );
                let value = if width == 64 { value } else { value & ((1u64 << width) - 1) };
                TranscriptChallengeResponse::Bits(value)
            }
        };
        self.record_fs_response(profile, response);
        Some(response)
    }

    /// Fresh verifier challenge in `E` (only sound after the prover's
    /// corresponding message has been appended — callers keep that order).
    pub fn challenge_fp2(&mut self) -> Fp2 {
        self.record_challenge_request(TranscriptChallengeRequest::Fp2);
        match self
            .fiat_shamir_challenge(TranscriptChallengeRequest::Fp2)
            .or_else(|| self.interactive_challenge(TranscriptChallengeRequest::Fp2))
        {
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
                TranscriptChallenges::Interactive(_) | TranscriptChallenges::FiatShamir(_) => {
                    unreachable!()
                }
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
        match self
            .fiat_shamir_challenge(TranscriptChallengeRequest::Fp)
            .or_else(|| self.interactive_challenge(TranscriptChallengeRequest::Fp))
        {
            Some(TranscriptChallengeResponse::Fp(value)) if value < P => Fp::new(value),
            Some(_) => {
                self.interactive_error
                    .get_or_insert_with(|| "interactive Fp challenge tag is noncanonical".into());
                Fp::ONE
            }
            None => match &mut self.challenges {
                TranscriptChallenges::Private(challenges) => challenges.next_fp(),
                TranscriptChallenges::Interactive(_) | TranscriptChallenges::FiatShamir(_) => {
                    unreachable!()
                }
            },
        }
    }

    /// Fresh exact-bit verifier challenge for a power-of-two query domain.
    pub fn challenge_bits(&mut self, width: u8) -> u64 {
        assert!((1..=64).contains(&width), "transcript bit width must be in 1..=64");
        self.record_challenge_request(TranscriptChallengeRequest::Bits(width));
        match self
            .fiat_shamir_challenge(TranscriptChallengeRequest::Bits(width))
            .or_else(|| self.interactive_challenge(TranscriptChallengeRequest::Bits(width)))
        {
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
                TranscriptChallenges::Interactive(_) | TranscriptChallenges::FiatShamir(_) => {
                    unreachable!()
                }
            },
        }
    }

    pub fn interactive_error(&self) -> Option<&str> {
        self.interactive_error.as_deref()
    }

    pub fn is_interactive(&self) -> bool {
        matches!(self.challenges, TranscriptChallenges::Interactive(_))
    }

    pub fn is_fiat_shamir(&self) -> bool {
        matches!(self.challenges, TranscriptChallenges::FiatShamir(_))
    }

    pub fn fiat_shamir_challenge_count(&self) -> Option<u64> {
        match &self.challenges {
            TranscriptChallenges::FiatShamir(state) => Some(state.challenge_index),
            TranscriptChallenges::Private(_) | TranscriptChallenges::Interactive(_) => None,
        }
    }

    /// Exact canonical provider-move and challenge-order identity. Seeded
    /// prover/verifier executions use this as a deterministic parity check;
    /// any legacy length-only event makes the identity unavailable.
    pub fn canonical_binding_digest(&self) -> Result<[u8; 32], String> {
        if let Some(error) = &self.interactive_error {
            return Err(error.clone());
        }
        if self.noncanonical_events != 0 {
            return Err(format!(
                "transcript contains {} noncanonical length-only events; first label {}",
                self.noncanonical_events,
                self.first_noncanonical_label.unwrap_or("unknown"),
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

    #[test]
    fn c62_compact_subfield_digest_replays_the_exact_move() {
        let values = [3u64, 5, 8, 13];
        let mut canonical_bytes = Vec::new();
        for value in values {
            canonical_bytes.extend_from_slice(&value.to_le_bytes());
        }
        let digest = *blake3::hash(&canonical_bytes).as_bytes();

        let mut full = Transcript::new_fiat_shamir([0x91; 32]).unwrap();
        full.append_fp_values_digest("auth_corrections", &values);
        let full_challenge = full.challenge_fp2();
        let full_binding = full.canonical_binding_digest().unwrap();

        let placeholders = [0u64; 4];
        let mut compact = Transcript::new_fiat_shamir([0x91; 32]).unwrap();
        compact
            .install_c62_subfield_digest_overrides(vec![(
                placeholders.as_ptr(),
                placeholders.len(),
                digest,
            )])
            .unwrap();
        compact.append_fp_values_digest("auth_corrections", &placeholders);
        compact.finish_c62_subfield_digest_overrides().unwrap();
        assert_eq!(compact.challenge_fp2(), full_challenge);
        assert_eq!(compact.canonical_binding_digest().unwrap(), full_binding);

        let mut missing = Transcript::new_fiat_shamir([0x92; 32]).unwrap();
        missing
            .install_c62_subfield_digest_overrides(vec![(
                placeholders.as_ptr(),
                placeholders.len(),
                digest,
            )])
            .unwrap();
        assert!(missing.finish_c62_subfield_digest_overrides().is_err());
    }

    #[test]
    fn c62_fiat_shamir_is_public_exact_and_domain_separated() {
        let run = |context: [u8; 32], message: &[u8]| {
            let mut transcript = Transcript::new_fiat_shamir(context).unwrap();
            assert!(transcript.is_fiat_shamir());
            transcript.append_message("c62_round", message);
            let fp = transcript.challenge_fp();
            transcript.append_fp2s("c62_pair", &[Fp2::new(fp, Fp::new(9))]);
            let fp2 = transcript.challenge_fp2();
            let bits = transcript.challenge_bits(17);
            assert!(transcript.interactive_error().is_none());
            (fp, fp2, bits, transcript.canonical_binding_digest().unwrap())
        };
        let first = run([0xA1; 32], &[1, 2, 3]);
        assert_eq!(first, run([0xA1; 32], &[1, 2, 3]));
        assert_ne!(first, run([0xA2; 32], &[1, 2, 3]));
        assert_ne!(first, run([0xA1; 32], &[1, 2, 4]));
        assert!(first.2 < (1 << 17));
    }

    #[test]
    fn c62_fiat_shamir_rejects_length_only_events() {
        assert!(Transcript::new_fiat_shamir([0; 32]).is_err());
        let mut transcript = Transcript::new_fiat_shamir([0xB1; 32]).unwrap();
        transcript.append("legacy", 16);
        assert_eq!(transcript.challenge_fp2(), Fp2::ONE);
        assert!(transcript.interactive_error().unwrap().contains("noncanonical length-only"));
    }

    #[test]
    fn c62_fiat_shamir_enforces_the_registered_query_bound() {
        assert_eq!(C62_FIAT_SHAMIR_MAX_RANDOM_ORACLE_QUERIES, 1_048_576);
        let mut transcript = Transcript::new_fiat_shamir([0xB2; 32]).unwrap();
        let TranscriptChallenges::FiatShamir(state) = &mut transcript.challenges else {
            unreachable!();
        };
        state.challenge_index = C62_FIAT_SHAMIR_MAX_CHALLENGES;
        assert_eq!(transcript.challenge_fp2(), Fp2::ONE);
        assert!(transcript.interactive_error().unwrap().contains("challenge census exceeds"));
    }

    #[test]
    fn c41_fiat_shamir_matches_roles_and_separates_c62() {
        assert_eq!(C41_FIAT_SHAMIR_MAX_RANDOM_ORACLE_QUERIES, 1_048_576);
        assert!(Transcript::new_c41_fiat_shamir([0; 32]).is_err());
        let run = |c41: bool, message: &[u8]| {
            let mut transcript = if c41 {
                Transcript::new_c41_fiat_shamir([0xC4; 32]).unwrap()
            } else {
                Transcript::new_fiat_shamir([0xC4; 32]).unwrap()
            };
            transcript.append_message("round", message);
            let challenge = transcript.challenge_fp2();
            (challenge, transcript.canonical_binding_digest().unwrap())
        };
        assert_eq!(run(true, &[1, 2, 3]), run(true, &[1, 2, 3]));
        assert_ne!(run(true, &[1, 2, 3]), run(true, &[1, 2, 4]));
        assert_ne!(run(true, &[1, 2, 3]), run(false, &[1, 2, 3]));

        let mut noncanonical = Transcript::new_c41_fiat_shamir([0xC5; 32]).unwrap();
        noncanonical.append("legacy", 1);
        assert_eq!(noncanonical.challenge_fp(), Fp::ONE);
        assert!(noncanonical.interactive_error().unwrap().starts_with("C41FS1"));
    }
}

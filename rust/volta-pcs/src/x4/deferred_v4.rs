//! X4d deferred-settlement state, accumulator, and wire envelope.
//!
//! The static schema-4 commitment and every schema-4 child frame remain
//! unchanged.  X4d adds one connection-scoped append-only claim accumulator
//! and a distinct top-level settlement envelope.  The response path only
//! freezes already-authenticated claims; it never constructs an opening.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use super::frame::{
    AuthenticatedOutputLinkFrame, Digest, FrameError, M9TransferFrame, ReducedClaimFrame,
    ResponseZeroBatchFrame,
};
use super::frame_v4::{
    decode_v4, opening_schedule_digest_v4, profile_digest_v4, FoldCommitmentFrameV4, FrameV4,
    ManifestFrameV4, PackedBatchOpeningFrameV4, PackedOpeningScheduleV4,
};

pub const X4D_PROFILE_NAME_V1: &[u8] = b"x4-zkdeepfold-ud-e29-x4d-v1";
pub const X4D_MAGIC_V1: [u8; 8] = *b"VOLTAX4D";
pub const X4D_SCHEMA_V1: u16 = 1;
pub const X4D_SETTLEMENT_KIND_V1: u8 = 1;
pub const X4D_HEADER_BYTES_V1: usize = 16;

/// Single source of truth for every X4d accumulator, range, codec and
/// settlement validator.  The historical schema-4 literal remains immutable.
pub const X4D_PENDING_CLAIM_CAP_V1: usize = super::folding_v4::MAX_RESPONSE_CLAIMS_V4;
pub const X4D_MASKED_GROUP_CAP_V1: usize = 1_660;
pub const X4D_BACKGROUND_TRIGGER_CLAIMS_V1: usize = 1_632;
pub const X4D_GPT2_CLAIMS_PER_RESPONSE_V1: usize = 102;
pub const X4D_GPT2_GROUPS_PER_RESPONSE_V1: usize = 51;
pub const X4D_QUERY_COUNT_V1: usize = 111;
pub const X4D_GPT2_RESPONSE_BYTES_V1: u64 = 41_270_464;
pub const X4D_GPT2_SETTLEMENT_FIXED_BYTES_V1: u64 = 2_632_812;
pub const X4D_GPT2_SETTLEMENT_PER_RESPONSE_BYTES_V1: u64 = 50_424;

pub const X4D_ACCUMULATOR_INIT_CONTEXT_V1: &str = "volta-zk/x4d/claim-accumulator-init/v1";
pub const X4D_ACCUMULATOR_STEP_CONTEXT_V1: &str = "volta-zk/x4d/claim-accumulator-step/v1";
pub const X4D_AUTH_HANDLE_CONTEXT_V1: &str = "volta-zk/x4d/authenticated-value-handle/v1";
pub const X4D_LINK_SCHEDULE_CONTEXT_V1: &str = "volta-zk/x4d/auth-output-link-schedule/v1";
pub const X4D_OPENING_SCHEDULE_CONTEXT_V1: &str = "volta-zk/x4d/opening-schedule/v1";
pub const X4D_SETTLEMENT_CONTEXT_DIGEST_V1: &str = "volta-zk/x4d/settlement-context/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X4dErrorV1 {
    Invalid(&'static str),
    CapacityRefused { pending: usize, incoming: usize, cap: usize },
    Overflow,
    DigestMismatch,
    WrongSubset,
    Replay,
    Terminal,
    SettlementInFlight,
    NoPendingClaims,
    Frame(FrameError),
}

impl From<FrameError> for X4dErrorV1 {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

pub fn x4d_profile_digest_v1() -> Digest {
    *blake3::hash(X4D_PROFILE_NAME_V1).as_bytes()
}

pub fn x4d_gpt2_settlement_bytes_v1(responses: usize) -> Result<u64, X4dErrorV1> {
    let responses = u64::try_from(responses).map_err(|_| X4dErrorV1::Overflow)?;
    X4D_GPT2_SETTLEMENT_PER_RESPONSE_BYTES_V1
        .checked_mul(responses)
        .and_then(|variable| X4D_GPT2_SETTLEMENT_FIXED_BYTES_V1.checked_add(variable))
        .ok_or(X4dErrorV1::Overflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4dSettlementPolicyV1 {
    pub hard_pending_claim_cap: usize,
    pub background_trigger_claims: usize,
    pub background_trigger_responses: usize,
    pub max_inflight_settlements: usize,
}

impl X4dSettlementPolicyV1 {
    pub const fn production_gpt2() -> Self {
        Self {
            hard_pending_claim_cap: X4D_PENDING_CLAIM_CAP_V1,
            background_trigger_claims: X4D_BACKGROUND_TRIGGER_CLAIMS_V1,
            background_trigger_responses: 16,
            max_inflight_settlements: 1,
        }
    }

    pub fn validate(self) -> Result<(), X4dErrorV1> {
        if self.hard_pending_claim_cap != X4D_PENDING_CLAIM_CAP_V1
            || self.background_trigger_claims != X4D_BACKGROUND_TRIGGER_CLAIMS_V1
            || self.background_trigger_responses != 16
            || self.max_inflight_settlements != 1
        {
            return Err(X4dErrorV1::Invalid("X4d settlement policy"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4dResponseStateV1 {
    Authorized,
    ModelAuthenticated,
    WeightPending,
    WeightVerified,
    TerminalUnverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4dConnectionStateV1 {
    Open,
    Burned,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dFrozenClaimIdentityV1 {
    pub connection_id: Digest,
    pub response_nonce: Digest,
    pub claim_index: u64,
    pub auth_handle_digest: Digest,
    pub claim_frame: ReducedClaimFrame,
}

impl X4dFrozenClaimIdentityV1 {
    pub fn canonical_leaf(&self) -> Result<Vec<u8>, X4dErrorV1> {
        let frame = FrameV4::ReducedClaim(self.claim_frame.clone()).encode()?;
        let frame_len = u32::try_from(frame.len()).map_err(|_| X4dErrorV1::Overflow)?;
        let mut leaf = Vec::with_capacity(32 + 32 + 8 + 32 + 4 + frame.len());
        leaf.extend_from_slice(&self.connection_id);
        leaf.extend_from_slice(&self.response_nonce);
        leaf.extend_from_slice(&self.claim_index.to_le_bytes());
        leaf.extend_from_slice(&self.auth_handle_digest);
        leaf.extend_from_slice(&frame_len.to_le_bytes());
        leaf.extend_from_slice(&frame);
        Ok(leaf)
    }
}

pub fn x4d_authenticated_value_handle_v1(
    connection_id: Digest,
    response_nonce: Digest,
    claim_index: u64,
    auth_domain: u64,
    model_transcript_digest: Digest,
) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(X4D_AUTH_HANDLE_CONTEXT_V1);
    hasher.update(&connection_id);
    hasher.update(&response_nonce);
    hasher.update(&claim_index.to_le_bytes());
    hasher.update(&auth_domain.to_le_bytes());
    hasher.update(&model_transcript_digest);
    *hasher.finalize().as_bytes()
}

fn x4d_initial_accumulator_digest_v1(
    pcs_profile_digest: Digest,
    static_weight_commitment_digest: Digest,
    connection_id: Digest,
) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(X4D_ACCUMULATOR_INIT_CONTEXT_V1);
    hasher.update(&pcs_profile_digest);
    hasher.update(&static_weight_commitment_digest);
    hasher.update(&connection_id);
    *hasher.finalize().as_bytes()
}

fn x4d_accumulator_step_v1(
    prior: Digest,
    claim: &X4dFrozenClaimIdentityV1,
) -> Result<Digest, X4dErrorV1> {
    let mut hasher = blake3::Hasher::new_derive_key(X4D_ACCUMULATOR_STEP_CONTEXT_V1);
    hasher.update(&prior);
    hasher.update(&claim.canonical_leaf()?);
    Ok(*hasher.finalize().as_bytes())
}

/// Write-once local share table addressed by the public opaque handle.
/// Substitution after freeze is rejected before any settlement proof runs.
#[derive(Clone, Debug)]
pub struct X4dAuthenticatedValueStoreV1<T> {
    values: BTreeMap<Digest, T>,
}

impl<T> Default for X4dAuthenticatedValueStoreV1<T> {
    fn default() -> Self {
        Self { values: BTreeMap::new() }
    }
}

impl<T: PartialEq> X4dAuthenticatedValueStoreV1<T> {
    pub fn freeze(&mut self, handle: Digest, value: T) -> Result<(), X4dErrorV1> {
        if handle == [0; 32] {
            return Err(X4dErrorV1::Invalid("zero authenticated-value handle"));
        }
        match self.values.get(&handle) {
            Some(existing) if existing == &value => Err(X4dErrorV1::Replay),
            Some(_) => Err(X4dErrorV1::DigestMismatch),
            None => {
                self.values.insert(handle, value);
                Ok(())
            }
        }
    }

    pub fn get(&self, handle: &Digest) -> Option<&T> {
        self.values.get(handle)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dFrozenResponseV1 {
    pub response_nonce: Digest,
    pub model_transcript_digest: Digest,
    pub first_claim_index: u64,
    pub claim_count: u32,
    pub ending_accumulator_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dFreezeReceiptV1 {
    pub first_claim_index: u64,
    pub appended_count: u32,
    pub ending_accumulator_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dSettlementRangeV1 {
    pub connection_id: Digest,
    pub settlement_epoch: u64,
    pub first_claim_index: u64,
    pub claim_count: u32,
    pub starting_accumulator_digest: Digest,
    pub sealed_accumulator_digest: Digest,
    pub ordered_response_nonces: Vec<Digest>,
}

impl X4dSettlementRangeV1 {
    pub fn end_claim_index(&self) -> Result<u64, X4dErrorV1> {
        self.first_claim_index.checked_add(u64::from(self.claim_count)).ok_or(X4dErrorV1::Overflow)
    }
}

#[derive(Clone, Debug)]
pub struct X4dClaimAccumulatorV1 {
    pcs_profile_digest: Digest,
    static_weight_commitment_digest: Digest,
    connection_id: Digest,
    policy: X4dSettlementPolicyV1,
    entries: Vec<X4dFrozenClaimIdentityV1>,
    prefix_digests: Vec<Digest>,
    responses: Vec<X4dFrozenResponseV1>,
    response_states: BTreeMap<Digest, X4dResponseStateV1>,
    verified_claims: usize,
    inflight: Option<X4dSettlementRangeV1>,
    next_settlement_epoch: u64,
    state: X4dConnectionStateV1,
    pub cap_refusals: u64,
    pub settlement_ranges_sealed: u64,
    pub settlement_epochs_burned: u64,
}

impl X4dClaimAccumulatorV1 {
    pub fn new(
        static_weight_commitment_digest: Digest,
        connection_id: Digest,
        policy: X4dSettlementPolicyV1,
    ) -> Result<Self, X4dErrorV1> {
        policy.validate()?;
        if static_weight_commitment_digest == [0; 32] || connection_id == [0; 32] {
            return Err(X4dErrorV1::Invalid("X4d accumulator identity"));
        }
        let pcs_profile_digest = profile_digest_v4();
        let initial = x4d_initial_accumulator_digest_v1(
            pcs_profile_digest,
            static_weight_commitment_digest,
            connection_id,
        );
        Ok(Self {
            pcs_profile_digest,
            static_weight_commitment_digest,
            connection_id,
            policy,
            entries: Vec::new(),
            prefix_digests: vec![initial],
            responses: Vec::new(),
            response_states: BTreeMap::new(),
            verified_claims: 0,
            inflight: None,
            next_settlement_epoch: 1,
            state: X4dConnectionStateV1::Open,
            cap_refusals: 0,
            settlement_ranges_sealed: 0,
            settlement_epochs_burned: 0,
        })
    }

    pub fn connection_id(&self) -> Digest {
        self.connection_id
    }

    pub fn static_weight_commitment_digest(&self) -> Digest {
        self.static_weight_commitment_digest
    }

    pub fn pcs_profile_digest(&self) -> Digest {
        self.pcs_profile_digest
    }

    pub fn state(&self) -> X4dConnectionStateV1 {
        self.state
    }

    pub fn entries(&self) -> &[X4dFrozenClaimIdentityV1] {
        &self.entries
    }

    pub fn responses(&self) -> &[X4dFrozenResponseV1] {
        &self.responses
    }

    pub fn inflight_range(&self) -> Option<&X4dSettlementRangeV1> {
        self.inflight.as_ref()
    }

    pub fn response_state(&self, nonce: Digest) -> Option<X4dResponseStateV1> {
        self.response_states.get(&nonce).copied()
    }

    pub fn pending_claims(&self) -> usize {
        self.entries.len() - self.verified_claims
    }

    pub fn open_batch_claims(&self) -> usize {
        let first = self
            .inflight
            .as_ref()
            .and_then(|range| range.end_claim_index().ok())
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(self.verified_claims);
        self.entries.len().saturating_sub(first)
    }

    pub fn should_start_background_settlement(&self) -> bool {
        self.inflight.is_none()
            && (self.open_batch_claims() >= self.policy.background_trigger_claims
                || self
                    .responses
                    .iter()
                    .filter(|response| {
                        self.response_state(response.response_nonce)
                            == Some(X4dResponseStateV1::WeightPending)
                    })
                    .count()
                    >= self.policy.background_trigger_responses)
    }

    /// Must run before model proving or response-nonce consumption.
    pub fn preflight_response_claims(&mut self, incoming: usize) -> Result<(), X4dErrorV1> {
        self.ensure_open()?;
        if incoming == 0 {
            return Err(X4dErrorV1::Invalid("zero X4d response claims"));
        }
        let pending = self.pending_claims();
        if pending.checked_add(incoming).ok_or(X4dErrorV1::Overflow)?
            > self.policy.hard_pending_claim_cap
        {
            self.cap_refusals = self.cap_refusals.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
            return Err(X4dErrorV1::CapacityRefused {
                pending,
                incoming,
                cap: self.policy.hard_pending_claim_cap,
            });
        }
        Ok(())
    }

    pub fn authorize_response(&mut self, response_nonce: Digest) -> Result<(), X4dErrorV1> {
        self.ensure_open()?;
        if response_nonce == [0; 32]
            || self.response_states.insert(response_nonce, X4dResponseStateV1::Authorized).is_some()
        {
            return Err(X4dErrorV1::Replay);
        }
        Ok(())
    }

    pub fn mark_model_authenticated(&mut self, response_nonce: Digest) -> Result<(), X4dErrorV1> {
        self.transition_response(
            response_nonce,
            X4dResponseStateV1::Authorized,
            X4dResponseStateV1::ModelAuthenticated,
        )
    }

    pub fn freeze_response(
        &mut self,
        response_nonce: Digest,
        model_transcript_digest: Digest,
        claim_frames: Vec<ReducedClaimFrame>,
    ) -> Result<X4dFreezeReceiptV1, X4dErrorV1> {
        self.ensure_open()?;
        if self.response_state(response_nonce) != Some(X4dResponseStateV1::ModelAuthenticated)
            || model_transcript_digest == [0; 32]
        {
            return Err(X4dErrorV1::Invalid("X4d response freeze state"));
        }
        self.preflight_response_claims(claim_frames.len())?;
        let first = self.entries.len();
        let first_u64 = u64::try_from(first).map_err(|_| X4dErrorV1::Overflow)?;
        let mut staged_entries = Vec::with_capacity(claim_frames.len());
        let mut staged_digests = Vec::with_capacity(claim_frames.len());
        let mut digest = *self
            .prefix_digests
            .last()
            .ok_or(X4dErrorV1::Invalid("X4d accumulator missing initial digest"))?;
        for (offset, claim_frame) in claim_frames.into_iter().enumerate() {
            claim_frame.validate()?;
            let claim_index = first_u64
                .checked_add(u64::try_from(offset).map_err(|_| X4dErrorV1::Overflow)?)
                .ok_or(X4dErrorV1::Overflow)?;
            let auth_handle_digest = x4d_authenticated_value_handle_v1(
                self.connection_id,
                response_nonce,
                claim_index,
                claim_frame.auth_domain,
                model_transcript_digest,
            );
            let identity = X4dFrozenClaimIdentityV1 {
                connection_id: self.connection_id,
                response_nonce,
                claim_index,
                auth_handle_digest,
                claim_frame,
            };
            digest = x4d_accumulator_step_v1(digest, &identity)?;
            staged_entries.push(identity);
            staged_digests.push(digest);
        }
        let count = u32::try_from(staged_entries.len()).map_err(|_| X4dErrorV1::Overflow)?;
        self.entries.extend(staged_entries);
        self.prefix_digests.extend(staged_digests);
        self.responses.push(X4dFrozenResponseV1 {
            response_nonce,
            model_transcript_digest,
            first_claim_index: first_u64,
            claim_count: count,
            ending_accumulator_digest: digest,
        });
        self.response_states.insert(response_nonce, X4dResponseStateV1::WeightPending);
        Ok(X4dFreezeReceiptV1 {
            first_claim_index: first_u64,
            appended_count: count,
            ending_accumulator_digest: digest,
        })
    }

    pub fn compare_freeze_receipts(
        prover: &X4dFreezeReceiptV1,
        verifier: &X4dFreezeReceiptV1,
    ) -> Result<(), X4dErrorV1> {
        if prover == verifier {
            Ok(())
        } else {
            Err(X4dErrorV1::DigestMismatch)
        }
    }

    pub fn seal_pending_range(&mut self) -> Result<X4dSettlementRangeV1, X4dErrorV1> {
        self.ensure_open()?;
        if self.inflight.is_some() {
            return Err(X4dErrorV1::SettlementInFlight);
        }
        if self.verified_claims == self.entries.len() {
            return Err(X4dErrorV1::NoPendingClaims);
        }
        let first = self.verified_claims;
        let end = self.entries.len();
        let response_nonces = self
            .responses
            .iter()
            .filter(|response| {
                usize::try_from(response.first_claim_index)
                    .ok()
                    .is_some_and(|index| index >= first && index < end)
            })
            .map(|response| response.response_nonce)
            .collect::<Vec<_>>();
        if response_nonces.is_empty() {
            return Err(X4dErrorV1::Invalid("X4d settlement response range"));
        }
        let range = X4dSettlementRangeV1 {
            connection_id: self.connection_id,
            settlement_epoch: self.next_settlement_epoch,
            first_claim_index: u64::try_from(first).map_err(|_| X4dErrorV1::Overflow)?,
            claim_count: u32::try_from(end - first).map_err(|_| X4dErrorV1::Overflow)?,
            starting_accumulator_digest: self.prefix_digests[first],
            sealed_accumulator_digest: self.prefix_digests[end],
            ordered_response_nonces: response_nonces,
        };
        self.next_settlement_epoch =
            self.next_settlement_epoch.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
        self.settlement_ranges_sealed =
            self.settlement_ranges_sealed.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
        self.settlement_epochs_burned =
            self.settlement_epochs_burned.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
        self.inflight = Some(range.clone());
        Ok(range)
    }

    pub fn expected_range_claims(
        &self,
        range: &X4dSettlementRangeV1,
    ) -> Result<&[X4dFrozenClaimIdentityV1], X4dErrorV1> {
        self.validate_range_identity(range)?;
        let first = usize::try_from(range.first_claim_index).map_err(|_| X4dErrorV1::Overflow)?;
        let end = usize::try_from(range.end_claim_index()?).map_err(|_| X4dErrorV1::Overflow)?;
        self.entries.get(first..end).ok_or(X4dErrorV1::WrongSubset)
    }

    pub fn verify_exact_union(
        &self,
        range: &X4dSettlementRangeV1,
        claims: &[X4dFrozenClaimIdentityV1],
    ) -> Result<(), X4dErrorV1> {
        if self.expected_range_claims(range)? == claims {
            Ok(())
        } else {
            Err(X4dErrorV1::WrongSubset)
        }
    }

    pub fn settlement_succeeded(&mut self, range: &X4dSettlementRangeV1) -> Result<(), X4dErrorV1> {
        self.ensure_open()?;
        if self.inflight.as_ref() != Some(range) {
            return Err(X4dErrorV1::Replay);
        }
        let end = usize::try_from(range.end_claim_index()?).map_err(|_| X4dErrorV1::Overflow)?;
        for nonce in &range.ordered_response_nonces {
            if self.response_state(*nonce) != Some(X4dResponseStateV1::WeightPending) {
                return Err(X4dErrorV1::Invalid("X4d settlement response state"));
            }
        }
        for nonce in &range.ordered_response_nonces {
            self.response_states.insert(*nonce, X4dResponseStateV1::WeightVerified);
        }
        self.verified_claims = end;
        self.inflight = None;
        Ok(())
    }

    pub fn settlement_failed(&mut self) -> Result<(), X4dErrorV1> {
        if self.state != X4dConnectionStateV1::Open || self.inflight.is_none() {
            return Err(X4dErrorV1::Terminal);
        }
        self.burn_pending();
        Ok(())
    }

    pub fn abort(&mut self) {
        if self.state == X4dConnectionStateV1::Open {
            self.burn_pending();
        }
    }

    pub fn close_after_all_verified(&mut self) -> Result<(), X4dErrorV1> {
        self.ensure_open()?;
        if self.pending_claims() != 0 || self.inflight.is_some() {
            return Err(X4dErrorV1::Invalid("X4d close with pending claims"));
        }
        self.state = X4dConnectionStateV1::Closed;
        Ok(())
    }

    fn burn_pending(&mut self) {
        for state in self.response_states.values_mut() {
            if *state != X4dResponseStateV1::WeightVerified {
                *state = X4dResponseStateV1::TerminalUnverified;
            }
        }
        self.inflight = None;
        self.state = X4dConnectionStateV1::Burned;
    }

    fn validate_range_identity(&self, range: &X4dSettlementRangeV1) -> Result<(), X4dErrorV1> {
        let first = usize::try_from(range.first_claim_index).map_err(|_| X4dErrorV1::Overflow)?;
        let end = usize::try_from(range.end_claim_index()?).map_err(|_| X4dErrorV1::Overflow)?;
        if range.connection_id != self.connection_id
            || range.claim_count == 0
            || usize::try_from(range.claim_count).map_err(|_| X4dErrorV1::Overflow)?
                > X4D_PENDING_CLAIM_CAP_V1
            || end > self.entries.len()
            || self.prefix_digests.get(first).copied() != Some(range.starting_accumulator_digest)
            || self.prefix_digests.get(end).copied() != Some(range.sealed_accumulator_digest)
        {
            return Err(X4dErrorV1::WrongSubset);
        }
        Ok(())
    }

    fn transition_response(
        &mut self,
        nonce: Digest,
        expected: X4dResponseStateV1,
        next: X4dResponseStateV1,
    ) -> Result<(), X4dErrorV1> {
        self.ensure_open()?;
        if self.response_state(nonce) != Some(expected) {
            return Err(X4dErrorV1::Invalid("X4d response transition"));
        }
        self.response_states.insert(nonce, next);
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), X4dErrorV1> {
        if self.state == X4dConnectionStateV1::Open {
            Ok(())
        } else {
            Err(X4dErrorV1::Terminal)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dSettlementContextV1 {
    pub range: X4dSettlementRangeV1,
}

fn write_context_v1(out: &mut Vec<u8>, context: &X4dSettlementContextV1) -> Result<(), X4dErrorV1> {
    let response_count = u32::try_from(context.range.ordered_response_nonces.len())
        .map_err(|_| X4dErrorV1::Overflow)?;
    out.extend_from_slice(&context.range.connection_id);
    out.extend_from_slice(&context.range.settlement_epoch.to_le_bytes());
    out.extend_from_slice(&context.range.first_claim_index.to_le_bytes());
    out.extend_from_slice(&context.range.claim_count.to_le_bytes());
    out.extend_from_slice(&context.range.starting_accumulator_digest);
    out.extend_from_slice(&context.range.sealed_accumulator_digest);
    out.extend_from_slice(&response_count.to_le_bytes());
    for nonce in &context.range.ordered_response_nonces {
        out.extend_from_slice(nonce);
    }
    Ok(())
}

pub fn x4d_settlement_context_digest_v1(
    context: &X4dSettlementContextV1,
) -> Result<Digest, X4dErrorV1> {
    let mut encoded = Vec::new();
    write_context_v1(&mut encoded, context)?;
    let mut hasher = blake3::Hasher::new_derive_key(X4D_SETTLEMENT_CONTEXT_DIGEST_V1);
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

pub fn authenticated_output_link_schedule_digest_x4d_v1(
    context: &X4dSettlementContextV1,
    claim_frames: &[ReducedClaimFrame],
    descriptor_digests: &[Digest],
    ordered_h_symbols: &[volta_field::Fp2],
    m9_frames: &[M9TransferFrame],
    round_count: u8,
    round_correlation_domain_ids: &[u64],
) -> Result<Digest, X4dErrorV1> {
    if claim_frames.len()
        != usize::try_from(context.range.claim_count).map_err(|_| X4dErrorV1::Overflow)?
        || descriptor_digests.is_empty()
        || ordered_h_symbols.len() != m9_frames.len()
        || m9_frames.len() > X4D_MASKED_GROUP_CAP_V1
        || round_count > 30
        || round_correlation_domain_ids.len() != 2 * usize::from(round_count)
        || !round_correlation_domain_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(X4dErrorV1::Invalid("X4d link schedule geometry"));
    }
    let claim_count = u32::try_from(claim_frames.len()).map_err(|_| X4dErrorV1::Overflow)?;
    let descriptor_count =
        u16::try_from(descriptor_digests.len()).map_err(|_| X4dErrorV1::Overflow)?;
    let symbol_count = u16::try_from(ordered_h_symbols.len()).map_err(|_| X4dErrorV1::Overflow)?;
    let descriptors = descriptor_digests.iter().copied().collect::<BTreeSet<_>>();
    if descriptors.len() != descriptor_digests.len()
        || claim_frames.iter().any(|claim| !descriptors.contains(&claim.descriptor_digest))
        || m9_frames.iter().any(|frame| !descriptors.contains(&frame.descriptor_digest))
    {
        return Err(X4dErrorV1::Invalid("X4d link schedule descriptors"));
    }
    let mut preimage = Vec::new();
    write_context_v1(&mut preimage, context)?;
    preimage.extend_from_slice(&claim_count.to_le_bytes());
    for claim in claim_frames {
        let bytes = FrameV4::ReducedClaim(claim.clone()).encode()?;
        let frame_len = u32::try_from(bytes.len()).map_err(|_| X4dErrorV1::Overflow)?;
        preimage.extend_from_slice(&frame_len.to_le_bytes());
        preimage.extend_from_slice(&bytes);
    }
    preimage.extend_from_slice(&descriptor_count.to_le_bytes());
    for descriptor in descriptor_digests {
        preimage.extend_from_slice(descriptor);
    }
    preimage.extend_from_slice(&symbol_count.to_le_bytes());
    for symbol in ordered_h_symbols {
        preimage.extend_from_slice(&symbol.c0.value().to_le_bytes());
        preimage.extend_from_slice(&symbol.c1.value().to_le_bytes());
    }
    for frame in m9_frames {
        let bytes = FrameV4::M9Transfer(frame.clone()).encode()?;
        let frame_len = u32::try_from(bytes.len()).map_err(|_| X4dErrorV1::Overflow)?;
        preimage.extend_from_slice(&frame_len.to_le_bytes());
        preimage.extend_from_slice(&bytes);
    }
    preimage.push(round_count);
    for domain in round_correlation_domain_ids {
        preimage.extend_from_slice(&domain.to_le_bytes());
    }
    let mut hasher = blake3::Hasher::new_derive_key(X4D_LINK_SCHEDULE_CONTEXT_V1);
    hasher.update(&preimage);
    Ok(*hasher.finalize().as_bytes())
}

pub fn opening_schedule_digest_x4d_v1(
    context: &X4dSettlementContextV1,
    schedule: &PackedOpeningScheduleV4,
) -> Result<Digest, X4dErrorV1> {
    schedule.validate()?;
    if schedule.epoch != context.range.settlement_epoch {
        return Err(X4dErrorV1::Invalid("X4d opening epoch"));
    }
    let canonical_v4 = opening_schedule_digest_v4(schedule)?;
    let mut preimage = Vec::new();
    write_context_v1(&mut preimage, context)?;
    preimage.extend_from_slice(&canonical_v4);
    let mut hasher = blake3::Hasher::new_derive_key(X4D_OPENING_SCHEDULE_CONTEXT_V1);
    hasher.update(&preimage);
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dSettlementEnvelopeV1 {
    pub profile_digest: Digest,
    pub model_root: Digest,
    pub settlement_epoch: u64,
    pub descriptor_digests: Vec<Digest>,
    pub manifest_frames: Vec<ManifestFrameV4>,
    pub claim_frames: Vec<ReducedClaimFrame>,
    pub ordered_h_symbols: Vec<volta_field::Fp2>,
    pub m9_frames: Vec<M9TransferFrame>,
    pub authenticated_output_link_frame: AuthenticatedOutputLinkFrame,
    pub fold_frames: Vec<FoldCommitmentFrameV4>,
    pub packed_opening_frame: PackedBatchOpeningFrameV4,
    pub zero_batch_frame: ResponseZeroBatchFrame,
}

impl X4dSettlementEnvelopeV1 {
    pub fn validate(
        &self,
        context: &X4dSettlementContextV1,
        expected_claims: &[X4dFrozenClaimIdentityV1],
        expected_manifest_frames: &[ManifestFrameV4],
        round_correlation_domain_ids: &[u64],
        opening_schedule: &PackedOpeningScheduleV4,
    ) -> Result<(), X4dErrorV1> {
        let expected_frames =
            expected_claims.iter().map(|claim| &claim.claim_frame).collect::<Vec<_>>();
        if self.profile_digest != x4d_profile_digest_v1()
            || self.model_root == [0; 32]
            || self.settlement_epoch != context.range.settlement_epoch
            || self.claim_frames.len() > X4D_PENDING_CLAIM_CAP_V1
            || self.claim_frames.len()
                != usize::try_from(context.range.claim_count).map_err(|_| X4dErrorV1::Overflow)?
            || self.claim_frames.iter().collect::<Vec<_>>() != expected_frames
            || self.manifest_frames != expected_manifest_frames
            || self.descriptor_digests.is_empty()
            || self.descriptor_digests.iter().copied().collect::<BTreeSet<_>>().len()
                != self.descriptor_digests.len()
            || self.ordered_h_symbols.len() > X4D_MASKED_GROUP_CAP_V1
            || self.ordered_h_symbols.len() != self.m9_frames.len()
            || usize::from(self.zero_batch_frame.claim_count) != self.m9_frames.len()
            || usize::from(self.authenticated_output_link_frame.relation_count)
                != 2 * self.m9_frames.len()
            || self.fold_frames.is_empty()
            || self.fold_frames.len() > 30
            || opening_schedule.model_root != self.model_root
            || opening_schedule.epoch != self.settlement_epoch
            || opening_schedule.fold_frames != self.fold_frames
        {
            return Err(X4dErrorV1::Invalid("X4d settlement statement"));
        }
        let descriptors = self.descriptor_digests.iter().copied().collect::<BTreeSet<_>>();
        if self.claim_frames.iter().any(|claim| !descriptors.contains(&claim.descriptor_digest))
            || self.m9_frames.iter().any(|frame| !descriptors.contains(&frame.descriptor_digest))
        {
            return Err(X4dErrorV1::Invalid("X4d settlement descriptor membership"));
        }
        for frame in &self.manifest_frames {
            frame_as_v4(frame).encode()?;
        }
        for frame in &self.claim_frames {
            FrameV4::ReducedClaim(frame.clone()).encode()?;
        }
        for frame in &self.m9_frames {
            FrameV4::M9Transfer(frame.clone()).encode()?;
        }
        for (index, frame) in self.fold_frames.iter().enumerate() {
            frame.validate()?;
            if usize::from(frame.fold_round) != index + 1 {
                return Err(X4dErrorV1::Invalid("X4d fold order"));
            }
        }
        FrameV4::AuthenticatedOutputLink(self.authenticated_output_link_frame.clone()).encode()?;
        FrameV4::ResponseZeroBatch(self.zero_batch_frame.clone()).encode()?;
        let expected_link = authenticated_output_link_schedule_digest_x4d_v1(
            context,
            &self.claim_frames,
            &self.descriptor_digests,
            &self.ordered_h_symbols,
            &self.m9_frames,
            self.authenticated_output_link_frame.round_count,
            round_correlation_domain_ids,
        )?;
        if expected_link != self.authenticated_output_link_frame.link_schedule_digest {
            return Err(X4dErrorV1::DigestMismatch);
        }
        let expected_opening = opening_schedule_digest_x4d_v1(context, opening_schedule)?;
        if self.packed_opening_frame.opening_schedule_digest != expected_opening {
            return Err(X4dErrorV1::DigestMismatch);
        }
        // Reuse the complete schema-4 structural validator after replacing
        // only the domain-separated digest field in a temporary view.
        let mut structural_view = self.packed_opening_frame.clone();
        structural_view.opening_schedule_digest = opening_schedule_digest_v4(opening_schedule)?;
        structural_view.validate_against_schedule(opening_schedule)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, X4dErrorV1> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.profile_digest);
        body.extend_from_slice(&self.model_root);
        body.extend_from_slice(&self.settlement_epoch.to_le_bytes());
        put_u16(&mut body, self.descriptor_digests.len())?;
        for descriptor in &self.descriptor_digests {
            body.extend_from_slice(descriptor);
        }
        put_u32(&mut body, self.manifest_frames.len())?;
        for frame in &self.manifest_frames {
            put_nested(&mut body, &frame_as_v4(frame).encode()?)?;
        }
        put_u32(&mut body, self.claim_frames.len())?;
        for frame in &self.claim_frames {
            put_nested(&mut body, &FrameV4::ReducedClaim(frame.clone()).encode()?)?;
        }
        put_u16(&mut body, self.ordered_h_symbols.len())?;
        for symbol in &self.ordered_h_symbols {
            body.extend_from_slice(&symbol.c0.value().to_le_bytes());
            body.extend_from_slice(&symbol.c1.value().to_le_bytes());
        }
        put_u16(&mut body, self.m9_frames.len())?;
        for frame in &self.m9_frames {
            put_nested(&mut body, &FrameV4::M9Transfer(frame.clone()).encode()?)?;
        }
        put_nested(
            &mut body,
            &FrameV4::AuthenticatedOutputLink(self.authenticated_output_link_frame.clone())
                .encode()?,
        )?;
        put_u32(&mut body, self.fold_frames.len())?;
        for frame in &self.fold_frames {
            put_nested(&mut body, &FrameV4::FoldCommitment(frame.clone()).encode()?)?;
        }
        put_u32(&mut body, 1)?;
        put_nested(
            &mut body,
            &FrameV4::PackedBatchOpening(self.packed_opening_frame.clone()).encode()?,
        )?;
        put_nested(
            &mut body,
            &FrameV4::ResponseZeroBatch(self.zero_batch_frame.clone()).encode()?,
        )?;
        let body_len = u32::try_from(body.len()).map_err(|_| X4dErrorV1::Overflow)?;
        let mut encoded = Vec::with_capacity(X4D_HEADER_BYTES_V1 + body.len());
        encoded.extend_from_slice(&X4D_MAGIC_V1);
        encoded.extend_from_slice(&X4D_SCHEMA_V1.to_le_bytes());
        encoded.push(X4D_SETTLEMENT_KIND_V1);
        encoded.push(0);
        encoded.extend_from_slice(&body_len.to_le_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, X4dErrorV1> {
        if bytes.len() < X4D_HEADER_BYTES_V1
            || bytes[..8] != X4D_MAGIC_V1
            || bytes[8..10] != X4D_SCHEMA_V1.to_le_bytes()
            || bytes[10] != X4D_SETTLEMENT_KIND_V1
            || bytes[11] != 0
        {
            return Err(X4dErrorV1::Invalid("X4d settlement header"));
        }
        let declared = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice"));
        if usize::try_from(declared).map_err(|_| X4dErrorV1::Overflow)?
            != bytes.len() - X4D_HEADER_BYTES_V1
        {
            return Err(X4dErrorV1::Invalid("X4d settlement body length"));
        }
        let mut input = X4dReaderV1::new(&bytes[X4D_HEADER_BYTES_V1..]);
        let profile_digest = input.digest()?;
        let model_root = input.digest()?;
        let settlement_epoch = input.u64()?;
        let descriptor_count = usize::from(input.u16()?);
        let mut descriptor_digests = Vec::with_capacity(descriptor_count);
        for _ in 0..descriptor_count {
            descriptor_digests.push(input.digest()?);
        }
        let manifest_count = input.usize_u32()?;
        let mut manifest_frames = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            manifest_frames.push(match input.nested_v4()? {
                FrameV4::ManifestLeaf(frame) => ManifestFrameV4::Leaf(frame),
                FrameV4::ManifestNode(frame) => ManifestFrameV4::Node(frame),
                _ => return Err(X4dErrorV1::Invalid("X4d manifest child kind")),
            });
        }
        let claim_count = input.usize_u32()?;
        let mut claim_frames = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            match input.nested_v4()? {
                FrameV4::ReducedClaim(frame) => claim_frames.push(frame),
                _ => return Err(X4dErrorV1::Invalid("X4d claim child kind")),
            }
        }
        let h_count = usize::from(input.u16()?);
        let mut ordered_h_symbols = Vec::with_capacity(h_count);
        for _ in 0..h_count {
            ordered_h_symbols.push(input.fp2()?);
        }
        let m9_count = usize::from(input.u16()?);
        let mut m9_frames = Vec::with_capacity(m9_count);
        for _ in 0..m9_count {
            match input.nested_v4()? {
                FrameV4::M9Transfer(frame) => m9_frames.push(frame),
                _ => return Err(X4dErrorV1::Invalid("X4d M9 child kind")),
            }
        }
        let authenticated_output_link_frame = match input.nested_v4()? {
            FrameV4::AuthenticatedOutputLink(frame) => frame,
            _ => return Err(X4dErrorV1::Invalid("X4d link child kind")),
        };
        let fold_count = input.usize_u32()?;
        let mut fold_frames = Vec::with_capacity(fold_count);
        for _ in 0..fold_count {
            match input.nested_v4()? {
                FrameV4::FoldCommitment(frame) => fold_frames.push(frame),
                _ => return Err(X4dErrorV1::Invalid("X4d fold child kind")),
            }
        }
        if input.u32()? != 1 {
            return Err(X4dErrorV1::Invalid("X4d opening multiplicity"));
        }
        let packed_opening_frame = match input.nested_v4()? {
            FrameV4::PackedBatchOpening(frame) => frame,
            _ => return Err(X4dErrorV1::Invalid("X4d packed-opening child kind")),
        };
        let zero_batch_frame = match input.nested_v4()? {
            FrameV4::ResponseZeroBatch(frame) => frame,
            _ => return Err(X4dErrorV1::Invalid("X4d ZeroBatch child kind")),
        };
        input.finish()?;
        Ok(Self {
            profile_digest,
            model_root,
            settlement_epoch,
            descriptor_digests,
            manifest_frames,
            claim_frames,
            ordered_h_symbols,
            m9_frames,
            authenticated_output_link_frame,
            fold_frames,
            packed_opening_frame,
            zero_batch_frame,
        })
    }
}

fn frame_as_v4(frame: &ManifestFrameV4) -> FrameV4 {
    match frame {
        ManifestFrameV4::Leaf(frame) => FrameV4::ManifestLeaf(frame.clone()),
        ManifestFrameV4::Node(frame) => FrameV4::ManifestNode(frame.clone()),
    }
}

fn put_u16(out: &mut Vec<u8>, value: usize) -> Result<(), X4dErrorV1> {
    out.extend_from_slice(&u16::try_from(value).map_err(|_| X4dErrorV1::Overflow)?.to_le_bytes());
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), X4dErrorV1> {
    out.extend_from_slice(&u32::try_from(value).map_err(|_| X4dErrorV1::Overflow)?.to_le_bytes());
    Ok(())
}

fn put_nested(out: &mut Vec<u8>, encoded: &[u8]) -> Result<(), X4dErrorV1> {
    if encoded.len() < 16 {
        return Err(X4dErrorV1::Invalid("short X4d nested frame"));
    }
    out.extend_from_slice(encoded);
    Ok(())
}

struct X4dReaderV1<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> X4dReaderV1<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], X4dErrorV1> {
        let end = self.cursor.checked_add(len).ok_or(X4dErrorV1::Overflow)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(X4dErrorV1::Invalid("truncated X4d settlement"))?;
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, X4dErrorV1> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }

    fn u32(&mut self) -> Result<u32, X4dErrorV1> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }

    fn u64(&mut self) -> Result<u64, X4dErrorV1> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }

    fn usize_u32(&mut self) -> Result<usize, X4dErrorV1> {
        usize::try_from(self.u32()?).map_err(|_| X4dErrorV1::Overflow)
    }

    fn digest(&mut self) -> Result<Digest, X4dErrorV1> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }

    fn fp2(&mut self) -> Result<volta_field::Fp2, X4dErrorV1> {
        let c0 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed slice"));
        let c1 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed slice"));
        if c0 >= volta_field::P || c1 >= volta_field::P {
            return Err(X4dErrorV1::Invalid("noncanonical X4d field element"));
        }
        Ok(volta_field::Fp2 { c0: volta_field::Fp::new(c0), c1: volta_field::Fp::new(c1) })
    }

    fn nested_v4(&mut self) -> Result<FrameV4, X4dErrorV1> {
        let header = self
            .bytes
            .get(self.cursor..self.cursor.checked_add(16).ok_or(X4dErrorV1::Overflow)?)
            .ok_or(X4dErrorV1::Invalid("truncated X4d nested header"))?;
        let body_len = u32::from_le_bytes(header[12..16].try_into().expect("fixed slice"));
        let total = 16usize
            .checked_add(usize::try_from(body_len).map_err(|_| X4dErrorV1::Overflow)?)
            .ok_or(X4dErrorV1::Overflow)?;
        Ok(decode_v4(self.take(total)?)?)
    }

    fn finish(self) -> Result<(), X4dErrorV1> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(X4dErrorV1::Invalid("trailing X4d settlement bytes"))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4dGpuLeaseHolderV1 {
    Idle,
    Response,
    Settlement,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4dBackgroundAccountingV1 {
    pub settlement_wall_ns: u64,
    pub active_cpu_ns: u64,
    pub active_gpu_ns: u64,
    pub lease_wait_ns: u64,
    pub pause_ns: u64,
    pub overlap_cpu_intervals: u64,
    pub overlap_gpu_intervals: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct X4dInterferenceDeltaV1 {
    pub isolated_response_ns: u64,
    pub overlapped_response_ns: u64,
    pub absolute_delta_ns: i128,
    pub percentage_delta: f64,
}

impl X4dInterferenceDeltaV1 {
    pub fn new(isolated_response_ns: u64, overlapped_response_ns: u64) -> Self {
        let absolute_delta_ns =
            i128::from(overlapped_response_ns) - i128::from(isolated_response_ns);
        let percentage_delta = if isolated_response_ns == 0 {
            f64::NAN
        } else {
            100.0 * absolute_delta_ns as f64 / isolated_response_ns as f64
        };
        Self { isolated_response_ns, overlapped_response_ns, absolute_delta_ns, percentage_delta }
    }
}

/// Cooperative one-GPU lease.  A response request never steals a running
/// kernel; settlement yields at the next explicit kernel boundary.
#[derive(Clone, Debug)]
pub struct X4dGpuLeaseV1 {
    holder: X4dGpuLeaseHolderV1,
    response_waiting: bool,
    pause_started: Option<Instant>,
    accounting: X4dBackgroundAccountingV1,
}

impl Default for X4dGpuLeaseV1 {
    fn default() -> Self {
        Self {
            holder: X4dGpuLeaseHolderV1::Idle,
            response_waiting: false,
            pause_started: None,
            accounting: X4dBackgroundAccountingV1::default(),
        }
    }
}

impl X4dGpuLeaseV1 {
    pub fn holder(&self) -> X4dGpuLeaseHolderV1 {
        self.holder
    }

    pub fn begin_settlement(&mut self) -> Result<(), X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Idle {
            return Err(X4dErrorV1::SettlementInFlight);
        }
        self.holder = X4dGpuLeaseHolderV1::Settlement;
        Ok(())
    }

    pub fn request_response(&mut self) -> bool {
        match self.holder {
            X4dGpuLeaseHolderV1::Idle => {
                self.holder = X4dGpuLeaseHolderV1::Response;
                true
            }
            X4dGpuLeaseHolderV1::Settlement => {
                self.response_waiting = true;
                false
            }
            X4dGpuLeaseHolderV1::Response => false,
        }
    }

    pub fn settlement_kernel_boundary(&mut self) -> Result<bool, X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Settlement {
            return Err(X4dErrorV1::Invalid("X4d settlement boundary without lease"));
        }
        if self.response_waiting {
            self.holder = X4dGpuLeaseHolderV1::Response;
            self.response_waiting = false;
            self.pause_started = Some(Instant::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn response_finished(&mut self) -> Result<(), X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Response {
            return Err(X4dErrorV1::Invalid("X4d response does not hold GPU lease"));
        }
        if let Some(started) = self.pause_started.take() {
            self.accounting.pause_ns = self
                .accounting
                .pause_ns
                .checked_add(duration_ns(started.elapsed())?)
                .ok_or(X4dErrorV1::Overflow)?;
            self.holder = X4dGpuLeaseHolderV1::Settlement;
        } else {
            self.holder = X4dGpuLeaseHolderV1::Idle;
        }
        Ok(())
    }

    pub fn settlement_finished(
        &mut self,
        wall: Duration,
    ) -> Result<X4dBackgroundAccountingV1, X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Settlement || self.pause_started.is_some() {
            return Err(X4dErrorV1::Invalid("X4d settlement finish state"));
        }
        self.accounting.settlement_wall_ns = duration_ns(wall)?;
        self.holder = X4dGpuLeaseHolderV1::Idle;
        Ok(self.accounting)
    }

    pub fn record_settlement_cpu_interval(
        &mut self,
        duration: Duration,
        overlaps_response: bool,
    ) -> Result<(), X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Settlement
            && !(self.holder == X4dGpuLeaseHolderV1::Response && self.pause_started.is_some())
        {
            return Err(X4dErrorV1::Invalid("X4d settlement CPU accounting outside settlement"));
        }
        self.accounting.active_cpu_ns = self
            .accounting
            .active_cpu_ns
            .checked_add(duration_ns(duration)?)
            .ok_or(X4dErrorV1::Overflow)?;
        if overlaps_response {
            self.accounting.overlap_cpu_intervals =
                self.accounting.overlap_cpu_intervals.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
        }
        Ok(())
    }

    pub fn record_settlement_gpu_interval(&mut self, duration: Duration) -> Result<(), X4dErrorV1> {
        if self.holder != X4dGpuLeaseHolderV1::Settlement {
            return Err(X4dErrorV1::Invalid("X4d settlement GPU accounting without lease"));
        }
        self.accounting.active_gpu_ns = self
            .accounting
            .active_gpu_ns
            .checked_add(duration_ns(duration)?)
            .ok_or(X4dErrorV1::Overflow)?;
        if self.response_waiting {
            self.accounting.overlap_gpu_intervals =
                self.accounting.overlap_gpu_intervals.checked_add(1).ok_or(X4dErrorV1::Overflow)?;
        }
        Ok(())
    }

    pub fn record_lease_wait(&mut self, duration: Duration) -> Result<(), X4dErrorV1> {
        self.accounting.lease_wait_ns = self
            .accounting
            .lease_wait_ns
            .checked_add(duration_ns(duration)?)
            .ok_or(X4dErrorV1::Overflow)?;
        Ok(())
    }
}

fn duration_ns(duration: Duration) -> Result<u64, X4dErrorV1> {
    u64::try_from(duration.as_nanos()).map_err(|_| X4dErrorV1::Overflow)
}

#[cfg(test)]
mod tests {
    use super::super::frame::Phase;
    use super::*;
    use volta_field::{Fp, Fp2};

    fn digest(byte: u8) -> Digest {
        [byte; 32]
    }

    fn claim(descriptor: Digest, ordinal: u64) -> ReducedClaimFrame {
        ReducedClaimFrame {
            descriptor_digest: descriptor,
            parent_claim_digest: digest(ordinal as u8),
            phase: if ordinal & 1 == 0 { Phase::Prefill } else { Phase::Decode },
            phase_ordinal: (ordinal & 1) as u16,
            point: vec![Fp2::from_base(Fp::new(ordinal + 1)); 14],
            affine_scale: Fp2::ONE,
            auth_domain: 0x9000 + ordinal,
        }
    }

    fn accumulator() -> X4dClaimAccumulatorV1 {
        X4dClaimAccumulatorV1::new(
            digest(0x11),
            digest(0x22),
            X4dSettlementPolicyV1::production_gpt2(),
        )
        .unwrap()
    }

    fn freeze(
        accumulator: &mut X4dClaimAccumulatorV1,
        nonce: Digest,
        frames: Vec<ReducedClaimFrame>,
    ) -> X4dFreezeReceiptV1 {
        accumulator.preflight_response_claims(frames.len()).unwrap();
        accumulator.authorize_response(nonce).unwrap();
        accumulator.mark_model_authenticated(nonce).unwrap();
        accumulator.freeze_response(nonce, digest(nonce[0].wrapping_add(1)), frames).unwrap()
    }

    #[test]
    fn accumulator_roles_match_and_omission_reorder_mismatch() {
        let descriptors = [digest(0x31), digest(0x32)];
        let frames = vec![claim(descriptors[0], 0), claim(descriptors[1], 1)];
        let mut prover = accumulator();
        let mut verifier = accumulator();
        let prover_receipt = freeze(&mut prover, digest(0x41), frames.clone());
        let verifier_receipt = freeze(&mut verifier, digest(0x41), frames.clone());
        X4dClaimAccumulatorV1::compare_freeze_receipts(&prover_receipt, &verifier_receipt).unwrap();
        assert_eq!(prover.entries(), verifier.entries());

        let mut omitted = accumulator();
        let omitted_receipt = freeze(&mut omitted, digest(0x41), frames[..1].to_vec());
        assert_eq!(
            X4dClaimAccumulatorV1::compare_freeze_receipts(&prover_receipt, &omitted_receipt),
            Err(X4dErrorV1::DigestMismatch)
        );

        let mut reordered = accumulator();
        let reordered_receipt =
            freeze(&mut reordered, digest(0x41), frames.into_iter().rev().collect());
        assert_eq!(
            X4dClaimAccumulatorV1::compare_freeze_receipts(&prover_receipt, &reordered_receipt),
            Err(X4dErrorV1::DigestMismatch)
        );
    }

    #[test]
    fn authenticated_value_store_rejects_post_freeze_substitution() {
        let mut store = X4dAuthenticatedValueStoreV1::default();
        store.freeze(digest(0x51), Fp2::ONE).unwrap();
        assert_eq!(store.freeze(digest(0x51), Fp2::ZERO), Err(X4dErrorV1::DigestMismatch));
        assert_eq!(store.get(&digest(0x51)), Some(&Fp2::ONE));
    }

    #[test]
    fn post_freeze_value_substitution_is_rejected_by_m2_mac() {
        use volta_mac::{
            zero_open_prover, zero_open_verify, ProverAuthed, Transcript, VerifierKey,
        };

        let handle = digest(0x52);
        let delta = Fp2::from_base(Fp::new(17));
        let honest =
            ProverAuthed { x: Fp2::from_base(Fp::new(23)), m: Fp2::from_base(Fp::new(29)) };
        let frozen_key = VerifierKey { k: honest.m + delta * honest.x };
        let mut prover_store = X4dAuthenticatedValueStoreV1::default();
        let mut verifier_store = X4dAuthenticatedValueStoreV1::default();
        prover_store.freeze(handle, honest).unwrap();
        verifier_store.freeze(handle, frozen_key).unwrap();

        // The handle is write-once. Even if a malicious prover locally
        // reopens its frozen share with a different plaintext while retaining
        // the old tag, the verifier keeps the original Delta-bound key.
        let substituted = ProverAuthed { x: honest.x + Fp2::ONE, m: honest.m };
        assert_eq!(prover_store.freeze(handle, substituted), Err(X4dErrorV1::DigestMismatch));
        let prover_residual = substituted.sub(ProverAuthed::from_public(substituted.x));
        let verifier_residual = verifier_store
            .get(&handle)
            .copied()
            .unwrap()
            .sub(VerifierKey::from_public(substituted.x, delta));
        let mut transcript = Transcript::new([0x53; 32]);
        let opened_tag = zero_open_prover(&prover_residual, &mut transcript);
        assert!(!zero_open_verify(verifier_residual, opened_tag));
    }

    #[test]
    fn claim_3321_refuses_until_settlement_succeeds() {
        let descriptor = digest(0x61);
        let mut accumulator = accumulator();
        let frames =
            (0..X4D_PENDING_CLAIM_CAP_V1).map(|index| claim(descriptor, index as u64)).collect();
        freeze(&mut accumulator, digest(0x62), frames);
        assert_eq!(accumulator.pending_claims(), X4D_PENDING_CLAIM_CAP_V1);
        assert_eq!(
            accumulator.preflight_response_claims(1),
            Err(X4dErrorV1::CapacityRefused {
                pending: X4D_PENDING_CLAIM_CAP_V1,
                incoming: 1,
                cap: X4D_PENDING_CLAIM_CAP_V1,
            })
        );
        assert_eq!(accumulator.cap_refusals, 1);
        let range = accumulator.seal_pending_range().unwrap();
        accumulator.settlement_succeeded(&range).unwrap();
        accumulator.preflight_response_claims(1).unwrap();
    }

    #[test]
    fn fixed_gpt2_response_33_is_refused_before_nonce_authorization() {
        let descriptor = digest(0x66);
        let mut accumulator = accumulator();
        for response in 0..32u8 {
            let frames = (0..X4D_GPT2_CLAIMS_PER_RESPONSE_V1)
                .map(|claim_index| {
                    claim(
                        descriptor,
                        u64::from(response) * X4D_GPT2_CLAIMS_PER_RESPONSE_V1 as u64
                            + claim_index as u64,
                    )
                })
                .collect();
            freeze(&mut accumulator, digest(0x80 + response), frames);
        }
        assert_eq!(accumulator.pending_claims(), 3_264);
        assert_eq!(
            accumulator.preflight_response_claims(X4D_GPT2_CLAIMS_PER_RESPONSE_V1),
            Err(X4dErrorV1::CapacityRefused {
                pending: 3_264,
                incoming: 102,
                cap: X4D_PENDING_CLAIM_CAP_V1,
            })
        );
        assert_eq!(accumulator.response_state(digest(0xA0)), None);
        assert_eq!(accumulator.cap_refusals, 1);
    }

    #[test]
    fn exact_range_rejects_subset_reorder_and_replay() {
        let descriptor = digest(0x71);
        let mut accumulator = accumulator();
        freeze(&mut accumulator, digest(0x72), vec![claim(descriptor, 0), claim(descriptor, 1)]);
        freeze(&mut accumulator, digest(0x73), vec![claim(descriptor, 2), claim(descriptor, 3)]);
        let range = accumulator.seal_pending_range().unwrap();
        let exact = accumulator.expected_range_claims(&range).unwrap().to_vec();
        accumulator.verify_exact_union(&range, &exact).unwrap();
        assert_eq!(
            accumulator.verify_exact_union(&range, &exact[..3]),
            Err(X4dErrorV1::WrongSubset)
        );
        let mut reordered = exact.clone();
        reordered.swap(0, 1);
        assert_eq!(
            accumulator.verify_exact_union(&range, &reordered),
            Err(X4dErrorV1::WrongSubset)
        );
        accumulator.settlement_succeeded(&range).unwrap();
        assert_eq!(accumulator.settlement_succeeded(&range), Err(X4dErrorV1::Replay));
    }

    #[test]
    fn settlement_failure_is_terminal_and_older_verified_stays_verified() {
        let descriptor = digest(0x81);
        let mut accumulator = accumulator();
        let first = digest(0x82);
        freeze(&mut accumulator, first, vec![claim(descriptor, 0)]);
        let range = accumulator.seal_pending_range().unwrap();
        accumulator.settlement_succeeded(&range).unwrap();
        let second = digest(0x83);
        freeze(&mut accumulator, second, vec![claim(descriptor, 1)]);
        accumulator.seal_pending_range().unwrap();
        accumulator.settlement_failed().unwrap();
        assert_eq!(accumulator.response_state(first), Some(X4dResponseStateV1::WeightVerified));
        assert_eq!(
            accumulator.response_state(second),
            Some(X4dResponseStateV1::TerminalUnverified)
        );
        assert_eq!(accumulator.state(), X4dConnectionStateV1::Burned);
        assert_eq!(accumulator.seal_pending_range(), Err(X4dErrorV1::Terminal));
    }

    #[test]
    fn explicit_abort_before_settlement_marks_pending_terminal_unverified() {
        let descriptor = digest(0x84);
        let nonce = digest(0x85);
        let mut accumulator = accumulator();
        freeze(&mut accumulator, nonce, vec![claim(descriptor, 0)]);
        assert_eq!(accumulator.response_state(nonce), Some(X4dResponseStateV1::WeightPending));

        accumulator.abort();

        assert_eq!(accumulator.state(), X4dConnectionStateV1::Burned);
        assert_eq!(accumulator.response_state(nonce), Some(X4dResponseStateV1::TerminalUnverified));
        assert_eq!(accumulator.seal_pending_range(), Err(X4dErrorV1::Terminal));
        assert_eq!(accumulator.close_after_all_verified(), Err(X4dErrorV1::Terminal));
    }

    #[test]
    fn gpu_lease_yields_only_at_boundary_and_accounts_pause() {
        let mut lease = X4dGpuLeaseV1::default();
        lease.begin_settlement().unwrap();
        lease.record_settlement_cpu_interval(Duration::from_micros(20), false).unwrap();
        lease.record_settlement_gpu_interval(Duration::from_micros(30)).unwrap();
        assert!(!lease.request_response());
        lease.record_settlement_gpu_interval(Duration::from_micros(40)).unwrap();
        assert_eq!(lease.holder(), X4dGpuLeaseHolderV1::Settlement);
        assert!(lease.settlement_kernel_boundary().unwrap());
        assert_eq!(lease.holder(), X4dGpuLeaseHolderV1::Response);
        lease.record_settlement_cpu_interval(Duration::from_micros(50), true).unwrap();
        lease.record_lease_wait(Duration::from_micros(60)).unwrap();
        lease.response_finished().unwrap();
        assert_eq!(lease.holder(), X4dGpuLeaseHolderV1::Settlement);
        let accounting = lease.settlement_finished(Duration::from_millis(3)).unwrap();
        assert_eq!(accounting.settlement_wall_ns, 3_000_000);
        assert_eq!(accounting.active_cpu_ns, 70_000);
        assert_eq!(accounting.active_gpu_ns, 70_000);
        assert_eq!(accounting.lease_wait_ns, 60_000);
        assert_eq!(accounting.overlap_cpu_intervals, 1);
        assert_eq!(accounting.overlap_gpu_intervals, 1);
    }

    #[test]
    fn codec_formula_and_response_projection_are_exact() {
        assert_eq!(X4D_GPT2_RESPONSE_BYTES_V1, 41_270_464);
        assert_eq!(x4d_gpt2_settlement_bytes_v1(1).unwrap(), 2_683_236);
        assert_eq!(x4d_gpt2_settlement_bytes_v1(8).unwrap(), 3_036_204);
        assert_eq!(x4d_gpt2_settlement_bytes_v1(16).unwrap(), 3_439_596);
        assert_eq!(x4d_gpt2_settlement_bytes_v1(32).unwrap(), 4_246_380);
    }

    #[test]
    fn interference_delta_is_reported_separately() {
        let delta = X4dInterferenceDeltaV1::new(1_000, 1_100);
        assert_eq!(delta.absolute_delta_ns, 100);
        assert!((delta.percentage_delta - 10.0).abs() < f64::EPSILON);
    }
}

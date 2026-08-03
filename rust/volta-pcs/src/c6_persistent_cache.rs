//! PCS-native persistent-cache layout and scaled transition reference for C6.
//!
//! Cache roots use response-independent slot descriptors.  The outer
//! transition binding carries the response-local old/new roles, epochs,
//! lengths and source-map digest, so a successor root can be reused unchanged
//! as the next predecessor root.  BLAKE3 below hashes public descriptors and
//! codec frames only; it is not treated as an algebraic cache-transition
//! oracle.
//!
//! This module deliberately stops at a direct scaled relation checker.  The
//! production source adapter, blind 24-round coordinator and pending-output
//! link remain separate gates.

use std::fmt;

use volta_field::Fp2;
use volta_proto::C6Workload;

pub const C6_PERSISTENT_CACHE_PROFILE_MAGIC: [u8; 8] = *b"C6CSP1\0\0";
pub const C6_PERSISTENT_CACHE_BINDING_MAGIC: [u8; 8] = *b"C6CTB1\0\0";
pub const C6_PERSISTENT_CACHE_VERSION: u16 = 1;
pub const C6_PERSISTENT_CACHE_SLOTS: usize = 8;
pub const C6_PERSISTENT_CACHE_LIVE_SLOTS: usize = 2;
pub const C6_PERSISTENT_CACHE_LAYERS: u16 = 12;
pub const C6_PERSISTENT_CACHE_CAPACITY_TOKENS: u16 = 1_024;
pub const C6_PERSISTENT_CACHE_WIDTH: u16 = 768;
pub const C6_PERSISTENT_CACHE_PADDED_LAYERS: u16 = 16;
pub const C6_PERSISTENT_CACHE_PADDED_WIDTH: u16 = 1_024;
pub const C6_PERSISTENT_CACHE_LIVE_ENTRIES: u64 = 9_437_184;
pub const C6_PERSISTENT_CACHE_SLOT_CAPACITY: u64 = 1 << 24;
pub const C6_PERSISTENT_CACHE_ROUNDS: u8 = 24;
pub const C6_PERSISTENT_CACHE_DEGREE: u8 = 2;
pub const C6_PERSISTENT_CACHE_RELATION_POINT_ROOTS: u64 = 24;
pub const C6_PERSISTENT_CACHE_POINTWISE_ROOTS_PER_REPETITION: u64 = 77;
pub const C6_PERSISTENT_CACHE_POINTWISE_EVENT_NUMERATOR: u64 = 5_929;
pub const C6_PERSISTENT_CACHE_ROOTS_PER_REPETITION: u64 = 653;
pub const C6_PERSISTENT_CACHE_EVENT_NUMERATOR: u64 = 426_409;
pub const C6_PERSISTENT_LINK_RELATIONS: u64 = 72;
pub const C6_PERSISTENT_LINK_ROOTS_PER_REPETITION: u64 = 149;
pub const C6_BLIND_HIDDEN_PLUS_PERSISTENT_LINK_NUMERATOR: u64 = 28_926;
pub const C6_PERSISTENT_CACHE_PHASE_SLOTS: usize = 2;
pub const C6_PERSISTENT_CACHE_HEADS: u64 = 12;
pub const C6_PERSISTENT_CACHE_FOLDS_PER_LIVE_BAND: u64 = 288;
pub const C6_PERSISTENT_CACHE_FOLD_CAPACITY: u64 = 576;

const PROFILE_DOMAIN: &str = "volta-zk/c6/persistent-cache-static-profile/v1";
const SLOT_DESCRIPTOR_DOMAIN: &str = "volta-zk/c6/persistent-cache-slot-descriptor/v1";
const DESCRIPTOR_SET_DOMAIN: &str = "volta-zk/c6/persistent-cache-descriptor-set/v1";
const BINDING_DOMAIN: &str = "volta-zk/c6/persistent-cache-transition-binding/v1";
const SOURCE_MAP_DOMAIN: &str = "volta-zk/c6/persistent-cache-source-map/v1";
const SOURCE_PLAN_DOMAIN: &str = "volta-zk/c6/persistent-cache-source-plan/v1";

type Digest = [u8; 32];
type Result<T> = std::result::Result<T, C6PersistentCacheError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheError(String);

impl C6PersistentCacheError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6PersistentCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6PersistentCacheError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheStaticProfile {
    pub protocol_digest: Digest,
    pub model_digest: Digest,
    pub params_digest: Digest,
    pub wrapper_profile_digest: Digest,
}

impl C6PersistentCacheStaticProfile {
    pub fn validate(&self) -> Result<()> {
        if [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.wrapper_profile_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(C6PersistentCacheError::new("zero C6 persistent-cache static digest"));
        }
        if u64::from(C6_PERSISTENT_CACHE_LAYERS)
            * u64::from(C6_PERSISTENT_CACHE_CAPACITY_TOKENS)
            * u64::from(C6_PERSISTENT_CACHE_WIDTH)
            != C6_PERSISTENT_CACHE_LIVE_ENTRIES
            || u64::from(C6_PERSISTENT_CACHE_PADDED_LAYERS)
                * u64::from(C6_PERSISTENT_CACHE_CAPACITY_TOKENS)
                * u64::from(C6_PERSISTENT_CACHE_PADDED_WIDTH)
                != C6_PERSISTENT_CACHE_SLOT_CAPACITY
        {
            return Err(C6PersistentCacheError::new(
                "C6 persistent-cache production geometry drift",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(184);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_PROFILE_MAGIC);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.protocol_digest);
        bytes.extend_from_slice(&self.model_digest);
        bytes.extend_from_slice(&self.params_digest);
        bytes.extend_from_slice(&self.wrapper_profile_digest);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_LAYERS.to_le_bytes());
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_CAPACITY_TOKENS.to_le_bytes());
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_WIDTH.to_le_bytes());
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_PADDED_LAYERS.to_le_bytes());
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_PADDED_WIDTH.to_le_bytes());
        bytes.extend_from_slice(&(C6_PERSISTENT_CACHE_SLOTS as u16).to_le_bytes());
        bytes.extend_from_slice(&domain_digest(PROFILE_DOMAIN, &bytes));
        debug_assert_eq!(bytes.len(), 184);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 184
            || bytes[..8] != C6_PERSISTENT_CACHE_PROFILE_MAGIC
            || u16_at(bytes, 8)? != C6_PERSISTENT_CACHE_VERSION
            || u16_at(bytes, 10)? != 0
            || u16_at(bytes, 140)? != C6_PERSISTENT_CACHE_LAYERS
            || u16_at(bytes, 142)? != C6_PERSISTENT_CACHE_CAPACITY_TOKENS
            || u16_at(bytes, 144)? != C6_PERSISTENT_CACHE_WIDTH
            || u16_at(bytes, 146)? != C6_PERSISTENT_CACHE_PADDED_LAYERS
            || u16_at(bytes, 148)? != C6_PERSISTENT_CACHE_PADDED_WIDTH
            || u16_at(bytes, 150)? != C6_PERSISTENT_CACHE_SLOTS as u16
            || bytes[152..184] != domain_digest(PROFILE_DOMAIN, &bytes[..152])
        {
            return Err(C6PersistentCacheError::new("noncanonical C6 persistent-cache profile"));
        }
        let profile = Self {
            protocol_digest: digest_at(bytes, 12)?,
            model_digest: digest_at(bytes, 44)?,
            params_digest: digest_at(bytes, 76)?,
            wrapper_profile_digest: digest_at(bytes, 108)?,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(domain_digest(PROFILE_DOMAIN, &self.encode()?))
    }

    pub fn slot_descriptor(&self, slot: u8) -> Result<Digest> {
        self.validate()?;
        if usize::from(slot) >= C6_PERSISTENT_CACHE_SLOTS {
            return Err(C6PersistentCacheError::new(
                "C6 persistent-cache slot is outside fixed profile",
            ));
        }
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&self.digest()?);
        bytes.push(slot);
        bytes.push(match slot {
            0 => C6CacheSlotKind::Key as u8,
            1 => C6CacheSlotKind::Value as u8,
            _ => 0,
        });
        Ok(domain_digest(SLOT_DESCRIPTOR_DOMAIN, &bytes))
    }

    pub fn slot_descriptors(&self) -> Result<[Digest; C6_PERSISTENT_CACHE_SLOTS]> {
        let mut descriptors = [[0; 32]; C6_PERSISTENT_CACHE_SLOTS];
        for (slot, descriptor) in descriptors.iter_mut().enumerate() {
            *descriptor = self.slot_descriptor(slot as u8)?;
        }
        Ok(descriptors)
    }

    pub fn descriptor_set_digest(&self) -> Result<Digest> {
        let descriptors = self.slot_descriptors()?;
        let mut bytes = Vec::with_capacity(C6_PERSISTENT_CACHE_SLOTS * 32);
        for descriptor in descriptors {
            bytes.extend_from_slice(&descriptor);
        }
        Ok(domain_digest(DESCRIPTOR_SET_DOMAIN, &bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheTransitionBinding {
    pub descriptor_set_digest: Digest,
    pub response_statement_digest: Digest,
    pub connection_id: Digest,
    pub predecessor_certificate_digest: Digest,
    pub nonce: Digest,
    pub old_root: Digest,
    pub new_root: Digest,
    pub source_map_digest: Digest,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_len: u16,
    pub new_len: u16,
}

impl C6PersistentCacheTransitionBinding {
    pub fn validate(&self, profile: &C6PersistentCacheStaticProfile) -> Result<()> {
        profile.validate()?;
        if self.descriptor_set_digest != profile.descriptor_set_digest()?
            || [
                self.response_statement_digest,
                self.connection_id,
                self.predecessor_certificate_digest,
                self.nonce,
                self.old_root,
                self.new_root,
                self.source_map_digest,
            ]
            .contains(&[0; 32])
            || self.new_epoch
                != self.old_epoch.checked_add(1).ok_or_else(|| {
                    C6PersistentCacheError::new("C6 cache transition epoch overflows")
                })?
            || self.old_len > self.new_len
            || self.new_len > C6_PERSISTENT_CACHE_CAPACITY_TOKENS
        {
            return Err(C6PersistentCacheError::new(
                "invalid C6 persistent-cache transition binding",
            ));
        }
        Ok(())
    }

    pub fn encode(&self, profile: &C6PersistentCacheStaticProfile) -> Result<Vec<u8>> {
        self.validate(profile)?;
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_BINDING_MAGIC);
        bytes.extend_from_slice(&C6_PERSISTENT_CACHE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for digest in [
            self.descriptor_set_digest,
            self.response_statement_digest,
            self.connection_id,
            self.predecessor_certificate_digest,
            self.nonce,
            self.old_root,
            self.new_root,
            self.source_map_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.old_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.new_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.old_len.to_le_bytes());
        bytes.extend_from_slice(&self.new_len.to_le_bytes());
        bytes.extend_from_slice(&domain_digest(BINDING_DOMAIN, &bytes));
        debug_assert_eq!(bytes.len(), 320);
        Ok(bytes)
    }

    pub fn decode(profile: &C6PersistentCacheStaticProfile, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 320
            || bytes[..8] != C6_PERSISTENT_CACHE_BINDING_MAGIC
            || u16_at(bytes, 8)? != C6_PERSISTENT_CACHE_VERSION
            || u16_at(bytes, 10)? != 0
            || bytes[288..320] != domain_digest(BINDING_DOMAIN, &bytes[..288])
        {
            return Err(C6PersistentCacheError::new(
                "noncanonical C6 persistent-cache transition binding",
            ));
        }
        let binding = Self {
            descriptor_set_digest: digest_at(bytes, 12)?,
            response_statement_digest: digest_at(bytes, 44)?,
            connection_id: digest_at(bytes, 76)?,
            predecessor_certificate_digest: digest_at(bytes, 108)?,
            nonce: digest_at(bytes, 140)?,
            old_root: digest_at(bytes, 172)?,
            new_root: digest_at(bytes, 204)?,
            source_map_digest: digest_at(bytes, 236)?,
            old_epoch: u64_at(bytes, 268)?,
            new_epoch: u64_at(bytes, 276)?,
            old_len: u16_at(bytes, 284)?,
            new_len: u16_at(bytes, 286)?,
        };
        binding.validate(profile)?;
        Ok(binding)
    }

    pub fn digest(&self, profile: &C6PersistentCacheStaticProfile) -> Result<Digest> {
        Ok(domain_digest(BINDING_DOMAIN, &self.encode(profile)?))
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6CacheSlotKind {
    Key = 1,
    Value = 2,
}

impl C6CacheSlotKind {
    fn slot(self) -> usize {
        match self {
            Self::Key => 0,
            Self::Value => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct C6CacheCell {
    pub kind: C6CacheSlotKind,
    pub layer: u16,
    pub position: u16,
    pub channel: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheLayout {
    pub layers: u16,
    pub capacity_tokens: u16,
    pub width: u16,
    pub padded_layers: u16,
    pub padded_width: u16,
}

impl C6PersistentCacheLayout {
    pub const fn production() -> Self {
        Self {
            layers: C6_PERSISTENT_CACHE_LAYERS,
            capacity_tokens: C6_PERSISTENT_CACHE_CAPACITY_TOKENS,
            width: C6_PERSISTENT_CACHE_WIDTH,
            padded_layers: C6_PERSISTENT_CACHE_PADDED_LAYERS,
            padded_width: C6_PERSISTENT_CACHE_PADDED_WIDTH,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.layers == 0
            || self.capacity_tokens == 0
            || self.width == 0
            || self.layers > self.padded_layers
            || self.width > self.padded_width
            || !self.capacity_tokens.is_power_of_two()
            || !self.padded_layers.is_power_of_two()
            || !self.padded_width.is_power_of_two()
            || !self.padded_entries_u64()?.is_power_of_two()
        {
            return Err(C6PersistentCacheError::new("invalid C6 persistent-cache layout"));
        }
        usize::try_from(self.padded_entries_u64()?)
            .map_err(|_| C6PersistentCacheError::new("C6 cache layout exceeds usize"))?;
        Ok(())
    }

    pub fn live_entries_u64(self) -> Result<u64> {
        u64::from(self.layers)
            .checked_mul(u64::from(self.capacity_tokens))
            .and_then(|value| value.checked_mul(u64::from(self.width)))
            .ok_or_else(|| C6PersistentCacheError::new("C6 cache live geometry overflows"))
    }

    pub fn padded_entries_u64(self) -> Result<u64> {
        u64::from(self.padded_layers)
            .checked_mul(u64::from(self.capacity_tokens))
            .and_then(|value| value.checked_mul(u64::from(self.padded_width)))
            .ok_or_else(|| C6PersistentCacheError::new("C6 cache padded geometry overflows"))
    }

    pub fn padded_entries(self) -> Result<usize> {
        self.validate()?;
        usize::try_from(self.padded_entries_u64()?)
            .map_err(|_| C6PersistentCacheError::new("C6 cache layout exceeds usize"))
    }

    pub fn flat_index(self, cell: C6CacheCell) -> Result<usize> {
        self.validate()?;
        if cell.layer >= self.padded_layers
            || cell.position >= self.capacity_tokens
            || cell.channel >= self.padded_width
        {
            return Err(C6PersistentCacheError::new("C6 cache cell is outside padded geometry"));
        }
        let index = u64::from(cell.layer)
            .checked_mul(u64::from(self.capacity_tokens))
            .and_then(|value| value.checked_add(u64::from(cell.position)))
            .and_then(|value| value.checked_mul(u64::from(self.padded_width)))
            .and_then(|value| value.checked_add(u64::from(cell.channel)))
            .ok_or_else(|| C6PersistentCacheError::new("C6 cache index overflows"))?;
        usize::try_from(index)
            .map_err(|_| C6PersistentCacheError::new("C6 cache index exceeds usize"))
    }

    fn validate_live_cell(self, cell: C6CacheCell, cache_len: u16) -> Result<()> {
        if cell.layer >= self.layers || cell.position >= cache_len || cell.channel >= self.width {
            return Err(C6PersistentCacheError::new("C6 cache source references a non-live cell"));
        }
        self.flat_index(cell).map(|_| ())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheStateWitness {
    pub slots: Vec<Vec<Fp2>>,
}

impl C6PersistentCacheStateWitness {
    pub fn zero(layout: C6PersistentCacheLayout) -> Result<Self> {
        let entries = layout.padded_entries()?;
        Ok(Self { slots: vec![vec![Fp2::ZERO; entries]; C6_PERSISTENT_CACHE_SLOTS] })
    }

    pub fn value(&self, layout: C6PersistentCacheLayout, cell: C6CacheCell) -> Result<Fp2> {
        let slot = self
            .slots
            .get(cell.kind.slot())
            .ok_or_else(|| C6PersistentCacheError::new("missing C6 cache live slot"))?;
        slot.get(layout.flat_index(cell)?)
            .copied()
            .ok_or_else(|| C6PersistentCacheError::new("missing C6 cache cell"))
    }

    pub fn set(
        &mut self,
        layout: C6PersistentCacheLayout,
        cell: C6CacheCell,
        value: Fp2,
    ) -> Result<()> {
        let index = layout.flat_index(cell)?;
        *self
            .slots
            .get_mut(cell.kind.slot())
            .and_then(|slot| slot.get_mut(index))
            .ok_or_else(|| C6PersistentCacheError::new("missing C6 cache cell"))? = value;
        Ok(())
    }

    /// Validate the exact fixed-capacity cache source committed by the C6
    /// wrapper.  Only K/V slots 0--1 and live cells before `cache_len` may be
    /// nonzero; all tail, padded and inactive-slot coordinates are canonical
    /// zero.
    pub fn validate_canonical(
        &self,
        layout: C6PersistentCacheLayout,
        cache_len: u16,
    ) -> Result<()> {
        let entries = layout.padded_entries()?;
        if cache_len > layout.capacity_tokens
            || self.slots.len() != C6_PERSISTENT_CACHE_SLOTS
            || self.slots.iter().any(|slot| slot.len() != entries)
        {
            return Err(C6PersistentCacheError::new("C6 cache state slot/length mismatch"));
        }
        for (slot_index, slot) in self.slots.iter().enumerate() {
            for layer in 0..layout.padded_layers {
                for position in 0..layout.capacity_tokens {
                    for channel in 0..layout.padded_width {
                        let valid = slot_index < C6_PERSISTENT_CACHE_LIVE_SLOTS
                            && layer < layout.layers
                            && position < cache_len
                            && channel < layout.width;
                        let index = layout.flat_index(C6CacheCell {
                            kind: if slot_index == 1 {
                                C6CacheSlotKind::Value
                            } else {
                                C6CacheSlotKind::Key
                            },
                            layer,
                            position,
                            channel,
                        })?;
                        if !valid && slot[index] != Fp2::ZERO {
                            return Err(C6PersistentCacheError::new(
                                "nonzero C6 cache tail/padding/zero slot",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheSourceValue {
    pub cell: C6CacheCell,
    pub value: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheReferenceAudit {
    pub padded_entries_per_slot: usize,
    pub checked_read_sources: usize,
    pub checked_append_sources: usize,
    pub pointwise_relation_rows: usize,
    pub roots_per_repetition: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6PersistentCacheBandRole {
    Prompt = 1,
    Decode = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheBandPlan {
    pub role: C6PersistentCacheBandRole,
    pub t0: u16,
    pub query_rows: u16,
    pub predecessor_rows: u16,
    pub earlier_response_rows: u16,
    pub own_rows: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PersistentCacheSourcePlan {
    pub workload: C6Workload,
    pub bands: Vec<C6PersistentCacheBandPlan>,
    pub persistent_cell_uses: u64,
    pub earlier_response_cell_uses: u64,
    pub appended_source_values: u64,
    pub fold_operations: u64,
}

impl C6PersistentCacheSourcePlan {
    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(128);
        for value in [
            self.workload.prompt_tokens,
            self.workload.decode_tokens,
            self.workload.old_context,
            self.workload.new_context,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.bands.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for band in &self.bands {
            bytes.push(band.role as u8);
            bytes.push(0);
            for value in [
                band.t0,
                band.query_rows,
                band.predecessor_rows,
                band.earlier_response_rows,
                band.own_rows,
            ] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        for value in [
            self.persistent_cell_uses,
            self.earlier_response_cell_uses,
            self.appended_source_values,
            self.fold_operations,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(domain_digest(SOURCE_PLAN_DOMAIN, &bytes))
    }

    fn validate(&self) -> Result<()> {
        let expected = derive_c6_persistent_cache_source_plan(self.workload)?;
        if self != &expected {
            return Err(C6PersistentCacheError::new(
                "noncanonical C6 persistent-cache source plan",
            ));
        }
        Ok(())
    }
}

/// Derive the compact, value-independent cache-fold topology from the exact
/// public C6 workload.  This does not materialize per-cell coefficients.
pub fn derive_c6_persistent_cache_source_plan(
    workload: C6Workload,
) -> Result<C6PersistentCacheSourcePlan> {
    workload.validate().map_err(|error| C6PersistentCacheError::new(error.to_string()))?;
    let old_context = u16::try_from(workload.old_context)
        .map_err(|_| C6PersistentCacheError::new("C6 old context exceeds u16"))?;
    let prompt_tokens = u16::try_from(workload.prompt_tokens)
        .map_err(|_| C6PersistentCacheError::new("C6 prompt count exceeds u16"))?;
    let decode_tokens = u16::try_from(workload.decode_tokens)
        .map_err(|_| C6PersistentCacheError::new("C6 decode count exceeds u16"))?;
    let mut bands = Vec::with_capacity(C6_PERSISTENT_CACHE_PHASE_SLOTS);
    if prompt_tokens != 0 {
        bands.push(C6PersistentCacheBandPlan {
            role: C6PersistentCacheBandRole::Prompt,
            t0: old_context,
            query_rows: prompt_tokens,
            predecessor_rows: old_context,
            earlier_response_rows: 0,
            own_rows: prompt_tokens,
        });
    }
    if decode_tokens != 0 {
        bands.push(C6PersistentCacheBandPlan {
            role: C6PersistentCacheBandRole::Decode,
            t0: old_context
                .checked_add(prompt_tokens)
                .ok_or_else(|| C6PersistentCacheError::new("C6 decode t0 overflows"))?,
            query_rows: decode_tokens,
            predecessor_rows: old_context,
            earlier_response_rows: prompt_tokens,
            own_rows: decode_tokens,
        });
    }
    if bands.is_empty() || bands.len() > C6_PERSISTENT_CACHE_PHASE_SLOTS {
        return Err(C6PersistentCacheError::new(
            "C6 cache source plan has an invalid live-band count",
        ));
    }

    let cells_per_token = u64::from(C6_PERSISTENT_CACHE_LAYERS)
        .checked_mul(u64::from(C6_PERSISTENT_CACHE_WIDTH))
        .and_then(|value| value.checked_mul(C6_PERSISTENT_CACHE_LIVE_SLOTS as u64))
        .ok_or_else(|| C6PersistentCacheError::new("C6 cache cell census overflows"))?;
    let persistent_cell_uses = cells_per_token
        .checked_mul(u64::from(old_context))
        .and_then(|value| value.checked_mul(bands.len() as u64))
        .ok_or_else(|| C6PersistentCacheError::new("C6 predecessor-use census overflows"))?;
    let earlier_response_rows = bands
        .iter()
        .try_fold(0u64, |sum, band| sum.checked_add(u64::from(band.earlier_response_rows)))
        .ok_or_else(|| C6PersistentCacheError::new("C6 current-prefix census overflows"))?;
    let earlier_response_cell_uses = cells_per_token
        .checked_mul(earlier_response_rows)
        .ok_or_else(|| C6PersistentCacheError::new("C6 current-prefix use census overflows"))?;
    let appended = workload
        .new_context
        .checked_sub(workload.old_context)
        .ok_or_else(|| C6PersistentCacheError::new("C6 append count underflows"))?;
    let appended_source_values = cells_per_token
        .checked_mul(u64::from(appended))
        .ok_or_else(|| C6PersistentCacheError::new("C6 append-source census overflows"))?;
    let fold_operations =
        C6_PERSISTENT_CACHE_FOLDS_PER_LIVE_BAND
            .checked_mul(bands.len() as u64)
            .ok_or_else(|| C6PersistentCacheError::new("C6 cache-fold census overflows"))?;

    Ok(C6PersistentCacheSourcePlan {
        workload,
        bands,
        persistent_cell_uses,
        earlier_response_cell_uses,
        appended_source_values,
        fold_operations,
    })
}

pub fn expected_c6_cache_append_cells(
    layout: C6PersistentCacheLayout,
    old_len: u16,
    new_len: u16,
) -> Result<Vec<C6CacheCell>> {
    layout.validate()?;
    if old_len > new_len || new_len > layout.capacity_tokens {
        return Err(C6PersistentCacheError::new("invalid C6 cache append interval"));
    }
    let count = C6_PERSISTENT_CACHE_LIVE_SLOTS
        .checked_mul(usize::from(layout.layers))
        .and_then(|value| value.checked_mul(usize::from(new_len - old_len)))
        .and_then(|value| value.checked_mul(usize::from(layout.width)))
        .ok_or_else(|| C6PersistentCacheError::new("C6 append census overflows"))?;
    let mut cells = Vec::with_capacity(count);
    for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
        for layer in 0..layout.layers {
            for position in old_len..new_len {
                for channel in 0..layout.width {
                    cells.push(C6CacheCell { kind, layer, position, channel });
                }
            }
        }
    }
    Ok(cells)
}

pub fn c6_cache_source_map_digest(
    layout: C6PersistentCacheLayout,
    old_len: u16,
    new_len: u16,
    read_cells: &[C6CacheCell],
) -> Result<Digest> {
    layout.validate()?;
    let append_cells = expected_c6_cache_append_cells(layout, old_len, new_len)?;
    for cell in read_cells {
        layout.validate_live_cell(*cell, old_len)?;
    }
    let mut bytes = Vec::new();
    for value in [
        layout.layers,
        layout.capacity_tokens,
        layout.width,
        layout.padded_layers,
        layout.padded_width,
        old_len,
        new_len,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&(read_cells.len() as u64).to_le_bytes());
    for cell in read_cells {
        encode_cell(&mut bytes, *cell);
    }
    bytes.extend_from_slice(&(append_cells.len() as u64).to_le_bytes());
    for cell in append_cells {
        encode_cell(&mut bytes, cell);
    }
    Ok(domain_digest(SOURCE_MAP_DOMAIN, &bytes))
}

#[allow(clippy::too_many_arguments)]
pub fn validate_c6_persistent_cache_transition_reference(
    profile: &C6PersistentCacheStaticProfile,
    layout: C6PersistentCacheLayout,
    binding: &C6PersistentCacheTransitionBinding,
    predecessor: &C6PersistentCacheStateWitness,
    successor: &C6PersistentCacheStateWitness,
    expected_read_cells: &[C6CacheCell],
    read_sources: &[C6CacheSourceValue],
    append_sources: &[C6CacheSourceValue],
) -> Result<C6PersistentCacheReferenceAudit> {
    binding.validate(profile)?;
    layout.validate()?;
    if binding.new_len > layout.capacity_tokens
        || binding.source_map_digest
            != c6_cache_source_map_digest(
                layout,
                binding.old_len,
                binding.new_len,
                expected_read_cells,
            )?
    {
        return Err(C6PersistentCacheError::new("C6 cache binding/source-map mismatch"));
    }
    predecessor.validate_canonical(layout, binding.old_len)?;
    successor.validate_canonical(layout, binding.new_len)?;

    if read_sources.len() != expected_read_cells.len() {
        return Err(C6PersistentCacheError::new("C6 predecessor-read source census mismatch"));
    }
    for (expected, source) in expected_read_cells.iter().zip(read_sources) {
        if source.cell != *expected || source.value != predecessor.value(layout, source.cell)? {
            return Err(C6PersistentCacheError::new("C6 predecessor-read source mismatch"));
        }
    }

    for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
        for layer in 0..layout.layers {
            for position in 0..binding.old_len {
                for channel in 0..layout.width {
                    let cell = C6CacheCell { kind, layer, position, channel };
                    if predecessor.value(layout, cell)? != successor.value(layout, cell)? {
                        return Err(C6PersistentCacheError::new(
                            "C6 cache successor changed predecessor prefix",
                        ));
                    }
                }
            }
        }
    }

    let expected_append = expected_c6_cache_append_cells(layout, binding.old_len, binding.new_len)?;
    if append_sources.len() != expected_append.len() {
        return Err(C6PersistentCacheError::new("C6 authenticated append-source census mismatch"));
    }
    for (expected, source) in expected_append.iter().zip(append_sources) {
        if source.cell != *expected || source.value != successor.value(layout, source.cell)? {
            return Err(C6PersistentCacheError::new("C6 authenticated append-source mismatch"));
        }
    }

    let padded_entries = layout.padded_entries()?;
    Ok(C6PersistentCacheReferenceAudit {
        padded_entries_per_slot: padded_entries,
        checked_read_sources: read_sources.len(),
        checked_append_sources: append_sources.len(),
        pointwise_relation_rows: C6_PERSISTENT_CACHE_LIVE_SLOTS
            .checked_mul(padded_entries)
            .ok_or_else(|| C6PersistentCacheError::new("C6 relation rows overflow"))?,
        roots_per_repetition: C6_PERSISTENT_CACHE_POINTWISE_ROOTS_PER_REPETITION,
    })
}

fn encode_cell(bytes: &mut Vec<u8>, cell: C6CacheCell) {
    bytes.push(cell.kind as u8);
    bytes.push(0);
    bytes.extend_from_slice(&cell.layer.to_le_bytes());
    bytes.extend_from_slice(&cell.position.to_le_bytes());
    bytes.extend_from_slice(&cell.channel.to_le_bytes());
}

fn domain_digest(domain: &str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<Digest> {
    let mut digest = [0; 32];
    digest.copy_from_slice(
        bytes
            .get(offset..offset + 32)
            .ok_or_else(|| C6PersistentCacheError::new("truncated C6 cache digest"))?,
    );
    Ok(digest)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let mut raw = [0; 2];
    raw.copy_from_slice(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| C6PersistentCacheError::new("truncated C6 cache u16"))?,
    );
    Ok(u16::from_le_bytes(raw))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let mut raw = [0; 8];
    raw.copy_from_slice(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| C6PersistentCacheError::new("truncated C6 cache u64"))?,
    );
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use volta_field::Fp;

    use super::*;

    fn profile() -> C6PersistentCacheStaticProfile {
        C6PersistentCacheStaticProfile {
            protocol_digest: [0x11; 32],
            model_digest: [0x22; 32],
            params_digest: [0x33; 32],
            wrapper_profile_digest: [0x44; 32],
        }
    }

    fn scaled_layout() -> C6PersistentCacheLayout {
        C6PersistentCacheLayout {
            layers: 2,
            capacity_tokens: 4,
            width: 3,
            padded_layers: 2,
            padded_width: 4,
        }
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(13 * value + 5))
    }

    fn live_cells(layout: C6PersistentCacheLayout, len: u16) -> Vec<C6CacheCell> {
        let mut cells = Vec::new();
        for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
            for layer in 0..layout.layers {
                for position in 0..len {
                    for channel in 0..layout.width {
                        cells.push(C6CacheCell { kind, layer, position, channel });
                    }
                }
            }
        }
        cells
    }

    struct Fixture {
        layout: C6PersistentCacheLayout,
        binding: C6PersistentCacheTransitionBinding,
        predecessor: C6PersistentCacheStateWitness,
        successor: C6PersistentCacheStateWitness,
        read_cells: Vec<C6CacheCell>,
        reads: Vec<C6CacheSourceValue>,
        appends: Vec<C6CacheSourceValue>,
    }

    fn fixture() -> Fixture {
        let layout = scaled_layout();
        let mut predecessor = C6PersistentCacheStateWitness::zero(layout).unwrap();
        for (ordinal, cell) in live_cells(layout, 2).into_iter().enumerate() {
            predecessor.set(layout, cell, fp2(ordinal as u64 + 1)).unwrap();
        }
        let mut successor = predecessor.clone();
        let append_cells = expected_c6_cache_append_cells(layout, 2, 3).unwrap();
        for (ordinal, cell) in append_cells.iter().copied().enumerate() {
            successor.set(layout, cell, fp2(1_000 + ordinal as u64)).unwrap();
        }
        let read_cells = vec![
            C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 1, channel: 2 },
            C6CacheCell { kind: C6CacheSlotKind::Value, layer: 1, position: 0, channel: 1 },
        ];
        let reads = read_cells
            .iter()
            .copied()
            .map(|cell| C6CacheSourceValue {
                cell,
                value: predecessor.value(layout, cell).unwrap(),
            })
            .collect();
        let appends = append_cells
            .iter()
            .copied()
            .map(|cell| C6CacheSourceValue { cell, value: successor.value(layout, cell).unwrap() })
            .collect();
        let static_profile = profile();
        let binding = C6PersistentCacheTransitionBinding {
            descriptor_set_digest: static_profile.descriptor_set_digest().unwrap(),
            response_statement_digest: [0x51; 32],
            connection_id: [0x52; 32],
            predecessor_certificate_digest: [0x53; 32],
            nonce: [0x54; 32],
            old_root: [0x55; 32],
            new_root: [0x56; 32],
            source_map_digest: c6_cache_source_map_digest(layout, 2, 3, &read_cells).unwrap(),
            old_epoch: 7,
            new_epoch: 8,
            old_len: 2,
            new_len: 3,
        };
        Fixture { layout, binding, predecessor, successor, read_cells, reads, appends }
    }

    #[test]
    fn production_capacity_and_exact_root_censuses_are_frozen() {
        let layout = C6PersistentCacheLayout::production();
        assert_eq!(layout.live_entries_u64().unwrap(), C6_PERSISTENT_CACHE_LIVE_ENTRIES);
        assert_eq!(layout.padded_entries_u64().unwrap(), C6_PERSISTENT_CACHE_SLOT_CAPACITY);
        assert!(
            std::hint::black_box(C6_PERSISTENT_CACHE_LIVE_ENTRIES)
                <= C6_PERSISTENT_CACHE_SLOT_CAPACITY
        );
        assert_eq!(C6_PERSISTENT_CACHE_RELATION_POINT_ROOTS, 24);
        assert_eq!(C6_PERSISTENT_CACHE_POINTWISE_ROOTS_PER_REPETITION, 77);
        assert_eq!(C6_PERSISTENT_CACHE_POINTWISE_EVENT_NUMERATOR, 77 * 77);
        assert_eq!(C6_PERSISTENT_CACHE_ROOTS_PER_REPETITION, 653);
        assert_eq!(C6_PERSISTENT_CACHE_EVENT_NUMERATOR, 653 * 653);
        assert_eq!(C6_PERSISTENT_LINK_RELATIONS + 3 * 25 + 2, 149);
        assert_eq!(C6_BLIND_HIDDEN_PLUS_PERSISTENT_LINK_NUMERATOR, 6_725 + 149 * 149);
        assert!(std::hint::black_box(C6_BLIND_HIDDEN_PLUS_PERSISTENT_LINK_NUMERATOR) < 1 << 15);
        assert_eq!(
            u64::from(C6_PERSISTENT_CACHE_LAYERS) * C6_PERSISTENT_CACHE_HEADS * 2,
            C6_PERSISTENT_CACHE_FOLDS_PER_LIVE_BAND
        );
        assert_eq!(
            C6_PERSISTENT_CACHE_FOLDS_PER_LIVE_BAND * C6_PERSISTENT_CACHE_PHASE_SLOTS as u64,
            C6_PERSISTENT_CACHE_FOLD_CAPACITY
        );
    }

    #[test]
    fn compact_source_plan_is_client_derived_and_wire_constant() {
        let first = derive_c6_persistent_cache_source_plan(C6Workload {
            prompt_tokens: 100,
            decode_tokens: 50,
            old_context: 0,
            new_context: 150,
        })
        .unwrap();
        assert_eq!(first.bands.len(), 2);
        assert_eq!(first.bands[0].role, C6PersistentCacheBandRole::Prompt);
        assert_eq!(first.bands[0].t0, 0);
        assert_eq!(first.bands[1].role, C6PersistentCacheBandRole::Decode);
        assert_eq!(first.bands[1].t0, 100);
        assert_eq!(first.persistent_cell_uses, 0);
        assert_eq!(first.earlier_response_cell_uses, 1_843_200);
        assert_eq!(first.appended_source_values, 2_764_800);
        assert_eq!(first.fold_operations, 576);

        let continuation = derive_c6_persistent_cache_source_plan(C6Workload {
            prompt_tokens: 0,
            decode_tokens: 50,
            old_context: 150,
            new_context: 200,
        })
        .unwrap();
        assert_eq!(continuation.bands.len(), 1);
        assert_eq!(continuation.bands[0].role, C6PersistentCacheBandRole::Decode);
        assert_eq!(continuation.bands[0].t0, 150);
        assert_eq!(continuation.persistent_cell_uses, 2_764_800);
        assert_eq!(continuation.earlier_response_cell_uses, 0);
        assert_eq!(continuation.appended_source_values, 921_600);
        assert_eq!(continuation.fold_operations, 288);
        assert_ne!(first.digest().unwrap(), continuation.digest().unwrap());

        let late = derive_c6_persistent_cache_source_plan(C6Workload {
            prompt_tokens: 0,
            decode_tokens: 50,
            old_context: 900,
            new_context: 950,
        })
        .unwrap();
        assert_eq!(late.persistent_cell_uses, 16_588_800);
        assert_eq!(late.appended_source_values, continuation.appended_source_values);
        assert_eq!(late.fold_operations, continuation.fold_operations);
    }

    #[test]
    fn compact_source_plan_rejects_noncanonical_workloads_and_mutation() {
        assert!(derive_c6_persistent_cache_source_plan(C6Workload {
            prompt_tokens: 0,
            decode_tokens: 0,
            old_context: 10,
            new_context: 10,
        })
        .is_err());
        let mut plan = derive_c6_persistent_cache_source_plan(C6Workload {
            prompt_tokens: 10,
            decode_tokens: 5,
            old_context: 20,
            new_context: 35,
        })
        .unwrap();
        plan.bands.swap(0, 1);
        assert!(plan.digest().is_err());
    }

    #[test]
    fn static_profile_codec_is_strict_and_descriptors_are_unique() {
        let profile = profile();
        let bytes = profile.encode().unwrap();
        assert_eq!(bytes.len(), 184);
        assert_eq!(C6PersistentCacheStaticProfile::decode(&bytes).unwrap(), profile);
        let descriptors = profile.slot_descriptors().unwrap();
        for left in 0..descriptors.len() {
            for right in left + 1..descriptors.len() {
                assert_ne!(descriptors[left], descriptors[right]);
            }
        }

        let mut corrupted = bytes.clone();
        corrupted[45] ^= 1;
        assert!(C6PersistentCacheStaticProfile::decode(&corrupted).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(C6PersistentCacheStaticProfile::decode(&trailing).is_err());
    }

    #[test]
    fn successor_root_reuses_the_same_static_descriptor_set() {
        let profile = profile();
        let first = fixture().binding;
        let mut second = first.clone();
        second.response_statement_digest = [0x61; 32];
        second.predecessor_certificate_digest = [0x62; 32];
        second.nonce = [0x63; 32];
        second.old_root = first.new_root;
        second.new_root = [0x64; 32];
        second.old_epoch = first.new_epoch;
        second.new_epoch = first.new_epoch + 1;
        second.old_len = first.new_len;
        second.new_len = first.new_len;
        second.source_map_digest = c6_cache_source_map_digest(scaled_layout(), 3, 3, &[]).unwrap();

        assert_eq!(first.descriptor_set_digest, second.descriptor_set_digest);
        assert_eq!(first.new_root, second.old_root);
        assert_ne!(first.digest(&profile).unwrap(), second.digest(&profile).unwrap());
        let bytes = first.encode(&profile).unwrap();
        assert_eq!(bytes.len(), 320);
        assert_eq!(C6PersistentCacheTransitionBinding::decode(&profile, &bytes).unwrap(), first);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(C6PersistentCacheTransitionBinding::decode(&profile, &trailing).is_err());
    }

    #[test]
    fn scaled_transition_checks_reads_prefix_append_tail_and_source_map() {
        let fixture = fixture();
        let audit = validate_c6_persistent_cache_transition_reference(
            &profile(),
            fixture.layout,
            &fixture.binding,
            &fixture.predecessor,
            &fixture.successor,
            &fixture.read_cells,
            &fixture.reads,
            &fixture.appends,
        )
        .unwrap();
        assert_eq!(audit.padded_entries_per_slot, 32);
        assert_eq!(audit.checked_read_sources, 2);
        assert_eq!(audit.checked_append_sources, 12);
        assert_eq!(audit.pointwise_relation_rows, 64);
        assert_eq!(audit.roots_per_repetition, 77);
    }

    #[test]
    fn scaled_transition_rejects_every_load_bearing_seam_mutation() {
        let check = |fixture: &Fixture| {
            validate_c6_persistent_cache_transition_reference(
                &profile(),
                fixture.layout,
                &fixture.binding,
                &fixture.predecessor,
                &fixture.successor,
                &fixture.read_cells,
                &fixture.reads,
                &fixture.appends,
            )
        };

        let mut prefix = fixture();
        let prefix_cell =
            C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 0, channel: 0 };
        prefix.successor.set(prefix.layout, prefix_cell, fp2(9_001)).unwrap();
        assert!(check(&prefix).is_err());

        let mut append = fixture();
        append.appends[0].value += fp2(1);
        assert!(check(&append).is_err());

        let mut append_order = fixture();
        append_order.appends.swap(0, 1);
        assert!(check(&append_order).is_err());

        let mut read = fixture();
        read.reads[0].value += fp2(1);
        assert!(check(&read).is_err());

        let mut read_order = fixture();
        read_order.reads.swap(0, 1);
        assert!(check(&read_order).is_err());

        let mut tail = fixture();
        let tail_cell =
            C6CacheCell { kind: C6CacheSlotKind::Value, layer: 0, position: 3, channel: 0 };
        tail.successor.set(tail.layout, tail_cell, fp2(9_002)).unwrap();
        assert!(check(&tail).is_err());

        let mut zero_slot = fixture();
        zero_slot.successor.slots[2][0] = fp2(9_003);
        assert!(check(&zero_slot).is_err());

        let mut source_map = fixture();
        source_map.binding.source_map_digest[0] ^= 1;
        assert!(check(&source_map).is_err());

        let mut wrong_descriptor = fixture();
        wrong_descriptor.binding.descriptor_set_digest[0] ^= 1;
        assert!(check(&wrong_descriptor).is_err());
    }
}

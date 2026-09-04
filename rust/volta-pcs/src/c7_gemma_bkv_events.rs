//! Fail-closed static compiler for the active Gemma-31B B/KV synthetic fixture.
//!
//! This module deliberately does not claim protocol or security credit.  It
//! compiles exact fixture data into deterministic records and rejects every
//! omitted field.  The real Gemma B/KV tree layouts and security numerators
//! must replace the synthetic fixture before admission.

use std::fmt;

pub const SCHEMA: &str = "volta-zk/c7/d126/gemma31b/bkv-events/synthetic/v1";
pub const GEMMA_MODEL: &str = "google/gemma-4-31B";
pub const GEMMA_REVISION: &str = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89";
pub const TERMINAL_MANIFEST_BLAKE3_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-terminals-v1.blake3");
pub const CONTEXT_CAP: u32 = 4_096;
pub const Q_FS_GLOBAL: u128 = 1u128 << 64;
pub const RESPONSE_ATTEMPT_LIFETIME: u64 = 1 << 20;
pub const RESPONSE_ATTEMPTS_PER_ROOT: u32 = 4_096;
pub const LIFECYCLE_LOAD_RESERVE_PER_ROOT: u32 = 512;
/// Stress-fixture query caps. They are not compiled/minimal B/KV queries.
pub const SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND: [u32; 8] = [357, 163, 152, 149, 149, 149, 149, 149];
/// Stress-fixture leaf payload. It is not real B/KV tree geometry.
pub const SYNTHETIC_SYMBOLS_PER_OPENED_LEAF: u64 = 141;
pub const TRANSFORMER_LAYERS: u32 = 60;
pub const GLOBAL_ATTENTION_LAYERS: [u32; 10] = [5, 11, 17, 23, 29, 35, 41, 47, 53, 59];
pub const HIDDEN_SIZE: u32 = 5_376;
pub const LOCAL_KV_HEADS: u32 = 16;
pub const LOCAL_KV_HEAD_DIM: u32 = 256;
pub const GLOBAL_KV_HEADS: u32 = 4;
pub const GLOBAL_KV_HEAD_DIM: u32 = 512;
pub const I16_BYTES: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError(String);

impl CompileError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CompileError {}

pub type Result<T> = std::result::Result<T, CompileError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlaneKind {
    PlaneB,
    KvOld,
    KvNew,
}

impl PlaneKind {
    fn tag(self) -> u8 {
        match self {
            Self::PlaneB => 0,
            Self::KvOld => 1,
            Self::KvNew => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PlaneB => "PlaneB",
            Self::KvOld => "KV-old",
            Self::KvNew => "KV-new",
        }
    }

    fn expected_terminals(self) -> &'static [u16] {
        match self {
            Self::PlaneB => &[472, 473, 474, 475],
            Self::KvOld => &[476, 477],
            Self::KvNew => &[478, 479],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventScope {
    ResponseAttempt,
    FullResponseLifetime,
    GlobalClassicalRomLifetime,
}

impl EventScope {
    fn tag(self) -> u8 {
        match self {
            Self::ResponseAttempt => 0,
            Self::FullResponseLifetime => 1,
            Self::GlobalClassicalRomLifetime => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsFactor {
    /// The event has an explicit factor of one; this is not an unknown value.
    One,
    /// The active global factor `Q_FS_global + 1`.
    GlobalQfsPlusOne,
}

impl FsFactor {
    fn value(self) -> u128 {
        match self {
            Self::One => 1,
            Self::GlobalQfsPlusOne => Q_FS_GLOBAL + 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventLifetime {
    OneAttempt,
    AllResponseAttempts,
}

impl EventLifetime {
    fn value(self) -> u64 {
        match self {
            Self::OneAttempt => 1,
            Self::AllResponseAttempts => RESPONSE_ATTEMPT_LIFETIME,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFixture {
    pub model: Option<String>,
    pub revision: Option<String>,
    pub text_only: Option<bool>,
    pub terminal_manifest_blake3: Option<String>,
    pub context_cap: Option<u32>,
    pub q_fs_global: Option<u128>,
    pub response_attempt_lifetime: Option<u64>,
    pub response_attempts_per_root: Option<u32>,
    pub synthetic_symbols_per_opened_leaf: Option<u64>,
    pub transformer_layers: Option<u32>,
    pub global_attention_layers: Option<Vec<u32>>,
    pub hidden_size: Option<u32>,
    pub local_kv_heads: Option<u32>,
    pub local_kv_head_dim: Option<u32>,
    pub global_kv_heads: Option<u32>,
    pub global_kv_head_dim: Option<u32>,
    pub global_k_v_widths_equal: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundFixture {
    pub round: Option<u8>,
    pub tree_leaves: Option<u64>,
    /// Each query must name its two distinct, consecutive opened leaves.
    pub query_leaf_pairs: Option<Vec<[u64; 2]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneFixture {
    pub kind: Option<PlaneKind>,
    /// Mandatory fixture relation name.  It does not bind a real protocol
    /// relation and therefore cannot unlock admission.
    pub synthetic_semantic_binding: Option<String>,
    /// Explicit stress-fixture root multiplicity. It is not inferred from
    /// terminal count and supplies no real physical-root credit.
    pub synthetic_root_count: Option<u32>,
    pub terminal_ordinals: Option<Vec<u16>>,
    pub rounds: Option<Vec<RoundFixture>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityEventFixture {
    pub id: Option<String>,
    pub owner: Option<PlaneKind>,
    pub numerator: Option<String>,
    pub denominator: Option<String>,
    pub fs_factor: Option<FsFactor>,
    pub lifetime: Option<EventLifetime>,
    pub scope: Option<EventScope>,
    pub includes_abort: Option<bool>,
    pub includes_retry: Option<bool>,
    pub includes_local_queries: Option<bool>,
    pub includes_concurrent_sessions: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRegistryFixture {
    /// Exact ordered inventory.  Rows not listed here are also rejected.
    pub required_ids: Option<Vec<String>>,
    pub rows: Option<Vec<SecurityEventFixture>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GemmaBkvFixture {
    pub profile: ProfileFixture,
    pub planes: Option<Vec<PlaneFixture>>,
    pub events: EventRegistryFixture,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledProfile {
    pub model: String,
    pub revision: String,
    pub text_only: bool,
    pub terminal_manifest_blake3: String,
    pub context_cap: u32,
    pub q_fs_global: u128,
    pub response_attempt_lifetime: u64,
    pub response_attempts_per_root: u32,
    pub root_epochs: u64,
    /// Transitions between epochs in one root-family lifetime.
    pub root_family_refreshes: u64,
    pub synthetic_symbols_per_opened_leaf: u64,
    pub transformer_layers: u32,
    pub global_attention_layers: Vec<u32>,
    pub local_attention_layers: u32,
    pub hidden_size: u32,
    pub local_kv_heads: u32,
    pub local_kv_head_dim: u32,
    pub global_kv_heads: u32,
    pub global_kv_head_dim: u32,
    pub global_k_v_widths_equal: bool,
    pub kv_values_per_token: u64,
    pub kv_arena_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRound {
    pub round: u8,
    pub tree_leaves: u64,
    pub query_leaf_pairs: Vec<[u64; 2]>,
    pub q: u32,
    pub u: u64,
    pub s: u64,
    pub h: u64,
    pub mask_loads: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPlane {
    pub kind: PlaneKind,
    pub synthetic_semantic_binding: String,
    pub synthetic_root_count: u32,
    pub terminal_ordinals: Vec<u16>,
    pub rounds: Vec<CompiledRound>,
    pub mask_loads_per_attempt: u64,
    pub service_mask_loads_per_root_epoch: u64,
    pub lifecycle_reserve_mask_loads_per_root_epoch: u64,
    pub provisioned_mask_cells_per_root_epoch: u64,
    pub service_lifetime_mask_loads_per_root: u64,
    pub lifecycle_reserve_lifetime_mask_loads_per_root: u64,
    pub provisioned_lifetime_mask_loads_per_root: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTerminal {
    pub ordinal: u16,
    pub kind: PlaneKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledSecurityEvent {
    pub id: String,
    pub owner: PlaneKind,
    pub numerator: String,
    pub denominator: String,
    pub fs_factor: u128,
    pub lifetime: u64,
    pub composed_numerator: String,
    pub scope: EventScope,
    pub includes_abort: bool,
    pub includes_retry: bool,
    pub includes_local_queries: bool,
    pub includes_concurrent_sessions: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionStatus {
    BlockedSyntheticOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledGemmaBkv {
    pub schema: &'static str,
    pub profile: CompiledProfile,
    pub planes: Vec<CompiledPlane>,
    pub terminals: Vec<CompiledTerminal>,
    pub events: Vec<CompiledSecurityEvent>,
    pub total_mask_loads_per_attempt_across_synthetic_roots: u64,
    pub total_provisioned_mask_cells_per_epoch_across_synthetic_roots: u64,
    pub total_service_lifetime_mask_loads_across_synthetic_roots: u64,
    pub total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots: u64,
    pub total_provisioned_lifetime_mask_loads_across_synthetic_roots: u64,
    pub admission: AdmissionStatus,
    pub security_credit: bool,
}

fn present<T>(value: Option<T>, path: &str) -> Result<T> {
    value.ok_or_else(|| CompileError::new(format!("missing required field {path}")))
}

fn require_equal<T: PartialEq + fmt::Debug>(actual: T, expected: T, path: &str) -> Result<T> {
    if actual != expected {
        return Err(CompileError::new(format!(
            "{path} differs: expected {expected:?}, got {actual:?}"
        )));
    }
    Ok(actual)
}

pub fn expected_terminal_manifest_blake3() -> Result<&'static str> {
    let digest = TERMINAL_MANIFEST_BLAKE3_SIDECAR
        .strip_suffix('\n')
        .ok_or_else(|| CompileError::new("terminal manifest BLAKE3 sidecar lacks final LF"))?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CompileError::new(
            "terminal manifest BLAKE3 sidecar is not 64 lowercase hex characters",
        ));
    }
    Ok(digest)
}

fn compile_profile(input: ProfileFixture) -> Result<CompiledProfile> {
    let model = require_equal(
        present(input.model, "profile.model")?,
        GEMMA_MODEL.to_owned(),
        "profile.model",
    )?;
    let revision = require_equal(
        present(input.revision, "profile.revision")?,
        GEMMA_REVISION.to_owned(),
        "profile.revision",
    )?;
    let text_only =
        require_equal(present(input.text_only, "profile.text_only")?, true, "profile.text_only")?;
    let terminal_manifest_blake3 = require_equal(
        present(input.terminal_manifest_blake3, "profile.terminal_manifest_blake3")?,
        expected_terminal_manifest_blake3()?.to_owned(),
        "profile.terminal_manifest_blake3",
    )?;
    let context_cap = require_equal(
        present(input.context_cap, "profile.context_cap")?,
        CONTEXT_CAP,
        "profile.context_cap",
    )?;
    let q_fs_global = require_equal(
        present(input.q_fs_global, "profile.q_fs_global")?,
        Q_FS_GLOBAL,
        "profile.q_fs_global",
    )?;
    let response_attempt_lifetime = require_equal(
        present(input.response_attempt_lifetime, "profile.response_attempt_lifetime")?,
        RESPONSE_ATTEMPT_LIFETIME,
        "profile.response_attempt_lifetime",
    )?;
    let response_attempts_per_root = require_equal(
        present(input.response_attempts_per_root, "profile.response_attempts_per_root")?,
        RESPONSE_ATTEMPTS_PER_ROOT,
        "profile.response_attempts_per_root",
    )?;
    let attempts_per_root = u64::from(response_attempts_per_root);
    let root_epochs = response_attempt_lifetime
        .checked_add(attempts_per_root - 1)
        .ok_or_else(|| CompileError::new("root epoch ceiling overflows u64"))?
        / attempts_per_root;
    let root_family_refreshes =
        root_epochs.checked_sub(1).ok_or_else(|| CompileError::new("root epoch count is zero"))?;
    let synthetic_symbols_per_opened_leaf = require_equal(
        present(
            input.synthetic_symbols_per_opened_leaf,
            "profile.synthetic_symbols_per_opened_leaf",
        )?,
        SYNTHETIC_SYMBOLS_PER_OPENED_LEAF,
        "profile.synthetic_symbols_per_opened_leaf",
    )?;
    let transformer_layers = require_equal(
        present(input.transformer_layers, "profile.transformer_layers")?,
        TRANSFORMER_LAYERS,
        "profile.transformer_layers",
    )?;
    let global_attention_layers = require_equal(
        present(input.global_attention_layers, "profile.global_attention_layers")?,
        GLOBAL_ATTENTION_LAYERS.to_vec(),
        "profile.global_attention_layers",
    )?;
    let hidden_size = require_equal(
        present(input.hidden_size, "profile.hidden_size")?,
        HIDDEN_SIZE,
        "profile.hidden_size",
    )?;
    let local_kv_heads = require_equal(
        present(input.local_kv_heads, "profile.local_kv_heads")?,
        LOCAL_KV_HEADS,
        "profile.local_kv_heads",
    )?;
    let local_kv_head_dim = require_equal(
        present(input.local_kv_head_dim, "profile.local_kv_head_dim")?,
        LOCAL_KV_HEAD_DIM,
        "profile.local_kv_head_dim",
    )?;
    let global_kv_heads = require_equal(
        present(input.global_kv_heads, "profile.global_kv_heads")?,
        GLOBAL_KV_HEADS,
        "profile.global_kv_heads",
    )?;
    let global_kv_head_dim = require_equal(
        present(input.global_kv_head_dim, "profile.global_kv_head_dim")?,
        GLOBAL_KV_HEAD_DIM,
        "profile.global_kv_head_dim",
    )?;
    let global_k_v_widths_equal = require_equal(
        present(input.global_k_v_widths_equal, "profile.global_k_v_widths_equal")?,
        true,
        "profile.global_k_v_widths_equal",
    )?;
    let global_attention_layer_count = u64::try_from(global_attention_layers.len())
        .map_err(|_| CompileError::new("global attention layer count exceeds u64"))?;
    let local_attention_layers = transformer_layers
        .checked_sub(global_attention_layer_count as u32)
        .ok_or_else(|| CompileError::new("global attention layers exceed all layers"))?;
    let local_values = u64::from(local_attention_layers)
        .checked_mul(u64::from(local_kv_heads))
        .and_then(|value| value.checked_mul(u64::from(local_kv_head_dim)))
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(|| CompileError::new("local K/V values overflow u64"))?;
    let global_values = global_attention_layer_count
        .checked_mul(u64::from(global_kv_heads))
        .and_then(|value| value.checked_mul(u64::from(global_kv_head_dim)))
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(|| CompileError::new("global K/V values overflow u64"))?;
    let kv_values_per_token = local_values
        .checked_add(global_values)
        .ok_or_else(|| CompileError::new("K/V values per token overflow u64"))?;
    let kv_arena_bytes = kv_values_per_token
        .checked_mul(u64::from(context_cap))
        .and_then(|value| value.checked_mul(I16_BYTES))
        .ok_or_else(|| CompileError::new("K/V arena bytes overflow u64"))?;
    Ok(CompiledProfile {
        model,
        revision,
        text_only,
        terminal_manifest_blake3,
        context_cap,
        q_fs_global,
        response_attempt_lifetime,
        response_attempts_per_root,
        root_epochs,
        root_family_refreshes,
        synthetic_symbols_per_opened_leaf,
        transformer_layers,
        global_attention_layers,
        local_attention_layers,
        hidden_size,
        local_kv_heads,
        local_kv_head_dim,
        global_kv_heads,
        global_kv_head_dim,
        global_k_v_widths_equal,
        kv_values_per_token,
        kv_arena_bytes,
    })
}

fn ragged_left_len(n: u64) -> u64 {
    debug_assert!(n > 1);
    1u64 << (63 - (n - 1).leading_zeros())
}

fn frontier_hashes(base: u64, len: u64, opened: &[u64]) -> Result<u64> {
    let end =
        base.checked_add(len).ok_or_else(|| CompileError::new("tree interval overflows u64"))?;
    let first = opened.partition_point(|leaf| *leaf < base);
    let last = opened.partition_point(|leaf| *leaf < end);
    if first == last {
        return Ok(1);
    }
    if len == 1 {
        return Ok(0);
    }
    let left_len = ragged_left_len(len);
    frontier_hashes(base, left_len, &opened[first..last])?
        .checked_add(frontier_hashes(base + left_len, len - left_len, &opened[first..last])?)
        .ok_or_else(|| CompileError::new("H overflows u64"))
}

fn compile_round(
    kind: PlaneKind,
    expected_round: usize,
    input: RoundFixture,
) -> Result<CompiledRound> {
    let prefix = format!("planes.{}.rounds[{expected_round}]", kind.label());
    let round = require_equal(
        present(input.round, &format!("{prefix}.round"))?,
        expected_round as u8,
        &format!("{prefix}.round"),
    )?;
    let tree_leaves = present(input.tree_leaves, &format!("{prefix}.tree_leaves"))?;
    if tree_leaves == 0 {
        return Err(CompileError::new(format!("{prefix}.tree_leaves is zero")));
    }
    let pairs = present(input.query_leaf_pairs, &format!("{prefix}.query_leaf_pairs"))?;
    let q = u32::try_from(pairs.len())
        .map_err(|_| CompileError::new(format!("{prefix}.q exceeds u32")))?;
    require_equal(q, SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND[expected_round], &format!("{prefix}.q"))?;

    let mut opened = Vec::with_capacity(pairs.len() * 2);
    for (query, pair) in pairs.iter().copied().enumerate() {
        if pair[0].checked_add(1) != Some(pair[1]) {
            return Err(CompileError::new(format!(
                "{prefix}.query_leaf_pairs[{query}] is not one consecutive leaf pair"
            )));
        }
        if pair[1] >= tree_leaves {
            return Err(CompileError::new(format!(
                "{prefix}.query_leaf_pairs[{query}] exceeds tree_leaves"
            )));
        }
        if opened.last().is_some_and(|previous| *previous >= pair[0]) {
            return Err(CompileError::new(format!(
                "{prefix}.query_leaf_pairs are reordered or overlap"
            )));
        }
        opened.extend_from_slice(&pair);
    }

    let u = u64::try_from(opened.len())
        .map_err(|_| CompileError::new(format!("{prefix}.U exceeds u64")))?;
    let s = u
        .checked_mul(SYNTHETIC_SYMBOLS_PER_OPENED_LEAF)
        .ok_or_else(|| CompileError::new(format!("{prefix}.S overflows u64")))?;
    let h = frontier_hashes(0, tree_leaves, &opened)?;
    Ok(CompiledRound {
        round,
        tree_leaves,
        query_leaf_pairs: pairs,
        q,
        u,
        s,
        h,
        // One fresh field mask is loaded for every visible field symbol.
        mask_loads: s,
    })
}

fn compile_plane(
    expected_kind: PlaneKind,
    input: PlaneFixture,
    root_epochs: u64,
) -> Result<CompiledPlane> {
    let kind =
        require_equal(present(input.kind, "planes.kind")?, expected_kind, "planes.kind/order")?;
    let synthetic_semantic_binding = present(
        input.synthetic_semantic_binding,
        &format!("planes.{}.synthetic_semantic_binding", kind.label()),
    )?;
    if synthetic_semantic_binding.is_empty()
        || !synthetic_semantic_binding.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_/".contains(&byte)
        })
    {
        return Err(CompileError::new(format!(
            "planes.{}.synthetic_semantic_binding is not canonical",
            kind.label()
        )));
    }
    let synthetic_root_count = present(
        input.synthetic_root_count,
        &format!("planes.{}.synthetic_root_count", kind.label()),
    )?;
    if synthetic_root_count == 0 {
        return Err(CompileError::new(format!(
            "planes.{}.synthetic_root_count is zero",
            kind.label()
        )));
    }
    let terminal_ordinals = require_equal(
        present(input.terminal_ordinals, &format!("planes.{}.terminal_ordinals", kind.label()))?,
        kind.expected_terminals().to_vec(),
        &format!("planes.{}.terminal_ordinals", kind.label()),
    )?;
    let rounds = present(input.rounds, &format!("planes.{}.rounds", kind.label()))?;
    if rounds.len() != SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND.len() {
        return Err(CompileError::new(format!(
            "planes.{}.rounds: expected {}, got {}",
            kind.label(),
            SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND.len(),
            rounds.len()
        )));
    }
    let rounds = rounds
        .into_iter()
        .enumerate()
        .map(|(index, round)| compile_round(kind, index, round))
        .collect::<Result<Vec<_>>>()?;
    let mask_loads_per_attempt = rounds.iter().try_fold(0u64, |total, round| {
        total
            .checked_add(round.mask_loads)
            .ok_or_else(|| CompileError::new("plane mask loads overflow u64"))
    })?;
    let service_mask_loads_per_root_epoch = mask_loads_per_attempt
        .checked_mul(u64::from(RESPONSE_ATTEMPTS_PER_ROOT))
        .ok_or_else(|| CompileError::new("attempt mask loads per root overflow u64"))?;
    let lifecycle_reserve_mask_loads_per_root_epoch = mask_loads_per_attempt
        .checked_mul(u64::from(LIFECYCLE_LOAD_RESERVE_PER_ROOT))
        .ok_or_else(|| CompileError::new("lifecycle mask reserve per root overflows u64"))?;
    let provisioned_mask_cells_per_root_epoch = service_mask_loads_per_root_epoch
        .checked_add(lifecycle_reserve_mask_loads_per_root_epoch)
        .ok_or_else(|| CompileError::new("reserved mask cells per root overflow u64"))?;
    let service_lifetime_mask_loads_per_root = mask_loads_per_attempt
        .checked_mul(RESPONSE_ATTEMPT_LIFETIME)
        .ok_or_else(|| CompileError::new("response lifetime mask loads overflow u64"))?;
    let lifecycle_reserve_lifetime_mask_loads_per_root =
        lifecycle_reserve_mask_loads_per_root_epoch
            .checked_mul(root_epochs)
            .ok_or_else(|| CompileError::new("lifecycle lifetime mask loads overflow u64"))?;
    let provisioned_lifetime_mask_loads_per_root = service_lifetime_mask_loads_per_root
        .checked_add(lifecycle_reserve_lifetime_mask_loads_per_root)
        .ok_or_else(|| CompileError::new("provisioned lifetime mask loads overflow u64"))?;
    Ok(CompiledPlane {
        kind,
        synthetic_semantic_binding,
        synthetic_root_count,
        terminal_ordinals,
        rounds,
        mask_loads_per_attempt,
        service_mask_loads_per_root_epoch,
        lifecycle_reserve_mask_loads_per_root_epoch,
        provisioned_mask_cells_per_root_epoch,
        service_lifetime_mask_loads_per_root,
        lifecycle_reserve_lifetime_mask_loads_per_root,
        provisioned_lifetime_mask_loads_per_root,
    })
}

fn valid_positive_decimal(raw: String, path: &str) -> Result<String> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) || raw.starts_with('0') {
        return Err(CompileError::new(format!("{path} must be a canonical positive decimal")));
    }
    Ok(raw)
}

fn decimal_lt(left: &str, right: &str) -> bool {
    left.len() < right.len() || (left.len() == right.len() && left < right)
}

fn decimal_mul_u128(value: &str, multiplier: u128) -> String {
    debug_assert!(multiplier > 0);
    let mut carry = 0u128;
    let mut reversed = Vec::with_capacity(value.len() + 40);
    for digit in value.bytes().rev() {
        let product = u128::from(digit - b'0') * multiplier + carry;
        reversed.push(b'0' + (product % 10) as u8);
        carry = product / 10;
    }
    while carry > 0 {
        reversed.push(b'0' + (carry % 10) as u8);
        carry /= 10;
    }
    reversed.reverse();
    String::from_utf8(reversed).expect("decimal multiplication emits ASCII")
}

fn event_union_factor(
    fs_factor: FsFactor,
    lifetime: EventLifetime,
    scope: EventScope,
    path: &str,
) -> Result<u128> {
    match (fs_factor, lifetime, scope) {
        // Q_FS_global already counts every query in the complete lifetime.
        // Multiplying by RESPONSE_ATTEMPT_LIFETIME here would count attempts twice.
        (
            FsFactor::GlobalQfsPlusOne,
            EventLifetime::AllResponseAttempts,
            EventScope::GlobalClassicalRomLifetime,
        ) => Ok(Q_FS_GLOBAL + 1),
        (FsFactor::One, EventLifetime::AllResponseAttempts, EventScope::FullResponseLifetime) => {
            Ok(u128::from(RESPONSE_ATTEMPT_LIFETIME))
        }
        (FsFactor::One, EventLifetime::OneAttempt, EventScope::ResponseAttempt) => Ok(1),
        _ => Err(CompileError::new(format!(
            "{path} has an inconsistent FS/lifetime/scope combination"
        ))),
    }
}

fn compile_events(input: EventRegistryFixture) -> Result<Vec<CompiledSecurityEvent>> {
    let required_ids = present(input.required_ids, "events.required_ids")?;
    let rows = present(input.rows, "events.rows")?;
    if required_ids.is_empty() {
        return Err(CompileError::new("events.required_ids is empty"));
    }
    if required_ids.iter().any(|id| {
        id.is_empty()
            || !id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._/".contains(&byte)
            })
    }) {
        return Err(CompileError::new("events.required_ids contains a non-canonical identifier"));
    }
    if !required_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(CompileError::new(
            "events.required_ids must be strictly ordered without duplicates",
        ));
    }
    if rows.len() != required_ids.len() {
        return Err(CompileError::new(format!(
            "event inventory differs: expected {}, got {}",
            required_ids.len(),
            rows.len()
        )));
    }

    let mut owners = [false; 3];
    let mut compiled = Vec::with_capacity(rows.len());
    for (index, (expected_id, row)) in required_ids.into_iter().zip(rows).enumerate() {
        let prefix = format!("events.rows[{index}]");
        let id = require_equal(
            present(row.id, &format!("{prefix}.id"))?,
            expected_id,
            &format!("{prefix}.id/order"),
        )?;
        let owner = present(row.owner, &format!("{prefix}.owner"))?;
        owners[owner.tag() as usize] = true;
        let numerator = valid_positive_decimal(
            present(row.numerator, &format!("{prefix}.numerator"))?,
            &format!("{prefix}.numerator"),
        )?;
        let denominator = valid_positive_decimal(
            present(row.denominator, &format!("{prefix}.denominator"))?,
            &format!("{prefix}.denominator"),
        )?;
        if !decimal_lt(&numerator, &denominator) {
            return Err(CompileError::new(format!("{prefix} must have numerator < denominator")));
        }
        let fs_factor = present(row.fs_factor, &format!("{prefix}.fs_factor"))?;
        let lifetime = present(row.lifetime, &format!("{prefix}.lifetime"))?;
        let scope = present(row.scope, &format!("{prefix}.scope"))?;
        let includes_abort = present(row.includes_abort, &format!("{prefix}.includes_abort"))?;
        let includes_retry = present(row.includes_retry, &format!("{prefix}.includes_retry"))?;
        let includes_local_queries =
            present(row.includes_local_queries, &format!("{prefix}.includes_local_queries"))?;
        let includes_concurrent_sessions = present(
            row.includes_concurrent_sessions,
            &format!("{prefix}.includes_concurrent_sessions"),
        )?;
        if !includes_abort || !includes_retry {
            return Err(CompileError::new(format!(
                "{prefix} must account for both abort and retry"
            )));
        }
        if fs_factor == FsFactor::GlobalQfsPlusOne
            && (!includes_local_queries || !includes_concurrent_sessions)
        {
            return Err(CompileError::new(format!(
                "{prefix} global FS factor must include local queries and concurrent sessions"
            )));
        }
        let union_factor = event_union_factor(fs_factor, lifetime, scope, &prefix)?;
        let composed_numerator = decimal_mul_u128(&numerator, union_factor);
        if !decimal_lt(&composed_numerator, &denominator) {
            return Err(CompileError::new(format!(
                "{prefix} amplified event bound is not below one"
            )));
        }
        compiled.push(CompiledSecurityEvent {
            id,
            owner,
            numerator,
            denominator,
            fs_factor: fs_factor.value(),
            lifetime: lifetime.value(),
            composed_numerator,
            scope,
            includes_abort,
            includes_retry,
            includes_local_queries,
            includes_concurrent_sessions,
        });
    }
    if owners != [true, true, true] {
        return Err(CompileError::new(
            "event inventory must contain at least one row for PlaneB, KV-old and KV-new",
        ));
    }
    Ok(compiled)
}

pub fn compile_gemma_bkv_fixture(input: GemmaBkvFixture) -> Result<CompiledGemmaBkv> {
    let profile = compile_profile(input.profile)?;
    let root_epochs = profile.root_epochs;
    let planes = present(input.planes, "planes")?;
    let expected = [PlaneKind::PlaneB, PlaneKind::KvOld, PlaneKind::KvNew];
    if planes.len() != expected.len() {
        return Err(CompileError::new(format!(
            "planes: expected {}, got {}",
            expected.len(),
            planes.len()
        )));
    }
    let planes = expected
        .into_iter()
        .zip(planes)
        .map(|(kind, plane)| compile_plane(kind, plane, root_epochs))
        .collect::<Result<Vec<_>>>()?;
    let terminals = planes
        .iter()
        .flat_map(|plane| {
            plane
                .terminal_ordinals
                .iter()
                .copied()
                .map(move |ordinal| CompiledTerminal { ordinal, kind: plane.kind })
        })
        .collect::<Vec<_>>();
    if terminals.len() != 8 {
        return Err(CompileError::new("B/KV terminal census is not eight"));
    }
    let total_mask_loads_per_attempt_across_synthetic_roots =
        planes.iter().try_fold(0u64, |total, plane| {
            let plane_total = plane
                .mask_loads_per_attempt
                .checked_mul(u64::from(plane.synthetic_root_count))
                .ok_or_else(|| CompileError::new("plane attempt mask loads overflow u64"))?;
            total
                .checked_add(plane_total)
                .ok_or_else(|| CompileError::new("total mask loads overflow u64"))
        })?;
    let total_provisioned_mask_cells_per_epoch_across_synthetic_roots =
        planes.iter().try_fold(0u64, |total, plane| {
            let plane_total = plane
                .provisioned_mask_cells_per_root_epoch
                .checked_mul(u64::from(plane.synthetic_root_count))
                .ok_or_else(|| CompileError::new("plane root mask cells overflow u64"))?;
            total
                .checked_add(plane_total)
                .ok_or_else(|| CompileError::new("total root mask cells overflow u64"))
        })?;
    let sum_across_synthetic_roots = |select: fn(&CompiledPlane) -> u64| -> Result<u64> {
        planes.iter().try_fold(0u64, |total, plane| {
            let plane_total = select(plane)
                .checked_mul(u64::from(plane.synthetic_root_count))
                .ok_or_else(|| CompileError::new("plane lifetime mask loads overflow u64"))?;
            total
                .checked_add(plane_total)
                .ok_or_else(|| CompileError::new("total lifetime mask loads overflow u64"))
        })
    };
    let total_service_lifetime_mask_loads_across_synthetic_roots =
        sum_across_synthetic_roots(|plane| plane.service_lifetime_mask_loads_per_root)?;
    let total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots =
        sum_across_synthetic_roots(|plane| plane.lifecycle_reserve_lifetime_mask_loads_per_root)?;
    let total_provisioned_lifetime_mask_loads_across_synthetic_roots =
        sum_across_synthetic_roots(|plane| plane.provisioned_lifetime_mask_loads_per_root)?;
    let events = compile_events(input.events)?;
    Ok(CompiledGemmaBkv {
        schema: SCHEMA,
        profile,
        planes,
        terminals,
        events,
        total_mask_loads_per_attempt_across_synthetic_roots,
        total_provisioned_mask_cells_per_epoch_across_synthetic_roots,
        total_service_lifetime_mask_loads_across_synthetic_roots,
        total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots,
        total_provisioned_lifetime_mask_loads_across_synthetic_roots,
        admission: AdmissionStatus::BlockedSyntheticOnly,
        security_credit: false,
    })
}

pub fn verify_gemma_bkv_compilation(
    input: GemmaBkvFixture,
    compiled: &CompiledGemmaBkv,
) -> Result<()> {
    let expected = compile_gemma_bkv_fixture(input)?;
    if &expected != compiled {
        return Err(CompileError::new(
            "compiled B/KV record differs from deterministic recompilation",
        ));
    }
    Ok(())
}

impl CompiledGemmaBkv {
    /// Stable bytes for a later transcript/refinement binding.  No security
    /// property is attributed to these bytes in the synthetic checkpoint.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn push_u64(out: &mut Vec<u8>, value: u64) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn push_u128(out: &mut Vec<u8>, value: u128) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn push_str(out: &mut Vec<u8>, value: &str) {
            push_u64(out, value.len() as u64);
            out.extend_from_slice(value.as_bytes());
        }

        let mut out = Vec::new();
        push_str(&mut out, self.schema);
        push_str(&mut out, &self.profile.model);
        push_str(&mut out, &self.profile.revision);
        out.push(u8::from(self.profile.text_only));
        push_str(&mut out, &self.profile.terminal_manifest_blake3);
        out.extend_from_slice(&self.profile.context_cap.to_le_bytes());
        push_u128(&mut out, self.profile.q_fs_global);
        push_u64(&mut out, self.profile.response_attempt_lifetime);
        out.extend_from_slice(&self.profile.response_attempts_per_root.to_le_bytes());
        push_u64(&mut out, self.profile.root_epochs);
        push_u64(&mut out, self.profile.root_family_refreshes);
        push_u64(&mut out, self.profile.synthetic_symbols_per_opened_leaf);
        out.extend_from_slice(&self.profile.transformer_layers.to_le_bytes());
        push_u64(&mut out, self.profile.global_attention_layers.len() as u64);
        for layer in &self.profile.global_attention_layers {
            out.extend_from_slice(&layer.to_le_bytes());
        }
        out.extend_from_slice(&self.profile.local_attention_layers.to_le_bytes());
        out.extend_from_slice(&self.profile.hidden_size.to_le_bytes());
        out.extend_from_slice(&self.profile.local_kv_heads.to_le_bytes());
        out.extend_from_slice(&self.profile.local_kv_head_dim.to_le_bytes());
        out.extend_from_slice(&self.profile.global_kv_heads.to_le_bytes());
        out.extend_from_slice(&self.profile.global_kv_head_dim.to_le_bytes());
        out.push(u8::from(self.profile.global_k_v_widths_equal));
        push_u64(&mut out, self.profile.kv_values_per_token);
        push_u64(&mut out, self.profile.kv_arena_bytes);
        push_u64(&mut out, self.planes.len() as u64);
        for plane in &self.planes {
            out.push(plane.kind.tag());
            push_str(&mut out, &plane.synthetic_semantic_binding);
            out.extend_from_slice(&plane.synthetic_root_count.to_le_bytes());
            push_u64(&mut out, plane.terminal_ordinals.len() as u64);
            for ordinal in &plane.terminal_ordinals {
                out.extend_from_slice(&ordinal.to_le_bytes());
            }
            push_u64(&mut out, plane.rounds.len() as u64);
            for round in &plane.rounds {
                out.push(round.round);
                push_u64(&mut out, round.tree_leaves);
                push_u64(&mut out, round.query_leaf_pairs.len() as u64);
                for pair in &round.query_leaf_pairs {
                    push_u64(&mut out, pair[0]);
                    push_u64(&mut out, pair[1]);
                }
                out.extend_from_slice(&round.q.to_le_bytes());
                for value in [round.u, round.s, round.h, round.mask_loads] {
                    push_u64(&mut out, value);
                }
            }
            push_u64(&mut out, plane.mask_loads_per_attempt);
            push_u64(&mut out, plane.service_mask_loads_per_root_epoch);
            push_u64(&mut out, plane.lifecycle_reserve_mask_loads_per_root_epoch);
            push_u64(&mut out, plane.provisioned_mask_cells_per_root_epoch);
            push_u64(&mut out, plane.service_lifetime_mask_loads_per_root);
            push_u64(&mut out, plane.lifecycle_reserve_lifetime_mask_loads_per_root);
            push_u64(&mut out, plane.provisioned_lifetime_mask_loads_per_root);
        }
        push_u64(&mut out, self.terminals.len() as u64);
        for terminal in &self.terminals {
            out.extend_from_slice(&terminal.ordinal.to_le_bytes());
            out.push(terminal.kind.tag());
        }
        push_u64(&mut out, self.events.len() as u64);
        for event in &self.events {
            push_str(&mut out, &event.id);
            out.push(event.owner.tag());
            push_str(&mut out, &event.numerator);
            push_str(&mut out, &event.denominator);
            push_u128(&mut out, event.fs_factor);
            push_u64(&mut out, event.lifetime);
            push_str(&mut out, &event.composed_numerator);
            out.push(event.scope.tag());
            out.push(u8::from(event.includes_abort));
            out.push(u8::from(event.includes_retry));
            out.push(u8::from(event.includes_local_queries));
            out.push(u8::from(event.includes_concurrent_sessions));
        }
        push_u64(&mut out, self.total_mask_loads_per_attempt_across_synthetic_roots);
        push_u64(&mut out, self.total_provisioned_mask_cells_per_epoch_across_synthetic_roots);
        push_u64(&mut out, self.total_service_lifetime_mask_loads_across_synthetic_roots);
        push_u64(&mut out, self.total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots);
        push_u64(&mut out, self.total_provisioned_lifetime_mask_loads_across_synthetic_roots);
        out.push(0); // BlockedSyntheticOnly
        out.push(u8::from(self.security_credit));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_DENOMINATOR: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936";

    fn active_profile() -> ProfileFixture {
        ProfileFixture {
            model: Some(GEMMA_MODEL.to_owned()),
            revision: Some(GEMMA_REVISION.to_owned()),
            text_only: Some(true),
            terminal_manifest_blake3: Some(expected_terminal_manifest_blake3().unwrap().to_owned()),
            context_cap: Some(CONTEXT_CAP),
            q_fs_global: Some(Q_FS_GLOBAL),
            response_attempt_lifetime: Some(RESPONSE_ATTEMPT_LIFETIME),
            response_attempts_per_root: Some(RESPONSE_ATTEMPTS_PER_ROOT),
            synthetic_symbols_per_opened_leaf: Some(SYNTHETIC_SYMBOLS_PER_OPENED_LEAF),
            transformer_layers: Some(TRANSFORMER_LAYERS),
            global_attention_layers: Some(GLOBAL_ATTENTION_LAYERS.to_vec()),
            hidden_size: Some(HIDDEN_SIZE),
            local_kv_heads: Some(LOCAL_KV_HEADS),
            local_kv_head_dim: Some(LOCAL_KV_HEAD_DIM),
            global_kv_heads: Some(GLOBAL_KV_HEADS),
            global_kv_head_dim: Some(GLOBAL_KV_HEAD_DIM),
            global_k_v_widths_equal: Some(true),
        }
    }

    fn rounds() -> Vec<RoundFixture> {
        SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND
            .into_iter()
            .enumerate()
            .map(|(round, q)| {
                let query_leaf_pairs =
                    (0..u64::from(q)).map(|query| [4 * query, 4 * query + 1]).collect::<Vec<_>>();
                let tree_leaves = query_leaf_pairs.last().unwrap()[1] + 1;
                RoundFixture {
                    round: Some(round as u8),
                    tree_leaves: Some(tree_leaves),
                    query_leaf_pairs: Some(query_leaf_pairs),
                }
            })
            .collect()
    }

    fn event(id: &str, owner: PlaneKind) -> SecurityEventFixture {
        SecurityEventFixture {
            id: Some(id.to_owned()),
            owner: Some(owner),
            numerator: Some("1".to_owned()),
            denominator: Some(SYNTHETIC_DENOMINATOR.to_owned()),
            fs_factor: Some(FsFactor::GlobalQfsPlusOne),
            lifetime: Some(EventLifetime::AllResponseAttempts),
            scope: Some(EventScope::GlobalClassicalRomLifetime),
            includes_abort: Some(true),
            includes_retry: Some(true),
            includes_local_queries: Some(true),
            includes_concurrent_sessions: Some(true),
        }
    }

    fn fixture() -> GemmaBkvFixture {
        let ids = vec![
            "b.synthetic-bound".to_owned(),
            "kv-new.synthetic-bound".to_owned(),
            "kv-old.synthetic-bound".to_owned(),
        ];
        GemmaBkvFixture {
            profile: active_profile(),
            planes: Some(vec![
                PlaneFixture {
                    kind: Some(PlaneKind::PlaneB),
                    synthetic_semantic_binding: Some("fixture/plane-b/unbound".to_owned()),
                    synthetic_root_count: Some(1),
                    terminal_ordinals: Some(vec![472, 473, 474, 475]),
                    rounds: Some(rounds()),
                },
                PlaneFixture {
                    kind: Some(PlaneKind::KvOld),
                    synthetic_semantic_binding: Some("fixture/kv-old/query-tape".to_owned()),
                    synthetic_root_count: Some(1),
                    terminal_ordinals: Some(vec![476, 477]),
                    rounds: Some(rounds()),
                },
                PlaneFixture {
                    kind: Some(PlaneKind::KvNew),
                    synthetic_semantic_binding: Some("fixture/kv-new/query-tape".to_owned()),
                    synthetic_root_count: Some(1),
                    terminal_ordinals: Some(vec![478, 479]),
                    rounds: Some(rounds()),
                },
            ]),
            events: EventRegistryFixture {
                required_ids: Some(ids),
                rows: Some(vec![
                    event("b.synthetic-bound", PlaneKind::PlaneB),
                    event("kv-new.synthetic-bound", PlaneKind::KvNew),
                    event("kv-old.synthetic-bound", PlaneKind::KvOld),
                ]),
            },
        }
    }

    #[test]
    fn minimal_active_fixture_derives_exact_bkv_schedule() {
        let compiled = compile_gemma_bkv_fixture(fixture()).unwrap();
        assert_eq!(
            compiled.planes.iter().map(|plane| plane.kind).collect::<Vec<_>>(),
            [PlaneKind::PlaneB, PlaneKind::KvOld, PlaneKind::KvNew]
        );
        assert_eq!(compiled.terminals.len(), 8);
        assert_eq!(compiled.profile.local_attention_layers, 50);
        assert_eq!(compiled.profile.global_attention_layers.len(), 10);
        assert_eq!(compiled.profile.kv_values_per_token, 450_560);
        assert_eq!(compiled.profile.kv_arena_bytes, 3_690_987_520);
        assert_eq!(
            compiled.profile.terminal_manifest_blake3,
            expected_terminal_manifest_blake3().unwrap()
        );
        assert_eq!(compiled.profile.root_epochs, 256);
        assert_eq!(compiled.profile.root_family_refreshes, 255);
        assert_eq!(
            compiled.profile.root_epochs,
            RESPONSE_ATTEMPT_LIFETIME.div_ceil(u64::from(RESPONSE_ATTEMPTS_PER_ROOT))
        );
        assert_eq!(compiled.profile.root_family_refreshes, compiled.profile.root_epochs - 1);
        assert_eq!(
            compiled.terminals.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
            (472..480).collect::<Vec<_>>()
        );
        for plane in &compiled.planes {
            assert_eq!(
                plane.rounds.iter().map(|round| round.q).collect::<Vec<_>>(),
                SYNTHETIC_ADMISSION_CAP_Q_BY_ROUND
            );
            assert!(plane.rounds.iter().all(|round| round.u == 2 * u64::from(round.q)));
            assert!(plane
                .rounds
                .iter()
                .all(|round| round.s == SYNTHETIC_SYMBOLS_PER_OPENED_LEAF * round.u));
            assert!(plane.rounds.iter().all(|round| round.mask_loads == round.s));
            assert_eq!(plane.mask_loads_per_attempt, 399_594);
            assert_eq!(
                plane.rounds.iter().map(|round| round.h).collect::<Vec<_>>(),
                [356, 162, 151, 148, 148, 148, 148, 148]
            );
            assert_eq!(plane.service_mask_loads_per_root_epoch, 1_636_737_024);
            assert_eq!(plane.lifecycle_reserve_mask_loads_per_root_epoch, 204_592_128);
            assert_eq!(plane.provisioned_mask_cells_per_root_epoch, 1_841_329_152);
            assert_eq!(plane.synthetic_root_count, 1);
            assert_eq!(plane.service_lifetime_mask_loads_per_root, 419_004_678_144);
            assert_eq!(plane.lifecycle_reserve_lifetime_mask_loads_per_root, 52_375_584_768);
            assert_eq!(plane.provisioned_lifetime_mask_loads_per_root, 471_380_262_912);
            assert_eq!(
                plane.service_lifetime_mask_loads_per_root,
                plane.mask_loads_per_attempt * RESPONSE_ATTEMPT_LIFETIME
            );
            assert_eq!(
                plane.lifecycle_reserve_lifetime_mask_loads_per_root,
                plane.lifecycle_reserve_mask_loads_per_root_epoch * compiled.profile.root_epochs
            );
            assert_eq!(
                plane.provisioned_lifetime_mask_loads_per_root,
                plane.service_lifetime_mask_loads_per_root
                    + plane.lifecycle_reserve_lifetime_mask_loads_per_root
            );
        }
        assert_eq!(compiled.total_mask_loads_per_attempt_across_synthetic_roots, 1_198_782);
        assert_eq!(
            compiled.total_provisioned_mask_cells_per_epoch_across_synthetic_roots,
            5_523_987_456
        );
        assert_eq!(
            compiled.total_service_lifetime_mask_loads_across_synthetic_roots,
            1_257_014_034_432
        );
        assert_eq!(
            compiled.total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots,
            157_126_754_304
        );
        assert_eq!(
            compiled.total_provisioned_lifetime_mask_loads_across_synthetic_roots,
            1_414_140_788_736
        );
        assert_eq!(
            compiled.total_provisioned_lifetime_mask_loads_across_synthetic_roots,
            compiled.total_service_lifetime_mask_loads_across_synthetic_roots
                + compiled.total_lifecycle_reserve_lifetime_mask_loads_across_synthetic_roots
        );
        assert_eq!(compiled.admission, AdmissionStatus::BlockedSyntheticOnly);
        assert!(!compiled.security_credit);
        assert_eq!(
            compiled.events.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            ["b.synthetic-bound", "kv-new.synthetic-bound", "kv-old.synthetic-bound"]
        );
        assert!(compiled
            .events
            .iter()
            .all(|event| { event.composed_numerator == (Q_FS_GLOBAL + 1).to_string() }));
        assert_eq!(
            compiled.canonical_bytes(),
            compile_gemma_bkv_fixture(fixture()).unwrap().canonical_bytes()
        );

        let mut two_synthetic_b_roots = fixture();
        two_synthetic_b_roots.planes.as_mut().unwrap()[0].synthetic_root_count = Some(2);
        let two_synthetic_b_roots = compile_gemma_bkv_fixture(two_synthetic_b_roots).unwrap();
        assert_eq!(
            two_synthetic_b_roots.total_provisioned_mask_cells_per_epoch_across_synthetic_roots,
            5_523_987_456 + 1_841_329_152
        );
        assert_eq!(
            two_synthetic_b_roots.total_mask_loads_per_attempt_across_synthetic_roots,
            1_198_782 + 399_594
        );
        assert_eq!(
            two_synthetic_b_roots.total_provisioned_lifetime_mask_loads_across_synthetic_roots,
            1_414_140_788_736 + 471_380_262_912
        );
    }

    #[test]
    fn global_fs_does_not_count_response_lifetime_twice() {
        let global = compile_gemma_bkv_fixture(fixture()).unwrap();
        assert_eq!(global.events[0].fs_factor, Q_FS_GLOBAL + 1);
        assert_eq!(global.events[0].lifetime, RESPONSE_ATTEMPT_LIFETIME);
        assert_eq!(global.events[0].composed_numerator, (Q_FS_GLOBAL + 1).to_string());

        let mut non_fs = fixture();
        let row = &mut non_fs.events.rows.as_mut().unwrap()[0];
        row.fs_factor = Some(FsFactor::One);
        row.scope = Some(EventScope::FullResponseLifetime);
        let compiled = compile_gemma_bkv_fixture(non_fs).unwrap();
        assert_eq!(compiled.events[0].composed_numerator, RESPONSE_ATTEMPT_LIFETIME.to_string());

        let mut inconsistent = fixture();
        inconsistent.events.rows.as_mut().unwrap()[0].fs_factor = Some(FsFactor::One);
        assert!(compile_gemma_bkv_fixture(inconsistent).is_err());
    }

    #[test]
    fn exact_query_tape_is_bound_even_when_q_u_s_h_match() {
        let original_fixture = fixture();
        let original = compile_gemma_bkv_fixture(original_fixture.clone()).unwrap();

        let mut alternate_fixture = fixture();
        alternate_fixture.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap()[0]
            .query_leaf_pairs
            .as_mut()
            .unwrap()[0] = [2, 3];
        let alternate = compile_gemma_bkv_fixture(alternate_fixture).unwrap();

        let left = &original.planes[0].rounds[0];
        let right = &alternate.planes[0].rounds[0];
        assert_eq!((left.q, left.u, left.s, left.h), (right.q, right.u, right.s, right.h));
        assert_ne!(left.query_leaf_pairs, right.query_leaf_pairs);
        assert_ne!(original.canonical_bytes(), alternate.canonical_bytes());
        assert!(verify_gemma_bkv_compilation(original_fixture, &alternate).is_err());
    }

    #[test]
    fn rejects_reordering_duplicates_and_omissions() {
        let mut reordered = fixture();
        reordered.planes.as_mut().unwrap().swap(0, 1);
        assert!(compile_gemma_bkv_fixture(reordered).is_err());

        let mut duplicate = fixture();
        duplicate.planes.as_mut().unwrap()[0].terminal_ordinals.as_mut().unwrap()[3] = 474;
        assert!(compile_gemma_bkv_fixture(duplicate).is_err());

        let mut omitted = fixture();
        omitted.planes.as_mut().unwrap().pop();
        assert!(compile_gemma_bkv_fixture(omitted).is_err());

        let mut round_order = fixture();
        round_order.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap().swap(0, 1);
        assert!(compile_gemma_bkv_fixture(round_order).is_err());

        let mut query_order = fixture();
        query_order.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap()[0]
            .query_leaf_pairs
            .as_mut()
            .unwrap()
            .swap(0, 1);
        assert!(compile_gemma_bkv_fixture(query_order).is_err());

        let mut event_order = fixture();
        event_order.events.rows.as_mut().unwrap().swap(0, 1);
        assert!(compile_gemma_bkv_fixture(event_order).is_err());

        let mut duplicate_event = fixture();
        duplicate_event.events.required_ids.as_mut().unwrap()[1] = "b.synthetic-bound".to_owned();
        assert!(compile_gemma_bkv_fixture(duplicate_event).is_err());
    }

    #[test]
    fn rejects_non_active_or_ad_hoc_parameters() {
        let mut wrong_context = fixture();
        wrong_context.profile.context_cap = Some(CONTEXT_CAP - 1);
        assert!(compile_gemma_bkv_fixture(wrong_context).is_err());

        let mut wrong_q = fixture();
        wrong_q.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap()[0]
            .query_leaf_pairs
            .as_mut()
            .unwrap()
            .pop();
        assert!(compile_gemma_bkv_fixture(wrong_q).is_err());

        let mut wrong_lifetime = fixture();
        wrong_lifetime.profile.response_attempt_lifetime = Some(RESPONSE_ATTEMPT_LIFETIME - 1);
        assert!(compile_gemma_bkv_fixture(wrong_lifetime).is_err());

        let mut wrong_attempts = fixture();
        wrong_attempts.profile.response_attempts_per_root = Some(RESPONSE_ATTEMPTS_PER_ROOT + 1);
        assert!(compile_gemma_bkv_fixture(wrong_attempts).is_err());

        let mut wrong_model = fixture();
        wrong_model.profile.model = Some("unrelated-small-model".to_owned());
        assert!(compile_gemma_bkv_fixture(wrong_model).is_err());

        let mut non_text_scope = fixture();
        non_text_scope.profile.text_only = Some(false);
        assert!(compile_gemma_bkv_fixture(non_text_scope).is_err());

        let mut wrong_manifest = fixture();
        let mut wrong_digest = expected_terminal_manifest_blake3().unwrap().to_owned();
        let replacement = if wrong_digest.starts_with('0') { "1" } else { "0" };
        wrong_digest.replace_range(..1, replacement);
        wrong_manifest.profile.terminal_manifest_blake3 = Some(wrong_digest);
        assert!(compile_gemma_bkv_fixture(wrong_manifest).is_err());

        let mut wrong_global_layers = fixture();
        wrong_global_layers.profile.global_attention_layers.as_mut().unwrap()[0] = 4;
        assert!(compile_gemma_bkv_fixture(wrong_global_layers).is_err());

        let mut wrong_hidden_size = fixture();
        wrong_hidden_size.profile.hidden_size = Some(HIDDEN_SIZE - 1);
        assert!(compile_gemma_bkv_fixture(wrong_hidden_size).is_err());
    }

    #[test]
    fn missing_or_zero_event_data_never_becomes_zero() {
        let mut missing = fixture();
        missing.events.rows.as_mut().unwrap()[0].numerator = None;
        assert!(compile_gemma_bkv_fixture(missing).is_err());

        let mut zero = fixture();
        zero.events.rows.as_mut().unwrap()[0].numerator = Some("0".to_owned());
        assert!(compile_gemma_bkv_fixture(zero).is_err());

        let mut missing_tree = fixture();
        missing_tree.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap()[0].tree_leaves = None;
        assert!(compile_gemma_bkv_fixture(missing_tree).is_err());

        let mut missing_semantics = fixture();
        missing_semantics.planes.as_mut().unwrap()[0].synthetic_semantic_binding = None;
        assert!(compile_gemma_bkv_fixture(missing_semantics).is_err());

        let mut missing_roots = fixture();
        missing_roots.planes.as_mut().unwrap()[0].synthetic_root_count = None;
        assert!(compile_gemma_bkv_fixture(missing_roots).is_err());

        let mut missing_scope = fixture();
        missing_scope.events.rows.as_mut().unwrap()[0].includes_retry = None;
        assert!(compile_gemma_bkv_fixture(missing_scope).is_err());

        let mut excludes_abort = fixture();
        excludes_abort.events.rows.as_mut().unwrap()[0].includes_abort = Some(false);
        assert!(compile_gemma_bkv_fixture(excludes_abort).is_err());

        let mut excludes_retry = fixture();
        excludes_retry.events.rows.as_mut().unwrap()[0].includes_retry = Some(false);
        assert!(compile_gemma_bkv_fixture(excludes_retry).is_err());

        let mut excludes_local = fixture();
        excludes_local.events.rows.as_mut().unwrap()[0].includes_local_queries = Some(false);
        assert!(compile_gemma_bkv_fixture(excludes_local).is_err());

        let mut excludes_concurrent = fixture();
        excludes_concurrent.events.rows.as_mut().unwrap()[0].includes_concurrent_sessions =
            Some(false);
        assert!(compile_gemma_bkv_fixture(excludes_concurrent).is_err());
    }

    #[test]
    fn rejects_out_of_range_minimal_tree_and_tampered_compilation() {
        let mut too_small = fixture();
        too_small.planes.as_mut().unwrap()[0].rounds.as_mut().unwrap()[0]
            .tree_leaves
            .as_mut()
            .map(|leaves| *leaves -= 1);
        assert!(compile_gemma_bkv_fixture(too_small).is_err());

        let original = fixture();
        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.planes[0].rounds[0].h += 1;
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.events[0].denominator.push('1');
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.planes[0].synthetic_root_count = 2;
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let control = compile_gemma_bkv_fixture(original.clone()).unwrap();
        let mut compiled = control.clone();
        compiled.terminals[0].ordinal += 1;
        assert_ne!(compiled.canonical_bytes(), control.canonical_bytes());
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.events[0].includes_abort = false;
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.events[0].includes_retry = false;
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.events[0].includes_local_queries = false;
        assert!(verify_gemma_bkv_compilation(original.clone(), &compiled).is_err());

        let mut compiled = compile_gemma_bkv_fixture(original.clone()).unwrap();
        compiled.events[0].includes_concurrent_sessions = false;
        assert!(verify_gemma_bkv_compilation(original, &compiled).is_err());
    }
}

//! Runtime model geometry and public operator schedules.
//!
//! The frozen GPT-2 profile remains an implicit compatibility profile: its
//! transcript preflight is unchanged.  Every non-legacy profile binds the
//! canonical digest returned by [`ModelConfig::session_digest`].

use std::fmt;

pub const MODEL_CONFIG_SCHEMA: u32 = 1;
pub const LEGACY_GPT2_MODEL_ID: &str = "gpt2-small-t1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigBinding {
    LegacyImplicit,
    DigestV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormKind {
    LayerNorm,
    RmsNorm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationKind {
    Gelu,
    SwiGlu { clamp_min: i16, clamp_max: i16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionMode {
    FullCausal,
    Sliding { window: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterTieRule {
    /// Sort descending by `(score, expert_id)`: the larger expert id wins a
    /// tied cutoff, matching C3b's last-maximum rule.
    ScoreThenHigherExpertId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RopeConfig {
    pub rotary_dim: usize,
    pub base_num: u64,
    pub base_den: u64,
    pub frequency_scale_num: u64,
    pub frequency_scale_den: u64,
    pub coefficient_fraction_bits: u32,
    pub coefficient_table_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExpertBlockShifts {
    pub gate_up: u32,
    pub down: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonlinearTableConfig {
    pub ln_var_shift: u32,
    pub ln_rsqrt_log2: u32,
    pub exp_in_log2: u32,
    pub exp_out_log2: u32,
    pub recip_den_shift: u32,
    pub recip_log2: u32,
    pub gelu_scale_log2: u32,
    pub softmax_row_shift: bool,
}

impl Default for NonlinearTableConfig {
    fn default() -> Self {
        Self {
            ln_var_shift: 7,
            ln_rsqrt_log2: 18,
            exp_in_log2: 10,
            exp_out_log2: 12,
            recip_den_shift: 6,
            recip_log2: 26,
            gelu_scale_log2: 10,
            softmax_row_shift: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayerShiftSchedule {
    pub residual_fraction_bits: u32,
    pub layer_norm: u32,
    pub qkv: u32,
    pub scores: u32,
    pub softmax_norm: u32,
    pub av: u32,
    pub attention_out: u32,
    pub ffn_up: u32,
    pub ffn_down: u32,
    pub residual_seam: u32,
    pub router_requant: u32,
    pub router_norm: u32,
    pub expert_blocks: Vec<ExpertBlockShifts>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelConfig {
    pub schema_version: u32,
    pub model_id: String,
    pub binding: ConfigBinding,
    pub vocab_size: usize,
    pub max_positions: usize,
    pub tied_output: bool,
    pub n_layers: usize,
    pub d_model: usize,
    pub d_ff: usize,
    pub n_q_heads: usize,
    pub n_kv_heads: usize,
    pub head_dim: usize,
    pub n_experts: usize,
    pub top_k: usize,
    pub attention: Vec<AttentionMode>,
    pub norm: NormKind,
    pub activation: ActivationKind,
    pub attention_sinks_per_q_head: usize,
    pub rope: Option<RopeConfig>,
    pub nonlinear_tables: NonlinearTableConfig,
    pub embedding_shift: i32,
    pub final_norm_shift: u32,
    pub layer_shifts: Vec<LayerShiftSchedule>,
    pub thin_k: usize,
    pub router_tie_rule: RouterTieRule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl ModelConfig {
    /// Frozen GPT-2-small geometry.  Runtime shift schedules are populated by
    /// the artifact loader; the zero schedules here are sufficient for shape
    /// validation and legacy one-layer wrappers.
    pub fn gpt2_small() -> Self {
        Self {
            schema_version: MODEL_CONFIG_SCHEMA,
            model_id: LEGACY_GPT2_MODEL_ID.to_owned(),
            binding: ConfigBinding::LegacyImplicit,
            vocab_size: 50_257,
            max_positions: 1_024,
            tied_output: true,
            n_layers: 12,
            d_model: 768,
            d_ff: 3_072,
            n_q_heads: 12,
            n_kv_heads: 12,
            head_dim: 64,
            n_experts: 0,
            top_k: 0,
            attention: vec![AttentionMode::FullCausal; 12],
            norm: NormKind::LayerNorm,
            activation: ActivationKind::Gelu,
            attention_sinks_per_q_head: 0,
            rope: None,
            nonlinear_tables: NonlinearTableConfig::default(),
            embedding_shift: 0,
            final_norm_shift: 0,
            layer_shifts: vec![LayerShiftSchedule::default(); 12],
            thin_k: 4,
            router_tie_rule: RouterTieRule::ScoreThenHigherExpertId,
        }
    }

    pub fn q_dim(&self) -> usize {
        self.n_q_heads.checked_mul(self.head_dim).expect("validated q dimension")
    }

    pub fn kv_dim(&self) -> usize {
        self.n_kv_heads.checked_mul(self.head_dim).expect("validated KV dimension")
    }

    pub fn qkv_dim(&self) -> usize {
        self.q_dim()
            .checked_add(self.kv_dim().checked_mul(2).expect("validated 2*KV dimension"))
            .expect("validated QKV dimension")
    }

    pub fn gqa_group_size(&self) -> usize {
        self.n_q_heads / self.n_kv_heads
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != MODEL_CONFIG_SCHEMA {
            return Err(ConfigError::new("unsupported ModelConfig schema"));
        }
        if self.model_id.is_empty() {
            return Err(ConfigError::new("model_id must not be empty"));
        }
        for (name, value) in [
            ("vocab_size", self.vocab_size),
            ("max_positions", self.max_positions),
            ("n_layers", self.n_layers),
            ("d_model", self.d_model),
            ("d_ff", self.d_ff),
            ("n_q_heads", self.n_q_heads),
            ("n_kv_heads", self.n_kv_heads),
            ("head_dim", self.head_dim),
            ("thin_k", self.thin_k),
        ] {
            if value == 0 {
                return Err(ConfigError::new(format!("{name} must be positive")));
            }
        }
        let q_dim = self
            .n_q_heads
            .checked_mul(self.head_dim)
            .ok_or_else(|| ConfigError::new("query dimension overflow"))?;
        let kv_dim = self
            .n_kv_heads
            .checked_mul(self.head_dim)
            .ok_or_else(|| ConfigError::new("KV dimension overflow"))?;
        let qkv_dim = q_dim
            .checked_add(
                kv_dim.checked_mul(2).ok_or_else(|| ConfigError::new("QKV dimension overflow"))?,
            )
            .ok_or_else(|| ConfigError::new("QKV dimension overflow"))?;
        if q_dim != self.d_model {
            return Err(ConfigError::new("n_q_heads * head_dim must equal d_model"));
        }
        if self.n_q_heads % self.n_kv_heads != 0 {
            return Err(ConfigError::new("n_q_heads must be divisible by n_kv_heads"));
        }
        self.n_q_heads
            .checked_mul(self.attention_sinks_per_q_head)
            .ok_or_else(|| ConfigError::new("attention-sink shape overflow"))?;
        match (self.n_experts, self.top_k) {
            (0, 0) => {}
            (experts, top_k) if experts > 0 && top_k > 0 && top_k <= experts => {}
            _ => {
                return Err(ConfigError::new("dense uses 0/0; MoE requires 0 < top_k <= n_experts"))
            }
        }
        if self.attention.len() != self.n_layers || self.layer_shifts.len() != self.n_layers {
            return Err(ConfigError::new("per-layer schedules must match n_layers"));
        }
        for (rows, cols) in [
            (self.max_positions, self.d_model),
            (self.vocab_size, self.d_model),
            (self.d_model, qkv_dim),
            (q_dim, self.d_model),
            (self.d_model, self.d_ff),
            (self.d_ff, self.d_model),
        ] {
            PaddedMatrixLayout::new(rows, cols)?;
        }
        for mode in &self.attention {
            if matches!(mode, AttentionMode::Sliding { window: 0 }) {
                return Err(ConfigError::new("sliding-window size must be positive"));
            }
        }
        if let ActivationKind::SwiGlu { clamp_min, clamp_max } = self.activation {
            if clamp_min > clamp_max {
                return Err(ConfigError::new("SwiGLU clamp_min exceeds clamp_max"));
            }
        }
        if let Some(rope) = &self.rope {
            if rope.rotary_dim == 0
                || rope.rotary_dim > self.head_dim
                || rope.rotary_dim % 2 != 0
                || rope.base_den == 0
                || rope.frequency_scale_den == 0
            {
                return Err(ConfigError::new("invalid RoPE geometry or rational parameter"));
            }
        }
        let table_exponents = [
            self.nonlinear_tables.ln_var_shift,
            self.nonlinear_tables.ln_rsqrt_log2,
            self.nonlinear_tables.exp_in_log2,
            self.nonlinear_tables.exp_out_log2,
            self.nonlinear_tables.recip_den_shift,
            self.nonlinear_tables.recip_log2,
            self.nonlinear_tables.gelu_scale_log2,
        ];
        if table_exponents.into_iter().any(|shift| shift > 31)
            || !(-31..=31).contains(&self.embedding_shift)
            || self.final_norm_shift > 31
        {
            return Err(ConfigError::new("global LUT/embedding shift exceeds signed 31-bit bound"));
        }
        for (layer, shifts) in self.layer_shifts.iter().enumerate() {
            let scalars = [
                shifts.residual_fraction_bits,
                shifts.layer_norm,
                shifts.qkv,
                shifts.scores,
                shifts.softmax_norm,
                shifts.av,
                shifts.attention_out,
                shifts.ffn_up,
                shifts.ffn_down,
                shifts.residual_seam,
                shifts.router_requant,
                shifts.router_norm,
            ];
            if scalars.into_iter().any(|shift| shift > 31)
                || shifts.expert_blocks.iter().any(|shift| shift.gate_up > 31 || shift.down > 31)
            {
                return Err(ConfigError::new(format!("layer {layer} shift exceeds 31")));
            }
            if self.n_experts == 0 && !shifts.expert_blocks.is_empty() {
                return Err(ConfigError::new("dense layer has expert block shifts"));
            }
            if self.n_experts > 0 && shifts.expert_blocks.len() != self.n_experts {
                return Err(ConfigError::new(format!(
                    "layer {layer} expert shift count does not match n_experts"
                )));
            }
        }
        if self.binding == ConfigBinding::LegacyImplicit && !self.is_legacy_gpt2_geometry() {
            return Err(ConfigError::new("legacy implicit binding is reserved for frozen GPT-2"));
        }
        Ok(())
    }

    pub fn is_legacy_gpt2_geometry(&self) -> bool {
        self.model_id == LEGACY_GPT2_MODEL_ID
            && self.vocab_size == 50_257
            && self.max_positions == 1_024
            && self.tied_output
            && self.n_layers == 12
            && self.d_model == 768
            && self.d_ff == 3_072
            && self.n_q_heads == 12
            && self.n_kv_heads == 12
            && self.head_dim == 64
            && self.n_experts == 0
            && self.top_k == 0
            && self.attention.iter().all(|mode| *mode == AttentionMode::FullCausal)
            && self.norm == NormKind::LayerNorm
            && self.activation == ActivationKind::Gelu
            && self.attention_sinks_per_q_head == 0
            && self.rope.is_none()
            && self.thin_k == 4
    }

    /// Versioned, platform-independent bytes.  Integers are little-endian;
    /// vectors are length-prefixed.  No `usize` native representation enters
    /// the encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(b"VOLTA-MODEL-CONFIG\0");
        put_u32(&mut out, self.schema_version);
        put_bytes(&mut out, self.model_id.as_bytes());
        put_u8(&mut out, binding_tag(self.binding));
        put_u8(&mut out, u8::from(self.tied_output));
        for value in [
            self.vocab_size,
            self.max_positions,
            self.n_layers,
            self.d_model,
            self.d_ff,
            self.n_q_heads,
            self.n_kv_heads,
            self.head_dim,
            self.n_experts,
            self.top_k,
            self.attention_sinks_per_q_head,
            self.thin_k,
        ] {
            put_usize(&mut out, value)?;
        }
        put_u8(&mut out, norm_tag(self.norm));
        match self.activation {
            ActivationKind::Gelu => put_u8(&mut out, 0),
            ActivationKind::SwiGlu { clamp_min, clamp_max } => {
                put_u8(&mut out, 1);
                out.extend_from_slice(&clamp_min.to_le_bytes());
                out.extend_from_slice(&clamp_max.to_le_bytes());
            }
        }
        put_u8(&mut out, 0); // RouterTieRule::ScoreThenHigherExpertId
        for value in [
            self.nonlinear_tables.ln_var_shift,
            self.nonlinear_tables.ln_rsqrt_log2,
            self.nonlinear_tables.exp_in_log2,
            self.nonlinear_tables.exp_out_log2,
            self.nonlinear_tables.recip_den_shift,
            self.nonlinear_tables.recip_log2,
            self.nonlinear_tables.gelu_scale_log2,
        ] {
            put_u32(&mut out, value);
        }
        put_u8(&mut out, u8::from(self.nonlinear_tables.softmax_row_shift));
        out.extend_from_slice(&self.embedding_shift.to_le_bytes());
        put_u32(&mut out, self.final_norm_shift);
        put_usize(&mut out, self.attention.len())?;
        for mode in &self.attention {
            match mode {
                AttentionMode::FullCausal => put_u8(&mut out, 0),
                AttentionMode::Sliding { window } => {
                    put_u8(&mut out, 1);
                    put_usize(&mut out, *window)?;
                }
            }
        }
        match &self.rope {
            None => put_u8(&mut out, 0),
            Some(rope) => {
                put_u8(&mut out, 1);
                put_usize(&mut out, rope.rotary_dim)?;
                for value in [
                    rope.base_num,
                    rope.base_den,
                    rope.frequency_scale_num,
                    rope.frequency_scale_den,
                ] {
                    put_u64(&mut out, value);
                }
                put_u32(&mut out, rope.coefficient_fraction_bits);
                out.extend_from_slice(&rope.coefficient_table_digest);
            }
        }
        put_usize(&mut out, self.layer_shifts.len())?;
        for shifts in &self.layer_shifts {
            for value in [
                shifts.residual_fraction_bits,
                shifts.layer_norm,
                shifts.qkv,
                shifts.scores,
                shifts.softmax_norm,
                shifts.av,
                shifts.attention_out,
                shifts.ffn_up,
                shifts.ffn_down,
                shifts.residual_seam,
                shifts.router_requant,
                shifts.router_norm,
            ] {
                put_u32(&mut out, value);
            }
            put_usize(&mut out, shifts.expert_blocks.len())?;
            for expert in &shifts.expert_blocks {
                put_u32(&mut out, expert.gate_up);
                put_u32(&mut out, expert.down);
            }
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], ConfigError> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }

    /// Generic profiles bind this digest in their versioned preflight.  The
    /// frozen GPT-2 path returns `None`, preserving its transcript exactly.
    pub fn session_digest(&self) -> Result<Option<[u8; 32]>, ConfigError> {
        self.validate()?;
        match self.binding {
            ConfigBinding::LegacyImplicit => Ok(None),
            ConfigBinding::DigestV1 => self.digest().map(Some),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaddedMatrixLayout {
    pub rows: usize,
    pub cols: usize,
    pub row_pad: usize,
    pub col_pad: usize,
}

impl PaddedMatrixLayout {
    pub fn new(rows: usize, cols: usize) -> Result<Self, ConfigError> {
        if rows == 0 || cols == 0 {
            return Err(ConfigError::new("matrix dimensions must be positive"));
        }
        let row_pad = rows
            .checked_next_power_of_two()
            .ok_or_else(|| ConfigError::new("row padding overflow"))?;
        let col_pad = cols
            .checked_next_power_of_two()
            .ok_or_else(|| ConfigError::new("column padding overflow"))?;
        row_pad
            .checked_mul(col_pad)
            .ok_or_else(|| ConfigError::new("padded matrix length overflow"))?;
        Ok(Self { rows, cols, row_pad, col_pad })
    }

    pub fn flat(&self, row: usize, col: usize) -> Option<usize> {
        if row >= self.row_pad || col >= self.col_pad {
            return None;
        }
        row.checked_mul(self.col_pad)?.checked_add(col)
    }

    pub fn padded_len(&self) -> usize {
        self.row_pad * self.col_pad
    }

    pub fn col_bits(&self) -> usize {
        self.col_pad.ilog2() as usize
    }

    pub fn row_bits(&self) -> usize {
        self.row_pad.ilog2() as usize
    }

    /// MLE points are `r_col || r_row`: column variables are first and are
    /// the low/LSB-first variables of the row-major flattening.
    pub fn split_point<'a, T>(&self, point: &'a [T]) -> Option<(&'a [T], &'a [T])> {
        if point.len() != self.col_bits() + self.row_bits() {
            return None;
        }
        Some(point.split_at(self.col_bits()))
    }

    pub fn aligned_block_offset(&self, offset: usize) -> bool {
        offset % self.padded_len() == 0
    }
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_usize(out: &mut Vec<u8>, value: usize) -> Result<(), ConfigError> {
    let value = u64::try_from(value).map_err(|_| ConfigError::new("usize does not fit u64"))?;
    put_u64(out, value);
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u64(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn binding_tag(binding: ConfigBinding) -> u8 {
    match binding {
        ConfigBinding::LegacyImplicit => 0,
        ConfigBinding::DigestV1 => 1,
    }
}

fn norm_tag(norm: NormKind) -> u8 {
    match norm {
        NormKind::LayerNorm => 0,
        NormKind::RmsNorm => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_profile_has_no_new_session_digest() {
        let config = ModelConfig::gpt2_small();
        config.validate().unwrap();
        assert!(config.session_digest().unwrap().is_none());
    }

    #[test]
    fn generic_digest_is_deterministic_and_shape_sensitive() {
        let mut config = ModelConfig::gpt2_small();
        config.model_id = "toy-nonpow2".to_owned();
        config.binding = ConfigBinding::DigestV1;
        let digest = config.session_digest().unwrap().unwrap();
        assert_eq!(digest, config.session_digest().unwrap().unwrap());
        config.thin_k = 2;
        assert_ne!(digest, config.session_digest().unwrap().unwrap());
        let thin_digest = config.session_digest().unwrap().unwrap();
        config.nonlinear_tables.exp_out_log2 += 1;
        assert_ne!(thin_digest, config.session_digest().unwrap().unwrap());
        let table_digest = config.session_digest().unwrap().unwrap();
        config.tied_output = false;
        assert_ne!(table_digest, config.session_digest().unwrap().unwrap());
    }

    #[test]
    fn padded_layout_is_row_major_with_column_bits_first() {
        let layout = PaddedMatrixLayout::new(7, 48).unwrap();
        assert_eq!((layout.row_pad, layout.col_pad), (8, 64));
        assert_eq!(layout.flat(6, 47), Some(6 * 64 + 47));
        assert_eq!(layout.padded_len(), 512);
        assert_eq!(layout.split_point(&[0u8; 9]).map(|(c, r)| (c.len(), r.len())), Some((6, 3)));
        assert!(layout.aligned_block_offset(1024));
        assert!(!layout.aligned_block_offset(768));
    }

    #[test]
    fn legacy_binding_rejects_nonlegacy_geometry() {
        let mut config = ModelConfig::gpt2_small();
        config.d_ff = 80;
        assert!(config.validate().is_err());
    }
}

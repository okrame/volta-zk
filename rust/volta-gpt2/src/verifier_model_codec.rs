//! Canonical setup codec for the C6.1 client-side GPT-2 verifier profile.
//!
//! The encoding deliberately excludes every committed matrix and embedding.
//! All remaining vectors have frozen GPT-2-small lengths except the public
//! token sequence, whose strict cap is the model context bound.

use crate::layer::{GemmBiases, LayerWeights, D, DFF};
use crate::luts::{LutParams, Luts};
use crate::model::{Gpt2VerifierModel, P5Params, L, NPOS};
use std::fmt;

const MAGIC: &[u8] = b"VC6GVM1\0";
const TABLE_LEN: usize = 1 << 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierModelCodecError(String);

impl VerifierModelCodecError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for VerifierModelCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VerifierModelCodecError {}

type Result<T> = std::result::Result<T, VerifierModelCodecError>;

struct Writer(Vec<u8>);

impl Writer {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn i16s(&mut self, values: &[i16]) {
        for value in values {
            self.0.extend_from_slice(&value.to_le_bytes());
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| VerifierModelCodecError::new("verifier-model offset overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| VerifierModelCodecError::new("truncated verifier-model encoding"))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed width")))
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().expect("fixed width")))
    }

    fn i16s(&mut self, len: usize) -> Result<Vec<i16>> {
        self.take(
            len.checked_mul(2)
                .ok_or_else(|| VerifierModelCodecError::new("verifier-model length overflows"))?,
        )?
        .chunks_exact(2)
        .map(|bytes| Ok(i16::from_le_bytes([bytes[0], bytes[1]])))
        .collect()
    }

    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(VerifierModelCodecError::new("trailing verifier-model bytes"))
        }
    }
}

fn write_lut_params(out: &mut Writer, params: LutParams) {
    for value in [
        params.ln_var_shift,
        params.ln_rsqrt_log2,
        params.shift_ln_norm,
        params.exp_in_log2,
        params.exp_out_log2,
        params.recip_den_shift,
        params.recip_log2,
        params.gelu_scale_log2,
        params.shift_qkv,
        params.shift_scores,
        params.shift_softmax_norm,
        params.shift_av,
        params.shift_attn_proj,
        params.shift_ffn_up,
        params.shift_ffn_down,
    ] {
        out.u32(value);
    }
    out.byte(u8::from(params.softmax_row_shift));
}

fn read_lut_params(input: &mut Reader<'_>) -> Result<LutParams> {
    Ok(LutParams {
        ln_var_shift: input.u32()?,
        ln_rsqrt_log2: input.u32()?,
        shift_ln_norm: input.u32()?,
        exp_in_log2: input.u32()?,
        exp_out_log2: input.u32()?,
        recip_den_shift: input.u32()?,
        recip_log2: input.u32()?,
        gelu_scale_log2: input.u32()?,
        shift_qkv: input.u32()?,
        shift_scores: input.u32()?,
        shift_softmax_norm: input.u32()?,
        shift_av: input.u32()?,
        shift_attn_proj: input.u32()?,
        shift_ffn_up: input.u32()?,
        shift_ffn_down: input.u32()?,
        softmax_row_shift: match input.byte()? {
            0 => false,
            1 => true,
            _ => return Err(VerifierModelCodecError::new("noncanonical verifier-model Boolean")),
        },
    })
}

pub fn encode_verifier_model_canonical(model: &Gpt2VerifierModel) -> Result<Vec<u8>> {
    model.validate_layout().map_err(VerifierModelCodecError::new)?;
    let model = model.schedule_model();
    let mut out = Writer(MAGIC.to_vec());
    write_lut_params(&mut out, model.p.lut);
    for values in
        [&model.p.shift_attn_proj, &model.p.shift_ffn_down, &model.p.seam_shifts, &model.p.f_res]
    {
        for value in values {
            out.u32(*value);
        }
    }
    out.i32(model.p.shift_embed);
    out.u32(
        u32::try_from(model.p.tokens.len())
            .map_err(|_| VerifierModelCodecError::new("token count exceeds u32"))?,
    );
    for token in &model.p.tokens {
        out.u32(*token);
    }
    for table in
        [&model.luts.exp, &model.luts.gelu, &model.luts.ln_rsqrt, &model.luts.softmax_recip]
    {
        out.i16s(table);
    }
    for (weights, biases) in &model.layers {
        for values in [
            &weights.ln1_gain,
            &weights.ln1_bias,
            &weights.ln2_gain,
            &weights.ln2_bias,
            &biases.c_attn,
            &biases.attn_proj,
            &biases.ffn_up,
            &biases.ffn_down,
        ] {
            out.i16s(values);
        }
    }
    out.i16s(&model.lnf_gain);
    out.i16s(&model.lnf_bias);
    Ok(out.0)
}

pub fn decode_verifier_model_canonical(bytes: &[u8]) -> Result<Gpt2VerifierModel> {
    let mut input = Reader { bytes, offset: 0 };
    if input.take(MAGIC.len())? != MAGIC {
        return Err(VerifierModelCodecError::new("wrong verifier-model magic"));
    }
    let lut = read_lut_params(&mut input)?;
    let read_u32s = |input: &mut Reader<'_>, len: usize| -> Result<Vec<u32>> {
        (0..len).map(|_| input.u32()).collect()
    };
    let shift_attn_proj = read_u32s(&mut input, L)?;
    let shift_ffn_down = read_u32s(&mut input, L)?;
    let seam_shifts = read_u32s(&mut input, L - 1)?;
    let f_res = read_u32s(&mut input, L)?;
    let shift_embed = input.i32()?;
    let token_len = usize::try_from(input.u32()?).expect("u32 fits usize");
    if token_len > NPOS {
        return Err(VerifierModelCodecError::new("token count exceeds context bound"));
    }
    let tokens = read_u32s(&mut input, token_len)?;
    let luts = Luts {
        params: lut,
        exp: input.i16s(TABLE_LEN)?,
        gelu: input.i16s(TABLE_LEN)?,
        ln_rsqrt: input.i16s(TABLE_LEN)?,
        softmax_recip: input.i16s(TABLE_LEN)?,
    };
    let mut layers = Vec::with_capacity(L);
    for _ in 0..L {
        layers.push((
            LayerWeights {
                c_attn: Vec::new(),
                attn_proj: Vec::new(),
                ffn_up: Vec::new(),
                ffn_down: Vec::new(),
                ln1_gain: input.i16s(D)?,
                ln1_bias: input.i16s(D)?,
                ln2_gain: input.i16s(D)?,
                ln2_bias: input.i16s(D)?,
            },
            GemmBiases {
                c_attn: input.i16s(3 * D)?,
                attn_proj: input.i16s(D)?,
                ffn_up: input.i16s(DFF)?,
                ffn_down: input.i16s(D)?,
            },
        ));
    }
    let lnf_gain = input.i16s(D)?;
    let lnf_bias = input.i16s(D)?;
    input.finish()?;
    let p =
        P5Params { lut, shift_attn_proj, shift_ffn_down, seam_shifts, shift_embed, f_res, tokens };
    let model = Gpt2VerifierModel::from_redacted_parts(p, luts, layers, lnf_gain, lnf_bias)
        .map_err(VerifierModelCodecError::new)?;
    if encode_verifier_model_canonical(&model)? != bytes {
        return Err(VerifierModelCodecError::new("noncanonical verifier-model encoding"));
    }
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_model, Gpt2VerifierModel};
    use std::path::PathBuf;

    fn weights_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    #[test]
    fn frozen_verifier_model_codec_is_strict_and_excludes_weights() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping verifier codec check: frozen artifact not present");
            return;
        }
        let profile = Gpt2VerifierModel::from_model(&load_model(&dir).unwrap()).unwrap();
        let bytes = encode_verifier_model_canonical(&profile).unwrap();
        assert!(bytes.len() < 1_000_000);
        let decoded = decode_verifier_model_canonical(&bytes).unwrap();
        assert_eq!(encode_verifier_model_canonical(&decoded).unwrap(), bytes);
        assert!(decoded.schedule_model().layers.iter().all(|(weights, _)| {
            weights.c_attn.is_empty()
                && weights.attn_proj.is_empty()
                && weights.ffn_up.is_empty()
                && weights.ffn_down.is_empty()
        }));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_verifier_model_canonical(&trailing).is_err());
        assert!(decode_verifier_model_canonical(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_verifier_model_canonical(b"wrong").is_err());

        let mut bad_bool = bytes.clone();
        bad_bool[MAGIC.len() + 15 * 4] = 2;
        assert!(decode_verifier_model_canonical(&bad_bool).is_err());

        let mut too_many_tokens = bytes;
        let token_len_offset = MAGIC.len() + 15 * 4 + 1 + (L + L + (L - 1) + L) * 4 + 4;
        too_many_tokens[token_len_offset..token_len_offset + 4]
            .copy_from_slice(&u32::try_from(NPOS + 1).unwrap().to_le_bytes());
        assert!(decode_verifier_model_canonical(&too_many_tokens).is_err());
    }
}

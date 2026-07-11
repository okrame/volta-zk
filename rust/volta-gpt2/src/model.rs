//! P5 full-model witness generator + frozen-artifact loader.
//!
//! Loads the quantized GPT-2 small artifact produced by
//! `scripts/export_gpt2.py` (`gpt2s-q.bin` raw LE i16 tensors in the frozen
//! LAYER_TENSORS order + wte/wpe/ln_f + the 4 frozen LUTs; `gpt2s-q.params`
//! flat i32 sidecar, magic "VGPT2Q2\0") and runs the fixed-point forward for
//! the whole model: embed → 12 layers (per-layer residual shifts, seam
//! requants) → final LN on the last row → i64 logits (tied wte, no requant).
//! Bit-for-bit mirror of `scripts/gpt2_fixed.py::forward_model` per
//! docs/quantization-spec.md §P5.

use std::path::Path;

use rayon::prelude::*;
use volta_accel::{AccelError, Backend, BackendKind, Operation};

use crate::layer::{
    forward_layer_with_backend, layer_norm, requant_into, GemmBiases, LayerWeights, LayerWitness,
    LookupTrace, D, DFF,
};
use crate::luts::{LutParams, Luts};

pub const L: usize = 12;
pub const VOCAB: usize = 50257;
pub const NPOS: usize = 1024;

// ---------------------------------------------------------------------------
// Params sidecar
// ---------------------------------------------------------------------------

/// Calibrated parameters of the frozen artifact. `lut` carries the global
/// scalars (its `shift_attn_proj`/`shift_ffn_down` are overwritten per layer
/// from the arrays below; `softmax_row_shift` is always true for P5).
#[derive(Clone, Debug)]
pub struct P5Params {
    pub lut: LutParams,
    pub shift_attn_proj: [u32; L],
    pub shift_ffn_down: [u32; L],
    pub seam_shifts: [u32; L - 1],
    /// May be ≤ 0: a non-positive value is a LEFT shift by −s (exact,
    /// linear, no lookup).
    pub shift_embed: i32,
    pub f_res: [u32; L],
    pub tokens: Vec<u32>,
}

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn i32(&mut self) -> i32 {
        let v = i32::from_le_bytes(self.b[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }
    fn u32(&mut self) -> u32 {
        self.i32() as u32
    }
}

fn parse_params(bytes: &[u8]) -> P5Params {
    assert_eq!(&bytes[..8], b"VGPT2Q2\0", "bad gpt2s-q.params magic");
    let mut r = Rd { b: bytes, pos: 8 };
    // Scalars, exactly export_gpt2.py::PARAMS_ORDER.
    let ln_var_shift = r.u32();
    let ln_rsqrt_log2 = r.u32();
    let shift_ln_norm = r.u32();
    let exp_in_log2 = r.u32();
    let exp_out_log2 = r.u32();
    let recip_den_shift = r.u32();
    let recip_log2 = r.u32();
    let gelu_scale_log2 = r.u32();
    let shift_qkv = r.u32();
    let shift_scores = r.u32();
    let shift_softmax_norm = r.u32();
    let shift_av = r.u32();
    let shift_ffn_up = r.u32();
    let shift_embed = r.i32();
    for _ in 0..12 {
        r.i32(); // f_ln..f_ln_gain (8) + fw_* (4) — in the JSON, unused here
    }
    // Arrays, exactly export_gpt2.py::ARRAYS_ORDER.
    let mut f_res = [0u32; L];
    let mut shift_attn_proj = [0u32; L];
    let mut shift_ffn_down = [0u32; L];
    let mut seam_shifts = [0u32; L - 1];
    for v in f_res.iter_mut() {
        *v = r.u32();
    }
    for v in shift_attn_proj.iter_mut() {
        *v = r.u32();
    }
    for v in shift_ffn_down.iter_mut() {
        *v = r.u32();
    }
    for v in seam_shifts.iter_mut() {
        *v = r.u32();
    }
    let n_tok = r.u32() as usize;
    let tokens: Vec<u32> = (0..n_tok).map(|_| r.u32()).collect();
    assert_eq!(r.pos, bytes.len(), "trailing bytes in gpt2s-q.params");

    let lut = LutParams {
        ln_var_shift,
        ln_rsqrt_log2,
        shift_ln_norm,
        exp_in_log2,
        exp_out_log2,
        recip_den_shift,
        recip_log2,
        gelu_scale_log2,
        shift_qkv,
        shift_scores,
        shift_softmax_norm,
        shift_av,
        shift_attn_proj: shift_attn_proj[0], // per-layer override at use site
        shift_ffn_up,
        shift_ffn_down: shift_ffn_down[0],
        softmax_row_shift: true,
    };
    P5Params { lut, shift_attn_proj, shift_ffn_down, seam_shifts, shift_embed, f_res, tokens }
}

// ---------------------------------------------------------------------------
// Weight blob
// ---------------------------------------------------------------------------

pub struct Gpt2Model {
    pub p: P5Params,
    pub luts: Luts,
    pub layers: Vec<(LayerWeights, GemmBiases)>,
    pub wte: Vec<i16>, // VOCAB × d (tied: embedding + logits weight)
    pub wpe: Vec<i16>, // NPOS × d
    pub lnf_gain: Vec<i16>,
    pub lnf_bias: Vec<i16>,
}

/// Loads `gpt2s-q.{bin,params}` from `dir` (see module docs for the frozen
/// layout — any layout change must bump the magic in export_gpt2.py).
pub fn load_model(dir: &Path) -> std::io::Result<Gpt2Model> {
    let p = parse_params(&std::fs::read(dir.join("gpt2s-q.params"))?);
    let blob = std::fs::read(dir.join("gpt2s-q.bin"))?;
    assert_eq!(blob.len() % 2, 0);

    let mut pos = 0usize;
    let mut take = |n: usize| -> Vec<i16> {
        let out: Vec<i16> = blob[pos..pos + 2 * n]
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        pos += 2 * n;
        out
    };

    let mut layers = Vec::with_capacity(L);
    for _ in 0..L {
        // Order = export_gpt2.py::LAYER_TENSORS, frozen.
        let c_attn = take(D * 3 * D);
        let c_attn_bias = take(3 * D);
        let attn_proj = take(D * D);
        let attn_proj_bias = take(D);
        let ffn_up = take(D * DFF);
        let ffn_up_bias = take(DFF);
        let ffn_down = take(DFF * D);
        let ffn_down_bias = take(D);
        let ln1_gain = take(D);
        let ln1_bias = take(D);
        let ln2_gain = take(D);
        let ln2_bias = take(D);
        layers.push((
            LayerWeights {
                c_attn,
                attn_proj,
                ffn_up,
                ffn_down,
                ln1_gain,
                ln1_bias,
                ln2_gain,
                ln2_bias,
            },
            GemmBiases {
                c_attn: c_attn_bias,
                attn_proj: attn_proj_bias,
                ffn_up: ffn_up_bias,
                ffn_down: ffn_down_bias,
            },
        ));
    }
    let wte = take(VOCAB * D);
    let wpe = take(NPOS * D);
    let lnf_gain = take(D);
    let lnf_bias = take(D);
    let exp = take(1 << 16);
    let gelu = take(1 << 16);
    let ln_rsqrt = take(1 << 16);
    let softmax_recip = take(1 << 16);
    assert_eq!(pos, blob.len(), "trailing bytes in gpt2s-q.bin");

    let luts = Luts { params: p.lut, exp, gelu, ln_rsqrt, softmax_recip };
    Ok(Gpt2Model { p, luts, layers, wte, wpe, lnf_gain, lnf_bias })
}

// ---------------------------------------------------------------------------
// Full-model witness
// ---------------------------------------------------------------------------

/// Embedding witness: `acc = wte[tok] + wpe[pos]` (T×d, i64), requantized to
/// the segment-0 residual scale. `trace` is None for `shift_embed ≤ 0`
/// (exact left shift — linear, no lookup).
#[derive(Debug, PartialEq, Eq)]
pub struct EmbedWitness {
    pub acc: Vec<i64>,
    pub out: Vec<i16>,
    pub trace: Option<LookupTrace>,
}

/// Final-LN witness (last position only) + its two lookup traces (the tables
/// are the shared ln_rsqrt / ln_norm_requant).
#[derive(Debug, PartialEq, Eq)]
pub struct FinalLnWitness {
    pub mean: i64,
    pub var: i64,
    pub rsqrt_in: i64,
    pub rsqrt_out: i16,
    pub out: Vec<i16>, // d
    pub rsqrt_trace: LookupTrace,
    pub norm_trace: LookupTrace,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ModelWitness {
    pub t: usize,
    pub embed: EmbedWitness,
    pub layers: Vec<LayerWitness>,
    /// Seam requant traces: index l is the seam between layer l and l+1;
    /// None when the seam shift is 0 (identity, free).
    pub seams: Vec<Option<LookupTrace>>,
    pub final_ln: FinalLnWitness,
    /// Last-position logits: i64 accumulators over the tied wte, NO requant
    /// (spec §P5 embedding requant).
    pub logits: Vec<i64>,
}

/// Fixed-point forward of the whole model on the first `t` prompt tokens.
pub fn forward_model(m: &Gpt2Model, t: usize) -> ModelWitness {
    let mut backend = Backend::cpu();
    forward_model_with_backend(m, t, &mut backend).expect("CPU backend is infallible")
}

pub fn forward_model_with_backend(
    m: &Gpt2Model,
    t: usize,
    backend: &mut Backend,
) -> Result<ModelWitness, AccelError> {
    assert!(t <= m.p.tokens.len());
    forward_model_tokens_with_backend(m, &m.p.tokens[..t], backend)
}

/// [`forward_model`] on an EXPLICIT token sequence (P6: prompt + generated
/// tokens — the fixed-point forward is causal, so the first `t0` rows are
/// bit-identical to the prefill run's).
pub fn forward_model_tokens(m: &Gpt2Model, tokens: &[u32]) -> ModelWitness {
    let mut backend = Backend::cpu();
    forward_model_tokens_with_backend(m, tokens, &mut backend).expect("CPU backend is infallible")
}

pub fn forward_model_tokens_with_backend(
    m: &Gpt2Model,
    tokens: &[u32],
    backend: &mut Backend,
) -> Result<ModelWitness, AccelError> {
    if backend.kind() == BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "cuda-resident requires the device-witness API; staged ModelWitness materialization is forbidden",
        ));
    }
    let t = tokens.len();
    assert!(t <= NPOS);

    // ---- embedding ----
    let embed = backend.cpu_residual(Operation::Gemm, || {
        let mut acc = vec![0i64; t * D];
        for (i, &tok) in tokens.iter().enumerate() {
            let wt = &m.wte[tok as usize * D..(tok as usize + 1) * D];
            let wp = &m.wpe[i * D..(i + 1) * D];
            for j in 0..D {
                acc[i * D + j] = wt[j] as i64 + wp[j] as i64;
            }
        }
        let s_emb = m.p.shift_embed;
        let (out, trace) = if s_emb > 0 {
            let mut tr = LookupTrace::new_requant(s_emb as u32);
            let out = acc
                .iter()
                .map(|&a| requant_into(&mut tr, "requant_embed", a, s_emb as u32))
                .collect();
            (out, Some(tr))
        } else {
            let out = acc
                .iter()
                .map(|&a| {
                    let v = a << (-s_emb) as u32;
                    assert!(
                        (i16::MIN as i64..=i16::MAX as i64).contains(&v),
                        "embed left shift overflows i16"
                    );
                    v as i16
                })
                .collect();
            (out, None)
        };
        EmbedWitness { acc, out, trace }
    })?;

    // ---- layers + seams ----
    let mut layers = Vec::with_capacity(L);
    let mut seams: Vec<Option<LookupTrace>> = Vec::with_capacity(L - 1);
    let mut x = embed.out.clone();
    for l in 0..L {
        let mut params = m.p.lut;
        params.shift_attn_proj = m.p.shift_attn_proj[l];
        params.shift_ffn_down = m.p.shift_ffn_down[l];
        let (w, b) = &m.layers[l];
        let wit = forward_layer_with_backend(&x, w, Some(b), &m.luts, params, t, backend)?;
        x = wit.ffn_block_out.clone();
        layers.push(wit);
        if l < L - 1 {
            let s = m.p.seam_shifts[l];
            if s > 0 {
                let (next, tr) = backend.cpu_residual(Operation::Gemm, || {
                    let mut tr = LookupTrace::new_requant(s);
                    let next = x
                        .iter()
                        .map(|&v| requant_into(&mut tr, "seam_requant", v as i64, s))
                        .collect();
                    (next, tr)
                })?;
                x = next;
                seams.push(Some(tr));
            } else {
                seams.push(None);
            }
        }
    }

    // ---- final LN (last row) ----
    let final_ln = backend.cpu_residual(Operation::Gemm, || {
        let last = &x[(t - 1) * D..t * D];
        let mut rsqrt_trace = LookupTrace::new(1 << 16);
        let mut norm_trace = LookupTrace::new_requant(m.p.lut.shift_ln_norm);
        let ln = layer_norm(
            last,
            &m.lnf_gain,
            &m.lnf_bias,
            &m.luts,
            1,
            &mut rsqrt_trace,
            &mut norm_trace,
        );
        FinalLnWitness {
            mean: ln.mean[0],
            var: ln.var[0],
            rsqrt_in: ln.rsqrt_in[0],
            rsqrt_out: ln.rsqrt_out[0],
            out: ln.out,
            rsqrt_trace,
            norm_trace,
        }
    })?;

    // ---- logits (tied wte, i64 accumulators, no requant) ----
    let logits = backend.cpu_residual(Operation::Gemm, || {
        let fin = &final_ln.out;
        (0..VOCAB)
            .into_par_iter()
            .map(|v| {
                let row = &m.wte[v * D..(v + 1) * D];
                let mut s = 0i64;
                for j in 0..D {
                    s += fin[j] as i64 * row[j] as i64;
                }
                s
            })
            .collect::<Vec<i64>>()
    })?;

    Ok(ModelWitness { t, embed, layers, seams, final_ln, logits })
}

// ---------------------------------------------------------------------------
// Golden test (skipped when the frozen artifact is not present)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn weights_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    /// Bit-exactness against scripts/dump_golden.py (numpy reference on the
    /// SAME frozen artifact): full logits vector + tensor checksums.
    #[test]
    fn golden_check_t100() {
        let dir = weights_dir();
        let golden_path = dir.join("golden-p5.bin");
        if !golden_path.exists() || !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping golden_check_t100: frozen artifact not present");
            return;
        }
        let g = std::fs::read(golden_path).unwrap();
        assert_eq!(&g[..8], b"VGOLD1\0\0");
        let rd_u32 = |o: usize| u32::from_le_bytes(g[o..o + 4].try_into().unwrap());
        let rd_i64 = |o: usize| i64::from_le_bytes(g[o..o + 8].try_into().unwrap());
        let t = rd_u32(8) as usize;
        let argmax = rd_u32(12) as usize;
        let mut off = 16;
        let logits_ref: Vec<i64> = (0..VOCAB).map(|i| rd_i64(off + 8 * i)).collect();
        off += 8 * VOCAB;
        let embed_sum = rd_i64(off);
        let finln_sum = rd_i64(off + 8);
        off += 16;
        let ffn_sums: Vec<i64> = (0..L).map(|i| rd_i64(off + 8 * i)).collect();
        off += 8 * L;
        let row_shift_sums: Vec<i64> = (0..L).map(|i| rd_i64(off + 8 * i)).collect();
        assert_eq!(off + 8 * L, g.len());

        let m = load_model(&dir).unwrap();
        let wit = forward_model(&m, t);

        assert_eq!(wit.logits, logits_ref, "logits mismatch vs numpy reference");
        let am = (0..VOCAB).max_by_key(|&v| wit.logits[v]).unwrap();
        assert_eq!(am, argmax);
        let sum_i16 = |v: &[i16]| v.iter().map(|&x| x as i64).sum::<i64>();
        assert_eq!(sum_i16(&wit.embed.out), embed_sum, "embed_out checksum");
        assert_eq!(sum_i16(&wit.final_ln.out), finln_sum, "final_ln checksum");
        for l in 0..L {
            assert_eq!(sum_i16(&wit.layers[l].ffn_block_out), ffn_sums[l], "ffn_block_out l={l}");
            assert_eq!(sum_i16(&wit.layers[l].row_shift), row_shift_sums[l], "row_shift l={l}");
        }
    }
}

//! P6 band witness: the decode chunk's slice of a full causal forward.
//!
//! The fixed-point forward is causal, so the witness of the response's rows
//! `t0..T` is a SLICE of `forward_model_tokens` at the full length T — no
//! separate decode-mode witness generator is needed (the KV-cached
//! `decode` module is the native baseline, asserted bit-exact against the
//! same full forward). Row-local tensors slice directly; the causal-packed
//! attention wires repack to band windows `t0+i+1`; the band's final LN +
//! logits (needed at EVERY decode position — each sampled token must be
//! checkable) are computed here since the full forward only materializes the
//! last row's.

use crate::layer::{layer_norm, LayerWitness, LookupTrace};
use crate::model::{layer_lut_params, Gpt2Model, ModelWitness};
use rayon::prelude::*;

/// Band (decode-chunk) witness of the whole model: rows `t0..t0+q` of the
/// full response forward.
pub struct BandModelWitness {
    pub t0: usize,
    pub q: usize,
    /// Band-packed per-layer witnesses: `t = q`, attention windows
    /// `t0+i+1`, `k`/`v` = the band's NEW cache rows only.
    pub layers: Vec<LayerWitness>,
    /// Band rows of the embedding: acc/out (q×D).
    pub embed_acc: Vec<i64>,
    pub embed_out: Vec<i16>,
    /// Final LN over ALL band rows of the last layer's output (q rows).
    pub fin_mean: Vec<i64>,
    pub fin_var: Vec<i64>,
    pub fin_rsqrt_in: Vec<i64>,
    pub fin_rsqrt_out: Vec<i16>,
    pub fin_acc: Vec<i64>,
    pub fin_out: Vec<i16>, // q×D
    /// Band logits (q×VOCAB, i64 accumulators over the tied wte): PUBLIC
    /// response output — row r (position t0+r) samples the token at t0+r+1.
    pub logits: Vec<i64>,
}

fn slice_rows_i16(x: &[i16], t0: usize, t: usize, width: usize) -> Vec<i16> {
    x[t0 * width..t * width].to_vec()
}

fn slice_rows_i64(x: &[i64], t0: usize, t: usize, width: usize) -> Vec<i64> {
    x[t0 * width..t * width].to_vec()
}

fn tri(x: usize) -> usize {
    x * (x + 1) / 2
}

/// Repack a causal-packed per-head field (full windows `i+1`) into the band
/// packing (rows `t0..t`, same windows — i.e. band row r has window
/// `t0+r+1`).
fn repack<T: Copy>(full: &[T], t0: usize, t: usize, heads: usize) -> Vec<T> {
    let caus_full = tri(t);
    let per_head = caus_full - tri(t0);
    let mut out = Vec::with_capacity(heads * per_head);
    for h in 0..heads {
        out.extend_from_slice(&full[h * caus_full + tri(t0)..(h) * caus_full + caus_full]);
    }
    out
}

/// Slice an h×T row table to h×q (band rows).
fn slice_row_table<T: Copy>(full: &[T], t0: usize, t: usize, heads: usize) -> Vec<T> {
    let q = t - t0;
    let mut out = Vec::with_capacity(heads * q);
    for h in 0..heads {
        out.extend_from_slice(&full[h * t + t0..h * t + t]);
    }
    out
}

/// Extract the band witness (rows `t0..full.t`) from a full-response
/// forward. `full = forward_model_tokens(m, seq)` with `seq.len() > t0`.
pub fn band_model_witness(m: &Gpt2Model, full: &ModelWitness, t0: usize) -> BandModelWitness {
    m.validate_layout().expect("model/config preflight failed");
    let config = &m.config;
    let d = config.d_model;
    let dff = config.d_ff;
    let q_dim = config.q_dim();
    let kv_dim = config.kv_dim();
    let qkv_dim = config.qkv_dim();
    let heads = config.n_q_heads;
    let vocab = config.vocab_size;
    let t = full.t;
    assert!(t0 > 0 && t0 < t, "band must be a proper suffix");
    let q = t - t0;

    assert_eq!(full.layers.len(), config.n_layers);
    let layers = (0..config.n_layers)
        .map(|l| {
            let lw = &full.layers[l];
            let params = layer_lut_params(m.luts.params, &config.layer_shifts[l]);
            // Traces are unused by the prover (accumulators are recomputed
            // from boundaries + stats); keep well-shaped empty ones.
            let traces: [LookupTrace; 12] = [
                LookupTrace::new(1 << 16),
                LookupTrace::new_requant(params.shift_ln_norm),
                LookupTrace::new_requant(params.shift_qkv),
                LookupTrace::new_requant(params.shift_scores),
                LookupTrace::new(1 << 16),
                LookupTrace::new(1 << 16),
                LookupTrace::new_requant(params.shift_softmax_norm),
                LookupTrace::new_requant(params.shift_av),
                LookupTrace::new_requant(params.shift_attn_proj),
                LookupTrace::new_requant(params.shift_ffn_up),
                LookupTrace::new(1 << 16),
                LookupTrace::new_requant(params.shift_ffn_down),
            ];
            LayerWitness {
                t: q,
                x_in: slice_rows_i16(&lw.x_in, t0, t, d),
                k: slice_rows_i16(&lw.k, t0, t, kv_dim),
                v: slice_rows_i16(&lw.v, t0, t, kv_dim),
                attn_block_out: slice_rows_i16(&lw.attn_block_out, t0, t, d),
                ffn_block_out: slice_rows_i16(&lw.ffn_block_out, t0, t, d),
                ln1_mean: lw.ln1_mean[t0..t].to_vec(),
                ln1_var: lw.ln1_var[t0..t].to_vec(),
                ln1_rsqrt_in: lw.ln1_rsqrt_in[t0..t].to_vec(),
                ln1_rsqrt_out: lw.ln1_rsqrt_out[t0..t].to_vec(),
                ln1_acc: slice_rows_i64(&lw.ln1_acc, t0, t, d),
                ln1_out: slice_rows_i16(&lw.ln1_out, t0, t, d),
                qkv_acc: lw.qkv_acc[t0 * qkv_dim..t * qkv_dim].to_vec(),
                q: slice_rows_i16(&lw.q, t0, t, q_dim),
                scores_acc: repack(&lw.scores_acc, t0, t, heads),
                scores_q: repack(&lw.scores_q, t0, t, heads),
                row_shift: slice_row_table(&lw.row_shift, t0, t, heads),
                exp_out: repack(&lw.exp_out, t0, t, heads),
                denoms: slice_row_table(&lw.denoms, t0, t, heads),
                recips: slice_row_table(&lw.recips, t0, t, heads),
                softmax_w: repack(&lw.softmax_w, t0, t, heads),
                av_acc: slice_rows_i64(&lw.av_acc, t0, t, q_dim),
                av_q: slice_rows_i16(&lw.av_q, t0, t, q_dim),
                proj_acc: slice_rows_i64(&lw.proj_acc, t0, t, d),
                attn_proj_q: slice_rows_i16(&lw.attn_proj_q, t0, t, d),
                ln2_mean: lw.ln2_mean[t0..t].to_vec(),
                ln2_var: lw.ln2_var[t0..t].to_vec(),
                ln2_rsqrt_in: lw.ln2_rsqrt_in[t0..t].to_vec(),
                ln2_rsqrt_out: lw.ln2_rsqrt_out[t0..t].to_vec(),
                ln2_acc: slice_rows_i64(&lw.ln2_acc, t0, t, d),
                ln2_out: slice_rows_i16(&lw.ln2_out, t0, t, d),
                ffn_up_acc: lw.ffn_up_acc[t0 * dff..t * dff].to_vec(),
                ffn_up_q: lw.ffn_up_q[t0 * dff..t * dff].to_vec(),
                gelu_out: lw.gelu_out[t0 * dff..t * dff].to_vec(),
                ffn_down_acc: slice_rows_i64(&lw.ffn_down_acc, t0, t, d),
                ffn_down_q: slice_rows_i16(&lw.ffn_down_q, t0, t, d),
                traces,
            }
        })
        .collect();

    // Final LN over every band row of the last layer's output.
    let x_fin = slice_rows_i16(&full.layers[config.n_layers - 1].ffn_block_out, t0, t, d);
    let mut rsqrt_trace = LookupTrace::new(1 << 16);
    let mut norm_trace = LookupTrace::new_requant(config.final_norm_shift);
    let mut final_params = m.luts.params;
    final_params.shift_ln_norm = config.final_norm_shift;
    let ln = layer_norm(
        &x_fin,
        &m.lnf_gain,
        &m.lnf_bias,
        &m.luts,
        final_params,
        q,
        &mut rsqrt_trace,
        &mut norm_trace,
    );

    // Band logits (q×VOCAB): fin_out · wteᵀ, i64, no requant.
    let fin = &ln.out;
    let logits: Vec<i64> = (0..q * vocab)
        .into_par_iter()
        .map(|idx| {
            let (r, v) = (idx / vocab, idx % vocab);
            let row = &m.output_weights()[v * d..(v + 1) * d];
            let f = &fin[r * d..(r + 1) * d];
            let mut s = 0i64;
            for j in 0..d {
                s += f[j] as i64 * row[j] as i64;
            }
            s
        })
        .collect();

    BandModelWitness {
        t0,
        q,
        layers,
        embed_acc: slice_rows_i64(&full.embed.acc, t0, t, d),
        embed_out: slice_rows_i16(&full.embed.out, t0, t, d),
        fin_mean: ln.mean,
        fin_var: ln.var,
        fin_rsqrt_in: ln.rsqrt_in,
        fin_rsqrt_out: ln.rsqrt_out,
        fin_acc: ln.acc,
        fin_out: ln.out,
        logits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{forward_model_tokens, load_model};
    use crate::{D, H, VOCAB};

    /// Band slicing invariants + the band logits' last row must equal the
    /// full forward's last-position logits.
    #[test]
    fn band_extraction_consistency() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping band_extraction_consistency: artifact not present");
            return;
        }
        let m = load_model(&dir).unwrap();
        let seq: Vec<u32> = m.p.tokens[..14].to_vec();
        let full = forward_model_tokens(&m, &seq);
        let band = band_model_witness(&m, &full, 10);
        assert_eq!(band.q, 4);
        // Packed windows: band row r of head h has t0+r+1 entries.
        let caus_band: usize = (0..band.q).map(|r| band.t0 + r + 1).sum();
        assert_eq!(band.layers[0].scores_q.len(), H * caus_band);
        // Band logits last row == full last-position logits.
        assert_eq!(&band.logits[(band.q - 1) * VOCAB..], &full.logits[..]);
        // Band fin_out last row == full final_ln.out.
        assert_eq!(&band.fin_out[(band.q - 1) * D..], &full.final_ln.out[..]);
    }
}

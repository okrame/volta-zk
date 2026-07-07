//! P6 native decode: incremental KV-cached forward (one row per step) and
//! greedy autoregressive generation.
//!
//! Bit-exact with `forward_model` restricted to the new row (the fixed-point
//! forward is causal and row-local outside attention, so the prefix values
//! never change as the sequence grows — asserted by the tests). This is the
//! NATIVE decode baseline for ρ_decode: no lookup traces, no witness
//! bookkeeping — just the O(seq·d) per-token work.

use crate::layer::{GemmBiases, LayerWeights, D, DFF, DH, H};
use crate::model::{Gpt2Model, L, NPOS, VOCAB};
use rayon::prelude::*;

/// Traceless mirror of `layer::requant_into` (round-half-up, double-round
/// chained semantics for shift > 16, no-clamp assertion).
#[inline]
pub fn requant_plain(acc: i64, shift: u32) -> i16 {
    let (stage2_in, s2) = if shift <= 16 {
        (acc, shift)
    } else {
        let s1 = shift - 16;
        ((acc + (1i64 << (s1 - 1))) >> s1, 16)
    };
    let rounded = (stage2_in + (1i64 << (s2 - 1))) >> s2;
    assert!(
        (i16::MIN as i64..=i16::MAX as i64).contains(&rounded),
        "requant saturated in decode (no-clamp deviation violated): acc={acc}, shift={shift}",
    );
    rounded as i16
}

/// One row's LayerNorm (mirror of `layer::layer_norm` at t = 1, traceless).
fn ln_row(x: &[i16], gain: &[i16], bias: &[i16], m: &Gpt2Model) -> Vec<i16> {
    let p = &m.luts.params;
    let d = D as i64;
    let sum: i64 = x.iter().map(|&v| v as i64).sum();
    let mean = (sum + d / 2).div_euclid(d);
    let var_sum: i64 = x.iter().map(|&v| (v as i64 - mean) * (v as i64 - mean)).sum();
    let var = (var_sum + d / 2).div_euclid(d);
    let vin = var >> p.ln_var_shift;
    assert!(vin < 1 << 16, "ln_rsqrt input exceeds u16 domain");
    let r = m.luts.ln_rsqrt[vin as usize];
    (0..D)
        .map(|j| {
            let acc = (x[j] as i64 - mean) * r as i64 * gain[j] as i64
                + ((bias[j] as i64) << p.shift_ln_norm);
            requant_plain(acc, p.shift_ln_norm)
        })
        .collect()
}

/// Row × (in_dim×out_dim) matvec with the bias folded at the output scale.
fn row_gemm(x: &[i16], w: &[i16], out_dim: usize, bias: Option<&[i16]>, shift: u32) -> Vec<i64> {
    let in_dim = x.len();
    let mut acc: Vec<i64> = (0..out_dim)
        .into_par_iter()
        .map(|j| {
            let mut s = 0i64;
            for (i, &xv) in x.iter().enumerate() {
                s += xv as i64 * w[i * out_dim + j] as i64;
            }
            debug_assert_eq!(w.len(), in_dim * out_dim);
            s
        })
        .collect();
    if let Some(b) = bias {
        for (a, &bv) in acc.iter_mut().zip(b) {
            *a += (bv as i64) << shift;
        }
    }
    acc
}

/// Per-layer append-only KV cache (rows are positions).
pub struct KvCache {
    /// `k[l]` / `v[l]`: seq×D, growing one row per step.
    pub k: Vec<Vec<i16>>,
    pub v: Vec<Vec<i16>>,
    /// Positions currently cached.
    pub len: usize,
}

impl KvCache {
    /// Seed the cache from a prefill's per-layer K/V boundary tensors.
    pub fn from_prefill(layers_kv: &[(&[i16], &[i16])], t0: usize) -> KvCache {
        assert_eq!(layers_kv.len(), L);
        let k = layers_kv.iter().map(|(k, _)| k.to_vec()).collect::<Vec<_>>();
        let v = layers_kv.iter().map(|(_, v)| v.to_vec()).collect::<Vec<_>>();
        for l in 0..L {
            assert_eq!(k[l].len(), t0 * D);
            assert_eq!(v[l].len(), t0 * D);
        }
        KvCache { k, v, len: t0 }
    }
}

/// One decode step at position `pos` (== cache.len): runs the full stack on
/// the single new row, appends the row's K/V to the cache, and returns the
/// logits row (i64 accumulators over the tied wte, mirror of
/// `forward_model`'s last-position logits).
pub fn decode_step(m: &Gpt2Model, cache: &mut KvCache, token: u32, pos: usize) -> Vec<i64> {
    assert!(pos == cache.len && pos < NPOS);
    let p = m.p.lut;

    // ---- embedding row ----
    let tok = token as usize;
    let mut acc_e = vec![0i64; D];
    for j in 0..D {
        acc_e[j] = m.wte[tok * D + j] as i64 + m.wpe[pos * D + j] as i64;
    }
    let s_emb = m.p.shift_embed;
    let mut x: Vec<i16> = if s_emb > 0 {
        acc_e.iter().map(|&a| requant_plain(a, s_emb as u32)).collect()
    } else {
        acc_e
            .iter()
            .map(|&a| {
                let v = a << (-s_emb) as u32;
                assert!((i16::MIN as i64..=i16::MAX as i64).contains(&v));
                v as i16
            })
            .collect()
    };

    // ---- layers ----
    for l in 0..L {
        let (w, b): (&LayerWeights, &GemmBiases) = (&m.layers[l].0, &m.layers[l].1);
        let s_ap = m.p.shift_attn_proj[l];
        let s_fd = m.p.shift_ffn_down[l];

        // LN1 + qkv row.
        let ln1 = ln_row(&x, &w.ln1_gain, &w.ln1_bias, m);
        let qkv_acc = row_gemm(&ln1, &w.c_attn, 3 * D, Some(&b.c_attn), p.shift_qkv);
        let qkv: Vec<i16> = qkv_acc.iter().map(|&a| requant_plain(a, p.shift_qkv)).collect();
        let (q_row, rest) = qkv.split_at(D);
        let (k_row, v_row) = rest.split_at(D);
        cache.k[l].extend_from_slice(k_row);
        cache.v[l].extend_from_slice(v_row);

        // Per-head attention over the cache (rows 0..=pos).
        let seq = pos + 1;
        let kc = &cache.k[l];
        let vc = &cache.v[l];
        let mut av = vec![0i16; D];
        for h in 0..H {
            let qh = &q_row[h * DH..(h + 1) * DH];
            // Scores row (requant), row max, exp, denom, recip, weights.
            let mut s_q = Vec::with_capacity(seq);
            for j in 0..seq {
                let mut a = 0i64;
                for l2 in 0..DH {
                    a += qh[l2] as i64 * kc[j * D + h * DH + l2] as i64;
                }
                s_q.push(requant_plain(a, p.shift_scores));
            }
            let c: i16 = if p.softmax_row_shift { *s_q.iter().max().unwrap() } else { 0 };
            let mut denom = 0i64;
            let mut e_row = Vec::with_capacity(seq);
            for &s in &s_q {
                let sp = s as i32 - c as i32;
                assert!(sp >= i16::MIN as i32, "softmax row spread exceeds exp domain");
                let e = m.luts.exp[(sp as i16 as u16) as usize];
                e_row.push(e);
                denom += e as i64;
            }
            let rin = denom >> p.recip_den_shift;
            assert!(rin < 1 << 16, "softmax_recip input exceeds u16 domain");
            let rc = m.luts.softmax_recip[rin as usize];
            // w·V over the cache.
            for l2 in 0..DH {
                let mut a = 0i64;
                for (j, &e) in e_row.iter().enumerate() {
                    let wq = requant_plain(e as i64 * rc as i64, p.shift_softmax_norm);
                    a += wq as i64 * vc[j * D + h * DH + l2] as i64;
                }
                av[h * DH + l2] = requant_plain(a, p.shift_av);
            }
        }

        // Out-proj + residual, LN2, FFN, residual, seam.
        let proj_acc = row_gemm(&av, &w.attn_proj, D, Some(&b.attn_proj), s_ap);
        let mut abo = vec![0i16; D];
        for j in 0..D {
            let s = x[j] as i32 + requant_plain(proj_acc[j], s_ap) as i32;
            assert!((i16::MIN as i32..=i16::MAX as i32).contains(&s));
            abo[j] = s as i16;
        }
        let ln2 = ln_row(&abo, &w.ln2_gain, &w.ln2_bias, m);
        let up_acc = row_gemm(&ln2, &w.ffn_up, DFF, Some(&b.ffn_up), p.shift_ffn_up);
        let gelu: Vec<i16> = up_acc
            .iter()
            .map(|&a| {
                let y = requant_plain(a, p.shift_ffn_up);
                m.luts.gelu[(y as u16) as usize]
            })
            .collect();
        let dn_acc = row_gemm(&gelu, &w.ffn_down, D, Some(&b.ffn_down), s_fd);
        for j in 0..D {
            let s = abo[j] as i32 + requant_plain(dn_acc[j], s_fd) as i32;
            assert!((i16::MIN as i32..=i16::MAX as i32).contains(&s));
            x[j] = s as i16;
        }
        if l < L - 1 {
            let s = m.p.seam_shifts[l];
            if s > 0 {
                for xv in x.iter_mut() {
                    *xv = requant_plain(*xv as i64, s);
                }
            }
        }
    }
    cache.len += 1;

    // ---- final LN + logits row (tied wte, i64, no requant) ----
    let fin = ln_row(&x, &m.lnf_gain, &m.lnf_bias, m);
    (0..VOCAB)
        .into_par_iter()
        .map(|vv| {
            let row = &m.wte[vv * D..(vv + 1) * D];
            let mut s = 0i64;
            for j in 0..D {
                s += fin[j] as i64 * row[j] as i64;
            }
            s
        })
        .collect()
}

pub fn argmax(logits: &[i64]) -> u32 {
    (0..logits.len()).max_by_key(|&v| logits[v]).unwrap() as u32
}

/// Greedy autoregressive generation: prefill on `m.p.tokens[..t0]` (the
/// caller supplies the prefill witness's K/V and last-position logits), then
/// `n_gen` KV-cached decode steps. Returns the generated tokens and every
/// sampled position's logits row (position t0−1+i produces token i).
pub fn generate(
    m: &Gpt2Model,
    cache: &mut KvCache,
    logits_t0: &[i64],
    t0: usize,
    n_gen: usize,
) -> (Vec<u32>, Vec<Vec<i64>>) {
    assert_eq!(cache.len, t0);
    let mut tokens = Vec::with_capacity(n_gen);
    let mut logits_rows = Vec::with_capacity(n_gen);
    let mut next = argmax(logits_t0);
    for i in 0..n_gen {
        tokens.push(next);
        let lg = decode_step(m, cache, next, t0 + i);
        if i + 1 < n_gen {
            next = argmax(&lg);
        }
        logits_rows.push(lg);
    }
    (tokens, logits_rows)
}

// ---------------------------------------------------------------------------
// Tests (skipped when the frozen artifact is not present)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{forward_model, forward_model_tokens, load_model};

    fn weights_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    fn cache_from_wit(wit: &crate::model::ModelWitness, t0: usize) -> KvCache {
        let kv: Vec<(&[i16], &[i16])> =
            wit.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        KvCache::from_prefill(&kv, t0)
    }

    /// KV-cached decode is bit-exact with the full causal re-forward: K/V
    /// caches, residual outputs and every sampled logits row must match.
    #[test]
    fn decode_matches_full_forward_small() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping decode_matches_full_forward_small: artifact not present");
            return;
        }
        let m = load_model(&dir).unwrap();
        let (t0, n_gen) = (12usize, 4usize);
        let wit0 = forward_model(&m, t0);
        let mut cache = cache_from_wit(&wit0, t0);
        let (gen, logits_rows) = generate(&m, &mut cache, &wit0.logits, t0, n_gen);
        assert_eq!(cache.len, t0 + n_gen);

        // Naive reference: full re-forward at each length.
        let mut seq: Vec<u32> = m.p.tokens[..t0].to_vec();
        for (i, &tk) in gen.iter().enumerate() {
            seq.push(tk);
            let wit_i = forward_model_tokens(&m, &seq);
            assert_eq!(wit_i.logits, logits_rows[i], "logits row mismatch at step {i}");
            for l in 0..L {
                assert_eq!(
                    &cache.k[l][..wit_i.layers[l].k.len()],
                    &wit_i.layers[l].k[..],
                    "K cache mismatch at step {i} layer {l}"
                );
                assert_eq!(
                    &cache.v[l][..wit_i.layers[l].v.len()],
                    &wit_i.layers[l].v[..],
                    "V cache mismatch at step {i} layer {l}"
                );
            }
            // Greedy chain: token i+1 = argmax of row i.
            if i + 1 < n_gen {
                assert_eq!(gen[i + 1], argmax(&logits_rows[i]));
            }
        }
    }

    /// Golden decode vs the numpy reference (scripts/dump_golden.py --gen):
    /// generated tokens + per-step logits checksums, bit-exact.
    #[test]
    fn golden_decode_check() {
        let dir = weights_dir();
        let path = dir.join("golden-p6.bin");
        if !path.exists() || !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping golden_decode_check: golden-p6.bin not present");
            return;
        }
        let g = std::fs::read(path).unwrap();
        assert_eq!(&g[..8], b"VGOLD2\0\0");
        let rd_u32 = |o: usize| u32::from_le_bytes(g[o..o + 4].try_into().unwrap());
        let rd_i64 = |o: usize| i64::from_le_bytes(g[o..o + 8].try_into().unwrap());
        let t0 = rd_u32(8) as usize;
        let n_gen = rd_u32(12) as usize;
        let tokens_ref: Vec<u32> = (0..n_gen).map(|i| rd_u32(16 + 4 * i)).collect();
        let off = 16 + 4 * n_gen;
        let sums_ref: Vec<i64> = (0..n_gen).map(|i| rd_i64(off + 8 * i)).collect();
        assert_eq!(off + 8 * n_gen, g.len());

        let m = load_model(&dir).unwrap();
        let wit0 = forward_model(&m, t0);
        let mut cache = cache_from_wit(&wit0, t0);
        let (gen, logits_rows) = generate(&m, &mut cache, &wit0.logits, t0, n_gen);
        assert_eq!(gen, tokens_ref, "generated tokens diverge from numpy");
        // Checksum i pins the logits row that SAMPLED token i: row t0-1+i,
        // i.e. wit0.logits for i = 0 and decode row i-1 after.
        assert_eq!(wit0.logits.iter().sum::<i64>(), sums_ref[0]);
        for i in 1..n_gen {
            assert_eq!(
                logits_rows[i - 1].iter().sum::<i64>(),
                sums_ref[i],
                "logits checksum mismatch at sampled position {}",
                t0 + i - 1
            );
        }
    }
}

//! One-layer fixed-point GPT-2 forward pass = the P4 witness generator.
//!
//! Follows docs/quantization-spec.md exactly: i16 tensors, i64 GEMM
//! accumulators (via `gemm::gemm_i64`), round-half-up shift requant, LN
//! mean/variance in i64 + `ln_rsqrt` LUT, exp/softmax LUT path, GELU LUT,
//! causal mask. Every value looked up in one of the 12 budget tables
//! (scripts/budget_p0.py) is recorded as a stream entry + a multiplicity
//! increment, so P4's LogUp prover consumes this witness directly.
//!
//! **No-clamp deviation (pre-registered for P4):** every requant asserts —
//! in debug AND release — that the pre-clamp value already fits i16. The
//! synthetic weights/scales below are sized so this holds at T = 100.

use crate::gemm::gemm_i64;
use crate::luts::Luts;

/// GPT-2 small layer shape (d = 768, h = 12, d_h = 64, d_ff = 3072).
pub const D: usize = 768;
pub const H: usize = 12;
pub const DH: usize = 64;
pub const DFF: usize = 3072;

// ---------------------------------------------------------------------------
// Table IDs — names match scripts/budget_p0.py exactly.
// ---------------------------------------------------------------------------

/// The 12 per-layer lookup tables of the P0 budget, in budget order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableId {
    LnRsqrt = 0,
    LnNormRequant,
    RequantQkv,
    RequantScores,
    Exp,
    SoftmaxRecip,
    SoftmaxNormRequant,
    RequantAv,
    RequantAttnProj,
    RequantFfnUp,
    Gelu,
    RequantFfnDown,
}

impl TableId {
    pub const ALL: [TableId; 12] = [
        TableId::LnRsqrt,
        TableId::LnNormRequant,
        TableId::RequantQkv,
        TableId::RequantScores,
        TableId::Exp,
        TableId::SoftmaxRecip,
        TableId::SoftmaxNormRequant,
        TableId::RequantAv,
        TableId::RequantAttnProj,
        TableId::RequantFfnUp,
        TableId::Gelu,
        TableId::RequantFfnDown,
    ];

    /// budget_p0.py key for this table.
    pub fn name(self) -> &'static str {
        match self {
            TableId::LnRsqrt => "ln_rsqrt",
            TableId::LnNormRequant => "ln_norm_requant",
            TableId::RequantQkv => "requant_qkv",
            TableId::RequantScores => "requant_scores",
            TableId::Exp => "exp",
            TableId::SoftmaxRecip => "softmax_recip",
            TableId::SoftmaxNormRequant => "softmax_norm_requant",
            TableId::RequantAv => "requant_av",
            TableId::RequantAttnProj => "requant_attn_proj",
            TableId::RequantFfnUp => "requant_ffn_up",
            TableId::Gelu => "gelu",
            TableId::RequantFfnDown => "requant_ffn_down",
        }
    }
}

// ---------------------------------------------------------------------------
// Lookup traces
// ---------------------------------------------------------------------------

/// Lookup stream + multiplicities for one table.
///
/// Stream entry i is `(inputs[i], outputs[i])` — for the nonlinear LUTs the
/// input is the 16-bit table index (sign-extended to i64), for requant tables
/// it is the full i64 accumulator. The multiplicity vector runs over the
/// table's 16-bit domain: for nonlinear LUTs indexed by the input
/// (`x as u16`); for a requant table with shift `s` the domain is the
/// rounding remainder `rem = acc + 2^(s-1) - y·2^s ∈ [0, 2^s)` — the range
/// value the LogUp argument actually checks (the i16 range check on `y`
/// itself is subsumed by the no-clamp assertion in P4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTrace {
    pub inputs: Vec<i64>,
    pub outputs: Vec<i16>,
    pub multiplicity: Vec<u32>,
}

impl LookupTrace {
    fn new(table_len: usize) -> Self {
        LookupTrace { inputs: Vec::new(), outputs: Vec::new(), multiplicity: vec![0; table_len] }
    }

    #[inline]
    fn push(&mut self, input: i64, output: i16, mult_idx: usize) {
        self.inputs.push(input);
        self.outputs.push(output);
        self.multiplicity[mult_idx] += 1;
    }

    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// Requant + trace: round-half-up shift, no-clamp assertion (debug AND
/// release), stream entry `(acc, y)`, multiplicity over the remainder domain.
/// Bit-identical to `gemm::requant` whenever that one does not clamp.
#[inline]
fn requant_traced(traces: &mut [LookupTrace; 12], id: TableId, acc: i64, shift: u32) -> i16 {
    let half = 1i64 << (shift - 1);
    let rounded = (acc + half) >> shift;
    assert!(
        (i16::MIN as i64..=i16::MAX as i64).contains(&rounded),
        "requant saturated in {} (P4 no-clamp deviation violated): acc={acc}, shift={shift}",
        id.name(),
    );
    let rem = (acc + half - (rounded << shift)) as usize; // in [0, 2^shift)
    let y = rounded as i16;
    traces[id as usize].push(acc, y, rem);
    y
}

// ---------------------------------------------------------------------------
// Weights
// ---------------------------------------------------------------------------

/// One GPT-2 layer's weights, all i16, row-major (in_dim × out_dim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerWeights {
    /// Fused QKV projection, 768 × 2304; output columns are [Q | K | V],
    /// head h of each occupying columns h·64 .. (h+1)·64 of its block.
    pub c_attn: Vec<i16>,
    /// Attention output projection, 768 × 768.
    pub attn_proj: Vec<i16>,
    /// FFN up projection, 768 × 3072.
    pub ffn_up: Vec<i16>,
    /// FFN down projection, 3072 × 768.
    pub ffn_down: Vec<i16>,
    pub ln1_gain: Vec<i16>,
    pub ln1_bias: Vec<i16>,
    pub ln2_gain: Vec<i16>,
    pub ln2_bias: Vec<i16>,
}

/// splitmix64 — tiny deterministic PRNG for synthetic data.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Deterministic synthetic weights (real weights arrive with P5's export).
///
/// Magnitudes are the no-clamp sizing choice: projection weights uniform in
/// [-63, 63] (~6 bits), LN gains in [48, 80] (≈1.0 at 6 fraction bits), LN
/// biases in [-128, 127]. With activations ~±2^10 this keeps every GEMM
/// accumulator ≳4 bits below the requant-shifted i16 limit at T = 100.
pub fn synthetic_weights(seed: u64) -> LayerWeights {
    let mut st = seed;
    let mut mat = |len: usize| -> Vec<i16> {
        (0..len).map(|_| (splitmix64(&mut st) % 127) as i16 - 63).collect()
    };
    let c_attn = mat(D * 3 * D);
    let attn_proj = mat(D * D);
    let ffn_up = mat(D * DFF);
    let ffn_down = mat(DFF * D);
    let mut gains = |len: usize| -> Vec<i16> {
        (0..len).map(|_| 48 + (splitmix64(&mut st) % 33) as i16).collect()
    };
    let ln1_gain = gains(D);
    let ln2_gain = gains(D);
    let mut biases = |len: usize| -> Vec<i16> {
        (0..len).map(|_| (splitmix64(&mut st) % 256) as i16 - 128).collect()
    };
    let ln1_bias = biases(D);
    let ln2_bias = biases(D);
    LayerWeights { c_attn, attn_proj, ffn_up, ffn_down, ln1_gain, ln1_bias, ln2_gain, ln2_bias }
}

/// Deterministic synthetic layer input (T × d, uniform in [-1024, 1023]).
pub fn synthetic_input(seed: u64, t: usize) -> Vec<i16> {
    let mut st = seed ^ 0xA5A5_A5A5_A5A5_A5A5;
    (0..t * D).map(|_| (splitmix64(&mut st) % 2048) as i16 - 1024).collect()
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

/// Every wire of one layer forward pass, plus the 12 lookup traces.
///
/// Attention tensors marked "causal-packed" are laid out head-major with
/// only the caus = T(T+1)/2 causal entries per head: entry (head, i, j),
/// j ≤ i, lives at `head·caus + i(i+1)/2 + j`. Scores are *computed* as
/// rectangular T×T GEMMs per head (simplest reuse of `gemm_i64`) but the
/// non-causal outputs are discarded before any witness field or lookup
/// stream is written — streams contain causal entries only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerWitness {
    pub t: usize,
    // -- boundary tensors (authenticated in the fused-block design) --
    pub x_in: Vec<i16>,           // T×d (copy of the input)
    pub k: Vec<i16>,              // T×d
    pub v: Vec<i16>,              // T×d
    pub attn_block_out: Vec<i16>, // T×d (x_in + attention output)
    pub ffn_block_out: Vec<i16>,  // T×d (attn_block_out + FFN output)
    // -- LN1 internals --
    pub ln1_mean: Vec<i64>,      // T (round-half-up of row sum / d)
    pub ln1_var: Vec<i64>,       // T
    pub ln1_rsqrt_in: Vec<i64>,  // T (var >> ln_var_shift, the LUT index)
    pub ln1_rsqrt_out: Vec<i16>, // T
    pub ln1_out: Vec<i16>,       // T×d
    // -- attention internals --
    pub qkv_acc: Vec<i64>,   // T×3d (c_attn GEMM accumulators)
    pub q: Vec<i16>,         // T×d
    pub scores_acc: Vec<i64>, // causal-packed, h·caus (QK^T accumulators)
    pub scores_q: Vec<i16>,  // causal-packed (requantized scores)
    pub exp_out: Vec<i16>,   // causal-packed
    pub denoms: Vec<i64>,    // h×T (row sums of exp)
    pub recips: Vec<i16>,    // h×T (softmax_recip outputs)
    pub softmax_w: Vec<i16>, // causal-packed (normalized weights)
    pub av_acc: Vec<i64>,    // T×d, head h in cols h·64.. (w·V accumulators)
    pub av_q: Vec<i16>,      // T×d
    pub proj_acc: Vec<i64>,  // T×d (out-proj accumulators)
    pub attn_proj_q: Vec<i16>, // T×d (requantized out-proj, pre-residual)
    // -- LN2 internals --
    pub ln2_mean: Vec<i64>,
    pub ln2_var: Vec<i64>,
    pub ln2_rsqrt_in: Vec<i64>,
    pub ln2_rsqrt_out: Vec<i16>,
    pub ln2_out: Vec<i16>,
    // -- FFN internals --
    pub ffn_up_acc: Vec<i64>,  // T×d_ff
    pub ffn_up_q: Vec<i16>,    // T×d_ff
    pub gelu_out: Vec<i16>,    // T×d_ff
    pub ffn_down_acc: Vec<i64>, // T×d
    pub ffn_down_q: Vec<i16>,  // T×d (pre-residual)
    // -- lookups, indexed by TableId as usize --
    pub traces: [LookupTrace; 12],
}

impl LayerWitness {
    /// (budget name, stream length) for the 12 tables, in budget order.
    pub fn lookup_counts(&self) -> [(&'static str, usize); 12] {
        TableId::ALL.map(|id| (id.name(), self.traces[id as usize].len()))
    }
}

// ---------------------------------------------------------------------------
// LayerNorm
// ---------------------------------------------------------------------------

/// Fixed-point LayerNorm over rows of `x` (T×d), spec §Nonlinearities:
/// mean/var as exact i64 sums with round-half-up division by d, `ln_rsqrt`
/// LUT on `var >> ln_var_shift`, then one `ln_norm_requant` per element of
/// `acc = (x - mean)·r·gain + (bias << shift)`. The bias is pre-shifted into
/// the accumulator so the whole affine costs exactly one lookup per element
/// (matching the 2Td budget count); the var → u16 reduction is deterministic
/// pre-scaling folded into the table semantics (asserted to fit).
struct LnOut {
    mean: Vec<i64>,
    var: Vec<i64>,
    rsqrt_in: Vec<i64>,
    rsqrt_out: Vec<i16>,
    out: Vec<i16>,
}

fn layer_norm(
    x: &[i16],
    gain: &[i16],
    bias: &[i16],
    luts: &Luts,
    t: usize,
    traces: &mut [LookupTrace; 12],
) -> LnOut {
    let p = &luts.params;
    let d = D as i64;
    let mut mean = Vec::with_capacity(t);
    let mut var = Vec::with_capacity(t);
    let mut rsqrt_in = Vec::with_capacity(t);
    let mut rsqrt_out = Vec::with_capacity(t);
    let mut out = vec![0i16; t * D];

    for i in 0..t {
        let row = &x[i * D..(i + 1) * D];
        let sum: i64 = row.iter().map(|&v| v as i64).sum();
        // Round-half-up division by d (same convention as requant's
        // (acc + half) >> shift, i.e. floor((x + d/2)/d)).
        let m = (sum + d / 2).div_euclid(d);
        let var_sum: i64 = row.iter().map(|&v| (v as i64 - m) * (v as i64 - m)).sum();
        let vr = (var_sum + d / 2).div_euclid(d);

        let vin = vr >> p.ln_var_shift;
        assert!(vin < 1 << 16, "ln_rsqrt input exceeds u16 domain: var={vr}");
        let r = luts.ln_rsqrt[vin as usize];
        traces[TableId::LnRsqrt as usize].push(vin, r, vin as usize);

        for j in 0..D {
            let dev = row[j] as i64 - m;
            let acc = dev * r as i64 * gain[j] as i64 + ((bias[j] as i64) << p.shift_ln_norm);
            out[i * D + j] = requant_traced(traces, TableId::LnNormRequant, acc, p.shift_ln_norm);
        }
        mean.push(m);
        var.push(vr);
        rsqrt_in.push(vin);
        rsqrt_out.push(r);
    }
    LnOut { mean, var, rsqrt_in, rsqrt_out, out }
}

/// Residual add in i32 with an i16-fit assertion (adds are linear — no
/// lookup — but the sum is an authenticated boundary value and must be i16).
#[inline]
fn residual_add(a: &[i16], b: &[i16]) -> Vec<i16> {
    a.iter()
        .zip(b)
        .map(|(&x, &y)| {
            let s = x as i32 + y as i32;
            assert!(
                (i16::MIN as i32..=i16::MAX as i32).contains(&s),
                "residual add overflows i16 (P4 no-clamp deviation violated)"
            );
            s as i16
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Forward pass
// ---------------------------------------------------------------------------

/// Full one-layer forward: LN1 → c_attn → causal softmax attention →
/// out-proj → residual → LN2 → FFN (up, GELU, down) → residual.
/// GEMMs run on `gemm_i64` (rayon); the lookup-traced epilogues are serial,
/// so stream order is deterministic (head-major, then row-major).
pub fn forward_layer(x_in: &[i16], w: &LayerWeights, luts: &Luts, t: usize) -> LayerWitness {
    assert_eq!(x_in.len(), t * D);
    let p = luts.params;
    let caus = t * (t + 1) / 2;

    // Table domain sizes: nonlinear LUTs are 2^16, requant tables 2^shift
    // (the rounding-remainder range table).
    let mut traces = [
        LookupTrace::new(1 << 16),                    // ln_rsqrt
        LookupTrace::new(1 << p.shift_ln_norm),       // ln_norm_requant
        LookupTrace::new(1 << p.shift_qkv),           // requant_qkv
        LookupTrace::new(1 << p.shift_scores),        // requant_scores
        LookupTrace::new(1 << 16),                    // exp
        LookupTrace::new(1 << 16),                    // softmax_recip
        LookupTrace::new(1 << p.shift_softmax_norm),  // softmax_norm_requant
        LookupTrace::new(1 << p.shift_av),            // requant_av
        LookupTrace::new(1 << p.shift_attn_proj),     // requant_attn_proj
        LookupTrace::new(1 << p.shift_ffn_up),        // requant_ffn_up
        LookupTrace::new(1 << 16),                    // gelu
        LookupTrace::new(1 << p.shift_ffn_down),      // requant_ffn_down
    ];

    // ---- LN1 ----
    let ln1 = layer_norm(x_in, &w.ln1_gain, &w.ln1_bias, luts, t, &mut traces);

    // ---- fused QKV projection ----
    let qkv_acc = gemm_i64(&ln1.out, &w.c_attn, t, D, 3 * D);
    let mut q = vec![0i16; t * D];
    let mut k = vec![0i16; t * D];
    let mut v = vec![0i16; t * D];
    for i in 0..t {
        for j in 0..3 * D {
            let y = requant_traced(&mut traces, TableId::RequantQkv, qkv_acc[i * 3 * D + j], p.shift_qkv);
            match j / D {
                0 => q[i * D + j] = y,
                1 => k[i * D + (j - D)] = y,
                _ => v[i * D + (j - 2 * D)] = y,
            }
        }
    }

    // ---- per-head causal attention ----
    let mut scores_acc = Vec::with_capacity(H * caus);
    let mut scores_q = Vec::with_capacity(H * caus);
    let mut exp_out = Vec::with_capacity(H * caus);
    let mut denoms = Vec::with_capacity(H * t);
    let mut recips = Vec::with_capacity(H * t);
    let mut softmax_w = Vec::with_capacity(H * caus);
    let mut av_acc = vec![0i64; t * D];
    let mut av_q = vec![0i16; t * D];

    for head in 0..H {
        // Contiguous per-head views: Q_h (t×64) and K_h^T (64×t).
        let mut qh = vec![0i16; t * DH];
        let mut kht = vec![0i16; DH * t];
        for i in 0..t {
            for l in 0..DH {
                qh[i * DH + l] = q[i * D + head * DH + l];
                kht[l * t + i] = k[i * D + head * DH + l];
            }
        }
        // Rectangular t×t GEMM; the upper triangle (j > i) is computed but
        // discarded — witness fields and lookup streams are causal-only.
        let s_full = gemm_i64(&qh, &kht, t, DH, t);

        // Causal-packed weight matrix, re-expanded to padded t×t for the
        // w·V GEMM (zeros above the diagonal contribute nothing).
        let mut w_pad = vec![0i16; t * t];
        for i in 0..t {
            let mut denom: i64 = 0;
            let row_start = softmax_w.len(); // == exp row start too
            for j in 0..=i {
                let acc = s_full[i * t + j];
                let s = requant_traced(&mut traces, TableId::RequantScores, acc, p.shift_scores);
                let e = luts.exp[(s as u16) as usize];
                traces[TableId::Exp as usize].push(s as i64, e, (s as u16) as usize);
                scores_acc.push(acc);
                scores_q.push(s);
                exp_out.push(e);
                denom += e as i64;
            }
            let rin = denom >> p.recip_den_shift;
            assert!(rin < 1 << 16, "softmax_recip input exceeds u16 domain: denom={denom}");
            let rc = luts.softmax_recip[rin as usize];
            traces[TableId::SoftmaxRecip as usize].push(rin, rc, rin as usize);
            denoms.push(denom);
            recips.push(rc);
            for j in 0..=i {
                let e = exp_out[row_start + j];
                let wq = requant_traced(
                    &mut traces,
                    TableId::SoftmaxNormRequant,
                    e as i64 * rc as i64,
                    p.shift_softmax_norm,
                );
                softmax_w.push(wq);
                w_pad[i * t + j] = wq;
            }
        }

        // w·V for this head: (t×t)·(t×64), then requant into cols head·64…
        let mut vh = vec![0i16; t * DH];
        for i in 0..t {
            vh[i * DH..(i + 1) * DH]
                .copy_from_slice(&v[i * D + head * DH..i * D + (head + 1) * DH]);
        }
        let avh = gemm_i64(&w_pad, &vh, t, t, DH);
        for i in 0..t {
            for l in 0..DH {
                let acc = avh[i * DH + l];
                av_acc[i * D + head * DH + l] = acc;
                av_q[i * D + head * DH + l] =
                    requant_traced(&mut traces, TableId::RequantAv, acc, p.shift_av);
            }
        }
    }

    // ---- attention output projection + residual ----
    let proj_acc = gemm_i64(&av_q, &w.attn_proj, t, D, D);
    let attn_proj_q: Vec<i16> = proj_acc
        .iter()
        .map(|&acc| requant_traced(&mut traces, TableId::RequantAttnProj, acc, p.shift_attn_proj))
        .collect();
    let attn_block_out = residual_add(x_in, &attn_proj_q);

    // ---- LN2 ----
    let ln2 = layer_norm(&attn_block_out, &w.ln2_gain, &w.ln2_bias, luts, t, &mut traces);

    // ---- FFN ----
    let ffn_up_acc = gemm_i64(&ln2.out, &w.ffn_up, t, D, DFF);
    let ffn_up_q: Vec<i16> = ffn_up_acc
        .iter()
        .map(|&acc| requant_traced(&mut traces, TableId::RequantFfnUp, acc, p.shift_ffn_up))
        .collect();
    let gelu_out: Vec<i16> = ffn_up_q
        .iter()
        .map(|&x| {
            let g = luts.gelu[(x as u16) as usize];
            traces[TableId::Gelu as usize].push(x as i64, g, (x as u16) as usize);
            g
        })
        .collect();
    let ffn_down_acc = gemm_i64(&gelu_out, &w.ffn_down, t, DFF, D);
    let ffn_down_q: Vec<i16> = ffn_down_acc
        .iter()
        .map(|&acc| requant_traced(&mut traces, TableId::RequantFfnDown, acc, p.shift_ffn_down))
        .collect();
    let ffn_block_out = residual_add(&attn_block_out, &ffn_down_q);

    LayerWitness {
        t,
        x_in: x_in.to_vec(),
        k,
        v,
        attn_block_out,
        ffn_block_out,
        ln1_mean: ln1.mean,
        ln1_var: ln1.var,
        ln1_rsqrt_in: ln1.rsqrt_in,
        ln1_rsqrt_out: ln1.rsqrt_out,
        ln1_out: ln1.out,
        qkv_acc,
        q,
        scores_acc,
        scores_q,
        exp_out,
        denoms,
        recips,
        softmax_w,
        av_acc,
        av_q,
        proj_acc,
        attn_proj_q,
        ln2_mean: ln2.mean,
        ln2_var: ln2.var,
        ln2_rsqrt_in: ln2.rsqrt_in,
        ln2_rsqrt_out: ln2.rsqrt_out,
        ln2_out: ln2.out,
        ffn_up_acc,
        ffn_up_q,
        gelu_out,
        ffn_down_acc,
        ffn_down_q,
        traces,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::luts::{build_luts, LutParams};

    fn run(seed: u64, t: usize) -> LayerWitness {
        let luts = build_luts(LutParams::default());
        let w = synthetic_weights(seed);
        let x = synthetic_input(seed.wrapping_add(1), t);
        forward_layer(&x, &w, &luts, t)
    }

    fn check_trace_invariants(wit: &LayerWitness) {
        for id in TableId::ALL {
            let tr = &wit.traces[id as usize];
            assert_eq!(tr.inputs.len(), tr.outputs.len(), "{}", id.name());
            let msum: u64 = tr.multiplicity.iter().map(|&m| m as u64).sum();
            assert_eq!(msum as usize, tr.len(), "multiplicity sum mismatch in {}", id.name());
        }
    }

    /// Budget coherence at the gate shape T=100: stream lengths must equal
    /// the scripts/budget_p0.py formulas exactly (1,412,000 total). Running
    /// this also proves the no-clamp assertion holds at T=100 with the
    /// synthetic weights/scales (any saturation would panic inside forward).
    #[test]
    fn budget_coherence_t100() {
        let t = 100;
        let caus = t * (t + 1) / 2; // 5050
        let wit = run(42, t);
        let expected: [(&str, usize); 12] = [
            ("ln_rsqrt", 2 * t),
            ("ln_norm_requant", 2 * t * D),
            ("requant_qkv", 3 * t * D),
            ("requant_scores", H * caus),
            ("exp", H * caus),
            ("softmax_recip", H * t),
            ("softmax_norm_requant", H * caus),
            ("requant_av", t * D),
            ("requant_attn_proj", t * D),
            ("requant_ffn_up", t * DFF),
            ("gelu", t * DFF),
            ("requant_ffn_down", t * D),
        ];
        assert_eq!(wit.lookup_counts(), expected);
        let total: usize = wit.lookup_counts().iter().map(|&(_, n)| n).sum();
        assert_eq!(total, 1_412_000);
        check_trace_invariants(&wit);
    }

    #[test]
    fn determinism_same_seed_same_witness() {
        let a = run(7, 4);
        let b = run(7, 4);
        assert!(a == b, "same seed must produce an identical witness");
        let c = run(8, 4);
        assert!(a != c, "different seed should perturb the witness");
    }

    #[test]
    fn shapes_and_streams_t4() {
        let t = 4;
        let caus = t * (t + 1) / 2; // 10
        let wit = run(3, t);

        // Boundary tensors.
        for buf in [&wit.x_in, &wit.k, &wit.v, &wit.attn_block_out, &wit.ffn_block_out] {
            assert_eq!(buf.len(), t * D);
        }
        // LN wires.
        assert_eq!(wit.ln1_mean.len(), t);
        assert_eq!(wit.ln1_rsqrt_out.len(), t);
        assert_eq!(wit.ln2_var.len(), t);
        assert_eq!(wit.ln1_out.len(), t * D);
        assert_eq!(wit.ln2_out.len(), t * D);
        // Attention wires (causal-packed).
        assert_eq!(wit.qkv_acc.len(), t * 3 * D);
        assert_eq!(wit.q.len(), t * D);
        assert_eq!(wit.scores_acc.len(), H * caus);
        assert_eq!(wit.scores_q.len(), H * caus);
        assert_eq!(wit.exp_out.len(), H * caus);
        assert_eq!(wit.softmax_w.len(), H * caus);
        assert_eq!(wit.denoms.len(), H * t);
        assert_eq!(wit.recips.len(), H * t);
        assert_eq!(wit.av_acc.len(), t * D);
        assert_eq!(wit.proj_acc.len(), t * D);
        // FFN wires.
        assert_eq!(wit.ffn_up_acc.len(), t * DFF);
        assert_eq!(wit.gelu_out.len(), t * DFF);
        assert_eq!(wit.ffn_down_acc.len(), t * D);

        check_trace_invariants(&wit);

        // Requant streams replay: output must equal the round-half-up shift
        // of the input (bit-identical to gemm::requant when unclamped).
        let p = LutParams::default();
        for (id, shift) in [
            (TableId::LnNormRequant, p.shift_ln_norm),
            (TableId::RequantQkv, p.shift_qkv),
            (TableId::RequantScores, p.shift_scores),
            (TableId::SoftmaxNormRequant, p.shift_softmax_norm),
            (TableId::RequantAv, p.shift_av),
            (TableId::RequantAttnProj, p.shift_attn_proj),
            (TableId::RequantFfnUp, p.shift_ffn_up),
            (TableId::RequantFfnDown, p.shift_ffn_down),
        ] {
            let tr = &wit.traces[id as usize];
            for (&acc, &y) in tr.inputs.iter().zip(&tr.outputs) {
                assert_eq!(crate::gemm::requant(acc, shift), y, "{}", id.name());
            }
        }

        // Denominators are the row sums of the causal exp entries.
        let mut idx = 0usize;
        for head in 0..H {
            for i in 0..t {
                let row_sum: i64 =
                    wit.exp_out[idx..idx + i + 1].iter().map(|&e| e as i64).sum();
                assert_eq!(row_sum, wit.denoms[head * t + i]);
                idx += i + 1;
            }
        }
    }
}

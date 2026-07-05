//! 16-bit lookup tables for the fixed-point GPT-2 layer (spec §Nonlinearities).
//!
//! Four nonlinear LUTs (`exp`, `gelu`, `ln_rsqrt`, `softmax_recip`) plus the
//! per-GEMM requant shifts (spec §Scales: power-of-two scales, so a requant
//! table is fully described by its shift `e` — in-kernel it is the
//! round-half-up shift `requant(acc, e)`, in-circuit a range table of size
//! `2^e` over the rounding remainder).
//!
//! All tables are pure functions of `LutParams`: prover, verifier and the
//! numpy reference build byte-identical tables from the same parameters.
//! `ln_rsqrt` and `softmax_recip` are constructed with integer arithmetic
//! only; `exp` and `gelu` use f64 `exp2`/`tanh` (deterministic for a fixed
//! platform/libm — P5's `export_gpt2.py` ships the frozen real tables, these
//! synthetic ones are P4-internal).
//!
//! Scale parameters here are **synthetic** (real calibrated scales arrive
//! with P5's export script). They are chosen so that, with the synthetic
//! weights of `layer::synthetic_weights`, no requant in the layer saturates
//! at T = 100 (the pre-registered P4 no-clamp deviation, enforced by
//! `assert!` in the forward pass).

/// Synthetic scale/shift parameters. Everything is a power of two (spec
/// §Scales); the fields below are the exponents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LutParams {
    // --- LayerNorm path ---
    /// Variance is reduced to the 16-bit LUT domain as `var >> ln_var_shift`
    /// (deterministic pre-scaling folded into the `ln_rsqrt` table semantics;
    /// asserted to fit u16, it is not a separate lookup — the budget counts
    /// only the `ln_rsqrt` lookup itself).
    pub ln_var_shift: u32,
    /// `ln_rsqrt[v] ≈ 2^ln_rsqrt_log2 / sqrt((v+1) << ln_var_shift)`.
    pub ln_rsqrt_log2: u32,
    /// Requant shift of the LN affine output (`ln_norm_requant` table).
    pub shift_ln_norm: u32,
    // --- softmax path ---
    /// `exp[x] = round(2^exp_out_log2 · 2^(x / 2^exp_in_log2))`, saturated at
    /// `i16::MAX` (table semantics, not a runtime clamp).
    pub exp_in_log2: u32,
    pub exp_out_log2: u32,
    /// Denominators are reduced to the LUT domain as `denom >> recip_den_shift`
    /// (same folded-pre-scaling convention as `ln_var_shift`).
    pub recip_den_shift: u32,
    /// `softmax_recip[v] ≈ 2^recip_log2 / denom`, saturated at `i16::MAX`.
    pub recip_log2: u32,
    // --- GELU ---
    /// Input and output fixed-point scale of the GELU table (fraction bits).
    pub gelu_scale_log2: u32,
    // --- per-GEMM / per-op requant shifts (each defines one requant table) ---
    pub shift_qkv: u32,
    pub shift_scores: u32,
    pub shift_softmax_norm: u32,
    pub shift_av: u32,
    pub shift_attn_proj: u32,
    pub shift_ffn_up: u32,
    pub shift_ffn_down: u32,
}

impl Default for LutParams {
    /// Synthetic defaults, tuned for `synthetic_weights` magnitudes
    /// (activations ~±2^10, weights in [-63, 63]) so the no-clamp assertion
    /// holds at T = 100 with wide margin — see layer.rs tests.
    fn default() -> Self {
        LutParams {
            ln_var_shift: 7,
            ln_rsqrt_log2: 18,
            shift_ln_norm: 16,
            exp_in_log2: 10,
            exp_out_log2: 12,
            recip_den_shift: 6,
            recip_log2: 26,
            gelu_scale_log2: 10,
            shift_qkv: 10,
            shift_scores: 10,
            shift_softmax_norm: 14,
            shift_av: 12,
            shift_attn_proj: 10,
            shift_ffn_up: 10,
            shift_ffn_down: 10,
        }
    }
}

/// The four nonlinear 16-bit tables + parameters (which carry the requant
/// shifts). `exp` and `gelu` are indexed by the i16 input reinterpreted as
/// u16 (`(x as u16) as usize`); `ln_rsqrt` and `softmax_recip` have a
/// non-negative u16 domain and are indexed directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Luts {
    pub params: LutParams,
    pub exp: Vec<i16>,
    pub gelu: Vec<i16>,
    pub ln_rsqrt: Vec<i16>,
    pub softmax_recip: Vec<i16>,
}

const TABLE_LEN: usize = 1 << 16;

/// Floor integer square root (u64). Deterministic, no float dependence.
fn isqrt_u64(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    // f64 sqrt is correctly rounded (IEEE 754); fix up to the exact floor.
    let mut s = (x as f64).sqrt() as u64;
    while s.saturating_mul(s) > x {
        s -= 1;
    }
    while (s + 1).saturating_mul(s + 1) <= x {
        s += 1;
    }
    s
}

/// Round-half-up integer division for non-negative operands.
fn div_round(num: u64, den: u64) -> u64 {
    (num + den / 2) / den
}

/// Build all tables from the parameters. Deterministic; shared by prover,
/// verifier and reference.
pub fn build_luts(params: LutParams) -> Luts {
    let exp_in = f64::from(1u32 << params.exp_in_log2);
    let exp_out = f64::from(1u32 << params.exp_out_log2);
    let gelu_s = f64::from(1u32 << params.gelu_scale_log2);

    let mut exp = vec![0i16; TABLE_LEN];
    let mut gelu = vec![0i16; TABLE_LEN];
    let mut ln_rsqrt = vec![0i16; TABLE_LEN];
    let mut softmax_recip = vec![0i16; TABLE_LEN];

    for u in 0..TABLE_LEN {
        let x = u as u16 as i16; // i16 bit pattern for the signed-domain tables

        // exp[x] = round(2^out · 2^(x/2^in)), saturating at i16::MAX. Values
        // below the representable step round to 0 (softmax numerator).
        let ev = (exp_out * (f64::from(x) / exp_in).exp2()).round();
        exp[u] = ev.min(f64::from(i16::MAX)) as i16;

        // gelu[x] = round(gelu(x/2^s) · 2^s), tanh approximation (GPT-2's).
        let xr = f64::from(x) / gelu_s;
        let g = 0.5 * xr * (1.0 + (0.797_884_560_802_865_4 * (xr + 0.044715 * xr * xr * xr)).tanh());
        gelu[u] = (g * gelu_s)
            .round()
            .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16;

        // ln_rsqrt[v] over the u16 domain v = var >> ln_var_shift:
        // round(2^R / floor_sqrt((v+1) << ln_var_shift)) — the "+1" keeps the
        // divisor nonzero and stands in for the spec's ε. Integer-only.
        let var_back = ((u as u64) + 1) << params.ln_var_shift;
        let s = isqrt_u64(var_back);
        ln_rsqrt[u] = div_round(1u64 << params.ln_rsqrt_log2, s).min(i16::MAX as u64) as i16;

        // softmax_recip[v] over the u16 domain v = denom >> recip_den_shift:
        // round(2^R / (v·2^den_shift + 2^(den_shift-1))) (midpoint of the
        // bucket), saturated at i16::MAX for tiny denominators. Integer-only.
        let den_back = ((u as u64) << params.recip_den_shift) + (1 << (params.recip_den_shift - 1));
        softmax_recip[u] = div_round(1u64 << params.recip_log2, den_back).min(i16::MAX as u64) as i16;
    }

    Luts { params, exp, gelu, ln_rsqrt, softmax_recip }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_deterministic_and_sane() {
        let p = LutParams::default();
        let a = build_luts(p);
        let b = build_luts(p);
        assert!(a == b);

        // exp: monotone on the signed domain, exp[0] = 2^out.
        assert_eq!(a.exp[0], 1 << p.exp_out_log2);
        let idx = |x: i16| (x as u16) as usize;
        assert!(a.exp[idx(-1024)] < a.exp[idx(0)]);
        assert!(a.exp[idx(0)] < a.exp[idx(1024)]);
        assert_eq!(a.exp[idx(i16::MIN)], 0); // exp(-32) underflows to 0

        // gelu: ~identity for large positive x, ~0 for large negative x.
        assert_eq!(a.gelu[idx(0)], 0);
        assert_eq!(a.gelu[idx(i16::MAX)], i16::MAX);
        assert_eq!(a.gelu[idx(i16::MIN)], 0);

        // ln_rsqrt / softmax_recip: positive, non-increasing in the domain.
        assert!(a.ln_rsqrt[0] > 0 && a.ln_rsqrt[0] <= i16::MAX);
        assert!(a.ln_rsqrt[100] >= a.ln_rsqrt[101]);
        assert!(a.softmax_recip[100] >= a.softmax_recip[101]);
    }
}

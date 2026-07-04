//! Blocked integer GEMM (i16 × i16 → i64 accumulators, no modular reduction
//! inside the kernel — see docs/quantization-spec.md) with two epilogues:
//!
//! * native: requantize to i16 (round-half-up shift + clamp) — the baseline
//!   kernel, identical to what plain quantized inference runs;
//! * fused MAC: requantize + authenticate each output element
//!   (δ = x − r with r from the domain-separated mock-PCG stream, tag = tag_r
//!   so the prover-side tag costs nothing).
//!
//! ρ_kernel = t(fused) / t(native) is the P1 gate number.

use rayon::prelude::*;
use volta_field::{Fp, FpStream};

/// Requantization: `clamp(round_half_up(acc / 2^shift))` — must match the
/// requant LUT semantics exactly (spec §Scales).
#[inline]
pub fn requant(acc: i64, shift: u32) -> i16 {
    let rounded = (acc + (1i64 << (shift - 1))) >> shift;
    rounded.clamp(i16::MIN as i64, i16::MAX as i64) as i16
}

/// Epilogue parameters for one output tensor.
#[derive(Clone, Copy)]
pub struct EpilogueSpec {
    pub shift: u32,
    /// Mock-PCG seed shared by prover and verifier.
    pub seed: [u8; 32],
    /// Domain-separation tag for this tensor (packed with the row index per
    /// stream, mirroring the M4/M6 one-time-index discipline).
    pub tensor_tag: u32,
}

/// Core: compute one output row of `a(m×k)·b(k×n)` into `acc` (i64, exact).
/// Loop order (l outer, j inner) lets the autovectorizer widen i16→i32→i64.
#[inline]
fn gemm_row(a_row: &[i16], b: &[i16], n: usize, acc: &mut [i64]) {
    acc.fill(0);
    for (l, &a_il) in a_row.iter().enumerate() {
        if a_il == 0 {
            continue;
        }
        let a_val = a_il as i32;
        let b_row = &b[l * n..l * n + n];
        for (dst, &b_lj) in acc.iter_mut().zip(b_row) {
            *dst += (a_val as i64) * (b_lj as i64);
        }
    }
}

/// Exact accumulator GEMM (no requant) — the tensor the P3 Thaler sumcheck
/// binds; requant consistency is P4's lookup business.
pub fn gemm_i64(a: &[i16], b: &[i16], m: usize, k: usize, n: usize) -> Vec<i64> {
    assert_eq!(a.len(), m * k);
    assert_eq!(b.len(), k * n);
    let mut out = vec![0i64; m * n];
    out.par_chunks_mut(n)
        .enumerate()
        .for_each(|(i, out_row)| gemm_row(&a[i * k..(i + 1) * k], b, n, out_row));
    out
}

/// Native kernel: GEMM + requant. Row-major `a: m×k`, `b: k×n` → `i16 m×n`.
pub fn gemm_requant(a: &[i16], b: &[i16], m: usize, k: usize, n: usize, shift: u32) -> Vec<i16> {
    assert_eq!(a.len(), m * k);
    assert_eq!(b.len(), k * n);
    let mut out = vec![0i16; m * n];
    out.par_chunks_mut(n)
        .enumerate()
        .for_each_init(
            || vec![0i64; n],
            |acc, (i, out_row)| {
                gemm_row(&a[i * k..(i + 1) * k], b, n, acc);
                for (o, &v) in out_row.iter_mut().zip(acc.iter()) {
                    *o = requant(v, shift);
                }
            },
        );
    out
}

/// Fused kernel: GEMM + requant + MAC authentication of every output element.
/// Returns the quantized output (consumed by the next layer, as in native
/// inference) and the corrections `δ = x − r` (F_p-typed, 8 B each — the only
/// extra bytes the prover sends for this tensor).
pub fn gemm_requant_auth(
    a: &[i16],
    b: &[i16],
    m: usize,
    k: usize,
    n: usize,
    ep: EpilogueSpec,
) -> (Vec<i16>, Vec<u64>) {
    assert_eq!(a.len(), m * k);
    assert_eq!(b.len(), k * n);
    let mut out = vec![0i16; m * n];
    let mut corr = vec![0u64; m * n];
    out.par_chunks_mut(n)
        .zip(corr.par_chunks_mut(n))
        .enumerate()
        .for_each_init(
            || vec![0i64; n],
            |acc, (i, (out_row, corr_row))| {
                gemm_row(&a[i * k..(i + 1) * k], b, n, acc);
                // Per-row stream: deterministic under any thread schedule.
                let domain = ((ep.tensor_tag as u64) << 32) | i as u64;
                let mut masks = FpStream::domain_separated(ep.seed, domain);
                for ((o, c), &v) in out_row.iter_mut().zip(corr_row.iter_mut()).zip(acc.iter()) {
                    let y = requant(v, ep.shift);
                    *o = y;
                    let x = Fp::from_i64(y as i64);
                    let r = masks.next_fp();
                    *c = (x - r).value();
                    // Prover tag: m_x = m_r — no arithmetic, the tag stream
                    // stays aligned with the mask stream by construction.
                }
            },
        );
    (out, corr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_gemm(a: &[i16], b: &[i16], m: usize, k: usize, n: usize) -> Vec<i64> {
        let mut out = vec![0i64; m * n];
        for i in 0..m {
            for l in 0..k {
                for j in 0..n {
                    out[i * n + j] += (a[i * k + l] as i64) * (b[l * n + j] as i64);
                }
            }
        }
        out
    }

    #[test]
    fn matches_reference_and_fused_matches_native() {
        let (m, k, n) = (7, 33, 12);
        let a: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
        let b: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
        let shift = 8;
        let native = gemm_requant(&a, &b, m, k, n, shift);
        let reference: Vec<i16> = ref_gemm(&a, &b, m, k, n)
            .iter()
            .map(|&v| requant(v, shift))
            .collect();
        assert_eq!(native, reference);

        let ep = EpilogueSpec { shift, seed: [1; 32], tensor_tag: 3 };
        let (fused, corr) = gemm_requant_auth(&a, &b, m, k, n, ep);
        assert_eq!(fused, native);

        // Verifier-side replay: same masks ⇒ δ + r must re-embed the output.
        for i in 0..m {
            let mut masks = FpStream::domain_separated(ep.seed, (3u64 << 32) | i as u64);
            for j in 0..n {
                let r = masks.next_fp();
                let x = Fp::new(corr[i * n + j]) + r;
                assert_eq!(x, Fp::from_i64(native[i * n + j] as i64));
            }
        }
    }

    #[test]
    fn requant_rounds_half_up_and_clamps() {
        assert_eq!(requant(128, 8), 1); // 0.5 rounds up
        assert_eq!(requant(127, 8), 0);
        assert_eq!(requant(-128, 8), 0); // -0.5 rounds up to 0
        assert_eq!(requant(-129, 8), -1);
        assert_eq!(requant(i64::from(i16::MAX) << 9, 8), i16::MAX);
        assert_eq!(requant(i64::from(i16::MIN) << 9, 8), i16::MIN);
    }
}

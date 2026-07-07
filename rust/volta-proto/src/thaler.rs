//! Thaler matmul sumcheck for `Y = X·W`: the claim
//! `Ỹ(r_i, r_j) = Σ_l X̃(r_i, l)·W̃(l, r_j)` reduces one m×k·k×n GEMM to a
//! log₂(k)-round product sumcheck over the pre-folded tables
//! `A(l) = X̃(r_i, l)` and `B(l) = W̃(l, r_j)`. The folding passes are the
//! Freivalds-style fingerprint the first step degenerates to.
//!
//! Matrices are row-major with independent row/column variable blocks
//! (LSB-first within each block), zero-padded to powers of two.

use crate::mle::eq_vec;
use volta_field::{Fp, Fp2};

pub fn pad_bits(x: usize) -> usize {
    x.next_power_of_two().trailing_zeros() as usize
}

/// `A(l) = Σ_i eq_i[i]·x[i,l]`, length padded to 2^log(k).
pub fn fold_x(x: &[i16], m: usize, k: usize, eq_i: &[Fp2]) -> Vec<Fp2> {
    assert!(eq_i.len() >= m);
    let k_pad = k.next_power_of_two();
    let mut a = vec![Fp2::ZERO; k_pad];
    for i in 0..m {
        let e = eq_i[i];
        let row = &x[i * k..(i + 1) * k];
        for (l, &v) in row.iter().enumerate() {
            if v != 0 {
                a[l] += e.mul_base(Fp::from_i64(v as i64));
            }
        }
    }
    a
}

/// `B(l) = Σ_j eq_j[j]·w[l,j]`, length padded to 2^log(k).
pub fn fold_w(w: &[i16], k: usize, n: usize, eq_j: &[Fp2]) -> Vec<Fp2> {
    assert!(eq_j.len() >= n);
    let k_pad = k.next_power_of_two();
    let mut b = vec![Fp2::ZERO; k_pad];
    for (l, b_l) in b.iter_mut().enumerate().take(k) {
        let row = &w[l * n..(l + 1) * n];
        let mut acc = Fp2::ZERO;
        for (j, &v) in row.iter().enumerate() {
            if v != 0 {
                acc += eq_j[j].mul_base(Fp::from_i64(v as i64));
            }
        }
        *b_l = acc;
    }
    b
}

/// `Ỹ(r_i, r_j) = Σ_{i,j} eq_i[i]·eq_j[j]·y[i,j]` over the exact accumulators.
pub fn fold_y_acc(y: &[i64], m: usize, n: usize, eq_i: &[Fp2], eq_j: &[Fp2]) -> Fp2 {
    let mut total = Fp2::ZERO;
    for i in 0..m {
        let row = &y[i * n..(i + 1) * n];
        let mut acc = Fp2::ZERO;
        for (j, &v) in row.iter().enumerate() {
            acc += eq_j[j].mul_base(Fp::from_i64(v));
        }
        total += eq_i[i] * acc;
    }
    total
}

/// Convenience: eq tables for the row/column points of an m×n output.
pub fn output_eqs(r_i: &[Fp2], r_j: &[Fp2]) -> (Vec<Fp2>, Vec<Fp2>) {
    (eq_vec(r_i), eq_vec(r_j))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mle::eval_mle;
    use crate::sumcheck_clear::{prove_clear, verify_clear};
    use rand::{Rng, SeedableRng};
    use volta_field::FpStream;

    #[test]
    fn thaler_matches_direct_eval() {
        // (16×32)·(32×16): full pipeline against brute-force MLE evals.
        let mut rng = rand::rngs::StdRng::seed_from_u64(61);
        let (m, k, n) = (16usize, 32usize, 16usize);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-500..500)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-500..500)).collect();
        let y = volta_gpt2::gemm_i64(&x, &w, m, k, n);

        let seed = [3u8; 32];
        let mut chal = FpStream::domain_separated(seed, 7);
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| chal.next_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| chal.next_fp2()).collect();
        let (eq_i, eq_j) = output_eqs(&r_i, &r_j);

        let a = fold_x(&x, m, k, &eq_i);
        let b = fold_w(&w, k, n, &eq_j);
        let claim = fold_y_acc(&y, m, n, &eq_i, &eq_j);

        let (proof, _) = prove_clear(a.clone(), b.clone(), &mut chal);
        let mut vchal = FpStream::domain_separated(seed, 7);
        for _ in 0..r_i.len() + r_j.len() {
            vchal.next_fp2();
        }
        let point = verify_clear(claim, &proof, &mut vchal).expect("thaler sumcheck accepts");

        // Final claims equal brute-force MLE evaluations.
        assert_eq!(proof.a_final, eval_mle(&a, &point));
        assert_eq!(proof.b_final, eval_mle(&b, &point));
        // And A/B really are X̃(r_i,·), W̃(·,r_j): spot-check on hypercube l.
        for l in 0..k {
            let col: Vec<Fp2> =
                (0..m).map(|i| Fp2::from_base(Fp::from_i64(x[i * k + l] as i64))).collect();
            assert_eq!(a[l], eval_mle(&col, &r_i));
        }
    }
}

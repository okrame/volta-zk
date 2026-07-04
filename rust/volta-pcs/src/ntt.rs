//! Radix-2 NTT over Goldilocks (2-adicity 32; multiplicative generator 7,
//! same as plonky2/plonky3). Used as the Reed–Solomon encoder of the Ligero
//! commitment: encode = zero-pad message coefficients to the code length and
//! evaluate at all 2^k roots of unity.

use volta_field::{Fp, P};

/// Primitive 2^bits-th root of unity, `7^((P-1)/2^bits)`.
pub fn root_of_unity(bits: u32) -> Fp {
    assert!(bits <= 32, "Goldilocks 2-adicity is 32");
    Fp::new(7).pow((P - 1) >> bits)
}

/// Precomputed twiddles for a fixed size (shared read-only across rows).
pub struct NttPlan {
    pub size: usize,
    /// Powers ω^0..ω^(size/2 - 1) of the primitive size-th root.
    twiddles: Vec<Fp>,
}

impl NttPlan {
    pub fn new(size: usize) -> NttPlan {
        assert!(size.is_power_of_two() && size >= 2);
        let w = root_of_unity(size.trailing_zeros());
        let mut twiddles = Vec::with_capacity(size / 2);
        let mut acc = Fp::ONE;
        for _ in 0..size / 2 {
            twiddles.push(acc);
            acc = acc * w;
        }
        NttPlan { size, twiddles }
    }

    /// In-place forward NTT (decimation-in-time, bit-reversed input reorder):
    /// `a[j] <- Σ_i a[i]·ω^{ij}`.
    pub fn forward(&self, a: &mut [Fp]) {
        let n = self.size;
        assert_eq!(a.len(), n);
        // Bit-reversal permutation.
        let bits = n.trailing_zeros();
        for i in 0..n {
            let j = (i as u64).reverse_bits() as usize >> (64 - bits);
            if i < j {
                a.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= n {
            let step = n / len; // twiddle stride for this stage
            for start in (0..n).step_by(len) {
                for k in 0..len / 2 {
                    let w = self.twiddles[k * step];
                    let u = a[start + k];
                    let v = a[start + k + len / 2] * w;
                    a[start + k] = u + v;
                    a[start + k + len / 2] = u - v;
                }
            }
            len *= 2;
        }
    }

    /// RS-encode: zero-pad `msg` to the plan size and evaluate everywhere.
    pub fn encode(&self, msg: &[Fp]) -> Vec<Fp> {
        assert!(msg.len() <= self.size);
        let mut a = vec![Fp::ZERO; self.size];
        a[..msg.len()].copy_from_slice(msg);
        self.forward(&mut a);
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_exact_order() {
        for bits in [1u32, 4, 15, 32] {
            let w = root_of_unity(bits);
            if bits >= 1 {
                // ω^(2^(bits-1)) = -1 ⇒ order exactly 2^bits.
                assert_eq!(w.pow(1u64 << (bits - 1)).value(), P - 1, "bits={bits}");
            }
            assert_eq!(w.pow(1u64 << bits).value(), 1);
        }
    }

    #[test]
    fn ntt_matches_naive_dft() {
        let n = 16;
        let plan = NttPlan::new(n);
        let w = root_of_unity(4);
        let a: Vec<Fp> = (0..n as u64).map(|i| Fp::new(i * i + 3)).collect();
        let mut fast = a.clone();
        plan.forward(&mut fast);
        for j in 0..n {
            let mut s = Fp::ZERO;
            for (i, &ai) in a.iter().enumerate() {
                s += ai * w.pow((i * j) as u64);
            }
            assert_eq!(fast[j], s, "position {j}");
        }
    }

    #[test]
    fn encode_is_polynomial_evaluation() {
        // Degree < msg_len polynomial: codeword[j] = poly(ω^j).
        let plan = NttPlan::new(32);
        let msg: Vec<Fp> = (0..5u64).map(|i| Fp::new(7 * i + 1)).collect();
        let code = plan.encode(&msg);
        let w = root_of_unity(5);
        for j in [0usize, 1, 17, 31] {
            let x = w.pow(j as u64);
            let mut acc = Fp::ZERO;
            for &c in msg.iter().rev() {
                acc = acc * x + c;
            }
            assert_eq!(code[j], acc);
        }
    }
}

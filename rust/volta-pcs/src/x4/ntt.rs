//! Radix-2 Reed--Solomon encoding over the amended field `E = Fp2`.
//!
//! A single deterministic primitive `2^33` root supplies every nested domain,
//! so squaring a round-`i` domain element lands exactly in round `i+1`.

use std::sync::OnceLock;

use volta_field::{Fp, Fp2, P};

use super::merkle::MerkleError;

const TWO_ADICITY: u32 = 33;

pub fn fp2_pow(mut base: Fp2, mut exponent: u128) -> Fp2 {
    let mut result = Fp2::ONE;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn primitive_root_2_33() -> Fp2 {
    static ROOT: OnceLock<Fp2> = OnceLock::new();
    *ROOT.get_or_init(|| {
        let field_order_minus_one = u128::from(P) * u128::from(P) - 1;
        let cofactor = field_order_minus_one >> TWO_ADICITY;
        // Deterministic search is performed once.  The exact-order checks are
        // repeated in tests and do not trust the candidate shape.
        for c0 in 0..P {
            let candidate = Fp2::new(Fp::new(c0), Fp::ONE);
            let root = fp2_pow(candidate, cofactor);
            if fp2_pow(root, 1u128 << TWO_ADICITY) == Fp2::ONE
                && fp2_pow(root, 1u128 << (TWO_ADICITY - 1)) != Fp2::ONE
            {
                return root;
            }
        }
        unreachable!("Fp2 has the proved 2^33 subgroup")
    })
}

pub fn root_of_unity(bits: u32) -> Result<Fp2, MerkleError> {
    if bits > TWO_ADICITY {
        return Err(MerkleError::InvalidGeometry("Fp2 domain log"));
    }
    if bits == 0 {
        return Ok(Fp2::ONE);
    }
    Ok(fp2_pow(primitive_root_2_33(), 1u128 << (TWO_ADICITY - bits)))
}

#[derive(Clone, Debug)]
pub struct Fp2NttPlan {
    pub size: usize,
    root: Fp2,
    twiddles: Vec<Fp2>,
}

impl Fp2NttPlan {
    pub fn new(size: usize) -> Result<Self, MerkleError> {
        if size < 2 || !size.is_power_of_two() || size.ilog2() > TWO_ADICITY {
            return Err(MerkleError::InvalidGeometry("Fp2 NTT size"));
        }
        let root = root_of_unity(size.ilog2())?;
        let mut twiddles = Vec::with_capacity(size / 2);
        let mut value = Fp2::ONE;
        for _ in 0..size / 2 {
            twiddles.push(value);
            value = value * root;
        }
        Ok(Self { size, root, twiddles })
    }

    pub fn root(&self) -> Fp2 {
        self.root
    }

    pub fn twiddle_bytes(&self) -> u64 {
        (self.twiddles.len() as u64) * 16
    }

    pub fn forward(&self, values: &mut [Fp2]) -> Result<(), MerkleError> {
        if values.len() != self.size {
            return Err(MerkleError::InvalidGeometry("Fp2 NTT input"));
        }
        let bits = self.size.ilog2();
        for index in 0..self.size {
            let reversed = (index as u64).reverse_bits() as usize >> (usize::BITS - bits);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let mut len = 2usize;
        while len <= self.size {
            let step = self.size / len;
            for start in (0..self.size).step_by(len) {
                for offset in 0..len / 2 {
                    let left = values[start + offset];
                    let right = values[start + offset + len / 2] * self.twiddles[offset * step];
                    values[start + offset] = left + right;
                    values[start + offset + len / 2] = left - right;
                }
            }
            len = len.checked_mul(2).ok_or(MerkleError::Overflow)?;
        }
        Ok(())
    }

    pub fn encode(&self, coefficients: &[Fp2]) -> Result<Vec<Fp2>, MerkleError> {
        if coefficients.len() > self.size {
            return Err(MerkleError::InvalidGeometry("RS message length"));
        }
        let mut values = vec![Fp2::ZERO; self.size];
        values[..coefficients.len()].copy_from_slice(coefficients);
        self.forward(&mut values)?;
        Ok(values)
    }
}

pub fn encode_rate_eighth(coefficients: &[Fp2]) -> Result<Vec<Fp2>, MerkleError> {
    if coefficients.is_empty() || !coefficients.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("RS coefficient length"));
    }
    let code_len = coefficients.len().checked_mul(8).ok_or(MerkleError::Overflow)?;
    Fp2NttPlan::new(code_len)?.encode(coefficients)
}

/// Convert Boolean-hypercube evaluations (LSB-first variables) into the
/// multilinear monomial coefficients committed by BaseFold's twin
/// polynomial.
pub fn multilinear_coefficients(evaluations: &[Fp2]) -> Result<Vec<Fp2>, MerkleError> {
    if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("MLE evaluation table"));
    }
    let mut coefficients = evaluations.to_vec();
    let variables = evaluations.len().ilog2();
    for bit in 0..variables {
        let mask = 1usize << bit;
        for index in 0..coefficients.len() {
            if index & mask != 0 {
                coefficients[index] = coefficients[index] - coefficients[index ^ mask];
            }
        }
    }
    Ok(coefficients)
}

pub fn evaluate_multilinear_coefficients(
    coefficients: &[Fp2],
    point: &[Fp2],
) -> Result<Fp2, MerkleError> {
    if coefficients.len() != 1usize.checked_shl(point.len() as u32).unwrap_or(0) {
        return Err(MerkleError::InvalidGeometry("MLE coefficient evaluation"));
    }
    let mut folded = coefficients.to_vec();
    for challenge in point {
        let half = folded.len() / 2;
        for index in 0..half {
            folded[index] = folded[2 * index] + *challenge * folded[2 * index + 1];
        }
        folded.truncate(half);
    }
    Ok(folded[0])
}

pub fn evaluate_multilinear_table(evaluations: &[Fp2], point: &[Fp2]) -> Result<Fp2, MerkleError> {
    if evaluations.len() != 1usize.checked_shl(point.len() as u32).unwrap_or(0) {
        return Err(MerkleError::InvalidGeometry("MLE table evaluation"));
    }
    let mut folded = evaluations.to_vec();
    for challenge in point {
        let half = folded.len() / 2;
        for index in 0..half {
            let left = folded[2 * index];
            let right = folded[2 * index + 1];
            folded[index] = left + *challenge * (right - left);
        }
        folded.truncate(half);
    }
    Ok(folded[0])
}

pub fn fold_coefficients(coefficients: &[Fp2], challenge: Fp2) -> Result<Vec<Fp2>, MerkleError> {
    if coefficients.len() < 2 || !coefficients.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("fold coefficient length"));
    }
    Ok(coefficients.chunks_exact(2).map(|pair| pair[0] + challenge * pair[1]).collect())
}

/// Fold evaluations on `L` into evaluations on `L^2`.  The input order is
/// `omega^j`; positions `j` and `j+n/2` are therefore `+x` and `-x`.
pub fn fold_codeword(values: &[Fp2], challenge: Fp2) -> Result<Vec<Fp2>, MerkleError> {
    if values.len() < 2 || !values.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("fold codeword length"));
    }
    let half = values.len() / 2;
    let omega_inverse = root_of_unity(values.len().ilog2())?.inv();
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    let mut inverse_x = Fp2::ONE;
    let mut folded = Vec::with_capacity(half);
    for index in 0..half {
        let positive = values[index];
        let negative = values[index + half];
        let even = (positive + negative) * inverse_two;
        let odd = (positive - negative) * inverse_two * inverse_x;
        folded.push(even + challenge * odd);
        inverse_x = inverse_x * omega_inverse;
    }
    Ok(folded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(3 * value + 1))
    }

    #[test]
    fn amended_field_domains_are_exact_and_nested_through_33_bits() {
        for bits in [0, 1, 2, 14, 29, 32, 33] {
            let root = root_of_unity(bits).unwrap();
            assert_eq!(fp2_pow(root, 1u128 << bits), Fp2::ONE);
            if bits > 0 {
                assert_ne!(fp2_pow(root, 1u128 << (bits - 1)), Fp2::ONE);
            }
            if bits > 1 {
                assert_eq!(root * root, root_of_unity(bits - 1).unwrap());
            }
        }
        assert_eq!(root_of_unity(34), Err(MerkleError::InvalidGeometry("Fp2 domain log")));
    }

    #[test]
    fn ntt_matches_naive_polynomial_evaluation() {
        let plan = Fp2NttPlan::new(32).unwrap();
        let coefficients: Vec<_> = (0..9).map(symbol).collect();
        let encoded = plan.encode(&coefficients).unwrap();
        let mut x = Fp2::ONE;
        for actual in encoded {
            let mut expected = Fp2::ZERO;
            for coefficient in coefficients.iter().rev() {
                expected = expected * x + *coefficient;
            }
            assert_eq!(actual, expected);
            x = x * plan.root();
        }
    }

    #[test]
    fn codeword_fold_matches_coefficient_fold_and_nested_ntt() {
        let coefficients: Vec<_> = (0..16).map(|index| symbol(index + 1)).collect();
        let challenge = symbol(91);
        let codeword = encode_rate_eighth(&coefficients).unwrap();
        let folded_values = fold_codeword(&codeword, challenge).unwrap();
        let folded_coefficients = fold_coefficients(&coefficients, challenge).unwrap();
        assert_eq!(folded_values, encode_rate_eighth(&folded_coefficients).unwrap());
    }

    #[test]
    fn boolean_table_mobius_transform_preserves_every_mle_evaluation() {
        let table: Vec<_> = (0..16).map(|index| symbol(index * index + 2)).collect();
        let coefficients = multilinear_coefficients(&table).unwrap();
        let point = vec![symbol(5), symbol(7), symbol(11), symbol(13)];
        assert_eq!(
            evaluate_multilinear_table(&table, &point).unwrap(),
            evaluate_multilinear_coefficients(&coefficients, &point).unwrap()
        );
        for index in 0..16 {
            let boolean_point: Vec<_> = (0..4)
                .map(|bit| if index & (1 << bit) == 0 { Fp2::ZERO } else { Fp2::ONE })
                .collect();
            assert_eq!(
                evaluate_multilinear_coefficients(&coefficients, &boolean_point).unwrap(),
                table[index]
            );
        }
    }
}

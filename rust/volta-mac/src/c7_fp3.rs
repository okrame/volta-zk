//! Carrier-independent C7 terminal transfer over `Fp3`.
//!
//! This is the smallest executable seam for the Lean equation
//! `k = m + Delta*x`. It does not instantiate PCG/VOLE or a PCS prover.

use volta_field::{Fp3, Fp3DecodeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3ProverAuthed {
    pub x: Fp3,
    pub m: Fp3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3VerifierKey {
    pub k: Fp3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Fp3TransferCorrection(Fp3);

impl C7Fp3ProverAuthed {
    pub const ZERO: Self = Self { x: Fp3::ZERO, m: Fp3::ZERO };

    #[inline]
    pub const fn new(x: Fp3, m: Fp3) -> Self {
        Self { x, m }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.x + rhs.x, self.m + rhs.m)
    }

    #[inline]
    pub fn scale(self, coefficient: Fp3) -> Self {
        Self::new(coefficient * self.x, coefficient * self.m)
    }
}

impl C7Fp3VerifierKey {
    pub const ZERO: Self = Self { k: Fp3::ZERO };

    #[inline]
    pub const fn new(k: Fp3) -> Self {
        Self { k }
    }

    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.k + rhs.k)
    }

    #[inline]
    pub fn scale(self, coefficient: Fp3) -> Self {
        Self::new(coefficient * self.k)
    }
}

impl C7Fp3TransferCorrection {
    pub const ENCODED_BYTES: usize = Fp3::ENCODED_BYTES;

    #[inline]
    pub const fn new(value: Fp3) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn value(self) -> Fp3 {
        self.0
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; Self::ENCODED_BYTES] {
        self.0.to_bytes()
    }

    #[inline]
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, Fp3DecodeError> {
        Fp3::from_bytes(encoded).map(Self)
    }
}

/// Provider half of transfer-into-MAC. `Delta` is deliberately absent.
#[inline]
pub fn c7_fp3_transfer_prover(
    correlation: C7Fp3ProverAuthed,
    target: Fp3,
) -> (C7Fp3TransferCorrection, C7Fp3ProverAuthed) {
    (
        C7Fp3TransferCorrection::new(target - correlation.x),
        C7Fp3ProverAuthed::new(target, correlation.m),
    )
}

/// Verifier half of the same transfer under one shared extension-field Delta.
#[inline]
pub fn c7_fp3_transfer_verifier(
    correlation_key: C7Fp3VerifierKey,
    delta: Fp3,
    correction: C7Fp3TransferCorrection,
) -> C7Fp3VerifierKey {
    C7Fp3VerifierKey::new(correlation_key.k + delta * correction.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, P};

    fn fp3(a: u64, b: u64, c: u64) -> Fp3 {
        Fp3::new(Fp::new(a), Fp::new(b), Fp::new(c))
    }

    fn correlation(delta: Fp3, x: Fp3, m: Fp3) -> (C7Fp3ProverAuthed, C7Fp3VerifierKey) {
        (C7Fp3ProverAuthed::new(x, m), C7Fp3VerifierKey::new(m + delta * x))
    }

    fn valid(delta: Fp3, prover: C7Fp3ProverAuthed, verifier: C7Fp3VerifierKey) -> bool {
        verifier.k == prover.m + delta * prover.x
    }

    #[test]
    fn transfer_codec_and_multi_commit_linearity_share_one_delta() {
        let delta = fp3(17, 19, 23);
        let (corr0, key0) = correlation(delta, fp3(1, 2, 3), fp3(5, 7, 11));
        let (corr1, key1) = correlation(delta, fp3(13, 17, 19), fp3(23, 29, 31));
        let (wire0, auth0) = c7_fp3_transfer_prover(corr0, fp3(37, 41, 43));
        let (wire1, auth1) = c7_fp3_transfer_prover(corr1, fp3(47, 53, 59));
        let corrected0 = c7_fp3_transfer_verifier(key0, delta, wire0);
        let corrected1 = c7_fp3_transfer_verifier(key1, delta, wire1);
        assert!(valid(delta, auth0, corrected0));
        assert!(valid(delta, auth1, corrected1));

        let beta0 = fp3(61, 67, 71);
        let beta1 = fp3(73, 79, 83);
        let batched_auth = auth0.scale(beta0).add(auth1.scale(beta1));
        let batched_key = corrected0.scale(beta0).add(corrected1.scale(beta1));
        assert!(valid(delta, batched_auth, batched_key));

        let encoded = wire0.to_bytes();
        assert_eq!(encoded.len(), 24);
        assert_eq!(C7Fp3TransferCorrection::from_bytes(&encoded), Ok(wire0));
        for limb in 0..3 {
            let mut noncanonical = encoded;
            noncanonical[limb * 8..(limb + 1) * 8].copy_from_slice(&P.to_le_bytes());
            assert!(C7Fp3TransferCorrection::from_bytes(&noncanonical).is_err());

            let mut mutated = wire0.value();
            match limb {
                0 => mutated.c0 += Fp::ONE,
                1 => mutated.c1 += Fp::ONE,
                _ => mutated.c2 += Fp::ONE,
            }
            let wrong =
                c7_fp3_transfer_verifier(key0, delta, C7Fp3TransferCorrection::new(mutated));
            assert!(!valid(delta, auth0, wrong));
        }
    }
}

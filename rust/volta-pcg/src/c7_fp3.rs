//! Shared C7 Fp3 authenticated-value algebra; no correlation generation.
//! Callers own transcript binding and one-time consumption.

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

/// Pure algebra for one ordered product batch. The caller must bind every
/// triple before sampling `lambda`, and owns transcript phase/recording.
pub fn c7_fp3_product_batch_prover(
    triples: impl IntoIterator<Item = [C7Fp3ProverAuthed; 3]>,
    mask: C7Fp3ProverAuthed,
    lambda: Fp3,
) -> [Fp3; 2] {
    let (mut a, mut b, mut power) = (mask.x, mask.m, Fp3::ONE);
    for [x, y, z] in triples {
        a += power * (x.x * y.m + y.x * x.m - z.m);
        b += power * x.m * y.m;
        power = power * lambda;
    }
    [a, b]
}

/// Verifier half of [`c7_fp3_product_batch_prover`] under `k=m+Delta*x`.
pub fn c7_fp3_product_batch_verify(
    triples: impl IntoIterator<Item = [C7Fp3VerifierKey; 3]>,
    mask: C7Fp3VerifierKey,
    wire: [Fp3; 2],
    lambda: Fp3,
    delta: Fp3,
) -> bool {
    let (mut expected, mut power) = (mask.k, Fp3::ONE);
    for [x, y, z] in triples {
        expected += power * (x.k * y.k - delta * z.k);
        power = power * lambda;
    }
    wire[1] + delta * wire[0] == expected
}

//! Goldilocks field `F_p`, `p = 2^64 - 2^32 + 1`, its quadratic extension
//! `F_p[X]/(X^2 - 7)`, and C7's cubic extension `F_p[u]/(u^3 - 2)`.
//! Canonical base-field representation is `[0, p)`.
//!
//! Quantized plaintexts (i16) embed into `F_p`; existing MAC tags, keys, Δ and
//! challenges use `Fp2`, while C7's carrier-independent seam uses `Fp3`.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
/// `2^64 mod P = 2^32 - 1`.
const EPSILON: u64 = 0xFFFF_FFFF;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    #[inline]
    pub const fn new(x: u64) -> Fp {
        // x < 2^64 and 2^64 - P < P, so one conditional subtraction canonicalizes.
        Fp(if x >= P { x - P } else { x })
    }

    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Embed a signed quantized value (|x| < P).
    #[inline]
    pub fn from_i64(x: i64) -> Fp {
        if x >= 0 {
            Fp::new(x as u64)
        } else {
            Fp(P - x.unsigned_abs())
        }
    }

    #[inline]
    pub fn add(self, rhs: Fp) -> Fp {
        let (r, carry) = self.0.overflowing_add(rhs.0);
        let r = if carry { r.wrapping_add(EPSILON) } else { r };
        Fp(if r >= P { r - P } else { r })
    }

    #[inline]
    pub fn sub(self, rhs: Fp) -> Fp {
        let (r, borrow) = self.0.overflowing_sub(rhs.0);
        Fp(if borrow { r.wrapping_sub(EPSILON) } else { r })
    }

    #[inline]
    pub fn neg(self) -> Fp {
        if self.0 == 0 {
            Fp::ZERO
        } else {
            Fp(P - self.0)
        }
    }

    #[inline]
    pub fn mul(self, rhs: Fp) -> Fp {
        reduce128((self.0 as u128) * (rhs.0 as u128))
    }

    pub fn pow(self, mut e: u64) -> Fp {
        let mut base = self;
        let mut acc = Fp::ONE;
        while e != 0 {
            if e & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        acc
    }

    /// Multiplicative inverse (Fermat). Panics on zero.
    pub fn inv(self) -> Fp {
        assert!(self.0 != 0, "inverse of zero");
        self.pow(P - 2)
    }
}

/// Reduce a 128-bit product using `2^64 ≡ 2^32 - 1` and `2^96 ≡ -1 (mod P)`.
#[inline]
pub fn reduce128(x: u128) -> Fp {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;
    // x ≡ lo - hi_hi + EPSILON * hi_lo (mod P)
    let (t, borrow) = lo.overflowing_sub(hi_hi);
    let t = if borrow { t.wrapping_sub(EPSILON) } else { t };
    let t1 = hi_lo * EPSILON; // ≤ (2^32-1)^2 < 2^64
    let (r, carry) = t.overflowing_add(t1);
    let r = if carry { r.wrapping_add(EPSILON) } else { r };
    Fp(if r >= P { r - P } else { r })
}

impl core::ops::Add for Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        Fp::add(self, rhs)
    }
}
impl core::ops::Sub for Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: Fp) -> Fp {
        Fp::sub(self, rhs)
    }
}
impl core::ops::Mul for Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        Fp::mul(self, rhs)
    }
}
impl core::ops::Neg for Fp {
    type Output = Fp;
    #[inline]
    fn neg(self) -> Fp {
        Fp::neg(self)
    }
}
impl core::ops::AddAssign for Fp {
    #[inline]
    fn add_assign(&mut self, rhs: Fp) {
        *self = *self + rhs;
    }
}

/// Quadratic non-residue defining the extension `E = F_p[φ]/(φ² - W)`.
pub const W: u64 = 7;

/// `E = F_p²`: `c0 + c1·φ` with `φ² = 7`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };
    pub const ONE: Fp2 = Fp2 { c0: Fp::ONE, c1: Fp::ZERO };

    #[inline]
    pub const fn new(c0: Fp, c1: Fp) -> Fp2 {
        Fp2 { c0, c1 }
    }

    #[inline]
    pub const fn from_base(x: Fp) -> Fp2 {
        Fp2 { c0: x, c1: Fp::ZERO }
    }

    #[inline]
    pub fn add(self, rhs: Fp2) -> Fp2 {
        Fp2::new(self.c0 + rhs.c0, self.c1 + rhs.c1)
    }

    #[inline]
    pub fn sub(self, rhs: Fp2) -> Fp2 {
        Fp2::new(self.c0 - rhs.c0, self.c1 - rhs.c1)
    }

    #[inline]
    pub fn mul(self, rhs: Fp2) -> Fp2 {
        let w = Fp::new(W);
        Fp2::new(self.c0 * rhs.c0 + w * (self.c1 * rhs.c1), self.c0 * rhs.c1 + self.c1 * rhs.c0)
    }

    /// Multiply by a base-field scalar (the hot verifier path: `k_r + Δ·δ`
    /// with `δ ∈ F_p` costs 2 base mults, not a full `Fp2` mult).
    #[inline]
    pub fn mul_base(self, x: Fp) -> Fp2 {
        Fp2::new(self.c0 * x, self.c1 * x)
    }

    pub fn inv(self) -> Fp2 {
        // (c0 - c1·φ) / (c0² - 7·c1²)
        let w = Fp::new(W);
        let norm = self.c0 * self.c0 - w * (self.c1 * self.c1);
        let n_inv = norm.inv();
        Fp2::new(self.c0 * n_inv, (-self.c1) * n_inv)
    }
}

impl core::ops::Add for Fp2 {
    type Output = Fp2;
    #[inline]
    fn add(self, rhs: Fp2) -> Fp2 {
        Fp2::add(self, rhs)
    }
}
impl core::ops::Sub for Fp2 {
    type Output = Fp2;
    #[inline]
    fn sub(self, rhs: Fp2) -> Fp2 {
        Fp2::sub(self, rhs)
    }
}
impl core::ops::Mul for Fp2 {
    type Output = Fp2;
    #[inline]
    fn mul(self, rhs: Fp2) -> Fp2 {
        Fp2::mul(self, rhs)
    }
}
impl core::ops::AddAssign for Fp2 {
    #[inline]
    fn add_assign(&mut self, rhs: Fp2) {
        *self = *self + rhs;
    }
}

/// `F_p³ = F_p[u]/(u³ - 2)`: `c0 + c1·u + c2·u²`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct Fp3 {
    pub c0: Fp,
    pub c1: Fp,
    pub c2: Fp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fp3DecodeError {
    WrongLength { actual: usize },
    NonCanonicalLimb { limb: usize },
}

impl core::fmt::Display for Fp3DecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { actual } => {
                write!(formatter, "Fp3 encoding is {actual} bytes, expected 24")
            }
            Self::NonCanonicalLimb { limb } => {
                write!(formatter, "Fp3 limb {limb} is not canonical")
            }
        }
    }
}

impl std::error::Error for Fp3DecodeError {}

impl Fp3 {
    pub const ZERO: Fp3 = Fp3 { c0: Fp::ZERO, c1: Fp::ZERO, c2: Fp::ZERO };
    pub const ONE: Fp3 = Fp3 { c0: Fp::ONE, c1: Fp::ZERO, c2: Fp::ZERO };
    pub const ENCODED_BYTES: usize = 24;

    #[inline]
    pub const fn new(c0: Fp, c1: Fp, c2: Fp) -> Fp3 {
        Fp3 { c0, c1, c2 }
    }

    #[inline]
    pub const fn from_base(x: Fp) -> Fp3 {
        Fp3 { c0: x, c1: Fp::ZERO, c2: Fp::ZERO }
    }

    #[inline]
    pub fn add(self, rhs: Fp3) -> Fp3 {
        Fp3::new(self.c0 + rhs.c0, self.c1 + rhs.c1, self.c2 + rhs.c2)
    }

    #[inline]
    pub fn sub(self, rhs: Fp3) -> Fp3 {
        Fp3::new(self.c0 - rhs.c0, self.c1 - rhs.c1, self.c2 - rhs.c2)
    }

    #[inline]
    pub fn mul(self, rhs: Fp3) -> Fp3 {
        let two = Fp::new(2);
        Fp3::new(
            self.c0 * rhs.c0 + two * (self.c1 * rhs.c2 + self.c2 * rhs.c1),
            self.c0 * rhs.c1 + self.c1 * rhs.c0 + two * (self.c2 * rhs.c2),
            self.c0 * rhs.c2 + self.c1 * rhs.c1 + self.c2 * rhs.c0,
        )
    }

    #[inline]
    pub fn mul_base(self, rhs: Fp) -> Fp3 {
        Fp3::new(self.c0 * rhs, self.c1 * rhs, self.c2 * rhs)
    }

    pub fn to_bytes(self) -> [u8; Self::ENCODED_BYTES] {
        let mut encoded = [0u8; Self::ENCODED_BYTES];
        for (index, limb) in [self.c0, self.c1, self.c2].into_iter().enumerate() {
            encoded[index * 8..(index + 1) * 8].copy_from_slice(&limb.value().to_le_bytes());
        }
        encoded
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Fp3, Fp3DecodeError> {
        if encoded.len() != Self::ENCODED_BYTES {
            return Err(Fp3DecodeError::WrongLength { actual: encoded.len() });
        }
        let mut limbs = [Fp::ZERO; 3];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let raw = u64::from_le_bytes(encoded[index * 8..(index + 1) * 8].try_into().unwrap());
            if raw >= P {
                return Err(Fp3DecodeError::NonCanonicalLimb { limb: index });
            }
            *limb = Fp(raw);
        }
        Ok(Fp3::new(limbs[0], limbs[1], limbs[2]))
    }
}

impl core::ops::Add for Fp3 {
    type Output = Fp3;

    #[inline]
    fn add(self, rhs: Fp3) -> Fp3 {
        Fp3::add(self, rhs)
    }
}

impl core::ops::Sub for Fp3 {
    type Output = Fp3;

    #[inline]
    fn sub(self, rhs: Fp3) -> Fp3 {
        Fp3::sub(self, rhs)
    }
}

impl core::ops::Mul for Fp3 {
    type Output = Fp3;

    #[inline]
    fn mul(self, rhs: Fp3) -> Fp3 {
        Fp3::mul(self, rhs)
    }
}

impl core::ops::Neg for Fp3 {
    type Output = Fp3;

    #[inline]
    fn neg(self) -> Fp3 {
        Fp3::ZERO - self
    }
}

impl core::ops::AddAssign for Fp3 {
    #[inline]
    fn add_assign(&mut self, rhs: Fp3) {
        *self = *self + rhs;
    }
}

/// Deterministic stream of field elements from a seed (mock-PCG stand-in:
/// both parties expand the same stream; Δ stays verifier-only).
pub struct FpStream {
    rng: ChaCha8Rng,
}

impl FpStream {
    pub fn from_seed(seed: [u8; 32]) -> FpStream {
        FpStream { rng: ChaCha8Rng::from_seed(seed) }
    }

    /// Domain-separated stream: (session, layer, head, position, tensor_tag)
    /// packed into the ChaCha stream number, so distinct indices never share
    /// output (mirrors the M4/M6 freshness discipline).
    pub fn domain_separated(seed: [u8; 32], domain: u64) -> FpStream {
        let mut rng = ChaCha8Rng::from_seed(seed);
        rng.set_stream(domain);
        FpStream { rng }
    }

    /// Uniform `F_p` element by rejection sampling (reject prob ~2^-32).
    #[inline]
    pub fn next_fp(&mut self) -> Fp {
        loop {
            let x: u64 = self.rng.gen();
            if x < P {
                return Fp(x);
            }
        }
    }

    #[inline]
    pub fn next_fp2(&mut self) -> Fp2 {
        Fp2::new(self.next_fp(), self.next_fp())
    }

    /// Uniform integer from exactly `width` fresh random bits.  Unlike field
    /// reduction, this is suitable for power-of-two query domains.
    #[inline]
    pub fn next_bits(&mut self, width: u8) -> u64 {
        assert!((1..=63).contains(&width), "exact-bit width must be in 1..=63");
        let raw: u64 = self.rng.gen();
        raw & ((1u64 << width) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;

    #[test]
    fn exact_bit_draws_stay_in_the_power_of_two_domain() {
        let mut stream = FpStream::from_seed([0xA5; 32]);
        let draws = (0..512).map(|_| stream.next_bits(33)).collect::<Vec<_>>();
        assert!(draws.iter().all(|draw| *draw < (1u64 << 33)));
        assert!(draws.iter().any(|draw| *draw >= (1u64 << 32)));
    }

    fn ref_mul(a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % (P as u128)) as u64
    }
    fn ref_add(a: u64, b: u64) -> u64 {
        ((a as u128 + b as u128) % (P as u128)) as u64
    }
    fn ref_sub(a: u64, b: u64) -> u64 {
        ((a as u128 + P as u128 - b as u128) % (P as u128)) as u64
    }

    fn rand_fp(rng: &mut StdRng) -> u64 {
        rng.gen_range(0..P)
    }

    #[test]
    fn differential_against_u128_reference() {
        let mut rng = StdRng::seed_from_u64(0xB0);
        for _ in 0..100_000 {
            let a = rand_fp(&mut rng);
            let b = rand_fp(&mut rng);
            assert_eq!((Fp(a) * Fp(b)).value(), ref_mul(a, b));
            assert_eq!((Fp(a) + Fp(b)).value(), ref_add(a, b));
            assert_eq!((Fp(a) - Fp(b)).value(), ref_sub(a, b));
        }
    }

    #[test]
    fn edge_cases() {
        let pm1 = Fp(P - 1);
        assert_eq!((pm1 * pm1).value(), 1); // (-1)^2
        assert_eq!((pm1 + Fp::ONE).value(), 0);
        assert_eq!((Fp::ZERO - Fp::ONE).value(), P - 1);
        assert_eq!(Fp::new(u64::MAX).value(), u64::MAX - P);
        // 2^64 ≡ 2^32 - 1, 2^96 ≡ -1
        assert_eq!(Fp(2).pow(64).value(), EPSILON);
        assert_eq!(Fp(2).pow(96).value(), P - 1);
        assert_eq!(Fp::from_i64(-5), Fp::ZERO - Fp(5));
    }

    #[test]
    fn inverses() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..200 {
            let a = Fp(rng.gen_range(1..P));
            assert_eq!((a * a.inv()).value(), 1);
        }
    }

    #[test]
    fn seven_is_a_quadratic_nonresidue() {
        // Euler criterion: 7^((P-1)/2) ≡ -1 so X² - 7 is irreducible.
        assert_eq!(Fp(W).pow((P - 1) / 2).value(), P - 1);
    }

    #[test]
    fn fp2_field_axioms_sampled() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut r = || Fp2::new(Fp(rng.gen_range(0..P)), Fp(rng.gen_range(0..P)));
        for _ in 0..200 {
            let (a, b, c) = (r(), r(), r());
            assert_eq!(a * b, b * a);
            assert_eq!((a * b) * c, a * (b * c));
            assert_eq!(a * (b + c), a * b + a * c);
            if a != Fp2::ZERO {
                assert_eq!(a * a.inv(), Fp2::ONE);
            }
            assert_eq!(a.mul_base(Fp(3)), a * Fp2::from_base(Fp(3)));
        }
    }

    #[test]
    fn fp3_codec_and_multiplication_kat() {
        let left = Fp3::new(Fp::new(1), Fp::new(2), Fp::new(3));
        let right = Fp3::new(Fp::new(4), Fp::new(5), Fp::new(6));
        assert_eq!(left * right, Fp3::new(Fp::new(58), Fp::new(49), Fp::new(28)));

        let encoded = left.to_bytes();
        assert_eq!(Fp3::from_bytes(&encoded), Ok(left));
        assert_eq!(&encoded[..8], &1u64.to_le_bytes());
        assert_eq!(&encoded[8..16], &2u64.to_le_bytes());
        assert_eq!(&encoded[16..], &3u64.to_le_bytes());
        assert!(matches!(
            Fp3::from_bytes(&encoded[..23]),
            Err(Fp3DecodeError::WrongLength { actual: 23 })
        ));

        for limb in 0..3 {
            let mut noncanonical = encoded;
            noncanonical[limb * 8..(limb + 1) * 8].copy_from_slice(&P.to_le_bytes());
            assert_eq!(
                Fp3::from_bytes(&noncanonical),
                Err(Fp3DecodeError::NonCanonicalLimb { limb })
            );
        }
    }

    #[test]
    fn two_is_a_cubic_nonresidue() {
        assert_eq!(Fp::new(2).pow((P - 1) / 3).value(), (1u64 << 32) - 1);
    }

    #[test]
    fn stream_is_deterministic_and_domain_separated() {
        let seed = [42u8; 32];
        let mut s1 = FpStream::domain_separated(seed, 7);
        let mut s2 = FpStream::domain_separated(seed, 7);
        let mut s3 = FpStream::domain_separated(seed, 8);
        let a: Vec<u64> = (0..32).map(|_| s1.next_fp().value()).collect();
        let b: Vec<u64> = (0..32).map(|_| s2.next_fp().value()).collect();
        let c: Vec<u64> = (0..32).map(|_| s3.next_fp().value()).collect();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.iter().all(|&x| x < P));
    }
}

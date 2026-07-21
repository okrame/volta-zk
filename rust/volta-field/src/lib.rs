//! Goldilocks field `F_p`, `p = 2^64 - 2^32 + 1`, and its quadratic extension
//! `E = F_p[X]/(X^2 - 7)`. Canonical representation in `[0, p)`.
//!
//! Quantized plaintexts (i16) embed into `F_p`; MAC tags, keys, Δ and
//! challenges live in `E` (~2^124 statistical soundness per opening).

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

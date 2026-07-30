//! Authenticated-value types, split by party (the Lean `Authed {x, m, k}`
//! carries both parties' state inside one proof object; at runtime the prover
//! holds `(x, m)` and the verifier holds `k` with the session-global `Δ`).
//!
//! Invariant (Mac.lean `Valid`): `k = m + Δ·x`. Linear operations preserve it
//! (Mac.lean `Valid.add/smul/neg/sub`), so both halves expose the same
//! linear-algebra surface and stay in lockstep.

use crate::c6_trace::C6TraceToken;
use volta_field::{Fp, Fp2};

/// Prover half of a full-field authenticated value: plaintext and tag in `E`.
/// Used for round coefficients, RLC accumulators, masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverAuthed {
    pub x: Fp2,
    pub m: Fp2,
    #[cfg(feature = "c6-trace")]
    trace: C6TraceToken,
}

/// Prover half of a subfield-authenticated value (M5): plaintext in `F_p`
/// (quantized tensor element), tag in `E`. Corrections for these cost 8 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverSubAuthed {
    pub x: Fp,
    pub m: Fp2,
    #[cfg(feature = "c6-trace")]
    trace: C6TraceToken,
}

/// Verifier half: the MAC key. `Δ` lives in `VerifierCtx`, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierKey {
    pub k: Fp2,
}

impl ProverAuthed {
    pub const ZERO: ProverAuthed =
        ProverAuthed::from_traced_parts(Fp2::ZERO, Fp2::ZERO, C6TraceToken::public_zero());

    #[inline]
    pub const fn new(x: Fp2, m: Fp2) -> ProverAuthed {
        Self::from_traced_parts(x, m, C6TraceToken::untracked())
    }

    #[inline]
    pub(crate) const fn from_traced_parts(x: Fp2, m: Fp2, _trace: C6TraceToken) -> ProverAuthed {
        ProverAuthed {
            x,
            m,
            #[cfg(feature = "c6-trace")]
            trace: _trace,
        }
    }

    #[inline]
    pub fn c6_trace_token(self) -> C6TraceToken {
        #[cfg(feature = "c6-trace")]
        {
            self.trace
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            C6TraceToken::untracked()
        }
    }

    /// Preserve an already-derived diagnostic provenance token while
    /// attaching the value/tag produced by an equivalent resident or fused
    /// linear kernel. Ordinary builds have no token and reduce to `new`.
    #[doc(hidden)]
    #[inline]
    pub fn with_same_c6_trace(self, x: Fp2, m: Fp2) -> ProverAuthed {
        ProverAuthed::from_traced_parts(x, m, self.c6_trace_token())
    }

    /// Public constant: tag 0 (Mac.lean `ofPublic`; verifier side is `Δ·c`).
    #[inline]
    pub fn from_public(c: Fp2) -> ProverAuthed {
        ProverAuthed::from_traced_parts(c, Fp2::ZERO, C6TraceToken::public(c))
    }

    #[inline]
    pub fn add(self, rhs: ProverAuthed) -> ProverAuthed {
        ProverAuthed::from_traced_parts(
            self.x + rhs.x,
            self.m + rhs.m,
            self.c6_trace_token().add(rhs.c6_trace_token()),
        )
    }

    #[inline]
    pub fn sub(self, rhs: ProverAuthed) -> ProverAuthed {
        ProverAuthed::from_traced_parts(
            self.x - rhs.x,
            self.m - rhs.m,
            self.c6_trace_token().sub(rhs.c6_trace_token()),
        )
    }

    /// Scale by a public scalar (Mac.lean `Valid.smul`).
    #[inline]
    pub fn scale(self, c: Fp2) -> ProverAuthed {
        ProverAuthed::from_traced_parts(self.x * c, self.m * c, self.c6_trace_token().scale(c))
    }
}

impl ProverSubAuthed {
    #[inline]
    pub const fn new(x: Fp, m: Fp2) -> ProverSubAuthed {
        Self::from_traced_parts(x, m, C6TraceToken::untracked())
    }

    #[inline]
    pub(crate) const fn from_traced_parts(x: Fp, m: Fp2, _trace: C6TraceToken) -> ProverSubAuthed {
        ProverSubAuthed {
            x,
            m,
            #[cfg(feature = "c6-trace")]
            trace: _trace,
        }
    }

    #[inline]
    pub fn c6_trace_token(self) -> C6TraceToken {
        #[cfg(feature = "c6-trace")]
        {
            self.trace
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            C6TraceToken::untracked()
        }
    }

    /// Embed into the full field (Subfield.lean `SubAuthed.toAuthed`).
    #[inline]
    pub fn embed(self) -> ProverAuthed {
        ProverAuthed::from_traced_parts(Fp2::from_base(self.x), self.m, self.c6_trace_token())
    }
}

impl VerifierKey {
    pub const ZERO: VerifierKey = VerifierKey { k: Fp2::ZERO };

    /// Public constant: `k = Δ·c` (tag 0 on the prover side).
    #[inline]
    pub fn from_public(c: Fp2, delta: Fp2) -> VerifierKey {
        VerifierKey { k: delta * c }
    }

    #[inline]
    pub fn add(self, rhs: VerifierKey) -> VerifierKey {
        VerifierKey { k: self.k + rhs.k }
    }

    #[inline]
    pub fn sub(self, rhs: VerifierKey) -> VerifierKey {
        VerifierKey { k: self.k - rhs.k }
    }

    #[inline]
    pub fn scale(self, c: Fp2) -> VerifierKey {
        VerifierKey { k: self.k * c }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Test-only view of both halves, for asserting the Lean `Valid` invariant.
    pub struct BothSides {
        pub p: ProverAuthed,
        pub k: VerifierKey,
    }

    impl BothSides {
        pub fn valid(&self, delta: Fp2) -> bool {
            self.k.k == self.p.m + delta * self.p.x
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::BothSides;
    use super::*;
    use rand::{Rng, SeedableRng};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
    }

    #[cfg(not(feature = "c6-trace"))]
    #[test]
    fn ordinary_authenticated_value_layouts_remain_pinned() {
        assert_eq!(std::mem::size_of::<ProverAuthed>(), 32);
        assert_eq!(std::mem::size_of::<ProverSubAuthed>(), 24);
        assert_eq!(std::mem::size_of::<VerifierKey>(), 16);
    }

    fn rand_authed(rng: &mut impl Rng, delta: Fp2) -> BothSides {
        let x = rand_fp2(rng);
        let m = rand_fp2(rng);
        BothSides { p: ProverAuthed::new(x, m), k: VerifierKey { k: m + delta * x } }
    }

    #[test]
    fn linear_ops_preserve_valid() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let delta = rand_fp2(&mut rng);
        for _ in 0..200 {
            let a = rand_authed(&mut rng, delta);
            let b = rand_authed(&mut rng, delta);
            let c = rand_fp2(&mut rng);
            assert!(a.valid(delta) && b.valid(delta));
            let sum = BothSides { p: a.p.add(b.p), k: a.k.add(b.k) };
            let dif = BothSides { p: a.p.sub(b.p), k: a.k.sub(b.k) };
            let scl = BothSides { p: a.p.scale(c), k: a.k.scale(c) };
            let pubc = BothSides {
                p: ProverAuthed::from_public(c),
                k: VerifierKey::from_public(c, delta),
            };
            assert!(sum.valid(delta) && dif.valid(delta) && scl.valid(delta) && pubc.valid(delta));
        }
    }

    #[test]
    fn subfield_embed_preserves_valid() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(12);
        let delta = rand_fp2(&mut rng);
        for _ in 0..200 {
            let x = Fp::from_i64(rng.gen_range(-32768i64..32768));
            let m = rand_fp2(&mut rng);
            let k = VerifierKey { k: m + delta.mul_base(x) };
            let bs = BothSides { p: ProverSubAuthed::new(x, m).embed(), k };
            assert!(bs.valid(delta));
        }
    }
}

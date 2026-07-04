//! Mock-PCG correlation streams (P0 decision 4): both parties expand the same
//! ChaCha seed deterministically; `Δ` exists only in `VerifierCtx`. Every
//! consumption is counted, indices are domain-separated and one-time-use
//! (M4/M6 discipline: a domain drawn twice is a protocol bug, so it panics).
//!
//! Stream layout for a base domain `dom` (top two bits of `dom` reserved):
//! * subfield correlations (M5): mask `r ∈ F_p` from `stream(dom).next_fp()`
//!   — byte-compatible with the P1 GEMM epilogue — and tag `m_r ∈ E` from
//!   `stream(dom | TAG_BIT).next_fp2()`;
//! * full-field correlations (masks for ZeroBatch / round coefficients):
//!   value `x ∈ E` from `stream(dom | FULL_BIT).next_fp2()`, tag from
//!   `stream(dom | FULL_BIT | TAG_BIT).next_fp2()`.

use std::collections::HashMap;
use volta_field::{Fp, Fp2, FpStream};

pub const TAG_BIT: u64 = 1 << 63;
pub const FULL_BIT: u64 = 1 << 62;

/// Domain-separated correlation index. Packs to the P1 GEMM convention
/// `(tensor_tag << 32) | row` with `tensor_tag = session·2^24 | layer·2^16 |
/// head·2^8 | tensor`; the top two bits of `tensor_tag` must stay clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CorrIndex {
    pub session: u8,
    pub layer: u8,
    pub head: u8,
    pub tensor: u8,
    /// Row / position within the tensor stream.
    pub row: u32,
}

impl CorrIndex {
    #[inline]
    pub fn tensor_tag(&self) -> u32 {
        // Top three domain bits are reserved (TAG_BIT, FULL_BIT, ledger shadow).
        assert!(self.session < 0x20, "top three tag bits reserved");
        ((self.session as u32) << 24)
            | ((self.layer as u32) << 16)
            | ((self.head as u32) << 8)
            | self.tensor as u32
    }

    #[inline]
    pub fn domain(&self) -> u64 {
        ((self.tensor_tag() as u64) << 32) | self.row as u64
    }
}

/// Prover half of a subfield correlation: `(r, m_r)`, `k_r = m_r + Δ·r` on V's side.
#[derive(Clone, Copy, Debug)]
pub struct SubCorr {
    pub r: Fp,
    pub m: Fp2,
}

/// Prover half of a full-field correlation (fresh mask): `(x, m)`, `k = m + Δ·x`.
#[derive(Clone, Copy, Debug)]
pub struct FullCorr {
    pub x: Fp2,
    pub m: Fp2,
}

/// Consumption counters — compared against the P0 analytic budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CorrCounters {
    pub sub_corrs: u64,
    pub full_corrs: u64,
    /// Domains opened (one-time indices actually used).
    pub domains: u64,
}

/// Shared one-time-use ledger: domain → number of correlations drawn there.
/// Sequential draws only; re-opening a domain panics (M4: never reuse).
#[derive(Default)]
struct DomainLedger {
    consumed: HashMap<u64, u64>,
}

impl DomainLedger {
    fn open(&mut self, dom: u64, n: usize) {
        assert!(dom & (TAG_BIT | FULL_BIT) == 0, "reserved domain bits set");
        let prev = self.consumed.insert(dom, n as u64);
        assert!(prev.is_none(), "correlation domain {dom:#x} reused (one-time-use violation)");
    }
}

/// Prover-side correlation expander.
pub struct CorrelationStream {
    seed: [u8; 32],
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl CorrelationStream {
    pub fn new(seed: [u8; 32]) -> CorrelationStream {
        CorrelationStream { seed, ledger: DomainLedger::default(), counters: CorrCounters::default() }
    }

    /// Draw `n` subfield correlations at `dom`. One-shot per domain.
    pub fn draw_subs(&mut self, dom: u64, n: usize) -> Vec<SubCorr> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        let mut rs = FpStream::domain_separated(self.seed, dom);
        let mut ms = FpStream::domain_separated(self.seed, dom | TAG_BIT);
        (0..n).map(|_| SubCorr { r: rs.next_fp(), m: ms.next_fp2() }).collect()
    }

    /// Draw the mask stream only (what the P1 GEMM epilogue consumes); the
    /// tags are expanded lazily by `draw_sub_tags` at opening time (ledger
    /// deviation 2026-07-03: that cost is charged to P3's prover budget).
    pub fn draw_sub_masks(&mut self, dom: u64, n: usize) -> Vec<Fp> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        let mut rs = FpStream::domain_separated(self.seed, dom);
        (0..n).map(|_| rs.next_fp()).collect()
    }

    /// Lazy tag expansion for a domain already opened via `draw_sub_masks`.
    pub fn draw_sub_tags(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let drawn = self.ledger.consumed.get(&dom).copied();
        assert_eq!(drawn, Some(n as u64), "tag expansion must match the mask draw at {dom:#x}");
        let mut ms = FpStream::domain_separated(self.seed, dom | TAG_BIT);
        (0..n).map(|_| ms.next_fp2()).collect()
    }

    /// Draw `n` full-field correlations at `dom`. One-shot per domain.
    pub fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        let mut xs = FpStream::domain_separated(self.seed, dom | FULL_BIT);
        let mut ms = FpStream::domain_separated(self.seed, dom | FULL_BIT | TAG_BIT);
        (0..n).map(|_| FullCorr { x: xs.next_fp2(), m: ms.next_fp2() }).collect()
    }
}

/// Full-domain shadow key in the ledger so `draw_subs(dom)` and
/// `draw_fulls(dom)` are tracked as distinct one-time indices (the underlying
/// ChaCha streams are already separated by `FULL_BIT`).
const FULL_BIT_SHADOW: u64 = 1 << 61;

/// Verifier-side context: `Δ`, the shared seed, and its own mirror counters.
pub struct VerifierCtx {
    pub delta: Fp2,
    seed: [u8; 32],
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl VerifierCtx {
    pub fn new(seed: [u8; 32], delta: Fp2) -> VerifierCtx {
        VerifierCtx { delta, seed, ledger: DomainLedger::default(), counters: CorrCounters::default() }
    }

    /// Keys `k_r = m_r + Δ·r` for `n` subfield correlations at `dom`.
    pub fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        let mut rs = FpStream::domain_separated(self.seed, dom);
        let mut ms = FpStream::domain_separated(self.seed, dom | TAG_BIT);
        (0..n).map(|_| ms.next_fp2() + self.delta.mul_base(rs.next_fp())).collect()
    }

    /// Keys `k = m + Δ·x` for `n` full-field correlations at `dom`.
    pub fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        let mut xs = FpStream::domain_separated(self.seed, dom | FULL_BIT);
        let mut ms = FpStream::domain_separated(self.seed, dom | FULL_BIT | TAG_BIT);
        (0..n).map(|_| ms.next_fp2() + self.delta * xs.next_fp2()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corr_index_matches_p1_packing() {
        let idx = CorrIndex { session: 0, layer: 0, head: 0, tensor: 3, row: 5 };
        assert_eq!(idx.domain(), (3u64 << 32) | 5); // P1 epilogue: (tensor_tag<<32)|row
    }

    #[test]
    fn prover_and_verifier_expansions_are_correlated() {
        let seed = [9u8; 32];
        let delta = Fp2::new(Fp::new(1234567), Fp::new(89));
        let mut p = CorrelationStream::new(seed);
        let mut v = VerifierCtx::new(seed, delta);
        let subs = p.draw_subs(77, 32);
        let keys = v.expand_sub_keys(77, 32);
        for (s, k) in subs.iter().zip(&keys) {
            assert_eq!(*k, s.m + delta.mul_base(s.r)); // k_r = m_r + Δ·r
        }
        let fulls = p.draw_fulls(77, 8);
        let fkeys = v.expand_full_keys(77, 8);
        for (f, k) in fulls.iter().zip(&fkeys) {
            assert_eq!(*k, f.m + delta * f.x);
        }
        assert_eq!(p.counters, v.counters);
        assert_eq!(p.counters.sub_corrs, 32);
        assert_eq!(p.counters.full_corrs, 8);
    }

    #[test]
    fn lazy_tags_match_eager_draw() {
        let seed = [3u8; 32];
        let mut p1 = CorrelationStream::new(seed);
        let mut p2 = CorrelationStream::new(seed);
        let eager = p1.draw_subs(5, 16);
        let masks = p2.draw_sub_masks(5, 16);
        let tags = p2.draw_sub_tags(5, 16);
        for ((e, r), m) in eager.iter().zip(&masks).zip(&tags) {
            assert_eq!(e.r, *r);
            assert_eq!(e.m, *m);
        }
    }

    #[test]
    #[should_panic(expected = "one-time-use violation")]
    fn counter_no_reuse_panics() {
        let mut p = CorrelationStream::new([1u8; 32]);
        let _ = p.draw_subs(42, 4);
        let _ = p.draw_subs(42, 4);
    }
}

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
use volta_pcg::{FullVole, ProverPcgPool, SubVole, VerifierPcgPool};

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
    backend: ProverBackend,
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl CorrelationStream {
    pub fn new(seed: [u8; 32]) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Mock { seed },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn from_pcg_pool(pool: ProverPcgPool) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Pooled(PooledProver::new(pool)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            ProverBackend::Mock { .. } => None,
            ProverBackend::Pooled(p) => Some(p.allocation_digest_hex()),
        }
    }

    /// Draw `n` subfield correlations at `dom`. One-shot per domain.
    pub fn draw_subs(&mut self, dom: u64, n: usize) -> Vec<SubCorr> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut rs = FpStream::domain_separated(*seed, dom);
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| SubCorr { r: rs.next_fp(), m: ms.next_fp2() }).collect()
            }
            ProverBackend::Pooled(p) => p.draw_subs(dom, n),
        }
    }

    /// Draw the mask stream only (what the P1 GEMM epilogue consumes); the
    /// tags are expanded lazily by `draw_sub_tags` at opening time (ledger
    /// deviation 2026-07-03: that cost is charged to P3's prover budget).
    pub fn draw_sub_masks(&mut self, dom: u64, n: usize) -> Vec<Fp> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut rs = FpStream::domain_separated(*seed, dom);
                (0..n).map(|_| rs.next_fp()).collect()
            }
            ProverBackend::Pooled(p) => p.draw_sub_masks(dom, n),
        }
    }

    /// Lazy tag expansion for a domain already opened via `draw_sub_masks`.
    pub fn draw_sub_tags(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let drawn = self.ledger.consumed.get(&dom).copied();
        assert_eq!(drawn, Some(n as u64), "tag expansion must match the mask draw at {dom:#x}");
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2()).collect()
            }
            ProverBackend::Pooled(p) => p.draw_sub_tags(dom, n),
        }
    }

    /// Draw `n` full-field correlations at `dom`. One-shot per domain.
    pub fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n).map(|_| FullCorr { x: xs.next_fp2(), m: ms.next_fp2() }).collect()
            }
            ProverBackend::Pooled(p) => p.draw_fulls(dom, n),
        }
    }
}

/// Full-domain shadow key in the ledger so `draw_subs(dom)` and
/// `draw_fulls(dom)` are tracked as distinct one-time indices (the underlying
/// ChaCha streams are already separated by `FULL_BIT`).
const FULL_BIT_SHADOW: u64 = 1 << 61;

/// Verifier-side context: `Δ`, the shared seed, and its own mirror counters.
pub struct VerifierCtx {
    pub delta: Fp2,
    backend: VerifierBackend,
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl VerifierCtx {
    pub fn new(seed: [u8; 32], delta: Fp2) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Mock { seed },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn from_pcg_pool(delta: Fp2, pool: VerifierPcgPool) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Pooled(PooledVerifier::new(pool)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            VerifierBackend::Mock { .. } => None,
            VerifierBackend::Pooled(v) => Some(v.allocation_digest_hex()),
        }
    }

    /// Keys `k_r = m_r + Δ·r` for `n` subfield correlations at `dom`.
    pub fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            VerifierBackend::Mock { seed } => {
                let mut rs = FpStream::domain_separated(*seed, dom);
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta.mul_base(rs.next_fp())).collect()
            }
            VerifierBackend::Pooled(v) => v.expand_sub_keys(dom, n),
        }
    }

    /// Keys `k = m + Δ·x` for `n` full-field correlations at `dom`.
    pub fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            VerifierBackend::Mock { seed } => {
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta * xs.next_fp2()).collect()
            }
            VerifierBackend::Pooled(v) => v.expand_full_keys(dom, n),
        }
    }
}

enum ProverBackend {
    Mock { seed: [u8; 32] },
    Pooled(PooledProver),
}

enum VerifierBackend {
    Mock { seed: [u8; 32] },
    Pooled(PooledVerifier),
}

struct PooledProver {
    subs: Vec<SubVole>,
    fulls: Vec<FullVole>,
    next_sub: usize,
    next_full: usize,
    sub_domains: HashMap<u64, (usize, usize)>,
    hasher: blake3::Hasher,
}

impl PooledProver {
    fn new(pool: ProverPcgPool) -> PooledProver {
        PooledProver {
            subs: pool.subs,
            fulls: pool.fulls,
            next_sub: 0,
            next_full: 0,
            sub_domains: HashMap::new(),
            hasher: blake3::Hasher::new(),
        }
    }

    fn draw_subs(&mut self, dom: u64, n: usize) -> Vec<SubCorr> {
        let off = self.take_sub_domain(dom, n);
        self.subs[off..off + n].iter().map(|s| SubCorr { r: s.r, m: s.m }).collect()
    }

    fn draw_sub_masks(&mut self, dom: u64, n: usize) -> Vec<Fp> {
        let off = self.take_sub_domain(dom, n);
        self.subs[off..off + n].iter().map(|s| s.r).collect()
    }

    fn draw_sub_tags(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let Some((off, drawn)) = self.sub_domains.get(&dom).copied() else {
            panic!("pooled tag expansion before mask draw at {dom:#x}");
        };
        assert_eq!(drawn, n, "pooled tag expansion length mismatch at {dom:#x}");
        self.subs[off..off + n].iter().map(|s| s.m).collect()
    }

    fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        assert!(self.next_full + n <= self.fulls.len(), "pooled full correlation underflow");
        let off = self.next_full;
        self.next_full += n;
        record_alloc(&mut self.hasher, b"full", dom, off, n);
        self.fulls[off..off + n].iter().map(|f| FullCorr { x: f.x, m: f.m }).collect()
    }

    fn take_sub_domain(&mut self, dom: u64, n: usize) -> usize {
        assert!(self.next_sub + n <= self.subs.len(), "pooled sub correlation underflow");
        let off = self.next_sub;
        self.next_sub += n;
        let prev = self.sub_domains.insert(dom, (off, n));
        assert!(prev.is_none(), "pooled sub domain {dom:#x} allocated twice");
        record_alloc(&mut self.hasher, b"sub", dom, off, n);
        off
    }

    fn allocation_digest_hex(&self) -> String {
        self.hasher.clone().finalize().to_hex().to_string()
    }
}

struct PooledVerifier {
    sub_keys: Vec<Fp2>,
    full_keys: Vec<Fp2>,
    next_sub: usize,
    next_full: usize,
    hasher: blake3::Hasher,
}

impl PooledVerifier {
    fn new(pool: VerifierPcgPool) -> PooledVerifier {
        PooledVerifier {
            sub_keys: pool.sub_keys,
            full_keys: pool.full_keys,
            next_sub: 0,
            next_full: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        assert!(self.next_sub + n <= self.sub_keys.len(), "pooled sub-key underflow");
        let off = self.next_sub;
        self.next_sub += n;
        record_alloc(&mut self.hasher, b"sub", dom, off, n);
        self.sub_keys[off..off + n].to_vec()
    }

    fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        assert!(self.next_full + n <= self.full_keys.len(), "pooled full-key underflow");
        let off = self.next_full;
        self.next_full += n;
        record_alloc(&mut self.hasher, b"full", dom, off, n);
        self.full_keys[off..off + n].to_vec()
    }

    fn allocation_digest_hex(&self) -> String {
        self.hasher.clone().finalize().to_hex().to_string()
    }
}

fn record_alloc(h: &mut blake3::Hasher, kind: &[u8], dom: u64, off: usize, n: usize) {
    h.update(kind);
    h.update(&dom.to_le_bytes());
    h.update(&(off as u64).to_le_bytes());
    h.update(&(n as u64).to_le_bytes());
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

    #[test]
    fn pooled_backend_preserves_mac_relation_and_allocation_hash() {
        let seed = [0x44u8; 32];
        let delta = Fp2::new(Fp::new(7), Fp::new(11));
        let params = volta_pcg::PhaseAParams::tiny_for_test(12 + 2 * 3);
        let pool = volta_pcg::expand_phase_a(seed, delta, 12, 3, params);
        let mut p = CorrelationStream::from_pcg_pool(pool.prover);
        let mut v = VerifierCtx::from_pcg_pool(delta, pool.verifier);

        let masks = p.draw_sub_masks(0x10, 5);
        let tags = p.draw_sub_tags(0x10, 5);
        let keys = v.expand_sub_keys(0x10, 5);
        for ((r, m), k) in masks.iter().zip(&tags).zip(&keys) {
            assert_eq!(*k, *m + delta.mul_base(*r));
        }

        let subs = p.draw_subs(0x11, 7);
        let sub_keys = v.expand_sub_keys(0x11, 7);
        for (s, k) in subs.iter().zip(&sub_keys) {
            assert_eq!(*k, s.m + delta.mul_base(s.r));
        }

        let fulls = p.draw_fulls(0x12, 3);
        let full_keys = v.expand_full_keys(0x12, 3);
        for (f, k) in fulls.iter().zip(&full_keys) {
            assert_eq!(*k, f.m + delta * f.x);
        }
        assert_eq!(p.counters, v.counters);
        assert_eq!(p.allocation_digest_hex(), v.allocation_digest_hex());
    }
}

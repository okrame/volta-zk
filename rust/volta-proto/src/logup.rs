//! P4 LogUp: fraction-tree GKR (Papini–Haböck), superseding the P2.5 spike
//! (`volta-bench::logup`) with the pre-registered iteration plan applied:
//!
//! 1. **Gruen eq-split** — the eq factor is pulled out of the round message:
//!    g_j(X) = ℓ_j(X)·h_j(X) with ℓ_j(X) = eq(point_j, X) public, so the
//!    prover sends the degree-2 [h(0), h(2)] instead of degree-3 evals and
//!    never folds an eq table. Suffix eq tables S_j (over point[j+1..]) are
//!    precomputed once per layer; the bound prefix is a running scalar.
//! 2. **Base-field leaf structure** — leaf denominators α−f have constant
//!    imaginary part α₁, so the first tree combine and the leaf layer's first
//!    sumcheck round run mostly in F_p. On the lookup side p ≡ 1 identically
//!    (the all-ones MLE is constant), so the whole leaf-layer sumcheck skips
//!    the p vectors and their folds.
//! 3. **rayon** over round evaluations, folds, and tree combines.
//!
//! E-mult accounting: every multiplication is counted in `Counters`, bulk
//! per loop (formulas sit next to the code they mirror; serial == parallel
//! by construction, asserted in tests). Convention unchanged from P2.5:
//! 1 Fp2 mult = 5 base mults, Fp2×Fp = 2, Fp×Fp = 1.
//!
//! MLE variable order is LSB-first throughout (node y's children are 2y and
//! 2y+1), as in `mle` and the spike.

use crate::mle::lagrange3;
use rayon::prelude::*;
use std::time::Instant;
use volta_accel::{
    AccelError, Backend, BackendKind, DeviceBuffer, DeviceSlice, Fp2Repr, Operation,
};
use volta_field::{Fp, Fp2, FpStream, W};

/// Below this vector length the round loops stay serial.
pub const PAR_THRESHOLD: usize = 1 << 12;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub fp2_mults: u64,
    pub base_mults: u64,
}

impl Counters {
    #[inline]
    fn mul(&mut self, a: Fp2, b: Fp2) -> Fp2 {
        self.fp2_mults += 1;
        a * b
    }

    #[inline]
    fn bulk(&mut self, fp2: u64, base: u64) {
        self.fp2_mults += fp2;
        self.base_mults += base;
    }

    /// Total in full-Fp2-mult equivalents (1 Fp2 mul = 5 base mults).
    pub fn emult_equiv(&self) -> f64 {
        self.fp2_mults as f64 + self.base_mults as f64 / 5.0
    }
}

#[inline]
fn neg(a: Fp2) -> Fp2 {
    Fp2::ZERO - a
}

/// Leaf numerators: all-ones (lookup side) or −multiplicities (table side).
pub enum LeafP<'a> {
    Ones,
    NegMult(&'a [u32]),
}

/// Leaf denominators α − f_i in structured form: real parts `a_i = α₀ − f_i`
/// with shared constant imaginary part α₁. Built mul-free by `lift_q`.
pub struct LeafQ {
    pub a: Vec<Fp>,
    pub alpha1: Fp,
}

impl LeafQ {
    #[inline]
    fn get(&self, i: usize) -> Fp2 {
        Fp2::new(self.a[i], self.alpha1)
    }
}

/// α − f_i for i16 values (no multiplications).
pub fn lift_q(values: &[i16], alpha: Fp2) -> LeafQ {
    LeafQ {
        a: values.iter().map(|&v| alpha.c0 - Fp::from_i64(v as i64)).collect(),
        alpha1: alpha.c1,
    }
}

/// α − f_i for pre-lifted base-field leaf values.
pub fn lift_q_fp(values: &[Fp], alpha: Fp2) -> LeafQ {
    LeafQ { a: values.iter().map(|&v| alpha.c0 - v).collect(), alpha1: alpha.c1 }
}

/// One layer: Gruen round messages [h(0), h(2)] plus the four split claims.
#[derive(Debug, PartialEq, Eq)]
pub struct LayerProof {
    pub rounds: Vec<[Fp2; 2]>,
    pub p0: Fp2,
    pub p1: Fp2,
    pub q0: Fp2,
    pub q1: Fp2,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FracProof {
    pub root_p: Fp2,
    pub root_q: Fp2,
    pub layers: Vec<LayerProof>,
}

impl FracProof {
    /// Transcript bytes: 16 B per Fp2 message.
    pub fn bytes(&self) -> u64 {
        32 + self.layers.iter().map(|l| 16 * (2 * l.rounds.len() as u64 + 4)).sum::<u64>()
    }
}

// ---------------------------------------------------------------------------
// Tree build
// ---------------------------------------------------------------------------

/// Internal layers only (levels 0..depth−1); leaves stay in `LeafQ`/`LeafP`.
struct Tree {
    p: Vec<Vec<Fp2>>,
    q: Vec<Vec<Fp2>>,
    depth: usize,
}

fn build_tree(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    ctr: &mut Counters,
    backend: Option<&mut Backend>,
) -> Tree {
    if let Some(backend) = backend {
        if !backend.is_cpu() {
            assert_eq!(
                backend.kind(),
                BackendKind::CudaHybrid,
                "staged LogUp is not the cuda-resident gate"
            );
            let mult = match leaf_p {
                LeafP::Ones => None,
                LeafP::NegMult(m) => Some(*m),
            };
            let (p, q) = backend
                .logup_tree(&leaf_q.a, leaf_q.alpha1, mult)
                .unwrap_or_else(|e| panic!("CUDA LogUp tree failed: {e}"));
            let half = leaf_q.a.len() / 2;
            ctr.bulk(0, (if mult.is_some() { 5 } else { 2 }) * half as u64);
            let mut len = half;
            while len > 1 {
                len /= 2;
                ctr.bulk(3 * len as u64, 0);
            }
            return Tree { depth: p.len(), p, q };
        }
    }
    build_tree_cpu(leaf_p, leaf_q, ctr)
}

fn build_tree_cpu(leaf_p: &LeafP, leaf_q: &LeafQ, ctr: &mut Counters) -> Tree {
    let n = leaf_q.a.len();
    assert!(n.is_power_of_two() && n >= 2);
    let depth = n.trailing_zeros() as usize;
    let half = n / 2;
    let a1 = leaf_q.alpha1;
    let w7a1sq = Fp::new(W) * a1 * a1; // shared constant, not counted

    // First combine in structured form: (a,α₁)·(b,α₁) = (ab + 7α₁², (a+b)α₁).
    // q: 2 base mults/pair. p Ones: adds only. p NegMult: 3 base mults/pair.
    let q_first = |i: usize| {
        let (a, b) = (leaf_q.a[2 * i], leaf_q.a[2 * i + 1]);
        Fp2::new(a * b + w7a1sq, (a + b) * a1)
    };
    let (p_cur, q_cur): (Vec<Fp2>, Vec<Fp2>) = match leaf_p {
        LeafP::Ones => {
            ctr.bulk(0, 2 * half as u64);
            let pq = |i: usize| {
                let s = leaf_q.a[2 * i] + leaf_q.a[2 * i + 1];
                (Fp2::new(s, a1 + a1), q_first(i))
            };
            if half >= PAR_THRESHOLD {
                (0..half).into_par_iter().map(pq).unzip()
            } else {
                (0..half).map(pq).unzip()
            }
        }
        LeafP::NegMult(mult) => {
            assert_eq!(mult.len(), n);
            ctr.bulk(0, 5 * half as u64);
            let pq = |i: usize| {
                let (a, b) = (leaf_q.a[2 * i], leaf_q.a[2 * i + 1]);
                let (ma, mb) = (Fp::new(mult[2 * i] as u64), Fp::new(mult[2 * i + 1] as u64));
                let p = Fp2::new(-(ma * b + mb * a), -((ma + mb) * a1));
                (p, q_first(i))
            };
            if half >= PAR_THRESHOLD {
                (0..half).into_par_iter().map(pq).unzip()
            } else {
                (0..half).map(pq).unzip()
            }
        }
    };

    let mut p_layers = vec![Vec::new(); depth];
    let mut q_layers = vec![Vec::new(); depth];
    let mut p_cur = p_cur;
    let mut q_cur = q_cur;
    // General combines: (p₁q₂+p₂q₁, q₁q₂) — 3 fp2 mults/pair.
    for k in (1..depth).rev() {
        let s = p_cur.len() / 2;
        ctr.bulk(3 * s as u64, 0);
        let comb = |i: usize| {
            let (pa, pb) = (p_cur[2 * i], p_cur[2 * i + 1]);
            let (qa, qb) = (q_cur[2 * i], q_cur[2 * i + 1]);
            (pa * qb + pb * qa, qa * qb)
        };
        let (p_next, q_next): (Vec<Fp2>, Vec<Fp2>) = if s >= PAR_THRESHOLD {
            (0..s).into_par_iter().map(comb).unzip()
        } else {
            (0..s).map(comb).unzip()
        };
        p_layers[k] = std::mem::replace(&mut p_cur, p_next);
        q_layers[k] = std::mem::replace(&mut q_cur, q_next);
    }
    p_layers[0] = p_cur;
    q_layers[0] = q_cur;
    Tree { p: p_layers, q: q_layers, depth }
}

// ---------------------------------------------------------------------------
// Gruen layer sumcheck
// ---------------------------------------------------------------------------

/// Suffix eq tables: S[j] is eq(point[j+1..], ·) over 2^(l−1−j) entries,
/// LSB-first. Σ 2^k ≈ 2^(l−1) fp2 mults total.
fn suffix_eq_tables(point: &[Fp2], ctr: &mut Counters) -> Vec<Vec<Fp2>> {
    let l = point.len();
    let mut tables = vec![Vec::new(); l];
    let mut cur = vec![Fp2::ONE];
    for j in (0..l).rev() {
        tables[j] = cur.clone();
        if j > 0 {
            ctr.bulk(cur.len() as u64, 0);
            let pj = point[j];
            let mut next = Vec::with_capacity(cur.len() * 2);
            for &v in &cur {
                let v1 = v * pj;
                next.push(v - v1);
                next.push(v1);
            }
            cur = next;
        }
    }
    tables
}

/// Linear evaluation at t ∈ {0, 2} from (v(0), v(1)) — adds only.
#[inline]
fn at02(v0: Fp2, v1: Fp2) -> (Fp2, Fp2) {
    let d = v1 - v0;
    (v0, v0 + d + d)
}

#[inline]
fn at02_fp(v0: Fp, v1: Fp) -> (Fp, Fp) {
    let d = v1 - v0;
    (v0, v0 + d + d)
}

/// Linear evaluation at t ∈ {0, 2, 3} — adds only.
#[inline]
fn at023(v0: Fp2, v1: Fp2) -> (Fp2, Fp2, Fp2) {
    let d = v1 - v0;
    let v2 = v0 + d + d;
    (v0, v2, v2 + d)
}

#[inline]
fn at023_fp(v0: Fp, v1: Fp) -> (Fp, Fp, Fp) {
    let d = v1 - v0;
    let v2 = v0 + d + d;
    (v0, v2, v2 + d)
}

/// Cubic Lagrange weights at `r` for nodes {0, 1, 2, 3} (public scalars).
pub fn lagrange4(r: Fp2) -> [Fp2; 4] {
    let six_inv = Fp::new(6).inv();
    let two_inv = Fp::new(2).inv();
    let m: [Fp2; 4] = core::array::from_fn(|k| r - Fp2::from_base(Fp::new(k as u64)));
    [
        (m[1] * m[2] * m[3]).mul_base(six_inv.neg()),
        (m[0] * m[2] * m[3]).mul_base(two_inv),
        (m[0] * m[1] * m[3]).mul_base(two_inv.neg()),
        (m[0] * m[1] * m[2]).mul_base(six_inv),
    ]
}

/// Per-round sums Σ S[i]·(ad+bc) and Σ S[i]·cd at t ∈ {0, 2}.
#[derive(Clone, Copy, Default)]
struct RoundAcc {
    pq0: Fp2,
    pq2: Fp2,
    qq0: Fp2,
    qq2: Fp2,
}

impl RoundAcc {
    #[inline]
    fn add(mut self, o: RoundAcc) -> RoundAcc {
        self.pq0 += o.pq0;
        self.pq2 += o.pq2;
        self.qq0 += o.qq0;
        self.qq2 += o.qq2;
        self
    }
}

/// Public end-of-layer data for one folded aux claim: the verifier rebuilds
/// eq(ρ[1..], r') and the μ-weighted child factors itself; the prover's sink
/// uses them for the extended zero row.
pub struct AuxFinal {
    pub col: usize,
    pub w0: Fp2,
    pub w1: Fp2,
    pub eq_r: Fp2,
}

/// What a layer engine reports to / draws from the proof side. Keeps clear
/// and blind provers on one round engine, challenges in lockstep.
trait Sink {
    /// Root values, reported once before the first layer.
    fn root(&mut self, p: Fp2, q: Fp2);
    /// Layer start: draw λ (claim becomes λ·cp + cq on the sink's side).
    fn lambda(&mut self) -> Fp2;
    /// Round message [h(0), h(2)] for current variable `pt_j`; returns r.
    fn round(&mut self, h: [Fp2; 2], pt_j: Fp2) -> Fp2;
    /// End-of-layer split claims; returns the child-bit challenge t.
    fn splits(&mut self, s: [Fp2; 4]) -> Fp2;
    /// Aux leaf layer only: μ challenges, one per folded external claim
    /// (drawn after λ; the sink also adds Σ μ_k·v_k to its running claim).
    fn aux_mus(&mut self, claims: &[ProverAuthed]) -> Vec<Fp2> {
        let _ = claims;
        unimplemented!("aux folding requires a blind sink")
    }
    /// Degree-3 round message [g(0), g(2), g(3)] (aux leaf layer); returns r.
    fn round3(&mut self, g: [Fp2; 3], pt_j: Fp2) -> Fp2 {
        let _ = (g, pt_j);
        unimplemented!("aux folding requires a blind sink")
    }
    /// Layer splits + per-col [ṽ0, ṽ1] claims + per-claim public factors.
    fn splits_aux(&mut self, s: [Fp2; 4], cols: &[[Fp2; 2]], finals: &[AuxFinal]) -> Fp2 {
        let _ = (s, cols, finals);
        unimplemented!("aux folding requires a blind sink")
    }
}

/// General rounds `start..l` over four Fp2 vectors (upper layers, and leaf
/// layers after their specialized round 0). 10 fp2/pair-round for the evals
/// + 4 fp2/pair for the folds + 4 fp2/round for λ/prefix finalization.
#[allow(clippy::too_many_arguments)]
fn run_general_rounds(
    p0: &mut Vec<Fp2>,
    p1: &mut Vec<Fp2>,
    q0: &mut Vec<Fp2>,
    q1: &mut Vec<Fp2>,
    stables: &[Vec<Fp2>],
    point: &[Fp2],
    start: usize,
    lambda: Fp2,
    cpref: &mut Fp2,
    rprime: &mut Vec<Fp2>,
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: &mut Option<&mut Backend>,
) {
    let l = point.len();
    for j in start..l {
        let half = p0.len() / 2;
        let s = &stables[j];
        debug_assert_eq!(s.len(), half);
        ctr.bulk(10 * half as u64 + 4, 0);
        let body = |i: usize| {
            let (a0, a2) = at02(p0[2 * i], p0[2 * i + 1]);
            let (b0, b2) = at02(p1[2 * i], p1[2 * i + 1]);
            let (c0, c2) = at02(q0[2 * i], q0[2 * i + 1]);
            let (d0, d2) = at02(q1[2 * i], q1[2 * i + 1]);
            RoundAcc {
                pq0: s[i] * (a0 * d0 + b0 * c0),
                pq2: s[i] * (a2 * d2 + b2 * c2),
                qq0: s[i] * (c0 * d0),
                qq2: s[i] * (c2 * d2),
            }
        };
        let acc = if let Some(cuda) = backend.as_deref_mut().filter(|b| !b.is_cpu()) {
            let [pq0, pq2, qq0, qq2] = cuda
                .logup_general_round(p0, p1, q0, q1, s)
                .unwrap_or_else(|e| panic!("CUDA LogUp round failed: {e}"));
            RoundAcc { pq0, pq2, qq0, qq2 }
        } else if half >= PAR_THRESHOLD {
            (0..half).into_par_iter().map(body).reduce(RoundAcc::default, RoundAcc::add)
        } else {
            (0..half).map(body).fold(RoundAcc::default(), RoundAcc::add)
        };
        let h0 = *cpref * (lambda * acc.pq0 + acc.qq0);
        let h2 = *cpref * (lambda * acc.pq2 + acc.qq2);
        let r = sink.round([h0, h2], point[j]);
        ctr.bulk(4 * half as u64 + 2, 0);
        if let Some(cuda) = backend.as_deref_mut().filter(|b| !b.is_cpu()) {
            let [np0, np1, nq0, nq1] = cuda
                .logup_fold4(p0, p1, q0, q1, r)
                .unwrap_or_else(|e| panic!("CUDA LogUp fold failed: {e}"));
            *p0 = np0;
            *p1 = np1;
            *q0 = nq0;
            *q1 = nq1;
        } else {
            fold4(p0, p1, q0, q1, r, half);
        }
        // c ← c·eq(point_j, r): 2 fp2 (counted above).
        let pr = point[j] * r;
        *cpref = *cpref * (pr + pr - point[j] - r + Fp2::ONE);
        rprime.push(r);
    }
}

fn fold4(
    p0: &mut Vec<Fp2>,
    p1: &mut Vec<Fp2>,
    q0: &mut Vec<Fp2>,
    q1: &mut Vec<Fp2>,
    r: Fp2,
    half: usize,
) {
    for v in [p0, p1, q0, q1] {
        fold_vec(v, r, half);
    }
}

fn fold_vec(v: &mut Vec<Fp2>, r: Fp2, half: usize) {
    if half >= PAR_THRESHOLD {
        let next: Vec<Fp2> =
            (0..half).into_par_iter().map(|i| v[2 * i] + (v[2 * i + 1] - v[2 * i]) * r).collect();
        *v = next;
    } else {
        for i in 0..half {
            let d = v[2 * i + 1] - v[2 * i];
            v[i] = v[2 * i] + d * r;
        }
        v.truncate(half);
    }
}

/// One full layer over general Fp2 children (upper layers).
fn layer_general(
    mut p0: Vec<Fp2>,
    mut p1: Vec<Fp2>,
    mut q0: Vec<Fp2>,
    mut q1: Vec<Fp2>,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: Option<&mut Backend>,
) -> (Vec<Fp2>, [Fp2; 4]) {
    let lambda = sink.lambda();
    let stables = suffix_eq_tables(point, ctr);
    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(point.len());
    let mut backend = backend;
    run_general_rounds(
        &mut p0,
        &mut p1,
        &mut q0,
        &mut q1,
        &stables,
        point,
        0,
        lambda,
        &mut cpref,
        &mut rprime,
        sink,
        ctr,
        &mut backend,
    );
    (rprime, [p0[0], p1[0], q0[0], q1[0]])
}

/// Leaf layer, lookup side: p ≡ 1 for the whole layer (ad+bc = c+d, no p
/// vectors, no p folds). Round 0 runs on structured (Fp, α₁) leaves:
/// 4 fp2 + 4 base per pair for the evals, 4 base per pair for the q folds.
/// Rounds ≥ 1: 6 fp2/pair evals + 2 fp2/pair folds.
fn layer_leaf_ones(
    leaf_q: &LeafQ,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
) -> (Vec<Fp2>, [Fp2; 4]) {
    let lambda = sink.lambda();
    let l = point.len();
    let stables = suffix_eq_tables(point, ctr);
    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(l);
    let a1 = leaf_q.alpha1;
    let w7a1sq = Fp::new(W) * a1 * a1;

    // Handle depth-1 trees (no rounds, splits are the leaves themselves).
    let (mut q0v, mut q1v);
    if l == 0 {
        q0v = vec![leaf_q.get(0)];
        q1v = vec![leaf_q.get(1)];
    } else {
        // Round 0, fully in F_p: with q-children structured as (cr, α₁) the
        // per-t values are cd = (cr·dr + 7α₁²) + α₁·(cr+dr)·φ and
        // c+d = (cr+dr) + 2α₁·φ, so pre-scaling the eq table once per entry
        // (u₀ = α₁·s₀, u₁ = 7α₁·s₁) turns both S-mults into a handful of
        // base mults: S·(c+d) = (s₀x + 2u₁, s₁x + 2u₀) [2 base],
        // S·cd = (s₀y + u₁z, s₁y + u₀z) [4 base], plus y = cr·dr [1 base].
        // Per pair: 2 (pre-scale) + 2·(1+2+4) = 16 base mults.
        let half = 1usize << (l - 1);
        let s = &stables[0];
        let wa1 = Fp::new(W) * a1; // shared constant, not counted
        ctr.bulk(4, 16 * half as u64);
        let body = |i: usize| {
            // q0 pair = leaves (4i, 4i+2), q1 pair = leaves (4i+1, 4i+3):
            // pair index runs over y', X is the leaf-pair bit (LSB).
            let (s0, s1) = (s[i].c0, s[i].c1);
            let (u0, u1) = (a1 * s0, wa1 * s1);
            let (c0r, c2r) = at02_fp(leaf_q.a[4 * i], leaf_q.a[4 * i + 2]);
            let (d0r, d2r) = at02_fp(leaf_q.a[4 * i + 1], leaf_q.a[4 * i + 3]);
            let ssum = |x: Fp| Fp2::new(s0 * x + u1 + u1, s1 * x + u0 + u0);
            let scd = |cr: Fp, dr: Fp| {
                let (y, z) = (cr * dr + w7a1sq, cr + dr);
                Fp2::new(s0 * y + u1 * z, s1 * y + u0 * z)
            };
            RoundAcc {
                pq0: ssum(c0r + d0r),
                pq2: ssum(c2r + d2r),
                qq0: scd(c0r, d0r),
                qq2: scd(c2r, d2r),
            }
        };
        let acc = if half >= PAR_THRESHOLD {
            (0..half).into_par_iter().map(body).reduce(RoundAcc::default, RoundAcc::add)
        } else {
            (0..half).map(body).fold(RoundAcc::default(), RoundAcc::add)
        };
        let h0 = cpref * (lambda * acc.pq0 + acc.qq0);
        let h2 = cpref * (lambda * acc.pq2 + acc.qq2);
        let r = sink.round([h0, h2], point[0]);
        // Fold structured leaves: Δ is base-field ⇒ 2 base per entry, 2 vecs.
        ctr.bulk(2, 4 * half as u64);
        let foldq = |base: usize, i: usize| {
            let (lo, hi) = (leaf_q.a[4 * i + base], leaf_q.a[4 * i + 2 + base]);
            Fp2::new(lo, a1) + r.mul_base(hi - lo)
        };
        if half >= PAR_THRESHOLD {
            q0v = (0..half).into_par_iter().map(|i| foldq(0, i)).collect();
            q1v = (0..half).into_par_iter().map(|i| foldq(1, i)).collect();
        } else {
            q0v = (0..half).map(|i| foldq(0, i)).collect();
            q1v = (0..half).map(|i| foldq(1, i)).collect();
        }
        let pr = point[0] * r;
        cpref = cpref * (pr + pr - point[0] - r + Fp2::ONE);
        rprime.push(r);

        // Rounds ≥ 1: p ≡ 1, general q. 6 fp2/pair evals + 2 fp2/pair folds.
        for j in 1..l {
            let half = q0v.len() / 2;
            let s = &stables[j];
            ctr.bulk(6 * half as u64 + 4, 0);
            let body = |i: usize| {
                let (c0, c2) = at02(q0v[2 * i], q0v[2 * i + 1]);
                let (d0, d2) = at02(q1v[2 * i], q1v[2 * i + 1]);
                RoundAcc {
                    pq0: s[i] * (c0 + d0),
                    pq2: s[i] * (c2 + d2),
                    qq0: s[i] * (c0 * d0),
                    qq2: s[i] * (c2 * d2),
                }
            };
            let acc = if half >= PAR_THRESHOLD {
                (0..half).into_par_iter().map(body).reduce(RoundAcc::default, RoundAcc::add)
            } else {
                (0..half).map(body).fold(RoundAcc::default(), RoundAcc::add)
            };
            let h0 = cpref * (lambda * acc.pq0 + acc.qq0);
            let h2 = cpref * (lambda * acc.pq2 + acc.qq2);
            let r = sink.round([h0, h2], point[j]);
            ctr.bulk(2 * half as u64 + 2, 0);
            fold_vec(&mut q0v, r, half);
            fold_vec(&mut q1v, r, half);
            let pr = point[j] * r;
            cpref = cpref * (pr + pr - point[j] - r + Fp2::ONE);
            rprime.push(r);
        }
    }
    (rprime, [Fp2::ONE, Fp2::ONE, q0v[0], q1v[0]])
}

/// Leaf layer, table side: numerators −mult (base field) and structured q
/// in round 0, then materialized to the general path.
fn layer_leaf_negmult(
    mult: &[u32],
    leaf_q: &LeafQ,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: Option<&mut Backend>,
) -> (Vec<Fp2>, [Fp2; 4]) {
    let lambda = sink.lambda();
    let l = point.len();
    let stables = suffix_eq_tables(point, ctr);
    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(l);
    let a1 = leaf_q.alpha1;
    let w7a1sq = Fp::new(W) * a1 * a1;
    let nm = |i: usize| -Fp::new(mult[i] as u64);

    if l == 0 {
        let splits = [Fp2::from_base(nm(0)), Fp2::from_base(nm(1)), leaf_q.get(0), leaf_q.get(1)];
        return (rprime, splits);
    }

    // Round 0: p base-field, q structured. Per pair per t: ad 2 base +
    // bc 2 base + cd 2 base + 2 fp2 ⇒ ×2 t = 12 base + 4 fp2; folds 8 base.
    let half = 1usize << (l - 1);
    let s = &stables[0];
    ctr.bulk(4 * half as u64 + 4, 12 * half as u64);
    let body = |i: usize| {
        let (a0, a2) = at02_fp(nm(4 * i), nm(4 * i + 2));
        let (b0, b2) = at02_fp(nm(4 * i + 1), nm(4 * i + 3));
        let (c0r, c2r) = at02_fp(leaf_q.a[4 * i], leaf_q.a[4 * i + 2]);
        let (d0r, d2r) = at02_fp(leaf_q.a[4 * i + 1], leaf_q.a[4 * i + 3]);
        let (c0, c2) = (Fp2::new(c0r, a1), Fp2::new(c2r, a1));
        let (d0, d2) = (Fp2::new(d0r, a1), Fp2::new(d2r, a1));
        let cd0 = Fp2::new(c0r * d0r + w7a1sq, (c0r + d0r) * a1);
        let cd2 = Fp2::new(c2r * d2r + w7a1sq, (c2r + d2r) * a1);
        RoundAcc {
            pq0: s[i] * (d0.mul_base(a0) + c0.mul_base(b0)),
            pq2: s[i] * (d2.mul_base(a2) + c2.mul_base(b2)),
            qq0: s[i] * cd0,
            qq2: s[i] * cd2,
        }
    };
    let acc = if half >= PAR_THRESHOLD {
        (0..half).into_par_iter().map(body).reduce(RoundAcc::default, RoundAcc::add)
    } else {
        (0..half).map(body).fold(RoundAcc::default(), RoundAcc::add)
    };
    let h0 = cpref * (lambda * acc.pq0 + acc.qq0);
    let h2 = cpref * (lambda * acc.pq2 + acc.qq2);
    let r = sink.round([h0, h2], point[0]);
    ctr.bulk(2, 16 * half as u64);
    let fold_base = |lo: Fp, hi: Fp| Fp2::from_base(lo) + r.mul_base(hi - lo);
    let mk = |f: &dyn Fn(usize) -> Fp2| (0..half).map(f).collect::<Vec<_>>();
    let mut p0v = mk(&|i| fold_base(nm(4 * i), nm(4 * i + 2)));
    let mut p1v = mk(&|i| fold_base(nm(4 * i + 1), nm(4 * i + 3)));
    let mut q0v =
        mk(&|i| Fp2::new(leaf_q.a[4 * i], a1) + r.mul_base(leaf_q.a[4 * i + 2] - leaf_q.a[4 * i]));
    let mut q1v = mk(&|i| {
        Fp2::new(leaf_q.a[4 * i + 1], a1) + r.mul_base(leaf_q.a[4 * i + 3] - leaf_q.a[4 * i + 1])
    });
    let pr = point[0] * r;
    cpref = cpref * (pr + pr - point[0] - r + Fp2::ONE);
    rprime.push(r);

    let mut backend = backend;
    run_general_rounds(
        &mut p0v,
        &mut p1v,
        &mut q0v,
        &mut q1v,
        &stables,
        point,
        1,
        lambda,
        &mut cpref,
        &mut rprime,
        sink,
        ctr,
        &mut backend,
    );
    (rprime, [p0v[0], p1v[0], q0v[0], q1v[0]])
}

/// Leaf layer, lookup side, with aux-claim folding: degree-3 combined
/// sumcheck. The layer term keeps its Gruen accumulators and is assembled as
/// ℓ_j(t)·c_pref·(λA_t + B_t); each external claim k on column c adds
/// eq(ρ_k[1..], y')·(w0k·v0_c + w1k·v1_c)(y') with w0k = μ_k(1−ρ_k0),
/// w1k = μ_k·ρ_k0. Messages are [g(0), g(2), g(3)], g(1) = claim − g(0).
/// Returns (r', layer splits, per-col [ṽ0, ṽ1], per-claim public factors).
fn layer_leaf_ones_aux(
    leaf_q: &LeafQ,
    ax: &mut LeafAux,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
) -> (Vec<Fp2>, [Fp2; 4], Vec<[Fp2; 2]>, Vec<AuxFinal>) {
    let lambda = sink.lambda();
    let claim_vals: Vec<ProverAuthed> = ax.claims.iter().map(|c| c.value).collect();
    let mus = sink.aux_mus(&claim_vals);
    let l = point.len();
    for c in &ax.claims {
        assert_eq!(c.point.len(), l + 1, "aux claim dimension mismatch");
    }
    let stables = suffix_eq_tables(point, ctr);
    let a1 = leaf_q.alpha1;
    let w7a1sq = Fp::new(W) * a1 * a1;
    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(l);

    // Per-claim weights and (folded) eq tables over ρ[1..].
    let ws: Vec<(Fp2, Fp2)> = ax
        .claims
        .iter()
        .zip(&mus)
        .map(|(c, &mu)| (mu * (Fp2::ONE - c.point[0]), mu * c.point[0]))
        .collect();
    ctr.bulk(2 * ws.len() as u64, 0);
    let mut eqk: Vec<Vec<Fp2>> =
        ax.claims.iter().map(|c| crate::mle::eq_vec(&c.point[1..])).collect();
    ctr.bulk(eqk.iter().map(|t| t.len() as u64).sum(), 0);

    // Leaf q as working vectors: round 0 uses the structured form, later
    // rounds the general one; the aux terms are uniform across rounds.
    let n_half = 1usize << l;
    let mut q0v: Vec<Fp2> = Vec::new();
    let mut q1v: Vec<Fp2> = Vec::new();

    for j in 0..l {
        let structured = j == 0;
        let half = if structured { n_half / 2 } else { q0v.len() / 2 };
        let s = &stables[j];
        let (l0, l2, l3) = {
            let pt = point[j];
            (Fp2::ONE - pt, pt + pt + pt - Fp2::ONE, pt + pt + pt + pt + pt - Fp2::ONE - Fp2::ONE)
        };
        // Layer-term accumulators at t ∈ {0,2,3}.
        let mut acc = [Fp2::ZERO; 6]; // pq0, pq2, pq3, qq0, qq2, qq3
        if structured {
            let wa1 = Fp::new(W) * a1;
            ctr.bulk(0, 24 * half as u64);
            for i in 0..half {
                let (s0, s1) = (s[i].c0, s[i].c1);
                let (u0, u1) = (a1 * s0, wa1 * s1);
                let (c0r, c2r, c3r) = at023_fp(leaf_q.a[4 * i], leaf_q.a[4 * i + 2]);
                let (d0r, d2r, d3r) = at023_fp(leaf_q.a[4 * i + 1], leaf_q.a[4 * i + 3]);
                let ssum = |x: Fp| Fp2::new(s0 * x + u1 + u1, s1 * x + u0 + u0);
                let scd = |cr: Fp, dr: Fp| {
                    let (y, z) = (cr * dr + w7a1sq, cr + dr);
                    Fp2::new(s0 * y + u1 * z, s1 * y + u0 * z)
                };
                acc[0] += ssum(c0r + d0r);
                acc[1] += ssum(c2r + d2r);
                acc[2] += ssum(c3r + d3r);
                acc[3] += scd(c0r, d0r);
                acc[4] += scd(c2r, d2r);
                acc[5] += scd(c3r, d3r);
            }
        } else {
            ctr.bulk(9 * half as u64, 0);
            for i in 0..half {
                let (c0, c2, c3) = at023(q0v[2 * i], q0v[2 * i + 1]);
                let (d0, d2, d3) = at023(q1v[2 * i], q1v[2 * i + 1]);
                acc[0] += s[i] * (c0 + d0);
                acc[1] += s[i] * (c2 + d2);
                acc[2] += s[i] * (c3 + d3);
                acc[3] += s[i] * (c0 * d0);
                acc[4] += s[i] * (c2 * d2);
                acc[5] += s[i] * (c3 * d3);
            }
        }
        // Aux terms at t ∈ {0,2,3}.
        let mut aux_acc = [Fp2::ZERO; 3];
        for (k, cl) in ax.claims.iter().enumerate() {
            let (w0, w1) = ws[k];
            let col = &ax.cols[cl.col];
            let ek = &eqk[k];
            ctr.bulk(9 * half as u64, 0);
            for i in 0..half {
                let (v00, v02, v03) = at023(col.half0[2 * i], col.half0[2 * i + 1]);
                let (v10, v12, v13) = at023(col.half1[2 * i], col.half1[2 * i + 1]);
                let (e0, e2, e3) = at023(ek[2 * i], ek[2 * i + 1]);
                aux_acc[0] += e0 * (w0 * v00 + w1 * v10);
                aux_acc[1] += e2 * (w0 * v02 + w1 * v12);
                aux_acc[2] += e3 * (w0 * v03 + w1 * v13);
            }
        }
        let fin = |t: usize, lt: Fp2, acc: &[Fp2; 6], aux: &[Fp2; 3]| {
            lt * (cpref * (lambda * acc[t] + acc[t + 3])) + aux[t]
        };
        ctr.bulk(9, 0);
        let g =
            [fin(0, l0, &acc, &aux_acc), fin(1, l2, &acc, &aux_acc), fin(2, l3, &acc, &aux_acc)];
        let r = sink.round3(g, point[j]);

        // Folds: q (structured → general on round 0), aux cols, eq tables.
        if structured {
            ctr.bulk(2, 4 * half as u64);
            let foldq = |base: usize, i: usize| {
                let (lo, hi) = (leaf_q.a[4 * i + base], leaf_q.a[4 * i + 2 + base]);
                Fp2::new(lo, a1) + r.mul_base(hi - lo)
            };
            q0v = (0..half).map(|i| foldq(0, i)).collect();
            q1v = (0..half).map(|i| foldq(1, i)).collect();
        } else {
            ctr.bulk(2 * half as u64 + 2, 0);
            fold_vec(&mut q0v, r, half);
            fold_vec(&mut q1v, r, half);
        }
        for col in ax.cols.iter_mut() {
            ctr.bulk(2 * half as u64, 0);
            fold_vec(&mut col.half0, r, half);
            fold_vec(&mut col.half1, r, half);
        }
        for ek in eqk.iter_mut() {
            ctr.bulk(half as u64, 0);
            fold_vec(ek, r, half);
        }
        let pt = point[j];
        let pr = pt * r;
        cpref = cpref * (pr + pr - pt - r + Fp2::ONE);
        rprime.push(r);
    }

    if l == 0 {
        q0v = vec![leaf_q.get(0)];
        q1v = vec![leaf_q.get(1)];
        for col in &ax.cols {
            assert_eq!(col.half0.len(), 1);
        }
    }
    let colsp: Vec<[Fp2; 2]> = ax.cols.iter().map(|c| [c.half0[0], c.half1[0]]).collect();
    let finals: Vec<AuxFinal> = ax
        .claims
        .iter()
        .zip(&ws)
        .map(|(c, &(w0, w1))| AuxFinal {
            col: c.col,
            w0,
            w1,
            eq_r: crate::mle::eq_points(&c.point[1..], &rprime),
        })
        .collect();
    ctr.bulk(2 * (l as u64) * finals.len() as u64, 0);
    (rprime, [Fp2::ONE, Fp2::ONE, q0v[0], q1v[0]], colsp, finals)
}

// ---------------------------------------------------------------------------
// Prover engine (clear and blind share this via `Sink`)
// ---------------------------------------------------------------------------

/// Aux columns and external claims folded into the lookup side's leaf-layer
/// sumcheck (P4 wire binding). Columns are the instance's own (padded,
/// base-lifted) data columns split into even/odd halves; claims bind their
/// MLEs at external points.
pub struct LeafAuxCol {
    pub half0: Vec<Fp2>,
    pub half1: Vec<Fp2>,
}

pub struct LeafAuxClaim {
    pub col: usize,
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
}

pub struct LeafAux {
    pub cols: Vec<LeafAuxCol>,
    pub claims: Vec<LeafAuxClaim>,
}

struct ResidentAuxState<'a> {
    /// Per column: even half followed by odd half, each base-lifted to Fp2.
    columns: Option<DeviceBuffer<Fp2Repr>>,
    column_count: usize,
    claims: &'a [LeafAuxClaim],
}

/// Build aux columns from a base-lifted padded column (LSB split).
pub fn aux_col(vals: &[Fp]) -> LeafAuxCol {
    LeafAuxCol {
        half0: (0..vals.len() / 2).map(|i| Fp2::from_base(vals[2 * i])).collect(),
        half1: (0..vals.len() / 2).map(|i| Fp2::from_base(vals[2 * i + 1])).collect(),
    }
}

/// Resident upper-tree engine fed from host leaves. This is an incremental
/// bridge, not the P7 resident witness gate: the leaf layer (including aux
/// columns) still executes on the host. Internal tree nodes, upper-layer
/// round vectors, folds and suffix-equality tables never leave the device;
/// Rust receives only roots, round messages and split claims.
fn prove_engine_resident_from_host_leaves(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    aux: Option<&mut LeafAux>,
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: &mut Backend,
) -> (Fp2, Fp2, Vec<Fp2>) {
    let n = leaf_q.a.len();
    assert!(n >= 2 && n.is_power_of_two());
    let leaf_raw: Vec<u64> = leaf_q.a.iter().map(|x| x.value()).collect();
    let dleaf = backend
        .upload_new_device(&leaf_raw)
        .unwrap_or_else(|e| panic!("resident LogUp leaf upload failed: {e}"));
    let dmult = match leaf_p {
        LeafP::Ones => None,
        LeafP::NegMult(mult) => Some(
            backend
                .upload_new_device(*mult)
                .unwrap_or_else(|e| panic!("resident LogUp multiplicity upload failed: {e}")),
        ),
    };
    let resident_aux = aux.map(|ax| {
        let vector_len = n / 2;
        let mut columns_raw = Vec::with_capacity(ax.cols.len() * n);
        for col in &ax.cols {
            assert_eq!(col.half0.len(), vector_len);
            assert_eq!(col.half1.len(), vector_len);
            columns_raw.extend(col.half0.iter().copied().map(Fp2Repr::from));
            columns_raw.extend(col.half1.iter().copied().map(Fp2Repr::from));
        }
        let columns = backend
            .upload_new_device(&columns_raw)
            .unwrap_or_else(|e| panic!("resident LogUp aux-column upload failed: {e}"));
        ResidentAuxState { columns: Some(columns), column_count: ax.cols.len(), claims: &ax.claims }
    });
    let result = prove_engine_resident_from_device_leaves(
        &dleaf,
        dmult.as_ref(),
        n,
        leaf_q.alpha1,
        resident_aux,
        sink,
        ctr,
        backend,
    );
    if let Some(mult) = dmult {
        backend.free_device(mult).expect("resident LogUp multiplicity free");
    }
    backend.free_device(dleaf).expect("resident LogUp leaf free");
    result
}

#[allow(clippy::too_many_arguments)]
fn prove_engine_resident_from_device_leaves(
    dleaf: &DeviceBuffer<u64>,
    dmult: Option<&DeviceBuffer<u32>>,
    n: usize,
    alpha1: Fp,
    mut aux: Option<ResidentAuxState<'_>>,
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: &mut Backend,
) -> (Fp2, Fp2, Vec<Fp2>) {
    assert!(n >= 2 && n.is_power_of_two());
    assert_eq!(dleaf.len(), n);
    if let Some(mult) = dmult {
        assert_eq!(mult.len(), n);
    }
    assert!(aux.is_none() || dmult.is_none(), "aux folding is lookup-side only");
    let depth = n.trailing_zeros() as usize;
    let mult_ref = dmult.map(|m| (m, 0));
    let (tree_p, tree_q) = backend
        .logup_tree_device(dleaf, 0, alpha1, mult_ref, n)
        .unwrap_or_else(|e| panic!("resident LogUp tree failed: {e}"));

    let half = n / 2;
    ctr.bulk(0, (if dmult.is_some() { 5 } else { 2 }) * half as u64);
    let mut len = half;
    while len > 1 {
        len /= 2;
        ctr.bulk(3 * len as u64, 0);
    }
    let root_p: Fp2 =
        backend.download_device(&tree_p, 0, 1).expect("resident LogUp root-p download")[0].into();
    let root_q: Fp2 =
        backend.download_device(&tree_q, 0, 1).expect("resident LogUp root-q download")[0].into();
    sink.root(root_p, root_q);
    let mut point: Vec<Fp2> = Vec::new();

    for l in 0..depth {
        let leaf_layer = l + 1 == depth;
        if leaf_layer && aux.is_some() {
            let ax = aux.as_mut().unwrap();
            let (rprime, splits, colsp, finals) =
                layer_leaf_ones_aux_resident(dleaf, n, alpha1, ax, &point, sink, ctr, backend);
            let t = sink.splits_aux(splits, &colsp, &finals);
            point = std::iter::once(t).chain(rprime).collect();
            continue;
        }
        let (rprime, splits) = if leaf_layer {
            let mode = if dmult.is_some() {
                ResidentLayerCount::LeafNegMult
            } else {
                ResidentLayerCount::LeafOnes
            };
            let leaf_mult = dmult.map(|m| (m, 0));
            let (leaf_p_device, leaf_q_device) = backend
                .logup_materialize_leaves_device(dleaf, 0, alpha1, leaf_mult, n)
                .unwrap_or_else(|e| panic!("resident LogUp leaf materialization failed: {e}"));
            let result = layer_general_resident(
                &leaf_p_device,
                &leaf_q_device,
                0,
                n,
                &point,
                sink,
                ctr,
                backend,
                mode,
            );
            backend.free_device(leaf_q_device).expect("resident LogUp leaf-q free");
            backend.free_device(leaf_p_device).expect("resident LogUp leaf-p free");
            result
        } else {
            let child_len = 1usize << (l + 1);
            let child_offset = child_len - 1;
            layer_general_resident(
                &tree_p,
                &tree_q,
                child_offset,
                child_len,
                &point,
                sink,
                ctr,
                backend,
                ResidentLayerCount::General,
            )
        };
        let t = sink.splits(splits);
        point = std::iter::once(t).chain(rprime).collect();
    }
    backend.free_device(tree_q).expect("resident LogUp q-tree free");
    backend.free_device(tree_p).expect("resident LogUp p-tree free");
    (root_p, root_q, point)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn layer_leaf_ones_aux_resident(
    dleaf: &DeviceBuffer<u64>,
    n: usize,
    alpha1: Fp,
    ax: &mut ResidentAuxState<'_>,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: &mut Backend,
) -> (Vec<Fp2>, [Fp2; 4], Vec<[Fp2; 2]>, Vec<AuxFinal>) {
    let lambda = sink.lambda();
    let claim_values: Vec<ProverAuthed> = ax.claims.iter().map(|c| c.value).collect();
    let mus = sink.aux_mus(&claim_values);
    let l = point.len();
    let vector_len = n / 2;
    assert_eq!(vector_len, 1usize << l);
    for claim in ax.claims {
        assert_eq!(claim.point.len(), l + 1, "aux claim dimension mismatch");
        assert!(claim.col < ax.column_count, "aux claim column out of range");
    }

    let weights_host: Vec<(Fp2, Fp2)> = ax
        .claims
        .iter()
        .zip(&mus)
        .map(|(claim, &mu)| (mu * (Fp2::ONE - claim.point[0]), mu * claim.point[0]))
        .collect();
    ctr.bulk(2 * weights_host.len() as u64, 0);

    let mut columns = ax.columns.take().expect("resident aux columns already consumed");
    assert_eq!(columns.len(), ax.column_count * n, "resident aux-column geometry mismatch");

    let claim_count = ax.claims.len();
    let claim_points = if claim_count > 0 && l > 0 {
        let raw: Vec<Fp2Repr> = ax
            .claims
            .iter()
            .flat_map(|claim| claim.point[1..].iter().copied().map(Fp2Repr::from))
            .collect();
        Some(
            backend
                .upload_new_device(&raw)
                .unwrap_or_else(|e| panic!("resident LogUp aux-point upload failed: {e}")),
        )
    } else {
        None
    };
    let mut eq_rows = if claim_count > 0 {
        Some(
            backend
                .logup_eq_rows_device(claim_points.as_ref(), claim_count, l)
                .unwrap_or_else(|e| panic!("resident LogUp aux-eq build failed: {e}")),
        )
    } else {
        None
    };
    ctr.bulk((claim_count * vector_len) as u64, 0);

    let claim_cols = if claim_count > 0 {
        let raw: Vec<u32> = ax.claims.iter().map(|claim| claim.col as u32).collect();
        Some(
            backend
                .upload_new_device(&raw)
                .unwrap_or_else(|e| panic!("resident LogUp aux-column-id upload failed: {e}")),
        )
    } else {
        None
    };
    let weights = if claim_count > 0 {
        let raw: Vec<Fp2Repr> = weights_host
            .iter()
            .flat_map(|&(w0, w1)| [Fp2Repr::from(w0), Fp2Repr::from(w1)])
            .collect();
        Some(
            backend
                .upload_new_device(&raw)
                .unwrap_or_else(|e| panic!("resident LogUp aux-weight upload failed: {e}")),
        )
    } else {
        None
    };

    let (leaf_p_device, leaf_q_device) = backend
        .logup_materialize_leaves_device(dleaf, 0, alpha1, None, n)
        .unwrap_or_else(|e| panic!("resident LogUp aux-leaf materialization failed: {e}"));
    backend.free_device(leaf_p_device).expect("resident LogUp aux leaf-p free");
    let (mut q0, mut q1) = backend
        .fp2_deinterleave_device(&leaf_q_device, 0, vector_len)
        .unwrap_or_else(|e| panic!("resident LogUp aux q deinterleave failed: {e}"));
    backend.free_device(leaf_q_device).expect("resident LogUp aux leaf-q free");

    let point_device = if l > 0 {
        let raw: Vec<Fp2Repr> = point.iter().copied().map(Fp2Repr::from).collect();
        Some(
            backend
                .upload_new_device(&raw)
                .unwrap_or_else(|e| panic!("resident LogUp aux challenge upload failed: {e}")),
        )
    } else {
        None
    };
    let suffix = point_device.as_ref().map(|points| {
        backend
            .logup_suffix_eq_device(points, 0, l)
            .unwrap_or_else(|e| panic!("resident LogUp aux suffix build failed: {e}"))
    });
    if l > 1 {
        ctr.bulk((1usize << (l - 1)) as u64 - 1, 0);
    }

    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(l);
    let mut current_len = vector_len;
    for (j, &pt_j) in point.iter().enumerate() {
        let half = current_len / 2;
        if j == 0 {
            ctr.bulk(0, 24 * half as u64);
        } else {
            ctr.bulk(9 * half as u64, 0);
        }
        ctr.bulk(9 * half as u64 * claim_count as u64, 0);
        ctr.bulk(9, 0);
        let suffix_offset = (1usize << (l - 1 - j)) - 1;
        let g = backend
            .logup_aux_round_device(
                &q0,
                &q1,
                suffix.as_ref().expect("aux round without suffix table"),
                suffix_offset,
                &columns,
                eq_rows.as_ref(),
                claim_cols.as_ref(),
                weights.as_ref(),
                ax.column_count,
                claim_count,
                current_len,
                lambda,
                cpref,
                pt_j,
            )
            .unwrap_or_else(|e| panic!("resident LogUp aux round failed: {e}"));
        let r = sink.round3(g, pt_j);

        let next_q0 = backend
            .fp2_fold_rows_device(&q0, 0, 1, current_len, r)
            .unwrap_or_else(|e| panic!("resident LogUp aux q0 fold failed: {e}"));
        let next_q1 = backend
            .fp2_fold_rows_device(&q1, 0, 1, current_len, r)
            .unwrap_or_else(|e| panic!("resident LogUp aux q1 fold failed: {e}"));
        let next_columns = backend
            .fp2_fold_rows_device(&columns, 0, 2 * ax.column_count, current_len, r)
            .unwrap_or_else(|e| panic!("resident LogUp aux column fold failed: {e}"));
        let next_eq = eq_rows.as_ref().map(|eq| {
            backend
                .fp2_fold_rows_device(eq, 0, claim_count, current_len, r)
                .unwrap_or_else(|e| panic!("resident LogUp aux eq fold failed: {e}"))
        });
        backend.free_device(q0).expect("resident LogUp aux old-q0 free");
        backend.free_device(q1).expect("resident LogUp aux old-q1 free");
        backend.free_device(columns).expect("resident LogUp aux old-columns free");
        if let Some(eq) = eq_rows {
            backend.free_device(eq).expect("resident LogUp aux old-eq free");
        }
        q0 = next_q0;
        q1 = next_q1;
        columns = next_columns;
        eq_rows = next_eq;

        if j == 0 {
            ctr.bulk(2, 4 * half as u64);
        } else {
            ctr.bulk(2 * half as u64 + 2, 0);
        }
        ctr.bulk(2 * half as u64 * ax.column_count as u64, 0);
        ctr.bulk(half as u64 * claim_count as u64, 0);
        let pr = pt_j * r;
        cpref = cpref * (pr + pr - pt_j - r + Fp2::ONE);
        rprime.push(r);
        current_len = half;
    }
    assert_eq!(current_len, 1);

    let q0_final: Fp2 =
        backend.download_device(&q0, 0, 1).expect("resident LogUp aux q0 split")[0].into();
    let q1_final: Fp2 =
        backend.download_device(&q1, 0, 1).expect("resident LogUp aux q1 split")[0].into();
    let col_values: Vec<Fp2> = backend
        .download_device(&columns, 0, 2 * ax.column_count)
        .expect("resident LogUp aux column splits")
        .into_iter()
        .map(Into::into)
        .collect();
    let colsp: Vec<[Fp2; 2]> = col_values.chunks_exact(2).map(|c| [c[0], c[1]]).collect();
    let finals: Vec<AuxFinal> = ax
        .claims
        .iter()
        .zip(&weights_host)
        .map(|(claim, &(w0, w1))| AuxFinal {
            col: claim.col,
            w0,
            w1,
            eq_r: crate::mle::eq_points(&claim.point[1..], &rprime),
        })
        .collect();
    ctr.bulk(2 * l as u64 * finals.len() as u64, 0);

    backend.free_device(columns).expect("resident LogUp aux columns free");
    backend.free_device(q1).expect("resident LogUp aux q1 free");
    backend.free_device(q0).expect("resident LogUp aux q0 free");
    if let Some(eq) = eq_rows {
        backend.free_device(eq).expect("resident LogUp aux eq free");
    }
    if let Some(buffer) = weights {
        backend.free_device(buffer).expect("resident LogUp aux weights free");
    }
    if let Some(buffer) = claim_cols {
        backend.free_device(buffer).expect("resident LogUp aux column ids free");
    }
    if let Some(buffer) = suffix {
        backend.free_device(buffer).expect("resident LogUp aux suffix free");
    }
    if let Some(buffer) = point_device {
        backend.free_device(buffer).expect("resident LogUp aux challenges free");
    }
    if let Some(buffer) = claim_points {
        backend.free_device(buffer).expect("resident LogUp aux points free");
    }
    (rprime, [Fp2::ONE, Fp2::ONE, q0_final, q1_final], colsp, finals)
}

#[derive(Clone, Copy)]
enum ResidentLayerCount {
    General,
    LeafOnes,
    LeafNegMult,
}

#[allow(clippy::too_many_arguments)]
fn layer_general_resident(
    tree_p: &DeviceBuffer<Fp2Repr>,
    tree_q: &DeviceBuffer<Fp2Repr>,
    child_offset: usize,
    child_len: usize,
    point: &[Fp2],
    sink: &mut impl Sink,
    ctr: &mut Counters,
    backend: &mut Backend,
    count_mode: ResidentLayerCount,
) -> (Vec<Fp2>, [Fp2; 4]) {
    let vector_len = child_len / 2;
    assert_eq!(vector_len, 1usize << point.len());
    let (p0, p1) = backend
        .fp2_deinterleave_device(tree_p, child_offset, vector_len)
        .unwrap_or_else(|e| panic!("resident LogUp p deinterleave failed: {e}"));
    let (q0, q1) = backend
        .fp2_deinterleave_device(tree_q, child_offset, vector_len)
        .unwrap_or_else(|e| panic!("resident LogUp q deinterleave failed: {e}"));
    let mut vectors = [p0, p1, q0, q1];
    let lambda = sink.lambda();
    let mut cpref = Fp2::ONE;
    let mut rprime = Vec::with_capacity(point.len());

    let point_device = if point.is_empty() {
        None
    } else {
        let raw: Vec<Fp2Repr> = point.iter().copied().map(Into::into).collect();
        Some(
            backend
                .upload_new_device(&raw)
                .unwrap_or_else(|e| panic!("resident LogUp challenge upload failed: {e}")),
        )
    };
    let suffix_device = point_device.as_ref().map(|points| {
        backend
            .logup_suffix_eq_device(points, 0, point.len())
            .unwrap_or_else(|e| panic!("resident LogUp suffix-eq build failed: {e}"))
    });
    if point.len() > 1 {
        ctr.bulk((1usize << (point.len() - 1)) as u64 - 1, 0);
    }

    let mut current_len = vector_len;
    for (j, &pt_j) in point.iter().enumerate() {
        let half = current_len / 2;
        let suffix_offset = (1usize << (point.len() - 1 - j)) - 1;
        match (count_mode, j) {
            (ResidentLayerCount::General, _)
            | (ResidentLayerCount::LeafNegMult, 1..)
            | (ResidentLayerCount::LeafOnes, 1..) => {
                let per_pair =
                    if matches!(count_mode, ResidentLayerCount::LeafOnes) { 6 } else { 10 };
                ctr.bulk(per_pair * half as u64 + 4, 0);
            }
            (ResidentLayerCount::LeafOnes, 0) => ctr.bulk(4, 16 * half as u64),
            (ResidentLayerCount::LeafNegMult, 0) => {
                ctr.bulk(4 * half as u64 + 4, 12 * half as u64);
            }
        }
        let [pq0, pq2, qq0, qq2] = backend
            .logup_general_round_device(
                &vectors[0],
                0,
                &vectors[1],
                0,
                &vectors[2],
                0,
                &vectors[3],
                0,
                suffix_device.as_ref().expect("non-empty point without suffix tables"),
                suffix_offset,
                half,
            )
            .unwrap_or_else(|e| panic!("resident LogUp round failed: {e}"));
        let h0 = cpref * (lambda * pq0 + qq0);
        let h2 = cpref * (lambda * pq2 + qq2);
        let r = sink.round([h0, h2], pt_j);
        match (count_mode, j) {
            (ResidentLayerCount::General, _) | (ResidentLayerCount::LeafNegMult, 1..) => {
                ctr.bulk(4 * half as u64 + 2, 0)
            }
            (ResidentLayerCount::LeafOnes, 1..) => ctr.bulk(2 * half as u64 + 2, 0),
            (ResidentLayerCount::LeafOnes, 0) => ctr.bulk(2, 4 * half as u64),
            (ResidentLayerCount::LeafNegMult, 0) => ctr.bulk(2, 16 * half as u64),
        }
        let next = backend
            .logup_fold4_device(
                &vectors[0],
                0,
                &vectors[1],
                0,
                &vectors[2],
                0,
                &vectors[3],
                0,
                half,
                r,
            )
            .unwrap_or_else(|e| panic!("resident LogUp fold failed: {e}"));
        let old = std::mem::replace(&mut vectors, next);
        for buffer in old {
            backend.free_device(buffer).expect("resident LogUp folded-input free");
        }
        let pr = pt_j * r;
        cpref = cpref * (pr + pr - pt_j - r + Fp2::ONE);
        rprime.push(r);
        current_len = half;
    }
    assert_eq!(current_len, 1);
    let mut splits = [Fp2::ZERO; 4];
    for (dst, buffer) in splits.iter_mut().zip(&vectors) {
        *dst =
            backend.download_device(buffer, 0, 1).expect("resident LogUp split download")[0].into();
    }
    for buffer in vectors {
        backend.free_device(buffer).expect("resident LogUp final-vector free");
    }
    if let Some(suffix) = suffix_device {
        backend.free_device(suffix).expect("resident LogUp suffix free");
    }
    if let Some(points) = point_device {
        backend.free_device(points).expect("resident LogUp challenge free");
    }
    (rprime, splits)
}

/// Returns the roots and the final leaf point (LSB-first).
fn prove_engine(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    mut aux: Option<&mut LeafAux>,
    sink: &mut impl Sink,
    ctr: &mut Counters,
    mut backend: Option<&mut Backend>,
) -> (Fp2, Fp2, Vec<Fp2>) {
    if backend.as_deref().map(Backend::kind) == Some(BackendKind::CudaResident) {
        return prove_engine_resident_from_host_leaves(
            leaf_p,
            leaf_q,
            aux,
            sink,
            ctr,
            backend.take().expect("resident backend disappeared"),
        );
    }
    if let Some(b) = backend.as_deref() {
        assert_eq!(
            b.kind(),
            BackendKind::CudaHybrid,
            "staged LogUp cannot be used for the cuda-resident gate"
        );
    }
    let stats_before = backend.as_deref().map(|b| b.stats().expect("CUDA stats"));
    let wall_start = Instant::now();
    let tree = build_tree(leaf_p, leaf_q, ctr, backend.as_deref_mut());
    sink.root(tree.p[0][0], tree.q[0][0]);
    let mut point: Vec<Fp2> = Vec::new();

    for l in 0..tree.depth {
        let leaf_layer = l + 1 == tree.depth;
        if leaf_layer && aux.is_some() {
            assert!(matches!(leaf_p, LeafP::Ones), "aux folding is lookup-side only");
            let ax = aux.as_deref_mut().unwrap();
            let (rprime, s, colsp, finals) = layer_leaf_ones_aux(leaf_q, ax, &point, sink, ctr);
            let t = sink.splits_aux(s, &colsp, &finals);
            point = std::iter::once(t).chain(rprime).collect();
            continue;
        }
        let (rprime, splits) = if leaf_layer {
            match leaf_p {
                LeafP::Ones => layer_leaf_ones(leaf_q, &point, sink, ctr),
                LeafP::NegMult(m) => {
                    layer_leaf_negmult(m, leaf_q, &point, sink, ctr, backend.as_deref_mut())
                }
            }
        } else {
            let evens = |v: &Vec<Fp2>| (0..v.len() / 2).map(|i| v[2 * i]).collect::<Vec<_>>();
            let odds = |v: &Vec<Fp2>| (0..v.len() / 2).map(|i| v[2 * i + 1]).collect::<Vec<_>>();
            layer_general(
                evens(&tree.p[l + 1]),
                odds(&tree.p[l + 1]),
                evens(&tree.q[l + 1]),
                odds(&tree.q[l + 1]),
                &point,
                sink,
                ctr,
                backend.as_deref_mut(),
            )
        };
        let t = sink.splits(splits);
        point = std::iter::once(t).chain(rprime.iter().copied()).collect();
    }
    let out = (tree.p[0][0], tree.q[0][0], point);
    if let (Some(b), Some(before)) = (backend, stats_before) {
        b.account_staged_wall(Operation::Logup, wall_start.elapsed(), before)
            .expect("CUDA LogUp residual accounting");
    }
    out
}

/// Clear sink: records messages, draws challenges from an `FpStream`.
struct ClearSink<'a> {
    chal: &'a mut FpStream,
    rounds_cur: Vec<[Fp2; 2]>,
    layers: Vec<LayerProof>,
}

impl Sink for ClearSink<'_> {
    fn root(&mut self, _p: Fp2, _q: Fp2) {}
    fn lambda(&mut self) -> Fp2 {
        self.chal.next_fp2()
    }
    fn round(&mut self, h: [Fp2; 2], _pt_j: Fp2) -> Fp2 {
        self.rounds_cur.push(h);
        self.chal.next_fp2()
    }
    fn splits(&mut self, s: [Fp2; 4]) -> Fp2 {
        self.layers.push(LayerProof {
            rounds: std::mem::take(&mut self.rounds_cur),
            p0: s[0],
            p1: s[1],
            q0: s[2],
            q1: s[3],
        });
        self.chal.next_fp2()
    }
}

/// Prove one fraction tree (clear). Challenges consumed in lockstep with
/// `verify_frac_tree` (interactive-mock DV exchange).
pub fn prove_frac_tree(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> FracProof {
    let mut sink = ClearSink { chal, rounds_cur: Vec::new(), layers: Vec::new() };
    let (root_p, root_q, _) = prove_engine(leaf_p, leaf_q, None, &mut sink, ctr, None);
    FracProof { root_p, root_q, layers: sink.layers }
}

// ---------------------------------------------------------------------------
// Clear verifier
// ---------------------------------------------------------------------------

/// Verify one fraction tree against caller-supplied leaf-MLE evaluations.
pub fn verify_frac_tree(
    proof: &FracProof,
    leaf_p_eval: impl FnOnce(&[Fp2], &mut Counters) -> Fp2,
    leaf_q_eval: impl FnOnce(&[Fp2], &mut Counters) -> Fp2,
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> bool {
    let depth = proof.layers.len();
    let mut point: Vec<Fp2> = Vec::new();
    let mut cp = proof.root_p;
    let mut cq = proof.root_q;

    for (l, layer) in proof.layers.iter().enumerate() {
        if layer.rounds.len() != l {
            return false;
        }
        let lambda = chal.next_fp2();
        let mut claim = ctr.mul(lambda, cp) + cq;
        let mut cpref = Fp2::ONE;
        let mut rprime = Vec::with_capacity(l);
        for (j, h) in layer.rounds.iter().enumerate() {
            // g(X) = ℓ(X)·h(X); claim = ℓ(0)h(0) + ℓ(1)h(1) recovers h(1).
            let ptj = point[j];
            if ptj == Fp2::ZERO {
                return false;
            }
            let ell0 = Fp2::ONE - ptj;
            let ell0_h0 = ctr.mul(ell0, h[0]);
            let h1 = ctr.mul(claim - ell0_h0, ptj.inv());
            let r = chal.next_fp2();
            let w = lagrange3(r);
            ctr.bulk(3, 0);
            let hr = w[0] * h[0] + w[1] * h1 + w[2] * h[1];
            let ell_r = ell0 + ctr.mul(ptj + ptj - Fp2::ONE, r); // (1−pt)(1−r)+pt·r
            claim = ctr.mul(ell_r, hr);
            let pr = ctr.mul(ptj, r);
            cpref = ctr.mul(cpref, pr + pr - ptj - r + Fp2::ONE);
            rprime.push(r);
        }
        // Final check: claim == c_l·(λ(p0q1+p1q0) + q0q1).
        let ad = ctr.mul(layer.p0, layer.q1);
        let bc = ctr.mul(layer.p1, layer.q0);
        let cd = ctr.mul(layer.q0, layer.q1);
        let frac = ctr.mul(lambda, ad + bc) + cd;
        if claim != ctr.mul(cpref, frac) {
            return false;
        }
        let t = chal.next_fp2();
        cp = layer.p0 + ctr.mul(t, layer.p1 - layer.p0);
        cq = layer.q0 + ctr.mul(t, layer.q1 - layer.q0);
        point = std::iter::once(t).chain(rprime).collect();
    }
    debug_assert_eq!(point.len(), depth);
    cp == leaf_p_eval(&point, ctr) && cq == leaf_q_eval(&point, ctr)
}

/// Counted fold-based MLE evaluation (LSB-first).
pub fn eval_mle_counted(values: &[Fp2], point: &[Fp2], ctr: &mut Counters) -> Fp2 {
    assert_eq!(values.len(), 1 << point.len());
    let mut v = values.to_vec();
    for &r in point {
        let half = v.len() / 2;
        ctr.bulk(half as u64, 0);
        for i in 0..half {
            let d = v[2 * i + 1] - v[2 * i];
            v[i] = v[2 * i] + d * r;
        }
        v.truncate(half);
    }
    v[0]
}

// ---------------------------------------------------------------------------
// Clear LogUp instance
// ---------------------------------------------------------------------------

pub struct LogupProof {
    pub lookup_side: FracProof,
    pub table_side: FracProof,
}

impl LogupProof {
    pub fn bytes(&self) -> u64 {
        self.lookup_side.bytes() + self.table_side.bytes()
    }
}

pub fn logup_prove(
    f: &[i16],
    table: &[i16],
    mult: &[u32],
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> (Fp2, LogupProof) {
    let alpha = chal.next_fp2();
    let lookup_side = prove_frac_tree(&LeafP::Ones, &lift_q(f, alpha), chal, ctr);
    let table_side = prove_frac_tree(&LeafP::NegMult(mult), &lift_q(table, alpha), chal, ctr);
    (alpha, LogupProof { lookup_side, table_side })
}

pub fn logup_verify(
    f: &[i16],
    table: &[i16],
    mult: &[u32],
    proof: &LogupProof,
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> bool {
    let alpha = chal.next_fp2();
    // Root cross-check: p_f·q_t + p_t·q_f = 0 with nonzero denominators.
    let (pf, qf) = (proof.lookup_side.root_p, proof.lookup_side.root_q);
    let (pt, qt) = (proof.table_side.root_p, proof.table_side.root_q);
    if ctr.mul(pf, qt) + ctr.mul(pt, qf) != Fp2::ZERO || qf == Fp2::ZERO || qt == Fp2::ZERO {
        return false;
    }
    let lift_vals = |vals: &[i16]| -> Vec<Fp2> {
        vals.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect()
    };
    let ok_f = verify_frac_tree(
        &proof.lookup_side,
        |_pt, _c| Fp2::ONE,
        |pt_, c| eval_mle_counted(&lift_vals(f), pt_, c),
        chal,
        ctr,
    );
    if !ok_f {
        return false;
    }
    verify_frac_tree(
        &proof.table_side,
        |pt_, c| {
            let vals: Vec<Fp2> =
                mult.iter().map(|&m| neg(Fp2::from_base(Fp::new(m as u64)))).collect();
            eval_mle_counted(&vals, pt_, c)
        },
        |pt_, c| eval_mle_counted(&lift_vals(table), pt_, c),
        chal,
        ctr,
    )
}

// ---------------------------------------------------------------------------
// Blind mode (M3 schema): round messages and all claims are transferred as
// authenticated values via corrections against fresh full-field masks; the
// end-of-layer degree-2 relation closes through Π_Prod triples and a
// Π_ZeroBatch row, both accumulated for the caller to batch per layer/block.
// ---------------------------------------------------------------------------

use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

/// Sequential one-time-domain allocator; prover and verifier consume the
/// same sequence (the `DomainLedger` enforces global uniqueness).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Doms {
    next: u64,
}

impl Doms {
    pub fn new(base: u64) -> Doms {
        Doms { next: base }
    }
    pub fn take(&mut self, n: u64) -> u64 {
        let d = self.next;
        self.next += n;
        d
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlindLayerProof {
    /// Per round: corrections for h(0), h(2).
    pub round_corrs: Vec<[Fp2; 2]>,
    /// Corrections for the split claims p0, p1, q0, q1.
    pub split_corrs: [Fp2; 4],
    /// Corrections for the product outputs p0·q1, p1·q0, q0·q1.
    pub z_corrs: [Fp2; 3],
}

/// Aux-folded leaf layer extras: degree-3 round corrections and the per-col
/// [ṽ0, ṽ1] split-claim corrections.
#[derive(Debug, PartialEq, Eq)]
pub struct BlindAuxPart {
    pub rounds3: Vec<[Fp2; 3]>,
    pub col_corrs: Vec<[Fp2; 2]>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlindFracProof {
    /// Corrections for root_p, root_q.
    pub root_corrs: [Fp2; 2],
    pub layers: Vec<BlindLayerProof>,
    pub aux: Option<BlindAuxPart>,
}

impl BlindFracProof {
    pub fn bytes(&self) -> u64 {
        32 + self.layers.iter().map(|l| 16 * (2 * l.round_corrs.len() as u64 + 7)).sum::<u64>()
            + self
                .aux
                .as_ref()
                .map_or(0, |a| 16 * (3 * a.rounds3.len() as u64 + 2 * a.col_corrs.len() as u64))
    }
}

/// An MLE evaluation claim left open for the caller: `value` is the
/// authenticated evaluation of a secret vector at `point` (LSB-first).
pub struct OpenClaim {
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
}

/// Verifier half of an [`OpenClaim`].
pub struct OpenKey {
    pub point: Vec<Fp2>,
    pub key: VerifierKey,
}

pub type ProdTriples = Vec<(ProverAuthed, ProverAuthed, ProverAuthed)>;
pub type ProdKeyTriples = Vec<(VerifierKey, VerifierKey, VerifierKey)>;

struct BlindSink<'a> {
    stream: &'a mut CorrelationStream,
    tx: &'a mut Transcript,
    doms: &'a mut Doms,
    prod: &'a mut ProdTriples,
    zero: &'a mut Vec<ProverAuthed>,
    ctr: Counters,
    // running authenticated state
    cp: ProverAuthed,
    cq: ProverAuthed,
    claim: ProverAuthed,
    lambda: Fp2,
    cpref: Fp2,
    // proof under construction
    root_corrs: [Fp2; 2],
    rounds_cur: Vec<[Fp2; 2]>,
    layers: Vec<BlindLayerProof>,
    roots: (ProverAuthed, ProverAuthed),
    // aux leaf layer (instance mode)
    rounds3_cur: Vec<[Fp2; 3]>,
    col_corrs: Vec<[Fp2; 2]>,
    aux_col_claims: Vec<ProverAuthed>,
}

impl Sink for BlindSink<'_> {
    fn root(&mut self, p: Fp2, q: Fp2) {
        let dom = self.doms.take(1);
        let masks = self.stream.draw_fulls(dom, 2);
        self.root_corrs = [p - masks[0].x, q - masks[1].x];
        self.tx.append("logup_root_corrections", 32);
        self.roots = (ProverAuthed { x: p, m: masks[0].m }, ProverAuthed { x: q, m: masks[1].m });
        self.cp = self.roots.0;
        self.cq = self.roots.1;
    }

    fn lambda(&mut self) -> Fp2 {
        let l = self.tx.challenge_fp2();
        self.lambda = l;
        self.ctr.bulk(4, 0);
        self.claim = self.cp.scale(l).add(self.cq);
        self.cpref = Fp2::ONE;
        l
    }

    fn round(&mut self, h: [Fp2; 2], pt_j: Fp2) -> Fp2 {
        let dom = self.doms.take(1);
        let masks = self.stream.draw_fulls(dom, 2);
        self.rounds_cur.push([h[0] - masks[0].x, h[1] - masks[1].x]);
        self.tx.append("logup_round_corrections", 32);
        let h0 = ProverAuthed { x: h[0], m: masks[0].m };
        let h2 = ProverAuthed { x: h[1], m: masks[1].m };
        let r = self.tx.challenge_fp2();
        // h(1) from the claim, then claim' = ℓ(r)·h(r). All-public scalars.
        let ell0 = Fp2::ONE - pt_j;
        let h1 = self.claim.sub(h0.scale(ell0)).scale(pt_j.inv());
        let w = lagrange3(r);
        let ell_r = ell0 + (pt_j + pt_j - Fp2::ONE) * r;
        self.claim = h0.scale(w[0]).add(h1.scale(w[1])).add(h2.scale(w[2])).scale(ell_r);
        let pr = pt_j * r;
        self.cpref = self.cpref * (pr + pr - pt_j - r + Fp2::ONE);
        self.ctr.bulk(16, 0);
        r
    }

    fn splits(&mut self, s: [Fp2; 4]) -> Fp2 {
        let dom = self.doms.take(1);
        let masks = self.stream.draw_fulls(dom, 4);
        let split_corrs =
            [s[0] - masks[0].x, s[1] - masks[1].x, s[2] - masks[2].x, s[3] - masks[3].x];
        self.tx.append("logup_split_corrections", 64);
        let p0 = ProverAuthed { x: s[0], m: masks[0].m };
        let p1 = ProverAuthed { x: s[1], m: masks[1].m };
        let q0 = ProverAuthed { x: s[2], m: masks[2].m };
        let q1 = ProverAuthed { x: s[3], m: masks[3].m };
        // z₁ = p0·q1, z₂ = p1·q0, z₃ = q0·q1 as authenticated products.
        let zx = [s[0] * s[3], s[1] * s[2], s[2] * s[3]];
        let zdom = self.doms.take(1);
        let zmasks = self.stream.draw_fulls(zdom, 3);
        let z_corrs = [zx[0] - zmasks[0].x, zx[1] - zmasks[1].x, zx[2] - zmasks[2].x];
        self.tx.append("logup_prod_corrections", 48);
        let z: Vec<ProverAuthed> =
            zx.iter().zip(&zmasks).map(|(&x, mk)| ProverAuthed { x, m: mk.m }).collect();
        self.prod.push((p0, q1, z[0]));
        self.prod.push((p1, q0, z[1]));
        self.prod.push((q0, q1, z[2]));
        // Layer-end relation: c_l·(λ(z₁+z₂) + z₃) − claim = 0.
        let row = z[0]
            .add(z[1])
            .scale(self.lambda * self.cpref)
            .add(z[2].scale(self.cpref))
            .sub(self.claim);
        debug_assert_eq!(row.x, Fp2::ZERO, "layer-end relation violated");
        self.zero.push(row);
        let t = self.tx.challenge_fp2();
        self.cp = p0.add(p1.sub(p0).scale(t));
        self.cq = q0.add(q1.sub(q0).scale(t));
        self.ctr.bulk(3 + 8 + 4, 0);
        self.layers.push(BlindLayerProof {
            round_corrs: std::mem::take(&mut self.rounds_cur),
            split_corrs,
            z_corrs,
        });
        t
    }

    fn aux_mus(&mut self, claims: &[ProverAuthed]) -> Vec<Fp2> {
        let mus: Vec<Fp2> = claims.iter().map(|_| self.tx.challenge_fp2()).collect();
        for (v, &mu) in claims.iter().zip(&mus) {
            self.claim = self.claim.add(v.scale(mu));
        }
        self.ctr.bulk(2 * claims.len() as u64, 0);
        mus
    }

    fn round3(&mut self, g: [Fp2; 3], pt_j: Fp2) -> Fp2 {
        let dom = self.doms.take(1);
        let masks = self.stream.draw_fulls(dom, 3);
        self.rounds3_cur.push([g[0] - masks[0].x, g[1] - masks[1].x, g[2] - masks[2].x]);
        self.tx.append("logup_aux_round_corrections", 48);
        let ga: Vec<ProverAuthed> =
            g.iter().zip(&masks).map(|(&x, mk)| ProverAuthed { x, m: mk.m }).collect();
        let r = self.tx.challenge_fp2();
        // g(1) = claim − g(0); claim' = g(r) by cubic interpolation.
        let g1 = self.claim.sub(ga[0]);
        let w = lagrange4(r);
        self.claim =
            ga[0].scale(w[0]).add(g1.scale(w[1])).add(ga[1].scale(w[2])).add(ga[2].scale(w[3]));
        let pr = pt_j * r;
        self.cpref = self.cpref * (pr + pr - pt_j - r + Fp2::ONE);
        self.ctr.bulk(12, 0);
        r
    }

    fn splits_aux(&mut self, s: [Fp2; 4], cols: &[[Fp2; 2]], finals: &[AuxFinal]) -> Fp2 {
        let dom = self.doms.take(1);
        let masks = self.stream.draw_fulls(dom, 4);
        let split_corrs =
            [s[0] - masks[0].x, s[1] - masks[1].x, s[2] - masks[2].x, s[3] - masks[3].x];
        self.tx.append("logup_split_corrections", 64);
        let p0 = ProverAuthed { x: s[0], m: masks[0].m };
        let p1 = ProverAuthed { x: s[1], m: masks[1].m };
        let q0 = ProverAuthed { x: s[2], m: masks[2].m };
        let q1 = ProverAuthed { x: s[3], m: masks[3].m };
        let zx = [s[0] * s[3], s[1] * s[2], s[2] * s[3]];
        let zdom = self.doms.take(1);
        let zmasks = self.stream.draw_fulls(zdom, 3);
        let z_corrs = [zx[0] - zmasks[0].x, zx[1] - zmasks[1].x, zx[2] - zmasks[2].x];
        self.tx.append("logup_prod_corrections", 48);
        let z: Vec<ProverAuthed> =
            zx.iter().zip(&zmasks).map(|(&x, mk)| ProverAuthed { x, m: mk.m }).collect();
        self.prod.push((p0, q1, z[0]));
        self.prod.push((p1, q0, z[1]));
        self.prod.push((q0, q1, z[2]));
        // Per-col split claims ṽ0, ṽ1.
        let cdom = self.doms.take(1);
        let cmasks = self.stream.draw_fulls(cdom, 2 * cols.len());
        self.tx.append("logup_col_corrections", 32 * cols.len() as u64);
        let mut cols_a = Vec::with_capacity(cols.len());
        for (ci, c) in cols.iter().enumerate() {
            self.col_corrs.push([c[0] - cmasks[2 * ci].x, c[1] - cmasks[2 * ci + 1].x]);
            cols_a.push([
                ProverAuthed { x: c[0], m: cmasks[2 * ci].m },
                ProverAuthed { x: c[1], m: cmasks[2 * ci + 1].m },
            ]);
        }
        // Extended layer-end relation:
        // claim = c_l·(λ(z₁+z₂) + z₃) + Σ_k eq_r·(w0·ṽ0 + w1·ṽ1).
        let mut row = z[0]
            .add(z[1])
            .scale(self.lambda * self.cpref)
            .add(z[2].scale(self.cpref))
            .sub(self.claim);
        for f in finals {
            let c = &cols_a[f.col];
            row = row.add(c[0].scale(f.w0).add(c[1].scale(f.w1)).scale(f.eq_r));
        }
        debug_assert_eq!(row.x, Fp2::ZERO, "aux layer-end relation violated");
        self.zero.push(row);
        let t = self.tx.challenge_fp2();
        self.cp = p0.add(p1.sub(p0).scale(t));
        self.cq = q0.add(q1.sub(q0).scale(t));
        self.aux_col_claims = cols_a.iter().map(|c| c[0].add(c[1].sub(c[0]).scale(t))).collect();
        self.ctr.bulk(3 + 8 + 4 + 6 * finals.len() as u64 + 2 * cols.len() as u64, 0);
        self.layers.push(BlindLayerProof {
            round_corrs: std::mem::take(&mut self.rounds_cur),
            split_corrs,
            z_corrs,
        });
        t
    }
}

/// Blind prover for one fraction tree. Returns the proof, the leaf point,
/// the authenticated leaf claims (cp, cq) and the authenticated roots.
/// Contract: the leaves must already be bound in the caller's transcript
/// (α drawn after auth of f/mult) — this function only proves the tree.
#[allow(clippy::type_complexity)]
pub fn blind_prove_frac_tree(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (BlindFracProof, Vec<Fp2>, ProverAuthed, ProverAuthed, (ProverAuthed, ProverAuthed)) {
    blind_prove_frac_tree_impl(leaf_p, leaf_q, stream, doms, tx, ctr, prod, zero, None)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn blind_prove_frac_tree_with_backend(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> (BlindFracProof, Vec<Fp2>, ProverAuthed, ProverAuthed, (ProverAuthed, ProverAuthed)) {
    blind_prove_frac_tree_impl(leaf_p, leaf_q, stream, doms, tx, ctr, prod, zero, Some(backend))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn blind_prove_frac_tree_impl(
    leaf_p: &LeafP,
    leaf_q: &LeafQ,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: Option<&mut Backend>,
) -> (BlindFracProof, Vec<Fp2>, ProverAuthed, ProverAuthed, (ProverAuthed, ProverAuthed)) {
    let mut sink = new_blind_sink(stream, tx, doms, prod, zero);
    let (_rp, _rq, point) = prove_engine(leaf_p, leaf_q, None, &mut sink, ctr, backend);
    ctr.bulk(sink.ctr.fp2_mults, sink.ctr.base_mults);
    let proof = BlindFracProof { root_corrs: sink.root_corrs, layers: sink.layers, aux: None };
    (proof, point, sink.cp, sink.cq, sink.roots)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn blind_prove_frac_tree_table_resident(
    dleaf: &DeviceBuffer<u64>,
    dmult: &DeviceBuffer<u32>,
    entries: usize,
    alpha1: Fp,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> (BlindFracProof, Vec<Fp2>, ProverAuthed, ProverAuthed, (ProverAuthed, ProverAuthed)) {
    let mut sink = new_blind_sink(stream, tx, doms, prod, zero);
    let (_rp, _rq, point) = prove_engine_resident_from_device_leaves(
        dleaf,
        Some(dmult),
        entries,
        alpha1,
        None,
        &mut sink,
        ctr,
        backend,
    );
    ctr.bulk(sink.ctr.fp2_mults, sink.ctr.base_mults);
    let proof = BlindFracProof { root_corrs: sink.root_corrs, layers: sink.layers, aux: None };
    (proof, point, sink.cp, sink.cq, sink.roots)
}

fn new_blind_sink<'a>(
    stream: &'a mut CorrelationStream,
    tx: &'a mut Transcript,
    doms: &'a mut Doms,
    prod: &'a mut ProdTriples,
    zero: &'a mut Vec<ProverAuthed>,
) -> BlindSink<'a> {
    BlindSink {
        stream,
        tx,
        doms,
        prod,
        zero,
        ctr: Counters::default(),
        cp: ProverAuthed::ZERO,
        cq: ProverAuthed::ZERO,
        claim: ProverAuthed::ZERO,
        lambda: Fp2::ZERO,
        cpref: Fp2::ONE,
        root_corrs: [Fp2::ZERO; 2],
        rounds_cur: Vec::new(),
        layers: Vec::new(),
        roots: (ProverAuthed::ZERO, ProverAuthed::ZERO),
        rounds3_cur: Vec::new(),
        col_corrs: Vec::new(),
        aux_col_claims: Vec::new(),
    }
}

/// Blind prover for the lookup tree WITH aux-claim folding. Additionally
/// returns the per-col consolidated claims ṽ_c(point).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn blind_prove_frac_tree_aux(
    leaf_q: &LeafQ,
    ax: &mut LeafAux,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (
    BlindFracProof,
    Vec<Fp2>,
    ProverAuthed,
    ProverAuthed,
    (ProverAuthed, ProverAuthed),
    Vec<ProverAuthed>,
) {
    blind_prove_frac_tree_aux_impl(leaf_q, ax, stream, doms, tx, ctr, prod, zero, None)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn blind_prove_frac_tree_aux_with_backend(
    leaf_q: &LeafQ,
    ax: &mut LeafAux,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> (
    BlindFracProof,
    Vec<Fp2>,
    ProverAuthed,
    ProverAuthed,
    (ProverAuthed, ProverAuthed),
    Vec<ProverAuthed>,
) {
    blind_prove_frac_tree_aux_impl(leaf_q, ax, stream, doms, tx, ctr, prod, zero, Some(backend))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn blind_prove_frac_tree_aux_impl(
    leaf_q: &LeafQ,
    ax: &mut LeafAux,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: Option<&mut Backend>,
) -> (
    BlindFracProof,
    Vec<Fp2>,
    ProverAuthed,
    ProverAuthed,
    (ProverAuthed, ProverAuthed),
    Vec<ProverAuthed>,
) {
    let mut sink = new_blind_sink(stream, tx, doms, prod, zero);
    let (_rp, _rq, point) = prove_engine(&LeafP::Ones, leaf_q, Some(ax), &mut sink, ctr, backend);
    ctr.bulk(sink.ctr.fp2_mults, sink.ctr.base_mults);
    let aux_part = BlindAuxPart {
        rounds3: std::mem::take(&mut sink.rounds3_cur),
        col_corrs: std::mem::take(&mut sink.col_corrs),
    };
    let proof =
        BlindFracProof { root_corrs: sink.root_corrs, layers: sink.layers, aux: Some(aux_part) };
    (proof, point, sink.cp, sink.cq, sink.roots, sink.aux_col_claims)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn blind_prove_frac_tree_aux_resident(
    dleaf: &DeviceBuffer<u64>,
    n: usize,
    alpha1: Fp,
    aux_columns: DeviceBuffer<Fp2Repr>,
    column_count: usize,
    aux_claims: &[LeafAuxClaim],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> (
    BlindFracProof,
    Vec<Fp2>,
    ProverAuthed,
    ProverAuthed,
    (ProverAuthed, ProverAuthed),
    Vec<ProverAuthed>,
) {
    let mut sink = new_blind_sink(stream, tx, doms, prod, zero);
    let resident_aux =
        ResidentAuxState { columns: Some(aux_columns), column_count, claims: aux_claims };
    let (_rp, _rq, point) = prove_engine_resident_from_device_leaves(
        dleaf,
        None,
        n,
        alpha1,
        Some(resident_aux),
        &mut sink,
        ctr,
        backend,
    );
    ctr.bulk(sink.ctr.fp2_mults, sink.ctr.base_mults);
    let aux_part = BlindAuxPart {
        rounds3: std::mem::take(&mut sink.rounds3_cur),
        col_corrs: std::mem::take(&mut sink.col_corrs),
    };
    let proof =
        BlindFracProof { root_corrs: sink.root_corrs, layers: sink.layers, aux: Some(aux_part) };
    (proof, point, sink.cp, sink.cq, sink.roots, sink.aux_col_claims)
}

/// Blind verifier for one fraction tree: mirrors the recursion on keys.
/// Returns the leaf point, the leaf-claim keys and the root keys.
#[allow(clippy::type_complexity)]
pub fn blind_verify_frac_tree(
    depth: usize,
    proof: &BlindFracProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Option<(Vec<Fp2>, VerifierKey, VerifierKey, (VerifierKey, VerifierKey))> {
    if proof.layers.len() != depth {
        return None;
    }
    let kroots = {
        let ks = ctx.expand_full_keys(doms.take(1), 2);
        (
            VerifierKey { k: ks[0] + ctx.delta * proof.root_corrs[0] },
            VerifierKey { k: ks[1] + ctx.delta * proof.root_corrs[1] },
        )
    };
    let mut kcp = kroots.0;
    let mut kcq = kroots.1;
    let mut point: Vec<Fp2> = Vec::new();

    for (l, layer) in proof.layers.iter().enumerate() {
        if layer.round_corrs.len() != l {
            return None;
        }
        let lambda = tx.challenge_fp2();
        let mut kclaim = kcp.scale(lambda).add(kcq);
        let mut cpref = Fp2::ONE;
        let mut rprime = Vec::with_capacity(l);
        for (j, corrs) in layer.round_corrs.iter().enumerate() {
            let kms = ctx.expand_full_keys(doms.take(1), 2);
            let kh0 = VerifierKey { k: kms[0] + ctx.delta * corrs[0] };
            let kh2 = VerifierKey { k: kms[1] + ctx.delta * corrs[1] };
            let ptj = point[j];
            if ptj == Fp2::ZERO {
                return None;
            }
            let ell0 = Fp2::ONE - ptj;
            let kh1 = kclaim.sub(kh0.scale(ell0)).scale(ptj.inv());
            let r = tx.challenge_fp2();
            let w = lagrange3(r);
            let ell_r = ell0 + (ptj + ptj - Fp2::ONE) * r;
            kclaim = kh0.scale(w[0]).add(kh1.scale(w[1])).add(kh2.scale(w[2])).scale(ell_r);
            let pr = ptj * r;
            cpref = cpref * (pr + pr - ptj - r + Fp2::ONE);
            rprime.push(r);
        }
        let kss = ctx.expand_full_keys(doms.take(1), 4);
        let ksp: Vec<VerifierKey> = kss
            .iter()
            .zip(&layer.split_corrs)
            .map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c })
            .collect();
        let kzs = ctx.expand_full_keys(doms.take(1), 3);
        let kz: Vec<VerifierKey> = kzs
            .iter()
            .zip(&layer.z_corrs)
            .map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c })
            .collect();
        kprod.push((ksp[0], ksp[3], kz[0]));
        kprod.push((ksp[1], ksp[2], kz[1]));
        kprod.push((ksp[2], ksp[3], kz[2]));
        kzero.push(kz[0].add(kz[1]).scale(lambda * cpref).add(kz[2].scale(cpref)).sub(kclaim));
        let t = tx.challenge_fp2();
        kcp = ksp[0].add(ksp[1].sub(ksp[0]).scale(t));
        kcq = ksp[2].add(ksp[3].sub(ksp[2]).scale(t));
        point = std::iter::once(t).chain(rprime).collect();
    }
    Some((point, kcp, kcq, kroots))
}

/// Blind verifier for the lookup tree with aux folding (degree-3 leaf
/// layer). `aux_claims` are (col, point, key) of the folded external claims,
/// in the prover's order. Returns leaf point, leaf-claim keys, root keys and
/// the per-col consolidated claim keys.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn blind_verify_frac_tree_aux(
    depth: usize,
    proof: &BlindFracProof,
    aux_claims: &[(usize, Vec<Fp2>, VerifierKey)],
    n_cols: usize,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Option<(Vec<Fp2>, VerifierKey, VerifierKey, (VerifierKey, VerifierKey), Vec<VerifierKey>)> {
    if proof.layers.len() != depth {
        return None;
    }
    let aux = proof.aux.as_ref()?;
    if aux.rounds3.len() != depth - 1 || aux.col_corrs.len() != n_cols {
        return None;
    }
    for (_, p, _) in aux_claims {
        if p.len() != depth {
            return None;
        }
    }
    let kroots = {
        let ks = ctx.expand_full_keys(doms.take(1), 2);
        (
            VerifierKey { k: ks[0] + ctx.delta * proof.root_corrs[0] },
            VerifierKey { k: ks[1] + ctx.delta * proof.root_corrs[1] },
        )
    };
    let mut kcp = kroots.0;
    let mut kcq = kroots.1;
    let mut point: Vec<Fp2> = Vec::new();

    for (l, layer) in proof.layers.iter().enumerate() {
        let leaf = l + 1 == depth;
        let lambda = tx.challenge_fp2();
        let mut kclaim = kcp.scale(lambda).add(kcq);
        let mut cpref = Fp2::ONE;
        let mut rprime = Vec::with_capacity(l);
        let mut ws: Vec<(Fp2, Fp2)> = Vec::new();
        if leaf {
            if !layer.round_corrs.is_empty() {
                return None;
            }
            for (_, p, key) in aux_claims {
                let mu = tx.challenge_fp2();
                kclaim = kclaim.add(key.scale(mu));
                ws.push((mu * (Fp2::ONE - p[0]), mu * p[0]));
            }
            for (j, corrs) in aux.rounds3.iter().enumerate() {
                let kms = ctx.expand_full_keys(doms.take(1), 3);
                let kg: Vec<VerifierKey> = kms
                    .iter()
                    .zip(corrs)
                    .map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c })
                    .collect();
                let r = tx.challenge_fp2();
                let kg1 = kclaim.sub(kg[0]);
                let w = lagrange4(r);
                kclaim = kg[0]
                    .scale(w[0])
                    .add(kg1.scale(w[1]))
                    .add(kg[1].scale(w[2]))
                    .add(kg[2].scale(w[3]));
                let ptj = point[j];
                let pr = ptj * r;
                cpref = cpref * (pr + pr - ptj - r + Fp2::ONE);
                rprime.push(r);
            }
        } else {
            if layer.round_corrs.len() != l {
                return None;
            }
            for (j, corrs) in layer.round_corrs.iter().enumerate() {
                let kms = ctx.expand_full_keys(doms.take(1), 2);
                let kh0 = VerifierKey { k: kms[0] + ctx.delta * corrs[0] };
                let kh2 = VerifierKey { k: kms[1] + ctx.delta * corrs[1] };
                let ptj = point[j];
                if ptj == Fp2::ZERO {
                    return None;
                }
                let ell0 = Fp2::ONE - ptj;
                let kh1 = kclaim.sub(kh0.scale(ell0)).scale(ptj.inv());
                let r = tx.challenge_fp2();
                let w = lagrange3(r);
                let ell_r = ell0 + (ptj + ptj - Fp2::ONE) * r;
                kclaim = kh0.scale(w[0]).add(kh1.scale(w[1])).add(kh2.scale(w[2])).scale(ell_r);
                let pr = ptj * r;
                cpref = cpref * (pr + pr - ptj - r + Fp2::ONE);
                rprime.push(r);
            }
        }
        let kss = ctx.expand_full_keys(doms.take(1), 4);
        let ksp: Vec<VerifierKey> = kss
            .iter()
            .zip(&layer.split_corrs)
            .map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c })
            .collect();
        let kzs = ctx.expand_full_keys(doms.take(1), 3);
        let kz: Vec<VerifierKey> = kzs
            .iter()
            .zip(&layer.z_corrs)
            .map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c })
            .collect();
        kprod.push((ksp[0], ksp[3], kz[0]));
        kprod.push((ksp[1], ksp[2], kz[1]));
        kprod.push((ksp[2], ksp[3], kz[2]));
        let mut row = kz[0].add(kz[1]).scale(lambda * cpref).add(kz[2].scale(cpref)).sub(kclaim);
        let t;
        if leaf {
            let kcs = ctx.expand_full_keys(doms.take(1), 2 * n_cols);
            let kcols: Vec<[VerifierKey; 2]> = (0..n_cols)
                .map(|ci| {
                    [
                        VerifierKey { k: kcs[2 * ci] + ctx.delta * aux.col_corrs[ci][0] },
                        VerifierKey { k: kcs[2 * ci + 1] + ctx.delta * aux.col_corrs[ci][1] },
                    ]
                })
                .collect();
            for ((col, p, _), &(w0, w1)) in aux_claims.iter().zip(&ws) {
                let eq_r = crate::mle::eq_points(&p[1..], &rprime);
                let c = &kcols[*col];
                row = row.add(c[0].scale(w0).add(c[1].scale(w1)).scale(eq_r));
            }
            kzero.push(row);
            t = tx.challenge_fp2();
            kcp = ksp[0].add(ksp[1].sub(ksp[0]).scale(t));
            kcq = ksp[2].add(ksp[3].sub(ksp[2]).scale(t));
            let col_keys: Vec<VerifierKey> =
                kcols.iter().map(|c| c[0].add(c[1].sub(c[0]).scale(t))).collect();
            point = std::iter::once(t).chain(rprime).collect();
            return Some((point, kcp, kcq, kroots, col_keys));
        }
        kzero.push(row);
        t = tx.challenge_fp2();
        kcp = ksp[0].add(ksp[1].sub(ksp[0]).scale(t));
        kcq = ksp[2].add(ksp[3].sub(ksp[2]).scale(t));
        point = std::iter::once(t).chain(rprime).collect();
    }
    None
}

/// Root cross-check and q-root nonzeroness (both trees), prover side.
fn cross_prover(
    roots_f: (ProverAuthed, ProverAuthed),
    roots_t: (ProverAuthed, ProverAuthed),
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> [Fp2; 4] {
    let (pf, qf) = roots_f;
    let (ptn, qt) = roots_t;
    let zx = [pf.x * qt.x, ptn.x * qf.x, qf.x.inv(), qt.x.inv()];
    let dom = doms.take(1);
    let masks = stream.draw_fulls(dom, 4);
    let cross_corrs =
        [zx[0] - masks[0].x, zx[1] - masks[1].x, zx[2] - masks[2].x, zx[3] - masks[3].x];
    tx.append("logup_cross_corrections", 64);
    let za = ProverAuthed { x: zx[0], m: masks[0].m };
    let zb = ProverAuthed { x: zx[1], m: masks[1].m };
    let inv_f = ProverAuthed { x: zx[2], m: masks[2].m };
    let inv_t = ProverAuthed { x: zx[3], m: masks[3].m };
    prod.push((pf, qt, za));
    prod.push((ptn, qf, zb));
    prod.push((qf, inv_f, ProverAuthed::from_public(Fp2::ONE)));
    prod.push((qt, inv_t, ProverAuthed::from_public(Fp2::ONE)));
    zero.push(za.add(zb));
    ctr.bulk(4, 0);
    cross_corrs
}

/// Verifier mirror of [`cross_prover`].
fn cross_verifier(
    kroots_f: (VerifierKey, VerifierKey),
    kroots_t: (VerifierKey, VerifierKey),
    cross_corrs: &[Fp2; 4],
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) {
    let kms = ctx.expand_full_keys(doms.take(1), 4);
    let kz: Vec<VerifierKey> =
        kms.iter().zip(cross_corrs).map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c }).collect();
    let one_k = VerifierKey::from_public(Fp2::ONE, ctx.delta);
    kprod.push((kroots_f.0, kroots_t.1, kz[0]));
    kprod.push((kroots_t.0, kroots_f.1, kz[1]));
    kprod.push((kroots_f.1, kz[2], one_k));
    kprod.push((kroots_t.1, kz[3], one_k));
    kzero.push(kz[0].add(kz[1]));
}

// ---------------------------------------------------------------------------
// LogUp instance: packed columns + aux folding + closures (P4 fused blocks)
// ---------------------------------------------------------------------------

/// A blind LogUp instance over one or more data columns packed in-field:
/// f_i = Σ_c col_c[i]·2^{shift_c} over the PACKED cols (shift = Some).
/// Pair-LUTs pack two columns (shifts 0, 16); requant range instances pack
/// only the rounding remainder and carry the output as an unpacked aux col
/// (bound by claims + the linear requant relation, not by the table).
///
/// **P6 shared-α restructure**: an instance is now LOOKUP-SIDE ONLY. The
/// table side runs ONCE per table CONTENT per model ([`table_side_prove`])
/// against one global multiplicity vector; each instance's authenticated
/// root fraction is tied to it by the fraction-sum chain there. α is drawn
/// by the caller per content, strictly after phase 1 (all element auths +
/// all multiplicity vectors bound model-wide).
#[derive(Debug, PartialEq, Eq)]
pub struct BlindInstance {
    pub lookup: BlindFracProof,
}

impl BlindInstance {
    pub fn bytes(&self) -> u64 {
        self.lookup.bytes()
    }
}

/// Identity of a table CONTENT (the merge key of the per-model multiset
/// argument). `Range(s)` covers every requant/remainder range table of shift
/// `s` (equal shifts are content-identical across sites, layers and decode
/// chunks); the pair LUTs are global per model (P5 froze one LUT set).
/// `Ord` gives both parties the same canonical content order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TableKey {
    Range(u32),
    Exp,
    Gelu,
    LnRsqrt,
    SoftmaxRecip,
}

pub struct InstanceOutP {
    pub proof: BlindInstance,
    pub alpha: Fp2,
    /// Lookup leaf point; all col claims are at this point.
    pub point: Vec<Fp2>,
    /// Consolidated authenticated col evaluations ṽ_c(point) — these carry
    /// the leaf closure AND every folded external claim; they must be
    /// resolved upstream (producer GEMM / boundary / relation).
    pub col_claims: Vec<OpenClaim>,
    /// Authenticated root fraction (p, q) of the lookup tree — consumed by
    /// the per-content fraction-sum chain in [`table_side_prove`].
    pub roots: (ProverAuthed, ProverAuthed),
}

/// Prove one lookup-side instance with a caller-drawn shared α. `cols` are
/// base-lifted, padded to a power of two; `aux_claims` are the external
/// claims to drain (col index, point, value). Contract: cols and the global
/// multiplicity vectors were bound (authenticated / claimed) before α was
/// drawn by the caller.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_prove(
    cols: &[Vec<Fp>],
    shifts: &[Option<u32>],
    alpha: Fp2,
    aux_claims: Vec<LeafAuxClaim>,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> InstanceOutP {
    blind_instance_prove_impl(
        cols, shifts, alpha, aux_claims, stream, doms, tx, ctr, prod, zero, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn blind_instance_prove_with_backend(
    cols: &[Vec<Fp>],
    shifts: &[Option<u32>],
    alpha: Fp2,
    aux_claims: Vec<LeafAuxClaim>,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> InstanceOutP {
    blind_instance_prove_impl(
        cols,
        shifts,
        alpha,
        aux_claims,
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
        Some(backend),
    )
}

/// Lookup-side instance whose padded base-field columns already reside on
/// the GPU. Packing `α−f`, tree construction, aux-column folds and every
/// upper round stay resident; only protocol roots/rounds/splits return to
/// Rust. The source column view remains owned by the caller.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_prove_resident(
    columns: DeviceSlice<'_, u64>,
    column_count: usize,
    entries: usize,
    shifts: &[Option<u32>],
    alpha: Fp2,
    aux_claims: Vec<LeafAuxClaim>,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> Result<InstanceOutP, AccelError> {
    if column_count == 0
        || shifts.len() != column_count
        || entries < 2
        || !entries.is_power_of_two()
        || columns.len() < column_count * entries
    {
        return Err(AccelError::InvalidInput("invalid resident LogUp instance geometry"));
    }
    let dleaf =
        backend.pack_lookup_leaf_device(columns, column_count, entries, shifts, alpha.c0)?;
    let aux_columns = match backend.deinterleave_base_columns_device(columns, column_count, entries)
    {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(dleaf);
            return Err(error);
        }
    };
    ctr.bulk(0, (entries * shifts.iter().flatten().count()) as u64);
    let (lookup, point, cp_f, cq_f, roots_f, col_authed) = blind_prove_frac_tree_aux_resident(
        &dleaf,
        entries,
        alpha.c1,
        aux_columns,
        column_count,
        &aux_claims,
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
        backend,
    );
    backend.free_device(dleaf)?;

    zero.push(cp_f.sub(ProverAuthed::from_public(Fp2::ONE)));
    let mut row = cq_f.sub(ProverAuthed::from_public(alpha));
    for (claim, &shift) in col_authed.iter().zip(shifts) {
        if let Some(shift) = shift {
            row = row.add(claim.scale(Fp2::from_base(Fp::new(1u64 << shift))));
        }
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "resident packed leaf closure violated");
    zero.push(row);
    ctr.bulk(2 * column_count as u64, 0);

    Ok(InstanceOutP {
        proof: BlindInstance { lookup },
        alpha,
        col_claims: col_authed
            .into_iter()
            .map(|value| OpenClaim { point: point.clone(), value })
            .collect(),
        roots: roots_f,
        point,
    })
}

#[allow(clippy::too_many_arguments)]
fn blind_instance_prove_impl(
    cols: &[Vec<Fp>],
    shifts: &[Option<u32>],
    alpha: Fp2,
    aux_claims: Vec<LeafAuxClaim>,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: Option<&mut Backend>,
) -> InstanceOutP {
    assert_eq!(cols.len(), shifts.len());
    assert!(shifts.iter().any(|s| s.is_some()), "at least one packed column");
    let n = cols[0].len();
    let packed: Vec<Fp> = (0..n)
        .map(|i| {
            cols.iter().zip(shifts).fold(Fp::ZERO, |a, (c, &s)| match s {
                Some(s) => a + c[i] * Fp::new(1u64 << s),
                None => a,
            })
        })
        .collect();
    ctr.bulk(0, (n * shifts.iter().flatten().count()) as u64);
    let leaf_q = lift_q_fp(&packed, alpha);
    let mut ax = LeafAux { cols: cols.iter().map(|c| aux_col(c)).collect(), claims: aux_claims };
    let (lp, point, cp_f, cq_f, roots_f, col_authed) = blind_prove_frac_tree_aux_impl(
        &leaf_q, &mut ax, stream, doms, tx, ctr, prod, zero, backend,
    );

    // Leaf closures: p_f ≡ 1; q_f = α − Σ_c 2^{shift_c}·col̃_c.
    zero.push(cp_f.sub(ProverAuthed::from_public(Fp2::ONE)));
    let mut row = cq_f.sub(ProverAuthed::from_public(alpha));
    for (ca, &s) in col_authed.iter().zip(shifts) {
        if let Some(s) = s {
            row = row.add(ca.scale(Fp2::from_base(Fp::new(1u64 << s))));
        }
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "packed leaf closure violated");
    zero.push(row);
    ctr.bulk(2 * cols.len() as u64, 0);

    InstanceOutP {
        proof: BlindInstance { lookup: lp },
        alpha,
        col_claims: col_authed
            .into_iter()
            .map(|value| OpenClaim { point: point.clone(), value })
            .collect(),
        roots: roots_f,
        point,
    }
}

pub struct InstanceOutV {
    pub point: Vec<Fp2>,
    pub col_keys: Vec<OpenKey>,
    pub kroots: (VerifierKey, VerifierKey),
}

/// Verify one lookup-side instance; `aux_claims` mirror the prover's
/// (col, point, key) and `alpha` is the caller-drawn shared challenge.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_verify(
    n_bits: usize,
    shifts: &[Option<u32>],
    alpha: Fp2,
    proof: &BlindInstance,
    aux_claims: &[(usize, Vec<Fp2>, VerifierKey)],
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Option<InstanceOutV> {
    let (point, kcp_f, kcq_f, kroots_f, col_keys) = blind_verify_frac_tree_aux(
        n_bits,
        &proof.lookup,
        aux_claims,
        shifts.len(),
        ctx,
        doms,
        tx,
        kprod,
        kzero,
    )?;

    kzero.push(kcp_f.sub(VerifierKey::from_public(Fp2::ONE, ctx.delta)));
    let mut row = kcq_f.sub(VerifierKey::from_public(alpha, ctx.delta));
    for (ck, &s) in col_keys.iter().zip(shifts) {
        if let Some(s) = s {
            row = row.add(ck.scale(Fp2::from_base(Fp::new(1u64 << s))));
        }
    }
    kzero.push(row);

    Some(InstanceOutV {
        col_keys: col_keys.into_iter().map(|key| OpenKey { point: point.clone(), key }).collect(),
        kroots: kroots_f,
        point,
    })
}

// ---------------------------------------------------------------------------
// Per-content shared table side (P6): one multiset argument per table content
// ---------------------------------------------------------------------------

/// Proof of one table CONTENT's side: the table fraction tree over the ONE
/// global multiplicity vector, plus the authenticated fraction-sum chain
/// tying Σ_sites p_s/q_s = p_t/q_t (3 corrections per site beyond the first,
/// then the standard root cross-check).
#[derive(Debug, PartialEq, Eq)]
pub struct TableSideProof {
    pub table: BlindFracProof,
    /// Per additional site: corrections for (P·q_s, p_s·Q, Q·q_s).
    pub agg_corrs: Vec<[Fp2; 3]>,
    pub cross_corrs: [Fp2; 4],
}

impl TableSideProof {
    pub fn bytes(&self) -> u64 {
        self.table.bytes() + 48 * self.agg_corrs.len() as u64 + 64
    }
}

/// Prove one content's table side. `sites` are the authenticated lookup-tree
/// root fractions of EVERY instance of this content, in canonical program
/// order (both parties push them identically). Returns the proof and the m̃
/// open claim to resolve against the global authenticated multiplicity
/// vector.
#[allow(clippy::too_many_arguments)]
pub fn table_side_prove(
    table_vals: &[Fp],
    mult: &[u32],
    alpha: Fp2,
    sites: &[(ProverAuthed, ProverAuthed)],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (TableSideProof, OpenClaim) {
    table_side_prove_impl(table_vals, mult, alpha, sites, stream, doms, tx, ctr, prod, zero, None)
}

#[allow(clippy::too_many_arguments)]
pub fn table_side_prove_with_backend(
    table_vals: &[Fp],
    mult: &[u32],
    alpha: Fp2,
    sites: &[(ProverAuthed, ProverAuthed)],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> (TableSideProof, OpenClaim) {
    table_side_prove_impl(
        table_vals,
        mult,
        alpha,
        sites,
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
        Some(backend),
    )
}

/// Resident table-side proof over a public table and a device-owned global
/// multiplicity vector. Table leaves are uploaded from public data; the
/// multiplicities, fraction tree and final MLE evaluation never materialize
/// on the host. The returned scalar/open claim are existing protocol
/// messages, so the proof and verifier formats remain unchanged.
#[allow(clippy::too_many_arguments)]
pub fn table_side_prove_resident(
    table_vals: &[Fp],
    mult: &DeviceBuffer<u32>,
    alpha: Fp2,
    sites: &[(ProverAuthed, ProverAuthed)],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> Result<(TableSideProof, OpenClaim), AccelError> {
    if sites.is_empty()
        || table_vals.len() < 2
        || !table_vals.len().is_power_of_two()
        || mult.len() != table_vals.len()
    {
        return Err(AccelError::InvalidInput("invalid resident table-side geometry"));
    }

    let table_raw: Vec<u64> = table_vals.iter().map(|value| value.value()).collect();
    let table = backend.upload_new_device(&table_raw)?;
    let leaf = match backend.pack_lookup_leaf_device(
        DeviceSlice::new(&table, 0, table.len()).expect("whole public table"),
        1,
        table_vals.len(),
        &[Some(0)],
        alpha.c0,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(table);
            return Err(error);
        }
    };
    if let Err(error) = backend.free_device(table) {
        let _ = backend.free_device(leaf);
        return Err(error);
    }

    let (tp, pt_t, cp_t, cq_t, roots_t) = blind_prove_frac_tree_table_resident(
        &leaf,
        mult,
        table_vals.len(),
        alpha.c1,
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
        backend,
    );
    let t_eval = backend.mle_eval_device(
        DeviceSlice::new(&leaf, 0, leaf.len()).expect("whole resident table leaf"),
        &pt_t,
    );
    let free_result = backend.free_device(leaf);
    let mut t_eval = match (t_eval, free_result) {
        (Ok(value), Ok(())) => value,
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    t_eval += Fp2::new(Fp::ZERO, alpha.c1);
    ctr.bulk((table_vals.len() - 1) as u64, 0);

    Ok(finish_table_side_prove(
        tp, pt_t, cp_t, cq_t, roots_t, t_eval, sites, stream, doms, tx, ctr, prod, zero,
    ))
}

#[allow(clippy::too_many_arguments)]
fn table_side_prove_impl(
    table_vals: &[Fp],
    mult: &[u32],
    alpha: Fp2,
    sites: &[(ProverAuthed, ProverAuthed)],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: Option<&mut Backend>,
) -> (TableSideProof, OpenClaim) {
    assert!(!sites.is_empty(), "table content with no lookup sites");
    let (tp, pt_t, cp_t, cq_t, roots_t) = blind_prove_frac_tree_impl(
        &LeafP::NegMult(mult),
        &lift_q_fp(table_vals, alpha),
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
        backend,
    );
    let t_eval = {
        let lifted: Vec<Fp2> = table_vals.iter().map(|&v| alpha - Fp2::from_base(v)).collect();
        eval_mle_counted(&lifted, &pt_t, ctr)
    };
    finish_table_side_prove(
        tp, pt_t, cp_t, cq_t, roots_t, t_eval, sites, stream, doms, tx, ctr, prod, zero,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_table_side_prove(
    tp: BlindFracProof,
    pt_t: Vec<Fp2>,
    cp_t: ProverAuthed,
    cq_t: ProverAuthed,
    roots_t: (ProverAuthed, ProverAuthed),
    t_eval: Fp2,
    sites: &[(ProverAuthed, ProverAuthed)],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (TableSideProof, OpenClaim) {
    zero.push(cq_t.sub(ProverAuthed::from_public(t_eval)));

    // Fraction-sum chain: (P, Q) += (p_s, q_s) via P' = P·q_s + p_s·Q,
    // Q' = Q·q_s — three authenticated products per additional site. The
    // final Q = Π_s q_s, so the cross-check's inv(Q) row certifies EVERY
    // site's q_s ≠ 0.
    let (mut pr, mut qr) = sites[0];
    let mut agg_corrs = Vec::with_capacity(sites.len().saturating_sub(1));
    for &(ps, qs) in &sites[1..] {
        let zx = [pr.x * qs.x, ps.x * qr.x, qr.x * qs.x];
        let dom = doms.take(1);
        let masks = stream.draw_fulls(dom, 3);
        agg_corrs.push([zx[0] - masks[0].x, zx[1] - masks[1].x, zx[2] - masks[2].x]);
        tx.append("logup_aggregate_corrections", 48);
        let z1 = ProverAuthed { x: zx[0], m: masks[0].m };
        let z2 = ProverAuthed { x: zx[1], m: masks[1].m };
        let z3 = ProverAuthed { x: zx[2], m: masks[2].m };
        prod.push((pr, qs, z1));
        prod.push((ps, qr, z2));
        prod.push((qr, qs, z3));
        pr = z1.add(z2);
        qr = z3;
        ctr.bulk(3, 0);
    }
    let cross_corrs = cross_prover((pr, qr), roots_t, stream, doms, tx, ctr, prod, zero);

    (
        TableSideProof { table: tp, agg_corrs, cross_corrs },
        OpenClaim { point: pt_t, value: ProverAuthed::ZERO.sub(cp_t) },
    )
}

/// Verifier mirror of [`table_side_prove`].
#[allow(clippy::too_many_arguments)]
pub fn table_side_verify(
    table_vals: &[Fp],
    alpha: Fp2,
    proof: &TableSideProof,
    ksites: &[(VerifierKey, VerifierKey)],
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Option<OpenKey> {
    if ksites.is_empty() || proof.agg_corrs.len() != ksites.len() - 1 {
        return None;
    }
    let t_bits = table_vals.len().trailing_zeros() as usize;
    let (pt_t, kcp_t, kcq_t, kroots_t) =
        blind_verify_frac_tree(t_bits, &proof.table, ctx, doms, tx, kprod, kzero)?;
    let t_eval = {
        let lifted: Vec<Fp2> = table_vals.iter().map(|&v| alpha - Fp2::from_base(v)).collect();
        crate::mle::eval_mle(&lifted, &pt_t)
    };
    kzero.push(kcq_t.sub(VerifierKey::from_public(t_eval, ctx.delta)));

    let (mut kpr, mut kqr) = ksites[0];
    for (&(kps, kqs), corrs) in ksites[1..].iter().zip(&proof.agg_corrs) {
        let kms = ctx.expand_full_keys(doms.take(1), 3);
        let kz: Vec<VerifierKey> =
            kms.iter().zip(corrs).map(|(&k, &c)| VerifierKey { k: k + ctx.delta * c }).collect();
        kprod.push((kpr, kqs, kz[0]));
        kprod.push((kps, kqr, kz[1]));
        kprod.push((kqr, kqs, kz[2]));
        kpr = kz[0].add(kz[1]);
        kqr = kz[2];
    }
    cross_verifier((kpr, kqr), kroots_t, &proof.cross_corrs, ctx, doms, kprod, kzero);

    Some(OpenKey { point: pt_t, key: VerifierKey::ZERO.sub(kcp_t) })
}

pub struct BlindLogupProof {
    pub lookup: BlindFracProof,
    pub table: BlindFracProof,
    /// Corrections for z_a = p_f·q_t, z_b = p_t·q_f, inv(q_f), inv(q_t).
    pub cross_corrs: [Fp2; 4],
}

impl BlindLogupProof {
    pub fn bytes(&self) -> u64 {
        self.lookup.bytes() + self.table.bytes() + 64
    }
}

/// Blind LogUp: `f` and `mult` secret, `table` public. Contract: the caller
/// authenticated `f` and `mult` (boundary auth) BEFORE drawing challenges
/// here; α is bound by that ordering. Returns the two open evaluation
/// claims (f̃ at the lookup point, m̃ at the table point) for the caller to
/// close against the authenticated vectors; the table-side denominator
/// closes against the public table (zero row), likewise p_f ≡ 1.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn blind_logup_prove(
    f: &[i16],
    table: &[i16],
    mult: &[u32],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (BlindLogupProof, Fp2, OpenClaim, OpenClaim) {
    let alpha = tx.challenge_fp2();
    let (pf_proof, pt_f, cp_f, cq_f, roots_f) =
        blind_prove_frac_tree(&LeafP::Ones, &lift_q(f, alpha), stream, doms, tx, ctr, prod, zero);
    let (pt_proof, pt_t, cp_t, cq_t, roots_t) = blind_prove_frac_tree(
        &LeafP::NegMult(mult),
        &lift_q(table, alpha),
        stream,
        doms,
        tx,
        ctr,
        prod,
        zero,
    );

    // Leaf closures that need no external opening:
    //   lookup-side numerator ≡ 1, table-side denominator = α − t̃(point).
    zero.push(cp_f.sub(ProverAuthed::from_public(Fp2::ONE)));
    let t_eval = {
        let lifted: Vec<Fp2> =
            table.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect();
        eval_mle_counted(&lifted, &pt_t, ctr)
    };
    zero.push(cq_t.sub(ProverAuthed::from_public(t_eval)));

    let cross_corrs = cross_prover(roots_f, roots_t, stream, doms, tx, ctr, prod, zero);

    // Open claims: f̃(pt_f) = α − cq_f (value side), m̃(pt_t) = −cp_t.
    let f_claim = OpenClaim { point: pt_f, value: ProverAuthed::from_public(alpha).sub(cq_f) };
    let m_claim = OpenClaim { point: pt_t, value: ProverAuthed::ZERO.sub(cp_t) };
    (BlindLogupProof { lookup: pf_proof, table: pt_proof, cross_corrs }, alpha, f_claim, m_claim)
}

/// Blind LogUp verifier. `n_bits`/`t_bits` are the two tree depths. The
/// caller must close the returned open-claim keys plus the accumulated
/// `kprod`/`kzero` (Π_Prod and Π_ZeroBatch) to finish the argument.
#[allow(clippy::too_many_arguments)]
pub fn blind_logup_verify(
    n_bits: usize,
    table: &[i16],
    proof: &BlindLogupProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Option<(OpenKey, OpenKey)> {
    let t_bits = table.len().trailing_zeros() as usize;
    let alpha = tx.challenge_fp2();
    let (pt_f, kcp_f, kcq_f, kroots_f) =
        blind_verify_frac_tree(n_bits, &proof.lookup, ctx, doms, tx, kprod, kzero)?;
    let (pt_t, kcp_t, kcq_t, kroots_t) =
        blind_verify_frac_tree(t_bits, &proof.table, ctx, doms, tx, kprod, kzero)?;

    kzero.push(kcp_f.sub(VerifierKey::from_public(Fp2::ONE, ctx.delta)));
    let t_eval = {
        let lifted: Vec<Fp2> =
            table.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect();
        crate::mle::eval_mle(&lifted, &pt_t)
    };
    kzero.push(kcq_t.sub(VerifierKey::from_public(t_eval, ctx.delta)));

    cross_verifier(kroots_f, kroots_t, &proof.cross_corrs, ctx, doms, kprod, kzero);

    let f_key = OpenKey { point: pt_f, key: VerifierKey::from_public(alpha, ctx.delta).sub(kcq_f) };
    let m_key = OpenKey { point: pt_t, key: VerifierKey::ZERO.sub(kcp_t) };
    Some((f_key, m_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    #[cfg(feature = "cuda")]
    fn active_resident_bytes(backend: &Backend) -> u64 {
        let live = backend.stats().unwrap().live_device_bytes;
        let memory = backend.device_memory_breakdown().unwrap();
        let accounted = memory
            .workspace_bytes
            .checked_add(memory.resident_bytes)
            .and_then(|bytes| bytes.checked_add(memory.cached_resident_bytes))
            .expect("resident CUDA memory accounting overflow");
        assert_eq!(live, accounted, "resident CUDA memory categories must sum to live bytes");
        memory.resident_bytes
    }

    fn chal_pair(seed_byte: u8) -> (FpStream, FpStream) {
        let s = [seed_byte; 32];
        (FpStream::domain_separated(s, 0x1004), FpStream::domain_separated(s, 0x1004))
    }

    fn instance(n: usize, table_bits: u32, rng: &mut impl Rng) -> (Vec<i16>, Vec<i16>, Vec<u32>) {
        let table: Vec<i16> =
            (0..1i32 << table_bits).map(|j| (j - (1 << (table_bits - 1))) as i16).collect();
        let f: Vec<i16> = (0..n).map(|_| table[rng.gen_range(0..table.len())]).collect();
        let mut mult = vec![0u32; table.len()];
        let offset = 1i32 << (table_bits - 1);
        for &v in &f {
            mult[(v as i32 + offset) as usize] += 1;
        }
        (f, table, mult)
    }

    #[test]
    fn frac_tree_completeness_all_depths() {
        for bits in 1..8u32 {
            let n = 1usize << bits;
            let f: Vec<i16> = (0..n as i16).map(|i| i - (n / 2) as i16).collect();
            let (mut cp, mut cv) = chal_pair(200 + bits as u8);
            let alpha = cp.next_fp2();
            assert_eq!(alpha, cv.next_fp2());
            let mut ctr = Counters::default();
            let proof = prove_frac_tree(&LeafP::Ones, &lift_q(&f, alpha), &mut cp, &mut ctr);
            let lifted: Vec<Fp2> =
                f.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect();
            let ok = verify_frac_tree(
                &proof,
                |_p, _c| Fp2::ONE,
                |p, c| eval_mle_counted(&lifted, p, c),
                &mut cv,
                &mut ctr,
            );
            assert!(ok, "ones-tree completeness failed at depth {bits}");
        }
    }

    #[test]
    fn frac_tree_completeness_negmult() {
        for bits in 1..8u32 {
            let n = 1usize << bits;
            let t: Vec<i16> = (0..n as i16).collect();
            let mult: Vec<u32> = (0..n as u32).map(|i| (i * 7 + 1) % 23).collect();
            let (mut cp, mut cv) = chal_pair(220 + bits as u8);
            let alpha = cp.next_fp2();
            assert_eq!(alpha, cv.next_fp2());
            let mut ctr = Counters::default();
            let proof =
                prove_frac_tree(&LeafP::NegMult(&mult), &lift_q(&t, alpha), &mut cp, &mut ctr);
            let lifted: Vec<Fp2> =
                t.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect();
            let mvals: Vec<Fp2> =
                mult.iter().map(|&m| neg(Fp2::from_base(Fp::new(m as u64)))).collect();
            let ok = verify_frac_tree(
                &proof,
                |p, c| eval_mle_counted(&mvals, p, c),
                |p, c| eval_mle_counted(&lifted, p, c),
                &mut cv,
                &mut ctr,
            );
            assert!(ok, "negmult-tree completeness failed at depth {bits}");
        }
    }

    #[test]
    fn logup_accepts_valid_multiset() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(31);
        let (f, table, mult) = instance(1 << 10, 6, &mut rng);
        let (mut cp, mut cv) = chal_pair(1);
        let mut ctr = Counters::default();
        let (_a, proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        assert!(logup_verify(&f, &table, &mult, &proof, &mut cv, &mut ctr));
    }

    #[test]
    fn logup_rejects_wrong_multiplicity() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(32);
        let (f, table, mut mult) = instance(1 << 8, 5, &mut rng);
        mult[3] += 1;
        let (mut cp, mut cv) = chal_pair(2);
        let mut ctr = Counters::default();
        let (_a, proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        assert!(!logup_verify(&f, &table, &mult, &proof, &mut cv, &mut ctr));
    }

    #[test]
    fn logup_rejects_out_of_table() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(33);
        let (mut f, table, mult) = instance(1 << 8, 5, &mut rng);
        f[7] = i16::MAX;
        let (mut cp, mut cv) = chal_pair(3);
        let mut ctr = Counters::default();
        let (_a, proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        assert!(!logup_verify(&f, &table, &mult, &proof, &mut cv, &mut ctr));
    }

    #[test]
    fn logup_rejects_tampered_round_message() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(34);
        let (f, table, mult) = instance(1 << 8, 5, &mut rng);
        let (mut cp, mut cv) = chal_pair(4);
        let mut ctr = Counters::default();
        let (_a, mut proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        let last = proof.lookup_side.layers.last_mut().unwrap();
        last.rounds[2][1] = last.rounds[2][1] + Fp2::ONE;
        assert!(!logup_verify(&f, &table, &mult, &proof, &mut cv, &mut ctr));
    }

    #[test]
    fn logup_rejects_tampered_split_claim() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(35);
        let (f, table, mult) = instance(1 << 8, 5, &mut rng);
        let (mut cp, mut cv) = chal_pair(5);
        let mut ctr = Counters::default();
        let (_a, mut proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        proof.table_side.layers[1].q0 = proof.table_side.layers[1].q0 + Fp2::ONE;
        assert!(!logup_verify(&f, &table, &mult, &proof, &mut cv, &mut ctr));
    }

    // ------------------------------------------------------------------
    // Blind mode
    // ------------------------------------------------------------------

    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};

    struct BlindHarness {
        ps: CorrelationStream,
        vc: VerifierCtx,
        txp: Transcript,
        txv: Transcript,
    }

    fn harness(seed: u8, rng: &mut impl Rng) -> BlindHarness {
        let cs = [seed; 32];
        let ts = [seed ^ 0xAA; 32];
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        BlindHarness {
            ps: CorrelationStream::new(cs),
            vc: VerifierCtx::new(cs, delta),
            txp: Transcript::new(ts),
            txv: Transcript::new(ts),
        }
    }

    /// Run blind logup end-to-end, close Π_Prod + Π_ZeroBatch, and MAC-open
    /// the two leaf claims against the true evaluations. `tamper` mutates
    /// the proof between prove and verify.
    fn blind_case(
        seed: u8,
        n_bits: usize,
        t_bits: u32,
        tamper: impl FnOnce(&mut BlindLogupProof),
    ) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 700);
        let (f, table, mult) = instance(1 << n_bits, t_bits, &mut rng);
        let mut h = harness(seed, &mut rng);
        let mut ctr = Counters::default();

        let mut domsp = Doms::new(500);
        let mut prod: ProdTriples = Vec::new();
        let mut zero: Vec<ProverAuthed> = Vec::new();
        let (mut proof, _alpha, f_claim, m_claim) = blind_logup_prove(
            &f, &table, &mult, &mut h.ps, &mut domsp, &mut h.txp, &mut ctr, &mut prod, &mut zero,
        );
        tamper(&mut proof);

        let mut domsv = Doms::new(500);
        let mut kprod: ProdKeyTriples = Vec::new();
        let mut kzero: Vec<VerifierKey> = Vec::new();
        let Some((f_key, m_key)) = blind_logup_verify(
            n_bits, &table, &proof, &mut h.vc, &mut domsv, &mut h.txv, &mut kprod, &mut kzero,
        ) else {
            return false;
        };

        // Close the leaf claims against the true evaluations (stand-in for
        // the step-2 wire openings; both sides computable in the test).
        let f_vals: Vec<Fp2> = f.iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect();
        let m_vals: Vec<Fp2> = mult.iter().map(|&m| Fp2::from_base(Fp::new(m as u64))).collect();
        let f_true = crate::mle::eval_mle(&f_vals, &f_claim.point);
        let m_true = crate::mle::eval_mle(&m_vals, &m_claim.point);
        zero.push(f_claim.value.sub(ProverAuthed::from_public(f_true)));
        zero.push(m_claim.value.sub(ProverAuthed::from_public(m_true)));
        kzero.push(f_key.key.sub(VerifierKey::from_public(f_true, h.vc.delta)));
        kzero.push(m_key.key.sub(VerifierKey::from_public(m_true, h.vc.delta)));

        // Batched closures (mask domains after everything else).
        let chi = h.txp.challenge_fp2();
        assert_eq!(chi, h.txv.challenge_fp2());
        let mask = h.ps.draw_fulls(9000, 1)[0];
        let k_mask = h.vc.expand_full_keys(9000, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut h.txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, h.vc.delta, chi, &pp);
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut h.ps, &mut h.vc, 9001, &mut h.txp);
        ok_prod && ok_zero
    }

    #[test]
    fn blind_logup_completeness() {
        assert!(blind_case(41, 8, 5, |_| {}));
        assert!(blind_case(42, 6, 6, |_| {}));
        assert!(blind_case(43, 5, 3, |_| {}));
    }

    #[test]
    fn blind_logup_rejects_tampered_round_corr() {
        assert!(!blind_case(44, 8, 5, |p| {
            let last = p.lookup.layers.last_mut().unwrap();
            last.round_corrs[1][0] += Fp2::ONE;
        }));
    }

    #[test]
    fn blind_logup_rejects_tampered_split_corr() {
        assert!(!blind_case(45, 8, 5, |p| {
            p.table.layers[1].split_corrs[2] += Fp2::ONE;
        }));
    }

    #[test]
    fn blind_logup_rejects_tampered_product_corr() {
        assert!(!blind_case(46, 8, 5, |p| {
            p.lookup.layers[2].z_corrs[0] += Fp2::ONE;
        }));
    }

    #[test]
    fn blind_logup_rejects_tampered_root() {
        assert!(!blind_case(47, 8, 5, |p| {
            p.lookup.root_corrs[0] += Fp2::ONE;
        }));
    }

    /// A dishonest witness (wrong multiplicity) must fail even when the
    /// prover runs the honest protocol on it. Mirrors the clear smoke, in
    /// blind mode; the root cross-check zero row catches it.
    #[test]
    fn blind_logup_rejects_wrong_witness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(748);
        let (f, table, mut mult) = instance(1 << 8, 5, &mut rng);
        mult[3] += 1;
        let mut h = harness(48, &mut rng);
        let mut ctr = Counters::default();
        let mut domsp = Doms::new(500);
        let mut prod: ProdTriples = Vec::new();
        let mut zero: Vec<ProverAuthed> = Vec::new();
        // The layer-end debug assert would fire on a false relation only if
        // the tree itself were inconsistent — a wrong multiset keeps every
        // layer honest, only the root cross-check is violated. The zero row
        // za+zb is nonzero, so zero_batch_prover's debug assert would fire;
        // emulate the cheating prover by clearing the offending row's x.
        let (proof, _a, _fc, _mc) = blind_logup_prove(
            &f, &table, &mult, &mut h.ps, &mut domsp, &mut h.txp, &mut ctr, &mut prod, &mut zero,
        );
        let mut domsv = Doms::new(500);
        let mut kprod: ProdKeyTriples = Vec::new();
        let mut kzero: Vec<VerifierKey> = Vec::new();
        if blind_logup_verify(
            8, &table, &proof, &mut h.vc, &mut domsv, &mut h.txv, &mut kprod, &mut kzero,
        )
        .is_none()
        {
            return; // early reject also fine
        }
        // Cheating prover zeroes the nonzero cross row value (keeps tag).
        for row in zero.iter_mut() {
            if row.x != Fp2::ZERO {
                row.x = Fp2::ZERO;
            }
        }
        let chi = h.txp.challenge_fp2();
        assert_eq!(chi, h.txv.challenge_fp2());
        let mask = h.ps.draw_fulls(9000, 1)[0];
        let k_mask = h.vc.expand_full_keys(9000, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut h.txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, h.vc.delta, chi, &pp);
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut h.ps, &mut h.vc, 9001, &mut h.txp);
        assert!(!(ok_prod && ok_zero), "wrong multiplicity accepted in blind mode");
    }

    /// Blind and clear must agree message-by-message: reconstruct the blind
    /// h-values and splits from corrections + the shared mask stream and
    /// compare with a clear run under the transcript's challenge stream.
    #[test]
    fn blind_matches_clear_differential() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(749);
        let (f, table, mult) = instance(1 << 7, 4, &mut rng);
        let mut h = harness(49, &mut rng);
        let mut ctr = Counters::default();
        let mut domsp = Doms::new(500);
        let mut prod: ProdTriples = Vec::new();
        let mut zero: Vec<ProverAuthed> = Vec::new();
        let (proof, alpha, _fc, _mc) = blind_logup_prove(
            &f, &table, &mult, &mut h.ps, &mut domsp, &mut h.txp, &mut ctr, &mut prod, &mut zero,
        );

        // Clear reference under the same challenges: Transcript challenges
        // come from domain u64::MAX of the tx seed.
        let mut chal = FpStream::domain_separated([49 ^ 0xAA; 32], u64::MAX);
        let mut cctr = Counters::default();
        let (alpha_c, cproof) = logup_prove(&f, &table, &mult, &mut chal, &mut cctr);
        assert_eq!(alpha, alpha_c);

        // Replay the mask stream in the exact domain order.
        let mut check = CorrelationStream::new([49; 32]);
        let mut doms = Doms::new(500);
        for (side, cside) in
            [(&proof.lookup, &cproof.lookup_side), (&proof.table, &cproof.table_side)]
        {
            let rm = check.draw_fulls(doms.take(1), 2);
            assert_eq!(rm[0].x + side.root_corrs[0], cside.root_p, "root p");
            assert_eq!(rm[1].x + side.root_corrs[1], cside.root_q, "root q");
            for (l, layer) in side.layers.iter().enumerate() {
                for (j, rc) in layer.round_corrs.iter().enumerate() {
                    let ms = check.draw_fulls(doms.take(1), 2);
                    assert_eq!(ms[0].x + rc[0], cside.layers[l].rounds[j][0], "h0 l{l} r{j}");
                    assert_eq!(ms[1].x + rc[1], cside.layers[l].rounds[j][1], "h2 l{l} r{j}");
                }
                let sm = check.draw_fulls(doms.take(1), 4);
                let cl = &cside.layers[l];
                for (k, expect) in [cl.p0, cl.p1, cl.q0, cl.q1].iter().enumerate() {
                    assert_eq!(sm[k].x + layer.split_corrs[k], *expect, "split {k} layer {l}");
                }
                let _zm = check.draw_fulls(doms.take(1), 3);
            }
        }
    }

    // ------------------------------------------------------------------
    // Instance mode (aux-claim folding)
    // ------------------------------------------------------------------

    /// Authenticate a value both sides (test-only mock-stream shortcut).
    fn authed_at(
        ps: &mut CorrelationStream,
        vc: &mut VerifierCtx,
        dom: u64,
        x: Fp2,
    ) -> (ProverAuthed, VerifierKey) {
        let f = ps.draw_fulls(dom, 1)[0];
        let kf = vc.expand_full_keys(dom, 1)[0];
        (ProverAuthed { x, m: f.m }, VerifierKey { k: kf + vc.delta * (x - f.x) })
    }

    fn rand_point(rng: &mut impl Rng, n: usize) -> Vec<Fp2> {
        (0..n)
            .map(|_| {
                Fp2::new(
                    Fp::new(rng.gen_range(0..volta_field::P)),
                    Fp::new(rng.gen_range(0..volta_field::P)),
                )
            })
            .collect()
    }

    /// Pair-LUT instance: table t_j = in + 2^16·out; external claims on both
    /// cols at random points; full closure incl. resolving the col claims
    /// against true evaluations. `tamper` mutates the proof.
    fn instance_case(seed: u8, tamper: impl FnOnce(&mut BlindInstance)) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 900);
        let (n_bits, t_bits) = (7usize, 5u32);
        let n = 1usize << n_bits;
        let tin: Vec<i16> = (0..1i16 << t_bits).map(|j| j - (1 << (t_bits - 1))).collect();
        let tout: Vec<i16> = tin.iter().map(|&x| x.wrapping_mul(x) >> 2).collect();
        let idx: Vec<usize> = (0..n).map(|_| rng.gen_range(0..tin.len())).collect();
        let xcol: Vec<Fp> = idx.iter().map(|&j| Fp::from_i64(tin[j] as i64)).collect();
        let ycol: Vec<Fp> = idx.iter().map(|&j| Fp::from_i64(tout[j] as i64)).collect();
        let mut mult = vec![0u32; tin.len()];
        for &j in &idx {
            mult[j] += 1;
        }
        let table_vals: Vec<Fp> = tin
            .iter()
            .zip(&tout)
            .map(|(&i, &o)| Fp::from_i64(i as i64) + Fp::from_i64(o as i64) * Fp::new(1 << 16))
            .collect();

        let mut h = harness(seed, &mut rng);
        let mut ctr = Counters::default();
        // External claims (values = true evals, authenticated).
        let rho_x = rand_point(&mut rng, n_bits);
        let rho_y = rand_point(&mut rng, n_bits);
        let xf: Vec<Fp2> = xcol.iter().map(|&v| Fp2::from_base(v)).collect();
        let yf: Vec<Fp2> = ycol.iter().map(|&v| Fp2::from_base(v)).collect();
        let vx = crate::mle::eval_mle(&xf, &rho_x);
        let vy = crate::mle::eval_mle(&yf, &rho_y);
        let (ax, kx) = authed_at(&mut h.ps, &mut h.vc, 400, vx);
        let (ay, ky) = authed_at(&mut h.ps, &mut h.vc, 401, vy);

        let mut domsp = Doms::new(500);
        let mut prod: ProdTriples = Vec::new();
        let mut zero: Vec<ProverAuthed> = Vec::new();
        let aux_claims = vec![
            LeafAuxClaim { col: 0, point: rho_x.clone(), value: ax },
            LeafAuxClaim { col: 1, point: rho_y.clone(), value: ay },
        ];
        let shifts = [Some(0u32), Some(16u32)];
        let alpha = h.txp.challenge_fp2();
        let mut out = blind_instance_prove(
            &[xcol.clone(), ycol.clone()],
            &shifts,
            alpha,
            aux_claims,
            &mut h.ps,
            &mut domsp,
            &mut h.txp,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        let (ts, mult_claim) = table_side_prove(
            &table_vals,
            &mult,
            alpha,
            &[out.roots],
            &mut h.ps,
            &mut domsp,
            &mut h.txp,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        tamper(&mut out.proof);

        let mut domsv = Doms::new(500);
        let mut kprod: ProdKeyTriples = Vec::new();
        let mut kzero: Vec<VerifierKey> = Vec::new();
        let aux_meta = vec![(0usize, rho_x, kx), (1usize, rho_y, ky)];
        let alpha_v = h.txv.challenge_fp2();
        assert_eq!(alpha, alpha_v);
        let Some(vout) = blind_instance_verify(
            n_bits, &shifts, alpha_v, &out.proof, &aux_meta, &mut h.vc, &mut domsv, &mut h.txv,
            &mut kprod, &mut kzero,
        ) else {
            return false;
        };
        let Some(mult_key) = table_side_verify(
            &table_vals,
            alpha_v,
            &ts,
            &[vout.kroots],
            &mut h.vc,
            &mut domsv,
            &mut h.txv,
            &mut kprod,
            &mut kzero,
        ) else {
            return false;
        };

        // Resolve the consolidated col claims + mult claim (true evals).
        let x_true = crate::mle::eval_mle(&xf, &out.point);
        let y_true = crate::mle::eval_mle(&yf, &out.point);
        let m_vals: Vec<Fp2> = mult.iter().map(|&m| Fp2::from_base(Fp::new(m as u64))).collect();
        let m_true = crate::mle::eval_mle(&m_vals, &mult_claim.point);
        for (claim, (key, tv)) in
            out.col_claims.iter().zip(vout.col_keys.iter().zip([x_true, y_true]))
        {
            zero.push(claim.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(key.key.sub(VerifierKey::from_public(tv, h.vc.delta)));
        }
        zero.push(mult_claim.value.sub(ProverAuthed::from_public(m_true)));
        kzero.push(mult_key.key.sub(VerifierKey::from_public(m_true, h.vc.delta)));

        let chi = h.txp.challenge_fp2();
        assert_eq!(chi, h.txv.challenge_fp2());
        let mask = h.ps.draw_fulls(9000, 1)[0];
        let k_mask = h.vc.expand_full_keys(9000, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut h.txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, h.vc.delta, chi, &pp);
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut h.ps, &mut h.vc, 9001, &mut h.txp);
        ok_prod && ok_zero
    }

    #[test]
    fn instance_pair_completeness() {
        assert!(instance_case(60, |_| {}));
        assert!(instance_case(61, |_| {}));
    }

    #[test]
    fn instance_rejects_tampered_col_corr() {
        assert!(!instance_case(62, |p| {
            p.lookup.aux.as_mut().unwrap().col_corrs[1][0] += Fp2::ONE;
        }));
    }

    #[test]
    fn instance_rejects_tampered_round3() {
        assert!(!instance_case(63, |p| {
            p.lookup.aux.as_mut().unwrap().rounds3[3][2] += Fp2::ONE;
        }));
    }

    /// Range instance: rem packed, out as unpacked aux col; the emitted acc
    /// claim (2^s·oũt + rẽm − 2^{s−1}) must match the true accumulator MLE —
    /// the full requant claim transport.
    #[test]
    fn instance_range_requant_transport() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(964);
        let (n_bits, s) = (7usize, 4u32);
        let n = 1usize << n_bits;
        let acc: Vec<i64> = (0..n).map(|_| rng.gen_range(-4000i64..4000)).collect();
        let out: Vec<i64> = acc.iter().map(|&a| (a + 8) >> 4).collect();
        let rem: Vec<i64> = acc.iter().zip(&out).map(|(&a, &o)| a + 8 - (o << 4)).collect();
        assert!(rem.iter().all(|&r| (0..16).contains(&r)));
        let mut mult = vec![0u32; 16];
        for &r in &rem {
            mult[r as usize] += 1;
        }
        let table_vals: Vec<Fp> = (0..16).map(Fp::new).collect();
        let rem_col: Vec<Fp> = rem.iter().map(|&r| Fp::new(r as u64)).collect();
        let out_col: Vec<Fp> = out.iter().map(|&o| Fp::from_i64(o)).collect();

        let mut h = harness(64, &mut rng);
        let mut ctr = Counters::default();
        // Consumer claim on OUT at a random point.
        let rho = rand_point(&mut rng, n_bits);
        let of: Vec<Fp2> = out_col.iter().map(|&v| Fp2::from_base(v)).collect();
        let vo = crate::mle::eval_mle(&of, &rho);
        let (ao, ko) = authed_at(&mut h.ps, &mut h.vc, 400, vo);

        let mut domsp = Doms::new(500);
        let mut prod: ProdTriples = Vec::new();
        let mut zero: Vec<ProverAuthed> = Vec::new();
        let shifts = [Some(0u32), None];
        let alpha = h.txp.challenge_fp2();
        let out_p = blind_instance_prove(
            &[rem_col.clone(), out_col.clone()],
            &shifts,
            alpha,
            vec![LeafAuxClaim { col: 1, point: rho.clone(), value: ao }],
            &mut h.ps,
            &mut domsp,
            &mut h.txp,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        let (ts, mult_claim) = table_side_prove(
            &table_vals,
            &mult,
            alpha,
            &[out_p.roots],
            &mut h.ps,
            &mut domsp,
            &mut h.txp,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        let mut domsv = Doms::new(500);
        let mut kprod: ProdKeyTriples = Vec::new();
        let mut kzero: Vec<VerifierKey> = Vec::new();
        let alpha_v = h.txv.challenge_fp2();
        assert_eq!(alpha, alpha_v);
        let vout = blind_instance_verify(
            n_bits,
            &shifts,
            alpha_v,
            &out_p.proof,
            &[(1usize, rho, ko)],
            &mut h.vc,
            &mut domsv,
            &mut h.txv,
            &mut kprod,
            &mut kzero,
        )
        .expect("verify");
        let mult_key = table_side_verify(
            &table_vals,
            alpha_v,
            &ts,
            &[vout.kroots],
            &mut h.vc,
            &mut domsv,
            &mut h.txv,
            &mut kprod,
            &mut kzero,
        )
        .expect("table side");

        // Emit the acc claim from the requant relation and check it against
        // the true accumulator MLE (the upstream GEMM would consume this).
        let two_s = Fp2::from_base(Fp::new(1 << s));
        let half_s = Fp2::from_base(Fp::new(1 << (s - 1)));
        let acc_claim = out_p.col_claims[1]
            .value
            .scale(two_s)
            .add(out_p.col_claims[0].value)
            .sub(ProverAuthed::from_public(half_s));
        let acc_key = vout.col_keys[1]
            .key
            .scale(two_s)
            .add(vout.col_keys[0].key)
            .sub(VerifierKey::from_public(half_s, h.vc.delta));
        let af: Vec<Fp2> = acc.iter().map(|&a| Fp2::from_base(Fp::from_i64(a))).collect();
        let acc_true = crate::mle::eval_mle(&af, &out_p.point);
        assert_eq!(acc_claim.x, acc_true, "acc transport value mismatch");
        zero.push(acc_claim.sub(ProverAuthed::from_public(acc_true)));
        kzero.push(acc_key.sub(VerifierKey::from_public(acc_true, h.vc.delta)));
        // mult claim
        let m_vals: Vec<Fp2> = mult.iter().map(|&m| Fp2::from_base(Fp::new(m as u64))).collect();
        let m_true = crate::mle::eval_mle(&m_vals, &mult_claim.point);
        zero.push(mult_claim.value.sub(ProverAuthed::from_public(m_true)));
        kzero.push(mult_key.key.sub(VerifierKey::from_public(m_true, h.vc.delta)));

        let chi = h.txp.challenge_fp2();
        assert_eq!(chi, h.txv.challenge_fp2());
        let mask = h.ps.draw_fulls(9000, 1)[0];
        let k_mask = h.vc.expand_full_keys(9000, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut h.txp);
        assert!(prod_batch_verify(&kprod, k_mask, h.vc.delta, chi, &pp));
        assert!(zero_batch_exchange(&zero, &kzero, &mut h.ps, &mut h.vc, 9001, &mut h.txp));
    }

    /// Same instance through the P2.5 spike's semantics is checked in
    /// volta-bench (differential); here: the counter must be well below the
    /// spike's measured 23.2 E-mult/lookup on a mid-size instance.
    #[test]
    fn emult_constant_improves_on_spike() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(36);
        let n = 1 << 14;
        let (f, table, mult) = instance(n, 10, &mut rng);
        let (mut cp, _cv) = chal_pair(6);
        let mut ctr = Counters::default();
        let (_a, _proof) = logup_prove(&f, &table, &mult, &mut cp, &mut ctr);
        let per_lookup = ctr.emult_equiv() / n as f64;
        // Includes the (unamortized at n=2^14, 2^10 table) table side.
        assert!(
            per_lookup < 16.0,
            "prover E-mult/lookup {per_lookup:.1} not clearly below spike's 23.2"
        );
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_lookup_instance_matches_cpu_and_reuses_source() {
        let mut resident = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident lookup-instance differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };

        // Model a padded range-lookup site: the remainder is packed into the
        // leaf while the output column participates only in the aux closure.
        let entries = 64usize;
        let logical_entries = 45usize;
        let mut remainder = vec![Fp::ZERO; entries];
        let mut output = vec![Fp::ZERO; entries];
        for i in 0..logical_entries {
            remainder[i] = Fp::new(((i * 11 + 3) % 16) as u64);
            output[i] = Fp::from_i64((i as i64 * 37 - 701) / 9);
        }
        let columns = [remainder.clone(), output.clone()];
        let shifts = [Some(0u32), None];
        let alpha = Fp2::new(Fp::new(0x1234_5678), Fp::new(0x9abc_def0));
        let external_point: Vec<Fp2> = (0..entries.ilog2())
            .map(|i| Fp2::new(Fp::new(i as u64 * 101 + 7), Fp::new(i as u64 * 127 + 11)))
            .collect();
        let output_lifted: Vec<Fp2> = output.iter().copied().map(Fp2::from_base).collect();
        let external_value = crate::mle::eval_mle(&output_lifted, &external_point);
        let external_auth =
            ProverAuthed { x: external_value, m: Fp2::new(Fp::new(0xfeed), Fp::new(0xcafe)) };

        let make_aux =
            || vec![LeafAuxClaim { col: 1, point: external_point.clone(), value: external_auth }];
        let finish = |out: InstanceOutP,
                      prod: ProdTriples,
                      zero: Vec<ProverAuthed>,
                      ctr: Counters,
                      stream: CorrelationStream,
                      tx: Transcript| {
            let InstanceOutP { proof, alpha, point, col_claims, roots } = out;
            let claims: Vec<(Vec<Fp2>, ProverAuthed)> =
                col_claims.into_iter().map(|claim| (claim.point, claim.value)).collect();
            (
                proof,
                alpha,
                point,
                claims,
                roots,
                prod,
                zero,
                ctr,
                stream.counters,
                tx.ledger().clone(),
            )
        };

        let expected = {
            let mut stream = CorrelationStream::new([71; 32]);
            let mut doms = Doms::new(0x7100);
            let mut tx = Transcript::new([72; 32]);
            let mut ctr = Counters::default();
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let out = blind_instance_prove(
                &columns,
                &shifts,
                alpha,
                make_aux(),
                &mut stream,
                &mut doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
            );
            finish(out, prod, zero, ctr, stream, tx)
        };

        let raw_columns: Vec<u64> =
            columns.iter().flat_map(|column| column.iter().map(|value| value.value())).collect();
        let resident_before_source = active_resident_bytes(&resident);
        let device_columns = resident.upload_new_device(&raw_columns).unwrap();
        resident.begin_measurement().unwrap();
        let run_resident = |backend: &mut Backend| {
            let mut stream = CorrelationStream::new([71; 32]);
            let mut doms = Doms::new(0x7100);
            let mut tx = Transcript::new([72; 32]);
            let mut ctr = Counters::default();
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let view = DeviceSlice::new(&device_columns, 0, raw_columns.len()).unwrap();
            let out = blind_instance_prove_resident(
                view,
                columns.len(),
                entries,
                &shifts,
                alpha,
                make_aux(),
                &mut stream,
                &mut doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
                backend,
            )
            .unwrap();
            finish(out, prod, zero, ctr, stream, tx)
        };

        let got = run_resident(&mut resident);
        assert_eq!(got, expected);
        let live_after_first = resident.stats().unwrap().live_device_bytes;
        let got_reused = run_resident(&mut resident);
        assert_eq!(got_reused, expected);
        assert_eq!(
            resident.stats().unwrap().live_device_bytes,
            live_after_first,
            "resident lookup instance leaked across context reuse"
        );
        let stats = resident.finish_measurement().unwrap();
        assert!(stats.operation(Operation::Logup).calls > 0);
        assert_eq!(stats.operation(Operation::Logup).cpu_residual_ns, 0);
        resident.free_device(device_columns).unwrap();
        assert_eq!(
            active_resident_bytes(&resident),
            resident_before_source,
            "resident lookup source allocation remained active after free"
        );
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_blind_tree_and_aux_proofs_match_cpu_byte_for_byte() {
        let mut gpu = match Backend::cuda_hybrid() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA LogUp differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let n = 1 << 10;
        let vals: Vec<Fp> =
            (0..n).map(|i| Fp::new((i as u64 * 0x9E37_79B9 + 17) % volta_field::P)).collect();
        let mult: Vec<u32> = (0..n).map(|i| ((i * 19 + 7) % 31) as u32).collect();
        let alpha = Fp2::new(Fp::new(12345), Fp::new(67890));

        let run = |backend: Option<&mut Backend>| {
            let q = lift_q_fp(&vals, alpha);
            let mut stream = CorrelationStream::new([41; 32]);
            let mut doms = Doms::new(0x4100);
            let mut tx = Transcript::new([42; 32]);
            let mut ctr = Counters::default();
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let out = blind_prove_frac_tree_impl(
                &LeafP::NegMult(&mult),
                &q,
                &mut stream,
                &mut doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
                backend,
            );
            (out, prod, zero, ctr, stream.counters, tx.ledger().clone())
        };
        let expected = run(None);
        gpu.begin_measurement().unwrap();
        let got = run(Some(&mut gpu));
        assert_eq!(got, expected);

        let run_aux = |backend: Option<&mut Backend>| {
            let q = lift_q_fp(&vals, alpha);
            let point: Vec<Fp2> = (0..10)
                .map(|i| Fp2::new(Fp::new(i as u64 * 101 + 7), Fp::new(i as u64 * 127 + 11)))
                .collect();
            let lifted: Vec<Fp2> = vals.iter().copied().map(Fp2::from_base).collect();
            let value = crate::mle::eval_mle(&lifted, &point);
            let mut aux = LeafAux {
                cols: vec![aux_col(&vals)],
                claims: vec![LeafAuxClaim {
                    col: 0,
                    point,
                    value: ProverAuthed::from_public(value),
                }],
            };
            let mut stream = CorrelationStream::new([51; 32]);
            let mut doms = Doms::new(0x5100);
            let mut tx = Transcript::new([52; 32]);
            let mut ctr = Counters::default();
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let out = blind_prove_frac_tree_aux_impl(
                &q,
                &mut aux,
                &mut stream,
                &mut doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
                backend,
            );
            (out, prod, zero, ctr, stream.counters, tx.ledger().clone())
        };
        let expected_aux = run_aux(None);
        let got_aux = run_aux(Some(&mut gpu));
        assert_eq!(got_aux, expected_aux);
        let hybrid_stats = gpu.finish_measurement().unwrap();
        assert!(hybrid_stats.operation(Operation::Logup).calls > 0);
        assert!(hybrid_stats.operation(Operation::Logup).cpu_residual_ns > 0);

        let mut resident =
            Backend::cuda_resident().unwrap_or_else(|e| panic!("CUDA required: {e}"));
        resident.begin_measurement().unwrap();
        let got_resident = run(Some(&mut resident));
        assert_eq!(got_resident, expected);
        let got_aux_resident = run_aux(Some(&mut resident));
        assert_eq!(got_aux_resident, expected_aux);
        let live_after_first = resident.stats().unwrap().live_device_bytes;
        let got_resident_reused = run(Some(&mut resident));
        let got_aux_resident_reused = run_aux(Some(&mut resident));
        assert_eq!(got_resident_reused, expected);
        assert_eq!(got_aux_resident_reused, expected_aux);
        assert_eq!(
            resident.stats().unwrap().live_device_bytes,
            live_after_first,
            "resident LogUp leaked across context reuse"
        );
        let resident_stats = resident.finish_measurement().unwrap();
        assert!(resident_stats.operation(Operation::Logup).calls > 0);
        assert_eq!(resident_stats.operation(Operation::Logup).cpu_residual_ns, 0);
        assert!(
            resident_stats.d2h_bytes < hybrid_stats.d2h_bytes,
            "resident upper tree must return fewer bytes than staged LogUp"
        );
    }
}

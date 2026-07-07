//! P2.5 spike: clear (unauthenticated) LogUp fractional-GKR prover/verifier,
//! Papini–Haböck style, to measure the per-lookup prover constant before P4.
//!
//! Claim: Σ_i 1/(α − f_i) = Σ_j mult_j/(α − t_j). Each side is a binary
//! fraction tree with leaves (1, α−f_i) resp. (−mult_j, α−t_j) and combine
//! rule (p₁,q₁)+(p₂,q₂) = (p₁q₂+p₂q₁, q₁q₂); no field inversions anywhere on
//! the prover path. One degree-3 sumcheck per layer walks the claims from the
//! two roots down to the leaf MLEs, which the (clear) verifier evaluates
//! itself. Interactive-mock challenges from a shared ChaCha stream, as in P2.
//!
//! MLE variable order is LSB-first: node y's children are 2y (bit 0) and
//! 2y+1 (bit 1), so a child evaluation point is the parent's point with the
//! child-bit challenge prepended.
//!
//! Every field multiplication is counted (`Counters`): a full `Fp2` mul
//! weighs 5 base mults, `mul_base` weighs 2 — `emult_equiv` is what the
//! budget's "O(1) E-mults per lookup" line is compared against.

use volta_field::{Fp, Fp2, FpStream};

#[derive(Clone, Copy, Debug, Default)]
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
    fn mul_base(&mut self, a: Fp2, b: Fp) -> Fp2 {
        self.base_mults += 2;
        a.mul_base(b)
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

impl LeafP<'_> {
    fn value(&self, i: usize) -> Fp2 {
        match self {
            LeafP::Ones => Fp2::ONE,
            LeafP::NegMult(m) => neg(Fp2::from_base(Fp::new(m[i] as u64))),
        }
    }
}

/// One layer's sumcheck messages plus the four end-of-layer split claims.
pub struct LayerProof {
    /// Per round: g(0), g(2), g(3) — g(1) = claim − g(0).
    pub rounds: Vec<[Fp2; 3]>,
    pub p0: Fp2,
    pub p1: Fp2,
    pub q0: Fp2,
    pub q1: Fp2,
}

pub struct FracProof {
    pub root_p: Fp2,
    pub root_q: Fp2,
    pub layers: Vec<LayerProof>,
}

impl FracProof {
    /// Transcript bytes: 16 B per Fp2 message.
    pub fn bytes(&self) -> u64 {
        32 + self.layers.iter().map(|l| 16 * (3 * l.rounds.len() as u64 + 4)).sum::<u64>()
    }
}

/// Cubic interpolation of g at r from evals at nodes {0,1,2,3}.
fn interp_cubic(g: [Fp2; 4], r: Fp2, ctr: &mut Counters) -> Fp2 {
    let six_inv = Fp::new(6).inv();
    let two_inv = Fp::new(2).inv();
    let m: [Fp2; 4] = core::array::from_fn(|k| r - Fp2::from_base(Fp::new(k as u64)));
    let n01 = ctr.mul(m[0], m[1]);
    let n23 = ctr.mul(m[2], m[3]);
    let t12 = ctr.mul(m[1], m[2]);
    let t123 = ctr.mul(t12, m[3]);
    let t230 = ctr.mul(n23, m[0]);
    let t013 = ctr.mul(n01, m[3]);
    let t012 = ctr.mul(n01, m[2]);
    let l0 = ctr.mul_base(t123, six_inv.neg());
    let l1 = ctr.mul_base(t230, two_inv);
    let l2 = ctr.mul_base(t013, two_inv.neg());
    let l3 = ctr.mul_base(t012, six_inv);
    let s0 = ctr.mul(l0, g[0]);
    let s1 = ctr.mul(l1, g[1]);
    let s2 = ctr.mul(l2, g[2]);
    let s3 = ctr.mul(l3, g[3]);
    s0 + s1 + s2 + s3
}

/// eq(r, r') for equal-length points.
fn eq_points(r: &[Fp2], rp: &[Fp2], ctr: &mut Counters) -> Fp2 {
    let mut acc = Fp2::ONE;
    for (&a, &b) in r.iter().zip(rp) {
        let ab = ctr.mul(a, b);
        acc = ctr.mul(acc, ab + ab - a - b + Fp2::ONE); // ab + (1−a)(1−b)
    }
    acc
}

/// eq(r, ·) table over 2^len entries, LSB-first.
fn eq_table(r: &[Fp2], ctr: &mut Counters) -> Vec<Fp2> {
    let mut t = vec![Fp2::ONE];
    // Each pass makes the processed variable the LSB of the table index, so
    // process in reverse to end LSB-first overall.
    for &ri in r.iter().rev() {
        let mut next = Vec::with_capacity(t.len() * 2);
        for &v in &t {
            let v1 = ctr.mul(v, ri);
            next.push(v - v1);
            next.push(v1);
        }
        t = next;
    }
    t
}

/// Linear evaluation v(t) for t ∈ {0,2,3} from (v(0), v(1)) — adds only.
#[inline]
fn at_t(v0: Fp2, v1: Fp2, t: u32) -> Fp2 {
    let d = v1 - v0;
    match t {
        0 => v0,
        2 => v0 + d + d,
        3 => v0 + d + d + d,
        _ => unreachable!(),
    }
}

struct Tree {
    /// p[k], q[k]: layer-k vectors of size 2^k; q[depth] are the leaf
    /// denominators (leaf numerators stay implicit in `LeafP`).
    p: Vec<Vec<Fp2>>,
    q: Vec<Vec<Fp2>>,
    depth: usize,
}

/// Build all internal layers from the leaves (N−1 combines total).
fn build_tree(leaf_p: &LeafP, leaf_q: Vec<Fp2>, ctr: &mut Counters) -> Tree {
    let n = leaf_q.len();
    assert!(n.is_power_of_two() && n >= 2);
    let depth = n.trailing_zeros() as usize;
    let mut p_layers = vec![Vec::new(); depth + 1];
    let mut q_layers = vec![Vec::new(); depth + 1];

    // First combine exploits leaf structure (numerators are 1 / small ints).
    let mut p_cur: Vec<Fp2> = match leaf_p {
        LeafP::Ones => leaf_q.chunks_exact(2).map(|c| c[0] + c[1]).collect(),
        LeafP::NegMult(mult) => {
            assert_eq!(mult.len(), n);
            leaf_q
                .chunks_exact(2)
                .zip(mult.chunks_exact(2))
                .map(|(qc, mc)| {
                    neg(ctr.mul_base(qc[1], Fp::new(mc[0] as u64))
                        + ctr.mul_base(qc[0], Fp::new(mc[1] as u64)))
                })
                .collect()
        }
    };
    let mut q_cur: Vec<Fp2> = leaf_q.chunks_exact(2).map(|c| ctr.mul(c[0], c[1])).collect();
    q_layers[depth] = leaf_q;

    for k in (1..depth).rev() {
        let (p_next, q_next): (Vec<Fp2>, Vec<Fp2>) = (0..p_cur.len() / 2)
            .map(|i| {
                let (pa, pb) = (p_cur[2 * i], p_cur[2 * i + 1]);
                let (qa, qb) = (q_cur[2 * i], q_cur[2 * i + 1]);
                (ctr.mul(pa, qb) + ctr.mul(pb, qa), ctr.mul(qa, qb))
            })
            .unzip();
        p_layers[k] = std::mem::replace(&mut p_cur, p_next);
        q_layers[k] = std::mem::replace(&mut q_cur, q_next);
    }
    p_layers[0] = p_cur;
    q_layers[0] = q_cur;
    Tree { p: p_layers, q: q_layers, depth }
}

/// Prove one fraction tree top-down. `chal` must be consumed in lockstep by
/// the verifier (interactive-mock DV exchange).
pub fn prove_frac_tree(
    leaf_p: &LeafP,
    leaf_q: Vec<Fp2>,
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> FracProof {
    let tree = build_tree(leaf_p, leaf_q, ctr);
    let mut layers = Vec::with_capacity(tree.depth);
    let mut point: Vec<Fp2> = Vec::new(); // claim point for layer l, LSB-first

    for l in 0..tree.depth {
        let _lambda = chal.next_fp2(); // drawn for parity with the verifier
        let lambda = _lambda;
        let s = 1usize << l;
        let leaf_layer = l + 1 == tree.depth;
        let mut p0: Vec<Fp2>;
        let mut p1: Vec<Fp2>;
        if leaf_layer {
            p0 = (0..s).map(|i| leaf_p.value(2 * i)).collect();
            p1 = (0..s).map(|i| leaf_p.value(2 * i + 1)).collect();
        } else {
            p0 = (0..s).map(|i| tree.p[l + 1][2 * i]).collect();
            p1 = (0..s).map(|i| tree.p[l + 1][2 * i + 1]).collect();
        }
        let mut q0: Vec<Fp2> = (0..s).map(|i| tree.q[l + 1][2 * i]).collect();
        let mut q1: Vec<Fp2> = (0..s).map(|i| tree.q[l + 1][2 * i + 1]).collect();
        let mut eq = eq_table(&point, ctr);

        let mut rounds = Vec::with_capacity(l);
        let mut rprime = Vec::with_capacity(l);
        for _ in 0..l {
            let half = eq.len() / 2;
            let mut g = [Fp2::ZERO; 3]; // evals at t = 0, 2, 3
            for i in 0..half {
                for (slot, &t) in [0u32, 2, 3].iter().enumerate() {
                    let e = at_t(eq[2 * i], eq[2 * i + 1], t);
                    let a = at_t(p0[2 * i], p0[2 * i + 1], t);
                    let b = at_t(p1[2 * i], p1[2 * i + 1], t);
                    let c = at_t(q0[2 * i], q0[2 * i + 1], t);
                    let d = at_t(q1[2 * i], q1[2 * i + 1], t);
                    let ad = ctr.mul(a, d);
                    let bc = ctr.mul(b, c);
                    let cd = ctr.mul(c, d);
                    let frac = ctr.mul(lambda, ad + bc) + cd;
                    g[slot] += ctr.mul(e, frac);
                }
            }
            rounds.push(g);
            let r = chal.next_fp2();
            rprime.push(r);
            for v in [&mut eq, &mut p0, &mut p1, &mut q0, &mut q1] {
                for i in 0..half {
                    let d = v[2 * i + 1] - v[2 * i];
                    v[i] = v[2 * i] + ctr.mul(d, r);
                }
                v.truncate(half);
            }
        }
        layers.push(LayerProof { rounds, p0: p0[0], p1: p1[0], q0: q0[0], q1: q1[0] });

        // Child claim point: child-bit challenge prepended to r' (LSB-first).
        let t = chal.next_fp2();
        point = std::iter::once(t).chain(rprime).collect();
    }
    FracProof { root_p: tree.p[0][0], root_q: tree.q[0][0], layers }
}

/// Verify one fraction tree against leaf-MLE evaluations supplied by the
/// caller (the clear verifier computes them itself). Returns the final claim
/// checked, or None on rejection.
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
        let mut rprime = Vec::with_capacity(l);
        for g3 in &layer.rounds {
            let g = [g3[0], claim - g3[0], g3[1], g3[2]]; // g(1) = claim − g(0)
            let r = chal.next_fp2();
            claim = interp_cubic(g, r, ctr);
            rprime.push(r);
        }
        // Final check: claim == eq(point, r')·(λ(p0q1+p1q0) + q0q1).
        let eqv = eq_points(&point, &rprime, ctr);
        let ad = ctr.mul(layer.p0, layer.q1);
        let bc = ctr.mul(layer.p1, layer.q0);
        let cd = ctr.mul(layer.q0, layer.q1);
        let frac = ctr.mul(lambda, ad + bc) + cd;
        if claim != ctr.mul(eqv, frac) {
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

/// Fold-based MLE evaluation (LSB-first variables).
pub fn eval_mle(values: &[Fp2], point: &[Fp2], ctr: &mut Counters) -> Fp2 {
    assert_eq!(values.len(), 1 << point.len());
    let mut v = values.to_vec();
    for &r in point {
        let half = v.len() / 2;
        for i in 0..half {
            let d = v[2 * i + 1] - v[2 * i];
            v[i] = v[2 * i] + ctr.mul(d, r);
        }
        v.truncate(half);
    }
    v[0]
}

/// LogUp instance: lookups `f` into `table` with multiplicities `mult`.
pub struct LogupProof {
    pub lookup_side: FracProof,
    pub table_side: FracProof,
}

impl LogupProof {
    pub fn bytes(&self) -> u64 {
        self.lookup_side.bytes() + self.table_side.bytes()
    }
}

fn lift_q(values: &[i16], alpha: Fp2) -> Vec<Fp2> {
    values.iter().map(|&v| alpha - Fp2::from_base(Fp::from_i64(v as i64))).collect()
}

pub fn logup_prove(
    f: &[i16],
    table: &[i16],
    mult: &[u32],
    chal: &mut FpStream,
    ctr: &mut Counters,
) -> (Fp2, LogupProof) {
    let alpha = chal.next_fp2();
    let lookup_side = prove_frac_tree(&LeafP::Ones, lift_q(f, alpha), chal, ctr);
    let table_side = prove_frac_tree(&LeafP::NegMult(mult), lift_q(table, alpha), chal, ctr);
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
    let cross_a = ctr.mul(pf, qt);
    let cross_b = ctr.mul(pt, qf);
    if cross_a + cross_b != Fp2::ZERO || qf == Fp2::ZERO || qt == Fp2::ZERO {
        return false;
    }
    let ok_f = verify_frac_tree(
        &proof.lookup_side,
        |_pt, _c| Fp2::ONE,
        |pt_, c| eval_mle(&lift_q(f, alpha), pt_, c),
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
            eval_mle(&vals, pt_, c)
        },
        |pt_, c| eval_mle(&lift_q(table, alpha), pt_, c),
        chal,
        ctr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn chal_pair(seed_byte: u8) -> (FpStream, FpStream) {
        let s = [seed_byte; 32];
        (FpStream::domain_separated(s, 0xC4A1), FpStream::domain_separated(s, 0xC4A1))
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
    fn frac_tree_completeness_small() {
        for bits in 1..6u32 {
            let n = 1usize << bits;
            let f: Vec<i16> = (0..n as i16).collect();
            let (mut cp, mut cv) = chal_pair(200 + bits as u8);
            let alpha = cp.next_fp2();
            let alpha_v = cv.next_fp2();
            assert_eq!(alpha, alpha_v);
            let mut ctr = Counters::default();
            let proof = prove_frac_tree(&LeafP::Ones, super::lift_q(&f, alpha), &mut cp, &mut ctr);
            let ok = verify_frac_tree(
                &proof,
                |_p, _c| Fp2::ONE,
                |p, c| eval_mle(&super::lift_q(&f, alpha), p, c),
                &mut cv,
                &mut ctr,
            );
            assert!(ok, "single tree completeness failed at depth {bits}");
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
        f[7] = i16::MAX; // not in the 5-bit table; mult can't account for it
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
}

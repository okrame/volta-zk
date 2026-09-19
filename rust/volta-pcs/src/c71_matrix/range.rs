//! Same-W range caller: private histogram, fraction-tree GKR, original MAC
//! endpoint. Reuses the LogUp tree relation, with native Fp3 and cubic rounds.
//! The caller closes the returned forms/targets in ONE linear PCS batch.

use super::*;

component_wire!(Layer { rounds, split });
component_wire!(Proof { histogram, roots, layers, leaf_tag, products });
use linear::Cube;

#[derive(Clone, Copy)]
pub(super) enum Alphabet {
    Symmetric(i16),
    Byte,
}

impl From<i16> for Alphabet {
    fn from(limit: i16) -> Self {
        Self::Symmetric(limit)
    }
}

impl Alphabet {
    fn len(self) -> usize {
        match self {
            Self::Symmetric(limit) if limit > 0 => 2 * limit as usize + 1,
            Self::Symmetric(_) => 0,
            Self::Byte => 256,
        }
    }

    fn lower(self) -> i64 {
        match self {
            Self::Symmetric(limit) => -i64::from(limit),
            Self::Byte => 0,
        }
    }
}

pub(super) struct Layer {
    rounds: Vec<[Fp3; 5]>,
    split: [Fp3; 8], // four children, three products, one zero-MAC tag
}

pub(super) fn tree_proof_heap_capacity_bytes(layers: &[Layer], capacity: usize) -> usize {
    capacity * core::mem::size_of::<Layer>()
        + layers
            .iter()
            .map(|layer| layer.rounds.capacity() * core::mem::size_of::<[Fp3; 5]>())
            .sum::<usize>()
}

#[cfg(test)]
pub(super) fn tree_proof_logical_heap_bytes(depth: usize, top_bits: usize) -> usize {
    depth * core::mem::size_of::<Layer>()
        + (0..depth)
            .map(|layer| (top_bits + layer) * core::mem::size_of::<[Fp3; 5]>())
            .sum::<usize>()
}

pub(super) struct Proof {
    histogram: Vec<Fp3>,
    roots: [Fp3; 3], // numerator, denominator, denominator inverse
    layers: Vec<Layer>,
    leaf_tag: Fp3,
    products: [Fp3; 2],
}

pub(super) fn required(bits: usize, limit: impl Into<Alphabet>) -> usize {
    limit.into().len() + 2 * bits * bits + 5 * bits + 4
}

#[allow(clippy::too_many_arguments)]
fn bind(
    domain: impl Into<Domain>,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: impl Into<Alphabet>,
    fs: &mut Fs,
) -> Result<usize, String> {
    let domain = domain.into();
    let config = domain.config()?;
    let limit = limit.into();
    if limit.len() == 0
        || live == 0
        || live > 1usize << config.num_variables
        || root.num_roots() != 1
        || !attempt.valid()
        || layout == [0; 32]
    {
        return Err("B12 range statement mismatch".into());
    }
    let mut bytes = match limit {
        Alphabet::Symmetric(_) => {
            b"C71-range-B12-v1;MSB-first;symmetric;zero-suffix;original-MAC".to_vec()
        }
        Alphabet::Byte => {
            b"C71-range-B12-v1;MSB-first;byte-0-255;zero-suffix;original-MAC".to_vec()
        }
    };
    bytes.extend(gamma(&config));
    bytes.extend(domain.identity().to_le_bytes());
    bytes.extend(root.roots()[0]);
    bytes.extend(attempt.encode());
    bytes.extend(layout);
    bytes.extend((live as u64).to_le_bytes());
    if let Alphabet::Symmetric(limit) = limit {
        bytes.extend(limit.to_le_bytes());
    }
    fs.set_phase(0x400);
    fs.record(0x40, &bytes);
    Ok(config.num_variables)
}

// A public forbidden alpha is rejected independently of the private histogram.
fn challenges(
    bits: usize,
    limit: Alphabet,
    fs: &mut Fs,
) -> Result<(Fp3, Vec<Fp3>, Vec<Fp3>), String> {
    let alpha = fs.fp3();
    let mut denominators = Vec::with_capacity(limit.len());
    for t in limit.lower()..limit.lower() + limit.len() as i64 {
        let d = alpha - signed(t);
        if d == Fp3::ZERO {
            return Err("B12 range public pole".into());
        }
        denominators.push(d.inv());
    }
    let point: Vec<_> = (0..bits).map(|_| fs.fp3()).collect();
    Ok((alpha, denominators, point))
}

fn suffix(live: usize, point: &[Fp3]) -> Vec<Cube> {
    let mut offset = live;
    let mut result = Vec::new();
    while offset < 1usize << point.len() {
        let bits = offset.trailing_zeros() as usize;
        let prefix = point.len() - bits;
        let coefficient = point[..prefix].iter().enumerate().fold(Fp3::ONE, |s, (i, &r)| {
            s * if offset >> (point.len() - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        result.push(Cube { offset, point: point[prefix..].to_vec(), coefficient });
        offset += 1usize << bits;
    }
    result
}

pub(super) fn authenticate<const N: usize>(
    values: [Fp3; N],
    rows: &mut std::vec::IntoIter<Auth>,
) -> ([Fp3; N], [Auth; N]) {
    let mut wire = [Fp3::ZERO; N];
    let auth = std::array::from_fn(|i| {
        let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), values[i]);
        wire[i] = c.value();
        a
    });
    (wire, auth)
}

pub(super) fn correct<const N: usize>(
    wire: [Fp3; N],
    delta: Fp3,
    rows: &mut std::vec::IntoIter<Key>,
) -> [Key; N] {
    std::array::from_fn(|i| {
        c7_fp3_transfer_verifier(rows.next().unwrap(), delta, C7Fp3TransferCorrection::new(wire[i]))
    })
}

// One fresh mask for the ENTIRE ordered product batch, after every triple is
// fixed in the transcript. k=m+Delta*x. No division by lambda or Delta.
pub(super) fn prove_products(triples: &[[Auth; 3]], mask: Auth, fs: &mut Fs) -> [Fp3; 2] {
    fs.set_phase(0x600);
    let lambda = fs.fp3();
    let wire = c7_fp3_product_batch_prover(triples.iter().copied(), mask, lambda);
    record_values(fs, 0x45, &wire);
    wire
}

pub(super) fn verify_products(
    triples: &[[Key; 3]],
    mask: Key,
    wire: [Fp3; 2],
    delta: Fp3,
    fs: &mut Fs,
) -> Result<(), String> {
    fs.set_phase(0x600);
    let lambda = fs.fp3();
    if !c7_fp3_product_batch_verify(triples.iter().copied(), mask, wire, lambda, delta) {
        return Err("B12 range product MAC rejected".into());
    }
    record_values(fs, 0x45, &wire);
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn prove(
    model: &Model,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: impl Into<Alphabet>,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, [Vec<Cube>; 2], [Auth; 2]), String> {
    let weights: Vec<_> = model
        .polynomial()
        .as_slice()
        .iter()
        .map(|x| Fp3::from_base(Fp::new(x.as_canonical_u64())))
        .collect();
    prove_from_getter(
        model.domain,
        &model.root,
        attempt,
        layout,
        live,
        limit.into(),
        &|i| weights[i],
        false,
        fs,
        correlations,
    )
}

/// Reduced reference: immutable original source, no dense witness or fraction tree.
/// Regeneration is charged to proof work; this is not the canonical GPU schedule.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn prove_sourcewise(
    domain: Domain,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: impl Into<Alphabet>,
    get: &impl Fn(usize) -> Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, [Vec<Cube>; 2], [Auth; 2]), String> {
    prove_from_getter(
        domain,
        root,
        attempt,
        layout,
        live,
        limit.into(),
        get,
        true,
        fs,
        correlations,
    )
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn prove_from_getter(
    domain: Domain,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: Alphabet,
    get: &impl Fn(usize) -> Fp3,
    sourcewise: bool,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, [Vec<Cube>; 2], [Auth; 2]), String> {
    let bits = bind(domain, root, attempt, layout, live, limit, fs)?;
    let count = required(bits, limit);
    if correlations.len() < count {
        return Err("B12 range prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let mut histogram = vec![Fp3::ZERO; limit.len()];
    for i in 0..(1usize << bits) {
        let w = get(i);
        let index = (w - signed(limit.lower())).c0.value();
        // A candidate with an out-of-range private witness is still provable
        // syntactically; the verifier's rational/product check must reject it.
        if index < histogram.len() as u64 {
            histogram[index as usize] += Fp3::ONE;
        }
    }
    let (histogram, authed): (Vec<_>, Vec<_>) = histogram
        .into_iter()
        .map(|h| {
            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), h);
            (c.value(), a)
        })
        .unzip();
    record_values(fs, 0x41, &histogram);
    let (alpha, inverse, rho) = challenges(bits, limit, fs)?;
    let h = authed.iter().zip(&inverse).fold(Auth::ZERO, |s, (&a, &d)| s.add(a.scale(d)));
    // ponytail: scalar subtree regeneration is the small-input oracle. The
    // canonical canopy/Gram schedule must supply its own work/traffic ledger.
    fn subtree(get: &impl Fn(usize) -> Fp3, alpha: Fp3, height: usize, index: usize) -> [Fp3; 2] {
        if height == 0 {
            return [Fp3::ONE, alpha - get(index)];
        }
        let [p, q] = subtree(get, alpha, height - 1, 2 * index);
        let [r, s] = subtree(get, alpha, height - 1, 2 * index + 1);
        [p * s + r * q, q * s]
    }
    let tree = if sourcewise {
        Vec::new()
    } else {
        let mut tree =
            vec![(0..(1usize << bits)).map(|i| [Fp3::ONE, alpha - get(i)]).collect::<Vec<_>>()];
        while tree.last().unwrap().len() > 1 {
            tree.push(
                tree.last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| {
                        let ([p, q], [r, s]) = (pair[0], pair[1]);
                        [p * s + r * q, q * s]
                    })
                    .collect(),
            );
        }
        tree
    };
    let [p, q] = if sourcewise { subtree(get, alpha, bits, 0) } else { tree.last().unwrap()[0] };
    if q == Fp3::ZERO {
        return Err("B12 range witness pole".into());
    }
    let (roots, root) = authenticate([p, q, q.inv()], &mut rows);
    fs.set_phase(0x401);
    record_values(fs, 0x42, &roots);
    let mut triples =
        vec![[h, root[1], root[0]], [root[1], root[2], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let (layers, point, claims) = if sourcewise {
        let (layers, point, claims, _) = prove_tree_sourcewise(
            bits,
            Vec::new(),
            [root[0], root[1]],
            |layer, index| {
                let [p, q] = subtree(get, alpha, bits - 1 - layer, 2 * index);
                let [r, s] = subtree(get, alpha, bits - 1 - layer, 2 * index + 1);
                [p, q, r, s]
            },
            fs,
            &mut rows,
            &mut triples,
        );
        (layers, point, claims)
    } else {
        prove_tree(&tree, Vec::new(), [root[0], root[1]], fs, &mut rows, &mut triples)
    };
    let leaf_tag = claims[0].m; // numerator is the constant one at every leaf
    record_values(fs, 0x46, &[leaf_tag]);
    let products = prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    let target = Auth::new(alpha - claims[1].x, -claims[1].m);
    let forms = [vec![Cube { offset: 0, point, coefficient: Fp3::ONE }], suffix(live, &rho)];
    Ok((Proof { histogram, roots, layers, leaf_tag, products }, forms, [target, Auth::ZERO]))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn verify(
    domain: impl Into<Domain>,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    limit: impl Into<Alphabet>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<([Vec<Cube>; 2], [Key; 2]), String> {
    let limit = limit.into();
    let bits = bind(domain, root, attempt, layout, live, limit, fs)?;
    let count = required(bits, limit);
    if proof.histogram.len() != limit.len()
        || !tree_shape(&proof.layers, bits, 0)
        || correlations.len() < count
    {
        return Err("B12 range proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let histogram: Vec<_> =
        proof.histogram.iter().map(|&c| correct([c], delta, &mut rows)[0]).collect();
    record_values(fs, 0x41, &proof.histogram);
    let (alpha, inverse, rho) = challenges(bits, limit, fs)?;
    let h = histogram.iter().zip(&inverse).fold(Key::ZERO, |s, (&a, &d)| s.add(a.scale(d)));
    let root = correct(proof.roots, delta, &mut rows);
    fs.set_phase(0x401);
    record_values(fs, 0x42, &proof.roots);
    let mut triples = vec![[h, root[1], root[0]], [root[1], root[2], Key::new(delta)]];
    let (point, claims) = verify_tree(
        &proof.layers,
        Vec::new(),
        [root[0], root[1]],
        delta,
        fs,
        &mut rows,
        &mut triples,
    )?;
    if claims[0].k - delta != proof.leaf_tag {
        return Err("B12 range leaf MAC rejected".into());
    }
    record_values(fs, 0x46, &[proof.leaf_tag]);
    verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    debug_assert!(rows.next().is_none());
    let target = Key::new(delta * alpha - claims[1].k);
    let forms = [vec![Cube { offset: 0, point, coefficient: Fp3::ONE }], suffix(live, &rho)];
    Ok((forms, [target, Key::ZERO]))
}

// Shared fraction-tree kernel. The top may be a public multilinear point
// over cells/lanes; each descent appends the next tree-index coordinate.
// Callers validate dimensions and reserve every row before entering here.
pub(super) fn prove_tree(
    tree: &[Vec<[Fp3; 2]>],
    point: Vec<Fp3>,
    claims: [Auth; 2],
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
    triples: &mut Vec<[Auth; 3]>,
) -> (Vec<Layer>, Vec<Fp3>, [Auth; 2]) {
    prove_tree_with_first_weight(tree, point, claims, fs, rows, triples, None)
}

/// Source-level accounting for the scalar regenerating fraction-tree prover.
/// These are exact Rust operations/getter calls, not machine instructions or
/// a runtime lower. Proof/output vectors and correlation storage remain
/// external; `owned_regeneration_heap_peak_bytes` counts only the coexisting
/// input-point, next-point and incremental prefix-weight capacities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct SourceTreeWork {
    pub getter_calls: u64,
    pub getter_scalar_values: u64,
    pub prefix_terms: u64,
    pub equality_multiplications: u64,
    pub equality_additions: u64,
    pub equality_subtractions: u64,
    pub cubic_multiplications: u64,
    pub cubic_additions: u64,
    pub cubic_subtractions: u64,
    pub fold_multiplications: u64,
    pub fold_additions: u64,
    pub fold_subtractions: u64,
    pub eq_weights_capacity_bytes: usize,
    pub owned_regeneration_heap_peak_bytes: usize,
}

fn source_folded_children(
    layer: usize,
    original: usize,
    challenges: &[Fp3],
    suffix: usize,
    get: &impl Fn(usize, usize) -> [Fp3; 4],
    weights: &mut Vec<Fp3>,
    work: &mut SourceTreeWork,
) -> [Fp3; 4] {
    let q = challenges.len();
    let current = original >> q;
    let mut sums = [Fp3::ZERO; 4];
    weights.clear();
    weights.push(Fp3::ONE);
    for (bit, &r) in challenges.iter().enumerate() {
        weights.push(weights[bit] * (Fp3::ONE - r));
        work.equality_multiplications += 1;
        work.equality_subtractions += 1;
    }
    work.eq_weights_capacity_bytes =
        work.eq_weights_capacity_bytes.max(weights.capacity() * core::mem::size_of::<Fp3>());
    for prefix in 0..1usize << q {
        if prefix != 0 {
            let start = q - 1 - prefix.trailing_zeros() as usize;
            for bit in start..q {
                let r = challenges[bit];
                let factor = if prefix >> (q - 1 - bit) & 1 == 1 {
                    r
                } else {
                    work.equality_subtractions += 1;
                    Fp3::ONE - r
                };
                weights[bit + 1] = weights[bit] * factor;
                work.equality_multiplications += 1;
            }
        }
        let values = get(layer, prefix * current + suffix);
        work.getter_calls += 1;
        work.getter_scalar_values += 4;
        work.prefix_terms += 1;
        for child in 0..4 {
            sums[child] += weights[q] * values[child];
            work.fold_multiplications += 1;
            work.fold_additions += 1;
        }
    }
    sums
}

fn source_folded_equality(
    point: &[Fp3],
    challenges: &[Fp3],
    suffix: usize,
    work: &mut SourceTreeWork,
) -> Fp3 {
    let mut value = Fp3::ONE;
    for (&p, &r) in point.iter().zip(challenges) {
        value = value * ((Fp3::ONE - p) * (Fp3::ONE - r) + p * r);
        work.equality_multiplications += 3;
        work.equality_additions += 1;
        work.equality_subtractions += 2;
    }
    let tail = &point[challenges.len()..];
    for (bit, &p) in tail.iter().enumerate() {
        value = value * if suffix >> (tail.len() - 1 - bit) & 1 == 1 { p } else { Fp3::ONE - p };
        work.equality_multiplications += 1;
        if suffix >> (tail.len() - 1 - bit) & 1 == 0 {
            work.equality_subtractions += 1;
        }
    }
    value
}

/// Transcript-identical scalar reference for a fraction tree supplied by four
/// public child functions per layer. It regenerates prior folds and retains no
/// vector proportional to the multilinear domain. This is deliberately a CPU
/// reference; an admitted canonical schedule still needs the bounded Gram
/// implementation and its own complete traffic/runtime ledger.
pub(super) fn prove_tree_sourcewise(
    bits: usize,
    mut point: Vec<Fp3>,
    mut claims: [Auth; 2],
    get: impl Fn(usize, usize) -> [Fp3; 4],
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
    triples: &mut Vec<[Auth; 3]>,
) -> (Vec<Layer>, Vec<Fp3>, [Auth; 2], SourceTreeWork) {
    let mut layers = Vec::with_capacity(bits);
    triples.reserve_exact(3 * bits);
    let mut work = SourceTreeWork::default();
    let mut prefix_weights = Vec::with_capacity(point.len() + bits);
    for l in 0..bits {
        let lambda = fs.fp3();
        let mut target = claims[0].scale(lambda).add(claims[1]);
        let original = 1usize << point.len();
        let (mut next_point, mut rounds) =
            (Vec::with_capacity(point.len() + 1), Vec::with_capacity(point.len()));
        work.owned_regeneration_heap_peak_bytes = work
            .owned_regeneration_heap_peak_bytes
            .max(point.capacity() * core::mem::size_of::<Fp3>());
        for round in 0..point.len() {
            fs.set_phase(0x500 + (32 * l + round) as u16);
            let current = original >> round;
            let half = current / 2;
            let mut c = [Fp3::ZERO; 4];
            for i in 0..half {
                let a = source_folded_children(
                    l,
                    original,
                    &next_point,
                    i,
                    &get,
                    &mut prefix_weights,
                    &mut work,
                );
                let upper = source_folded_children(
                    l,
                    original,
                    &next_point,
                    i + half,
                    &get,
                    &mut prefix_weights,
                    &mut work,
                );
                let d: [Fp3; 4] = std::array::from_fn(|child| upper[child] - a[child]);
                work.cubic_subtractions += 4;
                let mut v = [Fp3::ZERO; 3];
                for (x, y, coefficient) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
                    v[0] += coefficient * a[x] * a[y];
                    v[1] += coefficient * (d[x] * a[y] + a[x] * d[y]);
                    v[2] += coefficient * d[x] * d[y];
                    work.cubic_multiplications += 7;
                    work.cubic_additions += 4;
                }
                let equality = source_folded_equality(&point, &next_point, i, &mut work);
                let equality_hi = source_folded_equality(&point, &next_point, i + half, &mut work);
                let de = equality_hi - equality;
                work.cubic_subtractions += 1;
                for j in 0..3 {
                    c[j] += equality * v[j];
                    c[j + 1] += de * v[j];
                    work.cubic_multiplications += 2;
                    work.cubic_additions += 2;
                }
            }
            work.owned_regeneration_heap_peak_bytes = work.owned_regeneration_heap_peak_bytes.max(
                (point.capacity() + next_point.capacity()) * core::mem::size_of::<Fp3>()
                    + work.eq_weights_capacity_bytes,
            );
            let (corrections, a) = authenticate(c, rows);
            let tag = a[0].m + a[0].m + a[1].m + a[2].m + a[3].m - target.m;
            let wire = [corrections[0], corrections[1], corrections[2], corrections[3], tag];
            record_values(fs, 0x43, &wire);
            let r = fs.fp3();
            target = a.iter().rev().fold(Auth::ZERO, |s, &x| s.scale(r).add(x));
            next_point.push(r);
            work.owned_regeneration_heap_peak_bytes = work
                .owned_regeneration_heap_peak_bytes
                .max((point.capacity() + next_point.capacity()) * core::mem::size_of::<Fp3>());
            rounds.push(wire);
        }
        let folded = source_folded_children(
            l,
            original,
            &next_point,
            0,
            &get,
            &mut prefix_weights,
            &mut work,
        );
        work.owned_regeneration_heap_peak_bytes = work.owned_regeneration_heap_peak_bytes.max(
            (point.capacity() + next_point.capacity()) * core::mem::size_of::<Fp3>()
                + work.eq_weights_capacity_bytes,
        );
        let [p, q, r, s] = folded;
        let equality = source_folded_equality(&point, &next_point, 0, &mut work);
        let (wire, a) = authenticate([p, q, r, s, p * s, r * q, q * s], rows);
        triples.extend([[a[0], a[3], a[4]], [a[2], a[1], a[5]], [a[1], a[3], a[6]]]);
        let residual = a[4].add(a[5]).scale(lambda).add(a[6]).scale(equality);
        let split =
            [wire[0], wire[1], wire[2], wire[3], wire[4], wire[5], wire[6], residual.m - target.m];
        fs.set_phase(0x410 + l as u16);
        record_values(fs, 0x44, &split);
        let t = fs.fp3();
        claims = [
            a[0].scale(Fp3::ONE - t).add(a[2].scale(t)),
            a[1].scale(Fp3::ONE - t).add(a[3].scale(t)),
        ];
        next_point.push(t);
        point = next_point;
        layers.push(Layer { rounds, split });
    }
    (layers, point, claims, work)
}

// A public multilinear first-layer weight can combine original point claims.
// Subsequent layers use the ordinary equality weight at the returned point.
// The caller binds the weight recipe and validates the top dimension.
pub(super) fn prove_tree_with_first_weight(
    tree: &[Vec<[Fp3; 2]>],
    mut point: Vec<Fp3>,
    mut claims: [Auth; 2],
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
    triples: &mut Vec<[Auth; 3]>,
    mut first_weight: Option<Vec<Fp3>>,
) -> (Vec<Layer>, Vec<Fp3>, [Auth; 2]) {
    if let Some(w) = &first_weight {
        assert_eq!(w.len(), 1usize << point.len());
    }
    let bits = tree.len() - 1;
    let mut layers = Vec::new();
    for l in 0..bits {
        let lambda = fs.fp3();
        let mut target = claims[0].scale(lambda).add(claims[1]);
        let level = &tree[bits - 1 - l];
        let mut children: [Vec<Fp3>; 4] =
            std::array::from_fn(|j| level.chunks_exact(2).map(|pair| pair[j / 2][j % 2]).collect());
        let mut equality = first_weight.take().unwrap_or_else(|| eq(&point));
        let (mut next_point, mut rounds) = (Vec::new(), Vec::new());
        for round in 0..point.len() {
            fs.set_phase(0x500 + (32 * l + round) as u16);
            let half = equality.len() / 2;
            let mut c = [Fp3::ZERO; 4];
            for i in 0..half {
                let a: [Fp3; 4] = std::array::from_fn(|j| children[j][i]);
                let d: [Fp3; 4] = std::array::from_fn(|j| children[j][i + half] - a[j]);
                let mut v = [Fp3::ZERO; 3];
                for (x, y, coefficient) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
                    v[0] += coefficient * a[x] * a[y];
                    v[1] += coefficient * (d[x] * a[y] + a[x] * d[y]);
                    v[2] += coefficient * d[x] * d[y];
                }
                let de = equality[i + half] - equality[i];
                for j in 0..3 {
                    c[j] += equality[i] * v[j];
                    c[j + 1] += de * v[j];
                }
            }
            let (corrections, a) = authenticate(c, rows);
            let tag = a[0].m + a[0].m + a[1].m + a[2].m + a[3].m - target.m;
            let wire = [corrections[0], corrections[1], corrections[2], corrections[3], tag];
            record_values(fs, 0x43, &wire);
            let r = fs.fp3();
            target = a.iter().rev().fold(Auth::ZERO, |s, &x| s.scale(r).add(x));
            for child in &mut children {
                fold(child, r);
            }
            fold(&mut equality, r);
            next_point.push(r);
            rounds.push(wire);
        }
        let [p, q, r, s] = std::array::from_fn(|i| children[i][0]);
        let (wire, a) = authenticate([p, q, r, s, p * s, r * q, q * s], rows);
        triples.extend([[a[0], a[3], a[4]], [a[2], a[1], a[5]], [a[1], a[3], a[6]]]);
        let residual = a[4].add(a[5]).scale(lambda).add(a[6]).scale(equality[0]);
        let split =
            [wire[0], wire[1], wire[2], wire[3], wire[4], wire[5], wire[6], residual.m - target.m];
        fs.set_phase(0x410 + l as u16);
        record_values(fs, 0x44, &split);
        let t = fs.fp3();
        claims = [
            a[0].scale(Fp3::ONE - t).add(a[2].scale(t)),
            a[1].scale(Fp3::ONE - t).add(a[3].scale(t)),
        ];
        next_point.push(t);
        point = next_point;
        layers.push(Layer { rounds, split });
    }
    (layers, point, claims)
}

pub(super) fn tree_shape(layers: &[Layer], depth: usize, top_bits: usize) -> bool {
    layers.len() == depth
        && layers.iter().enumerate().all(|(i, layer)| layer.rounds.len() == top_bits + i)
}

pub(super) fn verify_tree(
    layers: &[Layer],
    point: Vec<Fp3>,
    claims: [Key; 2],
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Key>,
    triples: &mut Vec<[Key; 3]>,
) -> Result<(Vec<Fp3>, [Key; 2]), String> {
    verify_tree_with_first_weight(layers, point, claims, delta, fs, rows, triples, None)
}

pub(super) fn verify_tree_with_first_weight(
    layers: &[Layer],
    mut point: Vec<Fp3>,
    mut claims: [Key; 2],
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Key>,
    triples: &mut Vec<[Key; 3]>,
    first_weight: Option<&dyn Fn(&[Fp3]) -> Fp3>,
) -> Result<(Vec<Fp3>, [Key; 2]), String> {
    for (l, layer) in layers.iter().enumerate() {
        let lambda = fs.fp3();
        let mut target = claims[0].scale(lambda).add(claims[1]);
        let (mut equality, mut next_point) = (Fp3::ONE, Vec::new());
        for (round, wire) in layer.rounds.iter().enumerate() {
            fs.set_phase(0x500 + (32 * l + round) as u16);
            let a = correct([wire[0], wire[1], wire[2], wire[3]], delta, rows);
            if a[0].k + a[0].k + a[1].k + a[2].k + a[3].k - target.k != wire[4] {
                return Err("B12 range cubic MAC rejected".into());
            }
            record_values(fs, 0x43, wire);
            let r = fs.fp3();
            target = a.iter().rev().fold(Key::ZERO, |s, &x| s.scale(r).add(x));
            if l != 0 || first_weight.is_none() {
                equality =
                    equality * ((Fp3::ONE - point[round]) * (Fp3::ONE - r) + point[round] * r);
            }
            next_point.push(r);
        }
        if l == 0 {
            if let Some(weight) = first_weight {
                equality = weight(&next_point);
            }
        }
        let a = correct(std::array::from_fn::<_, 7, _>(|i| layer.split[i]), delta, rows);
        triples.extend([[a[0], a[3], a[4]], [a[2], a[1], a[5]], [a[1], a[3], a[6]]]);
        let residual = a[4].add(a[5]).scale(lambda).add(a[6]).scale(equality);
        if residual.k - target.k != layer.split[7] {
            return Err("B12 range split MAC rejected".into());
        }
        fs.set_phase(0x410 + l as u16);
        record_values(fs, 0x44, &layer.split);
        let t = fs.fp3();
        claims = [
            a[0].scale(Fp3::ONE - t).add(a[2].scale(t)),
            a[1].scale(Fp3::ONE - t).add(a[3].scale(t)),
        ];
        next_point.push(t);
        point = next_point;
    }
    Ok((point, claims))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sourcewise_range_matches_dense_original_wire_and_mac() {
        use crate::c71_matrix::wire::Wire;
        let model =
            Model::new_in(Domain::Flat(10), (0..731).map(|i| (i % 7) as i16).collect()).unwrap();
        let weights = model.polynomial();
        let get = |i: usize| Fp3::from_base(Fp::new(weights.as_slice()[i].as_canonical_u64()));
        let count = required(10, Alphabet::Byte);
        let rows: Vec<_> =
            (0..count).map(|i| Auth::new(signed(i as i64 + 1), signed(3 * i as i64 + 7))).collect();
        let (mut dense_fs, mut source_fs) =
            (Fs::new(b"range parity", 10000), Fs::new(b"range parity", 10000));
        let (mut dense_rows, mut source_rows) =
            (rows.clone().into_iter(), rows.clone().into_iter());
        let (dense, df, dt) =
            prove(&model, context(), [9; 32], 731, Alphabet::Byte, &mut dense_fs, &mut dense_rows)
                .unwrap();
        let (source, sf, st) = prove_sourcewise(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            Alphabet::Byte,
            &get,
            &mut source_fs,
            &mut source_rows,
        )
        .unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        dense.write(&mut a);
        source.write(&mut b);
        assert_eq!(a, b);
        assert_eq!(dense_fs.digest(), source_fs.digest());
        for (a, b) in dt.iter().zip(st) {
            assert_eq!(a.x, b.x);
            assert_eq!(a.m, b.m);
        }
        for (a, b) in df.iter().flatten().zip(sf.iter().flatten()) {
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.point, b.point);
            assert_eq!(a.coefficient, b.coefficient);
        }
        assert_eq!(dense_rows.len(), 0);
        assert_eq!(source_rows.len(), 0);
        let delta = signed(29);
        let mut keys =
            rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect::<Vec<_>>().into_iter();
        let mut fs = Fs::new(b"range parity", 10000);
        verify(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            Alphabet::Byte,
            &source,
            delta,
            &mut fs,
            &mut keys,
        )
        .unwrap();
        assert_eq!(fs.digest(), source_fs.digest());
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn incremental_prefix_weights_reuse_one_buffer_and_match_scalar_reference() {
        let all_challenges = [
            Fp3::ZERO,
            Fp3::ONE,
            Fp3::new(Fp::new(3), Fp::new(5), Fp::new(7)),
            Fp3::new(Fp::new(11), Fp::new(13), Fp::new(17)),
            Fp3::new(Fp::new(19), Fp::new(23), Fp::new(29)),
            Fp3::new(Fp::new(31), Fp::new(37), Fp::new(41)),
        ];
        let get = |layer: usize, index: usize| {
            std::array::from_fn(|child| {
                Fp3::new(
                    Fp::new((1 + layer + 7 * index + child) as u64),
                    Fp::new((3 + 2 * layer + index + 5 * child) as u64),
                    Fp::new((9 + layer + 3 * index + 11 * child) as u64),
                )
            })
        };
        let original = 64;
        let mut prefix_weights = Vec::with_capacity(all_challenges.len() + 1);
        let allocation = prefix_weights.as_ptr();
        let capacity = prefix_weights.capacity();
        for q in 0..=6 {
            let challenges = &all_challenges[..q];
            let current = original >> q;
            for suffix in 0..current {
                let expected: [Fp3; 4] = std::array::from_fn(|child| {
                    (0..1usize << q).fold(Fp3::ZERO, |sum, prefix| {
                        let weight =
                            challenges.iter().enumerate().fold(Fp3::ONE, |weight, (bit, &r)| {
                                weight
                                    * if prefix >> (q - 1 - bit) & 1 == 1 {
                                        r
                                    } else {
                                        Fp3::ONE - r
                                    }
                            });
                        sum + weight * get(2, prefix * current + suffix)[child]
                    })
                });
                let mut work = SourceTreeWork::default();
                let actual = source_folded_children(
                    2,
                    original,
                    challenges,
                    suffix,
                    &get,
                    &mut prefix_weights,
                    &mut work,
                );
                assert_eq!(actual, expected);
                assert_eq!(prefix_weights.as_ptr(), allocation);
                assert_eq!(prefix_weights.capacity(), capacity);
                assert_eq!(work.getter_calls, 1 << q);
                assert_eq!(work.getter_scalar_values, 4 << q);
                assert_eq!(work.prefix_terms, 1 << q);
                assert_eq!(work.equality_multiplications, (2 << q) - 2);
                assert_eq!(work.equality_subtractions, (1 << q) - 1);
                assert_eq!(work.fold_multiplications, 4 << q);
                assert_eq!(work.fold_additions, 4 << q);
                assert_eq!(work.eq_weights_capacity_bytes, capacity * core::mem::size_of::<Fp3>());
            }
        }
    }

    fn context() -> AttemptContext {
        AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        }
    }

    fn transcript(n: usize) -> Fs {
        Fs::new(b"B12 same-root range component", request_limit(&matrix_config(n).unwrap()) + 256)
    }

    #[test]
    fn c71_b12_flat_sources_close_odd_domains_and_keep_original_targets_and_padding() {
        use rand_010::RngExt;
        let domain = Domain::Flat(11);
        let delta = signed(29);
        let layout = [17; 32];
        let mut rng = MatrixRng::from_seed([143; 32]);
        let start = || {
            Fs::new(
                b"B12 flat source range and original PCS",
                request_limit(&domain.config().unwrap()) + 256,
            )
        };
        for alphabet in [Alphabet::Symmetric(3), Alphabet::Byte] {
            for fault in 0..3 {
                let mut values: Vec<_> = (0..1031)
                    .map(|i| (alphabet.lower() + (i % alphabet.len()) as i64) as i16)
                    .collect();
                if fault == 2 {
                    values.resize(1537, 0);
                    values[1536] = 1; // valid alphabet, outside the live prefix
                }
                let model = Model::new_in(domain, values).unwrap();
                let polynomial = model.polynomial();
                assert_eq!(polynomial.as_slice().len(), 2048);
                let probe = Cube {
                    offset: 1024,
                    point: [3, 5, 7].map(signed).to_vec(),
                    coefficient: Fp3::ONE,
                };
                let value = eq(&probe.point).iter().enumerate().fold(Fp3::ZERO, |v, (i, &r)| {
                    v + r * Fp3::from_base(Fp::new(
                        polynomial.as_slice()[1024 + i].as_canonical_u64(),
                    ))
                }) + if fault == 1 { Fp3::ONE } else { Fp3::ZERO };
                let count = 1 + required(11, alphabet) + 35;
                assert_eq!(count, if matches!(alphabet, Alphabet::Byte) { 593 } else { 344 });
                let rows: Vec<_> = (0..count)
                    .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                    .collect();
                let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
                let (mut fs, mut prows) = (start(), rows.into_iter());
                let (wire, original) = authenticate([value], &mut prows);
                record_values(&mut fs, 0x47, &wire);
                let (proof, forms, targets) =
                    prove(&model, context(), layout, 1031, alphabet, &mut fs, &mut prows).unwrap();
                let mut forms = Vec::from(forms);
                forms.push(vec![probe.clone()]);
                let (pcs, digest) = linear::prove(
                    &model,
                    context(),
                    layout,
                    &forms,
                    &[targets[0], targets[1], original[0]],
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                assert_eq!(prows.len(), 0);
                let (mut fs, mut vrows) = (start(), keys.into_iter());
                let original = correct(wire, delta, &mut vrows);
                record_values(&mut fs, 0x47, &wire);
                let (forms, targets) = verify(
                    domain,
                    &model.root,
                    context(),
                    layout,
                    1031,
                    alphabet,
                    &proof,
                    delta,
                    &mut fs,
                    &mut vrows,
                )
                .unwrap();
                let mut forms = Vec::from(forms);
                forms.push(vec![probe]);
                let checked = linear::verify(
                    domain,
                    &model.root,
                    context(),
                    layout,
                    &forms,
                    &[targets[0], targets[1], original[0]],
                    &pcs,
                    delta,
                    &mut fs,
                    &mut vrows,
                );
                if fault == 0 {
                    assert_eq!(checked.unwrap(), digest);
                    assert_eq!(vrows.len(), 0);
                } else {
                    assert_eq!(checked.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                }
            }
        }
        // Full domains are public configuration/framing checks only. No source,
        // tree, codeword, Gemma trace or large correlation pool is allocated.
        let root = C61Commitment::new(vec![[7; 32]]);
        for bits in [10, 11, 34, 35] {
            let mut fs = start();
            assert_eq!(
                bind(
                    Domain::Flat(bits),
                    &root,
                    context(),
                    layout,
                    (1 << bits) - 3,
                    Alphabet::Byte,
                    &mut fs
                )
                .unwrap(),
                bits,
            );
            assert_eq!(fs.requests(), 0);
        }
        let (mut matrix, mut flat) = (start(), start());
        bind(32, &root, context(), layout, 1000, Alphabet::Byte, &mut matrix).unwrap();
        bind(Domain::Flat(10), &root, context(), layout, 1000, Alphabet::Byte, &mut flat).unwrap();
        assert_ne!(matrix.digest(), flat.digest());
        assert!(Domain::Flat(36).config().is_err());
        assert!(Model::new_in(Domain::Flat(10), vec![0; 1025]).is_err());
    }

    #[test]
    fn c71_b12_range_bytes_are_unsigned_and_keep_the_original_root_mac() {
        use rand_010::RngExt;
        let delta = signed(19);
        let mut rng = MatrixRng::from_seed([123; 32]);
        for invalid in [None, Some(-1), Some(256)] {
            let mut values = vec![0; 1024];
            for (i, value) in values[..256].iter_mut().enumerate() {
                *value = i as i16;
            }
            if let Some(value) = invalid {
                values[0] = value;
            }
            let model = Model::new(32, values).unwrap();
            let count = required(10, Alphabet::Byte) + 32;
            assert_eq!(count, 542);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let mut fs = transcript(32);
            let mut rows = rows.into_iter();
            let layout = [15; 32];
            let (proof, forms, targets) =
                prove(&model, context(), layout, 256, Alphabet::Byte, &mut fs, &mut rows).unwrap();
            let (pcs, digest) =
                linear::prove(&model, context(), layout, &forms, &targets, &mut fs, &mut rows)
                    .unwrap();
            assert!(rows.next().is_none());
            let mut fs = transcript(32);
            let mut rows = keys.into_iter();
            let checked = verify(
                32,
                &model.root,
                context(),
                layout,
                256,
                Alphabet::Byte,
                &proof,
                delta,
                &mut fs,
                &mut rows,
            );
            if invalid.is_some() {
                assert_eq!(checked.err().unwrap(), "B12 range product MAC rejected");
            } else {
                let (forms, targets) = checked.unwrap();
                assert_eq!(
                    linear::verify(
                        32,
                        &model.root,
                        context(),
                        layout,
                        &forms,
                        &targets,
                        &pcs,
                        delta,
                        &mut fs,
                        &mut rows
                    )
                    .unwrap(),
                    digest
                );
                assert!(rows.next().is_none());
            }
        }
        // The old symmetric transcript is preserved; bytes have a distinct
        // public alphabet, not the invalid shortcut [-255,255].
        let root = C61Commitment::new(vec![[1; 32]]);
        let mut symmetric = transcript(32);
        let mut bytes = transcript(32);
        bind(32, &root, context(), [15; 32], 256, 255, &mut symmetric).unwrap();
        bind(32, &root, context(), [15; 32], 256, Alphabet::Byte, &mut bytes).unwrap();
        assert_ne!(symmetric.digest(), bytes.digest());
    }

    #[test]
    fn c71_b12_range_i16_and_padding_close_the_original_leaf_mac() {
        use rand_010::RngExt;
        let n = 32;
        let bits = 10;
        let layout = [4; 32];
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        let mut rng = MatrixRng::from_seed([101; 32]);
        for (first, padding, range_ok) in
            [(-32767, 0, true), (32767, 0, true), (-32768, 0, false), (7, 1, true)]
        {
            let mut weights = vec![0; n * n];
            weights[..7].copy_from_slice(&[first, -2, 3, 0, 17, -31, 1]);
            weights[23] = padding;
            let model = Model::new(n, weights).unwrap();
            let required = required(bits, 32767) + 3 * bits + 2;
            assert_eq!(required, 65821);
            let rows: Vec<_> = (0..required)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let mut rows = rows.into_iter();
            let mut fs = transcript(n);
            let (mut range, forms, targets) =
                prove(&model, context(), layout, 7, 32767, &mut fs, &mut rows).unwrap();
            assert_eq!(fs.requests(), 77);
            let (pcs, digest) =
                linear::prove(&model, context(), layout, &forms, &targets, &mut fs, &mut rows)
                    .unwrap();
            assert!(rows.next().is_none());
            let check = |proof: &Proof, detach: bool| {
                let mut rows = keys.clone().into_iter();
                let mut fs = transcript(n);
                let (forms, mut targets) = verify(
                    n,
                    &model.root,
                    context(),
                    layout,
                    7,
                    32767,
                    proof,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                if detach {
                    targets[0].k += Fp3::ONE;
                }
                let checked = linear::verify(
                    n,
                    &model.root,
                    context(),
                    layout,
                    &forms,
                    &targets,
                    &pcs,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                assert!(rows.next().is_none());
                Ok::<_, String>(checked)
            };
            if !range_ok {
                assert_eq!(check(&range, false).unwrap_err(), "B12 range product MAC rejected");
            } else if padding != 0 {
                assert_eq!(check(&range, false).unwrap_err(), "C71 matrix sumcheck MAC rejected");
            } else {
                assert_eq!(check(&range, false).unwrap(), digest);
                assert!(check(&range, true).is_err());
                range.histogram[0] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.histogram[0] += -Fp3::ONE;
                range.roots[2] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.roots[2] += -Fp3::ONE;
                range.layers[3].rounds[1][2] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.layers[3].rounds[1][2] += -Fp3::ONE;
                range.products[0] += Fp3::ONE;
                assert!(check(&range, false).is_err());
                range.products[0] += -Fp3::ONE;
                range.leaf_tag += Fp3::ONE;
                assert!(check(&range, false).is_err());
            }
        }
        let root = C61Commitment::new(vec![[9; 32]]);
        for (live, limit) in [(0, 3), (1025, 3), (7, 0), (7, -1)] {
            assert!(bind(n, &root, context(), layout, live, limit, &mut transcript(n)).is_err());
        }
    }

    #[test]
    fn c71_b12_product_batch_uses_one_fresh_mask_and_the_native_sign() {
        let x = Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5));
        let y = Fp3::new(Fp::new(7), Fp::new(11), Fp::new(13));
        for delta in [Fp3::ZERO, Fp3::ONE, x] {
            let a = Auth::new(x, y);
            let b = Auth::new(y, x);
            let c = Auth::new(x * y, x + y);
            let mask = Auth::new(y * y, x * x);
            let triples = [[a, b, c], [b, a, c]];
            let key = |a: Auth| Key::new(a.m + delta * a.x);
            let keys = triples.map(|t| t.map(key));
            let mut fs = Fs::new(b"product algebra", 1);
            let wire = prove_products(&triples, mask, &mut fs);
            verify_products(&keys, key(mask), wire, delta, &mut Fs::new(b"product algebra", 1))
                .unwrap();
            assert!(verify_products(
                &keys,
                key(mask),
                [wire[0], wire[1] + Fp3::ONE],
                delta,
                &mut Fs::new(b"product algebra", 1)
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_range_real_fixed_pool_accepts_then_ends_on_a_false_range() {
        use std::{io, sync::mpsc, time::Duration};
        use volta_pcg::c71_lifetime::{Attempt, Lifetime, ModelBinding};
        let n = 32;
        let mut weights = vec![0; n * n];
        weights[..7].copy_from_slice(&[2, -3, 1, 0, -2, 3, -1]);
        let model = Model::new(n, weights).unwrap();
        let root = model.root.clone();
        let layout = [4; 32];
        let binding =
            ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: layout };
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-b12-range-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ppath = directory.join("prover");
        let vpath = directory.join("verifier");
        let prover_path = ppath.clone();
        let count = |limit| required(10, limit) + 32;
        let capacity = 3 * (count(3) + count(1));
        assert_eq!(capacity, 1746);
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let context = |a: &Attempt| AttemptContext {
            session: [1; 32],
            capacity: a.capacity,
            slot: (a.ordinal - 1) as u8,
            predecessor: a.predecessor,
            nonce: [3; 32],
        };
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for channel in [&pc, &vc] {
            channel.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
            channel.set_write_timeout(Some(Duration::from_secs(45))).unwrap();
        }
        let (send, receive) = mpsc::sync_channel(1);
        let (ack, wait_ack) = mpsc::sync_channel(1);
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let mut pool = store.prover_fixed_run(&mut pc, [1; 32], [2; 32], capacity).unwrap();
            for limit in [3, 1] {
                pool.attempt(count(limit), |attempt, rows, _| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| {
                            let tag = |a: [u64; 4]| field([a[1], a[2], a[3]]);
                            Auth::new(
                                field([r[0][0], r[1][0], r[2][0]]),
                                tag(r[0]) + u * tag(r[1]) + u * u * tag(r[2]),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_iter();
                    let attempt = context(&attempt);
                    let mut fs = transcript(n);
                    let (range, forms, targets) =
                        prove(&model, attempt, layout, 7, limit, &mut fs, &mut rows)
                            .map_err(io::Error::other)?;
                    let (pcs, digest) = linear::prove(
                        &model, attempt, layout, &forms, &targets, &mut fs, &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert!(rows.next().is_none());
                    send.send((range, pcs, digest)).unwrap();
                    let head = wait_ack.recv_timeout(Duration::from_secs(45)).unwrap();
                    assert_eq!(head, if limit == 3 { Some(*digest.as_bytes()) } else { None });
                    Ok(((), head))
                })
                .unwrap();
            }
            assert!(pool.attempt::<()>(1, |_, _, _| panic!("failed range continued")).is_err());
        });
        let mut store = Lifetime::install(&vpath, binding).unwrap();
        let mut pool = store.verifier_fixed_run(&mut vc, [1; 32], [2; 32], capacity).unwrap();
        for limit in [3, 1] {
            let head = pool
                .attempt(count(limit), |attempt, rows, delta| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| Key::new(field(r[0]) + u * field(r[1]) + u * u * field(r[2])))
                        .collect::<Vec<_>>()
                        .into_iter();
                    let delta = -field(*delta.unwrap());
                    let attempt = context(&attempt);
                    let (range, pcs, digest) =
                        receive.recv_timeout(Duration::from_secs(45)).unwrap();
                    let mut fs = transcript(n);
                    let checked = verify(
                        n, &root, attempt, layout, 7, limit, &range, delta, &mut fs, &mut rows,
                    );
                    if limit == 1 {
                        assert_eq!(checked.err().unwrap(), "B12 range product MAC rejected");
                        return Ok((None, None));
                    }
                    let (forms, targets) = checked.map_err(io::Error::other)?;
                    let checked = linear::verify(
                        n, &root, attempt, layout, &forms, &targets, &pcs, delta, &mut fs,
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert_eq!(checked, digest);
                    assert!(rows.next().is_none());
                    Ok((Some(*checked.as_bytes()), Some(*checked.as_bytes())))
                })
                .unwrap();
            ack.send(head).unwrap();
        }
        assert!(pool.attempt::<()>(1, |_, _, _| panic!("rejected range continued")).is_err());
        prover.join().unwrap();
        drop(pool);
        drop(store);
        for path in [ppath, vpath] {
            assert!(Lifetime::open(&path, binding).is_err());
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}

//! Experimental joint RNE byte-function reduction. Test-only, no B12 admission.
use super::*;

component_wire!(Proof { layers, leaf_tag, products });

pub(crate) struct Proof {
    layers: Vec<range::Layer>,
    leaf_tag: Fp3,
    products: [Fp3; 2],
}

/// Pack public power-of-two views without padding each to the largest view.
pub(crate) fn geometry(bits: &[usize]) -> Result<(usize, Vec<usize>), String> {
    if bits.is_empty() || bits.len() > 1024 || bits.iter().any(|&b| b > 34) {
        return Err("joint byte view shape".into());
    }
    let mut order: Vec<_> = (0..bits.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(bits[i]));
    let mut offsets = vec![0; bits.len()];
    let mut end = 0usize;
    for i in order {
        offsets[i] = end;
        end += 1usize << bits[i];
    }
    let d = end.next_power_of_two().ilog2() as usize;
    if d > 34 {
        return Err("joint byte view exceeds D34".into());
    }
    Ok((d, offsets))
}

/// Keep each virtual view within D34; membership follows the public order.
pub(crate) fn groups(bits: &[usize]) -> Result<Vec<Vec<usize>>, String> {
    if bits.is_empty() || bits.len() > 1024 || bits.iter().any(|&b| b > 34) {
        return Err("joint byte group shape".into());
    }
    let mut groups = vec![Vec::new()];
    let mut cells = 0usize;
    for (i, &b) in bits.iter().enumerate() {
        if cells + (1usize << b) > 1usize << 34 {
            groups.push(Vec::new());
            cells = 0;
        }
        groups.last_mut().unwrap().push(i);
        cells += 1usize << b;
    }
    Ok(groups)
}

/// Dyadic bins with no new padded cells; order is public (size, original ID).
pub(crate) fn unpadded_groups(bits: &[usize]) -> Result<Vec<Vec<usize>>, String> {
    if bits.is_empty() || bits.len() > 1024 || bits.iter().any(|&b| b > 34) {
        return Err("joint byte group shape".into());
    }
    let mut order: Vec<_> = (0..bits.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(bits[i]));
    let mut remaining: usize = bits.iter().map(|&b| 1usize << b).sum();
    let mut groups = Vec::new();
    let mut next = 0;
    while remaining != 0 {
        let size = 1usize << remaining.ilog2().min(34);
        let mut group = Vec::new();
        let mut filled = 0;
        while filled < size {
            let i = order[next];
            filled += 1usize << bits[i];
            group.push(i);
            next += 1;
        }
        assert_eq!(filled, size); // descending dyadic blocks tile each bin exactly
        remaining -= size;
        groups.push(group);
    }
    Ok(groups)
}

pub(crate) fn required(d: usize) -> usize {
    super::required(d)
}

pub(crate) fn wire_bytes(d: usize) -> usize {
    super::wire_bytes(d)
}

fn prefix(offset: usize, local_bits: usize, point: &[Fp3]) -> Fp3 {
    point[..point.len() - local_bits].iter().enumerate().fold(Fp3::ONE, |v, (i, &r)| {
        v * if offset >> (point.len() - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
    })
}

struct Public {
    d: usize,
    offsets: Vec<usize>,
    points: Vec<Vec<Fp3>>,
    powers: Vec<Fp3>,
}

fn bind_batch(statements: &[Statement<'_>], fs: &mut Fs) -> Result<Public, String> {
    let bits: Vec<_> = statements.iter().map(|s| s.cell_point.len() + 3).collect();
    let (d, offsets) = geometry(&bits)?;
    let first = &statements[0];
    let mut views = std::collections::BTreeSet::new();
    if statements.iter().any(|s| {
        s.tables.len() != 8
            || s.live_cells != 1usize << s.cell_point.len()
            || s.root.roots() != first.root.roots()
            || s.profile != first.profile
            || s.attempt.encode() != first.attempt.encode()
            || !views.insert(s.view)
    }) {
        return Err("joint byte statements must share one source and attempt".into());
    }
    fs.set_phase(0xa00);
    fs.record(
        0x75,
        b"C71-RNE-joint-byte-experiment-v2;weighted-first-GKR;ordered-originals;packed-MSB",
    );
    let mut header = (statements.len() as u32).to_le_bytes().to_vec();
    for &offset in &offsets {
        header.extend((offset as u64).to_le_bytes());
    }
    fs.record(0x76, &header);
    let mut points = Vec::new();
    for s in statements {
        let lanes = super::bind(s, 8, false, fs)?;
        points.push(s.cell_point.iter().chain(&lanes).copied().collect());
    }
    let lambda = fs.fp3();
    let mut power = Fp3::ONE;
    let powers = statements
        .iter()
        .map(|_| {
            let current = power;
            power = power * lambda;
            current
        })
        .collect();
    Ok(Public { d, offsets, points, powers })
}

impl Public {
    fn weight(&self, point: &[Fp3]) -> Fp3 {
        self.points.iter().enumerate().fold(Fp3::ZERO, |v, (i, r)| {
            let equality = r
                .iter()
                .zip(&point[self.d - r.len()..])
                .fold(Fp3::ONE, |v, (&r, &s)| v * ((Fp3::ONE - r) * (Fp3::ONE - s) + r * s));
            v + self.powers[i] * prefix(self.offsets[i], r.len(), point) * equality
        })
    }

    fn leaf(&self, coefficients: &[Vec<[Fp3; 256]>], point: &[Fp3]) -> (Fp3, Fp3) {
        let lanes = eq(&point[self.d - 3..self.d]);
        let gates = eq(&point[self.d..]);
        let coefficient = coefficients.iter().enumerate().fold(Fp3::ZERO, |v, (i, tables)| {
            let c = tables.iter().zip(&lanes).fold(Fp3::ZERO, |v, (table, &lane)| {
                v + lane * table.iter().zip(&gates).fold(Fp3::ZERO, |v, (&c, &g)| v + c * g)
            });
            v + prefix(self.offsets[i], self.points[i].len(), &point[..self.d]) * c
        });
        let index = point[self.d..]
            .iter()
            .enumerate()
            .fold(Fp3::ZERO, |v, (i, &r)| v + signed(1 << (7 - i)) * r);
        (coefficient, index)
    }
}

pub(crate) fn prove(
    statements: &[Statement<'_>],
    originals: &[[Auth; 8]],
    get: impl Fn(usize, usize) -> u8,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth), String> {
    let public = bind_batch(statements, fs)?;
    // ponytail: dense small experiment only; a streaming physical schedule is required for D34.
    if public.d > 9 || originals.len() != statements.len() || rows.len() < required(public.d) {
        return Err("joint byte local size or capacity".into());
    }
    let c: Vec<_> = statements.iter().map(|s| coefficients(s.tables)).collect();
    let mut bottom = vec![[Fp3::ZERO; 2]; 256 << public.d];
    // Unused packed cells have public byte zero and zero numerator coefficients.
    let covered: usize = public.points.iter().map(|p| 1usize << p.len()).sum();
    for cell in bottom[256 * covered..].chunks_exact_mut(256) {
        for (j, v) in cell.iter_mut().enumerate() {
            v[1] = -signed(j as i64);
        }
    }
    let mut weight = vec![Fp3::ZERO; 1 << public.d];
    let mut target = Auth::ZERO;
    for (i, original) in originals.iter().enumerate() {
        let local = &public.points[i];
        let lane_weights = eq_scaled(&local[local.len() - 3..], public.powers[i]);
        target = original.iter().zip(lane_weights).fold(target, |v, (&a, w)| v.add(a.scale(w)));
        for (j, w) in eq_scaled(local, public.powers[i]).into_iter().enumerate() {
            let cell = public.offsets[i] + j;
            weight[cell] = w;
            let byte = signed(i64::from(get(i, j)));
            for k in 0..256 {
                bottom[256 * cell + k] = [c[i][j % 8][k], byte - signed(k as i64)];
            }
        }
    }
    let mut tree = vec![bottom];
    for _ in 0..8 {
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
    let mut triples = Vec::new();
    // Use the original weighted sum directly in the first cubic GKR layer.
    // The placeholder coordinates carry only its public dimension; the
    // supplied weight replaces their equality polynomial in that layer.
    let (layers, mut point, claims) = range::prove_tree_with_first_weight(
        &tree,
        vec![Fp3::ZERO; public.d],
        [target, Auth::ZERO],
        fs,
        rows,
        &mut triples,
        Some(weight),
    );
    let (_, index) = public.leaf(&c, &point);
    let leaf_tag = claims[0].m;
    record_values(fs, 0x79, &[leaf_tag]);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    point.truncate(public.d);
    Ok((Proof { layers, leaf_tag, products }, point, Auth::new(claims[1].x + index, claims[1].m)))
}

pub(crate) fn verify(
    statements: &[Statement<'_>],
    originals: &[[Key; 8]],
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Key>,
) -> Result<(Vec<Fp3>, Key), String> {
    let public = bind_batch(statements, fs)?;
    if originals.len() != statements.len()
        || !range::tree_shape(&proof.layers, 8, public.d)
        || rows.len() < required(public.d)
    {
        return Err("joint byte proof shape or capacity".into());
    }
    let mut target = Key::ZERO;
    for (i, original) in originals.iter().enumerate() {
        let local = &public.points[i];
        target = original
            .iter()
            .zip(eq_scaled(&local[local.len() - 3..], public.powers[i]))
            .fold(target, |v, (&a, w)| v.add(a.scale(w)));
    }
    let mut triples = Vec::new();
    let (mut point, claims) = range::verify_tree_with_first_weight(
        &proof.layers,
        vec![Fp3::ZERO; public.d],
        [target, Key::ZERO],
        delta,
        fs,
        rows,
        &mut triples,
        Some(&|point| public.weight(point)),
    )?;
    let c: Vec<_> = statements.iter().map(|s| coefficients(s.tables)).collect();
    let (coefficient, index) = public.leaf(&c, &point);
    if claims[0].k - delta * coefficient != proof.leaf_tag {
        return Err("joint byte public leaf MAC rejected".into());
    }
    record_values(fs, 0x79, &[proof.leaf_tag]);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    point.truncate(public.d);
    Ok((point, Key::new(claims[1].k + delta * index)))
}

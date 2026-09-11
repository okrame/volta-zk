//! Experimental joint RNE byte-function reduction. Test-only, no B12 admission.
use super::*;

component_wire!(Proof { rounds, root, layers, leaf_tag, products });

pub(crate) struct Proof {
    rounds: Vec<[Fp3; 4]>,
    root: [Fp3; 2],
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

pub(crate) fn required(d: usize) -> usize {
    3 * d + 1 + super::required(d)
}

pub(crate) fn wire_bytes(d: usize) -> usize {
    4 + 4 * 24 * d + 2 * 24 + super::wire_bytes(d)
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
    fs.record(0x75, b"C71-RNE-joint-byte-experiment-v1;ordered-originals;packed-MSB");
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
    for cell in bottom.chunks_exact_mut(256) {
        for (j, v) in cell.iter_mut().enumerate() {
            v[1] = -signed(j as i64);
        }
    }
    let mut weight = vec![Fp3::ZERO; 1 << public.d];
    let mut target = Auth::ZERO;
    for (i, original) in originals.iter().enumerate() {
        let local = &public.points[i];
        let lane_weights = eq(&local[local.len() - 3..]);
        target = original
            .iter()
            .zip(lane_weights)
            .fold(target, |v, (&a, w)| v.add(a.scale(public.powers[i] * w)));
        for (j, w) in eq(local).into_iter().enumerate() {
            let cell = public.offsets[i] + j;
            weight[cell] = public.powers[i] * w;
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
    let mut values: Vec<_> = tree[8].iter().map(|v| v[0]).collect();
    let (mut rounds, mut point) = (Vec::new(), Vec::new());
    for round in 0..public.d {
        let half = values.len() / 2;
        let mut coefficients = [Fp3::ZERO; 3];
        for i in 0..half {
            let (a, b) = (values[i], weight[i]);
            let (da, db) = (values[i + half] - a, weight[i + half] - b);
            coefficients[0] += a * b;
            coefficients[1] += da * b + a * db;
            coefficients[2] += da * db;
        }
        let (wire, a) = range::authenticate(coefficients, rows);
        let tag = a[0].m + a[0].m + a[1].m + a[2].m - target.m;
        let wire = [wire[0], wire[1], wire[2], tag];
        fs.set_phase(0xa10 + round as u16);
        record_values(fs, 0x77, &wire);
        let r = fs.fp3();
        target = a.iter().rev().fold(Auth::ZERO, |v, &a| v.scale(r).add(a));
        fold(&mut values, r);
        fold(&mut weight, r);
        point.push(r);
        rounds.push(wire);
    }
    let (wire, a) = range::authenticate([values[0]], rows);
    let root = [wire[0], a[0].m * weight[0] - target.m];
    record_values(fs, 0x78, &root);
    let mut triples = Vec::new();
    let (layers, mut point, claims) =
        range::prove_tree(&tree, point, [a[0], Auth::ZERO], fs, rows, &mut triples);
    let (_, index) = public.leaf(&c, &point);
    let leaf_tag = claims[0].m;
    record_values(fs, 0x79, &[leaf_tag]);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    point.truncate(public.d);
    Ok((
        Proof { rounds, root, layers, leaf_tag, products },
        point,
        Auth::new(claims[1].x + index, claims[1].m),
    ))
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
        || proof.rounds.len() != public.d
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
            .zip(eq(&local[local.len() - 3..]))
            .fold(target, |v, (&a, w)| v.add(a.scale(public.powers[i] * w)));
    }
    let mut point = Vec::new();
    for (round, wire) in proof.rounds.iter().enumerate() {
        let a = range::correct([wire[0], wire[1], wire[2]], delta, rows);
        if a[0].k + a[0].k + a[1].k + a[2].k - target.k != wire[3] {
            return Err("joint byte quadratic MAC rejected".into());
        }
        fs.set_phase(0xa10 + round as u16);
        record_values(fs, 0x77, wire);
        let r = fs.fp3();
        target = a.iter().rev().fold(Key::ZERO, |v, &a| v.scale(r).add(a));
        point.push(r);
    }
    let a = range::correct([proof.root[0]], delta, rows)[0];
    if a.k * public.weight(&point) - target.k != proof.root[1] {
        return Err("joint byte root MAC rejected".into());
    }
    record_values(fs, 0x78, &proof.root);
    let mut triples = Vec::new();
    let (mut point, claims) =
        range::verify_tree(&proof.layers, point, [a, Key::ZERO], delta, fs, rows, &mut triples)?;
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

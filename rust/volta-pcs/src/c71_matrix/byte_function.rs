//! Public byte functions through the SAME fraction-tree GKR as range.
//! Incoming function MACs share one cell point; the returned byte MAC must
//! join the caller's original byte-source forms in its one shared PCS.

use super::*;

#[cfg(test)]
pub(super) mod batch;

mod contraction;

component_wire!(Proof { layers, leaf_tag, products });

pub(super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub cell_point: &'a [Fp3],
    pub live_cells: usize,
    pub tables: &'a [[Fp3; 256]],
}

pub(super) struct Proof {
    layers: Vec<range::Layer>,
    leaf_tag: Fp3,
    products: [Fp3; 2],
}

impl Proof {
    pub(super) fn heap_capacity_bytes(&self) -> usize {
        range::tree_proof_heap_capacity_bytes(&self.layers, self.layers.capacity())
    }
}

pub(super) enum Original<'a, T> {
    Lanes(&'a [T]),
    // One ORIGINAL sum claim; never split it using fresh correlations.
    Sum(T),
}

pub(super) fn required(view_bits: usize) -> usize {
    32 * view_bits + 169
}

/// Exact current Wire size: eight mandatory fraction-tree layers, no PCS.
pub(super) fn wire_bytes(view_bits: usize) -> usize {
    let rounds: usize = (0..8).map(|i| view_bits + i).sum();
    4 + 8 * (4 + 8 * 24) + 5 * 24 * rounds + 3 * 24
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
struct BindWork {
    prefix_capacity_bytes: usize,
    point_capacity_bytes: usize,
    attempt_capacity_bytes: usize,
    transcript_bytes: usize,
}

fn bind(
    s: &Statement<'_>,
    count: usize,
    sum: bool,
    fs: &mut Fs,
) -> Result<(Vec<Fp3>, BindWork), String> {
    if !s.tables.len().is_power_of_two()
        || s.tables.len() > 16
        || count != if sum { 1 } else { s.tables.len() }
        || s.cell_point.len() > 34
        || s.live_cells == 0
        || s.live_cells > 1usize << s.cell_point.len()
        || s.root.num_roots() != 1
        || s.profile.is_empty()
        || s.view == [0; 32]
        || !s.attempt.valid()
    {
        return Err("B12 byte-function statement mismatch".into());
    }
    let lane_bits = s.tables.len().ilog2() as usize;
    if s.cell_point.len() + lane_bits > 34 {
        return Err("B12 byte-function view exceeds D34".into());
    }
    let domain: &[u8] = if sum {
        b"C71-byte-function-B12-v2;P-S-SUM;fixed-half-lanes;original-MAC"
    } else {
        b"C71-byte-function-B12-v1;P-S;cell-lane-gate-MSB;original-MAC"
    };
    let attempt = s.attempt.encode();
    let encoded_values = s
        .cell_point
        .len()
        .checked_add(s.tables.len().checked_mul(256).expect("byte table count overflow"))
        .and_then(|count| count.checked_mul(core::mem::size_of::<Fp3>()))
        .expect("byte-function value transcript length overflow");
    let prefix_len = [
        s.root.roots()[0].len(),
        8,
        s.profile.len(),
        s.view.len(),
        attempt.len(),
        4,
        8,
        4,
        encoded_values,
    ]
    .into_iter()
    .try_fold(domain.len(), |total, len| total.checked_add(len))
    .expect("byte-function prefix transcript length overflow");
    let mut bytes = Vec::with_capacity(prefix_len);
    bytes.extend(domain);
    bytes.extend(s.root.roots()[0]);
    bytes.extend((s.profile.len() as u64).to_le_bytes());
    bytes.extend(s.profile);
    bytes.extend(s.view);
    let attempt_capacity_bytes = attempt.capacity();
    bytes.extend(&attempt);
    drop(attempt);
    bytes.extend((s.cell_point.len() as u32).to_le_bytes());
    bytes.extend((s.live_cells as u64).to_le_bytes());
    bytes.extend((s.tables.len() as u32).to_le_bytes());
    for &value in s.cell_point.iter().chain(s.tables.iter().flatten()) {
        bytes.extend(value.to_bytes());
    }
    debug_assert_eq!(bytes.len(), prefix_len);
    fs.set_phase(0x800);
    fs.record(0x60, &bytes);
    let transcript_bytes = bytes.len();
    let prefix_capacity_bytes = bytes.capacity();
    let point = if sum {
        vec![signed(2).inv(); lane_bits]
    } else {
        (0..lane_bits).map(|_| fs.fp3()).collect()
    };
    let work = BindWork {
        prefix_capacity_bytes,
        point_capacity_bytes: point.capacity() * core::mem::size_of::<Fp3>(),
        attempt_capacity_bytes,
        transcript_bytes,
    };
    Ok((point, work))
}

// Public Lagrange weights f(j)/product_{k!=j}(j-k); only public nonzero
// constants are inverted. The P/S tree has no witness-dependent division.
fn coefficients(tables: &[[Fp3; 256]]) -> Vec<[Fp3; 256]> {
    let mut factorial = [Fp3::ONE; 256];
    for j in 1..256 {
        factorial[j] = factorial[j - 1] * signed(j as i64);
    }
    tables
        .iter()
        .map(|f| {
            std::array::from_fn(|j| {
                let c = f[j] * (factorial[j] * factorial[255 - j]).inv();
                if (255 - j) & 1 == 1 {
                    -c
                } else {
                    c
                }
            })
        })
        .collect()
}

const BYTE_TREE_NODES: usize = 511;

/// Public per-lane/per-byte fraction trees. The table is independent of the
/// cell domain and can be shared by every regenerated sumcheck scan.
struct ByteTrees {
    lanes: usize,
    nodes: Vec<[Fp3; 2]>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct SourceWork {
    pub tree: range::SourceTreeWork,
    pub bind_prefix_capacity_bytes: usize,
    pub bind_point_capacity_bytes: usize,
    pub bind_attempt_capacity_bytes: usize,
    pub bind_transcript_bytes: usize,
    pub combined_point_capacity_bytes: usize,
    pub row_capacity_bytes: usize,
    pub triples_capacity_bytes: usize,
    pub proof_capacity_bytes: usize,
    pub root_eq_capacity_peak_bytes: usize,
    pub leaf_eq_capacity_peak_bytes: usize,
    pub root_phase_owned_heap_peak_bytes: usize,
    pub bind_phase_owned_heap_peak_bytes: usize,
    pub tree_phase_owned_heap_peak_bytes: usize,
    pub coefficient_capacity_bytes: usize,
    pub lut_nodes: usize,
    pub lut_capacity_bytes: usize,
    pub lut_build_multiplications: u64,
    pub lut_build_additions: u64,
}

impl ByteTrees {
    fn new(coefficients: &[[Fp3; 256]]) -> Self {
        let mut nodes = vec![[Fp3::ZERO; 2]; coefficients.len() * 256 * BYTE_TREE_NODES];
        for (lane, coefficients) in coefficients.iter().enumerate() {
            for byte in 0..256 {
                let tree = &mut nodes[(lane * 256 + byte) * BYTE_TREE_NODES
                    ..(lane * 256 + byte + 1) * BYTE_TREE_NODES];
                for j in 0..256 {
                    tree[255 + j] = [coefficients[j], signed(byte as i64) - signed(j as i64)];
                }
                for node in (0..255).rev() {
                    let [p, q] = tree[2 * node + 1];
                    let [r, s] = tree[2 * node + 2];
                    tree[node] = [p * s + r * q, q * s];
                }
            }
        }
        Self { lanes: coefficients.len(), nodes }
    }

    fn children(
        &self,
        layer: usize,
        index: usize,
        live_cells: usize,
        get_byte: &impl Fn(usize) -> u8,
    ) -> [Fp3; 4] {
        debug_assert!(layer < 8);
        let node_pairs = 1usize << layer;
        let top = index >> layer;
        let pair = index & (node_pairs - 1);
        let (cell, lane) = (top / self.lanes, top % self.lanes);
        let live = cell < live_cells;
        let byte = if live { usize::from(get_byte(top)) } else { 0 };
        let first = (1usize << (layer + 1)) - 1 + 2 * pair;
        let tree = &self.nodes
            [(lane * 256 + byte) * BYTE_TREE_NODES..(lane * 256 + byte + 1) * BYTE_TREE_NODES];
        [
            if live { tree[first][0] } else { Fp3::ZERO },
            tree[first][1],
            if live { tree[first + 1][0] } else { Fp3::ZERO },
            tree[first + 1][1],
        ]
    }
}

pub(super) fn live_mass(live: usize, point: &[Fp3]) -> Fp3 {
    if live == 1usize << point.len() {
        return Fp3::ONE;
    }
    let (mut prefix, mut equal) = (Fp3::ZERO, Fp3::ONE);
    for (i, &r) in point.iter().enumerate() {
        if live >> (point.len() - 1 - i) & 1 == 1 {
            prefix += equal * (Fp3::ONE - r);
            equal = equal * r;
        } else {
            equal = equal * (Fp3::ONE - r);
        }
    }
    prefix
}

fn leaf(s: &Statement<'_>, coefficients: &[[Fp3; 256]], point: &[Fp3]) -> (Fp3, Fp3, usize) {
    let cells = s.cell_point.len();
    let gates = point.len() - 8;
    let (lane_eq, lane_eq_peak) = eq_scaled_counted(&point[cells..gates], Fp3::ONE);
    let (gate_eq, gate_eq_peak) = eq_scaled_counted(&point[gates..], Fp3::ONE);
    let eq_capacity_peak_bytes =
        lane_eq_peak.max(lane_eq.capacity() * core::mem::size_of::<Fp3>() + gate_eq_peak);
    let coefficient = coefficients.iter().zip(lane_eq).fold(Fp3::ZERO, |sum, (c, w)| {
        sum + w * c.iter().zip(&gate_eq).fold(Fp3::ZERO, |v, (&c, &r)| v + c * r)
    });
    let index = point[gates..]
        .iter()
        .enumerate()
        .fold(Fp3::ZERO, |v, (i, &r)| v + signed(1 << (7 - i)) * r);
    (live_mass(s.live_cells, &point[..cells]) * coefficient, index, eq_capacity_peak_bytes)
}

// The caller records every original function correction under its public
// identity before this call. All claims use s.cell_point; dummy cells are
// zero outputs, including when f(0)!=0. The getter reads the fixed byte view
// in cell-major/lane-fastest order and must not inspect unused correlations.
/// Counted scalar reference. The nested row, proof and tree capacities are
/// measured here; the caller's backing correlation allocation, authenticated
/// arithmetic internals and allocator metadata remain external.
pub(super) fn prove_sourcewise(
    s: &Statement<'_>,
    original: Original<'_, Auth>,
    get_byte: impl Fn(usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth, SourceWork), String> {
    prove_sourcewise_impl(s, original, get_byte, fs, correlations, false)
}

/// Reduced integration path. The canonical compact streaming getter is separate.
pub(super) fn prove_contracted(
    s: &Statement<'_>,
    original: Original<'_, Auth>,
    get_byte: impl Fn(usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth, SourceWork), String> {
    if s.cell_point.len() > 7 || s.live_cells != 1usize << s.cell_point.len() {
        return Err("byte contraction requires a reduced complete frame domain".into());
    }
    prove_sourcewise_impl(s, original, get_byte, fs, correlations, true)
}

fn prove_sourcewise_impl(
    s: &Statement<'_>,
    original: Original<'_, Auth>,
    get_byte: impl Fn(usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
    contracted: bool,
) -> Result<(Proof, Vec<Fp3>, Auth, SourceWork), String> {
    let (len, sum) = match &original {
        Original::Lanes(v) => (v.len(), false),
        Original::Sum(_) => (1, true),
    };
    let (lane_point, bind_work) = bind(s, len, sum, fs)?;
    let point: Vec<_> = s.cell_point.iter().chain(&lane_point).copied().collect();
    let combined_point_capacity_bytes = point.capacity() * core::mem::size_of::<Fp3>();
    let count = required(point.len());
    if correlations.len() < count {
        return Err("B12 byte-function prover capacity exhausted".into());
    }
    let row_values = correlations.by_ref().take(count).collect::<Vec<_>>();
    let row_capacity_bytes = row_values.capacity() * core::mem::size_of::<Auth>();
    let mut rows = row_values.into_iter();
    let (root, root_eq_capacity_peak_bytes) = match original {
        Original::Lanes(v) => {
            let (weights, peak) = eq_scaled_counted(&lane_point, Fp3::ONE);
            let root = v.iter().zip(weights).fold(Auth::ZERO, |v, (&a, r)| v.add(a.scale(r)));
            (root, peak)
        }
        Original::Sum(a) => (a.scale(signed(s.tables.len() as i64).inv()), 0),
    };
    let c = coefficients(s.tables);
    let trees = ByteTrees::new(&c);
    let mut triples = Vec::new();
    let evaluator =
        std::cell::RefCell::new(contraction::Prover::new(&trees, s.cell_point.len(), &get_byte));
    let (layers, mut point, claims, tree_work) = range::prove_tree_sourcewise_custom(
        8,
        point,
        [root, Auth::ZERO],
        |layer, index| trees.children(layer, index, s.live_cells, &get_byte),
        fs,
        &mut rows,
        &mut triples,
        |layer, point, lambda, prefix| {
            contracted.then(|| evaluator.borrow_mut().coefficients(layer, point, lambda, prefix))
        },
        |layer, point| contracted.then(|| evaluator.borrow_mut().terminal(layer, point)),
    );
    let (_, index, leaf_eq_capacity_peak_bytes) = leaf(s, &c, &point);
    let leaf_point_capacity_bytes = point.capacity() * core::mem::size_of::<Fp3>();
    let leaf_tag = claims[0].m;
    record_values(fs, 0x61, &[leaf_tag]);
    let triples_capacity_bytes = triples.capacity() * core::mem::size_of::<[Auth; 3]>();
    let proof_capacity_bytes = range::tree_proof_heap_capacity_bytes(&layers, layers.capacity());
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    drop(triples);
    debug_assert!(rows.next().is_none());
    point.truncate(point.len() - 8);
    let internal_nodes = (s.tables.len() * 256 * 255) as u64;
    let coefficient_capacity_bytes = c.capacity() * core::mem::size_of::<[Fp3; 256]>();
    let lut_capacity_bytes = trees.nodes.capacity() * core::mem::size_of::<[Fp3; 2]>();
    let bind_phase_owned_heap_peak_bytes = (bind_work.prefix_capacity_bytes
        + bind_work.point_capacity_bytes.max(bind_work.attempt_capacity_bytes))
    .max(bind_work.point_capacity_bytes + combined_point_capacity_bytes);
    let root_phase_owned_heap_peak_bytes = bind_work.point_capacity_bytes
        + combined_point_capacity_bytes
        + row_capacity_bytes
        + root_eq_capacity_peak_bytes;
    let tree_phase_owned_heap_peak_bytes = root_phase_owned_heap_peak_bytes.max(
        bind_work.point_capacity_bytes
            + row_capacity_bytes
            + triples_capacity_bytes
            + proof_capacity_bytes
            + coefficient_capacity_bytes
            + lut_capacity_bytes
            + tree_work
                .owned_regeneration_heap_peak_bytes
                .max(leaf_point_capacity_bytes + leaf_eq_capacity_peak_bytes),
    );
    let work = SourceWork {
        tree: tree_work,
        bind_prefix_capacity_bytes: bind_work.prefix_capacity_bytes,
        bind_point_capacity_bytes: bind_work.point_capacity_bytes,
        bind_attempt_capacity_bytes: bind_work.attempt_capacity_bytes,
        bind_transcript_bytes: bind_work.transcript_bytes,
        combined_point_capacity_bytes,
        row_capacity_bytes,
        triples_capacity_bytes,
        proof_capacity_bytes,
        root_eq_capacity_peak_bytes,
        leaf_eq_capacity_peak_bytes,
        root_phase_owned_heap_peak_bytes,
        bind_phase_owned_heap_peak_bytes,
        tree_phase_owned_heap_peak_bytes,
        coefficient_capacity_bytes,
        lut_nodes: trees.nodes.len(),
        lut_capacity_bytes,
        lut_build_multiplications: 3 * internal_nodes,
        lut_build_additions: internal_nodes,
    };
    Ok((
        Proof { layers, leaf_tag, products },
        point,
        Auth::new(claims[1].x + index, claims[1].m),
        work,
    ))
}

pub(super) fn prove(
    s: &Statement<'_>,
    original: Original<'_, Auth>,
    get_byte: impl Fn(usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth), String> {
    let (proof, point, original, _) = prove_sourcewise(s, original, get_byte, fs, correlations)?;
    Ok((proof, point, original))
}

#[cfg(test)]
fn prove_dense(
    s: &Statement<'_>,
    original: Original<'_, Auth>,
    get_byte: impl Fn(usize) -> u8,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth), String> {
    let (len, sum) = match &original {
        Original::Lanes(v) => (v.len(), false),
        Original::Sum(_) => (1, true),
    };
    let (lane_point, _) = bind(s, len, sum, fs)?;
    let point: Vec<_> = s.cell_point.iter().chain(&lane_point).copied().collect();
    let count = required(point.len());
    if correlations.len() < count {
        return Err("B12 byte-function prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let root = match original {
        Original::Lanes(v) => {
            v.iter().zip(eq(&lane_point)).fold(Auth::ZERO, |v, (&a, r)| v.add(a.scale(r)))
        }
        Original::Sum(a) => a.scale(signed(s.tables.len() as i64).inv()),
    };
    let c = coefficients(s.tables);
    let mut bottom = Vec::with_capacity(256 << point.len());
    for i in 0..1usize << point.len() {
        let byte = signed(i64::from(get_byte(i)));
        let live = i / s.tables.len() < s.live_cells;
        for j in 0..256 {
            bottom.push([
                if live { c[i % s.tables.len()][j] } else { Fp3::ZERO },
                byte - signed(j as i64),
            ]);
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
    let (layers, mut point, claims) =
        range::prove_tree(&tree, point, [root, Auth::ZERO], fs, &mut rows, &mut triples);
    let (_, index, _) = leaf(s, &c, &point);
    let leaf_tag = claims[0].m;
    record_values(fs, 0x61, &[leaf_tag]);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    point.truncate(point.len() - 8);
    Ok((Proof { layers, leaf_tag, products }, point, Auth::new(claims[1].x + index, claims[1].m)))
}

pub(super) fn verify(
    s: &Statement<'_>,
    original: Original<'_, Key>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<(Vec<Fp3>, Key), String> {
    let (len, sum) = match &original {
        Original::Lanes(v) => (v.len(), false),
        Original::Sum(_) => (1, true),
    };
    let (lane_point, _) = bind(s, len, sum, fs)?;
    let point: Vec<_> = s.cell_point.iter().chain(&lane_point).copied().collect();
    let count = required(point.len());
    if !range::tree_shape(&proof.layers, 8, point.len()) || correlations.len() < count {
        return Err("B12 byte-function proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let root = match original {
        Original::Lanes(v) => {
            v.iter().zip(eq(&lane_point)).fold(Key::ZERO, |v, (&a, r)| v.add(a.scale(r)))
        }
        Original::Sum(a) => a.scale(signed(s.tables.len() as i64).inv()),
    };
    let mut triples = Vec::new();
    let (mut point, claims) = range::verify_tree(
        &proof.layers,
        point,
        [root, Key::ZERO],
        delta,
        fs,
        &mut rows,
        &mut triples,
    )?;
    let (coefficient, index, _) = leaf(s, &coefficients(s.tables), &point);
    if claims[0].k - delta * coefficient != proof.leaf_tag {
        return Err("B12 byte-function public leaf MAC rejected".into());
    }
    record_values(fs, 0x61, &[proof.leaf_tag]);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    drop(triples);
    debug_assert!(rows.next().is_none());
    point.truncate(point.len() - 8);
    Ok((point, Key::new(claims[1].k + delta * index)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::RngExt;

    #[test]
    fn c71_b12_byte_functions_close_original_byte_macs_in_one_ranged_pcs() {
        let n = 32;
        let source = [2u8, 5, 7, 129, 255, 0, 0, 0];
        let mut weights = vec![0; n * n];
        for (w, &b) in weights.iter_mut().zip(&source) {
            *w = i16::from(b);
        }
        let model = Model::new(n, weights).unwrap();
        let profile = gamma(&matrix_config(n).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let layout = [17; 32];
        let tables = [
            std::array::from_fn(|j| {
                Fp3::new(Fp::new((j & 1) as u64), Fp::new((j + 1) as u64), Fp::new((2 * j) as u64))
            }),
            std::array::from_fn(|j| {
                Fp3::new(
                    Fp::new((7 + j / 2 + usize::from(j % 4 == 3)) as u64),
                    Fp::new((3 * j + 1) as u64),
                    Fp::new((5 * j + 2) as u64),
                )
            }),
        ];
        let point = [signed(3), signed(11)];
        let statement = Statement {
            root: &model.root,
            profile: &profile,
            view: [18; 32],
            attempt,
            cell_point: &point,
            live_cells: 3,
            tables: &tables,
        };
        let delta = signed(19);
        let count = 2 + required(3) + range::required(10, range::Alphabet::Byte) + 32;
        assert_eq!(count, 809);
        let mut rng = MatrixRng::from_seed([126; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let start = || Fs::new(b"byte function original sources", 100_000);
        // A false incoming function must fail GKR; a consistent function of
        // changed bytes must reach GKR's endpoint and fail the SAME source PCS.
        for (live_cells, fault) in [3, 4].into_iter().flat_map(|n| (0..3).map(move |f| (n, f))) {
            let statement = Statement { live_cells, ..statement };
            let mut used = source;
            if fault == 2 {
                used[0] = 3;
            }
            let mut values: [Fp3; 2] = std::array::from_fn(|lane| {
                eq(&point).iter().take(live_cells).enumerate().fold(Fp3::ZERO, |v, (cell, &r)| {
                    v + r * tables[lane][used[2 * cell + lane] as usize]
                })
            });
            if fault == 1 {
                values[0] += Fp3::ONE;
            }
            let mut fs = start();
            let mut prows = rows.clone().into_iter();
            let (wire, original) = range::authenticate(values, &mut prows);
            record_values(&mut fs, 0x62, &wire);
            let (proof, byte_point, byte, source_work) = if live_cells == 4 {
                prove_contracted(
                    &statement,
                    Original::Lanes(&original),
                    |i| used[i],
                    &mut fs,
                    &mut prows,
                )
            } else {
                prove_sourcewise(
                    &statement,
                    Original::Lanes(&original),
                    |i| used[i],
                    &mut fs,
                    &mut prows,
                )
            }
            .unwrap();
            assert_eq!(source_work.lut_nodes, tables.len() * 256 * BYTE_TREE_NODES);
            if live_cells == 4 {
                assert_eq!(source_work.tree.custom_terminals, 8);
                assert_eq!(source_work.tree.custom_rounds, (0..8).map(|l| 3 + l).sum::<u64>());
            } else {
                assert!(source_work.tree.getter_calls > 0);
            }
            assert!(
                source_work.root_eq_capacity_peak_bytes
                    > tables.len() * core::mem::size_of::<Fp3>()
            );
            assert!(source_work.leaf_eq_capacity_peak_bytes > 256 * core::mem::size_of::<Fp3>());
            assert!(
                source_work.tree_phase_owned_heap_peak_bytes
                    >= source_work.root_phase_owned_heap_peak_bytes
            );
            if fault == 0 {
                if live_cells == 4 {
                    println!(
                        "C71_BYTE_CONTRACTED_PROOF original_wire_fs_mac=true fault_checks=true"
                    );
                }
                println!("C71_BYTE_SOURCE_WORK {}", serde_json::json!(source_work));
                let mut dense_fs = start();
                let mut dense_rows = rows.clone().into_iter();
                let (dense_wire, dense_original) = range::authenticate(values, &mut dense_rows);
                record_values(&mut dense_fs, 0x62, &dense_wire);
                let (dense, dense_point, dense_byte) = prove_dense(
                    &statement,
                    Original::Lanes(&dense_original),
                    |i| used[i],
                    &mut dense_fs,
                    &mut dense_rows,
                )
                .unwrap();
                let (mut source_bytes, mut dense_bytes) = (Vec::new(), Vec::new());
                crate::c71_matrix::wire::Wire::write(&proof, &mut source_bytes);
                crate::c71_matrix::wire::Wire::write(&dense, &mut dense_bytes);
                assert_eq!(source_bytes, dense_bytes);
                assert_eq!(byte_point, dense_point);
                assert_eq!((byte.x, byte.m), (dense_byte.x, dense_byte.m));
                assert_eq!(fs.digest(), dense_fs.digest());
            }
            assert_eq!(fs.requests(), 70);
            let (range_proof, mut forms, targets) = range::prove(
                &model,
                attempt,
                layout,
                8,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let byte_form = vec![Cube { offset: 0, point: byte_point, coefficient: Fp3::ONE }];
            let mut all_forms = forms.iter_mut().map(std::mem::take).collect::<Vec<_>>();
            all_forms.push(byte_form);
            let targets = [targets[0], targets[1], byte];
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &all_forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.clone().into_iter();
            let original = range::correct(wire, delta, &mut vrows);
            record_values(&mut fs, 0x62, &wire);
            let checked =
                verify(&statement, Original::Lanes(&original), &proof, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert_eq!(checked.unwrap_err(), "B12 range cubic MAC rejected");
                continue;
            }
            let (byte_point, byte) = checked.unwrap();
            let (forms, targets) = range::verify(
                n,
                &model.root,
                attempt,
                layout,
                8,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut all_forms = Vec::from(forms);
            all_forms.push(vec![Cube { offset: 0, point: byte_point, coefficient: Fp3::ONE }]);
            let targets = [targets[0], targets[1], byte];
            let checked = linear::verify(
                n,
                &model.root,
                attempt,
                layout,
                &all_forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert_eq!(checked.unwrap_err(), "C71 matrix sumcheck MAC rejected");
            } else {
                assert_eq!(checked.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
        }
        // Public coefficient identity, all 256 byte values in both tables,
        // and the ragged live-prefix polynomial including Boolean coordinates.
        let c = coefficients(&tables);
        for lane in 0..2 {
            for u in 0..256 {
                let mut tree: Vec<_> =
                    (0..256).map(|j| [c[lane][j], signed(u - j as i64)]).collect();
                while tree.len() > 1 {
                    tree = tree
                        .chunks_exact(2)
                        .map(|pair| {
                            let ([p, q], [r, s]) = (pair[0], pair[1]);
                            [p * s + r * q, q * s]
                        })
                        .collect();
                }
                assert_eq!(tree[0], [tables[lane][u as usize], Fp3::ZERO]);
            }
        }
        for point in [vec![], vec![Fp3::ZERO], vec![Fp3::ONE], point.to_vec()] {
            for live in 0..=1usize << point.len() {
                assert_eq!(
                    live_mass(live, &point),
                    eq(&point).into_iter().take(live).fold(Fp3::ZERO, |a, b| a + b)
                );
            }
        }
    }
}

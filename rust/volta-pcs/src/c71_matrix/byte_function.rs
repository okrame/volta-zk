//! Public byte functions through the SAME fraction-tree GKR as range.
//! Incoming function MACs share one cell point; the returned byte MAC must
//! join the caller's original byte-source forms in its one shared PCS.

use super::*;

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

pub(super) enum Original<'a, T> {
    Lanes(&'a [T]),
    // One ORIGINAL sum claim; never split it using fresh correlations.
    Sum(T),
}

pub(super) fn required(view_bits: usize) -> usize {
    32 * view_bits + 169
}

fn bind(s: &Statement<'_>, count: usize, sum: bool, fs: &mut Fs) -> Result<Vec<Fp3>, String> {
    if !s.tables.len().is_power_of_two()
        || s.tables.len() > 16
        || count != if sum { 1 } else { s.tables.len() }
        || s.cell_point.len() > 10
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
    if s.cell_point.len() + lane_bits > 10 {
        return Err("B12 byte-function dense view exceeds D10".into());
    }
    let mut bytes = if sum {
        b"C71-byte-function-B12-v2;P-S-SUM;fixed-half-lanes;original-MAC".to_vec()
    } else {
        b"C71-byte-function-B12-v1;P-S;cell-lane-gate-MSB;original-MAC".to_vec()
    };
    bytes.extend(s.root.roots()[0]);
    bytes.extend((s.profile.len() as u64).to_le_bytes());
    bytes.extend(s.profile);
    bytes.extend(s.view);
    bytes.extend(s.attempt.encode());
    bytes.extend((s.cell_point.len() as u32).to_le_bytes());
    bytes.extend((s.live_cells as u64).to_le_bytes());
    bytes.extend((s.tables.len() as u32).to_le_bytes());
    for &value in s.cell_point.iter().chain(s.tables.iter().flatten()) {
        bytes.extend(value.to_bytes());
    }
    fs.set_phase(0x800);
    fs.record(0x60, &bytes);
    Ok(if sum {
        vec![signed(2).inv(); lane_bits]
    } else {
        (0..lane_bits).map(|_| fs.fp3()).collect()
    })
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

fn leaf(s: &Statement<'_>, coefficients: &[[Fp3; 256]], point: &[Fp3]) -> (Fp3, Fp3) {
    let cells = s.cell_point.len();
    let gates = point.len() - 8;
    let lane_eq = eq(&point[cells..gates]);
    let gate_eq = eq(&point[gates..]);
    let coefficient = coefficients.iter().zip(lane_eq).fold(Fp3::ZERO, |sum, (c, w)| {
        sum + w * c.iter().zip(&gate_eq).fold(Fp3::ZERO, |v, (&c, &r)| v + c * r)
    });
    let index = point[gates..]
        .iter()
        .enumerate()
        .fold(Fp3::ZERO, |v, (i, &r)| v + signed(1 << (7 - i)) * r);
    (live_mass(s.live_cells, &point[..cells]) * coefficient, index)
}

// The caller records every original function correction under its public
// identity before this call. All claims use s.cell_point; dummy cells are
// zero outputs, including when f(0)!=0. The getter reads the fixed byte view
// in cell-major/lane-fastest order and must not inspect unused correlations.
pub(super) fn prove(
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
    let lane_point = bind(s, len, sum, fs)?;
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
    // ponytail: bounded dense view D<=10. Full Gemma uses the existing R2
    // public fold-table schedule; this component never allocates that trace.
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
    let (_, index) = leaf(s, &c, &point);
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
    let lane_point = bind(s, len, sum, fs)?;
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
    let (coefficient, index) = leaf(s, &coefficients(s.tables), &point);
    if claims[0].k - delta * coefficient != proof.leaf_tag {
        return Err("B12 byte-function public leaf MAC rejected".into());
    }
    record_values(fs, 0x61, &[proof.leaf_tag]);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
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
            std::array::from_fn(|j| signed((j & 1) as i64)),
            std::array::from_fn(|j| signed((7 + j / 2 + usize::from(j % 4 == 3)) as i64)),
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
        for fault in 0..3 {
            let mut used = source;
            if fault == 2 {
                used[0] = 3;
            }
            let mut values: [Fp3; 2] = std::array::from_fn(|lane| {
                eq(&point).iter().take(3).enumerate().fold(Fp3::ZERO, |v, (cell, &r)| {
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
            let (proof, byte_point, byte) =
                prove(&statement, Original::Lanes(&original), |i| used[i], &mut fs, &mut prows)
                    .unwrap();
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

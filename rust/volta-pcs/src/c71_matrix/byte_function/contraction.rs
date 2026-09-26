//! Reduced native evaluator; canonical streaming and hardware rates stay open.
//! Uses the original public ByteTrees LUT. No new transcript or MAC input.
use super::*;

fn children(trees: &ByteTrees, lane: usize, layer: usize, byte: usize) -> Vec<Fp3> {
    let start = (lane * 256 + byte) * BYTE_TREE_NODES + (2 << layer) - 1;
    trees.nodes[start..start + (2 << layer)].iter().flatten().copied().collect()
}

fn contract(
    trees: &ByteTrees,
    lane: usize,
    layer: usize,
    node_eq: &[Fp3],
    lambda: Fp3,
) -> Vec<(Fp3, [Fp3; 256])> {
    let count = 4 << layer;
    let degree = 1 << (7 - layer);
    let width = count.min(degree + 1);
    let (basis, vectors): (Vec<[Fp3; 256]>, Vec<Vec<Fp3>>) = if width == count {
        (
            (0..count)
                .map(|j| std::array::from_fn(|b| children(trees, lane, layer, b)[j]))
                .collect(),
            (0..count).map(|j| (0..width).map(|k| signed(i64::from(j == k))).collect()).collect(),
        )
    } else {
        // Degree <= D permits the Lagrange basis at public bytes 0..=D.
        // This avoids rebuilding polynomial coefficients beside the native LUT.
        let basis = (0..width)
            .map(|j| {
                let denom = (0..width)
                    .filter(|&k| k != j)
                    .fold(Fp3::ONE, |x, k| x * signed(j as i64 - k as i64))
                    .inv();
                std::array::from_fn(|b| {
                    (0..width)
                        .filter(|&k| k != j)
                        .fold(denom, |x, k| x * signed(b as i64 - k as i64))
                })
            })
            .collect();
        let vectors = (0..count)
            .map(|j| (0..width).map(|b| children(trees, lane, layer, b)[j]).collect())
            .collect();
        (basis, vectors)
    };
    // Check the degree premise against EVERY original byte, before contracting.
    for b in 0..256 {
        for (j, want) in children(trees, lane, layer, b).into_iter().enumerate() {
            assert_eq!(
                vectors[j].iter().zip(&basis).fold(Fp3::ZERO, |s, (&w, f)| s + w * f[b]),
                want
            );
        }
    }
    let mut m = vec![vec![Fp3::ZERO; width]; width];
    for (node, &e) in node_eq.iter().enumerate() {
        for (a, b, w) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
            let w = e * w;
            for i in 0..width {
                for j in 0..width {
                    m[i][j] += w * vectors[4 * node + a][i] * vectors[4 * node + b][j];
                }
            }
        }
    }
    let half = signed(2).inv();
    for i in 0..width {
        for j in i..width {
            let value = (m[i][j] + m[j][i]) * half;
            m[i][j] = value;
            m[j][i] = value;
        }
    }
    let mut features = Vec::new();
    loop {
        let pivot = (0..width).find(|&i| m[i][i] != Fp3::ZERO);
        let (d, row) = if let Some(i) = pivot {
            (m[i][i], m[i].clone())
        } else {
            let pair = (0..width)
                .find_map(|i| ((i + 1)..width).find(|&j| m[i][j] != Fp3::ZERO).map(|j| (i, j)));
            let Some((i, j)) = pair else { break };
            (m[i][j] + m[i][j], m[i].iter().zip(&m[j]).map(|(&a, &b)| a + b).collect())
        };
        let inv = d.inv();
        let v: Vec<_> = row.iter().map(|&x| x * inv).collect();
        let f = std::array::from_fn(|b| {
            v.iter().zip(&basis).fold(Fp3::ZERO, |s, (&w, f)| s + w * f[b])
        });
        features.push((d, f));
        for i in 0..width {
            for j in 0..width {
                m[i][j] = m[i][j] - d * v[i] * v[j];
            }
        }
        assert!(features.len() <= width);
    }
    features
}

fn fold(mut rows: Vec<Vec<Fp3>>, prefix: &[Fp3]) -> Vec<Vec<Fp3>> {
    for &r in prefix {
        let half = rows.len() / 2;
        for i in 0..half {
            for j in 0..rows[i].len() {
                let value = rows[i][j] + r * (rows[i + half][j] - rows[i][j]);
                rows[i][j] = value;
            }
        }
        rows.truncate(half);
    }
    rows
}

fn equality(point: &[Fp3], prefix: &[Fp3], suffix: usize) -> Fp3 {
    let mut value = Fp3::ONE;
    for (&p, &r) in point.iter().zip(prefix) {
        value = value * ((Fp3::ONE - p) * (Fp3::ONE - r) + p * r);
    }
    let tail = &point[prefix.len()..];
    for (bit, &p) in tail.iter().enumerate() {
        value = value * if suffix >> (tail.len() - 1 - bit) & 1 == 1 { p } else { Fp3::ONE - p };
    }
    value
}

pub(super) struct Prover<'a, G> {
    trees: &'a ByteTrees,
    cells: usize,
    get: &'a G,
    features: Vec<Vec<(Fp3, [Fp3; 256])>>,
    values: Vec<Vec<Vec<Fp3>>>,
    recovered: Option<Vec<Vec<Fp3>>>,
}

impl<'a, G: Fn(usize) -> u8> Prover<'a, G> {
    pub(super) fn new(trees: &'a ByteTrees, cells: usize, get: &'a G) -> Self {
        Self { trees, cells, get, features: Vec::new(), values: Vec::new(), recovered: None }
    }

    fn recover(&mut self, layer: usize, point: &[Fp3]) {
        if self.recovered.is_some() {
            return;
        }
        let weights = eq(&point[..self.cells]);
        let mut values = Vec::new();
        for lane in 0..self.trees.lanes {
            let mut histogram = [Fp3::ZERO; 256];
            for (cell, &w) in weights.iter().enumerate() {
                histogram[usize::from((self.get)(cell * self.trees.lanes + lane))] += w;
            }
            let mut children_at_cell = vec![Fp3::ZERO; 4 << layer];
            for (b, &w) in histogram.iter().enumerate() {
                for (out, v) in
                    children_at_cell.iter_mut().zip(children(self.trees, lane, layer, b))
                {
                    *out += w * v;
                }
            }
            values.extend(children_at_cell.chunks_exact(4).map(|v| v.to_vec()));
        }
        self.features.clear();
        self.values.clear();
        self.recovered = Some(values);
    }

    pub(super) fn coefficients(
        &mut self,
        layer: usize,
        point: &[Fp3],
        lambda: Fp3,
        prefix: &[Fp3],
    ) -> [Fp3; 4] {
        let lane_bits = self.trees.lanes.trailing_zeros() as usize;
        if prefix.is_empty() {
            self.recovered = None;
            let node_eq = eq(&point[self.cells + lane_bits..]);
            self.features = (0..self.trees.lanes)
                .map(|lane| contract(self.trees, lane, layer, &node_eq, lambda))
                .collect();
            // ponytail: reduced domain <=128 only; replace with the planned
            // streaming/checkpoint getter before any canonical admission.
            self.values = self
                .features
                .iter()
                .enumerate()
                .map(|(lane, features)| {
                    (0..1usize << self.cells)
                        .map(|cell| {
                            let b = usize::from((self.get)(cell * self.trees.lanes + lane));
                            features.iter().map(|(_, f)| f[b]).collect()
                        })
                        .collect()
                })
                .collect();
        }
        let mut c = [Fp3::ZERO; 4];
        if prefix.len() < self.cells {
            let lane_eq = eq(&point[self.cells..self.cells + lane_bits]);
            let half = 1usize << (self.cells - prefix.len() - 1);
            for (lane, features) in self.features.iter().enumerate() {
                let values = fold(self.values[lane].clone(), prefix);
                for i in 0..half {
                    let mut v = [Fp3::ZERO; 3];
                    for (j, (d, _)) in features.iter().enumerate() {
                        let a = values[i][j];
                        let delta = values[i + half][j] - a;
                        let da = *d * a;
                        let dd = *d * delta;
                        v[0] += da * a;
                        v[1] += signed(2) * da * delta;
                        v[2] += dd * delta;
                    }
                    let e = lane_eq[lane] * equality(&point[..self.cells], prefix, i);
                    let de = lane_eq[lane] * equality(&point[..self.cells], prefix, i + half) - e;
                    for j in 0..3 {
                        c[j] += e * v[j];
                        c[j + 1] += de * v[j];
                    }
                }
            }
        } else {
            self.recover(layer, prefix);
            let values = fold(self.recovered.as_ref().unwrap().clone(), &prefix[self.cells..]);
            let half = values.len() / 2;
            for i in 0..half {
                let a = &values[i];
                let d: [Fp3; 4] = std::array::from_fn(|j| values[i + half][j] - a[j]);
                let mut v = [Fp3::ZERO; 3];
                for (x, y, w) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
                    v[0] += w * a[x] * a[y];
                    v[1] += w * (d[x] * a[y] + a[x] * d[y]);
                    v[2] += w * d[x] * d[y];
                }
                let e = equality(point, prefix, i);
                let de = equality(point, prefix, i + half) - e;
                for j in 0..3 {
                    c[j] += e * v[j];
                    c[j + 1] += de * v[j];
                }
            }
        }
        c
    }

    pub(super) fn terminal(&mut self, layer: usize, point: &[Fp3]) -> [Fp3; 4] {
        self.recover(layer, point);
        fold(self.recovered.as_ref().unwrap().clone(), &point[self.cells..])[0]
            .as_slice()
            .try_into()
            .unwrap()
    }
}

#[test]
fn c71_byte_node_contraction_matches_native_lut_cubics_and_terminal_children() {
    let c: Vec<[Fp3; 256]> = (0..2)
        .map(|lane| {
            std::array::from_fn(|j| {
                Fp3::new(
                    Fp::new((j + lane + 1) as u64),
                    Fp::new((j * j + 3) as u64),
                    Fp::new((j + 7) as u64),
                )
            })
        })
        .collect();
    let trees = ByteTrees::new(&c);
    let extension = Fp3::new(Fp::new(13), Fp::new(17), Fp::new(19));
    let challenges = [extension, Fp3::ZERO, Fp3::ONE];
    let weights = eq(&challenges);
    let lambda = extension + signed(3);
    let bounds = [4, 8, 16, 17, 9, 5, 3, 2];
    for (layer, &bound) in bounds.iter().enumerate() {
        let node_eq = eq(&vec![extension; layer]);
        for lane in 0..2 {
            let features = contract(&trees, lane, layer, &node_eq, lambda);
            assert!(features.len() <= bound);
            // Public padding is byte zero inside the full EXP30 frame domain.
            let bytes = [0, 255, 0, 0, 17 + lane, 128, 0, 0];
            let original: Vec<_> =
                bytes.iter().map(|&b| children(&trees, lane, layer, b)).collect();
            let compact: Vec<_> =
                bytes.iter().map(|&b| features.iter().map(|(_, f)| f[b]).collect()).collect();
            for round in 0..3 {
                let dense = fold(original.clone(), &challenges[..round]);
                let folded = fold(compact.clone(), &challenges[..round]);
                let half = dense.len() / 2;
                for trial in [Fp3::ZERO, Fp3::ONE, signed(2), signed(3), extension + signed(5)] {
                    for i in 0..half {
                        let values: Vec<_> = dense[i]
                            .iter()
                            .zip(&dense[i + half])
                            .map(|(&a, &b)| a + trial * (b - a))
                            .collect();
                        let want =
                            values.chunks_exact(4).zip(&node_eq).fold(Fp3::ZERO, |s, (v, &e)| {
                                s + e * ((lambda * v[0] + v[1]) * v[3] + lambda * v[2] * v[1])
                            });
                        let got = features
                            .iter()
                            .zip(folded[i].iter().zip(&folded[i + half]))
                            .fold(Fp3::ZERO, |s, ((d, _), (&a, &b))| {
                                let v = a + trial * (b - a);
                                s + *d * v * v
                            });
                        assert_eq!(got, want);
                    }
                }
            }
            // Replay, including zero padding mass, recovers discarded directions.
            let mut histogram = [Fp3::ZERO; 256];
            for (&b, &w) in bytes.iter().zip(&weights) {
                histogram[b] += w;
            }
            let mut recovered = vec![Fp3::ZERO; 4 << layer];
            for (b, &w) in histogram.iter().enumerate() {
                for (out, v) in recovered.iter_mut().zip(children(&trees, lane, layer, b)) {
                    *out += w * v;
                }
            }
            assert_eq!(recovered, fold(original, &challenges)[0]);
        }
    }
    println!("C71_BYTE_NODE_CONTRACTION alphabet=256 layers=8 lanes=2 rank_sum_bound=64 native_LUT=true original_children=true proof_connected=false");
}

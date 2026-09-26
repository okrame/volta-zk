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
    checkpoint: usize,
    active: Vec<usize>,
    keys: Vec<usize>,
    get: &'a G,
    features: Vec<Vec<(Fp3, [Fp3; 256])>>,
    values: Vec<Vec<Vec<Fp3>>>,
    recovered: Option<Vec<Vec<Fp3>>>,
}

impl<'a, G: Fn(usize) -> u8> Prover<'a, G> {
    pub(super) fn new(
        trees: &'a ByteTrees,
        cells: usize,
        get: &'a G,
        public_support: impl Fn(usize) -> bool,
    ) -> Self {
        Self {
            trees,
            cells,
            checkpoint: 9.min(cells / 2),
            active: (0..1usize << cells).filter(|&i| public_support(i)).collect(),
            keys: Vec::new(),
            get,
            features: Vec::new(),
            values: Vec::new(),
            recovered: None,
        }
    }

    fn scaled(&self, lane: usize, prefix: &[Fp3]) -> Vec<Vec<[Fp3; 256]>> {
        eq(prefix)
            .into_iter()
            .map(|w| {
                self.features[lane]
                    .iter()
                    .map(|(_, f)| std::array::from_fn(|b| w * (f[b] - f[0])))
                    .collect()
            })
            .collect()
    }

    fn regenerate(
        &self,
        lane: usize,
        rounds: usize,
        start: usize,
        count: usize,
        scaled: &[Vec<[Fp3; 256]>],
    ) -> Vec<Vec<Fp3>> {
        let current = 1usize << (self.cells - rounds);
        (start..start + count)
            .map(|i| {
                let mut values: Vec<_> = self.features[lane].iter().map(|(_, f)| f[0]).collect();
                for (prefix, table) in scaled.iter().enumerate() {
                    if self.active.binary_search(&(prefix * current + i)).is_err() {
                        continue;
                    }
                    let b =
                        usize::from((self.get)((prefix * current + i) * self.trees.lanes + lane));
                    for (out, f) in values.iter_mut().zip(table) {
                        *out += f[b];
                    }
                }
                values
            })
            .collect()
    }

    fn projected(&self, period: usize) -> Vec<usize> {
        let mut keys: Vec<_> = self.active.iter().map(|i| i % period).collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn retained_value(&self, lane: usize, key: usize, j: usize) -> Fp3 {
        self.keys
            .binary_search(&key)
            .map(|i| self.values[lane][i][j])
            .unwrap_or(self.features[lane][j].1[0])
    }

    fn recover(&mut self, layer: usize, point: &[Fp3]) {
        if self.recovered.is_some() {
            return;
        }
        self.features.clear();
        self.values.clear(); // No retained feature is needed by the original-byte replay.
        let weights = eq(&point[..self.cells]);
        let mut values = Vec::new();
        for lane in 0..self.trees.lanes {
            let mut histogram = [Fp3::ZERO; 256];
            let mut mass = Fp3::ZERO;
            for &cell in &self.active {
                histogram[usize::from((self.get)(cell * self.trees.lanes + lane))] += weights[cell];
                mass += weights[cell];
            }
            histogram[0] += Fp3::ONE - mass;
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
            self.values.clear();
        }
        let mut c = [Fp3::ZERO; 4];
        if prefix.len() < self.cells {
            let lane_eq = eq(&point[self.cells..self.cells + lane_bits]);
            let half = 1usize << (self.cells - prefix.len() - 1);
            if prefix.len() == self.checkpoint {
                self.keys = self.projected(2 * half);
                self.values = (0..self.trees.lanes)
                    .map(|lane| {
                        let scaled = self.scaled(lane, prefix);
                        self.keys
                            .iter()
                            .map(|&key| {
                                self.regenerate(lane, prefix.len(), key, 1, &scaled).remove(0)
                            })
                            .collect()
                    })
                    .collect();
            } else if prefix.len() > self.checkpoint {
                let r = *prefix.last().unwrap();
                let keys = self.projected(2 * half);
                let next: Vec<_> = (0..self.trees.lanes)
                    .map(|lane| {
                        keys.iter()
                            .map(|&i| {
                                (0..self.features[lane].len())
                                    .map(|j| {
                                        let a = self.retained_value(lane, i, j);
                                        let b = self.retained_value(lane, i + 2 * half, j);
                                        a + r * (b - a)
                                    })
                                    .collect()
                            })
                            .collect()
                    })
                    .collect();
                // Both allocations stay live until the destination is complete.
                self.values = next;
                self.keys = keys;
            }
            let pairs = self.projected(half);
            for (lane, features) in self.features.iter().enumerate() {
                let baseline = features.iter().fold(Fp3::ZERO, |s, (d, f)| s + *d * f[0] * f[0]);
                let mut fixed = Fp3::ONE;
                for (&p, &r) in point.iter().zip(prefix) {
                    fixed = fixed * ((Fp3::ONE - p) * (Fp3::ONE - r) + p * r);
                }
                let at = point[prefix.len()];
                let e0 = lane_eq[lane] * fixed * (Fp3::ONE - at);
                let e1 = lane_eq[lane] * fixed * at;
                c[0] += e0 * baseline;
                c[1] += (e1 - e0) * baseline;
                let scaled = if prefix.len() < self.checkpoint {
                    self.scaled(lane, prefix)
                } else {
                    Vec::new()
                };
                for batch in pairs.chunks(16) {
                    let streamed = if prefix.len() < self.checkpoint {
                        Some(
                            batch
                                .iter()
                                .map(|&i| {
                                    (
                                        self.regenerate(lane, prefix.len(), i, 1, &scaled)
                                            .remove(0),
                                        self.regenerate(lane, prefix.len(), i + half, 1, &scaled)
                                            .remove(0),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        None
                    };
                    for (offset, &i) in batch.iter().enumerate() {
                        let mut v = [-baseline, Fp3::ZERO, Fp3::ZERO];
                        for (j, (d, _)) in features.iter().enumerate() {
                            let (a, b) = match &streamed {
                                Some(rows) => (rows[offset].0[j], rows[offset].1[j]),
                                None => (
                                    self.retained_value(lane, i, j),
                                    self.retained_value(lane, i + half, j),
                                ),
                            };
                            let delta = b - a;
                            let da = *d * a;
                            let dd = *d * delta;
                            let cross = da * delta;
                            v[0] += da * a;
                            v[1] += cross + cross;
                            v[2] += dd * delta;
                        }
                        let e = lane_eq[lane] * equality(&point[..self.cells], prefix, i);
                        let de =
                            lane_eq[lane] * equality(&point[..self.cells], prefix, i + half) - e;
                        for j in 0..3 {
                            c[j] += e * v[j];
                            c[j + 1] += de * v[j];
                        }
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

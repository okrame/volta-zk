//! Bounded native evaluator; canonical selection and hardware rates stay open.
//! Uses the original public ByteTrees LUT. No new transcript or MAC input.
use super::*;
use std::cell::Cell;

// Two states <=16 MiB, public feature tables <8 MiB, transform/Eq/support/tails <8 MiB.
const STATE_BYTES: usize = 8 << 20;
pub(super) const HEAP_UPPER_BYTES: usize = 32 << 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(in crate::c71_matrix) struct Work {
    pub original_byte_reads: u64,
    pub regenerated_rows: u64,
    pub retained_rows_peak: usize,
    pub retained_state_capacity_peak_bytes: usize,
    pub checkpoint_min: usize,
    pub checkpoint_max: usize,
    pub heap_capacity_upper_bytes: usize,
}

pub(in crate::c71_matrix) fn validate(cells: usize, lanes: usize, support: &[(u32,u32)], live_lanes: usize)
    -> Result<(), String> {
    if cells > 29 || !lanes.is_power_of_two() || lanes > 16 || live_lanes > lanes
        || support.len() > 16384 {
        return Err("byte contraction bounded geometry differs".into());
    }
    let mut previous = 0;
    for &(start,end) in support {
        if start < previous || start >= end || end as usize > 1usize << cells {
            return Err("byte contraction support differs".into());
        }
        previous = end;
    }
    Ok(())
}

#[test]
fn c71_byte_streamed_contraction_budget_support_and_original_coefficients() {
    assert!(validate(30,2,&[],2).is_err());
    assert!(validate(3,2,&[(0,3),(2,5)],2).is_err());
    assert!(validate(3,2,&[(0,9)],2).is_err());
    assert!(validate(3,2,&[(1,1)],2).is_err());
    let f=Fp3::new(Fp::new(13),Fp::new(17),Fp::new(19));
    let coefficients=(0..2).map(|lane|std::array::from_fn(|i| f*signed((i+lane+1) as i64))).collect::<Vec<_>>();
    let trees=ByteTrees::new(&coefficients);
    let support=[(0,3),(5,8)];
    let get=|i:usize| {
        let cell=i/2;assert!(cell<3 || cell>=5);
        ((i*29+3)%256) as u8
    };
    let literal=|i:usize|if i/2<3 || i/2>=5 {get(i)} else {0};
    for layer in [0,3,7] {
        let point=vec![f+signed(2);4+layer];
        let challenges=(0..point.len()).map(|i|[f,Fp3::ZERO,Fp3::ONE][i%3]).collect::<Vec<_>>();
        let original=(0..1usize<<point.len()).map(|i|trees.children(layer,i,8,&literal).to_vec()).collect::<Vec<_>>();
        let mut reads=Vec::new();
        for budget in [0,1024,STATE_BYTES] {
            let mut prover=Prover::new(&trees,3,&get,&support,2);prover.state_limit=budget;
            let lambda=if layer==0 {Fp3::ZERO} else {f};
            for round in 0..point.len() {
                let prefix=&challenges[..round];
                let got=prover.coefficients(layer,&point,lambda,prefix);
                let rows=fold(original.clone(),prefix);let half=rows.len()/2;
                let mut want=[Fp3::ZERO;4];
                for i in 0..half {
                    let a=&rows[i];let d:[Fp3;4]=std::array::from_fn(|j|rows[i+half][j]-a[j]);
                    let mut v=[Fp3::ZERO;3];
                    for (x,y,w) in [(0,3,lambda),(2,1,lambda),(1,3,Fp3::ONE)] {
                        v[0]+=w*a[x]*a[y];v[1]+=w*(d[x]*a[y]+a[x]*d[y]);v[2]+=w*d[x]*d[y];
                    }
                    let e=equality(&point,prefix,i);let de=equality(&point,prefix,i+half)-e;
                    for j in 0..3 {want[j]+=e*v[j];want[j+1]+=de*v[j];}
                }
                assert_eq!(got,want,"layer {layer}, round {round}, budget {budget}");
            }
            assert_eq!(prover.terminal(layer,&challenges).as_slice(),fold(original.clone(),&challenges)[0]);
            assert!(prover.work().retained_state_capacity_peak_bytes<=budget);
            reads.push(prover.work().original_byte_reads);
        }
        assert!(reads[2]<=reads[0]);
    }
    // Canonical geometry admission computes a late checkpoint without an N-sized allocation.
    let mut wide=Prover::new(&trees,29,&|_|panic!("public planning must not read bytes"),&[(0,1<<29)],2);
    wide.features=(0..2).map(|_|vec![(f,[f;256]);17]).collect();
    let checkpoint=wide.choose_checkpoint();assert!(checkpoint>7 && checkpoint<29);
    assert!(wide.state_bytes(1usize<<(29-checkpoint))<=STATE_BYTES);
    assert!(wide.state_bytes(1usize<<(30-checkpoint))>STATE_BYTES);
}

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

/// Public half-open original-coordinate spans; projection never depends on bytes.
pub(in crate::c71_matrix) fn project_support(spans: &[(u32, u32)], period: u32) -> Vec<(u32, u32)> {
    assert!(period.is_power_of_two());
    let mut pieces = Vec::new();
    for &(start, end) in spans {
        assert!(start < end);
        let len = end - start;
        if len >= period {
            return vec![(0, period)];
        }
        let first = start % period;
        if first + len <= period {
            pieces.push((first, first + len));
        } else {
            pieces.push((first, period));
            pieces.push((0, first + len - period));
        }
    }
    pieces.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    for (start, end) in pieces {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

pub(super) struct Prover<'a, G> {
    trees: &'a ByteTrees,
    cells: usize,
    live_lanes: usize,
    checkpoint: usize,
    active: Vec<(u32, u32)>,
    keys: Vec<usize>,
    get: &'a G,
    features: Vec<Vec<(Fp3, [Fp3; 256])>>,
    weighted_features: Vec<Vec<[Fp3; 256]>>,
    values: Vec<Vec<Vec<Fp3>>>,
    recovered: Option<Vec<Vec<Fp3>>>,
    work: Cell<Work>,
    state_limit: usize,
}

impl<'a, G: Fn(usize) -> u8> Prover<'a, G> {
    pub(super) fn new(
        trees: &'a ByteTrees,
        cells: usize,
        get: &'a G,
        public_support: &[(u32, u32)],
        live_lanes: usize,
    ) -> Self {
        validate(cells, trees.lanes, public_support, live_lanes).expect("validated byte support");
        Self {
            trees,
            cells,
            live_lanes,
            checkpoint: cells,
            active: project_support(public_support, 1u32 << cells),
            keys: Vec::new(),
            get,
            features: Vec::new(),
            weighted_features: Vec::new(),
            values: Vec::new(),
            recovered: None,
            work: Cell::new(Work { checkpoint_min: cells, heap_capacity_upper_bytes: HEAP_UPPER_BYTES,
                ..Work::default() }),
            state_limit: STATE_BYTES,
        }
    }

    pub(super) fn work(&self) -> Work { self.work.get() }

    fn read(&self, i: usize) -> u8 {
        let mut work=self.work.get();work.original_byte_reads+=1;self.work.set(work);
        (self.get)(i)
    }

    fn state_bytes(&self, rows: usize) -> usize {
        self.live_lanes * core::mem::size_of::<Vec<Vec<Fp3>>>()
            + rows * (core::mem::size_of::<usize>() + self.live_lanes * core::mem::size_of::<Vec<Fp3>>()
                + self.features[..self.live_lanes].iter().map(|f| 2*f.len()*core::mem::size_of::<Fp3>()).sum::<usize>())
    }

    fn choose_checkpoint(&self) -> usize {
        (0..self.cells).find(|&round| {
            let count: usize=self.projected(1usize << (self.cells-round)).iter()
                .map(|&(a,b)| (b-a) as usize).sum();
            self.state_bytes(count) <= self.state_limit
        }).unwrap_or(self.cells)
    }

    fn observe_state(&self, keys: &Vec<usize>, values: &Vec<Vec<Vec<Fp3>>>) {
        let bytes=keys.capacity()*core::mem::size_of::<usize>()
            + values.capacity()*core::mem::size_of::<Vec<Vec<Fp3>>>()
            + values.iter().map(|lane| lane.capacity()*core::mem::size_of::<Vec<Fp3>>()
                + lane.iter().map(|row| row.capacity()*core::mem::size_of::<Fp3>()).sum::<usize>()).sum::<usize>();
        assert!(bytes <= self.state_limit, "byte contraction state exceeds budget");
        let mut work=self.work.get();work.retained_rows_peak=work.retained_rows_peak.max(keys.len());
        work.retained_state_capacity_peak_bytes=work.retained_state_capacity_peak_bytes.max(bytes);
        self.work.set(work);
    }

    fn regenerate(
        &self,
        lane: usize,
        rounds: usize,
        start: usize,
        count: usize,
        prefix: &[Fp3],
    ) -> Vec<Vec<Fp3>> {
        assert_eq!(rounds,prefix.len());
        let current = 1usize << (self.cells - rounds);
        (start..start + count)
            .map(|i| {
                let mut values: Vec<_> = (0..2 * self.features[lane].len()).map(|j| self.baseline(lane, j)).collect();
                // Incremental Eq keeps only the completed prefix, including zero/one challenges.
                let mut path=[Fp3::ONE;30];
                for (bit,&r) in prefix.iter().enumerate() {path[bit+1]=path[bit]*(Fp3::ONE-r);}
                for at in 0..1usize << rounds {
                    if at != 0 {
                        let start=rounds-1-at.trailing_zeros() as usize;
                        for bit in start..rounds {
                            path[bit+1]=path[bit]*if at >> (rounds-1-bit)&1==1 {prefix[bit]} else {Fp3::ONE-prefix[bit]};
                        }
                    }
                    if !self.contains(at * current + i) {
                        continue;
                    }
                    let b=usize::from(self.read((at * current + i) * self.trees.lanes + lane));
                    for (j,out) in values.iter_mut().enumerate() {
                        let f=if j%2==0 {&self.features[lane][j/2].1} else {&self.weighted_features[lane][j/2]};
                        *out += path[rounds]*(f[b]-f[0]);
                    }
                }
                let mut work=self.work.get();work.regenerated_rows+=1;self.work.set(work);
                values
            })
            .collect()
    }

    fn contains(&self, i: usize) -> bool {
        let at = self.active.partition_point(|&(start, _)| start as usize <= i);
        at > 0 && i < (self.active[at - 1].1 as usize)
    }

    fn projected(&self, period: usize) -> Vec<(u32, u32)> {
        project_support(&self.active, period as u32)
    }

    fn projected_keys(&self, period: usize) -> Vec<usize> {
        let spans=self.projected(period);
        let count=spans.iter().map(|&(a,b)| (b-a) as usize).sum();
        assert!(self.state_bytes(count)<=self.state_limit);
        let mut keys=Vec::with_capacity(count);
        for (start,end) in spans {keys.extend((start..end).map(|i| i as usize));}
        keys
    }

    fn baseline(&self, lane: usize, j: usize) -> Fp3 {
        if j % 2 == 0 { self.features[lane][j / 2].1[0] }
        else { self.weighted_features[lane][j / 2][0] }
    }

    fn retained_value(&self, lane: usize, key: usize, j: usize) -> Fp3 {
        self.keys
            .binary_search(&key)
            .map(|i| self.values[lane][i][j])
            .unwrap_or_else(|_| self.baseline(lane, j))
    }

    fn recover(&mut self, layer: usize, point: &[Fp3]) {
        if self.recovered.is_some() {
            return;
        }
        self.features.clear();
        self.weighted_features.clear();
        self.values.clear(); // No retained feature is needed by the original-byte replay.
        let split = self.cells / 2;
        let high = eq(&point[..split]);
        let low = eq(&point[split..self.cells]);
        let low_bits = self.cells - split;
        let mut values = Vec::new();
        for lane in 0..self.trees.lanes {
            if lane >= self.live_lanes {
                values.extend(
                    children(self.trees, lane, layer, 0).chunks_exact(4).map(|v| v.to_vec()),
                );
                continue;
            }
            let mut histogram = [Fp3::ZERO; 256];
            let mut mass = Fp3::ZERO;
            for cell in self.active.iter().flat_map(|&(start, end)| start..end).map(|i| i as usize)
            {
                let weight = high[cell >> low_bits] * low[cell & (low.len() - 1)];
                histogram[usize::from(self.read(cell * self.trees.lanes + lane))] += weight;
                mass += weight;
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
            self.values.clear();
            self.keys.clear();
            let node_eq = eq(&point[self.cells + lane_bits..]);
            self.features = (0..self.trees.lanes)
                .map(|lane| contract(self.trees, lane, layer, &node_eq, lambda))
                .collect();
            self.weighted_features = self.features.iter().map(|lane| {
                lane.iter().map(|(d, f)| std::array::from_fn(|b| *d * f[b])).collect()
            }).collect();
            self.checkpoint=self.choose_checkpoint();
            let mut work=self.work.get();work.checkpoint_min=work.checkpoint_min.min(self.checkpoint);
            work.checkpoint_max=work.checkpoint_max.max(self.checkpoint);self.work.set(work);
        }
        let mut c = [Fp3::ZERO; 4];
        if prefix.len() < self.cells {
            let lane_eq = eq(&point[self.cells..self.cells + lane_bits]);
            let half = 1usize << (self.cells - prefix.len() - 1);
            if prefix.len() == self.checkpoint {
                self.keys = self.projected_keys(2 * half);
                self.values = (0..self.live_lanes)
                    .map(|lane| {
                        self.keys
                            .iter()
                            .map(|&key| {
                                self.regenerate(lane, prefix.len(), key, 1, prefix).remove(0)
                            })
                            .collect()
                    })
                    .collect();
                self.observe_state(&self.keys,&self.values);
            } else if prefix.len() > self.checkpoint {
                let r = *prefix.last().unwrap();
                let keys = self.projected_keys(2 * half);
                let next: Vec<_> = (0..self.live_lanes)
                    .map(|lane| {
                        keys.iter()
                            .map(|&i| {
                                (0..2 * self.features[lane].len())
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
                self.observe_state(&keys,&next);
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
                if lane >= self.live_lanes {
                    continue;
                }
                let mut quadratic = [Fp3::ZERO; 3];
                let mut indices =
                    pairs.iter().flat_map(|&(start, end)| start..end).map(|i| i as usize);
                loop {
                    let batch: Vec<_> = indices.by_ref().take(16).collect();
                    if batch.is_empty() {
                        break;
                    }
                    let streamed = if prefix.len() < self.checkpoint {
                        Some(
                            batch
                                .iter()
                                .map(|&i| {
                                    (
                                        self.regenerate(lane, prefix.len(), i, 1, prefix)
                                            .remove(0),
                                        self.regenerate(lane, prefix.len(), i + half, 1, prefix)
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
                        for j in 0..features.len() {
                            let value = |k, high| match &streamed {
                                Some(rows) => if high { rows[offset].1[k] } else { rows[offset].0[k] },
                                None => self.retained_value(lane, i + if high { half } else { 0 }, k),
                            };
                            let a = value(2*j, false);
                            let delta = value(2*j, true) - a;
                            let da = value(2*j+1, false);
                            let dd = value(2*j+1, true) - da;
                            let cross = da * delta;
                            v[0] += da * a;
                            v[1] += cross + cross;
                            v[2] += dd * delta;
                        }
                        let e = lane_eq[lane] * fixed
                            * equality(&point[prefix.len()+1..self.cells], &[], i);
                        for j in 0..3 {
                            quadratic[j] += e * v[j];
                        }
                    }
                }
                for j in 0..3 {
                    c[j] += (Fp3::ONE - at) * quadratic[j];
                    c[j+1] += (at + at - Fp3::ONE) * quadratic[j];
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

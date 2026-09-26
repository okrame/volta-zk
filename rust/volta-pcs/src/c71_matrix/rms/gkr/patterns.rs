//! Same cubic messages, with gate weights applied after position histograms.
//! No correlations or challenger are accessible from this module.
use super::*;

#[derive(Clone, Default, Debug, Eq, PartialEq, serde::Serialize)]
pub(super) struct Work {
    pub prefix_rounds: u64,
    pub original_frames: u64,
    pub packed_replays: u64,
    pub packed_boolean_gates: u64,
    pub histogram_updates: u64,
    pub deferred_base_reductions: u64,
    pub late_weight_products: u64,
    pub position_weight_products: u64,
    pub histogram_payload_peak: usize,
    pub packed_replay_capacity_peak: usize,
}

// Evaluation-only DAG: the committed layered circuit is never rewritten.
// Copies are aliases; public Boolean identities and identical gates share nodes.
struct ReplayPlan {
    nodes: Vec<Gate>,
    outputs: Vec<usize>,
}

impl ReplayPlan {
    fn new(program: &Circuit, depth: usize) -> Result<Self, String> {
        if depth > program.levels.len() {
            return Err("pattern replay depth differs".into());
        }
        let mut nodes = Vec::<Gate>::new();
        let mut aliases: Vec<_> = (0..program.ports).collect();
        let mut shared = std::collections::HashMap::new();
        for level in &program.levels[..depth] {
            let mut next = Vec::with_capacity(level.len());
            for g in level {
                let (&a, &b) = aliases
                    .get(g.x)
                    .zip(aliases.get(g.y))
                    .ok_or("pattern replay parent out of range")?;
                let (x, y) = (a.min(b), a.max(b));
                let alias = match g.op {
                    Op::Copy if g.x == g.y => Some(a),
                    Op::Copy => return Err("pattern copy parents differ".into()),
                    Op::And if x == 0 => Some(0),
                    Op::And if x == 1 || x == y => Some(y),
                    Op::Xor if x == y => Some(0),
                    Op::Xor if x == 0 => Some(y),
                    _ => None,
                };
                let id = alias.unwrap_or_else(|| {
                    *shared.entry((g.op, x, y)).or_insert_with(|| {
                        let id = program.ports + nodes.len();
                        nodes.push(Gate { op: g.op, x, y });
                        id
                    })
                });
                next.push(id);
            }
            aliases = next;
        }
        // Only ancestors of the requested original wires survive.
        let mut needed = vec![false; program.ports + nodes.len()];
        for &id in &aliases {
            needed[id] = true;
        }
        for (i, g) in nodes.iter().enumerate().rev() {
            if needed[program.ports + i] {
                needed[g.x] = true;
                needed[g.y] = true;
            }
        }
        let mut map: Vec<_> = (0..needed.len()).collect();
        let mut compact = Vec::new();
        for (i, g) in nodes.iter().enumerate() {
            if needed[program.ports + i] {
                map[program.ports + i] = program.ports + compact.len();
                compact.push(Gate { op: g.op, x: map[g.x], y: map[g.y] });
            }
        }
        Ok(Self { nodes: compact, outputs: aliases.into_iter().map(|i| map[i]).collect() })
    }

    fn replay(
        &self,
        program: &Circuit,
        inputs: &[u64],
        live: u64,
        values: &mut Vec<u64>,
        selected: &mut Vec<u64>,
    ) -> Result<(), String> {
        program.validate_replay_inputs(inputs, live)?;
        values.clear();
        values.reserve_exact(program.ports + self.nodes.len());
        values.extend_from_slice(inputs);
        for g in &self.nodes {
            values.push(match g.op {
                Op::And => values[g.x] & values[g.y],
                Op::Xor => values[g.x] ^ values[g.y],
                Op::Copy => unreachable!("copies are aliases"),
            });
        }
        selected.clear();
        selected.extend(self.outputs.iter().map(|&i| values[i]));
        Ok(())
    }

    fn bytes(&self) -> usize {
        self.nodes.capacity() * std::mem::size_of::<Gate>()
            + self.outputs.capacity() * std::mem::size_of::<usize>()
    }
}

// Each stage reads only older values. Slots retired by a stage become reusable
// AFTER its barrier; no in-place overwrite can race another thread's operand.
#[cfg(test)]
struct ParallelReplay {
    ops: Vec<[u32; 4]>, // And=0/Xor=1, output slot, x slot, y slot.
    boundaries: Vec<u32>,
    outputs: Vec<u32>,
    slots: usize,
}

#[cfg(test)]
impl ReplayPlan {
    fn parallel(&self, ports: usize) -> ParallelReplay {
        let mut depth = vec![0; ports];
        for g in &self.nodes {
            depth.push(1 + depth[g.x].max(depth[g.y]));
        }
        let stages = *depth.iter().max().unwrap();
        let mut levels = vec![Vec::new(); stages + 1];
        let mut last = vec![0; depth.len()];
        for (i, g) in self.nodes.iter().enumerate() {
            let d = depth[ports + i];
            levels[d].push(i);
            last[g.x] = last[g.x].max(d);
            last[g.y] = last[g.y].max(d);
        }
        for &i in &self.outputs { last[i] = stages + 1; }
        let mut retired = vec![Vec::new(); stages + 2];
        for (i, &d) in last.iter().enumerate() { retired[d].push(i); }
        let mut slots = ports;
        let mut map = vec![usize::MAX; depth.len()];
        for (i, m) in map[..ports].iter_mut().enumerate() { *m = i; }
        let mut free = retired[0].clone();
        let mut ops = Vec::with_capacity(self.nodes.len());
        let mut boundaries = vec![0];
        for d in 1..=stages {
            for &i in &levels[d] {
                let g = self.nodes[i];
                let slot = free.pop().unwrap_or_else(|| { let i = slots; slots += 1; i });
                map[ports + i] = slot;
                ops.push([u32::from(g.op == Op::Xor), slot as u32, map[g.x] as u32, map[g.y] as u32]);
            }
            boundaries.push(ops.len() as u32);
            free.extend(retired[d].iter().map(|&i| map[i]));
        }
        ParallelReplay { ops, boundaries, outputs: self.outputs.iter().map(|&i| map[i] as u32).collect(), slots }
    }
}

#[cfg(test)]
impl ParallelReplay {
    #[cfg(test)]
    fn replay(&self, inputs: &[u64]) -> Vec<u64> {
        let mut values = vec![0; self.slots];
        values[..inputs.len()].copy_from_slice(inputs);
        for range in self.boundaries.windows(2) {
            let stage = &self.ops[range[0] as usize..range[1] as usize];
            let writes: std::collections::BTreeSet<_> = stage.iter().map(|g| g[1]).collect();
            assert_eq!(writes.len(), stage.len());
            for &[op, z, x, y] in stage {
                assert!(!writes.contains(&x) && !writes.contains(&y));
                values[z as usize] = if op == 0 { values[x as usize] & values[y as usize] }
                    else { values[x as usize] ^ values[y as usize] };
            }
        }
        self.outputs.iter().map(|&i| values[i as usize]).collect()
    }
}

struct Histogram {
    mask: u64,
    tiles: Vec<Vec<usize>>,
    offsets: Vec<usize>,
    size: usize,
    gate_offsets: Vec<usize>,
    raw: Vec<[u64; 3]>,
    carries: Vec<[u32; 3]>,
    quadratic: Vec<Fp3>,
    linear: Vec<Fp3>,
}

impl Histogram {
    fn new(mask: u64, gates: &[Gate], tile_bits: usize) -> Self {
        let positions: Vec<_> = (0..16).filter(|j| mask >> j & 1 != 0).collect();
        let tiles: Vec<_> = positions.chunks(tile_bits).map(<[usize]>::to_vec).collect();
        let mut size = 0;
        let offsets = tiles
            .iter()
            .map(|t| {
                let o = size;
                size += 1 << t.len();
                o
            })
            .collect();
        let mut len = 0;
        let gate_offsets = gates
            .iter()
            .map(|g| {
                let o = len;
                len += if g.op == Op::Copy { size } else { size * size };
                o
            })
            .collect();
        Self {
            mask,
            tiles,
            offsets,
            size,
            gate_offsets,
            raw: vec![],
            carries: vec![],
            quadratic: vec![],
            linear: vec![],
        }
    }

    fn payload(&self, gates: &[Gate]) -> usize {
        let raw = gates
            .iter()
            .map(|g| if g.op == Op::Copy { self.size } else { self.size * self.size })
            .sum::<usize>();
        raw * 36 + (self.size * self.size + self.size) * 24
    }

    fn allocate(&mut self, gates: &[Gate]) {
        let len = (self.payload(gates) - (self.size * self.size + self.size) * 24) / 36;
        self.raw = vec![[0; 3]; len];
        self.carries = vec![[0; 3]; len];
        self.quadratic = vec![Fp3::ZERO; self.size * self.size];
        self.linear = vec![Fp3::ZERO; self.size];
    }

    fn accumulate(
        &mut self,
        gates: &[Gate],
        planes: &[u64],
        shift: usize,
        weight: Fp3,
        work: &mut Work,
    ) {
        let patterns: Vec<Vec<usize>> = planes
            .iter()
            .map(|&plane| {
                self.tiles
                    .iter()
                    .zip(&self.offsets)
                    .map(|(tile, &offset)| {
                        offset
                            + tile
                                .iter()
                                .enumerate()
                                .map(|(bit, &j)| (((plane >> (j + shift)) & 1) as usize) << bit)
                                .sum::<usize>()
                    })
                    .collect()
            })
            .collect();
        for (g, &offset) in gates.iter().zip(&self.gate_offsets) {
            for &x in &patterns[g.x] {
                if g.op == Op::Copy {
                    add_wide(&mut self.raw[offset + x], &mut self.carries[offset + x], weight);
                    work.histogram_updates += 1;
                } else {
                    for &y in &patterns[g.y] {
                        let slot = offset + x * self.size + y;
                        add_wide(&mut self.raw[slot], &mut self.carries[slot], weight);
                        work.histogram_updates += 1;
                    }
                }
            }
        }
    }

    fn finish(&mut self, gates: &[Gate], weights: &[Fp3], work: &mut Work) {
        let first = 1 << self.tiles[0].len();
        for ((g, &offset), &weight) in gates.iter().zip(&self.gate_offsets).zip(weights) {
            if g.op == Op::Copy {
                for x in 0..self.size {
                    self.linear[x] +=
                        weight * reduce_wide(self.raw[offset + x], self.carries[offset + x]);
                    work.late_weight_products += 1;
                    work.deferred_base_reductions += 3;
                }
            } else {
                for x in 0..self.size {
                    for y in 0..self.size {
                        let slot = offset + x * self.size + y;
                        let value = weight * reduce_wide(self.raw[slot], self.carries[slot]);
                        work.late_weight_products += 1;
                        work.deferred_base_reductions += 3;
                        let slot = &mut self.quadratic[x * self.size + y];
                        if g.op == Op::And {
                            *slot += value;
                        } else {
                            *slot = *slot - (value + value);
                            // Marginals from tile zero pay each linear term once.
                            if y < first {
                                self.linear[x] += value;
                            }
                            if x < first {
                                self.linear[y] += value;
                            }
                        }
                    }
                }
            }
        }
        self.raw = Vec::new(); // Last consumer; release before cubic evaluation.
        self.carries = Vec::new();
    }
}

fn add_wide(lo: &mut [u64; 3], hi: &mut [u32; 3], value: Fp3) {
    for (i, v) in [value.c0.value(), value.c1.value(), value.c2.value()].into_iter().enumerate() {
        let (next, carry) = lo[i].overflowing_add(v);
        lo[i] = next;
        hi[i] += u32::from(carry);
    }
}

fn reduce_wide(lo: [u64; 3], hi: [u32; 3]) -> Fp3 {
    let v = std::array::from_fn::<_, 3, _>(|i| {
        volta_field::reduce128((u128::from(hi[i]) << 64) | u128::from(lo[i]))
    });
    Fp3::new(v[0], v[1], v[2])
}

pub(super) struct Prefix {
    bits: usize,
    selector: Vec<Fp3>,
    histograms: Vec<Histogram>,
}

pub(super) fn build(
    s: &Statement<'_>,
    depth: usize,
    point: &[Fp3],
    weights: &[Fp3],
    read: &impl Fn(usize) -> [u8; 12],
    work: &mut Work,
    tile_bits: usize,
) -> Result<Option<Prefix>, String> {
    // One-bit tiles are a CPU moment oracle; production still uses five bits.
    // The nonzero pattern of each one-bit tile is exactly an original wire.
    if !matches!(tile_bits, 1 | 5) {
        return Err("unsupported pattern tile width".into());
    }
    let bits = 4.min(point.len().saturating_sub(1));
    if bits == 0 {
        return Ok(None);
    }
    if s.programs.len() != 1 {
        return Err("pattern prefix requires one public program".into());
    }
    let block = 1usize << bits;
    let suffix = s.assignments.len() / block;
    // Every raw slot receives at most one canonical limb per suffix index.
    // Thus its carry word is <suffix, even for adversarial field challenges.
    if suffix > u32::MAX as usize {
        return Err("pattern integer accumulator bound exceeded".into());
    }
    let gates = gates(&s.programs[0], depth);
    let mask_at = |k| {
        (0..block)
            .fold(0u64, |m, j| m | ((s.assignments.get(j * suffix + k).is_some() as u64) << j))
    };
    let masks: std::collections::BTreeSet<_> =
        (0..suffix).map(mask_at).filter(|&m| m != 0).collect();
    let mut histograms: Vec<_> =
        masks.into_iter().map(|m| Histogram::new(m, gates, tile_bits)).collect();
    let payload = histograms.iter().map(|h| h.payload(gates)).sum::<usize>();
    // Public cap on this component, not a claim about the complete arena.
    if payload > 1024 * 1024 * 1024 {
        return Err("pattern histograms exceed component cap".into());
    }
    work.histogram_payload_peak = work.histogram_payload_peak.max(payload);
    for h in &mut histograms {
        h.allocate(gates);
    }
    let program = &s.programs[0];
    let plan = ReplayPlan::new(program, depth - 1)?;
    let mut inputs = vec![0u64; program.ports];
    let mut values = Vec::new();
    let mut selected = Vec::new();
    let mut path = vec![Fp3::ONE; point.len() - bits + 1];
    // Division-free incremental Eq; zero/one challenges are allowed.
    let packed_groups = 64 / block;
    for start in (0..suffix).step_by(packed_groups) {
        let mut groups = Vec::with_capacity(packed_groups);
        inputs.fill(0);
        let mut live = 0u64;
        for k in start..suffix.min(start + packed_groups) {
            let suffix_bits = point.len() - bits;
            let changed = if k == 0 { suffix_bits } else { (k ^ (k - 1)).ilog2() as usize + 1 };
            for d in suffix_bits - changed..suffix_bits {
                let r = point[bits + d];
                path[d + 1] =
                    path[d] * if (k >> (suffix_bits - 1 - d)) & 1 == 0 { Fp3::ONE - r } else { r };
                work.position_weight_products += 1;
            }
            let mask = mask_at(k);
            if mask == 0 {
                continue;
            }
            let shift = (k - start) * block;
            live |= mask << shift;
            for j in 0..block {
                if mask >> j & 1 != 0 {
                    let frame = read(j * suffix + k);
                    work.original_frames += 1;
                    for bit in 0..program.ports - 2 {
                        inputs[bit + 2] |=
                            u64::from((frame[bit / 8] >> (bit % 8)) & 1) << (j + shift);
                    }
                }
            }
            groups.push((mask, shift, path[suffix_bits]));
        }
        if live == 0 {
            continue;
        }
        inputs[1] = live;
        plan.replay(program, &inputs, live, &mut values, &mut selected)?;
        work.packed_replays += 1;
        work.packed_boolean_gates += plan.nodes.len() as u64;
        work.packed_replay_capacity_peak = work
            .packed_replay_capacity_peak
            .max(plan.bytes() + 8 * (inputs.capacity() + values.capacity() + selected.capacity()));
        for (mask, shift, weight) in groups {
            histograms
                .iter_mut()
                .find(|h| h.mask == mask)
                .unwrap()
                .accumulate(gates, &selected, shift, weight, work);
        }
    }
    for h in &mut histograms {
        h.finish(gates, weights, work);
    }
    work.prefix_rounds += bits as u64;
    Ok(Some(Prefix { bits, selector: eq(&point[..bits]), histograms }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_pattern_replay_dag_matches_every_original_exp30_level() {
        let program = super::super::super::compile_ratio(14).unwrap();
        let mut records = Vec::new();
        use std::io::Write;
        let mut fixture = std::env::var_os("C71_EXP30_SHARED_FIXTURE").map(|p|
            std::io::BufWriter::new(std::fs::File::create(p).unwrap()));
        if let Some(f) = &mut fixture {
            f.write_all(b"C71DAG01").unwrap();
            f.write_all(&((program.levels.len() + 1) as u32).to_le_bytes()).unwrap();
        }
        for depth in 0..=program.levels.len() {
            let plan = ReplayPlan::new(&program, depth).unwrap();
            let parallel = plan.parallel(program.ports);
            if let Some(f) = &mut fixture {
                for n in [depth, program.ports, parallel.slots, parallel.boundaries.len()-1,
                          parallel.ops.len(), parallel.outputs.len()] {
                    f.write_all(&(n as u32).to_le_bytes()).unwrap();
                }
                for n in parallel.boundaries.iter().chain(parallel.ops.iter().flatten()).chain(parallel.outputs.iter()) {
                    f.write_all(&n.to_le_bytes()).unwrap();
                }
            }
            let mut values = Vec::new();
            let mut selected = Vec::new();
            for live in [u64::MAX, 0x8421_137f_aab9_7654, 0] {
                let mut inputs: Vec<_> = (0..program.ports)
                    .map(|i| {
                        (i as u64)
                            .wrapping_add(7)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .rotate_left(i as u32 % 64)
                            & live
                    })
                    .collect();
                inputs[0] = 0;
                inputs[1] = live;
                let (expected, _) = program.replay_layer(&inputs, live, depth).unwrap();
                plan.replay(&program, &inputs, live, &mut values, &mut selected).unwrap();
                assert_eq!(selected, expected, "depth {depth}");
                assert_eq!(parallel.replay(&inputs), expected, "parallel depth {depth}");
                if let Some(f) = &mut fixture {
                    for n in inputs.iter().chain(expected.iter()) { f.write_all(&n.to_le_bytes()).unwrap(); }
                }
            }
            records.push(serde_json::json!({"depth":depth,
                "word_operations":plan.nodes.len(), "plan_bytes":plan.bytes(),
                "shared_slots":parallel.slots, "shared_bytes_per_CTA":8*parallel.slots,
                "parallel_stages":parallel.boundaries.len()-1,
                "parallel_plan_bytes":16*parallel.ops.len()+4*(parallel.boundaries.len()+parallel.outputs.len()),
                "value_bytes":8*values.capacity(), "selected_bytes":8*selected.capacity(),
                "input_bytes":8*program.ports,
                "original_word_operations":program.levels[..depth].iter().map(Vec::len).sum::<usize>()}));
        }
        eprintln!("C71_EXP30_REPLAY_DAG {}", serde_json::to_string(&records).unwrap());
    }

    #[test]
    fn c71_pattern_wide_accumulator_matches_field_at_carry_boundaries() {
        let p = volta_field::P;
        let values = [Fp3::new(Fp::new(p - 1), Fp::new(p - 2), Fp::new(p - 3)), Fp3::ONE];
        let mut lo = [0; 3];
        let mut hi = [0; 3];
        let mut expected = Fp3::ZERO;
        for i in 0..257 {
            let x = values[i % 2];
            add_wide(&mut lo, &mut hi, x);
            expected += x;
            assert_eq!(reduce_wide(lo, hi), expected);
        }
        assert!(hi.iter().any(|&h| h > 0));
        // Largest public carry envelope, without enumerating those updates.
        for high in [0, 1, (1 << 25) - 1] {
            let low = [0, u64::MAX, p - 1];
            let upper = [high; 3];
            let actual = reduce_wide(low, upper);
            let expected = low.map(|v| {
                Fp::new((((u128::from(high) << 64) | u128::from(v)) % u128::from(p)) as u64)
            });
            assert_eq!(actual, Fp3::new(expected[0], expected[1], expected[2]));
        }
    }
}

impl Prefix {
    pub(super) fn bits(&self) -> usize {
        self.bits
    }
    pub(super) fn coefficients(&self, prefix: &[Fp3]) -> [Fp3; 4] {
        assert!(prefix.len() < self.bits);
        let remaining = self.bits - prefix.len() - 1;
        let previous = eq(prefix);
        let mut out = [Fp3::ZERO; 4];
        for tail in 0..1usize << remaining {
            let mut lo = vec![Fp3::ZERO; 1 << self.bits];
            let mut hi = lo.clone();
            for (j, &v) in previous.iter().enumerate() {
                lo[(j << (remaining + 1)) + tail] = v;
                hi[(j << (remaining + 1)) + (1 << remaining) + tail] = v;
            }
            for h in &self.histograms {
                let mut values = vec![[Fp3::ZERO; 2]; h.size];
                for (tile, &offset) in h.tiles.iter().zip(&h.offsets) {
                    for pattern in 1usize..1 << tile.len() {
                        let bit = pattern.trailing_zeros() as usize;
                        let base = values[offset + (pattern & (pattern - 1))];
                        values[offset + pattern] =
                            [base[0] + lo[tile[bit]], base[1] + hi[tile[bit]]];
                    }
                }
                for v in &mut values {
                    v[1] = v[1] - v[0];
                }
                let mut u = [Fp3::ZERO; 3];
                for (x, &[a, da]) in values.iter().enumerate() {
                    u[0] += h.linear[x] * a;
                    u[1] += h.linear[x] * da;
                    for (y, &[b, db]) in values.iter().enumerate() {
                        let w = h.quadratic[x * h.size + y];
                        u[0] += w * (a * b);
                        u[1] += w * (a * db + da * b);
                        u[2] += w * (da * db);
                    }
                }
                let a = (0..1 << self.bits)
                    .filter(|j| h.mask >> j & 1 != 0)
                    .fold(Fp3::ZERO, |v, j| v + self.selector[j] * lo[j]);
                let b = (0..1 << self.bits)
                    .filter(|j| h.mask >> j & 1 != 0)
                    .fold(Fp3::ZERO, |v, j| v + self.selector[j] * hi[j])
                    - a;
                for j in 0..3 {
                    out[j] += a * u[j];
                    out[j + 1] += b * u[j];
                }
            }
        }
        out
    }
}

//! Joint RMS-J GKR: public profile wiring, Boolean replay before folding,
//! sparse index messages, and the ORIGINAL input-bit claim through byte P/S.
//! Returning success leaves one original byte-view obligation for the SAME A PCS.

use super::super::*;
use super::{Circuit, Gate, Op};

pub(in super::super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    // Compiled by the verifier from its fixed public quantization parameters.
    pub programs: &'a [Circuit],
    pub assignments: &'a [Option<usize>],
}

struct Layer {
    rounds: Vec<Vec<Fp3>>, // cubic cell rounds, then two quadratic index reductions
    terminal: [Fp3; 4],    // X/Y/XY corrections and the affine zero-MAC tag
}

pub(in super::super) struct Proof {
    layers: Vec<Layer>,
    products: [Fp3; 2],
    functions: byte_function::Proof,
}

impl Statement<'_> {
    fn geometry(&self) -> Result<Vec<usize>, String> {
        if !self.assignments.len().is_power_of_two()
            || self.assignments.len() > 64
            || self.programs.is_empty()
            || self.programs.len() > 8
            || self.assignments.iter().flatten().any(|&p| p >= self.programs.len())
            || self.assignments.iter().all(Option::is_none)
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 RMS statement mismatch".into());
        }
        let height = self.programs.iter().map(|p| p.levels.len()).max().unwrap();
        if height == 0 || height > 128 {
            return Err("B12 RMS joint height exceeds 128".into());
        }
        let mut widths = vec![1usize; height + 1];
        for p in self.programs {
            if ![16, 32].contains(&p.product_bits)
                || p.ports != 2 + p.product_bits + 48 + 16
                || p.valid != 0
                || p.levels.last().is_none_or(|v| v.len() != 1)
                || p.levels.iter().map(Vec::len).sum::<usize>() > 2_000_000
            {
                return Err("B12 RMS public program differs".into());
            }
            widths[0] = widths[0].max(p.ports);
            let mut previous = p.ports;
            for (d, layer) in p.levels.iter().enumerate() {
                if layer.is_empty()
                    || layer.len() > 1 << 14
                    || layer.iter().any(|g| {
                        g.x >= previous || g.y >= previous || (g.op == Op::Copy && g.x != g.y)
                    })
                {
                    return Err("B12 RMS public wiring differs".into());
                }
                widths[d + 1] = widths[d + 1].max(layer.len());
                previous = layer.len();
            }
        }
        Ok(widths.into_iter().map(usize::next_power_of_two).collect())
    }

    pub fn required(&self) -> Result<usize, String> {
        let widths = self.geometry()?;
        let c = self.assignments.len().ilog2() as usize;
        Ok(widths[..widths.len() - 1]
            .iter()
            .map(|w| 4 * c + 6 * w.ilog2() as usize + 3)
            .sum::<usize>()
            + 1
            + byte_function::required(c + 4))
    }

    fn bind(&self, fs: &mut Fs) -> Vec<Fp3> {
        let mut bytes =
            b"C71-RMS-J-B12-v1;Boolean-XOR;cell-wire-MSB;P-S-Y-byte-view;original-MAC".to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        bytes.extend((self.programs.len() as u32).to_le_bytes());
        for p in self.programs {
            bytes.extend((p.ports as u32).to_le_bytes());
            bytes.extend((p.product_bits as u32).to_le_bytes());
            for c in p.coefficients {
                bytes.extend(c.to_le_bytes());
            }
            bytes.extend((p.arithmetic_bits as u32).to_le_bytes());
            bytes.extend((p.levels.len() as u32).to_le_bytes());
            for layer in &p.levels {
                bytes.extend((layer.len() as u32).to_le_bytes());
                for g in layer {
                    bytes.push(match g.op {
                        Op::And => 0,
                        Op::Xor => 1,
                        Op::Copy => 2,
                    });
                    bytes.extend((g.x as u32).to_le_bytes());
                    bytes.extend((g.y as u32).to_le_bytes());
                }
            }
        }
        bytes.extend((self.assignments.len() as u32).to_le_bytes());
        bytes.extend(self.assignments.iter().map(|p| p.map_or(255, |p| p as u8)));
        fs.set_phase(0xa00);
        fs.record(0x80, &bytes);
        (0..self.assignments.len().ilog2()).map(|_| fs.fp3()).collect()
    }

    fn live(&self, point: &[Fp3]) -> Fp3 {
        self.assignments
            .iter()
            .zip(eq(point))
            .filter(|(p, _)| p.is_some())
            .fold(Fp3::ZERO, |v, (_, r)| v + r)
    }

    fn selectors(&self, point: &[Fp3]) -> Vec<Vec<Fp3>> {
        let equality = eq(point);
        (0..self.programs.len())
            .map(|p| {
                self.assignments
                    .iter()
                    .zip(&equality)
                    .map(|(a, &r)| if *a == Some(p) { r } else { Fp3::ZERO })
                    .collect()
            })
            .collect()
    }

    // Sixteen lanes per cell. Unweighted frames use ten bytes, weighted
    // frames twelve; unused lanes and dummy cells are PUBLIC zeros.
    fn byte(&self, frames: &[[u8; 12]], i: usize) -> u8 {
        let (cell, lane) = (i / 16, i % 16);
        match self.assignments[cell] {
            Some(p) if lane < (self.programs[p].ports - 2) / 8 => frames[cell][lane],
            _ => 0,
        }
    }
}

fn gates(p: &Circuit, depth: usize) -> &[Gate] {
    p.levels.get(depth - 1).map_or(&[Gate { op: Op::Copy, x: 0, y: 0 }], Vec::as_slice)
}

// Exact field arithmetic of Boolean gates AFTER the source bitplanes fold.
fn polynomial(op: Op, x: Fp3, dx: Fp3, y: Fp3, dy: Fp3) -> [Fp3; 3] {
    let product = [x * y, x * dy + dx * y, dx * dy];
    match op {
        Op::And => product,
        Op::Xor => [
            x + y - signed(2) * product[0],
            dx + dy - signed(2) * product[1],
            -signed(2) * product[2],
        ],
        Op::Copy => [x, dx, Fp3::ZERO],
    }
}

fn cell_coefficients(
    s: &Statement<'_>,
    depth: usize,
    width: usize,
    v: &[Fp3],
    selectors: &[Vec<Fp3>],
    weights: &[Fp3],
) -> [Fp3; 4] {
    let half = v.len() / width / 2;
    let mut c = [Fp3::ZERO; 4];
    for (p, selector) in s.programs.iter().zip(selectors) {
        for (g, &weight) in gates(p, depth).iter().zip(weights) {
            for cell in 0..half {
                let (lo, hi) = (cell * width, (cell + half) * width);
                let a = selector[cell] * weight;
                let b = (selector[cell + half] - selector[cell]) * weight;
                let f = polynomial(
                    g.op,
                    v[lo + g.x],
                    v[hi + g.x] - v[lo + g.x],
                    v[lo + g.y],
                    v[hi + g.y] - v[lo + g.y],
                );
                for j in 0..3 {
                    c[j] += a * f[j];
                    c[j + 1] += b * f[j];
                }
            }
        }
    }
    c
}

// Sparse wiring: each edge supplies one equality selector. There is no
// quadratic-size wire-pair table, even for a public layer of thousands of gates.
struct Edge {
    gate: Gate,
    weight: Fp3,
}

fn edges(s: &Statement<'_>, depth: usize, weights: &[Fp3], selectors: &[Fp3]) -> Vec<Edge> {
    s.programs
        .iter()
        .zip(selectors)
        .flat_map(|(p, &selector)| {
            gates(p, depth)
                .iter()
                .zip(weights)
                .map(move |(&gate, &w)| Edge { gate, weight: w * selector })
        })
        .collect()
}

fn index_coefficients(
    edges: &[Edge],
    source: &[Fp3],
    folded: &[Fp3],
    left: Option<Fp3>,
) -> [Fp3; 3] {
    let half = folded.len() / 2;
    let mut c = [Fp3::ZERO; 3];
    for e in edges {
        let index = if left.is_some() { e.gate.y } else { e.gate.x };
        let lo = index % half;
        let (a, b) = if index & half == 0 { (Fp3::ONE, -Fp3::ONE) } else { (Fp3::ZERO, Fp3::ONE) };
        let value = folded[lo];
        let difference = folded[lo + half] - value;
        let f = match left {
            None => polynomial(e.gate.op, value, difference, source[e.gate.y], Fp3::ZERO),
            Some(x) => polynomial(e.gate.op, x, Fp3::ZERO, value, difference),
        };
        c[0] += e.weight * a * f[0];
        c[1] += e.weight * (a * f[1] + b * f[0]);
        c[2] += e.weight * b * f[1];
    }
    c
}

fn fold_edges(edges: &mut [Edge], half: usize, right: bool, r: Fp3) {
    for e in edges {
        let index = if right { e.gate.y } else { e.gate.x };
        e.weight = e.weight * if index & half == 0 { Fp3::ONE - r } else { r };
    }
}

fn terminal_coefficients(edges: &[Edge]) -> [Fp3; 3] {
    let mut c = [Fp3::ZERO; 3];
    for e in edges {
        match e.gate.op {
            Op::And => c[2] += e.weight,
            Op::Xor => {
                c[0] += e.weight;
                c[1] += e.weight;
                c[2] = c[2] - signed(2) * e.weight;
            }
            Op::Copy => c[0] += e.weight,
        }
    }
    c
}

fn round_prove(
    coefficients: &[Fp3],
    target: &mut Auth,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
) -> (Vec<Fp3>, Fp3) {
    let (mut wire, auth): (Vec<_>, Vec<_>) = coefficients
        .iter()
        .map(|&v| {
            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), v);
            (c.value(), a)
        })
        .unzip();
    wire.push(auth[0].m + auth.iter().fold(Fp3::ZERO, |v, a| v + a.m) - target.m);
    record_values(fs, 0x81, &wire);
    let r = fs.fp3();
    *target = auth.iter().rev().fold(Auth::ZERO, |v, &a| v.scale(r).add(a));
    (wire, r)
}

fn round_verify(
    wire: &[Fp3],
    target: &mut Key,
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Key>,
) -> Result<Fp3, String> {
    let keys: Vec<_> =
        wire[..wire.len() - 1].iter().map(|&c| range::correct([c], delta, rows)[0]).collect();
    if keys[0].k + keys.iter().fold(Fp3::ZERO, |v, k| v + k.k) - target.k != *wire.last().unwrap() {
        return Err("B12 RMS sumcheck MAC rejected".into());
    }
    record_values(fs, 0x81, wire);
    let r = fs.fp3();
    *target = keys.iter().rev().fold(Key::ZERO, |v, &k| v.scale(r).add(k));
    Ok(r)
}

fn next_weights(left: &[Fp3], right: &[Fp3], beta: Fp3) -> Vec<Fp3> {
    eq(left).into_iter().zip(eq(right)).map(|(a, b)| a + beta * b).collect()
}

fn tables(weights: &[Fp3]) -> [[Fp3; 256]; 16] {
    std::array::from_fn(|lane| {
        std::array::from_fn(|byte| {
            (0..8).fold(Fp3::ZERO, |v, bit| {
                v + if byte >> bit & 1 == 1 {
                    weights.get(2 + 8 * lane + bit).copied().unwrap_or(Fp3::ZERO)
                } else {
                    Fp3::ZERO
                }
            })
        })
    })
}

pub(in super::super) fn prove(
    s: &Statement<'_>,
    get_frame: impl Fn(usize) -> [u8; 12],
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth), String> {
    let widths = s.geometry()?;
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 RMS prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let mut point = s.bind(fs);
    let mut target = Auth::new(s.live(&point), Fp3::ZERO);
    let mut weights = vec![Fp3::ONE];
    let frames: Vec<_> = s
        .assignments
        .iter()
        .enumerate()
        .map(|(i, p)| if p.is_some() { get_frame(i) } else { [0; 12] })
        .collect();
    // ponytail: <=64 cells in u64 planes, <=8 public profiles. A full caller
    // must use the existing RMS-J block replay schedule, never this dense lift.
    let traces: Vec<_> = s
        .programs
        .iter()
        .enumerate()
        .map(|(p, program)| {
            let mut planes = vec![0u64; program.ports];
            for (cell, assignment) in s.assignments.iter().enumerate() {
                if *assignment == Some(p) {
                    planes[1] |= 1 << cell;
                    for bit in 0..program.ports - 2 {
                        planes[2 + bit] |=
                            u64::from((frames[cell][bit / 8] >> (bit % 8)) & 1) << cell;
                    }
                }
            }
            program.replay(&planes, planes[1])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (mut layers, mut triples) = (Vec::new(), Vec::new());
    for depth in (1..widths.len()).rev() {
        let width = widths[depth - 1];
        let mut previous = vec![Fp3::ZERO; s.assignments.len() * width];
        for trace in &traces {
            let planes = &trace[(depth - 1).min(trace.len() - 1)];
            for (wire, &plane) in planes.iter().enumerate() {
                for cell in 0..s.assignments.len() {
                    if plane >> cell & 1 == 1 {
                        previous[cell * width + wire] = Fp3::ONE;
                    }
                }
            }
        }
        let mut selectors = s.selectors(&point);
        let mut following = Vec::new();
        let mut rounds = Vec::new();
        for _ in 0..point.len() {
            let c = cell_coefficients(s, depth, width, &previous, &selectors, &weights);
            fs.set_phase(0x1000 + 64 * depth as u16 + rounds.len() as u16);
            let (wire, r) = round_prove(&c, &mut target, fs, &mut rows);
            fold(&mut previous, r);
            for selector in &mut selectors {
                fold(selector, r);
            }
            following.push(r);
            rounds.push(wire);
        }
        let selectors: Vec<_> = selectors.iter().map(|v| v[0]).collect();
        let mut edges = edges(s, depth, &weights, &selectors);
        let mut points = [Vec::new(), Vec::new()];
        let mut values = [Fp3::ZERO; 2];
        for side in 0..2 {
            let mut vector = previous.clone();
            while vector.len() > 1 {
                let c = index_coefficients(
                    &edges,
                    &previous,
                    &vector,
                    (side == 1).then_some(values[0]),
                );
                fs.set_phase(0x1000 + 64 * depth as u16 + rounds.len() as u16);
                let (wire, r) = round_prove(&c, &mut target, fs, &mut rows);
                fold_edges(&mut edges, vector.len() / 2, side == 1, r);
                fold(&mut vector, r);
                points[side].push(r);
                rounds.push(wire);
            }
            values[side] = vector[0];
        }
        let c = terminal_coefficients(&edges);
        let (wire, original) =
            range::authenticate([values[0], values[1], values[0] * values[1]], &mut rows);
        let tag = c.iter().zip(&original).fold(-target.m, |v, (&c, a)| v + c * a.m);
        let terminal = [wire[0], wire[1], wire[2], tag];
        fs.set_phase(0x4000 + depth as u16);
        record_values(fs, 0x82, &terminal);
        let beta = fs.fp3();
        target = original[0].add(original[1].scale(beta));
        weights = next_weights(&points[0], &points[1], beta);
        point = following;
        triples.push(original);
        layers.push(Layer { rounds, terminal });
    }
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    let target = Auth::new(target.x - weights[1] * s.live(&point), target.m);
    let tables = tables(&weights);
    let bs = byte_function::Statement {
        root: s.root,
        profile: s.profile,
        view: s.view,
        attempt: s.attempt,
        cell_point: &point,
        live_cells: s.assignments.len(),
        tables: &tables,
    };
    let (functions, point, original) = byte_function::prove(
        &bs,
        byte_function::Original::Sum(target),
        |i| s.byte(&frames, i),
        fs,
        &mut rows,
    )?;
    debug_assert!(rows.next().is_none());
    Ok((Proof { layers, products, functions }, point, original))
}

pub(in super::super) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<(Vec<Fp3>, Key), String> {
    let widths = s.geometry()?;
    let count = s.required()?;
    let c = s.assignments.len().ilog2() as usize;
    if correlations.len() < count
        || proof.layers.len() != widths.len() - 1
        || proof.layers.iter().zip(widths[..widths.len() - 1].iter().rev()).any(|(layer, w)| {
            layer.rounds.len() != c + 2 * w.ilog2() as usize
                || layer
                    .rounds
                    .iter()
                    .enumerate()
                    .any(|(i, r)| r.len() != if i < c { 5 } else { 4 })
        })
    {
        return Err("B12 RMS proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let mut point = s.bind(fs);
    let mut target = Key::new(delta * s.live(&point));
    let mut weights = vec![Fp3::ONE];
    let mut triples = Vec::new();
    for (layer, depth) in proof.layers.iter().zip((1..widths.len()).rev()) {
        let mut following = Vec::new();
        for (j, wire) in layer.rounds[..c].iter().enumerate() {
            fs.set_phase(0x1000 + 64 * depth as u16 + j as u16);
            following.push(round_verify(wire, &mut target, delta, fs, &mut rows)?);
        }
        let equality = eq(&following);
        let selectors: Vec<_> = s
            .selectors(&point)
            .iter()
            .map(|v| v.iter().zip(&equality).fold(Fp3::ZERO, |sum, (&a, &b)| sum + a * b))
            .collect();
        let mut edges = edges(s, depth, &weights, &selectors);
        let mut points = [Vec::new(), Vec::new()];
        let bits = widths[depth - 1].ilog2() as usize;
        for side in 0..2 {
            for j in 0..bits {
                fs.set_phase(0x1000 + 64 * depth as u16 + (c + side * bits + j) as u16);
                let r = round_verify(
                    &layer.rounds[c + side * bits + j],
                    &mut target,
                    delta,
                    fs,
                    &mut rows,
                )?;
                fold_edges(&mut edges, 1 << (bits - 1 - j), side == 1, r);
                points[side].push(r);
            }
        }
        let original = range::correct(
            [layer.terminal[0], layer.terminal[1], layer.terminal[2]],
            delta,
            &mut rows,
        );
        let coefficients = terminal_coefficients(&edges);
        if coefficients.iter().zip(&original).fold(-target.k, |v, (&c, k)| v + c * k.k)
            != layer.terminal[3]
        {
            return Err("B12 RMS terminal MAC rejected".into());
        }
        fs.set_phase(0x4000 + depth as u16);
        record_values(fs, 0x82, &layer.terminal);
        let beta = fs.fp3();
        target = original[0].add(original[1].scale(beta));
        weights = next_weights(&points[0], &points[1], beta);
        point = following;
        triples.push(original);
    }
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    let target = Key::new(target.k - delta * weights[1] * s.live(&point));
    let tables = tables(&weights);
    let bs = byte_function::Statement {
        root: s.root,
        profile: s.profile,
        view: s.view,
        attempt: s.attempt,
        cell_point: &point,
        live_cells: s.assignments.len(),
        tables: &tables,
    };
    let result = byte_function::verify(
        &bs,
        byte_function::Original::Sum(target),
        &proof.functions,
        delta,
        fs,
        &mut rows,
    )?;
    debug_assert!(rows.next().is_none());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_010::RngExt;

    fn frame(p: i64, s: i64, y: i64, weighted: bool) -> [u8; 12] {
        let mut result = [0; 12];
        let mut offset = 0;
        for (v, bits) in [(p, if weighted { 32 } else { 16 }), (s, 48), (y, 16)] {
            let biased = (v + (1i64 << (bits - 1))) as u64;
            for j in 0..bits / 8 {
                result[offset + j] = (biased >> (8 * j)) as u8;
            }
            offset += bits / 8;
        }
        result
    }

    #[test]
    fn c71_b12_rms_joint_gkr_reaches_original_ranged_bytes_without_bit_reauthentication() {
        let n = 32;
        let programs = [
            super::super::compile(3, 0, 0, 0, true).unwrap(),
            super::super::compile(256, 0, 0, 0, false).unwrap(),
        ];
        let assignments = [Some(0), Some(1), None, Some(0)];
        let honest =
            [frame(6, 14, 3, true), frame(-3, 9, -16, false), [0; 12], frame(0, 0, 0, true)];
        let profile = gamma(&matrix_config(n).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        let layout = [41; 32];
        for fault in 0..3 {
            let mut committed = honest;
            if fault == 1 {
                committed[1] = frame(-3, 9, -15, false);
            }
            let mut values = vec![0; n * n];
            for cell in 0..4 {
                for lane in 0..12 {
                    values[16 * cell + lane] = i16::from(committed[cell][lane]);
                }
            }
            let model = Model::new(n, values).unwrap();
            let statement = Statement {
                root: &model.root,
                profile: &profile,
                view: [42; 32],
                attempt,
                programs: &programs,
                assignments: &assignments,
            };
            let mut used = committed;
            if fault == 2 {
                used[0] = frame(6, 15, 3, true);
            }
            // Invalid dummy getter bytes are ignored; the public source view
            // and every circuit bitplane have exactly zero padding.
            used[2] = [255; 12];
            let count =
                statement.required().unwrap() + range::required(10, range::Alphabet::Byte) + 32;
            assert_eq!(count, 7299);
            let widths = statement.geometry().unwrap();
            let fs_count = 2
                + widths[..widths.len() - 1]
                    .iter()
                    .map(|w| 2 + 2 * w.ilog2() as usize + 1)
                    .sum::<usize>()
                + 1
                + 8 * 6
                + 45;
            let mut rng = MatrixRng::from_seed([127; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"joint exact RMS same-byte-root check", 100_000);
            let mut fs = start();
            let mut prows = rows.clone().into_iter();
            let (proof, point, original) =
                prove(&statement, |i| used[i], &mut fs, &mut prows).unwrap();
            assert_eq!(fs.requests(), fs_count);
            let (range_proof, forms, targets) = range::prove(
                &model,
                attempt,
                layout,
                64,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let mut forms = Vec::from(forms);
            forms.push(vec![linear::Cube { offset: 0, point, coefficient: Fp3::ONE }]);
            let targets = [targets[0], targets[1], original];
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.clone().into_iter();
            let checked = verify(&statement, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert_eq!(checked.unwrap_err(), "B12 RMS sumcheck MAC rejected");
                continue;
            }
            let (point, original) = checked.unwrap();
            assert_eq!(fs.requests(), fs_count);
            let (forms, targets) = range::verify(
                n,
                &model.root,
                attempt,
                layout,
                64,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut forms = Vec::from(forms);
            forms.push(vec![linear::Cube { offset: 0, point, coefficient: Fp3::ONE }]);
            let targets = [targets[0], targets[1], original];
            let checked = linear::verify(
                n,
                &model.root,
                attempt,
                layout,
                &forms,
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
            // Malformed proof and exhausted pool reject before burning rows.
            let mut short = keys[..statement.required().unwrap() - 1].to_vec().into_iter();
            let remaining = short.len();
            assert!(verify(&statement, &proof, delta, &mut start(), &mut short).is_err());
            assert_eq!(short.len(), remaining);
            assert_eq!(fs_count, 2163);
        }
    }
}

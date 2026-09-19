//! Joint RMS-J GKR: public profile wiring, Boolean replay before folding,
//! sparse index messages, and the ORIGINAL input-bit claim through byte P/S.
//! Returning success leaves one original byte-view obligation for the SAME A PCS.

use super::super::*;

component_wire!(Layer { rounds, terminal });
component_wire!(Proof { layers, products, functions });
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

fn widths(programs: &[Circuit]) -> Result<Vec<usize>, String> {
    if programs.is_empty() || programs.len() > 421 {
        return Err("B12 RMS public program count differs".into());
    }
    let height = programs.iter().map(|p| p.levels.len()).max().unwrap();
    if height == 0 || height > 128 {
        return Err("B12 RMS joint height exceeds 128".into());
    }
    let mut widths = vec![1usize; height + 1];
    for p in programs {
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
                || layer
                    .iter()
                    .any(|g| g.x >= previous || g.y >= previous || (g.op == Op::Copy && g.x != g.y))
            {
                return Err("B12 RMS public wiring differs".into());
            }
            widths[d + 1] = widths[d + 1].max(layer.len());
            previous = layer.len();
        }
    }
    Ok(widths.into_iter().map(usize::next_power_of_two).collect())
}

fn correlation_count(widths: &[usize], c: usize) -> usize {
    widths[..widths.len() - 1].iter().map(|w| 4 * c + 6 * w.ilog2() as usize + 3).sum::<usize>()
        + 1
        + byte_function::required(c + 4)
}

/// Public preflight: no cell assignments, witness, FS or correlation rows.
pub(in super::super) fn required(programs: &[Circuit], cell_bits: usize) -> Result<usize, String> {
    if cell_bits > 29 {
        return Err("B12 RMS cell domain exceeds D29".into());
    }
    Ok(correlation_count(&widths(programs)?, cell_bits))
}

impl Statement<'_> {
    fn geometry(&self) -> Result<Vec<usize>, String> {
        if !self.assignments.len().is_power_of_two()
            || self.assignments.len() > 1 << 29
            || self.programs.is_empty()
            || self.programs.len() > 421
            || self.assignments.iter().flatten().any(|&p| p >= self.programs.len())
            || self.assignments.iter().all(Option::is_none)
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 RMS statement mismatch".into());
        }
        widths(self.programs)
    }

    pub fn required(&self) -> Result<usize, String> {
        let widths = self.geometry()?;
        let c = self.assignments.len().ilog2() as usize;
        Ok(correlation_count(&widths, c))
    }

    fn bind(&self, fs: &mut Fs) -> Vec<Fp3> {
        // Keep the original framing when every profile fits below its 255
        // padding sentinel. Canonical RMS may have 421 distinct programs.
        let wide = self.programs.len() > 255;
        let mut bytes = if wide {
            b"C71-RMS-J-B12-v2;assignment-u16;Boolean-XOR;cell-wire-MSB;P-S-Y-byte-view;original-MAC".to_vec()
        } else {
            b"C71-RMS-J-B12-v1;Boolean-XOR;cell-wire-MSB;P-S-Y-byte-view;original-MAC".to_vec()
        };
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
        for p in self.assignments {
            if wide {
                bytes.extend(p.map_or(u16::MAX, |p| p as u16).to_le_bytes());
            } else {
                bytes.push(p.map_or(255, |p| p as u8));
            }
        }
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

#[cfg(test)]
pub(in super::super) fn work_census(
    programs: &[Circuit],
    assigned: &[u64],
    cell_bits: usize,
) -> Result<serde_json::Value, String> {
    if cell_bits > 29 || assigned.len() != programs.len() {
        return Err("GKR work census shape".into());
    }
    let n = 1u64 << cell_bits;
    let c = cell_bits as u64;
    let live: u64 = assigned.iter().sum();
    if live > n {
        return Err("GKR work census live cells".into());
    }
    let widths = widths(programs)?;
    let depth = widths.len() - 1;
    let mut layers = Vec::new();
    let (mut mul, mut add, mut sub, mut frame_callbacks) = (0u64, 0u64, 0u64, 0u64);
    let mut boolean_replay_gates = 0u64;
    for d in 1..=depth {
        let mut counts = [0u64; 3];
        for program in programs {
            if let Some(layer) = program.levels.get(d - 1) {
                assert!(layer.len() <= widths[d]);
                for gate in layer {
                    counts[match gate.op {
                        Op::And => 0,
                        Op::Xor => 1,
                        Op::Copy => 2,
                    }] += 1;
                }
            } else {
                counts[2] += 1;
            }
        }
        let g = counts.iter().sum::<u64>();
        let [and, xor, copy] = counts;
        // Factor the shared program selector after summing weighted gate
        // polynomials; Copy omits y/dy and Xor uses additions for doubling.
        let products = (7 * and + 7 * xor + 2 * copy + 6 * programs.len() as u64) * (n - 1);
        let additions = (4 * and + 9 * xor + 2 * copy + 6 * programs.len() as u64) * (n - 1);
        let subtractions = (2 * and + 4 * xor + copy + programs.len() as u64) * (n - 1);
        mul += products;
        add += additions;
        sub += subtractions;
        frame_callbacks += live * c;
        // Cell-first reconstruction: each live original cell is replayed
        // once per cell challenge, stopping at the required input layer.
        let replay: u64 = programs
            .iter()
            .zip(assigned)
            .map(|(p, &cells)| {
                cells * p.levels.iter().take(d - 1).map(|l| l.len() as u64).sum::<u64>()
            })
            .sum::<u64>()
            * c;
        boolean_replay_gates += replay;
        let w = widths[d - 1] as u64;
        layers.push(serde_json::json!({
                "depth":d, "input_width":w, "output_width":widths[d],
                "and":and, "xor":xor, "copy":copy,
                "logical_cell_gate_iterations_before_structural_support_pruning":g*(n-1),
                "cell_Fp3_mul_source_level_upper_before_structural_support_pruning":products,
                "cell_Fp3_add_source_level_upper_before_structural_support_pruning":additions,
                "cell_Fp3_sub_source_level_upper_before_structural_support_pruning":subtractions,
                "eager_original_Fp3_mul":(12*g+3*xor)*(n-1),
                "cell_Fp3_negations_upper_before_structural_support_pruning":xor*(n-1),
                "dense_previous_interpolations":w*(n-1),
                "dense_selector_interpolations":programs.len() as u64*(n-1),
                "index_edge_iterations":2*g*w.ilog2() as u64,
                "index_vector_interpolations":2*(w-1),
                "dense_previous_bytes":n*w*24,
                "cell_first_rows_selectors_and_support_bytes":(3*w+2*programs.len() as u64)*24+programs.len() as u64,
                "logical_live_frame_callbacks":live*c,
                "field_value_source_scalars":live*c*w,
                "field_fold_mul_add_each":live*c*(w+1),
                "prefix_weight_multiplications":n*c*c.saturating_sub(1)/2,
                "prefix_weight_subtractions":n*c*c.saturating_sub(1)/4,
                "scalar_boolean_replay_gate_evaluations":replay,
            }));
    }
    Ok(serde_json::json!({
        "credit":false, "scope":"exact public synthetic-profile geometry; source-level partial work",

        "live_cells":live, "padded_cells":n, "programs":programs.len(),
        "assigned_cells_by_program":assigned, "depth":depth,
        "dense_frame_bytes":n*12,
        "public_program_descriptor_bytes":programs.len()*core::mem::size_of::<Circuit>(),
        "public_program_inner_vec_capacity_bytes":programs.iter().map(|p|
            p.levels.capacity()*core::mem::size_of::<Vec<Gate>>()+
            p.levels.iter().map(|l| l.capacity()*core::mem::size_of::<Gate>()).sum::<usize>()
        ).sum::<usize>(),
        "selected_Boolean_replay_two_vectors_payload_upper_bytes":programs.iter().map(|p|
            p.levels.iter().enumerate().map(|(d,l)| 8*(l.len()+if d==0 {p.ports} else {p.levels[d-1].len()})).max().unwrap_or(8*p.ports)
        ).max().unwrap_or(0),
        "dense_assignment_bytes":n*std::mem::size_of::<Option<usize>>() as u64,
        "dense_selector_bytes":n*programs.len() as u64*24,
        "cell_Fp3_multiplications_source_level_upper_before_structural_support_pruning":mul,
        "cell_Fp3_additions_source_level_upper_before_structural_support_pruning":add,
        "cell_Fp3_subtractions_source_level_upper_before_structural_support_pruning":sub,
        "cell_first_logical_frame_callbacks":frame_callbacks,
        "dummy_row_callbacks":0,
        "field_value_source_scalars":live*c*widths[..depth].iter().map(|&w| w as u64).sum::<u64>(),
        "field_fold_mul_add_each":live*c*(widths[..depth].iter().map(|&w| w as u64).sum::<u64>()+depth as u64),
        "prefix_weight_multiplications":n*c*c.saturating_sub(1)/2*depth as u64,
        "prefix_weight_subtractions":n*c*c.saturating_sub(1)/4*depth as u64,
        "cell_first_scalar_boolean_replay_gates":boolean_replay_gates,
        "structural_selector_callbacks":n*c*depth as u64,
        "structural_selector_assigned_terms":live*c*depth as u64,
        "selector_specialization_saved_callbacks":(programs.len() as u64-1)*n*c*depth as u64,
        "selector_specialization_saved_Fp3_mul_add_each":
            (programs.len() as u64*n-live)*c*depth as u64,
        "compiler_constant_folding_or_Boolean_specialization_credit":false,
        "canonical_calibrated_profile":false, "complete_work":false,
        "complete_physical_peak":false, "layers":layers,
    }))
}

/// Work owned by the bounded cell-round coefficient builder. Counts are
/// source-level operations before optimization, not machine instructions,
/// physical traffic, or a runtime lower. Getter workspace is external.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SourceCellWork {
    logical_gate_cell_iterations: u64,
    gate_cell_iterations: u64,
    unsupported_program_cells: u64,
    unsupported_gate_iterations_saved: u64,
    row_source_callbacks: u64,
    value_source_scalars: u64,
    selector_source_callbacks: u64,
    selector_assigned_terms: u64,
    fold_weight_multiplications: u64,
    fold_value_multiplications: u64,
    fold_additions: u64,
    fold_subtractions: u64,
    coefficient_multiplications: u64,
    coefficient_additions: u64,
    coefficient_subtractions: u64,
    coefficient_negations: u64,
    owned_heap_peak_bytes: usize,
}

fn prefix_weight(prefix: usize, challenges: &[Fp3], work: &mut SourceCellWork) -> Fp3 {
    let mut weight = Fp3::ONE;
    for (round, &r) in challenges.iter().enumerate() {
        let bit = prefix >> (challenges.len() - 1 - round) & 1;
        if bit == 0 {
            weight = weight * (Fp3::ONE - r);
            work.fold_subtractions += 1;
        } else {
            weight = weight * r;
        }
        work.fold_weight_multiplications += 1;
    }
    weight
}

/// Bounded equivalent of `cell_coefficients` for one cell-domain round.
/// `row(cell,out)` fills the complete unfurled Boolean layer row, normally by
/// bounded `Circuit::replay`. `selector(cell)` supplies the cell's single
/// assigned program and original Eq weight, or `None` for a dummy cell. This
/// structural API cannot silently introduce two programs for one cell. The
/// five owned vectors are exactly
/// three width-W rows and two P-selector rows; there is no N*W or P*N table.
fn source_cell_coefficients(
    programs: &[Circuit],
    depth: usize,
    width: usize,
    cell_count: usize,
    challenges: &[Fp3],
    row: &impl Fn(usize, &mut [Fp3]) -> Result<(), String>,
    selector: &impl Fn(usize) -> Result<Option<(usize, Fp3)>, String>,
    weights: &[Fp3],
    work: &mut SourceCellWork,
) -> Result<[Fp3; 4], String> {
    if depth == 0
        || cell_count == 0
        || cell_count > 1 << 29
        || !cell_count.is_power_of_two()
        || !width.is_power_of_two()
        || width > 1 << 14
        || programs.is_empty()
        || programs.len() > 421
        || challenges.len() >= cell_count.ilog2() as usize
        || programs.iter().any(|program| {
            let gates = gates(program, depth);
            gates.len() > weights.len()
                || gates.iter().any(|gate| gate.x >= width || gate.y >= width)
        })
    {
        return Err("RMS sourcewise coefficient geometry differs".into());
    }
    let active = cell_count >> challenges.len();
    let half = active / 2;
    let program_count = programs.len();
    let mut lo = vec![Fp3::ZERO; width];
    let mut hi = vec![Fp3::ZERO; width];
    let mut scratch = vec![Fp3::ZERO; width];
    let mut selector_lo = vec![Fp3::ZERO; program_count];
    let mut selector_hi = vec![Fp3::ZERO; program_count];
    let mut present = vec![false; program_count];
    work.owned_heap_peak_bytes = work.owned_heap_peak_bytes.max(
        (lo.capacity()
            + hi.capacity()
            + scratch.capacity()
            + selector_lo.capacity()
            + selector_hi.capacity())
            * core::mem::size_of::<Fp3>()
            + present.capacity(),
    );
    let leaves = 1usize << challenges.len();
    let mut c = [Fp3::ZERO; 4];
    for cell in 0..half {
        lo.fill(Fp3::ZERO);
        hi.fill(Fp3::ZERO);
        selector_lo.fill(Fp3::ZERO);
        selector_hi.fill(Fp3::ZERO);
        present.fill(false);
        for side in 0..2 {
            let index = cell + side * half;
            let (folded, folded_selectors) =
                if side == 0 { (&mut lo, &mut selector_lo) } else { (&mut hi, &mut selector_hi) };
            for prefix in 0..leaves {
                let weight = prefix_weight(prefix, challenges, work);
                let source_cell = index + prefix * active;
                work.selector_source_callbacks += 1;
                if let Some((program, value)) = selector(source_cell)? {
                    let slot = folded_selectors
                        .get_mut(program)
                        .ok_or("RMS sourcewise selector program differs")?;
                    present[program] = true;
                    *slot += weight * value;
                    work.selector_assigned_terms += 1;
                    work.fold_value_multiplications += 1;
                    work.fold_additions += 1;
                    // Public padding has a fixed zero Boolean row. Do not
                    // invoke the original-byte getter for a dummy cell.
                    row(source_cell, &mut scratch)?;
                    work.row_source_callbacks += 1;
                    work.value_source_scalars += width as u64;
                    for wire in 0..width {
                        folded[wire] += weight * scratch[wire];
                        work.fold_value_multiplications += 1;
                        work.fold_additions += 1;
                    }
                }
            }
        }
        for (program_index, program) in programs.iter().enumerate() {
            let program_gates = gates(program, depth);
            work.logical_gate_cell_iterations += program_gates.len() as u64;
            if !present[program_index] {
                work.unsupported_program_cells += 1;
                work.unsupported_gate_iterations_saved += program_gates.len() as u64;
                continue;
            }
            // The public selector is shared by every gate of this program.
            // Accumulate its weighted gate polynomial first, then multiply by
            // that selector once. This preserves the four transcript values.
            let mut u = [Fp3::ZERO; 3];
            for (gate, &gate_weight) in program_gates.iter().zip(weights) {
                work.gate_cell_iterations += 1;
                let x = lo[gate.x];
                let dx = hi[gate.x] - x;
                if gate.op == Op::Copy {
                    u[0] += gate_weight * x;
                    u[1] += gate_weight * dx;
                    work.coefficient_multiplications += 2;
                    work.coefficient_additions += 2;
                    work.coefficient_subtractions += 1;
                } else {
                    let y = lo[gate.y];
                    let dy = hi[gate.y] - y;
                    let mut f = [x * y, x * dy + dx * y, dx * dy];
                    if gate.op == Op::Xor {
                        f = [x + y - (f[0] + f[0]), dx + dy - (f[1] + f[1]), -(f[2] + f[2])];
                        work.coefficient_additions += 5;
                        work.coefficient_subtractions += 2;
                        work.coefficient_negations += 1;
                    }
                    for j in 0..3 {
                        u[j] += gate_weight * f[j];
                    }
                    work.coefficient_multiplications += 7;
                    work.coefficient_additions += 4;
                    work.coefficient_subtractions += 2;
                }
            }
            let a = selector_lo[program_index];
            let b = selector_hi[program_index] - a;
            for j in 0..3 {
                c[j] += a * u[j];
                c[j + 1] += b * u[j];
            }
            work.coefficient_multiplications += 6;
            work.coefficient_additions += 6;
            work.coefficient_subtractions += 1;
        }
    }
    Ok(c)
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
    // Boolean replay is local to each 64-cell word. All blocks then enter
    // ONE cell-domain GKR and one original byte obligation; no block proof.
    // ponytail: retain the Boolean traces and one dense field layer. A physical
    // Gemma schedule needs bounded replay/folding; this is the analytic caller.
    let mut traces = Vec::new();
    for (block, assignments) in s.assignments.chunks(64).enumerate() {
        for (p, program) in s.programs.iter().enumerate() {
            if !assignments.contains(&Some(p)) {
                continue;
            }
            let mut planes = vec![0u64; program.ports];
            for (cell, assignment) in assignments.iter().enumerate() {
                if *assignment == Some(p) {
                    planes[1] |= 1 << cell;
                    for bit in 0..program.ports - 2 {
                        planes[2 + bit] |=
                            u64::from((frames[64 * block + cell][bit / 8] >> (bit % 8)) & 1)
                                << cell;
                    }
                }
            }
            traces.push((64 * block, program.replay(&planes, planes[1])?));
        }
    }
    let (mut layers, mut triples) = (Vec::new(), Vec::new());
    for depth in (1..widths.len()).rev() {
        let width = widths[depth - 1];
        let mut previous = vec![Fp3::ZERO; s.assignments.len() * width];
        for (offset, trace) in &traces {
            let planes = &trace[(depth - 1).min(trace.len() - 1)];
            for (wire, &plane) in planes.iter().enumerate() {
                for cell in 0..64.min(s.assignments.len() - offset) {
                    if plane >> cell & 1 == 1 {
                        previous[(offset + cell) * width + wire] = Fp3::ONE;
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

    #[test]
    fn sourcewise_cell_coefficients_match_dense_folds_without_cell_wire_matrix() {
        let programs = [
            Circuit {
                ports: 4,
                product_bits: 16,
                levels: vec![vec![
                    Gate { op: Op::And, x: 0, y: 1 },
                    Gate { op: Op::Xor, x: 2, y: 3 },
                ]],
                valid: 0,
                coefficients: [0; 3],
                arithmetic_bits: 1,
                raw_gates: 2,
            },
            Circuit {
                ports: 4,
                product_bits: 16,
                levels: vec![vec![
                    Gate { op: Op::Copy, x: 1, y: 1 },
                    Gate { op: Op::Xor, x: 0, y: 3 },
                ]],
                valid: 0,
                coefficients: [0; 3],
                arithmetic_bits: 1,
                raw_gates: 2,
            },
        ];
        let assignments = [Some(0), Some(1), None, Some(0)];
        let root = C61Commitment::new(vec![[7; 32]]);
        let profile = [8];
        let statement = Statement {
            root: &root,
            profile: &profile,
            view: [9; 32],
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [3; 32],
            },
            programs: &programs,
            assignments: &assignments,
        };
        let width = 4;
        let traces: Vec<_> = programs
            .iter()
            .enumerate()
            .map(|(program, circuit)| {
                let live = assignments.iter().enumerate().fold(0u64, |bits, (cell, assignment)| {
                    bits | (u64::from(*assignment == Some(program)) << cell)
                });
                circuit.replay(&[0, live, live & 0b0101, live & 0b1010], live).unwrap()
            })
            .collect();
        let trace_ref = &traces;
        let original: Vec<_> = assignments
            .iter()
            .enumerate()
            .flat_map(|(cell, assignment)| {
                (0..width).map(move |wire| {
                    assignment.map_or(Fp3::ZERO, |program| {
                        Fp3::from_base(Fp::new((trace_ref[program][0][wire] >> cell) & 1))
                    })
                })
            })
            .collect();
        let selector_point = [
            Fp3::new(Fp::new(17), Fp::new(2), Fp::new(3)),
            Fp3::new(Fp::new(19), Fp::new(5), Fp::new(7)),
        ];
        let equality = eq(&selector_point);
        let original_selectors: Vec<Vec<Fp3>> = (0..programs.len())
            .map(|program| {
                assignments
                    .iter()
                    .enumerate()
                    .map(
                        |(cell, assignment)| {
                            if *assignment == Some(program) {
                                equality[cell]
                            } else {
                                Fp3::ZERO
                            }
                        },
                    )
                    .collect()
            })
            .collect();
        let weights = [Fp3::from_base(Fp::new(5)), Fp3::from_base(Fp::new(7))];
        let challenges = [
            Fp3::new(Fp::new(11), Fp::new(2), Fp::new(3)),
            Fp3::new(Fp::new(13), Fp::new(5), Fp::new(7)),
        ];
        let mut dense = original.clone();
        let mut dense_selectors = original_selectors.clone();
        let mut prefix = Vec::new();
        for &challenge in &challenges {
            let expected =
                cell_coefficients(&statement, 1, width, &dense, &dense_selectors, &weights);
            let mut work = SourceCellWork::default();
            let actual = source_cell_coefficients(
                statement.programs,
                1,
                width,
                assignments.len(),
                &prefix,
                &|cell, out| {
                    out.fill(Fp3::ZERO);
                    if let Some(program) = assignments[cell] {
                        for (wire, value) in out.iter_mut().enumerate() {
                            *value =
                                Fp3::from_base(Fp::new((traces[program][0][wire] >> cell) & 1));
                        }
                    }
                    Ok(())
                },
                &|cell| Ok(assignments[cell].map(|program| (program, equality[cell]))),
                &weights,
                &mut work,
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                work.owned_heap_peak_bytes,
                (3 * width + 2 * programs.len()) * core::mem::size_of::<Fp3>() + programs.len()
            );
            assert_eq!(work.row_source_callbacks, 3);
            assert_eq!(work.value_source_scalars, (3 * width) as u64);
            assert_eq!(work.selector_source_callbacks, assignments.len() as u64);
            assert_eq!(work.selector_assigned_terms, 3);
            let expected_work = if prefix.is_empty() {
                // One of the two cell pairs has no program-1 selector.
                (8, 6, 2, 55, 55, 20)
            } else {
                (4, 4, 0, 35, 36, 13)
            };
            assert_eq!(work.logical_gate_cell_iterations, expected_work.0);
            assert_eq!(work.gate_cell_iterations, expected_work.1);
            assert_eq!(work.unsupported_gate_iterations_saved, expected_work.2);
            assert_eq!(work.coefficient_multiplications, expected_work.3);
            assert_eq!(work.coefficient_additions, expected_work.4);
            assert_eq!(work.coefficient_subtractions, expected_work.5);
            fold(&mut dense, challenge);
            for selector in &mut dense_selectors {
                fold(selector, challenge);
            }
            prefix.push(challenge);
        }

        let mut work = SourceCellWork::default();
        assert!(source_cell_coefficients(
            statement.programs,
            0,
            width,
            assignments.len(),
            &[],
            &|_, _| Ok(()),
            &|_| Ok(None),
            &weights,
            &mut work,
        )
        .is_err());
        assert!(source_cell_coefficients(
            statement.programs,
            1,
            width,
            assignments.len(),
            &[],
            &|_, _| Ok(()),
            &|_| Ok(None),
            &weights[..1],
            &mut work,
        )
        .is_err());
        let failure = source_cell_coefficients(
            statement.programs,
            1,
            width,
            assignments.len(),
            &[],
            &|_, _| Err("replay getter rejected".into()),
            &|_| Ok(Some((0, Fp3::ONE))),
            &weights,
            &mut work,
        )
        .unwrap_err();
        assert_eq!(failure, "replay getter rejected");

        let failure = source_cell_coefficients(
            statement.programs,
            1,
            width,
            assignments.len(),
            &[],
            &|_, out| {
                out.fill(Fp3::ZERO);
                Ok(())
            },
            &|_| Err("tile selector rejected".into()),
            &weights,
            &mut SourceCellWork::default(),
        )
        .unwrap_err();
        assert_eq!(failure, "tile selector rejected");

        let selector_failure = source_cell_coefficients(
            statement.programs,
            1,
            width,
            assignments.len(),
            &[],
            &|_, out| {
                out.fill(Fp3::ZERO);
                Ok(())
            },
            &|_| Ok(Some((programs.len(), Fp3::ONE))),
            &weights,
            &mut SourceCellWork::default(),
        )
        .unwrap_err();
        assert_eq!(selector_failure, "RMS sourcewise selector program differs");
    }

    #[test]
    fn sourcewise_real_boolean_replay_matches_dense_coefficients_at_selected_depths() {
        let programs = [
            super::super::compile(256, 0, 0, 0, true).unwrap(),
            super::super::compile(256, 0, 0, 0, false).unwrap(),
        ];
        let assignments = [Some(0), Some(1), None, Some(0)];
        let frames =
            [frame(9, 81, 16, true), frame(-3, 9, -16, false), [0; 12], frame(0, 0, 0, true)];
        let input = |cell: usize| {
            let p = assignments[cell].unwrap();
            let mut bits = vec![0u64; programs[p].ports];
            bits[1] = 1;
            for bit in 0..programs[p].ports - 2 {
                bits[bit + 2] = u64::from(frames[cell][bit / 8] >> (bit % 8) & 1);
            }
            bits
        };
        // Full traces belong only to the independent dense reference.
        let reference: Vec<_> = (0..4)
            .map(|i| assignments[i].map(|p| programs[p].replay(&input(i), 1).unwrap()))
            .collect();
        let geometry = widths(&programs).unwrap();
        let root = C61Commitment::new(vec![[71; 32]]);
        let statement = Statement {
            root: &root,
            profile: b"bounded real replay",
            view: [72; 32],
            attempt: AttemptContext {
                session: [73; 32],
                capacity: [74; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [75; 32],
            },
            programs: &programs,
            assignments: &assignments,
        };
        let point = [signed(3), signed(7)];
        let equality = eq(&point);
        for depth in [1, 7, geometry.len() - 1] {
            let width = geometry[depth - 1];
            let mut dense = vec![Fp3::ZERO; 4 * width];
            for cell in 0..4 {
                if let Some(trace) = &reference[cell] {
                    let layer = &trace[(depth - 1).min(trace.len() - 1)];
                    for (wire, &v) in layer.iter().enumerate() {
                        dense[cell * width + wire] = signed(v as i64);
                    }
                }
            }
            let weights: Vec<_> = (0..geometry[depth]).map(|i| signed(i as i64 + 2)).collect();
            let mut selectors = statement.selectors(&point);
            let mut prefix = Vec::new();
            for r in [signed(11), signed(13)] {
                let mut work = SourceCellWork::default();
                let actual = source_cell_coefficients(
                    &programs,
                    depth,
                    width,
                    4,
                    &prefix,
                    &|cell, out| {
                        let p = assignments[cell].expect("dummy cells never replay");
                        let (layer, replay_work) = programs[p].replay_layer(
                            &input(cell),
                            1,
                            (depth - 1).min(programs[p].levels.len()),
                        )?;
                        assert!(replay_work.peak_two_vector_capacity_bytes <= 2 * 4096 * 8);
                        out.fill(Fp3::ZERO);
                        for (v, bit) in out.iter_mut().zip(layer) {
                            *v = signed(bit as i64);
                        }
                        Ok(())
                    },
                    &|cell| Ok(assignments[cell].map(|p| (p, equality[cell]))),
                    &weights,
                    &mut work,
                )
                .unwrap();
                assert_eq!(
                    actual,
                    cell_coefficients(&statement, depth, width, &dense, &selectors, &weights)
                );
                assert_eq!(work.row_source_callbacks, 3);
                fold(&mut dense, r);
                for selector in &mut selectors {
                    fold(selector, r);
                }
                prefix.push(r);
            }
        }
    }

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
        let programs = [
            super::super::compile(3, 0, 0, 0, true).unwrap(),
            super::super::compile(256, 0, 0, 0, false).unwrap(),
        ];
        let honest =
            [frame(6, 14, 3, true), frame(-3, 9, -16, false), [0; 12], frame(0, 0, 0, true)];
        assert_eq!(
            check(&programs, honest, frame(-3, 9, -15, false), frame(6, 15, 3, true)),
            (7299, 2163)
        );
    }

    #[test]
    fn c71_b12_ratio_joint_gkr_keeps_original_numerator_denominator_and_output_bytes() {
        let programs =
            [super::super::compile_ratio(0).unwrap(), super::super::compile_ratio(14).unwrap()];
        let honest =
            [frame(3, 2, 2, true), frame(1, 32768, 0, true), [0; 12], frame(0, 1, 0, true)];
        let (count, draws) =
            check(&programs, honest, frame(1, 32768, 1, true), frame(4, 2, 2, true));
        eprintln!("ratio ranged A and PCS: {count} Fp3, {draws} kernel FS draws");
        assert!(count <= 12000 && draws <= 4000);
    }

    fn check(
        programs: &[Circuit],
        honest: [[u8; 12]; 4],
        wrong_output: [u8; 12],
        changed_input: [u8; 12],
    ) -> (usize, usize) {
        let assignments = [Some(0), Some(1), None, Some(0)];
        check_cells(programs, &assignments, &honest, (1, wrong_output), (0, changed_input))
    }

    #[test]
    fn c71_b12_replay_crosses_u64_and_profile_byte_boundaries_in_one_ranged_pcs() {
        // Small public parity programs isolate packing/dispatch from the
        // separately checked RMS/ratio arithmetic. This is not an RMS profile.
        let programs: Vec<_> = (0..421)
            .map(|i| {
                let product_bits = if i % 2 == 0 { 16 } else { 32 };
                Circuit {
                    ports: 2 + product_bits + 48 + 16,
                    product_bits,
                    levels: vec![
                        vec![
                            Gate { op: Op::Xor, x: 2, y: 2 + product_bits + 48 },
                            Gate { op: Op::Copy, x: 1, y: 1 },
                        ],
                        vec![Gate { op: Op::Xor, x: 0, y: 1 }],
                    ],
                    valid: 0,
                    coefficients: [0; 3],
                    arithmetic_bits: 1,
                    raw_gates: 3,
                }
            })
            .collect();
        let assignments: Vec<_> = (0..128)
            .map(|i| [Some(0), Some(255), None, Some(256), Some(420), Some(1)][i % 6])
            .collect();
        let honest: Vec<_> =
            assignments.iter().map(|p| p.map_or([0; 12], |p| frame(0, 0, 0, p % 2 == 1))).collect();
        let (count, draws) = check_cells(
            &programs,
            &assignments,
            &honest,
            (65, frame(0, 0, 1, true)),
            (64, frame(2, 0, 0, false)),
        );
        assert_eq!((count, draws), (1278, 173));
    }

    fn check_cells(
        programs: &[Circuit],
        assignments: &[Option<usize>],
        honest: &[[u8; 12]],
        wrong_output: (usize, [u8; 12]),
        changed_input: (usize, [u8; 12]),
    ) -> (usize, usize) {
        let c = assignments.len().ilog2() as usize;
        let n = 1usize << ((c + 4).div_ceil(2)).max(5);
        let dimension = 2 * n.ilog2() as usize;
        let mut observed = (0, 0);
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
            let mut committed = honest.to_vec();
            if fault == 1 {
                committed[wrong_output.0] = wrong_output.1;
            }
            let mut values = vec![0; n * n];
            for cell in 0..honest.len() {
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
                programs,
                assignments,
            };
            let mut used = committed;
            if fault == 2 {
                used[changed_input.0] = changed_input.1;
            }
            // Invalid dummy getter bytes are ignored; the public source view
            // and every circuit bitplane have exactly zero padding.
            for (i, p) in assignments.iter().enumerate() {
                if p.is_none() {
                    used[i] = [255; 12];
                }
            }
            let count = statement.required().unwrap()
                + range::required(dimension, range::Alphabet::Byte)
                + 3 * dimension
                + 2;
            let widths = statement.geometry().unwrap();
            let fs_count = c
                + widths[..widths.len() - 1]
                    .iter()
                    .map(|w| c + 2 * w.ilog2() as usize + 1)
                    .sum::<usize>()
                + 1
                + 8 * (c + 4)
                + 45;
            observed = (count, fs_count);
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
            if fault == 0 && programs.len() > 255 {
                // Programs 0 and 256 have identical gates here. A u8-cast
                // collision would therefore accept this changed assignment.
                let mut changed = assignments.to_vec();
                *changed.iter_mut().find(|p| **p == Some(256)).unwrap() = Some(0);
                let altered = Statement { assignments: &changed, ..statement };
                assert!(verify(
                    &altered,
                    &proof,
                    delta,
                    &mut start(),
                    &mut keys.clone().into_iter()
                )
                .is_err());
            }
            let (range_proof, forms, targets) = range::prove(
                &model,
                attempt,
                layout,
                16 * honest.len(),
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
                16 * honest.len(),
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
        }
        observed
    }
}

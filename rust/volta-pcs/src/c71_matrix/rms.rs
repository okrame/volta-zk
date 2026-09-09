//! Exact RMS predicate compiler, ported from the existing integer/Boolean
//! reference. Public parameters alone determine every gate and copy wire.

use std::collections::{BTreeSet, HashMap};

pub(super) mod gkr;
pub(super) mod statistic;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Op {
    And,
    Xor,
    Copy,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Gate {
    pub op: Op,
    pub x: usize,
    pub y: usize,
}

pub(super) struct Circuit {
    pub ports: usize,
    pub product_bits: usize,
    pub levels: Vec<Vec<Gate>>,
    pub valid: usize,
    pub coefficients: [u128; 3],
    pub arithmetic_bits: usize,
    pub raw_gates: usize,
}

struct Builder {
    ports: usize,
    gates: Vec<Gate>,
    depths: Vec<usize>,
    shared: HashMap<(Op, usize, usize), usize>,
}

impl Builder {
    fn gate(&mut self, op: Op, x: usize, y: usize) -> usize {
        if x == y {
            return if op == Op::And { x } else { 0 };
        }
        if op == Op::And {
            if x == 0 || y == 0 {
                return 0;
            }
            if x == 1 || y == 1 {
                return if x == 1 { y } else { x };
            }
        } else if x == 0 || y == 0 {
            return if x == 0 { y } else { x };
        }
        let key = (op, x.min(y), x.max(y));
        if let Some(&wire) = self.shared.get(&key) {
            return wire;
        }
        let wire = self.depths.len();
        self.shared.insert(key, wire);
        self.gates.push(Gate { op, x, y });
        self.depths.push(1 + self.depths[x].max(self.depths[y]));
        wire
    }
    fn and(&mut self, x: usize, y: usize) -> usize {
        self.gate(Op::And, x, y)
    }
    fn xor(&mut self, x: usize, y: usize) -> usize {
        self.gate(Op::Xor, x, y)
    }
    fn not(&mut self, x: usize) -> usize {
        self.xor(x, 1)
    }
    fn or(&mut self, x: usize, y: usize) -> usize {
        let a = self.xor(x, y);
        let b = self.and(x, y);
        self.xor(a, b)
    }
    fn mux(&mut self, bit: usize, yes: usize, no: usize) -> usize {
        let a = self.xor(yes, no);
        let b = self.and(bit, a);
        self.xor(no, b)
    }
    fn all(&mut self, mut word: Vec<usize>) -> usize {
        while word.len() > 1 {
            word = word
                .chunks(2)
                .map(|p| if p.len() == 2 { self.and(p[0], p[1]) } else { p[0] })
                .collect();
        }
        word.first().copied().unwrap_or(1)
    }
    fn prefix(&mut self, mut g: Vec<usize>, mut p: Vec<usize>) -> (Vec<usize>, Vec<usize>) {
        let mut distance = 1;
        while distance < g.len() {
            let ng = (0..g.len())
                .map(|i| {
                    if i >= distance {
                        let a = self.and(p[i], g[i - distance]);
                        self.xor(g[i], a)
                    } else {
                        g[i]
                    }
                })
                .collect();
            p = (0..p.len())
                .map(|i| if i >= distance { self.and(p[i], p[i - distance]) } else { p[i] })
                .collect();
            g = ng;
            distance *= 2;
        }
        (g, p)
    }
    fn add(&mut self, x: &[usize], y: &[usize], n: usize) -> Vec<usize> {
        let (x, y) = (pad(x, n), pad(y, n));
        let initial: Vec<_> = x.iter().zip(&y).map(|(&x, &y)| self.xor(x, y)).collect();
        let g = x.iter().zip(&y).map(|(&x, &y)| self.and(x, y)).collect();
        let (g, _) = self.prefix(g, initial.clone());
        initial
            .iter()
            .enumerate()
            .map(|(i, &v)| if i == 0 { v } else { self.xor(v, g[i - 1]) })
            .collect()
    }
    fn sum(&mut self, rows: Vec<Vec<usize>>, n: usize) -> Vec<usize> {
        let mut rows: Vec<_> =
            rows.into_iter().filter(|r| r.iter().any(|&v| v != 0)).map(|r| pad(&r, n)).collect();
        if rows.is_empty() {
            return vec![0; n];
        }
        while rows.len() > 2 {
            let mut merged = Vec::new();
            for p in rows.chunks_exact(3) {
                let t: Vec<_> = p[0].iter().zip(&p[1]).map(|(&x, &y)| self.xor(x, y)).collect();
                merged.push(t.iter().zip(&p[2]).map(|(&x, &y)| self.xor(x, y)).collect());
                let mut carry = vec![0];
                for j in 0..n - 1 {
                    let a = self.and(p[0][j], p[1][j]);
                    let b = self.and(t[j], p[2][j]);
                    carry.push(self.xor(a, b));
                }
                merged.push(carry);
            }
            merged.extend_from_slice(&rows[rows.len() / 3 * 3..]);
            rows = merged;
        }
        if rows.len() == 1 {
            rows.pop().unwrap()
        } else {
            self.add(&rows[0], &rows[1], n)
        }
    }
    fn multiply(&mut self, x: &[usize], y: &[usize], n: usize) -> Vec<usize> {
        let (x, y) = if y.len() > x.len() { (y, x) } else { (x, y) };
        let mut rows = Vec::new();
        if x == y {
            rows.push(
                (0..n).map(|i| if i % 2 == 0 && i / 2 < x.len() { x[i / 2] } else { 0 }).collect(),
            );
            for (i, &u) in x.iter().enumerate() {
                if u != 0 && 2 * i + 2 < n {
                    let mut row = vec![0; 2 * i + 2];
                    row.extend(x[i + 1..x.len().min(n - i - 1)].iter().map(|&v| self.and(u, v)));
                    rows.push(row);
                }
            }
        } else {
            for (i, &v) in y.iter().take(n).enumerate() {
                if v != 0 {
                    let mut row = vec![0; i];
                    row.extend(x.iter().take(n - i).map(|&u| self.and(u, v)));
                    rows.push(row);
                }
            }
        }
        self.sum(rows, n)
    }
    fn compare(&mut self, x: &[usize], y: &[usize], n: usize) -> (usize, usize) {
        let (x, y) = (pad(x, n), pad(y, n));
        let lt = x
            .iter()
            .zip(&y)
            .map(|(&x, &y)| {
                let a = self.not(x);
                self.and(a, y)
            })
            .collect();
        let eq = x
            .iter()
            .zip(&y)
            .map(|(&x, &y)| {
                let a = self.xor(x, y);
                self.not(a)
            })
            .collect();
        let (lt, eq) = self.prefix(lt, eq);
        (lt[n - 1], eq[n - 1])
    }
    fn le(&mut self, x: &[usize], y: &[usize], n: usize) -> usize {
        let (lt, eq) = self.compare(x, y, n);
        self.xor(lt, eq)
    }
    fn magnitude(&mut self, word: &[usize]) -> (Vec<usize>, usize) {
        let negative = self.not(*word.last().unwrap());
        let mut twos = word.to_vec();
        *twos.last_mut().unwrap() = negative;
        let v: Vec<_> = twos.iter().map(|&v| self.xor(v, negative)).collect();
        (self.add(&v, &[negative], word.len()), negative)
    }
    fn threshold(&mut self, denominator: &[usize], odd: &[usize], width: usize) -> Vec<usize> {
        let square = self.multiply(odd, odd, 2 * odd.len());
        self.multiply(denominator, &square, width)
    }
    fn layered(
        self,
        valid: usize,
        product_bits: usize,
        coefficients: [u128; 3],
        arithmetic_bits: usize,
    ) -> Result<Circuit, String> {
        let height = self.depths[valid];
        let mut needed = vec![false; self.depths.len()];
        let mut stack = vec![valid];
        while let Some(w) = stack.pop() {
            if needed[w] {
                continue;
            }
            needed[w] = true;
            if w >= self.ports {
                let g = self.gates[w - self.ports];
                stack.extend([g.x, g.y]);
            }
        }
        let mut last = vec![0; self.depths.len()];
        last[valid] = height + 1;
        for (i, g) in self.gates.iter().enumerate() {
            let w = i + self.ports;
            if needed[w] {
                for parent in [g.x, g.y] {
                    last[parent] = last[parent].max(self.depths[w]);
                }
            }
        }
        let rows: usize = last
            .iter()
            .enumerate()
            .map(|(w, &end)| end.saturating_sub(self.depths[w].max(1)))
            .sum();
        if rows > 2_000_000 {
            return Err("RMS public circuit exceeds two million layer rows".into());
        }
        let mut births = vec![Vec::new(); height + 2];
        let mut expires = births.clone();
        for (w, &end) in last.iter().enumerate() {
            if w < self.ports || needed[w] {
                if w >= self.ports {
                    births[self.depths[w]].push(w);
                }
                expires[end.max(1)].push(w);
            }
        }
        let mut active: BTreeSet<_> = (0..self.ports).collect();
        let mut previous = vec![usize::MAX; last.len()];
        for (i, p) in previous.iter_mut().take(self.ports).enumerate() {
            *p = i;
        }
        let mut levels = Vec::new();
        for depth in 1..=height {
            for w in &expires[depth] {
                active.remove(w);
            }
            active.extend(&births[depth]);
            let mut layer = Vec::new();
            let mut following = vec![usize::MAX; last.len()];
            for (i, &w) in active.iter().enumerate() {
                following[w] = i;
                let g = if self.depths[w] == depth {
                    self.gates[w - self.ports]
                } else {
                    Gate { op: Op::Copy, x: w, y: w }
                };
                assert!(previous[g.x] != usize::MAX && previous[g.y] != usize::MAX);
                layer.push(Gate { op: g.op, x: previous[g.x], y: previous[g.y] });
            }
            levels.push(layer);
            previous = following;
        }
        debug_assert_eq!(levels.iter().map(Vec::len).sum::<usize>(), rows);
        Ok(Circuit {
            ports: self.ports,
            product_bits,
            levels,
            valid: previous[valid],
            coefficients,
            arithmetic_bits,
            raw_gates: self.gates.len(),
        })
    }
}

fn pad(word: &[usize], n: usize) -> Vec<usize> {
    let mut v = word.to_vec();
    v.resize(n, 0);
    v
}
fn constant(value: u128, n: usize) -> Vec<usize> {
    (0..n).map(|i| usize::from(i < 128 && value >> i & 1 == 1)).collect()
}

pub(super) fn compile(
    columns: usize,
    input_exponent: i32,
    scale_exponent: i32,
    output_exponent: i32,
    weighted: bool,
) -> Result<Circuit, String> {
    if columns == 0 || columns > 5376 || (!weighted && scale_exponent != 0) {
        return Err("RMS public parameters differ".into());
    }
    let ex = i64::from(input_exponent) + i64::from(scale_exponent) - i64::from(output_exponent);
    let shift = 0.max(-2 * ex).max(-2 * i64::from(input_exponent));
    let shifted = |n: u128, s: i64| -> Result<u128, String> {
        if !(0..128).contains(&s) {
            return Err("RMS public coefficient exceeds u128".into());
        }
        n.checked_mul(1u128 << s).ok_or_else(|| "RMS public coefficient exceeds u128".into())
    };
    let mut coefficients = [
        shifted(1_000_000 * columns as u128, 2 * ex + shift)?,
        shifted(columns as u128, shift)?,
        shifted(1_000_000, 2 * i64::from(input_exponent) + shift)?,
    ];
    let mut common = coefficients[0];
    for mut v in coefficients[1..].iter().copied() {
        while v != 0 {
            (common, v) = (v, common % v);
        }
    }
    for v in &mut coefficients {
        *v /= common;
    }
    let [a, b, c] = coefficients;
    let pw = if weighted { 32 } else { 16 };
    let top = a.checked_mul(4).and_then(|v| v.checked_mul(1u128 << (2 * (pw - 1))));
    let bottom = c
        .checked_mul((1u128 << 47) - 1)
        .and_then(|v| v.checked_add(b))
        .and_then(|v| v.checked_mul(((1u128 << 17) - 1).pow(2)));
    let (top, bottom) = top.zip(bottom).ok_or("RMS circuit exceeds local 128-bit limit")?;
    let width = 128 - top.leading_zeros().min(bottom.leading_zeros()) as usize;
    let limit = if weighted { 32767u128.pow(2) } else { 32767 };
    let ports = 2 + pw + 48 + 16;
    let mut g =
        Builder { ports, gates: Vec::new(), depths: vec![0; ports], shared: HashMap::new() };
    let product: Vec<_> = (2..2 + pw).collect();
    let statistic: Vec<_> = (2 + pw..2 + pw + 48).collect();
    let output: Vec<_> = (2 + pw + 48..ports).collect();
    let (pmag, pneg) = g.magnitude(&product);
    let pg = g.le(&pmag, &constant(limit, pw), pw);
    let surrogate = &statistic[..47];
    let sg = g.le(surrogate, &constant(columns as u128 * 32767u128.pow(2), 47), 47);
    let sg = g.and(statistic[47], sg);
    let square = g.multiply(&pmag, &pmag, 2 * pw);
    let numerator = g.multiply(&square, &constant(4 * a, width), width);
    let denominator = g.multiply(surrogate, &constant(c, width), width);
    let denominator = g.add(&denominator, &constant(b, width), width);
    let (m, negative) = g.magnitude(&output);
    let inverses = m.iter().map(|&v| g.not(v)).collect();
    let zero = g.all(inverses);
    let inverses = output.iter().map(|&v| g.not(v)).collect();
    let yg = g.all(inverses);
    let yg = g.not(yg);
    let sign = g.xor(pneg, negative);
    let sign = g.not(sign);
    let sign = g.or(zero, sign);
    let mut doubled = vec![0];
    doubled.extend(&m);
    let odd = g.add(&doubled, &constant((1 << 17) - 1, 17), 17);
    let lower = g.threshold(&denominator, &odd, width);
    let odd = g.add(&doubled, &[1], 17);
    let upper = g.threshold(&denominator, &odd, width);
    let (lo, lo_eq) = g.compare(&lower, &numerator, width);
    let (hi, hi_eq) = g.compare(&numerator, &upper, width);
    let even = g.not(m[0]);
    let tie = g.and(lo_eq, even);
    let lo = g.xor(lo, tie);
    let tie = g.and(hi_eq, even);
    let hi = g.xor(hi, tie);
    let between = g.and(lo, hi);
    let zero_bound = g.le(&numerator, &denominator, width);
    let bound = g.mux(zero, zero_bound, between);
    let valid = g.all(vec![pg, sg, yg, sign, bound]);
    g.layered(valid, pw, coefficients, width)
}

impl Circuit {
    /// At most 64 Boolean cells, one bit per cell, before any field fold.
    /// Padding is zero in EVERY plane, including the public constant one.
    pub fn replay(&self, inputs: &[u64], live: u64) -> Result<Vec<Vec<u64>>, String> {
        if inputs.len() != self.ports
            || inputs[0] != 0
            || inputs[1] != live
            || inputs.iter().any(|&v| v & !live != 0)
        {
            return Err("RMS Boolean inputs or padding differ".into());
        }
        let mut trace = vec![inputs.to_vec()];
        for layer in &self.levels {
            let previous = trace.last().unwrap();
            let mut next = Vec::with_capacity(layer.len());
            for &Gate { op, x, y } in layer {
                let (&a, &b) = previous
                    .get(x)
                    .zip(previous.get(y))
                    .ok_or("RMS Boolean parent out of range")?;
                next.push(match op {
                    Op::And => a & b,
                    Op::Xor => a ^ b,
                    Op::Copy if x == y => a,
                    _ => return Err("RMS Boolean copy differs".into()),
                });
            }
            trace.push(next);
        }
        Ok(trace)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::c71_matrix) fn expected(
        p: i64,
        s: i64,
        columns: usize,
        weighted: bool,
        [a, b, c]: [u128; 3],
    ) -> Option<i64> {
        let limit = if weighted { 32767i64.pow(2) } else { 32767 };
        if p.abs() > limit || s < 0 || s > columns as i64 * 32767i64.pow(2) {
            return None;
        }
        let n = a * (p.unsigned_abs() as u128).pow(2);
        let d = b + c * s as u128;
        if 4 * n >= d * 65535u128.pow(2) {
            return None;
        }
        let (mut lo, mut hi) = (0u128, 32768u128);
        while hi - lo > 1 {
            let middle = (lo + hi) / 2;
            if d * middle * middle <= n {
                lo = middle;
            } else {
                hi = middle;
            }
        }
        let threshold = d * (2 * lo + 1).pow(2);
        let y = lo + u128::from(4 * n > threshold || (4 * n == threshold && lo & 1 == 1));
        Some(if p < 0 { -(y as i64) } else { y as i64 })
    }

    #[test]
    fn c71_b12_rms_public_circuit_matches_integer_predicate_and_boolean_reference() {
        for (columns, ex, ew, ey, weighted, coefficients, gates, depth, rows) in [
            (5376, 0, 0, 0, true, [84000000, 84, 15625], 46712, 98, 86168),
            (256, 0, 0, 0, false, [4000000, 4, 15625], 39971, 97, 72714),
            (3, 0, 0, 0, true, [3000000, 3, 1000000], 46949, 93, 82367),
            (256, 0, 0, 4, true, [15625, 4, 15625], 45890, 98, 83073),
            (512, -2, 0, -1, false, [32000000, 128, 15625], 39945, 97, 72492),
        ] {
            let circuit = compile(columns, ex, ew, ey, weighted).unwrap();
            assert_eq!((circuit.raw_gates, circuit.levels.len()), (gates, depth));
            assert_eq!(circuit.coefficients, coefficients);
            assert_eq!(circuit.levels.iter().map(Vec::len).sum::<usize>(), rows);
            assert_eq!(circuit.valid, 0);
            assert_eq!(circuit.levels.last().unwrap().len(), 1);
            assert!(circuit.arithmetic_bits <= 128);
            let limit = if weighted { 32767i64.pow(2) } else { 32767 };
            let mut cases = Vec::new();
            for (p, s) in [
                (0, 0),
                (1, 0),
                (-1, 0),
                (1, 1),
                (-3, 9),
                (31, 77),
                (limit, columns as i64 * 32767i64.pow(2)),
                (-limit, columns as i64 * 32767i64.pow(2)),
                (limit, 0),
                (0, -1),
                (0, -(1 << 47)),
                (0, (1 << 47) - 1),
                (-(1i64 << (circuit.product_bits - 1)), 0),
            ] {
                let e = expected(p, s, columns, weighted, circuit.coefficients);
                let y = e.unwrap_or(0);
                cases.push((p, s, y, e.is_some()));
                if y < 32767 {
                    cases.push((p, s, y + 1, false));
                }
                cases.push((p, s, -32768, false));
            }
            assert!(cases.len() < 64);
            let live = (1u64 << cases.len()) - 1;
            let mut planes = vec![0u64; circuit.ports];
            planes[1] = live;
            for (cell, &(p, s, y, _)) in cases.iter().enumerate() {
                let mut offset = 2;
                for (v, bits) in [(p, circuit.product_bits), (s, 48), (y, 16)] {
                    let biased = (v + (1i64 << (bits - 1))) as u64;
                    for bit in 0..bits {
                        planes[offset + bit] |= ((biased >> bit) & 1) << cell;
                    }
                    offset += bits;
                }
            }
            let trace = circuit.replay(&planes, live).unwrap();
            let valid = trace.last().unwrap()[circuit.valid];
            for (cell, &(p, s, y, expected)) in cases.iter().enumerate() {
                assert_eq!(
                    valid >> cell & 1,
                    u64::from(expected),
                    "RMS({p},{s})={y}, columns {columns}"
                );
            }
            assert!(trace.iter().flatten().all(|&v| v & !live == 0));
            planes[0] = 1;
            assert!(circuit.replay(&planes, live).is_err());
        }
        for (columns, ex, ew, ey, weighted) in [
            (0, 0, 0, 0, true),
            (5377, 0, 0, 0, true),
            (256, 0, 1, 0, false),
            (256, 0, 96, 0, true),
            (256, i32::MAX, 0, i32::MIN, true),
            (256, i32::MIN, i32::MAX, 0, true),
        ] {
            assert!(compile(columns, ex, ew, ey, weighted).is_err());
        }
    }
}

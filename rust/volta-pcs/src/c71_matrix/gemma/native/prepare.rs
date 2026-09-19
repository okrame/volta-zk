//! Private preparation has no FS, DV key, correlation iterator or PCS seed input.
use super::*;

pub(super) struct Installed {
    packed: Vec<i16>,
    pub(super) model: Model,
}

impl Installed {
    #[cfg(test)]
    pub(super) fn corrupt_weight(&mut self, index: usize, value: i16) {
        self.packed[index] = value;
    }

    pub(super) fn new(p: &Profile, packed: Vec<i16>) -> Result<Self, String> {
        Self::new_with_source(p, packed, |values| Model::new_in(DOMAIN_W, values))
    }

    pub(super) fn new_with_source(
        p: &Profile,
        packed: Vec<i16>,
        build: impl FnOnce(Vec<i16>) -> Result<Model, String>,
    ) -> Result<Self, String> {
        if packed.len() != p.plan.live || packed.iter().any(|&x| x == i16::MIN) {
            return Err("private W layout or symmetric range differs".into());
        }
        let values = (0..p.plan.live)
            .map(|i| p.plan.virtual_to_packed(i).map(|j| j.map_or(0, |j| packed[j])))
            .collect::<Result<_, _>>()?;
        Ok(Self { packed, model: build(values)? })
    }

    #[cfg(test)]
    pub(super) fn source_view(&self, root: C61Commitment) -> Self {
        Self {
            packed: self.packed.clone(),
            model: Model {
                domain: DOMAIN_W,
                weights: self.model.weights.clone(),
                root,
                seed: [0; 32],
                salt_seed: [0; 32],
                retained: None,
            },
        }
    }
    pub(super) fn weight(&self, p: &Profile, id: usize, row: usize, col: usize) -> i64 {
        let s = &p.plan.sources[id];
        i64::from(self.packed[s.packed_offset + row * s.cols + col])
    }
}

pub(super) struct Snapshot {
    values: Vec<Vec<i64>>,
    pub(super) tokens: [u32; 2],
    pub(super) source: Model,
    pub(super) model_root: [u8; 32],
}

/// Source-level scalar operations executed directly by `evaluate_row` on a
/// successful row. These are not machine instructions: loop/index arithmetic,
/// iterator control, allocation, and helper internals are excluded. Calls into
/// RMS/RNE/affine/divide helpers stay explicit instead of becoming zero work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct RowWork {
    pub integer_additions: usize,
    pub integer_subtractions: usize,
    pub integer_multiplications: usize,
    pub integer_comparisons: usize,
    /// Direct evaluator arithmetic is integer-only; GKR/helper field work is excluded.
    pub fp_additions: usize,
    pub fp_multiplications: usize,
    pub table_reads: usize,
    pub divide_calls: usize,
    pub opaque_rms_calls: usize,
    pub opaque_rne_calls: usize,
    pub opaque_affine_calls: usize,
    pub result_logical_bytes: usize,
    pub result_capacity_bytes: usize,
    pub caller_transient_logical_bytes_upper: usize,
}

impl RowWork {
    pub fn add_assign(&mut self, rhs: Self) {
        self.integer_additions += rhs.integer_additions;
        self.integer_subtractions += rhs.integer_subtractions;
        self.integer_multiplications += rhs.integer_multiplications;
        self.integer_comparisons += rhs.integer_comparisons;
        self.fp_additions += rhs.fp_additions;
        self.fp_multiplications += rhs.fp_multiplications;
        self.table_reads += rhs.table_reads;
        self.divide_calls += rhs.divide_calls;
        self.opaque_rms_calls += rhs.opaque_rms_calls;
        self.opaque_rne_calls += rhs.opaque_rne_calls;
        self.opaque_affine_calls += rhs.opaque_affine_calls;
        self.result_logical_bytes += rhs.result_logical_bytes;
        self.result_capacity_bytes += rhs.result_capacity_bytes;
        self.caller_transient_logical_bytes_upper =
            self.caller_transient_logical_bytes_upper.max(rhs.caller_transient_logical_bytes_upper);
    }

    pub fn arithmetic_complete(self) -> bool {
        self.opaque_rms_calls == 0
            && self.opaque_rne_calls == 0
            && self.opaque_affine_calls == 0
            && self.divide_calls == 0
    }
}

fn account_row_work(p: &Profile, step: &Step, row: usize, result: &[(usize, Vec<i64>)]) -> RowWork {
    let sources = &p.bytes().scalar.layout.sources;
    let mut work = RowWork {
        result_logical_bytes: result.iter().map(|(_, values)| values.len() * 8).sum(),
        result_capacity_bytes: result.iter().map(|(_, values)| values.capacity() * 8).sum(),
        ..RowWork::default()
    };
    match step {
        Step::Embedding => {}
        Step::Matrix(i) => {
            let columns = result[0].1.len();
            let inner = sources[p.bytes().scalar.input_sources[i - 1]].cols;
            work.integer_multiplications = columns * inner;
            work.integer_additions = columns * inner;
        }
        Step::Norm(i) => {
            let norm = &p.rms.norms[*i];
            work.opaque_rms_calls = 1;
            work.caller_transient_logical_bytes_upper =
                8 * norm.columns * norm.heads + norm.cohort.map_or(0, |_| 2 * norm.columns);
        }
        Step::Rne(pair) => {
            work.opaque_rne_calls = 1;
            work.caller_transient_logical_bytes_upper = 8 * sources[pair.raw].cols;
        }
        Step::Affine(i) => {
            let relation = &p.affine[*i];
            work.opaque_affine_calls = 1;
            work.caller_transient_logical_bytes_upper =
                8 * relation.inputs.iter().map(|(id, _)| sources[*id].cols).sum::<usize>();
        }
        Step::Gelu | Step::Softcap => {
            let columns = result.first().map_or(0, |(_, values)| values.len());
            work.integer_subtractions = columns;
            work.integer_comparisons = 2 * columns;
            work.table_reads = columns;
        }
        Step::Gate => work.integer_multiplications = result[0].1.len(),
        Step::Rope(_) => {
            work.integer_multiplications = 4;
            work.integer_additions = 1;
            work.integer_subtractions = 1;
        }
        Step::Qk => {
            let live = p.old + row + 1;
            work.integer_multiplications = 2 * live;
            work.integer_additions = 2 * live;
            work.integer_comparisons = p.old + 2;
        }
        Step::Softmax => {
            let width = p.old + 2;
            let live = p.old + row + 1;
            work.integer_additions = live;
            work.integer_subtractions = live + width;
            work.integer_multiplications = live;
            // max comparisons; the two public `j < live` branches; checked
            // signed conversion and table bounds for every exponential.
            work.integer_comparisons = live.saturating_sub(1) + 4 * width;
            work.table_reads = width;
            work.divide_calls = live;
            work.caller_transient_logical_bytes_upper = 3 * width * 8;
        }
        Step::Pv => {
            let live = p.old + row + 1;
            work.integer_multiplications = 2 * live;
            work.integer_additions = 2 * live;
        }
        Step::Argmax => {
            work.integer_subtractions = 6;
            work.integer_comparisons = 3;
        }
    }
    // The common output validation performs two signed bound comparisons.
    work.integer_comparisons += 2 * result.iter().map(|(_, values)| values.len()).sum::<usize>();
    work
}

/// Same integer producer used by dense preparation and bounded replay.
/// Inputs are private values fixed before FS; no MAC/PCS/coin input exists.
pub(super) fn evaluate_row(
    p: &Profile,
    weight: impl Fn(usize, usize, usize) -> i64,
    step: &Step,
    row: usize,
    tokens: &mut [u32; 2],
    get: impl Fn(usize, usize, usize) -> i64,
    tail: impl Fn(usize, usize, usize) -> i64,
) -> Result<Vec<(usize, Vec<i64>)>, String> {
    evaluate_row_counted(p, weight, step, row, tokens, get, tail, &mut RowWork::default())
}

pub(super) fn evaluate_row_counted(
    p: &Profile,
    weight: impl Fn(usize, usize, usize) -> i64,
    step: &Step,
    row: usize,
    tokens: &mut [u32; 2],
    get: impl Fn(usize, usize, usize) -> i64,
    tail: impl Fn(usize, usize, usize) -> i64,
    work: &mut RowWork,
) -> Result<Vec<(usize, Vec<i64>)>, String> {
    let stop = || "private preparation Stop".to_string();
    let sources = &p.bytes().scalar.layout.sources;
    let mut result: Vec<(usize, Vec<i64>)> = Vec::new();
    match step {
        Step::Embedding => {
            result.push((0, (0..2).map(|c| weight(0, tokens[row] as usize, c)).collect()))
        }
        Step::Matrix(i) => {
            let cohort = &p.plan.cohorts[*i];
            let input = p.bytes().scalar.input_sources[i - 1];
            result.push((
                *i,
                (0..2)
                    .map(|c| (0..2).map(|j| get(input, row, j) * weight(cohort.tensor, c, j)).sum())
                    .collect(),
            ));
        }
        Step::Norm(i) => {
            let n = &p.rms.norms[*i];
            let x: Vec<_> = (0..n.columns * n.heads).map(|c| get(n.input, row, c)).collect();
            let weights: Option<Vec<_>> = n.cohort.map(|i| {
                (0..n.columns).map(|c| weight(p.plan.cohorts[i].tensor, 0, c) as i16).collect()
            });
            let (s, products, y) =
                n.prepare_row([0; 3], &x, weights.as_deref()).map_err(|_| stop())?;
            if let Some(i) = n.cohort {
                result.push((i, products));
            }
            result.extend([(n.statistic, s), (n.output, y)]);
        }
        Step::Rne(pair) => {
            let raw: Vec<_> = (0..sources[pair.raw].cols).map(|c| get(pair.raw, row, c)).collect();
            let y = p.bytes().prepare_rne_row(&p.plan, pair, &raw).map_err(|_| stop())?;
            result.push((pair.output, y));
        }
        Step::Affine(i) => {
            let r = &p.affine[*i];
            let input: [Vec<_>; 2] = std::array::from_fn(|i| {
                let id = r.inputs[i].0;
                (0..sources[id].cols).map(|c| get(id, row, c)).collect()
            });
            let raw =
                p.bytes().prepare_affine_row(r, [&input[0], &input[1]]).map_err(|_| stop())?;
            result.push((r.raw, raw));
        }
        Step::Gelu | Step::Softcap => {
            let (o, table) = if matches!(step, Step::Gelu) {
                (&p.gelu, GELU.as_slice())
            } else {
                (&p.output, SOFTCAP.as_slice())
            };
            let y = (0..2)
                .map(|c| {
                    let x = get(o.input, row, c) - i64::from(o.lower);
                    usize::try_from(x)
                        .ok()
                        .and_then(|i| table.get(i))
                        .copied()
                        .map(i64::from)
                        .ok_or_else(stop)
                })
                .collect::<Result<Vec<_>, _>>()?;
            result.push((o.output, y));
        }
        Step::Gate => result.push((
            p.gate[0],
            (0..2).map(|c| get(p.gate[2], row, c) * get(p.gate[3], row, c)).collect(),
        )),
        Step::Rope(i) => {
            let [raw, _, input] = p.rotations[*i];
            let [cos, sin] = Q30[p.old + row].map(i64::from);
            let (x, y) = (get(input, row, 0), get(input, row, 1));
            result.push((raw, vec![cos * x - sin * y, sin * x + cos * y]));
        }
        Step::Qk => {
            let q = p.rotations[0][1];
            let k = p.rotations[1][1];
            result.push((
                p.attention[0],
                (0..p.old + 2)
                    .map(|j| {
                        if j <= p.old + row {
                            (0..2).map(|c| get(q, row, c) * tail(k, j, c)).sum()
                        } else {
                            0
                        }
                    })
                    .collect(),
            ));
        }
        Step::Softmax => {
            let s = &p.softmax.layers[0];
            let live = p.old + row + 1;
            let maximum = (0..live).map(|j| get(s.score, row, j)).max().unwrap();
            let differences = (0..p.old + 2)
                .map(|j| if j < live { maximum - get(s.score, row, j) } else { 0 })
                .collect::<Vec<_>>();
            let e = differences
                .iter()
                .map(|&d| {
                    usize::try_from(d)
                        .ok()
                        .and_then(|d| EXP30.get(d))
                        .map(|&e| i64::from(e))
                        .ok_or_else(stop)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let z: i64 = e[..live].iter().sum();
            let pi = e
                .iter()
                .enumerate()
                .map(|(j, &e)| {
                    if j < live {
                        kernel::rne::divide(16384 * e, z).map(i64::from)
                    } else {
                        Ok(0)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| stop())?;
            result.extend([
                (s.maximum, vec![maximum]),
                (s.difference, differences.into_iter().map(|d| d - 32767).collect()),
                (s.exponential, e),
                (s.denominator, vec![z]),
                (s.pi, pi),
            ]);
        }
        Step::Pv => {
            let v = p.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output;
            let pi = p.softmax.layers[0].pi;
            result.push((
                p.attention[1],
                (0..2)
                    .map(|c| (0..=p.old + row).map(|j| get(pi, row, j) * tail(v, j, c)).sum())
                    .collect(),
            ));
        }
        Step::Argmax => {
            let y = [get(p.output.output, row, 0), get(p.output.output, row, 1)];
            let token = usize::from(y[1] > y[0]);
            tokens[1] = token as u32;
            result.push((
                p.output.slack,
                (0..2).map(|j| y[token] - y[j] - i64::from(j < token) - 32768).collect(),
            ));
        }
    }
    for (id, words) in &result {
        let bound = 1i64 << (8 * p.bytes().widths[*id] - 1);
        if words.len() != sources[*id].cols || words.iter().any(|&v| v < -bound || v >= bound) {
            return Err(stop());
        }
    }
    work.add_assign(account_row_work(p, step, row, &result));
    Ok(result)
}

impl Snapshot {
    #[cfg(test)]
    pub(super) fn corrupt_value(&mut self, p: &Profile, id: usize, row: usize, col: usize) {
        self.values[id][row * p.bytes().scalar.layout.sources[id].cols + col] += 1;
    }

    pub(super) fn value(&self, p: &Profile, id: usize, row: usize, col: usize) -> i64 {
        let s = &p.bytes().scalar.layout.sources[id];
        if row >= s.rows || col >= s.cols {
            0
        } else {
            self.values[id][row * s.cols + col]
        }
    }
    pub(super) fn byte(&self, p: &Profile, id: usize, row: usize, col: usize, b: usize) -> u8 {
        let s = &p.bytes().scalar.layout.sources[id];
        if row >= s.rows || col >= s.cols {
            return 0;
        }
        (self.value(p, id, row, col) as u64 >> (8 * b)) as u8
            ^ if b + 1 == p.bytes().widths[id] { 128 } else { 0 }
    }
    pub(super) fn word6(&self, p: &Profile, id: usize, row: usize, col: usize) -> [u8; 6] {
        std::array::from_fn(|b| self.byte(p, id, row, col, b))
    }

    /// Computes both tokens in causal order. The second pass absorbs the emitted
    /// token into every layer's K/V; it does not emit another token.
    pub(super) fn prepare(
        p: &Profile,
        w: &Installed,
        old: &[Snapshot],
        prompt: u32,
    ) -> Result<Self, String> {
        Self::prepare_with_source(p, w, old, prompt, |values| Model::new_in(DOMAIN_A, values))
    }

    pub(super) fn prepare_with_source(
        p: &Profile,
        w: &Installed,
        old: &[Snapshot],
        prompt: u32,
        build: impl FnOnce(Vec<i16>) -> Result<Model, String>,
    ) -> Result<Self, String> {
        let stop = || "private preparation Stop".to_string();
        if prompt >= 2
            || old.len() * TOKENS != p.old
            || old.iter().any(|s| s.model_root != w.model.root.roots()[0])
        {
            return Err(stop());
        }
        let sources = &p.bytes().scalar.layout.sources;
        let mut values = sources.iter().map(|s| vec![0i64; s.rows * s.cols]).collect::<Vec<_>>();
        let mut tokens = [prompt, 0];
        let get = |v: &[Vec<i64>], id: usize, r: usize, c: usize| v[id][r * sources[id].cols + c];
        let tail = |v: &[Vec<i64>], id: usize, t: usize, c: usize| {
            if t < p.old {
                old[t / TOKENS].values[id][(t % TOKENS) * sources[id].cols + c]
            } else {
                get(v, id, t - p.old, c)
            }
        };
        for row in 0..TOKENS {
            for step in &p.steps {
                let outputs = p.outputs(step);
                let out = outputs[0];
                // Histogram sources are completed after all private rows exist.
                if row >= sources[out].rows {
                    continue;
                }
                let result = evaluate_row(
                    p,
                    |id, r, c| w.weight(p, id, r, c),
                    step,
                    row,
                    &mut tokens,
                    |id, r, c| get(&values, id, r, c),
                    |id, r, c| tail(&values, id, r, c),
                )?;
                for (id, words) in result {
                    values[id][row * words.len()..(row + 1) * words.len()].copy_from_slice(&words);
                }
            }
        }
        for o in [&p.gelu, &p.output] {
            for i in 0..values[o.input].len() {
                let index =
                    usize::try_from(values[o.input][i] - i64::from(o.lower)).map_err(|_| stop())?;
                values[o.histogram][index] += 1;
            }
        }
        let sm = &p.softmax.layers[0];
        for i in 0..values[sm.difference].len() {
            let index = (values[sm.difference][i] + 32767) as usize;
            values[sm.histogram][index] += 1;
        }
        let packed = values
            .iter()
            .enumerate()
            .flat_map(|(id, v)| {
                v.iter().flat_map(move |x| x.to_le_bytes()[..p.bytes().widths[id]].to_vec())
            })
            .collect::<Vec<_>>();
        let encoded = (0..p.bytes().live)
            .map(|i| {
                p.bytes()
                    .virtual_to_packed(i)
                    .map(|a| a.map_or(0, |(j, x)| i16::from(packed[j] ^ x)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // C_A and its independent random coins exist only after every private check.
        Ok(Self { values, tokens, source: build(encoded)?, model_root: w.model.root.roots()[0] })
    }

    pub(super) fn compact(
        &self,
        p: &Profile,
        w: &Installed,
        points: &[Vec<Fp3>],
    ) -> Result<Vec<caller::Compact>, String> {
        compact(p, w, points, |id, r, c| self.value(p, id, r, c))
    }
}

pub(super) fn compact(
    p: &Profile,
    w: &Installed,
    points: &[Vec<Fp3>],
    value: impl Fn(usize, usize, usize) -> i64,
) -> Result<Vec<caller::Compact>, String> {
    p.plan
        .cohorts
        .iter()
        .enumerate()
        .zip(points)
        .map(|((i, c), point)| {
            let (r, s) = point.split_at(bits(c.rows));
            let (er, es) = (eq(r), eq(s));
            let output = (0..c.rows)
                .map(|r| {
                    (0..c.columns)
                        .map(|s| er[r] * es[s] * signed(value(i, r, s)))
                        .fold(Fp3::ZERO, |a, b| a + b)
                })
                .fold(Fp3::ZERO, |a, b| a + b);
            if c.kind == Kind::Lookup {
                return Ok(caller::Compact { output, x: Vec::new(), w: Vec::new() });
            }
            let route = p.plan.input_route(i)?;
            let input = p.bytes().scalar.input_sources[i - 1];
            let x = (0..2)
                .map(|j| {
                    (0..c.rows)
                        .map(|r| er[r] * signed(value(input, r + route.row_offset, j)))
                        .fold(Fp3::ZERO, |a, b| a + b)
                })
                .collect();
            let weights = (0..2)
                .map(|j| {
                    if c.kind == Kind::Norm {
                        signed(w.weight(p, c.tensor, 0, j))
                    } else {
                        (0..2)
                            .map(|s| es[s] * signed(w.weight(p, c.tensor, s, j)))
                            .fold(Fp3::ZERO, |a, b| a + b)
                    }
                })
                .collect();
            Ok(caller::Compact { output, x, w: weights })
        })
        .collect()
}

#[cfg(test)]
mod work_tests {
    use super::*;

    fn result_shape(p: &Profile, step: &Step) -> Vec<(usize, Vec<i64>)> {
        p.outputs(step)
            .into_iter()
            .map(|id| (id, vec![0; p.bytes().scalar.layout.sources[id].cols]))
            .collect()
    }

    #[test]
    fn c71_row_work_counts_source_level_shapes_and_helper_gaps() {
        let p = Profile::small(0).unwrap();
        let matrix = p.steps.iter().find(|step| matches!(step, Step::Matrix(_))).unwrap();
        let matrix_work = account_row_work(&p, matrix, 0, &result_shape(&p, matrix));
        assert_eq!(matrix_work.integer_multiplications, 4);
        assert_eq!(matrix_work.integer_additions, 4);
        assert_eq!(matrix_work.integer_comparisons, 4);
        assert!(matrix_work.arithmetic_complete());

        let rope = p.steps.iter().find(|step| matches!(step, Step::Rope(_))).unwrap();
        let rope_work = account_row_work(&p, rope, 0, &result_shape(&p, rope));
        assert_eq!(rope_work.integer_multiplications, 4);
        assert_eq!(rope_work.integer_additions, 1);
        assert_eq!(rope_work.integer_subtractions, 1);

        let softmax = p.steps.iter().find(|step| matches!(step, Step::Softmax)).unwrap();
        let s = &p.softmax.layers[0];
        let softmax_result = [s.maximum, s.difference, s.exponential, s.denominator, s.pi]
            .map(|id| (id, vec![0; p.bytes().scalar.layout.sources[id].cols]))
            .into_iter()
            .collect::<Vec<_>>();
        let softmax_work = account_row_work(&p, softmax, 1, &softmax_result);
        assert_eq!(softmax_work.integer_multiplications, 2); // 16384 * e for two live cells.
        assert_eq!(softmax_work.integer_additions, 2);
        assert_eq!(softmax_work.integer_subtractions, 4);
        assert_eq!(softmax_work.integer_comparisons, 25);
        assert_eq!(softmax_work.table_reads, 2);
        assert_eq!(softmax_work.divide_calls, 2);
        assert!(!softmax_work.arithmetic_complete());

        let rne = p.steps.iter().find(|step| matches!(step, Step::Rne(_))).unwrap();
        let Step::Rne(pair) = rne else { unreachable!() };
        let rne_result =
            vec![(pair.output, vec![0; p.bytes().scalar.layout.sources[pair.output].cols])];
        let rne_work = account_row_work(&p, rne, 0, &rne_result);
        assert_eq!(rne_work.opaque_rne_calls, 1);
        assert!(!rne_work.arithmetic_complete());
        assert_eq!(matrix_work.fp_additions + matrix_work.fp_multiplications, 0);
    }
}

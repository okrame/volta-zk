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
        if packed.len() != p.plan.live || packed.iter().any(|&x| x == i16::MIN) {
            return Err("private W layout or symmetric range differs".into());
        }
        let values = (0..p.plan.live)
            .map(|i| p.plan.virtual_to_packed(i).map(|j| j.map_or(0, |j| packed[j])))
            .collect::<Result<_, _>>()?;
        Ok(Self { packed, model: Model::new_in(DOMAIN_W, values)? })
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

pub(super) fn rne(n: i128, d: i128) -> i64 {
    let q = n.div_euclid(d);
    let r = n.rem_euclid(d);
    (q + i128::from(2 * r > d || (2 * r == d && q & 1 != 0))) as i64
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
                let mut result: Vec<(usize, Vec<i64>)> = Vec::new();
                match step {
                    Step::Embedding => result.push((
                        0,
                        (0..2).map(|c| w.weight(p, 0, tokens[row] as usize, c)).collect(),
                    )),
                    Step::Matrix(i) => {
                        let cohort = &p.plan.cohorts[*i];
                        let input = p.bytes().scalar.input_sources[i - 1];
                        result.push((
                            *i,
                            (0..2)
                                .map(|c| {
                                    (0..2)
                                        .map(|j| {
                                            get(&values, input, row, j)
                                                * w.weight(p, cohort.tensor, c, j)
                                        })
                                        .sum()
                                })
                                .collect(),
                        ));
                    }
                    Step::Norm(i) => {
                        let n = &p.rms.norms[*i];
                        let x: Vec<_> = (0..n.columns * n.heads)
                            .map(|c| get(&values, n.input, row, c))
                            .collect();
                        let weights: Option<Vec<_>> = n.cohort.map(|i| {
                            (0..n.columns)
                                .map(|c| w.weight(p, p.plan.cohorts[i].tensor, 0, c) as i16)
                                .collect()
                        });
                        let (s, products, y) =
                            n.prepare_row([0; 3], &x, weights.as_deref()).map_err(|_| stop())?;
                        if let Some(i) = n.cohort {
                            result.push((i, products));
                        }
                        result.extend([(n.statistic, s), (n.output, y)]);
                    }
                    Step::Rne(pair) => {
                        let y = (0..sources[pair.raw].cols)
                            .map(|c| {
                                rne(i128::from(get(&values, pair.raw, row, c)), 1i128 << pair.shift)
                            })
                            .collect::<Vec<_>>();
                        if y.iter().any(|x| !(-32767..=32767).contains(x)) {
                            return Err(stop());
                        }
                        result.push((pair.output, y));
                    }
                    Step::Affine(i) => {
                        let r = &p.affine[*i];
                        result.push((
                            r.raw,
                            (0..2)
                                .map(|c| {
                                    r.inputs
                                        .iter()
                                        .map(|&(id, k)| k * get(&values, id, row, c))
                                        .sum()
                                })
                                .collect(),
                        ));
                    }
                    Step::Gelu | Step::Softcap => {
                        let (o, table) = if matches!(step, Step::Gelu) {
                            (&p.gelu, GELU.as_slice())
                        } else {
                            (&p.output, SOFTCAP.as_slice())
                        };
                        let y = (0..2)
                            .map(|c| {
                                let x = get(&values, o.input, row, c) - i64::from(o.lower);
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
                        (0..2)
                            .map(|c| {
                                get(&values, p.gate[2], row, c) * get(&values, p.gate[3], row, c)
                            })
                            .collect(),
                    )),
                    Step::Rope(i) => {
                        let [raw, _, input] = p.rotations[*i];
                        let [cos, sin] = Q30[p.old + row].map(i64::from);
                        let (x, y) = (get(&values, input, row, 0), get(&values, input, row, 1));
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
                                        (0..2)
                                            .map(|c| {
                                                get(&values, q, row, c) * tail(&values, k, j, c)
                                            })
                                            .sum()
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
                        let maximum =
                            (0..live).map(|j| get(&values, s.score, row, j)).max().unwrap();
                        let differences =
                            (0..p.old + 2)
                                .map(|j| {
                                    if j < live {
                                        maximum - get(&values, s.score, row, j)
                                    } else {
                                        0
                                    }
                                })
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
                                    rne(16384 * i128::from(e), i128::from(z))
                                } else {
                                    0
                                }
                            })
                            .collect();
                        result.extend([
                            (s.maximum, vec![maximum]),
                            (s.difference, differences.into_iter().map(|d| d - 32767).collect()),
                            (s.exponential, e),
                            (s.denominator, vec![z]),
                            (s.pi, pi),
                        ]);
                    }
                    Step::Pv => {
                        let v =
                            p.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output;
                        let pi = p.softmax.layers[0].pi;
                        result.push((
                            p.attention[1],
                            (0..2)
                                .map(|c| {
                                    (0..=p.old + row)
                                        .map(|j| get(&values, pi, row, j) * tail(&values, v, j, c))
                                        .sum()
                                })
                                .collect(),
                        ));
                    }
                    Step::Argmax => {
                        let y = [
                            get(&values, p.output.output, row, 0),
                            get(&values, p.output.output, row, 1),
                        ];
                        let token = usize::from(y[1] > y[0]);
                        tokens[1] = token as u32;
                        result.push((
                            p.output.slack,
                            (0..2)
                                .map(|j| y[token] - y[j] - i64::from(j < token) - 32768)
                                .collect(),
                        ));
                    }
                }
                for (id, words) in result {
                    let width = p.bytes().widths[id];
                    let bound = 1i64 << (8 * width - 1);
                    if words.len() != sources[id].cols
                        || words.iter().any(|&v| v < -bound || v >= bound)
                    {
                        return Err(stop());
                    }
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
        Ok(Self {
            values,
            tokens,
            source: Model::new_in(DOMAIN_A, encoded)?,
            model_root: w.model.root.roots()[0],
        })
    }

    pub(super) fn compact(
        &self,
        p: &Profile,
        w: &Installed,
        points: &[Vec<Fp3>],
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
                            .map(|s| er[r] * es[s] * signed(self.value(p, i, r, s)))
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
                            .map(|r| er[r] * signed(self.value(p, input, r + route.row_offset, j)))
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
}

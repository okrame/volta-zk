//! R2 degree-seven RNE, with public byte functions linked by P/S to the
//! original byte source. No independent indicator or output authentication.

use super::*;

component_wire!(Proof { rounds, terminal, tag, products, functions });

struct Function {
    lane: usize,
    table: [Fp3; 256],
}

struct Term {
    coefficient: Fp3,
    factors: Vec<usize>,
}

struct Recipe {
    functions: Vec<Function>,
    polynomials: [Vec<Term>; 2], // rounded signed value, symmetric-i16 validity
}

impl Recipe {
    fn function(&mut self, lane: usize, f: impl Fn(usize) -> i64) -> usize {
        let table = std::array::from_fn(|j| signed(f(j)));
        if let Some(i) = self.functions.iter().position(|v| v.lane == lane && v.table == table) {
            return i;
        }
        self.functions.push(Function { lane, table });
        self.functions.len() - 1
    }

    fn less_than(&mut self, bound: i64) -> Vec<Term> {
        if bound <= 0 {
            return Vec::new();
        }
        if bound >= 1 << 48 {
            return vec![Term { coefficient: Fp3::ONE, factors: Vec::new() }];
        }
        let mut result: Vec<Term> = Vec::new();
        for lane in 0..6 {
            let digit = ((bound >> (8 * lane)) & 255) as usize;
            let equal = self.function(lane, |j| i64::from(j == digit));
            for term in &mut result {
                term.factors.push(equal);
            }
            let below = self.function(lane, |j| i64::from(j < digit));
            result.push(Term { coefficient: Fp3::ONE, factors: vec![below] });
        }
        result
    }

    // Literal low-degree identities from rne48_indicator_polynomials. Keep
    // only the public byte functions actually used by this public shift;
    // their MLEs, not functions of folded bytes, are the terminal witnesses.
    fn new(shift: i32) -> Self {
        let mut r = Self { functions: Vec::new(), polynomials: [Vec::new(), Vec::new()] };
        if shift >= 48 {
            r.polynomials[1].push(Term { coefficient: Fp3::ONE, factors: Vec::new() });
            return r;
        }
        if shift <= -15 {
            let factors = (0..6)
                .map(|lane| r.function(lane, |j| i64::from(j == if lane == 5 { 128 } else { 0 })))
                .collect();
            r.polynomials[1].push(Term { coefficient: Fp3::ONE, factors });
            return r;
        }
        let mut rounded = Vec::new();
        let bound;
        if shift <= 0 {
            for lane in 0..6 {
                let f = r.function(lane, |j| j as i64);
                rounded.push(Term {
                    coefficient: signed(1i64 << (8 * lane as i32 - shift)),
                    factors: vec![f],
                });
            }
            rounded.push(Term { coefficient: -signed(1i64 << (47 - shift)), factors: Vec::new() });
            bound = 32767 >> -shift;
        } else {
            let (lane, bit) = (shift as usize / 8, shift as usize % 8);
            let f = r.function(lane, |j| (j >> bit) as i64);
            rounded.push(Term { coefficient: Fp3::ONE, factors: vec![f] });
            for j in lane + 1..6 {
                let f = r.function(j, |v| v as i64);
                rounded.push(Term {
                    coefficient: signed(1i64 << (8 * j as i32 - shift)),
                    factors: vec![f],
                });
            }
            rounded.push(Term { coefficient: -signed(1i64 << (47 - shift)), factors: Vec::new() });
            let (half_lane, half_bit) = ((shift as usize - 1) / 8, (shift as usize - 1) % 8);
            let half = r.function(half_lane, |j| ((j >> half_bit) & 1) as i64);
            rounded.push(Term { coefficient: Fp3::ONE, factors: vec![half] });
            let mut factors: Vec<_> =
                (0..half_lane).map(|l| r.function(l, |j| i64::from(j == 0))).collect();
            if half_bit < 7 {
                let suppress = r.function(half_lane, |j| {
                    (((j >> half_bit) & 1)
                        * usize::from(j % (1 << half_bit) == 0)
                        * (1 - (((j >> (half_bit + 1)) & 1) ^ usize::from(shift == 47))))
                        as i64
                });
                factors.push(suppress);
                rounded.push(Term { coefficient: -Fp3::ONE, factors });
            } else {
                let half = r.function(half_lane, |j| i64::from(j == 128));
                factors.push(half);
                rounded.push(Term { coefficient: -Fp3::ONE, factors: factors.clone() });
                let parity = r.function(half_lane + 1, |j| (j & 1) as i64);
                factors.push(parity);
                rounded.push(Term { coefficient: Fp3::ONE, factors });
            }
            bound = 65535 * (1i64 << (shift - 1)) - 1;
        }
        let mut valid = r.less_than((1 << 47) + bound + 1);
        valid.extend(
            r.less_than((1 << 47) - bound)
                .into_iter()
                .map(|t| Term { coefficient: -t.coefficient, factors: t.factors }),
        );
        r.polynomials = [rounded, valid];
        r
    }

    fn evaluate(&self, values: &[Fp3]) -> [Fp3; 2] {
        std::array::from_fn(|i| {
            self.polynomials[i].iter().fold(Fp3::ZERO, |v, t| {
                v + t.factors.iter().fold(t.coefficient, |v, &f| v * values[f])
            })
        })
    }

    fn products(&self) -> usize {
        self.polynomials.iter().flatten().map(|t| t.factors.len().saturating_sub(1)).sum()
    }
}

pub(super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub output_point: &'a [Fp3],
    pub shape: [usize; 2], // live rows/columns; each axis padded independently
    pub shift: i32,
}

impl Statement<'_> {
    fn live(&self, i: usize) -> bool {
        let columns = self.shape[1].next_power_of_two();
        i / columns < self.shape[0] && i % columns < self.shape[1]
    }
}

pub(super) struct Proof {
    rounds: Vec<[Fp3; 9]>, // g(0),...,g(7) corrections, zero tag for g(0)+g(1)
    terminal: Vec<Fp3>,    // original byte-function claims, then product results
    tag: Fp3,
    products: [Fp3; 2],
    functions: byte_function::Proof,
}

pub(super) fn required(cell_bits: usize, shift: i32) -> usize {
    let recipe = Recipe::new(shift);
    8 * cell_bits
        + recipe.functions.len()
        + recipe.products()
        + 1
        + byte_function::required(cell_bits + 3)
}

fn bind(s: &Statement<'_>, fs: &mut Fs) -> Result<(Vec<Fp3>, Fp3), String> {
    if s.output_point.len() > 31
        || s.shape.iter().any(|&n| n == 0 || n > 1 << 18)
        || s.shape.iter().map(|&n| n.next_power_of_two().ilog2() as usize).sum::<usize>()
            != s.output_point.len()
        || s.root.num_roots() != 1
        || s.profile.is_empty()
        || s.view == [0; 32]
        || !s.attempt.valid()
    {
        return Err("B12 RNE statement mismatch".into());
    }
    let mut bytes =
        b"C71-RNE-B12-v2;i48-to-symmetric-i16;row-col-MSB;R2-degree7;original-output-MAC".to_vec();
    bytes.extend(s.root.roots()[0]);
    bytes.extend((s.profile.len() as u64).to_le_bytes());
    bytes.extend(s.profile);
    bytes.extend(s.view);
    bytes.extend(s.attempt.encode());
    bytes.extend((s.output_point.len() as u32).to_le_bytes());
    for &n in &s.shape {
        bytes.extend((n as u64).to_le_bytes());
    }
    bytes.extend(s.shift.to_le_bytes());
    for &r in s.output_point {
        bytes.extend(r.to_bytes());
    }
    fs.set_phase(0x900);
    fs.record(0x70, &bytes);
    Ok(((0..s.output_point.len()).map(|_| fs.fp3()).collect(), fs.fp3()))
}

fn interpolation(point: Fp3) -> [Fp3; 8] {
    std::array::from_fn(|i| {
        (0..8).filter(|&j| j != i).fold(Fp3::ONE, |v, j| {
            v * (point - signed(j as i64)) * signed(i as i64 - j as i64).inv()
        })
    })
}

fn function_tables(recipe: &Recipe, beta: Fp3) -> (Vec<[Fp3; 256]>, Vec<Fp3>) {
    let mut tables = vec![[Fp3::ZERO; 256]; 8];
    let mut powers = Vec::new();
    let mut power = Fp3::ONE;
    for function in &recipe.functions {
        for (v, &f) in tables[function.lane].iter_mut().zip(&function.table) {
            *v += power * f;
        }
        powers.push(power);
        power = power * beta;
    }
    (tables, powers)
}

// Output correction is already bound by the caller. The byte view has eight
// lanes: the six biased i48 bytes followed by two public zeros, and all-zero
// bytes on dummy cells on either axis. The returned byte obligation still needs the SAME PCS.
pub(super) fn prove(
    s: &Statement<'_>,
    mut target: Auth,
    get_bytes: impl Fn(usize) -> [u8; 6],
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Vec<Fp3>, Auth), String> {
    let (rho, tau) = bind(s, fs)?;
    let recipe = Recipe::new(s.shift);
    let count = required(s.output_point.len(), s.shift);
    if correlations.len() < count {
        return Err("B12 RNE prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let mut f = eq(s.output_point);
    let mut g = eq(&rho);
    for i in 0..f.len() {
        if !s.live(i) {
            f[i] = Fp3::ZERO;
            g[i] = Fp3::ZERO;
        }
        g[i] = g[i] * tau;
    }
    // ponytail: dense function tables for c<=7, no full Gemma trace. The R2
    // fold-table reader remains necessary before admitting a larger caller.
    let mut functions: Vec<Vec<Fp3>> = recipe
        .functions
        .iter()
        .map(|function| {
            (0..f.len())
                .map(|i| {
                    function.table[if s.live(i) { get_bytes(i)[function.lane] as usize } else { 0 }]
                })
                .collect()
        })
        .collect();
    let (mut point, mut rounds) = (Vec::new(), Vec::new());
    for round in 0..s.output_point.len() {
        let half = f.len() / 2;
        let evaluations: [Fp3; 8] = std::array::from_fn(|j| {
            let r = signed(j as i64);
            (0..half).fold(Fp3::ZERO, |sum, i| {
                let v: Vec<_> = functions.iter().map(|v| v[i] + r * (v[i + half] - v[i])).collect();
                let [y, valid] = recipe.evaluate(&v);
                sum + (f[i] + r * (f[i + half] - f[i])) * y
                    + (g[i] + r * (g[i + half] - g[i])) * (Fp3::ONE - valid)
            })
        });
        let (wire, a) = range::authenticate(evaluations, &mut rows);
        let mut record = [Fp3::ZERO; 9];
        record[..8].copy_from_slice(&wire);
        record[8] = a[0].m + a[1].m - target.m;
        fs.set_phase(0x910 + round as u16);
        record_values(fs, 0x71, &record);
        let r = fs.fp3();
        target = a.iter().zip(interpolation(r)).fold(Auth::ZERO, |v, (&a, c)| v.add(a.scale(c)));
        for v in &mut functions {
            fold(v, r);
        }
        fold(&mut f, r);
        fold(&mut g, r);
        point.push(r);
        rounds.push(record);
    }
    let (mut terminal, original): (Vec<_>, Vec<_>) = functions
        .iter()
        .map(|v| {
            let (wire, a) = range::authenticate([v[0]], &mut rows);
            (wire[0], a[0])
        })
        .unzip();
    let mut triples = Vec::new();
    let evaluated: [Auth; 2] = std::array::from_fn(|i| {
        recipe.polynomials[i].iter().fold(Auth::ZERO, |sum, term| {
            let mut factors = term.factors.iter();
            let mut value = factors.next().map_or(Auth::new(Fp3::ONE, Fp3::ZERO), |&j| original[j]);
            for &j in factors {
                let (wire, a) = range::authenticate([value.x * original[j].x], &mut rows);
                terminal.push(wire[0]);
                triples.push([value, original[j], a[0]]);
                value = a[0];
            }
            sum.add(value.scale(term.coefficient))
        })
    });
    let expected = evaluated[0]
        .scale(f[0])
        .add(Auth::new(Fp3::ONE, Fp3::ZERO).add(evaluated[1].scale(-Fp3::ONE)).scale(g[0]));
    let tag = expected.m - target.m;
    fs.set_phase(0x920);
    record_values(fs, 0x72, &terminal);
    record_values(fs, 0x73, &[tag]);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    let beta = fs.fp3();
    let (tables, powers) = function_tables(&recipe, beta);
    let mut aggregate = [Auth::ZERO; 8];
    for ((function, &a), &power) in recipe.functions.iter().zip(&original).zip(&powers) {
        aggregate[function.lane] = aggregate[function.lane].add(a.scale(power));
    }
    let statement = byte_function::Statement {
        root: s.root,
        profile: s.profile,
        view: s.view,
        attempt: s.attempt,
        cell_point: &point,
        live_cells: 1 << point.len(),
        tables: &tables,
    };
    let (functions, point, original) = byte_function::prove(
        &statement,
        byte_function::Original::Lanes(&aggregate),
        |i| {
            if s.live(i / 8) && i % 8 < 6 {
                get_bytes(i / 8)[i % 8]
            } else {
                0
            }
        },
        fs,
        &mut rows,
    )?;
    debug_assert!(rows.next().is_none());
    Ok((Proof { rounds, terminal, tag, products, functions }, point, original))
}

pub(super) fn verify(
    s: &Statement<'_>,
    mut target: Key,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<(Vec<Fp3>, Key), String> {
    let (rho, tau) = bind(s, fs)?;
    let recipe = Recipe::new(s.shift);
    let count = required(s.output_point.len(), s.shift);
    if proof.rounds.len() != s.output_point.len()
        || proof.terminal.len() != recipe.functions.len() + recipe.products()
        || correlations.len() < count
    {
        return Err("B12 RNE proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let mut point = Vec::new();
    for (round, wire) in proof.rounds.iter().enumerate() {
        let a = range::correct(std::array::from_fn::<_, 8, _>(|i| wire[i]), delta, &mut rows);
        if a[0].k + a[1].k - target.k != wire[8] {
            return Err("B12 RNE sumcheck MAC rejected".into());
        }
        fs.set_phase(0x910 + round as u16);
        record_values(fs, 0x71, wire);
        let r = fs.fp3();
        target = a.iter().zip(interpolation(r)).fold(Key::ZERO, |v, (&a, c)| v.add(a.scale(c)));
        point.push(r);
    }
    let original: Vec<_> = proof.terminal[..recipe.functions.len()]
        .iter()
        .map(|&w| range::correct([w], delta, &mut rows)[0])
        .collect();
    let mut products = proof.terminal[recipe.functions.len()..].iter();
    let mut triples = Vec::new();
    let evaluated: [Key; 2] = std::array::from_fn(|i| {
        recipe.polynomials[i].iter().fold(Key::ZERO, |sum, term| {
            let mut factors = term.factors.iter();
            let mut value = factors.next().map_or(Key::new(delta), |&j| original[j]);
            for &j in factors {
                let a = range::correct([*products.next().unwrap()], delta, &mut rows)[0];
                triples.push([value, original[j], a]);
                value = a;
            }
            sum.add(value.scale(term.coefficient))
        })
    });
    let e = eq(&point);
    let f = eq(s.output_point)
        .iter()
        .zip(&e)
        .enumerate()
        .filter(|(i, _)| s.live(*i))
        .fold(Fp3::ZERO, |v, (_, (&a, &b))| v + a * b);
    let g = tau
        * eq(&rho)
            .iter()
            .zip(&e)
            .enumerate()
            .filter(|(i, _)| s.live(*i))
            .fold(Fp3::ZERO, |v, (_, (&a, &b))| v + a * b);
    let expected =
        evaluated[0].scale(f).add(Key::new(delta).add(evaluated[1].scale(-Fp3::ONE)).scale(g));
    if expected.k - target.k != proof.tag {
        return Err("B12 RNE terminal MAC rejected".into());
    }
    fs.set_phase(0x920);
    record_values(fs, 0x72, &proof.terminal);
    record_values(fs, 0x73, &[proof.tag]);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    let beta = fs.fp3();
    let (tables, powers) = function_tables(&recipe, beta);
    let mut aggregate = [Key::ZERO; 8];
    for ((function, &a), &power) in recipe.functions.iter().zip(&original).zip(&powers) {
        aggregate[function.lane] = aggregate[function.lane].add(a.scale(power));
    }
    let statement = byte_function::Statement {
        root: s.root,
        profile: s.profile,
        view: s.view,
        attempt: s.attempt,
        cell_point: &point,
        live_cells: 1 << point.len(),
        tables: &tables,
    };
    let result = byte_function::verify(
        &statement,
        byte_function::Original::Lanes(&aggregate),
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
    use linear::Cube;
    use rand_010::RngExt;

    fn bytes(value: i64) -> [u8; 6] {
        (value + (1 << 47)).to_le_bytes()[..6].try_into().unwrap()
    }

    fn reference(value: i64, shift: i32) -> Option<i64> {
        let value = i128::from(value);
        let y = if shift >= 48 {
            0
        } else if shift <= -15 {
            if value == 0 {
                0
            } else {
                return None;
            }
        } else if shift <= 0 {
            value << -shift
        } else {
            let d = 1i128 << shift;
            let (q, r) = (value.div_euclid(d), value.rem_euclid(d));
            q + i128::from(2 * r > d || (2 * r == d && q & 1 == 1))
        };
        if (-32767..=32767).contains(&y) {
            Some(y as i64)
        } else {
            None
        }
    }

    #[test]
    fn c71_b12_rne_recipes_cover_all_64_shift_classes_and_degree_seven() {
        let mut maximum = (0, 0);
        for shift in -15..=48 {
            let recipe = Recipe::new(shift);
            maximum.0 = maximum.0.max(recipe.functions.len());
            maximum.1 = maximum.1.max(recipe.products());
            for term in recipe.polynomials.iter().flatten() {
                assert!(term.factors.len() <= 6);
                let mut lanes: Vec<_> =
                    term.factors.iter().map(|&i| recipe.functions[i].lane).collect();
                lanes.sort_unstable();
                lanes.dedup();
                assert_eq!(lanes.len(), term.factors.len());
            }
            let mut cases = vec![
                -(1 << 47),
                (1 << 47) - 1,
                -65537,
                -32768,
                -32767,
                -1,
                0,
                1,
                32767,
                32768,
                65537,
            ];
            if (1..48).contains(&shift) {
                for q in [-32768i64, -32767, -3, -2, -1, 0, 1, 2, 3, 32766, 32767] {
                    for d in [-1, 0, 1] {
                        let v = (i128::from(q) << shift) + (1i128 << (shift - 1)) + d;
                        if (-(1i128 << 47)..1i128 << 47).contains(&v) {
                            cases.push(v as i64);
                        }
                    }
                }
            }
            for value in cases {
                let b = bytes(value);
                let values: Vec<_> =
                    recipe.functions.iter().map(|f| f.table[b[f.lane] as usize]).collect();
                let [y, valid] = recipe.evaluate(&values);
                let expected = reference(value, shift);
                assert_eq!(
                    valid,
                    if expected.is_some() { Fp3::ONE } else { Fp3::ZERO },
                    "validity {value} shift {shift}"
                );
                if let Some(expected) = expected {
                    assert_eq!(y, signed(expected), "RNE {value} shift {shift}");
                }
            }
            // Arbitrary affine function claims, outside the Boolean byte
            // vertices: multiplication by an affine public form has degree 7.
            let mut samples: Vec<_> = (0..9)
                .map(|j| {
                    let t = signed(j);
                    let values: Vec<_> = (0..recipe.functions.len())
                        .map(|i| signed(i as i64 + 3) + t * signed(2 * i as i64 + 1))
                        .collect();
                    let [y, valid] = recipe.evaluate(&values);
                    (t + signed(2)) * y + (t + signed(5)) * (Fp3::ONE - valid)
                })
                .collect();
            for _ in 0..8 {
                samples = samples.windows(2).map(|p| p[1] - p[0]).collect();
            }
            assert_eq!(samples, [Fp3::ZERO]);
        }
        assert!(maximum.0 <= 38 && maximum.1 <= 39, "recipe census {maximum:?}");
        for shift in [i32::MIN, i32::MAX] {
            let recipe = Recipe::new(shift);
            assert!(recipe.functions.len() <= 6);
            assert_eq!(reference(0, shift), Some(0));
        }
        for x in [Fp3::ZERO, Fp3::ONE, signed(7), Fp3::new(Fp::new(2), Fp::new(3), Fp::new(5))] {
            let weights = interpolation(x);
            for degree in 0..8 {
                let value = weights.iter().enumerate().fold(Fp3::ZERO, |v, (j, &w)| {
                    v + w * (0..degree).fold(Fp3::ONE, |v, _| v * signed(j as i64))
                });
                assert_eq!(value, (0..degree).fold(Fp3::ONE, |v, _| v * x));
            }
        }
    }

    #[test]
    fn c71_b12_rne_ties_overflow_and_original_bytes_share_one_pcs() {
        let n = 32;
        let profile = gamma(&matrix_config(n).unwrap());
        let point = [signed(3), signed(11)];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(19);
        let layout = [20; 32];
        let count = 1 + required(2, 2) + range::required(10, range::Alphabet::Byte) + 32;
        assert_eq!(count, 951);
        let mut rng = MatrixRng::from_seed([127; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        for fault in 0..5 {
            let mut raw = [-6, -10, 14];
            let mut output = [-2, -2, 4];
            if fault == 1 {
                output[0] = -1;
            }
            if fault == 3 {
                raw[0] = 131070;
                output[0] = 32767;
            }
            if fault == 4 {
                raw[0] = -131070;
                output[0] = -32768;
            }
            let mut source = vec![0i16; n * n];
            for i in 0..3 {
                for (j, b) in bytes(raw[i]).into_iter().enumerate() {
                    source[8 * i + j] = i16::from(b);
                }
                for (j, b) in (output[i] + 32768i64).to_le_bytes()[..2].iter().enumerate() {
                    source[32 + 2 * i + j] = i16::from(*b);
                }
            }
            let model = Model::new(n, source).unwrap();
            let statement = Statement {
                root: &model.root,
                profile: &profile,
                view: [21; 32],
                attempt,
                output_point: &point,
                shape: [3, 1],
                shift: 2,
            };
            let start = || Fs::new(b"original RNE input and output source", 100_000);
            let value =
                output.iter().zip(eq(&point)).fold(Fp3::ZERO, |v, (&y, r)| v + signed(y) * r);
            let mut fs = start();
            let mut prows = rows.clone().into_iter();
            let (output_wire, original) = range::authenticate([value], &mut prows);
            record_values(&mut fs, 0x74, &output_wire);
            if fault == 2 {
                raw[0] = -7;
            } // same correct rounded output, different committed bytes
            let (proof, byte_point, byte) =
                prove(&statement, original[0], |i| bytes(raw[i]), &mut fs, &mut prows).unwrap();
            assert_eq!(fs.requests(), 95);
            let (range_proof, forms, targets) = range::prove(
                &model,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let make_forms = |point: Vec<Fp3>, forms: [Vec<Cube>; 2]| {
                let mut result = Vec::from(forms);
                result.push(vec![Cube { offset: 0, point, coefficient: Fp3::ONE }]);
                let mut output_point = statement.output_point.to_vec();
                output_point.push(signed(256) * signed(257).inv());
                result.push(vec![Cube {
                    offset: 32,
                    point: output_point,
                    coefficient: signed(257),
                }]);
                result
            };
            let bias = signed(32768) * byte_function::live_mass(3, &point);
            let output = Auth::new(original[0].x + bias, original[0].m);
            let (pcs, digest) = linear::prove(
                &model,
                attempt,
                layout,
                &make_forms(byte_point, forms),
                &[targets[0], targets[1], byte, output],
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.clone().into_iter();
            let original = range::correct(output_wire, delta, &mut vrows);
            record_values(&mut fs, 0x74, &output_wire);
            let checked = verify(&statement, original[0], &proof, delta, &mut fs, &mut vrows);
            if [1, 3, 4].contains(&fault) {
                assert_eq!(checked.unwrap_err(), "B12 RNE sumcheck MAC rejected");
                continue;
            }
            let (point, byte) = checked.unwrap();
            let (forms, targets) = range::verify(
                n,
                &model.root,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let output = Key::new(original[0].k + delta * bias);
            let checked = linear::verify(
                n,
                &model.root,
                attempt,
                layout,
                &make_forms(point, forms),
                &[targets[0], targets[1], byte, output],
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
    }
}

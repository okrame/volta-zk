//! B12 component: open an ordered batch of public linear forms against one
//! installed root, starting from the caller's ORIGINAL authenticated targets.
//! The Gemma compiler, i16 range proof and full-size prover remain separate.

use super::*;

pub(super) const MAX_CUBES: usize = 524288;
pub(super) const MAX_TARGETS: usize = 8192;

/// EQ-supported aligned cube in the root's Boolean table. Both this point
/// and the PCS use most-significant-variable first (Python W-cut uses LSB).
#[derive(Clone)]
pub(super) struct Cube {
    pub offset: usize,
    pub point: Vec<Fp3>,
    pub coefficient: Fp3,
}

impl Cube {
    fn at(&self, point: &[Fp3]) -> Fp3 {
        let prefix = point.len() - self.point.len();
        let index = self.offset >> self.point.len();
        let high = point[..prefix].iter().enumerate().fold(Fp3::ONE, |s, (i, &r)| {
            s * if index >> (prefix - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        self.coefficient
            * high
            * self
                .point
                .iter()
                .zip(&point[prefix..])
                .fold(Fp3::ONE, |s, (&r, &t)| s * ((Fp3::ONE - r) * (Fp3::ONE - t) + r * t))
    }
}

/// Bind the public forms after the caller's target-correction messages and
/// before lambda. No value/tag/key is serialized here, and no new MAC for
/// the aggregate is requested. One root, one batch, one PCS chain.
fn bind(
    domain: impl Into<Domain>,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    count: usize,
    fs: &mut Fs,
) -> Result<(ZkWhirConfig<E, Goldilocks, Fs>, Vec<Fp3>), String> {
    let domain = domain.into();
    let config = domain.config()?;
    let bits = config.num_variables;
    if root.num_roots() != 1
        || !attempt.valid()
        || layout == [0; 32]
        || forms.is_empty()
        || forms.len() > MAX_TARGETS
        || count != forms.len()
        || forms.iter().map(Vec::len).sum::<usize>() > MAX_CUBES
    {
        return Err("B12 linear batch shape, layout or attempt mismatch".into());
    }
    let mut bytes = b"C71-linear-B12-v1;MSB-first;original-target-MACs;one-PCS".to_vec();
    bytes.extend(gamma(&config));
    bytes.extend(domain.identity().to_le_bytes());
    bytes.extend(root.roots()[0]);
    bytes.extend(attempt.encode());
    bytes.extend(layout);
    bytes.extend((forms.len() as u32).to_le_bytes());
    for form in forms {
        bytes.extend((form.len() as u32).to_le_bytes());
        for cube in form {
            if cube.point.len() > bits {
                return Err("B12 linear cube arity exceeds root domain".into());
            }
            let size = 1usize << cube.point.len();
            if cube.offset % size != 0
                || cube.offset.checked_add(size).is_none_or(|end| end > 1usize << bits)
            {
                return Err("B12 linear cube is unaligned or outside root domain".into());
            }
            bytes.extend((cube.offset as u64).to_le_bytes());
            bytes.extend((cube.point.len() as u32).to_le_bytes());
            bytes.extend(cube.coefficient.to_bytes());
            for x in &cube.point {
                bytes.extend(x.to_bytes());
            }
        }
    }
    fs.set_phase(0x300);
    fs.record(0x30, &bytes);
    let lambda = fs.fp3();
    let mut power = Fp3::ONE;
    let coefficients = forms
        .iter()
        .map(|_| {
            let next = power;
            power = power * lambda;
            next
        })
        .collect();
    Ok((config, coefficients))
}

// The caller reserves/burns 3*D+2 fresh correlations and its target transfers
// before entering. fs already contains the original target-correction wire.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove(
    model: &Model,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Auth],
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    prove_dense_with_coins(model, attempt, layout, forms, targets, fs, correlations, None)
}

#[allow(clippy::too_many_arguments)]
fn prove_dense_with_coins(
    model: &Model,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Auth],
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
    coins: Option<PcsCoins>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    let required = 3 * model.domain.config()?.num_variables + 2;
    if correlations.len() < required {
        return Err("B12 linear prover correlations exhausted".into());
    }
    let mut reserved = correlations.by_ref().take(required);
    let (config, coefficients) =
        bind(model.domain, &model.root, attempt, layout, forms, targets.len(), fs)?;
    let target =
        targets.iter().zip(&coefficients).fold(Auth::ZERO, |s, (&x, &c)| s.add(x.scale(c)));
    let mut form = vec![Fp3::ZERO; 1usize << config.num_variables];
    for (cubes, &coefficient) in forms.iter().zip(&coefficients) {
        for cube in cubes {
            for (i, weight) in eq(&cube.point).into_iter().enumerate() {
                form[cube.offset + i] += coefficient * cube.coefficient * weight;
            }
        }
    }
    // ponytail: dense source/form materialization within the analytic bound.
    // Physical Gemma admission still requires its streaming/tiled schedule.
    let weights = model
        .polynomial()
        .as_slice()
        .iter()
        .map(|x| Fp3::from_base(Fp::new(x.as_canonical_u64())))
        .collect();
    let (rounds, point, target, value, public_endpoint) =
        prove_product(weights, form, target, fs, &mut reserved);
    fs.set_phase(0x100);
    let (correction, terminal) = c7_fp3_transfer_prover(reserved.next().unwrap(), value);
    let terminal_wire = [correction.value(), target.m - public_endpoint * terminal.m];
    record_values(fs, 0x11, &terminal_wire);
    let mask = reserved.next().unwrap();
    let point = Point::new(point.into_iter().map(to_p3).collect());
    let (pcs, close_tag) = match coins {
        Some(coins) => prove_pcs_with_coins(model, &config, point, terminal, mask, fs, coins)?,
        None => prove_pcs(model, &config, point, terminal, mask, fs)?,
    };
    Ok((MatrixProof { rounds, terminal: terminal_wire, pcs, close_tag }, fs.digest()))
}

#[cfg(test)]
fn folded_source(
    value: &mut dyn FnMut(usize) -> Fp3,
    prefix_point: &[Fp3],
    suffix: usize,
    remaining: usize,
) -> Fp3 {
    (0..1usize << prefix_point.len()).fold(Fp3::ZERO, |sum, prefix| {
        let weight = prefix_point.iter().enumerate().fold(Fp3::ONE, |weight, (bit, &r)| {
            weight
                * if prefix >> (prefix_point.len() - 1 - bit) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        sum + weight * value((prefix << remaining) | suffix)
    })
}

#[cfg(test)]
fn public_value(forms: &[Vec<Cube>], coefficients: &[Fp3], point: &[Fp3]) -> Fp3 {
    forms.iter().zip(coefficients).fold(Fp3::ZERO, |sum, (form, &coefficient)| {
        sum + coefficient * form.iter().fold(Fp3::ZERO, |value, cube| value + cube.at(point))
    })
}

// Bounded EQ tables cover at most eight prefix bits apiece. Arbitrary source
// order and challenges 0/1 require neither division nor a folded-source table.
struct PrefixWeights(Vec<(usize, Vec<Fp3>)>);
impl PrefixWeights {
    fn new(point: &[Fp3]) -> Self {
        Self(point.chunks(8).enumerate().map(|(i, chunk)| {
            (point.len() - 8 * i - chunk.len(), eq(chunk))
        }).collect())
    }
    fn at(&self, index: usize) -> Fp3 {
        self.0.iter().fold(Fp3::ONE, |value, (shift, table)| {
            value * table[(index >> shift) & (table.len() - 1)]
        })
    }
}

struct ResidualCube<'a> {
    interval: usize,
    point: &'a [Fp3],
    lower: Fp3,
    upper: Fp3,
}

// Dyadic residuals are indexed by their suffix width and aligned interval.
// Only cubes containing the suffix have their Boolean EQ evaluated.
struct PublicRound<'a>(Vec<(usize, Vec<ResidualCube<'a>>)>);
impl<'a> PublicRound<'a> {
    fn new(bits: usize, forms: &'a [Vec<Cube>], coefficients: &[Fp3], prefix: &[Fp3]) -> Self {
        let remaining = bits - prefix.len();
        let half = 1usize << (remaining - 1);
        let mut intervals: Vec<Vec<ResidualCube<'a>>> =
            (0..remaining).map(|_| Vec::new()).collect();
        for (form, &coefficient) in forms.iter().zip(coefficients) {
            for cube in form {
                let fixed = bits - cube.point.len();
                let mut gamma = coefficient * cube.coefficient;
                for (i, &r) in prefix.iter().take(fixed).enumerate() {
                    gamma = gamma * if (cube.offset >> (bits - 1 - i)) & 1 == 1 { r } else { Fp3::ONE - r };
                }
                for (&r, &q) in prefix.iter().skip(fixed).zip(&cube.point) {
                    gamma = gamma * ((Fp3::ONE - r) * (Fp3::ONE - q) + r * q);
                }
                if gamma == Fp3::ZERO { continue; }
                let (point, lower, upper, offset) = if prefix.len() >= fixed {
                    let next = prefix.len() - fixed;
                    let q = cube.point[next];
                    (&cube.point[next + 1..], gamma * (Fp3::ONE - q), gamma * q, 0)
                } else if cube.offset & half == 0 {
                    (&cube.point[..], gamma, Fp3::ZERO, cube.offset & (half - 1))
                } else {
                    (&cube.point[..], Fp3::ZERO, gamma, cube.offset & (half - 1))
                };
                intervals[point.len()].push(ResidualCube {
                    interval: offset >> point.len(), point, lower, upper,
                });
            }
        }
        for cubes in &mut intervals { cubes.sort_unstable_by_key(|cube| cube.interval); }
        Self(intervals.into_iter().enumerate().filter(|(_, cubes)| !cubes.is_empty()).collect())
    }
    fn at(&self, suffix: usize) -> (Fp3, Fp3) {
        let mut values = (Fp3::ZERO, Fp3::ZERO);
        for (bits, intervals) in &self.0 {
            let interval = suffix >> bits;
            let first = intervals.partition_point(|cube| cube.interval < interval);
            for cube in intervals[first..].iter().take_while(|cube| cube.interval == interval) {
                let weight = cube.point.iter().enumerate().fold(Fp3::ONE, |weight, (i, &r)| {
                    weight * if (suffix >> (bits - 1 - i)) & 1 == 1 { r } else { Fp3::ONE - r }
                });
                values.0 += cube.lower * weight;
                values.1 += cube.upper * weight;
            }
        }
        values
    }
}

fn source_coefficients(
    bits: usize, live: usize, prefix: &[Fp3], forms: &[Vec<Cube>], coefficients: &[Fp3],
    scan: impl FnOnce(&mut dyn FnMut(usize, Fp3) -> Result<(), String>) -> Result<(), String>,
) -> Result<([Fp3; 3], Option<(Fp3, Fp3, Fp3, Fp3)>), String> {
    let remaining = bits - prefix.len();
    let half = 1usize << (remaining - 1);
    let weights = PrefixWeights::new(prefix);
    let public = PublicRound::new(bits, forms, coefficients, prefix);
    let mut last_prefix = (usize::MAX, Fp3::ZERO);
    let mut last_suffix = (usize::MAX, (Fp3::ZERO, Fp3::ZERO));
    let mut result = [Fp3::ZERO; 3];
    let mut endpoints = (Fp3::ZERO, Fp3::ZERO);
    let mut count = 0;
    scan(&mut |index, original| {
        if index >= live || count >= live { return Err("linear original scan index or count differs".into()); }
        count += 1;
        let high = index >> remaining;
        if high != last_prefix.0 { last_prefix = (high, weights.at(high)); }
        let value = original * last_prefix.1;
        if value == Fp3::ZERO { return Ok(()); }
        let suffix = index & (half - 1);
        if suffix != last_suffix.0 { last_suffix = (suffix, public.at(suffix)); }
        let (lower, upper) = last_suffix.1;
        if index & half == 0 {
            result[0] += value * lower;
            result[1] += value * (upper - lower - lower);
            result[2] += value * (lower - upper);
            if half == 1 { endpoints.0 += value; }
        } else {
            result[1] += value * lower;
            result[2] += value * (upper - lower);
            if half == 1 { endpoints.1 += value; }
        }
        Ok(())
    })?;
    if count != live { return Err("linear original scan incomplete".into()); }
    let terminal = if half == 1 {
        let (lower, upper) = public.at(0);
        Some((endpoints.0, endpoints.1, lower, upper))
    } else { None };
    Ok((result, terminal))
}

fn prove_product_sourcewise(
    model: &b12::replay::ReplayModel,
    forms: &[Vec<Cube>],
    coefficients: &[Fp3],
    mut target: Auth,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Vec<[Fp3; 4]>, Vec<Fp3>, Auth, Fp3, Fp3), String> {
    let bits = model.domain().config()?.num_variables;
    let mut phase = crate::c71_matrix::progress::Span::start("linear_original_scan",
        serde_json::json!({"domain_log2": bits, "live": model.live_len(), "rounds": bits,
            "public_cubes": forms.iter().map(Vec::len).sum::<usize>(), "prefix_eq_max_bits": 8}))?;
    let mut point = Vec::with_capacity(bits);
    let mut rounds = Vec::with_capacity(bits);
    let mut endpoints = None;
    for round in 0..bits {
        fs.set_phase(1 + round as u16);
        let mut visited = 0usize;
        let (coefficients_round, terminal) = source_coefficients(
            bits, model.live_len(), &point, forms, coefficients, |emit| {
                model.scan_original(&mut |index, value| {
                    emit(index, value)?;
                    visited += 1;
                    if visited & ((1 << 20) - 1) == 0 {
                        phase.checkpoint(|| serde_json::json!({"completed_scans": round,
                            "total_scans": bits, "active_scan_visits": visited,
                            "source_visits": round * model.live_len() + visited,
                            "public_tail_reads": 0}))?;
                    }
                    Ok(())
                })
            },
        )?;
        if terminal.is_some() { endpoints = terminal; }
        let mut authenticated = [Auth::ZERO; 3];
        let mut wire = [Fp3::ZERO; 4];
        for i in 0..3 {
            let (correction, value) =
                c7_fp3_transfer_prover(correlations.next().unwrap(), coefficients_round[i]);
            wire[i] = correction.value();
            authenticated[i] = value;
        }
        wire[3] = authenticated[0].m + authenticated[0].m + authenticated[1].m + authenticated[2].m
            - target.m;
        record_values(fs, 0x10, &wire);
        let r = fs.fp3();
        target = authenticated[0].add(authenticated[1].scale(r)).add(authenticated[2].scale(r * r));
        point.push(r);
        rounds.push(wire);
        phase.checkpoint(|| serde_json::json!({"completed_scans": round + 1,
            "total_scans": bits, "source_visits": (round + 1) * model.live_len(),
            "public_tail_reads": 0}))?;
    }
    let (a, upper, b, b_upper) = endpoints.expect("nonempty flat source");
    let r = *point.last().unwrap();
    phase.finish(serde_json::json!({"completed_scans": bits,
        "source_visits": bits * model.live_len(), "public_tail_reads": 0}))?;
    Ok((rounds, point, target, a + r * (upper - a), b + r * (b_upper - b)))
}

/// Sourcewise counterpart of `prove`: it retains neither the original A
/// polynomial nor the dense public EQ form. The immutable originals are scanned
/// once per product-sumcheck round in any order, then handed to the
/// sourcewise WHIR backend for the same terminal point.
#[allow(clippy::too_many_arguments)]
pub(in crate::c71_matrix) fn prove_sourcewise(
    model: &b12::replay::ReplayModel,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Auth],
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    prove_sourcewise_with_coins(model, attempt, layout, forms, targets, fs, correlations, None)
}

#[allow(clippy::too_many_arguments)]
fn prove_sourcewise_with_coins(
    model: &b12::replay::ReplayModel,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Auth],
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
    coins: Option<PcsCoins>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    let required = 3 * model.domain().config()?.num_variables + 2;
    if correlations.len() < required {
        return Err("B12 linear prover correlations exhausted".into());
    }
    let mut reserved = correlations.by_ref().take(required);
    let (config, coefficients) =
        bind(model.domain(), model.root(), attempt, layout, forms, targets.len(), fs)?;
    let target =
        targets.iter().zip(&coefficients).fold(Auth::ZERO, |s, (&x, &c)| s.add(x.scale(c)));
    let (rounds, point, target, value, public_endpoint) =
        prove_product_sourcewise(model, forms, &coefficients, target, fs, &mut reserved)?;
    fs.set_phase(0x100);
    let (correction, terminal) = c7_fp3_transfer_prover(reserved.next().unwrap(), value);
    let terminal_wire = [correction.value(), target.m - public_endpoint * terminal.m];
    record_values(fs, 0x11, &terminal_wire);
    let mask = reserved.next().unwrap();
    let point = Point::new(point.into_iter().map(to_p3).collect());
    let (pcs, close_tag) = match coins {
        Some(coins) => b12::replay::prove_pcs_sourcewise_with_coins(
            model, &config, point, terminal, mask, fs, coins,
        )?,
        None => b12::replay::prove_pcs_sourcewise(model, &config, point, terminal, mask, fs)?,
    };
    Ok((MatrixProof { rounds, terminal: terminal_wire, pcs, close_tag }, fs.digest()))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    domain: impl Into<Domain>,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    forms: &[Vec<Cube>],
    targets: &[Key],
    proof: &MatrixProof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<blake3::Hash, String> {
    let domain = domain.into();
    let bits = domain.config()?.num_variables;
    let required = 3 * bits + 2;
    if correlations.len() < required || proof.rounds.len() != bits {
        return Err("B12 linear verifier correlations or round count mismatch".into());
    }
    let mut reserved = correlations.by_ref().take(required);
    let (config, coefficients) = bind(domain, root, attempt, layout, forms, targets.len(), fs)?;
    let target = targets.iter().zip(&coefficients).fold(Key::ZERO, |s, (&x, &c)| s.add(x.scale(c)));
    let (target, point) = verify_product(&proof.rounds, target, delta, fs, &mut reserved)?;
    // O(D * cube count) verifier work: no N-cell public form or W.
    let public_endpoint = forms.iter().zip(&coefficients).fold(Fp3::ZERO, |s, (cubes, &c)| {
        s + c * cubes.iter().fold(Fp3::ZERO, |v, cube| v + cube.at(&point))
    });
    fs.set_phase(0x100);
    let terminal = c7_fp3_transfer_verifier(
        reserved.next().unwrap(),
        delta,
        C7Fp3TransferCorrection::new(proof.terminal[0]),
    );
    if target.k - public_endpoint * terminal.k != proof.terminal[1] {
        return Err("B12 linear terminal MAC rejected".into());
    }
    record_values(fs, 0x11, &proof.terminal);
    let mask = reserved.next().unwrap();
    let point = Point::new(point.into_iter().map(to_p3).collect());
    verify_pcs(&config, root, point, &proof.pcs, proof.close_tag, terminal, mask, delta, fs)?;
    Ok(fs.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mixed_forms(bits: usize) -> Vec<Vec<Cube>> {
        let extension = |i| Fp3::new(Fp::new(i), Fp::ONE, Fp::ONE);
        let small = Cube {
            offset: 16, point: vec![Fp3::ZERO, Fp3::ONE, extension(3)], coefficient: signed(3),
        };
        vec![
            vec![
                Cube {
                    offset: 0, point: (0..bits).map(|i| extension(i as u64 + 2)).collect(),
                    coefficient: signed(-7),
                },
                small.clone(), small,
                Cube { offset: 17, point: vec![], coefficient: signed(11) },
            ],
            vec![
                Cube { offset: 0, point: vec![extension(5); 5], coefficient: signed(5) },
                Cube {
                    offset: (1 << bits) - 16,
                    point: vec![Fp3::ONE, Fp3::ZERO, extension(7), signed(-3)],
                    coefficient: signed(-11),
                },
            ],
            vec![],
            vec![Cube { offset: 0, point: vec![extension(9); bits], coefficient: Fp3::ZERO }],
        ]
    }

    fn dense_public(bits: usize, forms: &[Vec<Cube>], coefficients: &[Fp3]) -> Vec<Fp3> {
        let mut result = vec![Fp3::ZERO; 1 << bits];
        for (form, &coefficient) in forms.iter().zip(coefficients) {
            for cube in form {
                for (i, weight) in eq(&cube.point).into_iter().enumerate() {
                    result[cube.offset + i] += coefficient * cube.coefficient * weight;
                }
            }
        }
        result
    }

    fn dense_coefficients(a: &[Fp3], b: &[Fp3]) -> [Fp3; 3] {
        let half = a.len() / 2;
        let mut result = [Fp3::ZERO; 3];
        for i in 0..half {
            let da = a[i + half] - a[i];
            let db = b[i + half] - b[i];
            result[0] += a[i] * b[i];
            result[1] += da * b[i] + a[i] * db;
            result[2] += da * db;
        }
        result
    }

    // Independent pre-optimization oracle: enumerate every prefix for each
    // pair, including the public zero tail, and evaluate every public cube.
    fn ordinary_coefficients(
        bits: usize, prefix: &[Fp3], forms: &[Vec<Cube>], coefficients: &[Fp3],
        value: &mut dyn FnMut(usize) -> Fp3,
    ) -> [Fp3; 3] {
        let remaining = bits - prefix.len();
        let half = 1usize << (remaining - 1);
        let mut result = [Fp3::ZERO; 3];
        for suffix in 0..half {
            let a = folded_source(value, prefix, suffix, remaining);
            let upper = folded_source(value, prefix, suffix + half, remaining);
            let mut lower_point = Vec::with_capacity(bits);
            lower_point.extend_from_slice(prefix);
            lower_point.push(Fp3::ZERO);
            lower_point.extend((0..remaining - 1).map(|i| {
                if suffix >> (remaining - 2 - i) & 1 == 1 { Fp3::ONE } else { Fp3::ZERO }
            }));
            let mut upper_point = lower_point.clone();
            upper_point[prefix.len()] = Fp3::ONE;
            let b = public_value(forms, coefficients, &lower_point);
            let b_upper = public_value(forms, coefficients, &upper_point);
            let da = upper - a;
            let db = b_upper - b;
            result[0] += a * b;
            result[1] += da * b + a * db;
            result[2] += da * db;
        }
        result
    }

    fn round_heap_capacity(bits: usize, prefix: &[Fp3], forms: &[Vec<Cube>], coefficients: &[Fp3])
        -> (usize, usize, usize)
    {
        use std::mem::size_of;
        let weights = PrefixWeights::new(prefix);
        let public = PublicRound::new(bits, forms, coefficients, prefix);
        let prefix_cells = weights.0.iter().map(|(_, table)| table.capacity()).sum::<usize>();
        let prefix_bytes = weights.0.capacity() * size_of::<(usize, Vec<Fp3>)>()
            + prefix_cells * size_of::<Fp3>();
        let public_bytes = public.0.capacity() * size_of::<(usize, Vec<ResidualCube<'_>>)>()
            + public.0.iter().map(|(_, cubes)| cubes.capacity() * size_of::<ResidualCube<'_>>())
                .sum::<usize>();
        // Allow replacement allocations to overlap their old vectors, and
        // the old width headers to overlap the collected nonempty headers.
        // Sorting itself allocates no heap scratch; allocator metadata and
        // process RSS remain separate from these capacity bounds.
        let build_headers = (bits - prefix.len()) * size_of::<Vec<ResidualCube<'_>>>();
        (2 * (prefix_bytes + public_bytes) + build_headers, prefix_cells, public_bytes)
    }

    #[test]
    fn c71_b12_sourcewise_linear_scan_coefficients_and_component_benchmark() {
        use std::mem::size_of;
        use std::time::Instant;
        let extension = Fp3::new(Fp::new(7), Fp::ONE, Fp::new(3));
        let challenges = [Fp3::ZERO, Fp3::ONE, extension, signed(-3)];
        for bits in [10, 12] {
            let forms = mixed_forms(bits);
            let coefficients = [Fp3::ONE, extension, signed(5), Fp3::ZERO];
            let form_bytes = forms.capacity() * size_of::<Vec<Cube>>()
                + forms.iter().map(|form| form.capacity() * size_of::<Cube>()
                    + form.iter().map(|cube| cube.point.capacity() * size_of::<Fp3>())
                        .sum::<usize>()).sum::<usize>();
            let size = 1 << bits;
            for live in [size, size / 3, 0] {
                let originals: Vec<_> = (0..size).map(|i| {
                    if i < live { signed(((i * 29 + i * i * 3) % 251) as i64 - 125) }
                    else { Fp3::ZERO }
                }).collect();
                let mut dense_a = originals.clone();
                let mut dense_b = dense_public(bits, &forms, &coefficients);
                let mut prefix = Vec::with_capacity(bits);
                let mut old_reads = 0;
                let mut visits = 0;
                let mut old_ns = 0;
                let mut scan_ns = 0;
                let mut heap_peak = 0;
                let mut prefix_cells_peak = 0;
                let mut public_bytes_peak = 0;
                for round in 0..bits {
                    let expected = dense_coefficients(&dense_a, &dense_b);
                    let old_start = Instant::now();
                    let old = ordinary_coefficients(bits, &prefix, &forms, &coefficients,
                        &mut |index| { old_reads += 1; originals[index] });
                    old_ns += old_start.elapsed().as_nanos();
                    let scan_start = Instant::now();
                    let (actual, endpoints) = source_coefficients(
                        bits, live, &prefix, &forms, &coefficients, |emit| {
                            for position in 0..live {
                                let index = if round % 2 == 0 { live - 1 - position }
                                    else { (position + live / 3) % live };
                                visits += 1;
                                emit(index, originals[index])?;
                            }
                            Ok(())
                        },
                    ).unwrap();
                    scan_ns += scan_start.elapsed().as_nanos();
                    assert_eq!(old, expected, "old oracle D{bits} live{live} round{round}");
                    assert_eq!(actual, expected, "scan D{bits} live{live} round{round}");
                    let half = dense_a.len() / 2;
                    assert_eq!(endpoints, (half == 1).then(|| {
                        (dense_a[0], dense_a[1], dense_b[0], dense_b[1])
                    }));
                    let public = PublicRound::new(bits, &forms, &coefficients, &prefix);
                    for suffix in [0, half / 2, half - 1] {
                        assert_eq!(public.at(suffix), (dense_b[suffix], dense_b[suffix + half]));
                    }
                    let (heap, cells, public_bytes) = round_heap_capacity(bits, &prefix,
                        &forms, &coefficients);
                    heap_peak = heap_peak.max(heap);
                    prefix_cells_peak = prefix_cells_peak.max(cells);
                    public_bytes_peak = public_bytes_peak.max(public_bytes);
                    let r = challenges[round % challenges.len()];
                    fold(&mut dense_a, r);
                    fold(&mut dense_b, r);
                    prefix.push(r);
                }
                assert_eq!(old_reads, bits * size);
                assert_eq!(visits, bits * live);
                assert!(prefix_cells_peak <= bits.div_ceil(8) * 256);
                println!("C71_LINEAR_SCAN {}", serde_json::json!({
                    "domain_log2":bits,"live":live,"rounds":bits,"ordinary_ns":old_ns as u64,
                    "scan_ns":scan_ns as u64,"ordinary_original_reads":old_reads,
                    "scan_original_visits":visits,"scans":bits,"public_tail_reads":0,
                    "prefix_eq_capacity_peak_cells":prefix_cells_peak,
                    "owned_heap_capacity_peak_bound_bytes":heap_peak,
                    "public_residual_capacity_peak_bytes":public_bytes_peak,
                    "borrowed_form_capacity_bytes":form_bytes,
                    "ordinary_round_point_capacity_bytes":2 * bits * size_of::<Fp3>(),
                    "harness_domain_arrays_peak_bound_bytes":5 * size * size_of::<Fp3>(),
                    "device_bytes":0,"transfer_bytes":0,"correlations":0,"credit":false,
                    "scope":"CPU coefficient component, old then scan per round; heap capacities and borrowed forms, not allocator metadata/process RSS or model/PCS/replay workspace; full-domain arrays belong only to the independent test oracle"
                }));
            }
        }
    }

    #[test]
    fn c71_b12_sourcewise_linear_scan_rejects_incomplete_extra_and_producer_errors() {
        for fault in 0..4 {
            let result = source_coefficients(10, 4, &[], &[], &[], |emit| {
                for index in 0..if fault == 0 { 3 } else { 4 } {
                    emit(if fault == 1 { 4 } else { index }, signed(index as i64))?;
                    if fault == 2 { return Err("linear producer failed after one cell".into()); }
                }
                if fault == 3 { emit(0, Fp3::ZERO)?; }
                Ok(())
            });
            let error = result.unwrap_err();
            if fault == 0 { assert_eq!(error, "linear original scan incomplete"); }
            if fault == 2 { assert_eq!(error, "linear producer failed after one cell"); }
        }
    }

    #[test]
    fn c71_b12_sourcewise_linear_scanned_wire_fs_mac_and_failed_round_consumption() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let bits = 12;
        let live = 93;
        let values: Arc<Vec<u8>> = Arc::new((0..live).map(|i| (i * 17 % 251) as u8).collect());
        let mode = Arc::new(AtomicUsize::new(0));
        let scans = Arc::new(AtomicUsize::new(0));
        let scan: b12::replay::BaseScan = {
            let values = values.clone(); let mode = mode.clone(); let scans = scans.clone();
            Arc::new(move |emit| {
                let call = scans.fetch_add(1, Ordering::Relaxed);
                let fault = mode.load(Ordering::Relaxed);
                for index in (0..live).rev() {
                    if fault == 1 && index == 0 { continue; }
                    emit(if fault == 2 && index == 0 { live } else { index },
                        Goldilocks::from_u8(values[index]))?;
                    if fault == 3 || fault == 5 && call == 2 {
                        return Err("linear producer failed after one cell".into());
                    }
                }
                if fault == 4 { emit(0, Goldilocks::ZERO)?; }
                Ok(())
            })
        };
        let window: b12::replay::ByteWindow = {
            let values = values.clone();
            Arc::new(move |first, bytes| {
                bytes.copy_from_slice(&values[first..first + bytes.len()]); Ok(())
            })
        };
        let model = b12::replay::ReplayModel::new_scanned(Domain::Flat(bits), [43; 32], [47; 32],
            Arc::new(|_| panic!("linear scan called scalar getter")), scan, window, live).unwrap();
        let forms = mixed_forms(bits);
        let coefficients = [Fp3::ONE, signed(13), signed(17), Fp3::ZERO];
        let a: Vec<_> = (0..1 << bits).map(|i| {
            if i < live { signed(i64::from(values[i])) } else { Fp3::ZERO }
        }).collect();
        let b = dense_public(bits, &forms, &coefficients);
        let target = Auth::new(a.iter().zip(&b).fold(Fp3::ZERO, |s, (&a, &b)| s + a * b),
            signed(19));
        let correlations: Vec<_> = (0..3 * bits + 2)
            .map(|i| Auth::new(signed(i as i64 + 23), signed(i as i64 + 29))).collect();
        let mut dense_rows = correlations.clone().into_iter();
        let mut scan_rows = correlations.clone().into_iter();
        let mut dense_fs = Fs::new(b"linear original scanner parity", bits);
        let mut scan_fs = Fs::new(b"linear original scanner parity", bits);
        scans.store(0, Ordering::Relaxed);
        let dense = prove_product(a, b, target, &mut dense_fs, &mut dense_rows);
        let scanned = prove_product_sourcewise(&model, &forms, &coefficients, target,
            &mut scan_fs, &mut scan_rows).unwrap();
        assert_eq!(dense.0, scanned.0); assert_eq!(dense.1, scanned.1);
        assert_eq!((dense.2.x, dense.2.m), (scanned.2.x, scanned.2.m));
        assert_eq!((dense.3, dense.4), (scanned.3, scanned.4));
        assert_eq!(dense_fs.digest(), scan_fs.digest());
        assert_eq!(dense_rows.len(), 2); assert_eq!(scan_rows.len(), 2);
        assert_eq!(scans.load(Ordering::Relaxed), bits);
        for fault in 1..=5 {
            mode.store(fault, Ordering::Relaxed); scans.store(0, Ordering::Relaxed);
            let mut rows = correlations.clone().into_iter();
            let mut fs = Fs::new(b"linear failed scan", bits);
            let initial_digest = fs.digest();
            let result = prove_product_sourcewise(&model, &forms, &coefficients, target,
                &mut fs, &mut rows);
            assert!(result.is_err(), "fault {fault}");
            let successful_rounds = if fault == 5 { 2 } else { 0 };
            assert_eq!(rows.len(), correlations.len() - 3 * successful_rounds);
            assert_eq!(fs.requests(), successful_rounds);
            if successful_rounds == 0 { assert_eq!(fs.digest(), initial_digest); }
        }
        println!("C71_LINEAR_SCANNED {{\"domain_log2\":{bits},\"live\":{live},\"scans\":{bits},\"round_correlations\":{},\"reserved_terminal_correlations\":2,\"failed_scans\":5,\"credit\":false}}", 3 * bits);
    }

    #[test]
    fn c71_b12_sourcewise_linear_matches_dense_wire_fs_point_and_original_mac() {
        use std::sync::Arc;

        let bits = 10;
        let weights: Vec<_> =
            (0..1usize << bits).map(|i| ((i * 29 + i * i * 3) % 251) as i16 - 125).collect();
        let model = Model::new_in(Domain::Flat(bits), weights).unwrap();
        let values: Vec<_> = model.polynomial().as_slice().iter().map(|&x| E::from(x)).collect();
        let source = {
            let values = Arc::new(values);
            Arc::new(move |i| values[i])
        };
        let replay = b12::replay::ReplayModel::new_checked(
            model.domain,
            model.root.clone(),
            model.seed,
            model.salt_seed,
            source,
        )
        .unwrap();
        let forms = vec![
            vec![
                Cube { offset: 0, point: vec![signed(2), signed(3)], coefficient: signed(5) },
                Cube { offset: 512, point: vec![signed(7)], coefficient: signed(-11) },
            ],
            vec![Cube { offset: 256, point: vec![signed(13); 4], coefficient: signed(17) }],
        ];
        let scalar_values: Vec<_> = model
            .polynomial()
            .as_slice()
            .iter()
            .map(|x| Fp3::from_base(Fp::new(x.as_canonical_u64())))
            .collect();
        let target_value = |form: &[Cube]| {
            form.iter().fold(Fp3::ZERO, |sum, cube| {
                sum + eq(&cube.point).into_iter().enumerate().fold(
                    Fp3::ZERO,
                    |value, (i, weight)| {
                        value + cube.coefficient * weight * scalar_values[cube.offset + i]
                    },
                )
            })
        };
        let targets = [
            Auth::new(target_value(&forms[0]), signed(23)),
            Auth::new(target_value(&forms[1]), signed(31)),
        ];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let layout = [4; 32];
        let correlations: Vec<_> = (0..3 * bits + 2)
            .map(|i| Auth::new(signed(i as i64 + 37), signed(i as i64 + 71)))
            .collect();

        // First compare the reduction itself, including its reconstructed point
        // and the original authenticated target after every identical round.
        let mut dense_fs = Fs::new(b"sourcewise linear parity", 10_000);
        let mut source_fs = Fs::new(b"sourcewise linear parity", 10_000);
        let (_, dense_coefficients) =
            bind(model.domain, &model.root, attempt, layout, &forms, targets.len(), &mut dense_fs)
                .unwrap();
        let (_, source_coefficients) = bind(
            replay.domain(),
            replay.root(),
            attempt,
            layout,
            &forms,
            targets.len(),
            &mut source_fs,
        )
        .unwrap();
        assert_eq!(dense_coefficients, source_coefficients);
        let target = targets
            .iter()
            .zip(&dense_coefficients)
            .fold(Auth::ZERO, |sum, (&value, &coefficient)| sum.add(value.scale(coefficient)));
        let mut dense_form = vec![Fp3::ZERO; 1 << bits];
        for (form, &coefficient) in forms.iter().zip(&dense_coefficients) {
            for cube in form {
                for (i, weight) in eq(&cube.point).into_iter().enumerate() {
                    dense_form[cube.offset + i] += coefficient * cube.coefficient * weight;
                }
            }
        }
        let dense_values = scalar_values;
        let mut dense_rows = correlations[..3 * bits].to_vec().into_iter();
        let mut source_rows = correlations[..3 * bits].to_vec().into_iter();
        let dense = prove_product(dense_values, dense_form, target, &mut dense_fs, &mut dense_rows);
        let source = prove_product_sourcewise(
            &replay,
            &forms,
            &source_coefficients,
            target,
            &mut source_fs,
            &mut source_rows,
        ).unwrap();
        assert_eq!(dense.0, source.0);
        assert_eq!(dense.1, source.1);
        assert_eq!((dense.2.x, dense.2.m), (source.2.x, source.2.m));
        assert_eq!((dense.3, dense.4), (source.3, source.4));
        assert_eq!(dense_fs.digest(), source_fs.digest());

        // Fixed test-only proof coins make the PCS bytes comparable. Production
        // wrappers still draw fresh OS randomness on every attempt.
        let coins = PcsCoins { seed: [5; 32], salt_seed: [6; 32] };
        let mut dense_fs = Fs::new(b"sourcewise linear full parity", 100_000);
        let mut source_fs = Fs::new(b"sourcewise linear full parity", 100_000);
        let mut dense_rows = correlations.clone().into_iter();
        let mut source_rows = correlations.into_iter();
        let (dense, dense_digest) = prove_dense_with_coins(
            &model,
            attempt,
            layout,
            &forms,
            &targets,
            &mut dense_fs,
            &mut dense_rows,
            Some(coins),
        )
        .unwrap();
        let (source, source_digest) = prove_sourcewise_with_coins(
            &replay,
            attempt,
            layout,
            &forms,
            &targets,
            &mut source_fs,
            &mut source_rows,
            Some(coins),
        )
        .unwrap();
        assert_eq!(
            codec::encode_linear(Domain::Flat(bits), &dense).unwrap(),
            codec::encode_linear(Domain::Flat(bits), &source).unwrap()
        );
        assert_eq!(dense_digest, source_digest);
        assert_eq!(dense_fs.digest(), source_fs.digest());
        assert!(dense_rows.next().is_none() && source_rows.next().is_none());
        let delta = signed(41);
        let target_keys: Vec<_> = targets.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let mut verifier_rows = (0..3 * bits + 2)
            .map(|i| {
                let a = Auth::new(signed(i as i64 + 37), signed(i as i64 + 71));
                Key::new(a.m + delta * a.x)
            })
            .collect::<Vec<_>>()
            .into_iter();
        let mut verifier_fs = Fs::new(b"sourcewise linear full parity", 100_000);
        let verified = verify(
            replay.domain(),
            replay.root(),
            attempt,
            layout,
            &forms,
            &target_keys,
            &source,
            delta,
            &mut verifier_fs,
            &mut verifier_rows,
        )
        .unwrap();
        assert_eq!(verified, source_digest);
        assert_eq!(verifier_fs.digest(), source_fs.digest());
        assert!(verifier_rows.next().is_none());
    }

    #[test]
    fn c71_b12_cube_evaluator_matches_dense_forms_and_rejects_bad_layout() {
        let point: Vec<_> = (0..10).map(|i| Fp3::new(Fp::new(i + 2), Fp::ONE, Fp::ONE)).collect();
        let rho = eq(&point);
        for bits in 0..=10 {
            for offset in (0..1024).step_by(1 << bits) {
                let cube = Cube { offset, point: point[..bits].to_vec(), coefficient: signed(-7) };
                let expected = eq(&cube.point)
                    .iter()
                    .enumerate()
                    .fold(Fp3::ZERO, |s, (i, &r)| s + cube.coefficient * r * rho[offset + i]);
                assert_eq!(cube.at(&point), expected);
            }
        }
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let root = C61Commitment::new(vec![[4; 32]]);
        for cube in [
            Cube { offset: 1, point: vec![Fp3::ONE], coefficient: Fp3::ONE },
            Cube { offset: 1024, point: vec![], coefficient: Fp3::ONE },
            Cube { offset: 0, point: vec![Fp3::ONE; 11], coefficient: Fp3::ONE },
            Cube { offset: usize::MAX, point: vec![], coefficient: Fp3::ONE },
        ] {
            assert!(bind(
                32,
                &root,
                attempt,
                [5; 32],
                &[vec![cube]],
                1,
                &mut Fs::new(b"bad cube", 0)
            )
            .is_err());
        }
        for bits in [11, 34, 35] {
            let form = vec![Cube {
                offset: (1usize << bits) - 8,
                point: point[..3].to_vec(),
                coefficient: Fp3::ONE,
            }];
            let mut fs = Fs::new(b"flat cube metadata only", 1);
            let (config, weights) =
                bind(Domain::Flat(bits), &root, attempt, [5; 32], &[form], 1, &mut fs).unwrap();
            assert_eq!(config.num_variables, bits);
            assert_eq!(weights, vec![Fp3::ONE]);
            assert_eq!(fs.requests(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_real_pool_linear_batch_keeps_matrix_norm_and_tied_embedding_macs() {
        check_real_pool_linear_batch(false);
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_fixed_run_linear_batch_accepts_then_stops_on_false_target() {
        check_real_pool_linear_batch(true);
    }

    #[cfg(unix)]
    fn check_real_pool_linear_batch(fixed_run: bool) {
        use std::io;
        use std::sync::mpsc;
        use volta_pcg::c71_lifetime::{Attempt, Lifetime, ModelBinding};

        let n = 32;
        let mut weights = vec![0i16; n * n];
        weights[..11].copy_from_slice(&[2, -3, 5, 7, -11, 13, 17, -19, 23, -29, 31]);
        weights[16..24].copy_from_slice(&[37, -41, 43, 47, -53, 59, 61, -67]);
        let cube = |offset, point: &[i64], coefficient| Cube {
            offset,
            point: point.iter().map(|&x| signed(x)).collect(),
            coefficient: signed(coefficient),
        };
        let forms = vec![
            vec![cube(0, &[2, 5, 7], 1)],              // matrix 2 x 4
            vec![cube(8, &[3], 7), cube(10, &[], 11)], // ragged norm, width 3
            vec![cube(20, &[13], 1)],                  // embedding token 2
            vec![cube(16, &[2, 3, 17], 1)],            // logits: SAME embedding
        ];
        // Independent contractions of the tiny operator outputs, not reads
        // through Cube::at or the prover's dense-form construction.
        let matrix_input = [24, -28, -30, 35];
        let matrix_outputs: Vec<i64> = weights[..8]
            .chunks_exact(4)
            .map(|row| row.iter().zip(matrix_input).map(|(&w, x)| i64::from(w) * x).sum())
            .collect();
        let logits: Vec<i64> = weights[16..24]
            .chunks_exact(2)
            .map(|row| -16 * i64::from(row[0]) + 17 * i64::from(row[1]))
            .collect();
        let targets = [
            -matrix_outputs[0] + 2 * matrix_outputs[1],
            -14 * i64::from(weights[8]) + 21 * i64::from(weights[9]) + 11 * i64::from(weights[10]),
            -12 * i64::from(weights[20]) + 13 * i64::from(weights[21]),
            2 * logits[0] - 3 * logits[1] - 4 * logits[2] + 6 * logits[3],
        ]
        .map(signed);
        let model = Model::new(n, weights).unwrap();
        let root = model.root.clone();
        let layout = *blake3::hash(b"tiny matrix[0,8);norm[8,11);tied-embedding[16,24)").as_bytes();
        let binding =
            ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: layout };
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-b12-linear-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ppath = directory.join("prover");
        let vpath = directory.join("verifier");
        let prover_path = ppath.clone();
        let required = 4 + 3 * matrix_config(n).unwrap().num_variables + 2;
        assert_eq!(required * 3, 108);
        let bad_required = required - 3; // one falsely claimed norm target
        assert_eq!(3 * (required + bad_required), 207);
        let field = |a: [u64; 3]| Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]));
        let u = field([0, 1, 0]);
        let context = |a: &Attempt| AttemptContext {
            session: [4; 32],
            capacity: a.capacity,
            slot: (a.ordinal - 1) as u8,
            predecessor: a.predecessor,
            nonce: [6; 32],
        };
        let start = move |corrections: &[Fp3]| {
            let mut fs = Fs::new(
                b"B12 tiny operator caller; not a Gemma trace",
                request_limit(&matrix_config(n).unwrap()) + 1,
            );
            record_values(&mut fs, 0x31, corrections);
            fs
        };
        let (mut pc, mut vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for channel in [&pc, &vc] {
            channel.set_read_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
            channel.set_write_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
        }
        // In-memory proof transport only; this test does not claim a wire
        // codec, a compiler-emitted GKR trace or a complete Gemma execution.
        let (send, receive) = mpsc::sync_channel(1);
        let (ack, wait_ack) = mpsc::sync_channel(1);
        let pforms = forms.clone();
        let prover = std::thread::spawn(move || {
            let mut store = Lifetime::install(&prover_path, binding).unwrap();
            let capacity = 3 * (required + bad_required);
            let mut pool = if fixed_run {
                store.prover_fixed_run(&mut pc, [4; 32], [5; 32], capacity)
            } else {
                store.prover(&mut pc, [4; 32], [5; 32], capacity)
            }
            .unwrap();
            for (slot, count) in [required, bad_required].into_iter().enumerate() {
                pool.attempt(count, |attempt, rows, _| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| {
                            let tag = |a: [u64; 4]| field([a[1], a[2], a[3]]);
                            Auth::new(
                                field([r[0][0], r[1][0], r[2][0]]),
                                tag(r[0]) + u * tag(r[1]) + u * u * tag(r[2]),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_iter();
                    let values =
                        if slot == 0 { targets.to_vec() } else { vec![targets[1] + Fp3::ONE] };
                    let current_forms = if slot == 0 { &pforms[..] } else { &pforms[1..2] };
                    let (corrections, original): (Vec<_>, Vec<_>) = values
                        .into_iter()
                        .map(|x| {
                            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), x);
                            (c.value(), a)
                        })
                        .unzip();
                    let mut fs = start(&corrections);
                    let (proof, digest) = prove(
                        &model,
                        context(&attempt),
                        layout,
                        current_forms,
                        &original,
                        &mut fs,
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert!(rows.next().is_none());
                    send.send((proof, corrections, digest)).unwrap();
                    let accepted =
                        wait_ack.recv_timeout(std::time::Duration::from_secs(40)).unwrap();
                    assert_eq!(accepted, if slot == 0 { *digest.as_bytes() } else { [0; 32] });
                    Ok(((), (slot == 0).then_some(accepted)))
                })
                .unwrap();
            }
            assert!(pool.attempt::<()>(1, |_, _, _| panic!("exhausted capacity reused")).is_err());
        });
        let mut store = Lifetime::install(&vpath, binding).unwrap();
        let capacity = 3 * (required + bad_required);
        let mut pool = if fixed_run {
            store.verifier_fixed_run(&mut vc, [4; 32], [5; 32], capacity)
        } else {
            store.verifier(&mut vc, [4; 32], [5; 32], capacity)
        }
        .unwrap();
        for (slot, count) in [required, bad_required].into_iter().enumerate() {
            let head = pool
                .attempt(count, |attempt, rows, delta| {
                    let mut rows = rows
                        .chunks_exact(3)
                        .map(|r| Key::new(field(r[0]) + u * field(r[1]) + u * u * field(r[2])))
                        .collect::<Vec<_>>()
                        .into_iter();
                    let delta = Fp3::ZERO - field(*delta.unwrap());
                    let (proof, corrections, digest) =
                        receive.recv_timeout(std::time::Duration::from_secs(40)).unwrap();
                    let original: Vec<_> = corrections
                        .iter()
                        .map(|&c| {
                            c7_fp3_transfer_verifier(
                                rows.next().unwrap(),
                                delta,
                                C7Fp3TransferCorrection::new(c),
                            )
                        })
                        .collect();
                    let attempt = context(&attempt);
                    if slot == 1 {
                        // Fresh rows, fresh proof, same root: the prover has validly
                        // authenticated norm(W)+1. Correct MACs alone must not pass.
                        let rejected = verify(
                            n,
                            &root,
                            attempt,
                            layout,
                            &forms[1..2],
                            &original,
                            &proof,
                            delta,
                            &mut start(&corrections),
                            &mut rows,
                        );
                        assert_eq!(rejected.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                        assert!(rows.len() > 0);
                        return Ok((None, None));
                    }
                    // Counterfactual verifier replays of ONE proof: no new prover
                    // emission or correlation use; these are rejection diagnostics.
                    let check =
                        |root: &C61Commitment, layout, forms: &[Vec<Cube>], keys: &[Key]| {
                            verify(
                                n,
                                root,
                                attempt,
                                layout,
                                forms,
                                keys,
                                &proof,
                                delta,
                                &mut start(&corrections),
                                &mut rows.clone(),
                            )
                        };
                    for index in 0..original.len() {
                        let mut detached = original.clone();
                        detached[index].k += delta; // another valid MAC, plaintext shifted by one
                        assert!(check(&root, layout, &forms, &detached).is_err());
                    }
                    let mut other = forms.clone();
                    other[2][0].offset = 18; // lookup switched to another embedding row
                    assert!(check(&root, layout, &other, &original).is_err());
                    assert!(check(&root, [7; 32], &forms, &original).is_err());
                    assert!(check(&C61Commitment::new(vec![[8; 32]]), layout, &forms, &original)
                        .is_err());
                    let checked = verify(
                        n,
                        &root,
                        attempt,
                        layout,
                        &forms,
                        &original,
                        &proof,
                        delta,
                        &mut start(&corrections),
                        &mut rows,
                    )
                    .map_err(io::Error::other)?;
                    assert_eq!(checked, digest);
                    assert!(rows.next().is_none());
                    Ok((Some(*checked.as_bytes()), Some(*checked.as_bytes())))
                })
                .unwrap();
            ack.send(head.unwrap_or([0; 32])).unwrap(); // head synced before acknowledgement
        } // the failed second attempt terminates this uninterrupted run
        prover.join().unwrap();
        drop(pool);
        drop(store);
        for path in [ppath, vpath] {
            if fixed_run {
                assert!(Lifetime::open(&path, binding).is_err());
            }
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}

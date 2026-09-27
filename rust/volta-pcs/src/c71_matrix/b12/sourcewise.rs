//! Bounded CPU reference for the sourcewise residual state. No dense fallback.
//! The canonical fast Eq/Pow reducer must refine these same state transitions.
use super::replay::{inverse_series, multiply_polynomials};
use super::*;
use p3_dft::TwoAdicSubgroupDft;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

pub(in crate::c71_matrix) type Getter = Arc<dyn Fn(usize) -> E + Send + Sync>;

const POWER_BLOCK_CAP: usize = 256;

struct PowerBlocks {
    size: usize,
    denominators: Vec<Vec<Vec<E>>>,
    inverse_spectrum: Vec<E>,
    advances: Vec<E>,
    dft: Radix2DFTSmallBatch<Goldilocks>,
}

impl PowerBlocks {
    fn new(terms: &[(E, E)], size: usize) -> Self {
        assert!(size.is_power_of_two() && size <= POWER_BLOCK_CAP);
        let dft = Radix2DFTSmallBatch::default();
        let mut leaves: Vec<_> = terms.iter().map(|&(point, _)| vec![E::ONE, -point]).collect();
        leaves.resize(terms.len().next_power_of_two(), vec![E::ONE]);
        let mut denominators = vec![leaves];
        while denominators.last().unwrap().len() > 1 {
            let level = denominators
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let mut product = multiply_polynomials(pair[0].clone(), pair[1].clone(), &dft);
                    product.truncate(size);
                    product
                })
                .collect();
            denominators.push(level);
        }
        let mut inverse = inverse_series(&denominators.last().unwrap()[0], size, &dft);
        inverse.resize(2 * size, E::ZERO);
        Self {
            size,
            denominators,
            inverse_spectrum: dft.dft_algebra(inverse),
            advances: terms.iter().map(|&(point, _)| point.exp_u64(size as u64)).collect(),
            dft,
        }
    }

    fn next(&self, amplitudes: &mut [E]) -> Vec<E> {
        assert_eq!(amplitudes.len(), self.advances.len());
        let mut numerators: Vec<_> = amplitudes.iter().map(|&scale| vec![scale]).collect();
        numerators.resize(self.denominators[0].len(), vec![E::ZERO]);
        for level in &self.denominators[..self.denominators.len() - 1] {
            numerators = numerators
                .chunks_exact(2)
                .zip(level.chunks_exact(2))
                .map(|(pair, factors)| {
                    let mut left =
                        multiply_polynomials(pair[0].clone(), factors[1].clone(), &self.dft);
                    let right =
                        multiply_polynomials(pair[1].clone(), factors[0].clone(), &self.dft);
                    left.resize(left.len().max(right.len()).min(self.size), E::ZERO);
                    for (value, contribution) in left.iter_mut().zip(right) {
                        *value += contribution;
                    }
                    left
                })
                .collect();
        }
        let mut numerator = numerators.pop().unwrap();
        numerator.resize(2 * self.size, E::ZERO);
        let mut spectrum = self.dft.dft_algebra(numerator);
        for (value, &factor) in spectrum.iter_mut().zip(&self.inverse_spectrum) {
            *value *= factor;
        }
        let mut values = self.dft.idft_algebra(spectrum);
        values.truncate(self.size);
        for (amplitude, &advance) in amplitudes.iter_mut().zip(&self.advances) {
            *amplitude *= advance;
        }
        values
    }
}

fn equality(point: &[E], index: usize) -> E {
    point.iter().enumerate().fold(E::ONE, |v, (bit, &r)| {
        v * if index >> (point.len() - 1 - bit) & 1 == 1 { r } else { E::ONE - r }
    })
}

fn equality_lookup(point: &[E], scale: E) -> impl Fn(usize) -> E {
    let split = point.len() / 2;
    let prefix = Poly::new_from_point(&point[..split], scale);
    let suffix = Poly::new_from_point(&point[split..], E::ONE);
    let suffix_bits = point.len() - split;
    move |index| {
        prefix.as_slice()[index >> suffix_bits]
            * suffix.as_slice()[index & ((1 << suffix_bits) - 1)]
    }
}

// One retained allocation. Logical folds never claim to free Vec capacity.
// Only a consumed replay handle can release a committed generation.
struct RetainedData {
    fallback: Option<Getter>,
    values: Option<Vec<E>>,
    variables: usize,
    applied: Vec<E>,
    current: u8, // 0 unregistered, 1 live, 2 released
    successor: Option<(Vec<E>, u8)>,
    fold_interpolations: u64,
}
struct Retained {
    data: RwLock<RetainedData>,
    reads: Arc<AtomicU64>,
}
pub(super) struct Lease {
    stage: Arc<Retained>,
    prefix: Vec<E>,
}
impl Lease {
    pub(super) fn release(self) -> Result<(), String> {
        let mut data = self.stage.data.write().map_err(|_| "retained lock poisoned")?;
        let state = if self.prefix == data.applied {
            &mut data.current
        } else {
            let (prefix, state) = data.successor.as_mut().ok_or("unknown successor release")?;
            if *prefix != self.prefix {
                return Err("different successor release".into());
            }
            state
        };
        if *state != 1 {
            return Err("duplicate or unregistered retained release".into());
        }
        *state = 2;
        Ok(())
    }
}
impl Retained {
    fn getter(self: &Arc<Self>, prefix: Vec<E>) -> Getter {
        let stage = self.clone();
        Arc::new(move |i| {
            let data = stage.data.read().expect("retained lock poisoned");
            assert!(
                prefix.len() <= data.variables && prefix.starts_with(&data.applied),
                "stale, overlong or different retained getter"
            );
            let suffix = &prefix[data.applied.len()..];
            let variables = data.variables - prefix.len();
            assert!(i < 1 << variables);
            match &data.values {
                Some(values) => {
                    stage.reads.fetch_add(1 << suffix.len(), Ordering::Relaxed);
                    (0..1 << suffix.len())
                        .map(|j| equality(suffix, j) * values[(j << variables) | i])
                        .sum()
                }
                None => {
                    let fallback = data.fallback.as_ref().expect("retained source unavailable");
                    (0..1 << suffix.len())
                        .map(|j| equality(suffix, j) * fallback((j << variables) | i))
                        .sum()
                }
            }
        })
    }
    fn lease(self: &Arc<Self>, prefix: &[E]) -> Result<Lease, String> {
        let mut data = self.data.write().map_err(|_| "retained lock poisoned")?;
        if prefix.len() > data.variables {
            return Err("overlong retained prefix".into());
        }
        if prefix == data.applied {
            if data.current != 0 {
                return Err("retained root registered twice".into());
            }
            data.current = 1;
        } else {
            if !prefix.starts_with(&data.applied) || data.successor.is_some() {
                return Err("retained successor differs or registered twice".into());
            }
            data.successor = Some((prefix.to_vec(), 1));
        }
        Ok(Lease { stage: self.clone(), prefix: prefix.to_vec() })
    }
    fn promote(&self, prefix: &[E]) -> Result<(), String> {
        let mut data = self.data.write().map_err(|_| "retained lock poisoned")?;
        if prefix.len() > data.variables || prefix == data.applied {
            return Err("overlong or non-advancing retained promotion".into());
        }
        if data.current != 2
            || data
                .successor
                .as_ref()
                .map(|(expected, state)| expected.as_slice() == prefix && *state == 1)
                != Some(true)
            || !prefix.starts_with(&data.applied)
        {
            return Err("retained predecessor not released or successor not fixed".into());
        }
        let done = data.applied.len();
        let values = data.values.as_mut().ok_or("retained values not materialized")?;
        let mut interpolations = 0;
        for &r in &prefix[done..] {
            let half = values.len() / 2;
            for i in 0..half {
                let a = values[i];
                values[i] = a + r * (values[i + half] - a);
            }
            values.truncate(half); // capacity stays reserved until State is dropped
            interpolations += half as u64;
        }
        data.fold_interpolations += interpolations;
        data.applied = prefix.to_vec();
        data.current = 1;
        data.successor = None;
        Ok(())
    }
}

/// Root-owned immutable original getter; folds are transcript-fixed descriptors.
pub(super) struct State {
    source: Getter,
    dimension: usize,
    prefix: Vec<E>,
    eq_point: Vec<E>,
    eq_scale: E,
    powers: Vec<(E, E)>,
    prefix_acc: Vec<E>,
    prefix_remaining: usize,
    sum: E,
    retain_first: bool,
    retained_bytes: usize,
    pending_retention: Option<(Getter, Vec<E>, usize)>,
    retained: Option<Arc<Retained>>,
    retained_reads: Arc<AtomicU64>,
    pub(super) source_reads: Arc<AtomicU64>,
}

impl State {
    pub(super) fn new(
        source: Getter,
        point: &[E],
        first_fold: usize,
        target: E,
        retain_first: bool,
    ) -> Result<Self, String> {
        // This executable comparison is deliberately bounded. The full resource
        // ledger must price the accelerated Eq/Pow adapter before lifting it.
        if !(1..=16).contains(&point.len()) || first_fold == 0 || first_fold > point.len() {
            return Err("bounded sourcewise geometry".into());
        }
        let source_reads = Arc::new(AtomicU64::new(0));
        let reads = source_reads.clone();
        let source: Getter = Arc::new(move |i| {
            reads.fetch_add(1, Ordering::Relaxed);
            source(i)
        });
        let mut prefix_acc = vec![E::ZERO; 1 << first_fold];
        let suffix = point.len() - first_fold;
        let suffix_equality = equality_lookup(&point[first_fold..], E::ONE);
        for i in 0..1 << point.len() {
            prefix_acc[i >> suffix] += source(i) * suffix_equality(i & ((1 << suffix) - 1));
        }
        let prefix_equality = equality_lookup(&point[..first_fold], E::ONE);
        let sum = prefix_acc
            .iter()
            .enumerate()
            .map(|(index, &value)| value * prefix_equality(index))
            .sum();
        if sum != target {
            return Err("sourcewise original claim differs".into());
        }
        Ok(Self {
            source,
            dimension: point.len(),
            prefix: Vec::new(),
            eq_point: point.to_vec(),
            eq_scale: E::ONE,
            powers: Vec::new(),
            prefix_acc,
            prefix_remaining: first_fold,
            sum,
            source_reads,
            retain_first,
            retained_bytes: 0,
            pending_retention: None,
            retained: None,
            retained_reads: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(super) fn getter(&self) -> Getter {
        if let Some(stage) = &self.retained {
            return stage.getter(self.prefix.clone());
        }
        let (source, prefix, n) = (self.source.clone(), self.prefix.clone(), self.num_variables());
        let prefix_equality = equality_lookup(&prefix, E::ONE);
        Arc::new(move |i| {
            assert!(i < 1 << n);
            (0..1 << prefix.len())
                .map(|index| prefix_equality(index) * source((index << n) | i))
                .sum()
        })
    }

    // Register only after Tree::commit succeeds: errors cannot leave a live lease.
    pub(super) fn replay_lease(&self) -> Result<Option<Lease>, String> {
        self.retained.as_ref().map(|stage| stage.lease(&self.prefix)).transpose()
    }

    fn weight(&self, index: usize) -> E {
        self.eq_scale * equality(&self.eq_point, index)
            + self
                .powers
                .iter()
                .map(|&(point, scale)| scale * point.exp_u64(index as u64))
                .sum::<E>()
    }

    pub(super) fn add_powers(&mut self, terms: &[(E, E)]) -> Result<(), String> {
        if self.prefix_remaining != 0 {
            return Err("power claims before first fold boundary".into());
        }
        // Called only after the predecessor's opening/release in WHIR.
        // The already-committed S1 oracle shares this immutable-value slot.
        if let Some((source, prefix, n)) = self.pending_retention.take() {
            // Read original A in address order, evaluating each window once.
            // This is the same j-ordered sum for every S1 cell as getter().
            let mut values = vec![E::ZERO; 1 << n];
            for j in 0..1 << prefix.len() {
                let weight = equality(&prefix, j);
                for (i, value) in values.iter_mut().enumerate() {
                    *value += weight * source((j << n) | i);
                }
            }
            self.retained_bytes = values.capacity() * std::mem::size_of::<E>();
            let stage = self.retained.as_ref().ok_or("retained holder missing")?;
            let mut data = stage.data.write().map_err(|_| "retained lock poisoned")?;
            if data.values.is_some() {
                return Err("S1 retained twice".into());
            }
            data.values = Some(values);
            data.fallback = None; // original A/cuts no longer captured by this stage
        } else if let Some(stage) = &self.retained {
            stage.promote(&self.prefix)?;
        }
        let get = self.getter();
        let length = 1 << self.num_variables();
        let size = POWER_BLOCK_CAP.min(length);
        let powers = PowerBlocks::new(terms, size);
        let mut amplitudes: Vec<_> = terms.iter().map(|&(_, scale)| scale).collect();
        for start in (0..length).step_by(size) {
            for (offset, delta) in powers.next(&mut amplitudes).into_iter().enumerate() {
                self.sum += get(start + offset) * delta;
            }
        }
        self.powers.extend_from_slice(terms);
        Ok(())
    }

    pub(super) fn named_bytes(&self) -> usize {
        self.retained_bytes
            + 24 * (self.prefix.capacity() + self.eq_point.capacity() + self.prefix_acc.capacity())
            + 48 * self.powers.capacity()
    }
}

impl ResidualSumcheckProver<Goldilocks, E> for State {
    type Error = String;
    fn claimed_sum(&self) -> E {
        self.sum
    }
    fn num_variables(&self) -> usize {
        self.dimension - self.prefix.len()
    }
    fn evals(&self) -> Result<Poly<E>, String> {
        if self.num_variables() > 6 {
            return Err("dense source evals fallback forbidden".into());
        }
        let get = self.getter();
        Ok(Poly::new((0..1 << self.num_variables()).map(|i| get(i)).collect()))
    }
    fn weights(&self) -> Result<Poly<E>, String> {
        if self.num_variables() > 6 {
            return Err("dense source weights fallback forbidden".into());
        }
        Ok(Poly::new((0..1 << self.num_variables()).map(|i| self.weight(i)).collect()))
    }
    fn eval(&self, point: &Point<E>) -> Result<E, String> {
        if point.num_variables() != self.num_variables() {
            return Err("sourcewise MLE point".into());
        }
        let get = self.getter();
        let equality = equality_lookup(point.as_slice(), E::ONE);
        Ok((0..1 << self.num_variables()).map(|index| get(index) * equality(index)).sum())
    }
    fn round_coefficients(&self) -> Result<(E, E), String> {
        if self.num_variables() == 0 {
            return Err("sourcewise exhausted".into());
        }
        let (mut c0, mut c2) = (E::ZERO, E::ZERO);
        if self.prefix_remaining > 0 {
            let half = self.prefix_acc.len() / 2;
            let equality = equality_lookup(&self.eq_point[..self.prefix_remaining], self.eq_scale);
            for i in 0..half {
                let (a, b) = (self.prefix_acc[i], self.prefix_acc[i + half]);
                let x = equality(i);
                let y = equality(i + half);
                c0 += a * x;
                c2 += (b - a) * (y - x);
            }
        } else {
            let get = self.getter();
            let half = 1 << (self.num_variables() - 1);
            let equality = equality_lookup(&self.eq_point, self.eq_scale);
            let size = POWER_BLOCK_CAP.min(half);
            let powers = PowerBlocks::new(&self.powers, size);
            let mut low: Vec<_> = self.powers.iter().map(|&(_, scale)| scale).collect();
            let mut high: Vec<_> = self
                .powers
                .iter()
                .map(|&(point, scale)| scale * point.exp_u64(half as u64))
                .collect();
            for start in (0..half).step_by(size) {
                let left_powers = powers.next(&mut low);
                let right_powers = powers.next(&mut high);
                for offset in 0..size {
                    let index = start + offset;
                    let (left, right) = (get(index), get(index + half));
                    let left_weight = equality(index) + left_powers[offset];
                    let right_weight = equality(index + half) + right_powers[offset];
                    c0 += left * left_weight;
                    c2 += (right - left) * (right_weight - left_weight);
                }
            }
        }
        Ok((c0, c2))
    }
    fn fold_round_with_coefficients(&mut self, c0: E, c2: E, r: E) -> Result<(), String> {
        if self.num_variables() == 0 {
            return Err("sourcewise exhausted".into());
        }
        let half = 1 << (self.num_variables() - 1);
        self.sum = c0 * (E::ONE - r) + (self.sum - c0) * r + c2 * r * (r - E::ONE);
        let a = self.eq_point.remove(0);
        self.eq_scale *= (E::ONE - a) * (E::ONE - r) + a * r;
        for (point, scale) in &mut self.powers {
            *scale *= E::ONE - r + r * point.exp_u64(half as u64);
        }
        if self.prefix_remaining > 0 {
            let half = self.prefix_acc.len() / 2;
            for i in 0..half {
                let a = self.prefix_acc[i];
                let b = self.prefix_acc[i + half];
                self.prefix_acc[i] = a + r * (b - a);
            }
            self.prefix_acc.truncate(half);
            self.prefix_remaining -= 1;
            if self.prefix_remaining == 0 {
                self.prefix_acc = Vec::new();
            }
        }
        self.prefix.push(r);
        if self.retain_first && self.prefix_remaining == 0 {
            // Bind S1 now, but allocate only after the original A opening.
            // The frozen getter is shared with the S1 root, so subsequent
            // queries see identical values from the one retained allocation.
            let get = self.getter();
            let n = self.num_variables();
            let original_source = self.source.clone();
            let original_prefix = self.prefix.clone();
            self.retained = Some(Arc::new(Retained {
                data: RwLock::new(RetainedData {
                    fallback: Some(get),
                    values: None,
                    variables: n,
                    applied: Vec::new(),
                    current: 0,
                    successor: None,
                    fold_interpolations: 0,
                }),
                reads: self.retained_reads.clone(),
            }));
            self.source = Arc::new(|_| panic!("original source replaced by retained stage"));
            self.pending_retention = Some((original_source, original_prefix, n));
            self.dimension = n;
            self.prefix.clear();
            self.retain_first = false;
        }
        Ok(())
    }
    fn scale_weights_and_claim(&mut self, scale: E) -> Result<(), String> {
        self.eq_scale *= scale;
        self.sum *= scale;
        for (_, s) in &mut self.powers {
            *s *= scale;
        }
        Ok(())
    }
    fn accumulate_claim(&mut self, _: &[E], _: E) -> Result<(), String> {
        Err("dense source weight delta fallback forbidden".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_sumcheck_c61::{
        product_polynomial::ProductPolynomial,
        strategy::{SumcheckProver, VariableOrder},
    };

    #[test]
    fn c71_b12_retained_lifecycle_rejects_reordering_and_preserves_storage() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let keepalive = Arc::new(());
        let weak = Arc::downgrade(&keepalive);
        let captured = keepalive.clone();
        let fallback: Getter = Arc::new(move |i| {
            let _keep_source_alive = &captured;
            E::from(Goldilocks::new(i as u64 + 1))
        });
        drop(keepalive);

        let mut values = Vec::with_capacity(16);
        values.extend((0..8).map(|i| E::from(Goldilocks::new(i + 1))));
        let reserved = values.capacity();
        let stage = Arc::new(Retained {
            data: RwLock::new(RetainedData {
                fallback: Some(fallback),
                values: None,
                variables: 3,
                applied: Vec::new(),
                current: 0,
                successor: None,
                fold_interpolations: 0,
            }),
            reads: Arc::new(AtomicU64::new(0)),
        });

        // This is the materialization transition in add_powers: the immutable
        // source capture is gone once the retained vector becomes authoritative.
        {
            let mut data = stage.data.write().unwrap();
            data.values = Some(values);
            data.fallback = None;
        }
        assert!(weak.upgrade().is_none());

        assert!(stage.lease(&[E::ONE; 4]).is_err());
        assert!(stage.promote(&[E::ONE; 4]).is_err());
        let overlong = stage.getter(vec![E::ONE; 4]);
        assert!(catch_unwind(AssertUnwindSafe(|| overlong(0))).is_err());
        let s1 = stage.lease(&[]).unwrap();
        assert!(stage.lease(&[]).is_err());
        assert!(stage.promote(&[]).is_err());
        let duplicate_s1 = Lease { stage: stage.clone(), prefix: Vec::new() };
        let stale_s1_getter = stage.getter(Vec::new());

        let r = E::new([Goldilocks::new(5), Goldilocks::new(7), Goldilocks::new(11)]);
        let s2_prefix = vec![r];
        let s2_getter = stage.getter(s2_prefix.clone());
        let before: Vec<_> = (0..4).map(|i| s2_getter(i)).collect();
        let s2 = stage.lease(&s2_prefix).unwrap();

        assert!(stage.promote(&s2_prefix).is_err()); // predecessor still live
        s1.release().unwrap();
        assert!(duplicate_s1.release().is_err());
        stage.promote(&s2_prefix).unwrap();

        let after: Vec<_> = (0..4).map(|i| s2_getter(i)).collect();
        assert_eq!(before, after);
        let data = stage.data.read().unwrap();
        assert_eq!(data.values.as_ref().unwrap().len(), 4);
        assert_eq!(data.values.as_ref().unwrap().capacity(), reserved);
        drop(data);

        assert!(catch_unwind(AssertUnwindSafe(|| stale_s1_getter(0))).is_err());
        s2.release().unwrap();
    }

    #[test]
    fn c71_b12_rational_power_blocks_match_direct_extension_powers() {
        for count in [0, 1, 3, 5, 17, 513] {
            let terms: Vec<_> = (0..count)
                .map(|index| {
                    let point = match index % 5 {
                        0 => E::ZERO,
                        1 | 2 => E::ONE,
                        _ => E::new([
                            Goldilocks::new(index as u64 + 3),
                            Goldilocks::new(7),
                            Goldilocks::new(11),
                        ]),
                    };
                    let scale = if index % 4 == 3 {
                        E::ZERO
                    } else {
                        E::from(Goldilocks::new(index as u64 + 13))
                    };
                    (point, scale)
                })
                .collect();
            for size in [1, 2, 8, 32, POWER_BLOCK_CAP] {
                let blocks = PowerBlocks::new(&terms, size);
                let mut amplitudes: Vec<_> = terms.iter().map(|&(_, scale)| scale).collect();
                for block in 0..3 {
                    let expected: Vec<E> = (0..size)
                        .map(|offset| {
                            terms
                                .iter()
                                .map(|&(point, scale)| {
                                    scale * point.exp_u64((block * size + offset) as u64)
                                })
                                .sum()
                        })
                        .collect();
                    assert_eq!(blocks.next(&mut amplitudes), expected);
                }
            }
        }
        println!("C71_RATIONAL_POW base_and_extension=true blocks=3 block_cap=256 canonical_credit=false");
    }

    #[test]
    fn c71_b12_sourcewise_adaptive_rounds_match_dense_and_forbid_fallbacks() {
        for (dimension, first, retain) in
            [(10, 1, false), (12, 1, false), (12, 7, false), (12, 7, true)]
        {
            let source: Getter =
                Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
            let point: Vec<_> = (0..dimension)
                .map(|i| match i % 5 {
                    0 => E::ZERO,
                    1 => E::ONE,
                    _ => E::new([
                        Goldilocks::new(i as u64 + 3),
                        Goldilocks::new(7),
                        Goldilocks::new(11),
                    ]),
                })
                .collect();
            let values: Vec<_> = (0..1 << dimension).map(|i| source(i)).collect();
            let weights: Vec<_> = (0..1 << dimension).map(|i| equality(&point, i)).collect();
            let target = values.iter().zip(&weights).map(|(&x, &y)| x * y).sum();
            let mut state = State::new(source, &point, first, target, retain).unwrap();
            let mut dense: SumcheckProver<Goldilocks, E> = SumcheckProver::new(
                ProductPolynomial::new_unpacked(
                    VariableOrder::Prefix,
                    Poly::new(values),
                    Poly::new(weights),
                ),
                target,
            );
            assert!(state.evals().is_err());
            assert!(state.weights().is_err());
            assert!(state.accumulate_claim(&[], E::ZERO).is_err());
            for round in 0..dimension {
                if round == first {
                    let frozen = state.getter();
                    let before: Vec<_> =
                        (0..1 << state.num_variables()).map(|i| frozen(i)).collect();
                    assert_eq!(state.retained_bytes, 0);
                    let terms = [
                        (E::ZERO, E::from(Goldilocks::new(17))),
                        (E::ONE, E::from(Goldilocks::new(23))),
                        (E::from(Goldilocks::new(29)), E::ZERO),
                        (E::from(Goldilocks::new(19)), E::from(Goldilocks::new(5))),
                        (
                            E::new([Goldilocks::new(3), Goldilocks::new(2), Goldilocks::new(1)]),
                            E::from(Goldilocks::new(13)),
                        ),
                    ];
                    state.add_powers(&terms).unwrap();
                    assert_eq!(
                        before,
                        (0..1 << state.num_variables()).map(|i| frozen(i)).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        state.retained_bytes,
                        if retain { 24 << (dimension - first) } else { 0 }
                    );
                    let delta: Vec<_> = (0..1 << state.num_variables())
                        .map(|i| terms.iter().map(|&(p, c)| c * p.exp_u64(i as u64)).sum())
                        .collect();
                    let claim =
                        dense.evals().as_slice().iter().zip(&delta).map(|(&a, &b)| a * b).sum();
                    ResidualSumcheckProver::accumulate_claim(&mut dense, &delta, claim).unwrap();
                    let scale = E::from(Goldilocks::new(31));
                    state.scale_weights_and_claim(scale).unwrap();
                    ResidualSumcheckProver::scale_weights_and_claim(&mut dense, scale).unwrap();
                }
                let coefficients = state.round_coefficients().unwrap();
                assert_eq!(
                    coefficients,
                    ResidualSumcheckProver::round_coefficients(&dense).unwrap()
                );
                let r = E::new([
                    Goldilocks::new(37 + round as u64),
                    Goldilocks::new(17),
                    Goldilocks::new(5),
                ]);
                state.fold_round_with_coefficients(coefficients.0, coefficients.1, r).unwrap();
                ResidualSumcheckProver::fold_round_with_coefficients(
                    &mut dense,
                    coefficients.0,
                    coefficients.1,
                    r,
                )
                .unwrap();
                assert_eq!(state.claimed_sum(), dense.claimed_sum());
            }
            assert_eq!(state.evals().unwrap(), dense.evals());
            assert_eq!(state.weights().unwrap(), dense.weights());
            eprintln!("sourcewise dimension={dimension} first={first} original_reads={} named_final_bytes={}",state.source_reads.load(Ordering::Relaxed),state.named_bytes());
        }
    }
}

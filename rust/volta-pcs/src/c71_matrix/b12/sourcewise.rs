//! Bounded CPU reference for the sourcewise residual state. No dense fallback.
//! The canonical fast Eq/Pow reducer must refine these same state transitions.
use super::*;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};

pub(super) type Getter = Arc<dyn Fn(usize) -> E + Send + Sync>;

fn equality(point: &[E], index: usize) -> E {
    point.iter().enumerate().fold(E::ONE, |v, (bit, &r)| {
        v * if index >> (point.len() - 1 - bit) & 1 == 1 { r } else { E::ONE - r }
    })
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
    pending_retention: Option<(Getter, Arc<OnceLock<Arc<Vec<E>>>>, Vec<E>, usize)>,
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
        for i in 0..1 << point.len() {
            prefix_acc[i >> suffix] +=
                source(i) * equality(&point[first_fold..], i & ((1 << suffix) - 1));
        }
        let sum = prefix_acc
            .iter()
            .enumerate()
            .map(|(i, &v)| v * equality(&point[..first_fold], i))
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
            retained_reads: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(super) fn getter(&self) -> Getter {
        let (source, prefix, n) = (self.source.clone(), self.prefix.clone(), self.num_variables());
        Arc::new(move |i| {
            assert!(i < 1 << n);
            (0..1 << prefix.len()).map(|j| equality(&prefix, j) * source((j << n) | i)).sum()
        })
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
        if let Some((source, slot, prefix, n)) = self.pending_retention.take() {
            // Read original A in address order, evaluating each window once.
            // This is the same j-ordered sum for every S1 cell as getter().
            let mut values = vec![E::ZERO; 1 << n];
            for j in 0..1 << prefix.len() {
                let weight = equality(&prefix, j);
                for (i, value) in values.iter_mut().enumerate() {
                    *value += weight * source((j << n) | i);
                }
            }
            // Move the Vec header; do not copy a full temporary into Arc<[E]>.
            let values = Arc::new(values);
            self.retained_bytes = values.capacity() * std::mem::size_of::<E>();
            slot.set(values).map_err(|_| "S1 retained twice")?;
        }
        let get = self.getter();
        for i in 0..1 << self.num_variables() {
            let delta: E =
                terms.iter().map(|&(point, scale)| scale * point.exp_u64(i as u64)).sum();
            self.sum += get(i) * delta;
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
        Ok((0..1 << self.num_variables()).map(|i| get(i) * equality(point.as_slice(), i)).sum())
    }
    fn round_coefficients(&self) -> Result<(E, E), String> {
        if self.num_variables() == 0 {
            return Err("sourcewise exhausted".into());
        }
        let (mut c0, mut c2) = (E::ZERO, E::ZERO);
        if self.prefix_remaining > 0 {
            let half = self.prefix_acc.len() / 2;
            for i in 0..half {
                let (a, b) = (self.prefix_acc[i], self.prefix_acc[i + half]);
                let x = self.eq_scale * equality(&self.eq_point[..self.prefix_remaining], i);
                let y = self.eq_scale * equality(&self.eq_point[..self.prefix_remaining], i + half);
                c0 += a * x;
                c2 += (b - a) * (y - x);
            }
        } else {
            let get = self.getter();
            let half = 1 << (self.num_variables() - 1);
            for i in 0..half {
                let (a, b, x, y) = (get(i), get(i + half), self.weight(i), self.weight(i + half));
                c0 += a * x;
                c2 += (b - a) * (y - x);
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
            let slot = Arc::new(OnceLock::<Arc<Vec<E>>>::new());
            let shared = slot.clone();
            let fallback = get.clone();
            let reads = self.retained_reads.clone();
            let original_source = self.source.clone();
            let original_prefix = self.prefix.clone();
            self.source = Arc::new(move |i| match shared.get() {
                Some(values) => {
                    reads.fetch_add(1, Ordering::Relaxed);
                    values[i]
                }
                None => fallback(i),
            });
            self.pending_retention = Some((original_source, slot, original_prefix, n));
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
    fn c71_b12_sourcewise_adaptive_rounds_match_dense_and_forbid_fallbacks() {
        for (dimension, first, retain) in [(10, 1, false), (12, 7, false), (12, 7, true)] {
            let source: Getter =
                Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
            let point: Vec<_> = (0..dimension)
                .map(|i| {
                    E::new([Goldilocks::new(i as u64 + 3), Goldilocks::new(7), Goldilocks::new(11)])
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

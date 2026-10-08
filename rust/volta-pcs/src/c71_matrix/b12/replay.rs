//! Bounded end-to-end sourcewise WHIR refinement against the native transcript.
use super::*;
use super::{
    replay_tree::Tree,
    sourcewise::{power_lookup, Getter, Lease, State},
};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
#[cfg(test)]
use p3_matrix::Matrix;
use p3_matrix::{dense::DenseMatrix, extension::FlatMatrixView};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use p3_whir_c61::pcs::{
    proof::{QueryOpenings, SharedProofOpening},
    zk::{
        BaseCaseZkProof, ZkRoundProof, ZkWhirInitialMessage, ZkWhirOracleCommitter,
        ZkWhirReplayHandle,
    },
};
use rand_010::RngExt;
use std::sync::{Arc, Mutex};
use crate::c71_matrix::progress::Span;
use serde_json::json;
use crate::c71_matrix::range::windowed::native as device;

/// The installation's same sealed W/owner and trusted original public layout.
/// This carries no challenge, correlation or numerical-producer interface.
pub(in crate::c71_matrix) struct NativeWeights {
    pub runtime: Arc<Mutex<device::Runtime>>,
    pub weights: Arc<Vec<i16>>,
    pub layout: [u8; 32],
    pub tiles: Vec<device::WeightTile>,
}

/// Trusted immutable source: emit each live coefficient exactly once, in any
/// order, with the same value as the original getter. No PCS coins are exposed.
pub(in crate::c71_matrix) type BaseScan = Arc<
    dyn Fn(&mut dyn FnMut(usize, Goldilocks) -> Result<(), String>) -> Result<(), String>
        + Send
        + Sync,
>;
/// Original A bytes only, before public flat padding or private PCS pads.
/// Like BaseScan, this trusted reader must agree with the immutable getter.
pub(in crate::c71_matrix) type ByteWindow =
    Arc<dyn Fn(usize, &mut [u8]) -> Result<(), String> + Send + Sync>;
const QUERY_BYTE_WINDOW: usize = 1 << 28;
fn limbs(x: &E) -> &[Goldilocks] {
    <E as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(x)
}
fn base_coefficient(value: E) -> Goldilocks {
    let coordinates = limbs(&value);
    assert_eq!(&coordinates[1..], &[Goldilocks::ZERO; 2], "non-base replay coefficient");
    coordinates[0]
}
enum Pads {
    Base(Arc<[Goldilocks]>),
    Extension(Vec<E>),
}
impl Pads {
    fn len(&self) -> usize {
        match self {
            Self::Base(v) => v.len(),
            Self::Extension(v) => v.len(),
        }
    }
    fn get(&self, i: usize) -> E {
        match self {
            Self::Base(v) => E::from(v[i]),
            Self::Extension(v) => v[i],
        }
    }
}
struct Code {
    get: Getter,
    scan: Option<BaseScan>,
    window: Option<ByteWindow>,
    len: usize,
    live: usize,
    width: usize,
    height: usize,
    pads: Pads,
}

pub(super) fn multiply_polynomials<Coefficient: p3_field::ExtensionField<Goldilocks>>(
    mut left: Vec<Coefficient>,
    mut right: Vec<Coefficient>,
    dft: &Radix2DFTSmallBatch<Goldilocks>,
) -> Vec<Coefficient> {
    let length = left.len() + right.len() - 1;
    let size = length.next_power_of_two();
    left.resize(size, Coefficient::ZERO);
    right.resize(size, Coefficient::ZERO);
    let mut spectrum = dft.dft_algebra(left);
    for (value, factor) in spectrum.iter_mut().zip(dft.dft_algebra(right)) {
        *value *= factor;
    }
    let mut product = dft.idft_algebra(spectrum);
    product.truncate(length);
    product
}

pub(super) fn inverse_series<Coefficient: p3_field::ExtensionField<Goldilocks>>(
    series: &[Coefficient],
    length: usize,
    dft: &Radix2DFTSmallBatch<Goldilocks>,
) -> Vec<Coefficient> {
    assert!(length.is_power_of_two());
    assert_eq!(series[0], Coefficient::ONE);
    let mut inverse = vec![Coefficient::ONE];
    while inverse.len() < length {
        let next = 2 * inverse.len();
        let mut prefix = series[..series.len().min(next)].to_vec();
        prefix.resize(next, Coefficient::ZERO);
        let mut correction = multiply_polynomials(prefix, inverse.clone(), dft);
        correction.truncate(next);
        for value in &mut correction {
            *value = -*value;
        }
        correction[0] += Coefficient::ONE + Coefficient::ONE;
        inverse = multiply_polynomials(inverse, correction, dft);
        inverse.truncate(next);
    }
    inverse
}

struct QueryFactors<'a> {
    inverse: &'a [Goldilocks],
    modulus: &'a [Goldilocks],
}

struct QueryLevel {
    inverse: Vec<Goldilocks>,
    modulus: Vec<Goldilocks>,
    factor_len: usize,
}
impl QueryLevel {
    fn len(&self) -> usize {
        self.inverse.len() / self.factor_len
    }
    fn factor(&self, index: usize) -> QueryFactors<'_> {
        let range = index * self.factor_len..(index + 1) * self.factor_len;
        QueryFactors { inverse: &self.inverse[range.clone()], modulus: &self.modulus[range] }
    }
}

fn query_tree(points: &[Goldilocks], dft: &Radix2DFTSmallBatch<Goldilocks>) -> Vec<QueryLevel> {
    assert!(points.len().is_power_of_two());
    // Two contiguous spectra per level; no allocation retained per leaf.
    let mut level: Vec<_> = points.iter().flat_map(|&point| [-point, Goldilocks::ONE]).collect();
    let mut degree = 1;
    let mut factors = Vec::new();
    loop {
        let mut spectra = QueryLevel {
            inverse: Vec::with_capacity(2 * points.len()),
            modulus: Vec::with_capacity(2 * points.len()),
            factor_len: 2 * degree,
        };
        for polynomial in level.chunks_exact(degree + 1) {
            let reverse: Vec<_> = polynomial.iter().rev().copied().collect();
            let mut inverse = inverse_series(&reverse, degree, dft);
            inverse.resize(2 * degree, Goldilocks::ZERO);
            let mut modulus = polynomial.to_vec();
            modulus.resize(2 * degree, Goldilocks::ZERO);
            spectra.inverse.extend(dft.dft(inverse));
            spectra.modulus.extend(dft.dft(modulus));
        }
        factors.push(spectra);
        if degree == points.len() {
            return factors;
        }
        let mut next = Vec::with_capacity(points.len() + points.len() / (2 * degree));
        for pair in level.chunks_exact(2 * (degree + 1)) {
            next.extend(multiply_polynomials(
                pair[..degree + 1].to_vec(),
                pair[degree + 1..].to_vec(),
                dft,
            ));
        }
        level = next;
        degree *= 2;
    }
}

impl QueryFactors<'_> {
    fn remainder<Coefficient: p3_field::ExtensionField<Goldilocks>>(
        &self,
        high: &[Coefficient],
        low: impl Fn(usize) -> Coefficient,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Vec<Coefficient> {
        let cap = self.inverse.len() / 2;
        assert_eq!(high.len(), cap);
        // The leaves of every product tree divide by x-a. Recover a from
        // its two-point spectrum and avoid four FFTs for one field value.
        if cap == 1 {
            let point = Goldilocks::ONE - self.modulus[0];
            return vec![low(0) + high[0] * point];
        }
        if cap == 2 {
            // For x²+m1*x+m0, DC and Nyquist recover m0,m1 exactly.
            let half = Goldilocks::new(0x7fffffff80000001);
            let m0 = (self.modulus[0] + self.modulus[2]) * half - Goldilocks::ONE;
            let m1 = (self.modulus[0] - self.modulus[2]) * half;
            let q0 = high[0] - high[1] * m1;
            return vec![low(0) - q0 * m0, low(1) - high[1] * m0 - q0 * m1];
        }
        if cap <= 8 {
            let modulus = dft.idft(self.modulus.to_vec());
            let mut high = high.to_vec();
            let mut remainder: Vec<_> = (0..cap).map(low).collect();
            for degree in (0..cap).rev() {
                let quotient = high[degree];
                for (j, &coefficient) in modulus[..cap].iter().enumerate() {
                    let index = degree + j;
                    if index < cap { remainder[index] -= quotient * coefficient; }
                    else { high[index - cap] -= quotient * coefficient; }
                }
            }
            return remainder;
        }
        let mut reversed: Vec<_> = high.iter().rev().copied().collect();
        reversed.resize(2 * cap, Coefficient::ZERO);
        let mut spectrum = dft.dft_algebra(reversed);
        for (value, &factor) in spectrum.iter_mut().zip(self.inverse) {
            *value *= factor;
        }
        let mut quotient = dft.idft_algebra(spectrum);
        quotient.truncate(cap);
        quotient.reverse();
        quotient.resize(2 * cap, Coefficient::ZERO);
        let mut spectrum = dft.dft_algebra(quotient);
        for (value, &factor) in spectrum.iter_mut().zip(self.modulus) {
            *value *= factor;
        }
        let product = dft.idft_algebra(spectrum);
        (0..cap).map(|offset| low(offset) - product[offset]).collect()
    }

    fn monomial_spectrum(
        &self,
        exponent: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Vec<Goldilocks> {
        assert!(exponent.is_power_of_two());
        let cap = self.inverse.len() / 2;
        let mut shift = if exponent < cap {
            let mut values = vec![Goldilocks::ZERO; cap];
            values[exponent] = Goldilocks::ONE;
            values
        } else {
            let modulus = dft.idft(self.modulus.to_vec());
            modulus[..cap].iter().map(|value| -*value).collect()
        };
        let mut degree = cap;
        while degree < exponent {
            let mut product = multiply_polynomials(shift.clone(), shift, dft);
            product.resize(2 * cap, Goldilocks::ZERO);
            shift = self.remainder(&product[cap..], |offset| product[offset], dft);
            degree *= 2;
        }
        shift.resize(2 * cap, Goldilocks::ZERO);
        dft.dft(shift)
    }

    fn shifted_remainder<Coefficient: p3_field::ExtensionField<Goldilocks>>(
        &self,
        mut values: Vec<Coefficient>,
        shift: &[Goldilocks],
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Vec<Coefficient> {
        let cap = self.inverse.len() / 2;
        values.resize(2 * cap, Coefficient::ZERO);
        let mut spectrum = dft.dft_algebra(values);
        for (value, &factor) in spectrum.iter_mut().zip(shift) {
            *value *= factor;
        }
        let product = dft.idft_algebra(spectrum);
        self.remainder(&product[cap..], |offset| product[offset], dft)
    }
}

impl Code {
    fn base(&self) -> bool {
        matches!(self.pads, Pads::Base(_))
    }
    fn columns(&self) -> usize {
        self.width * if self.base() { 1 } else { 3 }
    }
    fn coefficient(&self, b: usize, j: usize) -> E {
        let n = self.len / self.width;
        let pad = self.pads.len() / self.width;
        if j < n {
            if b * n + j < self.live {
                (self.get)(b * n + j)
            } else {
                E::ZERO
            }
        } else {
            assert!(j < n + pad);
            self.pads.get(b * pad + j - n)
        }
    }
    fn coset(
        &self,
        c: usize,
        rows: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
        state: Option<&State>,
    ) -> Result<Vec<u64>, String> {
        if self.base() {
            self.coset_base(c, rows, dft)
        } else {
            self.coset_extension(c, rows, dft, state)
        }
    }

    fn coset_base(
        &self,
        coset: usize,
        rows: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Result<Vec<u64>, String> {
        Ok(self.coset_group(coset, rows, 1, dft, None)?.pop().unwrap())
    }

    fn coset_extension(
        &self,
        coset: usize,
        rows: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
        state: Option<&State>,
    ) -> Result<Vec<u64>, String> {
        Ok(self.coset_group(coset, rows, 1, dft, state)?.pop().unwrap())
    }

    /// A bounded group shares ONE original scan. Each coset keeps its own
    /// original evaluation point and padding; no new source, coin or MAC.
    /// Smaller FFTs/frontiers trade for `count` field accumulations per emitted
    /// coefficient. The pending cosets stay charged until hashed and dropped.
    fn coset_group(
        &self,
        first: usize,
        rows: usize,
        count: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
        state: Option<&State>,
    ) -> Result<Vec<Vec<u64>>, String> {
        if !rows.is_power_of_two()
            || rows > self.height
            || !matches!(count, 1 | 2 | 4)
            || first.checked_add(count).is_none_or(|end| end > self.height / rows)
            || state.is_some_and(|state| self.base() || 1 << state.num_variables() != self.len)
        {
            return Err("coset group geometry differs".into());
        }
        let n = self.len / self.width;
        let pad = self.pads.len() / self.width;
        let root = Goldilocks::two_adic_generator(self.height.ilog2() as usize);
        let powers: Vec<_> = (first..first + count)
            .map(|coset| power_lookup(root.exp_u64(coset as u64), n + pad))
            .collect();
        let mut group: Vec<_> = (0..count).map(|_| vec![0; rows * self.columns().max(4)]).collect();
        let mut add = |column: usize, j: usize, value: E| {
            for (cells, power) in group.iter_mut().zip(&powers) {
                if self.base() {
                    let target = &mut cells[column * rows + j % rows];
                    *target = (Goldilocks::new(*target) + base_coefficient(value) * power(j))
                        .as_canonical_u64();
                } else {
                    for (limb, &value) in limbs(&(value * power(j))).iter().enumerate() {
                        let target = &mut cells[(column * 3 + limb) * rows + j % rows];
                        *target = (Goldilocks::new(*target) + value).as_canonical_u64();
                    }
                }
            }
        };
        let mut emitted = 0usize;
        let mut phase = Span::start("pcs_source_accumulation", json!({
            "height": self.height, "first_coset": first, "cosets_in_group": count,
            "rows": rows, "base_columns": self.columns(), "live_source": self.live,
            "base": self.base(), "ordered_scan": self.scan.is_some()
        }))?;
        let mut emit = |index, value| {
            if index >= self.live {
                return Err("coset contribution outside live source".into());
            }
            emitted = emitted.checked_add(1).ok_or("coset emission count overflow")?;
            if self.base() && emitted > self.live {
                return Err("base scan emitted too many coefficients".into());
            }
            add(index / n, index % n, value);
            if emitted % 65536 == 0 {
                phase.checkpoint(|| json!({"source_visits": emitted,
                    "source_to_coset_contributions": emitted as u64 * count as u64}))?;
            }
            Ok(())
        };
        if let Some(state) = state {
            state.visit(&mut emit)?;
        } else if self.base() && self.scan.is_some() {
            self.scan.as_ref().unwrap()(&mut |index, value| emit(index, E::from(value)))?;
        } else {
            for index in 0..self.live {
                emit(index, (self.get)(index))?;
            }
        }
        if self.base() && emitted != self.live {
            return Err("base scan omitted original coefficients".into());
        }
        for column in 0..self.width {
            for j in 0..pad {
                add(column, n + j, self.pads.get(column * pad + j));
            }
        }
        phase.finish(json!({"source_visits": emitted, "source_scans": 1,
            "source_to_coset_contributions": emitted as u64 * count as u64,
            "pad_to_coset_contributions": self.pads.len() as u64 * count as u64}))?;
        drop(powers);
        for cells in &mut group {
            Self::fft_columns(cells, rows, self.columns(), dft)?;
        }
        Ok(group)
    }

    fn fft_columns(
        cells: &mut [u64],
        rows: usize,
        columns: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Result<(), String> {
        let mut column = vec![Goldilocks::ZERO; rows];
        let mut phase = Span::start("pcs_fft", json!({"rows": rows, "columns": columns}))?;
        for (index, values) in cells.chunks_exact_mut(rows).take(columns).enumerate() {
            for (out, &value) in column.iter_mut().zip(values.iter()) {
                *out = Goldilocks::new(value);
            }
            // dft_batch owns and transforms this one column in place; avoid
            // to_row_major_matrix(), which would copy an already-owned matrix.
            column = dft.dft_batch(DenseMatrix::new_col(column)).values;
            for (out, value) in values.iter_mut().zip(&column) {
                *out = value.as_canonical_u64();
            }
            phase.checkpoint(|| json!({"completed_columns": index + 1, "total_columns": columns}))?;
        }
        phase.finish(json!({"completed_columns": columns,
            "transformed_base_cells": rows as u64 * columns as u64,
            "analytic_radix2_butterflies": rows as u64 / 2 * rows.ilog2() as u64 * columns as u64,
            "host_copy_bytes": rows as u64 * columns as u64 * 16}))
    }
    #[cfg(test)]
    fn coset_typed<Coefficient: p3_field::ExtensionField<Goldilocks>>(
        &self,
        coset: usize,
        rows: usize,
        convert: impl Fn(E) -> Coefficient,
    ) -> Result<Vec<u64>, String> {
        let offset =
            Goldilocks::two_adic_generator(self.height.ilog2() as usize).exp_u64(coset as u64);
        let mut values = vec![Coefficient::ZERO; rows * self.width];
        for column in 0..self.width {
            let mut power = Goldilocks::ONE;
            for index in 0..(self.len + self.pads.len()) / self.width {
                values[(index % rows) * self.width + column] +=
                    convert(self.coefficient(column, index)) * power;
                power *= offset;
            }
        }
        let encoded = Radix2DFTSmallBatch::<Goldilocks>::default()
            .dft_algebra_batch(DenseMatrix::new(values, self.width))
            .to_row_major_matrix();
        let mut cells = vec![0; rows * self.columns().max(4)];
        for row in 0..rows {
            for column in 0..self.width {
                let coordinates =
                    <Coefficient as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                        &encoded.values[row * self.width + column],
                    );
                for (limb, value) in coordinates.iter().enumerate() {
                    cells[(coordinates.len() * column + limb) * rows + row] =
                        value.as_canonical_u64();
                }
            }
        }
        Ok(cells)
    }
    fn rows(&self, indices: &[usize]) -> Result<DenseMatrix<Goldilocks>, String> {
        if self.base() {
            self.rows_typed(indices, base_coefficient)
        } else {
            self.rows_typed(indices, std::convert::identity)
        }
    }
    fn rows_typed<Coefficient: p3_field::ExtensionField<Goldilocks>>(
        &self,
        indices: &[usize],
        convert: impl Fn(E) -> Coefficient,
    ) -> Result<DenseMatrix<Goldilocks>, String> {
        if indices.len() > replay_tree::query_batch_rows(self.height)
            || indices.iter().any(|&index| index >= self.height)
        {
            return Err("code query outside domain or reference batch cap".into());
        }
        if indices.is_empty() {
            return Ok(DenseMatrix::new(Vec::new(), self.columns()));
        }
        let mut phase = Span::start("pcs_query_remainders", json!({"height": self.height,
            "query_rows": indices.len(), "columns": self.width, "base": self.base(),
            "original_byte_windows": self.window.is_some()}))?;
        let message_rows = self.len / self.width;
        if self.window.is_some() && (!self.base() || !message_rows.is_power_of_two()) {
            return Err("byte query reader requires dyadic base columns".into());
        }
        // One opening-local reader, never retained by each historical A root.
        // Two original columns reproduce the selected 256 MiB A window at D34;
        // reduced geometries exercise the same cross-column reuse.
        let window_len = (2 * message_rows).min(QUERY_BYTE_WINDOW);
        let (mut window_first, mut bytes) = (usize::MAX, Vec::<u8>::new());
        let root = Goldilocks::two_adic_generator(self.height.ilog2() as usize);
        let cap = indices.len().next_power_of_two();
        let mut points: Vec<_> = indices.iter().map(|&index| root.exp_u64(index as u64)).collect();
        points.resize(cap, Goldilocks::ZERO);
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        let factors = query_tree(&points, &dft);
        let root_factors = factors.last().unwrap().factor(0);
        let coefficients = (self.len + self.pads.len()) / self.width;
        let pad_rows = self.pads.len() / self.width;
        // Splitting saves the large public zero suffix. When the message
        // fits in one query block it instead adds four unnecessary FFTs.
        let pad_shift = (self.live < self.len && message_rows.is_power_of_two() && message_rows > cap)
            .then(|| root_factors.monomial_spectrum(message_rows, &dft));
        // Write native base limbs directly into the only returned matrix. The
        // former Coefficient matrix duplicated up to 2 GiB at the initial cap.
        let mut values = vec![Goldilocks::ZERO; self.columns() * indices.len()];
        for column in 0..self.width {
            let active = self.live.saturating_sub(column * message_rows).min(message_rows);
            let split = pad_shift.is_some() && active < message_rows;
            let source_rows = if split { active } else { coefficients };
            let mut remainder = vec![Coefficient::ZERO; cap];
            for block in (0..source_rows.div_ceil(cap)).rev() {
                if let Some(read) = &self.window {
                    if block * cap < active {
                        let first = column * message_rows + block * cap;
                        let start = first / window_len * window_len;
                        let end = column * message_rows + ((block + 1) * cap).min(active);
                        if end > start + window_len {
                            return Err("query block crosses byte window".into());
                        }
                        if window_first != start {
                            bytes.resize(window_len.min(self.live - start), 0);
                            bytes.fill(0);
                            read(start, &mut bytes)?;
                            window_first = start;
                        }
                    }
                }
                remainder = root_factors.remainder(
                    &remainder,
                    |offset| {
                        let index = block * cap + offset;
                        if index < source_rows {
                            if self.window.is_some() && index < active {
                                convert(E::from(Goldilocks::from_u8(
                                    bytes[column * message_rows + index - window_first],
                                )))
                            } else {
                                convert(self.coefficient(column, index))
                            }
                        } else {
                            Coefficient::ZERO
                        }
                    },
                    &dft,
                );
            }
            if split {
                let mut pad = vec![Coefficient::ZERO; cap];
                if pad_rows <= cap {
                    for (offset, value) in pad.iter_mut().take(pad_rows).enumerate() {
                        *value = convert(self.pads.get(column * pad_rows + offset));
                    }
                } else {
                    for block in (0..pad_rows.div_ceil(cap)).rev() {
                        pad = root_factors.remainder(
                            &pad,
                            |offset| {
                                let index = block * cap + offset;
                                if index < pad_rows {
                                    convert(self.pads.get(column * pad_rows + index))
                                } else {
                                    Coefficient::ZERO
                                }
                            },
                            &dft,
                        );
                    }
                }
                let correction =
                    root_factors.shifted_remainder(pad, pad_shift.as_ref().unwrap(), &dft);
                for (value, contribution) in remainder.iter_mut().zip(correction) {
                    *value += contribution;
                }
            }
            let mut remainders = remainder;
            for level in factors[..factors.len() - 1].iter().rev() {
                let half = level.factor_len / 2;
                let mut children = Vec::with_capacity(cap);
                for (index, parent) in remainders.chunks_exact(2 * half).enumerate() {
                    for child in 0..2 {
                        children.extend(level.factor(2 * index + child).remainder(
                            &parent[half..],
                            |offset| parent[offset],
                            &dft,
                        ));
                    }
                }
                remainders = children;
            }
            for (row, value) in remainders.into_iter().take(indices.len()).enumerate() {
                let limbs =
                    <Coefficient as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                        &value,
                    );
                values[row * self.columns() + column * limbs.len()
                    ..row * self.columns() + (column + 1) * limbs.len()]
                    .copy_from_slice(limbs);
            }
            phase.checkpoint(|| json!({"completed_columns": column + 1, "total_columns": self.width}))?;
        }
        phase.finish(json!({"completed_columns": self.width, "output_base_cells": values.len()}))?;
        Ok(DenseMatrix::new(values, self.columns()))
    }
    fn commit(
        self,
        mmcs: &HidingMmcs,
        state: Option<&State>,
    ) -> Result<(replay_tree::Commitment, ZkWhirReplayHandle), String> {
        let base = self.base();
        let code = Arc::new(self);
        let rowcode = code.clone();
        let (rows, cut) = replay_tree::geometry(code.height, code.columns())?;
        let group = replay_tree::coset_group_size(code.height, code.columns());
        let mut pending = Vec::new().into_iter();
        // Both P3 twiddle tables remain allocated across all cosets.
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        let (root, mut tree) = Tree::commit(
            mmcs,
            code.height,
            code.columns(),
            rows,
            cut,
            |c| {
                if let Some(cells) = pending.next() {
                    return Ok(cells);
                }
                pending = code.coset_group(c, rows, group, &dft, state)?.into_iter();
                Ok(pending.next().unwrap())
            },
            Arc::new(move |indices| rowcode.rows(indices)),
        )?;
        let pending_bytes = (group - 1) * rows * code.columns().max(4) * size_of::<u64>();
        tree.memory.peak_coset_bytes += pending_bytes;
        tree.memory.peak_commit_scratch_bytes += pending_bytes;
        let lease = state.map(State::replay_lease).transpose()?.flatten();
        Ok((root, ZkWhirReplayHandle::new(Oracle { tree: Arc::new(tree), base, lease })))
    }

    fn commit_native_weights(self, mmcs: &HidingMmcs, native: NativeWeights)
        -> Result<(replay_tree::Commitment, ZkWhirReplayHandle), String> {
        let mut runtime = native.runtime.lock().map_err(|_| "native W owner poisoned")?;
        let result = (|| {
            if !self.base() || self.width != 128 || self.live != native.weights.len() ||
                !self.len.is_power_of_two() || self.scan.is_some() || self.window.is_some() {
                return runtime.abort("native W original source or shape differs");
            }
            let (rows, cut) = replay_tree::native_weight_geometry(self.height)?;
            let cosets = self.height / rows;
            let n = self.len / 128;
            let pad = self.pads.len() / 128;
            if n < rows || n / rows > 256 || pad == 0 || pad > 1536 || self.pads.len() != 128 * pad {
                return runtime.abort("native W signed accumulation or pad bound differs");
            }
            let code = Arc::new(self);
            let rowcode = code.clone();
            let (root, tree) = Tree::commit_resident_weights(mmcs, code.height,
                Arc::new(move |indices| rowcode.rows(indices)), |stream, current| {
                let before = runtime.stats()?;
                let tiles = runtime.pcs_weight_tiles(&native.weights, native.layout, &native.tiles)?;
                let pads = runtime.pcs_words(code.pads.len())?;
                // Only bounded original PCS pads are uploaded. Source W stays
                // sealed/resident and does not pass through the scalar getter.
                let pad_words: Vec<_> = (0..code.pads.len())
                    .map(|i| base_coefficient(code.pads.get(i)).as_canonical_u64()).collect();
                runtime.pcs_upload(&pads, 0, &pad_words)?;
                drop(pad_words);
                let twiddles = runtime.pcs_fft_twiddles(rows.ilog2() as usize)?;
                let groups = cosets / 32;
                let frontier = runtime.pcs_frontier(rows, groups)?;
                let group_rows = 32 * rows;
                let band = 65536.min(group_rows);
                let salt_buffer = runtime.pcs_words(4 * band)?;
                let mut salt_words = vec![0; 4 * band];
                let mut top = Vec::new();
                let mut work = replay_tree::ReplayWork::default();
                let mut source_visits = 0u64;
                let mut phase = Span::start("pcs_w_resident", json!({"height": code.height,
                    "rows": rows, "cosets": cosets, "groups": groups, "columns": 128,
                    "columns_in_ring": 8, "columns_per_fft": 4, "cosets_per_scan": 32}))?;
                for group in 0..groups {
                    let mut shape = device::WeightShape { message_rows: n as u64, rows: rows as u64,
                        pad_rows: pad as u32, cosets: cosets as u32, first_coset: (32 * group) as u32,
                        first_column: 0, slots: 0 };
                    let (low, high) = runtime.pcs_coset_powers(shape)?;
                    let ring = runtime.pcs_ring(rows)?;
                    let mut fill = |runtime: &mut device::Runtime, column: usize, slots| -> Result<(), String> {
                        shape.first_column = column as u32; shape.slots = slots;
                        runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &ring, shape)?;
                        let first = column * n;
                        source_visits += code.live.min(first + 4 * n).saturating_sub(first) as u64;
                        phase.checkpoint(|| json!({"completed_groups": group, "active_first_coset": 32 * group,
                            "completed_columns_in_group": column + 4, "source_visits": source_visits,
                            "source_to_coset_contributions": source_visits * 32, "native": runtime.stats().ok()}))
                    };
                    fill(&mut runtime, 0, 0)?; fill(&mut runtime, 4, 4)?;
                    let mut roots = runtime.pcs_hash_start(&ring)?;
                    for first in (4..=116).step_by(8) {
                        fill(&mut runtime, first + 4, 0)?;
                        runtime.pcs_hash_step(&ring, &roots, first)?;
                        if first < 116 { fill(&mut runtime, first + 8, 4)?; }
                    }
                    fill(&mut runtime, 124, 0)?;
                    runtime.release_buffer(low)?; runtime.release_buffer(high)?;
                    for first in (0..group_rows).step_by(band) {
                        for local in 0..band {
                            let row = (first + local) % rows;
                            let mut rng = stream.snapshot_at(current[row])?;
                            for col in 0..4 {
                                let value: Goldilocks = rng.random();
                                salt_words[col * band + local] = value.as_canonical_u64();
                            }
                            work.salt_candidate_bytes += rng.position() - current[row];
                            current[row] = rng.position();
                        }
                        runtime.pcs_upload(&salt_buffer, 0, &salt_words)?;
                        runtime.pcs_hash_finish(&ring, &salt_buffer, &mut roots, first)?;
                        phase.checkpoint(|| json!({"completed_groups": group, "completed_salt_leaves_in_group": first + band,
                            "salt_candidate_bytes": work.salt_candidate_bytes, "native": runtime.stats().ok()}))?;
                    }
                    runtime.release_buffer(ring)?; // Merkle outputs never overlap the ring
                    for _ in 0..5 {
                        let next = runtime.pcs_nodes_strided(&roots, rows)?;
                        runtime.release_buffer(roots)?; roots = next;
                    }
                    runtime.pcs_merge_group(&frontier, &roots, group)?;
                    work.leaf_hashes += group_rows as u64;
                    work.node_hashes += (group_rows - rows) as u64;
                    // Consecutive group binary frontier: one merge per set bit.
                    work.node_hashes += rows as u64 * group.trailing_ones() as u64;
                    work.coset_cells += (group_rows * 128) as u64;
                    if group + 1 == groups {
                        let mut count = rows;
                        while count > code.height / cut {
                            let next = runtime.pcs_nodes(&roots)?;
                            runtime.release_buffer(roots)?; roots = next; count /= 2;
                            work.node_hashes += count as u64;
                        }
                        loop {
                            top.push(runtime.pcs_digests(&roots, 0, count)?);
                            if count == 1 { break; }
                            let next = runtime.pcs_nodes(&roots)?;
                            runtime.release_buffer(roots)?; roots = next; count /= 2;
                            work.node_hashes += count as u64;
                        }
                    }
                    runtime.release_buffer(roots)?;
                    phase.checkpoint(|| json!({"completed_groups": group + 1, "leaf_hashes": work.leaf_hashes,
                        "node_hashes": work.node_hashes, "native": runtime.stats().ok()}))?;
                }
                runtime.release_buffer(frontier)?;
                runtime.release_buffer(pads)?; runtime.release_buffer(twiddles)?;
                runtime.release_buffer(tiles)?; runtime.release_buffer(salt_buffer)?;
                let after = runtime.stats()?;
                if source_visits != code.live as u64 * groups as u64 {
                    return runtime.abort("resident W column coverage differs");
                }
                phase.finish(json!({"completed_groups": groups, "source_visits": source_visits,
                    "equivalent_source_scans": groups, "logical_source_bytes": source_visits * 2,
                    "ordinary_signed_products": source_visits * 32,
                    "pad_field_products": code.pads.len() as u64 * cosets as u64,
                    "fft_base_cells": code.height as u64 * 128,
                    "analytic_fft_butterflies": code.height as u64 * 64 * rows.ilog2() as u64,
                    "leaf_hashes": work.leaf_hashes, "node_hashes": work.node_hashes,
                    "native_h2d_bytes": after.h2d_bytes - before.h2d_bytes,
                    "native_d2h_bytes": after.d2h_bytes - before.d2h_bytes,
                    "native_launches": after.launches - before.launches,
                    "native_fences": after.fences - before.fences, "native": after}))?;
                Ok((top, work, after.peak_capacity_bytes as usize))
            })?;
            Ok((root, ZkWhirReplayHandle::new(Oracle { tree: Arc::new(tree), base: true, lease: None })))
        })();
        if let Err(error) = &result { let _ = runtime.abort::<()>(error); }
        result
    }
}

/// Immutable base-field source behind one already committed flat oracle.
///
/// The caller owns the getter's storage and must keep its answers immutable
/// for the root's lifetime. Construction replays the installation coins and
/// rejects a root mismatch before this handle can be used by a proof.
pub(in crate::c71_matrix) struct ReplayModel {
    domain: Domain,
    root: C61Commitment,
    source: Getter,
    scan: Option<(BaseScan, usize)>,
    tree: Arc<Tree>,
    pads: Arc<[Goldilocks]>,
    retain_first: bool,
    pub(in crate::c71_matrix) range_bytes: Option<super::super::range::windowed::Source>,
    pub(in crate::c71_matrix) range_words: Option<super::super::range::windowed::Source<i16>>,
    byte_histogram: Arc<Mutex<Option<[u64; 256]>>>,
}

impl ReplayModel {
    pub(in crate::c71_matrix) fn retained_census(&self) -> serde_json::Value {
        let memory = &self.tree.memory;
        serde_json::json!({
            "domain_log2": self.domain.config().expect("validated domain").num_variables,
            "retained_merkle_digest_bytes": memory.retained_digest_bytes,
            "retained_salt_offset_bytes": memory.salt_offset_bytes,
            "retained_rng_bytes": memory.rng_snapshot_bytes,
            "retained_pcs_pad_bytes": self.pads.len() * size_of::<Goldilocks>(),
            "retained_range_histogram_capacity_bytes": self.range_bytes.as_ref().map_or(0, |source| source.histogram.capacity() * 8)
                + self.range_words.as_ref().map_or(0, |source| source.histogram.capacity() * 8),
            "initial_coset_bytes": memory.peak_coset_bytes,
            "initial_merkle_scratch_bytes": memory.peak_commit_scratch_bytes,
            "initial_native_peak_capacity_bytes": memory.native_peak_capacity_bytes,
            "query_subtree_bytes_each": memory.open_subtree_bytes_each,
            "retained_s1_policy": self.retain_first,
            "scope": "Merkle/pad payloads, not total host capacity; initial scratch includes coset and is no longer live; native high-water includes all buffers on the common owner, separately from this Merkle payload; S1 is retained only within active sequential PCS chain, not by this snapshot; other FFT/cache/query/sourcewise temporaries excluded"
        })
    }
    pub(in crate::c71_matrix) fn new(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
        live: usize,
    ) -> Result<Self, String> {
        Self::new_source(domain, seed, salt_seed, source, None, live, None)
    }

    pub(in crate::c71_matrix) fn new_scanned(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
        scan: BaseScan,
        window: ByteWindow,
        live: usize,
    ) -> Result<Self, String> {
        Self::new_source(domain, seed, salt_seed, source, Some((scan, window)), live, None)
    }

    pub(in crate::c71_matrix) fn new_native_weights(
        domain: Domain, seed: [u8; 32], salt_seed: [u8; 32], source: Getter,
        live: usize, native: NativeWeights,
    ) -> Result<Self, String> {
        let owner = native.runtime.clone();
        let result = Self::new_source(domain, seed, salt_seed, source, None, live, Some(native));
        if let Err(error) = &result {
            if let Ok(mut runtime) = owner.lock() { let _ = runtime.abort::<()>(error); }
        }
        result
    }

    fn new_source(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
        readers: Option<(BaseScan, ByteWindow)>,
        live: usize,
        native: Option<NativeWeights>,
    ) -> Result<Self, String> {
        let config = domain.config()?;
        let len = 1usize << config.num_variables;
        if live > len {
            return Err("C71 replay live prefix exceeds original domain".into());
        }
        let source: Getter = Arc::new(move |index| {
            assert!(index < len);
            if index < live {
                source(index)
            } else {
                E::ZERO
            }
        });
        let first = config.round_folding_factor(0);
        let mut rng = PrivateRng::from_seed(seed);
        let pads: Arc<[Goldilocks]> =
            (0..config.oracle_randomness[0] << first).map(|_| rng.random()).collect();
        let height = (len >> first) << config.starting_log_inv_rate;
        let mmcs = ObservedMmcs::new(Fs::new(b"C71 model setup, Delta independent", 0), salt_seed);
        let _extension = mmcs.clone();
        let (scan, window) =
            readers.map_or((None, None), |(scan, window)| (Some(scan), Some(window)));
        let byte_histogram = Arc::new(Mutex::new(None));
        let scan = scan.map(|scan| {
            let cached = byte_histogram.clone();
            Arc::new(move |emit: &mut dyn FnMut(usize, Goldilocks) -> Result<(), String>| {
                let mut cached = cached.lock().map_err(|_| "range histogram cache poisoned")?;
                if cached.is_some() {
                    return scan(emit);
                }
                let mut h = [0u64; 256];
                let mut count = 0;
                scan(&mut |i, value| {
                    let byte = value.as_canonical_u64();
                    if i >= live || byte >= 256 || count >= live {
                        return Err("original byte scan shape or alphabet differs".into());
                    }
                    h[byte as usize] += 1;
                    count += 1;
                    emit(i, value)
                })?;
                if count != live {
                    return Err("original byte histogram scan incomplete".into());
                }
                h[0] += (len - live) as u64;
                *cached = Some(h); // no partial histogram after either callback fails
                Ok(())
            }) as BaseScan
        });
        let code = Code {
            get: source.clone(),
            scan: scan.clone(),
            window,
            len,
            live,
            width: 1 << first,
            height,
            pads: Pads::Base(pads.clone()),
        };
        let (root, handle) = if let Some(native) = native {
            code.commit_native_weights(&mmcs.inner, native)?
        } else {
            code.commit(&mmcs.inner, None)?
        };
        let oracle = handle.downcast::<Oracle>().map_err(|_| "C71 initial replay handle type")?;
        Ok(Self {
            domain,
            root,
            source,
            scan: scan.map(|scan| (scan, live)),
            tree: oracle.tree,
            pads,
            retain_first: false,
            range_bytes: None,
            range_words: None,
            byte_histogram,
        })
    }

    pub(in crate::c71_matrix) fn new_checked(
        domain: Domain,
        root: C61Commitment,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
    ) -> Result<Self, String> {
        let model =
            Self::new(domain, seed, salt_seed, source, 1 << domain.config()?.num_variables)?;
        if root != model.root {
            return Err("C71 replay source changed the installed model root".into());
        }
        Ok(model)
    }

    pub(in crate::c71_matrix) fn domain(&self) -> Domain {
        self.domain
    }

    pub(in crate::c71_matrix) fn retain_first_fold(mut self) -> Self {
        self.retain_first = true;
        self
    }

    pub(in crate::c71_matrix) fn with_range_reader(
        mut self,
        read: super::super::range::windowed::Reader,
    ) -> Result<Self, String> {
        let histogram = self
            .byte_histogram
            .lock()
            .map_err(|_| "range histogram cache poisoned")?
            .ok_or("range requires a completed original byte scan")?;
        self.range_bytes = Some(super::super::range::windowed::Source {
            native: None,
            alphabet: super::super::range::Alphabet::Byte,
            histogram: histogram.to_vec(),
            read,
        });
        Ok(self)
    }

    pub(in crate::c71_matrix) fn with_signed_range_reader(
        mut self,
        packed: &[i16],
        read: super::super::range::windowed::Reader<i16>,
    ) -> Result<Self, String> {
        self.range_words = Some(super::super::range::windowed::Source::signed(
            self.domain.config()?.num_variables,
            packed,
            read,
        )?);
        Ok(self)
    }

    pub(in crate::c71_matrix) fn root(&self) -> &C61Commitment {
        &self.root
    }

    pub(in crate::c71_matrix) fn source(&self) -> Getter {
        self.source.clone()
    }

    pub(in crate::c71_matrix) fn value(&self, index: usize) -> Fp3 {
        from_p3((self.source)(index))
    }

    fn initial_handle(&self) -> ZkWhirReplayHandle {
        ZkWhirReplayHandle::new(Oracle { tree: self.tree.clone(), base: true, lease: None })
    }
}

pub(in crate::c71_matrix) fn prove_pcs_sourcewise(
    model: &ReplayModel,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    point: Point<E>,
    terminal: Auth,
    mask: Auth,
    fs: &mut Fs,
) -> Result<(ZkWhirProof<Goldilocks, E, ObservedMmcs>, Fp3), String> {
    prove_pcs_sourcewise_with_coins(model, config, point, terminal, mask, fs, fresh_pcs_coins()?)
}

pub(in crate::c71_matrix) fn prove_pcs_sourcewise_with_coins(
    model: &ReplayModel,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    point: Point<E>,
    terminal: Auth,
    mask: Auth,
    fs: &mut Fs,
    coins: PcsCoins,
) -> Result<(ZkWhirProof<Goldilocks, E, ObservedMmcs>, Fp3), String> {
    if model.domain.config()?.num_variables != config.num_variables {
        return Err("C71 replay source and PCS domains differ".into());
    }
    fs.set_phase(0x200);
    census::mark("prover_cached_initial_oracle")?;
    let handle = model.initial_handle();
    fs.observe(model.root.clone());
    census::mark("prover_pcs")?;
    let dft = Radix2DFTSmallBatch::default();
    let base = ObservedMmcs::new(fs.clone(), coins.salt_seed);
    let extension = base.clone();
    let base_ref = &base;
    let prover = HidingWhirProver {
        config,
        dft: &dft,
        mmcs: &base_ref,
        extension_mmcs: ExtensionMmcs::new(&extension),
    };
    let claims = [(point, to_p3(terminal.x))];
    let backend = Backend {
        base: &base,
        extension: &extension,
        source: Mutex::new(Some(model.source.clone())),
        scan: model.scan.clone(),
        first: config.round_folding_factor(0),
        retain_first: model.retain_first,
    };
    let mut rng = PrivateRng::from_seed(coins.seed);
    let proved = prover.prove_claimless_replay_with_oracle(
        1 << config.num_variables,
        &model.pads,
        handle,
        &claims,
        to_p3(mask.x),
        &backend,
        fs,
        &mut rng,
    )?;
    let close_tag =
        mask.m - from_p3(proved.base_case.gamma * proved.target.coefficient) * terminal.m;
    record_values(fs, 0x12, &[close_tag]);
    Ok((owned_proof(proved.proof), close_tag))
}

// `&ObservedMmcs` and `ObservedMmcs` have identical commitment/proof associated
// types. Move the payload between their nominal WHIR wrappers without a codec
// round trip or a second copy of any proof vector.
fn owned_proof(
    proof: ZkWhirProof<Goldilocks, E, &ObservedMmcs>,
) -> ZkWhirProof<Goldilocks, E, ObservedMmcs> {
    let ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case } = proof;
    let rounds = rounds
        .into_iter()
        .map(|round| {
            let ZkRoundProof { commitment, mask_commitment, ood_answers, pow_witness, openings } =
                round;
            ZkRoundProof { commitment, mask_commitment, ood_answers, pow_witness, openings }
        })
        .collect();
    let BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness,
        source_openings,
        fresh_main_openings,
        mask_openings,
    } = base_case;
    let base_case = BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness,
        source_openings,
        fresh_main_openings,
        mask_openings,
    };
    ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case }
}
struct Oracle {
    tree: Arc<Tree>,
    base: bool,
    lease: Option<Lease>,
}
struct Backend<'a> {
    base: &'a ObservedMmcs,
    extension: &'a ObservedMmcs,
    source: Mutex<Option<Getter>>,
    scan: Option<(BaseScan, usize)>,
    first: usize,
    retain_first: bool,
}
impl<'a> ZkWhirOracleCommitter<Goldilocks, E, &'a ObservedMmcs> for Backend<'a> {
    type Error = String;
    type SumcheckState = State;
    fn initialize_sumcheck(
        &self,
        message: ZkWhirInitialMessage<'_, Goldilocks>,
        claims: &[(Point<E>, E)],
        coefficients: &[E],
        target: E,
    ) -> Result<State, String> {
        if claims.len() != 1
            || coefficients != [E::ONE]
            || message.len() != 1 << claims[0].0.num_variables()
        {
            return Err("bounded singleton sourcewise claim".into());
        }
        let mut source = self.source.lock().map_err(|_| "source lock poisoned")?;
        let state = State::new(
            source.as_ref().ok_or("source already consumed")?.clone(),
            self.scan.clone(),
            claims[0].0.as_slice(),
            self.first,
            target,
            self.retain_first,
        )?;
        source.take(); // transfer ownership only after geometry and claim validation
        Ok(state)
    }
    fn commit_initial(
        &self,
        _: ZkWhirInitialMessage<'_, Goldilocks>,
        _: &[Goldilocks],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<DenseMatrix<Goldilocks>>,
        ),
        String,
    > {
        Err("dense initial commit forbidden".into())
    }
    fn commit_extension(
        &self,
        _: &[E],
        _: &[E],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<
                FlatMatrixView<Goldilocks, E, DenseMatrix<E>>,
            >,
        ),
        String,
    > {
        Err("dense extension commit forbidden".into())
    }
    fn commit_extension_replay_from_sumcheck(
        &self,
        state: &State,
        randomness: &[E],
        folding: usize,
        height: usize,
    ) -> Result<Option<(replay_tree::Commitment, ZkWhirReplayHandle)>, String> {
        let get = state.getter();
        Code {
            get,
            scan: None,
            window: None,
            len: 1 << state.num_variables(),
            live: 1 << state.num_variables(),
            width: 1 << folding,
            height,
            pads: Pads::Extension(randomness.to_vec()),
        }
        .commit(&self.extension.inner, Some(state))
        .map(Some)
    }
    fn evaluate_padded_ood_from_sumcheck(
        &self,
        state: &State,
        point: E,
        suffix: &[E],
    ) -> Result<Option<E>, String> {
        state.padded_ood(point, suffix).map(Some)
    }
    fn accumulate_round_claim_from_sumcheck(
        &self,
        state: &mut State,
        domain: usize,
        indices: &[usize],
        points: &[E],
        ood: &[E],
        queries: &[E],
    ) -> Result<bool, String> {
        let root = Goldilocks::two_adic_generator(domain.ilog2() as usize);
        let mut terms: Vec<_> = points.iter().copied().zip(ood.iter().copied()).collect();
        terms.extend(
            indices.iter().zip(queries).map(|(&i, &c)| (E::from(root.exp_u64(i as u64)), c)),
        );
        state.add_powers(&terms)?;
        Ok(true)
    }
    fn release_replay(&self, handle: ZkWhirReplayHandle) -> Result<(), String> {
        let oracle = handle.downcast::<Oracle>().map_err(|_| "replay handle type")?;
        let Oracle { tree, lease, .. } = *oracle;
        drop(tree); // no opening callback survives when the generation is released
        if let Some(lease) = lease {
            lease.release()?;
        }
        Ok(())
    }
    fn open_replay(
        &self,
        handle: &ZkWhirReplayHandle,
        indices: &[usize],
        randomness: &Point<E>,
    ) -> Result<Option<(QueryOpenings<Goldilocks, E, replay_tree::MultiProof>, Vec<E>)>, String>
    {
        let oracle = handle.downcast_ref::<Oracle>().ok_or("replay handle type")?;
        let (rows, proof) = oracle.tree.open(indices)?;
        // The C7.1 wrapper binds original rows/salts/frontier into FS before
        // the next coin, including extension rows in their native base layout.
        let mmcs = if oracle.base { self.base } else { self.extension };
        mmcs.bind(indices, &rows, &proof);
        let rows: Vec<_> = rows.into_iter().map(|mut v| v.remove(0)).collect();
        if oracle.base {
            let folded = rows.iter().map(|v| Poly::new(v.clone()).eval_base(randomness)).collect();
            Ok(Some((QueryOpenings::Base(SharedProofOpening { rows, proof }), folded)))
        } else {
            let rows: Vec<Vec<E>> = rows
                .iter()
                .map(|v| v.chunks_exact(3).map(|c| E::new(c.try_into().unwrap())).collect())
                .collect();
            let folded = rows
                .iter()
                .map(|v| Poly::new(v.clone()).eval_ext::<Goldilocks>(randomness))
                .collect();
            Ok(Some((QueryOpenings::Extension(SharedProofOpening { rows, proof }), folded)))
        }
    }
}
#[cfg(test)]
pub(in crate::c71_matrix) fn compare_source(
    dimension: usize,
    source: Getter,
    values: Vec<Goldilocks>,
    original: Option<&Model>,
    readers: Option<(BaseScan, ByteWindow)>,
) {
    compare_source_with_native(dimension, source, values, original, readers, None, false);
}
#[cfg(test)]
fn compare_source_with_native(
    dimension: usize, source: Getter, values: Vec<Goldilocks>, original: Option<&Model>,
    readers: Option<(BaseScan, ByteWindow)>, native: Option<NativeWeights>, fixture_initial_rows: bool,
) {
    use rand_010::RngExt;
    assert!((10..=17).contains(&dimension));
    assert_eq!(values.len(), 1 << dimension);
    census::start().unwrap();
    let config = config(dimension).unwrap();
    let dft = Radix2DFTSmallBatch::default();
    let salt_seed = original.map_or([73; 32], |m| m.salt_seed);
    let root_seed = original.map_or([91; 32], |m| m.seed);
    let witness = Poly::new(values);
    let point = Point::new(
        (0..dimension)
            .map(|i| {
                E::new([Goldilocks::new(i as u64 + 3), Goldilocks::new(7), Goldilocks::new(11)])
            })
            .collect(),
    );
    let value = witness.eval_base(&point);
    // Original endpoint fixed before the proof. Ideal MACs here, as in the
    // bounded composed runner; no reauthentication after challenges.
    let delta =
        Fp3::new(volta_field::Fp::new(7), volta_field::Fp::new(11), volta_field::Fp::new(13));
    let terminal_key = Key { k: Fp3::ONE };
    let terminal = Auth { x: from_p3(value), m: terminal_key.k - delta * from_p3(value) };
    let mask_key = Key { k: Fp3::ONE + Fp3::ONE };
    let mask = Auth { x: Fp3::ONE, m: mask_key.k - delta };
    let claims = [(point.clone(), value)];
    let mut fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    fs.set_phase(0x200);
    let root_mmcs = ObservedMmcs::new(fs.clone(), salt_seed);
    let root_prover = HidingWhirProver::new(&config, &dft, &root_mmcs);
    let mut root_rng = PrivateRng::from_seed(root_seed);
    let phase = Span::start("sourcewise_reference_commitment", json!({"domain_log2": dimension})).unwrap();
    let (root, data) = root_prover.commit(witness, &mut fs, &mut root_rng);
    phase.finish(json!({"complete_reference": true})).unwrap();
    // Isolate the changed native commitment/Tree/proof boundary without
    // repeating the unchanged CPU query evaluator for every initial leaf.
    // This bounded eager table is test-only and charged by the joint budget;
    // the separate Tree test exercises the production opening getter.
    let fixture_rows = fixture_initial_rows.then(|| {
        assert!(native.is_some());
        let matrices = root_mmcs.get_matrices(&data.merkle);
        assert_eq!(matrices.len(), 1);
        Arc::new(matrices[0].clone())
    });
    if let Some(original) = original {
        assert_eq!(root, original.root);
    }
    // Actual C7.1 discipline: fresh proof coins/MMCS, independent of root replay.
    let proof_mmcs = ObservedMmcs::new(fs.clone(), [83; 32]);
    let reference = HidingWhirProver::new(&config, &dft, &proof_mmcs);
    let mut rng = PrivateRng::from_seed([101; 32]);
    let phase = Span::start("sourcewise_reference_proof", json!({"domain_log2": dimension})).unwrap();
    let result = reference.prove_claimless(data, &claims, to_p3(mask.x), &mut fs, &mut rng);
    phase.finish(json!({"complete_reference": true})).unwrap();

    census::mark("sourcewise_initial_commit").unwrap();
    let mut replay_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    replay_fs.set_phase(0x200);
    let live = native.as_ref().map_or(1 << dimension, |native| native.weights.len());
    let mut model = ReplayModel::new_source(
        Domain::Flat(dimension),
        root_seed,
        salt_seed,
        source.clone(),
        readers,
        live,
        native,
    )
    .unwrap();
    assert_eq!(root, *model.root());
    if let Some(rows) = fixture_rows {
        let payload = rows.values.len() * size_of::<Goldilocks>();
        Arc::get_mut(&mut model.tree).unwrap().fixture_rows(Arc::new(move |indices| {
            Ok(DenseMatrix::new(indices.iter().flat_map(|&i|
                rows.values[i * rows.width..(i + 1) * rows.width].iter().copied()).collect(), rows.width))
        }));
        eprintln!("C71_NATIVE_W_CHAIN_FIXTURE initial_reference_rows_bytes={payload} production_cache=false");
    }
    if original.is_some() || model.scan.is_some() {
        model = model.retain_first_fold();
    }
    let mut initial_rng = PrivateRng::from_seed(root_seed);
    let first = config.round_folding_factor(0);
    let pads: Arc<[Goldilocks]> =
        (0..config.oracle_randomness[0] << first).map(|_| initial_rng.random()).collect();
    assert_eq!(pads, model.pads);
    let handle = model.initial_handle();
    assert_eq!(root_rng.position(), initial_rng.position());
    replay_fs.observe(model.root.clone());
    let base = ObservedMmcs::new(replay_fs.clone(), [83; 32]);
    let extension = base.clone();
    let base_ref = &base;
    let engine = HidingWhirProver {
        config: &config,
        dft: &dft,
        mmcs: &base_ref,
        extension_mmcs: ExtensionMmcs::new(&extension),
    };
    let mut replay_rng = PrivateRng::from_seed([101; 32]);
    census::mark("sourcewise_open_all_rounds").unwrap();
    let backend = Backend {
        base: &base,
        extension: &extension,
        source: Mutex::new(Some(source)),
        scan: model.scan.clone(),
        first,
        retain_first: model.retain_first,
    };
    let output = engine
        .prove_claimless_replay_with_oracle(
            1 << dimension,
            &pads,
            handle,
            &claims,
            to_p3(mask.x),
            &backend,
            &mut replay_fs,
            &mut replay_rng,
        )
        .unwrap();
    census::mark("codec_and_native_verifier").unwrap();
    assert_eq!(
        serde_json::to_vec(&result.proof).unwrap(),
        serde_json::to_vec(&output.proof).unwrap()
    );
    let close_tag =
        mask.m - from_p3(output.base_case.gamma * output.target.coefficient) * terminal.m;
    assert_eq!(
        close_tag,
        mask.m - from_p3(result.base_case.gamma * result.target.coefficient) * terminal.m
    );
    let canonical = |value| {
        let matrix = MatrixProof {
            rounds: vec![[Fp3::ZERO; 4]; dimension],
            terminal: [Fp3::ZERO; 2],
            pcs: serde_json::from_value(value).unwrap(),
            close_tag,
        };
        codec::encode_linear(Domain::Flat(dimension), &matrix).unwrap()
    };
    let bytes = canonical(serde_json::to_value(&result.proof).unwrap());
    assert_eq!(bytes, canonical(serde_json::to_value(&output.proof).unwrap()));
    eprintln!("sourcewise observed D{dimension} canonical_bytes={}", bytes.len());
    assert_eq!(fs.digest(), replay_fs.digest());
    assert_eq!(rng.position(), replay_rng.position());
    assert_eq!(result.target, output.target);
    assert_eq!(result.base_case, output.base_case);
    record_values(&mut fs, 0x12, &[close_tag]);
    record_values(&mut replay_fs, 0x12, &[close_tag]);
    let owned_proof: ZkWhirProof<Goldilocks, E, ObservedMmcs> =
        serde_json::from_value(serde_json::to_value(&output.proof).unwrap()).unwrap();
    let mut verifier_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    verify_pcs(
        &config,
        &root,
        point.clone(),
        &owned_proof,
        close_tag,
        terminal_key,
        mask_key,
        delta,
        &mut verifier_fs,
    )
    .unwrap();
    assert_eq!(verifier_fs.digest(), fs.digest());
    // A coherently encoded proof cannot be closed on a different endpoint MAC.
    let mut wrong_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    assert!(verify_pcs(
        &config,
        &root,
        point,
        &owned_proof,
        close_tag,
        Key { k: terminal_key.k + Fp3::ONE },
        mask_key,
        delta,
        &mut wrong_fs
    )
    .is_err());
    eprintln!("sourcewise_allocator={}", census::finish().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_durable_telemetry_exact_commitment_and_openings() {
        use crate::c71_matrix::progress::{Recording, check};
        let path = std::env::temp_dir().join(format!("c71-pcs-progress-{}-{}.jsonl",
            std::process::id(), rand::random::<u64>()));
        let run = || {
            let mut rng = PrivateRng::from_seed([65; 32]);
            let code = Code {
                get: Arc::new(|i| E::from(Goldilocks::new((i * 7919) as u64))),
                scan: None, window: None, len: 4096, live: 4000, width: 128, height: 512,
                pads: Pads::Base((0..1024).map(|_| rng.random()).collect()),
            };
            let (root, oracle) = code.commit(&mmcs([37; 32]), None).unwrap();
            let oracle = oracle.downcast::<Oracle>().ok().unwrap();
            let opening = oracle.tree.open(&[511, 2, 2, 0, 200]).unwrap();
            (root, serde_json::to_value(opening).unwrap(), oracle.tree.work)
        };
        let started = std::time::Instant::now();
        let expected = run();
        let without = started.elapsed().as_secs_f64();
        let recording = Recording::start(&path).unwrap();
        let started = std::time::Instant::now();
        let actual = run();
        let with = started.elapsed().as_secs_f64();
        check().unwrap();
        drop(recording);
        assert_eq!(actual, expected); // pads, values, root, salts, order and duplicate paths
        let content = std::fs::read_to_string(&path).unwrap();
        let events: Vec<serde_json::Value> = content.lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        let visits: u64 = events.iter().filter(|r| r["event"]["phase"] == "pcs_source_accumulation"
            && r["event"]["kind"] == "end")
            .map(|r| r["event"]["work"]["source_visits"].as_u64().unwrap()).sum();
        assert_eq!(visits, 8000); // two scans, four cosets each; no extra source replay
        for phase in ["pcs_salt_prescan", "pcs_source_accumulation", "pcs_fft", "pcs_leaf_hash",
            "pcs_merkle_merge", "pcs_commitment", "pcs_query_remainders", "pcs_opening"] {
            assert!(events.iter().any(|r| r["event"]["phase"] == phase && r["event"]["complete"] == true), "{phase}");
        }
        println!("C71_PCS_TELEMETRY_COMPONENT {}", json!({"credit": false,
            "without_recording_seconds": without, "with_recording_seconds": with,
            "durable_records": events.len(), "log_bytes": content.len(),
            "source_visits": visits, "leaf_hashes": actual.2.leaf_hashes,
            "scope": "reduced 128-column commitment and duplicate openings; no H100 credit"}));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn c71_b12_range_histogram_scan_errors_do_not_install_a_source() {
        for fault in 0..4 {
            let result = ReplayModel::new_scanned(
                Domain::Flat(10),
                [71; 32],
                [73; 32],
                Arc::new(|_| panic!("scalar scan fallback")),
                Arc::new(move |emit| {
                    emit(0, Goldilocks::from_u8(7))?;
                    match fault {
                        0 => Ok(()),                             // incomplete
                        1 => emit(2, Goldilocks::ZERO),          // index outside live prefix
                        2 => emit(1, Goldilocks::from_u64(256)), // non-byte
                        _ => Err("source failed after contribution".into()),
                    }
                }),
                Arc::new(|_, _| panic!("query reader before successful commitment")),
                2,
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn c71_b12_full_sourcewise_chain_d17_scanned_retained_original_mac() {
        let value = |i: usize| ((i * 37 + i / 11) % 251) as u8;
        let scan: BaseScan = Arc::new(move |emit| {
            for i in (0..1 << 17).rev() {
                emit(i, Goldilocks::from_u8(value(i)))?;
            }
            Ok(())
        });
        let window: ByteWindow = Arc::new(move |first, out| {
            for (offset, byte) in out.iter_mut().enumerate() {
                *byte = value(first + offset);
            }
            Ok(())
        });
        compare_source(
            17,
            Arc::new(|_| panic!("D17 scanned chain used original scalar getter")),
            (0..1 << 17).map(|i| Goldilocks::from_u8(value(i))).collect(),
            None,
            Some((scan, window)),
        );
    }

    #[test]
    fn c71_b12_scattered_initial_512_passes_matches_native_root_and_openings() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let dimension = 14;
        let config = config(dimension).unwrap();
        let live = (1 << dimension) - 13;
        let original = move |i: usize| Goldilocks::new(((i * 19 + i / 17) % 251) as u64);
        let scans = Arc::new(AtomicUsize::new(0));
        let visits = Arc::new(AtomicUsize::new(0));
        let gets = Arc::new(AtomicUsize::new(0));
        let windows = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(AtomicBool::new(false));
        let (s, v, g) = (scans.clone(), visits.clone(), gets.clone());
        let source: Getter = Arc::new(move |i| {
            g.fetch_add(1, Ordering::Relaxed);
            assert!(i < live);
            E::from(original(i))
        });
        let scan: BaseScan = Arc::new(move |emit| {
            s.fetch_add(1, Ordering::Relaxed);
            for i in (0..live).rev() {
                emit(i, original(i))?;
                v.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
        let (w, altered) = (windows.clone(), changed.clone());
        let window: ByteWindow = Arc::new(move |first, bytes| {
            w.fetch_add(1, Ordering::Relaxed);
            assert_eq!((first, bytes.len()), (0, live));
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = original(first + i).as_canonical_u64() as u8;
            }
            if altered.load(Ordering::Relaxed) {
                bytes[0] ^= 1;
            }
            Ok(())
        });
        let model = ReplayModel::new_scanned(
            Domain::Flat(dimension),
            [91; 32],
            [73; 32],
            source,
            scan,
            window,
            live,
        )
        .unwrap();
        assert_eq!(scans.load(Ordering::Relaxed), 512);
        assert_eq!(visits.load(Ordering::Relaxed), 512 * live);
        let mut histogram = [0u64; 256];
        for i in 0..live {
            histogram[original(i).as_canonical_u64() as usize] += 1;
        }
        histogram[0] += ((1 << dimension) - live) as u64;
        assert_eq!(*model.byte_histogram.lock().unwrap(), Some(histogram));
        assert_eq!(
            gets.load(Ordering::Relaxed),
            0,
            "commit must use one scan, not scalar regeneration"
        );
        let dft = Radix2DFTSmallBatch::default();
        let mut fs = Fs::new(b"independent dense commitment", request_limit(&config));
        let native = ObservedMmcs::new(fs.clone(), [73; 32]);
        let prover = HidingWhirProver::new(&config, &dft, &native);
        let values = (0..1 << dimension)
            .map(|i| if i < live { original(i) } else { Goldilocks::ZERO })
            .collect();
        let (expected, _) =
            prover.commit(Poly::new(values), &mut fs, &mut PrivateRng::from_seed([91; 32]));
        assert_eq!(&expected, model.root());
        let indices = [131071, 0, 11, 0];
        let (rows, proof) = model.tree.open(&indices).unwrap();
        native
            .inner
            .verify_multi_batch(
                model.root(),
                &[p3_matrix::Dimensions { width: 2, height: 1 << 17 }],
                &indices,
                &rows,
                &proof,
            )
            .unwrap();
        assert_eq!(rows[1], rows[3]);
        assert_eq!(scans.load(Ordering::Relaxed), 512, "openings must not recommit the source");
        assert_eq!(windows.load(Ordering::Relaxed), 1, "reuse the window across both columns");
        assert_eq!(
            gets.load(Ordering::Relaxed),
            0,
            "initial queries must not regenerate scalar windows"
        );
        changed.store(true, Ordering::Relaxed);
        assert!(
            model.tree.open(&indices).is_err(),
            "a changed original window must fail the retained Merkle root"
        );
        assert_eq!(
            windows.load(Ordering::Relaxed),
            2,
            "no window allocation is cached in the retained tree"
        );
    }

    #[test]
    fn c71_b12_scattered_coset_original_pad_positions_and_failures() {
        let dft = Radix2DFTSmallBatch::default();
        let live = 117;
        let mut code = Code {
            window: None,
            get: Arc::new(|i| E::from(Goldilocks::new((i * 7 + 9) as u64))),
            scan: Some(Arc::new(move |emit| {
                // Deliberately nonmonotone: causal order is not flat order.
                for parity in [1, 0] {
                    for i in (parity..live).step_by(2) {
                        emit(i, Goldilocks::new((i * 7 + 9) as u64))?;
                    }
                }
                Ok(())
            })),
            len: 128,
            live,
            width: 2,
            height: 1024,
            pads: Pads::Base((0..14).map(|i| Goldilocks::new((1000 + i) as u64)).collect()),
        };
        for rows in [16, 32, 64, 128] {
            for c in [0, 1, 1024 / rows - 1] {
                assert_eq!(
                    code.coset_base(c, rows, &dft).unwrap(),
                    code.coset_typed(c, rows, base_coefficient).unwrap()
                );
            }
        }
        // Four smaller cosets share one scan, including shuffled originals and
        // private pads. Their values equal four independent dense encodings.
        let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = scans.clone();
        let original_scan = code.scan.clone().unwrap();
        code.scan = Some(Arc::new(move |emit| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            original_scan(emit)
        }));
        for count in [1, 2, 4] {
            let before = scans.load(std::sync::atomic::Ordering::Relaxed);
            let group = code.coset_group(3, 16, count, &dft, None).unwrap();
            assert_eq!(scans.load(std::sync::atomic::Ordering::Relaxed), before + 1);
            assert_eq!(group.len(), count);
            for (i, cells) in group.iter().enumerate() {
                assert_eq!(*cells, code.coset_typed(3 + i, 16, base_coefficient).unwrap());
            }
        }
        assert!(code.coset_group(63, 16, 2, &dft, None).is_err());
        assert!(code.coset_group(0, 16, 3, &dft, None).is_err());
        for fault in 0..3 {
            code.scan = Some(Arc::new(move |emit| match fault {
                0 => Ok(()),
                1 => emit(live, Goldilocks::ZERO),
                _ => Err("source reconstruction failed".into()),
            }));
            assert!(code.coset_base(0, 16, &dft).is_err());
        }
        assert!(code.coset_base(64, 16, &dft).is_err());
        assert!(code.coset_base(0, 15, &dft).is_err());
    }

    #[test]
    fn c71_b12_retained_initial_oracle_shares_cache_without_source_recommit() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let reads = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(AtomicBool::new(false));
        let source_reads = reads.clone();
        let source_changed = changed.clone();
        let source: Getter = Arc::new(move |index| {
            source_reads.fetch_add(1, Ordering::Relaxed);
            let value =
                index % 251 + usize::from(index == 0 && source_changed.load(Ordering::Relaxed));
            E::from(Goldilocks::new(value as u64))
        });
        let model = ReplayModel::new(Domain::Flat(10), [91; 32], [73; 32], source.clone(), 1 << 10)
            .unwrap();
        let installed_reads = reads.load(Ordering::Relaxed);
        assert!(installed_reads > 0);
        for _ in 0..3 {
            let handle = model.initial_handle();
            let oracle = handle.downcast_ref::<Oracle>().unwrap();
            assert!(Arc::ptr_eq(&model.tree, &oracle.tree));
            assert_eq!(Arc::strong_count(&model.tree), 2);
            assert!(oracle.base);
            assert!(oracle.lease.is_none());
            assert_eq!(reads.load(Ordering::Relaxed), installed_reads);
        }
        assert_eq!(Arc::strong_count(&model.tree), 1);
        let first = model.initial_handle();
        let first = first.downcast_ref::<Oracle>().unwrap();
        let opened = first.tree.open(&[1, 33, 1]).unwrap();
        let second = model.initial_handle();
        let second = second.downcast_ref::<Oracle>().unwrap();
        let repeated = second.tree.open(&[1, 33, 1]).unwrap();
        assert_eq!(opened.0, repeated.0);
        assert_eq!(opened.1 .0, repeated.1 .0);
        assert_eq!(opened.1 .1.sibling_hashes, repeated.1 .1.sibling_hashes);
        changed.store(true, Ordering::Relaxed);
        assert!(first.tree.open(&[1, 33, 1]).is_err());
        assert!(ReplayModel::new_checked(
            Domain::Flat(10),
            model.root.clone(),
            [91; 32],
            [73; 32],
            source,
        )
        .is_err());
    }

    #[test]
    fn c71_b12_query_factors_balanced_product_and_newton_match_direct_oracle() {
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        for cap in [1_usize, 2, 4, 8, 32, 128, 1024] {
            let points: Vec<_> = (0..cap)
                .map(|index| Goldilocks::new(((index * index + 7 * index) % 19) as u64))
                .collect();
            let mut expected = vec![Goldilocks::ONE];
            for &point in &points {
                let mut next = vec![Goldilocks::ZERO; expected.len() + 1];
                for (degree, &coefficient) in expected.iter().enumerate() {
                    next[degree] -= coefficient * point;
                    next[degree + 1] += coefficient;
                }
                expected = next;
            }
            let factors = query_tree(&points, &dft);
            assert_eq!(factors.len(), cap.ilog2() as usize + 1);
            for (depth, level) in factors.iter().enumerate() {
                assert_eq!(level.len(), cap >> depth);
                assert_eq!(level.factor_len, 2usize << depth);
            }
            let root = factors.last().unwrap().factor(0);
            let (inverse, modulus) = (root.inverse.to_vec(), root.modulus.to_vec());
            assert_eq!(inverse.len(), 2 * cap);
            assert_eq!(modulus.len(), 2 * cap);
            let inverse = dft.idft(inverse);
            let modulus = dft.idft(modulus);
            assert_eq!(&modulus[..cap + 1], expected);
            assert!(modulus[cap + 1..].iter().all(|&value| value == Goldilocks::ZERO));
            assert!(inverse[cap..].iter().all(|&value| value == Goldilocks::ZERO));
            for degree in 0..cap {
                let coefficient: Goldilocks = (0..=degree)
                    .map(|offset| expected[cap - offset] * inverse[degree - offset])
                    .sum();
                assert_eq!(
                    coefficient,
                    if degree == 0 { Goldilocks::ONE } else { Goldilocks::ZERO }
                );
            }
        }
    }

    #[test]
    fn c71_b12_query_small_remainders_exact_fp3_and_cost() {
        use std::hint::black_box;
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        // Independent monic long division, in all three original Fp3 limbs.
        let mut cases = 0;
        for points in [vec![Goldilocks::ZERO], vec![-Goldilocks::ONE],
            vec![Goldilocks::ZERO, Goldilocks::ZERO],
            vec![Goldilocks::new(7), Goldilocks::new(11)],
            vec![-Goldilocks::ONE, Goldilocks::ONE],
            vec![Goldilocks::ZERO, Goldilocks::ONE, -Goldilocks::ONE, Goldilocks::new(11)],
            (0..8).map(|i| Goldilocks::new((i % 3) as u64)).collect()] {
            let tree = query_tree(&points, &dft);
            let factor = tree.last().unwrap().factor(0);
            let cap = points.len();
            let mut divisor = vec![Goldilocks::ONE];
            for &point in &points {
                let mut next = vec![Goldilocks::ZERO; divisor.len() + 1];
                for (i, &value) in divisor.iter().enumerate() {
                    next[i] -= value * point;
                    next[i + 1] += value;
                }
                divisor = next;
            }
            for seed in 0..256 {
                let values: Vec<_> = (0..2 * cap).map(|i| E::new([
                    Goldilocks::new((seed * 7919 + i * 31) as u64),
                    -Goldilocks::new((seed + i + 1) as u64),
                    Goldilocks::new((seed * seed + i * i + 7) as u64),
                ])).collect();
                let mut expected = values.clone();
                for degree in (cap..2 * cap).rev() {
                    let quotient = expected[degree];
                    for j in 0..=cap { expected[degree - cap + j] -= quotient * divisor[j]; }
                }
                assert_eq!(factor.remainder(&values[cap..], |i| values[i], &dft), expected[..cap]);
                cases += 1;
            }
        }
        // Same compiler, inputs and scopes. Reproduce the former four-FFT
        // path solely in this benchmark, without a production selector.
        let mut timings = Vec::new();
        for cap in [1_usize, 2, 4, 8] {
            let points: Vec<_> = (0..cap).map(|i| Goldilocks::new((7 + i * 19) as u64)).collect();
            let tree = query_tree(&points, &dft);
            let factor = tree.last().unwrap().factor(0);
            let high: Vec<_> = (0..cap).map(|i| -Goldilocks::new((127 + i * 7919) as u64)).collect();
            let low: Vec<_> = (0..cap).map(|i| Goldilocks::new((3 + i * 31) as u64)).collect();
            let mut sums = Vec::new();
            let mut seconds = Vec::new();
            let iterations = 128 * 1024 / cap;
            for direct in [false, true] {
                let start = std::time::Instant::now();
                let mut sum = Goldilocks::ZERO;
                for _ in 0..iterations {
                    let high = black_box(&high);
                    let values = if direct { factor.remainder(high, |i| low[i], &dft) } else {
                        let mut reversed: Vec<_> = high.iter().rev().copied().collect();
                        reversed.resize(2 * cap, Goldilocks::ZERO);
                        let mut spectrum = dft.dft_algebra(reversed);
                        for (value, &f) in spectrum.iter_mut().zip(factor.inverse) { *value *= f; }
                        let mut quotient = dft.idft_algebra(spectrum);
                        quotient.truncate(cap); quotient.reverse();
                        quotient.resize(2 * cap, Goldilocks::ZERO);
                        let mut spectrum = dft.dft_algebra(quotient);
                        for (value, &f) in spectrum.iter_mut().zip(factor.modulus) { *value *= f; }
                        let product = dft.idft_algebra(spectrum);
                        (0..cap).map(|i| low[i] - product[i]).collect()
                    };
                    sum += black_box(values)[0];
                }
                seconds.push(start.elapsed().as_secs_f64()); sums.push(sum);
            }
            assert_eq!(sums[0], sums[1]);
            timings.push(json!({"cap": cap, "iterations": iterations,
                "former_four_fft_seconds": seconds[0], "direct_seconds": seconds[1]}));
        }
        println!("C71_QUERY_SMALL_REMAINDERS {}", json!({"exact_fp3_cases": cases,
            "timings": timings, "same_binary_comparison": true,
            "scope": "four lowest levels for a 128-column/1024-point CPU opening batch",
            "gpu_execution": false, "credit": false}));
    }

    #[test]
    fn c71_b12_query_byte_windows_full_chain_original_mac_and_retained_s1() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let byte = |i: usize| ((i * 37 + i / 11) % 256) as u8;
        let original = Model::new(32, (0..1024).map(|i| i16::from(byte(i))).collect()).unwrap();
        let scans = Arc::new(AtomicUsize::new(0));
        let windows = Arc::new(AtomicUsize::new(0));
        let (s, w) = (scans.clone(), windows.clone());
        let scan: BaseScan = Arc::new(move |emit| {
            s.fetch_add(1, Ordering::Relaxed);
            for i in (0..1024).rev() {
                emit(i, Goldilocks::from_u8(byte(i)))?;
            }
            Ok(())
        });
        let window: ByteWindow = Arc::new(move |first, out| {
            w.fetch_add(1, Ordering::Relaxed);
            assert_eq!((first, out.len()), (0, 1024));
            for (i, value) in out.iter_mut().enumerate() {
                *value = byte(first + i);
            }
            Ok(())
        });
        compare_source(
            10,
            Arc::new(|_| panic!("scanned full chain used original scalar getter")),
            (0..1024).map(|i| Goldilocks::from_u8(byte(i))).collect(),
            Some(&original),
            Some((scan, window)),
        );
        let configuration = config(10).unwrap();
        let height =
            (1024 >> configuration.round_folding_factor(0)) << configuration.starting_log_inv_rate;
        let s1_height = configuration.inv_rate(0)
            * (1024
                >> (configuration.round_folding_factor(0) + configuration.round_folding_factor(1)));
        // Initial root, singleton, each S1 coset, OOD, then retention. No
        // pass is fused across a transcript barrier and later stages use S1.
        assert_eq!(
            scans.load(Ordering::Relaxed),
            height / 256
                + 1
                + s1_height / 256.min(s1_height)
                + configuration.round_parameters[0].ood_samples
                + 1
        );
        assert!(windows.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn c71_b12_scattered_extension_cosets_match_dense_original_pads() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let prefix =
            [E::ZERO, E::ONE, E::new([Goldilocks::new(3), Goldilocks::new(5), Goldilocks::new(7)])];
        let point = vec![E::from(Goldilocks::new(11)); 8];
        let dft = Radix2DFTSmallBatch::default();
        for live in [0, 1, 129, 255, 256] {
            let byte = |i: usize| Goldilocks::new((i * 19 + i / 3) as u64);
            let mut folded: Vec<_> =
                (0..256).map(|i| if i < live { E::from(byte(i)) } else { E::ZERO }).collect();
            let target =
                Poly::new(folded.clone()).eval_ext::<Goldilocks>(&Point::new(point.clone()));
            let scans = Arc::new(AtomicUsize::new(0));
            let s = scans.clone();
            let scan: BaseScan = Arc::new(move |emit| {
                s.fetch_add(1, Ordering::Relaxed);
                for i in (0..live).rev() {
                    emit(i, byte(i))?;
                }
                Ok(())
            });
            let mut state = State::new(
                Arc::new(|_| panic!("S1 coset used original scalar getter")),
                Some((scan, live)),
                &point,
                3,
                target,
                true,
            )
            .unwrap();
            for r in prefix {
                let (c0, c2) = state.round_coefficients().unwrap();
                state.fold_round_with_coefficients(c0, c2, r).unwrap();
                let half = folded.len() / 2;
                for i in 0..half {
                    let a = folded[i];
                    folded[i] = a + r * (folded[i + half] - a);
                }
                folded.truncate(half);
            }
            let code = Code {
                get: Arc::new(move |i| folded[i]),
                scan: None,
                window: None,
                len: 32,
                live: 32,
                width: 2,
                height: 256,
                pads: Pads::Extension(
                    (0..6)
                        .map(|i| {
                            E::new([
                                Goldilocks::new(i + 13),
                                Goldilocks::new(i + 17),
                                Goldilocks::new(i + 19),
                            ])
                        })
                        .collect(),
                ),
            };
            for rows in [8, 16, 64] {
                for c in [0, 1, code.height / rows - 1] {
                    let before = scans.load(Ordering::Relaxed);
                    assert_eq!(
                        code.coset(c, rows, &dft, Some(&state)).unwrap(),
                        code.coset_typed(c, rows, std::convert::identity).unwrap(),
                    );
                    assert_eq!(scans.load(Ordering::Relaxed), before + 1);
                }
            }
            assert!(code.coset(0, 0, &dft, Some(&state)).is_err());
            assert!(code.coset(32, 8, &dft, Some(&state)).is_err());
            assert!(code.coset(0, 512, &dft, Some(&state)).is_err());
        }
    }

    #[test]
    fn c71_b12_query_byte_windows_cross_columns_preserve_pads_and_fail_closed() {
        let original = |i: usize| ((i * 19 + i / 17) % 251) as u8;
        let pads: Arc<[Goldilocks]> = (0..48).map(|i| -Goldilocks::new(1000 + i)).collect();
        let root = Goldilocks::two_adic_generator(11);
        for live in [0, 1, 127, 128, 129, 511, 517, 900, 1024] {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let log = requests.clone();
            let mut code = Code {
                get: Arc::new(|_| panic!("byte query used scalar source")),
                scan: None,
                window: Some(Arc::new(move |first, bytes| {
                    log.lock().unwrap().push((first, bytes.len()));
                    assert!(first + bytes.len() <= live);
                    for (i, value) in bytes.iter_mut().enumerate() {
                        *value = original(first + i);
                    }
                    Ok(())
                })),
                len: 1024,
                live,
                width: 8,
                height: 2048,
                pads: Pads::Base(pads.clone()),
            };
            for indices in [vec![], vec![0], vec![17, 2047, 17], (0..512).rev().collect()] {
                requests.lock().unwrap().clear();
                let expected: Vec<Vec<_>> = indices
                    .iter()
                    .map(|&index| {
                        let point = root.exp_u64(index as u64);
                        (0..8)
                            .map(|column| {
                                (0..134).rev().fold(Goldilocks::ZERO, |value, j| {
                                    value * point
                                        + if j >= 128 {
                                            pads[column * 6 + j - 128]
                                        } else if column * 128 + j < live {
                                            Goldilocks::from_u8(original(column * 128 + j))
                                        } else {
                                            Goldilocks::ZERO
                                        }
                                })
                            })
                            .collect()
                    })
                    .collect();
                assert_eq!(
                    code.rows(&indices).unwrap().values,
                    expected.into_iter().flatten().collect::<Vec<_>>()
                );
                let expected_requests: Vec<_> = if indices.is_empty() {
                    Vec::new()
                } else {
                    (0..live).step_by(256).map(|i| (i, 256.min(live - i))).collect()
                };
                assert_eq!(*requests.lock().unwrap(), expected_requests);
            }
            requests.lock().unwrap().clear();
            assert!(code.rows(&[2048]).is_err());
            assert!(code.rows(&vec![0; 1025]).is_err());
            assert!(requests.lock().unwrap().is_empty());
            if live == 1024 {
                let log = requests.clone();
                code.window = Some(Arc::new(move |first, bytes| {
                    log.lock().unwrap().push((first, bytes.len()));
                    if first == 256 {
                        return Err("window reconstruction failed".into());
                    }
                    for (i, value) in bytes.iter_mut().enumerate() {
                        *value = original(first + i);
                    }
                    Ok(())
                }));
                assert_eq!(code.rows(&[0, 31]), Err("window reconstruction failed".into()));
                assert_eq!(*requests.lock().unwrap(), [(0, 256), (256, 256)]);
                code.len = 1040;
                assert!(code.rows(&[0]).is_err(), "non-dyadic byte columns rejected");
                code.len = 1024;
                code.pads = Pads::Extension(vec![E::ONE; 48]);
                assert!(code.rows(&[0]).is_err(), "byte reader cannot encode extension sources");
            }
        }
    }

    #[test]
    fn c71_b12_query_remainder_matches_original_base_and_extension_rows() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for extension in [false, true] {
            let reads = Arc::new(AtomicUsize::new(0));
            let counter = reads.clone();
            let original = move |index: usize| {
                E::new(std::array::from_fn(|limb| {
                    if limb == 0 || extension {
                        Goldilocks::new((index * index + 17 * index + 23 + limb) as u64)
                    } else {
                        Goldilocks::ZERO
                    }
                }))
            };
            let pads: Vec<_> = (0..6).map(|index| -original(index + 131)).collect();
            let code = Code {
                scan: None,
                window: None,
                get: Arc::new(move |index| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    original(index)
                }),
                len: 130,
                live: 130,
                width: 2,
                height: 1024,
                pads: if extension {
                    Pads::Extension(pads.clone())
                } else {
                    Pads::Base(pads.iter().map(|value| limbs(value)[0]).collect())
                },
            };
            let root = Goldilocks::two_adic_generator(10);
            for indices in [
                vec![],
                vec![0],
                vec![1023, 0, 31],
                vec![1, 1, 1, 7, 127],
                (0..1024).rev().collect(),
            ] {
                let expected: Vec<Vec<_>> = indices
                    .iter()
                    .map(|&index| {
                        let point = root.exp_u64(index as u64);
                        (0..2)
                            .flat_map(|column| {
                                let value = (0..68).rev().fold(E::ZERO, |value, offset| {
                                    value * point
                                        + if offset < 65 {
                                            original(column * 65 + offset)
                                        } else {
                                            pads[column * 3 + offset - 65]
                                        }
                                });
                                limbs(&value)[..if extension { 3 } else { 1 }].to_vec()
                            })
                            .collect()
                    })
                    .collect();
                reads.store(0, Ordering::Relaxed);
                assert_eq!(
                    code.rows(&indices).unwrap().values,
                    expected.into_iter().flatten().collect::<Vec<_>>()
                );
                assert_eq!(reads.load(Ordering::Relaxed), if indices.is_empty() { 0 } else { 130 });
            }
            reads.store(0, Ordering::Relaxed);
            assert!(code.rows(&[1024]).is_err());
            assert!(code.rows(&vec![0; 1025]).is_err());
            assert_eq!(reads.load(Ordering::Relaxed), 0);
        }
        println!("C71_QUERY_REMAINDER base_and_extension=true original_pads=true one_source_read_per_batch=true canonical_credit=false");
    }

    #[test]
    fn c71_b12_replay_base_rejects_extension_coefficients_before_encoding() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let code = Code {
            scan: None,
            window: None,
            get: Arc::new(|_| E::new([Goldilocks::ONE, Goldilocks::ONE, Goldilocks::ZERO])),
            len: 8,
            live: 8,
            width: 2,
            height: 64,
            pads: Pads::Base(vec![Goldilocks::ONE; 2].into()),
        };
        assert!(catch_unwind(AssertUnwindSafe(|| code.coset(
            0,
            8,
            &Radix2DFTSmallBatch::default(),
            None
        )))
        .is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| code.rows(&[1, 2]))).is_err());
        assert_eq!(std::mem::size_of::<Goldilocks>(), 8);
        assert_eq!(std::mem::size_of::<E>(), 24);
    }

    #[test]
    fn c71_b12_query_split_zero_tail_preserves_original_pad_and_rows() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for extension in [false, true] {
            for live in [0, 1, 63, 64, 65, 125, 128] {
                for pad_rows in [3, 17] {
                    let original = move |index: usize| {
                        E::new(std::array::from_fn(|limb| {
                            if limb == 0 || extension {
                                Goldilocks::new(
                                    (index * index + 11 * index + 7 + 101 * limb) as u64,
                                )
                            } else {
                                Goldilocks::ZERO
                            }
                        }))
                    };
                    let pads: Vec<_> =
                        (0..2 * pad_rows).map(|index| -original(index + 137)).collect();
                    let reads = Arc::new(AtomicUsize::new(0));
                    let counter = reads.clone();
                    let code = Code {
                        scan: None,
                        window: None,
                        get: Arc::new(move |index| {
                            assert!(index < live, "public zero tail must not read the source");
                            counter.fetch_add(1, Ordering::Relaxed);
                            original(index)
                        }),
                        len: 128,
                        live,
                        width: 2,
                        height: 1024,
                        pads: if extension {
                            Pads::Extension(pads.clone())
                        } else {
                            Pads::Base(pads.iter().map(|value| limbs(value)[0]).collect())
                        },
                    };
                    for cap in [1, 2, 4, 8, 32, 128] {
                        let indices: Vec<_> = (0..cap).map(|index| 1023 - index / 2).collect();
                        let expected: Vec<Vec<_>> = indices
                            .iter()
                            .map(|&index| {
                                let point =
                                    Goldilocks::two_adic_generator(10).exp_u64(index as u64);
                                (0..2)
                                    .flat_map(|column| {
                                        let value = (0..64 + pad_rows).rev().fold(
                                            E::ZERO,
                                            |value, offset| {
                                                value * point
                                                    + if offset >= 64 {
                                                        pads[column * pad_rows + offset - 64]
                                                    } else if column * 64 + offset < live {
                                                        original(column * 64 + offset)
                                                    } else {
                                                        E::ZERO
                                                    }
                                            },
                                        );
                                        limbs(&value)[..if extension { 3 } else { 1 }].to_vec()
                                    })
                                    .collect()
                            })
                            .collect();
                        reads.store(0, Ordering::Relaxed);
                        assert_eq!(
                            code.rows(&indices).unwrap().values,
                            expected.into_iter().flatten().collect::<Vec<_>>()
                        );
                        assert_eq!(reads.load(Ordering::Relaxed), live);
                    }
                }
            }
        }
        assert!(ReplayModel::new(
            Domain::Flat(10),
            [31; 32],
            [43; 32],
            Arc::new(|_| panic!("invalid prefix read")),
            1025
        )
        .is_err());
        println!("C71_SPLIT_PAD original_exponent=true zero_tail_reads=0 base_and_extension=true canonical_credit=false");
    }

    #[test]
    fn c71_b12_native_remainder_fft_vectors() {
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        for extension in [false, true] {
            let original = move |index: usize| {
                E::new(std::array::from_fn(|limb| {
                    if index % 64 >= 61 || (limb != 0 && !extension) {
                        Goldilocks::ZERO
                    } else {
                        Goldilocks::new((index * index + 17 * index + 23 + 101 * limb) as u64)
                    }
                }))
            };
            let pads: Vec<_> = (0..6).map(|index| -original(index + 131)).collect();
            let code = Code {
                scan: None,
                window: None,
                get: Arc::new(original),
                len: 128,
                live: 128,
                width: 2,
                height: 1024,
                pads: if extension {
                    Pads::Extension(pads)
                } else {
                    Pads::Base(pads.iter().map(|value| limbs(value)[0]).collect())
                },
            };
            for side in [2_usize, 4, 8, 16] {
                let cap = side * side / 2;
                let mut indices: Vec<_> = (0..cap - usize::from(cap > 2))
                    .map(|index| (1023 + 31 * index) % code.height)
                    .collect();
                indices[1] = indices[0];
                let mut points: Vec<_> = indices
                    .iter()
                    .map(|&index| Goldilocks::two_adic_generator(10).exp_u64(index as u64))
                    .collect();
                points.resize(cap, Goldilocks::ZERO);
                let tree = query_tree(&points, &dft);
                let factors = tree.last().unwrap().factor(0);
                let coefficients = (code.len + code.pads.len()) / code.width;
                let mut source = Vec::new();
                let mut expected = Vec::new();
                for column in 0..code.width {
                    let mut remainder = vec![E::ZERO; cap];
                    for block in (0..coefficients.div_ceil(cap)).rev() {
                        remainder = factors.remainder(
                            &remainder,
                            |offset| {
                                let index = block * cap + offset;
                                if index < coefficients {
                                    code.coefficient(column, index)
                                } else {
                                    E::ZERO
                                }
                            },
                            &dft,
                        );
                    }
                    for limb in 0..if extension { 3 } else { 1 } {
                        source.extend((0..coefficients).map(|offset| {
                            limbs(&code.coefficient(column, offset))[limb].as_canonical_u64()
                        }));
                        expected.extend(
                            remainder.iter().map(|value| limbs(value)[limb].as_canonical_u64()),
                        );
                    }
                }
                let rows = code.rows(&indices).unwrap();
                println!(
                    "C71_NATIVE_REMAINDER {}",
                    serde_json::json!({
                        "side": side, "columns": code.columns(), "coefficients": coefficients,
                        "queries": indices.len(), "extension": extension,
                        "inverse": factors.inverse.iter().map(|value| value.as_canonical_u64()).collect::<Vec<_>>(),
                        "modulus": factors.modulus.iter().map(|value| value.as_canonical_u64()).collect::<Vec<_>>(),
                        "source": source, "expected": expected,
                        "points": points[..indices.len()].iter().map(|value| value.as_canonical_u64()).collect::<Vec<_>>(),
                        "rows": rows.values.iter().map(|value| value.as_canonical_u64()).collect::<Vec<_>>(),
                    })
                );
            }
        }
    }

    #[test]
    fn c71_b12_full_sourcewise_chain_matches_native_bytes() {
        let source: Getter = Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
        let values = (0..1024).map(|i| limbs(&source(i))[0]).collect();
        compare_source(10, source, values, None, None);
    }

    fn native_hash_fixture(
        runtime: &mut crate::c71_matrix::range::windowed::native::Runtime,
        source: &[u64], salts: &[[Goldilocks; 4]], rows: usize,
    ) -> crate::c71_matrix::range::windowed::native::Buffer {
    let ring = runtime.pcs_words(8 * rows).unwrap();
    let mut cells = source[..8 * rows].to_vec();
    runtime.pcs_upload(&ring, 0, &cells).unwrap();
    let mut states = runtime.pcs_hash_start(&ring).unwrap();
    for first in (4..=116).step_by(8) {
        // The previous trailing four columns stay resident in slots
        // 4..7. Overwrite consumed slots with the next four columns.
        cells[..4 * rows].copy_from_slice(&source[(first + 4) * rows..(first + 8) * rows]);
        runtime.pcs_upload(&ring, 0, &cells[..4 * rows]).unwrap();
        runtime.pcs_hash_step(&ring, &states, first).unwrap();
        if first < 116 {
            cells[4 * rows..].copy_from_slice(&source[(first + 8) * rows..(first + 12) * rows]);
            runtime.pcs_upload(&ring, 4 * rows, &cells[4 * rows..]).unwrap();
        }
    }
    cells[..4 * rows].copy_from_slice(&source[124 * rows..128 * rows]);
    runtime.pcs_upload(&ring, 0, &cells[..4 * rows]).unwrap();
    // Salts remain exactly the original sampler stream, including
    // seek/replay. The device consumes bounded bands in leaf order.
    let band = 64.min(rows);
    let salt_buffer = runtime.pcs_words(4 * band).unwrap();
    for first in (0..rows).step_by(band) {
        let words: Vec<_> = (0..4).flat_map(|col| {
            let salts = &salts;
            (first..first + band).map(move |row| salts[row][col].as_canonical_u64())
        }).collect();
        runtime.pcs_upload(&salt_buffer, 0, &words).unwrap();
        runtime.pcs_hash_finish(&ring, &salt_buffer, &mut states, first).unwrap();
    }
    runtime.release_buffer(salt_buffer).unwrap();
    runtime.release_buffer(ring).unwrap();
        states
    }

    fn native_weight_source_fixture(dimension: usize, config: &device::Config)
        -> (NativeWeights, Getter, Arc<std::sync::atomic::AtomicU64>) {
        assert!((15..=17).contains(&dimension));
        let n = (1 << dimension) / 128;
        let weights = Arc::new((0..96 * n).map(|i| match i % 8 {
            0 => 0, 1 => 32767, 2 => -32767, 3 => 1, 4 => -1,
            _ => (((i * 19 + i / 96 * 23) % 65535) as i32 - 32767) as i16,
        }).collect::<Vec<_>>());
        let mut runtime = device::Runtime::new(config).unwrap();
        runtime.install_weights(weights.clone(), [17; 32]).unwrap();
        let original = weights.clone();
        let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = calls.clone();
        let get: Getter = Arc::new(move |i| {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if i >= 96 * n { return E::ZERO; }
            let address = if i < 64 * n { i / 64 * 96 + i % 64 }
                else { let local = i - 64 * n; local / 32 * 96 + 64 + local % 32 };
            let x = i64::from(original[address]);
            E::from(if x < 0 { -Goldilocks::new((-x) as u64) } else { Goldilocks::new(x as u64) })
        });
        (NativeWeights { runtime: Arc::new(Mutex::new(runtime)), weights, layout: [17; 32], tiles: vec![
            device::WeightTile { first: 0, count: (64 * n) as u64, packed_first: 0, packed_stride: 96, columns: 64 },
            device::WeightTile { first: (64 * n) as u64, count: (32 * n) as u64, packed_first: 64, packed_stride: 96, columns: 32 },
        ] }, get, calls)
    }

    #[test]
    fn c71_b12_native_weight_tree_exact_roots_openings_and_work() {
        let mut fixture = device::tests::fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let (native, get, calls) = native_weight_source_fixture(15, &fixture.config);
        let owner = native.runtime.clone();
        let live = native.weights.len();
        let _budget = crate::c71_matrix::census::Budget::new(&native.weights).unwrap();
        let path = std::env::temp_dir().join(format!("c71-native-w-tree-{}-{}.jsonl",
            std::process::id(), rand::random::<u64>()));
        let recording = crate::c71_matrix::progress::Recording::start(&path).unwrap();
        let started = std::time::Instant::now();
        let model = ReplayModel::new_native_weights(Domain::Flat(15), [91; 32], [73; 32],
            get.clone(), live, native).unwrap();
        let native_s = started.elapsed().as_secs_f64();
        let native_census = crate::c71_matrix::census::simultaneous();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(recording);
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&path).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        std::fs::remove_file(&path).unwrap();
        let end = events.iter().find(|r| r["event"]["phase"] == "pcs_w_resident" && r["event"]["complete"] == true).unwrap();
        let height = model.tree.geometry().0;
        let (rows, cut) = replay_tree::native_weight_geometry(height).unwrap();
        let groups = height / rows / 32;
        assert_eq!(end["event"]["work"]["source_visits"], (live * groups) as u64);
        assert_eq!(end["event"]["work"]["equivalent_source_scans"], groups);
        let stats = owner.lock().unwrap().stats().unwrap();
        assert_eq!(stats.arena_bytes, 0);
        assert_eq!(stats.d2h_bytes, (132 * groups + (2 * height / cut - 1) * 32) as u64);
        let started = std::time::Instant::now();
        let reference = ReplayModel::new(Domain::Flat(15), [91; 32], [73; 32], get, live).unwrap();
        let reference_s = started.elapsed().as_secs_f64();
        assert_eq!(model.root, reference.root);
        assert_eq!(model.pads, reference.pads);
        assert_eq!(model.tree.work, reference.tree.work);
        let indices = [0, height - 1, 257, 255, 256, height / 2, 0, 257];
        assert_eq!(serde_json::to_vec(&model.tree.open(&indices).unwrap()).unwrap(),
            serde_json::to_vec(&reference.tree.open(&indices).unwrap()).unwrap());
        println!("C71_NATIVE_W_TREE_LOCAL {}", json!({"domain_log2": 15,
            "native_geometry": model.tree.geometry(), "reference_geometry": reference.tree.geometry(),
            "native_commitment_host_s": native_s, "reference_commitment_o0_s": reference_s,
            "native": stats, "cache": model.retained_census(), "source_visits": live * groups,
            "durable_records": events.len(), "census": crate::c71_matrix::census::simultaneous(),
            "native_commitment_census": native_census,
            "different_compiler_optimization_no_speedup_claim": true, "gpu_execution": false, "credit": false}));
        owner.lock().unwrap().close().unwrap();
    }

    #[test]
    fn c71_b12_native_weight_composed_full_chain_original_mac_and_transcript() {
        let mut fixture = device::tests::fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let (native, get, _) = native_weight_source_fixture(15, &fixture.config);
        let owner = native.runtime.clone();
        let _budget = crate::c71_matrix::census::Budget::new(&native.weights).unwrap();
        // Preserve the durable prefix on the local deadline; it identifies
        // which unchanged proof phase still needs acceleration.
        let path = std::env::temp_dir().join(format!("c71-native-w-chain-{}-{}.jsonl",
            std::process::id(), rand::random::<u64>()));
        let _recording = crate::c71_matrix::progress::Recording::start(&path).unwrap();
        eprintln!("C71_NATIVE_W_CHAIN_PROGRESS {}", path.display());
        let values = (0..1 << 15).map(|i| base_coefficient(get(i))).collect();
        compare_source_with_native(15, get, values, None, None, Some(native), true);
        let stats = owner.lock().unwrap().close().unwrap();
        assert_eq!(stats.arena_bytes, 0);
        assert_eq!(stats.stopped, 0);
    }

    #[test]
    #[ignore = "D15 reference/prover/dual verification with CPU opening replay exceeds the local 60 s limit"]
    fn c71_b12_native_weight_uncached_full_chain_performance_obligation() {
        let mut fixture = device::tests::fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let (native, get, _) = native_weight_source_fixture(15, &fixture.config);
        let owner = native.runtime.clone();
        let _budget = crate::c71_matrix::census::Budget::new(&native.weights).unwrap();
        let values = (0..1 << 15).map(|i| base_coefficient(get(i))).collect();
        compare_source_with_native(15, get, values, None, None, Some(native), false);
        owner.lock().unwrap().close().unwrap();
    }

    #[test]
    fn c71_b12_native_weight_tree_fail_closed_without_scalar_fallback() {
        let mut fixture = device::tests::fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let injection = device::tests::Injection::new(&fixture.config);
        for fault in 0..8 {
            let (mut native, get, calls) = native_weight_source_fixture(15, &fixture.config);
            let owner = native.runtime.clone();
            let _budget = crate::c71_matrix::census::Budget::new(&native.weights).unwrap();
            let mut live = native.weights.len();
            let mut domain = Domain::Flat(15);
            match fault {
                0 => native.layout = [18; 32],
                1 => native.weights = Arc::new(native.weights.as_ref().clone()),
                2 => { native.tiles.pop(); },
                3 => live -= 1,
                4 => { domain = Domain::Flat(10); live = 1024; },
                5 => injection.set(1),
                6 => injection.set(2),
                7 => injection.set(9),
                _ => unreachable!(),
            }
            assert!(ReplayModel::new_native_weights(domain, [91; 32], [73; 32], get, live, native).is_err());
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(owner.lock().unwrap().stats().unwrap().stopped, 1);
            injection.set(0);
            let stats = owner.lock().unwrap().close().unwrap();
            assert_eq!(stats.arena_bytes, 0);
            assert_eq!(stats.cleanup_failed, 0);
        }
        println!("C71_NATIVE_W_TREE_REJECTIONS {{\"cases\":8,\"scalar_fallback_calls\":0,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_weight_geometry_and_resource_envelope() {
        let (rows, cut) = replay_tree::native_weight_geometry(1 << 32).unwrap();
        assert_eq!((rows, cut), (1 << 20, 4096));
        // A keeps its existing four-coset schedule, independently of W.
        let (a_rows, _) = replay_tree::geometry(1 << 31, 128).unwrap();
        assert_eq!((1usize << 31) / a_rows / replay_tree::coset_group_size(1 << 31, 128), 512);
        let parts = json!({"ring": rows * 32 * 8 * 8, "cv": rows * 32 * 32,
            "low_powers": rows * 32 * 8, "high_powers": 257 * 32 * 8,
            "twiddles": rows * 8, "pads": 128 * 1536 * 8, "frontier": rows * 7 * 32,
            "salt_band": 65536 * 4 * 8, "weight_and_hash_flags": 2 * 256,
            "tiles": (3156 * 40 + 255) & !255});
        let device = parts.as_object().unwrap().values().map(|v| v.as_u64().unwrap()).sum::<u64>();
        assert_eq!(device, 3_736_793_344);
        let named_host = 2 * rows * 8 + (2 * rows - 1) * 32 + 2 * 128 * 1536 * 8
            + 65536 * 4 * 8 + 3156 * 40 + 37152;
        let envelope = device + named_host as u64 + 785_789_696;
        assert!(envelope < crate::c71_matrix::census::PAYLOAD_LIMIT);
        println!("C71_NATIVE_W_RESOURCE_ENVELOPE {}", json!({"rows": rows, "cut": cut,
            "groups": 128, "device_parts": parts, "device_component_bytes": device,
            "named_host_payload_bytes": named_host, "component_plus_device_replay_upper_bytes": envelope,
            "remaining_payload_for_other_host_owners_bytes": crate::c71_matrix::census::PAYLOAD_LIMIT - envelope,
            "scope": "geometry screen before other host owners; their actual capacities are charged by the joint counter",
            "geometry_only": true, "gpu_execution": false, "credit": false}));
    }

    #[test]
    fn c71_b12_native_source_geometry_and_resource_envelope() {
        let (rows, cut) = replay_tree::native_source_geometry(1 << 31).unwrap();
        assert_eq!((rows, cut), (1 << 20, 4096));
        let groups = (1usize << 31) / rows / 4;
        assert_eq!(groups, 512);
        for height in [1024, 2048, 1 << 15, 1 << 17, 1 << 18, 1usize << 31] {
            let (r, _) = replay_tree::native_source_geometry(height).unwrap();
            let (cpu_r, _) = replay_tree::geometry(height, 128).unwrap();
            assert!(height / r / 4 <= height / cpu_r / replay_tree::coset_group_size(height, 128));
        }
        assert!(replay_tree::native_source_geometry(512).is_err());
        let common = json!({"values":128 * 4 * rows * 8,"frontier":rows * groups.ilog2() as usize * 32,
            "twiddles":rows * 8,"pads":128 * 1536 * 8,"salt_band":65536 * 4 * 8});
        let common_bytes = common.as_object().unwrap().values().map(|v| v.as_u64().unwrap()).sum::<u64>();
        let accumulation = common_bytes + (4 * rows * 8 + 129 * 4 * 8 + 256 * 8 + 256) as u64;
        let hashing = common_bytes + (4 * rows * 32 + 256) as u64;
        let named_host = (2 * ((1usize << 31) / cut) - 1) * 32 + rows * 8
            + ((1usize << 31) / cut) * 8 + 128 * 1536 * 8 + 65536 * 4 * 8 + 256 * 8 + 37152;
        let envelope = accumulation.max(hashing) + 785_789_696 + named_host as u64;
        assert!(envelope < crate::c71_matrix::census::PAYLOAD_LIMIT);
        println!("C71_NATIVE_A_RESOURCE_ENVELOPE {}", json!({"rows":rows,"cut":cut,"groups":groups,
            "cosets_per_reconstruction":4,"columns_per_reconstruction":128,
            "common_device_parts":common,"device_accumulation_phase_bytes":accumulation,
            "device_hash_phase_bytes":hashing,"named_host_bytes":named_host,
            "component_plus_device_replay_upper_bytes":envelope,
            "remaining_payload_for_other_host_owners_bytes":crate::c71_matrix::census::PAYLOAD_LIMIT-envelope,
            "scope":"phase envelope before other host owners; no full pipeline/physical memory claim",
            "geometry_only":true,"gpu_execution":false,"credit":false}));
    }

    #[test]
    fn c71_b12_native_source_four_cosets_fft_hash_original_bytes() {
        use device::{PcsSourceShape, PcsSourceTile, Pointwise, Runtime};
        use device::tests::{fixture, Injection};
        use super::super::streaming::{digest, hash_rows_in_place, node_hash};
        let mut fixture = fixture(128);
        fixture.config.arena_bytes = 8 << 20;
        let injection = Injection::new(&fixture.config);
        let weights = Arc::new(Vec::new());
        let _budget = crate::c71_matrix::census::Budget::new(&weights).unwrap();
        for (n, rows, pad, first_coset) in [(8, 4, 3, 0), (32, 16, 35, 28), (512, 4, 1536, 2044)] {
            let cosets = 16 * n / rows;
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let mut originals = Vec::new();
            let mut original_bytes = Vec::new();
            for (id, (base_rows, columns, width)) in [(3, 5, 2), (5, 7, 4), (9, 11, 6)].into_iter().enumerate() {
                let source_rows = base_rows * (n / 8);
                let stride = columns + 2;
                let words: Vec<i16> = (0..3 + source_rows * stride).map(|i|
                    [-32767, -257, -1, 0, 255, 32767][(i + id) % 6]).collect();
                let input = runtime.upload_signed(&words).unwrap();
                let coefficient = match width { 2 => 1, 4 => 1 << 14, _ => 1 << 30 };
                let output = if width == 2 { input } else {
                    let raw = runtime.pointwise([Some((&input, 0)), None], words.len(),
                        Pointwise { a: coefficient, b: 0, multiply: 0 }).unwrap();
                    runtime.release_buffer(input).unwrap();
                    raw
                };
                let first = original_bytes.len();
                for row in 0..source_rows {
                    for column in 0..columns {
                        let word = i64::from(words[3 + row * stride + column]) * coefficient;
                        let biased = (word + (1i64 << (8 * width - 1))).to_le_bytes();
                        original_bytes.extend_from_slice(&biased[..width]);
                    }
                }
                originals.push((output, first, source_rows, columns, stride, width));
            }
            let original_bytes = Arc::new(original_bytes);
            let original = original_bytes.clone();
            let get: Getter = Arc::new(move |i| E::from(Goldilocks::from_u8(original.get(i).copied().unwrap_or(0))));
            let mut rng = PrivateRng::from_seed([112; 32]);
            let pads: Arc<[Goldilocks]> = (0..128 * pad).map(|_| rng.random()).collect();
            let code = Code { get, scan: None, window: None, len: 128 * n, live: original_bytes.len(),
                width: 128, height: rows * cosets, pads: Pads::Base(pads.clone()) };
            let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
            let started = std::time::Instant::now();
            let reference: Vec<_> = (first_coset..first_coset + 4).map(|c| code.coset_base(c, rows, &dft).unwrap()).collect();
            let reference_s = started.elapsed().as_secs_f64();
            let mut expected = Vec::with_capacity(128 * 4 * rows);
            for column in 0..128 {
                for values in &reference { expected.extend_from_slice(&values[column * rows..(column + 1) * rows]); }
            }
            let shape = PcsSourceShape { message_rows: n as u64, rows: rows as u64, live: code.live as u64,
                pad_rows: pad as u32, cosets: cosets as u32, first_coset: first_coset as u32 };
            let pad_buffer = runtime.pcs_words(pads.len()).unwrap();
            runtime.pcs_upload(&pad_buffer, 0, &pads.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>()).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(rows.ilog2() as usize).unwrap();
            let (low, high) = runtime.pcs_source_powers(shape).unwrap();
            let before = runtime.stats().unwrap();
            let started = std::time::Instant::now();
            let (mut values, mut histogram) = runtime.pcs_source_begin(&low, &high, shape, first_coset == 0).unwrap();
            let mut tiles = 0;
            for (input, first, source_rows, columns, stride, width) in originals {
                for row in (0..source_rows).step_by(3).rev() {
                    runtime.pcs_source_tile(&input, PcsSourceTile {
                        input_first: (3 + row * stride) as u64, input_stride: stride as u64,
                        rows: 3.min(source_rows - row) as u64, columns: columns as u64,
                        original_first: (first + row * columns * width) as u64,
                        byte_first: 0, width: width as u32, signed_width: width as u32,
                    }).unwrap();
                    tiles += 1;
                }
                // Deferred driver must consume the borrowed input before release.
                runtime.release_buffer(input).unwrap();
            }
            injection.expect_pcs(&expected);
            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pad_buffer, &twiddles).unwrap();
            assert_eq!(runtime.stats().unwrap().d2h_bytes - before.d2h_bytes, 4);
            if let Some(h) = histogram.take() {
                let mut counts = [0i64; 256];
                runtime.download_words(&h, 0, &mut counts).unwrap();
                let mut expected_counts = [0i64; 256];
                for &byte in original_bytes.iter() { expected_counts[byte as usize] += 1; }
                assert_eq!(counts, expected_counts);
                runtime.release_buffer(h).unwrap();
            }
            let accumulated_s = started.elapsed().as_secs_f64();
            let group_rows = 4 * rows;
            let band = 8.min(group_rows);
            let salt_buffer = runtime.pcs_words(4 * band).unwrap();
            let mut salt_rng = PrivateRng::from_seed([73; 32]);
            let natural_salts: Vec<[Goldilocks; 4]> = (0..rows * cosets).map(|_| std::array::from_fn(|_| salt_rng.random())).collect();
            let salt = |leaf: usize| natural_salts[leaf % rows * cosets + first_coset + leaf / rows];
            let mut roots = runtime.pcs_full_hash_begin(group_rows).unwrap();
            for first in (0..group_rows).step_by(band) {
                let words: Vec<_> = (0..4).flat_map(|col| (first..first + band).map(move |leaf| salt(leaf)[col].as_canonical_u64())).collect();
                runtime.pcs_upload(&salt_buffer, 0, &words).unwrap();
                runtime.pcs_full_hash_band(&values, &salt_buffer, &mut roots, first).unwrap();
            }
            let after = runtime.stats().unwrap();
            assert_eq!(after.d2h_bytes - before.d2h_bytes, 8 + if first_coset == 0 { 2048 } else { 0 });
            assert_eq!(after.h2d_bytes - before.h2d_bytes, (4 * group_rows * 8) as u64);
            assert_eq!(after.launches - before.launches, tiles + 12 + (group_rows / band) as u64);
            hash_rows_in_place(&mut expected, group_rows, 128, salt).unwrap();
            let mut expected: Vec<_> = (0..group_rows).map(|row| digest(&expected, group_rows, row)).collect();
            assert_eq!(runtime.pcs_digests(&roots, 0, group_rows).unwrap(), expected);
            for buffer in values { runtime.release_buffer(buffer).unwrap(); }
            for _ in 0..2 {
                let next = runtime.pcs_nodes_strided(&roots, rows).unwrap();
                runtime.release_buffer(roots).unwrap(); roots = next;
                expected = (0..expected.len() / 2).map(|i| {
                    let left = 2 * (i / rows) * rows + i % rows;
                    node_hash(expected[left], expected[left + rows])
                }).collect();
                assert_eq!(runtime.pcs_digests(&roots, 0, expected.len()).unwrap(), expected);
            }
            for buffer in [roots, low, high, twiddles, pad_buffer, salt_buffer] { runtime.release_buffer(buffer).unwrap(); }
            assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
            println!("C71_PCS_SOURCE_COMPONENT {}", json!({"message_rows":n,"coset_rows":rows,"pad_rows":pad,
                "first_coset":first_coset,"original_bytes":code.live,"cosets_per_reconstruction":4,"reconstructions":1,
                "tiles":tiles,"reference_accumulation_fft_s":reference_s,"native_host_accumulation_fft_s":accumulated_s,
                "native_capacity_peak_bytes":after.peak_capacity_bytes,"source_d2h_bytes":0,
                "histogram_d2h_bytes":if first_coset==0 {2048}else{0},"d2h_flag_bytes":8,
                "native_owner_host_bytes":after.host_owner_bytes,"gpu_execution":false,"credit":false,
                "resource_census":crate::c71_matrix::census::simultaneous()}));
            runtime.close().unwrap();
        }
    }

    #[test]
    fn c71_b12_native_weight_columns_exact_signed_pads_fft_hash() {
        use crate::c71_matrix::range::windowed::native::{Runtime, WeightShape, WeightTile, tests::{fixture, Injection}};
        use super::super::streaming::{digest, hash_rows_in_place, node_hash};
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let injection = Injection::new(&fixture.config);
        for (n, rows, cosets, pad, first_coset) in [
            (64, 4, 256, 6, 32),
            (256, 16, 256, 35, 224),
            (4096, 16, 4096, 1536, 4032),
        ] {
            let weights = Arc::new((0..96 * n).map(|i| match i % 8 {
                0 => 0, 1 => 32767, 2 => -32767, 3 => 1, 4 => -1,
                _ => (((i * 19 + (i / 96) * 23) % 65535) as i32 - 32767) as i16,
            }).collect::<Vec<i16>>());
            let _budget = crate::c71_matrix::census::Budget::new(&weights).unwrap();
            let original = weights.clone();
            let get: Getter = Arc::new(move |i| {
                if i >= 96 * n { return E::ZERO; }
                let packed = if i < 64 * n { (i / 64) * 96 + i % 64 }
                    else { let local = i - 64 * n; (local / 32) * 96 + 64 + local % 32 };
                let signed = i64::from(original[packed]);
                E::from(if signed < 0 { -Goldilocks::new((-signed) as u64) }
                    else { Goldilocks::new(signed as u64) })
            });
            let mut rng = PrivateRng::from_seed([112; 32]);
            let pads: Arc<[Goldilocks]> = (0..128 * pad).map(|_| rng.random()).collect();
            let code = Code { get, scan: None, window: None, len: 128 * n,
                live: 96 * n, width: 128, height: rows * cosets, pads: Pads::Base(pads.clone()) };
            let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
            let started = std::time::Instant::now();
            let reference: Vec<_> = (first_coset..first_coset + 32)
                .map(|c| code.coset_base(c, rows, &dft).unwrap()).collect();
            let reference_s = started.elapsed().as_secs_f64();
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            runtime.install_weights(weights.clone(), [17; 32]).unwrap();
            let tiles = runtime.pcs_weight_tiles(&weights, [17; 32], &[
                WeightTile { first: 0, count: (64 * n) as u64, packed_first: 0, packed_stride: 96, columns: 64 },
                WeightTile { first: (64 * n) as u64, count: (32 * n) as u64, packed_first: 64, packed_stride: 96, columns: 32 },
            ]).unwrap();
            let pad_buffer = runtime.pcs_words(pads.len()).unwrap();
            runtime.pcs_upload(&pad_buffer, 0, &pads.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>()).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(rows.ilog2() as usize).unwrap();
            let ring = runtime.pcs_ring(rows).unwrap();
            let mut shape = WeightShape { message_rows: n as u64, rows: rows as u64,
                pad_rows: pad as u32, cosets: cosets as u32, first_coset: first_coset as u32,
                first_column: 0, slots: 0 };
            let (low, high) = runtime.pcs_coset_powers(shape).unwrap();
            let before = runtime.stats().unwrap();
            let started = std::time::Instant::now();
            let mut fill = |runtime: &mut Runtime, column: usize, slots| {
                shape.slots = slots;
                shape.first_column = column as u32;
                let mut expected = Vec::with_capacity(4 * 32 * rows);
                for column in shape.first_column as usize..shape.first_column as usize + 4 {
                    for values in &reference {
                        expected.extend_from_slice(&values[column * rows..(column + 1) * rows]);
                    }
                }
                injection.expect_pcs(&expected);
                runtime.pcs_weight_columns(&tiles, &pad_buffer, &low, &high, &twiddles, &ring, shape).unwrap();
            };
            fill(&mut runtime, 0, 0);
            fill(&mut runtime, 4, 4);
            let mut states = runtime.pcs_hash_start(&ring).unwrap();
            for first in (4..=116).step_by(8) {
                fill(&mut runtime, first + 4, 0);
                runtime.pcs_hash_step(&ring, &states, first).unwrap();
                if first < 116 { fill(&mut runtime, first + 8, 4); }
            }
            fill(&mut runtime, 124, 0);
            let scan_stats = runtime.stats().unwrap();
            assert_eq!(scan_stats.d2h_bytes - before.d2h_bytes, 128); // 32 terminal flags, no field downloads
            assert_eq!(scan_stats.launches - before.launches, 32 * 6 + 16); // scan/FFT + leaf start/steps
            let group_rows = 32 * rows;
            let band = 64.min(group_rows);
            let salt_buffer = runtime.pcs_words(4 * band).unwrap();
            let mut salt_rng = PrivateRng::from_seed([73; 32]);
            let natural_salts: Vec<[Goldilocks; 4]> = (0..rows * cosets)
                .map(|_| std::array::from_fn(|_| salt_rng.random())).collect();
            let salt = |leaf: usize| natural_salts[leaf % rows * cosets + first_coset + leaf / rows];
            for first in (0..group_rows).step_by(band) {
                let words: Vec<_> = (0..4).flat_map(|col| (first..first + band)
                    .map(move |leaf| salt(leaf)[col].as_canonical_u64())).collect();
                runtime.pcs_upload(&salt_buffer, 0, &words).unwrap();
                runtime.pcs_hash_finish(&ring, &salt_buffer, &mut states, first).unwrap();
            }
            let after = runtime.stats().unwrap();
            assert_eq!(after.d2h_bytes - before.d2h_bytes, 132); // flags only, including completed hash
            assert_eq!(after.launches - before.launches, 32 * 6 + 16 + (group_rows / band) as u64);
            assert_eq!(after.stopped, 0);
            let native_s = started.elapsed().as_secs_f64();
            for buffer in [ring, low, high, twiddles, pad_buffer, tiles, salt_buffer] { runtime.release_buffer(buffer).unwrap(); }
            let mut expected = vec![0; 128 * group_rows];
            for column in 0..128 {
                for (lane, values) in reference.iter().enumerate() {
                    expected[column * group_rows + lane * rows..column * group_rows + (lane + 1) * rows]
                        .copy_from_slice(&values[column * rows..(column + 1) * rows]);
                }
            }
            hash_rows_in_place(&mut expected, group_rows, 128, salt).unwrap();
            let mut expected: Vec<_> = (0..group_rows).map(|row| digest(&expected, group_rows, row)).collect();
            assert_eq!(runtime.pcs_digests(&states, 0, group_rows).unwrap(), expected);
            while expected.len() > rows {
                expected = (0..expected.len() / 2).map(|i| {
                    let left = 2 * (i / rows) * rows + i % rows;
                    node_hash(expected[left], expected[left + rows])
                }).collect();
                let next = runtime.pcs_nodes_strided(&states, rows).unwrap();
                runtime.release_buffer(states).unwrap();
                states = next;
                assert_eq!(runtime.pcs_digests(&states, 0, expected.len()).unwrap(), expected);
            }
            eprintln!("C71_NATIVE_W_COLUMNS_LOCAL {}", json!({"message_rows": n, "rows": rows,
                "cosets_in_group": 32, "pads_per_column": pad, "tested_columns": 128,
                "native_host_accum_fft_hash_s": native_s, "reference_accum_fft_s": reference_s,
                "comparison_scope": "different stages and Rust O0/C++ O2; no speedup comparison", "stats": runtime.stats().unwrap(),
                "census": crate::c71_matrix::census::simultaneous(),
                "gpu_execution": false, "credit": false}));
            runtime.release_buffer(states).unwrap();
            runtime.close().unwrap();
        }
    }

    #[test]
    fn c71_b12_native_incremental_hash_exact_roots_and_salt_bands() {
        use crate::c71_matrix::range::windowed::native::{Runtime, tests::fixture};
        use super::super::streaming::{digest, hash_rows_in_place, node_hash};
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 2 << 20;
        let no_exempt_weights = Arc::new(Vec::<i16>::new());
        let _budget = crate::c71_matrix::census::Budget::new(&no_exempt_weights).unwrap();
        for rows in [1, 2, 8, 256, 4096] {
            let mut rng = PrivateRng::from_seed([91; 32]);
            let mut source = vec![0; rows * 128];
            for (i, x) in source.iter_mut().enumerate() {
                let random: Goldilocks = rng.random();
                *x = match i % 7 {
                    0 => 0, 1 => Goldilocks::ORDER_U64 - 1, 2 => 1,
                    3 => 1 << 63, 4 => (1 << 32) - 1, _ => random.as_canonical_u64(),
                };
            }
            let mut salt_rng = PrivateRng::from_seed([73; 32]);
            let salts: Vec<[Goldilocks; 4]> = (0..rows)
                .map(|_| std::array::from_fn(|_| salt_rng.random())).collect();
            let rust_start = std::time::Instant::now();
            let mut expected = source.clone();
            let work = hash_rows_in_place(&mut expected, rows, 128, |row| salts[row]).unwrap();
            let rust_seconds = rust_start.elapsed().as_secs_f64();
            let mut expected: Vec<_> = (0..rows).map(|row| digest(&expected, rows, row)).collect();
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let native_start = std::time::Instant::now();
            let mut states = native_hash_fixture(&mut runtime, &source, &salts, rows);
            let band = 64.min(rows);
            assert_eq!(runtime.pcs_digests(&states, 0, rows).unwrap(), expected);
            while expected.len() > 1 {
                expected = expected.chunks_exact(2).map(|pair| node_hash(pair[0], pair[1])).collect();
                let next = runtime.pcs_nodes(&states).unwrap();
                runtime.release_buffer(states).unwrap();
                states = next;
                assert_eq!(runtime.pcs_digests(&states, 0, expected.len()).unwrap(), expected);
            }
            let native_seconds = native_start.elapsed().as_secs_f64();
            let stats = runtime.stats().unwrap();
            assert_eq!(work.blake3_compressions, 18 * rows);
            assert_eq!(stats.d2h_bytes, 4 + 32 * (2 * rows - 1) as u64);
            runtime.release_buffer(states).unwrap();
            let final_stats = runtime.close().unwrap();
            assert_eq!(final_stats.live_capacity_bytes, 0);
            println!("C71_INCREMENTAL_HASH {}", json!({"rows": rows, "columns": 128,
                "compact_state_bytes_each": 32, "ring_bytes": 64 * rows,
                "salt_band_bytes": 32 * band, "leaf_compressions": work.blake3_compressions,
                "node_compressions": 2 * (rows - 1), "rust_leaf_seconds": rust_seconds,
                "native_host_hash_and_merkle_seconds": native_seconds,
                "native_stats": stats, "root": expected[0], "gpu_execution": false, "credit": false}));
            println!("C71_INCREMENTAL_HASH_BUDGET {}", crate::c71_matrix::census::simultaneous());
        }
    }
    #[test]
    fn c71_b12_native_incremental_hash_coset_frontier_and_natural_root() {
        use crate::c71_matrix::range::windowed::native::{Runtime, tests::fixture};
        use super::super::streaming::{digest, hash_rows_in_place, node_hash, prepare_offsets};
        let fixture = fixture(512);
        let no_exempt_weights = Arc::new(Vec::<i16>::new());
        let _budget = crate::c71_matrix::census::Budget::new(&no_exempt_weights).unwrap();
        for (rows, width, groups) in [(2, 2, 2), (4, 8, 4), (8, 32, 8)] {
            let cosets = width * groups;
            let height = rows * cosets;
            let source: Vec<_> = (0..128 * height).map(|i| match i % 7 {
                0 => Goldilocks::ORDER_U64 - 1, 1 => 0, _ => (i * 7919 + i / height) as u64,
            }).collect();
            let mut rng = PrivateRng::from_seed([37; 32]);
            let salts: Vec<[Goldilocks; 4]> = (0..height)
                .map(|_| std::array::from_fn(|_| rng.random())).collect();
            let mut expected = source.clone();
            hash_rows_in_place(&mut expected, height, 128, |leaf| salts[leaf]).unwrap();
            let leaves: Vec<_> = (0..height).map(|leaf| digest(&expected, height, leaf)).collect();
            let mut cut: Vec<_> = leaves.chunks_exact(cosets).map(|chunk| {
                let mut nodes = chunk.to_vec();
                while nodes.len() > 1 {
                    nodes = nodes.chunks_exact(2).map(|p| node_hash(p[0], p[1])).collect();
                }
                nodes[0]
            }).collect();
            let mut prescan = PrivateRng::from_seed([37; 32]);
            let mut cursors = vec![0; rows];
            prepare_offsets(&mut prescan, cosets, &mut cursors, |_, _| {}).unwrap();
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let frontier = runtime.pcs_frontier(rows, groups).unwrap();
            let mut final_roots = None;
            for group in 0..groups {
                let mut group_values = Vec::with_capacity(128 * rows * width);
                for column in 0..128 {
                    for coset in group * width..(group + 1) * width {
                        for row in 0..rows { group_values.push(source[column * height + row * cosets + coset]); }
                    }
                }
                let mut group_salts = Vec::with_capacity(rows * width);
                let mut group_leaves = Vec::with_capacity(rows * width);
                for coset in group * width..(group + 1) * width {
                    for row in 0..rows {
                        let mut replay = prescan.snapshot_at(cursors[row]).unwrap();
                        let sampled: [Goldilocks; 4] = std::array::from_fn(|_| replay.random());
                        cursors[row] = replay.position();
                        assert_eq!(sampled, salts[row * cosets + coset]);
                        group_salts.push(sampled);
                        group_leaves.push(leaves[row * cosets + coset]);
                    }
                }
                let mut roots = native_hash_fixture(&mut runtime, &group_values, &group_salts, rows * width);
                assert_eq!(runtime.pcs_digests(&roots, 0, rows * width).unwrap(), group_leaves);
                for _ in 0..width.ilog2() {
                    let next = runtime.pcs_nodes_strided(&roots, rows).unwrap();
                    runtime.release_buffer(roots).unwrap(); roots = next;
                }
                runtime.pcs_merge_group(&frontier, &roots, group).unwrap();
                if group + 1 == groups { final_roots = Some(roots); }
                else { runtime.release_buffer(roots).unwrap(); }
            }
            let mut roots = final_roots.unwrap();
            assert_eq!(runtime.pcs_digests(&roots, 0, rows).unwrap(), cut);
            assert_eq!(cursors[rows - 1], prescan.position());
            runtime.release_buffer(frontier).unwrap();
            while cut.len() > 1 {
                cut = cut.chunks_exact(2).map(|p| node_hash(p[0], p[1])).collect();
                let next = runtime.pcs_nodes(&roots).unwrap();
                runtime.release_buffer(roots).unwrap(); roots = next;
            }
            assert_eq!(runtime.pcs_digests(&roots, 0, 1).unwrap()[0], cut[0]);
            let stats = runtime.stats().unwrap();
            runtime.release_buffer(roots).unwrap();
            assert_eq!(runtime.close().unwrap().live_capacity_bytes, 0);
            println!("C71_INCREMENTAL_COSET_HASH {}", json!({"rows": rows, "cosets_per_group": width,
                "groups": groups, "leaves": height, "frontier_bytes": rows * groups.ilog2() as usize * 32,
                "native_stats": stats, "root": cut[0], "gpu_execution": false, "credit": false}));
            println!("C71_INCREMENTAL_COSET_HASH_BUDGET {}", crate::c71_matrix::census::simultaneous());
        }
    }
}

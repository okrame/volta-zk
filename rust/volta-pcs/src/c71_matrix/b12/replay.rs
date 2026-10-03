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

struct QueryFactors {
    inverse: Vec<Goldilocks>,
    modulus: Vec<Goldilocks>,
}

fn query_tree(
    points: &[Goldilocks],
    dft: &Radix2DFTSmallBatch<Goldilocks>,
) -> Vec<Vec<QueryFactors>> {
    assert!(points.len().is_power_of_two());
    let mut level: Vec<_> = points.iter().map(|&point| vec![-point, Goldilocks::ONE]).collect();
    let mut factors = Vec::new();
    loop {
        factors.push(level.iter().map(|modulus| QueryFactors::new(modulus.clone(), dft)).collect());
        if level.len() == 1 {
            return factors;
        }
        let mut children = level.into_iter();
        level = Vec::with_capacity(children.len() / 2);
        while let Some(left) = children.next() {
            level.push(multiply_polynomials(left, children.next().unwrap(), dft));
        }
    }
}

impl QueryFactors {
    fn new(mut modulus: Vec<Goldilocks>, dft: &Radix2DFTSmallBatch<Goldilocks>) -> Self {
        let cap = modulus.len() - 1;
        let reverse: Vec<_> = modulus.iter().rev().copied().collect();
        let mut inverse = inverse_series(&reverse, cap, dft);
        inverse.resize(2 * cap, Goldilocks::ZERO);
        modulus.resize(2 * cap, Goldilocks::ZERO);
        Self { inverse: dft.dft(inverse), modulus: dft.dft(modulus) }
    }

    fn remainder<Coefficient: p3_field::ExtensionField<Goldilocks>>(
        &self,
        high: &[Coefficient],
        low: impl Fn(usize) -> Coefficient,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Vec<Coefficient> {
        let cap = self.inverse.len() / 2;
        assert_eq!(high.len(), cap);
        let mut reversed: Vec<_> = high.iter().rev().copied().collect();
        reversed.resize(2 * cap, Coefficient::ZERO);
        let mut spectrum = dft.dft_algebra(reversed);
        for (value, &factor) in spectrum.iter_mut().zip(&self.inverse) {
            *value *= factor;
        }
        let mut quotient = dft.idft_algebra(spectrum);
        quotient.truncate(cap);
        quotient.reverse();
        quotient.resize(2 * cap, Coefficient::ZERO);
        let mut spectrum = dft.dft_algebra(quotient);
        for (value, &factor) in spectrum.iter_mut().zip(&self.modulus) {
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
            let modulus = dft.idft(self.modulus.clone());
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

    /// One original-source scan per coset, independent of producer emission
    /// order. There is one coset buffer, one reusable FFT column and P3's two
    /// twiddle tables; never a second full coset or a dense original source.
    fn coset_base(
        &self,
        coset: usize,
        rows: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Result<Vec<u64>, String> {
        if !rows.is_power_of_two() || rows > self.height || coset >= self.height / rows {
            return Err("base coset geometry differs".into());
        }
        let Pads::Base(pads) = &self.pads else {
            return Err("base coset requires base pads".into());
        };
        let n = self.len / self.width;
        let pad = pads.len() / self.width;
        let offset =
            Goldilocks::two_adic_generator(self.height.ilog2() as usize).exp_u64(coset as u64);
        // Factor powers into two small tables, including the original pad
        // positions n..n+pad. A shuffled producer must not advance one global
        // power cursor or shift pads next to the live (unpadded) prefix.
        let power = power_lookup(offset, n + pad);
        let mut cells = vec![0; rows * self.width.max(4)];
        let mut count = 0usize;
        let mut emit = |index: usize, value: Goldilocks| -> Result<(), String> {
            if index >= self.live {
                return Err("base scan emitted outside live original source".into());
            }
            count = count.checked_add(1).ok_or("base scan count overflow")?;
            if count > self.live {
                return Err("base scan emitted too many coefficients".into());
            }
            let (column, j) = (index / n, index % n);
            let target = &mut cells[column * rows + j % rows];
            *target = (Goldilocks::new(*target) + value * power(j)).as_canonical_u64();
            Ok(())
        };
        if let Some(scan) = &self.scan {
            scan(&mut emit)?;
        } else {
            for index in 0..self.live {
                emit(index, base_coefficient((self.get)(index)))?;
            }
        }
        if count != self.live {
            return Err("base scan omitted original coefficients".into());
        }
        for column in 0..self.width {
            for j in 0..pad {
                let index = n + j;
                let target = &mut cells[column * rows + index % rows];
                *target = (Goldilocks::new(*target) + pads[column * pad + j] * power(index))
                    .as_canonical_u64();
            }
        }
        drop(power);
        Self::fft_columns(&mut cells, rows, self.width, dft);
        Ok(cells)
    }

    fn coset_extension(
        &self,
        coset: usize,
        rows: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
        state: Option<&State>,
    ) -> Result<Vec<u64>, String> {
        if !rows.is_power_of_two() || rows > self.height || coset >= self.height / rows {
            return Err("extension coset geometry differs".into());
        }
        if self.base() || state.is_some_and(|state| 1 << state.num_variables() != self.len) {
            return Err("extension coset source differs".into());
        }
        let n = self.len / self.width;
        let pad = self.pads.len() / self.width;
        let offset =
            Goldilocks::two_adic_generator(self.height.ilog2() as usize).exp_u64(coset as u64);
        let power = power_lookup(offset, n + pad);
        // The destination is already native base-limb, column-major storage.
        // Scatter original contributions into it; no dense folded S1 or full
        // row-major conversion copy is needed before its predecessor opens.
        let mut cells = vec![0; rows * self.columns().max(4)];
        let mut add = |column: usize, j: usize, value: E| {
            for (limb, &value) in limbs(&(value * power(j))).iter().enumerate() {
                let target = &mut cells[(column * 3 + limb) * rows + j % rows];
                *target = (Goldilocks::new(*target) + value).as_canonical_u64();
            }
        };
        let mut emit = |index, value| {
            if index >= self.live {
                return Err("extension contribution outside source".into());
            }
            add(index / n, index % n, value);
            Ok(())
        };
        if let Some(state) = state {
            state.visit(&mut emit)?;
        } else {
            for i in 0..self.live {
                emit(i, (self.get)(i))?;
            }
        }
        for column in 0..self.width {
            for j in 0..pad {
                add(column, n + j, self.pads.get(column * pad + j));
            }
        }
        drop(power);
        Self::fft_columns(&mut cells, rows, self.columns(), dft);
        Ok(cells)
    }

    fn fft_columns(
        cells: &mut [u64],
        rows: usize,
        columns: usize,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) {
        let mut column = vec![Goldilocks::ZERO; rows];
        for values in cells.chunks_exact_mut(rows).take(columns) {
            for (out, &value) in column.iter_mut().zip(values.iter()) {
                *out = Goldilocks::new(value);
            }
            // dft_batch owns and transforms this one column in place; avoid
            // to_row_major_matrix(), which would copy an already-owned matrix.
            column = dft.dft_batch(DenseMatrix::new_col(column)).values;
            for (out, value) in values.iter_mut().zip(&column) {
                *out = value.as_canonical_u64();
            }
        }
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
    fn rows(&self, indices: &[usize]) -> Result<Vec<Vec<Goldilocks>>, String> {
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
    ) -> Result<Vec<Vec<Goldilocks>>, String> {
        if indices.len() > replay_tree::query_batch_rows(self.height)
            || indices.iter().any(|&index| index >= self.height)
        {
            return Err("code query outside domain or reference batch cap".into());
        }
        if indices.is_empty() {
            return Ok(Vec::new());
        }
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
        let root_factors = &factors.last().unwrap()[0];
        let coefficients = (self.len + self.pads.len()) / self.width;
        let pad_rows = self.pads.len() / self.width;
        let pad_shift = (self.live < self.len && message_rows.is_power_of_two())
            .then(|| root_factors.monomial_spectrum(message_rows, &dft));
        // Write native base limbs directly into the only returned matrix. The
        // former Coefficient matrix duplicated up to 2 GiB at the initial cap.
        let mut values = vec![vec![Goldilocks::ZERO; self.columns()]; indices.len()];
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
            let mut remainders = vec![remainder];
            for level in factors[..factors.len() - 1].iter().rev() {
                let mut children = Vec::with_capacity(level.len());
                for (parent, pair) in remainders.into_iter().zip(level.chunks_exact(2)) {
                    let half = parent.len() / 2;
                    for factor in pair {
                        children.push(factor.remainder(
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
                        &value[0],
                    );
                values[row][column * limbs.len()..(column + 1) * limbs.len()]
                    .copy_from_slice(limbs);
            }
        }
        Ok(values)
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
        // Both P3 twiddle tables remain allocated across all cosets.
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        let (root, tree) = Tree::commit(
            mmcs,
            code.height,
            code.columns(),
            rows,
            cut,
            |c| code.coset(c, rows, &dft, state),
            Arc::new(move |indices| rowcode.rows(indices)),
        )?;
        let lease = state.map(State::replay_lease).transpose()?.flatten();
        Ok((root, ZkWhirReplayHandle::new(Oracle { tree: Arc::new(tree), base, lease })))
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
}

impl ReplayModel {
    pub(in crate::c71_matrix) fn new(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
        live: usize,
    ) -> Result<Self, String> {
        Self::new_source(domain, seed, salt_seed, source, None, live)
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
        Self::new_source(domain, seed, salt_seed, source, Some((scan, window)), live)
    }

    fn new_source(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
        readers: Option<(BaseScan, ByteWindow)>,
        live: usize,
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
        let (root, handle) = Code {
            get: source.clone(),
            scan: scan.clone(),
            window,
            len,
            live,
            width: 1 << first,
            height,
            pads: Pads::Base(pads.clone()),
        }
        .commit(&mmcs.inner, None)?;
        let oracle = handle.downcast::<Oracle>().map_err(|_| "C71 initial replay handle type")?;
        Ok(Self {
            domain,
            root,
            source,
            scan: scan.map(|scan| (scan, live)),
            tree: oracle.tree,
            pads,
            retain_first: false,
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
    let (root, data) = root_prover.commit(witness, &mut fs, &mut root_rng);
    if let Some(original) = original {
        assert_eq!(root, original.root);
    }
    // Actual C7.1 discipline: fresh proof coins/MMCS, independent of root replay.
    let proof_mmcs = ObservedMmcs::new(fs.clone(), [83; 32]);
    let reference = HidingWhirProver::new(&config, &dft, &proof_mmcs);
    let mut rng = PrivateRng::from_seed([101; 32]);
    let result = reference.prove_claimless(data, &claims, to_p3(mask.x), &mut fs, &mut rng);

    census::mark("sourcewise_initial_commit").unwrap();
    let mut replay_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    replay_fs.set_phase(0x200);
    let mut model = ReplayModel::new_source(
        Domain::Flat(dimension),
        root_seed,
        salt_seed,
        source.clone(),
        readers,
        1 << dimension,
    )
    .unwrap();
    assert_eq!(root, *model.root());
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
                assert!(level.iter().all(|factor| factor.inverse.len() == 2usize << depth));
            }
            let root = &factors.last().unwrap()[0];
            let (inverse, modulus) = (root.inverse.clone(), root.modulus.clone());
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
                assert_eq!(code.rows(&indices).unwrap(), expected);
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
                assert_eq!(code.rows(&indices).unwrap(), expected);
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
                        assert_eq!(code.rows(&indices).unwrap(), expected);
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
                let factors = &tree.last().unwrap()[0];
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
                        "rows": rows.iter().flatten().map(|value| value.as_canonical_u64()).collect::<Vec<_>>(),
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
}

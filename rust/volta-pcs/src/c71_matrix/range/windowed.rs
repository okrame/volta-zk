//! Original-value canopy/Gram range evaluator. CPU reference; the same private
//! arithmetic still needs exact CUDA integration and a complete physical ledger.
use super::*;
use crate::c71_matrix::gemma::eq_index;
use std::{cell::RefCell, sync::Arc};

pub(in crate::c71_matrix) mod native;
pub(in crate::c71_matrix) use native::Config as NativeConfig;

mod word {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for i16 {}
}
pub(in crate::c71_matrix) trait Word:
    word::Sealed + Copy + Default + Into<i64>
{
    const KIND: u32;
}
impl Word for u8 {
    const KIND: u32 = 0;
}
impl Word for i16 {
    const KIND: u32 = 1;
}

pub(in crate::c71_matrix) type Reader<T = u8> =
    Arc<dyn Fn(usize, usize, usize, &mut [T]) -> Result<(), String> + Send + Sync>;

pub(in crate::c71_matrix) struct Source<T = u8> {
    pub alphabet: Alphabet,
    pub histogram: Vec<u64>, // full original domain, including external zero suffix
    pub read: Reader<T>,     // suffix bits, subtree bits, first ordered value, output
    pub native: Option<NativeConfig>, // explicit opt-in; errors never select CPU
}

impl Source<i16> {
    /// One installation scan of the same immutable packed storage. Counts can
    /// be reused; every proof still authenticates them with fresh rows.
    pub(in crate::c71_matrix) fn signed(
        bits: usize,
        packed: &[i16],
        read: Reader<i16>,
    ) -> Result<Self, String> {
        if !(1..=35).contains(&bits) || packed.len() > 1usize << bits {
            return Err("range signed source shape differs".into());
        }
        let mut histogram = allocate(65535, 0u64)?;
        for &value in packed {
            if value == i16::MIN {
                return Err("range signed source outside symmetric alphabet".into());
            }
            histogram[(i64::from(value) + 32767) as usize] += 1;
        }
        histogram[32767] += (1u64 << bits) - packed.len() as u64;
        Ok(Self { alphabet: Alphabet::Symmetric(i16::MAX), histogram, read, native: None })
    }
}

impl<T> Source<T> {
    fn geometry(&self, bits: usize) -> (usize, usize, &'static [&'static [usize]]) {
        let (cut, cap, windows): (_, _, &[_]) = match self.alphabet {
            Alphabet::Byte => (10, 1usize << 31, &WINDOWS),
            // Selected W cut=11/m24, not the superseded cut=10/m25 plan.
            // 256 MiB staging; no second packed W or full virtual W allocation.
            Alphabet::Symmetric(_) => (11, 1usize << 27, &W_WINDOWS),
        };
        (bits.saturating_sub(cut).max(1).min(bits - 1), cap, windows)
    }
}

// Selected compositions, indexed by the number of folds before retention.
// Addresses use only completed prefixes; no future challenge enters a reader.
const WINDOWS: [&[usize]; 10] =
    [&[], &[1], &[2], &[3], &[4], &[5], &[2, 4], &[3, 4], &[2, 2, 4], &[2, 3, 4]];
const W_WINDOWS: [&[usize]; 11] =
    [&[], &[1], &[2], &[3], &[4], &[5], &[2, 4], &[3, 4], &[3, 5], &[2, 3, 4], &[2, 3, 5]];

#[derive(Default, Debug, serde::Serialize)]
pub(in crate::c71_matrix) struct Work {
    pub source_passes: u64,
    pub byte_windows: u64,
    pub requested_bytes: u64,
    pub fraction_merges: u64,
    pub gram_windows: u64,
    pub retained_levels: u64,
    pub named_evaluator_heap_peak_bytes: usize,
    pub native: Option<native::Stats>,
    pub native_shared: bool,
}

fn allocate<T: Clone>(length: usize, value: T) -> Result<Vec<T>, String> {
    let mut v = Vec::new();
    v.try_reserve_exact(length).map_err(|_| "range evaluator allocation failed")?;
    v.resize(length, value);
    Ok(v)
}

fn fraction<T: Copy + Into<i64>>(bytes: &[T], alpha: Fp3) -> [Fp3; 2] {
    if bytes.len() == 1 {
        return [Fp3::ONE, alpha - signed(bytes[0].into())];
    }
    let half = bytes.len() / 2;
    let [p, q] = fraction(&bytes[..half], alpha);
    let [r, s] = fraction(&bytes[half..], alpha);
    [p * s + r * q, q * s]
}

struct Evaluator<'a, T> {
    source: &'a Source<T>,
    bits: usize,
    retained: usize,
    window: usize,
    alpha: Fp3,
    canopy: Vec<Vec<[Fp3; 2]>>,
    layer: Option<usize>,
    children: Option<Vec<[Fp3; 4]>>,
    gram: Vec<Fp3>,
    gram_end: usize,
    folded: usize,
    work: Work,
}

impl<'a, T: Copy + Default + Into<i64>> Evaluator<'a, T> {
    fn new(source: &'a Source<T>, bits: usize, alpha: Fp3, window: usize) -> Result<Self, String> {
        if !(1..=35).contains(&bits)
            || !window.is_power_of_two()
            || window > (1usize << bits).min(1 << 31)
        {
            return Err("range evaluator shape differs".into());
        }
        let (retained, cap, _) = source.geometry(bits);
        if window > cap {
            return Err("range window exceeds staging cap".into());
        }
        let cut = bits - retained;
        if window < 1 << cut {
            return Err("range window splits initial subtree".into());
        }
        let mut e = Self {
            source,
            bits,
            retained,
            window,
            alpha,
            canopy: Vec::new(),
            layer: None,
            children: None,
            gram: Vec::new(),
            gram_end: 0,
            folded: 0,
            work: Work::default(),
        };
        let mut level = allocate(1 << retained, [Fp3::ZERO; 2])?;
        {
            let mut bytes = allocate(window, T::default())?;
            e.sample_heap(bytes.capacity() * core::mem::size_of::<T>() + level.capacity() * 48);
            e.work.source_passes += 1;
            for first in (0..1usize << bits).step_by(window) {
                e.read(0, 0, first, &mut bytes)?;
                for (i, subtree) in bytes.chunks_exact(1 << cut).enumerate() {
                    level[(first >> cut) + i] = fraction(subtree, alpha);
                }
            }
        }
        e.work.fraction_merges += ((1u64 << bits) - (1 << retained)) as u64;
        e.canopy.push(level);
        while e.canopy.last().unwrap().len() > 1 {
            let lower = e.canopy.last().unwrap();
            let mut upper = allocate(lower.len() / 2, [Fp3::ZERO; 2])?;
            for (out, pair) in upper.iter_mut().zip(lower.chunks_exact(2)) {
                let ([p, q], [r, s]) = (pair[0], pair[1]);
                *out = [p * s + r * q, q * s];
            }
            e.work.fraction_merges += upper.len() as u64;
            e.sample_heap(upper.capacity() * 48);
            e.canopy.push(upper);
        }
        Ok(e)
    }

    fn sample_heap(&mut self, extra: usize) {
        let named = self.canopy.capacity() * core::mem::size_of::<Vec<[Fp3; 2]>>()
            + self.canopy.iter().map(|v| v.capacity() * 48).sum::<usize>()
            + self.children.as_ref().map_or(0, |v| v.capacity() * 96)
            + self.gram.capacity() * 24
            + extra;
        self.work.named_evaluator_heap_peak_bytes =
            self.work.named_evaluator_heap_peak_bytes.max(named);
    }

    fn read(
        &mut self,
        suffix: usize,
        bottom: usize,
        first: usize,
        bytes: &mut [T],
    ) -> Result<(), String> {
        (self.source.read)(suffix, bottom, first, bytes)?;
        self.work.byte_windows += 1;
        self.work.requested_bytes += core::mem::size_of_val(bytes) as u64;
        Ok(())
    }

    fn start_layer(&mut self, layer: usize) -> Result<(), String> {
        if self.layer == Some(layer) {
            return Ok(());
        }
        if self.layer.map_or(layer != 0, |l| layer != l + 1) {
            return Err("range layer order differs".into());
        }
        self.children = None;
        self.gram = Vec::new();
        self.folded = 0;
        self.gram_end = 0;
        self.layer = Some(layer);
        if layer < self.retained {
            let level = self.canopy.pop().ok_or("range canopy exhausted")?;
            let mut children = allocate(level.len() / 2, [Fp3::ZERO; 4])?;
            self.sample_heap(level.capacity() * 48 + children.capacity() * 96);
            for (out, pair) in children.iter_mut().zip(level.chunks_exact(2)) {
                *out = [pair[0][0], pair[0][1], pair[1][0], pair[1][1]];
            }
            self.children = Some(children);
        }
        Ok(())
    }

    /// Stream [tail][completed prefix][u][subtree] and contract each tail's
    /// small group before moving on. No full-domain Eq or child vector.
    fn groups(
        &mut self,
        layer: usize,
        prefix: &[Fp3],
        width: usize,
        extra: usize,
        mut emit: impl FnMut(usize, &[[Fp3; 4]]),
    ) -> Result<(), String> {
        let bottom = self.bits - layer;
        let suffix = layer - prefix.len() - width;
        let length = 1 << width;
        let group = 1 << (prefix.len() + width);
        let mut bucket = allocate(length, [Fp3::ZERO; 4])?;
        let mut bytes = allocate(self.window, T::default())?;
        self.sample_heap(
            extra + bucket.capacity() * 96 + bytes.capacity() * core::mem::size_of::<T>(),
        );
        self.work.source_passes += 1;
        for first in (0..1usize << self.bits).step_by(self.window) {
            self.read(suffix, bottom, first, &mut bytes)?;
            for (i, block) in bytes.chunks_exact(1 << bottom).enumerate() {
                let index = (first >> bottom) + i;
                let u = index % length;
                let old = (index / length) % (1 << prefix.len());
                let weight = eq_index(prefix, old);
                let half = block.len() / 2;
                let [p, q] = fraction(&block[..half], self.alpha);
                let [r, s] = fraction(&block[half..], self.alpha);
                for (acc, value) in bucket[u].iter_mut().zip([p, q, r, s]) {
                    *acc += weight * value;
                }
                if index % group == group - 1 {
                    emit(index / group, &bucket);
                    bucket.fill([Fp3::ZERO; 4]);
                }
            }
        }
        self.work.fraction_merges += (1u64 << self.bits) - (1u64 << (layer + 1));
        Ok(())
    }

    fn retain(&mut self, layer: usize, prefix: &[Fp3]) -> Result<(), String> {
        self.gram = Vec::new(); // release H before the retained child allocation
        let mut children = allocate(1 << (layer - prefix.len()), [Fp3::ZERO; 4])?;
        self.groups(layer, prefix, 0, children.capacity() * 96, |tail, bucket| {
            children[tail] = bucket[0];
        })?;
        self.children = Some(children);
        self.folded = prefix.len();
        self.work.retained_levels += 1;
        Ok(())
    }

    fn fold_children(&mut self, prefix: &[Fp3]) {
        let children = self.children.as_mut().unwrap();
        for &r in &prefix[self.folded..] {
            let half = children.len() / 2;
            for i in 0..half {
                for j in 0..4 {
                    let (a, b) = (children[i][j], children[i + half][j]);
                    children[i][j] = a + r * (b - a);
                }
            }
            children.truncate(half); // capacity stays in the named ledger
        }
        self.folded = prefix.len();
    }

    fn coefficients(
        &mut self,
        layer: usize,
        point: &[Fp3],
        lambda: Fp3,
        prefix: &[Fp3],
    ) -> Result<[Fp3; 4], String> {
        self.start_layer(layer)?;
        let gap = layer.saturating_sub(self.retained);
        if prefix.len() >= gap {
            if self.children.is_none() {
                self.retain(layer, prefix)?;
            }
            self.fold_children(prefix);
            let children = self.children.as_ref().unwrap();
            let half = children.len() / 2;
            let mut out = [Fp3::ZERO; 4];
            let mut work = SourceTreeWork::default();
            for i in 0..half {
                let a = children[i];
                let d: [Fp3; 4] = std::array::from_fn(|j| children[i + half][j] - a[j]);
                let mut v = [Fp3::ZERO; 3];
                for (x, y, c) in [(0, 3, lambda), (2, 1, lambda), (1, 3, Fp3::ONE)] {
                    v[0] += c * a[x] * a[y];
                    v[1] += c * (d[x] * a[y] + a[x] * d[y]);
                    v[2] += c * d[x] * d[y];
                }
                let e = source_folded_equality(point, prefix, i, &mut work);
                let de = source_folded_equality(point, prefix, i + half, &mut work) - e;
                for j in 0..3 {
                    out[j] += e * v[j];
                    out[j + 1] += de * v[j];
                }
            }
            return Ok(out);
        }
        if self.gram.is_empty() || prefix.len() == self.gram_end {
            self.gram = Vec::new();
            let mut start = 0;
            let width = *self.source.geometry(self.bits).2[gap]
                .iter()
                .find(|&&w| {
                    let here = start == prefix.len();
                    start += w;
                    here
                })
                .ok_or("range Gram window order differs")?;
            let length = 1 << width;
            let mut h = allocate(length * length, Fp3::ZERO)?;
            self.groups(layer, prefix, width, h.capacity() * 24, |tail, bucket| {
                let weight = eq_index(&point[prefix.len() + width..], tail);
                for (u, &[p, q, r, _]) in bucket.iter().enumerate() {
                    let x = weight * (lambda * p + q);
                    let y = weight * lambda * r;
                    for (v, &[_, q, _, s]) in bucket.iter().enumerate() {
                        h[u * length + v] += x * s + y * q;
                    }
                }
            })?;
            self.gram = h;
            self.gram_end = prefix.len() + width;
            self.folded = prefix.len();
            self.work.gram_windows += 1;
        }
        for &r in &prefix[self.folded..] {
            let length = 1 << (self.gram_end - self.folded);
            let half = length / 2;
            for i in 0..half {
                for j in 0..half {
                    let a = self.gram[i * length + j];
                    let b = self.gram[i * length + j + half];
                    let c = self.gram[(i + half) * length + j];
                    let d = self.gram[(i + half) * length + j + half];
                    let low = a + r * (b - a);
                    let high = c + r * (d - c);
                    self.gram[i * half + j] = low + r * (high - low);
                }
            }
            self.gram.truncate(half * half);
            self.folded += 1;
        }
        let length = 1 << (self.gram_end - prefix.len());
        let half = length / 2;
        let mut v = [Fp3::ZERO; 3];
        for z in 0..half {
            let a = self.gram[z * length + z];
            let b = self.gram[z * length + z + half];
            let c = self.gram[(z + half) * length + z];
            let d = self.gram[(z + half) * length + z + half];
            let weight = eq_index(&point[prefix.len() + 1..self.gram_end], z);
            for (v, term) in v.iter_mut().zip([a, b + c - a - a, d - b - c + a]) {
                *v += weight * term;
            }
        }
        let e = point
            .iter()
            .zip(prefix)
            .fold(Fp3::ONE, |e, (&x, &r)| e * ((Fp3::ONE - x) * (Fp3::ONE - r) + x * r));
        let x = point[prefix.len()];
        let mut out = [Fp3::ZERO; 4];
        for j in 0..3 {
            out[j] += e * (Fp3::ONE - x) * v[j];
            out[j + 1] += e * (x + x - Fp3::ONE) * v[j];
        }
        Ok(out)
    }

    fn terminal(&mut self, layer: usize, prefix: &[Fp3]) -> Result<[Fp3; 4], String> {
        self.start_layer(layer)?;
        if self.children.is_none() {
            self.retain(layer, prefix)?;
        }
        self.fold_children(prefix);
        Ok(self.children.as_ref().unwrap()[0])
    }
}

enum ActiveEvaluator<'a, T> {
    Cpu(Evaluator<'a, T>),
    Native(native::Evaluator<'a, T>),
}
impl<T: Word> ActiveEvaluator<'_, T> {
    fn root(&mut self) -> Result<[Fp3; 2], String> {
        match self {
            Self::Cpu(e) => Ok(e.canopy.pop().ok_or("range canopy root missing")?[0]),
            Self::Native(e) => e.root(),
        }
    }
    fn coefficients(
        &mut self,
        l: usize,
        p: &[Fp3],
        lambda: Fp3,
        prefix: &[Fp3],
    ) -> Result<[Fp3; 4], String> {
        match self {
            Self::Cpu(e) => e.coefficients(l, p, lambda, prefix),
            Self::Native(e) => e.coefficients(l, p, lambda, prefix),
        }
    }
    fn terminal(&mut self, l: usize, prefix: &[Fp3]) -> Result<[Fp3; 4], String> {
        match self {
            Self::Cpu(e) => e.terminal(l, prefix),
            Self::Native(e) => e.terminal(l, prefix),
        }
    }
    fn finish(self) -> Result<Work, String> {
        match self {
            Self::Cpu(e) => Ok(e.work),
            Self::Native(e) => e.finish(),
        }
    }
}

pub(in crate::c71_matrix) fn prove<T: Word>(
    domain: Domain,
    root: &C61Commitment,
    attempt: AttemptContext,
    layout: [u8; 32],
    live: usize,
    source: &Source<T>,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, [Vec<Cube>; 2], [Auth; 2], Work), String> {
    let bits = domain.config()?.num_variables;
    let alphabet = source.alphabet;
    if !(1..=35).contains(&bits)
        || !matches!(alphabet, Alphabet::Byte | Alphabet::Symmetric(i16::MAX))
        || source.histogram.len() != alphabet.len()
        || source.histogram.iter().try_fold(0u64, |sum, &n| sum.checked_add(n))
            != Some(1u64 << bits)
    {
        return Err("range original histogram differs".into());
    }
    let bits = bind(domain, root, attempt, layout, live, alphabet, fs)?;
    let count = required(bits, alphabet);
    if correlations.len() < count {
        return Err("B12 range prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let (histogram, authed): (Vec<_>, Vec<_>) = source
        .histogram
        .iter()
        .map(|&h| {
            let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), signed(h as i64));
            (c.value(), a)
        })
        .unzip();
    record_values(fs, 0x41, &histogram);
    let (alpha, inverse, rho) = challenges(bits, alphabet, fs)?;
    let h = authed.iter().zip(&inverse).fold(Auth::ZERO, |s, (&a, &d)| s.add(a.scale(d)));
    let mut evaluator = match &source.native {
        Some(config) => {
            ActiveEvaluator::Native(native::Evaluator::new(source, bits, alpha, config)?)
        }
        None => ActiveEvaluator::Cpu(Evaluator::new(
            source,
            bits,
            alpha,
            (1usize << bits).min(source.geometry(bits).1),
        )?),
    };
    let [p, q] = evaluator.root()?;
    if q == Fp3::ZERO {
        return Err("B12 range witness pole".into());
    }
    let (roots, root) = authenticate([p, q, q.inv()], &mut rows);
    fs.set_phase(0x401);
    record_values(fs, 0x42, &roots);
    let mut triples =
        vec![[h, root[1], root[0]], [root[1], root[2], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let evaluator = RefCell::new(evaluator);
    let (layers, point, claims, _) = try_prove_tree_sourcewise_custom(
        bits,
        Vec::new(),
        [root[0], root[1]],
        |_, _| unreachable!("no scalar range fallback"),
        fs,
        &mut rows,
        &mut triples,
        |l, point, lambda, prefix| {
            evaluator.borrow_mut().coefficients(l, point, lambda, prefix).map(Some)
        },
        |l, prefix| evaluator.borrow_mut().terminal(l, prefix).map(Some),
    )?;
    let work = evaluator.into_inner().finish()?;
    let leaf_tag = claims[0].m;
    record_values(fs, 0x46, &[leaf_tag]);
    let products = prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    let target = Auth::new(alpha - claims[1].x, -claims[1].m);
    let forms = [vec![Cube { offset: 0, point, coefficient: Fp3::ONE }], suffix(live, &rho)];
    Ok((Proof { histogram, roots, layers, leaf_tag, products }, forms, [target, Auth::ZERO], work))
}

#[cfg(test)]
pub(in crate::c71_matrix) mod tests {
    use super::*;
    use crate::c71_matrix::wire::Wire;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(in crate::c71_matrix) fn source(bits: usize, live: usize) -> (Source, Arc<Vec<u8>>) {
        let values: Arc<Vec<_>> = Arc::new(
            (0..1 << bits)
                .map(|i| if i < live { ((i * 37 + i / 11) % 251) as u8 } else { 0 })
                .collect(),
        );
        let mut histogram = [0; 256];
        for &v in values.iter() {
            histogram[usize::from(v)] += 1;
        }
        let original = values.clone();
        let read = Arc::new(move |suffix: usize, bottom: usize, first: usize, out: &mut [u8]| {
            // Independent inverse address rotation. No field coins or rows.
            let high = bits - bottom - suffix;
            for (j, v) in out.iter_mut().enumerate() {
                let i = first + j;
                let top = i >> bottom;
                let original = (((top & ((1 << high) - 1)) << suffix) | (top >> high)) << bottom
                    | (i & ((1 << bottom) - 1));
                *v = values[original];
            }
            Ok(())
        });
        (
            Source { alphabet: Alphabet::Byte, histogram: histogram.to_vec(), read, native: None },
            original,
        )
    }

    fn context() -> AttemptContext {
        AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        }
    }

    fn rows(count: usize) -> Vec<Auth> {
        (0..count).map(|i| Auth::new(signed(i as i64 + 1), signed(7 * i as i64 + 3))).collect()
    }

    #[test]
    fn c71_b12_windowed_range_complete_transcript_and_original_mac() {
        for live in [1, 731, 1024] {
            let (source, values) = source(10, live);
            parity(10, live, source, values[..live].iter().map(|&v| i16::from(v)).collect(), 22);
        }
    }

    fn parity<T: Word>(bits: usize, live: usize, source: Source<T>, values: Vec<i16>, passes: u64) {
        let domain = Domain::Flat(bits);
        let alphabet = source.alphabet;
        let count = required(bits, alphabet);
        let pcs_rows = 3 * bits + 2;
        let model = Model::new_in(domain, values).unwrap();
        let fresh = || Fs::new(b"windowed range original MAC", 100_000);
        let all_rows = rows(count + pcs_rows);
        let (mut df, mut wf) = (fresh(), fresh());
        let (mut dr, mut wr) = (all_rows.clone().into_iter(), all_rows.clone().into_iter());
        let (dense, forms, targets) =
            super::super::prove(&model, context(), [9; 32], live, alphabet, &mut df, &mut dr)
                .unwrap();
        let (windowed, actual_forms, actual_targets, work) =
            prove(domain, &model.root, context(), [9; 32], live, &source, &mut wf, &mut wr)
                .unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        dense.write(&mut a);
        windowed.write(&mut b);
        assert_eq!(a, b);
        assert_eq!(df.digest(), wf.digest());
        for (a, b) in targets.iter().zip(actual_targets) {
            assert_eq!((a.x, a.m), (b.x, b.m));
        }
        for (a, b) in forms.iter().flatten().zip(actual_forms.iter().flatten()) {
            assert_eq!((a.offset, &a.point, a.coefficient), (b.offset, &b.point, b.coefficient));
        }
        assert_eq!(work.source_passes, passes);
        assert_eq!(work.gram_windows, passes - bits as u64);
        assert_eq!(work.retained_levels, bits as u64 - 1);
        assert_eq!(work.requested_bytes, passes * (1 << bits) * core::mem::size_of::<T>() as u64);
        if source.native.is_some() {
            let stats = work.native.as_ref().unwrap();
            if work.native_shared {
                assert!(stats.arena_bytes > 0 && stats.live_capacity_bytes > 0);
                assert_eq!((stats.stopped, stats.cleanup_failed), (0, 0));
                assert!(stats.h2d_bytes < work.requested_bytes);
            } else {
                assert_eq!(
                    (stats.arena_bytes, stats.live_capacity_bytes, stats.cleanup_failed),
                    (0, 0, 0)
                );
                assert_eq!(stats.h2d_bytes, work.requested_bytes);
            }
            assert!(stats.peak_capacity_bytes > 0 && stats.fences > 0 && stats.d2h_bytes > 48);
        } else {
            assert!(work.native.is_none());
        }
        assert_eq!(dr.len(), pcs_rows);
        assert_eq!(wr.len(), pcs_rows);

        // Close the new range's targets on the ORIGINAL dense commitment,
        // not a fresh authentication of the gathered values.
        let (pcs, digest) = linear::prove(
            &model,
            context(),
            [9; 32],
            &actual_forms,
            &actual_targets,
            &mut wf,
            &mut wr,
        )
        .unwrap();
        let delta = signed(29);
        let keys: Vec<_> = all_rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let (mut vf, mut vr) = (fresh(), keys.clone().into_iter());
        let (f, t) = verify(
            domain,
            &model.root,
            context(),
            [9; 32],
            live,
            alphabet,
            &windowed,
            delta,
            &mut vf,
            &mut vr,
        )
        .unwrap();
        let before = vf.clone();
        assert_eq!(
            linear::verify(
                domain,
                &model.root,
                context(),
                [9; 32],
                &f,
                &t,
                &pcs,
                delta,
                &mut vf,
                &mut vr
            )
            .unwrap(),
            digest
        );
        assert_eq!(vf.digest(), wf.digest());
        assert_eq!(wr.len(), 0);
        assert_eq!(vr.len(), 0);
        let mut wrong = t;
        wrong[0] = Key::new(wrong[0].k + Fp3::ONE);
        assert!(linear::verify(
            domain,
            &model.root,
            context(),
            [9; 32],
            &f,
            &wrong,
            &pcs,
            delta,
            &mut before.clone(),
            &mut keys[count..].to_vec().into_iter()
        )
        .is_err());
    }

    #[test]
    fn c71_b12_windowed_range_signed_transcript_original_mac_and_geometry() {
        let bits = 12;
        let live = 3001;
        let values: Vec<_> = (0..live).map(|i| [-32767, -1, 0, 1, 32767][i % 5]).collect();
        let original = values.clone();
        let source = Source::signed(
            bits,
            &values,
            Arc::new(move |suffix, bottom, first, out| {
                let high = bits - bottom - suffix;
                for (j, v) in out.iter_mut().enumerate() {
                    let i = first + j;
                    let top = i >> bottom;
                    let address = (((top & ((1 << high) - 1)) << suffix) | (top >> high)) << bottom
                        | (i & ((1 << bottom) - 1));
                    *v = original.get(address).copied().unwrap_or(0);
                }
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(source.histogram[0], 601);
        assert_eq!(source.histogram[65534], 600);
        assert_eq!(source.histogram[32767], 600 + 4096 - live as u64);
        let (retained, cap, windows) = source.geometry(35);
        assert_eq!((retained, cap), (24, 1 << 27));
        assert_eq!(1 + windows.iter().map(|w| 1 + w.len()).sum::<usize>(), 29);
        // D35 scheduling arithmetic only; never allocate a canonical buffer.
        for (gap, widths) in windows.iter().enumerate() {
            let layer = retained + gap;
            let mut prefix = 0;
            for width in widths.iter().copied().chain([0]) {
                assert!(prefix + width <= layer);
                assert!(cap >= 1 << (35 - layer));
                prefix += width;
            }
        }
        for (bad_bits, packed) in [(0, vec![]), (36, vec![]), (1, vec![0; 3]), (12, vec![i16::MIN])]
        {
            assert!(Source::signed(bad_bits, &packed, source.read.clone()).is_err());
        }
        parity(bits, live, source, values, 29);
    }

    #[test]
    fn c71_b12_windowed_native_byte_transcript_original_mac() {
        let fixture = native::tests::fixture(512);
        for live in [1, 731, 1024] {
            let (mut source, values) = source(10, live);
            source.native = Some(fixture.config.clone());
            parity(10, live, source, values[..live].iter().map(|&v| i16::from(v)).collect(), 22);
        }
    }

    #[test]
    fn c71_b12_windowed_native_shared_resident_transcript_original_mac() {
        let _budget = crate::c71_matrix::census::Budget::new(&Arc::new(Vec::new())).unwrap();
        let fixture = native::tests::fixture(512);
        shared_native_parity(fixture.config.clone());
        println!("C71_TEMPORARY_ALLOCATIONS {}", crate::c71_matrix::census::simultaneous());
    }

    fn shared_native_parity(config: native::Config) {
        use std::sync::Mutex;
        let runtime = Arc::new(Mutex::new(native::Runtime::new(&config).unwrap()));
        let (_, values) = source(10, 731);
        let words = values.iter().map(|&value| i16::from(value)).collect::<Vec<_>>();
        let original = {
            let mut owner = runtime.lock().unwrap();
            owner.install_weights(Arc::new(vec![1, 2, 3]), [9; 32]).unwrap();
            Arc::new(owner.upload_signed(&words).unwrap())
        };
        let before = runtime.lock().unwrap().stats().unwrap();
        let config = config
            .with_resident(
                runtime.clone(),
                Arc::new(move |owner, suffix, bottom, first, count| {
                    let output = owner.byte_window(count)?;
                    owner.scatter_bytes(
                        &original,
                        &native::ByteTile {
                            input_first: 0,
                            input_stride: 1024,
                            rows: 1,
                            columns: 1024,
                            original_first: 0,
                            window_first: first as u64,
                            window_length: count as u64,
                            byte_first: 0,
                            width: 1,
                            signed_width: 2,
                            dimension: 10,
                            suffix: suffix as u32,
                            bottom: bottom as u32,
                        },
                        &output,
                    )?;
                    owner.seal_bytes(output)
                }),
            )
            .unwrap();
        assert!(native::Runtime::new(&config).is_err());
        for _ in 0..2 {
            let (mut source, _) = source(10, 731);
            source.read = Arc::new(|_, _, _, _| panic!("resident proof called host reader"));
            source.native = Some(config.clone());
            parity(10, 731, source, words[..731].to_vec(), 22);
            let after = runtime.lock().unwrap().stats().unwrap();
            assert_eq!(after.h2d_bytes, before.h2d_bytes);
            assert_eq!(after.weights_bytes, before.weights_bytes);
            assert_eq!(after.arena_bytes, before.arena_bytes);
            assert_eq!(after.live_capacity_bytes, before.live_capacity_bytes);
            assert_eq!(after.allocations - before.allocations, after.releases - before.releases);
        }
        drop(config);
        runtime.lock().unwrap().close().unwrap();
    }

    #[test]
    fn c71_b12_windowed_native_shared_failures_stop_common_owner() {
        use std::sync::Mutex;
        let fixture = native::tests::fixture(512);
        for fault in 0..5 {
            let runtime = Arc::new(Mutex::new(native::Runtime::new(&fixture.config).unwrap()));
            let (mut source, values) = source(10, 731);
            let mut config = fixture
                .config
                .clone()
                .with_resident(
                    runtime.clone(),
                    Arc::new(move |owner, _, _, _, count| match fault {
                        0 => Err("resident reader failed".into()),
                        1 => owner.byte_window(count),
                        2 => owner.upload_signed(&vec![0; count]),
                        _ => {
                            let output = owner.byte_window(count / 2)?;
                            owner.seal_bytes(output)
                        }
                    }),
                )
                .unwrap();
            if fault == 4 {
                config.reserve_bytes += 256;
            }
            source.read = Arc::new(|_, _, _, _| panic!("failed resident reader fell back"));
            source.native = Some(config);
            let model = Model::new_in(
                Domain::Flat(10),
                values[..731].iter().map(|&value| i16::from(value)).collect(),
            )
            .unwrap();
            let count = required(10, Alphabet::Byte);
            let mut correlations = rows(count).into_iter();
            assert!(prove(
                model.domain,
                &model.root,
                context(),
                [9; 32],
                731,
                &source,
                &mut Fs::new(b"shared range failed", 100_000),
                &mut correlations
            )
            .is_err());
            assert_eq!(correlations.len(), count - 256);
            let mut owner = runtime.lock().unwrap();
            assert_eq!(owner.stats().unwrap().stopped, 1);
            assert!(owner.upload_signed(&[1]).is_err());
            owner.close().unwrap();
        }
    }

    #[test]
    fn c71_b12_windowed_native_signed_transcript_original_mac() {
        let fixture = native::tests::fixture(2048);
        signed_native_parity(fixture.config.clone());
    }

    fn signed_native_parity(config: native::Config) {
        let values: Vec<i16> = (0..3001).map(|i| [-32767, -1, 0, 1, 32767][i % 5]).collect();
        let original = values.clone();
        let mut source = Source::signed(
            12,
            &values,
            Arc::new(move |suffix, bottom, first, out| {
                let high = 12 - bottom - suffix;
                for (j, v) in out.iter_mut().enumerate() {
                    let i = first + j;
                    let top = i >> bottom;
                    let address = (((top & ((1 << high) - 1)) << suffix) | (top >> high)) << bottom
                        | (i & ((1 << bottom) - 1));
                    *v = original.get(address).copied().unwrap_or(0);
                }
                Ok(())
            }),
        )
        .unwrap();
        source.native = Some(config);
        parity(12, 3001, source, values, 29);
    }

    #[test]
    #[ignore = "explicit authorized GPU experiment; requires C71_NATIVE_PARITY_LIBRARY"]
    fn c71_b12_windowed_native_hardware_parity_explicit() {
        let library = std::env::var_os("C71_NATIVE_PARITY_LIBRARY")
            .expect("explicit native CUDA library required");
        let config = native::Config::new(library.into(), 0, 512 << 20, 256 << 20, 512, 3);
        shared_native_parity(config.clone());
        let mut signed = config;
        signed.window_words = 2048;
        signed_native_parity(signed);
    }

    #[test]
    fn c71_b12_windowed_native_failure_before_authentication() {
        let fixture = native::tests::fixture(512);
        let (mut source, values) = source(10, 731);
        source.native = Some(fixture.config.clone());
        let model =
            Model::new_in(Domain::Flat(10), values[..731].iter().map(|&v| i16::from(v)).collect())
                .unwrap();
        let count = required(10, Alphabet::Byte);
        // Keep this exact test library loaded while setting its driver fault.
        let injection = native::tests::Injection::new(&fixture.config);
        for fault in [1, 2, 4] {
            injection.set(fault);
            let mut rows = rows(count).into_iter();
            assert!(prove(
                model.domain,
                &model.root,
                context(),
                [9; 32],
                731,
                &source,
                &mut Fs::new(b"native failed", 100_000),
                &mut rows
            )
            .is_err());
            // Only histogram rows consumed: neither a root nor a later MAC.
            assert_eq!(rows.len(), count - 256);
        }
        injection.set(0);
        let original = source.read.clone();
        for fail in 1..=44 {
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = calls.clone();
            let read = original.clone();
            source.read = Arc::new(move |s, b, f, out| {
                read(s, b, f, out)?;
                if counter.fetch_add(1, Ordering::Relaxed) + 1 == fail {
                    Err("native reader failed".into())
                } else {
                    Ok(())
                }
            });
            let mut rows = rows(count).into_iter();
            assert_eq!(
                prove(
                    model.domain,
                    &model.root,
                    context(),
                    [9; 32],
                    731,
                    &source,
                    &mut Fs::new(b"native reader failed", 100_000),
                    &mut rows
                )
                .err()
                .unwrap(),
                "native reader failed"
            );
            assert_eq!(calls.load(Ordering::Relaxed), fail);
            assert!(rows.len() > 0);
        }
        source.read = original;
        injection.set(3);
        assert!(prove(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            &source,
            &mut Fs::new(b"native cleanup failed", 100_000),
            &mut rows(count).into_iter()
        )
        .err()
        .unwrap()
        .contains("injected CUDA failure"));
        injection.set(0);
        source.native.as_mut().unwrap().library = fixture.config.library.with_extension("missing");
        assert!(prove(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            &source,
            &mut Fs::new(b"native missing", 100_000),
            &mut rows(count).into_iter()
        )
        .err()
        .unwrap()
        .contains("unavailable"));
    }

    #[test]
    fn c71_b12_windowed_range_gram_zero_one_and_extension_folds() {
        let (source, values) = source(10, 731);
        let alpha = Fp3::new(Fp::new(3), Fp::new(5), Fp::new(7));
        let mut tree = vec![values
            .iter()
            .map(|&v| [Fp3::ONE, alpha - signed(i64::from(v))])
            .collect::<Vec<_>>()];
        while tree.last().unwrap().len() > 1 {
            tree.push(
                tree.last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|a| {
                        let ([p, q], [r, s]) = (a[0], a[1]);
                        [p * s + r * q, q * s]
                    })
                    .collect(),
            );
        }
        let mut e = Evaluator::new(&source, 10, alpha, 512).unwrap();
        assert_eq!(e.canopy.pop().unwrap()[0], tree[10][0]);
        let challenges = [Fp3::ZERO, Fp3::ONE, alpha];
        for layer in 0..10 {
            let point: Vec<_> = (0..layer).map(|i| challenges[(i + 1) % 3]).collect();
            let lambda = alpha + Fp3::ONE;
            let mut children: [Vec<_>; 4] = std::array::from_fn(|j| {
                tree[9 - layer].chunks_exact(2).map(|pair| pair[j / 2][j % 2]).collect()
            });
            let mut equality = eq(&point);
            let mut prefix = Vec::new();
            for round in 0..layer {
                let c = e.coefficients(layer, &point, lambda, &prefix).unwrap();
                let half = equality.len() / 2;
                for x in [0, 1, 2, 3].map(signed) {
                    let expected = (0..half).fold(Fp3::ZERO, |sum, i| {
                        let [p, q, r, s] = std::array::from_fn(|j| {
                            children[j][i] + x * (children[j][i + half] - children[j][i])
                        });
                        sum + (equality[i] + x * (equality[i + half] - equality[i]))
                            * (lambda * (p * s + r * q) + q * s)
                    });
                    assert_eq!(
                        c.iter().rev().fold(Fp3::ZERO, |v, &a| v * x + a),
                        expected,
                        "layer {layer} round {round}"
                    );
                }
                let r = challenges[round % 3];
                prefix.push(r);
                for child in &mut children {
                    fold(child, r);
                }
                fold(&mut equality, r);
            }
            assert_eq!(
                e.terminal(layer, &prefix).unwrap(),
                std::array::from_fn(|j| children[j][0])
            );
        }
        assert_eq!(e.work.source_passes, 22);
        assert_eq!(e.work.byte_windows, 44);
        assert!(e.canopy.is_empty());
        assert!(e.gram.is_empty() && e.gram.capacity() == 0);
        assert_eq!(e.children.as_ref().unwrap().len(), 1);
        assert_eq!(e.children.as_ref().unwrap().capacity(), 2); // retained, not freed by truncate
        for (bits, window) in [(0, 1), (35, 1), (10, 0), (10, 3), (10, 256), (10, 2048)] {
            assert!(Evaluator::new(&source, bits, alpha, window).is_err());
        }
    }

    #[test]
    fn c71_b12_windowed_range_permuted_values_fail_original_pcs() {
        let (mut source, values) = source(10, 731);
        let model =
            Model::new_in(Domain::Flat(10), values[..731].iter().map(|&v| i16::from(v)).collect())
                .unwrap();
        let original = source.read.clone();
        source.read = Arc::new(move |suffix, bottom, first, out| {
            original(suffix, bottom, first, out)?;
            for i in 0..2 {
                let upper = i >> bottom;
                let address = (((upper & ((1 << suffix) - 1)) << (10 - bottom - suffix))
                    | (upper >> suffix))
                    << bottom
                    | (i & ((1 << bottom) - 1));
                if address >= first && address - first < out.len() {
                    out[address - first] = values[1 - i];
                }
            }
            Ok(())
        });
        let all = rows(required(10, Alphabet::Byte) + 32);
        let delta = signed(29);
        let mut keys =
            all.iter().map(|a| Key::new(a.m + delta * a.x)).collect::<Vec<_>>().into_iter();
        let mut rows = all.into_iter();
        let (mut pf, mut vf) =
            (Fs::new(b"altered range reader", 100_000), Fs::new(b"altered range reader", 100_000));
        let (proof, forms, targets, _) =
            prove(model.domain, &model.root, context(), [9; 32], 731, &source, &mut pf, &mut rows)
                .unwrap();
        // The multiset/range is unchanged, so range alone must not detect this.
        let (vf_forms, vf_targets) = verify(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            Alphabet::Byte,
            &proof,
            delta,
            &mut vf,
            &mut keys,
        )
        .unwrap();
        let (pcs, _) =
            linear::prove(&model, context(), [9; 32], &forms, &targets, &mut pf, &mut rows)
                .unwrap();
        assert!(linear::verify(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            &vf_forms,
            &vf_targets,
            &pcs,
            delta,
            &mut vf,
            &mut keys
        )
        .is_err());
    }

    #[test]
    fn c71_b12_windowed_range_reader_errors_are_terminal_before_next_authentication() {
        let (source, values) = source(10, 731);
        let model =
            Model::new_in(Domain::Flat(10), values[..731].iter().map(|&v| i16::from(v)).collect())
                .unwrap();
        let count = required(10, Alphabet::Byte);
        for fail in 1..=22 {
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = calls.clone();
            let original = source.read.clone();
            let source = Source {
                alphabet: source.alphabet,
                histogram: source.histogram.clone(),
                native: None,
                read: Arc::new(move |s, b, f, out| {
                    original(s, b, f, out)?;
                    if counter.fetch_add(1, Ordering::Relaxed) + 1 == fail {
                        Err("reader failed after write".into())
                    } else {
                        Ok(())
                    }
                }),
            };
            let mut rows = rows(count).into_iter();
            let result = prove(
                model.domain,
                &model.root,
                context(),
                [9; 32],
                731,
                &source,
                &mut Fs::new(b"windowed failure", 100_000),
                &mut rows,
            );
            assert_eq!(result.err().unwrap(), "reader failed after write");
            assert_eq!(calls.load(Ordering::Relaxed), fail);
            assert!(rows.len() > 0);
            if fail == 1 {
                assert_eq!(rows.len(), count - 256);
            }
        }
        let mut invalid = source;
        invalid.histogram[0] += 1;
        let mut fs = Fs::new(b"bad histogram", 100_000);
        let digest = fs.digest();
        let mut rows = rows(count).into_iter();
        assert!(prove(
            model.domain,
            &model.root,
            context(),
            [9; 32],
            731,
            &invalid,
            &mut fs,
            &mut rows
        )
        .is_err());
        assert_eq!(fs.digest(), digest);
        assert_eq!(rows.len(), count);
    }
}

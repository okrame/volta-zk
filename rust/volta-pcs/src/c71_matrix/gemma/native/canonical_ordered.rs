//! Canonical numerical snapshots and source-ordered byte reconstruction.
//! No dense A, correlations, transcript or PCS coins in preparation. This CPU
//! reference supplies one complete source scan per initial commit coset.
//! Exact CUDA execution and physical resource admission remain separate.
use super::*;
use std::sync::{Arc, Mutex};

type Rows = Vec<Vec<Box<[i16]>>>;
type Cuts = BTreeMap<usize, Vec<i16>>;

struct Generation {
    owner: [u8; 32],
    cuts: Cuts,
    histograms: BTreeMap<usize, Vec<u32>>,
}

/// Shared by all accepted snapshots. Only one layer-checkpoint generation is
/// retained, including while opening historical A. KV remains snapshot-owned.
#[derive(Default)]
pub(super) struct Cache(Mutex<Option<Generation>>);

pub(super) struct Prepared {
    profile: Arc<Canonical>,
    tables: Arc<calibration_input::Tables>,
    weights: Arc<Vec<i16>>,
    previous: Vec<Arc<Prepared>>,
    tokens: [u32; 150],
    kv: Rows,
    owner: [u8; 32],
    cache: Arc<Cache>,
    limit: usize,
    row_cache: Mutex<Option<(usize, usize, Vec<i64>)>>,
    byte_cache: Mutex<(usize, [u8; 128])>,
}

impl Canonical {
    pub(super) fn checkpoint_ids(&self) -> Result<BTreeSet<usize>, String> {
        let ids: BTreeSet<_> = self
            .sources
            .operations
            .iter()
            .filter(|op| {
                op.name == "global/embedding_scale" || op.name.ends_with("/layer_scalar_mul")
            })
            .map(|op| op.output)
            .collect();
        if ids.len() != 61
            || ids.iter().any(|&id| {
                let s = &self.bytes().scalar.layout.sources[id];
                self.bytes().widths[id] != 2 || (s.rows, s.cols) != (150, 5376)
            })
        {
            return Err("canonical layer checkpoint census differs".into());
        }
        Ok(ids)
    }
}

impl Prepared {
    pub(super) fn prepare(
        profile: Arc<Canonical>,
        tables: Arc<calibration_input::Tables>,
        weights: Arc<Vec<i16>>,
        previous: &[Arc<Self>],
        prompt: &[u32; 100],
        cache: Arc<Cache>,
        limit: usize,
    ) -> Result<Arc<Self>, String> {
        let old = profile.sources.attention.rope.old;
        let expected = profile.plan.sources.iter().map(|s| s.rows * s.cols).sum::<usize>();
        if weights.len() != expected
            || prompt.iter().any(|&t| t >= 262144)
            || previous.len() * 150 != old
            || previous.iter().enumerate().any(|(i, p)| {
                p.profile.sources.attention.rope.old != i * 150
                    || p.profile.recipes.digest != profile.recipes.digest
                    || !Arc::ptr_eq(&p.weights, &weights)
                    || !Arc::ptr_eq(&p.tables, &tables)
                    || !Arc::ptr_eq(&p.cache, &cache)
            })
        {
            return Err("canonical prepared source identity differs".into());
        }
        let mut state = Self {
            profile,
            tables,
            weights,
            previous: previous.to_vec(),
            tokens: [0; 150],
            kv: Vec::new(),
            owner: [0; 32],
            cache,
            limit,
            row_cache: Mutex::new(None),
            byte_cache: Mutex::new((usize::MAX, [0; 128])),
        };
        state.tokens[..100].copy_from_slice(prompt);
        let mut active = state.cache.0.lock().map_err(|_| "checkpoint cache poisoned")?;
        *active = None; // release old capacity before allocating the next generation
        let (tokens, kv, generation) = state.build()?;
        state.tokens = tokens;
        state.kv = kv;
        state.owner = generation.owner;
        *active = Some(generation);
        drop(active);
        Ok(Arc::new(state))
    }

    pub(super) fn tokens(&self) -> [u32; 150] {
        self.tokens
    }

    pub(super) fn weight(&self, id: usize, row: usize, col: usize) -> Result<i64, String> {
        let s = self.profile.plan.sources.get(id).ok_or("unknown W source")?;
        if row >= s.rows || col >= s.cols {
            return Err("W address outside tensor".into());
        }
        let v = self.weights[s.packed_offset + row * s.cols + col];
        if v == i16::MIN {
            return Err("W overflow marker".into());
        }
        Ok(i64::from(v))
    }

    pub(super) fn tail(&self, id: usize, token: usize, col: usize) -> Result<i64, String> {
        let old = self.profile.sources.attention.rope.old;
        if token >= old + 150 {
            return Err("KV address outside completed response".into());
        }
        let (source, row) = if token < old {
            (&*self.previous[token / 150], token % 150)
        } else {
            (self, token - old)
        };
        source
            .kv
            .get(id)
            .and_then(|v| v.get(row))
            .and_then(|v| v.get(col))
            .map(|&v| i64::from(v))
            .ok_or("missing original KV".into())
    }

    fn build(&self) -> Result<([u32; 150], Rows, Generation), String> {
        let p = &self.profile;
        let ids = p.checkpoint_ids()?;
        let checkpoint_bytes = ids
            .iter()
            .map(|&id| {
                let s = &p.bytes().scalar.layout.sources[id];
                s.rows * s.cols * 2
            })
            .sum::<usize>();
        let budget = self
            .limit
            .checked_sub(checkpoint_bytes)
            .ok_or("canonical checkpoint budget exceeded")?;
        let mut cuts: Cuts = ids.iter().map(|&id| (id, Vec::with_capacity(150 * 5376))).collect();
        let mut trial = calibration::Trial::new(p, budget);
        let mut tokens = self.tokens;
        let mut h = blake3::Hasher::new();
        h.update(b"C71-canonical-private-snapshot-v1\0");
        h.update(&p.recipes.digest);
        h.update(&p.bytes().layout_digest);
        self.tables.with_slot(p.sources.attention.rope.old / 150, |tables| {
            for _ in 0..150 {
                trial.token_observed(
                    &mut tokens,
                    tables,
                    &|id, r, c| self.weight(id, r, c),
                    &|id, r, c| self.tail(id, r, c),
                    None,
                    |out| {
                        for (id, first, values) in &out.values {
                            h.update(&(*id as u64).to_le_bytes());
                            h.update(&(*first as u64).to_le_bytes());
                            for v in values {
                                h.update(&v.to_le_bytes());
                            }
                            if let Some(cut) = cuts.get_mut(id) {
                                if cut.len() != first * 5376 {
                                    return Err("checkpoint row order differs".into());
                                }
                                for &v in values {
                                    let v =
                                        i16::try_from(v).map_err(|_| "checkpoint outside i16")?;
                                    if v == i16::MIN {
                                        return Err("checkpoint overflow marker".into());
                                    }
                                    cut.push(v);
                                }
                            }
                        }
                        Ok(())
                    },
                )?;
            }
            trial.finish(None)
        })??;
        if cuts.values().any(|v| v.len() != 150 * 5376) {
            return Err("incomplete checkpoint generation".into());
        }
        let (kv, histograms, _) = trial.into_retained()?;
        for (id, histogram) in &histograms {
            h.update(&(*id as u64).to_le_bytes());
            for v in histogram {
                h.update(&v.to_le_bytes());
            }
        }
        for t in tokens {
            h.update(&t.to_le_bytes());
        }
        Ok((tokens, kv, Generation { owner: *h.finalize().as_bytes(), cuts, histograms }))
    }

    fn with_generation<T>(
        &self,
        use_generation: impl FnOnce(&Generation) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut active = self.cache.0.lock().map_err(|_| "checkpoint cache poisoned")?;
        if active.as_ref().is_none_or(|g| g.owner != self.owner) {
            *active = None;
            let (tokens, kv, generation) = self.build()?;
            if tokens != self.tokens || kv != self.kv || generation.owner != self.owner {
                return Err("canonical checkpoint reconstruction changed snapshot".into());
            }
            *active = Some(generation);
        }
        use_generation(active.as_ref().unwrap())
    }

    /// Replay in topological producer order, all fixed rows before the next
    /// consumer. Unlike initial generation, tokens and KV are already frozen.
    /// Public padding/histograms are emitted once from the original snapshot.
    fn scan(
        &self,
        generation: &Generation,
        targets: &BTreeSet<usize>,
        mut emit: impl FnMut(usize, usize, &[i64]) -> Result<(), String>,
    ) -> Result<(), String> {
        let p = &self.profile;
        let sources = &p.bytes().scalar.layout.sources;
        let frozen = |id: usize| {
            generation.cuts.contains_key(&id)
                || generation.histograms.contains_key(&id)
                || !self.kv[id].is_empty()
        };
        let mut owner = vec![usize::MAX; sources.len()];
        for (i, step) in p.steps.iter().enumerate() {
            for id in p.ports(step).1 {
                owner[id] = i;
            }
        }
        let mut needed = BTreeSet::new();
        let mut pending: Vec<_> = targets.iter().copied().collect();
        while let Some(id) = pending.pop() {
            if id >= sources.len() {
                return Err("getter source outside layout".into());
            }
            if frozen(id) {
                continue;
            }
            let i = owner[id];
            if i == usize::MAX {
                return Err("getter source has no producer".into());
            }
            if needed.insert(i) {
                pending.extend(p.ports(&p.steps[i]).0);
            }
        }
        let mut last = vec![None; sources.len()];
        for &i in &needed {
            for id in p.ports(&p.steps[i]).0 {
                last[id] = Some(i);
            }
        }
        let mut live: BTreeMap<(usize, usize), Vec<i64>> = BTreeMap::new();
        self.tables.with_slot(p.sources.attention.rope.old / 150, |tables| {
            for &i in &needed {
                let matrix = matches!(p.steps[i], Producer::Matrix(_));
                for token in 0..if matrix { 1 } else { 150 } {
                    let rows = if matrix { vec![0] } else { p.rows_at_token(&p.steps[i], token)? };
                    for row in rows {
                        let get = |id: usize, r: usize, c: usize| {
                            if let Some(v) = p.padding_word(id, r, c)? {
                                return Ok(v);
                            }
                            if let Some(v) = generation.cuts.get(&id) {
                                return v
                                    .get(r * sources[id].cols + c)
                                    .map(|&v| i64::from(v))
                                    .ok_or("checkpoint address missing".into());
                            }
                            if !self.kv[id].is_empty() {
                                return self.tail(id, p.sources.attention.rope.old + r, c);
                            }
                            live.get(&(id, r))
                                .and_then(|v| v.get(c))
                                .copied()
                                .ok_or("getter read before producer/after release".into())
                        };
                        let resident = live.values().map(|v| v.capacity() * 8).sum::<usize>();
                        let out = if let Producer::Matrix(raw) = p.steps[i] {
                            p.prepare_matrix_batch(
                                raw,
                                0,
                                p.plan.cohorts[raw].rows,
                                self.limit
                                    .checked_sub(resident)
                                    .ok_or("getter workspace budget exceeded")?,
                                |id, r, c| self.weight(id, r, c),
                                get,
                            )?
                        } else {
                            p.prepare_row(
                                &p.steps[i],
                                row,
                                self.tokens[token],
                                tables,
                                |id, r, c| self.weight(id, r, c),
                                get,
                                |id, r, c| self.tail(id, r, c),
                            )?
                        };
                        if let Some(next) = out.token {
                            if self.tokens.get(token + 1) != Some(&next) {
                                return Err("getter generated a different token".into());
                            }
                        }
                        let incoming =
                            out.values.iter().map(|(_, _, v)| v.capacity() * 8).sum::<usize>();
                        if resident + 2 * incoming > self.limit {
                            return Err("getter row workspace budget exceeded".into());
                        }
                        for (id, first, values) in out.values {
                            for (offset, row) in values.chunks_exact(sources[id].cols).enumerate() {
                                if targets.contains(&id) && !frozen(id) {
                                    emit(id, first + offset, row)?;
                                }
                                if last[id].is_some_and(|end| end > i) && !frozen(id) {
                                    if live.insert((id, first + offset), row.to_vec()).is_some() {
                                        return Err("getter overwrote live row".into());
                                    }
                                }
                            }
                        }
                    }
                }
                live.retain(|(id, _), _| last[*id] != Some(i));
            }
            if !live.is_empty() {
                return Err("getter retained rows after final consumer".into());
            }
            Ok::<_, String>(())
        })??;
        for &id in targets {
            let s = &sources[id];
            for row in 0..s.rows {
                let words = if let Some(v) = generation.cuts.get(&id) {
                    Some(
                        v[row * s.cols..(row + 1) * s.cols]
                            .iter()
                            .map(|&v| i64::from(v))
                            .collect::<Vec<_>>(),
                    )
                } else if let Some(v) = generation.histograms.get(&id) {
                    Some(v.iter().map(|&v| i64::from(v)).collect())
                } else if !self.kv[id].is_empty() {
                    Some(self.kv[id][row].iter().map(|&v| i64::from(v)).collect())
                } else {
                    p.padding_word(id, row, 0)?.map(|v| vec![v; s.cols])
                };
                if let Some(words) = words {
                    emit(id, row, &words)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn window(&self, first: usize, output: &mut [u8]) -> Result<(), String> {
        if first.checked_add(output.len()).is_none_or(|end| end > 1usize << 34)
            || output.len() > self.limit
        {
            return Err("canonical byte window exceeds domain/budget".into());
        }
        output.fill(0);
        let b = self.profile.bytes();
        let targets: BTreeSet<_> = b.window_sources(first, output.len())?.into_iter().collect();
        if targets.is_empty() {
            return Ok(());
        }
        self.scan_sources(&targets, &mut |index, byte| {
            if index >= first && index - first < output.len() {
                output[index - first] = byte;
            }
            Ok(())
        })
    }

    /// Native range input gather, capped at the selected 2 GiB byte window.
    /// The Gram/canopy prover must still schedule these windows at each FS
    /// barrier; this reader alone does not implement the 26-pass range proof.
    pub(super) fn range_window(
        &self,
        first: usize,
        output: &mut [u8],
        suffix: usize,
        bottom: usize,
    ) -> Result<(), String> {
        let window = bytes::RangeWindow::new(34, first, output.len(), suffix, bottom)?;
        if output.len() > self.limit {
            return Err("canonical range window exceeds budget".into());
        }
        let targets: BTreeSet<_> =
            self.profile.bytes().range_window_sources(&window)?.into_iter().collect();
        output.fill(0); // flat suffix only; signed internal zero is emitted biased
        if targets.is_empty() {
            return Ok(());
        }
        self.scan_sources(&targets, &mut |index, byte| {
            if let Some(offset) = window.offset(index) {
                output[offset] = byte;
            }
            Ok(())
        })
    }

    /// Reconstruct every original source once for one PCS coset. The row
    /// bitmap checks coverage without an A-sized byte bitmap; the fixed tile
    /// map emits every byte of a covered row exactly once. Public flat padding
    /// is omitted and supplied as zero by the PCS, never as biased signed zero.
    pub(super) fn scan_original(
        &self,
        emit: &mut dyn FnMut(usize, Goldilocks) -> Result<(), String>,
    ) -> Result<(), String> {
        let targets = (0..self.profile.bytes().widths.len()).collect();
        self.scan_sources(&targets, &mut |index, byte| emit(index, Goldilocks::from_u8(byte)))
    }

    fn scan_sources(
        &self,
        targets: &BTreeSet<usize>,
        emit: &mut dyn FnMut(usize, u8) -> Result<(), String>,
    ) -> Result<(), String> {
        let b = self.profile.bytes();
        let mut seen: BTreeMap<usize, Vec<u64>> = targets
            .iter()
            .map(|&id| {
                let source = b.scalar.layout.sources.get(id).ok_or("unknown scanned source")?;
                Ok((id, vec![0; source.rows.div_ceil(64)]))
            })
            .collect::<Result<_, String>>()?;
        self.with_generation(|generation| {
            self.scan(generation, targets, |id, row, words| {
                let source = b.scalar.layout.sources.get(id).ok_or("unknown emitted source")?;
                let bits = seen.get_mut(&id).ok_or("unexpected emitted source")?;
                if row >= source.rows || bits[row / 64] & (1u64 << (row % 64)) != 0 {
                    return Err("duplicate or out-of-range scanned row".into());
                }
                bits[row / 64] |= 1 << (row % 64);
                b.emit_row_bytes(id, row, words, &mut *emit)
            })
        })?;
        for (&id, bits) in &seen {
            if bits.iter().map(|v| v.count_ones() as usize).sum::<usize>()
                != b.scalar.layout.sources[id].rows
            {
                return Err("incomplete original source scan".into());
            }
        }
        Ok(())
    }

    pub(super) fn value(&self, id: usize, row: usize, col: usize) -> Result<i64, String> {
        let s = self.profile.bytes().scalar.layout.sources.get(id).ok_or("unknown A source")?;
        if row >= s.rows || col >= s.cols {
            return Err("A address outside source".into());
        }
        if let Some(v) = self.profile.padding_word(id, row, col)? {
            return Ok(v);
        }
        if !self.kv[id].is_empty() {
            return self.tail(id, self.profile.sources.attention.rope.old + row, col);
        }
        let frozen = self.with_generation(|g| {
            Ok(g.cuts
                .get(&id)
                .map(|v| i64::from(v[row * s.cols + col]))
                .or_else(|| g.histograms.get(&id).map(|v| i64::from(v[col]))))
        })?;
        if let Some(v) = frozen {
            return Ok(v);
        }
        let mut cached = self.row_cache.lock().map_err(|_| "canonical row cache poisoned")?;
        if let Some((i, r, values)) = cached.as_ref() {
            if (*i, *r) == (id, row) {
                return Ok(values[col]);
            }
        }
        *cached = None;
        let mut found = None;
        self.with_generation(|generation| {
            self.scan(generation, &[id].into_iter().collect(), |i, r, v| {
                if (i, r) == (id, row) && found.replace(v.to_vec()).is_some() {
                    return Err("getter emitted target twice".into());
                }
                Ok(())
            })
        })?;
        let found = found.ok_or("getter did not emit target")?;
        let value = found[col];
        *cached = Some((id, row, found));
        Ok(value)
    }

    /// Outside-source Boolean padding is zero bytes, not biased signed zero.
    /// Internal attention padding, in contrast, belongs to the actual source.
    pub(super) fn byte(
        &self,
        id: usize,
        row: usize,
        col: usize,
        byte: usize,
    ) -> Result<u8, String> {
        let b = self.profile.bytes();
        let s = b.scalar.layout.sources.get(id).ok_or("unknown A source")?;
        if byte >= b.widths[id] {
            return Err("byte outside source word".into());
        }
        if row >= s.rows || col >= s.cols {
            return Ok(0);
        }
        Ok((self.value(id, row, col)? as u64 >> (8 * byte)) as u8
            ^ if byte + 1 == b.widths[id] { 128 } else { 0 })
    }

    pub(super) fn byte_at(&self, index: usize) -> Result<u8, String> {
        if index >= 1usize << 34 {
            return Err("A coefficient outside domain".into());
        }
        if index >= self.profile.bytes().live {
            return Ok(0);
        }
        // ponytail: one small window, not the H100 512-reconstruction batch.
        let first = index / 128 * 128;
        let mut cache = self.byte_cache.lock().map_err(|_| "byte cache poisoned")?;
        if cache.0 != first {
            cache.0 = usize::MAX;
            self.window(first, &mut cache.1)?;
            cache.0 = first;
        }
        Ok(cache.1[index - first])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Arc<Canonical> {
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for layer in &softmax.layers {
            scales.insert(layer.pi, -14);
            scales.insert(layer.score, 128);
        }
        Arc::new(Canonical::compile(0, &[0; 772], &scales).unwrap())
    }

    #[test]
    fn c71_canonical_ordered_producer_batches_keep_rows_until_last_consumer() {
        let p = profile();
        let relation = &p.recipes.affine[0];
        let pair = *p.recipes.residual.iter().find(|pair| pair.raw == relation.raw).unwrap();
        let shape = &p.bytes().scalar.layout.sources[relation.raw];
        assert_eq!(shape.rows, 150);
        let value = |r: usize, c: usize| ((r * 7 + c) % 5) as i64 - 2;
        let original: Vec<_> = (0..shape.rows)
            .flat_map(|r| (0..shape.cols).map(move |c| value(r, c) as i16))
            .collect();
        let cuts = relation
            .inputs
            .iter()
            .filter(|(_, coefficient)| *coefficient != 0)
            .map(|&(id, _)| (id, original.clone()))
            .collect();
        let generation = Generation { owner: [9; 32], cuts, histograms: BTreeMap::new() };
        let mut reader = Prepared {
            profile: p.clone(),
            tables: Arc::new(calibration_input::Tables::shape_fixture()),
            weights: Arc::new(Vec::new()),
            previous: Vec::new(),
            tokens: [0; 150],
            kv: vec![Vec::new(); p.bytes().widths.len()],
            owner: [9; 32],
            cache: Arc::new(Cache(Mutex::new(Some(generation)))),
            limit: 16 << 20,
            row_cache: Mutex::new(None),
            byte_cache: Mutex::new((usize::MAX, [0; 128])),
        };
        let targets = [relation.raw, pair.output].into_iter().collect();
        let coefficient = relation.inputs.iter().map(|(_, k)| k).sum::<i64>();
        let mut visits = [0; 2];
        reader
            .with_generation(|g| {
                reader.scan(g, &targets, |id, row, values| {
                    let which = usize::from(id == pair.output);
                    if which == 1 {
                        assert_eq!(visits[0], 150, "all raw rows precede the RNE consumer");
                    }
                    assert_eq!(row, visits[which]);
                    visits[which] += 1;
                    for (col, &v) in values.iter().enumerate() {
                        let raw = coefficient * value(row, col);
                        let expected = if which == 0 {
                            raw
                        } else {
                            i64::from(kernel::rne::integer(raw, pair.shift).unwrap())
                        };
                        assert_eq!(v, expected);
                    }
                    Ok(())
                })
            })
            .unwrap();
        assert_eq!(visits, [150, 150]);
        reader.limit = 1 << 20;
        assert!(reader
            .with_generation(|g| reader.scan(g, &targets, |_, _, _| Ok(())))
            .unwrap_err()
            .contains("workspace budget"));
        reader.limit = 16 << 20;
        let mut calls = 0;
        assert_eq!(
            reader
                .with_generation(|g| reader.scan(g, &targets, |_, _, _| {
                    calls += 1;
                    Err("batch consumer stopped".into())
                }))
                .unwrap_err(),
            "batch consumer stopped"
        );
        assert_eq!(calls, 1);
        // Actual canonical matrix geometry: budget fails BEFORE a huge batch,
        // any original input access or W read. No malformed fixture is executed.
        let raw = p.plan.cohorts.iter().position(|c| c.kind == Kind::Matrix).unwrap();
        let input = p.bytes().scalar.input_sources[raw - 1];
        let descriptor_only = Generation {
            owner: [0; 32],
            cuts: [(input, Vec::new())].into_iter().collect(),
            histograms: BTreeMap::new(),
        };
        reader.limit = 1;
        assert_eq!(
            reader
                .scan(&descriptor_only, &[raw].into_iter().collect(), |_, _, _| panic!(
                    "unexpected output"
                ))
                .unwrap_err(),
            "matrix batch workspace budget exceeded"
        );
        eprintln!("C71_PRODUCER_BATCH_REPLAY rows=150 producers=2 token_major=false gpu=false");
    }

    #[test]
    fn c71_canonical_ordered_internal_padding_histogram_and_byte_window() {
        let p = profile();
        let checkpoint_ids = p.checkpoint_ids().unwrap();
        assert_eq!(checkpoint_ids.len(), 61);
        assert_eq!(checkpoint_ids.len() * 150 * 5376 * 2, 98_380_800);
        let count = p.bytes().widths.len();
        let sm = &p.softmax.layers[0];
        let (score, difference, exponential, denominator, pi, histogram) =
            (sm.score, sm.difference, sm.exponential, sm.denominator, sm.pi, sm.histogram);
        // A single real canonical EXP30 operator, with an explicit synthetic
        // checkpoint at its input. No full-model preparation or PCS claim.
        let mut histogram_values = vec![0; 65535];
        histogram_values[0] = 32 * 256 * 150;
        let generation = Generation {
            owner: [7; 32],
            cuts: [(score, vec![0; 32 * 256 * 150])].into_iter().collect(),
            histograms: [(histogram, histogram_values)].into_iter().collect(),
        };
        let reader = Prepared {
            profile: p,
            tables: Arc::new(calibration_input::Tables::shape_fixture()),
            weights: Arc::new(Vec::new()),
            previous: Vec::new(),
            tokens: [0; 150],
            kv: vec![Vec::new(); count],
            owner: [7; 32],
            cache: Arc::new(Cache(Mutex::new(Some(generation)))),
            limit: 32 << 20,
            row_cache: Mutex::new(None),
            byte_cache: Mutex::new((usize::MAX, [0; 128])),
        };
        let targets = [difference, exponential, denominator, pi, histogram].into_iter().collect();
        let mut words = BTreeMap::<usize, usize>::new();
        reader
            .with_generation(|g| {
                reader.scan(g, &targets, |id, row, values| {
                    *words.entry(id).or_default() += values.len();
                    if id == difference {
                        assert!(values.iter().all(|&v| v == -32767));
                    }
                    if id == exponential {
                        assert!(values.iter().all(|&v| v == 1 << 30));
                    }
                    if id == denominator {
                        assert_eq!(
                            values,
                            &[if row % 256 < 150 { ((row % 256 + 1) as i64) << 30 } else { 0 }]
                        );
                    }
                    if id == histogram {
                        assert_eq!(values[0], 32 * 256 * 150);
                    }
                    Ok(())
                })
            })
            .unwrap();
        for &id in &targets {
            let shape = &reader.profile.bytes().scalar.layout.sources[id];
            assert_eq!(words[&id], shape.rows * shape.cols);
        }
        // Include the frozen checkpoint, all synthesized internal padding and
        // the frozen histogram in the exact same byte-emission path as PCS.
        let mut scan_targets = targets.clone();
        scan_targets.insert(score);
        let b = reader.profile.bytes();
        let expected: usize = scan_targets
            .iter()
            .map(|&id| {
                let shape = &b.scalar.layout.sources[id];
                shape.rows * shape.cols * b.widths[id]
            })
            .sum();
        let mut emitted = 0;
        reader
            .scan_sources(&scan_targets, &mut |index, _| {
                assert!(index < b.live);
                emitted += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(emitted, expected);
        let mut calls = 0;
        assert_eq!(
            reader.scan_sources(&scan_targets, &mut |_, _| {
                calls += 1;
                Err("stop consumer".into())
            }),
            Err("stop consumer".into())
        );
        assert_eq!(calls, 1);
        assert_eq!(reader.value(difference, 255, 0).unwrap(), -32767);
        assert_eq!(reader.byte(difference, 255, 0, 0).unwrap(), 1);
        assert_eq!(reader.byte(difference, 255, 0, 1).unwrap(), 0);
        assert_eq!(reader.byte(difference, 8192, 0, 0).unwrap(), 0);
        assert_eq!(reader.byte(difference, 8192, 0, 1).unwrap(), 0);
        assert!(reader.byte(difference, 0, 0, 2).is_err());
        assert_eq!(reader.value(histogram, 0, 0).unwrap(), 32 * 256 * 150);
        assert!(reader.value(difference, 8192, 0).is_err());
        let mut first = usize::MAX;
        reader
            .profile
            .bytes()
            .emit_row_bytes(difference, 0, &[-32767; 150], |i, _| {
                first = first.min(i);
                Ok(())
            })
            .unwrap();
        let mut window = [0; 8];
        reader.window(first, &mut window).unwrap();
        assert_eq!(window, [1, 0, 1, 0, 1, 0, 1, 0]);
        for (offset, expected) in window.iter().enumerate() {
            assert_eq!(reader.byte_at(first + offset).unwrap(), *expected);
        }
        // Each transformed 8-byte window preserves a subtree while moving the
        // next bit to the MSB. Exercise reconstructed, checkpoint and histogram
        // sources without ever reading weights or a complete A.
        for id in [difference, score, histogram] {
            let shape = &b.scalar.layout.sources[id];
            let mut original = usize::MAX;
            b.emit_row_bytes(id, 0, &vec![0; shape.cols], |i, _| {
                original = original.min(i);
                Ok(())
            })
            .unwrap();
            assert_eq!(original % 8, 0);
            let mut expected = [0; 8];
            reader.window(original, &mut expected).unwrap();
            let ordered = ((original & 8) << 30) | ((original >> 4) << 3);
            reader.range_window(ordered, &mut window, 1, 3).unwrap();
            assert_eq!(window, expected);
        }
        // These windows contain only original flat padding. Neither requests
        // an owner, so an absent generation/weights cannot be silently used.
        reader.range_window((1usize << 34) - 8, &mut window, 1, 3).unwrap();
        assert_eq!(window, [0; 8]);
        window.fill(165);
        for (first, suffix, bottom) in [(1, 1, 3), (0, 35, 0), (0, 0, 4)] {
            assert!(reader.range_window(first, &mut window, suffix, bottom).is_err());
            assert_eq!(window, [165; 8], "geometry rejected before touching output");
        }
        reader.window((1usize << 34) - 8, &mut window).unwrap();
        assert_eq!(window, [0; 8]);
        assert!(reader.window((1usize << 34) - 7, &mut window).is_err());
        assert!(Prepared::prepare(
            reader.profile.clone(),
            reader.tables.clone(),
            Arc::new(Vec::new()),
            &[],
            &[0; 100],
            reader.cache.clone(),
            32 << 20
        )
        .is_err());
    }
}

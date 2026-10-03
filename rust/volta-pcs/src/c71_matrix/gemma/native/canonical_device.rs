use super::*;
use kernel::range::windowed::native::{Config, Stats};
use std::sync::{Mutex, MutexGuard};

pub(in crate::c71_matrix) struct Session {
    runtime: Arc<Mutex<Runtime>>,
    state: Mutex<State>,
    profiles: Vec<Arc<Canonical>>,
    tables: Arc<calibration_input::Tables>,
    weights: Arc<Vec<i16>>,
    config: Config,
    limit: usize,
}

#[derive(Default)]
struct State {
    promoted: usize,
    entries: Vec<Entry>,
    generation: Option<Generation>,
    tables: Option<NonlinearTables>,
}

struct Entry {
    tokens: [u32; 150],
    tails: BTreeMap<usize, Tail>,
}

struct Generation {
    slot: usize,
    inference_ns: u64,
    cuts: BTreeMap<usize, Rows>,
    histograms: BTreeMap<usize, Rows>,
}

impl Generation {
    fn release(self, runtime: &mut Runtime) -> Result<(), String> {
        for rows in self.cuts.into_values().chain(self.histograms.into_values()) {
            rows.release(runtime)?;
        }
        Ok(())
    }
}

pub(in crate::c71_matrix) struct Prepared {
    session: Arc<Session>,
    slot: usize,
    tokens: [u32; 150],
    inference_ns: u64,
    row_cache: Mutex<Option<(usize, usize, Vec<i64>)>>,
    byte_cache: Mutex<(usize, [u8; 128])>,
}

fn input_keys(plan: &Canonical, step: usize, row: usize) -> Result<Vec<(usize, usize)>, String> {
    let producer = plan.steps.get(step).ok_or("native producer missing")?;
    Ok(match producer {
        Producer::Matrix(raw) => vec![(
            plan.bytes().scalar.input_sources[raw - 1],
            plan.plan.input_route(*raw)?.row_offset + row,
        )],
        Producer::Qk(layer) => vec![(plan.sources.attention.layers[*layer].q, row % 256)],
        Producer::Pv(layer) => (0..32)
            .map(|head| (plan.sources.attention.layers[*layer].pi, head * 256 + row))
            .collect(),
        _ => plan.ports(producer).0.into_iter().map(|source| (source, row)).collect(),
    })
}

struct Engine<'a> {
    plan: &'a Canonical,
    runtime: &'a mut Runtime,
    weights: &'a Arc<Vec<i16>>,
    tables: &'a NonlinearTables,
    tails: &'a mut BTreeMap<usize, Tail>,
    frozen: &'a BTreeMap<usize, Rows>,
    live: BTreeMap<(usize, usize), Rows>,
    histograms: BTreeMap<usize, Histogram>,
    replay: bool,
}

impl Engine<'_> {
    fn produce(
        &mut self,
        step: usize,
        first: usize,
        count: usize,
        tokens: &[u32],
    ) -> Result<(Vec<Rows>, Vec<u32>), String> {
        let keys = input_keys(self.plan, step, first)?;
        if self.replay {
            for &(source, _) in &keys {
                if !self.frozen.contains_key(&source)
                    && !self.live.keys().any(|&(id, _)| id == source)
                {
                    if let Some(tail) = self.tails.get(&source) {
                        let buffer = self.runtime.signed_capacity(150 * tail.columns)?;
                        self.runtime.append_signed(
                            &tail.buffer,
                            tail.old * tail.columns,
                            150 * tail.columns,
                            &buffer,
                            0,
                        )?;
                        self.live.insert(
                            (source, 0),
                            Rows {
                                buffer,
                                source,
                                first: 0,
                                rows: 150,
                                columns: tail.columns,
                                layout: self.plan.bytes().layout_digest,
                                recipe: self.plan.recipes.digest,
                            },
                        );
                    }
                }
            }
        }
        let mut inputs = Vec::with_capacity(keys.len());
        for (source, row) in keys {
            let input = self
                .frozen
                .get(&source)
                .or_else(|| {
                    self.live.range((source, 0)..=(source, row)).next_back().map(|(_, rows)| rows)
                })
                .ok_or("native read before producer or after release")?;
            if row < input.first || row - input.first >= input.rows {
                return self.runtime.abort("native input row absent");
            }
            inputs.push(input);
        }
        let producer = &self.plan.steps[step];
        if matches!(producer, Producer::Gelu(_) | Producer::Softcap | Producer::Softmax(_))
            && !self.histograms.contains_key(&step)
        {
            self.histograms.insert(step, self.plan.native_histogram(self.runtime, step)?);
        }
        let tail = match producer {
            Producer::Qk(layer) => Some(
                self.tails
                    .get(&self.plan.sources.attention.layers[*layer].k)
                    .ok_or("native K tail missing")?,
            ),
            Producer::Pv(layer) => Some(
                self.tails
                    .get(&self.plan.sources.attention.layers[*layer].v)
                    .ok_or("native V tail missing")?,
            ),
            _ => None,
        };
        self.plan.produce_native(
            self.runtime,
            step,
            first,
            count,
            Inputs {
                weights: self.weights,
                tables: self.tables,
                rows: &inputs,
                tokens: if matches!(producer, Producer::Embedding) { tokens } else { &[] },
                tail,
                histogram: self.histograms.get_mut(&step),
            },
        )
    }

    fn retain(&mut self, output: Rows, needed: bool) -> Result<(), String> {
        if needed {
            if self.live.insert((output.source, output.first), output).is_some() {
                return self.runtime.abort("native live source overwritten");
            }
            Ok(())
        } else {
            output.release(self.runtime)
        }
    }

    fn release_sources(&mut self, sources: &[usize]) -> Result<(), String> {
        let keys = self
            .live
            .keys()
            .filter(|(source, _)| sources.contains(source))
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            self.live.remove(&key).unwrap().release(self.runtime)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<BTreeMap<usize, Rows>, String> {
        for rows in self.live.into_values() {
            rows.release(self.runtime)?;
        }
        let mut histograms = BTreeMap::new();
        for histogram in self.histograms.into_values() {
            let rows = histogram.finish(self.runtime)?;
            if histograms.insert(rows.source, rows).is_some() {
                return self.runtime.abort("native histogram duplicated");
            }
        }
        Ok(histograms)
    }
}

impl Session {
    pub(in crate::c71_matrix) fn new(
        profiles: Vec<Arc<Canonical>>,
        tables: Arc<calibration_input::Tables>,
        weights: Arc<Vec<i16>>,
        config: Config,
        limit: usize,
    ) -> Result<Arc<Self>, String> {
        if profiles.len() != 3
            || profiles.iter().enumerate().any(|(slot, profile)| {
                profile.sources.attention.rope.old != slot * 150
                    || profile.plan.layout_digest != profiles[0].plan.layout_digest
            })
            || limit < 98_380_800
        {
            return Err("native session profile or budget differs".into());
        }
        let mut runtime = Runtime::new(&config)?;
        install(&mut runtime, &profiles[0].plan, weights.clone())?;
        Ok(Arc::new(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            state: Mutex::new(State::default()),
            profiles,
            tables,
            weights,
            config,
            limit,
        }))
    }

    fn lock(&self) -> Result<(MutexGuard<'_, Runtime>, MutexGuard<'_, State>), String> {
        let runtime = self.runtime.lock().map_err(|_| "native runtime poisoned")?;
        if runtime.stats()?.stopped != 0 {
            return Err("native session stopped".into());
        }
        let state = self.state.lock().map_err(|_| "native snapshot poisoned")?;
        Ok((runtime, state))
    }

    fn tables(&self, runtime: &mut Runtime, state: &mut State, slot: usize) -> Result<(), String> {
        if state.tables.as_ref().is_some_and(|tables| tables.old == slot * 150) {
            return Ok(());
        }
        if let Some(tables) = state.tables.take() {
            tables.release(runtime)?;
        }
        state.tables = Some(self.tables.with_slot(slot, |tables| {
            NonlinearTables::install(runtime, &self.profiles[slot], tables)
        })??);
        Ok(())
    }

    fn build(
        &self,
        runtime: &mut Runtime,
        state: &mut State,
        slot: usize,
        prompt: &[u32; 100],
        replay: bool,
    ) -> Result<(Entry, Generation), String> {
        self.tables(runtime, state, slot)?;
        let plan = &self.profiles[slot];
        let mut tails = BTreeMap::new();
        let sources: BTreeSet<_> =
            plan.sources.attention.layers.iter().flat_map(|layer| [layer.k, layer.v]).collect();
        for source in sources {
            let tail = if replay {
                let prior =
                    state.entries[slot].tails.get(&source).ok_or("native retained KV missing")?;
                Tail {
                    buffer: runtime.share_buffer(&prior.buffer)?,
                    source,
                    old: prior.old,
                    prefix: prior.prefix,
                    columns: prior.columns,
                    layout: prior.layout,
                    recipe: prior.recipe,
                }
            } else {
                Tail::new(
                    runtime,
                    plan,
                    source,
                    if slot == 0 {
                        None
                    } else {
                        Some((
                            &self.profiles[slot - 1],
                            state.entries[slot - 1]
                                .tails
                                .get(&source)
                                .ok_or("native predecessor KV missing")?,
                        ))
                    },
                )?
            };
            tails.insert(source, tail);
        }
        let mut cuts = BTreeMap::new();
        let mut cut_prefix = BTreeMap::new();
        for source in plan.checkpoint_ids()? {
            let shape = &plan.bytes().scalar.layout.sources[source];
            cuts.insert(
                source,
                Rows {
                    buffer: runtime.signed_capacity(shape.rows * shape.cols)?,
                    source,
                    first: 0,
                    rows: shape.rows,
                    columns: shape.cols,
                    layout: plan.bytes().layout_digest,
                    recipe: plan.recipes.digest,
                },
            );
            cut_prefix.insert(source, 0usize);
        }
        let mut last = vec![None; plan.bytes().widths.len()];
        for (step, producer) in plan.steps.iter().enumerate() {
            for source in plan.ports(producer).0 {
                last[source] = Some(step);
            }
        }
        let mut release = vec![Vec::new(); plan.steps.len()];
        for (source, consumer) in last.iter().enumerate() {
            if let Some(step) = consumer {
                release[*step].push(source);
            }
        }
        let mut tokens = if replay { state.entries[slot].tokens } else { [0; 150] };
        tokens[..100].copy_from_slice(prompt);
        let frozen = BTreeMap::new();
        let mut engine = Engine {
            plan,
            runtime,
            weights: &self.weights,
            tables: state.tables.as_ref().unwrap(),
            tails: &mut tails,
            frozen: &frozen,
            live: BTreeMap::new(),
            histograms: BTreeMap::new(),
            replay: false,
        };
        let inference_started = std::time::Instant::now();
        for token in 0..150 {
            let mut decision = None;
            for (step, producer) in plan.steps.iter().enumerate() {
                for row in plan.rows_at_token(producer, token)? {
                    let (outputs, selected) = engine.produce(step, row, 1, &[tokens[token]])?;
                    if !selected.is_empty()
                        && (selected.len() != 1 || decision.replace(selected[0]).is_some())
                    {
                        return engine.runtime.abort("native duplicate causal decision");
                    }
                    for output in outputs {
                        if let Some(cut) = cuts.get(&output.source) {
                            let prefix = cut_prefix.get_mut(&output.source).unwrap();
                            if *prefix != output.first {
                                return engine
                                    .runtime
                                    .abort("native checkpoint row coverage differs");
                            }
                            engine.runtime.append_signed(
                                &output.buffer,
                                0,
                                output.rows * output.columns,
                                &cut.buffer,
                                output.first * output.columns,
                            )?;
                            *prefix += output.rows;
                        }
                        if !replay {
                            if let Some(tail) = engine.tails.get_mut(&output.source) {
                                tail.append(engine.runtime, plan, &output)?;
                            }
                        }
                        let needed = last[output.source].is_some_and(|consumer| consumer > step);
                        engine.retain(output, needed)?;
                    }
                }
                engine.release_sources(&release[step])?;
            }
            if !engine.live.is_empty() || (99..149).contains(&token) != decision.is_some() {
                return engine.runtime.abort("native causal token coverage differs");
            }
            if let Some(next) = decision {
                if replay && tokens[token + 1] != next {
                    return engine.runtime.abort("native replay changed public token");
                }
                tokens[token + 1] = next;
            }
        }
        let histograms = engine.finish()?;
        let inference_ns = u64::try_from(inference_started.elapsed().as_nanos())
            .map_err(|_| "native inference duration overflow")?;
        if cut_prefix.values().any(|&rows| rows != 150) {
            return runtime.abort("native checkpoint incomplete");
        }
        if tails.values().any(|tail| tail.prefix != (slot + 1) * 150) {
            return runtime.abort("native final KV prefix incomplete");
        }
        Ok((Entry { tokens, tails }, Generation { slot, inference_ns, cuts, histograms }))
    }

    pub(in crate::c71_matrix) fn prepare(
        self: &Arc<Self>,
        slot: usize,
        prompt: &[u32; 100],
    ) -> Result<Arc<Prepared>, String> {
        let (mut runtime, mut state) = self.lock()?;
        let result = (|| {
            if slot >= 3
                || state.promoted != slot
                || state.entries.len() != slot
                || prompt.iter().any(|&token| token >= 262144)
            {
                return runtime.abort("native attempt is not the accepted continuation");
            }
            if let Some(generation) = state.generation.take() {
                generation.release(&mut runtime)?;
            }
            let (entry, generation) = self.build(&mut runtime, &mut state, slot, prompt, false)?;
            let tokens = entry.tokens;
            let inference_ns = generation.inference_ns;
            state.entries.push(entry);
            state.generation = Some(generation);
            Ok(Arc::new(Prepared {
                session: self.clone(),
                slot,
                tokens,
                inference_ns,
                row_cache: Mutex::new(None),
                byte_cache: Mutex::new((usize::MAX, [0; 128])),
            }))
        })();
        if let Err(error) = result {
            return runtime.abort(error);
        }
        result
    }

    fn generation(
        &self,
        runtime: &mut Runtime,
        state: &mut State,
        slot: usize,
    ) -> Result<(), String> {
        if slot >= state.entries.len() {
            return runtime.abort("native snapshot missing");
        }
        if state.generation.as_ref().is_some_and(|generation| generation.slot == slot) {
            return Ok(());
        }
        if let Some(generation) = state.generation.take() {
            generation.release(runtime)?;
        }
        let prompt = state.entries[slot].tokens[..100].try_into().unwrap();
        let (entry, generation) = self.build(runtime, state, slot, &prompt, true)?;
        for tail in entry.tails.into_values() {
            tail.release(runtime)?;
        }
        state.generation = Some(generation);
        Ok(())
    }

    pub(in crate::c71_matrix) fn stats(&self) -> Result<Stats, String> {
        self.runtime.lock().unwrap_or_else(|poison| poison.into_inner()).stats()
    }
    pub(in crate::c71_matrix) fn census(&self) -> serde_json::Value {
        let Ok(runtime) = self.runtime.try_lock() else {
            return serde_json::json!({"sample_available": false, "reason": "native owner busy or poisoned"});
        };
        let Ok(state) = self.state.try_lock() else {
            return serde_json::json!({"sample_available": false, "reason": "snapshot busy or poisoned"});
        };
        let Ok(stats) = runtime.stats() else {
            return serde_json::json!({"sample_available": false, "reason": "native owner closed or stats unavailable"});
        };
        let mut unique = BTreeSet::new();
        let kv_bytes: usize = state
            .entries
            .iter()
            .flat_map(|entry| entry.tails.values())
            .filter(|tail| unique.insert(Arc::as_ptr(&tail.buffer) as usize))
            .map(|tail| 450 * tail.columns * 2)
            .sum();
        let cuts = state.generation.as_ref().map_or(0, |generation| {
            generation.cuts.values().map(|rows| rows.rows * rows.columns * 2).sum::<usize>()
        });
        let histograms = state.generation.as_ref().map_or(0, |generation| {
            generation.histograms.values().map(|rows| rows.rows * rows.columns * 8).sum::<usize>()
        });
        serde_json::json!({
            "sample_available": true, "native_cumulative": stats,
            "host_w_capacity_bytes": self.weights.capacity() * 2,
            "host_public_tables_capacity_bytes": self.tables.capacity_bytes(),
            "gpu_kv_capacity_payload_bytes": kv_bytes,
            "gpu_checkpoint_payload_bytes": cuts,
            "gpu_histogram_payload_bytes": histograms,
            "gpu_public_table_payload_bytes": if state.tables.is_some() { 23_954_072usize } else { 0 },
            "promoted_snapshots": state.promoted, "prepared_snapshots": state.entries.len(),
            "generation_slot": state.generation.as_ref().map(|generation| generation.slot),
            "scope": "named payloads are subsets of arena, not additions; W is outside arena; cumulative traffic and peaks must not be summed across samples; host metadata, protocol scratch and CUDA context require process/device observations"
        })
    }
    pub(in crate::c71_matrix) fn close(&self) -> Result<Stats, String> {
        self.runtime.lock().unwrap_or_else(|poison| poison.into_inner()).close()
    }
    pub(in crate::c71_matrix) fn stop(&self) {
        let _ = self
            .runtime
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .abort::<()>("canonical native attempt stopped");
    }
    pub(in crate::c71_matrix) fn require_identity(
        &self,
        profiles: &[Arc<Canonical>],
        tables: &Arc<calibration_input::Tables>,
        weights: &Arc<Vec<i16>>,
    ) -> Result<(), String> {
        if profiles.len() != self.profiles.len()
            || !Arc::ptr_eq(tables, &self.tables)
            || !Arc::ptr_eq(weights, &self.weights)
            || profiles.iter().zip(&self.profiles).any(|(left, right)| !Arc::ptr_eq(left, right))
        {
            self.stop();
            return Err("native proof installation identity differs".into());
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn weight_range_config(&self) -> Result<Config, String> {
        let plan = self.profiles[0].clone();
        let weights = self.weights.clone();
        let mut config = self.config.clone();
        config.window_words = 1 << 27;
        config.with_resident(
            self.runtime.clone(),
            Arc::new(move |runtime, suffix, bottom, first, length| {
                if length > 1 << 27 {
                    return runtime.abort("native W staging exceeds 256 MiB");
                }
                let mut output = vec![0i16; length];
                plan.plan.range_window(35, &weights, first, &mut output, suffix, bottom)?;
                runtime.upload_signed(&output)
            }),
        )
    }
}

fn batches(plan: &Canonical, step: usize) -> Result<Vec<(usize, usize)>, String> {
    let first = plan.rows_at_token(&plan.steps[step], 0)?;
    if first.is_empty() {
        Ok(plan.rows_at_token(&plan.steps[step], 99)?.into_iter().map(|row| (row, 50)).collect())
    } else {
        let source = plan.ports(&plan.steps[step]).1[0];
        let count = plan.bytes().scalar.layout.sources[source].rows.min(150);
        Ok(first.into_iter().map(|row| (row, count)).collect())
    }
}

fn public_padding(
    runtime: &mut Runtime,
    plan: &Canonical,
    source: usize,
    first: usize,
    rows: usize,
) -> Result<Rows, String> {
    let columns = plan.bytes().scalar.layout.sources[source].cols;
    let value = plan.padding_word(source, first, 0)?.ok_or("native padding source differs")?;
    let count = rows * columns;
    let buffer = if plan.bytes().widths[source] == 2 {
        runtime.upload_signed(&vec![
            i16::try_from(value)
                .map_err(|_| "native padding outside i16")?;
            count
        ])?
    } else {
        let input = if value == 0 { None } else { Some(runtime.upload_signed(&vec![1; count])?) };
        let buffer = runtime.pointwise(
            [input.as_ref().map(|input| (input, 0)), None],
            count,
            Pointwise { a: value, b: 0, multiply: 0 },
        )?;
        if let Some(input) = input {
            runtime.release_buffer(input)?;
        }
        buffer
    };
    Ok(Rows {
        buffer,
        source,
        first,
        rows,
        columns,
        layout: plan.bytes().layout_digest,
        recipe: plan.recipes.digest,
    })
}

impl Prepared {
    pub(in crate::c71_matrix) fn inference_ns(&self) -> u64 {
        self.inference_ns
    }
    pub(in crate::c71_matrix) fn tokens(&self) -> [u32; 150] {
        self.tokens
    }
    pub(in crate::c71_matrix) fn promote(&self) -> Result<(), String> {
        let (mut runtime, mut state) = self.session.lock()?;
        if state.promoted != self.slot || state.entries.len() != self.slot + 1 {
            return runtime.abort("native promotion order differs");
        }
        state.promoted += 1;
        Ok(())
    }

    pub(in crate::c71_matrix) fn weight(
        &self,
        source: usize,
        row: usize,
        column: usize,
    ) -> Result<i64, String> {
        let shape = self.session.profiles[self.slot]
            .plan
            .sources
            .get(source)
            .ok_or("native W source missing")?;
        if row >= shape.rows || column >= shape.cols {
            return Err("native W address outside source".into());
        }
        Ok(i64::from(self.session.weights[shape.packed_offset + row * shape.cols + column]))
    }

    fn scan_inner(
        &self,
        runtime: &mut Runtime,
        state: &mut State,
        targets: &BTreeSet<usize>,
        emit: &mut impl FnMut(&mut Runtime, usize, usize, usize, &Buffer, usize) -> Result<(), String>,
    ) -> Result<(), String> {
        self.session.generation(runtime, state, self.slot)?;
        let plan = &self.session.profiles[self.slot];
        let sources = &plan.bytes().scalar.layout.sources;
        let generation = state.generation.as_ref().unwrap();
        let tails = &mut state.entries[self.slot].tails;
        let frozen: BTreeSet<_> = generation
            .cuts
            .keys()
            .chain(generation.histograms.keys())
            .chain(tails.keys())
            .copied()
            .collect();
        let mut owner = vec![usize::MAX; sources.len()];
        for (step, producer) in plan.steps.iter().enumerate() {
            for source in plan.ports(producer).1 {
                owner[source] = step;
            }
        }
        let mut needed = BTreeSet::new();
        let mut pending = targets.iter().copied().collect::<Vec<_>>();
        while let Some(source) = pending.pop() {
            if source >= sources.len() {
                return runtime.abort("native scan source outside A");
            }
            if frozen.contains(&source) {
                continue;
            }
            let step = owner[source];
            if step == usize::MAX {
                return runtime.abort("native scan source has no producer");
            }
            if needed.insert(step) {
                pending.extend(plan.ports(&plan.steps[step]).0);
            }
        }
        let mut last = vec![None; sources.len()];
        for &step in &needed {
            for source in plan.ports(&plan.steps[step]).0 {
                last[source] = Some(step);
            }
        }
        let mut release = vec![Vec::new(); plan.steps.len()];
        for (source, consumer) in last.iter().enumerate() {
            if let Some(step) = consumer {
                release[*step].push(source);
            }
        }
        let mut engine = Engine {
            plan,
            runtime,
            weights: &self.session.weights,
            tables: state.tables.as_ref().unwrap(),
            tails,
            frozen: &generation.cuts,
            live: BTreeMap::new(),
            histograms: BTreeMap::new(),
            replay: true,
        };
        for step in needed {
            for (first, count) in batches(plan, step)? {
                let tokens = if matches!(plan.steps[step], Producer::Embedding) {
                    &self.tokens[first..first + count]
                } else {
                    &[]
                };
                let (outputs, selected) = engine.produce(step, first, count, tokens)?;
                if !selected.is_empty()
                    && (first + count > 50
                        || selected != self.tokens[100 + first..100 + first + count])
                {
                    return engine.runtime.abort("native batch replay changed public tokens");
                }
                for output in outputs {
                    if targets.contains(&output.source) && !frozen.contains(&output.source) {
                        emit(
                            engine.runtime,
                            output.source,
                            output.first,
                            output.rows,
                            &output.buffer,
                            0,
                        )?;
                    }
                    let retain = !frozen.contains(&output.source)
                        && last[output.source].is_some_and(|consumer| consumer > step);
                    engine.retain(output, retain)?;
                }
            }
            engine.release_sources(&release[step])?;
        }
        for histogram in engine.finish()?.into_values() {
            histogram.release(runtime)?;
        }
        for &source in targets {
            if let Some(rows) =
                generation.cuts.get(&source).or_else(|| generation.histograms.get(&source))
            {
                emit(runtime, source, rows.first, rows.rows, &rows.buffer, 0)?;
            } else if let Some(tail) = state.entries[self.slot].tails.get(&source) {
                emit(runtime, source, 0, 150, &tail.buffer, tail.old * tail.columns)?;
            } else {
                let shape = &sources[source];
                for head in 0..shape.rows.div_ceil(256) {
                    let first = head * 256 + 150;
                    if first < shape.rows && plan.padding_word(source, first, 0)?.is_some() {
                        let rows = public_padding(
                            runtime,
                            plan,
                            source,
                            first,
                            (shape.rows - first).min(106),
                        )?;
                        emit(runtime, source, rows.first, rows.rows, &rows.buffer, 0)?;
                        rows.release(runtime)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn scan(
        &self,
        runtime: &mut Runtime,
        state: &mut State,
        targets: &BTreeSet<usize>,
        mut emit: impl FnMut(&mut Runtime, usize, usize, usize, &Buffer, usize) -> Result<(), String>,
    ) -> Result<(), String> {
        let sources = &self.session.profiles[self.slot].bytes().scalar.layout.sources;
        let mut seen = targets
            .iter()
            .map(|&source| {
                sources
                    .get(source)
                    .map(|shape| (source, vec![false; shape.rows]))
                    .ok_or("native scan source missing")
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        self.scan_inner(
            runtime,
            state,
            targets,
            &mut |runtime, source, first, count, input, offset| {
                let coverage =
                    seen.get_mut(&source).ok_or("native scan emitted unexpected source")?;
                if count == 0
                    || first.checked_add(count).is_none_or(|end| end > coverage.len())
                    || coverage[first..first + count].iter().any(|&covered| covered)
                {
                    return runtime.abort("native scan duplicated or invalid rows");
                }
                coverage[first..first + count].fill(true);
                emit(runtime, source, first, count, input, offset)
            },
        )?;
        if seen.values().any(|rows| rows.iter().any(|&covered| !covered)) {
            return runtime.abort("native scan omitted rows");
        }
        Ok(())
    }

    fn window_native(
        &self,
        runtime: &mut Runtime,
        suffix: usize,
        bottom: usize,
        first: usize,
        length: usize,
    ) -> Result<Buffer, String> {
        if length > self.session.limit {
            return runtime.abort("native window exceeds preparation budget");
        }
        let plan = &self.session.profiles[self.slot];
        let mut state = self.session.state.lock().map_err(|_| "native snapshot poisoned")?;
        let mut window = ByteWindow::new(
            runtime,
            plan.bytes(),
            plan.recipes.digest,
            34,
            first,
            length,
            suffix,
            bottom,
        )?;
        let targets = window.sources().collect();
        self.scan(runtime, &mut state, &targets, |runtime, source, row, count, input, offset| {
            window.append_original(runtime, source, row, count, input, offset)
        })?;
        window.finish(runtime)
    }

    pub(in crate::c71_matrix) fn range_config(self: &Arc<Self>) -> Result<Config, String> {
        let prepared = self.clone();
        self.session.config.clone().with_resident(
            self.session.runtime.clone(),
            Arc::new(move |runtime, suffix, bottom, first, length| {
                prepared.window_native(runtime, suffix, bottom, first, length)
            }),
        )
    }

    pub(in crate::c71_matrix) fn window(
        &self,
        first: usize,
        output: &mut [u8],
    ) -> Result<(), String> {
        let mut runtime = self.session.runtime.lock().map_err(|_| "native runtime poisoned")?;
        let result = (|| {
            if output.len() > (1 << 28).min(self.session.limit)
                || first.checked_add(output.len()).is_none_or(|end| end > 1usize << 34)
            {
                return runtime.abort("native host staging window exceeds bound");
            }
            let length = output.len().max(128).next_power_of_two();
            let mut written = 0;
            while written < output.len() {
                let address = first + written;
                let start = address / length * length;
                let count = (length - (address - start)).min(output.len() - written);
                let input = self.window_native(&mut runtime, 0, 0, start, length)?;
                runtime.download_bytes(
                    &input,
                    address - start,
                    &mut output[written..written + count],
                )?;
                runtime.release_buffer(input)?;
                written += count;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return runtime.abort(error);
        }
        Ok(())
    }

    pub(in crate::c71_matrix) fn scan_original(
        &self,
        emit: &mut dyn FnMut(usize, Goldilocks) -> Result<(), String>,
    ) -> Result<(), String> {
        let (mut runtime, mut state) = self.session.lock()?;
        let plan = &self.session.profiles[self.slot];
        let targets = (0..plan.bytes().widths.len()).collect();
        let result = self.scan(
            &mut runtime,
            &mut state,
            &targets,
            |runtime, source, first, count, input, offset| {
                let columns = plan.bytes().scalar.layout.sources[source].cols;
                let mut words = vec![0; columns];
                for row in 0..count {
                    runtime.download_words(input, offset + row * columns, &mut words)?;
                    plan.bytes().emit_row_bytes(
                        source,
                        first + row,
                        &words,
                        &mut |index, byte| emit(index, Goldilocks::from_u8(byte)),
                    )?;
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            return runtime.abort(error);
        }
        Ok(())
    }

    pub(in crate::c71_matrix) fn value(
        &self,
        source: usize,
        row: usize,
        column: usize,
    ) -> Result<i64, String> {
        let plan = &self.session.profiles[self.slot];
        let shape = plan
            .bytes()
            .scalar
            .layout
            .sources
            .get(source)
            .ok_or("native original source missing")?;
        if row >= shape.rows || column >= shape.cols {
            return Err("native original address outside source".into());
        }
        if let Some(value) = plan.padding_word(source, row, column)? {
            return Ok(value);
        }
        let mut cache = self.row_cache.lock().map_err(|_| "native row cache poisoned")?;
        if let Some((cached_source, cached_row, values)) = cache.as_ref() {
            if (*cached_source, *cached_row) == (source, row) {
                return Ok(values[column]);
            }
        }
        *cache = None;
        let mut words = vec![0; shape.cols];
        let (mut runtime, mut state) = self.session.lock()?;
        let result = self.scan(
            &mut runtime,
            &mut state,
            &[source].into_iter().collect(),
            |runtime, emitted, first, count, input, offset| {
                if emitted == source && (first..first + count).contains(&row) {
                    runtime.download_words(
                        input,
                        offset + (row - first) * shape.cols,
                        &mut words,
                    )?;
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            return runtime.abort(error);
        }
        let value = words[column];
        *cache = Some((source, row, words));
        Ok(value)
    }

    pub(in crate::c71_matrix) fn tail(
        &self,
        source: usize,
        token: usize,
        column: usize,
    ) -> Result<i64, String> {
        if token >= (self.slot + 1) * 150 {
            return Err("native KV address after snapshot".into());
        }
        let mut cache = self.row_cache.lock().map_err(|_| "native row cache poisoned")?;
        let cache_row = 150 + token;
        if let Some((cached_source, cached_row, values)) = cache.as_ref() {
            if (*cached_source, *cached_row) == (source, cache_row) {
                return values.get(column).copied().ok_or("native KV column outside source".into());
            }
        }
        *cache = None;
        let (mut runtime, state) = self.session.lock()?;
        let tail = state.entries[self.slot].tails.get(&source).ok_or("native KV source missing")?;
        if column >= tail.columns {
            return runtime.abort("native KV column outside source");
        }
        let mut words = vec![0; tail.columns];
        runtime.download_words(&tail.buffer, token * tail.columns, &mut words)?;
        let value = words[column];
        *cache = Some((source, cache_row, words));
        Ok(value)
    }

    pub(in crate::c71_matrix) fn byte(
        &self,
        source: usize,
        row: usize,
        column: usize,
        byte: usize,
    ) -> Result<u8, String> {
        let bytes = self.session.profiles[self.slot].bytes();
        let shape = bytes.scalar.layout.sources.get(source).ok_or("native byte source missing")?;
        if byte >= bytes.widths[source] {
            return Err("native byte outside word".into());
        }
        if row >= shape.rows || column >= shape.cols {
            return Ok(0);
        }
        Ok((self.value(source, row, column)? as u64 >> (8 * byte)) as u8
            ^ if byte + 1 == bytes.widths[source] { 128 } else { 0 })
    }

    pub(in crate::c71_matrix) fn byte_at(&self, index: usize) -> Result<u8, String> {
        if index >= 1usize << 34 {
            return Err("native A address outside domain".into());
        }
        if index >= self.session.profiles[self.slot].bytes().live {
            return Ok(0);
        }
        let mut cache = self.byte_cache.lock().map_err(|_| "native byte cache poisoned")?;
        let first = index / 128 * 128;
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
    use kernel::range::windowed::native::tests::fixture;

    #[test]
    fn c71_canonical_device_schedule_all_producers_three_contexts() {
        for slot in 0..3 {
            let plan = super::super::tests::nonlinear_profile(slot);
            let mut last = BTreeMap::new();
            for (step, producer) in plan.steps.iter().enumerate() {
                for source in plan.ports(producer).0 {
                    last.insert(source, step);
                }
            }
            let kv: BTreeSet<_> =
                plan.sources.attention.layers.iter().flat_map(|layer| [layer.k, layer.v]).collect();
            let mut prefixes =
                kv.iter().map(|&source| (source, 0usize)).collect::<BTreeMap<_, _>>();
            let mut cuts = plan
                .checkpoint_ids()
                .unwrap()
                .into_iter()
                .map(|source| (source, 0usize))
                .collect::<BTreeMap<_, _>>();
            let mut live = BTreeSet::new();
            let mut decisions = 0;
            let mut categories = BTreeSet::new();
            for token in 0..150 {
                for (step, producer) in plan.steps.iter().enumerate() {
                    let rows = plan.rows_at_token(producer, token).unwrap();
                    for row in rows {
                        for key in input_keys(&plan, step, row).unwrap() {
                            assert!(
                                live.contains(&key),
                                "slot={slot} token={token} step={step} input={key:?}"
                            );
                        }
                        let category = match producer {
                            Producer::Embedding => 0,
                            Producer::Matrix(_) => 1,
                            Producer::Norm(_) => 2,
                            Producer::Rne(_) => 3,
                            Producer::Affine(_) => 4,
                            Producer::Gelu(_) => 5,
                            Producer::Gate(_) => 6,
                            Producer::Rope(_) => 7,
                            Producer::Qk(layer) => {
                                assert_eq!(
                                    prefixes[&plan.sources.attention.layers[*layer].k],
                                    token + 1
                                );
                                8
                            }
                            Producer::Softmax(_) => 9,
                            Producer::Pv(layer) => {
                                assert_eq!(
                                    prefixes[&plan.sources.attention.layers[*layer].v],
                                    token + 1
                                );
                                10
                            }
                            Producer::Softcap => 11,
                            Producer::Argmax => {
                                decisions += 1;
                                12
                            }
                        };
                        categories.insert(category);
                        for source in plan.ports(producer).1 {
                            let shape = &plan.bytes().scalar.layout.sources[source];
                            if (shape.rows, shape.cols) == (1, 65535) {
                                continue;
                            }
                            assert!(row < shape.rows);
                            if let Some(prefix) = prefixes.get_mut(&source) {
                                assert_eq!(*prefix, token);
                                *prefix += 1;
                            }
                            if let Some(prefix) = cuts.get_mut(&source) {
                                assert_eq!(*prefix, token);
                                *prefix += 1;
                            }
                            if last.get(&source).is_some_and(|&consumer| consumer > step) {
                                assert!(live.insert((source, row)));
                            }
                        }
                    }
                    live.retain(|(source, _)| last[source] != step);
                }
                assert!(live.is_empty());
            }
            assert_eq!(decisions, 50);
            assert_eq!(categories.len(), 13);
            assert!(prefixes.values().chain(cuts.values()).all(|&prefix| prefix == 150));
            for (step, producer) in plan.steps.iter().enumerate() {
                let scalar: BTreeSet<_> = (0..150)
                    .flat_map(|token| plan.rows_at_token(producer, token).unwrap())
                    .collect();
                let batched: BTreeSet<_> = batches(&plan, step)
                    .unwrap()
                    .into_iter()
                    .flat_map(|(first, count)| first..first + count)
                    .collect();
                assert_eq!(batched, scalar, "slot={slot} step={step}");
            }
        }
    }

    #[test]
    fn c71_canonical_device_replay_original_rows_windows_and_failure() {
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 64 << 20;
        let mut plan = super::super::tests::nonlinear_profile(0);
        let relation = &plan.recipes.affine[0];
        let pair = *plan.recipes.residual.iter().find(|pair| pair.raw == relation.raw).unwrap();
        plan.steps = vec![Producer::Affine(0), Producer::Rne(pair)];
        let plan = Arc::new(plan);
        let relation = &plan.recipes.affine[0];
        let tables = Arc::new(calibration_input::Tables::resident_fixture());
        let mut runtime = Runtime::new(&fixture.config).unwrap();
        let native_tables = tables
            .with_slot(0, |tables| NonlinearTables::install(&mut runtime, &plan, tables))
            .unwrap()
            .unwrap();
        let sample = |source: usize, row: usize, column: usize| {
            ((source + row * 3 + column * 7) % 5) as i16 - 2
        };
        let mut cuts = BTreeMap::new();
        for &(source, coefficient) in &relation.inputs {
            if coefficient == 0 {
                continue;
            }
            let shape = &plan.bytes().scalar.layout.sources[source];
            let values = (0..150)
                .flat_map(|row| (0..shape.cols).map(move |column| sample(source, row, column)))
                .collect::<Vec<_>>();
            cuts.insert(source, plan.upload_native_rows(&mut runtime, source, 0, &values).unwrap());
        }
        let session = Arc::new(Session {
            runtime: Arc::new(Mutex::new(runtime)),
            state: Mutex::new(State {
                promoted: 0,
                entries: vec![Entry { tokens: [0; 150], tails: BTreeMap::new() }],
                generation: Some(Generation {
                    slot: 0,
                    inference_ns: 0,
                    cuts,
                    histograms: BTreeMap::new(),
                }),
                tables: Some(native_tables),
            }),
            profiles: vec![plan.clone()],
            tables,
            weights: Arc::new(Vec::new()),
            config: fixture.config.clone(),
            limit: 64 << 20,
        });
        let prepared = Prepared {
            session: session.clone(),
            slot: 0,
            tokens: [0; 150],
            inference_ns: 0,
            row_cache: Mutex::new(None),
            byte_cache: Mutex::new((usize::MAX, [0; 128])),
        };
        let census = session.census();
        assert_eq!(census["sample_available"], true);
        assert_eq!(census["host_w_capacity_bytes"], 0);
        assert_eq!(census["gpu_public_table_payload_bytes"], 23_954_072usize);
        assert_eq!(census["prepared_snapshots"], 1);
        assert_eq!(census["promoted_snapshots"], 0);
        assert!(census["native_cumulative"]["live_capacity_bytes"].as_u64().unwrap() > 0);
        let columns = plan.bytes().scalar.layout.sources[relation.raw].cols;
        let raw = |row: usize, column: usize| {
            relation
                .inputs
                .iter()
                .map(|&(source, coefficient)| i64::from(sample(source, row, column)) * coefficient)
                .sum::<i64>()
        };
        let targets = [relation.raw, pair.output].into_iter().collect();
        let mut observed = 0;
        {
            let (mut runtime, mut state) = session.lock().unwrap();
            prepared
                .scan(
                    &mut runtime,
                    &mut state,
                    &targets,
                    |runtime, source, first, count, input, offset| {
                        let mut words = vec![0; columns];
                        for row in first..first + count {
                            runtime.download_words(
                                input,
                                offset + (row - first) * columns,
                                &mut words,
                            )?;
                            for (column, &value) in words.iter().enumerate() {
                                let expected = raw(row, column);
                                assert_eq!(
                                    value,
                                    if source == relation.raw {
                                        expected
                                    } else {
                                        i64::from(kernel::rne::integer(expected, pair.shift)?)
                                    }
                                );
                            }
                            observed += 1;
                        }
                        Ok(())
                    },
                )
                .unwrap();
        }
        assert_eq!(observed, 300);
        assert_eq!(prepared.value(relation.raw, 17, 44).unwrap(), raw(17, 44));
        let before = session.stats().unwrap();
        assert_eq!(prepared.value(relation.raw, 17, 45).unwrap(), raw(17, 45));
        assert_eq!(session.stats().unwrap().d2h_bytes, before.d2h_bytes);
        let mut expected = BTreeMap::new();
        for row in [17] {
            plan.bytes()
                .emit_row_bytes(
                    relation.raw,
                    row,
                    &(0..columns).map(|column| raw(row, column)).collect::<Vec<_>>(),
                    &mut |index, byte| {
                        expected.insert(index, byte);
                        Ok(())
                    },
                )
                .unwrap();
        }
        let first = *expected.keys().nth(256).unwrap() + 3;
        let mut output = [0u8; 37];
        prepared.window(first, &mut output).unwrap();
        for (offset, byte) in output.into_iter().enumerate() {
            assert_eq!(byte, expected[&(first + offset)]);
        }
        prepared.promote().unwrap();
        assert!(prepared.scan_original(&mut |_, _| Ok(())).is_err());
        assert_eq!(session.stats().unwrap().stopped, 1);
        assert!(prepared.promote().is_err());
        assert_eq!(session.state.lock().unwrap().promoted, 1);
        session.close().unwrap();
    }
}

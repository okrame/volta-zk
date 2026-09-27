//! Numeric bounded-profile replay, with no dense Snapshot or A allocation.
//! The canonical geometry/accelerator adapter is a separate obligation.
use super::*;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Default, Debug, serde::Serialize)]
pub(super) struct Work {
    pub(super) producer_rows: Vec<usize>,
    pub(super) numerical: prepare::RowWork,
    pub(super) original_scalar_reads: usize,
    pub(super) old_kv_reads: usize,
    pub(super) weight_scalar_reads: usize,
    pub(super) emitted_bytes: usize,
    pub(super) named_heap_peak: usize,
}

impl Work {
    fn absorb(&mut self, rhs: Self) {
        if self.producer_rows.len() < rhs.producer_rows.len() {
            self.producer_rows.resize(rhs.producer_rows.len(), 0);
        }
        for (dst, value) in self.producer_rows.iter_mut().zip(rhs.producer_rows) {
            *dst += value;
        }
        self.numerical.add_assign(rhs.numerical);
        self.original_scalar_reads += rhs.original_scalar_reads;
        self.old_kv_reads += rhs.old_kv_reads;
        self.weight_scalar_reads += rhs.weight_scalar_reads;
        self.emitted_bytes += rhs.emitted_bytes;
        self.named_heap_peak = self.named_heap_peak.max(rhs.named_heap_peak);
    }
}

/// Compact original K/V, not an acceptance receipt. Runtime history comes
/// from the native accepted owner. Component tests may construct diagnostic
/// predecessors; there is no production import from a certificate.
struct Frozen {
    tokens: [u32; 2],
    model_root: [u8; 32],
    profile: [u8; 32],
    old: usize,
    source_root: [u8; 32],
    kv: BTreeMap<usize, Vec<i16>>,
}

struct Cuts {
    owner: ([u8; 32], [u8; 32], [u8; 32], usize, [u32; 2]),
    values: BTreeMap<usize, Vec<i16>>,
}

fn kv_ids(p: &Profile) -> [usize; 2] {
    [p.rotations[1][1], p.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output]
}

fn replay(
    p: &Profile,
    w: &prepare::Installed,
    old: &[Arc<Frozen>],
    tokens: [u32; 2],
    cuts: &BTreeMap<usize, Vec<i16>>,
    targets: &BTreeSet<usize>,
    row_limit: usize,
    mut emit: impl FnMut(usize, usize, &[i64]) -> Result<(), String>,
) -> Result<Work, String> {
    if old.len() * TOKENS != p.old
        || tokens.iter().any(|&t| t >= 2)
        || old.iter().enumerate().any(|(slot, s)| {
            s.old != slot * TOKENS
                || s.model_root != w.model.root.roots()[0]
                || s.profile != p.digest
        })
    {
        return Err("ordered original source context differs".into());
    }
    let sources = &p.bytes().scalar.layout.sources;
    let mut owner = vec![usize::MAX; sources.len()];
    for (i, step) in p.steps.iter().enumerate() {
        for id in p.outputs(step) {
            owner[id] = i;
        }
    }
    let mut needed = BTreeSet::new();
    let mut pending: Vec<_> = targets.iter().copied().collect();
    while let Some(id) = pending.pop() {
        if cuts.contains_key(&id) {
            continue;
        }
        let step = *owner.get(id).ok_or("ordered target outside A")?;
        if step == usize::MAX {
            return Err("ordered source has no producer".into());
        }
        if needed.insert(step) {
            pending.extend(p.inputs(&p.steps[step]));
        }
    }
    let mut uses = vec![0usize; sources.len()];
    for &i in &needed {
        for id in p.inputs(&p.steps[i]) {
            if !cuts.contains_key(&id) {
                uses[id] += 1;
            }
        }
    }
    let mut live: BTreeMap<usize, Vec<i64>> = BTreeMap::new();
    let reads = Cell::new(0);
    let kv_reads = Cell::new(0);
    let weight_reads = Cell::new(0);
    let mut work = Work { producer_rows: vec![0; p.steps.len()], ..Work::default() };
    let cut_bytes = cuts.values().map(|v| v.capacity() * 2).sum::<usize>();
    for &i in &needed {
        let step = &p.steps[i];
        let outputs = p.outputs(step);
        let histogram = match step {
            Step::Gelu => Some(p.gelu.histogram),
            Step::Softcap => Some(p.output.histogram),
            Step::Softmax => Some(p.softmax.layers[0].histogram),
            _ => None,
        };
        let mut counts = histogram.map(|id| vec![0i64; sources[id].cols]);
        let mut produced: BTreeMap<usize, Vec<i64>> = outputs
            .iter()
            .copied()
            .filter(|&id| uses[id] > 0 && !cuts.contains_key(&id))
            .map(|id| (id, vec![0; sources[id].rows * sources[id].cols]))
            .collect();
        for row in 0..sources[outputs[0]].rows.min(row_limit) {
            let get = |id: usize, r: usize, c: usize| {
                reads.set(reads.get() + 1);
                let index = r * sources[id].cols + c;
                cuts.get(&id).map_or_else(|| live[&id][index], |v| i64::from(v[index]))
            };
            let tail = |id: usize, r: usize, c: usize| {
                assert!(r <= p.old + row, "future KV read");
                if r < p.old {
                    kv_reads.set(kv_reads.get() + 1);
                    i64::from(old[r / TOKENS].kv[&id][(r % TOKENS) * sources[id].cols + c])
                } else {
                    get(id, r - p.old, c)
                }
            };
            let mut emitted_tokens = tokens;
            let weight = |id, r, c| {
                weight_reads.set(weight_reads.get() + 1);
                w.weight(p, id, r, c)
            };
            let result = prepare::evaluate_row_counted(
                p,
                weight,
                step,
                row,
                &mut emitted_tokens,
                get,
                tail,
                &mut work.numerical,
            )?;
            if matches!(step, Step::Argmax) && emitted_tokens != tokens {
                return Err("ordered token differs from original inference".into());
            }
            work.producer_rows[i] += 1;
            work.named_heap_peak = work.named_heap_peak.max(
                cut_bytes
                    + live
                        .values()
                        .chain(produced.values())
                        .map(|v| v.capacity() * 8)
                        .sum::<usize>()
                    + counts.as_ref().map_or(0, |v| v.capacity() * 8)
                    + result.iter().map(|(_, v)| v.capacity() * 8).sum::<usize>(),
            );
            if let Some(h) = counts.as_mut() {
                let (input, lower) = match step {
                    Step::Gelu => (p.gelu.input, i64::from(p.gelu.lower)),
                    Step::Softcap => (p.output.input, i64::from(p.output.lower)),
                    Step::Softmax => (p.softmax.layers[0].difference, -32767),
                    _ => unreachable!(),
                };
                for col in 0..sources[input].cols {
                    let value = result
                        .iter()
                        .find(|(id, _)| *id == input)
                        .map_or_else(|| get(input, row, col), |(_, v)| v[col]);
                    let index = usize::try_from(value - lower).map_err(|_| "histogram index")?;
                    *h.get_mut(index).ok_or("histogram index outside table")? += 1;
                }
            }
            for (id, words) in result {
                if targets.contains(&id) {
                    emit(id, row, &words)?;
                }
                if let Some(out) = produced.get_mut(&id) {
                    let first = row * sources[id].cols;
                    out[first..first + words.len()].copy_from_slice(&words);
                }
            }
        }
        if let Some(id) = histogram {
            let counts = counts.unwrap();
            if targets.contains(&id) {
                emit(id, 0, &counts)?;
            }
            if let Some(out) = produced.get_mut(&id) {
                out.copy_from_slice(&counts);
            }
        }
        for id in p.inputs(step) {
            if cuts.contains_key(&id) {
                continue;
            }
            uses[id] -= 1;
            if uses[id] == 0 {
                live.remove(&id);
            }
        }
        live.extend(produced);
    }
    for &id in targets {
        if needed.contains(&owner[id]) {
            continue;
        }
        let values = cuts.get(&id).ok_or("missing original cut")?;
        for (row, words) in values.chunks_exact(sources[id].cols).enumerate() {
            let words: Vec<_> = words.iter().copied().map(i64::from).collect();
            emit(id, row, &words)?;
        }
    }
    assert!(live.is_empty());
    work.original_scalar_reads = reads.get();
    work.old_kv_reads = kv_reads.get();
    work.weight_scalar_reads = weight_reads.get();
    Ok(work)
}

/// Numerical source. Its identity and both causal tokens are fixed before
/// a PCS/FS caller obtains any getter. The PCS model remains a separate owner.
pub(super) struct Reader {
    profile: Arc<Profile>,
    weights: Arc<prepare::Installed>,
    frozen: Arc<Frozen>,
    old: Vec<Arc<Frozen>>,
    cuts: Cuts,
    row_cache: Mutex<Option<(usize, usize, Vec<i64>)>>,
    byte_cache: Mutex<(usize, [u8; 128])>,
    work: Mutex<Work>,
}

impl Reader {
    pub(super) fn prepare(
        profile: Arc<Profile>,
        weights: Arc<prepare::Installed>,
        old: &[Arc<Self>],
        prompt: u32,
    ) -> Result<Arc<Self>, String> {
        if old.len() * TOKENS != profile.old || prompt >= 2 {
            return Err("ordered reader history or binary prompt differs".into());
        }
        let old = old.iter().map(|reader| reader.frozen.clone()).collect::<Vec<_>>();
        // Discover only from causal row-0 logits. Row 1 and Argmax are outside
        // this replay, so the provisional second token is never privately read
        // or checked.
        let target = profile.output.output;
        let targets = [target].into_iter().collect();
        let mut logits = None;
        let discovery_work = replay(
            &profile,
            &weights,
            &old,
            [prompt, 0],
            &BTreeMap::new(),
            &targets,
            1,
            |id, row, words| {
                if id == target && row == 0 {
                    logits = Some(words.to_vec());
                }
                Ok(())
            },
        )?;
        let logits = logits.ok_or("ordered row-0 logits were not produced")?;
        if logits.len() != 2 {
            return Err("ordered row-0 logits width differs".into());
        }
        let generated = u32::from(logits[1] > logits[0]);
        let tokens = [prompt, generated];
        // Validate every producer and every private bound with the final causal
        // tokens before any getter can escape. Emission is streamed/discarded;
        // this retains neither Snapshot nor the full A source.
        let all_sources = profile.steps.iter().flat_map(|step| profile.outputs(step)).collect();
        let validation_work = replay(
            &profile,
            &weights,
            &old,
            tokens,
            &BTreeMap::new(),
            &all_sources,
            TOKENS,
            |_id, _row, _words| Ok(()),
        )?;
        // The numeric reader has no commitment yet. This private placeholder is
        // only the internal Frozen/Cuts ownership nonce; the caller constructs
        // and owns the eventual ReplayModel/root.
        let (frozen, cuts, frozen_work) =
            Frozen::prepare(&profile, &weights, &old, tokens, [0; 32])?;
        let mut work = Work::default();
        work.absorb(discovery_work);
        work.absorb(validation_work);
        work.absorb(frozen_work);
        Ok(Arc::new(Self {
            profile,
            weights,
            frozen: Arc::new(frozen),
            old,
            cuts,
            row_cache: Mutex::new(None),
            byte_cache: Mutex::new((usize::MAX, [0; 128])),
            work: Mutex::new(work),
        }))
    }

    pub(super) fn tokens(&self) -> [u32; 2] {
        self.frozen.tokens
    }

    pub(super) fn take_work(&self) -> Result<Work, String> {
        let mut work = self.work.lock().map_err(|_| "ordered work poisoned")?;
        Ok(core::mem::take(&mut *work))
    }

    pub(super) fn value(&self, id: usize, row: usize, col: usize) -> Result<i64, String> {
        let sources = &self.profile.bytes().scalar.layout.sources;
        let shape = sources.get(id).ok_or("ordered source id outside layout")?;
        if row >= shape.rows || col >= shape.cols {
            return Ok(0);
        }
        let mut cache = self.row_cache.lock().map_err(|_| "ordered row cache poisoned")?;
        if cache
            .as_ref()
            .is_none_or(|(cached_id, cached_row, _)| *cached_id != id || *cached_row != row)
        {
            let targets = [id].into_iter().collect();
            let mut selected = None;
            let replay_work = replay(
                &self.profile,
                &self.weights,
                &self.old,
                self.frozen.tokens,
                &self.cuts.values,
                &targets,
                TOKENS,
                |source, emitted_row, words| {
                    if source == id && emitted_row == row {
                        selected = Some(words.to_vec());
                    }
                    Ok(())
                },
            )?;
            self.work.lock().map_err(|_| "ordered work poisoned")?.absorb(replay_work);
            let selected = selected.ok_or("ordered source row was not produced")?;
            if selected.len() != shape.cols {
                return Err("ordered source row width differs".into());
            }
            *cache = Some((id, row, selected));
        }
        Ok(cache.as_ref().unwrap().2[col])
    }

    pub(super) fn byte_at(&self, index: usize) -> Result<u8, String> {
        let domain = match DOMAIN_A {
            Domain::Flat(bits) => 1usize << bits,
            _ => unreachable!(),
        };
        if index >= domain {
            return Err("ordered byte index outside padded source domain".into());
        }
        // DOMAIN_A can exceed the layout's minimum Boolean domain. These
        // public padding cells are fixed zeros in Model::polynomial too.
        if index >= self.profile.bytes().live {
            return Ok(0);
        }
        let first = index / 128 * 128;
        let mut cache = self.byte_cache.lock().map_err(|_| "ordered byte cache poisoned")?;
        if cache.0 != first {
            let window_work = self.frozen.window(
                &self.cuts,
                &self.profile,
                &self.weights,
                &self.old,
                first,
                &mut cache.1,
            )?;
            self.work.lock().map_err(|_| "ordered work poisoned")?.absorb(window_work);
            cache.0 = first;
        }
        Ok(cache.1[index - first])
    }
}

impl Frozen {
    fn prepare(
        p: &Profile,
        w: &prepare::Installed,
        old: &[Arc<Frozen>],
        tokens: [u32; 2],
        source_root: [u8; 32],
    ) -> Result<(Self, Cuts, Work), String> {
        let cuts = [p.residual[0].output, p.residual[3].output];
        let kv = kv_ids(p);
        let targets = cuts.into_iter().chain(kv).collect();
        let mut values = BTreeMap::new();
        let work =
            replay(p, w, old, tokens, &BTreeMap::new(), &targets, TOKENS, |id, _row, words| {
                let words = words
                    .iter()
                    .map(|&x| i16::try_from(x).map_err(|_| "cut/KV outside i16"))
                    .collect::<Result<Vec<_>, _>>()?;
                values.entry(id).or_insert_with(Vec::new).extend(words);
                Ok(())
            })?;
        let model_root = w.model.root.roots()[0];
        let checkpoint = Cuts {
            owner: (source_root, model_root, p.digest, p.old, tokens),
            values: cuts.into_iter().map(|id| (id, values.remove(&id).unwrap())).collect(),
        };
        Ok((
            Self {
                tokens,
                model_root,
                profile: p.digest,
                old: p.old,
                source_root,
                kv: kv.into_iter().map(|id| (id, values.remove(&id).unwrap())).collect(),
            },
            checkpoint,
            work,
        ))
    }

    fn window(
        &self,
        cuts: &Cuts,
        p: &Profile,
        w: &prepare::Installed,
        old: &[Arc<Frozen>],
        first: usize,
        output: &mut [u8],
    ) -> Result<Work, String> {
        if cuts.owner != (self.source_root, self.model_root, self.profile, self.old, self.tokens)
            || p.old != self.old
            || p.digest != self.profile
            || w.model.root.roots()[0] != self.model_root
            || first
                .checked_add(output.len())
                .is_none_or(|end| end > p.bytes().live.next_power_of_two())
        {
            return Err("ordered window context or bound differs".into());
        }
        let targets = p.bytes().window_sources(first, output.len())?.into_iter().collect();
        output.fill(0);
        let mut writes = 0;
        let mut work =
            replay(p, w, old, self.tokens, &cuts.values, &targets, TOKENS, |id, row, words| {
                p.bytes().emit_row_bytes(id, row, words, |index, value| {
                    if index >= first && index - first < output.len() {
                        output[index - first] = value;
                        writes += 1;
                    }
                })
            })?;
        work.emitted_bytes = writes;
        work.named_heap_peak += output.len();
        Ok(work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_b12_o0_reader_discovers_token_and_matches_numeric_source() {
        let p = Arc::new(Profile::small(0).unwrap());
        let packed = p
            .plan
            .sources
            .iter()
            .flat_map(|s| {
                (0..s.rows)
                    .flat_map(move |r| (0..s.cols).map(move |c| i16::from(s.rows == 1 || r == c)))
            })
            .collect();
        let w = Arc::new(prepare::Installed::new(&p, packed).unwrap());
        let dense = prepare::Snapshot::prepare(&p, &w, &[], 1).unwrap();
        let reader = Reader::prepare(p.clone(), w, &[], 1).unwrap();
        assert_eq!(reader.tokens(), dense.tokens);
        for id in [p.output.output, p.gate[2], p.softmax.layers[0].pi] {
            let shape = &p.bytes().scalar.layout.sources[id];
            for row in 0..shape.rows {
                for col in 0..shape.cols {
                    assert_eq!(reader.value(id, row, col).unwrap(), dense.value(&p, id, row, col));
                }
            }
        }
        for index in 0..(1usize << DOMAIN_A.config().unwrap().num_variables) {
            let expected = dense.source.weights.get(index).copied().unwrap_or(0) as u8;
            assert_eq!(reader.byte_at(index).unwrap(), expected, "byte={index}");
        }
        assert!(reader.byte_at(1usize << DOMAIN_A.config().unwrap().num_variables).is_err());
    }

    #[test]
    fn c71_b12_ordered_reader_history_matches_snapshot_and_rejects_wrong_owners() {
        let initial = Profile::small(0).unwrap();
        let packed: Vec<_> = initial
            .plan
            .sources
            .iter()
            .flat_map(|source| {
                (0..source.rows).flat_map(move |row| {
                    (0..source.cols).map(move |column| i16::from(source.rows == 1 || row == column))
                })
            })
            .collect();
        let weights = Arc::new(prepare::Installed::new(&initial, packed.clone()).unwrap());
        let other_model = Arc::new(prepare::Installed::new(&initial, packed).unwrap());
        let mut dense = Vec::new();
        let mut readers: Vec<Arc<Reader>> = Vec::new();
        for slot in 0..3 {
            let profile = Arc::new(Profile::small(slot).unwrap());
            let prompt = (slot % 2) as u32;
            let expected = prepare::Snapshot::prepare(&profile, &weights, &dense, prompt).unwrap();
            let reader =
                Reader::prepare(profile.clone(), weights.clone(), &readers, prompt).unwrap();
            assert_eq!(reader.tokens(), expected.tokens);
            for index in 0..1usize << DOMAIN_A.config().unwrap().num_variables {
                assert_eq!(
                    reader.byte_at(index).unwrap(),
                    expected.source.weights.get(index).copied().unwrap_or(0) as u8,
                    "slot={slot} byte={index}"
                );
            }
            for id in kv_ids(&profile) {
                for row in 0..TOKENS {
                    for column in 0..profile.bytes().scalar.layout.sources[id].cols {
                        assert_eq!(
                            reader.value(id, row, column).unwrap(),
                            expected.value(&profile, id, row, column)
                        );
                    }
                }
            }
            assert_eq!(reader.old.len(), slot);
            for (previous, owner) in reader.old.iter().zip(&readers) {
                assert!(Arc::ptr_eq(previous, &owner.frozen));
            }
            if slot != 0 {
                assert!(Reader::prepare(
                    profile.clone(),
                    weights.clone(),
                    &readers[..slot - 1],
                    prompt
                )
                .is_err());
                assert!(Reader::prepare(profile.clone(), other_model.clone(), &readers, prompt)
                    .is_err());
            }
            if slot == 2 {
                let reordered = [readers[1].clone(), readers[0].clone()];
                assert!(Reader::prepare(profile, weights.clone(), &reordered, prompt).is_err());
            }
            dense.push(expected);
            readers.push(reader);
        }
        for (slot, reader) in readers.iter().enumerate() {
            assert_eq!(Arc::strong_count(&reader.frozen), 3 - slot);
            assert_eq!(reader.frozen.kv.values().map(Vec::len).sum::<usize>(), 8);
        }
        println!("C71_ORDERED_HISTORY contexts=0,2,4 original_bytes=true compact_KV_shared=true complete_accepted_run=false");
    }

    #[test]
    fn c71_b12_native_ordered_bytes_equal_original_snapshot_across_history() {
        let p = Profile::small(0).unwrap();
        let weights = p
            .plan
            .sources
            .iter()
            .flat_map(|s| {
                (0..s.rows)
                    .flat_map(move |r| (0..s.cols).map(move |c| i16::from(s.rows == 1 || r == c)))
            })
            .collect();
        let w = prepare::Installed::new(&p, weights).unwrap();
        let (mut dense, mut frozen) = (Vec::new(), Vec::new());
        for slot in 0..3 {
            let p = Profile::small(slot).unwrap();
            let original = prepare::Snapshot::prepare(&p, &w, &dense, (slot % 2) as u32).unwrap();
            let (compact, mut cuts, _) =
                Frozen::prepare(&p, &w, &frozen, original.tokens, original.source.root.roots()[0])
                    .unwrap();
            let domain = p.bytes().live.next_power_of_two();
            for width in [1, 17, 128, 1024] {
                let mut calls = 0;
                let mut bytes = 0;
                let (mut w_reads, mut a_reads, mut kv_reads, mut peak) = (0, 0, 0, 0);
                for first in (0..domain).step_by(width) {
                    let mut output = vec![0; width.min(domain - first)];
                    let work = compact.window(&cuts, &p, &w, &frozen, first, &mut output).unwrap();
                    for (i, &value) in output.iter().enumerate() {
                        assert_eq!(
                            i16::from(value),
                            original.source.weights.get(first + i).copied().unwrap_or(0),
                            "slot={slot} byte={}",
                            first + i
                        );
                    }
                    bytes += work.emitted_bytes;
                    w_reads += work.weight_scalar_reads;
                    a_reads += work.original_scalar_reads;
                    kv_reads += work.old_kv_reads;
                    peak = peak.max(work.named_heap_peak);
                    calls += work.producer_rows.iter().sum::<usize>();
                }
                assert_eq!(bytes, p.bytes().live);
                eprintln!("ordered slot={slot} width={width} bytes={bytes} producer_rows={calls} W_reads={w_reads} A_reads={a_reads} KV_reads={kv_reads} named_peak={peak}");
            }
            assert!(compact.window(&cuts, &p, &w, &frozen, domain, &mut [0]).is_err());
            assert!(compact.window(&cuts, &p, &w, &frozen, usize::MAX, &mut [0; 2]).is_err());
            assert!(compact
                .window(
                    &cuts,
                    &Profile::small((slot + 1) % 3).unwrap(),
                    &w,
                    &frozen,
                    0,
                    &mut [0; 2]
                )
                .is_err());
            cuts.owner.0[0] ^= 1;
            assert!(compact.window(&cuts, &p, &w, &frozen, 0, &mut [0; 2]).is_err());
            cuts.owner.0[0] ^= 1;
            // Accepted KV stays compact; no old cut set is retained.
            assert_eq!(compact.kv.values().map(Vec::len).sum::<usize>(), 8);
            assert_eq!(cuts.values.values().map(Vec::len).sum::<usize>(), 8);
            dense.push(original);
            frozen.push(Arc::new(compact));
        }
    }
    // Each invocation is independently bounded by the local 60s/2GiB runner.
    fn compare_pcs(target: usize) {
        use std::sync::{Arc, Mutex};
        let p = Profile::small(0).unwrap();
        let weights = p
            .plan
            .sources
            .iter()
            .flat_map(|s| {
                (0..s.rows)
                    .flat_map(move |r| (0..s.cols).map(move |c| i16::from(s.rows == 1 || r == c)))
            })
            .collect();
        let w = prepare::Installed::new(&p, weights).unwrap();
        let (mut originals, mut accepted) = (Vec::new(), Vec::new());
        for slot in 0..=target {
            let p = Profile::small(slot).unwrap();
            let original =
                prepare::Snapshot::prepare(&p, &w, &originals, (slot % 2) as u32).unwrap();
            let (current, cuts, _) = Frozen::prepare(
                &p,
                &w,
                &accepted,
                original.tokens,
                original.source.root.roots()[0],
            )
            .unwrap();
            if slot == target {
                // Only the independent native reference receives dense original A.
                let expected = (0..1 << 12)
                    .map(|i| {
                        Goldilocks::new(original.source.weights.get(i).copied().unwrap_or(0) as u64)
                    })
                    .collect();
                let stats = Arc::new(Mutex::new((
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                    prepare::RowWork::default(),
                )));
                let count = stats.clone();
                // A single 128-byte original window. Never retains Snapshot or full A.
                let cache = Mutex::new((usize::MAX, [0u8; 128]));
                let source = Arc::new(move |i: usize| {
                    if i >= p.bytes().live {
                        return E::ZERO;
                    }
                    let first = i / 128 * 128;
                    let mut cache = cache.lock().unwrap();
                    if cache.0 != first {
                        let work =
                            current.window(&cuts, &p, &w, &accepted, first, &mut cache.1).unwrap();
                        cache.0 = first;
                        let mut count = count.lock().unwrap();
                        count.0 += 1;
                        count.1 += work.producer_rows.iter().sum::<usize>();
                        count.2 += work.weight_scalar_reads;
                        count.3 += work.original_scalar_reads;
                        count.4 += work.old_kv_reads;
                        count.5.add_assign(work.numerical);
                    }
                    E::from(Goldilocks::new(u64::from(cache.1[i - first])))
                });
                crate::c71_matrix::b12::replay::compare_source(
                    12,
                    source,
                    expected,
                    Some(&original.source),
                );
                eprintln!(
                    "ordered_sourcewise O={} windows_producerrows_W_A_KV_numerical={:?}",
                    target * TOKENS,
                    *stats.lock().unwrap()
                );
                return;
            }
            originals.push(original);
            accepted.push(Arc::new(current));
        }
    }
    #[test]
    fn c71_b12_ordered_sourcewise_o0() {
        compare_pcs(0)
    }
    #[test]
    fn c71_b12_ordered_sourcewise_o2() {
        compare_pcs(1)
    }
    #[test]
    fn c71_b12_ordered_sourcewise_o4() {
        compare_pcs(2)
    }
}

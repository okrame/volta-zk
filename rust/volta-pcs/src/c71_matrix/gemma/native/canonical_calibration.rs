//! Offline integer-trial storage. No proof, accepted-state import or GPU credit.
//! W and historical KV getters must be supplied from the pinned private trial.
//! Observed integer ranges do not select or certify a calibrated Gamma.
use super::*;
use std::cell::{Cell, RefCell};
use std::io::{Read, Seek, SeekFrom};

/// Row cache for an already validated immutable packed input. Length and
/// symmetric codec checks do NOT verify the checkpoint or packed-file hash.
/// The same std IO path accepts a tiny Cursor in local tests and a File later.
pub(super) struct PackedRows<'a, R> {
    sources: &'a [Source],
    input: R,
    row: Option<(usize, usize)>,
    buffer: Vec<u8>,
    pub row_loads: usize,
    pub completed_row_bytes: usize,
}

impl<'a, R: Read + Seek> PackedRows<'a, R> {
    pub(super) fn new(sources: &'a [Source], mut input: R) -> Result<Self, String> {
        let mut end: usize = 0;
        // Source IDs use metadata-key order; the file uses terminal order.
        let mut packed: Vec<_> = sources.iter().collect();
        packed.sort_by_key(|s| s.packed_offset);
        for s in packed {
            if s.rows == 0 || s.cols == 0 || s.packed_offset != end {
                return Err("packed W source layout differs".into());
            }
            end = end
                .checked_add(s.rows.checked_mul(s.cols).ok_or("packed W size overflow")?)
                .ok_or("packed W size overflow")?;
        }
        if sources.is_empty()
            || input.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?
                != (end as u64).checked_mul(2).ok_or("packed W size overflow")?
        {
            return Err("packed W byte length differs".into());
        }
        let bytes = sources
            .iter()
            .map(|s| s.cols)
            .max()
            .unwrap()
            .checked_mul(2)
            .ok_or("packed W row overflow")?;
        Ok(Self {
            sources,
            input,
            row: None,
            buffer: vec![0; bytes],
            row_loads: 0,
            completed_row_bytes: 0,
        })
    }

    pub(super) fn get(&mut self, id: usize, row: usize, col: usize) -> Result<i64, String> {
        let s = self.sources.get(id).ok_or("packed W tensor missing")?;
        if row >= s.rows || col >= s.cols {
            return Err("packed W address outside source".into());
        }
        if self.row != Some((id, row)) {
            self.row = None; // Never reuse bytes from a partial/failed row load.
            let offset = 2 * (s.packed_offset + row * s.cols) as u64;
            self.input.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
            let body = &mut self.buffer[..s.cols * 2];
            self.input.read_exact(body).map_err(|e| e.to_string())?;
            self.row_loads += 1;
            self.completed_row_bytes += body.len();
            if body.chunks_exact(2).any(|b| i16::from_le_bytes([b[0], b[1]]) == i16::MIN) {
                return Err("packed W outside symmetric i16".into());
            }
            self.row = Some((id, row));
        }
        Ok(i64::from(i16::from_le_bytes([self.buffer[2 * col], self.buffer[2 * col + 1]])))
    }
}

#[derive(Clone, Copy, Default, Debug, serde::Serialize)]
pub(super) struct Extent {
    pub words: usize,
    pub minimum: i64,
    pub maximum: i64,
}

struct History {
    recipes: [u8; 32],
    old: usize,
    rows: Vec<Vec<Box<[i16]>>>,
    payload: usize,
}

impl History {
    fn new(profile: &Canonical) -> Result<Self, String> {
        if profile.sources.attention.rope.old != 0 {
            return Err("calibration history must start empty".into());
        }
        Ok(Self {
            recipes: profile.recipes.digest,
            old: 0,
            rows: vec![Vec::new(); profile.bytes().widths.len()],
            payload: 0,
        })
    }

    fn check(&self, profile: &Canonical) -> Result<(), String> {
        if self.old >= 450
            || profile.sources.attention.rope.old != self.old
            || profile.recipes.digest != self.recipes
            || profile.bytes().widths.len() != self.rows.len()
        {
            return Err("calibration predecessor or common scale map differs".into());
        }
        Ok(())
    }

    fn read(&self, id: usize, token: usize, column: usize) -> Result<i64, String> {
        if token >= self.old {
            return Err("calibration historical KV outside completed prefix".into());
        }
        self.rows
            .get(id)
            .and_then(|rows| rows.get(token))
            .and_then(|row| row.get(column))
            .map(|&value| i64::from(value))
            .ok_or("calibration historical KV source/address missing".into())
    }

    fn append(&mut self, trial: &mut Trial<'_>) -> Result<(), String> {
        self.check(trial.profile)?;
        if !trial.finished || trial.failed || trial.next_token != 150 {
            return Err("calibration cannot retain an incomplete trial".into());
        }
        for (id, rows) in trial.kv.iter().enumerate() {
            if trial.kv_sources.contains(&id) {
                let columns = trial.profile.bytes().scalar.layout.sources[id].cols;
                if rows.len() != 150
                    || self.rows[id].len() != self.old
                    || rows.iter().any(|row| row.len() != columns)
                {
                    return Err("calibration completed KV shape differs".into());
                }
            } else if !rows.is_empty() || !self.rows[id].is_empty() {
                return Err("calibration non-KV source retained as history".into());
            }
        }
        for &id in &trial.kv_sources {
            let bytes = trial.kv[id].iter().map(|row| row.len() * 2).sum::<usize>();
            self.rows[id].append(&mut trial.kv[id]);
            self.payload += bytes;
            trial.live_payload -= bytes;
        }
        self.old += 150;
        Ok(())
    }
}

#[derive(serde::Serialize)]
pub(super) struct Response {
    pub old_tokens: usize,
    pub tokens: Vec<u32>,
    pub extents: Vec<Extent>,
    pub work: Work,
    pub packed_row_loads: usize,
    pub packed_row_bytes: usize,
    pub named_peak_with_previous_kv_and_weight_row_bytes: usize,
}

pub(super) fn fixed_run<R: Read + Seek>(
    public: &super::state::Public<'_>,
    reader: &mut PackedRows<'_, R>,
    payload_limit: usize,
) -> Result<Vec<Response>, String> {
    if public.profiles.len() != 3
        || reader.sources.len() != public.profiles[0].plan.sources.len()
        || reader.sources.iter().zip(&public.profiles[0].plan.sources).any(|(input, expected)| {
            input.name != expected.name
                || input.rows != expected.rows
                || input.cols != expected.cols
                || input.packed_offset != expected.packed_offset
        })
    {
        return Err("calibration fixed-run model layout differs".into());
    }
    let workload: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/c7-d126-gemma31b-workload-v1.json"
    )))
    .map_err(|error| error.to_string())?;
    let prompt: Vec<u32> = serde_json::from_value(workload["prompt"]["token_ids"].clone())
        .map_err(|error| error.to_string())?;
    if prompt.len() != 100 || prompt.iter().any(|&token| token >= 262144) {
        return Err("calibration pinned prompt differs".into());
    }
    let mut history = History::new(&public.profiles[0])?;
    let mut responses = Vec::with_capacity(3);
    for (slot, profile) in public.profiles.iter().enumerate() {
        history.check(profile)?;
        let external = history.payload + reader.buffer.capacity();
        let budget =
            payload_limit.checked_sub(external).ok_or("calibration run budget exceeded")?;
        let mut trial = Trial::new(profile, budget);
        let mut tokens = [0; 150];
        tokens[..100].copy_from_slice(&prompt);
        let before = (reader.row_loads, reader.completed_row_bytes);
        let weights = RefCell::new(&mut *reader);
        for token in 0..150 {
            trial
                .token(
                    &mut tokens,
                    &public.tables[slot],
                    &|id, row, column| weights.borrow_mut().get(id, row, column),
                    &|id, row, column| history.read(id, row, column),
                )
                .map_err(|error| format!("calibration O={} token={token}: {error}", slot * 150))?;
        }
        trial.finish()?;
        history.append(&mut trial)?;
        let peak = trial.work.payload_plus_incoming_bundle_peak_bytes + external;
        responses.push(Response {
            old_tokens: slot * 150,
            tokens: tokens.to_vec(),
            extents: std::mem::take(&mut trial.extents),
            work: std::mem::take(&mut trial.work),
            packed_row_loads: reader.row_loads - before.0,
            packed_row_bytes: reader.completed_row_bytes - before.1,
            named_peak_with_previous_kv_and_weight_row_bytes: peak,
        });
    }
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_native_canonical_calibration_three_context_kv_handoff() {
        let plan = super::super::super::super::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for layer in &softmax.layers {
            scales.insert(layer.pi, -14);
        }
        let profiles: Vec<_> =
            (0..3).map(|slot| Canonical::compile(slot, &[0; 772], &scales).unwrap()).collect();
        assert!(History::new(&profiles[1]).is_err());
        let mut history = History::new(&profiles[0]).unwrap();
        assert!(history.check(&profiles[1]).is_err());
        assert!(history.read(0, 0, 0).is_err());
        for (slot, profile) in profiles.iter().enumerate() {
            let mut trial = Trial::new(profile, 512 << 20);
            assert!(history.append(&mut trial).is_err());
            for &id in &trial.kv_sources {
                let columns = profile.bytes().scalar.layout.sources[id].cols;
                trial.kv[id] = (0..150)
                    .map(|token| vec![(id + slot * 150 + token) as i16; columns].into_boxed_slice())
                    .collect();
                trial.live_payload += 150 * columns * 2;
            }
            assert_eq!(trial.live_payload, 135_168_000);
            trial.finished = true;
            trial.next_token = 150;
            let id = *trial.kv_sources.first().unwrap();
            let pointer = trial.kv[id][149].as_ptr();
            trial.failed = true;
            assert!(history.append(&mut trial).is_err());
            trial.failed = false;
            let tail = trial.kv[id].pop().unwrap();
            assert!(history.append(&mut trial).is_err());
            assert_eq!(history.old, slot * 150);
            assert_eq!(trial.kv[id].len(), 149);
            trial.kv[id].push(tail);
            history.recipes[0] ^= 1;
            assert!(history.append(&mut trial).is_err());
            history.recipes[0] ^= 1;
            history.append(&mut trial).unwrap();
            assert_eq!(history.rows[id][slot * 150 + 149].as_ptr(), pointer);
            assert_eq!(trial.live_payload, 0);
            assert!(trial.kv.iter().all(Vec::is_empty));
            assert_eq!(history.old, (slot + 1) * 150);
            assert_eq!(history.payload, (slot + 1) * 135_168_000);
            for token in 0..history.old {
                assert_eq!(history.read(id, token, 0).unwrap(), (id + token) as i64);
            }
            assert!(history.read(id, history.old, 0).is_err());
            assert!(history.read(id, 0, history.rows[id][0].len()).is_err());
            assert!(history.read(0, 0, 0).is_err());
            assert!(history.append(&mut trial).is_err());
        }
        assert!(history.check(&profiles[2]).is_err());
        eprintln!("C71_CALIBRATION_HISTORY offsets=0/150/300 tokens=450 kv_bytes={} handoff_only=true calibrated=false", history.payload);
    }

    #[test]
    fn c71_b12_native_canonical_calibration_storage_release_and_ranges() {
        // Codec, row cache and failure invalidation use the same IO as File.
        let tiny = [Source { name: "test".into(), rows: 2, cols: 2, packed_offset: 0 }];
        let bytes: Vec<u8> =
            [-32767i16, 32767, 0, -1].into_iter().flat_map(i16::to_le_bytes).collect();
        let mut reader = PackedRows::new(&tiny, std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(reader.get(0, 0, 0).unwrap(), -32767);
        assert_eq!(reader.get(0, 0, 1).unwrap(), 32767);
        assert_eq!(reader.row_loads, 1);
        assert!(reader.get(1, 0, 0).is_err());
        assert!(reader.get(0, 2, 0).is_err());
        reader.input.get_mut().truncate(6);
        assert!(reader.get(0, 1, 0).is_err());
        assert!(reader.row.is_none());
        assert_eq!(reader.get(0, 0, 0).unwrap(), -32767);
        assert!(PackedRows::new(&tiny, std::io::Cursor::new(vec![0; 7])).is_err());
        let mut invalid =
            PackedRows::new(&tiny, std::io::Cursor::new([0u8, 128, 0, 0, 0, 0, 0, 0])).unwrap();
        assert!(invalid.get(0, 0, 1).is_err()); // Reject the whole row, not only requested word.
        assert!(invalid.row.is_none());
        let reordered = [
            Source { name: "a".into(), rows: 1, cols: 2, packed_offset: 2 },
            Source { name: "b".into(), rows: 1, cols: 2, packed_offset: 0 },
        ];
        let mut ordered =
            PackedRows::new(&reordered, std::io::Cursor::new([1u8, 0, 2, 0, 3, 0, 4, 0])).unwrap();
        assert_eq!(ordered.get(0, 0, 0).unwrap(), 3);
        assert_eq!(ordered.get(1, 0, 0).unwrap(), 1);
        let mut overlapping = reordered.clone();
        overlapping[0].packed_offset = 0;
        assert!(PackedRows::new(&overlapping, std::io::Cursor::new([0; 8])).is_err());
        let plan = super::super::super::super::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for l in &softmax.layers {
            scales.insert(l.pi, -14);
        }
        let empty = lookup::Table { profile: 0, lower: 0, outputs: lookup::Outputs::I16(&[]) };
        let identity: Vec<i16> = (-32767..=32767).map(|v| v as i16).collect();
        let gelu =
            [lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&identity) }];
        let tables = profile::Tables { gelu: &gelu, exp30: &[], softcap: &empty, rope: &[] };
        let absent = |_, _, _| -> Result<i64, String> { panic!("unexpected source access") };
        for old in [0, 150, 300] {
            // Real canonical row geometry, bounded producer subgraphs only.
            let mut p = Canonical::compile(old / 150, &[0; 772], &scales).unwrap();
            let affine = p
                .recipes
                .affine
                .iter()
                .position(|r| r.inputs[0].0 == 0 && r.inputs[1].1 == 0)
                .unwrap();
            let raw = p.recipes.affine[affine].raw;
            let pair = *p.recipes.residual.iter().find(|r| r.raw == raw).unwrap();
            p.steps = vec![Producer::Embedding, Producer::Affine(affine), Producer::Rne(pair)];
            let mut trial = Trial::new(&p, 16 << 20);
            let mut tokens = [0; 150];
            tokens[1] = 1;
            let tensor = p.plan.cohorts[0].tensor;
            let mut prefix = p.plan.sources[tensor].clone();
            prefix.rows = 2;
            prefix.packed_offset = 0;
            let bytes: Vec<u8> = (0..2)
                .flat_map(|r| {
                    (0..prefix.cols).flat_map(move |c| (((r + c) % 3) as i16 - 1).to_le_bytes())
                })
                .collect();
            let descriptors = [prefix]; // Explicit two-row prefix, not a model file.
            let reader =
                RefCell::new(PackedRows::new(&descriptors, std::io::Cursor::new(bytes)).unwrap());
            let calls = Cell::new(0);
            let weights = |id, r, c| {
                assert_eq!(id, tensor);
                calls.set(calls.get() + 1);
                reader.borrow_mut().get(0, r, c)
            };
            for _ in 0..2 {
                trial.token(&mut tokens, &tables, &weights, &absent).unwrap();
            }
            let columns = p.bytes().scalar.layout.sources[0].cols;
            assert_eq!(trial.extents[0].words, 2 * columns);
            assert_eq!((trial.extents[0].minimum, trial.extents[0].maximum), (-1, 1));
            assert_eq!(calls.get(), 2 * columns);
            assert_eq!(reader.borrow().row_loads, 2);
            assert_eq!(reader.borrow().completed_row_bytes, 4 * columns);
            assert!(trial.current.iter().all(BTreeMap::is_empty));
            assert_eq!(trial.live_payload, 0);
            assert!(trial.read(0, 0, 0).is_err());
            assert_eq!(trial.work.producer_rows, 6);
            assert_eq!(trial.work.weight_reads, 2 * columns);
            assert_eq!(trial.work.historical_kv_reads, 0);
            assert!(trial.finish().is_err()); // Never label a partial graph calibrated.
            let mut limited = Trial::new(&p, 1);
            assert!(limited.token(&mut tokens, &tables, &weights, &absent).is_err());
            let before = calls.get();
            assert!(limited.token(&mut tokens, &tables, &weights, &absent).is_err());
            assert_eq!(calls.get(), before); // fail closed, no retry after partial work

            let mut p = Canonical::compile(old / 150, &[0; 772], &scales).unwrap();
            let g = &p.sources.attention.rope.gate_up.gelu.gelu[0];
            let (x, y, h, cols) = (g.input, g.output, g.histogram, g.columns);
            let up = p.sources.attention.rope.gate_up.products[0].up;
            let raw = p.sources.attention.rope.gate_up.products[0].raw;
            p.steps = vec![Producer::Gelu(0), Producer::Gate(0)];
            let mut look = Trial::new(&p, 16 << 20);
            look.emit(prepare::Row {
                values: vec![
                    (x, 0, (0..cols).map(|j| (j % 3) as i64 - 1).collect()),
                    (up, 0, vec![2; cols]),
                ],
                ..Default::default()
            })
            .unwrap();
            look.token(&mut tokens, &tables, &absent, &absent).unwrap();
            assert_eq!(look.histograms[&h].iter().map(|&n| n as usize).sum::<usize>(), cols);
            assert_eq!((look.extents[y].minimum, look.extents[y].maximum), (-1, 1));
            assert_eq!((look.extents[raw].minimum, look.extents[raw].maximum), (-2, 2));
            assert!(look.current.iter().all(BTreeMap::is_empty));
            assert_eq!(look.live_payload, 65535 * 4); // Only the original histogram survives.

            let mut p = Canonical::compile(old / 150, &[0; 772], &scales).unwrap();
            let l = &p.sources.attention.layers[0];
            let (pi, v, raw, lanes, groups) = (l.pi, l.v, l.raw_output, l.lanes, l.groups);
            p.steps = vec![Producer::Pv(0)];
            let mut pv = Trial::new(&p, 16 << 20);
            let live = old + 1;
            let mut values = vec![(v, 0, vec![3; groups * lanes])];
            for head in 0..32 {
                values.push((
                    pi,
                    head * 256,
                    (0..old + 150).map(|t| i64::from(t < live)).collect(),
                ));
            }
            pv.emit(prepare::Row { values, ..Default::default() }).unwrap();
            pv.token(&mut tokens, &tables, &absent, &|id, t, c| {
                assert_eq!(id, v);
                assert!(t < old);
                assert!(c < groups * lanes);
                Ok(2)
            })
            .unwrap();
            assert_eq!(
                (pv.extents[raw].minimum, pv.extents[raw].maximum),
                ((2 * old + 3) as i64, (2 * old + 3) as i64)
            );
            assert_eq!(pv.work.historical_kv_reads, 32 * old * lanes);
            assert_eq!(pv.work.current_kv_reads, 32 * lanes);
            assert_eq!(pv.live_payload, groups * lanes * 2);
            assert_eq!(pv.read(v, 0, 0).unwrap(), 3);
            assert!(pv.read(v, 1, 0).is_err());
            assert!(pv.current.iter().all(BTreeMap::is_empty));
            let current_kv_bytes = p
                .sources
                .attention
                .layers
                .iter()
                .flat_map(|l| [l.k, l.v])
                .collect::<BTreeSet<_>>()
                .iter()
                .map(|&id| p.bytes().scalar.layout.sources[id].cols * 150 * 2)
                .sum::<usize>();
            let histogram_bytes = (2 * 60 + 1) * 65535 * 4;
            assert_eq!(current_kv_bytes, 135_168_000);
            eprintln!(
                "C71_CALIBRATION_STORAGE {}",
                serde_json::json!({"old_tokens":old,"embedding":trial.work,"lookup":look.work,"pv":pv.work,
                "full_current_KV_payload_bytes":current_kv_bytes,"full_histogram_payload_bytes":histogram_bytes,
                "external_prior_KV_payload_bytes":old*901120,"full_model":false,"calibrated":false,"complete_physical_peak":false})
            );
        }
    }
}

impl Extent {
    fn add(&mut self, value: i64, count: usize) {
        if count == 0 {
            return;
        }
        if self.words == 0 {
            self.minimum = value;
            self.maximum = value;
        }
        self.minimum = self.minimum.min(value);
        self.maximum = self.maximum.max(value);
        self.words += count;
    }
}

#[derive(Default, Debug, serde::Serialize)]
pub(super) struct Work {
    pub producer_rows: usize,
    pub weight_reads: usize,
    pub current_reads: usize,
    pub historical_kv_reads: usize,
    pub current_kv_reads: usize,
    pub emitted_words: usize,
    pub histogram_visits: usize,
    pub public_padding_words: usize,
    pub public_padding_histogram_visits: usize,
    pub named_payload_peak_bytes: usize,
    pub payload_plus_incoming_bundle_peak_bytes: usize,
}

pub(super) struct Trial<'a> {
    profile: &'a Canonical,
    release: Vec<Vec<usize>>,
    consumed: Vec<bool>,
    kv_sources: BTreeSet<usize>,
    current: Vec<BTreeMap<usize, Vec<i64>>>,
    // One exact-sized i16 row per token; no doubling of a large KV allocation.
    kv: Vec<Vec<Box<[i16]>>>,
    histograms: BTreeMap<usize, Vec<u32>>,
    pub(super) extents: Vec<Extent>,
    pub(super) work: Work,
    live_payload: usize,
    payload_limit: usize,
    next_token: usize,
    failed: bool,
    finished: bool,
}

impl<'a> Trial<'a> {
    pub(super) fn new(p: &'a Canonical, payload_limit: usize) -> Self {
        let count = p.bytes().widths.len();
        let mut last = vec![None; count];
        for (i, step) in p.steps.iter().enumerate() {
            for id in p.ports(step).0 {
                last[id] = Some(i);
            }
        }
        let consumed = last.iter().map(Option::is_some).collect();
        let mut release = vec![Vec::new(); p.steps.len()];
        for (id, last) in last.into_iter().enumerate() {
            if let Some(i) = last {
                release[i].push(id);
            }
        }
        let kv_sources = p.sources.attention.layers.iter().flat_map(|l| [l.k, l.v]).collect();
        Self {
            profile: p,
            release,
            consumed,
            kv_sources,
            current: vec![BTreeMap::new(); count],
            kv: vec![Vec::new(); count],
            histograms: BTreeMap::new(),
            extents: vec![Extent::default(); count],
            work: Work::default(),
            live_payload: 0,
            payload_limit,
            next_token: 0,
            failed: false,
            finished: false,
        }
    }

    fn read(&self, id: usize, row: usize, col: usize) -> Result<i64, String> {
        if let Some(v) = self.profile.padding_word(id, row, col)? {
            return Ok(v);
        }
        if self.kv_sources.contains(&id) {
            return self.kv[id]
                .get(row)
                .and_then(|r| r.get(col))
                .map(|&v| i64::from(v))
                .ok_or("current KV read before producer".into());
        }
        self.current[id]
            .get(&row)
            .and_then(|r| r.get(col))
            .copied()
            .ok_or("A row read before producer or after last consumer".into())
    }

    fn emit(&mut self, out: prepare::Row) -> Result<(), String> {
        let p = self.profile;
        let sources = &p.bytes().scalar.layout.sources;
        let bundle = out.values.iter().map(|(_, _, v)| v.capacity() * 8).sum::<usize>()
            + out
                .histogram
                .as_ref()
                .map_or(0, |(_, v)| v.capacity() * std::mem::size_of::<usize>());
        // Conservatively include all incoming storage through the handoff,
        // including head splits/i16 conversion and first histogram allocation.
        let added = out
            .values
            .iter()
            .map(|(id, _, v)| {
                if self.kv_sources.contains(id) {
                    v.len() * 2
                } else if self.consumed[*id] {
                    v.len() * 8
                } else {
                    0
                }
            })
            .sum::<usize>()
            + out.histogram.as_ref().map_or(0, |(id, _)| {
                if self.histograms.contains_key(id) {
                    0
                } else {
                    sources[*id].cols * 4
                }
            });
        let peak = self.live_payload + bundle + added;
        if peak > self.payload_limit {
            return Err("calibration named payload budget exceeded".into());
        }
        self.work.payload_plus_incoming_bundle_peak_bytes =
            self.work.payload_plus_incoming_bundle_peak_bytes.max(peak);
        for (id, first, values) in out.values {
            let source = &sources[id];
            if values.len() % source.cols != 0 || first + values.len() / source.cols > source.rows {
                return Err("calibration row bundle shape differs".into());
            }
            for &v in &values {
                self.extents[id].add(v, 1);
            }
            if self.extents[id].words > source.rows * source.cols {
                return Err("calibration source emitted twice".into());
            }
            self.work.emitted_words += values.len();
            if self.kv_sources.contains(&id) {
                if first != self.kv[id].len() {
                    return Err("calibration KV row is not consecutive".into());
                }
                for row in values.chunks_exact(source.cols) {
                    let packed = row
                        .iter()
                        .map(|&v| {
                            i16::try_from(v)
                                .ok()
                                .filter(|&v| v != i16::MIN)
                                .ok_or("calibration KV outside symmetric i16")
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_boxed_slice();
                    self.live_payload += packed.len() * 2;
                    self.kv[id].push(packed);
                }
            } else if self.consumed[id] {
                if values.len() == source.cols {
                    self.live_payload += values.capacity() * 8;
                    if self.current[id].insert(first, values).is_some() {
                        return Err("calibration live row overwritten".into());
                    }
                } else {
                    for (row, v) in values.chunks_exact(source.cols).enumerate() {
                        let v = v.to_vec();
                        self.live_payload += v.capacity() * 8;
                        if self.current[id].insert(first + row, v).is_some() {
                            return Err("calibration live head row overwritten".into());
                        }
                    }
                }
            }
        }
        if let Some((id, entries)) = out.histogram {
            if !self.histograms.contains_key(&id) {
                self.histograms.insert(id, vec![0; sources[id].cols]);
                self.live_payload += sources[id].cols * 4;
            }
            let h = self.histograms.get_mut(&id).unwrap();
            for entry in entries {
                let v = h.get_mut(entry).ok_or("calibration histogram entry outside source")?;
                *v = v.checked_add(1).ok_or("calibration histogram overflow")?;
                self.work.histogram_visits += 1;
            }
        }
        self.work.producer_rows += 1;
        self.work.named_payload_peak_bytes =
            self.work.named_payload_peak_bytes.max(self.live_payload);
        Ok(())
    }

    fn release_step(&mut self, step: usize) {
        for &id in &self.release[step] {
            self.live_payload -= self.current[id].values().map(|v| v.capacity() * 8).sum::<usize>();
            self.current[id].clear();
        }
    }

    pub(super) fn token(
        &mut self,
        tokens: &mut [u32; 150],
        tables: &profile::Tables<'_>,
        weights: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        previous: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
    ) -> Result<(), String> {
        if self.failed || self.finished || self.next_token >= 150 {
            return Err("calibration trial stopped".into());
        }
        self.failed = true; // Any error poisons partial storage; no retry/promotion.
        let p = self.profile;
        let token = self.next_token;
        let mut pending_tokens = *tokens;
        let (wr, ar, old, fresh) = (Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0));
        let state = RefCell::new(&mut *self);
        let result = p.prepare_token(
            token,
            &mut pending_tokens,
            tables,
            &|id, r, c| {
                wr.set(wr.get() + 1);
                weights(id, r, c)
            },
            &|id, r, c| {
                ar.set(ar.get() + 1);
                state.borrow().read(id, r, c)
            },
            &|id, t, c| {
                if t > p.sources.attention.rope.old + token {
                    return Err("calibration future KV read".into());
                }
                if t < p.sources.attention.rope.old {
                    old.set(old.get() + 1);
                    previous(id, t, c)
                } else {
                    fresh.set(fresh.get() + 1);
                    state.borrow().read(id, t - p.sources.attention.rope.old, c)
                }
            },
            |out| state.borrow_mut().emit(out),
            |step| {
                state.borrow_mut().release_step(step);
                Ok(())
            },
        );
        #[allow(clippy::drop_non_drop)]
        drop(state); // End the mutable self borrow captured by the callbacks.
        self.work.weight_reads += wr.get();
        self.work.current_reads += ar.get();
        self.work.historical_kv_reads += old.get();
        self.work.current_kv_reads += fresh.get();
        result?;
        if self.current.iter().any(|r| !r.is_empty()) {
            return Err("calibration live rows survived final consumer".into());
        }
        *tokens = pending_tokens;
        self.next_token += 1;
        self.failed = false;
        Ok(())
    }

    /// Finish all original sources, including virtual query padding and
    /// histogram zeros. This rejects partial/selected-stage test fixtures.
    pub(super) fn finish(&mut self) -> Result<(), String> {
        if self.failed || self.finished || self.next_token != 150 {
            return Err("calibration trial incomplete/stopped".into());
        }
        self.failed = true;
        let p = self.profile;
        for (id, s) in p.bytes().scalar.layout.sources.iter().enumerate() {
            if s.rows > 150 {
                if let Some(v) = p.padding_word(id, 150, 0)? {
                    let count = 32 * 106 * s.cols;
                    self.extents[id].add(v, count);
                    self.work.public_padding_words += count;
                }
            }
            if let Some((entry, count)) = p.padding_histogram(id) {
                let h =
                    self.histograms.get_mut(&id).ok_or("calibration missing EXP30 histogram")?;
                h[entry] = h[entry]
                    .checked_add(count as u32)
                    .ok_or("calibration padding histogram overflow")?;
                self.work.public_padding_histogram_visits += count;
            }
            if let Some(h) = self.histograms.get(&id) {
                for &v in h {
                    self.extents[id].add(i64::from(v), 1);
                }
            }
            if self.extents[id].words != s.rows * s.cols {
                return Err(format!("calibration source {id} coverage differs"));
            }
        }
        self.finished = true;
        self.failed = false;
        Ok(())
    }
}

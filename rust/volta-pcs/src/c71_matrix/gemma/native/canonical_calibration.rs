//! Offline integer-trial storage. No proof, accepted-state import or GPU credit.
//! W and historical KV getters must be supplied from the pinned private trial.
//! Observed integer ranges do not select or certify a calibrated Gamma.
use super::*;
use std::cell::{Cell, RefCell};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TRACE_MAGIC: &[u8; 8] = b"C71TRC01";
const TRACE_FRAME_BYTES: usize = 48;
const TRACE_CHUNK_BYTES: usize = 64 * 1024;
const TRACE_METADATA: u8 = 1;
const TRACE_VALUES: u8 = 2;
const TRACE_HISTOGRAM: u8 = 3;
const TRACE_PADDING: u8 = 4;
const TRACE_TOKENS: u8 = 5;
const TRACE_FINAL_KV: u8 = 6;
const TRACE_FOOTER: u8 = 255;

#[derive(serde::Serialize)]
pub(super) struct TraceReport {
    pub format: &'static str,
    pub bytes: u64,
    pub records: u64,
    pub logical_words: u64,
    pub stored_words: u64,
    pub final_kv_sources: u64,
    pub blake3_before_footer: String,
    pub encoder_scratch_bytes: usize,
}

pub(super) struct Trace {
    sink: BufWriter<File>,
    path: PathBuf,
    hasher: blake3::Hasher,
    bytes: u64,
    records: u64,
    logical_words: u64,
    stored_words: u64,
    final_kv_sources: u64,
    context: Option<u8>,
    complete: bool,
}

impl Trace {
    pub(super) fn create(path: &Path) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path).map_err(|error| error.to_string())?;
        let mut trace = Self {
            sink: BufWriter::new(file),
            path: path.to_path_buf(),
            hasher: blake3::Hasher::new(),
            bytes: 0,
            records: 0,
            logical_words: 0,
            stored_words: 0,
            final_kv_sources: 0,
            context: None,
            complete: false,
        };
        trace.write(TRACE_MAGIC)?;
        Ok(trace)
    }

    fn write(&mut self, body: &[u8]) -> Result<(), String> {
        self.sink.write_all(body).map_err(|error| error.to_string())?;
        self.hasher.update(body);
        self.bytes = self
            .bytes
            .checked_add(body.len() as u64)
            .ok_or("calibration trace byte count overflow")?;
        Ok(())
    }

    fn header(
        &mut self,
        kind: u8,
        context: u8,
        codec: u8,
        source: u32,
        first: u64,
        rows: u64,
        columns: u64,
        repeat: u64,
        stored_words: u64,
        logical_words: u64,
    ) -> Result<(), String> {
        let mut header = [0u8; TRACE_FRAME_BYTES];
        header[0] = kind;
        header[1] = context;
        header[2] = codec;
        header[4..8].copy_from_slice(&source.to_le_bytes());
        for (offset, value) in
            [(8, first), (16, rows), (24, columns), (32, repeat), (40, stored_words)]
        {
            header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        self.write(&header)?;
        self.records = self.records.checked_add(1).ok_or("calibration trace record overflow")?;
        self.stored_words = self
            .stored_words
            .checked_add(stored_words)
            .ok_or("calibration trace stored-word overflow")?;
        self.logical_words = self
            .logical_words
            .checked_add(logical_words)
            .ok_or("calibration trace logical-word overflow")?;
        Ok(())
    }

    fn bytes_frame(
        &mut self,
        kind: u8,
        context: u8,
        source: u32,
        first: u64,
        rows: u64,
        columns: u64,
        repeat: u64,
        body: &[u8],
        logical_words: u64,
    ) -> Result<(), String> {
        self.header(
            kind,
            context,
            1,
            source,
            first,
            rows,
            columns,
            repeat,
            body.len() as u64,
            logical_words,
        )?;
        self.write(body)
    }

    fn signed_frame(
        &mut self,
        kind: u8,
        context: u8,
        codec: usize,
        source: usize,
        first: usize,
        rows: usize,
        columns: usize,
        repeat: usize,
        values: &[i64],
        logical_words: usize,
    ) -> Result<(), String> {
        let dense_words = rows.checked_mul(columns).ok_or("calibration trace shape overflow")?;
        if !(1..=8).contains(&codec)
            || (kind == TRACE_PADDING && values.len() != 1)
            || (kind != TRACE_PADDING && values.len() != dense_words)
        {
            return Err("calibration trace signed-frame shape differs".into());
        }
        self.header(
            kind,
            context,
            codec as u8,
            source.try_into().map_err(|_| "calibration trace source overflow")?,
            first as u64,
            rows as u64,
            columns as u64,
            repeat as u64,
            values.len() as u64,
            logical_words as u64,
        )?;
        let words = (TRACE_CHUNK_BYTES / codec).max(1);
        let mut encoded = Vec::with_capacity(words * codec);
        for chunk in values.chunks(words) {
            encoded.clear();
            for &value in chunk {
                if codec < 8 {
                    let bound = (1i64 << (8 * codec - 1)) - 1;
                    if value < -bound - 1 || value > bound {
                        return Err("calibration trace value outside codec".into());
                    }
                }
                encoded.extend_from_slice(&value.to_le_bytes()[..codec]);
            }
            self.write(&encoded)?;
        }
        Ok(())
    }

    fn begin_context(&mut self, slot: usize, profile: &Canonical) -> Result<(), String> {
        if self.context.is_some() || slot >= 3 {
            return Err("calibration trace context order differs".into());
        }
        let context = slot as u8;
        let sources = &profile.bytes().scalar.layout.sources;
        let metadata = serde_json::to_vec(&serde_json::json!({
            "schema": "volta-c71-calibration-trace-context-v1",
            "old_tokens": 150 * slot,
            "recipe_digest": blake3::Hash::from_bytes(profile.recipes.digest).to_hex().to_string(),
            "sources": sources.iter().enumerate().map(|(id, source)| serde_json::json!({
                "id": id, "name": source.name, "rows": source.rows,
                "columns": source.cols, "codec_bytes": profile.bytes().widths[id]
            })).collect::<Vec<_>>(),
            "kv_sources": profile.sources.attention.layers.iter()
                .flat_map(|layer| [layer.k, layer.v]).collect::<BTreeSet<_>>(),
            "padding_row_first": 150,
            "padding_rows_per_block": 106,
            "padding_repeat": 32,
            "padding_row_stride": 256,
            "tokens": 150
        }))
        .map_err(|error| error.to_string())?;
        self.bytes_frame(TRACE_METADATA, context, u32::MAX, 0, 0, 0, 0, &metadata, 0)?;
        self.context = Some(context);
        Ok(())
    }

    fn values(
        &mut self,
        codec: usize,
        source: usize,
        first: usize,
        rows: usize,
        columns: usize,
        values: &[i64],
    ) -> Result<(), String> {
        let context = self.context.ok_or("calibration trace context missing")?;
        self.signed_frame(
            TRACE_VALUES,
            context,
            codec,
            source,
            first,
            rows,
            columns,
            1,
            values,
            values.len(),
        )
    }

    fn padding(
        &mut self,
        codec: usize,
        source: usize,
        columns: usize,
        value: i64,
    ) -> Result<(), String> {
        let context = self.context.ok_or("calibration trace context missing")?;
        self.signed_frame(
            TRACE_PADDING,
            context,
            codec,
            source,
            150,
            106,
            columns,
            32,
            &[value],
            32 * 106 * columns,
        )
    }

    fn histogram(&mut self, source: usize, values: &[u32]) -> Result<(), String> {
        let context = self.context.ok_or("calibration trace context missing")?;
        self.header(
            TRACE_HISTOGRAM,
            context,
            4,
            source.try_into().map_err(|_| "calibration trace source overflow")?,
            0,
            1,
            values.len() as u64,
            1,
            values.len() as u64,
            values.len() as u64,
        )?;
        let mut encoded = Vec::with_capacity(TRACE_CHUNK_BYTES);
        for chunk in values.chunks(TRACE_CHUNK_BYTES / 4) {
            encoded.clear();
            for value in chunk {
                encoded.extend_from_slice(&value.to_le_bytes());
            }
            self.write(&encoded)?;
        }
        Ok(())
    }

    fn end_context(&mut self, slot: usize, tokens: &[u32; 150]) -> Result<(), String> {
        if self.context != Some(slot as u8) {
            return Err("calibration trace context end differs".into());
        }
        self.header(
            TRACE_TOKENS,
            slot as u8,
            4,
            u32::MAX,
            0,
            1,
            tokens.len() as u64,
            1,
            tokens.len() as u64,
            tokens.len() as u64,
        )?;
        let mut encoded = Vec::with_capacity(tokens.len() * 4);
        for token in tokens {
            encoded.extend_from_slice(&token.to_le_bytes());
        }
        self.write(&encoded)?;
        self.context = None;
        Ok(())
    }

    fn final_kv(&mut self, history: &History, profile: &Canonical) -> Result<(), String> {
        if self.context.is_some() || history.old != 450 {
            return Err("calibration trace final KV state differs".into());
        }
        let kv: BTreeSet<_> =
            profile.sources.attention.layers.iter().flat_map(|layer| [layer.k, layer.v]).collect();
        for source in kv {
            let columns = profile.bytes().scalar.layout.sources[source].cols;
            let rows = history.rows.get(source).ok_or("calibration trace final KV missing")?;
            if rows.len() != 450 || rows.iter().any(|row| row.len() != columns) {
                return Err("calibration trace final KV shape differs".into());
            }
            let words = rows
                .len()
                .checked_mul(columns)
                .ok_or("calibration trace final KV size overflow")?;
            self.header(
                TRACE_FINAL_KV,
                2,
                2,
                source.try_into().map_err(|_| "calibration trace source overflow")?,
                0,
                rows.len() as u64,
                columns as u64,
                1,
                words as u64,
                words as u64,
            )?;
            let mut encoded = Vec::with_capacity(columns * 2);
            for row in rows {
                encoded.clear();
                for value in row.iter() {
                    encoded.extend_from_slice(&value.to_le_bytes());
                }
                self.write(&encoded)?;
            }
            self.final_kv_sources += 1;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<TraceReport, String> {
        if self.context.is_some() || self.final_kv_sources == 0 {
            return Err("calibration trace is incomplete".into());
        }
        let digest = *self.hasher.finalize().as_bytes();
        let records = self.records;
        let logical_words = self.logical_words;
        let stored_words = self.stored_words;
        let bytes_before_footer = self.bytes;
        let mut footer = [0u8; TRACE_FRAME_BYTES];
        footer[0] = TRACE_FOOTER;
        footer[1] = u8::MAX;
        footer[2] = 1;
        footer[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        for (offset, value) in [
            (8, records),
            (16, logical_words),
            (24, stored_words),
            (32, bytes_before_footer),
            (40, digest.len() as u64),
        ] {
            footer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        self.sink.write_all(&footer).map_err(|error| error.to_string())?;
        self.sink.write_all(&digest).map_err(|error| error.to_string())?;
        self.sink.flush().map_err(|error| error.to_string())?;
        self.sink.get_ref().sync_all().map_err(|error| error.to_string())?;
        self.bytes = self
            .bytes
            .checked_add((TRACE_FRAME_BYTES + digest.len()) as u64)
            .ok_or("calibration trace byte count overflow")?;
        self.complete = true;
        Ok(TraceReport {
            format: "C71TRC01",
            bytes: self.bytes,
            records,
            logical_words,
            stored_words,
            final_kv_sources: self.final_kv_sources,
            blake3_before_footer: blake3::Hash::from_bytes(digest).to_hex().to_string(),
            encoder_scratch_bytes: TRACE_CHUNK_BYTES,
        })
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

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

pub(super) fn read_packed(path: &Path, cells: usize) -> Result<(Arc<Vec<i16>>, String), String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() != (2 * cells) as u64 {
        return Err("canonical packed W length differs".into());
    }
    let mut words = Vec::new();
    words.try_reserve_exact(cells).map_err(|e| e.to_string())?;
    let mut h = blake3::Hasher::new();
    let mut chunk = [0; 65536];
    while words.len() < cells {
        let count = (2 * (cells - words.len())).min(chunk.len());
        file.read_exact(&mut chunk[..count]).map_err(|e| e.to_string())?;
        h.update(&chunk[..count]);
        for bytes in chunk[..count].chunks_exact(2) {
            let word = i16::from_le_bytes(bytes.try_into().unwrap());
            if word == i16::MIN {
                return Err("canonical W contains overflow marker".into());
            }
            words.push(word);
        }
    }
    if file.read(&mut chunk[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("canonical W changed length".into());
    }
    // Arc<Vec<_>> transfers ownership without a second full-size W allocation.
    Ok((Arc::new(words), h.finalize().to_hex().to_string()))
}

/// Offline calibration reuses the production integer matrix owner/kernel only.
/// All other producers, trace framing and causal state remain in Trial.
pub(super) struct MatrixDevice {
    runtime: RefCell<kernel::range::windowed::native::Runtime>,
    pub host_weight_capacity_bytes: usize,
    pub load_seconds: f64,
}

impl MatrixDevice {
    pub(super) fn new(
        plan: &Plan,
        packed: &std::path::Path,
        library: &std::path::Path,
    ) -> Result<Self, String> {
        use kernel::range::windowed::native::{Config, Runtime};
        let started = std::time::Instant::now();
        let cells = plan.sources.iter().map(|s| s.rows * s.cols).sum();
        let (weights, _) = read_packed(packed, cells)?;
        let host_weight_capacity_bytes = weights.capacity() * 2;
        let mut runtime =
            Runtime::new(&Config::new(library.to_owned(), 0, 64 << 20, 1 << 30, 1 << 14, 128))?;
        runtime.install_weights(weights, plan.layout_digest)?;
        Ok(Self {
            runtime: RefCell::new(runtime),
            host_weight_capacity_bytes,
            load_seconds: started.elapsed().as_secs_f64(),
        })
    }

    pub(super) fn dot(
        &self,
        batch: &prepare::MatrixBatch,
        input: &[i16],
    ) -> Result<Vec<i64>, String> {
        use kernel::range::windowed::native::DenseShape;
        if batch.rows != 1 || input.len() != batch.inner {
            return Err("calibration CUDA matrix shape differs".into());
        }
        let mut runtime = self.runtime.borrow_mut();
        let values = runtime.upload_signed(input)?;
        let product = runtime.product(
            &values,
            0,
            batch.weight_offset,
            DenseShape { m: 1, n: batch.columns as u32, k: batch.inner as u32 },
        )?;
        let mut output = vec![0; batch.columns];
        runtime.download_words(&product, 0, &mut output)?;
        runtime.release_buffer(product)?;
        runtime.release_buffer(values)?;
        Ok(output)
    }

    pub(super) fn close(&self) -> Result<serde_json::Value, String> {
        let mut runtime = self.runtime.borrow_mut();
        let before = runtime.stats()?;
        let after = runtime.close()?;
        Ok(serde_json::json!({"host_weight_capacity_bytes": self.host_weight_capacity_bytes,
            "load_seconds": self.load_seconds, "before_close": before, "after_close": after,
            "complete_physical_peak": false}))
    }
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
            .checked_mul(2 * 128)
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

    pub(super) fn matrix_dot(
        &mut self,
        batch: &prepare::MatrixBatch,
        input: &[i16],
    ) -> Result<Vec<i64>, String> {
        self.row = None;
        let source = self.sources.get(batch.tensor).ok_or("packed matrix tensor missing")?;
        if batch.rows != 1
            || batch.columns != source.rows
            || batch.inner != source.cols
            || batch.weight_offset != source.packed_offset
            || input.len() != source.cols
            || input.contains(&i16::MIN)
            || (source.cols as u128) * 32767u128.pow(2) >= 1u128 << 63
        {
            return Err("packed matrix shape/input/bound differs".into());
        }
        self.input
            .seek(SeekFrom::Start(2 * source.packed_offset as u64))
            .map_err(|e| e.to_string())?;
        let mut output = Vec::with_capacity(source.rows);
        for first in (0..source.rows).step_by(128) {
            let rows = (source.rows - first).min(128);
            let body = &mut self.buffer[..rows * source.cols * 2];
            self.input.read_exact(body).map_err(|e| e.to_string())?;
            self.row_loads += rows;
            self.completed_row_bytes += body.len();
            if body.chunks_exact(2).any(|b| i16::from_le_bytes([b[0], b[1]]) == i16::MIN) {
                return Err("packed W outside symmetric i16".into());
            }
            for row in body.chunks_exact(2 * source.cols) {
                output.push(
                    row.chunks_exact(2)
                        .zip(input)
                        .map(|(w, &x)| i64::from(i16::from_le_bytes([w[0], w[1]])) * i64::from(x))
                        .sum(),
                );
            }
        }
        Ok(output)
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
    mut trace: Option<&mut Trace>,
    device: Option<&MatrixDevice>,
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
        if let Some(trace) = trace.as_deref_mut() {
            trace.begin_context(slot, profile)?;
        }
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
                .token_observed_matrix(
                    &mut tokens,
                    &public.tables[slot],
                    &|id, row, column| weights.borrow_mut().get(id, row, column),
                    &|id, row, column| history.read(id, row, column),
                    trace.as_deref_mut(),
                    |_| Ok(()),
                    Some(&|batch, input| match device {
                        Some(device) => device.dot(batch, input),
                        None => weights.borrow_mut().matrix_dot(batch, input),
                    }),
                )
                .map_err(|error| format!("calibration O={} token={token}: {error}", slot * 150))?;
        }
        trial.finish(trace.as_deref_mut())?;
        if let Some(trace) = trace.as_deref_mut() {
            trace.end_context(slot, &tokens)?;
        }
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
    if let Some(trace) = trace {
        trace.final_kv(&history, &public.profiles[2])?;
    }
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_native_calibration_block_matrix_matches_i128_and_rejects_invalid() {
        for (rows, columns) in [(257, 129), (3, 21504)] {
            let sources = [Source { name: "matrix".into(), rows, cols: columns, packed_offset: 0 }];
            let words: Vec<i16> =
                (0..rows * columns).map(|i| ((i * 37 % 65535) as i32 - 32767) as i16).collect();
            let input: Vec<i16> =
                (0..columns).map(|i| if i % 2 == 0 { -32767 } else { 32767 }).collect();
            let bytes = words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>();
            let mut reader = PackedRows::new(&sources, std::io::Cursor::new(bytes)).unwrap();
            let batch = prepare::MatrixBatch {
                input: 0,
                input_first: 0,
                tensor: 0,
                weight_offset: 0,
                rows: 1,
                columns: rows,
                inner: columns,
            };
            let expected: Vec<i64> = words
                .chunks_exact(columns)
                .map(|row| {
                    row.iter()
                        .zip(&input)
                        .map(|(&w, &x)| i128::from(w) * i128::from(x))
                        .sum::<i128>() as i64
                })
                .collect();
            assert_eq!(reader.matrix_dot(&batch, &input).unwrap(), expected);
            assert_eq!(reader.row_loads, rows);
            assert_eq!(reader.completed_row_bytes, rows * columns * 2);
            assert!(reader.row.is_none());
            assert_eq!(
                reader.get(0, rows - 1, columns - 1).unwrap(),
                i64::from(*words.last().unwrap())
            );
            assert_eq!(reader.matrix_dot(&batch, &input).unwrap(), expected);
            assert!(reader.matrix_dot(&batch, &input[..columns - 1]).is_err());
            let mut invalid = input.clone();
            invalid[0] = i16::MIN;
            assert!(reader.matrix_dot(&batch, &invalid).is_err());
            reader.input.get_mut()[2..4].copy_from_slice(&i16::MIN.to_le_bytes());
            assert!(reader.matrix_dot(&batch, &input).is_err());
            assert!(reader.row.is_none());
            reader.input.get_mut().truncate(1);
            assert!(reader.matrix_dot(&batch, &input).is_err());
        }
    }

    #[test]
    fn c71_calibration_trace_codec_is_framed_and_fail_closed() {
        let suffix =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path =
            std::env::temp_dir().join(format!("c71-trace-{}-{suffix}.bin", std::process::id()));
        let mut trace = Trace::create(&path).unwrap();
        assert!(Trace::create(&path).is_err());
        trace.bytes_frame(TRACE_METADATA, 0, u32::MAX, 0, 0, 0, 0, br#"{}"#, 0).unwrap();
        trace.signed_frame(TRACE_VALUES, 0, 2, 0, 0, 1, 2, 1, &[-1, 2], 2).unwrap();
        trace.final_kv_sources = 1;
        let report = trace.finish().unwrap();
        let body = std::fs::read(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(&body[..8], TRACE_MAGIC);
        assert_eq!(report.records, 2);
        assert_eq!(report.logical_words, 2);
        assert_eq!(report.bytes as usize, body.len());
        assert_eq!(body[body.len() - 80], TRACE_FOOTER);
        std::fs::remove_file(&path).unwrap();

        let partial = path.with_extension("partial");
        drop(Trace::create(&partial).unwrap());
        assert!(!partial.exists());
    }

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
                trial.token(&mut tokens, &tables, &weights, &absent, None).unwrap();
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
            assert!(trial.finish(None).is_err()); // Never label a partial graph calibrated.
            let mut limited = Trial::new(&p, 1);
            assert!(limited.token(&mut tokens, &tables, &weights, &absent, None).is_err());
            let before = calls.get();
            assert!(limited.token(&mut tokens, &tables, &weights, &absent, None).is_err());
            assert_eq!(calls.get(), before); // fail closed, no retry after partial work
            let mut observed = Trial::new(&p, 16 << 20);
            let original_tokens = tokens;
            assert!(observed
                .token_observed(&mut tokens, &tables, &weights, &absent, None, |_| Err(
                    "checkpoint sink failed".into()
                ))
                .is_err());
            assert_eq!(tokens, original_tokens);
            let before = calls.get();
            assert!(observed.token(&mut tokens, &tables, &weights, &absent, None).is_err());
            assert_eq!(calls.get(), before);
            assert!(observed.into_retained().is_err());

            let mut p = Canonical::compile(old / 150, &[0; 772], &scales).unwrap();
            let g = &p.sources.attention.rope.gate_up.gelu.gelu[0];
            let (x, y, h, cols) = (g.input, g.output, g.histogram, g.columns);
            let up = p.sources.attention.rope.gate_up.products[0].up;
            let raw = p.sources.attention.rope.gate_up.products[0].raw;
            p.steps = vec![Producer::Gelu(0), Producer::Gate(0)];
            let mut look = Trial::new(&p, 16 << 20);
            look.emit(
                prepare::Row {
                    values: vec![
                        (x, 0, (0..cols).map(|j| (j % 3) as i64 - 1).collect()),
                        (up, 0, vec![2; cols]),
                    ],
                    ..Default::default()
                },
                None,
            )
            .unwrap();
            look.token(&mut tokens, &tables, &absent, &absent, None).unwrap();
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
            pv.emit(prepare::Row { values, ..Default::default() }, None).unwrap();
            pv.token(
                &mut tokens,
                &tables,
                &absent,
                &|id, t, c| {
                    assert_eq!(id, v);
                    assert!(t < old);
                    assert!(c < groups * lanes);
                    Ok(2)
                },
                None,
            )
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

    fn emit(&mut self, out: prepare::Row, mut trace: Option<&mut Trace>) -> Result<(), String> {
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
            if let Some(trace) = trace.as_deref_mut() {
                trace.values(
                    p.bytes().widths[id],
                    id,
                    first,
                    values.len() / source.cols,
                    source.cols,
                    &values,
                )?;
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
        trace: Option<&mut Trace>,
    ) -> Result<(), String> {
        self.token_observed(tokens, tables, weights, previous, trace, |_| Ok(()))
    }

    /// Observe validated numerical row bundles before their last consumer
    /// releases them. No correlations, challenges or keys enter this path.
    pub(super) fn token_observed(
        &mut self,
        tokens: &mut [u32; 150],
        tables: &profile::Tables<'_>,
        weights: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        previous: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        trace: Option<&mut Trace>,
        observe: impl FnMut(&prepare::Row) -> Result<(), String>,
    ) -> Result<(), String> {
        self.token_observed_matrix(tokens, tables, weights, previous, trace, observe, None)
    }

    fn token_observed_matrix(
        &mut self,
        tokens: &mut [u32; 150],
        tables: &profile::Tables<'_>,
        weights: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        previous: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        trace: Option<&mut Trace>,
        mut observe: impl FnMut(&prepare::Row) -> Result<(), String>,
        matrix: Option<&dyn Fn(&prepare::MatrixBatch, &[i16]) -> Result<Vec<i64>, String>>,
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
        let trace = RefCell::new(trace);
        let weight = |id, r, c| {
            wr.set(wr.get() + 1);
            weights(id, r, c)
        };
        let get = |id, r, c| {
            ar.set(ar.get() + 1);
            state.borrow().read(id, r, c)
        };
        let tail = |id, t, c| {
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
        };
        let result = p.prepare_token_with(
            token,
            &mut pending_tokens,
            |step, row, emitted_token| {
                if let (Producer::Matrix(raw), Some(matrix)) = (step, matrix) {
                    let batch = p.matrix_batch(*raw, row, 1)?;
                    let mut input = Vec::with_capacity(batch.inner);
                    for column in 0..batch.inner {
                        let value = get(batch.input, batch.input_first, column)?;
                        if !(-32767..=32767).contains(&value) {
                            return Err("calibration matrix input outside symmetric i16".into());
                        }
                        input.push(value as i16);
                    }
                    let output = matrix(&batch, &input)?;
                    if output.len() != batch.columns {
                        return Err("calibration matrix output length differs".into());
                    }
                    wr.set(wr.get() + batch.columns * batch.inner);
                    Ok(prepare::Row { values: vec![(*raw, row, output)], ..Default::default() })
                } else {
                    p.prepare_row(step, row, emitted_token, tables, &weight, &get, &tail)
                }
            },
            |out| {
                observe(&out)?;
                state.borrow_mut().emit(out, trace.borrow_mut().as_deref_mut())
            },
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
    pub(super) fn finish(&mut self, mut trace: Option<&mut Trace>) -> Result<(), String> {
        if self.failed || self.finished || self.next_token != 150 {
            return Err("calibration trial incomplete/stopped".into());
        }
        self.failed = true;
        let p = self.profile;
        for (id, s) in p.bytes().scalar.layout.sources.iter().enumerate() {
            if s.rows > 150 {
                if let Some(v) = p.padding_word(id, 150, 0)? {
                    let count = 32 * 106 * s.cols;
                    if let Some(trace) = trace.as_deref_mut() {
                        trace.padding(p.bytes().widths[id], id, s.cols, v)?;
                    }
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
                if let Some(trace) = trace.as_deref_mut() {
                    trace.histogram(id, h)?;
                }
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

    pub(super) fn into_retained(
        self,
    ) -> Result<(Vec<Vec<Box<[i16]>>>, BTreeMap<usize, Vec<u32>>, Work), String> {
        if self.failed || !self.finished || self.next_token != 150 {
            return Err("cannot retain incomplete canonical preparation".into());
        }
        Ok((self.kv, self.histograms, self.work))
    }
}

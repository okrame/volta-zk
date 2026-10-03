//! Original source blocks through the shared native owner. No host-output
//! download, transcript or CPU fallback. Full producer coverage remains open.
use super::*;
use kernel::range::windowed::native::{Buffer, DenseShape, Pointwise, RopeShape, Runtime};
use std::sync::Arc;

pub(super) struct Rows {
    buffer: Buffer,
    source: usize,
    first: usize,
    rows: usize,
    columns: usize,
    layout: [u8; 32],
    recipe: [u8; 32],
}

pub(super) struct NonlinearTables {
    buffer: Buffer,
    gelu: Vec<usize>,
    softcap: usize,
    rope: [usize; 2],
    layout: [u8; 32],
    recipe: [u8; 32],
    old: usize,
}

pub(super) struct Histogram {
    buffer: Buffer,
    source: usize,
    output: usize,
    seen: Vec<bool>,
    layout: [u8; 32],
    recipe: [u8; 32],
}

impl NonlinearTables {
    pub(super) fn install(
        runtime: &mut Runtime,
        plan: &Canonical,
        tables: &profile::Tables<'_>,
    ) -> Result<Self, String> {
        if tables.gelu.len() != 60 || tables.rope.len() != 2 {
            return runtime.abort("resident nonlinear table count differs");
        }
        let mut packed = Vec::with_capacity(61 * 65535 * 2 + 150 * 192 * 8 + 2);
        let mut gelu = Vec::with_capacity(60);
        let mut softcap = 0;
        for (index, table) in tables.gelu.iter().chain(std::iter::once(tables.softcap)).enumerate()
        {
            let lookup::Outputs::I16(values) = table.outputs else {
                return runtime.abort("resident lookup table type differs");
            };
            if values.len() != 65535
                || values.contains(&i16::MIN)
                || table.lower != -32767
                || table.profile as usize != if index == 60 { 0 } else { index }
            {
                return runtime.abort("resident lookup table shape or range differs");
            }
            if index == 60 {
                softcap = packed.len();
            } else {
                gelu.push(packed.len());
            }
            for value in values {
                packed.extend_from_slice(&value.to_le_bytes());
            }
        }
        packed.resize(packed.len().next_multiple_of(4), 0);
        let mut rope = [0; 2];
        for (family, table) in tables.rope.iter().enumerate() {
            let pairs = if family == 0 { 128 } else { 64 };
            if table.position != plan.sources.attention.rope.old
                || table.rows.len() != 150
                || table.rows.iter().any(|row| {
                    row.len() != pairs
                        || row.iter().flatten().any(|value| !(-(1 << 30)..=1 << 30).contains(value))
                })
            {
                return runtime.abort("resident RoPE absolute table window differs");
            }
            rope[family] = packed.len();
            for value in table.rows.iter().flatten().flatten() {
                packed.extend_from_slice(&value.to_le_bytes());
            }
        }
        Ok(Self {
            buffer: runtime.upload_table(&packed)?,
            gelu,
            softcap,
            rope,
            layout: plan.bytes().layout_digest,
            recipe: plan.recipes.digest,
            old: plan.sources.attention.rope.old,
        })
    }

    pub(super) fn release(self, runtime: &mut Runtime) -> Result<(), String> {
        runtime.release_buffer(self.buffer)
    }
}

impl Histogram {
    pub(super) fn finish(self, runtime: &mut Runtime) -> Result<Rows, String> {
        if self.seen.iter().any(|seen| !seen) {
            return runtime.abort("incomplete resident lookup histogram");
        }
        Ok(Rows {
            buffer: runtime.seal_histogram(self.buffer)?,
            source: self.source,
            first: 0,
            rows: 1,
            columns: 65535,
            layout: self.layout,
            recipe: self.recipe,
        })
    }
}

/// A pending window owns zero-filled external padding, but is NOT a range
/// source until the original source rows are complete and device work fenced.
pub(super) struct ByteWindow<'a> {
    bytes: &'a bytes::Bytes,
    recipe: [u8; 32],
    window: bytes::RangeWindow,
    length: usize,
    seen: BTreeMap<usize, Vec<u64>>,
    buffer: Buffer,
}
impl<'a> ByteWindow<'a> {
    pub(super) fn new(
        runtime: &mut Runtime,
        b: &'a bytes::Bytes,
        recipe: [u8; 32],
        dimension: usize,
        first: usize,
        length: usize,
        suffix: usize,
        bottom: usize,
    ) -> Result<Self, String> {
        let window = match bytes::RangeWindow::new(dimension, first, length, suffix, bottom) {
            Ok(w) => w,
            Err(e) => return runtime.abort(e),
        };
        let sources = match b.range_window_sources(&window) {
            Ok(s) => s,
            Err(e) => return runtime.abort(e),
        };
        // Same row bitmap contract as the CPU scanner, not an A-sized bitmap.
        let seen = sources
            .into_iter()
            .map(|id| (id, vec![0u64; b.scalar.layout.sources[id].rows.div_ceil(64)]))
            .collect();
        let buffer = runtime.byte_window(length)?;
        Ok(Self { bytes: b, recipe, window, length, seen, buffer })
    }

    pub(super) fn sources(&self) -> impl Iterator<Item = usize> + '_ {
        self.seen.keys().copied()
    }

    pub(super) fn append(&mut self, runtime: &mut Runtime, rows: &Rows) -> Result<(), String> {
        let b = self.bytes;
        let shape = b.scalar.layout.sources.get(rows.source);
        if rows.layout != b.layout_digest
            || rows.recipe != self.recipe
            || rows.rows == 0
            || shape.is_none_or(|s| {
                s.cols != rows.columns
                    || rows.first.checked_add(rows.rows).is_none_or(|end| end > s.rows)
            })
        {
            return runtime.abort("resident byte block identity or shape differs");
        }
        let Some(seen) = self.seen.get_mut(&rows.source) else {
            return runtime.abort("resident byte source not requested");
        };
        for r in rows.first..rows.first + rows.rows {
            if seen[r / 64] & (1 << (r % 64)) != 0 {
                return runtime.abort("duplicate resident byte row");
            }
            seen[r / 64] |= 1 << (r % 64);
        }
        if let Err(e) = b.resident_tiles(
            &self.window,
            self.length,
            rows.source,
            rows.first,
            rows.rows,
            |tile| runtime.scatter_bytes(&rows.buffer, &tile, &self.buffer),
        ) {
            return runtime.abort(e);
        }
        Ok(())
    }

    pub(super) fn finish(self, runtime: &mut Runtime) -> Result<Buffer, String> {
        for (&id, seen) in &self.seen {
            if seen.iter().map(|x| x.count_ones() as usize).sum::<usize>()
                != self.bytes.scalar.layout.sources[id].rows
            {
                return runtime.abort("incomplete resident byte window");
            }
        }
        runtime.seal_bytes(self.buffer)
    }
}

fn install(runtime: &mut Runtime, plan: &Plan, weights: Arc<Vec<i16>>) -> Result<(), String> {
    let words = plan.sources.iter().try_fold(0usize, |end, s| {
        s.rows
            .checked_mul(s.cols)
            .and_then(|n| s.packed_offset.checked_add(n))
            .map(|n| end.max(n))
            .ok_or("resident W layout overflow")
    });
    let words = match words {
        Ok(n) => n,
        Err(e) => return runtime.abort(e),
    };
    if weights.len() != words {
        return runtime.abort("resident W length differs from plan");
    }
    runtime.install_weights(weights, plan.layout_digest)
}

impl Rows {
    fn embedding(
        runtime: &mut Runtime,
        plan: &Plan,
        b: &bytes::Bytes,
        recipe: [u8; 32],
        weights: &Arc<Vec<i16>>,
        first: usize,
        tokens: &[u32],
    ) -> Result<Self, String> {
        let batch = match prepare::EmbeddingBatch::new(plan, b, first, tokens) {
            Ok(batch) => batch,
            Err(e) => return runtime.abort(e),
        };
        runtime.require_weights(weights, plan.layout_digest)?;
        let buffer =
            runtime.embedding(batch.weight_offset, batch.vocabulary, batch.columns, tokens)?;
        Ok(Self {
            buffer,
            source: 0,
            first,
            rows: tokens.len(),
            columns: batch.columns,
            layout: b.layout_digest,
            recipe,
        })
    }

    fn pointwise(
        runtime: &mut Runtime,
        b: &bytes::Bytes,
        recipe: [u8; 32],
        relation: &bytes::affine::Relation,
        multiply: bool,
        first: usize,
        rows: usize,
        inputs: &[&Rows],
    ) -> Result<Self, String> {
        let shape = match b.affine_shape(relation) {
            Ok(shape) => shape,
            Err(e) => return runtime.abort(e),
        };
        if rows == 0
            || first.checked_add(rows).is_none_or(|end| end > shape.rows)
            || inputs.len() != relation.inputs.iter().filter(|(_, c)| *c != 0).count()
            || (multiply && relation.inputs.iter().any(|(_, c)| *c != 1))
        {
            return runtime.abort("resident pointwise rows or operands differ");
        }
        let mut selected = [None, None];
        let mut next = 0;
        for (j, &(source, coefficient)) in relation.inputs.iter().enumerate() {
            if coefficient == 0 {
                continue;
            }
            let input = inputs[next];
            next += 1;
            if input.layout != b.layout_digest
                || input.recipe != recipe
                || input.source != source
                || input.columns != shape.cols
                || first < input.first
                || first - input.first > input.rows
                || rows > input.rows - (first - input.first)
            {
                return runtime.abort("resident pointwise original input differs");
            }
            selected[j] = Some((&input.buffer, (first - input.first) * shape.cols));
        }
        let Some(count) = rows.checked_mul(shape.cols) else {
            return runtime.abort("resident pointwise size overflow");
        };
        let buffer = runtime.pointwise(
            selected,
            count,
            Pointwise {
                a: relation.inputs[0].1,
                b: relation.inputs[1].1,
                multiply: u32::from(multiply),
            },
        )?;
        Ok(Self {
            buffer,
            source: relation.raw,
            first,
            rows,
            columns: shape.cols,
            layout: b.layout_digest,
            recipe,
        })
    }

    fn upload(
        runtime: &mut Runtime,
        b: &bytes::Bytes,
        recipe: [u8; 32],
        source: usize,
        first: usize,
        values: &[i16],
    ) -> Result<Self, String> {
        let Some(shape) = b.scalar.layout.sources.get(source) else {
            return runtime.abort("resident source missing");
        };
        if b.widths[source] != 2
            || shape.cols == 0
            || values.is_empty()
            || values.len() % shape.cols != 0
        {
            return runtime.abort("resident signed input shape");
        }
        let rows = values.len() / shape.cols;
        if first.checked_add(rows).is_none_or(|end| end > shape.rows) {
            return runtime.abort("resident input rows outside source");
        }
        let buffer = runtime.upload_signed(values)?;
        Ok(Self {
            buffer,
            source,
            first,
            rows,
            columns: shape.cols,
            layout: b.layout_digest,
            recipe,
        })
    }

    fn matrix(
        &self,
        runtime: &mut Runtime,
        plan: &Plan,
        b: &bytes::Bytes,
        recipe: [u8; 32],
        weights: &Arc<Vec<i16>>,
        raw: usize,
        first: usize,
        rows: usize,
    ) -> Result<Self, String> {
        runtime.require_weights(weights, plan.layout_digest)?;
        let batch = match prepare::MatrixBatch::new(plan, b, raw, first, rows) {
            Ok(batch) => batch,
            Err(error) => return runtime.abort(error),
        };
        if self.layout != b.layout_digest
            || self.recipe != recipe
            || self.source != batch.input
            || self.columns != batch.inner
            || batch.input_first < self.first
            || batch.input_first - self.first > self.rows
            || rows > self.rows - (batch.input_first - self.first)
        {
            return runtime.abort("resident matrix input identity or selected rows differ");
        }
        let buffer = runtime.product(
            &self.buffer,
            batch.input_first - self.first,
            batch.weight_offset,
            DenseShape { m: rows as u32, n: batch.columns as u32, k: batch.inner as u32 },
        )?;
        Ok(Self {
            buffer,
            source: raw,
            first,
            rows,
            columns: batch.columns,
            layout: self.layout,
            recipe: self.recipe,
        })
    }

    fn rne(
        &self,
        runtime: &mut Runtime,
        b: &bytes::Bytes,
        recipe: [u8; 32],
        pair: Pair,
        first: usize,
        rows: usize,
    ) -> Result<Self, String> {
        let shape = b.scalar.layout.sources.get(pair.output);
        if self.layout != b.layout_digest
            || self.recipe != recipe
            || self.source != pair.raw
            || self.first != first
            || self.rows != rows
            || b.widths.get(pair.raw) != Some(&6)
            || b.widths.get(pair.output) != Some(&2)
            || shape.is_none_or(|s| {
                s.cols != self.columns || first.checked_add(rows).is_none_or(|end| end > s.rows)
            })
        {
            return runtime.abort("resident RNE identity or complete raw block differs");
        }
        let buffer = runtime.quantize(&self.buffer, pair.shift)?;
        Ok(Self {
            buffer,
            source: pair.output,
            first,
            rows,
            columns: self.columns,
            layout: self.layout,
            recipe: self.recipe,
        })
    }

    // Explicit release: a Rust descriptor going out of scope is not GPU free.
    pub(super) fn release(self, runtime: &mut Runtime) -> Result<(), String> {
        runtime.release_buffer(self.buffer)
    }
}

impl Canonical {
    fn native_lookup_sources(&self, step: usize) -> Option<(usize, usize, usize)> {
        match self.steps.get(step)? {
            Producer::Gelu(index) => {
                let gelu = &self.sources.attention.rope.gate_up.gelu.gelu[*index];
                Some((gelu.input, gelu.output, gelu.histogram))
            }
            Producer::Softcap => {
                Some((self.output.input, self.output.output, self.output.histogram))
            }
            _ => None,
        }
    }

    pub(super) fn native_histogram(
        &self,
        runtime: &mut Runtime,
        step: usize,
    ) -> Result<Histogram, String> {
        let Some((_, output, source)) = self.native_lookup_sources(step) else {
            return runtime.abort("resident producer has no i16 lookup histogram");
        };
        Ok(Histogram {
            buffer: runtime.histogram()?,
            source,
            output,
            seen: vec![false; self.bytes().scalar.layout.sources[output].rows],
            layout: self.bytes().layout_digest,
            recipe: self.recipes.digest,
        })
    }

    pub(super) fn prepare_native_nonlinear_step(
        &self,
        runtime: &mut Runtime,
        tables: &NonlinearTables,
        step: usize,
        first: usize,
        rows: usize,
        input: &Rows,
        histogram: Option<&mut Histogram>,
    ) -> Result<(Rows, Vec<u32>), String> {
        let (source, output) = match self.steps.get(step) {
            Some(Producer::Gelu(_)) | Some(Producer::Softcap) => {
                let (source, output, _) = self.native_lookup_sources(step).unwrap();
                (source, output)
            }
            Some(Producer::Rope(index)) => {
                let rotation = &self.sources.attention.rope.rotations[*index];
                (
                    self.sources.attention.rope.gate_up.gelu.rms.norms[rotation.norm].output,
                    rotation.raw,
                )
            }
            Some(Producer::Argmax) => (self.output.output, self.output.slack),
            _ => return runtime.abort("resident nonlinear producer differs"),
        };
        let shape = &self.bytes().scalar.layout.sources[output];
        if tables.layout != self.bytes().layout_digest
            || tables.recipe != self.recipes.digest
            || tables.old != self.sources.attention.rope.old
            || input.layout != tables.layout
            || input.recipe != tables.recipe
            || input.source != source
            || input.columns != shape.cols
            || rows == 0
            || rows > 150
            || first < input.first
            || first - input.first > input.rows
            || rows > input.rows - (first - input.first)
            || first.checked_add(rows).is_none_or(|end| end > shape.rows)
        {
            return runtime.abort("resident nonlinear original input or table identity differs");
        }
        let offset = (first - input.first) * shape.cols;
        let (buffer, tokens) = match &self.steps[step] {
            Producer::Gelu(_) | Producer::Softcap => {
                let Some(histogram) = histogram else {
                    return runtime.abort("resident lookup histogram missing");
                };
                let (_, _, expected_histogram) = self.native_lookup_sources(step).unwrap();
                if histogram.layout != tables.layout
                    || histogram.recipe != tables.recipe
                    || histogram.source != expected_histogram
                    || histogram.output != output
                    || histogram.seen.len() != shape.rows
                    || histogram.seen[first..first + rows].iter().any(|seen| *seen)
                {
                    return runtime.abort("resident lookup histogram identity or duplicate rows");
                }
                let table_offset = match &self.steps[step] {
                    Producer::Gelu(index) => tables.gelu[*index],
                    _ => tables.softcap,
                };
                let buffer = runtime.lookup(
                    &input.buffer,
                    offset,
                    rows * shape.cols,
                    &tables.buffer,
                    table_offset,
                    &histogram.buffer,
                )?;
                histogram.seen[first..first + rows].fill(true);
                (buffer, Vec::new())
            }
            Producer::Rope(index) => {
                if histogram.is_some() {
                    return runtime.abort("unexpected resident RoPE histogram");
                }
                let rotation = &self.sources.attention.rope.rotations[*index];
                let pairs = if rotation.family == 0 { 128 } else { 64 };
                (
                    runtime.rope(
                        &input.buffer,
                        offset,
                        &tables.buffer,
                        tables.rope[rotation.family] + first * pairs * 8,
                        RopeShape {
                            rows: rows as u32,
                            heads: rotation.heads as u32,
                            width: rotation.width as u32,
                            pairs: pairs as u32,
                        },
                    )?,
                    Vec::new(),
                )
            }
            Producer::Argmax => {
                if histogram.is_some() {
                    return runtime.abort("unexpected resident argmax histogram");
                }
                runtime.argmax(&input.buffer, offset, rows, shape.cols)?
            }
            _ => unreachable!(),
        };
        Ok((
            Rows {
                buffer,
                source: output,
                first,
                rows,
                columns: shape.cols,
                layout: tables.layout,
                recipe: tables.recipe,
            },
            tokens,
        ))
    }

    pub(super) fn native_byte_window(
        &self,
        runtime: &mut Runtime,
        first: usize,
        length: usize,
        suffix: usize,
        bottom: usize,
    ) -> Result<ByteWindow<'_>, String> {
        ByteWindow::new(
            runtime,
            self.bytes(),
            self.recipes.digest,
            34,
            first,
            length,
            suffix,
            bottom,
        )
    }
    pub(super) fn install_native_weights(
        &self,
        runtime: &mut Runtime,
        weights: Arc<Vec<i16>>,
    ) -> Result<(), String> {
        install(runtime, &self.plan, weights)
    }
    pub(super) fn upload_native_rows(
        &self,
        runtime: &mut Runtime,
        source: usize,
        first: usize,
        values: &[i16],
    ) -> Result<Rows, String> {
        Rows::upload(runtime, self.bytes(), self.recipes.digest, source, first, values)
    }
    pub(super) fn prepare_native_step(
        &self,
        runtime: &mut Runtime,
        weights: &Arc<Vec<i16>>,
        step: usize,
        first: usize,
        rows: usize,
        tokens: &[u32],
        inputs: &[&Rows],
    ) -> Result<Rows, String> {
        if !matches!(self.steps.get(step), Some(Producer::Embedding)) && !tokens.is_empty() {
            return runtime.abort("unexpected native producer token input");
        }
        match self.steps.get(step) {
            Some(Producer::Embedding) => {
                if !inputs.is_empty() || tokens.len() != rows {
                    return runtime.abort("native embedding input arity");
                }
                Rows::embedding(
                    runtime,
                    &self.plan,
                    self.bytes(),
                    self.recipes.digest,
                    weights,
                    first,
                    tokens,
                )
            }
            Some(Producer::Matrix(raw)) if inputs.len() == 1 => inputs[0].matrix(
                runtime,
                &self.plan,
                self.bytes(),
                self.recipes.digest,
                weights,
                *raw,
                first,
                rows,
            ),
            Some(Producer::Rne(pair)) if inputs.len() == 1 => {
                inputs[0].rne(runtime, self.bytes(), self.recipes.digest, *pair, first, rows)
            }
            Some(Producer::Affine(i)) => Rows::pointwise(
                runtime,
                self.bytes(),
                self.recipes.digest,
                &self.recipes.affine[*i],
                false,
                first,
                rows,
                inputs,
            ),
            Some(Producer::Gate(i)) => {
                let gu = &self.sources.attention.rope.gate_up;
                let product = &gu.products[*i];
                let relation = bytes::affine::Relation {
                    raw: product.raw,
                    inputs: [(gu.gelu.gelu[*i].output, 1), (product.up, 1)],
                };
                Rows::pointwise(
                    runtime,
                    self.bytes(),
                    self.recipes.digest,
                    &relation,
                    true,
                    first,
                    rows,
                    inputs,
                )
            }
            _ => runtime.abort("canonical native producer not implemented"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::range::windowed::native::tests::{fixture, Injection};

    fn nonlinear_profile(slot: usize) -> Canonical {
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for layer in &softmax.layers {
            scales.insert(layer.pi, -14);
        }
        Canonical::compile(slot, &[0; 772], &scales).unwrap()
    }

    fn check_nonlinear_words(
        runtime: &mut Runtime,
        injection: &Injection,
        rows: &Rows,
        width: u32,
        expected: &[i64],
    ) {
        use kernel::range::windowed::native::ByteTile;
        assert_eq!(rows.rows * rows.columns, expected.len());
        let window = runtime.byte_window(128).unwrap();
        injection.expect_raw(expected);
        runtime
            .scatter_bytes(
                &rows.buffer,
                &ByteTile {
                    input_first: 0,
                    input_stride: expected.len() as u64,
                    rows: 1,
                    columns: expected.len() as u64,
                    original_first: 0,
                    window_first: 0,
                    window_length: 128,
                    byte_first: 0,
                    width,
                    signed_width: width,
                    dimension: (expected.len() * width as usize)
                        .max(128)
                        .next_power_of_two()
                        .ilog2(),
                    suffix: 0,
                    bottom: 0,
                },
                &window,
            )
            .unwrap();
        let window = runtime.seal_bytes(window).unwrap();
        runtime.release_buffer(window).unwrap();
    }

    #[test]
    fn c71_canonical_resident_nonlinear_original_routes() {
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 32 << 20;
        let injection = Injection::new(&fixture.config);
        let values: Vec<i16> = (-32767..=32767).map(|value| (value / 2) as i16).collect();
        let gelu: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I16(&values),
            })
            .collect();
        let softcap =
            lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&values) };
        for slot in 0..3 {
            let plan = nonlinear_profile(slot);
            let rotations = [128, 64].map(|pairs| {
                (0..150)
                    .map(|row| {
                        (0..pairs)
                            .map(|pair| {
                                if (row + slot * 150 + pair) % 2 == 0 {
                                    [0, 1 << 30]
                                } else {
                                    [1 << 30, 0]
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            });
            let rope = [0, 1].map(|family| kernel::rope::Table {
                position: slot * 150,
                rows: &rotations[family],
            });
            let public =
                profile::Tables { gelu: &gelu, exp30: &[], softcap: &softcap, rope: &rope };
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let tables = NonlinearTables::install(&mut runtime, &plan, &public).unwrap();
            let baseline = runtime.stats().unwrap().live_capacity_bytes;
            let mut counts = [0; 4];
            for (index, step) in plan.steps.iter().enumerate() {
                let (source, category) = match step {
                    Producer::Gelu(index) => {
                        (plan.sources.attention.rope.gate_up.gelu.gelu[*index].input, 0)
                    }
                    Producer::Rope(index) => {
                        let rotation = &plan.sources.attention.rope.rotations[*index];
                        (
                            plan.sources.attention.rope.gate_up.gelu.rms.norms[rotation.norm]
                                .output,
                            1,
                        )
                    }
                    Producer::Softcap => (plan.output.input, 2),
                    Producer::Argmax => (plan.output.output, 3),
                    _ => continue,
                };
                let shape = &plan.bytes().scalar.layout.sources[source];
                let first = shape.rows - 1;
                let sample =
                    |row: usize, column: usize| ((row + column * 7 + slot * 3) % 9) as i16 - 4;
                let input_values = (first - 1..=first)
                    .flat_map(|row| (0..shape.cols).map(move |column| sample(row, column)))
                    .collect::<Vec<_>>();
                let input = plan
                    .upload_native_rows(&mut runtime, source, first - 1, &input_values)
                    .unwrap();
                let mut histogram = plan
                    .native_lookup_sources(index)
                    .map(|_| plan.native_histogram(&mut runtime, index).unwrap());
                let reference = plan
                    .prepare_row(
                        step,
                        first,
                        0,
                        &public,
                        |_, _, _| panic!("nonlinear W read"),
                        |id, row, column| {
                            assert_eq!(id, source);
                            Ok(i64::from(sample(row, column)))
                        },
                        |_, _, _| panic!("nonlinear KV read"),
                    )
                    .unwrap();
                let before = runtime.stats().unwrap();
                let (output, tokens) = plan
                    .prepare_native_nonlinear_step(
                        &mut runtime,
                        &tables,
                        index,
                        first,
                        1,
                        &input,
                        histogram.as_mut(),
                    )
                    .unwrap();
                let after = runtime.stats().unwrap();
                assert_eq!(after.h2d_bytes, before.h2d_bytes);
                assert_eq!(after.d2h_bytes - before.d2h_bytes, if category == 3 { 8 } else { 4 });
                assert_eq!(tokens, reference.token.into_iter().collect::<Vec<_>>());
                assert_eq!(
                    (output.source, output.first),
                    (reference.values[0].0, reference.values[0].1)
                );
                check_nonlinear_words(
                    &mut runtime,
                    &injection,
                    &output,
                    plan.bytes().widths[output.source] as u32,
                    &reference.values[0].2,
                );
                if let Some(mut histogram) = histogram {
                    if category == 0 && counts[0] == 0 {
                        let prefix = (0..first)
                            .flat_map(|row| (0..shape.cols).map(move |column| sample(row, column)))
                            .collect::<Vec<_>>();
                        let prefix_input =
                            plan.upload_native_rows(&mut runtime, source, 0, &prefix).unwrap();
                        let (prefix_output, _) = plan
                            .prepare_native_nonlinear_step(
                                &mut runtime,
                                &tables,
                                index,
                                0,
                                first,
                                &prefix_input,
                                Some(&mut histogram),
                            )
                            .unwrap();
                        let mut visits = vec![0i64; 65535];
                        for row in 0..shape.rows {
                            for column in 0..shape.cols {
                                visits[(i32::from(sample(row, column)) + 32767) as usize] += 1;
                            }
                        }
                        let histogram = histogram.finish(&mut runtime).unwrap();
                        assert_eq!((histogram.rows, histogram.columns), (1, 65535));
                        check_nonlinear_words(&mut runtime, &injection, &histogram, 4, &visits);
                        histogram.release(&mut runtime).unwrap();
                        prefix_output.release(&mut runtime).unwrap();
                        prefix_input.release(&mut runtime).unwrap();
                    } else {
                        runtime.release_buffer(histogram.buffer).unwrap();
                    }
                }
                output.release(&mut runtime).unwrap();
                input.release(&mut runtime).unwrap();
                assert_eq!(runtime.stats().unwrap().live_capacity_bytes, baseline);
                counts[category] += 1;
            }
            assert_eq!(counts[0], 60);
            assert!(counts[1] > 60);
            assert_eq!(&counts[2..], &[1, 1]);
            eprintln!("C71_NONLINEAR_ROUTES slot={slot} counts={counts:?} gpu=false");
            tables.release(&mut runtime).unwrap();
            assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
            runtime.close().unwrap();
            if slot == 0 {
                let index =
                    plan.steps.iter().position(|step| matches!(step, Producer::Gelu(0))).unwrap();
                let source = plan.native_lookup_sources(index).unwrap().0;
                let columns = plan.bytes().scalar.layout.sources[source].cols;
                for case in 0..6 {
                    let mut runtime = Runtime::new(&fixture.config).unwrap();
                    let mut tables =
                        NonlinearTables::install(&mut runtime, &plan, &public).unwrap();
                    let mut input = plan
                        .upload_native_rows(&mut runtime, source, 0, &vec![1; columns])
                        .unwrap();
                    let mut histogram = plan.native_histogram(&mut runtime, index).unwrap();
                    match case {
                        2 => input.recipe[0] ^= 1,
                        3 => tables.old += 150,
                        4 => histogram.output += 1,
                        _ => (),
                    }
                    let result = if case == 0 {
                        histogram.finish(&mut runtime).map(|_| ())
                    } else {
                        if case == 1 {
                            let (output, _) = plan
                                .prepare_native_nonlinear_step(
                                    &mut runtime,
                                    &tables,
                                    index,
                                    0,
                                    1,
                                    &input,
                                    Some(&mut histogram),
                                )
                                .unwrap();
                            output.release(&mut runtime).unwrap();
                        }
                        plan.prepare_native_nonlinear_step(
                            &mut runtime,
                            &tables,
                            index,
                            0,
                            1,
                            &input,
                            if case == 5 { None } else { Some(&mut histogram) },
                        )
                        .map(|_| ())
                    };
                    assert!(result.is_err(), "canonical nonlinear rejection {case}");
                    assert_eq!(runtime.stats().unwrap().stopped, 1);
                    runtime.close().unwrap();
                }
            }
        }
    }

    fn gather_layout() -> bytes::Bytes {
        use crate::c71_matrix::gemma::{caller::Auxiliary, tiles, Source};
        let sources = (0..3)
            .map(|id| Source {
                name: format!("gather/{id}"),
                rows: 3,
                cols: 3,
                packed_offset: id * 9,
            })
            .collect::<Vec<_>>();
        let (tiles, live) = tiles(&sources);
        bytes::Bytes::new(
            Auxiliary {
                layout: Plan { sources, tiles, live, cohorts: Vec::new(), layout_digest: [11; 32] },
                weight_layout: [12; 32],
                input_sources: Vec::new(),
            },
            vec![6, 2, 4],
        )
        .unwrap()
    }

    fn gather_rows(
        runtime: &mut Runtime,
        b: &bytes::Bytes,
        id: usize,
        first: usize,
        values: &[i16],
    ) -> Rows {
        let input = runtime.upload_signed(values).unwrap();
        let raw = runtime
            .product(&input, 0, 0, DenseShape { m: (values.len() / 3) as u32, n: 3, k: 3 })
            .unwrap();
        runtime.release_buffer(input).unwrap();
        let buffer = if b.widths[id] == 2 {
            let y = runtime.quantize(&raw, 0).unwrap();
            runtime.release_buffer(raw).unwrap();
            y
        } else {
            raw
        };
        Rows {
            buffer,
            source: id,
            first,
            rows: values.len() / 3,
            columns: 3,
            layout: b.layout_digest,
            recipe: [7; 32],
        }
    }

    #[test]
    fn c71_canonical_resident_byte_windows_preserve_layout_and_order() {
        let f = fixture(512);
        let injection = Injection::new(&f.config);
        let b = gather_layout();
        let values = [-32767, -256, -1, 0, 1, 255, 256, 12345, 32767];
        let mut runtime = Runtime::new(&f.config).unwrap();
        runtime.install_weights(Arc::new(vec![1, 0, 0, 0, 1, 0, 0, 0, 1]), [12; 32]).unwrap();
        let blocks = [
            gather_rows(&mut runtime, &b, 0, 0, &values),
            gather_rows(&mut runtime, &b, 1, 2, &values[6..]),
            gather_rows(&mut runtime, &b, 1, 0, &values[..6]),
            gather_rows(&mut runtime, &b, 2, 0, &values),
        ];
        let mut original = vec![0u8; 128];
        for id in 0..3 {
            for row in 0..3 {
                let words =
                    values[row * 3..row * 3 + 3].iter().map(|&x| i64::from(x)).collect::<Vec<_>>();
                b.emit_row_bytes(id, row, &words, |i, x| {
                    original[i] = x;
                    Ok(())
                })
                .unwrap();
            }
        }
        let before = runtime.stats().unwrap();
        let alpha = Fp3::new(Fp::new(19), Fp::new(2), Fp::new(3));
        let mut windows = 0;
        for bottom in 0..=3 {
            for suffix in 0..=7 - bottom {
                for (first, length) in [(0, 128), (0, 32), (32, 32), (64, 32), (96, 32)] {
                    let reference =
                        bytes::RangeWindow::new(7, first, length, suffix, bottom).unwrap();
                    let mut expected = vec![0u8; length];
                    for (i, &x) in original.iter().enumerate() {
                        if let Some(j) = reference.offset(i) {
                            expected[j] = x;
                        }
                    }
                    let mut window = ByteWindow::new(
                        &mut runtime,
                        &b,
                        [7; 32],
                        7,
                        first,
                        length,
                        suffix,
                        bottom,
                    )
                    .unwrap();
                    let requested = window.sources().collect::<BTreeSet<_>>();
                    for block in blocks.iter().rev().filter(|b| requested.contains(&b.source)) {
                        window.append(&mut runtime, block).unwrap();
                    }
                    let sealed = window.finish(&mut runtime).unwrap();
                    // Root equality alone cannot catch a byte permutation.
                    injection.expect_bytes(&expected);
                    let signed = expected.iter().map(|&v| i16::from(v)).collect::<Vec<_>>();
                    assert_eq!(
                        runtime.root_check(&sealed, alpha).unwrap(),
                        expected_root(&signed, alpha)
                    );
                    runtime.release_buffer(sealed).unwrap();
                    assert_eq!(
                        runtime.stats().unwrap().live_capacity_bytes,
                        before.live_capacity_bytes
                    );
                    windows += 1;
                }
            }
        }
        let after = runtime.stats().unwrap();
        assert_eq!(after.h2d_bytes, before.h2d_bytes);
        assert_eq!(after.d2h_bytes - before.d2h_bytes, windows * 52); // sticky flag + scalar root only
        for block in blocks {
            block.release(&mut runtime).unwrap();
        }
        assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
        runtime.close().unwrap();
        eprintln!("C71_RESIDENT_BYTE_WINDOWS count={windows} codecs=6/2/4 max_bytes=128 exact_order=true intermediate_download_bytes=0 gpu=false");
    }

    #[test]
    fn c71_canonical_resident_byte_rejections_are_terminal() {
        let f = fixture(512);
        let b = gather_layout();
        for test in 0..9 {
            let mut runtime = Runtime::new(&f.config).unwrap();
            runtime.install_weights(Arc::new(vec![1, 0, 0, 0, 1, 0, 0, 0, 1]), [12; 32]).unwrap();
            let mut block = gather_rows(&mut runtime, &b, 1, 0, &[1; 9]);
            let mut window = ByteWindow::new(&mut runtime, &b, [7; 32], 7, 0, 128, 1, 1).unwrap();
            let injection = Injection::new(&f.config);
            match test {
                0 => block.layout[0] ^= 1,
                1 => block.recipe[0] ^= 1,
                2 => block.first = usize::MAX,
                3 => block.columns += 1,
                4 => block.source = 100,
                7 => injection.set(1),
                _ => (),
            }
            let result = if test == 5 {
                window.append(&mut runtime, &block).unwrap();
                window.append(&mut runtime, &block)
            } else if test == 6 {
                window.append(&mut runtime, &block).unwrap();
                window.finish(&mut runtime).map(|_| ())
            } else if test == 8 {
                runtime.root_check(&window.buffer, Fp3::ONE).map(|_| ())
            } else {
                window.append(&mut runtime, &block)
            };
            injection.set(0);
            assert!(result.is_err(), "byte rejection {test}");
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            assert!(runtime.byte_window(32).is_err());
            runtime.close().unwrap();
        }
        // Empty external padding may seal, but still must fence and check flag.
        for failure in [2, 4] {
            let mut runtime = Runtime::new(&f.config).unwrap();
            let window = ByteWindow::new(&mut runtime, &b, [7; 32], 8, 128, 128, 0, 0).unwrap();
            assert_eq!(window.sources().count(), 0);
            let injection = Injection::new(&f.config);
            injection.set(failure);
            assert!(window.finish(&mut runtime).is_err());
            injection.set(0);
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            runtime.close().unwrap();
        }
        eprintln!("C71_RESIDENT_BYTE_REJECTIONS count=11 terminal=true gpu=false");
    }

    fn weights(plan: &Plan) -> Arc<Vec<i16>> {
        let count = plan.sources.iter().map(|s| s.packed_offset + s.rows * s.cols).max().unwrap();
        Arc::new((0..count).map(|i| (i % 5) as i16 - 2).collect())
    }
    #[test]
    fn c71_canonical_resident_embedding_original_w_chain() {
        let f = fixture(512);
        let p = Profile::small(0).unwrap();
        let w = weights(&p.plan);
        let mut runtime = Runtime::new(&f.config).unwrap();
        install(&mut runtime, &p.plan, w.clone()).unwrap();
        let injection = Injection::new(&f.config);
        let alpha = Fp3::new(Fp::new(19), Fp::new(2), Fp::new(3));
        for (first, tokens) in [(0, vec![1, 0]), (0, vec![0, 0]), (1, vec![1])] {
            let before = runtime.stats().unwrap();
            let embedding =
                Rows::embedding(&mut runtime, &p.plan, p.bytes(), p.digest, &w, first, &tokens)
                    .unwrap();
            let after = runtime.stats().unwrap();
            assert_eq!(after.d2d_bytes - before.d2d_bytes, (tokens.len() * 2 * 2) as u64);
            assert_eq!(
                (after.h2d_bytes, after.d2h_bytes, after.launches),
                (before.h2d_bytes, before.d2h_bytes, before.launches)
            );
            assert_eq!(after.allocations - before.allocations, 1);
            let batch = prepare::EmbeddingBatch::new(&p.plan, p.bytes(), first, &tokens).unwrap();
            let expected = tokens
                .iter()
                .flat_map(|&t| {
                    w[batch.weight_offset + t as usize * 2
                        ..batch.weight_offset + t as usize * 2 + 2]
                        .iter()
                        .copied()
                })
                .collect::<Vec<_>>();
            let raw = Rows::pointwise(
                &mut runtime,
                p.bytes(),
                p.digest,
                &p.affine[0],
                false,
                first,
                tokens.len(),
                &[&embedding],
            )
            .unwrap();
            injection.expect_raw(&expected.iter().map(|&x| i64::from(x)).collect::<Vec<_>>());
            let output = raw
                .rne(&mut runtime, p.bytes(), p.digest, p.residual[0], first, tokens.len())
                .unwrap();
            assert_eq!(
                runtime.root_check(&output.buffer, alpha).unwrap(),
                expected_root(&expected, alpha)
            );
            raw.release(&mut runtime).unwrap();
            output.release(&mut runtime).unwrap();
            if tokens.len() == 2 {
                let mut addresses = Vec::new();
                let mut expected_bytes = Vec::new();
                for row in 0..2 {
                    let values = expected[row * 2..row * 2 + 2]
                        .iter()
                        .map(|&x| i64::from(x))
                        .collect::<Vec<_>>();
                    p.bytes()
                        .emit_row_bytes(0, row, &values, |i, v| {
                            addresses.push(i);
                            expected_bytes.push(v);
                            Ok(())
                        })
                        .unwrap();
                }
                assert!(addresses.windows(2).all(|a| a[1] == a[0] + 1));
                let mut window =
                    ByteWindow::new(&mut runtime, p.bytes(), p.digest, 12, addresses[0], 8, 0, 0)
                        .unwrap();
                assert_eq!(window.sources().collect::<Vec<_>>(), vec![0]);
                window.append(&mut runtime, &embedding).unwrap();
                let bytes = window.finish(&mut runtime).unwrap();
                injection.expect_bytes(&expected_bytes);
                let values = expected_bytes.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
                assert_eq!(
                    runtime.root_check(&bytes, alpha).unwrap(),
                    expected_root(&values, alpha)
                );
                runtime.release_buffer(bytes).unwrap();
            }
            embedding.release(&mut runtime).unwrap();
            assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
            assert_eq!(runtime.stats().unwrap().h2d_bytes, before.h2d_bytes);
        }
        assert_eq!(runtime.stats().unwrap().d2d_bytes, 20);
        runtime.close().unwrap();
        eprintln!("C71_RESIDENT_EMBEDDING batches=3 copied_bytes=20 h2d_after_W=0 kernels_for_embedding=0 exact_order=true gpu=false");
    }

    #[test]
    fn c71_canonical_resident_embedding_rejections_and_canonical_metadata() {
        let f = fixture(512);
        let p = Profile::small(0).unwrap();
        let w = weights(&p.plan);
        let injection = Injection::new(&f.config);
        for test in 0..8 {
            let mut runtime = Runtime::new(&f.config).unwrap();
            if test != 4 {
                install(&mut runtime, &p.plan, w.clone()).unwrap();
            }
            let mut tokens = vec![0, 1];
            let mut first = 0;
            let mut selected = w.clone();
            match test {
                0 => tokens.clear(),
                1 => tokens[1] = 2,
                2 => first = 1,
                3 => selected = Arc::new((*w).clone()),
                5 => injection.set(5),
                6 => injection.set(6),
                7 => injection.set(2),
                _ => (),
            }
            assert!(
                Rows::embedding(
                    &mut runtime,
                    &p.plan,
                    p.bytes(),
                    p.digest,
                    &selected,
                    first,
                    &tokens
                )
                .is_err(),
                "embedding rejection {test}"
            );
            injection.set(0);
            let stopped = runtime.stats().unwrap();
            assert_eq!(stopped.stopped, 1);
            assert_eq!(
                stopped.d2d_bytes,
                match test {
                    6 => 4,
                    7 => 8,
                    _ => 0,
                }
            );
            assert!(runtime.embedding(0, 2, 2, &[0]).is_err());
            assert_eq!(runtime.stats().unwrap().d2d_bytes, stopped.d2d_bytes);
            runtime.close().unwrap();
        }
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for layer in &softmax.layers {
            scales.insert(layer.pi, -14);
        }
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &scales).unwrap();
            for (first, tokens) in [(0, vec![262143; 150]), (149, vec![0])] {
                let batch =
                    prepare::EmbeddingBatch::new(&p.plan, p.bytes(), first, &tokens).unwrap();
                assert_eq!((batch.vocabulary, batch.columns), (262144, 5376));
                assert_eq!(
                    batch.weight_offset,
                    p.plan.sources[p.plan.cohorts[0].tensor].packed_offset
                );
            }
            let step = p.steps.iter().position(|s| matches!(s, Producer::Embedding)).unwrap();
            let mut runtime = Runtime::new(&f.config).unwrap();
            assert!(p
                .prepare_native_step(
                    &mut runtime,
                    &Arc::new(Vec::new()),
                    step,
                    149,
                    1,
                    &[262144],
                    &[]
                )
                .is_err());
            assert_eq!(runtime.stats().unwrap().allocations, 0);
            assert_eq!(runtime.stats().unwrap().d2d_bytes, 0);
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            runtime.close().unwrap();
        }
        eprintln!("C71_RESIDENT_EMBEDDING_REJECTIONS count=8 canonical_invalid_token_cases=3 canonical_geometry_only=true gpu=false");
    }
    #[test]
    fn c71_canonical_resident_pointwise_all_dispatch_routes() {
        let mut f = fixture(512);
        f.config.arena_bytes = 8 << 20;
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for layer in &softmax.layers {
            scales.insert(layer.pi, -14);
        }
        let injection = Injection::new(&f.config);
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &scales).unwrap();
            let b = p.bytes();
            let mut runtime = Runtime::new(&f.config).unwrap();
            let mut counts = [0, 0];
            for (index, step) in p.steps.iter().enumerate() {
                let (relation, multiply) = match step {
                    Producer::Affine(i) => (
                        bytes::affine::Relation {
                            raw: p.recipes.affine[*i].raw,
                            inputs: p.recipes.affine[*i].inputs,
                        },
                        false,
                    ),
                    Producer::Gate(i) => {
                        let gu = &p.sources.attention.rope.gate_up;
                        (
                            bytes::affine::Relation {
                                raw: gu.products[*i].raw,
                                inputs: [(gu.gelu.gelu[*i].output, 1), (gu.products[*i].up, 1)],
                            },
                            true,
                        )
                    }
                    _ => continue,
                };
                let shape = &b.scalar.layout.sources[relation.raw];
                let first = shape.rows - 1;
                assert!(first > 0);
                let value = |source: usize, row: usize, col: usize| {
                    ((source + row * 3 + col * 5) % 3) as i16 - 1
                };
                let mut operands = Vec::new();
                let mut reference = [vec![0i64; shape.cols], vec![0i64; shape.cols]];
                for (j, &(source, coefficient)) in relation.inputs.iter().enumerate() {
                    if coefficient == 0 {
                        continue;
                    }
                    let values = (first - 1..=first)
                        .flat_map(|r| (0..shape.cols).map(move |c| value(source, r, c)))
                        .collect::<Vec<_>>();
                    operands.push(
                        p.upload_native_rows(&mut runtime, source, first - 1, &values).unwrap(),
                    );
                    reference[j] =
                        (0..shape.cols).map(|c| i64::from(value(source, first, c))).collect();
                }
                let expected = if multiply {
                    reference[0]
                        .iter()
                        .zip(&reference[1])
                        .map(|(&x, &y)| (i128::from(x) * i128::from(y)) as i64)
                        .collect::<Vec<_>>()
                } else {
                    b.prepare_affine_row(&relation, [&reference[0], &reference[1]]).unwrap()
                };
                let refs = operands.iter().collect::<Vec<_>>();
                let before = runtime.stats().unwrap();
                let raw = p
                    .prepare_native_step(
                        &mut runtime,
                        &Arc::new(Vec::new()),
                        index,
                        first,
                        1,
                        &[],
                        &refs,
                    )
                    .unwrap();
                let rne = p
                    .steps
                    .iter()
                    .position(|s| matches!(s,Producer::Rne(pair) if pair.raw==relation.raw))
                    .unwrap();
                injection.expect_raw(&expected);
                let rounded = p
                    .prepare_native_step(
                        &mut runtime,
                        &Arc::new(Vec::new()),
                        rne,
                        first,
                        1,
                        &[],
                        &[&raw],
                    )
                    .unwrap();
                let after = runtime.stats().unwrap();
                assert_eq!(after.h2d_bytes, before.h2d_bytes);
                assert_eq!(after.d2h_bytes - before.d2h_bytes, 8);
                raw.release(&mut runtime).unwrap();
                rounded.release(&mut runtime).unwrap();
                for input in operands {
                    input.release(&mut runtime).unwrap();
                }
                assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
                counts[usize::from(multiply)] += 1;
            }
            assert_eq!(counts[1], 60);
            assert_eq!(counts[0], p.recipes.affine.len());
            assert_eq!(runtime.stats().unwrap().weights_bytes, 0);
            runtime.close().unwrap();
            eprintln!("C71_RESIDENT_POINTWISE slot={slot} affine={} gate={} selected_rows=1 exact_raw=true gpu=false",counts[0],counts[1]);
        }
    }

    #[test]
    fn c71_canonical_resident_pointwise_zero_terms_bounds_and_rejections() {
        let f = fixture(512);
        // Extend the existing ragged layout with a second ordinary i16 source.
        let b = gather_layout().append(vec![("pointwise/Y".into(), 3, 3, 2)]).unwrap();
        let mut runtime = Runtime::new(&f.config).unwrap();
        let x = Rows::upload(&mut runtime, &b, [7; 32], 1, 0, &[1, -2, 3, -4, 5, -6, 7, -8, 9])
            .unwrap();
        let y = Rows::upload(&mut runtime, &b, [7; 32], 3, 0, &[-9, 8, -7, 6, -5, 4, -3, 2, -1])
            .unwrap();
        let injection = Injection::new(&f.config);
        for (a, coefficient) in [(0, 0), (0, -2), (3, 0), (1 << 30, -(1 << 30))] {
            let relation = bytes::affine::Relation { raw: 0, inputs: [(1, a), (3, coefficient)] };
            let mut inputs = Vec::new();
            if a != 0 {
                inputs.push(&x);
            }
            if coefficient != 0 {
                inputs.push(&y);
            }
            let raw = Rows::pointwise(&mut runtime, &b, [7; 32], &relation, false, 1, 1, &inputs)
                .unwrap();
            let expected = [-4, 5, -6]
                .into_iter()
                .zip([6, -5, 4])
                .map(|(x, y)| a * x + coefficient * y)
                .collect::<Vec<_>>();
            injection.expect_raw(&expected);
            let output = runtime.quantize(&raw.buffer, 48).unwrap();
            runtime.release_buffer(output).unwrap();
            raw.release(&mut runtime).unwrap();
        }
        x.release(&mut runtime).unwrap();
        y.release(&mut runtime).unwrap();
        runtime.close().unwrap();
        for test in 0..12 {
            let mut runtime = Runtime::new(&f.config).unwrap();
            let mut x = Rows::upload(&mut runtime, &b, [7; 32], 1, 0, &[1; 9]).unwrap();
            let y = Rows::upload(&mut runtime, &b, [7; 32], 3, 0, &[1; 9]).unwrap();
            let mut relation = bytes::affine::Relation { raw: 0, inputs: [(1, 1), (3, 1)] };
            let mut first = 1;
            match test {
                0 => x.source = 3,
                1 => x.recipe[0] ^= 1,
                2 => x.layout[0] ^= 1,
                3 => x.first = 2,
                4 => relation.inputs[0].1 = 1 << 31,
                5 => first = usize::MAX,
                6 => relation.raw = 2, // i32, not raw i48
                9 => injection.set(1),
                10 => injection.set(2),
                11 => injection.set(4),
                _ => (),
            }
            let inputs = if test == 7 {
                vec![&x]
            } else if test == 8 {
                vec![&x, &y, &x]
            } else {
                vec![&x, &y]
            };
            assert!(
                Rows::pointwise(&mut runtime, &b, [7; 32], &relation, false, first, 1, &inputs)
                    .is_err(),
                "pointwise rejection {test}"
            );
            injection.set(0);
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            assert!(runtime.upload_signed(&[0]).is_err());
            runtime.close().unwrap();
        }
        eprintln!("C71_RESIDENT_POINTWISE_REJECTIONS count=12 terminal=true gpu=false");
    }
    fn expected_root(values: &[i16], alpha: Fp3) -> [Fp3; 2] {
        let denominators: Vec<_> = values.iter().map(|&x| alpha - signed(i64::from(x))).collect();
        let q = denominators.iter().fold(Fp3::ONE, |a, &b| a * b);
        let p = (0..values.len())
            .map(|i| {
                denominators
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .fold(Fp3::ONE, |a, (_, &b)| a * b)
            })
            .fold(Fp3::ZERO, |a, b| a + b);
        [p, q]
    }
    #[test]
    fn c71_canonical_resident_matrix_rne_original_owner_and_row_views() {
        let f = fixture(512);
        let p = Profile::small(0).unwrap();
        let w = weights(&p.plan);
        let raw = p.plan.cohorts.iter().position(|c| c.operation == "q_proj").unwrap();
        let pair = *p.matrix.iter().find(|pair| pair.raw == raw).unwrap();
        let batch = prepare::MatrixBatch::new(&p.plan, p.bytes(), raw, 0, 2).unwrap();
        let values = [1, 3, -2, 4];
        let mut runtime = Runtime::new(&f.config).unwrap();
        install(&mut runtime, &p.plan, w.clone()).unwrap();
        let input =
            Rows::upload(&mut runtime, p.bytes(), p.digest, batch.input, 0, &values).unwrap();
        let before = runtime.stats().unwrap();
        let alpha = Fp3::new(Fp::new(19), Fp::new(2), Fp::new(3));
        for (first, rows) in [(0, 2), (1, 1)] {
            let product = input
                .matrix(&mut runtime, &p.plan, p.bytes(), p.digest, &w, raw, first, rows)
                .unwrap();
            let rounded =
                product.rne(&mut runtime, p.bytes(), p.digest, pair, first, rows).unwrap();
            let expected: Vec<_> = (first..first + rows)
                .flat_map(|r| (0..2).map(move |j| (r, j)))
                .map(|(r, j)| {
                    let raw = (0..2)
                        .map(|k| {
                            i64::from(values[r * 2 + k])
                                * i64::from(w[batch.weight_offset + j * 2 + k])
                        })
                        .sum();
                    kernel::rne::integer(raw, pair.shift).unwrap()
                })
                .collect();
            assert_eq!(
                runtime.root_check(&rounded.buffer, alpha).unwrap(),
                expected_root(&expected, alpha)
            );
            assert_eq!(runtime.stats().unwrap().h2d_bytes, before.h2d_bytes);
            product.release(&mut runtime).unwrap();
            rounded.release(&mut runtime).unwrap();
            assert_eq!(runtime.stats().unwrap().live_capacity_bytes, before.live_capacity_bytes);
        }
        let after = runtime.stats().unwrap();
        assert_eq!(after.d2h_bytes - before.d2h_bytes, 112); // two flags and one scalar root per batch
        assert!(after.peak_capacity_bytes >= before.live_capacity_bytes + 3 * 256);
        input.release(&mut runtime).unwrap();
        assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
        let final_stats = runtime.close().unwrap();
        assert_eq!(final_stats.weights_bytes + final_stats.arena_bytes, 0);
        assert!(runtime.upload_signed(&values).is_err());
        eprintln!("C71_RESIDENT_BATCH rows=2/1 selected_first=0/1 W_words={} intermediate_download_bytes=0 gpu=false",w.len());
    }
    #[test]
    fn c71_canonical_resident_rejections_poison_the_shared_owner() {
        let f = fixture(512);
        let p = Profile::small(0).unwrap();
        let w = weights(&p.plan);
        let raw = p.plan.cohorts.iter().position(|c| c.operation == "q_proj").unwrap();
        let pair = *p.matrix.iter().find(|pair| pair.raw == raw).unwrap();
        let batch = prepare::MatrixBatch::new(&p.plan, p.bytes(), raw, 0, 2).unwrap();
        for test in 0..12 {
            let mut runtime = Runtime::new(&f.config).unwrap();
            install(&mut runtime, &p.plan, w.clone()).unwrap();
            let mut input =
                Rows::upload(&mut runtime, p.bytes(), p.digest, batch.input, 0, &[1, 3, -2, 4])
                    .unwrap();
            let injection = Injection::new(&f.config);
            let mut expected_w = w.clone();
            match test {
                0 => input.source += 1,
                1 => input.layout[0] ^= 1,
                2 => input.recipe[0] ^= 1,
                3 => input.first = 1,
                4 => expected_w = Arc::new((*w).clone()), // same bytes, wrong original owner
                5 => injection.set(1),
                6 => injection.set(2),
                7 => injection.set(4),
                _ => (),
            }
            let result = if test == 8 {
                Rows::upload(&mut runtime, p.bytes(), p.digest, batch.input, 2, &[1, 2])
            } else if test == 9 {
                Rows::upload(&mut runtime, p.bytes(), p.digest, batch.input, 0, &[i16::MIN, 0])
            } else {
                let product = input.matrix(
                    &mut runtime,
                    &p.plan,
                    p.bytes(),
                    p.digest,
                    &expected_w,
                    raw,
                    0,
                    2,
                );
                if test >= 10 {
                    let product = product.unwrap();
                    let pair = if test == 10 { Pair { shift: -15, ..pair } } else { pair };
                    product.rne(&mut runtime, p.bytes(), p.digest, pair, usize::from(test == 11), 2)
                } else {
                    product
                }
            };
            injection.set(0);
            assert!(result.is_err(), "rejection {test}");
            let stopped = runtime.stats().unwrap();
            assert_eq!(stopped.stopped, 1);
            assert!(runtime.upload_signed(&[1, 2]).is_err());
            let after = runtime.stats().unwrap();
            assert_eq!(
                (after.launches, after.allocations, after.h2d_bytes),
                (stopped.launches, stopped.allocations, stopped.h2d_bytes)
            );
            runtime.close().unwrap();
        }
        // The same Rust W owner does not make device buffers transferable.
        let mut owner = Runtime::new(&f.config).unwrap();
        let mut foreign = Runtime::new(&f.config).unwrap();
        install(&mut owner, &p.plan, w.clone()).unwrap();
        install(&mut foreign, &p.plan, w.clone()).unwrap();
        let input =
            Rows::upload(&mut owner, p.bytes(), p.digest, batch.input, 0, &[1, 3, -2, 4]).unwrap();
        assert!(input.matrix(&mut foreign, &p.plan, p.bytes(), p.digest, &w, raw, 0, 2).is_err());
        assert_eq!(foreign.stats().unwrap().stopped, 1);
        input.release(&mut owner).unwrap();
        owner.close().unwrap();
        foreign.close().unwrap();
        let mut short = Runtime::new(&f.config).unwrap();
        assert!(install(&mut short, &p.plan, Arc::new(vec![1, 2])).is_err());
        assert_eq!(short.stats().unwrap().stopped, 1);
        short.close().unwrap();
        eprintln!("C71_RESIDENT_REJECTIONS count=14 terminal=true gpu=false");
    }
    #[test]
    fn c71_canonical_resident_incomplete_producer_and_weights_fail_closed() {
        let f = fixture(512);
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
        let p = Canonical::compile(0, &[0; 772], &scales).unwrap();
        let mut runtime = Runtime::new(&f.config).unwrap();
        let window = p.native_byte_window(&mut runtime, (1 << 34) - 128, 128, 0, 0).unwrap();
        assert_eq!(window.sources().count(), 0);
        let padding = window.finish(&mut runtime).unwrap();
        Injection::new(&f.config).expect_bytes(&[0; 128]);
        let alpha = signed(13);
        assert_eq!(runtime.root_check(&padding, alpha).unwrap(), expected_root(&[0; 128], alpha));
        runtime.release_buffer(padding).unwrap();
        assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
        let launches = runtime.stats().unwrap().launches;
        let input = p.upload_native_rows(&mut runtime, 0, 149, &vec![1; 5376]).unwrap();
        let step = p.steps.iter().position(|step| matches!(step, Producer::Norm(_))).unwrap();
        assert_eq!(
            p.prepare_native_step(
                &mut runtime,
                &Arc::new(Vec::new()),
                step,
                149,
                1,
                &[],
                &[&input]
            )
            .err()
            .unwrap(),
            "canonical native producer not implemented"
        );
        assert_eq!(runtime.stats().unwrap().stopped, 1);
        assert_eq!(runtime.stats().unwrap().launches, launches);
        runtime.close().unwrap();
        let mut runtime = Runtime::new(&f.config).unwrap();
        assert!(p.install_native_weights(&mut runtime, Arc::new(vec![1, 2])).is_err());
        assert_eq!(runtime.stats().unwrap().weights_bytes, 0);
        assert_eq!(runtime.stats().unwrap().stopped, 1);
        runtime.close().unwrap();
    }
}

//! Original source blocks through the shared native owner. No host-output
//! download, transcript or CPU fallback. Full producer coverage remains open.
use super::*;
use kernel::range::windowed::native::{Buffer, DenseShape, Runtime};
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
        input: &Rows,
    ) -> Result<Rows, String> {
        match self.steps.get(step) {
            Some(Producer::Matrix(raw)) => input.matrix(
                runtime,
                &self.plan,
                self.bytes(),
                self.recipes.digest,
                weights,
                *raw,
                first,
                rows,
            ),
            Some(Producer::Rne(pair)) => {
                input.rne(runtime, self.bytes(), self.recipes.digest, *pair, first, rows)
            }
            _ => runtime.abort("canonical native producer not implemented"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::range::windowed::native::tests::{fixture, Injection};

    fn weights(plan: &Plan) -> Arc<Vec<i16>> {
        let count = plan.sources.iter().map(|s| s.packed_offset + s.rows * s.cols).max().unwrap();
        Arc::new((0..count).map(|i| (i % 5) as i16 - 2).collect())
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
        let input = p.upload_native_rows(&mut runtime, 0, 149, &vec![1; 5376]).unwrap();
        let step = p.steps.iter().position(|step| matches!(step, Producer::Embedding)).unwrap();
        assert_eq!(
            p.prepare_native_step(&mut runtime, &Arc::new(Vec::new()), step, 149, 1, &input)
                .err()
                .unwrap(),
            "canonical native producer not implemented"
        );
        assert_eq!(runtime.stats().unwrap().stopped, 1);
        assert_eq!(runtime.stats().unwrap().launches, 0);
        runtime.close().unwrap();
        let mut runtime = Runtime::new(&f.config).unwrap();
        assert!(p.install_native_weights(&mut runtime, Arc::new(vec![1, 2])).is_err());
        assert_eq!(runtime.stats().unwrap().weights_bytes, 0);
        assert_eq!(runtime.stats().unwrap().stopped, 1);
        runtime.close().unwrap();
    }
}

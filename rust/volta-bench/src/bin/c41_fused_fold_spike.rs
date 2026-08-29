use serde_json::json;
use std::error::Error;
use volta_accel::{Backend, Fp2Repr, Operation};
use volta_field::{Fp, Fp2};
use volta_proto::{c41_fold_typed_queries_reference, C41_TYPED_POLYNOMIAL_LANES};

const PRODUCTION_CELLS: usize = 3_110_400;
const ANCHOR_SECONDS: f64 = 4.104_595_717;
const GATE_RATIO: f64 = 1.30;

fn small_differential(backend: &mut Backend) -> Result<(), Box<dyn Error>> {
    let f = |x| Fp2::from_base(Fp::new(x));
    let query = [f(2), f(3), f(5)];
    let bitmap = [0b010u8];
    let mut a = Vec::new();
    let mut b = Vec::new();
    for lane in 0..C41_TYPED_POLYNOMIAL_LANES as u64 {
        a.extend([f(lane + 1), f(lane + 2), f(lane + 3)]);
        b.extend([f(2 * lane + 1), f(2 * lane + 2), f(2 * lane + 3)]);
    }
    let expected = c41_fold_typed_queries_reference(&a, &b, &query, &bitmap)?;
    let da = backend.upload_new_device(&a.iter().copied().map(Into::into).collect::<Vec<_>>())?;
    let db = backend.upload_new_device(&b.iter().copied().map(Into::into).collect::<Vec<_>>())?;
    let dq = backend.upload_new_device(&query.map(Fp2Repr::from))?;
    let de = backend.upload_new_device(&bitmap)?;
    let output = backend.c41_fold_typed_queries_device(&da, &db, &dq, &de, query.len())?;
    let got = backend.download_device(&output, 0, 24)?;
    let expected_raw =
        expected.a.into_iter().chain(expected.b).map(Fp2Repr::from).collect::<Vec<_>>();
    if got != expected_raw {
        return Err("C4.1 CUDA/reference differential mismatch".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let cells = args.next().map(|x| x.parse()).transpose()?.unwrap_or(PRODUCTION_CELLS);
    let samples: usize = args.next().map(|x| x.parse()).transpose()?.unwrap_or(7);
    if cells == 0 || samples == 0 || args.next().is_some() {
        return Err("usage: c41_fused_fold_spike [cells] [samples]".into());
    }

    let mut backend = Backend::cuda_resident()?;
    small_differential(&mut backend)?;

    let slab_len =
        C41_TYPED_POLYNOMIAL_LANES.checked_mul(cells).ok_or("C4.1 slab length overflow")?;
    let bitmap_len = cells.checked_add(7).ok_or("C4.1 bitmap length overflow")? / 8;
    let a = backend.alloc_device::<Fp2Repr>(slab_len)?;
    let b = backend.alloc_device::<Fp2Repr>(slab_len)?;
    let query = backend.alloc_device::<Fp2Repr>(cells)?;
    let bitmap = backend.alloc_device::<u8>(bitmap_len)?;
    let output = backend.alloc_device::<Fp2Repr>(24)?;
    backend.zero_device(&a, 0, a.len())?;
    backend.zero_device(&b, 0, b.len())?;
    backend.zero_device(&query, 0, query.len())?;
    backend.zero_device(&bitmap, 0, bitmap.len())?;
    backend.c41_fold_typed_queries_into_device(&a, &b, &query, &bitmap, cells, &output)?;
    backend.download_device(&output, 0, output.len())?;

    let mut kernel_ns = Vec::with_capacity(samples);
    let mut wall_ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        backend.begin_measurement()?;
        backend.c41_fold_typed_queries_into_device(&a, &b, &query, &bitmap, cells, &output)?;
        let stats = backend.finish_measurement()?;
        let auth = stats.operation(Operation::AuthMasks);
        if auth.calls != 1 {
            return Err("C4.1 spike did not record exactly one fused kernel".into());
        }
        kernel_ns.push(auth.kernel_ns);
        wall_ns.push(stats.measurement_wall_ns);
    }
    kernel_ns.sort_unstable();
    wall_ns.sort_unstable();
    let median_kernel_ns = kernel_ns[samples / 2];
    let median_wall_ns = wall_ns[samples / 2];
    let projected_ratio = (ANCHOR_SECONDS + median_wall_ns as f64 * 1e-9) / ANCHOR_SECONDS;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "c41-fused-fold-spike-v1",
            "credit": false,
            "cells": cells,
            "samples": samples,
            "setup_slab_bytes": 2 * slab_len * size_of::<Fp2Repr>(),
            "query_bytes": cells * size_of::<Fp2Repr>(),
            "correction_bitmap_bytes": bitmap_len,
            "median_kernel_ns": median_kernel_ns,
            "median_spike_wall_ns": median_wall_ns,
            "projected_additive_full_prover_ratio": projected_ratio,
            "analytic_spike_gate_pass": projected_ratio <= GATE_RATIO,
            "full_prover_gate_ratio": GATE_RATIO,
            "full_prover_gate": "pending paired full-prover measurement"
        }))?
    );
    Ok(())
}

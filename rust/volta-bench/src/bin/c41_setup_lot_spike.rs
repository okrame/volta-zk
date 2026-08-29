use serde_json::json;
use std::error::Error;
use std::time::Instant;
use volta_accel::{
    Backend, C41PackedProverDeviceLot, C41PackedVerifierDeviceLot, Fp2Repr, Operation,
};
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverSubAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_proto::c41_folded_tole::{
    c41_expand_packed_cells_reference, c41_expand_packed_keys_reference, c41_typed_setup_exchange,
    C41TypedSetupExchange, C41_BITS_PER_PACKED_CELL, C41_PRG_USABLE_BITS, C41_SEED_BITS,
};

const PRODUCTION_CELLS: usize = 3_110_400;
const PRODUCTION_SEED_ROWS: usize = 253;

fn setup(rows: usize) -> Result<C41TypedSetupExchange, Box<dyn Error>> {
    let delta = Fp2::new(Fp::new(0xC41), Fp::new(0xA100));
    let mut prover = CorrelationStream::new([0x71; 32]);
    let mut verifier = VerifierCtx::new([0x71; 32], delta);
    let mut prover_tx = Transcript::new([0x72; 32]);
    let mut verifier_tx = Transcript::new([0x72; 32]);
    Ok(c41_typed_setup_exchange(
        [0x73; 32],
        [0x74; 32],
        rows,
        0x4_1000,
        0x5_1000,
        &mut prover,
        &mut verifier,
        &mut prover_tx,
        &mut verifier_tx,
    )?)
}

fn prover_rows(exchange: &C41TypedSetupExchange) -> Vec<Vec<ProverSubAuthed>> {
    exchange
        .prover
        .bits
        .chunks_exact(C41_SEED_BITS)
        .zip(exchange.prover.tags.chunks_exact(C41_SEED_BITS))
        .map(|(bits, tags)| {
            bits.iter()
                .zip(tags)
                .map(|(&bit, &tag)| ProverSubAuthed::new(Fp::new(u64::from(bit)), tag))
                .collect()
        })
        .collect()
}

fn verifier_rows(exchange: &C41TypedSetupExchange) -> Vec<Vec<VerifierKey>> {
    exchange
        .verifier
        .keys
        .chunks_exact(C41_SEED_BITS)
        .map(|row| row.iter().copied().map(VerifierKey::new).collect())
        .collect()
}

fn upload_setup(
    backend: &mut Backend,
    exchange: &C41TypedSetupExchange,
) -> Result<
    (
        volta_accel::DeviceBuffer<u8>,
        volta_accel::DeviceBuffer<Fp2Repr>,
        volta_accel::DeviceBuffer<Fp2Repr>,
    ),
    Box<dyn Error>,
> {
    Ok((
        backend.upload_new_device(&exchange.prover.bits)?,
        backend.upload_new_device(
            &exchange.prover.tags.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
        )?,
        backend.upload_new_device(
            &exchange.verifier.keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
        )?,
    ))
}

fn free_prover_lot(
    backend: &mut Backend,
    lot: C41PackedProverDeviceLot,
) -> Result<(), Box<dyn Error>> {
    backend.free_device(lot.a)?;
    backend.free_device(lot.b)?;
    backend.free_device(lot.a_values)?;
    backend.free_device(lot.b_values)?;
    Ok(())
}

fn free_verifier_lot(
    backend: &mut Backend,
    lot: C41PackedVerifierDeviceLot,
) -> Result<(), Box<dyn Error>> {
    backend.free_device(lot.a_keys)?;
    backend.free_device(lot.b_keys)?;
    Ok(())
}

fn small_differential(backend: &mut Backend) -> Result<(), Box<dyn Error>> {
    let exchange = setup(2)?;
    let first = C41_PRG_USABLE_BITS - 9;
    let cells = 2;
    let expected_p =
        c41_expand_packed_cells_reference([0x74; 32], &prover_rows(&exchange), first, cells)?;
    let expected_v = c41_expand_packed_keys_reference(
        [0x74; 32],
        Fp2::new(Fp::new(0xC41), Fp::new(0xA100)),
        &verifier_rows(&exchange),
        first,
        cells,
    )?;
    let (bits, tags, keys) = upload_setup(backend, &exchange)?;
    let prover = backend.c41_expand_packed_prover_device(&bits, &tags, [0x74; 32], first, cells)?;
    let verifier = backend.c41_expand_packed_verifier_device(
        &keys,
        [0x74; 32],
        Fp2::new(Fp::new(0xC41), Fp::new(0xA100)),
        first,
        cells,
    )?;
    let got_a = backend.download_device(&prover.a, 0, prover.a.len())?;
    let got_b = backend.download_device(&prover.b, 0, prover.b.len())?;
    let got_av = backend.download_device(&prover.a_values, 0, cells)?;
    let got_bv = backend.download_device(&prover.b_values, 0, cells)?;
    let got_ak = backend.download_device(&verifier.a_keys, 0, cells)?;
    let got_bk = backend.download_device(&verifier.b_keys, 0, cells)?;
    let expected_bv = (0..cells)
        .map(|cell| (expected_p.b_bitmap[cell / 8] >> (cell % 8)) & 1)
        .collect::<Vec<_>>();
    if got_a != expected_p.a.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_b != expected_p.b.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_av != expected_p.a_values
        || got_bv != expected_bv
        || got_ak != expected_v.a_keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
        || got_bk != expected_v.b_keys.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>()
    {
        return Err("C4.1 setup CUDA/reference differential mismatch".into());
    }
    free_prover_lot(backend, prover)?;
    free_verifier_lot(backend, verifier)?;
    backend.free_device(bits)?;
    backend.free_device(tags)?;
    backend.free_device(keys)?;
    Ok(())
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let cells = args.next().map(|value| value.parse()).transpose()?.unwrap_or(PRODUCTION_CELLS);
    let samples: usize = args.next().map(|value| value.parse()).transpose()?.unwrap_or(3);
    let lot: usize = args.next().map(|value| value.parse()).transpose()?.unwrap_or(0);
    if cells == 0 || samples == 0 || lot >= 5 || args.next().is_some() {
        return Err("usage: c41_setup_lot_spike [cells] [samples] [lot:0..4]".into());
    }
    let first_global_bit = lot
        .checked_mul(cells)
        .and_then(|value| value.checked_mul(C41_BITS_PER_PACKED_CELL))
        .ok_or("C4.1 lot offset overflow")?;
    if first_global_bit + cells * C41_BITS_PER_PACKED_CELL
        > PRODUCTION_SEED_ROWS * C41_PRG_USABLE_BITS
    {
        return Err("C4.1 requested lot exceeds the five-response seed inventory".into());
    }

    let mut backend = Backend::cuda_resident()?;
    small_differential(&mut backend)?;
    let setup_started = Instant::now();
    let exchange = setup(PRODUCTION_SEED_ROWS)?;
    let seed_auth_wall_ns = setup_started.elapsed().as_nanos() as u64;
    let (bits, tags, keys) = upload_setup(&mut backend, &exchange)?;

    let mut prover_kernel_ns = Vec::with_capacity(samples);
    let mut prover_wall_ns = Vec::with_capacity(samples);
    let mut verifier_kernel_ns = Vec::with_capacity(samples);
    let mut verifier_wall_ns = Vec::with_capacity(samples);
    let mut final_prover = None;
    let mut final_verifier = None;
    for sample in 0..samples {
        backend.begin_measurement()?;
        let prover = backend.c41_expand_packed_prover_device(
            &bits,
            &tags,
            [0x74; 32],
            first_global_bit,
            cells,
        )?;
        let _ = backend.download_device(&prover.a_values, 0, 1)?;
        let stats = backend.finish_measurement()?;
        let auth = stats.operation(Operation::AuthMasks);
        if auth.calls != 1 {
            return Err("C4.1 prover lot expansion did not record one CUDA call".into());
        }
        prover_kernel_ns.push(auth.kernel_ns);
        prover_wall_ns.push(stats.measurement_wall_ns);

        backend.begin_measurement()?;
        let verifier = backend.c41_expand_packed_verifier_device(
            &keys,
            [0x74; 32],
            Fp2::new(Fp::new(0xC41), Fp::new(0xA100)),
            first_global_bit,
            cells,
        )?;
        let _ = backend.download_device(&verifier.a_keys, 0, 1)?;
        let stats = backend.finish_measurement()?;
        let auth = stats.operation(Operation::AuthMasks);
        if auth.calls != 1 {
            return Err("C4.1 verifier lot expansion did not record one CUDA call".into());
        }
        verifier_kernel_ns.push(auth.kernel_ns);
        verifier_wall_ns.push(stats.measurement_wall_ns);

        if sample + 1 == samples {
            final_prover = Some(prover);
            final_verifier = Some(verifier);
        } else {
            free_prover_lot(&mut backend, prover)?;
            free_verifier_lot(&mut backend, verifier)?;
        }
    }
    let prover_kernel_median_ns = median(&mut prover_kernel_ns);
    let prover_wall_median_ns = median(&mut prover_wall_ns);
    let verifier_kernel_median_ns = median(&mut verifier_kernel_ns);
    let verifier_wall_median_ns = median(&mut verifier_wall_ns);
    let memory = backend.stats()?;
    let proof = exchange.proof.encode()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "c41-setup-lot-spike-v1",
            "credit": false,
            "cuda_abi": volta_accel::CUDA_ABI_VERSION,
            "cells": cells,
            "samples": samples,
            "lot": lot,
            "seed_rows": PRODUCTION_SEED_ROWS,
            "authenticated_seed_bits": exchange.prover.bits.len(),
            "typed_setup_proof_bytes": proof.len(),
            "typed_setup_prover_to_verifier_bytes": exchange.metrics.prover_to_verifier_bytes,
            "typed_setup_verifier_to_prover_bytes": exchange.metrics.verifier_to_prover_bytes,
            "typed_setup_total_bytes": exchange.metrics.total_typed_setup_bytes,
            "seed_auth_and_bitness_wall_ns": seed_auth_wall_ns,
            "prover_lot_kernel_median_ns": prover_kernel_median_ns,
            "prover_lot_wall_median_ns": prover_wall_median_ns,
            "prover_lots_per_second": 1e9f64 / prover_wall_median_ns as f64,
            "verifier_lot_kernel_median_ns": verifier_kernel_median_ns,
            "verifier_lot_wall_median_ns": verifier_wall_median_ns,
            "verifier_lots_per_second": 1e9f64 / verifier_wall_median_ns as f64,
            "prover_slab_bytes": 2 * 12 * cells * size_of::<Fp2Repr>(),
            "prover_plaintext_mask_bytes": cells * (size_of::<u16>() + size_of::<u8>()),
            "verifier_key_bytes": 2 * cells * size_of::<Fp2Repr>(),
            "peak_device_bytes": memory.peak_device_bytes,
            "conditional_soundness_bits": exchange.metrics.conditional_soundness_bits,
            "conditional_weight_zk_bits": exchange.metrics.conditional_weight_zk_bits,
            "small_nonzero_cpu_cuda_differential": true
        }))?
    );

    free_prover_lot(&mut backend, final_prover.expect("one sample"))?;
    free_verifier_lot(&mut backend, final_verifier.expect("one sample"))?;
    backend.free_device(bits)?;
    backend.free_device(tags)?;
    backend.free_device(keys)?;
    Ok(())
}

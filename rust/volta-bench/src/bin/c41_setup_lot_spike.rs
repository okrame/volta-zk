use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::error::Error;
use std::path::Path;
use std::time::Instant;
use volta_accel::{
    Backend, C41PackedProverDeviceLot, C41PackedVerifierDeviceLot, Fp2Repr, Operation,
};
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverSubAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcg::{
    expand_phase_b_production, PhaseAParams, ResponseAuthorizationStore, SessionBinding,
};
use volta_proto::c41_folded_tole::{
    c41_expand_packed_cells_reference, c41_expand_packed_keys_reference, c41_typed_setup_exchange,
    C41TypedSetupExchange, C41_BITS_PER_PACKED_CELL, C41_PRG_USABLE_BITS, C41_SEED_BITS,
};

const PRODUCTION_CELLS: usize = 3_110_400;
const PRODUCTION_SEED_ROWS: usize = 253;
const C4_SETUP_BYTES: u64 = 38_371_465;

struct SetupRun {
    exchange: C41TypedSetupExchange,
    public_seed: [u8; 32],
    delta: Fp2,
    typed_setup_wall_ns: u64,
    real_pcg: Option<Value>,
}

fn random_identity() -> Result<[u8; 32], Box<dyn Error>> {
    let mut value = [0u8; 32];
    OsRng.try_fill_bytes(&mut value)?;
    if value == [0; 32] {
        return Err("OS entropy returned a zero C4.1 identity".into());
    }
    Ok(value)
}

fn setup_mock(rows: usize) -> Result<SetupRun, Box<dyn Error>> {
    let delta = Fp2::new(Fp::new(0xC41), Fp::new(0xA100));
    let public_seed = [0x74; 32];
    let mut prover = CorrelationStream::new([0x71; 32]);
    let mut verifier = VerifierCtx::new([0x71; 32], delta);
    let mut prover_tx = Transcript::new([0x72; 32]);
    let mut verifier_tx = Transcript::new([0x72; 32]);
    let started = Instant::now();
    let exchange = c41_typed_setup_exchange(
        [0x73; 32],
        public_seed,
        rows,
        0x4_1000,
        0x5_1000,
        &mut prover,
        &mut verifier,
        &mut prover_tx,
        &mut verifier_tx,
    )?;
    Ok(SetupRun {
        exchange,
        public_seed,
        delta,
        typed_setup_wall_ns: started.elapsed().as_nanos() as u64,
        real_pcg: None,
    })
}

fn setup_real(rows: usize, store_path: &Path) -> Result<SetupRun, Box<dyn Error>> {
    let sub_corrs = rows.checked_mul(C41_SEED_BITS).ok_or("C4.1 real-PCG count overflow")?;
    let store = ResponseAuthorizationStore::new(store_path)?;
    let binding = SessionBinding::new(random_identity()?, random_identity()?, random_identity()?)?;
    let started = Instant::now();
    let production = expand_phase_b_production(
        &store,
        binding,
        sub_corrs,
        1,
        PhaseAParams::for_counts(sub_corrs, 1),
    )?;
    let setup_wall_ns = started.elapsed().as_nanos() as u64;
    let comm = &production.expansion.setup.comm;
    let timings = production.expansion.timings;
    let audit = &production.production;
    let real_pcg = json!({
        "backend": "real/AES-128-MMO",
        "setup_wall_ns": setup_wall_ns,
        "setup_comm_total_bytes": comm.total_bytes,
        "setup_comm_prover_to_verifier_bytes": comm.prover_to_verifier_bytes,
        "setup_comm_verifier_to_prover_bytes": comm.verifier_to_prover_bytes,
        "setup_comm_base_ot_bytes": comm.base_ot_bytes,
        "setup_comm_ot_extension_bytes": comm.ot_extension_bytes,
        "setup_comm_ggm_bytes": comm.ggm_bytes,
        "setup_comm_consistency_bytes": comm.consistency_bytes,
        "base_ot_wall_s": timings.t_base_ot_s,
        "ot_extension_wall_s": timings.t_ot_extension_s,
        "base_vole_wall_s": timings.t_base_vole_from_setup_s,
        "ggm_pprf_wall_s": timings.t_ggm_pprf_s,
        "lpn_expand_wall_s": timings.t_lpn_expand_s,
        "full_combine_wall_s": timings.t_full_combine_s,
        "consistency_check_wall_s": timings.t_consistency_check_s,
        "total_setup_and_expansion_wall_s": timings.t_total_setup_and_expansion_s,
        "independent_role_entropy_samples": audit.independent_role_entropy_samples,
        "role_seed_commitments_distinct": audit.role_seed_commitments_distinct,
        "session_channel_identity_bound": audit.session_channel_identity_bound,
        "authorization_burned_before_setup": audit.response_authorization_burned_before_setup,
        "reconnect_retry_resume_allowed": audit.reconnect_retry_resume_allowed,
    });
    let delta = production.expansion.verifier_delta;
    let public_seed = random_identity()?;
    let secret_entropy = random_identity()?;
    let mut prover = CorrelationStream::from_pcg_pool(production.expansion.prover);
    let mut verifier = VerifierCtx::from_pcg_pool(delta, production.expansion.verifier);
    let transcript_seed = random_identity()?;
    let mut prover_tx = Transcript::new(transcript_seed);
    let mut verifier_tx = Transcript::new(transcript_seed);
    let started = Instant::now();
    let exchange = c41_typed_setup_exchange(
        secret_entropy,
        public_seed,
        rows,
        0x4_1000,
        0x5_1000,
        &mut prover,
        &mut verifier,
        &mut prover_tx,
        &mut verifier_tx,
    )?;
    Ok(SetupRun {
        exchange,
        public_seed,
        delta,
        typed_setup_wall_ns: started.elapsed().as_nanos() as u64,
        real_pcg: Some(real_pcg),
    })
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
    let run = setup_mock(2)?;
    let exchange = &run.exchange;
    let first = C41_PRG_USABLE_BITS - 9;
    let cells = 2;
    let expected_p =
        c41_expand_packed_cells_reference(run.public_seed, &prover_rows(exchange), first, cells)?;
    let expected_v = c41_expand_packed_keys_reference(
        run.public_seed,
        run.delta,
        &verifier_rows(exchange),
        first,
        cells,
    )?;
    let (bits, tags, keys) = upload_setup(backend, exchange)?;
    let prover =
        backend.c41_expand_packed_prover_device(&bits, &tags, run.public_seed, first, cells)?;
    let verifier = backend.c41_expand_packed_verifier_device(
        &keys,
        run.public_seed,
        run.delta,
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
    let setup_run = match std::env::var_os("VOLTA_C41_REAL_PCG_STORE") {
        Some(path) => setup_real(PRODUCTION_SEED_ROWS, Path::new(&path))?,
        None => setup_mock(PRODUCTION_SEED_ROWS)?,
    };
    let exchange = &setup_run.exchange;
    let seed_auth_wall_ns = setup_run.typed_setup_wall_ns;
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
            setup_run.public_seed,
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
            setup_run.public_seed,
            setup_run.delta,
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
    let combined_c4_and_typed_setup_bytes = setup_run.real_pcg.as_ref().map(|pcg| {
        C4_SETUP_BYTES
            + pcg["setup_comm_total_bytes"].as_u64().expect("real-PCG byte count")
            + exchange.metrics.total_typed_setup_bytes
    });
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
            "small_nonzero_cpu_cuda_differential": true,
            "real_pcg": setup_run.real_pcg,
            "combined_c4_and_typed_setup_bytes": combined_c4_and_typed_setup_bytes
        }))?
    );

    free_prover_lot(&mut backend, final_prover.expect("one sample"))?;
    free_verifier_lot(&mut backend, final_verifier.expect("one sample"))?;
    backend.free_device(bits)?;
    backend.free_device(tags)?;
    backend.free_device(keys)?;
    Ok(())
}

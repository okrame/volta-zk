#![cfg(feature = "cuda")]

use volta_accel::{AccelError, Backend, DeviceSlice, Operation};
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::{
    commit, commit_resident, commit_resident_from_device, commit_with_backend,
    free_resident_matrix, open_multi_zk, open_multi_zk_resident, open_multi_zk_with_backend,
    verify_multi_open, BlockClaim, LigeroParams, ResidentWeightPlacement,
};
use volta_proto::mle::eval_mle;

const PARAMS: LigeroParams =
    LigeroParams { rows: 1 << 5, col_bits: 5, pad: 8, code_bits: 6, n_queries: 8 };

fn cuda() -> Option<Backend> {
    match Backend::cuda_hybrid() {
        Ok(gpu) => Some(gpu),
        Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
            eprintln!("skipping CUDA PCS differential: {e}");
            None
        }
        Err(e) => panic!("CUDA required: {e}"),
    }
}

fn cuda_resident() -> Option<Backend> {
    match Backend::cuda_resident() {
        Ok(gpu) => Some(gpu),
        Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
            eprintln!("skipping resident CUDA PCS differential: {e}");
            None
        }
        Err(e) => panic!("CUDA required: {e}"),
    }
}

#[test]
fn cuda_commit_and_multi_open_match_cpu_and_fault_rejects() {
    let Some(mut gpu) = cuda() else { return };
    let w: Vec<i16> =
        (0..1 << PARAMS.n_vars()).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
    let pad_seed = [0x61; 32];
    let (cpu_commitment, cpu_pm) = commit(&w, &PARAMS, pad_seed);
    gpu.begin_measurement().unwrap();
    let (gpu_commitment, gpu_pm) = commit_with_backend(&w, &PARAMS, pad_seed, &mut gpu).unwrap();
    assert_eq!(gpu_commitment.root, cpu_commitment.root);

    let mut points = FpStream::domain_separated([0x62; 32], 17);
    let embedded: Vec<Fp2> = w.iter().map(|&x| Fp2::from_base(Fp::from_i64(x as i64))).collect();
    let claims: Vec<(BlockClaim, ProverAuthed)> = (0..3)
        .map(|_| {
            let point: Vec<Fp2> = (0..PARAMS.n_vars()).map(|_| points.next_fp2()).collect();
            let value = eval_mle(&embedded, &point);
            (BlockClaim { offset: 0, point }, ProverAuthed::from_public(value))
        })
        .collect();

    let pcg_seed = [0x63; 32];
    let tx_seed = [0x64; 32];
    let mut cpu_stream = CorrelationStream::new(pcg_seed);
    let mut cpu_tx = Transcript::new(tx_seed);
    let (cpu_proof, _cpu_tm) = open_multi_zk(
        &w,
        &cpu_pm,
        &claims,
        &mut cpu_stream,
        0x6500,
        0x6501,
        [0x65; 32],
        &mut cpu_tx,
    );
    let mut gpu_stream = CorrelationStream::new(pcg_seed);
    let mut gpu_tx = Transcript::new(tx_seed);
    let (mut gpu_proof, _gpu_tm) = open_multi_zk_with_backend(
        &w,
        &gpu_pm,
        &claims,
        &mut gpu_stream,
        0x6500,
        0x6501,
        [0x65; 32],
        &mut gpu_tx,
        &mut gpu,
    )
    .unwrap();
    assert_eq!(gpu_proof, cpu_proof);
    assert_eq!(gpu_stream.counters, cpu_stream.counters);
    assert_eq!(gpu_tx.ledger(), cpu_tx.ledger());

    let delta = Fp2::new(Fp::new(31337), Fp::new(271828));
    let claims_v: Vec<_> =
        claims.iter().map(|(c, v)| (c.clone(), VerifierKey::from_public(v.x, delta))).collect();
    let mut ctx = VerifierCtx::new(pcg_seed, delta);
    let mut txv = Transcript::new(tx_seed);
    assert!(verify_multi_open(
        &gpu_commitment.root,
        &PARAMS,
        &claims_v,
        &gpu_proof,
        &mut ctx,
        0x6500,
        0x6501,
        &mut txv,
    ));

    gpu_proof.columns[0].col[0] += Fp::ONE;
    let mut bad_ctx = VerifierCtx::new(pcg_seed, delta);
    let mut bad_tx = Transcript::new(tx_seed);
    assert!(!verify_multi_open(
        &gpu_commitment.root,
        &PARAMS,
        &claims_v,
        &gpu_proof,
        &mut bad_ctx,
        0x6500,
        0x6501,
        &mut bad_tx,
    ));

    let stats = gpu.finish_measurement().unwrap();
    assert!(stats.operation(Operation::PcsNtt).calls > 0);
    assert!(stats.operation(Operation::PcsRows).calls > 0);
    assert!(stats.operation(Operation::PcsMerkle).calls > 0);
    assert!(stats.cpu_residual_ns() > 0);
}

#[test]
fn session_fresh_mask_seed_changes_proof_but_not_size_or_validity() {
    let w: Vec<i16> =
        (0..1 << PARAMS.n_vars()).map(|i| ((i * 41 + 19) % 4001) as i16 - 2000).collect();
    let (commitment, pm) = commit(&w, &PARAMS, [0x66; 32]);
    let embedded: Vec<Fp2> = w.iter().map(|&x| Fp2::from_base(Fp::from_i64(x as i64))).collect();
    let mut points = FpStream::domain_separated([0x67; 32], 9);
    let claims: Vec<(BlockClaim, ProverAuthed)> = (0..3)
        .map(|_| {
            let point: Vec<Fp2> = (0..PARAMS.n_vars()).map(|_| points.next_fp2()).collect();
            let value = eval_mle(&embedded, &point);
            (BlockClaim { offset: 0, point }, ProverAuthed::from_public(value))
        })
        .collect();
    let pcg_seed = [0x68; 32];
    let tx_seed = [0x69; 32];
    let session_mask_seed = |session: u8| {
        let role = 0x44;
        let mut mask_seed = [role; 32];
        mask_seed[29] = session;
        mask_seed[30] = role;
        mask_seed[31] = 7;
        mask_seed
    };
    let open = |mask_seed| {
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let (proof, _) =
            open_multi_zk(&w, &pm, &claims, &mut stream, 0x6900, 0x6901, mask_seed, &mut tx);
        (proof, tx.ledger().clone())
    };
    let (proof_a, ledger_a) = open(session_mask_seed(0x40));
    let (proof_b, ledger_b) = open(session_mask_seed(0x41));

    assert_ne!(proof_a.mask_root, proof_b.mask_root);
    assert_ne!(proof_a, proof_b);
    assert_eq!(proof_a.bytes(), proof_b.bytes());
    assert_eq!(ledger_a, ledger_b);

    let delta = Fp2::new(Fp::new(31337), Fp::new(271828));
    let claims_v: Vec<_> =
        claims.iter().map(|(c, v)| (c.clone(), VerifierKey::from_public(v.x, delta))).collect();
    for proof in [&proof_a, &proof_b] {
        let mut ctx = VerifierCtx::new(pcg_seed, delta);
        let mut tx = Transcript::new(tx_seed);
        assert!(verify_multi_open(
            &commitment.root,
            &PARAMS,
            &claims_v,
            proof,
            &mut ctx,
            0x6900,
            0x6901,
            &mut tx,
        ));
    }
}

#[test]
fn cuda_resident_commit_and_open_match_cpu_without_state_leak() {
    let Some(mut gpu) = cuda_resident() else { return };
    let resident_bytes_before = gpu.device_memory_breakdown().unwrap().resident_bytes;
    let w: Vec<i16> =
        (0..1 << PARAMS.n_vars()).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
    let pad_seed = [0x71; 32];
    let (cpu_commitment, cpu_pm) = commit(&w, &PARAMS, pad_seed);

    let mut points = FpStream::domain_separated([0x72; 32], 17);
    let embedded: Vec<Fp2> = w.iter().map(|&x| Fp2::from_base(Fp::from_i64(x as i64))).collect();
    let claims: Vec<(BlockClaim, ProverAuthed)> = (0..3)
        .map(|_| {
            let point: Vec<Fp2> = (0..PARAMS.n_vars()).map(|_| points.next_fp2()).collect();
            let value = eval_mle(&embedded, &point);
            (BlockClaim { offset: 0, point }, ProverAuthed::from_public(value))
        })
        .collect();
    let pcg_seed = [0x73; 32];
    let tx_seed = [0x74; 32];
    let mask_seed = [0x75; 32];
    let mut cpu_stream = CorrelationStream::new(pcg_seed);
    let mut cpu_tx = Transcript::new(tx_seed);
    let (cpu_proof, _) = open_multi_zk(
        &w,
        &cpu_pm,
        &claims,
        &mut cpu_stream,
        0x7500,
        0x7501,
        mask_seed,
        &mut cpu_tx,
    );

    let source = gpu.upload_new_device(&w).unwrap();
    let placement = ResidentWeightPlacement::new(
        DeviceSlice::new(&source, 0, w.len()).unwrap(),
        PARAMS.rows(),
        PARAMS.cols(),
        0,
        PARAMS.cols(),
        PARAMS.rows() * PARAMS.cols(),
    )
    .unwrap();
    gpu.begin_measurement().unwrap();
    let (commitment, pm) =
        commit_resident_from_device(&[placement], &PARAMS, pad_seed, &mut gpu).unwrap();
    assert_eq!(commitment.root, cpu_commitment.root);
    let commit_stats = gpu.finish_measurement().unwrap();
    // A cold context uploads only the public NTT twiddle table. Weight and
    // pad payloads remain D2D/device-generated.
    let expected_twiddle_h2d = (PARAMS.code_len() / 2 * std::mem::size_of::<u64>()) as u64;
    assert_eq!(commit_stats.h2d_bytes, expected_twiddle_h2d);
    assert_eq!(commit_stats.explicit_d2d_copy_bytes, (w.len() * std::mem::size_of::<i16>()) as u64);
    assert_eq!(commit_stats.device_zeroed_bytes, (w.len() * std::mem::size_of::<i16>()) as u64);
    assert_eq!(
        commit_stats.device_generated_bytes,
        (PARAMS.rows() * PARAMS.pad * std::mem::size_of::<u64>()) as u64
    );
    gpu.begin_measurement().unwrap();

    // Inject a practical mid-opening failure: the transient mask commitment
    // is built in `foreign`, then the first PCS row pass rejects `pm` because
    // its persistent buffers belong to `gpu`. Every transient foreign handle
    // must be reclaimed by the opening guard.
    let mut foreign = Backend::cuda_resident()
        .expect("a second resident context must be available for injection");
    let foreign_bytes_before = foreign.device_memory_breakdown().unwrap().resident_bytes;
    let wrong_context_commit =
        match commit_resident_from_device(&[placement], &PARAMS, pad_seed, &mut foreign) {
            Ok(_) => panic!("cross-context resident commitment unexpectedly succeeded"),
            Err(error) => error,
        };
    assert!(matches!(
        wrong_context_commit,
        AccelError::InvalidInput("resident weight placement belongs to a different CUDA context")
    ));
    assert_eq!(
        foreign.device_memory_breakdown().unwrap().resident_bytes,
        foreign_bytes_before,
        "wrong-context resident commitment allocated target state"
    );
    gpu.free_device(source).unwrap();
    let mut failed_stream = CorrelationStream::new(pcg_seed);
    let mut failed_tx = Transcript::new(tx_seed);
    let error = match open_multi_zk_resident(
        &pm,
        &claims,
        &mut failed_stream,
        0x7500,
        0x7501,
        mask_seed,
        &mut failed_tx,
        &mut foreign,
    ) {
        Ok(_) => panic!("cross-context resident opening unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AccelError::InvalidInput("device buffer belongs to a different CUDA context")
    ));
    assert_eq!(
        foreign.device_memory_breakdown().unwrap().resident_bytes,
        foreign_bytes_before,
        "failed resident opening leaked transient buffers"
    );

    let run = |gpu: &mut Backend| {
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let (proof, timings) = open_multi_zk_resident(
            &pm,
            &claims,
            &mut stream,
            0x7500,
            0x7501,
            mask_seed,
            &mut tx,
            gpu,
        )
        .unwrap();
        (proof, timings, stream.counters, tx.ledger().clone())
    };
    let (proof, _timings, counters, ledger) = run(&mut gpu);
    assert_eq!(proof, cpu_proof);
    assert_eq!(counters, cpu_stream.counters);
    assert_eq!(ledger, *cpu_tx.ledger());
    let live_after_first = gpu.stats().unwrap().live_device_bytes;
    let (proof_reused, _, counters_reused, ledger_reused) = run(&mut gpu);
    assert_eq!(proof_reused, cpu_proof);
    assert_eq!(counters_reused, cpu_stream.counters);
    assert_eq!(ledger_reused, *cpu_tx.ledger());
    assert_eq!(
        gpu.stats().unwrap().live_device_bytes,
        live_after_first,
        "resident PCS leaked between openings"
    );

    let delta = Fp2::new(Fp::new(31337), Fp::new(271828));
    let claims_v: Vec<_> =
        claims.iter().map(|(c, v)| (c.clone(), VerifierKey::from_public(v.x, delta))).collect();
    let mut ctx = VerifierCtx::new(pcg_seed, delta);
    let mut txv = Transcript::new(tx_seed);
    assert!(verify_multi_open(
        &commitment.root,
        &PARAMS,
        &claims_v,
        &proof,
        &mut ctx,
        0x7500,
        0x7501,
        &mut txv,
    ));
    let mut faulted = proof_reused;
    faulted.columns[0].col[0] += Fp::ONE;
    let mut bad_ctx = VerifierCtx::new(pcg_seed, delta);
    let mut bad_tx = Transcript::new(tx_seed);
    assert!(!verify_multi_open(
        &commitment.root,
        &PARAMS,
        &claims_v,
        &faulted,
        &mut bad_ctx,
        0x7500,
        0x7501,
        &mut bad_tx,
    ));

    let wrong_owner_error = free_resident_matrix(pm, &mut foreign).unwrap_err();
    assert!(matches!(
        &wrong_owner_error,
        volta_pcs::ResidentMatrixFreeError::WrongBackend {
            error: AccelError::InvalidInput(
                "resident prover matrix belongs to a different CUDA context"
            ),
            ..
        }
    ));
    let pm = wrong_owner_error
        .into_matrix()
        .expect("wrong-context preflight must preserve matrix ownership");
    free_resident_matrix(pm, &mut gpu).unwrap();
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        resident_bytes_before,
        "resident commitment teardown did not return to its baseline"
    );
    let stats = gpu.finish_measurement().unwrap();
    assert!(stats.operation(Operation::PcsNtt).calls > 0);
    assert!(stats.operation(Operation::PcsRows).calls > 0);
    assert!(stats.operation(Operation::PcsMerkle).calls > 0);
    assert_eq!(stats.operation_cpu_residual_ns(), 0);
}

#[test]
fn cuda_resident_device_placements_pack_exact_rows_and_reject_overlap() {
    let Some(mut gpu) = cuda_resident() else { return };
    let params = LigeroParams { rows: 1 << 3, col_bits: 3, pad: 2, code_bits: 4, n_queries: 2 };
    let resident_bytes_before = gpu.device_memory_breakdown().unwrap().resident_bytes;
    let a: Vec<i16> = (1..=9).collect();
    let b: Vec<i16> = (101..=104).collect();
    let mut source_host = vec![-901, -902];
    let a_offset = source_host.len();
    source_host.extend_from_slice(&a);
    source_host.extend_from_slice(&[-903, -904, -905]);
    let b_offset = source_host.len();
    source_host.extend_from_slice(&b);
    source_host.extend_from_slice(&[-906, -907]);
    let source = gpu.upload_new_device(&source_host).unwrap();

    let mut packed = vec![0i16; params.rows() * params.cols()];
    for row in 0..3 {
        packed[row * 4..row * 4 + 3].copy_from_slice(&a[row * 3..(row + 1) * 3]);
    }
    for row in 0..2 {
        packed[32 + row * 2..32 + row * 2 + 2].copy_from_slice(&b[row * 2..(row + 1) * 2]);
    }
    let pad_seed = [0x79; 32];
    let (cpu_commitment, _) = commit(&packed, &params, pad_seed);
    let packed_len = packed.len();
    let place_a = ResidentWeightPlacement::new(
        DeviceSlice::new(&source, a_offset, a.len()).unwrap(),
        3,
        3,
        0,
        4,
        packed_len,
    )
    .unwrap();
    let place_b = ResidentWeightPlacement::new(
        DeviceSlice::new(&source, b_offset, b.len()).unwrap(),
        2,
        2,
        32,
        2,
        packed_len,
    )
    .unwrap();

    gpu.begin_measurement().unwrap();
    let (device_commitment, pm) =
        commit_resident_from_device(&[place_a, place_b], &params, pad_seed, &mut gpu).unwrap();
    let stats = gpu.finish_measurement().unwrap();
    assert_eq!(device_commitment.root, cpu_commitment.root);
    let expected_twiddle_h2d = (params.code_len() / 2 * std::mem::size_of::<u64>()) as u64;
    assert_eq!(stats.h2d_bytes, expected_twiddle_h2d);
    assert_eq!(
        stats.explicit_d2d_copy_bytes,
        ((a.len() + b.len()) * std::mem::size_of::<i16>()) as u64
    );
    assert_eq!(stats.device_zeroed_bytes, (packed_len * std::mem::size_of::<i16>()) as u64);
    assert_eq!(
        stats.device_generated_bytes,
        (params.rows() * params.pad * std::mem::size_of::<u64>()) as u64
    );

    let overlapping_b = ResidentWeightPlacement::new(
        DeviceSlice::new(&source, b_offset, b.len()).unwrap(),
        2,
        2,
        8,
        2,
        packed_len,
    )
    .unwrap();
    let active_before_rejection = gpu.device_memory_breakdown().unwrap().resident_bytes;
    let overlap_error =
        match commit_resident_from_device(&[place_a, overlapping_b], &params, pad_seed, &mut gpu) {
            Ok(_) => panic!("overlapping resident placements unexpectedly committed"),
            Err(error) => error,
        };
    assert!(matches!(
        overlap_error,
        AccelError::InvalidInput("resident weight placements overlap")
    ));
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        active_before_rejection,
        "overlap rejection allocated resident target state"
    );
    assert!(matches!(
        ResidentWeightPlacement::new(
            DeviceSlice::new(&source, b_offset, b.len()).unwrap(),
            2,
            2,
            1,
            2,
            packed_len,
        ),
        Err(AccelError::InvalidInput("resident weight placement block is not aligned"))
    ));
    assert!(matches!(
        ResidentWeightPlacement::new(
            DeviceSlice::new(&source, b_offset, b.len()).unwrap(),
            2,
            2,
            packed_len,
            2,
            packed_len,
        ),
        Err(AccelError::InvalidInput("resident weight placement exceeds packed target"))
    ));

    free_resident_matrix(pm, &mut gpu).unwrap();
    gpu.free_device(source).unwrap();
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        resident_bytes_before,
        "placement differential leaked resident allocations"
    );
}

#[test]
fn cuda_resident_commit_error_reclaims_partial_state() {
    let Some(mut gpu) = cuda_resident() else { return };
    let resident_bytes_before = gpu.device_memory_breakdown().unwrap().resident_bytes;
    // `pad=0` passes the public parameter checks, then device-side prover
    // secret generation rejects after the packed target has been allocated.
    let params = LigeroParams { rows: 1 << 1, col_bits: 1, pad: 0, code_bits: 1, n_queries: 0 };
    let weights = vec![1i16, -2, 3, -4];
    let error = match commit_resident(&weights, &params, [0x76; 32], &mut gpu) {
        Ok(_) => panic!("zero-pad resident commitment unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AccelError::InvalidInput("prover-secret ChaCha8 rows require non-zero geometry")
    ));
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        resident_bytes_before,
        "failed resident commitment leaked its uploaded weights"
    );

    let source = gpu.upload_new_device(&weights).unwrap();
    let placement = ResidentWeightPlacement::new(
        DeviceSlice::new(&source, 0, weights.len()).unwrap(),
        params.rows(),
        params.cols(),
        0,
        params.cols(),
        weights.len(),
    )
    .unwrap();
    let resident_bytes_with_source = gpu.device_memory_breakdown().unwrap().resident_bytes;
    let error = match commit_resident_from_device(&[placement], &params, [0x76; 32], &mut gpu) {
        Ok(_) => panic!("zero-pad device-source commitment unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AccelError::InvalidInput("prover-secret ChaCha8 rows require non-zero geometry")
    ));
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        resident_bytes_with_source,
        "failed device-source commitment leaked its packed target"
    );
    gpu.free_device(source).unwrap();
    assert_eq!(gpu.device_memory_breakdown().unwrap().resident_bytes, resident_bytes_before);
}

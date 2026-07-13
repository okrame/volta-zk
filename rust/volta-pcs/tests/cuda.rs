#![cfg(feature = "cuda")]

use volta_accel::{AccelError, Backend, Operation};
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::{
    commit, commit_resident, commit_with_backend, free_resident_matrix, open_multi_zk,
    open_multi_zk_resident, open_multi_zk_with_backend, verify_multi_open, BlockClaim,
    LigeroParams,
};
use volta_proto::mle::eval_mle;

const PARAMS: LigeroParams =
    LigeroParams { row_bits: 5, col_bits: 5, pad: 8, code_bits: 6, n_queries: 8 };

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

    gpu.begin_measurement().unwrap();
    let (commitment, pm) = commit_resident(&w, &PARAMS, pad_seed, &mut gpu).unwrap();
    assert_eq!(commitment.root, cpu_commitment.root);

    // Inject a practical mid-opening failure: the transient mask commitment
    // is built in `foreign`, then the first PCS row pass rejects `pm` because
    // its persistent buffers belong to `gpu`. Every transient foreign handle
    // must be reclaimed by the opening guard.
    let mut foreign = Backend::cuda_resident()
        .expect("a second resident context must be available for injection");
    let foreign_bytes_before = foreign.device_memory_breakdown().unwrap().resident_bytes;
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
fn cuda_resident_commit_error_reclaims_partial_state() {
    let Some(mut gpu) = cuda_resident() else { return };
    let resident_bytes_before = gpu.device_memory_breakdown().unwrap().resident_bytes;
    // `pad=0` passes the public parameter checks, then the empty pad upload
    // fails after the weight buffer has already been allocated and uploaded.
    let params = LigeroParams { row_bits: 1, col_bits: 1, pad: 0, code_bits: 1, n_queries: 0 };
    let weights = vec![1i16, -2, 3, -4];
    let error = match commit_resident(&weights, &params, [0x76; 32], &mut gpu) {
        Ok(_) => panic!("zero-pad resident commitment unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, AccelError::InvalidInput("zero or overflowing device allocation")));
    assert_eq!(
        gpu.device_memory_breakdown().unwrap().resident_bytes,
        resident_bytes_before,
        "failed resident commitment leaked its uploaded weights"
    );
}

#![cfg(feature = "cuda")]

use volta_accel::{Backend, Operation};
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::{
    commit, commit_with_backend, open_multi_zk, open_multi_zk_with_backend, verify_multi_open,
    BlockClaim, LigeroParams,
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

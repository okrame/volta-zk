//! X4d.1 Phase-2 local fused settlement-driver diagnostic.
//!
//! This CPU-only probe exercises the fused X4d authenticated-output driver at
//! k=1 and k=16 over the same two physical slots. It records phase walls and
//! exact counter equality, but it neither contacts a pod nor claims the
//! production flatness gate.

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, Transcript};
use volta_pcs::x4::{
    authenticate_pending_aux_prover_v4, evaluate_multilinear_table, multilinear_coefficients,
    prove_authenticated_output_link_x4d_v4, AuthenticatedOutputBlockProverV4,
    AuthenticatedOutputLinkPrefixV4, CohortIdentityV4, CohortVerifierConfigV4,
    CommittedModelGlobalCohortV4, Digest, LinkPolynomialProverV4, OracleKindV4, Phase,
    ReducedClaimFrame, X4OpeningRegistryV4, X4cArenaLayoutV4, X4cCpuReferenceRuntimeV4,
    X4cSealConfigV4, X4dSettlementContextV1, X4dSettlementQuerySeedV1, X4dSettlementRangeV1,
    X4C_DESIGN_SHA256_V4,
};

const DATE: &str = "2026-07-26";
const MILESTONE: &str = "X4d1-phase2-fused-settlement-local-v3";
const X4C_RECORD: &str = "benchmarks/results/x4c-gpt2-online-accelerated-2026-07-25-6277c3c.json";
const X4C_RECORD_SHA256: &str = "5a5417c11c0d5b4abe57af1e6ea5fa1191962c709c0f7b86fb780c30af1dac89";
const X4D_RECORD: &str =
    "benchmarks/results/x4d-gpt2-online-2026-07-26-bf4230c-bbd64aa1df41-local.json";
const X4D_RECORD_SHA256: &str = "d6017dbadd930baa390b174e57e8d93ec6a413fd886d505ad37ebb484e6dc24b";
const PRODUCTION_EVALUATION_TABLE_BYTES: u64 = 9_618_587_648;
const PRODUCTION_INITIAL_ENCODED_SYMBOLS_READ: u64 = 4_809_293_824;
const PRODUCTION_COMBINED_CODEWORD_SYMBOLS: u64 = 1_159_200_768;
const SYNTHETIC_DOMAIN_LOG2: [u8; 3] = [14, 16, 18];
const RESPONSE_COUNTS: [usize; 2] = [1, 16];
const MEASURED_CANDIDATES: usize = 3;

#[derive(Clone, Copy, Debug, Serialize)]
struct PhaseWallsRow {
    claim_coefficient_preparation_wall_ns: u64,
    oracle_read_combine_wall_ns: u64,
    fold_merkle_wall_ns: u64,
    query_gather_wall_ns: u64,
    caller_wall_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct CounterRow {
    relation_terms: u64,
    materialized_relation_terms: u64,
    fused_relation_terms: u64,
    unique_evaluation_tables: u64,
    evaluation_table_bytes: u64,
    evaluation_table_cpu_resident_bytes: u64,
    evaluation_table_gpu_resident_bytes: u64,
    evaluation_table_h2d_bytes: u64,
    evaluation_table_d2h_bytes: u64,
    materialized_evaluation_clone_bytes: u64,
    materialized_equality_table_bytes: u64,
    peak_relation_table_cpu_payload_bytes: u64,
    peak_relation_table_gpu_payload_bytes: u64,
    logical_evaluation_table_symbols_read: u64,
    logical_evaluation_table_bytes_read: u64,
    evaluation_table_passes_per_unique_table: u64,
    encoded_oracle_full_passes: u64,
    response_or_claim_proportional_encoded_oracle_passes: u64,
    source_coefficients_read: u64,
    initial_encoded_symbols_read: u64,
    combined_codeword_symbols: u64,
    query_gather_calls: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct CandidateRow {
    ordinal: usize,
    phases: PhaseWallsRow,
    counters: CounterRow,
    accepted: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct SelectedRow {
    phases: PhaseWallsRow,
    counters: CounterRow,
}

#[derive(Debug, Serialize)]
struct BatchRow {
    responses: usize,
    warmup_count: usize,
    measured_candidates: usize,
    candidates: Vec<CandidateRow>,
    selected_upper_median: SelectedRow,
    all_accepted: bool,
}

#[derive(Debug, Serialize)]
struct ScaleRow {
    evaluation_domain_log2: u8,
    evaluation_symbols_per_table: u64,
    unique_evaluation_table_bytes: u64,
    batches: Vec<BatchRow>,
    all_physical_counters_equal_k1_k16: bool,
    evaluation_table_pass_ratio_k16_over_k1: f64,
    claim_preparation_wall_ratio_k16_over_k1: f64,
    caller_wall_ratio_k16_over_k1: f64,
}

#[derive(Debug, Serialize)]
struct LocalFlatnessRow {
    largest_scale_caller_wall_ratio_k16_over_k1: f64,
    largest_scale_claim_preparation_wall_ratio_k16_over_k1: f64,
    all_scales_physical_counters_equal: bool,
    diagnostic_only: bool,
    production_gate_verdict: String,
}

#[derive(Debug, Serialize)]
struct FlatnessGateRow {
    preregistered: bool,
    wall_rule: String,
    symbol_rule: String,
    same_host_required: bool,
    informative_target: String,
    existing_gates_unchanged: String,
    verdict: String,
}

#[derive(Debug, Serialize)]
struct MachineRow {
    architecture: String,
    kernel: String,
    logical_cpus: usize,
    rayon_threads: usize,
    rayon_num_threads_environment: String,
}

#[derive(Debug, Serialize)]
struct SourceDigestRow {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct Record {
    schema: u64,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    phase: u64,
    pod_contacted: bool,
    proof_or_gate_verdict: bool,
    machine: MachineRow,
    instrumented_sources: Vec<SourceDigestRow>,
    x4c_record: String,
    x4c_record_sha256: String,
    x4d_record: String,
    x4d_record_sha256: String,
    immutable_scope: String,
    production_anchors: CounterRow,
    synthetic_scales: Vec<ScaleRow>,
    local_flatness: LocalFlatnessRow,
    fused_driver_implementation: String,
    flatness_gate: FlatnessGateRow,
    owner_phase2_rulings: Vec<String>,
    pod_checklist: Vec<String>,
    hard_stop: String,
}

fn symbol(value: u64) -> Fp2 {
    Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(7).wrapping_add(5)))
}

fn command(args: &[&str]) -> String {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(output.status.success(), "command failed: {args:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn git(args: &[&str]) -> String {
    let root = repo_root();
    let mut command_args = vec!["git", "-C", root.to_str().unwrap()];
    command_args.extend_from_slice(args);
    command(&command_args)
}

fn sha256(path: &Path) -> String {
    command(&["sha256sum", path.to_str().unwrap()]).split_whitespace().next().unwrap().to_owned()
}

fn upper_median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

struct Fixture {
    descriptor: Digest,
    weight_evaluations: Vec<Fp2>,
    auxiliary_evaluations: Vec<Fp2>,
    weight: CommittedModelGlobalCohortV4,
    auxiliary: CommittedModelGlobalCohortV4,
    evaluation_domain_log2: u8,
}

impl Fixture {
    fn new(evaluation_domain_log2: u8) -> Self {
        let len = 1usize << evaluation_domain_log2;
        let mut descriptor = [0xD1; 32];
        descriptor[..8].copy_from_slice(&u64::from(evaluation_domain_log2).to_le_bytes());
        let weight_evaluations =
            (0..len).map(|index| symbol(10_000 + index as u64)).collect::<Vec<_>>();
        let auxiliary_evaluations =
            (0..len).map(|index| symbol(30_000 + 3 * index as u64)).collect::<Vec<_>>();
        let committed = |cohort_id, kind, evaluations: &[Fp2]| {
            CommittedModelGlobalCohortV4::commit(
                CohortVerifierConfigV4 {
                    identity: CohortIdentityV4 { cohort_id, oracle_kind: kind, fold_round: 0 },
                    slot_descriptors: vec![Some(descriptor)],
                    outer_len: 8 * evaluations.len(),
                    expected_symbol_count: 1,
                },
                vec![Some(multilinear_coefficients(evaluations).unwrap())],
            )
            .unwrap()
        };
        let weight = committed(0xD101_0001, OracleKindV4::WeightExtension, &weight_evaluations);
        let auxiliary = committed(0xD101_0002, OracleKindV4::Auxiliary, &auxiliary_evaluations);
        Self {
            descriptor,
            weight_evaluations,
            auxiliary_evaluations,
            weight,
            auxiliary,
            evaluation_domain_log2,
        }
    }

    fn point(&self, response: usize) -> Vec<Fp2> {
        let mut point = (0..usize::from(self.evaluation_domain_log2 - 1))
            .map(|index| symbol(50_000 + 257 * response as u64 + index as u64))
            .collect::<Vec<_>>();
        point.push(Fp2::ZERO);
        point
    }
}

fn run_candidate(fixture: &Fixture, responses: usize, ordinal: usize) -> CandidateRow {
    let epoch = 0xD100_0000 + u64::from(fixture.evaluation_domain_log2) * 100 + ordinal as u64;
    let points = (0..responses).map(|index| fixture.point(index)).collect::<Vec<_>>();
    let weight_values = points
        .iter()
        .map(|point| evaluate_multilinear_table(&fixture.weight_evaluations, point).unwrap())
        .collect::<Vec<_>>();
    let auxiliary_values = points
        .iter()
        .map(|point| evaluate_multilinear_table(&fixture.auxiliary_evaluations, point).unwrap())
        .collect::<Vec<_>>();
    let public_h = weight_values
        .iter()
        .zip(&auxiliary_values)
        .map(|(weight, auxiliary)| *weight + *auxiliary)
        .collect::<Vec<_>>();
    let claims = (0..responses)
        .map(|index| {
            let mut parent = [0xD2; 32];
            parent[..8].copy_from_slice(&(index as u64).to_le_bytes());
            ReducedClaimFrame {
                descriptor_digest: fixture.descriptor,
                parent_claim_digest: parent,
                phase: Phase::Decode,
                phase_ordinal: u16::try_from(index).unwrap(),
                point: vec![symbol(70_000 + index as u64); 14],
                affine_scale: Fp2::ONE,
                auth_domain: 0xD200_0000 + index as u64,
            }
        })
        .collect::<Vec<_>>();
    let ordered_response_nonces = (0..responses)
        .map(|index| {
            let mut nonce = [0xD3; 32];
            nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
            nonce
        })
        .collect::<Vec<_>>();
    let context = X4dSettlementContextV1 {
        range: X4dSettlementRangeV1 {
            connection_id: [0xD4; 32],
            settlement_epoch: epoch,
            first_claim_index: 0,
            claim_count: responses as u32,
            starting_accumulator_digest: [0xD5; 32],
            sealed_accumulator_digest: [0xD6; 32],
            ordered_response_nonces,
        },
    };
    let mut prover_stream = CorrelationStream::new([0xD7; 32]);
    let mut prover_tx = Transcript::new([0xD8; 32]);
    let mut pending = Vec::with_capacity(responses);
    let mut m9_frames = Vec::with_capacity(responses);
    for (index, value) in auxiliary_values.iter().enumerate() {
        let (pending_aux, frame) = authenticate_pending_aux_prover_v4(
            fixture.descriptor,
            *value,
            &mut prover_stream,
            0xD300_0000 + index as u64,
            &mut prover_tx,
        )
        .unwrap();
        pending.push(pending_aux);
        m9_frames.push(frame);
    }
    let blocks = pending
        .into_iter()
        .enumerate()
        .map(|(index, pending_aux)| AuthenticatedOutputBlockProverV4 {
            descriptor_digest: fixture.descriptor,
            public_h: public_h[index],
            pending_aux,
            weight_extension: LinkPolynomialProverV4 {
                cohort: &fixture.weight,
                slot: 0,
                evaluations: &fixture.weight_evaluations,
                target_point: &points[index],
            },
            auxiliary: LinkPolynomialProverV4 {
                cohort: &fixture.auxiliary,
                slot: 0,
                evaluations: &fixture.auxiliary_evaluations,
                target_point: &points[index],
            },
        })
        .collect::<Vec<_>>();
    let descriptor_inventory = [fixture.descriptor];
    let round_domains = (0..2 * usize::from(fixture.evaluation_domain_log2))
        .map(|index| 0xD400_0000 + index as u64)
        .collect::<Vec<_>>();
    let prefix = AuthenticatedOutputLinkPrefixV4 {
        epoch,
        claim_frames: &claims,
        descriptor_digests: &descriptor_inventory,
        ordered_h_symbols: &public_h,
        m9_frames: &m9_frames,
        round_correlation_domain_ids: &round_domains,
    };
    let mut model_root = [0xD9; 32];
    model_root[..8].copy_from_slice(&epoch.to_le_bytes());
    let permit = X4OpeningRegistryV4::default()
        .authorize_after_persistent_freshness(model_root, epoch, [0xDA; 32])
        .unwrap();
    let mut runtime = X4cCpuReferenceRuntimeV4;
    let caller_started = Instant::now();
    let (_, _, link_metrics, x4c_metrics, phases, draws) = prove_authenticated_output_link_x4d_v4(
        permit,
        model_root,
        blocks,
        prefix,
        &context,
        &mut prover_stream,
        &mut prover_tx,
        X4dSettlementQuerySeedV1::new([0xDB; 32]).unwrap(),
        &mut runtime,
        X4cSealConfigV4 {
            design_sha256: X4C_DESIGN_SHA256_V4,
            clean_source_sha256: [0xDC; 32],
            response_ordinal: ordinal as u64,
            arena_layout: X4cArenaLayoutV4::new(fixture.evaluation_domain_log2 + 3, 3, 4096)
                .unwrap(),
        },
    )
    .unwrap();
    let caller_wall_ns = u64::try_from(caller_started.elapsed().as_nanos()).unwrap();
    let evaluation_symbols =
        u64::try_from(fixture.weight_evaluations.len() + fixture.auxiliary_evaluations.len())
            .unwrap();
    let evaluation_table_bytes = evaluation_symbols * 16;
    let logical_symbols = link_metrics.sumcheck_source_symbols_read;
    let expected_logical = evaluation_symbols;
    let materialized_payload_bytes = logical_symbols * 16;
    let global = x4c_metrics.global_open;
    let counters = CounterRow {
        relation_terms: link_metrics.sumcheck_relation_terms,
        materialized_relation_terms: link_metrics.sumcheck_materialized_terms,
        fused_relation_terms: link_metrics.sumcheck_fused_terms,
        unique_evaluation_tables: 2,
        evaluation_table_bytes,
        evaluation_table_cpu_resident_bytes: evaluation_table_bytes,
        evaluation_table_gpu_resident_bytes: 0,
        evaluation_table_h2d_bytes: 0,
        evaluation_table_d2h_bytes: 0,
        materialized_evaluation_clone_bytes: materialized_payload_bytes,
        materialized_equality_table_bytes: link_metrics.sumcheck_equality_symbols_materialized * 16,
        peak_relation_table_cpu_payload_bytes: 3 * evaluation_table_bytes,
        peak_relation_table_gpu_payload_bytes: 0,
        logical_evaluation_table_symbols_read: logical_symbols,
        logical_evaluation_table_bytes_read: materialized_payload_bytes,
        evaluation_table_passes_per_unique_table: 1,
        encoded_oracle_full_passes: 1,
        response_or_claim_proportional_encoded_oracle_passes: 0,
        source_coefficients_read: global.source_coefficients_read,
        initial_encoded_symbols_read: global.initial_encoded_symbols_read,
        combined_codeword_symbols: global.combined_codeword_symbols,
        query_gather_calls: x4c_metrics.execution.query_gather_calls,
    };
    let accepted = draws.len() == 111
        && counters.relation_terms == 2 * responses as u64
        && counters.materialized_relation_terms == 2
        && counters.fused_relation_terms == 2 * responses as u64 - 2
        && logical_symbols == expected_logical
        && counters.materialized_evaluation_clone_bytes == expected_logical * 16
        && counters.materialized_equality_table_bytes == expected_logical * 16
        && counters.peak_relation_table_cpu_payload_bytes == 3 * evaluation_table_bytes
        && global.source_coefficients_read == evaluation_symbols
        && global.initial_encoded_symbols_read == evaluation_symbols * 8
        && global.combined_codeword_symbols == evaluation_symbols * 8
        && x4c_metrics.execution.query_gather_calls == 1;
    CandidateRow {
        ordinal,
        phases: PhaseWallsRow {
            claim_coefficient_preparation_wall_ns: phases.claim_coefficient_preparation_wall_ns,
            oracle_read_combine_wall_ns: phases.oracle_read_combine_wall_ns,
            fold_merkle_wall_ns: phases.fold_merkle_wall_ns,
            query_gather_wall_ns: phases.query_gather_wall_ns,
            caller_wall_ns,
        },
        counters,
        accepted,
    }
}

fn selected(candidates: &[CandidateRow]) -> SelectedRow {
    let first = candidates[0].counters;
    assert!(candidates.iter().all(|candidate| candidate.accepted && candidate.counters == first));
    SelectedRow {
        phases: PhaseWallsRow {
            claim_coefficient_preparation_wall_ns: upper_median(
                candidates
                    .iter()
                    .map(|row| row.phases.claim_coefficient_preparation_wall_ns)
                    .collect(),
            ),
            oracle_read_combine_wall_ns: upper_median(
                candidates.iter().map(|row| row.phases.oracle_read_combine_wall_ns).collect(),
            ),
            fold_merkle_wall_ns: upper_median(
                candidates.iter().map(|row| row.phases.fold_merkle_wall_ns).collect(),
            ),
            query_gather_wall_ns: upper_median(
                candidates.iter().map(|row| row.phases.query_gather_wall_ns).collect(),
            ),
            caller_wall_ns: upper_median(
                candidates.iter().map(|row| row.phases.caller_wall_ns).collect(),
            ),
        },
        counters: first,
    }
}

fn run_scale(evaluation_domain_log2: u8) -> ScaleRow {
    let fixture = Fixture::new(evaluation_domain_log2);
    let mut batches = Vec::new();
    for responses in RESPONSE_COUNTS {
        let _warmup = run_candidate(&fixture, responses, 0);
        let candidates = (1..=MEASURED_CANDIDATES)
            .map(|ordinal| run_candidate(&fixture, responses, ordinal))
            .collect::<Vec<_>>();
        let selected_upper_median = selected(&candidates);
        batches.push(BatchRow {
            responses,
            warmup_count: 1,
            measured_candidates: candidates.len(),
            all_accepted: candidates.iter().all(|row| row.accepted),
            candidates,
            selected_upper_median,
        });
    }
    let k1 = &batches[0].selected_upper_median;
    let k16 = &batches[1].selected_upper_median;
    let all_physical_counters_equal_k1_k16 = k1.counters.materialized_relation_terms
        == k16.counters.materialized_relation_terms
        && k1.counters.unique_evaluation_tables == k16.counters.unique_evaluation_tables
        && k1.counters.evaluation_table_bytes == k16.counters.evaluation_table_bytes
        && k1.counters.materialized_evaluation_clone_bytes
            == k16.counters.materialized_evaluation_clone_bytes
        && k1.counters.materialized_equality_table_bytes
            == k16.counters.materialized_equality_table_bytes
        && k1.counters.peak_relation_table_cpu_payload_bytes
            == k16.counters.peak_relation_table_cpu_payload_bytes
        && k1.counters.logical_evaluation_table_symbols_read
            == k16.counters.logical_evaluation_table_symbols_read
        && k1.counters.evaluation_table_passes_per_unique_table
            == k16.counters.evaluation_table_passes_per_unique_table
        && k1.counters.source_coefficients_read == k16.counters.source_coefficients_read
        && k1.counters.initial_encoded_symbols_read == k16.counters.initial_encoded_symbols_read
        && k1.counters.combined_codeword_symbols == k16.counters.combined_codeword_symbols
        && k1.counters.encoded_oracle_full_passes == 1
        && k16.counters.encoded_oracle_full_passes == 1
        && k1.counters.query_gather_calls == k16.counters.query_gather_calls;
    assert!(all_physical_counters_equal_k1_k16);
    ScaleRow {
        evaluation_domain_log2,
        evaluation_symbols_per_table: 1u64 << evaluation_domain_log2,
        unique_evaluation_table_bytes: k1.counters.evaluation_table_bytes,
        evaluation_table_pass_ratio_k16_over_k1: k16.counters.logical_evaluation_table_bytes_read
            as f64
            / k1.counters.logical_evaluation_table_bytes_read as f64,
        claim_preparation_wall_ratio_k16_over_k1: k16.phases.claim_coefficient_preparation_wall_ns
            as f64
            / k1.phases.claim_coefficient_preparation_wall_ns as f64,
        caller_wall_ratio_k16_over_k1: k16.phases.caller_wall_ns as f64
            / k1.phases.caller_wall_ns as f64,
        all_physical_counters_equal_k1_k16,
        batches,
    }
}

fn record() -> Record {
    let root = repo_root();
    assert_eq!(sha256(&root.join(X4C_RECORD)), X4C_RECORD_SHA256);
    assert_eq!(sha256(&root.join(X4D_RECORD)), X4D_RECORD_SHA256);
    let scales = SYNTHETIC_DOMAIN_LOG2.into_iter().map(run_scale).collect::<Vec<_>>();
    let largest = scales.last().unwrap();
    let all_scales_physical_counters_equal =
        scales.iter().all(|scale| scale.all_physical_counters_equal_k1_k16);
    assert!(all_scales_physical_counters_equal);
    let local_flatness = LocalFlatnessRow {
        largest_scale_caller_wall_ratio_k16_over_k1: largest.caller_wall_ratio_k16_over_k1,
        largest_scale_claim_preparation_wall_ratio_k16_over_k1: largest
            .claim_preparation_wall_ratio_k16_over_k1,
        all_scales_physical_counters_equal,
        diagnostic_only: true,
        production_gate_verdict: "NOT EVALUATED LOCALLY".to_owned(),
    };
    let instrumented_sources = [
        "docs/x4d-deferred-settlement-design.md",
        "rust/volta-pcs/src/x4/folding_v4.rs",
        "rust/volta-pcs/src/x4/x4c_v4.rs",
        "rust/volta-pcs/src/x4/authenticated_output_v4.rs",
        "rust/volta-bench/src/x4d_gpt2.rs",
        "rust/volta-bench/src/bin/x4d_gpt2_pod_record.rs",
        "rust/volta-bench/src/bin/x4d1_flatness_record.rs",
        "rust/volta-bench/src/bin/x4d1_phase1.rs",
    ]
    .into_iter()
    .map(|path| SourceDigestRow { path: path.to_owned(), sha256: sha256(&root.join(path)) })
    .collect();
    Record {
        schema: 6,
        milestone: MILESTONE.to_owned(),
        date: DATE.to_owned(),
        git_sha: git(&["rev-parse", "HEAD"]),
        git_short_sha: git(&["rev-parse", "--short", "HEAD"]),
        git_dirty: !git(&["status", "--porcelain", "--untracked-files=normal"]).is_empty(),
        phase: 2,
        pod_contacted: false,
        proof_or_gate_verdict: false,
        machine: MachineRow {
            architecture: std::env::consts::ARCH.to_owned(),
            kernel: command(&["uname", "-srmo"]),
            logical_cpus: std::thread::available_parallelism().unwrap().get(),
            rayon_threads: rayon::current_num_threads(),
            rayon_num_threads_environment: std::env::var("RAYON_NUM_THREADS")
                .unwrap_or_else(|_| "unset".to_owned()),
        },
        instrumented_sources,
        x4c_record: X4C_RECORD.to_owned(),
        x4c_record_sha256: X4C_RECORD_SHA256.to_owned(),
        x4d_record: X4D_RECORD.to_owned(),
        x4d_record_sha256: X4D_RECORD_SHA256.to_owned(),
        immutable_scope: "no protocol, soundness, proof byte, codec, Lean, M12, 80.25537016399041-bit expression or existing gate-ceiling change".to_owned(),
        production_anchors: CounterRow {
            relation_terms: 1_632,
            materialized_relation_terms: 102,
            fused_relation_terms: 1_530,
            unique_evaluation_tables: 102,
            evaluation_table_bytes: PRODUCTION_EVALUATION_TABLE_BYTES,
            evaluation_table_cpu_resident_bytes: PRODUCTION_EVALUATION_TABLE_BYTES,
            evaluation_table_gpu_resident_bytes: 0,
            evaluation_table_h2d_bytes: 0,
            evaluation_table_d2h_bytes: 0,
            materialized_evaluation_clone_bytes: PRODUCTION_EVALUATION_TABLE_BYTES,
            materialized_equality_table_bytes: PRODUCTION_EVALUATION_TABLE_BYTES,
            peak_relation_table_cpu_payload_bytes: 3 * PRODUCTION_EVALUATION_TABLE_BYTES,
            peak_relation_table_gpu_payload_bytes: 0,
            logical_evaluation_table_symbols_read: PRODUCTION_EVALUATION_TABLE_BYTES / 16,
            logical_evaluation_table_bytes_read: PRODUCTION_EVALUATION_TABLE_BYTES,
            evaluation_table_passes_per_unique_table: 1,
            encoded_oracle_full_passes: 1,
            response_or_claim_proportional_encoded_oracle_passes: 0,
            source_coefficients_read: PRODUCTION_EVALUATION_TABLE_BYTES / 16,
            initial_encoded_symbols_read: PRODUCTION_INITIAL_ENCODED_SYMBOLS_READ,
            combined_codeword_symbols: PRODUCTION_COMBINED_CODEWORD_SYMBOLS,
            query_gather_calls: 1,
        },
        synthetic_scales: scales,
        local_flatness,
        fused_driver_implementation: "response-local equality/combination coefficients are reduced by physical cohort+slot before each unique source table is cloned; the sumcheck relation polynomial is round-exact, the protocol relation count remains unchanged, and the existing X4c GPU-resident encoded-oracle RLC, one combined fold/Merkle chain and one 111-query opening are reused".to_owned(),
        flatness_gate: FlatnessGateRow {
            preregistered: true,
            wall_rule: "settlement_wall(k=16) <= 1.30 * settlement_wall(k=1) on the same host".to_owned(),
            symbol_rule: "settlement initial_encoded_symbols_read(k=1) == initial_encoded_symbols_read(k=16), and combined_codeword_symbols equality is recorded as the paired structural counter".to_owned(),
            same_host_required: true,
            informative_target: "settlement_wall <= the immutable X4c pcs_total baseline band (288-307 s); not a gate".to_owned(),
            existing_gates_unchanged: "G1 response wall/bytes/interference, G2-G6, opening <=1.50 s and verify <=0.25 s all re-run without relaxation".to_owned(),
            verdict: "NOT EVALUATED: LOCAL CPU DIAGNOSTIC ONLY".to_owned(),
        },
        owner_phase2_rulings: vec![
            "Binding gate only: same-host settlement wall k=16 <=1.30x k=1 plus initial and combined symbol equality; 288-307 s is informative, so 350 s with green flatness is PASS with a note".to_owned(),
            "Rerun G1 and interference without relaxation: historical 4.87-5.04 s response range, exact 41,270,464 B and <=1.00% interference, with 0.399684884% as the accepted comparison anchor".to_owned(),
            "Do not rename or update the accelerated comparison document before eligible paired pod records and ledger closure".to_owned(),
        ],
        pod_checklist: vec![
            "STOP and ask before provisioning or contacting a pod".to_owned(),
            "NOTE-6 is the first production-size workload".to_owned(),
            "Fail closed unless selected SKU RAM >=274,877,906,944 B and volume >=150,000,000,000 B".to_owned(),
            "Write only fresh append-only x4d1-* records".to_owned(),
            "Stop the pod through the provider control plane from the SSH session at session end".to_owned(),
        ],
        hard_stop: "PHASE 2 LOCAL IMPLEMENTATION ONLY; no pod provisioned or contacted; explicit provisioning approval required".to_owned(),
    }
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(args == ["--stdout"] || args == ["--record"]);
    let record = record();
    let mut bytes = serde_json::to_vec_pretty(&record).unwrap();
    bytes.push(b'\n');
    if args == ["--stdout"] {
        print!("{}", String::from_utf8(bytes).unwrap());
        return;
    }
    let path = repo_root()
        .join("benchmarks/results")
        .join(format!("x4d1-phase2-fused-v3-{}-{}-local.json", DATE, record.git_short_sha));
    assert!(!path.exists(), "append-only Phase-2 record already exists: {}", path.display());
    fs::write(&path, bytes).unwrap();
    println!("{}", path.strip_prefix(repo_root()).unwrap().display());
}

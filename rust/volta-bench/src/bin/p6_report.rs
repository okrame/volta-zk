//! P6 report: decode with the authenticated KV cache — the kill benchmark.
//!
//! Workload of record: prompt 100 tokens + 50 greedy decode steps on the
//! frozen real-weight artifact. Two proving sessions are measured:
//!
//! 1. **Run of record** — prefill + ONE deferred chunk (Q = 50) proved by
//!    `prove_response` in one two-phase session, verified, all 96 weight
//!    claims + 6 embedding claims resolved through the REAL 13-commitment
//!    Ligero PCS (stacked openings — the P4 dev. #8 constraint: never
//!    per-token claims).
//! 2. **Flat-cost curve** — the same 50 tokens as 5 chunks of 10 (cache
//!    100→150): per-chunk prove wall must grow only by the O(seq·d)
//!    attention term, never O(seq²) — the architectural gate.
//!
//! The native decode baseline is the KV-cached `decode_step` (bit-exact vs
//! the full forward — golden-p6 checked); ρ_decode = (prove_response −
//! prove_prefill) / native-decode wall.
//!
//! Run: cargo run --release -p volta-bench --bin p6_report [-- --quick]
//! (`--quick`: prompt 16 + 8 decode, 2×4 curve, golden skipped.) Full runs
//! default to one warmup plus three measured repetitions; override with
//! `--warmup-repetitions N --repetitions N`.

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Instant;
use volta_accel::{
    Backend, BackendKind, BackendStats, DeviceBuffer, DeviceSlice, DeviceTimingMode, Operation,
    ResidentTimingPolicy, CUDA_ABI_VERSION,
};
use volta_bench::{cloud_metadata_from_env, logits_pack, time_paired_samples, CloudMetadata};
use volta_field::{Fp, Fp2, P};
use volta_gpt2::{
    band_model_witness, band_model_witness_resident, decode_step, forward_model,
    forward_model_tokens, forward_model_tokens_resident, forward_model_tokens_with_backend,
    forward_model_with_backend, load_model, upload_resident_model, BandModelWitness, Gpt2Model,
    KvCache, LayerWeightField, ModelWeightField, ResidentBandModelWitness, ResidentGpt2Model,
    ResidentModelWitness, D, L, VOCAB,
};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcg::{
    expand_phase_b_production_with_ggm_prg, GgmPrg, PhaseBTimings, ProductionSetupAudit,
    ProverPcgPool, ResponseAuthorizationStore, SessionBinding, SetupCommBreakdown, VerifierPcgPool,
};
use volta_pcs::{
    commit, commit_resident_from_device, commit_with_backend, free_resident_matrix,
    layout_gpt2_embed, layout_gpt2_layer, open_multi_zk, open_multi_zk_resident,
    open_multi_zk_with_backend, verify_multi_open, LigeroParams, ProverMatrix,
    ResidentProverMatrix, ResidentWeightPlacement, GPT2_FULL, P4_LAYER,
};
use volta_proto::block_proof::layer_dom_base;
use volta_proto::logup::Doms;
use volta_proto::model_proof::{
    prove_model_resident, prove_response, prove_response_resident, prove_response_with_backend,
    verify_response, ChunkPub, ChunkRef, ResidentChunkRef,
};
use volta_proto::{
    cattn_permuted, prod_batch_prover, prod_batch_verify, prove_model, prove_model_with_backend,
};

const P7B_PREFILL_CORE_GATE_S: f64 = 10.0;
const P7B_DECODE_MARGINAL_GATE_S: f64 = 4.0;
const P7B_GATE_PROFILE: &str = "runpod-a100-v1";
const FASE_D_POD_GATE_PROFILE: &str = "runpod-a100-realpcg-v1";
const P7B_SYNC_WALL_FRACTION_GATE: f64 = 0.02;
const P7B_OFFICIAL_RAYON_THREADS: usize = 8;
// Decimal MB, matching the preregistered ledger threshold.
const P7B_H2D_GATE_BYTES: u64 = 100_000_000;
// This is an unchanged product invariant, not a fifth P7b performance gate.
// It covers the complete packed response download (proof transcript plus
// public output), matching the handoff's 150--200 MB envelope.
const RESPONSE_COMMUNICATION_ENVELOPE_BYTES: u64 = 200_000_000;
// Clean P7 response reference at T=100+50/Q=200. P7b may reduce these values,
// but orchestration work may not buy prover time by increasing any component.
const P7B_TRANSCRIPT_REFERENCE_BYTES: u64 = 137_413_808;
const P7B_PCS_OPENING_REFERENCE_BYTES: u64 = 66_733_504;
const P7B_PACKED_LOGITS_REFERENCE_BYTES: u64 = 7_407_122;
const P7B_PACKED_RESPONSE_REFERENCE_BYTES: u64 = 144_820_930;
const C1_BASELINE_ARTIFACT: &str = "p6-2026-07-07-515bb1c.json";
const C1_BASELINE_PROVE_RESPONSE_S: f64 = 18.738_631_475;
const C1_BASELINE_VERIFY_RESPONSE_S: f64 = 0.567_143_475;
const C1_BASELINE_TRANSCRIPT_BYTES: u64 = 137_413_808;
const C1_BASELINE_AUTH_CORRECTION_BYTES: u64 = 67_839_408;
const C1_BASELINE_PACKED_RESPONSE_BYTES: u64 = 144_820_930;
const C1_BASELINE_SUB_CORRS: u64 = 8_479_926;
const C1_IDENTITY_SEAM_ALIASES: u64 = 1_036_800;
const C1_SAVED_BYTES: u64 = 8 * C1_IDENTITY_SEAM_ALIASES;
const C1_TRANSCRIPT_BYTES: u64 = C1_BASELINE_TRANSCRIPT_BYTES - C1_SAVED_BYTES;
const C1_AUTH_CORRECTION_BYTES: u64 = C1_BASELINE_AUTH_CORRECTION_BYTES - C1_SAVED_BYTES;
const C1_PACKED_RESPONSE_BYTES: u64 = C1_BASELINE_PACKED_RESPONSE_BYTES - C1_SAVED_BYTES;
const C1_SUB_CORRS: u64 = C1_BASELINE_SUB_CORRS - C1_IDENTITY_SEAM_ALIASES;
// Phase 0a may change this only after its >=10% instrumentation-tax decision
// is appended to the ledger. Until then, counter-only full runs are
// diagnostic and cannot become an official verdict.
const P7B_OFFICIAL_RESIDENT_TIMING: ResidentTimingArg = ResidentTimingArg::WallOnlyCounters;

#[derive(Serialize)]
struct ChunkCurveRow {
    chunk: usize,
    t0: usize,
    q: usize,
    cache_end: usize,
    prove_p1_s: f64,
    prove_p2_s: f64,
    prove_total_s: f64,
    per_token_s: f64,
}

#[derive(Serialize)]
struct PcsCommitmentRow {
    name: String,
    n_claims: usize,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
    opening_bytes: u64,
    opening_cached_query_cut_bytes: u64,
    opening_cached_query_marginal_bytes: u64,
    verified: bool,
}

#[derive(Clone, Serialize)]
struct AcceleratorOperationRow {
    calls: u64,
    kernel_s: Option<f64>,
    cpu_residual_s: f64,
}

#[derive(Clone, Serialize)]
struct AcceleratorStatsRow {
    scope: String,
    operations: BTreeMap<String, AcceleratorOperationRow>,
    timing_method: String,
    phase_attribution_available: bool,
    measurement_wall_s: f64,
    operation_cpu_residual_s: f64,
    unattributed_cpu_residual_s: Option<f64>,
    h2d_bytes: u64,
    d2h_bytes: u64,
    /// Explicit resident row-placement/copy traffic, not all kernel-internal D2D.
    explicit_d2d_copy_bytes: u64,
    device_zeroed_bytes: u64,
    device_generated_bytes: u64,
    h2d_s: Option<f64>,
    d2h_s: Option<f64>,
    resident_h2d_host_calls: u64,
    resident_d2h_host_calls: u64,
    resident_h2d_host_call_s: f64,
    resident_d2h_host_call_s: f64,
    synchronizations: u64,
    synchronization_s: f64,
    sync_host_output: u64,
    sync_upload_lifetime: u64,
    sync_timing_flush: u64,
    sync_profiling_legacy: u64,
    sync_allocator_flush: u64,
    /// Successful physical CUDA allocations, not logical arena requests.
    allocation_calls: u64,
    resident_alloc_requests: u64,
    resident_reuse_hits: u64,
    resident_free_requests: u64,
    physical_free_calls: u64,
    live_device_bytes: u64,
    peak_device_bytes: u64,
    timing_records: u64,
    timing_elapsed_query_attempts: u64,
    timing_elapsed_no_write: u64,
    timing_event_queries: u64,
    timing_event_api_calls: u64,
    timing_pending_high_water: u64,
    timing_flush_count: u64,
    coarse_timing_scopes: u64,
    /// CUDA-event time spanned by coarse epochs. This can include device idle
    /// gaps while a remote runtime awaits subsequent launch submissions.
    coarse_timing_s: Option<f64>,
    kernel_s: Option<f64>,
    cpu_residual_s: Option<f64>,
}

#[derive(Clone, Serialize)]
struct TimingDistribution {
    samples_s: Vec<f64>,
    median_s: f64,
    mad_s: f64,
    min_s: f64,
    max_s: f64,
}

impl TimingDistribution {
    fn new(samples_s: Vec<f64>) -> Self {
        assert!(!samples_s.is_empty(), "timing distribution needs a sample");
        assert!(samples_s.iter().all(|x| x.is_finite() && *x >= 0.0));
        let mut sorted = samples_s.clone();
        sorted.sort_by(f64::total_cmp);
        let median_s = sorted[sorted.len() / 2];
        let mut deviations: Vec<f64> = samples_s.iter().map(|x| (x - median_s).abs()).collect();
        deviations.sort_by(f64::total_cmp);
        let mad_s = deviations[deviations.len() / 2];
        TimingDistribution {
            samples_s,
            median_s,
            mad_s,
            min_s: sorted[0],
            max_s: *sorted.last().unwrap(),
        }
    }
}

fn median_index(samples: &[f64]) -> usize {
    assert!(!samples.is_empty());
    let mut indices: Vec<usize> = (0..samples.len()).collect();
    indices.sort_by(|&a, &b| samples[a].total_cmp(&samples[b]));
    indices[indices.len() / 2]
}

fn git_worktree_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.status.success() || !o.stdout.is_empty())
        .unwrap_or(true)
}

fn git_head_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

fn git_revision_unchanged(before_benchmark: &str, before_serialization: &str) -> bool {
    !before_benchmark.is_empty()
        && !before_serialization.is_empty()
        && before_benchmark == before_serialization
}

fn short_git_sha(full_sha: &str) -> String {
    full_sha.chars().take(7).collect()
}

fn detected_logical_cpu_cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

fn detected_physical_cpu_cores(logical_fallback: usize) -> usize {
    let mut cores = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(index) = name.strip_prefix("cpu") else {
                continue;
            };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let topology = entry.path().join("topology");
            let package = std::fs::read_to_string(topology.join("physical_package_id"));
            let core = std::fs::read_to_string(topology.join("core_id"));
            if let (Ok(package), Ok(core)) = (package, core) {
                cores.insert((package.trim().to_owned(), core.trim().to_owned()));
            }
        }
    }
    if cores.is_empty() {
        logical_fallback
    } else {
        cores.len()
    }
}

fn p7b_machine_eligible(
    cloud: Option<&CloudMetadata>,
    rayon_threads: usize,
    fase_d_realpcg_profile: bool,
) -> bool {
    let Some(cloud) = cloud else {
        return false;
    };
    let metadata_present = [
        &cloud.provider,
        &cloud.instance_id,
        &cloud.region,
        &cloud.image,
        &cloud.driver_version,
        &cloud.cuda_version,
        &cloud.gpu_sku,
        &cloud.cpu_model,
        &cloud.ram_gib,
        &cloud.vcpus,
    ]
    .into_iter()
    .all(|value| !value.trim().is_empty());
    let common = metadata_present
        && rayon_threads == P7B_OFFICIAL_RAYON_THREADS
        && cloud.provider == "RunPod"
        && cloud.gpu_sku == "NVIDIA A100-SXM4-80GB";
    if fase_d_realpcg_profile {
        // The new host class is intentionally first-measurement: preserve
        // complete metadata without inheriting the old pod's CPU, region,
        // RAM, image, driver, or CUDA-version identity as an eligibility gate.
        common
    } else {
        common
            && cloud.region == "eur-is-1"
            && cloud.image == "Ubuntu 24.04.3 LTS"
            && cloud.driver_version == "580.159.04"
            && cloud.cuda_version == "12.8"
            && cloud.cpu_model == "AMD EPYC 7713 64-Core Processor"
            && cloud.ram_gib == "1008"
            && cloud.vcpus == "255"
    }
}

fn synchronization_wall_fraction(stats: &BackendStats, session_wall_s: f64) -> f64 {
    assert!(session_wall_s.is_finite() && session_wall_s > 0.0);
    let fraction = stats.synchronization_ns as f64 / 1e9 / session_wall_s;
    assert!(fraction.is_finite() && fraction >= 0.0);
    fraction
}

fn p7b_communication_gate(
    transcript_bytes: u64,
    pcs_opening_bytes: u64,
    packed_logits_bytes: u64,
    fase_d_realpcg_profile: bool,
) -> bool {
    if fase_d_realpcg_profile {
        return transcript_bytes == C1_TRANSCRIPT_BYTES
            && pcs_opening_bytes == P7B_PCS_OPENING_REFERENCE_BYTES
            && packed_logits_bytes == P7B_PACKED_LOGITS_REFERENCE_BYTES
            && transcript_bytes
                .checked_add(packed_logits_bytes)
                .is_some_and(|total| total == C1_PACKED_RESPONSE_BYTES);
    }
    transcript_bytes <= P7B_TRANSCRIPT_REFERENCE_BYTES
        && pcs_opening_bytes <= P7B_PCS_OPENING_REFERENCE_BYTES
        && packed_logits_bytes <= P7B_PACKED_LOGITS_REFERENCE_BYTES
        && transcript_bytes
            .checked_add(packed_logits_bytes)
            .is_some_and(|total| total <= P7B_PACKED_RESPONSE_REFERENCE_BYTES)
}

#[allow(clippy::too_many_arguments)]
fn p7b_gate_eligible(
    git_sha_before_benchmark: &str,
    git_sha_before_serialization: &str,
    git_dirty_before_benchmark: bool,
    git_dirty_before_serialization: bool,
    machine_eligible: bool,
    quick: bool,
    t_prefill: usize,
    n_decode: usize,
    pcs_queries: usize,
    expected_pcs_queries: usize,
    warmup_repetitions: usize,
    measured_repetitions: usize,
) -> bool {
    git_revision_unchanged(git_sha_before_benchmark, git_sha_before_serialization)
        && !git_dirty_before_benchmark
        && !git_dirty_before_serialization
        && machine_eligible
        && !quick
        && t_prefill == 100
        && n_decode == 50
        && pcs_queries == expected_pcs_queries
        && warmup_repetitions >= 1
        && measured_repetitions >= 3
}

#[derive(Serialize)]
struct GitProvenance {
    /// Compatibility field: always the full commit captured before benchmark work.
    git_sha: String,
    git_dirty: bool,
    git_dirty_before_benchmark: bool,
    git_dirty_before_serialization: bool,
    /// Schema-6 provenance window. CPU schema-2 reports omit these additive fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    git_sha_before_benchmark: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_sha_before_serialization: Option<String>,
}

#[derive(Clone, Serialize)]
struct BenchmarkRepetitionRow {
    repetition: usize,
    seed: u8,
    t_prove_prefill_only_s: f64,
    t_prove_response_s: f64,
    t_prove_decode_marginal_s: f64,
    t_prover_online_accounted_response_s: f64,
    t_prover_online_accounted_decode_marginal_s: f64,
    t_response_session_wall_s: f64,
    t_protocol_closure_exchange_s: f64,
    t_verify_response_s: f64,
    t_verifier_accounted_s: f64,
    pcs_commit_total_s: f64,
    pcs_open_total_s: f64,
    pcs_verify_total_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_wall_fraction: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_prefill: Option<AcceleratorStatsRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_session: Option<AcceleratorStatsRow>,
}

impl AcceleratorStatsRow {
    fn from_stats(stats: BackendStats, scope: &str) -> Self {
        assert_eq!(
            stats.timing_elapsed_query_attempts,
            stats.timing_event_queries + stats.timing_elapsed_no_write,
            "elapsed CUDA timing query accounting must close"
        );
        if stats.timing_mode == DeviceTimingMode::WallOnlyCounters {
            assert_eq!(stats.timing_records, 0, "counter-only mode cannot enqueue event records");
            assert_eq!(
                stats.timing_event_api_calls, 0,
                "counter-only mode cannot issue CUDA event API calls"
            );
            assert_eq!(stats.timing_elapsed_query_attempts, 0);
            assert_eq!(stats.timing_event_queries, 0);
            assert_eq!(stats.timing_elapsed_no_write, 0);
            assert_eq!(stats.h2d_ns, 0);
            assert_eq!(stats.d2h_ns, 0);
            assert_eq!(stats.kernel_ns(), 0);
            assert_eq!(stats.coarse_timing_ns, 0);
        }
        let phase_attribution_available = stats.timing_mode.phase_attribution_available();
        let operations = Operation::ALL
            .into_iter()
            .map(|op| {
                let row = stats.operation(op);
                (
                    op.name().to_string(),
                    AcceleratorOperationRow {
                        calls: row.calls,
                        kernel_s: phase_attribution_available.then_some(row.kernel_ns as f64 / 1e9),
                        cpu_residual_s: row.cpu_residual_ns as f64 / 1e9,
                    },
                )
            })
            .collect();
        AcceleratorStatsRow {
            scope: scope.to_string(),
            operations,
            timing_method: stats.timing_mode.name().to_string(),
            phase_attribution_available,
            measurement_wall_s: stats.measurement_wall_ns as f64 / 1e9,
            operation_cpu_residual_s: stats.operation_cpu_residual_ns() as f64 / 1e9,
            unattributed_cpu_residual_s: phase_attribution_available
                .then_some(stats.unattributed_cpu_residual_ns as f64 / 1e9),
            h2d_bytes: stats.h2d_bytes,
            d2h_bytes: stats.d2h_bytes,
            explicit_d2d_copy_bytes: stats.explicit_d2d_copy_bytes,
            device_zeroed_bytes: stats.device_zeroed_bytes,
            device_generated_bytes: stats.device_generated_bytes,
            h2d_s: phase_attribution_available.then_some(stats.h2d_ns as f64 / 1e9),
            d2h_s: phase_attribution_available.then_some(stats.d2h_ns as f64 / 1e9),
            resident_h2d_host_calls: stats.resident_h2d_host_calls,
            resident_d2h_host_calls: stats.resident_d2h_host_calls,
            resident_h2d_host_call_s: stats.resident_h2d_host_call_ns as f64 / 1e9,
            resident_d2h_host_call_s: stats.resident_d2h_host_call_ns as f64 / 1e9,
            synchronizations: stats.synchronizations,
            synchronization_s: stats.synchronization_ns as f64 / 1e9,
            sync_host_output: stats.sync_host_output,
            sync_upload_lifetime: stats.sync_upload_lifetime,
            sync_timing_flush: stats.sync_timing_flush,
            sync_profiling_legacy: stats.sync_profiling_legacy,
            sync_allocator_flush: stats.sync_allocator_flush,
            allocation_calls: stats.allocation_calls,
            resident_alloc_requests: stats.resident_alloc_requests,
            resident_reuse_hits: stats.resident_reuse_hits,
            resident_free_requests: stats.resident_free_requests,
            physical_free_calls: stats.physical_free_calls,
            live_device_bytes: stats.live_device_bytes,
            peak_device_bytes: stats.peak_device_bytes,
            timing_records: stats.timing_records,
            timing_elapsed_query_attempts: stats.timing_elapsed_query_attempts,
            timing_elapsed_no_write: stats.timing_elapsed_no_write,
            timing_event_queries: stats.timing_event_queries,
            timing_event_api_calls: stats.timing_event_api_calls,
            timing_pending_high_water: stats.timing_pending_high_water,
            timing_flush_count: stats.timing_flush_count,
            coarse_timing_scopes: stats.coarse_timing_scopes,
            coarse_timing_s: phase_attribution_available
                .then_some(stats.coarse_timing_ns as f64 / 1e9),
            kernel_s: phase_attribution_available.then_some(stats.kernel_ns() as f64 / 1e9),
            cpu_residual_s: phase_attribution_available
                .then_some(stats.cpu_residual_ns() as f64 / 1e9),
        }
    }
}

#[derive(Serialize)]
struct Report {
    report_schema_version: u32,
    milestone: String,
    date: String,
    #[serde(flatten)]
    git: GitProvenance,
    machine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud: Option<CloudMetadata>,
    threads: usize,
    accelerator_backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_cuda_abi_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resident_timing_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_witness: Option<AcceleratorStatsRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_response_witness: Option<AcceleratorStatsRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_prefill_proving: Option<AcceleratorStatsRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_proving: Option<AcceleratorStatsRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_live_device_bytes_after_cleanup: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_workspace_device_bytes_after_cleanup: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_resident_device_bytes_after_cleanup: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_cached_resident_device_bytes_after_cleanup: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_live_device_bytes_after_cache_trim: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_workspace_device_bytes_after_cache_trim: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_resident_device_bytes_after_cache_trim: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator_cached_resident_device_bytes_after_cache_trim: Option<u64>,
    benchmark_warmup_repetitions: usize,
    benchmark_repetitions: usize,
    representative_repetition: usize,
    repetitions: Vec<BenchmarkRepetitionRow>,
    t_prefill: usize,
    n_decode: usize,
    // --- verdicts -------------------------------------------------------------
    accepted: bool,
    golden_decode_checked: bool,
    golden_decode_match: Option<bool>,
    generated_tokens: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c1_identity_seam_reuse: Option<C1IdentitySeamReuse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flip_readiness_criterion_2_runtime_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flip_readiness_criterion_3_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flip_readiness_external_review_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flip_readiness_cost_acceptance_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flip_readiness_default_flip_pending: Option<bool>,
    // P7b gates are emitted only by the resident schema. Quick runs retain
    // observations but deliberately do not emit pass/fail verdicts.
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_gate_evaluated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_gate_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_machine_eligible: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_timing_statistic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_counter_statistic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_prefill_core_gate_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_decode_marginal_gate_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_count_gate_retired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_wall_fraction_gate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_h2d_gate_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_prefill_core_observed_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_decode_marginal_observed_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_observed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_wall_fraction_observed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_h2d_observed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_prefill_core_gate_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_decode_marginal_gate_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_sync_wall_fraction_gate_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_h2d_gate_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_communication_envelope_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_communication_observed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_communication_invariant_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_transcript_reference_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_pcs_opening_reference_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_packed_logits_reference_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_packed_response_reference_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_response_communication_no_growth_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p7b_all_gates_pass: Option<bool>,
    // --- native baselines -------------------------------------------------------
    t_native_prefill_s: f64,
    /// KV-cached incremental decode, 50 steps (witness-free native anchor).
    t_native_decode_s: f64,
    native_timing_method: String,
    native_timing_rounds: usize,
    native_prefill_timing: TimingDistribution,
    native_decode_timing: TimingDistribution,
    native_decode_tokens_per_s: f64,
    // --- proving (run of record: prefill + ONE Q=50 chunk) ---------------------
    t_prove_prefill_only_s: f64,
    t_prove_response_s: f64,
    t_prove_decode_marginal_s: f64,
    /// Online prover components available in this single-process harness:
    /// protocol core + PCS opening + final product/zero closure exchange.
    /// The closure exchange contains both roles and is also broken out.
    t_prover_online_accounted_response_s: f64,
    t_prover_online_accounted_decode_marginal_s: f64,
    /// Actual wall around the whole response session: protocol core, public
    /// output codec, verifier, PCS commitment/open/verify and closures.
    t_response_session_wall_s: f64,
    t_protocol_closure_exchange_s: f64,
    t_verifier_accounted_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rho_prefill: Option<f64>,
    /// (prove_response − prove_prefill) / native decode wall — the decode
    /// marginal ratio (CPU; the ≤2 target is GPU, P7).
    #[serde(skip_serializing_if = "Option::is_none")]
    rho_decode: Option<f64>,
    rho_cpu_prefill: f64,
    rho_cpu_decode: f64,
    rho_denominator: String,
    verified_tokens_per_s: f64,
    t_verify_response_s: f64,
    prove_prefill_timing: TimingDistribution,
    prove_response_timing: TimingDistribution,
    prove_decode_marginal_timing: TimingDistribution,
    prover_online_accounted_response_timing: TimingDistribution,
    prover_online_accounted_decode_marginal_timing: TimingDistribution,
    response_session_wall_timing: TimingDistribution,
    protocol_closure_exchange_timing: TimingDistribution,
    verify_response_timing: TimingDistribution,
    verifier_accounted_timing: TimingDistribution,
    // --- flat-cost gate (5 chunks × 10 tokens, cache 100→150) ------------------
    chunk_curve: Vec<ChunkCurveRow>,
    curve_last_over_first: f64,
    gate_flat_cost_per_token: bool,
    t_prove_response_chunked_s: f64,
    chunked_accepted: bool,
    // --- communication -----------------------------------------------------------
    comm_prefill_bytes: u64,
    comm_response_bytes: u64,
    comm_decode_marginal_bytes: u64,
    comm_decode_bytes_per_token: u64,
    comm_prefill_by_label: BTreeMap<String, u64>,
    comm_response_by_label: BTreeMap<String, u64>,
    comm_pcs_by_label: BTreeMap<String, u64>,
    comm_decode_marginal_by_label: BTreeMap<String, u64>,
    /// PCS opening bytes are inside comm_response_bytes (transcript ledger).
    pcs_opening_bytes_total: u64,
    /// Accounting-only P7 lever: marginal PCS bytes if raw data columns plus
    /// their static commitment Merkle paths are verifier-cached.
    pcs_cached_query_marginal_bytes_total: u64,
    /// Public response outputs, NOT in the transcript: the band logits
    /// matrix (q×VOCAB×8) + the prefill last-row logits (VOCAB×8).
    public_logits_bytes: u64,
    /// Same logits bit-packed (VLPK1 row codec, handoff spec §4.6.E) — the
    /// actual download; the verifier consumes the decoded matrix.
    public_logits_packed_bytes: u64,
    total_response_download_bytes: u64,
    /// comm_response_bytes + public_logits_packed_bytes (packed download).
    total_response_download_packed_bytes: u64,
    // --- PCS (stacked claims) -----------------------------------------------------
    pcs_n_queries: usize,
    pcs_rate: f64,
    pcs_relative_distance: f64,
    pcs_query_error_bits: f64,
    pcs_commitments: Vec<PcsCommitmentRow>,
    pcs_commit_total_s: f64,
    pcs_open_total_s: f64,
    pcs_verify_total_s: f64,
    pcs_commit_timing: TimingDistribution,
    pcs_open_timing: TimingDistribution,
    pcs_verify_timing: TimingDistribution,
    n_weight_claims: usize,
    n_embed_claims: usize,
    closure_prod_claims: usize,
    closure_zero_claims: usize,
    closure_prod_scalar_soundness_bits: f64,
    closure_zero_scalar_soundness_bits: f64,
    closure_union_scalar_soundness_bits: f64,
    // --- counters -------------------------------------------------------------------
    emult_instances_total: f64,
    corr_sub_corrs: u64,
    corr_full_corrs: u64,
    peak_rss_gb: f64,
    // --- PCG backend gate ---------------------------------------------------------
    pcg_backend: String,
    ggm_prg: String,
    ggm_aes_feature: String,
    detected_physical_cpu_cores: usize,
    detected_logical_cpu_cores: usize,
    pcg_setup_rayon_threads: usize,
    pcg_production_ready: bool,
    pcg_setup_comm_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_instances: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_bytes_per_instance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_prover_to_verifier_bytes_per_instance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_verifier_to_prover_bytes_per_instance: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_total_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_base_ot_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_ot_extension_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_ggm_pprf_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_lpn_expand_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_consistency_check_s_per_instance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_production_entropy_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_independent_role_entropy_samples: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_session_channel_identity_bound: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_response_authorization_burned_before_setup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_burn_on_success_or_abort: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_reconnect_retry_resume_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_session_binding_digests_unique: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_role_seed_commitments_distinct: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_wire_count_invariant_pass: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_mock_prepass_channel_ledger_digest_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_mock_prepass_allocation_digest_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_base_vole: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_a_total_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_a_setup_stub_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_a_ggm_pprf_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_a_lpn_expand_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_a_consistency_check_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_total_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_base_ot_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_ot_extension_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_ggm_pprf_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_lpn_expand_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_real_phase_b_consistency_check_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_prover_to_verifier_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_verifier_to_prover_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_base_ot_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_ot_extension_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_ggm_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_setup_comm_consistency_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_channel_transcripts_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_mock_prepass_counters_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcg_allocation_hash_match: Option<bool>,
}

#[derive(Serialize)]
struct C1IdentitySeamReuse {
    scope: &'static str,
    baseline_artifact: &'static str,
    baseline_transcript_bytes: u64,
    baseline_auth_correction_bytes: u64,
    baseline_packed_response_bytes: u64,
    identity_seam_alias_values: u64,
    saved_response_bytes: u64,
    measured_transcript_bytes: u64,
    measured_auth_correction_bytes: u64,
    measured_packed_response_bytes: u64,
    baseline_sub_corrs: u64,
    measured_prover_sub_corrs: u64,
    measured_verifier_sub_corrs: u64,
    measured_prover_full_corrs: u64,
    measured_verifier_full_corrs: u64,
    full_corrs_unchanged: bool,
    pcs_parameters_unchanged: bool,
    claims_unchanged: bool,
    byte_formulas_reconcile: bool,
    counters_reconcile: bool,
    baseline_prove_response_s: f64,
    measured_prove_response_s: f64,
    prove_response_delta_s: f64,
    baseline_verify_response_s: f64,
    measured_verify_response_s: f64,
    verify_response_delta_s: f64,
    typed_correlation_lanes: u64,
    second_phase_b_shard_required: bool,
}

fn peak_rss_gb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<f64>().ok())
        .map(|kb| kb / 1024.0 / 1024.0)
        .unwrap_or(0.0)
}

fn detected_aes_feature() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("aes") {
        return "aes-ni";
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        return "armv8-ce";
    }
    "portable"
}

fn weights_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
}

fn ledger_to_owned(tx: &Transcript) -> BTreeMap<String, u64> {
    tx.ledger().iter().map(|(&k, &v)| (k.to_string(), v)).collect()
}

fn ledger_delta(
    total: &BTreeMap<String, u64>,
    subtract: &[&BTreeMap<String, u64>],
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (k, &v) in total {
        let mut x = v;
        for s in subtract {
            x = x.saturating_sub(s.get(k).copied().unwrap_or(0));
        }
        if x > 0 {
            out.insert(k.clone(), x);
        }
    }
    out
}

#[derive(Clone)]
struct Args {
    quick: bool,
    c1_record: bool,
    flip_readiness_record: bool,
    pcs_q: Option<usize>,
    pcg_backend: PcgBackendArg,
    ggm_prg: GgmPrg,
    diagnostic: bool,
    pcg_authorization_store: Option<PathBuf>,
    accelerator: AcceleratorArg,
    resident_timing: ResidentTimingArg,
    repetitions: Option<usize>,
    warmup_repetitions: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PcgBackendArg {
    Mock,
    Real,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AcceleratorArg {
    Cpu,
    CudaHybrid,
    CudaResident,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResidentTimingArg {
    DeferredEvents,
    WallOnlyCounters,
}

impl ResidentTimingArg {
    fn as_str(self) -> &'static str {
        match self {
            ResidentTimingArg::DeferredEvents => "deferred-events",
            ResidentTimingArg::WallOnlyCounters => "wall-only-counters",
        }
    }

    fn policy(self) -> ResidentTimingPolicy {
        match self {
            ResidentTimingArg::DeferredEvents => ResidentTimingPolicy::DeferredEvents,
            ResidentTimingArg::WallOnlyCounters => ResidentTimingPolicy::WallOnlyCounters,
        }
    }
}

impl AcceleratorArg {
    fn as_str(self) -> &'static str {
        match self {
            AcceleratorArg::Cpu => "cpu",
            AcceleratorArg::CudaHybrid => "cuda-hybrid",
            AcceleratorArg::CudaResident => "cuda-resident",
        }
    }
}

impl PcgBackendArg {
    fn as_str(self) -> &'static str {
        match self {
            PcgBackendArg::Mock => "mock",
            PcgBackendArg::Real => "real",
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: p6_report [--quick|--c1-record|--flip-readiness-record] [--pcs-q Q] \
         [--pcg-backend mock|real] [--pcg-authorization-store PATH] \
         [--ggm-prg aes128-mmo|blake3] [--diagnostic] \
         [--accelerator cpu|cuda-hybrid|cuda-resident] [--repetitions N] \
         [--warmup-repetitions N] \
         [--resident-timing deferred-events|wall-only-counters]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut out = Args {
        quick: false,
        c1_record: false,
        flip_readiness_record: false,
        pcs_q: None,
        pcg_backend: PcgBackendArg::Real,
        ggm_prg: GgmPrg::Aes128Mmo,
        diagnostic: false,
        pcg_authorization_store: None,
        accelerator: AcceleratorArg::Cpu,
        resident_timing: ResidentTimingArg::DeferredEvents,
        repetitions: None,
        warmup_repetitions: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--quick" {
            out.quick = true;
        } else if a == "--c1-record" {
            out.c1_record = true;
        } else if a == "--flip-readiness-record" {
            out.flip_readiness_record = true;
        } else if a == "--pcs-q" {
            let Some(q) = args.next() else { usage() };
            out.pcs_q = Some(q.parse().unwrap_or_else(|_| usage()));
        } else if let Some(q) = a.strip_prefix("--pcs-q=") {
            out.pcs_q = Some(q.parse().unwrap_or_else(|_| usage()));
        } else if a == "--pcg-backend" {
            let Some(b) = args.next() else { usage() };
            out.pcg_backend = parse_pcg_backend(&b);
        } else if let Some(b) = a.strip_prefix("--pcg-backend=") {
            out.pcg_backend = parse_pcg_backend(b);
        } else if a == "--ggm-prg" {
            let Some(prg) = args.next() else { usage() };
            out.ggm_prg = prg.parse().unwrap_or_else(|_| usage());
        } else if let Some(prg) = a.strip_prefix("--ggm-prg=") {
            out.ggm_prg = prg.parse().unwrap_or_else(|_| usage());
        } else if a == "--diagnostic" {
            out.diagnostic = true;
        } else if a == "--pcg-authorization-store" {
            let Some(path) = args.next() else { usage() };
            out.pcg_authorization_store = Some(PathBuf::from(path));
        } else if let Some(path) = a.strip_prefix("--pcg-authorization-store=") {
            out.pcg_authorization_store = Some(PathBuf::from(path));
        } else if a == "--accelerator" {
            let Some(b) = args.next() else { usage() };
            out.accelerator = parse_accelerator(&b);
        } else if let Some(b) = a.strip_prefix("--accelerator=") {
            out.accelerator = parse_accelerator(b);
        } else if a == "--resident-timing" {
            let Some(mode) = args.next() else { usage() };
            out.resident_timing = parse_resident_timing(&mode);
        } else if let Some(mode) = a.strip_prefix("--resident-timing=") {
            out.resident_timing = parse_resident_timing(mode);
        } else if a == "--repetitions" {
            let Some(n) = args.next() else { usage() };
            out.repetitions = Some(n.parse().unwrap_or_else(|_| usage()));
        } else if let Some(n) = a.strip_prefix("--repetitions=") {
            out.repetitions = Some(n.parse().unwrap_or_else(|_| usage()));
        } else if a == "--warmup-repetitions" {
            let Some(n) = args.next() else { usage() };
            out.warmup_repetitions = Some(n.parse().unwrap_or_else(|_| usage()));
        } else if let Some(n) = a.strip_prefix("--warmup-repetitions=") {
            out.warmup_repetitions = Some(n.parse().unwrap_or_else(|_| usage()));
        } else {
            usage();
        }
    }
    out
}

fn parse_accelerator(s: &str) -> AcceleratorArg {
    match s {
        "cpu" => AcceleratorArg::Cpu,
        "cuda-hybrid" => AcceleratorArg::CudaHybrid,
        "cuda-resident" => AcceleratorArg::CudaResident,
        _ => usage(),
    }
}

fn parse_resident_timing(s: &str) -> ResidentTimingArg {
    match s {
        "deferred-events" => ResidentTimingArg::DeferredEvents,
        "wall-only-counters" => ResidentTimingArg::WallOnlyCounters,
        _ => usage(),
    }
}

fn parse_pcg_backend(s: &str) -> PcgBackendArg {
    match s {
        "mock" => PcgBackendArg::Mock,
        "real" => PcgBackendArg::Real,
        _ => usage(),
    }
}

fn pcs_query_error_bits(params: &LigeroParams) -> f64 {
    let rate = params.msg_len() as f64 / params.code_len() as f64;
    let delta = 1.0 - rate;
    -(params.n_queries as f64) * (1.0 - delta / 2.0).log2()
}

fn same_ligero_params(a: &LigeroParams, b: &LigeroParams) -> bool {
    a.row_bits == b.row_bits
        && a.col_bits == b.col_bits
        && a.pad == b.pad
        && a.code_bits == b.code_bits
        && a.n_queries == b.n_queries
}

fn create_unique_result_file(
    label: &str,
    date: &str,
    sha: &str,
) -> (std::path::PathBuf, std::fs::File) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results");
    for suffix in 0..1000 {
        let filename = if suffix == 0 {
            format!("{label}-{date}-{sha}.json")
        } else {
            format!("{label}-{date}-{sha}-{suffix}.json")
        };
        let path = dir.join(filename);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return (path, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("could not create append-only result {}: {error}", path.display()),
        }
    }
    panic!("could not find unused append-only result path for {label}-{date}-{sha}");
}

/// One full response session: prove + verify + PCS + closures. Returns
/// (accepted, prove_s, verify_s, comm_bytes, pcs rows/times, out counters,
/// per-chunk phase timings).
#[allow(clippy::type_complexity)]
struct SessionResult {
    accepted: bool,
    prove_s: f64,
    verify_s: f64,
    session_wall_s: f64,
    closure_exchange_s: f64,
    comm_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    pcs_by_label: BTreeMap<String, u64>,
    pcs_rows: Vec<PcsCommitmentRow>,
    pcs_opening_bytes: u64,
    pcs_cached_query_marginal_bytes: u64,
    n_weight_claims: usize,
    n_embed_claims: usize,
    closure_prod_claims: usize,
    closure_zero_claims: usize,
    emult_instances: f64,
    sub_corrs: u64,
    full_corrs: u64,
    verifier_protocol_sub_corrs: u64,
    verifier_protocol_full_corrs: u64,
    identity_seam_alias_values: u64,
    pcg_pool_sub_corrs: u64,
    pcg_pool_full_corrs: u64,
    chunk_p1_s: Vec<f64>,
    chunk_p2_s: Vec<f64>,
    public_logits_packed_bytes: u64,
    pcg_allocation_hash_match: Option<bool>,
    accelerator_stats: Option<BackendStats>,
}

fn digest_u64_map(domain: &[u8], values: &BTreeMap<String, u64>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for (label, value) in values {
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn logical_allocation_digest(session: &SessionResult) -> String {
    let mut values = BTreeMap::new();
    values.insert("protocol/sub".into(), session.sub_corrs);
    values.insert("protocol/full".into(), session.full_corrs);
    values.insert("verifier/sub".into(), session.verifier_protocol_sub_corrs);
    values.insert("verifier/full".into(), session.verifier_protocol_full_corrs);
    values.insert("pool/sub".into(), session.pcg_pool_sub_corrs);
    values.insert("pool/full".into(), session.pcg_pool_full_corrs);
    values.insert("identity-seam-aliases".into(), session.identity_seam_alias_values);
    digest_u64_map(b"volta-pcg/logical-allocation-schedule/v1", &values)
}

fn assert_mock_real_parity(
    gate: &mut PcgGateStats,
    mock: &SessionResult,
    real: &SessionResult,
    label: &str,
) {
    let counters_match = mock.sub_corrs == real.sub_corrs
        && mock.full_corrs == real.full_corrs
        && mock.pcg_pool_sub_corrs == real.pcg_pool_sub_corrs
        && mock.pcg_pool_full_corrs == real.pcg_pool_full_corrs;
    let channel_ledger_digest_match =
        digest_u64_map(b"volta-pcg/mock-real-channel-ledger/v1", &mock.transcript_by_label)
            == digest_u64_map(b"volta-pcg/mock-real-channel-ledger/v1", &real.transcript_by_label);
    let allocation_digest_match =
        logical_allocation_digest(mock) == logical_allocation_digest(real);
    gate.mock_prepass_counters_match =
        Some(gate.mock_prepass_counters_match.unwrap_or(true) && counters_match);
    gate.mock_prepass_channel_ledger_digest_match = Some(
        gate.mock_prepass_channel_ledger_digest_match.unwrap_or(true)
            && channel_ledger_digest_match,
    );
    gate.mock_prepass_allocation_digest_match =
        Some(gate.mock_prepass_allocation_digest_match.unwrap_or(true) && allocation_digest_match);
    gate.allocation_hash_match = Some(
        gate.allocation_hash_match.unwrap_or(true)
            && real.pcg_allocation_hash_match.unwrap_or(false),
    );
    assert!(counters_match, "real-PCG {label} counters must match mock prepass");
    assert!(channel_ledger_digest_match, "real-PCG {label} channel ledger must match mock prepass");
    assert!(allocation_digest_match, "real-PCG {label} allocation digest must match mock prepass");
}

/// `E = F_p^2`.  The scalar-power implementation theorems bound a batch of
/// `T` claims by `(T+offset)/|E|`; report the corresponding conservative
/// `-log2(error)` rather than quoting the stronger vector-RLC constant.
fn scalar_batch_soundness_bits(claims: usize, offset: usize) -> f64 {
    2.0 * (P as f64).log2() - ((claims + offset) as f64).log2()
}

enum SessionProverMatrix {
    Host(ProverMatrix),
    Resident(ResidentProverMatrix),
}

struct PrefillResult {
    prove_s: f64,
    comm_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    accelerator_stats: Option<BackendStats>,
}

fn run_prefill(
    model: &Gpt2Model,
    wit: &volta_gpt2::ModelWitness,
    seed: u8,
    mut accelerator: Option<&mut Backend>,
) -> PrefillResult {
    let t0 = Instant::now();
    let mut stream = CorrelationStream::new([seed; 32]);
    let mut tx = Transcript::new([seed ^ 0x5A; 32]);
    let accelerator_stats = if let Some(accel) = accelerator.as_deref_mut() {
        accel.begin_measurement().expect("begin CUDA prefill measurement");
        let _ = prove_model_with_backend(model, wit, &mut stream, &mut tx, accel);
        Some(accel.finish_measurement().expect("finish CUDA prefill measurement"))
    } else {
        let _ = prove_model(model, wit, &mut stream, &mut tx);
        None
    };
    PrefillResult {
        prove_s: t0.elapsed().as_secs_f64(),
        comm_bytes: tx.total_bytes(),
        transcript_by_label: ledger_to_owned(&tx),
        accelerator_stats,
    }
}

fn run_prefill_resident(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    witness: &ResidentModelWitness,
    public_logits: &[i64],
    error: DeviceSlice<'_, u32>,
    seed: u8,
    backend: &mut Backend,
) -> PrefillResult {
    assert_eq!(backend.kind(), BackendKind::CudaResident);
    let started = Instant::now();
    let mut stream = CorrelationStream::new([seed; 32]);
    let mut tx = Transcript::new([seed ^ 0x5A; 32]);
    backend.begin_measurement().expect("begin resident prefill measurement");
    let _ = prove_model_resident(
        model,
        resident_model,
        witness,
        public_logits,
        error,
        &mut stream,
        &mut tx,
        backend,
    )
    .expect("resident prefill proof");
    let stats = backend.finish_measurement().expect("finish resident prefill measurement");
    PrefillResult {
        prove_s: started.elapsed().as_secs_f64(),
        comm_bytes: tx.total_bytes(),
        transcript_by_label: ledger_to_owned(&tx),
        accelerator_stats: Some(stats),
    }
}

enum SessionPcgBackend {
    Mock,
    Real { prover: ProverPcgPool, verifier: VerifierPcgPool, delta: Fp2 },
}

#[derive(Default)]
struct PcgGateStats {
    setup_comm_bytes: u64,
    setup_comm_prover_to_verifier_bytes: u64,
    setup_comm_verifier_to_prover_bytes: u64,
    setup_comm_base_ot_bytes: u64,
    setup_comm_ot_extension_bytes: u64,
    setup_comm_ggm_bytes: u64,
    setup_comm_consistency_bytes: u64,
    timings: Option<PhaseBTimings>,
    channel_transcripts_match: Option<bool>,
    mock_prepass_counters_match: Option<bool>,
    allocation_hash_match: Option<bool>,
    setup_instances: usize,
    per_setup_comm: Option<SetupCommBreakdown>,
    per_setup_timings: Option<PhaseBTimings>,
    production_entropy_source: Option<String>,
    independent_role_entropy_samples: bool,
    session_channel_identity_bound: bool,
    response_authorization_burned_before_setup: bool,
    burn_on_success_or_abort: bool,
    reconnect_retry_resume_allowed: bool,
    session_binding_digests: BTreeSet<String>,
    prover_role_seed_commitments: BTreeSet<String>,
    verifier_role_seed_commitments: BTreeSet<String>,
    role_seed_commitments_distinct: bool,
    setup_wire_count_invariant_pass: bool,
    mock_prepass_channel_ledger_digest_match: Option<bool>,
    mock_prepass_allocation_digest_match: Option<bool>,
}

fn session_delta() -> Fp2 {
    Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE))
}

/// Response-fresh, role-separated PCS masking randomness. This is prover-side
/// input; it is deliberately independent of transcript challenges and Delta.
fn pcs_mask_seed(session_seed: u8, role: u8, instance: u8) -> [u8; 32] {
    let mut mask_seed = [role; 32];
    mask_seed[29] = session_seed;
    mask_seed[30] = role;
    mask_seed[31] = instance;
    mask_seed
}

fn os_random_identity(label: &str) -> [u8; 32] {
    let mut value = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut value)
        .unwrap_or_else(|error| panic!("OS entropy unavailable for {label}: {error}"));
    value
}

fn real_session_backend(
    authorization_store: &ResponseAuthorizationStore,
    sub_corrs: u64,
    full_corrs: u64,
    ggm_prg: GgmPrg,
) -> (SessionPcgBackend, PhaseBTimings, SetupCommBreakdown, ProductionSetupAudit, bool) {
    let params = volta_pcg::PhaseAParams::for_counts(sub_corrs as usize, full_corrs as usize);
    let binding = SessionBinding::new(
        os_random_identity("PCG session identity"),
        os_random_identity("authenticated PCG channel identity"),
        os_random_identity("response-authorization nonce"),
    )
    .expect("nonzero OS-generated phase-B identities");
    let production = expand_phase_b_production_with_ggm_prg(
        authorization_store,
        binding,
        sub_corrs as usize,
        full_corrs as usize,
        params,
        ggm_prg,
    )
    .expect("production-provisioned real two-party phase-B PCG setup");
    let channel_transcripts_match = production.expansion.setup.setup_binding_digest
        == production.expansion.setup.channel.transcript_digest;
    let expansion = production.expansion;
    let setup_comm = expansion.setup.comm.clone();
    (
        SessionPcgBackend::Real {
            prover: expansion.prover,
            verifier: expansion.verifier,
            delta: expansion.verifier_delta,
        },
        expansion.timings,
        setup_comm,
        production.production,
        channel_transcripts_match,
    )
}

fn add_timings(dst: &mut Option<PhaseBTimings>, src: PhaseBTimings) {
    if let Some(d) = dst {
        d.t_base_ot_s += src.t_base_ot_s;
        d.t_ot_extension_s += src.t_ot_extension_s;
        d.t_base_vole_from_setup_s += src.t_base_vole_from_setup_s;
        d.t_ggm_pprf_s += src.t_ggm_pprf_s;
        d.t_lpn_expand_s += src.t_lpn_expand_s;
        d.t_full_combine_s += src.t_full_combine_s;
        d.t_consistency_check_s += src.t_consistency_check_s;
        d.t_total_setup_and_expansion_s += src.t_total_setup_and_expansion_s;
    } else {
        *dst = Some(src);
    }
}

fn add_setup_comm(dst: &mut PcgGateStats, src: &SetupCommBreakdown) {
    dst.setup_instances += 1;
    if let Some(reference) = &dst.per_setup_comm {
        assert_eq!(src.total_bytes, reference.total_bytes);
        assert_eq!(src.prover_to_verifier_bytes, reference.prover_to_verifier_bytes);
        assert_eq!(src.verifier_to_prover_bytes, reference.verifier_to_prover_bytes);
        assert_eq!(src.base_ot_bytes, reference.base_ot_bytes);
        assert_eq!(src.ot_extension_bytes, reference.ot_extension_bytes);
        assert_eq!(src.ggm_bytes, reference.ggm_bytes);
        assert_eq!(src.consistency_bytes, reference.consistency_bytes);
    } else {
        dst.per_setup_comm = Some(src.clone());
    }
    // Fase-D changes GGM seed width and therefore establishes new exact byte
    // assertions only from Part-B measurements.  The frozen 31,261,434-byte
    // fase-B value is intentionally not inherited here.
    let wire_count_invariant = src.total_bytes
        == src.prover_to_verifier_bytes + src.verifier_to_prover_bytes
        && src.total_bytes
            == src.base_ot_bytes + src.ot_extension_bytes + src.ggm_bytes + src.consistency_bytes;
    dst.setup_wire_count_invariant_pass =
        (dst.setup_instances == 1 || dst.setup_wire_count_invariant_pass) && wire_count_invariant;
    assert!(wire_count_invariant, "phase-B serialized channel byte count changed");
    dst.setup_comm_bytes += src.total_bytes;
    dst.setup_comm_prover_to_verifier_bytes += src.prover_to_verifier_bytes;
    dst.setup_comm_verifier_to_prover_bytes += src.verifier_to_prover_bytes;
    dst.setup_comm_base_ot_bytes += src.base_ot_bytes;
    dst.setup_comm_ot_extension_bytes += src.ot_extension_bytes;
    dst.setup_comm_ggm_bytes += src.ggm_bytes;
    dst.setup_comm_consistency_bytes += src.consistency_bytes;
}

fn add_production_setup(
    dst: &mut PcgGateStats,
    timing: PhaseBTimings,
    audit: ProductionSetupAudit,
    channel_transcripts_match: bool,
) {
    if dst.per_setup_timings.is_none() {
        dst.per_setup_timings = Some(timing);
    }
    add_timings(&mut dst.timings, timing);
    if let Some(source) = &dst.production_entropy_source {
        assert_eq!(source, &audit.entropy_source);
    } else {
        dst.production_entropy_source = Some(audit.entropy_source.clone());
    }
    dst.independent_role_entropy_samples = (dst.setup_instances == 1
        || dst.independent_role_entropy_samples)
        && audit.independent_role_entropy_samples;
    dst.session_channel_identity_bound = (dst.setup_instances == 1
        || dst.session_channel_identity_bound)
        && audit.session_channel_identity_bound;
    dst.response_authorization_burned_before_setup = (dst.setup_instances == 1
        || dst.response_authorization_burned_before_setup)
        && audit.response_authorization_burned_before_setup;
    dst.burn_on_success_or_abort = (dst.setup_instances == 1 || dst.burn_on_success_or_abort)
        && audit.burn_on_success_or_abort;
    dst.reconnect_retry_resume_allowed = (dst.setup_instances != 1
        && dst.reconnect_retry_resume_allowed)
        || audit.reconnect_retry_resume_allowed;
    dst.role_seed_commitments_distinct = (dst.setup_instances == 1
        || dst.role_seed_commitments_distinct)
        && audit.role_seed_commitments_distinct;
    dst.session_binding_digests.insert(audit.session_binding_digest);
    dst.prover_role_seed_commitments.insert(audit.prover_role_seed_commitment);
    dst.verifier_role_seed_commitments.insert(audit.verifier_role_seed_commitment);
    dst.channel_transcripts_match =
        Some(dst.channel_transcripts_match.unwrap_or(true) && channel_transcripts_match);
}

struct ResidentSessionInput<'a, 'source> {
    model: &'a ResidentGpt2Model,
    witness: &'a ResidentModelWitness,
    bands: &'a [&'a ResidentBandModelWitness<'source>],
    error: &'a DeviceBuffer<u32>,
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    model: &Gpt2Model,
    wit: &volta_gpt2::ModelWitness,
    bands: &[&BandModelWitness],
    seq: &[u32],
    layer_params: &LigeroParams,
    embed_params: &LigeroParams,
    with_pcs: bool,
    seed: u8,
    pcg_backend: SessionPcgBackend,
    accelerator: Option<&mut Backend>,
) -> SessionResult {
    run_session_impl(
        model,
        wit,
        bands,
        seq,
        layer_params,
        embed_params,
        with_pcs,
        seed,
        pcg_backend,
        None,
        accelerator,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_session_resident<'source>(
    model: &Gpt2Model,
    wit: &volta_gpt2::ModelWitness,
    bands: &[&BandModelWitness],
    seq: &[u32],
    resident_model: &ResidentGpt2Model,
    resident_witness: &ResidentModelWitness,
    resident_bands: &[&ResidentBandModelWitness<'source>],
    error: &DeviceBuffer<u32>,
    layer_params: &LigeroParams,
    embed_params: &LigeroParams,
    with_pcs: bool,
    seed: u8,
    pcg_backend: SessionPcgBackend,
    backend: &mut Backend,
) -> SessionResult {
    run_session_impl(
        model,
        wit,
        bands,
        seq,
        layer_params,
        embed_params,
        with_pcs,
        seed,
        pcg_backend,
        Some(ResidentSessionInput {
            model: resident_model,
            witness: resident_witness,
            bands: resident_bands,
            error,
        }),
        Some(backend),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_session_impl<'source>(
    model: &Gpt2Model,
    wit: &volta_gpt2::ModelWitness,
    bands: &[&BandModelWitness],
    seq: &[u32],
    layer_params: &LigeroParams,
    embed_params: &LigeroParams,
    with_pcs: bool,
    seed: u8,
    pcg_backend: SessionPcgBackend,
    resident: Option<ResidentSessionInput<'_, 'source>>,
    mut accelerator: Option<&mut Backend>,
) -> SessionResult {
    let session_started = Instant::now();
    if let Some(accel) = accelerator.as_deref_mut() {
        accel.begin_measurement().expect("begin accelerator measurement");
    }
    let t = wit.t;
    let mock_delta = session_delta();
    let (mut stream, mut vc, delta) = match pcg_backend {
        SessionPcgBackend::Mock => (
            CorrelationStream::new([seed; 32]),
            VerifierCtx::new([seed; 32], mock_delta),
            mock_delta,
        ),
        SessionPcgBackend::Real { prover, verifier, delta } => (
            CorrelationStream::from_pcg_pool(prover),
            VerifierCtx::from_pcg_pool(delta, verifier),
            delta,
        ),
    };
    let mut txp = Transcript::new([seed ^ 0x5A; 32]);
    let mut txv = Transcript::new([seed ^ 0x5A; 32]);
    let resident_model_for_pcs = resident.as_ref().map(|input| input.model);

    let tp0 = Instant::now();
    let (proof, out, prod, zero) = if let Some(resident) = resident {
        assert_eq!(resident.bands.len(), bands.len());
        let resident_chunks: Vec<ResidentChunkRef> = resident
            .bands
            .iter()
            .zip(bands)
            .map(|(device, public)| ResidentChunkRef { band: device, logits: &public.logits, seq })
            .collect();
        let accel = accelerator.as_deref_mut().expect("resident session requires CUDA backend");
        prove_response_resident(
            model,
            resident.model,
            resident.witness,
            &wit.logits,
            &resident_chunks,
            DeviceSlice::new(resident.error, 0, 1).expect("resident proof error word"),
            &mut stream,
            &mut txp,
            accel,
        )
        .expect("resident response proof")
    } else if let Some(accel) = accelerator.as_deref_mut() {
        let chunks_p: Vec<ChunkRef> = bands.iter().map(|b| ChunkRef { band: b, seq }).collect();
        prove_response_with_backend(model, wit, &chunks_p, &mut stream, &mut txp, accel)
    } else {
        let chunks_p: Vec<ChunkRef> = bands.iter().map(|b| ChunkRef { band: b, seq }).collect();
        prove_response(model, wit, &chunks_p, &mut stream, &mut txp)
    };
    let prove_s = tp0.elapsed().as_secs_f64();

    // P7 prep (handoff spec §4.6.E): the public logits travel bit-packed;
    // the verifier consumes the DECODED matrix (asserted bit-exact), so the
    // packed size is the real download and the codec is on the e2e path.
    // Transport-only — nothing enters the transcript.
    let mut public_logits_packed_bytes = 0u64;
    let dec_prefill = {
        let buf = logits_pack::pack_logits(1, wit.logits.len(), &wit.logits);
        public_logits_packed_bytes += buf.len() as u64;
        let (_, _, dec) = logits_pack::unpack_logits(&buf).expect("prefill logits decode");
        assert_eq!(dec, wit.logits, "logits codec must be bit-exact");
        dec
    };
    let dec_bands: Vec<Vec<i64>> = bands
        .iter()
        .map(|b| {
            let buf = logits_pack::pack_logits(b.q, b.logits.len() / b.q, &b.logits);
            public_logits_packed_bytes += buf.len() as u64;
            let (_, _, dec) = logits_pack::unpack_logits(&buf).expect("band logits decode");
            assert_eq!(dec, b.logits, "logits codec must be bit-exact");
            dec
        })
        .collect();
    let chunks_v: Vec<ChunkPub> = bands
        .iter()
        .zip(&dec_bands)
        .map(|(b, dec)| ChunkPub { q: b.q, logits: dec, seq })
        .collect();
    let tv0 = Instant::now();
    let (outv, kprod, kzero) =
        verify_response(model, t, &dec_prefill, &chunks_v, &proof, &mut vc, &mut txv)
            .expect("honest response must verify");
    let verify_s = tv0.elapsed().as_secs_f64();
    let verifier_protocol_counters = vc.counters;

    // --- PCS: 13 commitments, claims stacked per layer across phases -------
    let phases = 1 + bands.len();
    let mut pcs_rows = Vec::new();
    let mut pcs_opening_bytes = 0u64;
    let mut pcs_cached_query_marginal_bytes = 0u64;
    let mut pcs_all_ok = true;
    let tx_before_pcs = ledger_to_owned(&txp);
    if with_pcs {
        assert_eq!(out.weight_claims.len(), 4 * L * phases);
        let layout = layout_gpt2_layer();
        for l in 0..L {
            // CPU/hybrid retain the historical host flattening. The resident
            // path places the already-resident proof views D2D, including the
            // mandatory CAttnProof permutation prepared at model setup.
            let w_flat = if resident_model_for_pcs.is_none() {
                let w = &model.layers[l].0;
                let w_perm = cattn_permuted(&w.c_attn);
                Some(layout.place([&w_perm, &w.attn_proj, &w.ffn_up, &w.ffn_down]))
            } else {
                None
            };
            let mut pad_seed = [0x51u8; 32];
            pad_seed[31] = l as u8;
            let tc0 = Instant::now();
            let (com, pm) = if let Some(accel) = accelerator.as_deref_mut() {
                if accel.kind() == BackendKind::CudaResident {
                    let resident_model = resident_model_for_pcs
                        .expect("resident PCS commitment requires resident model weights");
                    let fields = [
                        LayerWeightField::CAttnProof,
                        LayerWeightField::AttnProj,
                        LayerWeightField::FfnUp,
                        LayerWeightField::FfnDown,
                    ];
                    let placements: Vec<_> = fields
                        .into_iter()
                        .zip(&layout.tensors)
                        .map(|(field, slot)| {
                            let source = resident_model.layer_weight(l, field)?;
                            ResidentWeightPlacement::new(
                                source,
                                slot.k,
                                slot.n,
                                slot.offset,
                                slot.n_pad,
                                layout.total_len,
                            )
                        })
                        .collect::<Result<_, volta_accel::AccelError>>()
                        .expect("valid resident layer PCS placements");
                    let (commitment, matrix) =
                        commit_resident_from_device(&placements, layer_params, pad_seed, accel)
                            .expect("resident CUDA layer commitment");
                    (commitment, SessionProverMatrix::Resident(matrix))
                } else {
                    let (commitment, matrix) = commit_with_backend(
                        w_flat.as_ref().expect("hybrid PCS needs host layer weights"),
                        layer_params,
                        pad_seed,
                        accel,
                    )
                    .expect("hybrid CUDA layer commitment");
                    (commitment, SessionProverMatrix::Host(matrix))
                }
            } else {
                let (commitment, matrix) = commit(
                    w_flat.as_ref().expect("CPU PCS needs host layer weights"),
                    layer_params,
                    pad_seed,
                );
                (commitment, SessionProverMatrix::Host(matrix))
            };
            let commit_s = tc0.elapsed().as_secs_f64();

            // Stacked claims: every phase's 4 claims for this layer.
            let idxs: Vec<usize> =
                (0..phases).flat_map(|ph| (0..4).map(move |k| 4 * (ph * L + l) + k)).collect();
            let claims_p: Vec<_> = idxs
                .iter()
                .map(|&i| {
                    let wc = &out.weight_claims[i];
                    (layout.block_claim(i % 4, &wc.point), wc.value)
                })
                .collect();
            let mut doms_p = Doms::new(layer_dom_base(242) + 8 * l as u64);
            let mut doms_v = Doms::new(layer_dom_base(242) + 8 * l as u64);
            let dom_s0 = doms_p.take(1);
            let dom_s1 = doms_p.take(1);
            debug_assert_eq!((dom_s0, dom_s1), (doms_v.take(1), doms_v.take(1)));
            let mask_seed = pcs_mask_seed(seed, 0x44, l as u8);
            let to0 = Instant::now();
            let (mproof, _mt) = match &pm {
                SessionProverMatrix::Resident(matrix) => open_multi_zk_resident(
                    matrix,
                    &claims_p,
                    &mut stream,
                    dom_s0,
                    dom_s1,
                    mask_seed,
                    &mut txp,
                    accelerator.as_deref_mut().expect("resident PCS backend"),
                )
                .expect("resident CUDA layer opening"),
                SessionProverMatrix::Host(matrix) => {
                    let host_weights =
                        w_flat.as_ref().expect("host PCS opening needs flattened layer weights");
                    if let Some(accel) = accelerator.as_deref_mut() {
                        open_multi_zk_with_backend(
                            host_weights,
                            matrix,
                            &claims_p,
                            &mut stream,
                            dom_s0,
                            dom_s1,
                            mask_seed,
                            &mut txp,
                            accel,
                        )
                        .expect("hybrid CUDA layer opening")
                    } else {
                        open_multi_zk(
                            host_weights,
                            matrix,
                            &claims_p,
                            &mut stream,
                            dom_s0,
                            dom_s1,
                            mask_seed,
                            &mut txp,
                        )
                    }
                }
            };
            let open_s = to0.elapsed().as_secs_f64();
            let ob = mproof.bytes();
            let mbd = mproof.byte_breakdown();
            pcs_opening_bytes += ob;
            pcs_cached_query_marginal_bytes += mbd.cached_query_marginal_bytes;
            let claims_v: Vec<_> = idxs
                .iter()
                .map(|&i| {
                    let (point, key) = &outv.weight_keys[i];
                    (layout.block_claim(i % 4, point), *key)
                })
                .collect();
            let tv1 = Instant::now();
            let ok = verify_multi_open(
                &com.root,
                layer_params,
                &claims_v,
                &mproof,
                &mut vc,
                dom_s0,
                dom_s1,
                &mut txv,
            );
            let verify_s = tv1.elapsed().as_secs_f64();
            pcs_all_ok &= ok;
            pcs_rows.push(PcsCommitmentRow {
                name: format!("layer_{l}"),
                n_claims: idxs.len(),
                commit_s,
                open_s,
                verify_s,
                opening_bytes: ob,
                opening_cached_query_cut_bytes: mbd.cached_query_cut_bytes,
                opening_cached_query_marginal_bytes: mbd.cached_query_marginal_bytes,
                verified: ok,
            });
            if let SessionProverMatrix::Resident(matrix) = pm {
                free_resident_matrix(
                    matrix,
                    accelerator.as_deref_mut().expect("resident PCS cleanup backend"),
                )
                .expect("free resident layer commitment");
            }
            drop((w_flat, com));
            eprintln!(
                "  layer {l}: {} claims, commit {commit_s:.2}s open {open_s:.3}s ok={ok}",
                idxs.len()
            );
        }
        // Embedding commitment: 3 claims per phase, tensor idx [0, 0, 1].
        assert_eq!(out.embed_claims.len(), 3 * phases);
        let layout_e = layout_gpt2_embed();
        let e_flat = if resident_model_for_pcs.is_none() {
            Some(layout_e.place(&[&model.wte, &model.wpe]))
        } else {
            None
        };
        let tc0 = Instant::now();
        let (com_e, pm_e) = if let Some(accel) = accelerator.as_deref_mut() {
            if accel.kind() == BackendKind::CudaResident {
                let resident_model = resident_model_for_pcs
                    .expect("resident embedding commitment requires resident model weights");
                let fields =
                    [ModelWeightField::TokenEmbedding, ModelWeightField::PositionEmbedding];
                let placements: Vec<_> = fields
                    .into_iter()
                    .zip(&layout_e.tensors)
                    .map(|(field, slot)| {
                        ResidentWeightPlacement::new(
                            resident_model.model_weight(field),
                            slot.k,
                            slot.n,
                            slot.offset,
                            slot.n_pad,
                            layout_e.total_len,
                        )
                    })
                    .collect::<Result<_, volta_accel::AccelError>>()
                    .expect("valid resident embedding PCS placements");
                let (commitment, matrix) =
                    commit_resident_from_device(&placements, embed_params, [0x52u8; 32], accel)
                        .expect("resident CUDA embed commitment");
                (commitment, SessionProverMatrix::Resident(matrix))
            } else {
                let (commitment, matrix) = commit_with_backend(
                    e_flat.as_ref().expect("hybrid PCS needs host embedding weights"),
                    embed_params,
                    [0x52u8; 32],
                    accel,
                )
                .expect("hybrid CUDA embed commitment");
                (commitment, SessionProverMatrix::Host(matrix))
            }
        } else {
            let (commitment, matrix) = commit(
                e_flat.as_ref().expect("CPU PCS needs host embedding weights"),
                embed_params,
                [0x52u8; 32],
            );
            (commitment, SessionProverMatrix::Host(matrix))
        };
        let commit_s = tc0.elapsed().as_secs_f64();
        let claims_p: Vec<_> = out
            .embed_claims
            .iter()
            .enumerate()
            .map(|(i, wc)| {
                let tidx = if i % 3 == 2 { 1 } else { 0 };
                (layout_e.block_claim(tidx, &wc.point), wc.value)
            })
            .collect();
        let mut doms_p = Doms::new(layer_dom_base(253));
        let mut doms_v = Doms::new(layer_dom_base(253));
        let dom_s0 = doms_p.take(1);
        let dom_s1 = doms_p.take(1);
        debug_assert_eq!((dom_s0, dom_s1), (doms_v.take(1), doms_v.take(1)));
        let embed_mask_seed = pcs_mask_seed(seed, 0x45, 0);
        let to0 = Instant::now();
        let (mproof_e, _mt) = match &pm_e {
            SessionProverMatrix::Resident(matrix) => open_multi_zk_resident(
                matrix,
                &claims_p,
                &mut stream,
                dom_s0,
                dom_s1,
                embed_mask_seed,
                &mut txp,
                accelerator.as_deref_mut().expect("resident PCS backend"),
            )
            .expect("resident CUDA embed opening"),
            SessionProverMatrix::Host(matrix) => {
                let host_weights =
                    e_flat.as_ref().expect("host PCS opening needs flattened embedding weights");
                if let Some(accel) = accelerator.as_deref_mut() {
                    open_multi_zk_with_backend(
                        host_weights,
                        matrix,
                        &claims_p,
                        &mut stream,
                        dom_s0,
                        dom_s1,
                        embed_mask_seed,
                        &mut txp,
                        accel,
                    )
                    .expect("hybrid CUDA embed opening")
                } else {
                    open_multi_zk(
                        host_weights,
                        matrix,
                        &claims_p,
                        &mut stream,
                        dom_s0,
                        dom_s1,
                        embed_mask_seed,
                        &mut txp,
                    )
                }
            }
        };
        let open_s = to0.elapsed().as_secs_f64();
        let ob = mproof_e.bytes();
        let mbd = mproof_e.byte_breakdown();
        pcs_opening_bytes += ob;
        pcs_cached_query_marginal_bytes += mbd.cached_query_marginal_bytes;
        let claims_v: Vec<_> = outv
            .embed_keys
            .iter()
            .enumerate()
            .map(|(i, (point, key))| {
                let tidx = if i % 3 == 2 { 1 } else { 0 };
                (layout_e.block_claim(tidx, point), *key)
            })
            .collect();
        let tv1 = Instant::now();
        let ok = verify_multi_open(
            &com_e.root,
            embed_params,
            &claims_v,
            &mproof_e,
            &mut vc,
            dom_s0,
            dom_s1,
            &mut txv,
        );
        let verify_s = tv1.elapsed().as_secs_f64();
        pcs_all_ok &= ok;
        pcs_rows.push(PcsCommitmentRow {
            name: "embed".into(),
            n_claims: out.embed_claims.len(),
            commit_s,
            open_s,
            verify_s,
            opening_bytes: ob,
            opening_cached_query_cut_bytes: mbd.cached_query_cut_bytes,
            opening_cached_query_marginal_bytes: mbd.cached_query_marginal_bytes,
            verified: ok,
        });
        if let SessionProverMatrix::Resident(matrix) = pm_e {
            free_resident_matrix(
                matrix,
                accelerator.as_deref_mut().expect("resident PCS cleanup backend"),
            )
            .expect("free resident embed commitment");
        }
        drop((e_flat, com_e));
        eprintln!(
            "  embed: {} claims, commit {commit_s:.2}s open {open_s:.3}s ok={ok}",
            3 * phases
        );
    }
    let tx_after_pcs = ledger_to_owned(&txp);
    let pcs_by_label = ledger_delta(&tx_after_pcs, &[&tx_before_pcs]);

    // --- closures ------------------------------------------------------------
    let closure_started = Instant::now();
    let closure_prod_claims = prod.len();
    let closure_zero_claims = zero.len();
    assert_eq!(closure_prod_claims, kprod.len(), "prover/verifier Prod batch length mismatch");
    assert_eq!(closure_zero_claims, kzero.len(), "prover/verifier ZeroBatch length mismatch");
    let chi = txp.challenge_fp2();
    assert_eq!(chi, txv.challenge_fp2());
    let mut domsp = Doms::new(layer_dom_base(255));
    let mut domsv = Doms::new(layer_dom_base(255));
    let md = domsp.take(1);
    assert_eq!(md, domsv.take(1));
    let mask = stream.draw_fulls(md, 1)[0];
    let k_mask = vc.expand_full_keys(md, 1)[0];
    let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
    let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
    let mz = domsp.take(1);
    assert_eq!(mz, domsv.take(1));
    // Without PCS the weight claims stay unresolved — the zero batch is then
    // run over the accumulated rows only (curve session: architecture-only).
    let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
    let closure_exchange_s = closure_started.elapsed().as_secs_f64();
    let accepted = ok_prod && ok_zero && (!with_pcs || pcs_all_ok);
    assert_eq!(stream.counters, vc.counters, "prover/verifier correlation counters diverged");
    let pcg_allocation_hash_match =
        match (stream.allocation_digest_hex(), vc.allocation_digest_hex()) {
            (Some(p), Some(v)) => Some(p == v),
            _ => None,
        };
    let pcg_pool_sub_corrs = stream.counters.sub_corrs;
    let pcg_pool_full_corrs = stream.counters.full_corrs;
    let identity_seam_alias_values = proof
        .layers
        .iter()
        .chain(proof.chunks.iter().flat_map(|chunk| chunk.layers.iter()))
        .filter(|layer| layer.xin_corr.is_empty())
        .map(|layer| {
            if layer.k_corr.len() % D != 0 {
                panic!("C1 alias layer has a non-canonical boundary shape");
            }
            layer.k_corr.len() as u64
        })
        .sum();
    let accelerator_stats = accelerator
        .map(|accel| accel.finish_measurement().expect("finish accelerator measurement"));
    let session_wall_s = session_started.elapsed().as_secs_f64();

    SessionResult {
        accepted,
        prove_s,
        verify_s,
        session_wall_s,
        closure_exchange_s,
        comm_bytes: txp.total_bytes(),
        transcript_by_label: ledger_to_owned(&txp),
        pcs_by_label,
        pcs_rows,
        pcs_opening_bytes,
        pcs_cached_query_marginal_bytes,
        n_weight_claims: out.weight_claims.len(),
        n_embed_claims: out.embed_claims.len(),
        closure_prod_claims,
        closure_zero_claims,
        emult_instances: out.ctr_instances.emult_equiv(),
        sub_corrs: out.corr_counters.sub_corrs,
        full_corrs: out.corr_counters.full_corrs,
        verifier_protocol_sub_corrs: verifier_protocol_counters.sub_corrs,
        verifier_protocol_full_corrs: verifier_protocol_counters.full_corrs,
        identity_seam_alias_values,
        pcg_pool_sub_corrs,
        pcg_pool_full_corrs,
        chunk_p1_s: out.chunk_p1_s,
        chunk_p2_s: out.chunk_p2_s,
        public_logits_packed_bytes,
        pcg_allocation_hash_match,
        accelerator_stats,
    }
}

fn main() {
    let args = parse_args();
    // Capture the full revision before any benchmark setup. The closing
    // fingerprint below prevents a clean A -> clean B checkout during a long
    // run from being attributed to B.
    let git_sha_before_benchmark = git_head_sha();
    if git_sha_before_benchmark.is_empty() {
        eprintln!("p6_report: git HEAD is unavailable; refusing to start an unattributed run");
        std::process::exit(2);
    }
    let cloud = cloud_metadata_from_env();
    let rayon_threads = rayon::current_num_threads();
    let fase_d_realpcg_profile = args.pcg_backend == PcgBackendArg::Real;
    let p7b_machine_is_eligible =
        p7b_machine_eligible(cloud.as_ref(), rayon_threads, fase_d_realpcg_profile);
    let logical_cpu_cores = detected_logical_cpu_cores();
    let physical_cpu_cores = detected_physical_cpu_cores(logical_cpu_cores);
    // A run of record must stay clean for the complete benchmark window, not
    // merely happen to be clean when the JSON verdict is assembled.
    let git_dirty_before_benchmark = git_worktree_dirty();
    let quick = args.quick;
    if args.pcg_backend == PcgBackendArg::Mock && !args.diagnostic {
        eprintln!(
            "p6_report: mock PCG is diagnostic-only after the fase-D default flip; add --diagnostic (no result artifact)"
        );
        std::process::exit(2);
    }
    if args.ggm_prg == GgmPrg::Blake3 && !args.diagnostic {
        eprintln!(
            "p6_report: BLAKE3 GGM is diagnostic-only; record-producing mode requires aes128-mmo"
        );
        std::process::exit(2);
    }
    if args.diagnostic && (args.c1_record || args.flip_readiness_record) {
        eprintln!("p6_report: diagnostic mode cannot be combined with a record mode");
        std::process::exit(2);
    }
    if args.c1_record && args.flip_readiness_record {
        eprintln!("p6_report: --c1-record and --flip-readiness-record are mutually exclusive");
        std::process::exit(2);
    }
    if args.c1_record
        && (quick
            || args.accelerator != AcceleratorArg::Cpu
            || args.pcg_backend != PcgBackendArg::Mock)
    {
        eprintln!("p6_report: --c1-record requires the full CPU mock-backend geometry");
        std::process::exit(2);
    }
    if args.c1_record && git_dirty_before_benchmark {
        eprintln!("p6_report: --c1-record requires a clean tree before benchmark setup");
        std::process::exit(2);
    }
    if args.flip_readiness_record
        && (quick
            || args.accelerator != AcceleratorArg::Cpu
            || args.pcg_backend != PcgBackendArg::Real)
    {
        eprintln!(
            "p6_report: --flip-readiness-record requires full CPU geometry and --pcg-backend real"
        );
        std::process::exit(2);
    }
    if args.flip_readiness_record && git_dirty_before_benchmark {
        eprintln!("p6_report: --flip-readiness-record requires a clean tree before setup");
        std::process::exit(2);
    }
    let repetitions =
        args.repetitions.unwrap_or(if quick || args.flip_readiness_record { 1 } else { 3 });
    let warmup_repetitions =
        args.warmup_repetitions.unwrap_or(if quick || args.flip_readiness_record { 0 } else { 1 });
    if repetitions == 0 {
        eprintln!("p6_report: --repetitions must be at least 1");
        std::process::exit(2);
    }
    if repetitions + warmup_repetitions > 32 {
        eprintln!("p6_report: at most 32 measured + warmup repetitions are supported");
        std::process::exit(2);
    }
    if args.resident_timing != ResidentTimingArg::DeferredEvents
        && args.accelerator != AcceleratorArg::CudaResident
    {
        eprintln!("p6_report: --resident-timing is valid only with --accelerator cuda-resident");
        std::process::exit(2);
    }
    let authorization_store_path = args
        .pcg_authorization_store
        .clone()
        .or_else(|| std::env::var_os("VOLTA_PCG_AUTHORIZATION_STORE").map(PathBuf::from));
    let pcg_authorization_store = if args.pcg_backend == PcgBackendArg::Real {
        let Some(path) = authorization_store_path else {
            eprintln!(
                "p6_report: real PCG requires --pcg-authorization-store PATH or VOLTA_PCG_AUTHORIZATION_STORE"
            );
            std::process::exit(2);
        };
        Some(ResponseAuthorizationStore::new(path).unwrap_or_else(|error| {
            eprintln!("p6_report: response-authorization capability preflight failed: {error}");
            std::process::exit(2);
        }))
    } else {
        None
    };
    let mut accelerator = match args.accelerator {
        AcceleratorArg::Cpu => None,
        AcceleratorArg::CudaHybrid => Some(Backend::cuda_hybrid().unwrap_or_else(|e| {
            eprintln!("p6_report: CUDA requested but unavailable: {e}");
            std::process::exit(2);
        })),
        AcceleratorArg::CudaResident => Some(
            Backend::cuda_resident_with_timing(args.resident_timing.policy()).unwrap_or_else(|e| {
                eprintln!("p6_report: resident CUDA requested but unavailable: {e}");
                std::process::exit(2);
            }),
        ),
    };
    let (t0, n_gen, curve_chunk) = if quick { (16usize, 8usize, 4usize) } else { (100, 50, 10) };
    let mut layer_params = P4_LAYER;
    let mut embed_params = GPT2_FULL;
    if let Some(q) = args.pcs_q {
        layer_params.n_queries = q;
        embed_params.n_queries = q;
        layer_params.validate();
        embed_params.validate();
        eprintln!(
            "P7 exploratory PCS query profile: Q={q}, error_bits≈{:.1} (default Q={})",
            pcs_query_error_bits(&layer_params),
            P4_LAYER.n_queries
        );
    }
    if (args.c1_record || args.flip_readiness_record)
        && layer_params.n_queries != P4_LAYER.n_queries
    {
        eprintln!("p6_report: record modes freeze PCS Q=200");
        std::process::exit(2);
    }

    let dir = weights_dir();
    if !dir.join("gpt2s-q.bin").exists() {
        eprintln!("p6_report: frozen artifact not found; run scripts/export_gpt2.py first");
        std::process::exit(1);
    }
    eprintln!("loading artifact + prefill witness at t0={t0} ...");
    let model = load_model(&dir).expect("load_model");
    let cpu_wit0 = forward_model(&model, t0);
    let mut resident_model: Option<ResidentGpt2Model> = None;
    let mut resident_prefill: Option<ResidentModelWitness> = None;
    let mut resident_source: Option<ResidentModelWitness> = None;
    let mut resident_band50: Option<ResidentBandModelWitness<'_>> = None;
    let mut resident_proof_error: Option<DeviceBuffer<u32>> = None;
    let (wit0, accelerator_witness_stats) = match args.accelerator {
        AcceleratorArg::Cpu => (cpu_wit0, None),
        AcceleratorArg::CudaHybrid => {
            let accel = accelerator.as_mut().expect("hybrid CUDA backend");
            accel.begin_measurement().expect("begin CUDA witness measurement");
            let gpu_wit =
                forward_model_with_backend(&model, t0, accel).expect("CUDA hybrid witness");
            let stats = accel.finish_measurement().expect("finish CUDA witness measurement");
            assert_eq!(gpu_wit, cpu_wit0, "CPU/CUDA ModelWitness must be bit-exact");
            (gpu_wit, Some(stats))
        }
        AcceleratorArg::CudaResident => {
            let accel = accelerator.as_mut().expect("resident CUDA backend");
            let uploaded = upload_resident_model(&model, accel).expect("upload resident model");
            accel.begin_measurement().expect("begin resident prefill witness measurement");
            let witness = forward_model_tokens_resident(&uploaded, &model.p.tokens[..t0], accel)
                .expect("resident prefill witness");
            let logits = accel
                .download_device(witness.logits().buffer(), witness.logits().offset(), VOCAB)
                .expect("download public prefill logits");
            let stats =
                accel.finish_measurement().expect("finish resident prefill witness measurement");
            assert_eq!(logits, cpu_wit0.logits, "resident prefill logits must be bit-exact");
            resident_proof_error =
                Some(accel.upload_new_device(&[0u32]).expect("proof error word"));
            resident_model = Some(uploaded);
            resident_prefill = Some(witness);
            (cpu_wit0, Some(stats))
        }
    };

    // --- native baselines (ABBA paired, new-machine load-bearing rule) -------
    let run_decode = || {
        let kv: Vec<(&[i16], &[i16])> =
            wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        let mut cache = KvCache::from_prefill(&kv, t0);
        let mut gen: Vec<u32> = Vec::with_capacity(n_gen);
        let mut next = volta_gpt2::argmax(&wit0.logits);
        for i in 0..n_gen {
            gen.push(next);
            let lg = decode_step(&model, &mut cache, next, t0 + i);
            next = volta_gpt2::argmax(&lg);
        }
        gen
    };
    let native_timing_rounds = if quick { 1 } else { 3 };
    eprintln!(
        "native baselines: ABBA paired, {native_timing_rounds} rounds (prefill {t0}, decode {n_gen}) ..."
    );
    let native_samples =
        time_paired_samples(1, native_timing_rounds, || forward_model(&model, t0), &run_decode);
    let (t_native_prefill, t_native_decode) = native_samples.medians();
    let native_prefill_timing =
        TimingDistribution::new(native_samples.a.iter().map(|x| x.as_secs_f64()).collect());
    let native_decode_timing =
        TimingDistribution::new(native_samples.b.iter().map(|x| x.as_secs_f64()).collect());
    let t_native_prefill_s = t_native_prefill.as_secs_f64();
    let t_native_decode_s = t_native_decode.as_secs_f64();
    let gen = run_decode();
    eprintln!(
        "  median prefill {t_native_prefill_s:.3} s; {n_gen} decode tokens in {t_native_decode_s:.3} s ({:.1} tok/s): {gen:?}",
        n_gen as f64 / t_native_decode_s
    );

    // --- golden decode check ---------------------------------------------------
    let golden_path = dir.join("golden-p6.bin");
    let (golden_checked, golden_match) = if !quick && golden_path.exists() {
        let g = std::fs::read(&golden_path).unwrap();
        assert_eq!(&g[..8], b"VGOLD2\0\0");
        let rd_u32 = |o: usize| u32::from_le_bytes(g[o..o + 4].try_into().unwrap());
        let gt0 = rd_u32(8) as usize;
        let gn = rd_u32(12) as usize;
        assert_eq!((gt0, gn), (t0, n_gen), "golden-p6 shape mismatch");
        let tokens_ref: Vec<u32> = (0..gn).map(|i| rd_u32(16 + 4 * i)).collect();
        let m = gen == tokens_ref;
        assert!(m, "P6 sanity: generated tokens must match golden-p6.bin");
        (true, Some(m))
    } else {
        (false, None)
    };

    // --- full-response witness + bands -----------------------------------------
    let mut seq: Vec<u32> = model.p.tokens[..t0].to_vec();
    seq.extend_from_slice(&gen);
    eprintln!("full-response witness (T={}) + band extraction ...", seq.len());
    let cpu_full = forward_model_tokens(&model, &seq);
    let mut accelerator_response_witness_stats = None;
    let full = match args.accelerator {
        AcceleratorArg::Cpu => cpu_full,
        AcceleratorArg::CudaHybrid => {
            let accel = accelerator.as_mut().expect("hybrid CUDA backend");
            accel.begin_measurement().expect("begin CUDA response witness");
            let gpu_full = forward_model_tokens_with_backend(&model, &seq, accel)
                .expect("CUDA response witness");
            accelerator_response_witness_stats =
                Some(accel.finish_measurement().expect("finish CUDA response witness"));
            assert_eq!(gpu_full, cpu_full, "CPU/CUDA response witness must be bit-exact");
            gpu_full
        }
        AcceleratorArg::CudaResident => {
            let accel = accelerator.as_mut().expect("resident CUDA backend");
            let uploaded = resident_model.as_ref().expect("resident model");
            accel.begin_measurement().expect("begin resident response witness measurement");
            let source =
                forward_model_tokens_resident(uploaded, &seq, accel).expect("resident response");
            resident_source = Some(source);
            let band = band_model_witness_resident(
                uploaded,
                resident_source.as_ref().expect("resident response source"),
                t0,
                n_gen,
                accel,
            )
            .expect("resident response band");
            let logits = accel
                .download_device(band.logits().buffer(), band.logits().offset(), n_gen * VOCAB)
                .expect("download public band logits");
            accelerator_response_witness_stats = Some(
                accel.finish_measurement().expect("finish resident response witness measurement"),
            );
            let expected = band_model_witness(&model, &cpu_full, t0);
            assert_eq!(logits, expected.logits, "resident band logits must be bit-exact");
            resident_band50 = Some(band);
            cpu_full
        }
    };
    let band50 = band_model_witness(&model, &full, t0);
    assert_eq!(band50.q, n_gen);
    let resident_band50_refs: Vec<&ResidentBandModelWitness<'_>> =
        resident_band50.as_ref().into_iter().collect();

    macro_rules! run_active_session {
        ($public_bands:expr, $resident_bands:expr, $with_pcs:expr, $seed:expr, $pcg:expr) => {{
            if args.accelerator == AcceleratorArg::CudaResident {
                run_session_resident(
                    &model,
                    &wit0,
                    $public_bands,
                    &seq,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    $resident_bands,
                    resident_proof_error.as_ref().expect("resident proof error word"),
                    &layer_params,
                    &embed_params,
                    $with_pcs,
                    $seed,
                    $pcg,
                    accelerator.as_mut().expect("resident CUDA backend"),
                )
            } else {
                run_session(
                    &model,
                    &wit0,
                    $public_bands,
                    &seq,
                    &layer_params,
                    &embed_params,
                    $with_pcs,
                    $seed,
                    $pcg,
                    accelerator.as_mut(),
                )
            }
        }};
    }

    macro_rules! run_active_prefill {
        ($seed:expr) => {{
            if args.accelerator == AcceleratorArg::CudaResident {
                run_prefill_resident(
                    &model,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    &wit0.logits,
                    DeviceSlice::new(
                        resident_proof_error.as_ref().expect("resident proof error word"),
                        0,
                        1,
                    )
                    .unwrap(),
                    $seed,
                    accelerator.as_mut().expect("resident CUDA backend"),
                )
            } else {
                run_prefill(&model, &wit0, $seed, accelerator.as_mut())
            }
        }};
    }

    // --- repeated prefill + full-response proving -------------------------------
    eprintln!("timed proving: {warmup_repetitions} warmup + {repetitions} measured repetitions");
    let mut pcg_gate = PcgGateStats::default();
    let mut prefill_results = Vec::with_capacity(repetitions);
    let mut session_results = Vec::with_capacity(repetitions);
    if args.pcg_backend == PcgBackendArg::Real {
        eprintln!("  real PCG gate: mock prepass for exact full-response counts ...");
        let pre = run_active_session!(
            &[&band50],
            &resident_band50_refs,
            true,
            0x21,
            SessionPcgBackend::Mock
        );

        for warmup in 0..warmup_repetitions {
            let i = warmup as u8;
            let _ = run_active_prefill!(0xC0 + i);
            let (backend, timings, setup_comm, production, channel_transcripts_match) =
                real_session_backend(
                    pcg_authorization_store.as_ref().expect("real-PCG authorization store"),
                    pre.pcg_pool_sub_corrs,
                    pre.pcg_pool_full_corrs,
                    args.ggm_prg,
                );
            add_setup_comm(&mut pcg_gate, &setup_comm);
            add_production_setup(&mut pcg_gate, timings, production, channel_transcripts_match);
            let warm =
                run_active_session!(&[&band50], &resident_band50_refs, true, 0xA0 + i, backend);
            assert_mock_real_parity(&mut pcg_gate, &pre, &warm, "warmup response");
            assert!(warm.accepted, "warmup response must verify");
            eprintln!("  warmup {} accepted", warmup + 1);
        }

        for repetition in 0..repetitions {
            let i = repetition as u8;
            let prefill = run_active_prefill!(0x60 + i);
            let (backend, timings, setup_comm, production, channel_transcripts_match) =
                real_session_backend(
                    pcg_authorization_store.as_ref().expect("real-PCG authorization store"),
                    pre.pcg_pool_sub_corrs,
                    pre.pcg_pool_full_corrs,
                    args.ggm_prg,
                );
            add_setup_comm(&mut pcg_gate, &setup_comm);
            add_production_setup(&mut pcg_gate, timings, production, channel_transcripts_match);
            let real =
                run_active_session!(&[&band50], &resident_band50_refs, true, 0x21 + i, backend);
            assert_mock_real_parity(&mut pcg_gate, &pre, &real, "full response");
            assert!(real.accepted, "measured response must verify");
            prefill_results.push(prefill);
            session_results.push(real);
            eprintln!("  repetition {} accepted", repetition + 1);
        }
    } else {
        for warmup in 0..warmup_repetitions {
            let i = warmup as u8;
            let warm = if args.accelerator == AcceleratorArg::CudaResident {
                let backend = accelerator.as_mut().expect("resident CUDA backend");
                let error = resident_proof_error.as_ref().expect("resident proof error word");
                let _ = run_prefill_resident(
                    &model,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    &wit0.logits,
                    DeviceSlice::new(error, 0, 1).unwrap(),
                    0xC0 + i,
                    backend,
                );
                let resident_bands = [resident_band50.as_ref().expect("resident response band")];
                run_session_resident(
                    &model,
                    &wit0,
                    &[&band50],
                    &seq,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    &resident_bands,
                    error,
                    &layer_params,
                    &embed_params,
                    true,
                    0xA0 + i,
                    SessionPcgBackend::Mock,
                    backend,
                )
            } else {
                let _ = run_prefill(&model, &wit0, 0xC0 + i, accelerator.as_mut());
                run_session(
                    &model,
                    &wit0,
                    &[&band50],
                    &seq,
                    &layer_params,
                    &embed_params,
                    true,
                    0xA0 + i,
                    SessionPcgBackend::Mock,
                    accelerator.as_mut(),
                )
            };
            assert!(warm.accepted, "warmup response must verify");
            eprintln!("  warmup {} accepted", warmup + 1);
        }
        for repetition in 0..repetitions {
            let i = repetition as u8;
            let (prefill, response) = if args.accelerator == AcceleratorArg::CudaResident {
                let backend = accelerator.as_mut().expect("resident CUDA backend");
                let error = resident_proof_error.as_ref().expect("resident proof error word");
                let prefill = run_prefill_resident(
                    &model,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    &wit0.logits,
                    DeviceSlice::new(error, 0, 1).unwrap(),
                    0x60 + i,
                    backend,
                );
                let resident_bands = [resident_band50.as_ref().expect("resident response band")];
                let response = run_session_resident(
                    &model,
                    &wit0,
                    &[&band50],
                    &seq,
                    resident_model.as_ref().expect("resident model"),
                    resident_prefill.as_ref().expect("resident prefill"),
                    &resident_bands,
                    error,
                    &layer_params,
                    &embed_params,
                    true,
                    0x40 + i,
                    SessionPcgBackend::Mock,
                    backend,
                );
                (prefill, response)
            } else {
                (
                    run_prefill(&model, &wit0, 0x60 + i, accelerator.as_mut()),
                    run_session(
                        &model,
                        &wit0,
                        &[&band50],
                        &seq,
                        &layer_params,
                        &embed_params,
                        true,
                        0x40 + i,
                        SessionPcgBackend::Mock,
                        accelerator.as_mut(),
                    ),
                )
            };
            eprintln!(
                "  repetition {}: prefill {:.2}s response {:.2}s verify {:.2}s accepted={}",
                repetition + 1,
                prefill.prove_s,
                response.prove_s,
                response.verify_s,
                response.accepted
            );
            prefill_results.push(prefill);
            session_results.push(response);
        }
    }

    let comm_prefill_bytes = prefill_results[0].comm_bytes;
    let comm_prefill_by_label = prefill_results[0].transcript_by_label.clone();
    for prefill in &prefill_results {
        assert_eq!(prefill.comm_bytes, comm_prefill_bytes);
        assert_eq!(prefill.transcript_by_label, comm_prefill_by_label);
    }
    let reference = &session_results[0];
    for response in &session_results {
        assert!(response.accepted, "measured response must verify");
        assert_eq!(response.comm_bytes, reference.comm_bytes);
        assert_eq!(response.transcript_by_label, reference.transcript_by_label);
        assert_eq!(response.pcs_by_label, reference.pcs_by_label);
        assert_eq!(response.pcs_opening_bytes, reference.pcs_opening_bytes);
        assert_eq!(response.sub_corrs, reference.sub_corrs);
        assert_eq!(response.full_corrs, reference.full_corrs);
    }

    let prefill_samples: Vec<f64> = prefill_results.iter().map(|x| x.prove_s).collect();
    let response_samples: Vec<f64> = session_results.iter().map(|x| x.prove_s).collect();
    let decode_samples: Vec<f64> = response_samples
        .iter()
        .zip(&prefill_samples)
        .map(|(response, prefill)| response - prefill)
        .collect();
    assert!(decode_samples.iter().all(|x| *x >= 0.0));
    let verify_samples: Vec<f64> = session_results.iter().map(|x| x.verify_s).collect();
    let pcs_commit_samples: Vec<f64> =
        session_results.iter().map(|x| x.pcs_rows.iter().map(|r| r.commit_s).sum()).collect();
    let pcs_open_samples: Vec<f64> =
        session_results.iter().map(|x| x.pcs_rows.iter().map(|r| r.open_s).sum()).collect();
    let pcs_verify_samples: Vec<f64> =
        session_results.iter().map(|x| x.pcs_rows.iter().map(|r| r.verify_s).sum()).collect();
    let online_response_samples: Vec<f64> = session_results
        .iter()
        .map(|x| {
            x.prove_s + x.pcs_rows.iter().map(|r| r.open_s).sum::<f64>() + x.closure_exchange_s
        })
        .collect();
    let online_decode_samples: Vec<f64> = online_response_samples
        .iter()
        .zip(&prefill_samples)
        .map(|(response, prefill)| response - prefill)
        .collect();
    assert!(online_decode_samples.iter().all(|x| *x >= 0.0));
    let response_session_wall_samples: Vec<f64> =
        session_results.iter().map(|x| x.session_wall_s).collect();
    let closure_exchange_samples: Vec<f64> =
        session_results.iter().map(|x| x.closure_exchange_s).collect();
    let verifier_accounted_samples: Vec<f64> = session_results
        .iter()
        .map(|x| x.verify_s + x.pcs_rows.iter().map(|r| r.verify_s).sum::<f64>())
        .collect();
    let prove_prefill_timing = TimingDistribution::new(prefill_samples);
    let prove_response_timing = TimingDistribution::new(response_samples.clone());
    let prove_decode_marginal_timing = TimingDistribution::new(decode_samples);
    let prover_online_accounted_response_timing = TimingDistribution::new(online_response_samples);
    let prover_online_accounted_decode_marginal_timing =
        TimingDistribution::new(online_decode_samples);
    let response_session_wall_timing = TimingDistribution::new(response_session_wall_samples);
    let protocol_closure_exchange_timing = TimingDistribution::new(closure_exchange_samples);
    let verify_response_timing = TimingDistribution::new(verify_samples);
    let verifier_accounted_timing = TimingDistribution::new(verifier_accounted_samples);
    let pcs_commit_timing = TimingDistribution::new(pcs_commit_samples);
    let pcs_open_timing = TimingDistribution::new(pcs_open_samples);
    let pcs_verify_timing = TimingDistribution::new(pcs_verify_samples);
    let representative_index = median_index(&response_samples);
    let representative_repetition = representative_index + 1;
    let is_resident = args.accelerator == AcceleratorArg::CudaResident;
    // Timing gates use the distributions' preregistered upper medians. For
    // count/traffic gates use the maximum measured session: selecting the
    // response-median repetition could otherwise hide cold-arena barriers.
    let p7b_prefill_core_observed_s = is_resident.then_some(prove_prefill_timing.median_s);
    let p7b_decode_marginal_observed_s =
        is_resident.then_some(prove_decode_marginal_timing.median_s);
    let p7b_sync_observed = is_resident.then(|| {
        session_results
            .iter()
            .map(|session| {
                session
                    .accelerator_stats
                    .as_ref()
                    .expect("resident measured session needs accelerator stats")
                    .synchronizations
            })
            .max()
            .expect("resident run needs a measured session")
    });
    let p7b_sync_wall_fraction_observed = is_resident.then(|| {
        session_results
            .iter()
            .map(|session| {
                synchronization_wall_fraction(
                    session
                        .accelerator_stats
                        .as_ref()
                        .expect("resident measured session needs accelerator stats"),
                    session.session_wall_s,
                )
            })
            .max_by(f64::total_cmp)
            .expect("resident run needs a measured session")
    });
    let p7b_h2d_observed_bytes = is_resident.then(|| {
        session_results
            .iter()
            .map(|session| {
                session
                    .accelerator_stats
                    .as_ref()
                    .expect("resident measured session needs accelerator stats")
                    .h2d_bytes
            })
            .max()
            .expect("resident run needs a measured session")
    });
    let repetitions_rows: Vec<BenchmarkRepetitionRow> = prefill_results
        .iter()
        .zip(&session_results)
        .enumerate()
        .map(|(i, (prefill, response))| BenchmarkRepetitionRow {
            repetition: i + 1,
            seed: if args.pcg_backend == PcgBackendArg::Real {
                0x21 + i as u8
            } else {
                0x40 + i as u8
            },
            t_prove_prefill_only_s: prefill.prove_s,
            t_prove_response_s: response.prove_s,
            t_prove_decode_marginal_s: response.prove_s - prefill.prove_s,
            t_prover_online_accounted_response_s: response.prove_s
                + response.pcs_rows.iter().map(|r| r.open_s).sum::<f64>()
                + response.closure_exchange_s,
            t_prover_online_accounted_decode_marginal_s: response.prove_s
                + response.pcs_rows.iter().map(|r| r.open_s).sum::<f64>()
                + response.closure_exchange_s
                - prefill.prove_s,
            t_response_session_wall_s: response.session_wall_s,
            t_protocol_closure_exchange_s: response.closure_exchange_s,
            t_verify_response_s: response.verify_s,
            t_verifier_accounted_s: response.verify_s
                + response.pcs_rows.iter().map(|r| r.verify_s).sum::<f64>(),
            pcs_commit_total_s: response.pcs_rows.iter().map(|r| r.commit_s).sum(),
            pcs_open_total_s: response.pcs_rows.iter().map(|r| r.open_s).sum(),
            pcs_verify_total_s: response.pcs_rows.iter().map(|r| r.verify_s).sum(),
            p7b_sync_wall_fraction: response
                .accelerator_stats
                .as_ref()
                .map(|stats| synchronization_wall_fraction(stats, response.session_wall_s)),
            accelerator_prefill: prefill
                .accelerator_stats
                .map(|stats| AcceleratorStatsRow::from_stats(stats, "prefill-proof")),
            accelerator_session: response.accelerator_stats.map(|stats| {
                AcceleratorStatsRow::from_stats(
                    stats,
                    "response-session-including-pcs-and-verifier",
                )
            }),
        })
        .collect();
    let accelerator_prefill_proving_stats = prefill_results[representative_index].accelerator_stats;
    let rec = session_results.swap_remove(representative_index);
    let t_prove_prefill_only_s = prove_prefill_timing.median_s;
    let t_prove_decode_marginal_s = prove_decode_marginal_timing.median_s;
    eprintln!(
        "  medians: prefill {:.2}s response {:.2}s decode marginal {:.2}s; representative repetition {}",
        t_prove_prefill_only_s,
        prove_response_timing.median_s,
        t_prove_decode_marginal_s,
        representative_repetition
    );

    // --- flat-cost curve: n chunks of curve_chunk tokens --------------------------
    let n_chunks = n_gen / curve_chunk;
    eprintln!("flat-cost curve: {n_chunks} chunks × {curve_chunk} tokens (no PCS) ...");
    // Chunk c = rows [t0+c·w, t0+(c+1)·w): extract each from the full
    // forward truncated at the chunk's end (causal prefix-consistency makes
    // the truncated run bit-identical to `full`'s first rows).
    let bands: Vec<BandModelWitness> = (0..n_chunks)
        .map(|c| {
            let t_end = t0 + (c + 1) * curve_chunk;
            let sub_full = forward_model_tokens(&model, &seq[..t_end]);
            band_model_witness(&model, &sub_full, t0 + c * curve_chunk)
        })
        .collect();
    let band_refs: Vec<&BandModelWitness> = bands.iter().collect();
    let mut resident_curve_bands = Vec::new();
    if args.accelerator == AcceleratorArg::CudaResident {
        let backend = accelerator.as_mut().expect("resident CUDA backend");
        for chunk in 0..n_chunks {
            resident_curve_bands.push(
                band_model_witness_resident(
                    resident_model.as_ref().expect("resident model"),
                    resident_source.as_ref().expect("resident response source"),
                    t0 + chunk * curve_chunk,
                    curve_chunk,
                    backend,
                )
                .expect("resident flat-cost band"),
            );
        }
    }
    let resident_curve_refs: Vec<&ResidentBandModelWitness<'_>> =
        resident_curve_bands.iter().collect();
    let chk = if args.pcg_backend == PcgBackendArg::Real {
        eprintln!("  real PCG gate: mock prepass for chunk-curve counts ...");
        let pre = run_active_session!(
            &band_refs,
            &resident_curve_refs,
            false,
            0x22,
            SessionPcgBackend::Mock
        );
        let (backend, timings, setup_comm, production, channel_transcripts_match) =
            real_session_backend(
                pcg_authorization_store.as_ref().expect("real-PCG authorization store"),
                pre.pcg_pool_sub_corrs,
                pre.pcg_pool_full_corrs,
                args.ggm_prg,
            );
        add_setup_comm(&mut pcg_gate, &setup_comm);
        add_production_setup(&mut pcg_gate, timings, production, channel_transcripts_match);
        let real = run_active_session!(&band_refs, &resident_curve_refs, false, 0x22, backend);
        assert_mock_real_parity(&mut pcg_gate, &pre, &real, "chunk curve");
        real
    } else {
        if args.accelerator == AcceleratorArg::CudaResident {
            run_session_resident(
                &model,
                &wit0,
                &band_refs,
                &seq,
                resident_model.as_ref().expect("resident model"),
                resident_prefill.as_ref().expect("resident prefill"),
                &resident_curve_refs,
                resident_proof_error.as_ref().expect("resident proof error word"),
                &layer_params,
                &embed_params,
                false,
                0x22,
                SessionPcgBackend::Mock,
                accelerator.as_mut().expect("resident CUDA backend"),
            )
        } else {
            run_session(
                &model,
                &wit0,
                &band_refs,
                &seq,
                &layer_params,
                &embed_params,
                false,
                0x22,
                SessionPcgBackend::Mock,
                accelerator.as_mut(),
            )
        }
    };
    let mut chunk_curve = Vec::with_capacity(n_chunks);
    for c in 0..n_chunks {
        let total = chk.chunk_p1_s[c] + chk.chunk_p2_s[c];
        chunk_curve.push(ChunkCurveRow {
            chunk: c,
            t0: t0 + c * curve_chunk,
            q: curve_chunk,
            cache_end: t0 + (c + 1) * curve_chunk,
            prove_p1_s: chk.chunk_p1_s[c],
            prove_p2_s: chk.chunk_p2_s[c],
            prove_total_s: total,
            per_token_s: total / curve_chunk as f64,
        });
        eprintln!(
            "  chunk {c}: cache {}→{} prove {:.3}s ({:.4} s/token)",
            t0 + c * curve_chunk,
            t0 + (c + 1) * curve_chunk,
            total,
            total / curve_chunk as f64
        );
    }
    let curve_last_over_first =
        chunk_curve.last().unwrap().prove_total_s / chunk_curve[0].prove_total_s;
    // Gate: per-token cost may grow only by the O(seq·d) attention term as
    // the cache grows (here ≤1.5× over 100→150 with wide margin); an
    // O(seq²) architecture would show ≥2× immediately.
    let gate_flat = curve_last_over_first <= 1.5;
    eprintln!(
        "  curve last/first = {curve_last_over_first:.2} (gate ≤1.5: {}) chunked accepted={}",
        if gate_flat { "PASS" } else { "FAIL" },
        chk.accepted
    );
    drop(resident_curve_refs);
    if args.accelerator == AcceleratorArg::CudaResident {
        let backend = accelerator.as_mut().expect("resident CUDA backend");
        for band in resident_curve_bands {
            band.free(backend).expect("free resident flat-cost band");
        }
    }

    // The resident objects have explicit ownership because their buffers must
    // be returned to the same CUDA context.  Release dependants before their
    // sources, then require that explicit opaque allocations reach zero. The
    // CUDA context may retain both primitive workspaces and inactive resident
    // arena capacity for reuse; both remain physical live device memory.
    let (
        accelerator_live_device_bytes_after_cleanup,
        accelerator_workspace_device_bytes_after_cleanup,
        accelerator_resident_device_bytes_after_cleanup,
        accelerator_cached_resident_device_bytes_after_cleanup,
        accelerator_live_device_bytes_after_cache_trim,
        accelerator_workspace_device_bytes_after_cache_trim,
        accelerator_resident_device_bytes_after_cache_trim,
        accelerator_cached_resident_device_bytes_after_cache_trim,
    ) = if args.accelerator == AcceleratorArg::CudaResident {
        let backend = accelerator.as_mut().expect("resident CUDA backend");
        resident_band50
            .take()
            .expect("resident response band")
            .free(backend)
            .expect("free resident response band");
        resident_source
            .take()
            .expect("resident response source")
            .free(backend)
            .expect("free resident response source");
        resident_prefill
            .take()
            .expect("resident prefill")
            .free(backend)
            .expect("free resident prefill");
        backend
            .free_device(resident_proof_error.take().expect("resident proof error word"))
            .expect("free resident proof error word");
        resident_model.take().expect("resident model").free(backend).expect("free resident model");
        let live = backend.stats().expect("resident CUDA cleanup stats").live_device_bytes;
        let memory = backend
            .device_memory_breakdown()
            .expect("resident CUDA memory breakdown after cleanup");
        assert_eq!(memory.resident_bytes, 0, "resident report leaked explicit device buffers");
        let retained = memory
            .workspace_bytes
            .checked_add(memory.cached_resident_bytes)
            .expect("cleanup retained-memory accounting overflow");
        assert_eq!(
            live, retained,
            "cleanup live total must equal reusable workspaces plus cached resident arena"
        );

        // Cache trimming is teardown accounting, deliberately outside every
        // timed measurement. Preserve the pre-trim high-water above, then
        // prove that physical arena storage is actually releasable.
        backend.trim_device_cache().expect("trim resident CUDA device cache");
        let trimmed_live =
            backend.stats().expect("resident CUDA cache-trim stats").live_device_bytes;
        let trimmed_memory = backend
            .device_memory_breakdown()
            .expect("resident CUDA memory breakdown after cache trim");
        assert_eq!(
            trimmed_memory.resident_bytes, 0,
            "cache trim found an active resident allocation"
        );
        assert_eq!(
            trimmed_memory.cached_resident_bytes, 0,
            "cache trim retained inactive resident arena capacity"
        );
        assert_eq!(
            trimmed_live, trimmed_memory.workspace_bytes,
            "post-trim live total must contain reusable CUDA workspaces only"
        );
        (
            Some(live),
            Some(memory.workspace_bytes),
            Some(memory.resident_bytes),
            Some(memory.cached_resident_bytes),
            Some(trimmed_live),
            Some(trimmed_memory.workspace_bytes),
            Some(trimmed_memory.resident_bytes),
            Some(trimmed_memory.cached_resident_bytes),
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };

    // --- report --------------------------------------------------------------------
    let public_logits_bytes = ((n_gen * VOCAB + VOCAB) * 8) as u64;
    // Transcript-only marginal: the run-of-record ledger minus its PCS
    // opening bytes (the prefill-only measurement has no PCS), minus the
    // prefill transcript.
    let comm_decode_marginal =
        rec.comm_bytes.saturating_sub(rec.pcs_opening_bytes).saturating_sub(comm_prefill_bytes);
    let date = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    // This is the second half of the clean-tree invariant. It is deliberately
    // taken after every benchmark/cleanup action and before verdict assembly.
    let git_sha_before_serialization = git_head_sha();
    let git_dirty_before_serialization = git_worktree_dirty();
    if !git_revision_unchanged(&git_sha_before_benchmark, &git_sha_before_serialization) {
        eprintln!(
            "p6_report: git HEAD is unavailable or changed during the benchmark; refusing to write a result"
        );
        std::process::exit(2);
    }
    let git_dirty = git_dirty_before_benchmark || git_dirty_before_serialization;
    let accepted = rec.accepted && chk.accepted;
    let p7b_gate_evaluated = is_resident.then_some(
        p7b_gate_eligible(
            &git_sha_before_benchmark,
            &git_sha_before_serialization,
            git_dirty_before_benchmark,
            git_dirty_before_serialization,
            p7b_machine_is_eligible,
            quick,
            t0,
            n_gen,
            layer_params.n_queries,
            P4_LAYER.n_queries,
            warmup_repetitions,
            repetitions,
        ) && args.resident_timing == P7B_OFFICIAL_RESIDENT_TIMING,
    );
    let gate_is_official = p7b_gate_evaluated == Some(true);
    let p7b_prefill_core_gate_pass = gate_is_official.then(|| {
        p7b_prefill_core_observed_s.expect("resident prefill observation")
            <= P7B_PREFILL_CORE_GATE_S
    });
    let p7b_decode_marginal_gate_pass = gate_is_official.then(|| {
        p7b_decode_marginal_observed_s.expect("resident decode observation")
            <= P7B_DECODE_MARGINAL_GATE_S
    });
    let p7b_sync_wall_fraction_gate_pass = gate_is_official.then(|| {
        p7b_sync_wall_fraction_observed.expect("resident sync-wall observation")
            <= P7B_SYNC_WALL_FRACTION_GATE
    });
    let p7b_h2d_gate_pass = gate_is_official
        .then(|| p7b_h2d_observed_bytes.expect("resident H2D observation") <= P7B_H2D_GATE_BYTES);
    let response_communication_observed_bytes = is_resident.then(|| {
        rec.comm_bytes
            .checked_add(rec.public_logits_packed_bytes)
            .expect("packed response communication accounting overflow")
    });
    let response_communication_invariant_pass = response_communication_observed_bytes
        .map(|bytes| bytes <= RESPONSE_COMMUNICATION_ENVELOPE_BYTES);
    let p7b_response_communication_no_growth_pass = gate_is_official.then(|| {
        p7b_communication_gate(
            rec.comm_bytes,
            rec.pcs_opening_bytes,
            rec.public_logits_packed_bytes,
            fase_d_realpcg_profile,
        )
    });
    let p7b_all_gates_pass = gate_is_official.then(|| {
        accepted
            && golden_checked
            && golden_match == Some(true)
            && gate_flat
            && response_communication_invariant_pass == Some(true)
            && p7b_response_communication_no_growth_pass == Some(true)
            && p7b_prefill_core_gate_pass.expect("prefill P7b verdict")
            && p7b_decode_marginal_gate_pass.expect("decode P7b verdict")
            && p7b_sync_wall_fraction_gate_pass.expect("sync-wall P7b verdict")
            && p7b_h2d_gate_pass.expect("H2D P7b verdict")
            && args.pcg_backend == PcgBackendArg::Real
            && args.ggm_prg == GgmPrg::Aes128Mmo
            && pcg_gate.mock_prepass_counters_match == Some(true)
            && pcg_gate.mock_prepass_channel_ledger_digest_match == Some(true)
            && pcg_gate.mock_prepass_allocation_digest_match == Some(true)
    });
    let t_prove_response_s = prove_response_timing.median_s;
    let t_verify_response_s = verify_response_timing.median_s;
    let pcs_commit_total_s = pcs_commit_timing.median_s;
    let pcs_open_total_s = pcs_open_timing.median_s;
    let pcs_verify_total_s = pcs_verify_timing.median_s;
    let c1_identity_seam_reuse = args.c1_record.then(|| {
        let measured_auth_correction_bytes = rec
            .transcript_by_label
            .get("auth_corrections")
            .copied()
            .expect("C1 record requires the auth_corrections byte label");
        let measured_packed_response_bytes = rec
            .comm_bytes
            .checked_add(rec.public_logits_packed_bytes)
            .expect("C1 packed response accounting overflow");
        let byte_formulas_reconcile = rec.identity_seam_alias_values == C1_IDENTITY_SEAM_ALIASES
            && rec.comm_bytes == C1_TRANSCRIPT_BYTES
            && measured_auth_correction_bytes == C1_AUTH_CORRECTION_BYTES
            && measured_packed_response_bytes == C1_PACKED_RESPONSE_BYTES;
        let counters_reconcile = rec.sub_corrs == C1_SUB_CORRS
            && rec.verifier_protocol_sub_corrs == C1_SUB_CORRS
            && rec.full_corrs == 176_880
            && rec.verifier_protocol_full_corrs == 176_880;
        assert!(byte_formulas_reconcile, "C1 byte/reuse formulas do not reconcile");
        assert!(counters_reconcile, "C1 prover/verifier correlation counters do not reconcile");
        assert_eq!(rec.pcs_opening_bytes, P7B_PCS_OPENING_REFERENCE_BYTES);
        assert_eq!((rec.n_weight_claims, rec.n_embed_claims), (96, 6));
        assert_eq!(layer_params.n_queries, 200);
        assert!(accepted && chk.accepted && golden_match == Some(true));
        C1IdentitySeamReuse {
            scope: "identity-seam x_in reuse only; Packed16/Lean/second shard absent",
            baseline_artifact: C1_BASELINE_ARTIFACT,
            baseline_transcript_bytes: C1_BASELINE_TRANSCRIPT_BYTES,
            baseline_auth_correction_bytes: C1_BASELINE_AUTH_CORRECTION_BYTES,
            baseline_packed_response_bytes: C1_BASELINE_PACKED_RESPONSE_BYTES,
            identity_seam_alias_values: rec.identity_seam_alias_values,
            saved_response_bytes: C1_SAVED_BYTES,
            measured_transcript_bytes: rec.comm_bytes,
            measured_auth_correction_bytes,
            measured_packed_response_bytes,
            baseline_sub_corrs: C1_BASELINE_SUB_CORRS,
            measured_prover_sub_corrs: rec.sub_corrs,
            measured_verifier_sub_corrs: rec.verifier_protocol_sub_corrs,
            measured_prover_full_corrs: rec.full_corrs,
            measured_verifier_full_corrs: rec.verifier_protocol_full_corrs,
            full_corrs_unchanged: rec.full_corrs == 176_880,
            pcs_parameters_unchanged: same_ligero_params(&layer_params, &P4_LAYER)
                && same_ligero_params(&embed_params, &GPT2_FULL),
            claims_unchanged: rec.n_weight_claims == 96 && rec.n_embed_claims == 6,
            byte_formulas_reconcile,
            counters_reconcile,
            baseline_prove_response_s: C1_BASELINE_PROVE_RESPONSE_S,
            measured_prove_response_s: t_prove_response_s,
            prove_response_delta_s: t_prove_response_s - C1_BASELINE_PROVE_RESPONSE_S,
            baseline_verify_response_s: C1_BASELINE_VERIFY_RESPONSE_S,
            measured_verify_response_s: t_verify_response_s,
            verify_response_delta_s: t_verify_response_s - C1_BASELINE_VERIFY_RESPONSE_S,
            typed_correlation_lanes: 0,
            second_phase_b_shard_required: false,
        }
    });
    let packed_response_bytes = rec
        .comm_bytes
        .checked_add(rec.public_logits_packed_bytes)
        .expect("packed response accounting overflow");
    let flip_readiness_criterion_2_runtime_pass = args.flip_readiness_record.then(|| {
        pcg_gate.setup_instances == 2
            && pcg_gate.independent_role_entropy_samples
            && pcg_gate.session_channel_identity_bound
            && pcg_gate.response_authorization_burned_before_setup
            && pcg_gate.burn_on_success_or_abort
            && !pcg_gate.reconnect_retry_resume_allowed
            && pcg_gate.session_binding_digests.len() == pcg_gate.setup_instances
            && pcg_gate.prover_role_seed_commitments.len() == pcg_gate.setup_instances
            && pcg_gate.verifier_role_seed_commitments.len() == pcg_gate.setup_instances
            && pcg_gate.role_seed_commitments_distinct
            && pcg_gate.channel_transcripts_match == Some(true)
    });
    let flip_readiness_criterion_3_pass = args.flip_readiness_record.then(|| {
        !git_dirty
            && t0 == 100
            && n_gen == 50
            && layer_params.n_queries == 200
            && golden_checked
            && golden_match == Some(true)
            && accepted
            && chk.accepted
            && rec.pcs_rows.len() == 13
            && rec.pcs_rows.iter().all(|row| row.verified)
            && rec.n_weight_claims == 96
            && rec.n_embed_claims == 6
            && rec.sub_corrs == C1_SUB_CORRS
            && rec.verifier_protocol_sub_corrs == C1_SUB_CORRS
            && rec.full_corrs == 176_880
            && rec.verifier_protocol_full_corrs == 176_880
            && rec.pcg_allocation_hash_match == Some(true)
            && pcg_gate.mock_prepass_counters_match == Some(true)
            && pcg_gate.mock_prepass_channel_ledger_digest_match == Some(true)
            && pcg_gate.mock_prepass_allocation_digest_match == Some(true)
            && pcg_gate.setup_wire_count_invariant_pass
            && packed_response_bytes == C1_PACKED_RESPONSE_BYTES
    });
    if args.flip_readiness_record {
        assert_eq!(flip_readiness_criterion_2_runtime_pass, Some(true));
        assert_eq!(flip_readiness_criterion_3_pass, Some(true));
    }
    let report = Report {
        report_schema_version: if args.flip_readiness_record {
            4
        } else if args.c1_record {
            3
        } else if args.accelerator == AcceleratorArg::Cpu {
            2
        } else {
            6
        },
        milestone: if args.flip_readiness_record {
            "FLIP-READINESS".into()
        } else if args.c1_record {
            "C1".into()
        } else {
            match (args.accelerator, quick) {
                // Every CUDA schema-6 result belongs to the active P7b code line.
                // P7 is closed and its schema-2/4 selectors stay immutable.
                (AcceleratorArg::CudaHybrid, true) => "P7b-integrated-hybrid-quick".into(),
                (AcceleratorArg::CudaHybrid, false) => "P7b-integrated-hybrid".into(),
                (AcceleratorArg::CudaResident, true) => "P7b-integrated-resident-quick".into(),
                (AcceleratorArg::CudaResident, false) => "P7b-integrated-resident".into(),
                (AcceleratorArg::Cpu, true) => "P6-quick".into(),
                (AcceleratorArg::Cpu, false) => "P6".into(),
            }
        },
        date: date.clone(),
        git: GitProvenance {
            git_sha: git_sha_before_benchmark.clone(),
            git_dirty,
            git_dirty_before_benchmark,
            git_dirty_before_serialization,
            git_sha_before_benchmark: (args.accelerator != AcceleratorArg::Cpu)
                .then(|| git_sha_before_benchmark.clone()),
            git_sha_before_serialization: (args.accelerator != AcceleratorArg::Cpu)
                .then(|| git_sha_before_serialization.clone()),
        },
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        cloud,
        threads: rayon_threads,
        accelerator_backend: args.accelerator.as_str().into(),
        accelerator_cuda_abi_version: (args.accelerator != AcceleratorArg::Cpu)
            .then_some(CUDA_ABI_VERSION),
        resident_timing_policy: is_resident.then(|| args.resident_timing.as_str().to_string()),
        accelerator_witness: accelerator_witness_stats
            .map(|stats| AcceleratorStatsRow::from_stats(stats, "witness-forward")),
        accelerator_response_witness: accelerator_response_witness_stats
            .map(|stats| AcceleratorStatsRow::from_stats(stats, "response-witness-forward")),
        accelerator_prefill_proving: accelerator_prefill_proving_stats
            .map(|stats| AcceleratorStatsRow::from_stats(stats, "prefill-proof")),
        accelerator_proving: rec.accelerator_stats.map(|stats| {
            AcceleratorStatsRow::from_stats(stats, "response-session-including-pcs-and-verifier")
        }),
        accelerator_live_device_bytes_after_cleanup,
        accelerator_workspace_device_bytes_after_cleanup,
        accelerator_resident_device_bytes_after_cleanup,
        accelerator_cached_resident_device_bytes_after_cleanup,
        accelerator_live_device_bytes_after_cache_trim,
        accelerator_workspace_device_bytes_after_cache_trim,
        accelerator_resident_device_bytes_after_cache_trim,
        accelerator_cached_resident_device_bytes_after_cache_trim,
        benchmark_warmup_repetitions: warmup_repetitions,
        benchmark_repetitions: repetitions,
        representative_repetition,
        repetitions: repetitions_rows,
        t_prefill: t0,
        n_decode: n_gen,
        accepted,
        golden_decode_checked: golden_checked,
        golden_decode_match: golden_match,
        generated_tokens: gen.clone(),
        c1_identity_seam_reuse,
        flip_readiness_criterion_2_runtime_pass,
        flip_readiness_criterion_3_pass,
        flip_readiness_external_review_pending: args.flip_readiness_record.then_some(true),
        flip_readiness_cost_acceptance_pending: args.flip_readiness_record.then_some(true),
        flip_readiness_default_flip_pending: args.flip_readiness_record.then_some(true),
        p7b_gate_evaluated,
        p7b_gate_profile: is_resident.then_some(
            if fase_d_realpcg_profile { FASE_D_POD_GATE_PROFILE } else { P7B_GATE_PROFILE }.into(),
        ),
        p7b_machine_eligible: is_resident.then_some(p7b_machine_is_eligible),
        p7b_timing_statistic: is_resident
            .then_some("upper median across measured repetitions".into()),
        p7b_counter_statistic: is_resident.then_some("maximum across measured sessions".into()),
        p7b_prefill_core_gate_s: is_resident.then_some(P7B_PREFILL_CORE_GATE_S),
        p7b_decode_marginal_gate_s: is_resident.then_some(P7B_DECODE_MARGINAL_GATE_S),
        p7b_sync_count_gate_retired: is_resident.then_some(true),
        p7b_sync_wall_fraction_gate: is_resident.then_some(P7B_SYNC_WALL_FRACTION_GATE),
        p7b_h2d_gate_bytes: is_resident.then_some(P7B_H2D_GATE_BYTES),
        p7b_prefill_core_observed_s,
        p7b_decode_marginal_observed_s,
        p7b_sync_observed,
        p7b_sync_wall_fraction_observed,
        p7b_h2d_observed_bytes,
        p7b_prefill_core_gate_pass,
        p7b_decode_marginal_gate_pass,
        p7b_sync_wall_fraction_gate_pass,
        p7b_h2d_gate_pass,
        response_communication_envelope_bytes: is_resident
            .then_some(RESPONSE_COMMUNICATION_ENVELOPE_BYTES),
        response_communication_observed_bytes,
        response_communication_invariant_pass,
        p7b_transcript_reference_bytes: is_resident.then_some(P7B_TRANSCRIPT_REFERENCE_BYTES),
        p7b_pcs_opening_reference_bytes: is_resident.then_some(P7B_PCS_OPENING_REFERENCE_BYTES),
        p7b_packed_logits_reference_bytes: is_resident.then_some(P7B_PACKED_LOGITS_REFERENCE_BYTES),
        p7b_packed_response_reference_bytes: is_resident.then_some(if fase_d_realpcg_profile {
            C1_PACKED_RESPONSE_BYTES
        } else {
            P7B_PACKED_RESPONSE_REFERENCE_BYTES
        }),
        p7b_response_communication_no_growth_pass,
        p7b_all_gates_pass,
        t_native_prefill_s,
        t_native_decode_s,
        native_timing_method: "ABBA paired median".into(),
        native_timing_rounds,
        native_prefill_timing,
        native_decode_timing,
        native_decode_tokens_per_s: n_gen as f64 / t_native_decode_s,
        t_prove_prefill_only_s,
        t_prove_response_s,
        t_prove_decode_marginal_s,
        t_prover_online_accounted_response_s: prover_online_accounted_response_timing.median_s,
        t_prover_online_accounted_decode_marginal_s: prover_online_accounted_decode_marginal_timing
            .median_s,
        t_response_session_wall_s: response_session_wall_timing.median_s,
        t_protocol_closure_exchange_s: protocol_closure_exchange_timing.median_s,
        t_verifier_accounted_s: verifier_accounted_timing.median_s,
        rho_prefill: (args.accelerator != AcceleratorArg::CudaResident)
            .then_some(t_prove_prefill_only_s / t_native_prefill_s),
        rho_decode: (args.accelerator != AcceleratorArg::CudaResident)
            .then_some(t_prove_decode_marginal_s / t_native_decode_s),
        rho_cpu_prefill: t_prove_prefill_only_s / t_native_prefill_s,
        rho_cpu_decode: t_prove_decode_marginal_s / t_native_decode_s,
        rho_denominator: if args.accelerator == AcceleratorArg::CudaResident {
            "same-host native GPU anchor joined by scripts/report.py".into()
        } else {
            "same-process CPU ABBA native baseline".into()
        },
        verified_tokens_per_s: n_gen as f64 / t_prove_response_s,
        t_verify_response_s,
        prove_prefill_timing,
        prove_response_timing,
        prove_decode_marginal_timing,
        prover_online_accounted_response_timing,
        prover_online_accounted_decode_marginal_timing,
        response_session_wall_timing,
        protocol_closure_exchange_timing,
        verify_response_timing,
        verifier_accounted_timing,
        chunk_curve,
        curve_last_over_first,
        gate_flat_cost_per_token: gate_flat,
        t_prove_response_chunked_s: chk.prove_s,
        chunked_accepted: chk.accepted,
        comm_prefill_bytes,
        comm_response_bytes: rec.comm_bytes,
        comm_decode_marginal_bytes: comm_decode_marginal,
        comm_decode_bytes_per_token: comm_decode_marginal / n_gen as u64,
        comm_prefill_by_label: comm_prefill_by_label.clone(),
        comm_response_by_label: rec.transcript_by_label.clone(),
        comm_pcs_by_label: rec.pcs_by_label.clone(),
        comm_decode_marginal_by_label: ledger_delta(
            &rec.transcript_by_label,
            &[&comm_prefill_by_label, &rec.pcs_by_label],
        ),
        pcs_opening_bytes_total: rec.pcs_opening_bytes,
        pcs_cached_query_marginal_bytes_total: rec.pcs_cached_query_marginal_bytes,
        public_logits_bytes,
        public_logits_packed_bytes: rec.public_logits_packed_bytes,
        total_response_download_bytes: rec.comm_bytes + public_logits_bytes,
        total_response_download_packed_bytes: rec.comm_bytes + rec.public_logits_packed_bytes,
        pcs_n_queries: layer_params.n_queries,
        pcs_rate: layer_params.msg_len() as f64 / layer_params.code_len() as f64,
        pcs_relative_distance: 1.0 - layer_params.msg_len() as f64 / layer_params.code_len() as f64,
        pcs_query_error_bits: pcs_query_error_bits(&layer_params),
        pcs_commitments: rec.pcs_rows,
        pcs_commit_total_s,
        pcs_open_total_s,
        pcs_verify_total_s,
        pcs_commit_timing,
        pcs_open_timing,
        pcs_verify_timing,
        n_weight_claims: rec.n_weight_claims,
        n_embed_claims: rec.n_embed_claims,
        closure_prod_claims: rec.closure_prod_claims,
        closure_zero_claims: rec.closure_zero_claims,
        closure_prod_scalar_soundness_bits: scalar_batch_soundness_bits(rec.closure_prod_claims, 2),
        closure_zero_scalar_soundness_bits: scalar_batch_soundness_bits(rec.closure_zero_claims, 1),
        closure_union_scalar_soundness_bits: scalar_batch_soundness_bits(
            rec.closure_prod_claims + rec.closure_zero_claims,
            3,
        ),
        emult_instances_total: rec.emult_instances,
        corr_sub_corrs: rec.sub_corrs,
        corr_full_corrs: rec.full_corrs,
        peak_rss_gb: peak_rss_gb(),
        pcg_backend: args.pcg_backend.as_str().into(),
        ggm_prg: args.ggm_prg.as_str().into(),
        ggm_aes_feature: detected_aes_feature().into(),
        detected_physical_cpu_cores: physical_cpu_cores,
        detected_logical_cpu_cores: logical_cpu_cores,
        pcg_setup_rayon_threads: rayon_threads,
        pcg_production_ready: false,
        pcg_setup_comm_bytes: pcg_gate.setup_comm_bytes,
        pcg_setup_instances: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_instances),
        pcg_setup_comm_bytes_per_instance: pcg_gate
            .per_setup_comm
            .as_ref()
            .map(|comm| comm.total_bytes),
        pcg_setup_comm_prover_to_verifier_bytes_per_instance: pcg_gate
            .per_setup_comm
            .as_ref()
            .map(|comm| comm.prover_to_verifier_bytes),
        pcg_setup_comm_verifier_to_prover_bytes_per_instance: pcg_gate
            .per_setup_comm
            .as_ref()
            .map(|comm| comm.verifier_to_prover_bytes),
        pcg_real_phase_b_total_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_total_setup_and_expansion_s),
        pcg_real_phase_b_base_ot_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_base_ot_s),
        pcg_real_phase_b_ot_extension_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_ot_extension_s),
        pcg_real_phase_b_ggm_pprf_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_ggm_pprf_s),
        pcg_real_phase_b_lpn_expand_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_lpn_expand_s),
        pcg_real_phase_b_consistency_check_s_per_instance: pcg_gate
            .per_setup_timings
            .map(|timing| timing.t_consistency_check_s),
        pcg_production_entropy_source: pcg_gate.production_entropy_source.clone(),
        pcg_independent_role_entropy_samples: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.independent_role_entropy_samples),
        pcg_session_channel_identity_bound: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.session_channel_identity_bound),
        pcg_response_authorization_burned_before_setup: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.response_authorization_burned_before_setup),
        pcg_burn_on_success_or_abort: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.burn_on_success_or_abort),
        pcg_reconnect_retry_resume_allowed: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.reconnect_retry_resume_allowed),
        pcg_session_binding_digests_unique: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.session_binding_digests.len() == pcg_gate.setup_instances),
        pcg_role_seed_commitments_distinct: (args.pcg_backend == PcgBackendArg::Real).then_some(
            pcg_gate.role_seed_commitments_distinct
                && pcg_gate.prover_role_seed_commitments.len() == pcg_gate.setup_instances
                && pcg_gate.verifier_role_seed_commitments.len() == pcg_gate.setup_instances,
        ),
        pcg_setup_wire_count_invariant_pass: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_wire_count_invariant_pass),
        pcg_mock_prepass_channel_ledger_digest_match: pcg_gate
            .mock_prepass_channel_ledger_digest_match,
        pcg_mock_prepass_allocation_digest_match: pcg_gate.mock_prepass_allocation_digest_match,
        pcg_base_vole: if args.pcg_backend == PcgBackendArg::Real {
            Some(
                "COPEe from Ristretto base OT; WYKW Figure-5 sacrifice checked; no dealer/shared seed"
                    .into(),
            )
        } else {
            None
        },
        pcg_real_phase_a_total_s: None,
        pcg_real_phase_a_setup_stub_s: None,
        pcg_real_phase_a_ggm_pprf_s: None,
        pcg_real_phase_a_lpn_expand_s: None,
        pcg_real_phase_a_consistency_check_s: None,
        pcg_real_phase_b_total_s: pcg_gate.timings.map(|t| t.t_total_setup_and_expansion_s),
        pcg_real_phase_b_base_ot_s: pcg_gate.timings.map(|t| t.t_base_ot_s),
        pcg_real_phase_b_ot_extension_s: pcg_gate.timings.map(|t| t.t_ot_extension_s),
        pcg_real_phase_b_ggm_pprf_s: pcg_gate.timings.map(|t| t.t_ggm_pprf_s),
        pcg_real_phase_b_lpn_expand_s: pcg_gate.timings.map(|t| t.t_lpn_expand_s),
        pcg_real_phase_b_consistency_check_s: pcg_gate.timings.map(|t| t.t_consistency_check_s),
        pcg_setup_comm_prover_to_verifier_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_prover_to_verifier_bytes),
        pcg_setup_comm_verifier_to_prover_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_verifier_to_prover_bytes),
        pcg_setup_comm_base_ot_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_base_ot_bytes),
        pcg_setup_comm_ot_extension_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_ot_extension_bytes),
        pcg_setup_comm_ggm_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_ggm_bytes),
        pcg_setup_comm_consistency_bytes: (args.pcg_backend == PcgBackendArg::Real)
            .then_some(pcg_gate.setup_comm_consistency_bytes),
        pcg_channel_transcripts_match: pcg_gate.channel_transcripts_match,
        pcg_mock_prepass_counters_match: pcg_gate.mock_prepass_counters_match,
        pcg_allocation_hash_match: pcg_gate.allocation_hash_match,
    };

    assert!(accepted, "P6 sanity: honest response (both sessions) must verify");
    assert!(gate_flat, "P6 gate: per-token cost must stay ~flat as the cache grows");
    let mut label = if args.flip_readiness_record {
        "flip-readiness".to_string()
    } else if args.c1_record {
        "c1".to_string()
    } else {
        match (args.accelerator, quick) {
            (AcceleratorArg::CudaHybrid, true) => "p7b-integrated-hybrid-quick".to_string(),
            (AcceleratorArg::CudaHybrid, false) => "p7b-integrated-hybrid".to_string(),
            (AcceleratorArg::CudaResident, true) => "p7b-integrated-resident-quick".to_string(),
            (AcceleratorArg::CudaResident, false) => "p7b-integrated-resident".to_string(),
            (AcceleratorArg::Cpu, true) => "p6-quick".to_string(),
            (AcceleratorArg::Cpu, false) => "p6".to_string(),
        }
    };
    if layer_params.n_queries != P4_LAYER.n_queries {
        label.push_str(&format!("-q{}", layer_params.n_queries));
    }
    if args.pcg_backend == PcgBackendArg::Real && !args.flip_readiness_record {
        label.push_str("-realpcg");
    }
    if args.resident_timing == ResidentTimingArg::WallOnlyCounters {
        label.push_str("-wall-only-counters");
    }
    let json = serde_json::to_string_pretty(&report).unwrap();
    if args.diagnostic {
        println!("{json}");
        eprintln!("diagnostic only; no result artifact written");
        return;
    }
    let filename_sha = short_git_sha(&git_sha_before_benchmark);
    let (path, mut file) = create_unique_result_file(&label, &date, &filename_sha);
    std::io::Write::write_all(&mut file, json.as_bytes()).unwrap();
    eprintln!("wrote {}", path.display());
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn c1_reference_is_exact_and_does_not_mutate_historical_p7b() {
        assert_eq!(C1_IDENTITY_SEAM_ALIASES, 9 * 150 * 768);
        assert_eq!(C1_SAVED_BYTES, 8_294_400);
        assert_eq!(C1_TRANSCRIPT_BYTES, 129_119_408);
        assert_eq!(C1_AUTH_CORRECTION_BYTES, 59_545_008);
        assert_eq!(C1_PACKED_RESPONSE_BYTES, 136_526_530);
        assert_eq!(C1_SUB_CORRS, 7_443_126);
        assert_eq!(P7B_PACKED_RESPONSE_REFERENCE_BYTES, 144_820_930);
    }

    #[test]
    fn timing_distribution_keeps_samples_and_reports_upper_median_mad() {
        let distribution = TimingDistribution::new(vec![9.0, 1.0, 5.0, 3.0]);
        assert_eq!(distribution.samples_s, vec![9.0, 1.0, 5.0, 3.0]);
        assert_eq!(distribution.median_s, 5.0);
        assert_eq!(distribution.mad_s, 4.0);
        assert_eq!((distribution.min_s, distribution.max_s), (1.0, 9.0));
        assert_eq!(median_index(&[9.0, 1.0, 5.0, 3.0]), 2);
    }

    #[test]
    fn wall_only_counter_rows_do_not_serialize_fake_phase_zeros() {
        let stats = BackendStats {
            timing_mode: DeviceTimingMode::WallOnlyCounters,
            measurement_wall_ns: 123,
            synchronizations: 1,
            synchronization_ns: 45,
            sync_host_output: 1,
            resident_h2d_host_calls: 2,
            resident_d2h_host_calls: 1,
            resident_h2d_host_call_ns: 67,
            resident_d2h_host_call_ns: 89,
            ..BackendStats::default()
        };
        let row = AcceleratorStatsRow::from_stats(stats, "counter-only-test");
        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value["timing_method"], "wall-only-counters");
        assert_eq!(value["phase_attribution_available"], false);
        assert!(value["h2d_s"].is_null());
        assert!(value["d2h_s"].is_null());
        assert!(value["kernel_s"].is_null());
        assert!(value["coarse_timing_s"].is_null());
        assert!(value["unattributed_cpu_residual_s"].is_null());
        assert!(value["operations"]["gemm"]["kernel_s"].is_null());
        assert_eq!(value["timing_event_api_calls"], 0);
        assert_eq!(value["resident_h2d_host_calls"], 2);
        assert_eq!(value["resident_d2h_host_calls"], 1);
        assert_eq!(value["resident_h2d_host_call_s"], 67e-9);
        assert_eq!(value["resident_d2h_host_call_s"], 89e-9);
    }

    #[test]
    fn p7b_gate_requires_clean_full_geometry_and_preregistered_sampling() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(p7b_gate_eligible(sha, sha, false, false, true, false, 100, 50, 200, 200, 1, 3));
        assert!(!p7b_gate_eligible(
            sha, other_sha, false, false, true, false, 100, 50, 200, 200, 1, 3
        ));
        assert!(!p7b_gate_eligible("", "", false, false, true, false, 100, 50, 200, 200, 1, 3));
        assert!(!p7b_gate_eligible(sha, sha, true, false, true, false, 100, 50, 200, 200, 1, 3));
        assert!(!p7b_gate_eligible(sha, sha, false, true, true, false, 100, 50, 200, 200, 1, 3));
        assert!(!p7b_gate_eligible(sha, sha, false, false, false, false, 100, 50, 200, 200, 1, 3));
        assert!(!p7b_gate_eligible(sha, sha, false, false, true, true, 16, 8, 200, 200, 0, 1));
        assert!(!p7b_gate_eligible(sha, sha, false, false, true, false, 100, 50, 200, 200, 0, 3));
        assert!(!p7b_gate_eligible(sha, sha, false, false, true, false, 100, 50, 200, 200, 1, 1));
        assert!(!p7b_gate_eligible(sha, sha, false, false, true, false, 100, 50, 199, 200, 1, 3));
    }

    #[test]
    fn schema6_serializes_stable_full_git_revision_window() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let provenance = GitProvenance {
            git_sha: sha.into(),
            git_dirty: false,
            git_dirty_before_benchmark: false,
            git_dirty_before_serialization: false,
            git_sha_before_benchmark: Some(sha.into()),
            git_sha_before_serialization: Some(sha.into()),
        };
        let value = serde_json::to_value(provenance).unwrap();
        assert_eq!(value["git_sha"], sha);
        assert_eq!(value["git_sha_before_benchmark"], sha);
        assert_eq!(value["git_sha_before_serialization"], sha);
        assert!(git_revision_unchanged(sha, sha));
        assert!(!git_revision_unchanged(sha, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert_eq!(short_git_sha(sha), "aaaaaaa");
    }

    #[test]
    fn pod_profiles_require_runpod_a100_metadata_and_eight_prover_threads() {
        let cloud = CloudMetadata {
            provider: "RunPod".into(),
            instance_id: "instance".into(),
            region: "eur-is-1".into(),
            image: "Ubuntu 24.04.3 LTS".into(),
            driver_version: "580.159.04".into(),
            cuda_version: "12.8".into(),
            gpu_sku: "NVIDIA A100-SXM4-80GB".into(),
            cpu_model: "AMD EPYC 7713 64-Core Processor".into(),
            ram_gib: "1008".into(),
            vcpus: "255".into(),
        };
        assert!(p7b_machine_eligible(Some(&cloud), 8, false));
        assert!(p7b_machine_eligible(Some(&cloud), 8, true));
        assert!(!p7b_machine_eligible(Some(&cloud), 7, true));
        assert!(!p7b_machine_eligible(None, 8, true));
        assert!(!p7b_machine_eligible(
            Some(&CloudMetadata { provider: "another provider".into(), ..cloud.clone() }),
            8,
            true,
        ));
        assert!(!p7b_machine_eligible(
            Some(&CloudMetadata { gpu_sku: "NVIDIA H100".into(), ..cloud.clone() }),
            8,
            true,
        ));
        assert!(!p7b_machine_eligible(
            Some(&CloudMetadata { region: "new-region".into(), ..cloud.clone() }),
            8,
            false,
        ));
        assert!(p7b_machine_eligible(
            Some(&CloudMetadata { region: "new-region".into(), ..cloud.clone() }),
            8,
            true,
        ));
        assert!(!p7b_machine_eligible(
            Some(&CloudMetadata { instance_id: String::new(), ..cloud }),
            8,
            true,
        ));
    }

    #[test]
    fn synchronization_wall_fraction_uses_session_wall() {
        let stats = BackendStats { synchronization_ns: 20_000_000, ..BackendStats::default() };
        assert_eq!(synchronization_wall_fraction(&stats, 2.0), 0.01);
    }

    #[test]
    fn old_p7b_may_shrink_but_fase_d_requires_exact_c1_bytes() {
        assert!(p7b_communication_gate(
            P7B_TRANSCRIPT_REFERENCE_BYTES,
            P7B_PCS_OPENING_REFERENCE_BYTES,
            P7B_PACKED_LOGITS_REFERENCE_BYTES,
            false,
        ));
        assert!(p7b_communication_gate(
            P7B_TRANSCRIPT_REFERENCE_BYTES - 1,
            P7B_PCS_OPENING_REFERENCE_BYTES - 1,
            P7B_PACKED_LOGITS_REFERENCE_BYTES - 1,
            false,
        ));
        assert!(!p7b_communication_gate(
            P7B_TRANSCRIPT_REFERENCE_BYTES + 1,
            P7B_PCS_OPENING_REFERENCE_BYTES,
            P7B_PACKED_LOGITS_REFERENCE_BYTES,
            false,
        ));
        assert!(p7b_communication_gate(
            C1_TRANSCRIPT_BYTES,
            P7B_PCS_OPENING_REFERENCE_BYTES,
            P7B_PACKED_LOGITS_REFERENCE_BYTES,
            true,
        ));
        assert!(!p7b_communication_gate(
            C1_TRANSCRIPT_BYTES + 1,
            P7B_PCS_OPENING_REFERENCE_BYTES + 1,
            P7B_PACKED_LOGITS_REFERENCE_BYTES,
            true,
        ));
        assert!(!p7b_communication_gate(
            C1_TRANSCRIPT_BYTES,
            P7B_PCS_OPENING_REFERENCE_BYTES,
            P7B_PACKED_LOGITS_REFERENCE_BYTES + 1,
            true,
        ));
    }
}

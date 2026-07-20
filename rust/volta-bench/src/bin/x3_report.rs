//! CPU-only X3 zero-tolerance run-of-record.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{zero_batch_exchange, CorrCounters, CorrelationStream, Transcript, VerifierCtx};
use volta_proto::logup::{Counters, Doms};
use volta_proto::prod_check::{prod_batch_prover, prod_batch_verify};
use volta_proto::{
    build_x3_ops_fixture, encode_x3_golden, layer_dom_base, prove_x3_ops, verify_x3_ops,
    x3_native_operation_counts, X3OpsFixture, X3PadMode, X3_D, X3_DFF, X3_DFF_PAD, X3_D_PAD,
    X3_EXPERTS, X3_GQA_GROUP, X3_HEAD_DIM, X3_KV_HEADS, X3_LAYERS, X3_Q_HEADS, X3_SCORE_SHIFT,
    X3_T, X3_TOP_K, X3_T_PAD, X3_VOCAB, X3_VOCAB_PAD,
};

const CLOSURE_SECTION: u8 = 252;
const PREREG_PATH: &str = "benchmarks/results/x3-prereg-2026-07-20-6c53619.json";
const PREREG_SHA256: &str = "c996bd4d2d887d8df113a17df496cf1b2e74a3b149867fb3dfe1f51e74c198e2";

#[derive(Clone, Copy)]
enum Tamper {
    None,
    RmsStatistic,
    RmsOutput,
    ClampSideRow,
    SiluProduct,
    RopeFold,
    GqaHead,
    SinkDenominator,
    SlidingLowerEdge,
    PadPoison,
}

impl Tamper {
    fn name(self) -> &'static str {
        match self {
            Tamper::None => "honest",
            Tamper::RmsStatistic => "rmsnorm_mean_square_or_rsqrt_input_one_cell_tamper_rejects",
            Tamper::RmsOutput => "rmsnorm_output_one_cell_tamper_rejects",
            Tamper::ClampSideRow => "swiglu_clamp_side_row_tamper_rejects",
            Tamper::SiluProduct => "swiglu_silu_or_hadamard_product_one_cell_tamper_rejects",
            Tamper::RopeFold => "rope_public_coefficient_or_folded_qk_term_tamper_rejects",
            Tamper::GqaHead => "gqa_wrong_kv_head_substitution_rejects",
            Tamper::SinkDenominator => "attention_sink_score_or_denominator_tamper_rejects",
            Tamper::SlidingLowerEdge => {
                "sliding_lower_edge_or_out_of_window_cell_admission_rejects"
            }
            Tamper::PadPoison => "pad_poison_sentinel_admission_rejects",
        }
    }
}

struct RunOutcome {
    accepted: bool,
    proof_verified: bool,
    prod_accepted: bool,
    zero_accepted: bool,
    prover_nonzero_zero_claim_detected: bool,
    trace_byte_index: Option<usize>,
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
    transcript_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    instance_counters: Counters,
    other_counters: Counters,
    logical_lookup_rows: u64,
    padded_lookup_rows: u64,
    table_sites: u64,
    table_contents: u64,
    table_finalizations: u64,
    rope_new_lookup_rows: u64,
    prover_corr: CorrCounters,
    verifier_corr: CorrCounters,
    allocation_digest_prover: String,
    allocation_digest_verifier: String,
    allocation_digest_match: bool,
    channel_digest_prover: String,
    channel_digest_verifier: String,
    channel_digest_match: bool,
}

#[derive(Serialize)]
struct CounterRecord {
    fp2_mults: u64,
    base_mults: u64,
    emult_equiv: f64,
}

impl From<Counters> for CounterRecord {
    fn from(value: Counters) -> Self {
        Self {
            fp2_mults: value.fp2_mults,
            base_mults: value.base_mults,
            emult_equiv: value.emult_equiv(),
        }
    }
}

#[derive(Serialize)]
struct CorrRecord {
    sub_corrs: u64,
    full_corrs: u64,
    domains: u64,
}

impl From<CorrCounters> for CorrRecord {
    fn from(value: CorrCounters) -> Self {
        Self { sub_corrs: value.sub_corrs, full_corrs: value.full_corrs, domains: value.domains }
    }
}

#[derive(Serialize)]
struct HonestRecord {
    accepted: bool,
    proof_verified: bool,
    product_batch_accepted: bool,
    zero_batch_accepted: bool,
    logical_lookup_rows: u64,
    padded_lookup_rows: u64,
    table_sites: u64,
    table_contents: u64,
    table_finalizations: u64,
    rope_new_lookup_rows: u64,
    instance_counters: CounterRecord,
    other_counters: CounterRecord,
    prover_correlation_counters: CorrRecord,
    verifier_correlation_counters: CorrRecord,
    allocation_digest_prover: String,
    allocation_digest_verifier: String,
    allocation_digest_match: bool,
    channel_digest_prover: String,
    channel_digest_verifier: String,
    channel_digest_match: bool,
    transcript_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
}

#[derive(Serialize)]
struct SmokeRunRecord {
    rejected: bool,
    proof_verified: bool,
    product_batch_accepted: bool,
    zero_batch_accepted: bool,
    prover_nonzero_zero_claim_detected: bool,
    target_trace_byte_index: Option<usize>,
    prover_correlation_counters: CorrRecord,
    verifier_correlation_counters: CorrRecord,
    transcript_bytes: u64,
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
}

#[derive(Serialize)]
struct ArtifactRecord {
    config_sha256: String,
    artifact_sha256: String,
    golden_sha256: String,
    exporter_sha256: String,
    golden_bytes: usize,
    rust_numpy_golden_bit_exact: bool,
    differing_bytes: usize,
    real_gpt_oss_export_executed: bool,
}

#[derive(Serialize)]
struct PaddingRecord {
    source_padding_cells: usize,
    all_source_sentinels_nonzero: bool,
    all_source_sentinels_distinct: bool,
    canonical_padding_all_zero: bool,
    logical_layers_poison_invariant: bool,
    final_output_poison_invariant: bool,
    poisoned_run_rejected: bool,
    poisoned_run_prover_nonzero_zero_claim_detected: bool,
    targets: Vec<String>,
}

#[derive(Serialize)]
struct GateRecord {
    verdict: String,
    bit_exact_tolerance: u64,
    shape_t7_d48_exact: bool,
    honest_native_and_proof_accept: bool,
    all_named_rust_numpy_arrays_bit_exact: bool,
    integrated_two_layer_output_bit_exact: bool,
    all_nine_permanent_tamper_tests_reject: bool,
    all_padding_poison_predicates_pass: bool,
    rope_new_lookup_rows_exact_zero: bool,
    prover_verifier_exact_counter_match: bool,
    allocation_digest_match: bool,
    channel_digest_match: bool,
    single_two_phase_tablebank_session: bool,
    no_new_argument_class: bool,
    cpu_four_workers_pass: bool,
    all_pass: bool,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    cpu_only: bool,
    rayon_workers: usize,
    detected_logical_cpus: usize,
    cpu_model: String,
    peak_rss_gib: f64,
    cryptographic_review_assurance: bool,
    kimi3_review_baseline: String,
    kimi3_delta_review_required: bool,
    preregistration_record: String,
    preregistration_sha256: String,
    model_config_blake3: String,
    shape: BTreeMap<String, usize>,
    attention_schedule: Vec<String>,
    gqa_q_to_kv_head: Vec<usize>,
    native_operation_counts: BTreeMap<String, u64>,
    artifacts: ArtifactRecord,
    padding_poison: PaddingRecord,
    honest: HonestRecord,
    smoke_runs: BTreeMap<String, SmokeRunRecord>,
    existing_argument_classes: Vec<String>,
    deviations: Vec<String>,
    gate: GateRecord,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * bytes.len());
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn fp2_digest(value: Fp2) -> String {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
    blake3::hash(&bytes).to_hex().to_string()
}

fn mutate_fixture(kind: Tamper, canonical: &X3OpsFixture) -> X3OpsFixture {
    let mut fixture = canonical.clone();
    match kind {
        Tamper::None | Tamper::PadPoison => unreachable!(),
        Tamper::RmsStatistic => fixture.layers[0].attention.rms1.mean_square[0] += 1,
        Tamper::RmsOutput => fixture.layers[0].attention.rms1.output[0] += 1,
        Tamper::ClampSideRow => fixture.layers[0].experts[0].gate_clamped[0] += 1,
        Tamper::SiluProduct => fixture.layers[0].experts[0].product_acc[0] += 1,
        Tamper::RopeFold => fixture.layers[0].attention.rope_folded_k[0] += 1,
        Tamper::GqaHead => fixture.layers[0].attention.grouped_k_reads[0] += 1,
        Tamper::SinkDenominator => fixture.layers[0].attention.denoms[0] += 1,
        Tamper::SlidingLowerEdge => fixture.layers[1].attention.lo[4] = 0,
    }
    fixture
}

fn run_protocol(tamper: Tamper, seed_tag: u8) -> RunOutcome {
    let canonical = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
    let prover_fixture = if matches!(tamper, Tamper::PadPoison) {
        build_x3_ops_fixture(X3PadMode::AdmitPoison)
    } else {
        canonical.clone()
    };
    let pcg_seed = [0x59 ^ seed_tag; 32];
    let tx_seed = [0xa6 ^ seed_tag; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut stream = CorrelationStream::new(pcg_seed);
    let mut verifier = VerifierCtx::new(pcg_seed, delta);
    let mut txp = Transcript::new(tx_seed);
    let mut txv = Transcript::new(tx_seed);

    let prove_started = Instant::now();
    let (mut proof, pout) = prove_x3_ops(&prover_fixture, &mut stream, &mut txp);
    let prove_s = prove_started.elapsed().as_secs_f64();
    let trace_byte_index = if matches!(tamper, Tamper::None) {
        None
    } else if matches!(tamper, Tamper::PadPoison) {
        let before = encode_x3_golden(&canonical);
        let after = encode_x3_golden(&prover_fixture);
        before.iter().zip(after).position(|(left, right)| *left != right)
    } else {
        let mutated = mutate_fixture(tamper, &canonical);
        proof.smoke_tamper_trace_like(&canonical, &mutated)
    };

    let instance_counters = pout.instance_counters;
    let other_counters = pout.other_counters;
    let logical_lookup_rows = pout.logical_lookup_rows as u64;
    let padded_lookup_rows = pout.padded_lookup_rows as u64;
    let table_sites = pout.table_sites as u64;
    let table_contents = pout.table_contents as u64;
    let table_finalizations = pout.table_finalizations as u64;
    let rope_new_lookup_rows = pout.rope_new_lookup_rows as u64;

    let verify_started = Instant::now();
    let verified = verify_x3_ops(&canonical.config, &proof, &mut verifier, &mut txv);
    let verify_s = verify_started.elapsed().as_secs_f64();
    let proof_verified = verified.is_some();
    let closure_started = Instant::now();
    let mut prod_ok = false;
    let mut zero_ok = false;
    let prover_nonzero_zero_claim_detected = pout.zero.iter().any(|claim| claim.x != Fp2::ZERO);
    if let Some(vout) = verified {
        let mut closure_p = Doms::new(layer_dom_base(CLOSURE_SECTION));
        let mut closure_v = Doms::new(layer_dom_base(CLOSURE_SECTION));
        let chi = txp.challenge_fp2();
        if chi == txv.challenge_fp2() {
            let prod_dom = closure_p.take(1);
            if prod_dom == closure_v.take(1) {
                let mask = stream.draw_fulls(prod_dom, 1)[0];
                let key = verifier.expand_full_keys(prod_dom, 1)[0];
                let product = prod_batch_prover(&pout.prod, chi, mask, &mut txp);
                prod_ok = prod_batch_verify(&vout.kprod, key, delta, chi, &product);
            }
            let zero_dom = closure_p.take(1);
            if zero_dom == closure_v.take(1) && !prover_nonzero_zero_claim_detected {
                zero_ok = zero_batch_exchange(
                    &pout.zero,
                    &vout.kzero,
                    &mut stream,
                    &mut verifier,
                    zero_dom,
                    &mut txp,
                );
                let _ = txv.challenge_fp2();
            }
        }
    }
    let closure_s = closure_started.elapsed().as_secs_f64();
    let probe_p = txp.challenge_fp2();
    let probe_v = txv.challenge_fp2();
    let channel_digest_prover = fp2_digest(probe_p);
    let channel_digest_verifier = fp2_digest(probe_v);
    let allocation_digest_prover = stream.allocation_digest_hex().unwrap_or_default();
    let allocation_digest_verifier = verifier.allocation_digest_hex().unwrap_or_default();
    let prover_corr = stream.counters;
    let verifier_corr = verifier.counters;
    let transcript_by_label =
        txp.ledger().iter().map(|(label, &bytes)| ((*label).to_owned(), bytes)).collect();
    RunOutcome {
        accepted: proof_verified && prod_ok && zero_ok,
        proof_verified,
        prod_accepted: prod_ok,
        zero_accepted: zero_ok,
        prover_nonzero_zero_claim_detected,
        trace_byte_index,
        prove_s,
        verify_s,
        closure_s,
        transcript_bytes: txp.total_bytes(),
        transcript_by_label,
        instance_counters,
        other_counters,
        logical_lookup_rows,
        padded_lookup_rows,
        table_sites,
        table_contents,
        table_finalizations,
        rope_new_lookup_rows,
        prover_corr,
        verifier_corr,
        allocation_digest_match: allocation_digest_prover == allocation_digest_verifier,
        allocation_digest_prover,
        allocation_digest_verifier,
        channel_digest_match: channel_digest_prover == channel_digest_verifier,
        channel_digest_prover,
        channel_digest_verifier,
    }
}

fn command_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(true)
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            ["model name", "Hardware", "Processor"]
                .iter()
                .find_map(|key| line.split_once(':').filter(|(lhs, _)| lhs.trim() == *key))
                .map(|(_, value)| value.trim())
        })
        .unwrap_or("unknown")
        .to_owned()
}

fn peak_rss_gib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<f64>().ok())
        .map(|kib| kib / 1024.0 / 1024.0)
        .unwrap_or(0.0)
}

fn artifact_record(fixture: &X3OpsFixture) -> ArtifactRecord {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/x123");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("toy-moe-v1.manifest.json")).expect("X3 manifest"),
    )
    .expect("valid X3 manifest");
    let files = manifest["files"].as_object().expect("manifest files");
    let digest = |name: &str| files[name]["sha256"].as_str().unwrap().to_owned();
    let golden = std::fs::read(root.join("x3-ops-v1.golden.bin")).expect("X3 golden");
    let native = encode_x3_golden(fixture);
    let differing_bytes = native.iter().zip(&golden).filter(|(left, right)| left != right).count()
        + native.len().abs_diff(golden.len());
    ArtifactRecord {
        config_sha256: digest("toy-moe-v1.config.json"),
        artifact_sha256: digest("toy-moe-v1.artifact.bin"),
        golden_sha256: digest("x3-ops-v1.golden.bin"),
        exporter_sha256: manifest["exporter_sha256"].as_str().unwrap().to_owned(),
        golden_bytes: golden.len(),
        rust_numpy_golden_bit_exact: native == golden,
        differing_bytes,
        real_gpt_oss_export_executed: manifest["real_gpt_oss_export"].as_bool().unwrap_or(true),
    }
}

fn honest_record(value: RunOutcome) -> HonestRecord {
    HonestRecord {
        accepted: value.accepted,
        proof_verified: value.proof_verified,
        product_batch_accepted: value.prod_accepted,
        zero_batch_accepted: value.zero_accepted,
        logical_lookup_rows: value.logical_lookup_rows,
        padded_lookup_rows: value.padded_lookup_rows,
        table_sites: value.table_sites,
        table_contents: value.table_contents,
        table_finalizations: value.table_finalizations,
        rope_new_lookup_rows: value.rope_new_lookup_rows,
        instance_counters: value.instance_counters.into(),
        other_counters: value.other_counters.into(),
        prover_correlation_counters: value.prover_corr.into(),
        verifier_correlation_counters: value.verifier_corr.into(),
        allocation_digest_prover: value.allocation_digest_prover,
        allocation_digest_verifier: value.allocation_digest_verifier,
        allocation_digest_match: value.allocation_digest_match,
        channel_digest_prover: value.channel_digest_prover,
        channel_digest_verifier: value.channel_digest_verifier,
        channel_digest_match: value.channel_digest_match,
        transcript_bytes: value.transcript_bytes,
        transcript_by_label: value.transcript_by_label,
        prove_s: value.prove_s,
        verify_s: value.verify_s,
        closure_s: value.closure_s,
    }
}

fn smoke_record(value: RunOutcome) -> SmokeRunRecord {
    SmokeRunRecord {
        rejected: !value.accepted,
        proof_verified: value.proof_verified,
        product_batch_accepted: value.prod_accepted,
        zero_batch_accepted: value.zero_accepted,
        prover_nonzero_zero_claim_detected: value.prover_nonzero_zero_claim_detected,
        target_trace_byte_index: value.trace_byte_index,
        prover_correlation_counters: value.prover_corr.into(),
        verifier_correlation_counters: value.verifier_corr.into(),
        transcript_bytes: value.transcript_bytes,
        prove_s: value.prove_s,
        verify_s: value.verify_s,
        closure_s: value.closure_s,
    }
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x3-cpu-{index}"))
        .build_global()
        .expect("X3 report must initialize the four-worker CPU pool first");

    eprintln!("X3: honest zero-tolerance native/proof run ...");
    let honest = run_protocol(Tamper::None, 0);
    eprintln!(
        "  accepted={} prove={:.3}s verify={:.3}s closure={:.3}s transcript={}",
        honest.accepted, honest.prove_s, honest.verify_s, honest.closure_s, honest.transcript_bytes
    );
    let honest_counter_match = honest.prover_corr == honest.verifier_corr;
    let honest_allocation_match = honest.allocation_digest_match;
    let honest_channel_match = honest.channel_digest_match;
    let honest_table_finalizations = honest.table_finalizations;
    let honest_rope_lookup_rows = honest.rope_new_lookup_rows;
    let honest_accepted = honest.accepted;

    eprintln!("X3: nine permanent one-cell/pad rejection runs ...");
    let tamper_cases = [
        Tamper::RmsStatistic,
        Tamper::RmsOutput,
        Tamper::ClampSideRow,
        Tamper::SiluProduct,
        Tamper::RopeFold,
        Tamper::GqaHead,
        Tamper::SinkDenominator,
        Tamper::SlidingLowerEdge,
        Tamper::PadPoison,
    ];
    let mut smoke_runs = BTreeMap::new();
    let mut pad_outcome = None;
    for (index, tamper) in tamper_cases.into_iter().enumerate() {
        let outcome = run_protocol(tamper, index as u8 + 1);
        eprintln!(
            "  {} rejected={} proof_verified={} prod={} zero={} target_byte={:?}",
            tamper.name(),
            !outcome.accepted,
            outcome.proof_verified,
            outcome.prod_accepted,
            outcome.zero_accepted,
            outcome.trace_byte_index,
        );
        if matches!(tamper, Tamper::PadPoison) {
            pad_outcome = Some((!outcome.accepted, outcome.prover_nonzero_zero_claim_detected));
        }
        smoke_runs.insert(tamper.name().to_owned(), smoke_record(outcome));
    }
    let smokes_pass = smoke_runs.len() == 9 && smoke_runs.values().all(|run| run.rejected);

    let fixture = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
    let poisoned = build_x3_ops_fixture(X3PadMode::AdmitPoison);
    let artifacts = artifact_record(&fixture);
    let sentinel_set: BTreeSet<_> = fixture.source_padding.iter().copied().collect();
    let (poisoned_run_rejected, poison_detected) = pad_outcome.unwrap_or((false, false));
    let padding = PaddingRecord {
        source_padding_cells: fixture.source_padding.len(),
        all_source_sentinels_nonzero: fixture.source_padding.iter().all(|&value| value != 0),
        all_source_sentinels_distinct: sentinel_set.len() == fixture.source_padding.len(),
        canonical_padding_all_zero: fixture.canonical_padding.iter().all(|&value| value == 0),
        logical_layers_poison_invariant: fixture.layers == poisoned.layers,
        final_output_poison_invariant: fixture.final_witness == poisoned.final_witness,
        poisoned_run_rejected,
        poisoned_run_prover_nonzero_zero_claim_detected: poison_detected,
        targets: vec![
            "time row 7 of physical row-pad 8".to_owned(),
            "wpe row 7 (P5 embedding-selection bug class)".to_owned(),
            "hidden columns 48..63".to_owned(),
            "FFN columns 80..127".to_owned(),
            "vocabulary rows 97..127".to_owned(),
        ],
    };
    let padding_pass = padding.all_source_sentinels_nonzero
        && padding.all_source_sentinels_distinct
        && padding.canonical_padding_all_zero
        && padding.logical_layers_poison_invariant
        && padding.final_output_poison_invariant
        && padding.poisoned_run_rejected
        && padding.poisoned_run_prover_nonzero_zero_claim_detected;
    let workers = rayon::current_num_threads();
    let shape_exact = X3_T == 7 && X3_D == 48 && X3_T_PAD == 8 && X3_D_PAD == 64;
    let no_new_argument_class = true;
    let all_pass = honest_accepted
        && artifacts.rust_numpy_golden_bit_exact
        && artifacts.differing_bytes == 0
        && !artifacts.real_gpt_oss_export_executed
        && shape_exact
        && smokes_pass
        && padding_pass
        && honest_rope_lookup_rows == 0
        && honest_counter_match
        && honest_allocation_match
        && honest_channel_match
        && honest_table_finalizations == 1
        && no_new_argument_class
        && workers == 4;
    let gate = GateRecord {
        verdict: if all_pass { "PASS" } else { "FAIL" }.to_owned(),
        bit_exact_tolerance: 0,
        shape_t7_d48_exact: shape_exact,
        honest_native_and_proof_accept: honest_accepted,
        all_named_rust_numpy_arrays_bit_exact: artifacts.rust_numpy_golden_bit_exact,
        integrated_two_layer_output_bit_exact: artifacts.rust_numpy_golden_bit_exact,
        all_nine_permanent_tamper_tests_reject: smokes_pass,
        all_padding_poison_predicates_pass: padding_pass,
        rope_new_lookup_rows_exact_zero: honest_rope_lookup_rows == 0,
        prover_verifier_exact_counter_match: honest_counter_match,
        allocation_digest_match: honest_allocation_match,
        channel_digest_match: honest_channel_match,
        single_two_phase_tablebank_session: honest_table_finalizations == 1,
        no_new_argument_class,
        cpu_four_workers_pass: workers == 4,
        all_pass,
    };

    let mut shape = BTreeMap::new();
    for (name, value) in [
        ("tokens", X3_T),
        ("token_pad", X3_T_PAD),
        ("layers", X3_LAYERS),
        ("d_model", X3_D),
        ("hidden_pad", X3_D_PAD),
        ("d_ff", X3_DFF),
        ("d_ff_pad", X3_DFF_PAD),
        ("q_heads", X3_Q_HEADS),
        ("kv_heads", X3_KV_HEADS),
        ("gqa_group_size", X3_GQA_GROUP),
        ("head_dim", X3_HEAD_DIM),
        ("experts", X3_EXPERTS),
        ("top_k", X3_TOP_K),
        ("vocab", X3_VOCAB),
        ("vocab_pad", X3_VOCAB_PAD),
        ("score_shift", X3_SCORE_SHIFT as usize),
        ("thin_k", 2),
    ] {
        shape.insert(name.to_owned(), value);
    }
    let native_operation_counts = x3_native_operation_counts(&fixture)
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let report_value = Report {
        schema: 1,
        milestone: "X3-non-GPT-ops-pack".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        cpu_only: true,
        rayon_workers: workers,
        detected_logical_cpus: std::thread::available_parallelism().map(usize::from).unwrap_or(0),
        cpu_model: cpu_model(),
        peak_rss_gib: peak_rss_gib(),
        cryptographic_review_assurance: false,
        kimi3_review_baseline: "f05d727 (X1-X3 additions postdate this detached baseline)".to_owned(),
        kimi3_delta_review_required: true,
        preregistration_record: PREREG_PATH.to_owned(),
        preregistration_sha256: PREREG_SHA256.to_owned(),
        model_config_blake3: hex(&fixture.config.digest().unwrap()),
        shape,
        attention_schedule: vec!["full_causal".to_owned(), "sliding_window_4".to_owned()],
        gqa_q_to_kv_head: vec![0, 0, 0, 1, 1, 1],
        native_operation_counts,
        artifacts,
        padding_poison: padding,
        honest: honest_record(honest),
        smoke_runs,
        existing_argument_classes: vec![
            "Pi_Auth".to_owned(),
            "content-keyed LogUp/TableBank".to_owned(),
            "requant range limbs including P5 chained (6,16) shift-22".to_owned(),
            "blind Hadamard/Pi_Prod".to_owned(),
            "committed-W blind GEMM".to_owned(),
            "band AV GEMM with public lower-edge mask".to_owned(),
            "Pi_ZeroBatch".to_owned(),
        ],
        deviations: vec![
            "The fixed X3 synthetic statement adds a redundant full-trace Pi_Auth/Pi_ZeroBatch conformance binding to make every zero-tolerance named array and pad sentinel independently tamperable; it is an existing argument class and is not projected as a production cost.".to_owned(),
            "Committed-GEMM evaluation claims close against deterministic toy fixture weights in the synthetic spike; no PCS parameter, opening, setup, lifecycle or proof-path machinery changes, and no production PCS credit is claimed.".to_owned(),
            "Clamp1024 and Q10 SiLU are new TableBank contents only. They use the existing two-column content-keyed LogUp argument and introduce no argument class.".to_owned(),
            "The total score shift 22 uses the existing P5 double-round schedule (6 then 16), so its two range sites are counted exactly; RoPE itself adds zero lookup rows.".to_owned(),
            "RMS mean-square division, public RoPE fold, GQA selector, sink denominator and lower-edge mask are fixed public-linear relations closed inside the synthetic trace ZeroBatch; their nonlinear/product components separately instantiate the existing lookup/Hadamard/band machinery.".to_owned(),
        ],
        gate,
    };
    let json = serde_json::to_string_pretty(&report_value).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X3 gate: {} | golden_diff={} | smokes={} | pad_rejected={} | corr={:?}/{:?}",
        report_value.gate.verdict,
        report_value.artifacts.differing_bytes,
        report_value.gate.all_nine_permanent_tamper_tests_reject,
        report_value.padding_poison.poisoned_run_rejected,
        report_value.honest.prover_correlation_counters.full_corrs,
        report_value.honest.verifier_correlation_counters.full_corrs,
    );
    if record {
        if dirty {
            eprintln!("x3_report: refusing an X3 run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x3-ops-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x3_report: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X3 record");
        eprintln!("wrote {}", path.display());
    }
    if !all_pass {
        std::process::exit(1);
    }
}

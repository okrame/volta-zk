//! X1 CPU-only synthetic top-4-of-32 routing gate.
//!
//! The run of record composes the existing VOLTA argument classes and binds
//! the four private router matrices through one unchanged `P4_LAYER` Ligero
//! commitment/opening.  Cheating smokes use the same proof path with a direct
//! synthetic-weight resolver so only the intended routing fault varies.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{zero_batch_exchange, CorrCounters, CorrelationStream, ProverAuthed, Transcript};
use volta_mac::{VerifierCtx, VerifierKey};
use volta_pcs::{commit, open_multi_zk, verify_multi_open, BlockClaim, P4_LAYER};
use volta_proto::logup::{Counters, Doms};
use volta_proto::mle::{eq_vec, eval_mle};
use volta_proto::prod_check::{prod_batch_prover, prod_batch_verify};
use volta_proto::thaler::fold_w;
use volta_proto::{
    build_x1_routing_fixture, encode_x1_golden, prove_x1_routing, verify_x1_routing,
    X1RoutingFixture, X1_D, X1_EXPERTS, X1_LAYERS, X1_T, X1_TOP_K,
};

const PREDICTED_EMULT_TOTAL: f64 = 82_138.296_875;
const PREDICTED_EMULT_PER_TOKEN_LAYER: f64 = 662.405_619_959_677_4;
const ACCEPTANCE_LOW: f64 = 0.80;
const ACCEPTANCE_HIGH: f64 = 1.20;
const CLOSURE_SECTION: u8 = 253;
const PCS_SECTION: u8 = 252;

#[derive(Clone, Copy)]
enum Tamper {
    None,
    WrongExpertSet,
    ScoreSwap,
    ForgedLimb,
    WorseTieCutoff,
    DuplicateId,
    OutOfRangeId,
}

#[derive(Default)]
struct PcsRun {
    accepted: bool,
    claims: usize,
    openings: usize,
    proof_bytes: u64,
    root_hex: String,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
}

struct RunOutcome {
    accepted: bool,
    proof_verified: bool,
    prod_accepted: bool,
    zero_accepted: bool,
    pcs: PcsRun,
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
    transcript_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    comparison_counters: Counters,
    router_instance_counters: Counters,
    total_instance_counters: Counters,
    prover_corr_counters: CorrCounters,
    verifier_corr_counters: CorrCounters,
    allocation_digest_prover: String,
    allocation_digest_verifier: String,
    allocation_digest_match: bool,
    channel_probe_digest_prover: String,
    channel_probe_digest_verifier: String,
    channel_probe_digest_match: bool,
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
struct CorrCounterRecord {
    sub_corrs: u64,
    full_corrs: u64,
    domains: u64,
}

impl From<CorrCounters> for CorrCounterRecord {
    fn from(value: CorrCounters) -> Self {
        Self { sub_corrs: value.sub_corrs, full_corrs: value.full_corrs, domains: value.domains }
    }
}

#[derive(Serialize)]
struct ShapeRecord {
    tokens: usize,
    layers: usize,
    d_model: usize,
    experts: usize,
    top_k: usize,
    token_layers: usize,
    logical_comparisons: usize,
    padded_comparisons: usize,
    comparison_limb_bits: u32,
    comparison_limbs: usize,
    score_bound: String,
    affine_bound_b: u32,
}

#[derive(Serialize)]
struct ArtifactRecord {
    config_file: String,
    config_sha256: String,
    artifact_file: String,
    artifact_sha256: String,
    golden_file: String,
    golden_sha256: String,
    exporter_sha256: String,
    rust_numpy_golden_bit_exact: bool,
    real_gpt_oss_export_executed: bool,
}

#[derive(Serialize)]
struct PcsRecord {
    parameter_profile: String,
    parameters_unchanged: bool,
    rows: usize,
    col_bits: u32,
    pad: usize,
    code_bits: u32,
    queries: usize,
    commitments: usize,
    batched_openings: usize,
    claims: usize,
    claim_point_vars_before_outer_padding: usize,
    claim_point_vars_at_pcs: usize,
    root_hex: String,
    proof_bytes: u64,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
    accepted: bool,
}

#[derive(Serialize)]
struct SmokeRecord {
    honest_accepts: bool,
    wrong_expert_set_rejects: bool,
    score_swap_rejects: bool,
    forged_limb_rejects: bool,
    crafted_tie_accepts_28_29_30_31: bool,
    tied_expert_27_substitution_rejects: bool,
    worse_tied_cutoff_rejects: bool,
    duplicate_id_preflight_rejects: bool,
    out_of_range_id_preflight_rejects: bool,
}

#[derive(Serialize)]
struct GateRecord {
    verdict: String,
    comparison_prediction_total_emult: f64,
    comparison_measured_total_emult: f64,
    comparison_prediction_per_token_layer_emult: f64,
    comparison_measured_per_token_layer_emult: f64,
    measured_over_prediction: f64,
    inclusive_acceptance_ratio: [f64; 2],
    inclusive_acceptance_per_token_layer_emult: [f64; 2],
    comparison_band_pass: bool,
    exact_geometry_pass: bool,
    correlation_counter_equality_pass: bool,
    allocation_digest_equality_pass: bool,
    channel_probe_digest_equality_pass: bool,
    golden_pass: bool,
    pcs_pass: bool,
    product_batch_pass: bool,
    zero_batch_pass: bool,
    smokes_pass: bool,
    cpu_four_workers_pass: bool,
    all_pass: bool,
}

#[derive(Serialize)]
struct TimingRecord {
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
    peak_rss_gib: f64,
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
    model_config_blake3: String,
    router_tie_rule: String,
    d1_public_metadata_encoding: String,
    d1_public_metadata_bytes: u64,
    cryptographic_review_assurance: bool,
    shape: ShapeRecord,
    artifacts: ArtifactRecord,
    comparison_counters: CounterRecord,
    router_instance_counters: CounterRecord,
    total_instance_counters: CounterRecord,
    prover_correlation_counters: CorrCounterRecord,
    verifier_correlation_counters: CorrCounterRecord,
    allocation_digest_prover: String,
    allocation_digest_verifier: String,
    channel_probe_digest_prover: String,
    channel_probe_digest_verifier: String,
    transcript_bytes: u64,
    transcript_by_label: BTreeMap<String, u64>,
    pcs: PcsRecord,
    smokes: SmokeRecord,
    timings: TimingRecord,
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

fn weight_eval(weight: &[i16], point: &[Fp2]) -> Fp2 {
    let folded = fold_w(weight, X1_D, X1_EXPERTS, &eq_vec(&point[..5]));
    eval_mle(&folded, &point[5..])
}

fn place_p4_weights(fixture: &X1RoutingFixture) -> Vec<i16> {
    let mut flat = vec![0i16; 1usize << P4_LAYER.n_vars()];
    let stride = 1usize << P4_LAYER.col_bits;
    for (layer, witness) in fixture.layers.iter().enumerate() {
        let offset = layer * stride;
        for row in 0..X1_D {
            flat[offset + row * X1_EXPERTS..offset + (row + 1) * X1_EXPERTS]
                .copy_from_slice(&witness.weights[row * X1_EXPERTS..(row + 1) * X1_EXPERTS]);
        }
    }
    flat
}

fn apply_tamper(
    tamper: Tamper,
    proof: &mut volta_proto::X1RoutingProof,
    routes: &mut [Vec<[u8; X1_TOP_K]>],
) {
    match tamper {
        Tamper::None => {}
        Tamper::WrongExpertSet => routes[0][0] = [27, 29, 30, 31],
        Tamper::ScoreSwap => proof.layers[0].score_corr.swap(0, 1),
        Tamper::ForgedLimb => proof.layers[0].comparison.lookup.root_corrs[0] += Fp2::ONE,
        Tamper::WorseTieCutoff => routes[0][0] = [29, 28, 30, 31],
        Tamper::DuplicateId => routes[0][0] = [28, 28, 30, 31],
        Tamper::OutOfRangeId => routes[0][0] = [32, 29, 30, 31],
    }
}

fn run_protocol(all_equal: bool, tamper: Tamper, with_pcs: bool, seed_tag: u8) -> RunOutcome {
    let fixture = build_x1_routing_fixture(all_equal);
    let pcg_seed = [0x31 ^ seed_tag; 32];
    let tx_seed = [0x91 ^ seed_tag; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut stream = CorrelationStream::new(pcg_seed);
    let mut verifier = VerifierCtx::new(pcg_seed, delta);
    let mut txp = Transcript::new(tx_seed);
    let mut txv = Transcript::new(tx_seed);

    let prove_started = Instant::now();
    let (mut proof, mut pout) = prove_x1_routing(&fixture, &mut stream, &mut txp);
    let prove_s = prove_started.elapsed().as_secs_f64();
    let comparison_counters = pout.comparison_counters;
    let router_instance_counters = pout.router_instance_counters;
    let total_instance_counters = pout.total_instance_counters;
    let public_x: Vec<_> = fixture.layers.iter().map(|layer| layer.x.clone()).collect();
    let mut routes: Vec<_> = fixture.layers.iter().map(|layer| layer.routes.clone()).collect();
    apply_tamper(tamper, &mut proof, &mut routes);

    let verify_started = Instant::now();
    let verified = verify_x1_routing(
        &fixture.config,
        &fixture.luts,
        &public_x,
        &routes,
        &proof,
        &mut verifier,
        &mut txv,
    );
    let verify_s = verify_started.elapsed().as_secs_f64();
    let proof_verified = verified.is_some();
    let mut pcs = PcsRun::default();
    let mut prod_ok = false;
    let mut zero_ok = false;
    let closure_started = Instant::now();

    if let Some(mut vout) = verified {
        if with_pcs {
            let weights = place_p4_weights(&fixture);
            let commit_started = Instant::now();
            let (commitment, matrix) = commit(&weights, &P4_LAYER, [0xA4; 32]);
            pcs.commit_s = commit_started.elapsed().as_secs_f64();
            let claims_p: Vec<_> = pout
                .weight_claims
                .iter()
                .enumerate()
                .map(|(layer, claim)| {
                    let mut point = claim.point.clone();
                    point.extend([Fp2::ZERO; 3]);
                    (BlockClaim { offset: layer << P4_LAYER.col_bits, point }, claim.value)
                })
                .collect();
            let claims_v: Vec<_> = vout
                .weight_keys
                .iter()
                .enumerate()
                .map(|(layer, (point, key))| {
                    let mut point = point.clone();
                    point.extend([Fp2::ZERO; 3]);
                    (BlockClaim { offset: layer << P4_LAYER.col_bits, point }, *key)
                })
                .collect();
            let mut pcs_p = Doms::new(volta_proto::layer_dom_base(PCS_SECTION));
            let mut pcs_v = Doms::new(volta_proto::layer_dom_base(PCS_SECTION));
            let dom_s = pcs_p.take(1);
            let dom_zb = pcs_p.take(1);
            assert_eq!((dom_s, dom_zb), (pcs_v.take(1), pcs_v.take(1)));
            let open_started = Instant::now();
            let (opening, _) = open_multi_zk(
                &weights,
                &matrix,
                &claims_p,
                &mut stream,
                dom_s,
                dom_zb,
                [0xB5; 32],
                &mut txp,
            );
            pcs.open_s = open_started.elapsed().as_secs_f64();
            let verify_started = Instant::now();
            pcs.accepted = verify_multi_open(
                &commitment.root,
                &P4_LAYER,
                &claims_v,
                &opening,
                &mut verifier,
                dom_s,
                dom_zb,
                &mut txv,
            );
            pcs.verify_s = verify_started.elapsed().as_secs_f64();
            pcs.claims = claims_p.len();
            pcs.openings = 1;
            pcs.proof_bytes = opening.bytes();
            pcs.root_hex = hex(&commitment.root);
            drop((opening, matrix, weights));
        } else {
            pcs.accepted = true;
            for ((claim, (point, key)), layer) in
                pout.weight_claims.iter().zip(&vout.weight_keys).zip(&fixture.layers)
            {
                if claim.point != *point {
                    pcs.accepted = false;
                    break;
                }
                let value = weight_eval(&layer.weights, point);
                pout.zero.push(claim.value.sub(ProverAuthed::from_public(value)));
                vout.kzero.push(key.sub(VerifierKey::from_public(value, delta)));
            }
        }

        let mut closure_p = Doms::new(volta_proto::layer_dom_base(CLOSURE_SECTION));
        let mut closure_v = Doms::new(volta_proto::layer_dom_base(CLOSURE_SECTION));
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
            if zero_dom == closure_v.take(1) {
                zero_ok = zero_batch_exchange(
                    &pout.zero,
                    &vout.kzero,
                    &mut stream,
                    &mut verifier,
                    zero_dom,
                    &mut txp,
                );
                // `zero_batch_exchange` owns only the prover transcript; the
                // verifier receives the same fresh challenge interactively.
                let _ = txv.challenge_fp2();
            }
        }
    }
    let closure_s = closure_started.elapsed().as_secs_f64();

    let probe_p = txp.challenge_fp2();
    let probe_v = txv.challenge_fp2();
    let channel_probe_digest_prover = fp2_digest(probe_p);
    let channel_probe_digest_verifier = fp2_digest(probe_v);
    let allocation_digest_prover = stream.allocation_digest_hex().unwrap_or_default();
    let allocation_digest_verifier = verifier.allocation_digest_hex().unwrap_or_default();
    let prover_corr_counters = stream.counters;
    let verifier_corr_counters = verifier.counters;
    let transcript_by_label =
        txp.ledger().iter().map(|(label, &bytes)| ((*label).to_owned(), bytes)).collect();
    let accepted = proof_verified && pcs.accepted && prod_ok && zero_ok;
    RunOutcome {
        accepted,
        proof_verified,
        prod_accepted: prod_ok,
        zero_accepted: zero_ok,
        pcs,
        prove_s,
        verify_s,
        closure_s,
        transcript_bytes: txp.total_bytes(),
        transcript_by_label,
        comparison_counters,
        router_instance_counters,
        total_instance_counters,
        prover_corr_counters,
        verifier_corr_counters,
        allocation_digest_match: allocation_digest_prover == allocation_digest_verifier,
        allocation_digest_prover,
        allocation_digest_verifier,
        channel_probe_digest_match: channel_probe_digest_prover == channel_probe_digest_verifier,
        channel_probe_digest_prover,
        channel_probe_digest_verifier,
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

fn artifact_record(fixture: &X1RoutingFixture) -> ArtifactRecord {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/x123");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("toy-moe-v1.manifest.json")).expect("X1 manifest"),
    )
    .expect("valid X1 manifest");
    let files = manifest["files"].as_object().expect("manifest files");
    let digest = |name: &str| files[name]["sha256"].as_str().unwrap().to_owned();
    let golden = std::fs::read(root.join("x1-router-v1.golden.bin")).expect("X1 golden");
    ArtifactRecord {
        config_file: "tests/fixtures/x123/toy-moe-v1.config.json".to_owned(),
        config_sha256: digest("toy-moe-v1.config.json"),
        artifact_file: "tests/fixtures/x123/toy-moe-v1.artifact.bin".to_owned(),
        artifact_sha256: digest("toy-moe-v1.artifact.bin"),
        golden_file: "tests/fixtures/x123/x1-router-v1.golden.bin".to_owned(),
        golden_sha256: digest("x1-router-v1.golden.bin"),
        exporter_sha256: manifest["exporter_sha256"].as_str().unwrap().to_owned(),
        rust_numpy_golden_bit_exact: encode_x1_golden(fixture) == golden,
        real_gpt_oss_export_executed: manifest["real_gpt_oss_export"].as_bool().unwrap_or(true),
    }
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x1-cpu-{index}"))
        .build_global()
        .expect("X1 report must initialize the four-worker CPU pool first");

    eprintln!("X1: honest committed routing proof + unchanged P4 PCS ...");
    let honest = run_protocol(false, Tamper::None, true, 0);
    eprintln!(
        "  honest={} prove={:.3}s verify={:.3}s PCS={} bytes={}",
        honest.accepted,
        honest.prove_s,
        honest.verify_s,
        honest.pcs.accepted,
        honest.transcript_bytes
    );
    eprintln!("X1: preregistered cheating smokes ...");
    let wrong = run_protocol(false, Tamper::WrongExpertSet, false, 1);
    let swap = run_protocol(false, Tamper::ScoreSwap, false, 2);
    let limb = run_protocol(false, Tamper::ForgedLimb, false, 3);
    let tied = run_protocol(true, Tamper::None, false, 4);
    let tied_27 = run_protocol(true, Tamper::WrongExpertSet, false, 5);
    let tied_cutoff = run_protocol(true, Tamper::WorseTieCutoff, false, 6);
    let duplicate = run_protocol(false, Tamper::DuplicateId, false, 7);
    let out_of_range = run_protocol(false, Tamper::OutOfRangeId, false, 8);

    let fixture = build_x1_routing_fixture(false);
    let tie_fixture = build_x1_routing_fixture(true);
    let artifacts = artifact_record(&fixture);
    let smokes = SmokeRecord {
        honest_accepts: honest.accepted,
        wrong_expert_set_rejects: !wrong.accepted,
        score_swap_rejects: !swap.accepted,
        forged_limb_rejects: !limb.accepted,
        crafted_tie_accepts_28_29_30_31: tied.accepted
            && tie_fixture.layers[0].routes[0] == [28, 29, 30, 31],
        tied_expert_27_substitution_rejects: !tied_27.accepted,
        worse_tied_cutoff_rejects: !tied_cutoff.accepted,
        duplicate_id_preflight_rejects: !duplicate.proof_verified && !duplicate.accepted,
        out_of_range_id_preflight_rejects: !out_of_range.proof_verified && !out_of_range.accepted,
    };
    let smokes_pass = smokes.honest_accepts
        && smokes.wrong_expert_set_rejects
        && smokes.score_swap_rejects
        && smokes.forged_limb_rejects
        && smokes.crafted_tie_accepts_28_29_30_31
        && smokes.tied_expert_27_substitution_rejects
        && smokes.worse_tied_cutoff_rejects
        && smokes.duplicate_id_preflight_rejects
        && smokes.out_of_range_id_preflight_rejects;

    let measured_total = honest.comparison_counters.emult_equiv();
    let token_layers = (X1_T * X1_LAYERS) as f64;
    let measured_per_token_layer = measured_total / token_layers;
    let ratio = measured_per_token_layer / PREDICTED_EMULT_PER_TOKEN_LAYER;
    let comparison_band_pass = (ACCEPTANCE_LOW..=ACCEPTANCE_HIGH).contains(&ratio);
    let exact_geometry_pass = X1_T * X1_LAYERS * X1_EXPERTS == 3_968
        && X1_LAYERS * (X1_T * X1_EXPERTS).next_power_of_two() == 4_096;
    let correlation_counter_equality_pass =
        honest.prover_corr_counters == honest.verifier_corr_counters;
    let pcs_pass = honest.pcs.accepted
        && honest.pcs.claims == X1_LAYERS
        && honest.pcs.openings == 1
        && P4_LAYER.rows == 1 << 10
        && P4_LAYER.col_bits == 14
        && P4_LAYER.pad == 512
        && P4_LAYER.code_bits == 15
        && P4_LAYER.n_queries == 200;
    let workers = rayon::current_num_threads();
    let cpu_four_workers_pass = workers == 4;
    let all_pass = honest.accepted
        && comparison_band_pass
        && exact_geometry_pass
        && correlation_counter_equality_pass
        && honest.allocation_digest_match
        && honest.channel_probe_digest_match
        && artifacts.rust_numpy_golden_bit_exact
        && !artifacts.real_gpt_oss_export_executed
        && pcs_pass
        && smokes_pass
        && cpu_four_workers_pass;
    let gate = GateRecord {
        verdict: if all_pass { "PASS" } else { "FAIL" }.to_owned(),
        comparison_prediction_total_emult: PREDICTED_EMULT_TOTAL,
        comparison_measured_total_emult: measured_total,
        comparison_prediction_per_token_layer_emult: PREDICTED_EMULT_PER_TOKEN_LAYER,
        comparison_measured_per_token_layer_emult: measured_per_token_layer,
        measured_over_prediction: ratio,
        inclusive_acceptance_ratio: [ACCEPTANCE_LOW, ACCEPTANCE_HIGH],
        inclusive_acceptance_per_token_layer_emult: [
            ACCEPTANCE_LOW * PREDICTED_EMULT_PER_TOKEN_LAYER,
            ACCEPTANCE_HIGH * PREDICTED_EMULT_PER_TOKEN_LAYER,
        ],
        comparison_band_pass,
        exact_geometry_pass,
        correlation_counter_equality_pass,
        allocation_digest_equality_pass: honest.allocation_digest_match,
        channel_probe_digest_equality_pass: honest.channel_probe_digest_match,
        golden_pass: artifacts.rust_numpy_golden_bit_exact,
        pcs_pass,
        product_batch_pass: honest.prod_accepted,
        zero_batch_pass: honest.zero_accepted,
        smokes_pass,
        cpu_four_workers_pass,
        all_pass,
    };

    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let model_config_blake3 = hex(&fixture.config.digest().unwrap());
    let report_value = Report {
        schema: 1,
        milestone: "X1-routing".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        cpu_only: true,
        rayon_workers: workers,
        detected_logical_cpus: std::thread::available_parallelism().map(usize::from).unwrap_or(0),
        cpu_model: cpu_model(),
        model_config_blake3,
        router_tie_rule: "descending (score, expert_id); higher expert id wins ties".to_owned(),
        d1_public_metadata_encoding: "[cutoff, remaining three selected ids ascending]".to_owned(),
        d1_public_metadata_bytes: (X1_T * X1_LAYERS * X1_TOP_K) as u64,
        cryptographic_review_assurance: false,
        shape: ShapeRecord {
            tokens: X1_T,
            layers: X1_LAYERS,
            d_model: X1_D,
            experts: X1_EXPERTS,
            top_k: X1_TOP_K,
            token_layers: X1_T * X1_LAYERS,
            logical_comparisons: X1_T * X1_LAYERS * X1_EXPERTS,
            padded_comparisons: X1_LAYERS * (X1_T * X1_EXPERTS).next_power_of_two(),
            comparison_limb_bits: 16,
            comparison_limbs: 1,
            score_bound: "signed i16 [-32768,32767]".to_owned(),
            affine_bound_b: 16,
        },
        artifacts,
        comparison_counters: honest.comparison_counters.into(),
        router_instance_counters: honest.router_instance_counters.into(),
        total_instance_counters: honest.total_instance_counters.into(),
        prover_correlation_counters: honest.prover_corr_counters.into(),
        verifier_correlation_counters: honest.verifier_corr_counters.into(),
        allocation_digest_prover: honest.allocation_digest_prover,
        allocation_digest_verifier: honest.allocation_digest_verifier,
        channel_probe_digest_prover: honest.channel_probe_digest_prover,
        channel_probe_digest_verifier: honest.channel_probe_digest_verifier,
        transcript_bytes: honest.transcript_bytes,
        transcript_by_label: honest.transcript_by_label,
        pcs: PcsRecord {
            parameter_profile: "P4_LAYER (unchanged)".to_owned(),
            parameters_unchanged: true,
            rows: P4_LAYER.rows,
            col_bits: P4_LAYER.col_bits,
            pad: P4_LAYER.pad,
            code_bits: P4_LAYER.code_bits,
            queries: P4_LAYER.n_queries,
            commitments: 1,
            batched_openings: honest.pcs.openings,
            claims: honest.pcs.claims,
            claim_point_vars_before_outer_padding: 11,
            claim_point_vars_at_pcs: 14,
            root_hex: honest.pcs.root_hex,
            proof_bytes: honest.pcs.proof_bytes,
            commit_s: honest.pcs.commit_s,
            open_s: honest.pcs.open_s,
            verify_s: honest.pcs.verify_s,
            accepted: honest.pcs.accepted,
        },
        smokes,
        timings: TimingRecord {
            prove_s: honest.prove_s,
            verify_s: honest.verify_s,
            closure_s: honest.closure_s,
            peak_rss_gib: peak_rss_gib(),
        },
        deviations: vec![
            "Reuses the existing P4 recip-in deviation: recip_in = denom >> recip_den_shift is prover-asserted while both vectors, the LUT membership, and denominator row sum are authenticated/proved.".to_owned(),
            "The synthetic 2^11 router BlockClaim is embedded in the first sub-block of an unchanged P4_LAYER row by three public zero high coordinates; no PCS parameter changed.".to_owned(),
        ],
        gate,
    };
    let json = serde_json::to_string_pretty(&report_value).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X1 gate: {} | measured {:.9} E-mult/token-layer | ratio {:.9}",
        report_value.gate.verdict, measured_per_token_layer, ratio
    );
    if record {
        if dirty {
            eprintln!("x1_report: refusing a run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x1-routing-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x1_report: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X1 record");
        eprintln!("wrote {}", path.display());
    }
    if !all_pass {
        std::process::exit(1);
    }
}

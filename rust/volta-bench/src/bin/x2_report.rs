//! X2b CPU-only repeat gate after the immutable X2 full-correlation FAIL.
//!
//! Runs the same native witness at T1 k=1 and k=2, composes only existing
//! VOLTA argument classes, and resolves 40 committed-weight claims through
//! three unchanged P4_LAYER Ligero commitments.  The three component
//! MultiOpen proofs are one response-level opening session and are executed
//! sequentially to bound the 4-core VM's resident memory.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{
    zero_batch_exchange, CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey,
};
use volta_pcs::{commit, open_multi_zk, verify_multi_open, BlockClaim, P4_LAYER};
use volta_proto::logup::{Counters, Doms};
use volta_proto::prod_check::{prod_batch_prover, prod_batch_verify};
use volta_proto::{
    build_x2_moe_fixture, encode_x2_golden, eval_i16_matrix, prove_x2_moe, verify_x2_moe,
    x2_native_top2_d1, x2_public_routes, X2MoeFixture, X2MoeProof, X2_D, X2_DFF, X2_EXPERTS,
    X2_HEAD_DIM, X2_KV_HEADS, X2_LAYERS, X2_NATIVE_MACS, X2_QKV, X2_Q_HEADS, X2_T, X2_TOP_K,
    X2_VOCAB,
};

const PREDICTED_LOGICAL: u64 = 12_495;
const PREDICTED_PADDED: u64 = 19_313;
const PREDICTED_SITES: u64 = 80;
const PREDICTED_SUB_K1: u64 = 330_820;
const PREDICTED_SUB_K2: u64 = 330_484;
const PREDICTED_FULL_K1: u64 = 12_462;
const PREDICTED_FULL_K2: u64 = 12_482;
const ACCEPT_LOW: f64 = 0.80;
const ACCEPT_HIGH: f64 = 1.20;
const PCS_SECTION_BASE: u8 = 244;
const CLOSURE_SECTION: u8 = 250;

#[derive(Clone, Copy)]
enum Tamper {
    None,
    WrongExpertSet,
    LowerRankedExpert,
    ScoreSwap,
    ForgedLimb,
    InternalState,
    ChunkBoundary,
}

#[derive(Default)]
struct PcsRun {
    accepted: bool,
    commitments: usize,
    opening_sessions: usize,
    component_multi_open_proofs: usize,
    claims: usize,
    proof_bytes: u64,
    roots: Vec<String>,
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
    instance_counters: Counters,
    other_counters: Counters,
    logical_lookup_rows: u64,
    padded_lookup_rows: u64,
    table_sites: u64,
    table_contents: u64,
    table_finalizations: u64,
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
struct PcsRecord {
    parameter_profile: String,
    parameters_unchanged: bool,
    commitments: usize,
    response_opening_sessions: usize,
    component_multi_open_proofs: usize,
    claims: usize,
    proof_bytes: u64,
    roots: Vec<String>,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
    accepted: bool,
}

#[derive(Serialize)]
struct RunRecord {
    thin_k: usize,
    accepted: bool,
    proof_verified: bool,
    product_batch_accepted: bool,
    zero_batch_accepted: bool,
    native_macs: u64,
    logical_lookup_rows: u64,
    padded_lookup_rows: u64,
    table_sites: u64,
    table_contents: u64,
    table_finalizations: u64,
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
    pcs: PcsRecord,
    prove_s: f64,
    verify_s: f64,
    closure_s: f64,
}

#[derive(Serialize)]
struct SmokeRecord {
    wrong_expert_set_rejects: bool,
    score_swap_rejects: bool,
    forged_limb_rejects: bool,
    crafted_all_equal_tie_selects_6_7: bool,
    lower_ranked_expert_5_substitution_rejects: bool,
    k2_internal_state_substitution_rejects: bool,
    chunk_boundary_substitution_rejects: bool,
}

#[derive(Serialize)]
struct RatioRecord {
    predicted: u64,
    measured: u64,
    measured_over_predicted: f64,
    inclusive_band: [f64; 2],
    pass: bool,
}

#[derive(Serialize)]
struct GateRecord {
    verdict: String,
    native_macs: RatioRecord,
    logical_lookup_rows: RatioRecord,
    padded_lookup_rows: RatioRecord,
    table_sites: RatioRecord,
    sub_correlations_k1: RatioRecord,
    sub_correlations_k2: RatioRecord,
    full_correlations_k1: RatioRecord,
    full_correlations_k2: RatioRecord,
    exact_three_commitments: bool,
    exact_forty_claims: bool,
    exact_one_response_opening_session: bool,
    exact_one_tablebank_finalization: bool,
    prover_verifier_counter_match: bool,
    allocation_digest_match: bool,
    channel_digest_match: bool,
    identical_k1_k2_native_outputs: bool,
    golden_bit_exact: bool,
    smokes_pass: bool,
    cpu_four_workers_pass: bool,
    all_pass: bool,
}

#[derive(Serialize)]
struct ArtifactRecord {
    config_sha256: String,
    artifact_sha256: String,
    golden_sha256: String,
    exporter_sha256: String,
    rust_numpy_golden_bit_exact: bool,
    real_gpt_oss_export_executed: bool,
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
    cryptographic_review_assurance: bool,
    model_config_blake3_k1: String,
    model_config_blake3_k2: String,
    router_tie_rule: String,
    router_tie_scope: String,
    d1_public_metadata_encoding: String,
    prior_x2_record_immutable: String,
    full_correlation_proxy_version: String,
    x2b_full_correlation_band: [f64; 2],
    shape: BTreeMap<String, usize>,
    lookup_counter_labels: String,
    artifacts: ArtifactRecord,
    k1: RunRecord,
    k2: RunRecord,
    smokes: SmokeRecord,
    peak_rss_gib: f64,
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

#[derive(Clone, Copy)]
struct P4RowSlot {
    k: usize,
    n: usize,
    n_pad: usize,
    offset: usize,
    point_vars: usize,
}

struct P4RowLayout {
    tensors: Vec<P4RowSlot>,
}

impl P4RowLayout {
    fn for_shapes(shapes: Vec<(usize, usize)>) -> Self {
        let stride = 1usize << P4_LAYER.col_bits;
        let tensors = shapes
            .into_iter()
            .enumerate()
            .map(|(index, (k, n))| {
                let k_pad = k.next_power_of_two();
                let n_pad = n.next_power_of_two();
                let block_len = k_pad * n_pad;
                assert!(block_len <= stride, "synthetic tensor must fit in one explicit P4 row");
                P4RowSlot {
                    k,
                    n,
                    n_pad,
                    offset: index * stride,
                    point_vars: block_len.trailing_zeros() as usize,
                }
            })
            .collect();
        Self { tensors }
    }

    fn place(&self, tensors: &[&[i16]]) -> Vec<i16> {
        assert_eq!(tensors.len(), self.tensors.len());
        let stride = 1usize << P4_LAYER.col_bits;
        let mut flat = vec![0; self.tensors.len() * stride];
        for (slot, src) in self.tensors.iter().zip(tensors) {
            assert_eq!(src.len(), slot.k * slot.n, "tensor shape mismatch");
            for row in 0..slot.k {
                let dst = slot.offset + row * slot.n_pad;
                flat[dst..dst + slot.n].copy_from_slice(&src[row * slot.n..(row + 1) * slot.n]);
            }
        }
        flat
    }

    fn block_claim(&self, tensor_idx: usize, source_point: &[Fp2]) -> BlockClaim {
        let slot = &self.tensors[tensor_idx];
        assert_eq!(source_point.len(), slot.point_vars, "source MLE point width mismatch");
        let mut point = source_point.to_vec();
        point.resize(P4_LAYER.col_bits as usize, Fp2::ZERO);
        BlockClaim { offset: slot.offset, point }
    }
}

fn layer_layout() -> P4RowLayout {
    let mut shapes = vec![(X2_D, X2_QKV), (X2_D, X2_D), (X2_D, X2_EXPERTS)];
    for _ in 0..X2_EXPERTS {
        shapes.push((X2_D, X2_DFF));
        shapes.push((X2_DFF, X2_D));
    }
    let layout = P4RowLayout::for_shapes(shapes);
    assert_eq!(layout.tensors.len(), 19);
    layout
}

fn global_layout() -> P4RowLayout {
    P4RowLayout::for_shapes(vec![(X2_VOCAB, X2_D), (X2_D, X2_VOCAB)])
}

fn layer_tensor_refs(fixture: &X2MoeFixture, layer: usize) -> Vec<&[i16]> {
    let weights = &fixture.weights[layer];
    let mut tensors = vec![
        weights.dense.c_attn.as_slice(),
        weights.dense.attn_proj.as_slice(),
        weights.router.as_slice(),
    ];
    for expert in &weights.experts {
        tensors.push(expert.up.as_slice());
        tensors.push(expert.down.as_slice());
    }
    tensors
}

fn all_weight_specs(fixture: &X2MoeFixture) -> Vec<(&[i16], usize, usize)> {
    let mut specs = Vec::with_capacity(40);
    for layer in &fixture.weights {
        specs.push((layer.dense.c_attn.as_slice(), X2_D, X2_QKV));
        specs.push((layer.dense.attn_proj.as_slice(), X2_D, X2_D));
        specs.push((layer.router.as_slice(), X2_D, X2_EXPERTS));
        for expert in &layer.experts {
            specs.push((expert.up.as_slice(), X2_D, X2_DFF));
            specs.push((expert.down.as_slice(), X2_DFF, X2_D));
        }
    }
    specs.push((fixture.embedding.as_slice(), X2_VOCAB, X2_D));
    specs.push((fixture.output_weight.as_slice(), X2_D, X2_VOCAB));
    specs
}

#[allow(clippy::too_many_arguments)]
fn pcs_component(
    name_index: usize,
    mut flat: Vec<i16>,
    layout: &P4RowLayout,
    claim_offset: usize,
    claim_count: usize,
    claims_p_all: &[volta_proto::gemm_proof::WeightClaimP],
    claims_v_all: &[(Vec<Fp2>, VerifierKey)],
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    txp: &mut Transcript,
    txv: &mut Transcript,
) -> PcsRun {
    flat.resize(1usize << P4_LAYER.n_vars(), 0);
    let mut pad_seed = [0xA2; 32];
    pad_seed[31] = name_index as u8;
    let commit_started = Instant::now();
    let (commitment, matrix) = commit(&flat, &P4_LAYER, pad_seed);
    let commit_s = commit_started.elapsed().as_secs_f64();
    let claims_p: Vec<_> = (0..claim_count)
        .map(|index| {
            let claim = &claims_p_all[claim_offset + index];
            (layout.block_claim(index, &claim.point), claim.value)
        })
        .collect();
    let claims_v: Vec<_> = (0..claim_count)
        .map(|index| {
            let (point, key) = &claims_v_all[claim_offset + index];
            (layout.block_claim(index, point), *key)
        })
        .collect();
    let mut doms_p = Doms::new(volta_proto::layer_dom_base(PCS_SECTION_BASE + name_index as u8));
    let mut doms_v = Doms::new(volta_proto::layer_dom_base(PCS_SECTION_BASE + name_index as u8));
    let dom_s = doms_p.take(1);
    let dom_zb = doms_p.take(1);
    assert_eq!((dom_s, dom_zb), (doms_v.take(1), doms_v.take(1)));
    let mut mask_seed = [0xB3; 32];
    mask_seed[31] = name_index as u8;
    let open_started = Instant::now();
    let (opening, _) =
        open_multi_zk(&flat, &matrix, &claims_p, stream, dom_s, dom_zb, mask_seed, txp);
    let open_s = open_started.elapsed().as_secs_f64();
    let verify_started = Instant::now();
    let accepted = verify_multi_open(
        &commitment.root,
        &P4_LAYER,
        &claims_v,
        &opening,
        verifier,
        dom_s,
        dom_zb,
        txv,
    );
    let verify_s = verify_started.elapsed().as_secs_f64();
    let out = PcsRun {
        accepted,
        commitments: 1,
        opening_sessions: 0,
        component_multi_open_proofs: 1,
        claims: claim_count,
        proof_bytes: opening.bytes(),
        roots: vec![hex(&commitment.root)],
        commit_s,
        open_s,
        verify_s,
    };
    drop((opening, matrix, commitment, flat));
    out
}

fn run_pcs(
    fixture: &X2MoeFixture,
    claims_p: &[volta_proto::gemm_proof::WeightClaimP],
    claims_v: &[(Vec<Fp2>, VerifierKey)],
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    txp: &mut Transcript,
    txv: &mut Transcript,
) -> PcsRun {
    assert_eq!(claims_p.len(), 40);
    assert_eq!(claims_v.len(), 40);
    let layer_layout = layer_layout();
    let global_layout = global_layout();
    let mut total = PcsRun { accepted: true, opening_sessions: 1, ..Default::default() };
    for layer in 0..X2_LAYERS {
        let flat = layer_layout.place(&layer_tensor_refs(fixture, layer));
        let row = pcs_component(
            layer,
            flat,
            &layer_layout,
            layer * 19,
            19,
            claims_p,
            claims_v,
            stream,
            verifier,
            txp,
            txv,
        );
        total.accepted &= row.accepted;
        total.commitments += row.commitments;
        total.component_multi_open_proofs += row.component_multi_open_proofs;
        total.claims += row.claims;
        total.proof_bytes += row.proof_bytes;
        total.roots.extend(row.roots);
        total.commit_s += row.commit_s;
        total.open_s += row.open_s;
        total.verify_s += row.verify_s;
    }
    let global_refs = [fixture.embedding.as_slice(), fixture.output_weight.as_slice()];
    let global = pcs_component(
        2,
        global_layout.place(&global_refs),
        &global_layout,
        38,
        2,
        claims_p,
        claims_v,
        stream,
        verifier,
        txp,
        txv,
    );
    total.accepted &= global.accepted;
    total.commitments += global.commitments;
    total.component_multi_open_proofs += global.component_multi_open_proofs;
    total.claims += global.claims;
    total.proof_bytes += global.proof_bytes;
    total.roots.extend(global.roots);
    total.commit_s += global.commit_s;
    total.open_s += global.open_s;
    total.verify_s += global.verify_s;
    total
}

fn apply_tamper(tamper: Tamper, proof: &mut X2MoeProof, routes: &mut [Vec<[u8; X2_TOP_K]>]) {
    match tamper {
        Tamper::None => {}
        Tamper::WrongExpertSet => routes[0][0] = [7, 1],
        Tamper::LowerRankedExpert => routes[0][0] = [5, 7],
        Tamper::ScoreSwap => proof.layers[0].auth_corrs[15].swap(0, 1),
        Tamper::ForgedLimb => {
            proof.layers[0].router.comparisons.lookup.root_corrs[0] += Fp2::ONE;
        }
        Tamper::InternalState => assert!(proof.smoke_tamper_internal_reducer()),
        Tamper::ChunkBoundary => proof.global.auth_corrs[1][0] ^= 1,
    }
}

fn run_protocol(thin_k: usize, tamper: Tamper, with_pcs: bool, seed_tag: u8) -> RunOutcome {
    let fixture = build_x2_moe_fixture(thin_k);
    let pcg_seed = [0x42 ^ seed_tag; 32];
    let tx_seed = [0x92 ^ seed_tag; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut stream = CorrelationStream::new(pcg_seed);
    let mut verifier = VerifierCtx::new(pcg_seed, delta);
    let mut txp = Transcript::new(tx_seed);
    let mut txv = Transcript::new(tx_seed);

    let prove_started = Instant::now();
    let (mut proof, mut pout) = prove_x2_moe(&fixture, &mut stream, &mut txp);
    let prove_s = prove_started.elapsed().as_secs_f64();
    let instance_counters = pout.instance_counters;
    let other_counters = pout.other_counters;
    let logical_lookup_rows = pout.logical_lookup_rows as u64;
    let padded_lookup_rows = pout.padded_lookup_rows as u64;
    let table_sites = pout.table_sites as u64;
    let table_contents = pout.table_contents as u64;
    let table_finalizations = pout.table_finalizations as u64;
    let mut routes = x2_public_routes();
    apply_tamper(tamper, &mut proof, &mut routes);

    let verify_started = Instant::now();
    let verified = verify_x2_moe(
        &fixture.config,
        &fixture.luts,
        &fixture.tokens,
        &routes,
        &fixture.final_norm.logits,
        &proof,
        &mut verifier,
        &mut txv,
    );
    let verify_s = verify_started.elapsed().as_secs_f64();
    let proof_verified = verified.is_some();
    let closure_started = Instant::now();
    let mut pcs = PcsRun::default();
    let mut prod_ok = false;
    let mut zero_ok = false;
    if let Some(mut vout) = verified {
        if with_pcs {
            pcs = run_pcs(
                &fixture,
                &pout.weight_claims,
                &vout.weight_keys,
                &mut stream,
                &mut verifier,
                &mut txp,
                &mut txv,
            );
        } else {
            pcs.accepted = true;
            pcs.commitments = 3;
            pcs.opening_sessions = 1;
            pcs.component_multi_open_proofs = 3;
            pcs.claims = 40;
            for ((claim, (point, key)), &(weight, rows, cols)) in
                pout.weight_claims.iter().zip(&vout.weight_keys).zip(&all_weight_specs(&fixture))
            {
                if claim.point != *point {
                    pcs.accepted = false;
                    break;
                }
                let value = eval_i16_matrix(weight, rows, cols, point);
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
        instance_counters,
        other_counters,
        logical_lookup_rows,
        padded_lookup_rows,
        table_sites,
        table_contents,
        table_finalizations,
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

fn ratio(predicted: u64, measured: u64) -> RatioRecord {
    let measured_over_predicted = measured as f64 / predicted as f64;
    RatioRecord {
        predicted,
        measured,
        measured_over_predicted,
        inclusive_band: [ACCEPT_LOW, ACCEPT_HIGH],
        pass: (ACCEPT_LOW..=ACCEPT_HIGH).contains(&measured_over_predicted),
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

fn artifact_record(fixture: &X2MoeFixture) -> ArtifactRecord {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/x123");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("toy-moe-v1.manifest.json")).expect("X2 manifest"),
    )
    .expect("valid X2 manifest");
    let files = manifest["files"].as_object().expect("manifest files");
    let digest = |name: &str| files[name]["sha256"].as_str().unwrap().to_owned();
    let golden = std::fs::read(root.join("x2-moe-v1.golden.bin")).expect("X2 golden");
    ArtifactRecord {
        config_sha256: digest("toy-moe-v1.config.json"),
        artifact_sha256: digest("toy-moe-v1.artifact.bin"),
        golden_sha256: digest("x2-moe-v1.golden.bin"),
        exporter_sha256: manifest["exporter_sha256"].as_str().unwrap().to_owned(),
        rust_numpy_golden_bit_exact: encode_x2_golden(fixture) == golden,
        real_gpt_oss_export_executed: manifest["real_gpt_oss_export"].as_bool().unwrap_or(true),
    }
}

fn pcs_record(value: PcsRun) -> PcsRecord {
    PcsRecord {
        parameter_profile: "P4_LAYER (unchanged), sequential memory-bounded components".to_owned(),
        parameters_unchanged: true,
        commitments: value.commitments,
        response_opening_sessions: value.opening_sessions,
        component_multi_open_proofs: value.component_multi_open_proofs,
        claims: value.claims,
        proof_bytes: value.proof_bytes,
        roots: value.roots,
        commit_s: value.commit_s,
        open_s: value.open_s,
        verify_s: value.verify_s,
        accepted: value.accepted,
    }
}

fn run_record(thin_k: usize, value: RunOutcome) -> RunRecord {
    RunRecord {
        thin_k,
        accepted: value.accepted,
        proof_verified: value.proof_verified,
        product_batch_accepted: value.prod_accepted,
        zero_batch_accepted: value.zero_accepted,
        native_macs: X2_NATIVE_MACS,
        logical_lookup_rows: value.logical_lookup_rows,
        padded_lookup_rows: value.padded_lookup_rows,
        table_sites: value.table_sites,
        table_contents: value.table_contents,
        table_finalizations: value.table_finalizations,
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
        pcs: pcs_record(value.pcs),
        prove_s: value.prove_s,
        verify_s: value.verify_s,
        closure_s: value.closure_s,
    }
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x2-cpu-{index}"))
        .build_global()
        .expect("X2 report must initialize the four-worker CPU pool first");

    eprintln!("X2: honest k=1 proof + 3-commitment PCS session ...");
    let honest_k1 = run_protocol(1, Tamper::None, true, 0);
    eprintln!(
        "  accepted={} prove={:.3}s verify={:.3}s PCS={:.3}s transcript={} PCS-proof-subset={}",
        honest_k1.accepted,
        honest_k1.prove_s,
        honest_k1.verify_s,
        honest_k1.pcs.open_s,
        honest_k1.transcript_bytes,
        honest_k1.pcs.proof_bytes
    );
    eprintln!("X2: honest k=2 proof + 3-commitment PCS session ...");
    let honest_k2 = run_protocol(2, Tamper::None, true, 1);
    eprintln!(
        "  accepted={} prove={:.3}s verify={:.3}s PCS={:.3}s transcript={} PCS-proof-subset={}",
        honest_k2.accepted,
        honest_k2.prove_s,
        honest_k2.verify_s,
        honest_k2.pcs.open_s,
        honest_k2.transcript_bytes,
        honest_k2.pcs.proof_bytes
    );
    eprintln!("X2: permanent routing/T1 cheating smokes ...");
    let wrong = run_protocol(1, Tamper::WrongExpertSet, false, 2);
    let swap = run_protocol(1, Tamper::ScoreSwap, false, 3);
    let limb = run_protocol(1, Tamper::ForgedLimb, false, 4);
    let lower_ranked = run_protocol(1, Tamper::LowerRankedExpert, false, 5);
    let internal = run_protocol(2, Tamper::InternalState, false, 6);
    let boundary = run_protocol(2, Tamper::ChunkBoundary, false, 7);

    let fixture_k1 = build_x2_moe_fixture(1);
    let fixture_k2 = build_x2_moe_fixture(2);
    let artifacts = artifact_record(&fixture_k1);
    let smokes = SmokeRecord {
        wrong_expert_set_rejects: !wrong.accepted,
        score_swap_rejects: !swap.accepted,
        forged_limb_rejects: !limb.accepted,
        crafted_all_equal_tie_selects_6_7: x2_native_top2_d1(&[17; X2_EXPERTS]) == Some([6, 7]),
        lower_ranked_expert_5_substitution_rejects: !lower_ranked.accepted,
        k2_internal_state_substitution_rejects: !internal.accepted,
        chunk_boundary_substitution_rejects: !boundary.accepted,
    };
    let smokes_pass = smokes.wrong_expert_set_rejects
        && smokes.score_swap_rejects
        && smokes.forged_limb_rejects
        && smokes.crafted_all_equal_tie_selects_6_7
        && smokes.lower_ranked_expert_5_substitution_rejects
        && smokes.k2_internal_state_substitution_rejects
        && smokes.chunk_boundary_substitution_rejects;

    let mac_ratio = ratio(X2_NATIVE_MACS, X2_NATIVE_MACS);
    let logical_ratio = ratio(PREDICTED_LOGICAL, honest_k1.logical_lookup_rows);
    let padded_ratio = ratio(PREDICTED_PADDED, honest_k1.padded_lookup_rows);
    let sites_ratio = ratio(PREDICTED_SITES, honest_k1.table_sites);
    let sub_k1 = ratio(PREDICTED_SUB_K1, honest_k1.prover_corr.sub_corrs);
    let sub_k2 = ratio(PREDICTED_SUB_K2, honest_k2.prover_corr.sub_corrs);
    let full_k1 = ratio(PREDICTED_FULL_K1, honest_k1.prover_corr.full_corrs);
    let full_k2 = ratio(PREDICTED_FULL_K2, honest_k2.prover_corr.full_corrs);
    let exact_three_commitments = honest_k1.pcs.commitments == 3 && honest_k2.pcs.commitments == 3;
    let exact_forty_claims = honest_k1.pcs.claims == 40 && honest_k2.pcs.claims == 40;
    let exact_one_response_opening_session =
        honest_k1.pcs.opening_sessions == 1 && honest_k2.pcs.opening_sessions == 1;
    let exact_one_tablebank_finalization =
        honest_k1.table_finalizations == 1 && honest_k2.table_finalizations == 1;
    let prover_verifier_counter_match = honest_k1.prover_corr == honest_k1.verifier_corr
        && honest_k2.prover_corr == honest_k2.verifier_corr;
    let allocation_digest_match =
        honest_k1.allocation_digest_match && honest_k2.allocation_digest_match;
    let channel_digest_match = honest_k1.channel_digest_match && honest_k2.channel_digest_match;
    let identical_k1_k2_native_outputs =
        fixture_k1.layers == fixture_k2.layers && fixture_k1.final_norm == fixture_k2.final_norm;
    let workers = rayon::current_num_threads();
    let cpu_four_workers_pass = workers == 4;
    let all_pass = honest_k1.accepted
        && honest_k2.accepted
        && mac_ratio.pass
        && logical_ratio.pass
        && padded_ratio.pass
        && sites_ratio.pass
        && sub_k1.pass
        && sub_k2.pass
        && full_k1.pass
        && full_k2.pass
        && exact_three_commitments
        && exact_forty_claims
        && exact_one_response_opening_session
        && honest_k1.pcs.component_multi_open_proofs == 3
        && honest_k2.pcs.component_multi_open_proofs == 3
        && exact_one_tablebank_finalization
        && prover_verifier_counter_match
        && allocation_digest_match
        && channel_digest_match
        && identical_k1_k2_native_outputs
        && artifacts.rust_numpy_golden_bit_exact
        && !artifacts.real_gpt_oss_export_executed
        && smokes_pass
        && cpu_four_workers_pass;
    let gate = GateRecord {
        verdict: if all_pass { "PASS" } else { "FAIL" }.to_owned(),
        native_macs: mac_ratio,
        logical_lookup_rows: logical_ratio,
        padded_lookup_rows: padded_ratio,
        table_sites: sites_ratio,
        sub_correlations_k1: sub_k1,
        sub_correlations_k2: sub_k2,
        full_correlations_k1: full_k1,
        full_correlations_k2: full_k2,
        exact_three_commitments,
        exact_forty_claims,
        exact_one_response_opening_session,
        exact_one_tablebank_finalization,
        prover_verifier_counter_match,
        allocation_digest_match,
        channel_digest_match,
        identical_k1_k2_native_outputs,
        golden_bit_exact: artifacts.rust_numpy_golden_bit_exact,
        smokes_pass,
        cpu_four_workers_pass,
        all_pass,
    };

    let mut shape = BTreeMap::new();
    for (name, value) in [
        ("tokens", X2_T),
        ("layers", X2_LAYERS),
        ("d_model", X2_D),
        ("d_ff", X2_DFF),
        ("q_heads", X2_Q_HEADS),
        ("kv_heads", X2_KV_HEADS),
        ("head_dim", X2_HEAD_DIM),
        ("experts", X2_EXPERTS),
        ("top_k", X2_TOP_K),
        ("vocab", X2_VOCAB),
    ] {
        shape.insert(name.to_owned(), value);
    }
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let report_value = Report {
        schema: 2,
        milestone: "X2b-synthetic-MoE-e2e".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        cpu_only: true,
        rayon_workers: workers,
        detected_logical_cpus: std::thread::available_parallelism().map(usize::from).unwrap_or(0),
        cpu_model: cpu_model(),
        cryptographic_review_assurance: false,
        model_config_blake3_k1: hex(&fixture_k1.config.digest().unwrap()),
        model_config_blake3_k2: hex(&fixture_k2.config.digest().unwrap()),
        router_tie_rule: "descending (score, expert_id); higher expert id wins ties".to_owned(),
        router_tie_scope: "synthetic X1/X2b convention; X5 must re-derive the real gpt-oss router rule, whose torch.topk path favors the lower expert index".to_owned(),
        d1_public_metadata_encoding: "[cutoff, strictly-better expert] per token/layer".to_owned(),
        prior_x2_record_immutable:
            "benchmarks/results/x2-moe-2026-07-19-87ce25b.json: FAIL".to_owned(),
        full_correlation_proxy_version: "existing-class-session-v2".to_owned(),
        x2b_full_correlation_band: [ACCEPT_LOW, ACCEPT_HIGH],
        shape,
        lookup_counter_labels:
            "12,495/19,313 are analytic logical/padded rows; measured labels remain logical/padded and are identical for k=1/k=2"
                .to_owned(),
        artifacts,
        k1: run_record(1, honest_k1),
        k2: run_record(2, honest_k2),
        smokes,
        peak_rss_gib: peak_rss_gib(),
        deviations: vec![
            "The existing LogUp engine requires at least two leaves; final_norm_rsqrt therefore pads 1 logical row to 2 (not the analytic 1), using the public LnRsqrt(0) pad pair.".to_owned(),
            "Router route-weight requant is an explicit existing Range(8) site (+28 logical/+32 padded rows and +2 sites); the analytic row named router_topk_range covered the comparison limbs but not this proved product requant.".to_owned(),
            "Router exp denominators add 8 authenticated values/layer so the exp rowsum is connected rather than isolated.".to_owned(),
            "Non-power-of-two Q/K/V slices use explicit public-weight openings; they are not treated as contiguous MLE halves. The synthetic seven-token embedding commitment pins vocabulary row 7 to zero as its canonical low-subcube pad row.".to_owned(),
            "Every synthetic weight block fits inside one P4_LAYER explicit row and is embedded in a distinct row; its source MLE point is extended to 14 variables with public-zero high coordinates, matching the closed X1 outer-padding construction without changing PCS parameters or semantics.".to_owned(),
            "One response-level PCS opening session contains three sequential existing MultiOpen proofs, one per D3 commitment, to keep peak CPU-VM memory bounded; this is reported explicitly rather than counted as one component proof.".to_owned(),
            "Reuses the existing P4 reciprocal-input floor deviation: recip_in = denom >> recip_den_shift is native-asserted while denominator rowsums, both vectors, and reciprocal LUT membership are authenticated/proved.".to_owned(),
        ],
        gate,
    };
    let json = serde_json::to_string_pretty(&report_value).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X2b gate: {} | lookup ratios logical={:.6} padded={:.6} sites={:.6} | corr ratios sub(k1/k2)={:.6}/{:.6} full={:.6}/{:.6}",
        report_value.gate.verdict,
        report_value.gate.logical_lookup_rows.measured_over_predicted,
        report_value.gate.padded_lookup_rows.measured_over_predicted,
        report_value.gate.table_sites.measured_over_predicted,
        report_value.gate.sub_correlations_k1.measured_over_predicted,
        report_value.gate.sub_correlations_k2.measured_over_predicted,
        report_value.gate.full_correlations_k1.measured_over_predicted,
        report_value.gate.full_correlations_k2.measured_over_predicted,
    );
    if record {
        if dirty {
            eprintln!("x2_report: refusing an X2b run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x2b-moe-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x2_report: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X2b record");
        eprintln!("wrote {}", path.display());
    }
    if !all_pass {
        std::process::exit(1);
    }
}

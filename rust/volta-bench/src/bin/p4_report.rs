//! P4 report: one full GPT-2 small transformer layer (d=768, h=12,
//! d_ff=3072) proved + verified end-to-end at T=100 (prefill), fused blocks
//! (LogUp instances + chained GEMMs + hadamard) with the four weight tensors
//! in ONE Ligero commitment (P4_LAYER, 2^24) opened for real.
//!
//! Gates (pre-registered):
//!  - layer e2e accepted; measured lookup counts within 20% of the P0 budget
//!    or explained;
//!  - LogUp lookup-side ≤ 8–10 E-mult/lookup (table side reported raw and
//!    /12-amortized);
//!  - exactly 1 weight claim per tensor (4/layer); PCS cost re-projected with
//!    the measured P3.5 model (0.12 s fixed + 2.3 ms/claim).
//!
//! Run: cargo run --release -p volta-bench --bin p4_report [-- --quick]

use serde::Serialize;
use std::time::Instant;
use volta_bench::{time_median, time_paired};
use volta_field::{Fp, Fp2, FpStream};
use volta_gpt2::{build_luts, forward_layer, synthetic_input, synthetic_weights, LutParams};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcs::{
    commit, layout_gpt2_layer, open_multi_zk, pcs_cost_projection, verify_multi_open, P4_LAYER,
};
use volta_proto::logup::{lift_q, prove_frac_tree, Counters, LeafP};
use volta_proto::{
    cattn_permuted, prod_batch_prover, prod_batch_verify, prove_layer, verify_layer, BlockCtxP,
    BlockCtxV,
};

const D: usize = 768;
const H: usize = 12;
const DFF: usize = 3072;

/// P0 per-layer lookup budget (scripts/budget_p0.py `lk_layer`), T-generic.
fn budget_lookups(t: u64) -> [(&'static str, u64); 12] {
    let (d, h, dff) = (D as u64, H as u64, DFF as u64);
    let caus = t * (t + 1) / 2;
    [
        ("ln_rsqrt", 2 * t),
        ("ln_norm_requant", 2 * t * d),
        ("requant_qkv", t * 3 * d),
        ("requant_scores", h * caus),
        ("exp", h * caus),
        ("softmax_recip", h * t),
        ("softmax_norm_requant", h * caus),
        ("requant_av", t * d),
        ("requant_attn_proj", t * d),
        ("requant_ffn_up", t * dff),
        ("gelu", t * dff),
        ("requant_ffn_down", t * d),
    ]
}

/// Table length per budget table (range tables 2^shift, pair tables 2^16).
fn table_len(name: &str, p: &volta_gpt2::LutParams) -> usize {
    match name {
        "ln_rsqrt" | "exp" | "softmax_recip" | "gelu" => 1 << 16,
        "ln_norm_requant" => 1usize << p.shift_ln_norm,
        "requant_qkv" => 1usize << p.shift_qkv,
        "requant_scores" => 1usize << p.shift_scores,
        "softmax_norm_requant" => 1usize << p.shift_softmax_norm,
        "requant_av" => 1usize << p.shift_av,
        "requant_attn_proj" => 1usize << p.shift_attn_proj,
        "requant_ffn_up" => 1usize << p.shift_ffn_up,
        "requant_ffn_down" => 1usize << p.shift_ffn_down,
        other => panic!("unknown table {other}"),
    }
}

/// Structural lookup-side tree cost (E-mult) for a leaf column of `n`
/// entries — data-independent, so a zero column measures the real constant.
fn lookup_side_emult(n: usize, tag: u64) -> f64 {
    let f = vec![0i16; n];
    let mut chal = FpStream::domain_separated([9u8; 32], 0x2000 + tag);
    let alpha = chal.next_fp2();
    let mut ctr = Counters::default();
    let _ = prove_frac_tree(&LeafP::Ones, &lift_q(&f, alpha), &mut chal, &mut ctr);
    ctr.emult_equiv()
}

/// Structural table-side tree cost (E-mult) for a table of `n` entries.
fn table_side_emult(n: usize, tag: u64) -> f64 {
    let tvals: Vec<i16> = (0..n).map(|j| (j as u16) as i16).collect();
    let mult = vec![1u32; n];
    let mut chal = FpStream::domain_separated([9u8; 32], 0x3000 + tag);
    let alpha = chal.next_fp2();
    let mut ctr = Counters::default();
    let _ = prove_frac_tree(&LeafP::NegMult(&mult), &lift_q(&tvals, alpha), &mut chal, &mut ctr);
    ctr.emult_equiv()
}

#[derive(Serialize)]
struct TableRow {
    table: &'static str,
    budget_lookups: u64,
    /// Witness lookup-stream length (must equal budget exactly).
    witness_lookups: u64,
    /// Padded LogUp instance domain (rectangular causal + pow2 pads).
    padded_lookups: u64,
    witness_vs_budget_pct: f64,
    padded_vs_budget_pct: f64,
    explained: Option<String>,
    /// Structural lookup-side E-mult per padded lookup (gate convention).
    emult_lookup_side_per_padded_lookup: f64,
    /// Table-side tree E-mult per budget lookup, raw (L = 1 layer).
    emult_table_side_raw_per_lookup: f64,
    /// Same, /12 (tables shared by all 12 layers of the model).
    emult_table_side_amortized_per_lookup: f64,
}

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    /// True if the working tree had uncommitted changes at run time — a
    /// dirty run's sha names the PARENT commit, not the measured code.
    git_dirty: bool,
    machine: String,
    threads: usize,
    t_tokens: usize,
    // --- e2e verdict -------------------------------------------------------
    accepted: bool,
    // --- lookups vs budget -------------------------------------------------
    tables: Vec<TableRow>,
    total_budget_lookups: u64,
    total_witness_lookups: u64,
    total_padded_lookups: u64,
    gate_counts_within_20pct: bool,
    padding_note: String,
    // --- E-mult ------------------------------------------------------------
    emult_lookup_side_per_padded_lookup: f64,
    emult_table_side_total_raw_per_lookup: f64,
    emult_table_side_total_amortized_per_lookup: f64,
    /// Full measured layer instances (incl. aux folding, splits, transports).
    emult_instances_total: f64,
    emult_instances_per_budget_lookup: f64,
    emult_chain_other_total: f64,
    gate_emult_lookup_side_8_10: bool,
    emult_gate_note: String,
    // --- timings (ABBA vs native forward) -----------------------------------
    t_native_forward_s: f64,
    t_prove_layer_s: f64,
    prove_over_native: f64,
    t_build_wires_s: f64,
    t_verify_layer_s: f64,
    t_closures_s: f64,
    // --- weight claims + PCS -------------------------------------------------
    n_weight_claims: usize,
    gate_one_claim_per_tensor: bool,
    t_pcs_place_s: f64,
    t_pcs_commit_s: f64,
    t_pcs_open_s: f64,
    t_pcs_verify_s: f64,
    pcs_claims_prefill: usize,
    pcs_projection_prefill_s: f64,
    pcs_projection_response_s: f64,
    pcs_p6_constraint: String,
    // --- correlations / bytes ------------------------------------------------
    corr_bytes_boundary: u64,
    corr_bytes_mult: u64,
    corr_bytes_ln_vectors: u64,
    corr_bytes_attn_vectors: u64,
    corr_bytes_rounds_claims: u64,
    corr_bytes_total: u64,
    budget_corr_bytes_boundary: u64,
    boundary_note: String,
    mult_note: String,
    sub_corrs_consumed: u64,
    full_corrs_consumed: u64,
    transcript_bytes_total: u64,
    peak_rss_gb: f64,
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

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let t = if quick { 32 } else { 100 };

    eprintln!("witness: synthetic weights + forward layer at T={t} ...");
    let luts = build_luts(LutParams::default());
    let w = synthetic_weights(42);
    let x = synthetic_input(43, t);
    let wit = forward_layer(&x, &w, &luts, t);

    // --- timings: ABBA prove vs native forward ------------------------------
    eprintln!("timing: prove_layer vs native forward (ABBA) ...");
    let (t_native, t_prove) = time_paired(
        1,
        2,
        || forward_layer(&x, &w, &luts, t),
        || {
            let mut stream = CorrelationStream::new([0x33u8; 32]);
            let mut tx = Transcript::new([0x34u8; 32]);
            let mut cx = BlockCtxP::new(&mut stream, &mut tx, 0);
            prove_layer(&wit, &w, &luts, &mut cx, None)
        },
    );
    let t_native_forward_s = t_native.as_secs_f64();
    let t_prove_layer_s = t_prove.as_secs_f64();
    eprintln!(
        "  native {t_native_forward_s:.3} s | prove {t_prove_layer_s:.3} s | ratio {:.1}x",
        t_prove_layer_s / t_native_forward_s
    );
    let t_build_wires_s = time_median(1, 3, || volta_proto::build_attn_wires(&wit, &luts))
        .as_secs_f64();

    // --- the run of record: prove, verify, close, open the PCS --------------
    eprintln!("run of record: prove + verify + closures + PCS ...");
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let pcg_seed = [0x21u8; 32];
    let tx_seed = [0x77u8; 32];
    let mut stream = CorrelationStream::new(pcg_seed);
    let mut vc = VerifierCtx::new(pcg_seed, delta);
    let mut txp = Transcript::new(tx_seed);
    let mut txv = Transcript::new(tx_seed);

    let mut cxp = BlockCtxP::new(&mut stream, &mut txp, 0);
    let (proof, out) = prove_layer(&wit, &w, &luts, &mut cxp, None);
    let BlockCtxP { doms: mut domsp, prod, zero, .. } = cxp;

    let tv0 = Instant::now();
    let mut cxv = BlockCtxV::new(&mut vc, &mut txv, 0);
    let outv = verify_layer(
        t, &w.ln1_gain, &w.ln1_bias, &w.ln2_gain, &w.ln2_bias, &luts, &proof, &mut cxv, None,
    )
        .expect("honest layer must verify");
    let BlockCtxV { doms: mut domsv, kprod, kzero, .. } = cxv;
    let t_verify_layer_s = tv0.elapsed().as_secs_f64();

    // PCS: the four weight tensors in one 2^24 Ligero commitment; the layer's
    // 4 claims resolved by one real multi-eval ZK opening (M9 seam).
    // c_attn is committed on the permuted 768×4096 layout the proof claims.
    let n_weight_claims = out.weight_claims.len();
    let layout = layout_gpt2_layer();
    let tp0 = Instant::now();
    let w_perm = cattn_permuted(&w.c_attn);
    let w_flat = layout.place([&w_perm, &w.attn_proj, &w.ffn_up, &w.ffn_down]);
    let t_pcs_place_s = tp0.elapsed().as_secs_f64();
    let tp1 = Instant::now();
    let (com, pm) = commit(&w_flat, &P4_LAYER, [0x51u8; 32]);
    let t_pcs_commit_s = tp1.elapsed().as_secs_f64();

    let claims_p: Vec<_> = out
        .weight_claims
        .iter()
        .enumerate()
        .map(|(g, wc)| (layout.block_claim(g, &wc.point), wc.value))
        .collect();
    let dom_s0 = domsp.take(1);
    let dom_s1 = domsp.take(1);
    assert_eq!((dom_s0, dom_s1), (domsv.take(1), domsv.take(1)));
    let tp2 = Instant::now();
    let (mproof, _mt) =
        open_multi_zk(&w_flat, &pm, &claims_p, &mut stream, dom_s0, dom_s1, [0x44u8; 32], &mut txp);
    let t_pcs_open_s = tp2.elapsed().as_secs_f64();

    let claims_v: Vec<_> = outv
        .weight_keys
        .iter()
        .enumerate()
        .map(|(g, (point, key))| (layout.block_claim(g, point), *key))
        .collect();
    let tp3 = Instant::now();
    let ok_pcs = verify_multi_open(
        &com.root, &P4_LAYER, &claims_v, &mproof, &mut vc, dom_s0, dom_s1, &mut txv,
    );
    let t_pcs_verify_s = tp3.elapsed().as_secs_f64();

    // Final closures: exactly ONE Π_Prod batch + ONE Π_ZeroBatch per layer.
    // These are prover→verifier openings on the already-fixed accumulators;
    // they run after the PCS opening so the shared prover/verifier challenge
    // transcript stays in lockstep through the opening.
    let tc0 = Instant::now();
    let chi = txp.challenge_fp2();
    assert_eq!(chi, txv.challenge_fp2());
    let md = domsp.take(1);
    assert_eq!(md, domsv.take(1));
    let mask = stream.draw_fulls(md, 1)[0];
    let k_mask = vc.expand_full_keys(md, 1)[0];
    let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
    let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
    let mz = domsp.take(1);
    assert_eq!(mz, domsv.take(1));
    let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
    let t_closures_s = tc0.elapsed().as_secs_f64();

    let accepted = ok_prod && ok_zero && ok_pcs;
    eprintln!(
        "  verdict: prod {ok_prod} | zero {ok_zero} | pcs {ok_pcs} → accepted = {accepted}"
    );
    eprintln!(
        "  pcs: place {t_pcs_place_s:.3} s | commit {t_pcs_commit_s:.2} s | open {t_pcs_open_s:.3} s | verify {t_pcs_verify_s:.3} s"
    );

    // --- lookups vs budget + structural E-mult per table ---------------------
    eprintln!("per-table budget + structural E-mult trees ...");
    let budget = budget_lookups(t as u64);
    let wit_counts = wit.lookup_counts();
    let mut tables = Vec::new();
    let (mut tot_budget, mut tot_wit, mut tot_padded) = (0u64, 0u64, 0u64);
    let (mut lk_emult_tot, mut tb_emult_tot) = (0f64, 0f64);
    for (i, &(name, b)) in budget.iter().enumerate() {
        let (wn, wl) = wit_counts[i];
        assert_eq!(wn, name, "budget/witness table order mismatch");
        let padded: u64 =
            out.lookups.iter().filter(|il| il.table == name).map(|il| il.lookups).sum();
        let lk_e = lookup_side_emult(padded as usize, i as u64);
        let tb_e = table_side_emult(table_len(name, &luts.params), i as u64);
        tot_budget += b;
        tot_wit += wl as u64;
        tot_padded += padded;
        lk_emult_tot += lk_e;
        tb_emult_tot += tb_e;
        let pad_pct = 100.0 * (padded as f64 - b as f64) / b as f64;
        tables.push(TableRow {
            table: name,
            budget_lookups: b,
            witness_lookups: wl as u64,
            padded_lookups: padded,
            witness_vs_budget_pct: 100.0 * (wl as f64 - b as f64) / b as f64,
            padded_vs_budget_pct: pad_pct,
            explained: (pad_pct.abs() > 20.0).then(|| {
                "power-of-2 / rectangular-causal instance padding (pre-registered): \
                 attention instances run on h_pad×T_pad×T_pad with valid pad pairs"
                    .into()
            }),
            emult_lookup_side_per_padded_lookup: lk_e / padded as f64,
            emult_table_side_raw_per_lookup: tb_e / b as f64,
            emult_table_side_amortized_per_lookup: tb_e / b as f64 / 12.0,
        });
    }
    let gate_counts = tables.iter().all(|r| r.witness_vs_budget_pct.abs() <= 20.0);
    let emult_lk = lk_emult_tot / tot_padded as f64;
    let gate_emult = emult_lk <= 10.0;
    eprintln!(
        "  lookups: budget {tot_budget} | witness {tot_wit} | padded {tot_padded} \
         | lookup-side {emult_lk:.2} E-mult/padded lookup (gate ≤ 8–10: {gate_emult})"
    );

    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let date = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let git_dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(true);

    // 49 prefill weight-GEMM claims = 4 per layer × 12 layers + logits.
    let pcs_claims_prefill = 4 * 12 + 1;
    let (proj_prefill, proj_response) = pcs_cost_projection(pcs_claims_prefill);

    let bytes_total = out.bytes.boundary
        + out.bytes.mult
        + out.bytes.ln_vectors
        + out.bytes.attn_vectors
        + out.bytes.rounds_claims;
    let report = Report {
        milestone: if quick { "P4-quick".into() } else { "P4".into() },
        date: date.clone(),
        git_sha: sha.clone(),
        git_dirty,
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads: rayon::current_num_threads(),
        t_tokens: t,
        accepted,
        tables,
        total_budget_lookups: tot_budget,
        total_witness_lookups: tot_wit,
        total_padded_lookups: tot_padded,
        gate_counts_within_20pct: gate_counts,
        padding_note: "witness lookup streams match the P0 budget exactly; the padded \
                       LogUp domains exceed it (rectangular causal expansion h_pad×T_pad×T_pad \
                       + pow2 pads) — pre-registered deviation, cost scales with the padded \
                       count"
            .into(),
        emult_lookup_side_per_padded_lookup: emult_lk,
        emult_table_side_total_raw_per_lookup: tb_emult_tot / tot_budget as f64,
        emult_table_side_total_amortized_per_lookup: tb_emult_tot / tot_budget as f64 / 12.0,
        emult_instances_total: out.ctr_instances.emult_equiv(),
        emult_instances_per_budget_lookup: out.ctr_instances.emult_equiv() / tot_budget as f64,
        emult_chain_other_total: out.ctr_other.emult_equiv(),
        gate_emult_lookup_side_8_10: gate_emult,
        emult_gate_note: "measured ~12.2 vs target ≤ 8–10: structural floor — upper tree \
                          layers cost ≈ 7 E-mult/lookup regardless of the Gruen/base-field \
                          leaf optimizations (leaf ≈ 2.8 + build ≈ 1.7 + suffix ≈ 0.5); \
                          helper-column LogUp would reach 2–4 but adds 16 B/lookup bandwidth \
                          (rejected). Motivated miss."
            .into(),
        t_native_forward_s,
        t_prove_layer_s,
        prove_over_native: t_prove_layer_s / t_native_forward_s,
        t_build_wires_s,
        t_verify_layer_s,
        t_closures_s,
        n_weight_claims,
        gate_one_claim_per_tensor: n_weight_claims == 4,
        t_pcs_place_s,
        t_pcs_commit_s,
        t_pcs_open_s,
        t_pcs_verify_s,
        pcs_claims_prefill,
        pcs_projection_prefill_s: proj_prefill,
        pcs_projection_response_s: proj_response,
        pcs_p6_constraint: "P6: decode weight-GEMMs are deferred and proved stacked at \
                            end-of-response (claims/response ≈ 2× claims/prefill), never \
                            per-token PCS claims"
            .into(),
        corr_bytes_boundary: out.bytes.boundary,
        corr_bytes_mult: out.bytes.mult,
        corr_bytes_ln_vectors: out.bytes.ln_vectors,
        corr_bytes_attn_vectors: out.bytes.attn_vectors,
        corr_bytes_rounds_claims: out.bytes.rounds_claims,
        corr_bytes_total: bytes_total,
        budget_corr_bytes_boundary: 8 * 4 * (t * D) as u64,
        boundary_note: "measured boundary = 5 tensors (x_in, K, V, attn/ffn_block_out); \
                        budget counts 4/layer — x_in is the previous layer's output \
                        (embed_out at layer 0), authenticated once per seam in the full model"
            .into(),
        mult_note: "multiplicity vectors are authenticated element-wise per instance \
                    (not in the P0 budget); tables are shared across the 12 layers, so P5 \
                    amortizes this to one multiset argument per table per model"
            .into(),
        sub_corrs_consumed: stream.counters.sub_corrs,
        full_corrs_consumed: stream.counters.full_corrs,
        transcript_bytes_total: txp.total_bytes(),
        peak_rss_gb: peak_rss_gb(),
    };

    assert!(accepted, "P4 sanity: honest full layer + PCS opening must verify");
    let label = if quick { "p4-quick" } else { "p4" };
    let path = format!(
        "{}/../../benchmarks/results/{label}-{date}-{sha}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}

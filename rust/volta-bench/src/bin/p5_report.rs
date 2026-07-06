//! P5 report: the WHOLE GPT-2 small model (12 layers + seams + embedding +
//! final LayerNorm + logits/selection claims) proved + verified end-to-end
//! at T=100 (prefill) on the frozen real-weight artifact, with REAL Ligero
//! PCS commitments for every weight tensor — 13 commitments total (12 ×
//! `P4_LAYER` layer commitments + 1 `GPT2_FULL` embedding commitment,
//! ledger deviation 2026-07-06 #7) opened for real via `open_multi_zk` /
//! `verify_multi_open`.
//!
//! Mirrors `p4_report.rs`'s conventions (JSON emission style, ABBA
//! `time_paired`, git sha/dirty capture, peak_rss) scaled from one layer to
//! the full model, driven through `volta_proto::model_proof::{prove_model,
//! verify_model}` exactly as `model_e2e_on_frozen_artifact` exercises it —
//! this binary is that test's driver, run of record, with the weight claims
//! resolved through the REAL PCS instead of the test's true-evaluation
//! stand-in.
//!
//! Run: cargo run --release -p volta-bench --bin p5_report [-- --quick]
//! (`--quick` = T=32, golden-logits comparison skipped — golden is T=100).

use serde::Serialize;
use std::time::Instant;
use volta_bench::time_paired;
use volta_field::{Fp, Fp2};
use volta_gpt2::{forward_model, load_model, Gpt2Model, ModelWitness, D, DFF, H, L, VOCAB};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcs::{
    commit, layout_gpt2_embed, layout_gpt2_layer, open_multi_zk, pcs_cost_projection,
    verify_multi_open, GPT2_FULL, P4_LAYER,
};
use volta_proto::block_proof::layer_dom_base;
use volta_proto::logup::Doms;
use volta_proto::{cattn_permuted, prod_batch_prover, prod_batch_verify, prove_model, verify_model};

/// P0 per-layer lookup budget (scripts/budget_p0.py `lk_layer`), T-generic —
/// copied verbatim from `p4_report.rs` (model-level budget = 12× this, per
/// `budget_p0.py`'s own `lookups_total = L * lookups_layer`).
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

#[derive(Serialize)]
struct TableRow {
    table: &'static str,
    /// Per-layer budget × 12 (whole model).
    budget_lookups_model: u64,
    witness_lookups_model: u64,
    padded_lookups_model: u64,
    witness_vs_budget_pct: f64,
}

#[derive(Serialize)]
struct PcsCommitmentRow {
    name: String,
    commit_s: f64,
    open_s: f64,
    verify_s: f64,
    opening_bytes: u64,
    verified: bool,
}

#[derive(Serialize)]
struct GoldenCheck {
    checked: bool,
    argmax: u64,
    expected_argmax: Option<u64>,
    logits_match: Option<bool>,
}

#[derive(Serialize)]
struct BytesBreakdown {
    boundary: u64,
    mult_vectors: u64,
    ln_vectors: u64,
    attn_vectors: u64,
    rounds_claims: u64,
    total: u64,
}

#[derive(Serialize)]
struct PcsReport {
    commitments: Vec<PcsCommitmentRow>,
    commit_total_s: f64,
    commit_layers_mean_s: f64,
    commit_embed_s: f64,
    open_total_s: f64,
    open_per_commitment_mean_s: f64,
    verify_total_s: f64,
    opening_bytes_total: u64,
    n_weight_claims: usize,
    n_embed_claims: usize,
    claims_prefill: usize,
    projection_prefill_s: f64,
    projection_response_s: f64,
    p6_constraint: String,
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
    golden: GoldenCheck,
    // --- lookups vs budget ---------------------------------------------------
    tables: Vec<TableRow>,
    total_budget_lookups_model: u64,
    total_witness_lookups_model: u64,
    total_padded_lookups_model: u64,
    gate_counts_within_20pct: bool,
    embed_lookups_note: String,
    // --- E-mult / correlations -----------------------------------------------
    emult_instances_total: f64,
    emult_instances_per_budget_lookup: f64,
    emult_other_total: f64,
    corr_sub_corrs: u64,
    corr_full_corrs: u64,
    corr_domains: u64,
    // --- timings (ABBA vs native forward, then run of record) ----------------
    /// The witness generator (`forward_model`) is the native-inference
    /// anchor — P4 convention, same denominator as `rho` in
    /// docs/benchmark-plan.md.
    t_witness_native_s: f64,
    t_prove_model_abba_s: f64,
    prove_over_native: f64,
    t_prove_model_record_s: f64,
    t_verify_model_s: f64,
    // --- PCS (13 real commitments) --------------------------------------------
    pcs: PcsReport,
    // --- communication bytes ---------------------------------------------------
    bytes: BytesBreakdown,
    transcript_bytes_total: u64,
    total_comm_response_bytes: u64,
    /// Naive 2× projection of the PCS-opening bytes only (decode weight-GEMM
    /// claims deferred/stacked at end-of-response per the P6 constraint —
    /// see `pcs.p6_constraint`); corrections/transcript are prefill-only
    /// here, so this is a lower bound on the true per-response total.
    total_comm_response_projected_2x_pcs_bytes: u64,
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

fn weights_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
}

/// Parse `benchmarks/weights/golden-p5.bin` (format: `scripts/dump_golden.py`
/// / `volta_gpt2::model`'s golden test) — magic "VGOLD1\0\0", u32 t, u32
/// argmax, i64 logits[VOCAB], then checksums we don't need here.
struct Golden {
    t: usize,
    argmax: u32,
    logits: Vec<i64>,
}

fn read_golden(path: &std::path::Path) -> Golden {
    let g = std::fs::read(path).expect("read golden-p5.bin");
    assert_eq!(&g[..8], b"VGOLD1\0\0", "golden file magic mismatch");
    let rd_u32 = |o: usize| u32::from_le_bytes(g[o..o + 4].try_into().unwrap());
    let rd_i64 = |o: usize| i64::from_le_bytes(g[o..o + 8].try_into().unwrap());
    let t = rd_u32(8) as usize;
    let argmax = rd_u32(12);
    let off = 16;
    let logits: Vec<i64> = (0..VOCAB).map(|i| rd_i64(off + 8 * i)).collect();
    Golden { t, argmax, logits }
}

fn argmax_i64(v: &[i64]) -> u32 {
    v.iter()
        .enumerate()
        .max_by_key(|&(_, &x)| x)
        .map(|(i, _)| i as u32)
        .unwrap_or(0)
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let t = if quick { 32 } else { 100 };

    let dir = weights_dir();
    if !dir.join("gpt2s-q.bin").exists() {
        eprintln!(
            "p5_report: frozen artifact not found at {:?}. Run `python3 scripts/export_gpt2.py` first.",
            dir
        );
        std::process::exit(1);
    }

    eprintln!("loading frozen artifact + forward_model at T={t} ...");
    let model: Gpt2Model = load_model(&dir).expect("load_model");
    let wit: ModelWitness = forward_model(&model, t);

    // --- golden check --------------------------------------------------------
    let golden_path = dir.join("golden-p5.bin");
    let golden = if !quick {
        if !golden_path.exists() {
            eprintln!(
                "p5_report: golden-p5.bin missing at {:?} — cannot validate T=100 golden logits. \
                 Run `python3 scripts/dump_golden.py` first.",
                golden_path
            );
            std::process::exit(1);
        }
        let g = read_golden(&golden_path);
        assert_eq!(g.t, t, "golden file was dumped at a different T");
        Some(g)
    } else if golden_path.exists() {
        Some(read_golden(&golden_path))
    } else {
        None
    };
    let argmax = argmax_i64(&wit.logits);
    let (expected_argmax, logits_match) = match (&golden, quick) {
        (Some(g), false) => {
            assert_eq!(wit.logits.len(), g.logits.len(), "logits length mismatch vs golden");
            let m = wit.logits == g.logits;
            assert!(m, "P5 sanity: full logits vector must match golden-p5.bin at T=100");
            assert_eq!(argmax, g.argmax, "P5 sanity: argmax must match golden-p5.bin");
            (Some(g.argmax as u64), Some(m))
        }
        _ => (None, None),
    };
    eprintln!("  argmax (last position) = {argmax}");
    let golden_report = GoldenCheck {
        checked: !quick && golden.is_some(),
        argmax: argmax as u64,
        expected_argmax,
        logits_match,
    };

    // --- ABBA timing: witness generation (native anchor) vs prove_model ------
    eprintln!("timing: forward_model (native) vs prove_model (ABBA) ...");
    let (t_native, t_prove) = time_paired(
        1,
        2,
        || forward_model(&model, t),
        || {
            let mut stream = CorrelationStream::new([0x33u8; 32]);
            let mut tx = Transcript::new([0x34u8; 32]);
            prove_model(&model, &wit, &mut stream, &mut tx)
        },
    );
    let t_witness_native_s = t_native.as_secs_f64();
    let t_prove_model_abba_s = t_prove.as_secs_f64();
    eprintln!(
        "  native (witness) {t_witness_native_s:.3} s | prove {t_prove_model_abba_s:.3} s | ratio {:.1}x",
        t_prove_model_abba_s / t_witness_native_s
    );

    // --- run of record: fresh stream/vc/transcripts (p4_report seed pattern) -
    eprintln!("run of record: prove_model + verify_model ...");
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let pcg_seed = [0x21u8; 32];
    let tx_seed = [0x77u8; 32];
    let mut stream = CorrelationStream::new(pcg_seed);
    let mut vc = VerifierCtx::new(pcg_seed, delta);
    let mut txp = Transcript::new(tx_seed);
    let mut txv = Transcript::new(tx_seed);

    let tp0 = Instant::now();
    let (proof, out, mut prod, mut zero) = prove_model(&model, &wit, &mut stream, &mut txp);
    let t_prove_model_record_s = tp0.elapsed().as_secs_f64();

    let tv0 = Instant::now();
    let (outv, mut kprod, mut kzero) = verify_model(&model, t, &wit.logits, &proof, &mut vc, &mut txv)
        .expect("honest model proof must verify");
    let t_verify_model_s = tv0.elapsed().as_secs_f64();

    // --- REAL PCS: 13 commitments (ledger deviation 2026-07-06 #7) -----------
    // Order: prove_model, verify_model (above), THEN per-commitment
    // [commit_l, open_l, verify_open_l] sequentially, dropping the flat
    // vector + prover matrix before the next layer — bounds peak RSS to
    // ~one layer's encoded matrix (~260 MB) + the 2 GB embed commitment,
    // never all 13 resident at once.
    eprintln!("PCS: 13 real Ligero commitments (12 layer + 1 embed) ...");
    assert_eq!(out.weight_claims.len(), 4 * L, "expected 48 weight claims");
    assert_eq!(outv.weight_keys.len(), 4 * L);
    let mut pcs_rows = Vec::with_capacity(13);
    let mut commit_layers_s = Vec::with_capacity(L);
    let mut open_times = Vec::with_capacity(13);
    let mut opening_bytes_total = 0u64;
    let mut pcs_all_ok = true;

    let layout = layout_gpt2_layer();
    for l in 0..L {
        let w = &model.layers[l].0;
        let w_perm = cattn_permuted(&w.c_attn);
        let w_flat = layout.place([&w_perm, &w.attn_proj, &w.ffn_up, &w.ffn_down]);

        let mut pad_seed = [0x51u8; 32];
        pad_seed[31] = l as u8;
        let tc0 = Instant::now();
        let (com, pm) = commit(&w_flat, &P4_LAYER, pad_seed);
        let commit_s = tc0.elapsed().as_secs_f64();
        commit_layers_s.push(commit_s);

        let claims_p: Vec<_> = (0..4)
            .map(|k| {
                let wc = &out.weight_claims[4 * l + k];
                (layout.block_claim(k, &wc.point), wc.value)
            })
            .collect();
        let mut doms_p = Doms::new(layer_dom_base(240 + l as u8));
        let mut doms_v = Doms::new(layer_dom_base(240 + l as u8));
        let dom_s0 = doms_p.take(1);
        let dom_s1 = doms_p.take(1);
        debug_assert_eq!((dom_s0, dom_s1), (doms_v.take(1), doms_v.take(1)));
        let mut mask_seed = [0x44u8; 32];
        mask_seed[31] = l as u8;

        let to0 = Instant::now();
        let (mproof, _mt) =
            open_multi_zk(&w_flat, &pm, &claims_p, &mut stream, dom_s0, dom_s1, mask_seed, &mut txp);
        let open_s = to0.elapsed().as_secs_f64();
        open_times.push(open_s);
        let ob = mproof.bytes();
        opening_bytes_total += ob;

        let claims_v: Vec<_> = (0..4)
            .map(|k| {
                let (point, key) = &outv.weight_keys[4 * l + k];
                (layout.block_claim(k, point), *key)
            })
            .collect();
        let tv1 = Instant::now();
        let ok = verify_multi_open(
            &com.root, &P4_LAYER, &claims_v, &mproof, &mut vc, dom_s0, dom_s1, &mut txv,
        );
        let verify_s = tv1.elapsed().as_secs_f64();
        pcs_all_ok &= ok;

        pcs_rows.push(PcsCommitmentRow {
            name: format!("layer_{l}"),
            commit_s,
            open_s,
            verify_s,
            opening_bytes: ob,
            verified: ok,
        });
        // Drop w_flat/pm/com before the next layer (RSS bound).
        drop((w_flat, pm, com));
        eprintln!("  layer {l}: commit {commit_s:.2}s open {open_s:.3}s verify {verify_s:.3}s bytes {ob} ok={ok}");
    }

    // Embedding commitment.
    assert_eq!(out.embed_claims.len(), 3, "expected 3 embedding claims");
    assert_eq!(outv.embed_keys.len(), 3);
    let layout_e = layout_gpt2_embed();
    let e_flat = layout_e.place(&[&model.wte, &model.wpe]);
    let te0 = Instant::now();
    let (com_e, pm_e) = commit(&e_flat, &GPT2_FULL, [0x52u8; 32]);
    let commit_embed_s = te0.elapsed().as_secs_f64();

    // Claim order [wte(logits), wte(selection), wpe] → tensor idx [0, 0, 1].
    let embed_tensor_idx = [0usize, 0, 1];
    let claims_p: Vec<_> = (0..3)
        .map(|i| {
            let wc = &out.embed_claims[i];
            (layout_e.block_claim(embed_tensor_idx[i], &wc.point), wc.value)
        })
        .collect();
    let mut doms_p = Doms::new(layer_dom_base(252));
    let mut doms_v = Doms::new(layer_dom_base(252));
    let dom_s0 = doms_p.take(1);
    let dom_s1 = doms_p.take(1);
    debug_assert_eq!((dom_s0, dom_s1), (doms_v.take(1), doms_v.take(1)));

    let to0 = Instant::now();
    let (mproof_e, _mt) =
        open_multi_zk(&e_flat, &pm_e, &claims_p, &mut stream, dom_s0, dom_s1, [0x45u8; 32], &mut txp);
    let open_embed_s = to0.elapsed().as_secs_f64();
    open_times.push(open_embed_s);
    let ob_e = mproof_e.bytes();
    opening_bytes_total += ob_e;

    let claims_v: Vec<_> = (0..3)
        .map(|i| {
            let (point, key) = &outv.embed_keys[i];
            (layout_e.block_claim(embed_tensor_idx[i], point), *key)
        })
        .collect();
    let tv1 = Instant::now();
    let ok_e = verify_multi_open(
        &com_e.root, &GPT2_FULL, &claims_v, &mproof_e, &mut vc, dom_s0, dom_s1, &mut txv,
    );
    let verify_embed_s = tv1.elapsed().as_secs_f64();
    pcs_all_ok &= ok_e;
    pcs_rows.push(PcsCommitmentRow {
        name: "embed".into(),
        commit_s: commit_embed_s,
        open_s: open_embed_s,
        verify_s: verify_embed_s,
        opening_bytes: ob_e,
        verified: ok_e,
    });
    drop((e_flat, pm_e, com_e));
    eprintln!(
        "  embed: commit {commit_embed_s:.2}s open {open_embed_s:.3}s verify {verify_embed_s:.3}s bytes {ob_e} ok={ok_e}"
    );

    let commit_total_s: f64 = commit_layers_s.iter().sum::<f64>() + commit_embed_s;
    let commit_layers_mean_s = commit_layers_s.iter().sum::<f64>() / commit_layers_s.len() as f64;
    let open_total_s: f64 = open_times.iter().sum();
    let open_per_commitment_mean_s = open_total_s / open_times.len() as f64;
    let verify_total_s: f64 = pcs_rows.iter().map(|r| r.verify_s).sum();

    // 51 committed-tensor claims total (48 layer + 2 wte + 1 wpe), per the
    // ledger's implementation-state note.
    let claims_prefill = out.weight_claims.len() + out.embed_claims.len();
    let (proj_prefill, proj_response) = pcs_cost_projection(claims_prefill);

    // --- final closures: ONE Π_Prod + ONE Π_ZeroBatch over the whole model ---
    // The real PCS opening + verify_multi_open already resolve every weight
    // claim (M9 seam) — no extra zero rows are pushed for claims here,
    // exactly `p4_report`'s pattern.
    eprintln!("closures: Π_Prod + Π_ZeroBatch ...");
    let tc0 = Instant::now();
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
    let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
    let t_closures_s = tc0.elapsed().as_secs_f64();
    prod.clear();
    zero.clear();
    kprod.clear();
    kzero.clear();
    let _ = t_closures_s;

    let accepted = ok_prod && ok_zero && pcs_all_ok;
    eprintln!(
        "  verdict: prod {ok_prod} | zero {ok_zero} | pcs {pcs_all_ok} → accepted = {accepted}"
    );

    // --- lookups vs budget (×12) -----------------------------------------------
    eprintln!("lookups vs P0 budget (×12) ...");
    let budget = budget_lookups(t as u64);
    let mut wit_by_table: std::collections::HashMap<&'static str, u64> = std::collections::HashMap::new();
    for lw in &wit.layers {
        for (name, n) in lw.lookup_counts() {
            *wit_by_table.entry(name).or_insert(0) += n as u64;
        }
    }
    let mut tables = Vec::new();
    let (mut tot_budget, mut tot_wit, mut tot_padded) = (0u64, 0u64, 0u64);
    for &(name, b) in budget.iter() {
        let b12 = b * L as u64;
        let wl = *wit_by_table.get(name).unwrap_or(&0);
        let padded: u64 = out.lookups.iter().filter(|il| il.table == name).map(|il| il.lookups).sum();
        tot_budget += b12;
        tot_wit += wl;
        tot_padded += padded;
        tables.push(TableRow {
            table: name,
            budget_lookups_model: b12,
            witness_lookups_model: wl,
            padded_lookups_model: padded,
            witness_vs_budget_pct: 100.0 * (wl as f64 - b12 as f64) / b12 as f64,
        });
    }
    let gate_counts = tables.iter().all(|r| r.witness_vs_budget_pct.abs() <= 20.0);

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
    // Dirty = TRACKED modifications only (untracked result JSONs and notes
    // are expected at run time and don't change the measured code).
    let git_dirty = std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(true);

    let bytes_total =
        out.bytes.boundary + out.bytes.mult + out.bytes.ln_vectors + out.bytes.attn_vectors + out.bytes.rounds_claims;
    // The Transcript byte ledger counts EVERY prover→verifier byte — the
    // correction streams above AND the PCS opening messages are already in
    // it, so it IS the total communication (adding the breakdown fields
    // again would double-count).
    let transcript_bytes_total = txp.total_bytes();
    let total_comm_response_bytes = transcript_bytes_total;
    let total_comm_response_projected_2x_pcs_bytes = transcript_bytes_total + opening_bytes_total;

    let report = Report {
        milestone: if quick { "P5-quick".into() } else { "P5".into() },
        date: date.clone(),
        git_sha: sha.clone(),
        git_dirty,
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads: rayon::current_num_threads(),
        t_tokens: t,
        accepted,
        golden: golden_report,
        tables,
        total_budget_lookups_model: tot_budget,
        total_witness_lookups_model: tot_wit,
        total_padded_lookups_model: tot_padded,
        gate_counts_within_20pct: gate_counts,
        embed_lookups_note: "embedding requant (13th table, T·d extra lookups/prefill) and the \
                             11 seam requants are NOT tracked in ModelOut.lookups (only the 12 \
                             per-layer LayerOut.lookups are collected) and are outside \
                             scripts/budget_p0.py's L*lookups_layer formula — pre-registered \
                             deviation, see docs/prototype-status.md 2026-07-06"
            .into(),
        emult_instances_total: out.ctr_instances.emult_equiv(),
        emult_instances_per_budget_lookup: out.ctr_instances.emult_equiv() / tot_budget as f64,
        emult_other_total: out.ctr_other.emult_equiv(),
        corr_sub_corrs: out.corr_counters.sub_corrs,
        corr_full_corrs: out.corr_counters.full_corrs,
        corr_domains: out.corr_counters.domains,
        t_witness_native_s,
        t_prove_model_abba_s,
        prove_over_native: t_prove_model_abba_s / t_witness_native_s,
        t_prove_model_record_s,
        t_verify_model_s,
        pcs: PcsReport {
            commitments: pcs_rows,
            commit_total_s,
            commit_layers_mean_s,
            commit_embed_s,
            open_total_s,
            open_per_commitment_mean_s,
            verify_total_s,
            opening_bytes_total,
            n_weight_claims: out.weight_claims.len(),
            n_embed_claims: out.embed_claims.len(),
            claims_prefill,
            projection_prefill_s: proj_prefill,
            projection_response_s: proj_response,
            p6_constraint: "P6: decode weight-GEMM claims are deferred and proved stacked at \
                            end-of-response (claims/response ≈ 2× claims/prefill), never \
                            per-token PCS claims; P5 runs e2e in committed-W mode by default"
                .into(),
        },
        bytes: BytesBreakdown {
            boundary: out.bytes.boundary,
            mult_vectors: out.bytes.mult,
            ln_vectors: out.bytes.ln_vectors,
            attn_vectors: out.bytes.attn_vectors,
            rounds_claims: out.bytes.rounds_claims,
            total: bytes_total,
        },
        transcript_bytes_total,
        total_comm_response_bytes,
        total_comm_response_projected_2x_pcs_bytes,
        peak_rss_gb: peak_rss_gb(),
    };

    assert!(accepted, "P5 sanity: honest full model + 13 PCS openings must verify");
    let label = if quick { "p5-quick" } else { "p5" };
    let path = format!(
        "{}/../../benchmarks/results/{label}-{date}-{sha}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}

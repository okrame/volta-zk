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
//! (`--quick`: prompt 16 + 8 decode, 2×4 curve, golden skipped.)

use serde::Serialize;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    band_model_witness, decode_step, forward_model, forward_model_tokens, load_model,
    BandModelWitness, Gpt2Model, KvCache, D, L, VOCAB,
};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcs::{
    commit, layout_gpt2_embed, layout_gpt2_layer, open_multi_zk, verify_multi_open, GPT2_FULL,
    P4_LAYER,
};
use volta_proto::block_proof::layer_dom_base;
use volta_proto::logup::Doms;
use volta_proto::model_proof::{prove_response, verify_response, ChunkPub, ChunkRef};
use volta_proto::{cattn_permuted, prod_batch_prover, prod_batch_verify, prove_model};

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
    verified: bool,
}

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    machine: String,
    threads: usize,
    t_prefill: usize,
    n_decode: usize,
    // --- verdicts -------------------------------------------------------------
    accepted: bool,
    golden_decode_checked: bool,
    golden_decode_match: Option<bool>,
    generated_tokens: Vec<u32>,
    // --- native baselines -------------------------------------------------------
    t_native_prefill_s: f64,
    /// KV-cached incremental decode, 50 steps (witness-free native anchor).
    t_native_decode_s: f64,
    native_decode_tokens_per_s: f64,
    // --- proving (run of record: prefill + ONE Q=50 chunk) ---------------------
    t_prove_prefill_only_s: f64,
    t_prove_response_s: f64,
    t_prove_decode_marginal_s: f64,
    rho_prefill: f64,
    /// (prove_response − prove_prefill) / native decode wall — the decode
    /// marginal ratio (CPU; the ≤2 target is GPU, P7).
    rho_decode: f64,
    verified_tokens_per_s: f64,
    t_verify_response_s: f64,
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
    /// PCS opening bytes are inside comm_response_bytes (transcript ledger).
    pcs_opening_bytes_total: u64,
    /// Public response outputs, NOT in the transcript: the band logits
    /// matrix (q×VOCAB×8) + the prefill last-row logits (VOCAB×8).
    public_logits_bytes: u64,
    total_response_download_bytes: u64,
    // --- PCS (stacked claims) -----------------------------------------------------
    pcs_commitments: Vec<PcsCommitmentRow>,
    pcs_commit_total_s: f64,
    pcs_open_total_s: f64,
    pcs_verify_total_s: f64,
    n_weight_claims: usize,
    n_embed_claims: usize,
    // --- counters -------------------------------------------------------------------
    emult_instances_total: f64,
    corr_sub_corrs: u64,
    corr_full_corrs: u64,
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

/// One full response session: prove + verify + PCS + closures. Returns
/// (accepted, prove_s, verify_s, comm_bytes, pcs rows/times, out counters,
/// per-chunk phase timings).
#[allow(clippy::type_complexity)]
struct SessionResult {
    accepted: bool,
    prove_s: f64,
    verify_s: f64,
    comm_bytes: u64,
    pcs_rows: Vec<PcsCommitmentRow>,
    pcs_opening_bytes: u64,
    n_weight_claims: usize,
    n_embed_claims: usize,
    emult_instances: f64,
    sub_corrs: u64,
    full_corrs: u64,
    chunk_p1_s: Vec<f64>,
    chunk_p2_s: Vec<f64>,
}

fn run_session(
    model: &Gpt2Model,
    wit: &volta_gpt2::ModelWitness,
    bands: &[&BandModelWitness],
    seq: &[u32],
    with_pcs: bool,
    seed: u8,
) -> SessionResult {
    let t = wit.t;
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut stream = CorrelationStream::new([seed; 32]);
    let mut vc = VerifierCtx::new([seed; 32], delta);
    let mut txp = Transcript::new([seed ^ 0x5A; 32]);
    let mut txv = Transcript::new([seed ^ 0x5A; 32]);

    let chunks_p: Vec<ChunkRef> = bands.iter().map(|b| ChunkRef { band: b, seq }).collect();
    let tp0 = Instant::now();
    let (proof, out, prod, zero) = prove_response(model, wit, &chunks_p, &mut stream, &mut txp);
    let prove_s = tp0.elapsed().as_secs_f64();

    let chunks_v: Vec<ChunkPub> = bands
        .iter()
        .map(|b| ChunkPub { q: b.q, logits: &b.logits, seq })
        .collect();
    let tv0 = Instant::now();
    let (outv, kprod, kzero) =
        verify_response(model, t, &wit.logits, &chunks_v, &proof, &mut vc, &mut txv)
            .expect("honest response must verify");
    let verify_s = tv0.elapsed().as_secs_f64();

    // --- PCS: 13 commitments, claims stacked per layer across phases -------
    let phases = 1 + bands.len();
    let mut pcs_rows = Vec::new();
    let mut pcs_opening_bytes = 0u64;
    let mut pcs_all_ok = true;
    if with_pcs {
        assert_eq!(out.weight_claims.len(), 4 * L * phases);
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
            let mut mask_seed = [0x44u8; 32];
            mask_seed[31] = l as u8;
            let to0 = Instant::now();
            let (mproof, _mt) = open_multi_zk(
                &w_flat, &pm, &claims_p, &mut stream, dom_s0, dom_s1, mask_seed, &mut txp,
            );
            let open_s = to0.elapsed().as_secs_f64();
            let ob = mproof.bytes();
            pcs_opening_bytes += ob;
            let claims_v: Vec<_> = idxs
                .iter()
                .map(|&i| {
                    let (point, key) = &outv.weight_keys[i];
                    (layout.block_claim(i % 4, point), *key)
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
                n_claims: idxs.len(),
                commit_s,
                open_s,
                verify_s,
                opening_bytes: ob,
                verified: ok,
            });
            drop((w_flat, pm, com));
            eprintln!(
                "  layer {l}: {} claims, commit {commit_s:.2}s open {open_s:.3}s ok={ok}",
                idxs.len()
            );
        }
        // Embedding commitment: 3 claims per phase, tensor idx [0, 0, 1].
        assert_eq!(out.embed_claims.len(), 3 * phases);
        let layout_e = layout_gpt2_embed();
        let e_flat = layout_e.place(&[&model.wte, &model.wpe]);
        let tc0 = Instant::now();
        let (com_e, pm_e) = commit(&e_flat, &GPT2_FULL, [0x52u8; 32]);
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
        let to0 = Instant::now();
        let (mproof_e, _mt) = open_multi_zk(
            &e_flat, &pm_e, &claims_p, &mut stream, dom_s0, dom_s1, [0x45u8; 32], &mut txp,
        );
        let open_s = to0.elapsed().as_secs_f64();
        let ob = mproof_e.bytes();
        pcs_opening_bytes += ob;
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
            &com_e.root, &GPT2_FULL, &claims_v, &mproof_e, &mut vc, dom_s0, dom_s1, &mut txv,
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
            verified: ok,
        });
        drop((e_flat, pm_e, com_e));
        eprintln!("  embed: {} claims, commit {commit_s:.2}s open {open_s:.3}s ok={ok}", 3 * phases);
    }

    // --- closures ------------------------------------------------------------
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
    let accepted = ok_prod && ok_zero && (!with_pcs || pcs_all_ok);

    SessionResult {
        accepted,
        prove_s,
        verify_s,
        comm_bytes: txp.total_bytes(),
        pcs_rows,
        pcs_opening_bytes,
        n_weight_claims: out.weight_claims.len(),
        n_embed_claims: out.embed_claims.len(),
        emult_instances: out.ctr_instances.emult_equiv(),
        sub_corrs: out.corr_counters.sub_corrs,
        full_corrs: out.corr_counters.full_corrs,
        chunk_p1_s: out.chunk_p1_s,
        chunk_p2_s: out.chunk_p2_s,
    }
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let (t0, n_gen, curve_chunk) = if quick { (16usize, 8usize, 4usize) } else { (100, 50, 10) };

    let dir = weights_dir();
    if !dir.join("gpt2s-q.bin").exists() {
        eprintln!("p6_report: frozen artifact not found; run scripts/export_gpt2.py first");
        std::process::exit(1);
    }
    eprintln!("loading artifact + prefill witness at t0={t0} ...");
    let model = load_model(&dir).expect("load_model");
    let tn0 = Instant::now();
    let wit0 = forward_model(&model, t0);
    let t_native_prefill_s = tn0.elapsed().as_secs_f64();

    // --- native decode baseline (KV-cached, witness-free) --------------------
    eprintln!("native decode baseline: {n_gen} KV-cached steps ...");
    let kv: Vec<(&[i16], &[i16])> =
        wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
    let mut cache = KvCache::from_prefill(&kv, t0);
    let td0 = Instant::now();
    let mut gen: Vec<u32> = Vec::with_capacity(n_gen);
    let mut next = volta_gpt2::argmax(&wit0.logits);
    for i in 0..n_gen {
        gen.push(next);
        let lg = decode_step(&model, &mut cache, next, t0 + i);
        next = volta_gpt2::argmax(&lg);
    }
    let t_native_decode_s = td0.elapsed().as_secs_f64();
    eprintln!(
        "  {n_gen} tokens in {t_native_decode_s:.3} s ({:.1} tok/s): {gen:?}",
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
    let full = forward_model_tokens(&model, &seq);
    let band50 = band_model_witness(&model, &full, t0);
    assert_eq!(band50.q, n_gen);

    // --- prefill-only prove (decode marginal baseline) ---------------------------
    eprintln!("prefill-only prove_model (marginal baseline) ...");
    let tpp0 = Instant::now();
    {
        let mut stream = CorrelationStream::new([0x33u8; 32]);
        let mut tx = Transcript::new([0x34u8; 32]);
        let _ = prove_model(&model, &wit0, &mut stream, &mut tx);
    }
    let t_prove_prefill_only_s = tpp0.elapsed().as_secs_f64();
    // Prefill-only comm for the marginal (fresh ledger, no PCS).
    let comm_prefill_bytes = {
        let mut stream = CorrelationStream::new([0x35u8; 32]);
        let mut tx = Transcript::new([0x36u8; 32]);
        let _ = prove_model(&model, &wit0, &mut stream, &mut tx);
        tx.total_bytes()
    };

    // --- run of record: prefill + ONE Q=n_gen chunk + real PCS -------------------
    eprintln!("run of record: prove_response (prefill + Q={n_gen} chunk) + PCS ...");
    let rec = run_session(&model, &wit0, &[&band50], &seq, true, 0x21);
    eprintln!(
        "  prove {:.2}s verify {:.2}s comm {:.1} MB accepted={}",
        rec.prove_s,
        rec.verify_s,
        rec.comm_bytes as f64 / 1e6,
        rec.accepted
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
    let chk = run_session(&model, &wit0, &band_refs, &seq, false, 0x22);
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

    // --- report --------------------------------------------------------------------
    let public_logits_bytes = ((n_gen * VOCAB + VOCAB) * 8) as u64;
    let t_prove_decode_marginal_s = rec.prove_s - t_prove_prefill_only_s;
    // Transcript-only marginal: the run-of-record ledger minus its PCS
    // opening bytes (the prefill-only measurement has no PCS), minus the
    // prefill transcript.
    let comm_decode_marginal = rec
        .comm_bytes
        .saturating_sub(rec.pcs_opening_bytes)
        .saturating_sub(comm_prefill_bytes);
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
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(true);

    let accepted = rec.accepted && chk.accepted;
    let report = Report {
        milestone: if quick { "P6-quick".into() } else { "P6".into() },
        date: date.clone(),
        git_sha: sha.clone(),
        git_dirty,
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads: rayon::current_num_threads(),
        t_prefill: t0,
        n_decode: n_gen,
        accepted,
        golden_decode_checked: golden_checked,
        golden_decode_match: golden_match,
        generated_tokens: gen.clone(),
        t_native_prefill_s,
        t_native_decode_s,
        native_decode_tokens_per_s: n_gen as f64 / t_native_decode_s,
        t_prove_prefill_only_s,
        t_prove_response_s: rec.prove_s,
        t_prove_decode_marginal_s,
        rho_prefill: t_prove_prefill_only_s / t_native_prefill_s,
        rho_decode: t_prove_decode_marginal_s / t_native_decode_s,
        verified_tokens_per_s: n_gen as f64 / rec.prove_s,
        t_verify_response_s: rec.verify_s,
        chunk_curve,
        curve_last_over_first,
        gate_flat_cost_per_token: gate_flat,
        t_prove_response_chunked_s: chk.prove_s,
        chunked_accepted: chk.accepted,
        comm_prefill_bytes,
        comm_response_bytes: rec.comm_bytes,
        comm_decode_marginal_bytes: comm_decode_marginal,
        comm_decode_bytes_per_token: comm_decode_marginal / n_gen as u64,
        pcs_opening_bytes_total: rec.pcs_opening_bytes,
        public_logits_bytes,
        total_response_download_bytes: rec.comm_bytes + public_logits_bytes,
        pcs_commitments: rec.pcs_rows,
        pcs_commit_total_s: 0.0,
        pcs_open_total_s: 0.0,
        pcs_verify_total_s: 0.0,
        n_weight_claims: rec.n_weight_claims,
        n_embed_claims: rec.n_embed_claims,
        emult_instances_total: rec.emult_instances,
        corr_sub_corrs: rec.sub_corrs,
        corr_full_corrs: rec.full_corrs,
        peak_rss_gb: peak_rss_gb(),
    };
    let mut report = report;
    report.pcs_commit_total_s = report.pcs_commitments.iter().map(|r| r.commit_s).sum();
    report.pcs_open_total_s = report.pcs_commitments.iter().map(|r| r.open_s).sum();
    report.pcs_verify_total_s = report.pcs_commitments.iter().map(|r| r.verify_s).sum();

    assert!(accepted, "P6 sanity: honest response (both sessions) must verify");
    assert!(gate_flat, "P6 gate: per-token cost must stay ~flat as the cache grows");
    let label = if quick { "p6-quick" } else { "p6" };
    let path = format!(
        "{}/../../benchmarks/results/{label}-{date}-{sha}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}

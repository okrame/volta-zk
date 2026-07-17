//! P4 (PCS side): one GPT-2 layer's four weight tensors in ONE Ligero
//! commitment (`P4_LAYER`, 2^24 coefficients), claims at WeightClaimP-style
//! points (r_j ‖ r_l) mapped to aligned BlockClaims via `LayerWeightLayout`,
//! opened with the row-local multi-eval opening and verified into MAC keys.
//!
//! Both the 1/16-scale version (with an extra layout/MLE cross-check) and
//! the full 2^24 version run by default; the full one stays well under the
//! runtime budget even in the debug profile (~5 s).

use std::time::Instant;
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{CorrIndex, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::{
    commit, layout_gpt2_layer, open_multi_zk, verify_multi_open, LayerWeightLayout, LigeroParams,
    P4_LAYER,
};
use volta_proto::mle::{eq_vec, eval_mle};

fn dom(tensor: u8, row: u32) -> u64 {
    CorrIndex { session: 4, layer: 0, head: 0, tensor, row }.domain()
}
const DOM_W_CLAIM: u8 = 0xE0;
const DOM_S: u8 = 0xE2;

fn rand_w(seed: u64, len: usize) -> Vec<i16> {
    (0..len)
        .map(|i| {
            let x = (i as u64).wrapping_add(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            (x >> 40) as i16
        })
        .collect()
}

fn embed(w: &[i16]) -> Vec<Fp2> {
    w.iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect()
}

/// Padded-MLE evaluation of a raw row-major k×n tensor at (r_j ‖ r_l):
/// Σ_{l<k, j<n} W[l·n+j]·eq(bits j, r_j)·eq(bits l, r_l). Zero padding makes
/// this equal the placed block's MLE at the same point.
fn padded_eval(t: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
    let nb = n.next_power_of_two().trailing_zeros() as usize;
    let eq_j = eq_vec(&point[..nb]);
    let eq_l = eq_vec(&point[nb..]);
    let mut acc = Fp2::ZERO;
    for l in 0..k {
        let mut row = Fp2::ZERO;
        for j in 0..n {
            row += eq_j[j].mul_base(Fp::from_i64(t[l * n + j] as i64));
        }
        acc += eq_l[l] * row;
    }
    acc
}

/// Full pipeline for one layer layout: place → commit → 4 claims (one per
/// tensor) at random (r_j ‖ r_l) points → open_multi_zk → verify (honest
/// passes, tampered claim value fails). `cross_check_mle` additionally
/// asserts padded_eval == block-slice MLE (cheap only at small scale).
fn run_layer(
    params: &LigeroParams,
    layout: &LayerWeightLayout,
    seed_tag: u8,
    cross_check_mle: bool,
) {
    assert_eq!(layout.total_len, 1 << params.n_vars(), "layout does not fill the commitment");
    let shapes: Vec<(usize, usize)> = layout.tensors.iter().map(|t| (t.k, t.n)).collect();
    let tensors: Vec<Vec<i16>> = (0..4)
        .map(|g| rand_w(seed_tag as u64 * 100 + g as u64, shapes[g].0 * shapes[g].1))
        .collect();

    let t0 = Instant::now();
    let w = layout.place([&tensors[0], &tensors[1], &tensors[2], &tensors[3]]);
    let t_place = t0.elapsed().as_secs_f64();

    let seed = [seed_tag; 32];
    let tx_seed = [0xB4u8; 32];
    let delta = Fp2::new(Fp::new(0xD31C), Fp::new(79));

    let t1 = Instant::now();
    let (com, pm) = commit(&w, params, [0x71u8 ^ seed_tag; 32]);
    let t_commit = t1.elapsed().as_secs_f64();

    // Prover: 4 authenticated claims, one per tensor, at random points.
    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let mut claims_p = Vec::new();
    let mut corr_vs = Vec::new();
    for g in 0..4usize {
        let slot = &layout.tensors[g];
        let mut src = FpStream::domain_separated([0x9Au8; 32], (seed_tag as u64) << 8 | g as u64);
        let point: Vec<Fp2> = (0..slot.point_len()).map(|_| src.next_fp2()).collect();
        let v = padded_eval(&tensors[g], slot.k, slot.n, &point);
        if cross_check_mle {
            // Layout semantics: block MLE at (r_j ‖ r_l) == padded-tensor eval.
            let blk = embed(&w[slot.offset..slot.offset + slot.block_len]);
            assert_eq!(v, eval_mle(&blk, &point), "tensor {g} layout/eval mismatch");
        }
        let fc = ps.draw_fulls(dom(DOM_W_CLAIM, g as u32), 1)[0];
        corr_vs.push(v - fc.x);
        tx.append("w_claim_correction", 16);
        claims_p.push((layout.block_claim(g, &point), ProverAuthed { x: v, m: fc.m }));
    }
    assert_eq!(claims_p.len(), 4);

    let t2 = Instant::now();
    let (oproof, otm) = open_multi_zk(
        &w,
        &pm,
        &claims_p,
        &mut ps,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        [0x72u8 ^ seed_tag; 32],
        &mut tx,
    );
    let t_open = t2.elapsed().as_secs_f64();
    assert_eq!(oproof.u_gs.len(), 4, "n_claims must be 4");
    let bd = oproof.byte_breakdown();
    assert_eq!(bd.total, oproof.bytes());
    assert_eq!(oproof.cached_query_marginal_bytes(), bd.cached_query_marginal_bytes);
    assert_eq!(bd.mask_root, 32);
    assert_eq!(bd.u_vectors, 16 * params.msg_len() as u64 * 5);
    assert_eq!(bd.corr_ss, 16 * 4);
    assert_eq!(bd.zero_batch, 32);
    assert_eq!(bd.column_indices, 4 * params.n_queries as u64);
    assert_eq!(bd.data_columns, 8 * params.rows() as u64 * params.n_queries as u64);
    assert_eq!(bd.mask_columns, 16 * 5 * params.n_queries as u64);
    assert_eq!(bd.commitment_merkle_paths, 32 * params.code_bits as u64 * params.n_queries as u64);
    assert_eq!(bd.mask_merkle_paths, 32 * params.code_bits as u64 * params.n_queries as u64);
    assert_eq!(
        bd.cached_query_marginal_bytes,
        bd.total - bd.data_columns - bd.commitment_merkle_paths
    );

    // Verifier (honest): all 4 claim keys bound to C_W.
    let claim_keys = |ctx: &mut VerifierCtx| -> Vec<VerifierKey> {
        (0..4)
            .map(|g| VerifierKey {
                k: ctx.expand_full_keys(dom(DOM_W_CLAIM, g as u32), 1)[0] + delta * corr_vs[g],
            })
            .collect()
    };
    let t3 = Instant::now();
    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let keys = claim_keys(&mut ctx);
    let claims_v: Vec<_> = claims_p.iter().zip(&keys).map(|((c, _), &k)| (c.clone(), k)).collect();
    assert!(verify_multi_open(
        &com.root,
        params,
        &claims_v,
        &oproof,
        &mut ctx,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut txv,
    ));
    let t_verify = t3.elapsed().as_secs_f64();

    // Tampered claim value (claim 2 shifted by 1 via its correction): reject.
    let mut ctx2 = VerifierCtx::new(seed, delta);
    let mut txv2 = Transcript::new(tx_seed);
    let mut keys2 = claim_keys(&mut ctx2);
    keys2[2] = VerifierKey { k: keys2[2].k + delta * Fp2::ONE };
    let claims_v2: Vec<_> =
        claims_p.iter().zip(&keys2).map(|((c, _), &k)| (c.clone(), k)).collect();
    assert!(!verify_multi_open(
        &com.root,
        params,
        &claims_v2,
        &oproof,
        &mut ctx2,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut txv2,
    ));

    println!(
        "p4_layer [{}v]: place {:.3}s commit {:.3}s open {:.3}s (masks {:.3} global {:.3} \
         blocks {:.3} ip/zb {:.3} cols {:.3}) verify {:.3}s proof {} B",
        params.n_vars(),
        t_place,
        t_commit,
        t_open,
        otm.t_masks_s,
        otm.t_global_pass_s,
        otm.t_block_passes_s,
        otm.t_ip_zb_s,
        otm.t_columns_s,
        t_verify,
        oproof.bytes()
    );
}

/// 1/16-scale shapes with the same layout logic: blocks 2^14, 2^12, 2^14,
/// 2^14 in a 2^16 commitment (offsets 0, 3·2^14, 2^14, 2^15 — same
/// largest-first placement rule as the full layer).
const SMALL_P4: LigeroParams =
    LigeroParams { rows: 1 << 6, col_bits: 10, pad: 64, code_bits: 11, n_queries: 32 };

#[test]
fn p4_layer_small_e2e() {
    let layout = LayerWeightLayout::for_shapes([(48, 144), (48, 48), (48, 192), (192, 48)]);
    assert_eq!(layout.tensors.map(|t| t.offset), [0, 3 << 14, 1 << 14, 1 << 15]);
    run_layer(&SMALL_P4, &layout, 0x11, true);
}

/// Full-scale: real GPT-2 layer shapes, 2^24-coefficient commitment with
/// `P4_LAYER`. Runs by default — measured ~5 s debug / 0.44 s release,
/// ~317 MB peak RSS (commit dominates: 1024-row NTT + Merkle over 2^15
/// columns). `--nocapture` prints the timing breakdown.
#[test]
fn p4_layer_full_e2e() {
    let layout = layout_gpt2_layer();
    run_layer(&P4_LAYER, &layout, 0x24, false);
}

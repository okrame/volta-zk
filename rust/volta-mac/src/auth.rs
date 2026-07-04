//! Π_Auth: authenticate quantized tensors against subfield correlations (M5).
//!
//! Prover: `δ_i = x_i − r_i ∈ F_p` (8 B each — the F_p-typed correction of the
//! ledger deviation 2026-07-03), tag `m_{x_i} = m_{r_i}` (free).
//! Verifier: `k_{x_i} = k_{r_i} + Δ·δ_i` (2 base mults via `mul_base`).
//! The δ format is byte-identical to `volta_gpt2::gemm_requant_auth`'s output,
//! so the fused GEMM epilogue *is* the prover half of Π_Auth for GEMM outputs.

use crate::authed::{ProverSubAuthed, VerifierKey};
use crate::corr::{CorrelationStream, VerifierCtx};
use crate::transcript::Transcript;
use volta_field::Fp;

/// Prover half: authenticate `xs` at domain `dom`, emitting corrections.
pub fn auth_prover(
    stream: &mut CorrelationStream,
    dom: u64,
    xs: &[i16],
    tx: &mut Transcript,
) -> (Vec<u64>, Vec<ProverSubAuthed>) {
    let subs = stream.draw_subs(dom, xs.len());
    let mut corr = Vec::with_capacity(xs.len());
    let mut authed = Vec::with_capacity(xs.len());
    for (&xq, s) in xs.iter().zip(&subs) {
        let x = Fp::from_i64(xq as i64);
        corr.push((x - s.r).value());
        authed.push(ProverSubAuthed { x, m: s.m });
    }
    tx.append("auth_corrections", 8 * corr.len() as u64);
    (corr, authed)
}

/// Verifier half: keys for a correction batch at `dom`.
pub fn auth_verifier(ctx: &mut VerifierCtx, dom: u64, corr: &[u64]) -> Vec<VerifierKey> {
    let delta = ctx.delta;
    ctx.expand_sub_keys(dom, corr.len())
        .into_iter()
        .zip(corr)
        .map(|(k_r, &c)| VerifierKey { k: k_r + delta.mul_base(Fp::new(c)) })
        .collect()
}

/// Verifier half for a fused-GEMM epilogue output (P1 seam): the epilogue
/// wrote one per-row stream at `(tensor_tag << 32) | row`, `n` corrections per
/// row, mask-first layout with lazy prover tags.
pub fn auth_verifier_from_epilogue(
    ctx: &mut VerifierCtx,
    tensor_tag: u32,
    m: usize,
    n: usize,
    corr: &[u64],
) -> Vec<VerifierKey> {
    assert_eq!(corr.len(), m * n);
    let mut keys = Vec::with_capacity(m * n);
    for row in 0..m {
        let dom = ((tensor_tag as u64) << 32) | row as u64;
        keys.extend(auth_verifier(ctx, dom, &corr[row * n..(row + 1) * n]));
    }
    keys
}

/// Prover tags for a fused-GEMM epilogue output, expanded lazily at opening
/// time (cost charged to P3 per the ledger deviation).
pub fn prover_tags_from_epilogue(
    stream: &mut CorrelationStream,
    tensor_tag: u32,
    out: &[i16],
    m: usize,
    n: usize,
) -> Vec<ProverSubAuthed> {
    assert_eq!(out.len(), m * n);
    let mut authed = Vec::with_capacity(m * n);
    for row in 0..m {
        let dom = ((tensor_tag as u64) << 32) | row as u64;
        // The epilogue consumed the mask stream; account for it, then expand tags.
        let _masks = stream.draw_sub_masks(dom, n);
        let tags = stream.draw_sub_tags(dom, n);
        for (j, mt) in tags.into_iter().enumerate() {
            authed.push(ProverSubAuthed { x: Fp::from_i64(out[row * n + j] as i64), m: mt });
        }
    }
    authed
}

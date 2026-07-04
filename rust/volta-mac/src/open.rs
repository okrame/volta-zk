//! Π_ZeroOpen and Π_ZeroBatch (M2).
//!
//! ZeroOpen: for an authenticated claim with `x = 0`, the prover reveals the
//! tag `m` (16 B); the verifier accepts iff `k == m` (honest: `k = m + Δ·0`).
//! Soundness: a wrong claim passes for exactly one `Δ` (`zeroOpen_sound`).
//!
//! ZeroBatch: T claims are RLC'd with a verifier challenge χ and masked with a
//! *fresh full-field* authenticated zero (mask value re-centred to 0 via a
//! 16 B correction) so the opened tag is uniform (M2's perfect-ZK simulator
//! requires the mask to be full-field and fresh — enforced by the type
//! `FullCorr` and the one-time-use ledger).

use crate::authed::{ProverAuthed, VerifierKey};
use crate::corr::{CorrelationStream, FullCorr, VerifierCtx};
use crate::transcript::Transcript;
use volta_field::Fp2;

/// Prover: open a zero claim by revealing its tag.
pub fn zero_open_prover(y: &ProverAuthed, tx: &mut Transcript) -> Fp2 {
    debug_assert_eq!(y.x, Fp2::ZERO, "ZeroOpen on a nonzero claim");
    tx.append("zero_open_tag", 16);
    y.m
}

/// Verifier: accept iff `k == m`.
pub fn zero_open_verify(key: VerifierKey, m: Fp2) -> bool {
    key.k == m
}

/// Prover: convert a fresh full correlation into an authenticated zero with a
/// uniform tag, emitting the 16 B re-centring correction `c = 0 − x`.
pub fn fresh_zero_mask(corr: FullCorr, tx: &mut Transcript) -> (ProverAuthed, Fp2) {
    let c = Fp2::ZERO - corr.x;
    tx.append("mask_correction", 16);
    (ProverAuthed { x: Fp2::ZERO, m: corr.m }, c)
}

/// Verifier: key of the re-centred mask, `k' = k + Δ·c`.
pub fn zero_mask_key(ctx: &VerifierCtx, k_full: Fp2, c: Fp2) -> VerifierKey {
    VerifierKey { k: k_full + ctx.delta * c }
}

/// Prover: batched zero opening. `chi` is the verifier's RLC challenge, drawn
/// AFTER all claims are fixed. Returns the single opened tag
/// `m_z = Σ χ^{j+1}·m_j + m_mask`.
pub fn zero_batch_prover(
    ys: &[ProverAuthed],
    mask: &ProverAuthed,
    chi: Fp2,
    tx: &mut Transcript,
) -> Fp2 {
    let mut z = *mask;
    let mut w = Fp2::ONE;
    for y in ys {
        debug_assert_eq!(y.x, Fp2::ZERO, "ZeroBatch on a nonzero claim");
        w = w * chi;
        z = z.add(y.scale(w));
    }
    tx.append("zero_batch_tag", 16);
    z.m
}

/// Verifier: accept iff `Σ χ^{j+1}·k_j + k_mask == m_z`.
pub fn zero_batch_verify(keys: &[VerifierKey], k_mask: VerifierKey, chi: Fp2, m_z: Fp2) -> bool {
    let mut acc = k_mask.k;
    let mut w = Fp2::ONE;
    for key in keys {
        w = w * chi;
        acc += key.k * w;
    }
    acc == m_z
}

/// Convenience: run the full masked ZeroBatch exchange in order (claims fixed
/// → mask correction sent → χ drawn → tag opened) and return the verdict plus
/// the pieces a caller needs for accounting.
pub fn zero_batch_exchange(
    ys: &[ProverAuthed],
    keys: &[VerifierKey],
    p_stream: &mut CorrelationStream,
    v_ctx: &mut VerifierCtx,
    mask_dom: u64,
    tx: &mut Transcript,
) -> bool {
    assert_eq!(ys.len(), keys.len());
    let corr = p_stream.draw_fulls(mask_dom, 1)[0];
    let k_full = v_ctx.expand_full_keys(mask_dom, 1)[0];
    let (mask, c) = fresh_zero_mask(corr, tx);
    let k_mask = zero_mask_key(v_ctx, k_full, c);
    let chi = tx.challenge_fp2();
    let m_z = zero_batch_prover(ys, &mask, chi, tx);
    zero_batch_verify(keys, k_mask, chi, m_z)
}

//! T1 multi-point -> single-point boundary-claim reduction.
//!
//! Two already-authenticated evaluations of one multilinear tensor are
//! affine-compressed only after a fresh verifier challenge.  The resulting
//! eq-sumcheck terminates in one freshly authenticated tensor evaluation;
//! its public equality coefficient closes with one linear zero row.  This is
//! the direct Rust mirror of M11a--c in `BoundaryThinningSound.lean`.

use crate::block_proof::{BlockCtxP, BlockCtxV};
use crate::mle::eval_mle;
use crate::mle::{eq_points, eq_vec};
use crate::sumcheck_blind::{
    blind_prove_resident_labeled, blind_prove_with_finals_labeled, blind_verify, BlindSumcheckProof,
};
use crate::thaler::pad_bits;
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceSlice, Fp2Repr, MatrixFoldAxis};
use volta_field::{Fp, Fp2};
use volta_mac::{ProverAuthed, VerifierKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EqReductionProof {
    pub(crate) sumcheck: BlindSumcheckProof,
    /// Fresh full-field transfer of the unique terminal `S(rho)` claim.
    pub(crate) terminal_corr: Fp2,
}

/// An authenticated evaluation routed between T1 relations. Unlike a GEMM
/// `WireOut`, it may be derived linearly and therefore has no standalone
/// correction field.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BoundaryClaimP {
    pub(crate) point: Vec<Fp2>,
    pub(crate) value: ProverAuthed,
}

pub(crate) struct BoundaryClaimK {
    pub(crate) point: Vec<Fp2>,
    pub(crate) key: VerifierKey,
}

#[derive(Clone, Copy)]
struct EqReductionDoms {
    rounds: u64,
    terminal: u64,
}

impl EqReductionDoms {
    fn alloc_p(cx: &mut BlockCtxP<'_>, n_vars: usize) -> Self {
        Self { rounds: cx.doms.take(n_vars as u64), terminal: cx.doms.take(1) }
    }

    fn alloc_v(cx: &mut BlockCtxV<'_>, n_vars: usize) -> Self {
        Self { rounds: cx.doms.take(n_vars as u64), terminal: cx.doms.take(1) }
    }
}

/// Canonical column-LSB, row-MSB zero-padded matrix table.
pub(crate) fn lift_matrix_i16(values: &[i16], rows: usize, cols: usize) -> Vec<Fp2> {
    assert_eq!(values.len(), rows * cols);
    let row_pad = rows.next_power_of_two();
    let col_pad = cols.next_power_of_two();
    let mut table = vec![Fp2::ZERO; row_pad * col_pad];
    for row in 0..rows {
        for col in 0..cols {
            table[row * col_pad + col] =
                Fp2::from_base(Fp::from_i64(values[row * cols + col] as i64));
        }
    }
    table
}

/// Freshly authenticate one existing matrix evaluation for transport into a
/// non-empty LogUp leaf auxiliary-claim list.  This is the 16-byte q bridge
/// preregistered by T1; the evaluation itself is never opened in clear.
pub(crate) fn prove_matrix_eval_claim_i16(
    values: &[i16],
    rows: usize,
    cols: usize,
    point: &[Fp2],
    cx: &mut BlockCtxP<'_>,
) -> (Fp2, BoundaryClaimP) {
    let n_vars = pad_bits(rows) + pad_bits(cols);
    assert_eq!(point.len(), n_vars);
    let table = lift_matrix_i16(values, rows, cols);
    let value = eval_mle(&table, point);
    cx.ctr_other.fp2_mults += (table.len() - 1) as u64;
    prove_matrix_eval_value(value, point, cx)
}

/// Resident twin: the padded matrix MLE stays on device and only its scalar
/// crosses D2H, matching the existing resident boundary-opening pattern.
pub(crate) fn prove_matrix_eval_claim_resident(
    values: DeviceSlice<'_, i16>,
    rows: usize,
    cols: usize,
    point: &[Fp2],
    cx: &mut BlockCtxP<'_>,
) -> Result<(Fp2, BoundaryClaimP), AccelError> {
    let n_vars = pad_bits(rows) + pad_bits(cols);
    if point.len() != n_vars || values.len() < rows.saturating_mul(cols) {
        return Err(AccelError::InvalidInput("T1 resident q-bridge geometry mismatch"));
    }
    let value = cx
        .backend
        .as_deref_mut()
        .ok_or(AccelError::InvalidInput("T1 resident q bridge requires a backend"))?
        .matrix_mle_eval_device(values, rows, cols, point)?;
    cx.ctr_other.fp2_mults += ((1usize << n_vars) - 1) as u64;
    Ok(prove_matrix_eval_value(value, point, cx))
}

fn prove_matrix_eval_value(
    value: Fp2,
    point: &[Fp2],
    cx: &mut BlockCtxP<'_>,
) -> (Fp2, BoundaryClaimP) {
    let domain = cx.doms.take(1);
    let mask = cx.stream.draw_fulls(domain, 1)[0];
    let correction = value - mask.x;
    cx.tx.append("t1_q_bridge_correction", 16);
    (
        correction,
        BoundaryClaimP { point: point.to_vec(), value: ProverAuthed { x: value, m: mask.m } },
    )
}

pub(crate) fn verify_matrix_eval_claim(
    point: &[Fp2],
    correction: Fp2,
    cx: &mut BlockCtxV<'_>,
) -> BoundaryClaimK {
    let domain = cx.doms.take(1);
    let key = VerifierKey { k: cx.ctx.expand_full_keys(domain, 1)[0] + cx.ctx.delta * correction };
    cx.tx.append("t1_q_bridge_correction", 16);
    BoundaryClaimK { point: point.to_vec(), key }
}

/// Reduce two fixed downstream claims on the same `rows x cols` tensor.
/// Both claims and their public routing metadata are sealed before `beta`.
pub(crate) fn prove_eq_reduction_i16(
    values: &[i16],
    rows: usize,
    cols: usize,
    first: &BoundaryClaimP,
    second: &BoundaryClaimP,
    cx: &mut BlockCtxP<'_>,
) -> (EqReductionProof, BoundaryClaimP) {
    let n_vars = pad_bits(rows) + pad_bits(cols);
    assert_eq!(first.point.len(), n_vars);
    assert_eq!(second.point.len(), n_vars);

    // Zero-byte marker models the interactive boundary: the two prior
    // authenticated claims and the public site identity are fixed now.
    cx.tx.append("t1_eq_claim_pair", 0);
    let beta = cx.tx.challenge_fp2();
    let claim0 = first.value.add(second.value.scale(beta));

    let tensor = lift_matrix_i16(values, rows, cols);
    let eq_first = eq_vec(&first.point);
    let eq_second = eq_vec(&second.point);
    let coefficient: Vec<Fp2> =
        eq_first.into_iter().zip(eq_second).map(|(a, b)| a + beta * b).collect();
    debug_assert_eq!(tensor.len(), coefficient.len());
    debug_assert_eq!(
        claim0.x,
        tensor.iter().zip(&coefficient).fold(Fp2::ZERO, |sum, (&a, &b)| sum + a * b),
        "T1 reducer received claims inconsistent with its tensor"
    );

    let doms = EqReductionDoms::alloc_p(cx, n_vars);
    let (sumcheck, point, final_claim, tensor_final, coefficient_final) =
        blind_prove_with_finals_labeled(
            tensor,
            coefficient,
            claim0,
            cx.stream,
            doms.rounds,
            cx.tx,
            "t1_eq_round_corrections",
        );

    let terminal_mask = cx.stream.draw_fulls(doms.terminal, 1)[0];
    let terminal_corr = tensor_final - terminal_mask.x;
    cx.tx.append("t1_eq_terminal_correction", 16);
    let terminal = ProverAuthed { x: tensor_final, m: terminal_mask.m };
    let close = terminal.scale(coefficient_final).sub(final_claim);
    debug_assert_eq!(
        coefficient_final,
        eq_points(&first.point, &point) + beta * eq_points(&second.point, &point)
    );
    debug_assert_eq!(close.x, Fp2::ZERO, "T1 reducer terminal relation failed");
    cx.zero.push(close);

    // Exact preregistered charged convention: equality tables + affine
    // combination + product-round bodies, excluding the two fold streams.
    let n = 1u64 << n_vars;
    cx.ctr_other.fp2_mults += 5 * n - 4;

    (EqReductionProof { sumcheck, terminal_corr }, BoundaryClaimP { point, value: terminal })
}

fn lift_matrix_i16_resident(
    values: DeviceSlice<'_, i16>,
    rows: usize,
    cols: usize,
    backend: &mut Backend,
) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
    if values.len() < rows.saturating_mul(cols) {
        return Err(AccelError::InvalidInput("T1 resident reducer tensor geometry mismatch"));
    }
    // Reuse the canonical lookup-column padder: its first column is exactly
    // the column-LSB, row-MSB zero-padded matrix table required by M11.
    let columns =
        backend.pair_lookup_columns_base_device(values, values, rows, cols, Fp::ZERO, Fp::ZERO)?;
    let table = backend.base_to_fp2_broadcast_device(columns.column(0)?, 1);
    let free = backend.free_lookup_columns(columns);
    match (table, free) {
        (Ok(table), Ok(())) => Ok(table),
        (Ok(table), Err(error)) => {
            let _ = backend.free_device(table);
            Err(error)
        }
        (Err(error), _) => Err(error),
    }
}

fn affine_eq_table_resident(
    first: &[Fp2],
    second: &[Fp2],
    beta: Fp2,
    backend: &mut Backend,
) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
    if first.len() != second.len() {
        return Err(AccelError::InvalidInput("T1 resident reducer point mismatch"));
    }
    let mut points = Vec::with_capacity(2 * first.len());
    points.extend(first.iter().copied().map(Fp2Repr::from));
    points.extend(second.iter().copied().map(Fp2Repr::from));
    let device_points = backend.upload_new_device(&points)?;
    let eq_rows = backend.logup_eq_rows_device(Some(&device_points), 2, first.len());
    let free_points = backend.free_device(device_points);
    let eq_rows = match (eq_rows, free_points) {
        (Ok(rows), Ok(())) => rows,
        (Ok(rows), Err(error)) => {
            let _ = backend.free_device(rows);
            return Err(error);
        }
        (Err(error), _) => return Err(error),
    };

    let weights = [Fp2Repr::from(Fp2::ONE), Fp2Repr::from(beta)];
    let device_weights = match backend.upload_new_device(&weights) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(eq_rows);
            return Err(error);
        }
    };
    let width = 1usize << first.len();
    let combined = backend.matrix_fold_device(
        DeviceSlice::new(&eq_rows, 0, 2 * width)?,
        DeviceSlice::new(&device_weights, 0, 2)?,
        2,
        width,
        MatrixFoldAxis::Rows,
    );
    let free_rows = backend.free_device(eq_rows).err();
    let free_weights = backend.free_device(device_weights).err();
    match (combined, free_rows.or(free_weights)) {
        (Ok(value), None) => Ok(value),
        (Ok(value), Some(error)) => {
            let _ = backend.free_device(value);
            Err(error)
        }
        (Err(error), _) => Err(error),
    }
}

/// Device-resident M11 reducer. Only transcript-sized points/coefficients and
/// the final two scalars cross the PCIe boundary; the `rows x cols` witness
/// table and every sumcheck fold remain resident.
pub(crate) fn prove_eq_reduction_resident(
    values: DeviceSlice<'_, i16>,
    rows: usize,
    cols: usize,
    first: &BoundaryClaimP,
    second: &BoundaryClaimP,
    cx: &mut BlockCtxP<'_>,
) -> Result<(EqReductionProof, BoundaryClaimP), AccelError> {
    let n_vars = pad_bits(rows) + pad_bits(cols);
    if first.point.len() != n_vars || second.point.len() != n_vars {
        return Err(AccelError::InvalidInput("T1 resident reducer claim geometry mismatch"));
    }

    cx.tx.append("t1_eq_claim_pair", 0);
    let beta = cx.tx.challenge_fp2();
    let claim0 = first.value.add(second.value.scale(beta));
    let doms = EqReductionDoms::alloc_p(cx, n_vars);
    let (sumcheck, point, final_claim, tensor_final, coefficient_final) = {
        let backend = cx
            .backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("T1 resident reducer requires a backend"))?;
        let tensor = lift_matrix_i16_resident(values, rows, cols, backend)?;
        let coefficient = match affine_eq_table_resident(&first.point, &second.point, beta, backend)
        {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(tensor);
                return Err(error);
            }
        };
        blind_prove_resident_labeled(
            tensor,
            coefficient,
            claim0,
            cx.stream,
            doms.rounds,
            cx.tx,
            backend,
            "t1_eq_round_corrections",
        )?
    };

    let terminal_mask = cx.stream.draw_fulls(doms.terminal, 1)[0];
    let terminal_corr = tensor_final - terminal_mask.x;
    cx.tx.append("t1_eq_terminal_correction", 16);
    let terminal = ProverAuthed { x: tensor_final, m: terminal_mask.m };
    cx.zero.push(terminal.scale(coefficient_final).sub(final_claim));
    debug_assert_eq!(
        coefficient_final,
        eq_points(&first.point, &point) + beta * eq_points(&second.point, &point)
    );
    let n = 1u64 << n_vars;
    cx.ctr_other.fp2_mults += 5 * n - 4;
    Ok((EqReductionProof { sumcheck, terminal_corr }, BoundaryClaimP { point, value: terminal }))
}

pub(crate) fn verify_eq_reduction(
    n_vars: usize,
    first: &BoundaryClaimK,
    second: &BoundaryClaimK,
    proof: &EqReductionProof,
    cx: &mut BlockCtxV<'_>,
) -> Option<BoundaryClaimK> {
    if first.point.len() != n_vars || second.point.len() != n_vars {
        return None;
    }
    cx.tx.append("t1_eq_claim_pair", 0);
    let beta = cx.tx.challenge_fp2();
    let claim0 = first.key.add(second.key.scale(beta));
    let doms = EqReductionDoms::alloc_v(cx, n_vars);
    let (point, final_key) =
        blind_verify(n_vars, claim0, &proof.sumcheck, cx.ctx, doms.rounds, cx.tx)?;
    let terminal_key = VerifierKey {
        k: cx.ctx.expand_full_keys(doms.terminal, 1)[0] + cx.ctx.delta * proof.terminal_corr,
    };
    let coefficient = eq_points(&first.point, &point) + beta * eq_points(&second.point, &point);
    cx.kzero.push(terminal_key.scale(coefficient).sub(final_key));
    Some(BoundaryClaimK { point, key: terminal_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_proof::{TableBankP, TableBankV};
    use crate::mle::eval_mle;
    use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};

    fn authed_claim(
        table: &[Fp2],
        point: Vec<Fp2>,
        stream: &mut CorrelationStream,
        domain: u64,
    ) -> (BoundaryClaimP, Fp2) {
        let value = eval_mle(table, &point);
        let mask = stream.draw_fulls(domain, 1)[0];
        (BoundaryClaimP { point, value: ProverAuthed { x: value, m: mask.m } }, value - mask.x)
    }

    #[test]
    fn eq_reducer_matches_m11_and_tamper_leaves_nonzero_closure() {
        let rows = 3usize;
        let cols = 5usize;
        let values: Vec<i16> = (0..rows * cols).map(|i| i as i16 - 7).collect();
        let table = lift_matrix_i16(&values, rows, cols);
        let seed = [0x31; 32];
        let transcript_seed = [0x72; 32];
        let delta = Fp2::new(Fp::new(17), Fp::new(29));
        let mut stream = CorrelationStream::new(seed);
        let mut verifier = VerifierCtx::new(seed, delta);
        let mut tx = Transcript::new(transcript_seed);
        let mut vtx = Transcript::new(transcript_seed);
        let n_vars = pad_bits(rows) + pad_bits(cols);
        let point_a: Vec<_> = (0..n_vars).map(|_| tx.challenge_fp2()).collect();
        let point_b: Vec<_> = (0..n_vars).map(|_| tx.challenge_fp2()).collect();
        for _ in 0..2 * n_vars {
            let _ = vtx.challenge_fp2();
        }
        let (first, first_corr) = authed_claim(&table, point_a, &mut stream, 9_000);
        let (second, second_corr) = authed_claim(&table, point_b, &mut stream, 9_001);
        let first_key = BoundaryClaimK {
            point: first.point.clone(),
            key: VerifierKey { k: verifier.expand_full_keys(9_000, 1)[0] + delta * first_corr },
        };
        let second_key = BoundaryClaimK {
            point: second.point.clone(),
            key: VerifierKey { k: verifier.expand_full_keys(9_001, 1)[0] + delta * second_corr },
        };
        let mut pbank = TableBankP::new();
        let mut vbank = TableBankV::empty();
        let mut pcx = BlockCtxP::new(&mut stream, &mut tx, 250, &mut pbank);
        let (proof, out) = prove_eq_reduction_i16(&values, rows, cols, &first, &second, &mut pcx);
        assert_eq!(pcx.zero.len(), 1);
        assert_eq!(pcx.zero[0].x, Fp2::ZERO);
        assert_eq!(out.value.x, eval_mle(&table, &out.point));

        let mut vcx = BlockCtxV::new(&mut verifier, &mut vtx, 250, &mut vbank);
        let key = verify_eq_reduction(n_vars, &first_key, &second_key, &proof, &mut vcx).unwrap();
        assert_eq!(vcx.kzero.len(), 1);
        assert_eq!(key.key.k, out.value.m + delta * out.value.x);
        assert_eq!(vcx.kzero[0].k, pcx.zero[0].m + delta * pcx.zero[0].x);
        let prover_zero = std::mem::take(&mut pcx.zero);
        drop(pcx);

        // A cheating prover that forges the terminal representation of an
        // unauthenticated intermediate seam changes the verifier's reducer
        // zero row. The honest prover-side row can no longer close.
        let mut forged_proof = proof.clone();
        forged_proof.terminal_corr += Fp2::ONE;
        let mut forged_verifier = VerifierCtx::new(seed, delta);
        let mut forged_vtx = Transcript::new(transcript_seed);
        for _ in 0..2 * n_vars {
            let _ = forged_vtx.challenge_fp2();
        }
        let forged_first_key = BoundaryClaimK {
            point: first.point.clone(),
            key: VerifierKey {
                k: forged_verifier.expand_full_keys(9_000, 1)[0] + delta * first_corr,
            },
        };
        let forged_second_key = BoundaryClaimK {
            point: second.point.clone(),
            key: VerifierKey {
                k: forged_verifier.expand_full_keys(9_001, 1)[0] + delta * second_corr,
            },
        };
        let mut forged_bank = TableBankV::empty();
        let mut forged_cx =
            BlockCtxV::new(&mut forged_verifier, &mut forged_vtx, 250, &mut forged_bank);
        let forged = verify_eq_reduction(
            n_vars,
            &forged_first_key,
            &forged_second_key,
            &forged_proof,
            &mut forged_cx,
        )
        .unwrap();
        assert_ne!(forged.key.k, out.value.m + delta * out.value.x);
        let forged_kzero = std::mem::take(&mut forged_cx.kzero);
        drop(forged_cx);
        assert!(!zero_batch_exchange(
            &prover_zero,
            &forged_kzero,
            &mut stream,
            &mut forged_verifier,
            9_999,
            &mut tx,
        ));
    }
}

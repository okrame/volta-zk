//! C3 private-logit greedy argmax argument.
//!
//! Fifty sampled rows share one 64 x 65,536 rectangle. For every real entry
//! `d = L_tau - L_j` and `strict = d - [j > tau]` are decomposed into three
//! little-endian u16 limbs. Six lookup-side instances share the model-wide
//! `Range(16)` table. Phase masks bind the private logit polynomial to the
//! existing tied-wte matvec claims without adding a PCS claim; an is-max
//! Hadamard binds `d_tau = 0`, preserving Rust's last-maximum tie rule.

use crate::block_proof::{
    auth_fp_vec_p, keys_fp_vec_v, layer_dom_base, open_fp_vec_k, open_fp_vec_p, BlockCtxP,
    BlockCtxV, TableBankP, TableBankV,
};
use crate::hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
use crate::logup::{
    BlindInstance, Counters, Doms, LeafAuxClaim, ProdKeyTriples, ProdTriples, TableKey,
};
use crate::mle::eq_vec;
use volta_accel::Backend;
use volta_field::{Fp, Fp2};
use volta_gpt2::VOCAB;
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

pub(crate) const ARGMAX_SECTION: u8 = 232;
pub(crate) const ARGMAX_ROW_BITS: usize = 6;
pub(crate) const ARGMAX_COL_BITS: usize = 16;
pub(crate) const ARGMAX_VARS: usize = ARGMAX_COL_BITS + ARGMAX_ROW_BITS;
pub(crate) const ARGMAX_ROWS: usize = 1 << ARGMAX_ROW_BITS;
pub(crate) const ARGMAX_COLS: usize = 1 << ARGMAX_COL_BITS;
pub(crate) const ARGMAX_ENTRIES: usize = ARGMAX_ROWS * ARGMAX_COLS;
const LIMBS: usize = 3;
const COLUMNS: usize = 2 * LIMBS;
const LIMB_BASE: u64 = 1 << 16;
const MAX_LOGIT_ABS: i64 = 768 * 32_768 * 32_768;

#[derive(Clone, Copy)]
pub(crate) struct ArgmaxPhaseInput<'a> {
    pub logits: &'a [i64],
    pub tokens: &'a [u32],
}

#[derive(Clone)]
struct PhaseRows {
    global_rows: Vec<usize>,
}

pub(crate) struct PrivateArgmaxWitness {
    columns: [Vec<Fp>; COLUMNS],
    logits: Vec<Fp2>,
    differences: Vec<Fp2>,
    selected_rows: Vec<Fp>,
    is_max: Vec<Fp2>,
    phases: Vec<PhaseRows>,
    tokens: Vec<(usize, usize)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrivateArgmaxProof {
    /// Element-wise authentication of the 64 selected-logit row values.
    pub selected_row_corr: Vec<u64>,
    /// One authenticated masked-logit claim per legacy logits/matvec phase.
    pub phase_claim_corrs: Vec<Fp2>,
    pub phase_hadamards: Vec<HadamardProof>,
    pub is_max_hadamard: HadamardProof,
    /// Three u16-limb evaluations at every phase-Hadamard point, then the
    /// is-max-Hadamard point.
    pub difference_aux_corrs: Vec<[Fp2; LIMBS]>,
    /// Six limb evaluations at the common `strict = d - [j>tau]` point.
    pub strict_aux_corrs: [Fp2; COLUMNS],
    /// Six independent Range(16) lookup-side instances.
    pub limb_instances: Vec<BlindInstance>,
    /// Closure of each instance's native column claim against its witness
    /// MLE. External aux claims carry the actual logits/argmax binding.
    pub limb_native_corrs: [Fp2; COLUMNS],
}

pub(crate) struct PrivateArgmaxPreparedP {
    witness: PrivateArgmaxWitness,
    doms: Doms,
    selected_row_dom: u64,
    selected_row_corr: Vec<u64>,
}

pub(crate) struct PrivateArgmaxPreparedV {
    doms: Doms,
    selected_row_keys: Vec<Fp2>,
}

pub(crate) struct PrivateArgmaxPhaseP {
    pub tau: Vec<Fp2>,
    pub claim: ProverAuthed,
    pub row_weights: Vec<Fp2>,
}

pub(crate) struct PrivateArgmaxPhaseV {
    pub tau: Vec<Fp2>,
    pub claim: VerifierKey,
    pub row_weights: Vec<Fp2>,
}

pub(crate) struct PrivateArgmaxOutP {
    pub proof: PrivateArgmaxProof,
    pub phases: Vec<PrivateArgmaxPhaseP>,
    pub prod: ProdTriples,
    pub zero: Vec<ProverAuthed>,
    pub ctr_instances: Counters,
    pub ctr_other: Counters,
}

pub(crate) struct PrivateArgmaxOutV {
    pub phases: Vec<PrivateArgmaxPhaseV>,
    pub prod: ProdKeyTriples,
    pub zero: Vec<VerifierKey>,
}

fn limb_values(value: u64) -> [Fp; LIMBS] {
    [Fp::new(value & 0xffff), Fp::new((value >> 16) & 0xffff), Fp::new((value >> 32) & 0xffff)]
}

fn combine_auth(values: &[ProverAuthed; LIMBS]) -> ProverAuthed {
    let b1 = Fp2::from_base(Fp::new(LIMB_BASE));
    let b2 = Fp2::from_base(Fp::new(LIMB_BASE * LIMB_BASE));
    values[0].add(values[1].scale(b1)).add(values[2].scale(b2))
}

fn combine_keys(values: &[VerifierKey; LIMBS]) -> VerifierKey {
    let b1 = Fp2::from_base(Fp::new(LIMB_BASE));
    let b2 = Fp2::from_base(Fp::new(LIMB_BASE * LIMB_BASE));
    values[0].add(values[1].scale(b1)).add(values[2].scale(b2))
}

fn validate_argmax_row(row: &[i64], token: usize) -> Option<i64> {
    if row.len() != VOCAB || token >= VOCAB {
        return None;
    }
    if row.iter().any(|value| value.unsigned_abs() > MAX_LOGIT_ABS as u64) {
        return None;
    }
    let selected = row[token];
    for (vocab, &value) in row.iter().enumerate() {
        let difference = selected.checked_sub(value)?;
        if difference < 0 || difference > 2 * MAX_LOGIT_ABS {
            return None;
        }
        if difference.checked_sub(i64::from(vocab > token))? < 0 {
            return None;
        }
    }
    Some(selected)
}

pub(crate) fn build_private_argmax_witness(
    inputs: &[ArgmaxPhaseInput<'_>],
) -> Option<PrivateArgmaxWitness> {
    if inputs.is_empty() {
        return None;
    }
    let total_rows: usize = inputs.iter().map(|input| input.tokens.len()).sum();
    if total_rows == 0 || total_rows > ARGMAX_ROWS {
        return None;
    }

    let mut columns: [Vec<Fp>; COLUMNS] = std::array::from_fn(|_| vec![Fp::ZERO; ARGMAX_ENTRIES]);
    let mut logits = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    let mut differences = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    let mut selected_rows = vec![Fp::ZERO; ARGMAX_ROWS];
    let mut is_max = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    let mut phases = Vec::with_capacity(inputs.len());
    let mut tokens = Vec::with_capacity(total_rows);
    let mut global_row = 0usize;

    for input in inputs {
        if input.logits.len() != input.tokens.len().checked_mul(VOCAB)? {
            return None;
        }
        let mut phase_rows = Vec::with_capacity(input.tokens.len());
        for (local_row, &token_u32) in input.tokens.iter().enumerate() {
            let token = token_u32 as usize;
            let row = &input.logits[local_row * VOCAB..(local_row + 1) * VOCAB];
            let selected = validate_argmax_row(row, token)?;
            selected_rows[global_row] = Fp::from_i64(selected);
            phase_rows.push(global_row);
            tokens.push((global_row, token));

            for (vocab, &value) in row.iter().enumerate() {
                let difference = selected.checked_sub(value)?;
                if difference < 0 || difference > 2 * MAX_LOGIT_ABS {
                    return None;
                }
                let strict = difference.checked_sub(i64::from(vocab > token))?;
                if strict < 0 {
                    return None;
                }
                let index = global_row * ARGMAX_COLS + vocab;
                logits[index] = Fp2::from_base(Fp::from_i64(value));
                differences[index] = Fp2::from_base(Fp::new(difference as u64));
                let d_limbs = limb_values(difference as u64);
                let s_limbs = limb_values(strict as u64);
                for limb in 0..LIMBS {
                    columns[limb][index] = d_limbs[limb];
                    columns[LIMBS + limb][index] = s_limbs[limb];
                }
            }
            is_max[global_row * ARGMAX_COLS + token] = Fp2::ONE;
            global_row += 1;
        }
        phases.push(PhaseRows { global_rows: phase_rows });
    }

    Some(PrivateArgmaxWitness {
        columns,
        logits,
        differences,
        selected_rows,
        is_max,
        phases,
        tokens,
    })
}

fn multiplicities(columns: &[Vec<Fp>; COLUMNS]) -> Vec<u32> {
    let mut counts = vec![0u32; 1 << 16];
    for column in columns {
        for value in column {
            counts[value.value() as usize] = counts[value.value() as usize]
                .checked_add(1)
                .expect("C3 range multiplicity overflow");
        }
    }
    counts
}

pub(crate) fn prepare_private_argmax_prover(
    witness: PrivateArgmaxWitness,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    mut backend: Option<&mut Backend>,
) -> Result<PrivateArgmaxPreparedP, volta_accel::AccelError> {
    let counts = multiplicities(&witness.columns);
    if let Some(accel) = backend.as_deref_mut() {
        let device = accel.upload_new_device(&counts)?;
        bank.add_mult_resident(TableKey::Range(16), device, accel)?;
    } else {
        bank.add_mult(TableKey::Range(16), &counts);
    }
    let mut doms = Doms::new(layer_dom_base(ARGMAX_SECTION));
    let selected_row_dom = doms.take(1);
    let selected_row_corr = auth_fp_vec_p(stream, tx, selected_row_dom, &witness.selected_rows);
    Ok(PrivateArgmaxPreparedP { witness, doms, selected_row_dom, selected_row_corr })
}

pub(crate) fn prepare_private_argmax_verifier(
    proof: &PrivateArgmaxProof,
    phase_count: usize,
    ctx: &mut VerifierCtx,
) -> Option<PrivateArgmaxPreparedV> {
    if proof.selected_row_corr.len() != ARGMAX_ROWS
        || proof.phase_claim_corrs.len() != phase_count
        || proof.phase_hadamards.len() != phase_count
        || proof.difference_aux_corrs.len() != phase_count + 1
        || proof.limb_instances.len() != COLUMNS
        || proof.phase_hadamards.iter().any(|proof| proof.round_corrs.len() != ARGMAX_VARS)
        || proof.is_max_hadamard.round_corrs.len() != ARGMAX_VARS
    {
        return None;
    }
    let mut doms = Doms::new(layer_dom_base(ARGMAX_SECTION));
    let selected_row_dom = doms.take(1);
    let selected_row_keys = keys_fp_vec_v(ctx, selected_row_dom, &proof.selected_row_corr);
    Some(PrivateArgmaxPreparedV { doms, selected_row_keys })
}

fn eval_base_column(column: &[Fp], point: &[Fp2]) -> Fp2 {
    let eq = eq_vec(point);
    column.iter().zip(eq).fold(Fp2::ZERO, |sum, (&value, weight)| {
        if value == Fp::ZERO {
            sum
        } else {
            sum + weight.mul_base(value)
        }
    })
}

fn eval_phase_mask(phase: &PhaseRows, point: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&point[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&point[ARGMAX_COL_BITS..]);
    let vocab_sum = eq_vocab[..VOCAB].iter().fold(Fp2::ZERO, |sum, &value| sum + value);
    phase.global_rows.iter().fold(Fp2::ZERO, |sum, &row| sum + eq_rows[row] * vocab_sum)
}

fn phase_mask_table(phase: &PhaseRows) -> Vec<Fp2> {
    let mut mask = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    for &row in &phase.global_rows {
        mask[row * ARGMAX_COLS..row * ARGMAX_COLS + VOCAB].fill(Fp2::ONE);
    }
    mask
}

fn phase_row_weights(phase: &PhaseRows, row_point: &[Fp2]) -> Vec<Fp2> {
    let eq_rows = eq_vec(row_point);
    phase.global_rows.iter().map(|&row| eq_rows[row]).collect()
}

fn eval_phase_logits(witness: &PrivateArgmaxWitness, phase: &PhaseRows, tau: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&tau[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&tau[ARGMAX_COL_BITS..]);
    phase.global_rows.iter().fold(Fp2::ZERO, |sum, &row| {
        let row_eval = (0..VOCAB).fold(Fp2::ZERO, |row_sum, vocab| {
            row_sum + eq_vocab[vocab] * witness.logits[row * ARGMAX_COLS + vocab]
        });
        sum + eq_rows[row] * row_eval
    })
}

fn eval_is_max(witness: &PrivateArgmaxWitness, point: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&point[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&point[ARGMAX_COL_BITS..]);
    witness.tokens.iter().fold(Fp2::ZERO, |sum, &(row, token)| sum + eq_rows[row] * eq_vocab[token])
}

fn eval_after(witness: &PrivateArgmaxWitness, point: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&point[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&point[ARGMAX_COL_BITS..]);
    witness.tokens.iter().fold(Fp2::ZERO, |sum, &(row, token)| {
        let suffix = eq_vocab[token + 1..VOCAB].iter().fold(Fp2::ZERO, |sum, &value| sum + value);
        sum + eq_rows[row] * suffix
    })
}

fn authenticate_scalar(
    value: Fp2,
    cx: &mut BlockCtxP<'_>,
    label: &'static str,
) -> (Fp2, ProverAuthed) {
    let domain = cx.doms.take(1);
    let correlation = cx.stream.draw_fulls(domain, 1)[0];
    let correction = value - correlation.x;
    cx.tx.append(label, 16);
    (correction, ProverAuthed { x: value, m: correlation.m })
}

fn verify_scalar(correction: Fp2, cx: &mut BlockCtxV<'_>) -> VerifierKey {
    let domain = cx.doms.take(1);
    VerifierKey { k: cx.ctx.expand_full_keys(domain, 1)[0] + cx.ctx.delta * correction }
}

fn authenticate_limb_point(
    witness: &PrivateArgmaxWitness,
    point: &[Fp2],
    count: usize,
    cx: &mut BlockCtxP<'_>,
) -> (Vec<Fp2>, Vec<ProverAuthed>) {
    let mut corrections = Vec::with_capacity(count);
    let mut values = Vec::with_capacity(count);
    for column in witness.columns.iter().take(count) {
        let value = eval_base_column(column, point);
        let (correction, authenticated) =
            authenticate_scalar(value, cx, "argmax_limb_aux_correction");
        corrections.push(correction);
        values.push(authenticated);
    }
    (corrections, values)
}

fn verify_limb_point(
    corrections: &[Fp2],
    point: &[Fp2],
    aux: &mut [Vec<(usize, Vec<Fp2>, VerifierKey)>; COLUMNS],
    cx: &mut BlockCtxV<'_>,
) -> Vec<VerifierKey> {
    corrections
        .iter()
        .enumerate()
        .map(|(column, &correction)| {
            let key = verify_scalar(correction, cx);
            aux[column].push((0, point.to_vec(), key));
            key
        })
        .collect()
}

pub(crate) fn prove_private_argmax(
    prepared: PrivateArgmaxPreparedP,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: Option<&mut Backend>,
) -> PrivateArgmaxOutP {
    let PrivateArgmaxPreparedP { witness, doms, selected_row_dom, selected_row_corr } = prepared;
    let mut cx = if let Some(accel) = backend {
        BlockCtxP::with_doms_and_backend(stream, tx, doms, bank, accel)
    } else {
        BlockCtxP::with_doms(stream, tx, doms, bank)
    };
    let mut aux: [Vec<LeafAuxClaim>; COLUMNS] = std::array::from_fn(|_| Vec::new());
    let mut phase_claim_corrs = Vec::with_capacity(witness.phases.len());
    let mut phase_hadamards = Vec::with_capacity(witness.phases.len());
    let mut difference_aux_corrs = Vec::with_capacity(witness.phases.len() + 1);
    let mut phase_outputs = Vec::with_capacity(witness.phases.len());

    for phase in &witness.phases {
        let tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
        let phase_value = eval_phase_logits(&witness, phase, &tau);
        let (phase_corr, phase_claim) =
            authenticate_scalar(phase_value, &mut cx, "argmax_phase_claim_correction");
        phase_claim_corrs.push(phase_corr);
        let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
        let (hadamard, point, logit_claim, mask_claim) = hadamard_prove(
            &tau,
            witness.logits.clone(),
            phase_mask_table(phase),
            phase_claim,
            &hadamard_doms,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
        );
        cx.zero.push(mask_claim.sub(ProverAuthed::from_public(eval_phase_mask(phase, &point))));

        let (corrections, limb_values) = authenticate_limb_point(&witness, &point, LIMBS, &mut cx);
        let correction_array: [Fp2; LIMBS] = corrections.try_into().expect("three d limbs");
        difference_aux_corrs.push(correction_array);
        for (column, value) in limb_values.iter().copied().enumerate() {
            aux[column].push(LeafAuxClaim { col: 0, point: point.clone(), value });
        }
        let d_claim = combine_auth(&limb_values.try_into().expect("three d limbs"));
        let c_claim = open_fp_vec_p(
            cx.stream,
            selected_row_dom,
            &witness.selected_rows,
            &point[ARGMAX_COL_BITS..],
        );
        let vocab_weight = eq_vec(&point[..ARGMAX_COL_BITS])[..VOCAB]
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        cx.zero.push(c_claim.scale(vocab_weight).sub(d_claim).sub(logit_claim));
        phase_hadamards.push(hadamard);
        phase_outputs.push(PrivateArgmaxPhaseP {
            tau: tau.clone(),
            claim: phase_claim,
            row_weights: phase_row_weights(phase, &tau[ARGMAX_COL_BITS..]),
        });
    }

    let is_max_tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let is_max_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
    let (is_max_hadamard, is_max_point, d_claim, marker_claim) = hadamard_prove(
        &is_max_tau,
        witness.differences.clone(),
        witness.is_max.clone(),
        ProverAuthed::ZERO,
        &is_max_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    cx.zero.push(marker_claim.sub(ProverAuthed::from_public(eval_is_max(&witness, &is_max_point))));
    let (max_corrections, max_limb_values) =
        authenticate_limb_point(&witness, &is_max_point, LIMBS, &mut cx);
    difference_aux_corrs.push(max_corrections.try_into().expect("three d limbs"));
    for (column, value) in max_limb_values.iter().copied().enumerate() {
        aux[column].push(LeafAuxClaim { col: 0, point: is_max_point.clone(), value });
    }
    cx.zero.push(combine_auth(&max_limb_values.try_into().expect("three d limbs")).sub(d_claim));

    let strict_point: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let (strict_corrections, strict_values) =
        authenticate_limb_point(&witness, &strict_point, COLUMNS, &mut cx);
    let strict_aux_corrs: [Fp2; COLUMNS] = strict_corrections.try_into().expect("six strict limbs");
    for (column, value) in strict_values.iter().copied().enumerate() {
        aux[column].push(LeafAuxClaim { col: 0, point: strict_point.clone(), value });
    }
    let d_at_strict = combine_auth(&strict_values[..LIMBS].try_into().expect("three d limbs"));
    let s_at_strict = combine_auth(&strict_values[LIMBS..].try_into().expect("three strict limbs"));
    cx.zero.push(
        s_at_strict
            .sub(d_at_strict)
            .add(ProverAuthed::from_public(eval_after(&witness, &strict_point))),
    );

    let mut limb_instances = Vec::with_capacity(COLUMNS);
    let mut limb_native_corrs = [Fp2::ZERO; COLUMNS];
    for column in 0..COLUMNS {
        let output = cx.inst(
            TableKey::Range(16),
            std::slice::from_ref(&witness.columns[column]),
            &[Some(0)],
            std::mem::take(&mut aux[column]),
        );
        let native_value = eval_base_column(&witness.columns[column], &output.point);
        let (native_corr, native_claim) =
            authenticate_scalar(native_value, &mut cx, "argmax_limb_native_correction");
        limb_native_corrs[column] = native_corr;
        cx.zero.push(output.col_claims[0].value.sub(native_claim));
        limb_instances.push(output.proof);
    }

    PrivateArgmaxOutP {
        proof: PrivateArgmaxProof {
            selected_row_corr,
            phase_claim_corrs,
            phase_hadamards,
            is_max_hadamard,
            difference_aux_corrs,
            strict_aux_corrs,
            limb_instances,
            limb_native_corrs,
        },
        phases: phase_outputs,
        prod: cx.prod,
        zero: cx.zero,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
    }
}

pub(crate) fn verify_private_argmax(
    prepared: PrivateArgmaxPreparedV,
    phase_rows: &[Vec<usize>],
    public_tokens: &[(usize, usize)],
    proof: &PrivateArgmaxProof,
    bank: &mut TableBankV,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<PrivateArgmaxOutV> {
    if phase_rows.len() != proof.phase_hadamards.len()
        || public_tokens.iter().any(|&(row, token)| row >= ARGMAX_ROWS || token >= VOCAB)
    {
        return None;
    }
    let phases: Vec<PhaseRows> =
        phase_rows.iter().cloned().map(|global_rows| PhaseRows { global_rows }).collect();
    let mut cx = BlockCtxV::with_doms(ctx, tx, prepared.doms, bank);
    let mut aux: [Vec<(usize, Vec<Fp2>, VerifierKey)>; COLUMNS] =
        std::array::from_fn(|_| Vec::new());
    let mut phase_outputs = Vec::with_capacity(phases.len());

    for (index, phase) in phases.iter().enumerate() {
        let tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
        let phase_claim = verify_scalar(proof.phase_claim_corrs[index], &mut cx);
        let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
        let (point, logit_key, mask_key) = hadamard_verify(
            &tau,
            phase_claim,
            &proof.phase_hadamards[index],
            &hadamard_doms,
            cx.ctx,
            cx.tx,
            &mut cx.kprod,
            &mut cx.kzero,
        )?;
        cx.kzero.push(
            mask_key.sub(VerifierKey::from_public(eval_phase_mask(phase, &point), cx.ctx.delta)),
        );
        let limb_keys_vec =
            verify_limb_point(&proof.difference_aux_corrs[index], &point, &mut aux, &mut cx);
        let limb_keys: [VerifierKey; LIMBS] = limb_keys_vec.try_into().ok()?;
        let d_key = combine_keys(&limb_keys);
        let c_key = open_fp_vec_k(&prepared.selected_row_keys, &point[ARGMAX_COL_BITS..]);
        let vocab_weight = eq_vec(&point[..ARGMAX_COL_BITS])[..VOCAB]
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        cx.kzero.push(c_key.scale(vocab_weight).sub(d_key).sub(logit_key));
        phase_outputs.push(PrivateArgmaxPhaseV {
            tau: tau.clone(),
            claim: phase_claim,
            row_weights: phase_row_weights(phase, &tau[ARGMAX_COL_BITS..]),
        });
    }

    let is_max_tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let is_max_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
    let (is_max_point, d_key, marker_key) = hadamard_verify(
        &is_max_tau,
        VerifierKey::ZERO,
        &proof.is_max_hadamard,
        &is_max_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let marker_eval = {
        let eq_vocab = eq_vec(&is_max_point[..ARGMAX_COL_BITS]);
        let eq_rows = eq_vec(&is_max_point[ARGMAX_COL_BITS..]);
        public_tokens
            .iter()
            .fold(Fp2::ZERO, |sum, &(row, token)| sum + eq_rows[row] * eq_vocab[token])
    };
    cx.kzero.push(marker_key.sub(VerifierKey::from_public(marker_eval, cx.ctx.delta)));
    let max_limb_keys_vec = verify_limb_point(
        &proof.difference_aux_corrs[phases.len()],
        &is_max_point,
        &mut aux,
        &mut cx,
    );
    let max_limb_keys: [VerifierKey; LIMBS] = max_limb_keys_vec.try_into().ok()?;
    cx.kzero.push(combine_keys(&max_limb_keys).sub(d_key));

    let strict_point: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let strict_keys = verify_limb_point(&proof.strict_aux_corrs, &strict_point, &mut aux, &mut cx);
    let d_strict: [VerifierKey; LIMBS] = strict_keys[..LIMBS].try_into().ok()?;
    let s_strict: [VerifierKey; LIMBS] = strict_keys[LIMBS..].try_into().ok()?;
    let after_eval = {
        let eq_vocab = eq_vec(&strict_point[..ARGMAX_COL_BITS]);
        let eq_rows = eq_vec(&strict_point[ARGMAX_COL_BITS..]);
        public_tokens.iter().fold(Fp2::ZERO, |sum, &(row, token)| {
            let suffix =
                eq_vocab[token + 1..VOCAB].iter().fold(Fp2::ZERO, |sum, &value| sum + value);
            sum + eq_rows[row] * suffix
        })
    };
    cx.kzero.push(
        combine_keys(&s_strict)
            .sub(combine_keys(&d_strict))
            .add(VerifierKey::from_public(after_eval, cx.ctx.delta)),
    );

    for column in 0..COLUMNS {
        let output = cx.inst(
            TableKey::Range(16),
            ARGMAX_VARS,
            &[Some(0)],
            &proof.limb_instances[column],
            &aux[column],
        )?;
        let native_key = verify_scalar(proof.limb_native_corrs[column], &mut cx);
        cx.kzero.push(output.col_keys[0].key.sub(native_key));
    }

    Some(PrivateArgmaxOutV { phases: phase_outputs, prod: cx.kprod, zero: cx.kzero })
}

pub(crate) fn phase_layout_from_lengths(
    lengths: &[usize],
) -> Option<(Vec<Vec<usize>>, Vec<usize>)> {
    let total: usize = lengths.iter().sum();
    if total == 0 || total > ARGMAX_ROWS {
        return None;
    }
    let mut cursor = 0usize;
    let mut phases = Vec::with_capacity(lengths.len());
    for &length in lengths {
        if length == 0 {
            return None;
        }
        phases.push((cursor..cursor + length).collect());
        cursor += length;
    }
    Some((phases, (0..total).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_max_tie_rule_accepts_only_the_last_index() {
        let mut row = vec![-7i64; VOCAB];
        row[11] = 9;
        row[37] = 9;
        assert_eq!(validate_argmax_row(&row, 37), Some(9));
        assert_eq!(validate_argmax_row(&row, 11), None);
    }

    #[test]
    fn lower_logit_and_out_of_bound_rows_reject() {
        let mut row = vec![0i64; VOCAB];
        row[4] = 5;
        assert_eq!(validate_argmax_row(&row, 3), None);
        row[4] = 0;
        row[0] = MAX_LOGIT_ABS + 1;
        assert_eq!(validate_argmax_row(&row, 0), None);
    }

    #[test]
    fn full_bound_round_trips_through_three_u16_limbs() {
        let value = (2 * MAX_LOGIT_ABS) as u64;
        assert!(value < (1u64 << 41));
        let limbs = limb_values(value);
        let rebuilt = limbs[0].value() + (limbs[1].value() << 16) + (limbs[2].value() << 32);
        assert_eq!(rebuilt, value);
    }

    #[test]
    fn phase_rows_are_global_and_bounded() {
        let (phases, rows) = phase_layout_from_lengths(&[1, 16, 16, 16, 1]).unwrap();
        assert_eq!(phases[0], vec![0]);
        assert_eq!(phases[4], vec![49]);
        assert_eq!(rows, (0..50).collect::<Vec<_>>());
        assert!(phase_layout_from_lengths(&[1, 64]).is_none());
        assert!(phase_layout_from_lengths(&[0, 1]).is_none());
    }
}

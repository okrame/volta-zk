//! C3 private-logit greedy argmax argument.
//!
//! Fifty sampled rows keep the canonical 64 x 65,536 constraint rectangle,
//! but only `strict = L_tau - L_j - [j > tau]` is range checked.  Its three
//! u16 limbs are packed as eight five-position segments in 2^21 plus two in
//! 2^19.  Batched public-selector sumchecks bind those packed columns back to
//! every rectangular opening, so the tight geometry does not change the MLE
//! statement.  All six jobs share the model-wide `Range(16)` table and one
//! alpha.  The native last-maximum tie rule is preserved bit-exactly.

use crate::block_proof::{
    auth_device_vector_p, auth_fp_vec_p, keys_fp_vec_v, layer_dom_base, open_fp_vec_k,
    open_fp_vec_p, open_fp_vec_resident_p, BlockCtxP, BlockCtxV, TableBankP, TableBankV,
};
use crate::hadamard::{
    hadamard_prove, hadamard_prove_resident, hadamard_verify, HadamardDoms, HadamardProof,
};
use crate::logup::{
    blind_instance_prove_batch_cpu, blind_instance_prove_resident_batch,
    blind_instance_verify_batch, BlindInstance, Counters, CpuLogupBatchJob, Doms, LeafAuxClaim,
    LogupBatchPlan, LogupBatchSite, ProdKeyTriples, ProdTriples, ResidentLogupBatchJob, TableKey,
    VerifyLogupBatchJob,
};
use crate::mle::eq_vec;
use crate::schedule::{RoundFamily, SchedulePlan, ScheduleSite, SiteId};
use crate::sumcheck_blind::{
    blind_prove_batch, blind_prove_resident_batch, blind_verify_batch, BlindSumcheckBatchJob,
    BlindSumcheckBatchVerifyJob, BlindSumcheckProof, BlindSumcheckResidentBatchJob,
};
use rayon::prelude::*;
use volta_accel::{
    Backend, DeviceBuffer, DevicePrivateArgmaxWitness, DeviceSlice, Fp2Repr, MatrixFoldAxis,
};
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
const PACKED_JOBS: usize = 2;
const INSTANCES: usize = LIMBS * PACKED_JOBS;
const SEGMENT_BITS: usize = 18;
const SEGMENT_ENTRIES: usize = 1 << SEGMENT_BITS;
const ROWS_PER_SEGMENT: usize = 5;
const FIRST_JOB_ENTRIES: usize = 1 << 21;
const SECOND_JOB_ENTRIES: usize = 1 << 19;
pub(crate) const ARGMAX_PACKED_ENTRIES_PER_LIMB: usize = FIRST_JOB_ENTRIES + SECOND_JOB_ENTRIES;
pub(crate) const ARGMAX_REAL_COMPARISONS: usize = 50 * VOCAB;
const ARGMAX_PACKED_ROWS: usize = ARGMAX_REAL_COMPARISONS / VOCAB;
const LIMB_BASE: u64 = 1 << 16;
const MAX_LOGIT_ABS: i64 = 768 * 32_768 * 32_768;

#[derive(Clone, Copy)]
pub(crate) struct ArgmaxPhaseInput<'a> {
    pub logits: &'a [i64],
    pub tokens: &'a [u32],
}

#[derive(Clone, Copy)]
pub(crate) struct ResidentArgmaxPhaseInput<'a> {
    pub logits: DeviceSlice<'a, i64>,
    pub tokens: &'a [u32],
}

#[derive(Clone)]
struct PhaseRows {
    global_rows: Vec<usize>,
}

struct HostPrivateArgmaxWitness {
    columns: [Vec<Fp>; LIMBS],
    packed_strict: Vec<Fp2>,
    logits: Vec<Fp2>,
    strict: Vec<Fp2>,
    selected_rows: Vec<Fp>,
    is_max: Vec<Fp2>,
}

enum PrivateArgmaxStorage {
    Host(HostPrivateArgmaxWitness),
    Resident(DevicePrivateArgmaxWitness),
}

pub(crate) struct PrivateArgmaxWitness {
    storage: PrivateArgmaxStorage,
    phases: Vec<PhaseRows>,
    tokens: Vec<(usize, usize)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PackedBridgeProof {
    /// One authenticated mapped linear claim per packed job.
    pub claim_corrs: [Fp2; PACKED_JOBS],
    /// Two round-synchronous public-selector product sumchecks.
    pub sumchecks: Vec<BlindSumcheckProof>,
    /// Authentication of the packed strict opening at each sumcheck point.
    pub strict_final_corrs: [Fp2; PACKED_JOBS],
    /// Three limb openings per job, limb-major then job-major.
    pub limb_final_corrs: [Fp2; INSTANCES],
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrivateArgmaxProof {
    /// Element-wise authentication of the 64 selected-logit row values.
    pub selected_row_corr: Vec<u64>,
    /// One authenticated masked-logit claim per legacy logits/matvec phase.
    pub phase_claim_corrs: Vec<Fp2>,
    /// Authenticated rectangular strict evaluations for the logits phases.
    pub phase_strict_corrs: Vec<Fp2>,
    pub phase_hadamards: Vec<HadamardProof>,
    pub is_max_hadamard: HadamardProof,
    /// One random-linear-combination bridge for every strict evaluation.
    pub packed_bridge: PackedBridgeProof,
    /// Three limbs x two packed jobs, proven in one flat scheduled cohort.
    pub limb_instances: Vec<BlindInstance>,
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
    if total_rows == 0 || total_rows > ARGMAX_PACKED_ROWS {
        return None;
    }

    let mut rows = Vec::with_capacity(total_rows);
    let mut selected_rows = vec![Fp::ZERO; ARGMAX_ROWS];
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
            rows.push((row, token, selected));
            global_row += 1;
        }
        phases.push(PhaseRows { global_rows: phase_rows });
    }

    let mut logits = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    logits.par_chunks_mut(ARGMAX_COLS).take(total_rows).zip(rows.par_iter()).for_each(
        |(output, (row, _, _))| {
            for (dst, &value) in output[..VOCAB].iter_mut().zip(*row) {
                *dst = Fp2::from_base(Fp::from_i64(value));
            }
        },
    );

    let mut strict = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    strict.par_chunks_mut(ARGMAX_COLS).take(total_rows).zip(rows.par_iter()).for_each(
        |(output, (row, token, selected))| {
            for (vocab, (&value, dst)) in row.iter().zip(&mut output[..VOCAB]).enumerate() {
                let value = selected - value - i64::from(vocab > *token);
                debug_assert!(value >= 0 && value < (1i64 << 48));
                *dst = Fp2::from_base(Fp::new(value as u64));
            }
        },
    );

    let columns: [Vec<Fp>; LIMBS] = std::array::from_fn(|limb| {
        let mut column = vec![Fp::ZERO; ARGMAX_PACKED_ENTRIES_PER_LIMB];
        column.par_chunks_mut(SEGMENT_ENTRIES).enumerate().for_each(|(segment, output)| {
            for within_row in 0..ROWS_PER_SEGMENT {
                let row_index = segment * ROWS_PER_SEGMENT + within_row;
                if let Some((row, token, selected)) = rows.get(row_index) {
                    let start = within_row * VOCAB;
                    for (vocab, (&value, dst)) in
                        row.iter().zip(&mut output[start..start + VOCAB]).enumerate()
                    {
                        let strict = selected - value - i64::from(vocab > *token);
                        debug_assert!(strict >= 0 && strict < (1i64 << 48));
                        *dst = limb_values(strict as u64)[limb];
                    }
                }
            }
        });
        column
    });
    let packed_strict = (0..ARGMAX_PACKED_ENTRIES_PER_LIMB)
        .into_par_iter()
        .map(|index| {
            let limbs: [ProverAuthed; LIMBS] = std::array::from_fn(|limb| ProverAuthed {
                x: Fp2::from_base(columns[limb][index]),
                m: Fp2::ZERO,
            });
            combine_auth(&limbs).x
        })
        .collect();

    let mut is_max = vec![Fp2::ZERO; ARGMAX_ENTRIES];
    for &(row, token) in &tokens {
        is_max[row * ARGMAX_COLS + token] = Fp2::ONE;
    }

    Some(PrivateArgmaxWitness {
        storage: PrivateArgmaxStorage::Host(HostPrivateArgmaxWitness {
            columns,
            packed_strict,
            logits,
            strict,
            selected_rows,
            is_max,
        }),
        phases,
        tokens,
    })
}

pub(crate) fn build_private_argmax_resident_witness(
    inputs: &[ResidentArgmaxPhaseInput<'_>],
    error: DeviceSlice<'_, u32>,
    backend: &mut Backend,
) -> Result<PrivateArgmaxWitness, volta_accel::AccelError> {
    if inputs.is_empty() {
        return Err(volta_accel::AccelError::InvalidInput("empty resident private argmax"));
    }
    let total_rows: usize = inputs.iter().map(|input| input.tokens.len()).sum();
    if total_rows == 0 || total_rows > ARGMAX_PACKED_ROWS {
        return Err(volta_accel::AccelError::InvalidInput(
            "resident private-argmax row count exceeds packed geometry",
        ));
    }
    let mut phases = Vec::with_capacity(inputs.len());
    let mut tokens = Vec::with_capacity(total_rows);
    let mut cursor = 0usize;
    for input in inputs {
        let expected = input.tokens.len().checked_mul(VOCAB).ok_or(
            volta_accel::AccelError::InvalidInput("resident private-argmax input overflow"),
        )?;
        if input.tokens.is_empty()
            || input.logits.len() != expected
            || input.tokens.iter().any(|&token| token as usize >= VOCAB)
        {
            return Err(volta_accel::AccelError::InvalidInput(
                "resident private-argmax input geometry mismatch",
            ));
        }
        let rows = (cursor..cursor + input.tokens.len()).collect::<Vec<_>>();
        for (row, &token) in rows.iter().zip(input.tokens) {
            tokens.push((*row, token as usize));
        }
        cursor += input.tokens.len();
        phases.push(PhaseRows { global_rows: rows });
    }

    let raw_len = total_rows.checked_mul(VOCAB).ok_or(volta_accel::AccelError::InvalidInput(
        "resident private-argmax raw geometry overflow",
    ))?;
    let raw = backend.alloc_device::<i64>(raw_len)?;
    let copy_result = (|| {
        let mut dst = 0usize;
        for input in inputs {
            backend.copy_device_rows(
                input.logits,
                VOCAB,
                &raw,
                dst,
                VOCAB,
                input.tokens.len(),
                VOCAB,
            )?;
            dst += input.tokens.len() * VOCAB;
        }
        backend.private_argmax_witness_device(
            DeviceSlice::new(&raw, 0, raw_len).expect("resident private-argmax raw slice"),
            error,
            total_rows,
            VOCAB,
            ARGMAX_ENTRIES,
            ARGMAX_PACKED_ENTRIES_PER_LIMB,
            FIRST_JOB_ENTRIES,
            ARGMAX_ROWS,
        )
    })();
    let cleanup = backend.free_device(raw);
    let resident = match (copy_result, cleanup) {
        (Ok(value), Ok(())) => value,
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    Ok(PrivateArgmaxWitness { storage: PrivateArgmaxStorage::Resident(resident), phases, tokens })
}

fn multiplicities(columns: &[Vec<Fp>; LIMBS]) -> Vec<u32> {
    columns
        .par_iter()
        .map(|column| {
            let mut counts = vec![0u32; 1 << 16];
            for value in column {
                counts[value.value() as usize] += 1;
            }
            counts
        })
        .reduce(
            || vec![0u32; 1 << 16],
            |mut left, right| {
                for (dst, value) in left.iter_mut().zip(right) {
                    *dst = dst.checked_add(value).expect("C3b range multiplicity overflow");
                }
                left
            },
        )
}

pub(crate) fn prepare_private_argmax_prover(
    witness: PrivateArgmaxWitness,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    mut backend: Option<&mut Backend>,
) -> Result<PrivateArgmaxPreparedP, volta_accel::AccelError> {
    let mut doms = Doms::new(layer_dom_base(ARGMAX_SECTION));
    let selected_row_dom = doms.take(1);
    let selected_row_corr = match &witness.storage {
        PrivateArgmaxStorage::Host(host) => Ok({
            let counts = multiplicities(&host.columns);
            bank.add_mult(TableKey::Range(16), &counts);
            auth_fp_vec_p(stream, tx, selected_row_dom, &host.selected_rows)
        }),
        PrivateArgmaxStorage::Resident(resident) => {
            let Some(accel) = backend.as_deref_mut() else {
                return Err(volta_accel::AccelError::InvalidInput(
                    "resident private argmax requires a backend",
                ));
            };
            (|| {
                let counts = accel.histogram_fp_device(resident.all_lookup_limbs(), 1 << 16)?;
                bank.add_mult_resident(TableKey::Range(16), counts, accel)?;
                auth_device_vector_p(stream, tx, selected_row_dom, resident.selected_rows(), accel)
            })()
        }
    };
    let selected_row_corr = match selected_row_corr {
        Ok(value) => value,
        Err(error) => {
            let cleanup = free_private_argmax_witness(witness, backend.as_deref_mut());
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
    };
    Ok(PrivateArgmaxPreparedP { witness, doms, selected_row_dom, selected_row_corr })
}

fn free_private_argmax_witness(
    witness: PrivateArgmaxWitness,
    backend: Option<&mut Backend>,
) -> Result<(), volta_accel::AccelError> {
    match witness.storage {
        PrivateArgmaxStorage::Host(_) => Ok(()),
        PrivateArgmaxStorage::Resident(resident) => backend
            .ok_or(volta_accel::AccelError::InvalidInput(
                "resident private argmax cleanup requires a backend",
            ))?
            .free_private_argmax_witness(resident),
    }
}

pub(crate) fn free_private_argmax_prepared(
    prepared: PrivateArgmaxPreparedP,
    backend: Option<&mut Backend>,
) -> Result<(), volta_accel::AccelError> {
    free_private_argmax_witness(prepared.witness, backend)
}

pub(crate) fn prepare_private_argmax_verifier(
    proof: &PrivateArgmaxProof,
    phase_count: usize,
    ctx: &mut VerifierCtx,
) -> Option<PrivateArgmaxPreparedV> {
    if proof.selected_row_corr.len() != ARGMAX_ROWS
        || proof.phase_claim_corrs.len() != phase_count
        || proof.phase_strict_corrs.len() != phase_count
        || proof.phase_hadamards.len() != phase_count
        || proof.limb_instances.len() != INSTANCES
        || proof.packed_bridge.sumchecks.len() != PACKED_JOBS
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

fn eval_fp2_column(column: &[Fp2], point: &[Fp2]) -> Fp2 {
    let eq = eq_vec(point);
    column
        .par_iter()
        .zip(eq.par_iter())
        .map(|(&value, &weight)| value * weight)
        .reduce(|| Fp2::ZERO, |left, right| left + right)
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

fn eval_phase_logits(witness: &HostPrivateArgmaxWitness, phase: &PhaseRows, tau: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&tau[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&tau[ARGMAX_COL_BITS..]);
    phase.global_rows.iter().fold(Fp2::ZERO, |sum, &row| {
        let row_eval = (0..VOCAB).fold(Fp2::ZERO, |row_sum, vocab| {
            row_sum + eq_vocab[vocab] * witness.logits[row * ARGMAX_COLS + vocab]
        });
        sum + eq_rows[row] * row_eval
    })
}

fn eval_is_max(tokens: &[(usize, usize)], point: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&point[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&point[ARGMAX_COL_BITS..]);
    tokens.iter().fold(Fp2::ZERO, |sum, &(row, token)| sum + eq_rows[row] * eq_vocab[token])
}

fn eval_after(tokens: &[(usize, usize)], point: &[Fp2]) -> Fp2 {
    let eq_vocab = eq_vec(&point[..ARGMAX_COL_BITS]);
    let eq_rows = eq_vec(&point[ARGMAX_COL_BITS..]);
    tokens.iter().fold(Fp2::ZERO, |sum, &(row, token)| {
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

fn job_entries(job: usize) -> usize {
    [FIRST_JOB_ENTRIES, SECOND_JOB_ENTRIES][job]
}

fn instance_index(limb: usize, job: usize) -> usize {
    limb * PACKED_JOBS + job
}

fn instance_limb_job(instance: usize) -> (usize, usize) {
    (instance / PACKED_JOBS, instance % PACKED_JOBS)
}

fn aggregation_coefficients(beta: Fp2, count: usize) -> Vec<Fp2> {
    let mut coefficients = Vec::with_capacity(count);
    let mut power = Fp2::ONE;
    for _ in 0..count {
        coefficients.push(power);
        power = power * beta;
    }
    coefficients
}

fn mapped_selector_values(rect_points: &[Vec<Fp2>], coefficients: &[Fp2], job: usize) -> Vec<Fp2> {
    assert_eq!(rect_points.len(), coefficients.len());
    assert!(rect_points.iter().all(|point| point.len() == ARGMAX_VARS));
    assert!(job < PACKED_JOBS);
    let equalities: Vec<_> = rect_points
        .iter()
        .zip(coefficients)
        .map(|(point, &coefficient)| {
            (eq_vec(&point[..ARGMAX_COL_BITS]), eq_vec(&point[ARGMAX_COL_BITS..]), coefficient)
        })
        .collect();
    let mut output = vec![Fp2::ZERO; job_entries(job)];
    output.par_chunks_mut(SEGMENT_ENTRIES).enumerate().for_each(|(local_segment, segment)| {
        let global_segment = if job == 0 { local_segment } else { 8 + local_segment };
        for within_row in 0..ROWS_PER_SEGMENT {
            let row = global_segment * ROWS_PER_SEGMENT + within_row;
            let start = within_row * VOCAB;
            for word in 0..VOCAB {
                segment[start + word] =
                    equalities.iter().fold(Fp2::ZERO, |sum, (eq_vocab, eq_rows, coefficient)| {
                        sum + eq_rows[row] * eq_vocab[word] * *coefficient
                    });
            }
        }
    });
    output
}

fn mapped_selector_eval(
    rect_points: &[Vec<Fp2>],
    coefficients: &[Fp2],
    job: usize,
    packed_point: &[Fp2],
) -> Fp2 {
    let selector = mapped_selector_values(rect_points, coefficients, job);
    let eq = eq_vec(packed_point);
    selector
        .par_iter()
        .zip(eq.par_iter())
        .map(|(&left, &right)| left * right)
        .reduce(|| Fp2::ZERO, |left, right| left + right)
}

fn mapping_schedule(doms: &mut Doms) -> (SchedulePlan, [u64; PACKED_JOBS]) {
    let mut bases = [0u64; PACKED_JOBS];
    let sites = (0..PACKED_JOBS)
        .map(|job| {
            let depth = job_entries(job).trailing_zeros() as usize;
            let base = doms.take(depth as u64);
            bases[job] = base;
            ScheduleSite {
                id: SiteId::new(ARGMAX_SECTION.into(), RoundFamily::BlindProduct, job as u32),
                rounds: depth,
                mask_dom_base: base,
                mask_dom_span: depth as u64,
            }
        })
        .collect();
    (SchedulePlan::new(sites).expect("valid private-argmax bridge schedule"), bases)
}

fn prove_packed_bridge_host(
    host: &HostPrivateArgmaxWitness,
    rect_points: &[Vec<Fp2>],
    rect_claims: &[ProverAuthed],
    aux: &mut [Vec<LeafAuxClaim>; INSTANCES],
    cx: &mut BlockCtxP<'_>,
) -> PackedBridgeProof {
    assert_eq!(rect_points.len(), rect_claims.len());
    let coefficients = aggregation_coefficients(cx.tx.challenge_fp2(), rect_points.len());
    let aggregate = rect_claims
        .iter()
        .zip(&coefficients)
        .fold(ProverAuthed::ZERO, |sum, (&claim, &coefficient)| sum.add(claim.scale(coefficient)));
    let mut claim_corrs = [Fp2::ZERO; PACKED_JOBS];
    let mut initial = [ProverAuthed::ZERO; PACKED_JOBS];
    let mut factors = Vec::with_capacity(PACKED_JOBS);
    for job in 0..PACKED_JOBS {
        let start = if job == 0 { 0 } else { FIRST_JOB_ENTRIES };
        let entries = job_entries(job);
        let selector = mapped_selector_values(rect_points, &coefficients, job);
        let column = &host.packed_strict[start..start + entries];
        let value = column
            .par_iter()
            .zip(selector.par_iter())
            .map(|(&entry, &weight)| entry * weight)
            .reduce(|| Fp2::ZERO, |left, right| left + right);
        let (correction, claim) =
            authenticate_scalar(value, cx, "argmax_packed_bridge_claim_correction");
        claim_corrs[job] = correction;
        initial[job] = claim;
        factors.push((column.to_vec(), selector));
    }
    cx.zero.push(initial[0].add(initial[1]).sub(aggregate));

    let (schedule, bases) = mapping_schedule(&mut cx.doms);
    let jobs = factors
        .into_iter()
        .enumerate()
        .map(|(job, (a, b))| BlindSumcheckBatchJob {
            site_id: schedule.sites()[job].id,
            a,
            b,
            claim0: initial[job],
            mask_dom_base: bases[job],
        })
        .collect();
    let outputs = blind_prove_batch(&schedule, jobs, cx.stream, cx.tx)
        .expect("private-argmax public-selector bridge is valid");
    let mut strict_final_corrs = [Fp2::ZERO; PACKED_JOBS];
    let mut limb_final_corrs = [Fp2::ZERO; INSTANCES];
    let mut sumchecks = Vec::with_capacity(PACKED_JOBS);
    for (job, output) in outputs.into_iter().enumerate() {
        let (correction, strict_final) =
            authenticate_scalar(output.a_final, cx, "argmax_packed_bridge_final_correction");
        strict_final_corrs[job] = correction;
        let eq = eq_vec(&output.point);
        let start = if job == 0 { 0 } else { FIRST_JOB_ENTRIES };
        let entries = job_entries(job);
        let limb_claims: [ProverAuthed; LIMBS] = std::array::from_fn(|limb| {
            let value = host.columns[limb][start..start + entries]
                .par_iter()
                .zip(eq.par_iter())
                .map(|(&entry, &weight)| weight.mul_base(entry))
                .reduce(|| Fp2::ZERO, |left, right| left + right);
            let instance = instance_index(limb, job);
            let (limb_correction, limb_claim) =
                authenticate_scalar(value, cx, "argmax_packed_bridge_limb_correction");
            limb_final_corrs[instance] = limb_correction;
            aux[instance].push(LeafAuxClaim {
                col: 0,
                point: output.point.clone(),
                value: limb_claim,
            });
            limb_claim
        });
        cx.zero.push(strict_final.sub(combine_auth(&limb_claims)));
        let selector_eval = mapped_selector_eval(rect_points, &coefficients, job, &output.point);
        debug_assert_eq!(selector_eval, output.b_final);
        cx.zero.push(strict_final.scale(selector_eval).sub(output.claim));
        sumchecks.push(output.proof);
    }
    PackedBridgeProof { claim_corrs, sumchecks, strict_final_corrs, limb_final_corrs }
}

fn resident_combined_selector(
    rect_points: &[Vec<Fp2>],
    coefficients: &[Fp2],
    job: usize,
    backend: &mut Backend,
) -> Result<volta_accel::DeviceBuffer<volta_accel::Fp2Repr>, volta_accel::AccelError> {
    let mut combined = None;
    for (point, &coefficient) in rect_points.iter().zip(coefficients) {
        let eq_vocab = match backend.equality_weights_device(&point[..ARGMAX_COL_BITS]) {
            Ok(value) => value,
            Err(error) => {
                if let Some(value) = combined.take() {
                    let _ = backend.free_device(value);
                }
                return Err(error);
            }
        };
        let eq_rows = match backend.equality_weights_device(&point[ARGMAX_COL_BITS..]) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(eq_vocab);
                if let Some(value) = combined.take() {
                    let _ = backend.free_device(value);
                }
                return Err(error);
            }
        };
        let selector = backend.private_argmax_selector_device(
            DeviceSlice::new(&eq_vocab, 0, eq_vocab.len()).expect("argmax vocab equality"),
            DeviceSlice::new(&eq_rows, 0, eq_rows.len()).expect("argmax row equality"),
            job_entries(job),
            job,
            VOCAB,
            coefficient,
        );
        let rows_cleanup = backend.free_device(eq_rows);
        let vocab_cleanup = backend.free_device(eq_vocab);
        let cleanup = rows_cleanup.and(vocab_cleanup);
        let selector = match (selector, cleanup) {
            (Ok(value), Ok(())) => value,
            (Ok(value), Err(error)) => {
                let _ = backend.free_device(value);
                if let Some(value) = combined.take() {
                    let _ = backend.free_device(value);
                }
                return Err(error);
            }
            (Err(error), _) => {
                if let Some(value) = combined.take() {
                    let _ = backend.free_device(value);
                }
                return Err(error);
            }
        };
        if let Some(target) = &combined {
            let add = backend.fp2_add_inplace_device(target, 0, &selector, 0, selector.len());
            let cleanup = backend.free_device(selector);
            match (add, cleanup) {
                (Ok(()), Ok(())) => {}
                (Err(error), _) | (_, Err(error)) => {
                    if let Some(value) = combined.take() {
                        let _ = backend.free_device(value);
                    }
                    return Err(error);
                }
            }
        } else {
            combined = Some(selector);
        }
    }
    combined.ok_or(volta_accel::AccelError::InvalidInput("empty argmax bridge"))
}

fn cleanup_bridge_pairs(
    backend: &mut Backend,
    pairs: impl IntoIterator<Item = (DeviceBuffer<Fp2Repr>, DeviceBuffer<Fp2Repr>)>,
) -> Result<(), volta_accel::AccelError> {
    let mut first = None;
    for (a, b) in pairs {
        for result in [backend.free_device(a), backend.free_device(b)] {
            if first.is_none() {
                first = result.err();
            }
        }
    }
    first.map_or(Ok(()), Err)
}

fn resident_limb_evals(
    resident: &DevicePrivateArgmaxWitness,
    job: usize,
    point: &[Fp2],
    backend: &mut Backend,
) -> Result<[Fp2; LIMBS], volta_accel::AccelError> {
    let weights = backend.equality_weights_device(point)?;
    let offset = if job == 0 { 0 } else { FIRST_JOB_ENTRIES };
    let folded = match backend.matrix_window_fold_device(
        resident.all_lookup_limbs(),
        DeviceSlice::new(&weights, 0, weights.len()).expect("argmax packed equality"),
        LIMBS,
        resident.lookup_entries(),
        offset,
        job_entries(job),
        MatrixFoldAxis::Columns,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(weights);
            return Err(error);
        }
    };
    let weights_cleanup = backend.free_device(weights);
    let values = backend.download_device(&folded, 0, LIMBS);
    let folded_cleanup = backend.free_device(folded);
    match (values, weights_cleanup.err().or(folded_cleanup.err())) {
        (Ok(values), None) => Ok(std::array::from_fn(|index| Fp2::from(values[index]))),
        (Err(error), _) | (_, Some(error)) => Err(error),
    }
}

fn prove_packed_bridge_resident(
    resident: &DevicePrivateArgmaxWitness,
    rect_points: &[Vec<Fp2>],
    rect_claims: &[ProverAuthed],
    aux: &mut [Vec<LeafAuxClaim>; INSTANCES],
    cx: &mut BlockCtxP<'_>,
) -> Result<PackedBridgeProof, volta_accel::AccelError> {
    let backend = cx
        .backend
        .take()
        .ok_or(volta_accel::AccelError::InvalidInput("resident bridge requires backend"))?;
    let result = (|| {
        let coefficients = aggregation_coefficients(cx.tx.challenge_fp2(), rect_points.len());
        let aggregate = rect_claims
            .iter()
            .zip(&coefficients)
            .fold(ProverAuthed::ZERO, |sum, (&claim, &coefficient)| {
                sum.add(claim.scale(coefficient))
            });
        let mut claim_corrs = [Fp2::ZERO; PACKED_JOBS];
        let mut initial = [ProverAuthed::ZERO; PACKED_JOBS];
        let mut jobs_owned = Vec::with_capacity(PACKED_JOBS);
        for job in 0..PACKED_JOBS {
            let source = match resident.packed_strict_job(job) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cleanup_bridge_pairs(backend, jobs_owned);
                    return Err(error);
                }
            };
            let a = match backend.clone_fp2_device(source) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cleanup_bridge_pairs(backend, jobs_owned);
                    return Err(error);
                }
            };
            let b = match resident_combined_selector(rect_points, &coefficients, job, backend) {
                Ok(value) => value,
                Err(error) => {
                    let _ = backend.free_device(a);
                    let _ = cleanup_bridge_pairs(backend, jobs_owned);
                    return Err(error);
                }
            };
            let value = match backend.fp2_dot_device(
                DeviceSlice::new(&a, 0, a.len()).expect("argmax bridge A"),
                DeviceSlice::new(&b, 0, b.len()).expect("argmax bridge B"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cleanup_bridge_pairs(backend, std::iter::once((a, b)));
                    let _ = cleanup_bridge_pairs(backend, jobs_owned);
                    return Err(error);
                }
            };
            let (correction, claim) =
                authenticate_scalar(value, cx, "argmax_packed_bridge_claim_correction");
            claim_corrs[job] = correction;
            initial[job] = claim;
            jobs_owned.push((a, b));
        }
        cx.zero.push(initial[0].add(initial[1]).sub(aggregate));
        let (schedule, bases) = mapping_schedule(&mut cx.doms);
        let jobs = jobs_owned
            .into_iter()
            .enumerate()
            .map(|(job, (a, b))| BlindSumcheckResidentBatchJob {
                site_id: schedule.sites()[job].id,
                a,
                b,
                claim0: initial[job],
                mask_dom_base: bases[job],
            })
            .collect();
        let outputs = match blind_prove_resident_batch(&schedule, jobs, cx.stream, cx.tx, backend) {
            Ok(value) => value,
            Err(error) => {
                if let Some(jobs) = error.into_jobs() {
                    let pairs = jobs.into_iter().map(|job| (job.a, job.b));
                    let _ = cleanup_bridge_pairs(backend, pairs);
                }
                return Err(volta_accel::AccelError::InvalidInput("resident argmax bridge failed"));
            }
        };
        let mut strict_final_corrs = [Fp2::ZERO; PACKED_JOBS];
        let mut limb_final_corrs = [Fp2::ZERO; INSTANCES];
        let mut sumchecks = Vec::with_capacity(PACKED_JOBS);
        for (job, output) in outputs.into_iter().enumerate() {
            let (correction, strict_final) =
                authenticate_scalar(output.a_final, cx, "argmax_packed_bridge_final_correction");
            strict_final_corrs[job] = correction;
            let limb_values = resident_limb_evals(resident, job, &output.point, backend)?;
            let limb_claims: [ProverAuthed; LIMBS] = std::array::from_fn(|limb| {
                let instance = instance_index(limb, job);
                let (limb_correction, limb_claim) = authenticate_scalar(
                    limb_values[limb],
                    cx,
                    "argmax_packed_bridge_limb_correction",
                );
                limb_final_corrs[instance] = limb_correction;
                aux[instance].push(LeafAuxClaim {
                    col: 0,
                    point: output.point.clone(),
                    value: limb_claim,
                });
                limb_claim
            });
            cx.zero.push(strict_final.sub(combine_auth(&limb_claims)));
            let selector_eval =
                mapped_selector_eval(rect_points, &coefficients, job, &output.point);
            debug_assert_eq!(selector_eval, output.b_final);
            cx.zero.push(strict_final.scale(selector_eval).sub(output.claim));
            sumchecks.push(output.proof);
        }
        Ok(PackedBridgeProof { claim_corrs, sumchecks, strict_final_corrs, limb_final_corrs })
    })();
    cx.backend = Some(backend);
    result
}

fn verify_packed_bridge(
    rect_points: &[Vec<Fp2>],
    rect_claims: &[VerifierKey],
    proof: &PackedBridgeProof,
    aux: &mut [Vec<(usize, Vec<Fp2>, VerifierKey)>; INSTANCES],
    cx: &mut BlockCtxV<'_>,
) -> Option<()> {
    if rect_points.len() != rect_claims.len() || proof.sumchecks.len() != PACKED_JOBS {
        return None;
    }
    let coefficients = aggregation_coefficients(cx.tx.challenge_fp2(), rect_points.len());
    let aggregate = rect_claims
        .iter()
        .zip(&coefficients)
        .fold(VerifierKey::ZERO, |sum, (&claim, &coefficient)| sum.add(claim.scale(coefficient)));
    let initial: [VerifierKey; PACKED_JOBS] =
        std::array::from_fn(|job| verify_scalar(proof.claim_corrs[job], cx));
    cx.kzero.push(initial[0].add(initial[1]).sub(aggregate));
    let (schedule, bases) = mapping_schedule(&mut cx.doms);
    let jobs = (0..PACKED_JOBS)
        .map(|job| BlindSumcheckBatchVerifyJob {
            site_id: schedule.sites()[job].id,
            n_vars: job_entries(job).trailing_zeros() as usize,
            claim0: initial[job],
            proof: &proof.sumchecks[job],
            mask_dom_base: bases[job],
        })
        .collect();
    let outputs = blind_verify_batch(&schedule, jobs, cx.ctx, cx.tx)?;
    for (job, output) in outputs.into_iter().enumerate() {
        let strict_final = verify_scalar(proof.strict_final_corrs[job], cx);
        let limb_keys: [VerifierKey; LIMBS] = std::array::from_fn(|limb| {
            let instance = instance_index(limb, job);
            let key = verify_scalar(proof.limb_final_corrs[instance], cx);
            aux[instance].push((0, output.point.clone(), key));
            key
        });
        cx.kzero.push(strict_final.sub(combine_keys(&limb_keys)));
        let selector_eval = mapped_selector_eval(rect_points, &coefficients, job, &output.point);
        cx.kzero.push(strict_final.scale(selector_eval).sub(output.claim));
    }
    Some(())
}

fn logup_domain_span(depth: usize) -> u64 {
    let depth = depth as u64;
    depth * depth.saturating_sub(1) / 2 + 2 * depth + 2
}

fn range_batch_plan(doms: &mut Doms, aux_count: usize) -> LogupBatchPlan {
    let sites = (0..INSTANCES)
        .map(|instance| {
            let (_, job) = instance_limb_job(instance);
            let depth = job_entries(job).trailing_zeros() as usize;
            let mask_dom_base = doms.take(logup_domain_span(depth));
            LogupBatchSite {
                id: SiteId::new(ARGMAX_SECTION.into(), RoundFamily::LogupAux, instance as u32),
                depth,
                column_count: 1,
                aux_claim_count: aux_count,
                mask_dom_base,
            }
        })
        .collect();
    LogupBatchPlan::new(sites).expect("valid C3b packed Range(16) cohort")
}

fn prove_range_batch_host(
    host: &HostPrivateArgmaxWitness,
    mut aux: [Vec<LeafAuxClaim>; INSTANCES],
    cx: &mut BlockCtxP<'_>,
) -> Vec<BlindInstance> {
    let plan = range_batch_plan(&mut cx.doms, aux[0].len());
    let alpha = cx.bank.alpha(TableKey::Range(16));
    let jobs = (0..INSTANCES)
        .map(|instance| {
            let (limb, job) = instance_limb_job(instance);
            let start = if job == 0 { 0 } else { FIRST_JOB_ENTRIES };
            let entries = job_entries(job);
            CpuLogupBatchJob {
                site: plan.sites()[instance].id,
                columns: vec![host.columns[limb][start..start + entries].to_vec()],
                shifts: vec![Some(0)],
                alpha,
                aux_claims: std::mem::take(&mut aux[instance]),
            }
        })
        .collect();
    let outputs = blind_instance_prove_batch_cpu(
        &plan,
        jobs,
        cx.stream,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    )
    .expect("valid C3b CPU Range(16) cohort");
    outputs
        .into_iter()
        .map(|output| {
            cx.bank.push_roots(TableKey::Range(16), output.output.roots);
            output.output.proof
        })
        .collect()
}

fn prove_range_batch_resident(
    resident: &DevicePrivateArgmaxWitness,
    mut aux: [Vec<LeafAuxClaim>; INSTANCES],
    cx: &mut BlockCtxP<'_>,
) -> Result<Vec<BlindInstance>, volta_accel::AccelError> {
    let plan = range_batch_plan(&mut cx.doms, aux[0].len());
    let alpha = cx.bank.alpha(TableKey::Range(16));
    let jobs = (0..INSTANCES)
        .map(|instance| {
            let (limb, job) = instance_limb_job(instance);
            Ok(ResidentLogupBatchJob {
                site: plan.sites()[instance].id,
                columns: resident.lookup_job(limb, job)?,
                column_count: 1,
                entries: job_entries(job),
                shifts: vec![Some(0)],
                alpha,
                aux_claims: std::mem::take(&mut aux[instance]),
            })
        })
        .collect::<Result<Vec<_>, volta_accel::AccelError>>()?;
    let backend = cx
        .backend
        .as_deref_mut()
        .ok_or(volta_accel::AccelError::InvalidInput("resident range batch requires backend"))?;
    let outputs = blind_instance_prove_resident_batch(
        &plan,
        jobs,
        cx.stream,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
        backend,
    )
    .map_err(|_| volta_accel::AccelError::InvalidInput("resident C3b Range(16) cohort failed"))?;
    Ok(outputs
        .into_iter()
        .map(|output| {
            cx.bank.push_roots(TableKey::Range(16), output.output.roots);
            output.output.proof
        })
        .collect())
}

fn prove_private_argmax_host(
    host: HostPrivateArgmaxWitness,
    phases: Vec<PhaseRows>,
    tokens: Vec<(usize, usize)>,
    doms: Doms,
    selected_row_dom: u64,
    selected_row_corr: Vec<u64>,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> PrivateArgmaxOutP {
    let mut cx = BlockCtxP::with_doms(stream, tx, doms, bank);
    let mut aux: [Vec<LeafAuxClaim>; INSTANCES] = std::array::from_fn(|_| Vec::new());
    let mut phase_claim_corrs = Vec::with_capacity(phases.len());
    let mut phase_strict_corrs = Vec::with_capacity(phases.len());
    let mut phase_hadamards = Vec::with_capacity(phases.len());
    let mut bridge_points = Vec::with_capacity(phases.len() + 1);
    let mut bridge_claims = Vec::with_capacity(phases.len() + 1);
    let mut phase_outputs = Vec::with_capacity(phases.len());

    for phase in &phases {
        let tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
        let phase_value = eval_phase_logits(&host, phase, &tau);
        let (phase_corr, phase_claim) =
            authenticate_scalar(phase_value, &mut cx, "argmax_phase_claim_correction");
        phase_claim_corrs.push(phase_corr);
        let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
        let (hadamard, point, logit_claim, mask_claim) = hadamard_prove(
            &tau,
            host.logits.clone(),
            phase_mask_table(phase),
            phase_claim,
            &hadamard_doms,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
        );
        cx.zero.push(mask_claim.sub(ProverAuthed::from_public(eval_phase_mask(phase, &point))));
        let strict_value = eval_fp2_column(&host.strict, &point);
        let (strict_corr, strict_claim) =
            authenticate_scalar(strict_value, &mut cx, "argmax_phase_strict_correction");
        phase_strict_corrs.push(strict_corr);
        bridge_points.push(point.clone());
        bridge_claims.push(strict_claim);
        let c_claim = open_fp_vec_p(
            cx.stream,
            selected_row_dom,
            &host.selected_rows,
            &point[ARGMAX_COL_BITS..],
        );
        let vocab_weight = eq_vec(&point[..ARGMAX_COL_BITS])[..VOCAB]
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        cx.zero.push(
            c_claim
                .scale(vocab_weight)
                .sub(strict_claim)
                .sub(ProverAuthed::from_public(eval_after(&tokens, &point)))
                .sub(logit_claim),
        );
        phase_hadamards.push(hadamard);
        phase_outputs.push(PrivateArgmaxPhaseP {
            tau: tau.clone(),
            claim: phase_claim,
            row_weights: phase_row_weights(phase, &tau[ARGMAX_COL_BITS..]),
        });
    }

    let is_max_tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let is_max_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
    let (is_max_hadamard, is_max_point, strict_hadamard_claim, marker_claim) = hadamard_prove(
        &is_max_tau,
        host.strict.clone(),
        host.is_max.clone(),
        ProverAuthed::ZERO,
        &is_max_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    cx.zero.push(marker_claim.sub(ProverAuthed::from_public(eval_is_max(&tokens, &is_max_point))));
    bridge_points.push(is_max_point);
    bridge_claims.push(strict_hadamard_claim);
    let packed_bridge =
        prove_packed_bridge_host(&host, &bridge_points, &bridge_claims, &mut aux, &mut cx);

    let limb_instances = prove_range_batch_host(&host, aux, &mut cx);
    PrivateArgmaxOutP {
        proof: PrivateArgmaxProof {
            selected_row_corr,
            phase_claim_corrs,
            phase_strict_corrs,
            phase_hadamards,
            is_max_hadamard,
            packed_bridge,
            limb_instances,
        },
        phases: phase_outputs,
        prod: cx.prod,
        zero: cx.zero,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_private_argmax_resident_inner(
    resident: &DevicePrivateArgmaxWitness,
    phases: &[PhaseRows],
    tokens: &[(usize, usize)],
    doms: Doms,
    selected_row_dom: u64,
    selected_row_corr: Vec<u64>,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<PrivateArgmaxOutP, volta_accel::AccelError> {
    let mut cx = BlockCtxP::with_doms_and_backend(stream, tx, doms, bank, backend);
    let mut aux: [Vec<LeafAuxClaim>; INSTANCES] = std::array::from_fn(|_| Vec::new());
    let mut phase_claim_corrs = Vec::with_capacity(phases.len());
    let mut phase_strict_corrs = Vec::with_capacity(phases.len());
    let mut phase_hadamards = Vec::with_capacity(phases.len());
    let mut bridge_points = Vec::with_capacity(phases.len() + 1);
    let mut bridge_claims = Vec::with_capacity(phases.len() + 1);
    let mut phase_outputs = Vec::with_capacity(phases.len());

    for phase in phases {
        let tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
        let row_start = *phase
            .global_rows
            .first()
            .ok_or(volta_accel::AccelError::InvalidInput("empty resident private-argmax phase"))?;
        let backend = cx.backend.as_deref_mut().expect("resident argmax backend");
        let (mask, masked) = backend.private_argmax_phase_factors_device(
            resident.logits(),
            row_start,
            phase.global_rows.len(),
            VOCAB,
        )?;
        let phase_value = backend.mle_eval_device(
            DeviceSlice::new(&masked, 0, masked.len()).expect("argmax masked logits"),
            &tau,
        );
        let masked_cleanup = backend.free_device(masked);
        let phase_value = match (phase_value, masked_cleanup) {
            (Ok(value), Ok(())) => value,
            (Err(error), _) | (_, Err(error)) => {
                let _ = backend.free_device(mask);
                return Err(error);
            }
        };
        let logits = match backend.clone_fp2_device(resident.logits()) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(mask);
                return Err(error);
            }
        };
        let (phase_corr, phase_claim) =
            authenticate_scalar(phase_value, &mut cx, "argmax_phase_claim_correction");
        phase_claim_corrs.push(phase_corr);
        let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
        let (hadamard, point, logit_claim, mask_claim) = hadamard_prove_resident(
            &tau,
            logits,
            mask,
            phase_claim,
            &hadamard_doms,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
            cx.backend.as_deref_mut().expect("resident argmax backend"),
        )?;
        cx.zero.push(mask_claim.sub(ProverAuthed::from_public(eval_phase_mask(phase, &point))));
        let strict_value = cx
            .backend
            .as_deref_mut()
            .expect("resident argmax backend")
            .mle_eval_device(resident.strict(), &point)?;
        let (strict_corr, strict_claim) =
            authenticate_scalar(strict_value, &mut cx, "argmax_phase_strict_correction");
        phase_strict_corrs.push(strict_corr);
        bridge_points.push(point.clone());
        bridge_claims.push(strict_claim);
        let c_claim = open_fp_vec_resident_p(
            cx.stream,
            selected_row_dom,
            resident.selected_rows(),
            &point[ARGMAX_COL_BITS..],
            cx.backend.as_deref_mut().expect("resident argmax backend"),
        )?;
        let vocab_weight = eq_vec(&point[..ARGMAX_COL_BITS])[..VOCAB]
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        cx.zero.push(
            c_claim
                .scale(vocab_weight)
                .sub(strict_claim)
                .sub(ProverAuthed::from_public(eval_after(tokens, &point)))
                .sub(logit_claim),
        );
        phase_hadamards.push(hadamard);
        phase_outputs.push(PrivateArgmaxPhaseP {
            tau: tau.clone(),
            claim: phase_claim,
            row_weights: phase_row_weights(phase, &tau[ARGMAX_COL_BITS..]),
        });
    }

    let is_max_tau: Vec<Fp2> = (0..ARGMAX_VARS).map(|_| cx.tx.challenge_fp2()).collect();
    let strict = cx
        .backend
        .as_deref_mut()
        .expect("resident argmax backend")
        .clone_fp2_device(resident.strict())?;
    let marker = match cx
        .backend
        .as_deref_mut()
        .expect("resident argmax backend")
        .clone_fp2_device(resident.is_max())
    {
        Ok(value) => value,
        Err(error) => {
            let _ = cx.backend.as_deref_mut().expect("resident argmax backend").free_device(strict);
            return Err(error);
        }
    };
    let is_max_doms = HadamardDoms::alloc(&mut cx.doms, ARGMAX_VARS);
    let (is_max_hadamard, is_max_point, strict_hadamard_claim, marker_claim) =
        hadamard_prove_resident(
            &is_max_tau,
            strict,
            marker,
            ProverAuthed::ZERO,
            &is_max_doms,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
            cx.backend.as_deref_mut().expect("resident argmax backend"),
        )?;
    cx.zero.push(marker_claim.sub(ProverAuthed::from_public(eval_is_max(tokens, &is_max_point))));
    bridge_points.push(is_max_point);
    bridge_claims.push(strict_hadamard_claim);
    let packed_bridge =
        prove_packed_bridge_resident(resident, &bridge_points, &bridge_claims, &mut aux, &mut cx)?;

    let limb_instances = prove_range_batch_resident(resident, aux, &mut cx)?;
    Ok(PrivateArgmaxOutP {
        proof: PrivateArgmaxProof {
            selected_row_corr,
            phase_claim_corrs,
            phase_strict_corrs,
            phase_hadamards,
            is_max_hadamard,
            packed_bridge,
            limb_instances,
        },
        phases: phase_outputs,
        prod: cx.prod,
        zero: cx.zero,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
    })
}

pub(crate) fn prove_private_argmax(
    prepared: PrivateArgmaxPreparedP,
    bank: &mut TableBankP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: Option<&mut Backend>,
) -> Result<PrivateArgmaxOutP, volta_accel::AccelError> {
    let PrivateArgmaxPreparedP { witness, doms, selected_row_dom, selected_row_corr } = prepared;
    let PrivateArgmaxWitness { storage, phases, tokens } = witness;
    match storage {
        PrivateArgmaxStorage::Host(host) => Ok(prove_private_argmax_host(
            host,
            phases,
            tokens,
            doms,
            selected_row_dom,
            selected_row_corr,
            bank,
            stream,
            tx,
        )),
        PrivateArgmaxStorage::Resident(resident) => {
            let backend = backend.ok_or(volta_accel::AccelError::InvalidInput(
                "resident private argmax requires backend",
            ))?;
            let result = prove_private_argmax_resident_inner(
                &resident,
                &phases,
                &tokens,
                doms,
                selected_row_dom,
                selected_row_corr,
                bank,
                stream,
                tx,
                backend,
            );
            let cleanup = backend.free_private_argmax_witness(resident);
            match (result, cleanup) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
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
    let mut aux: [Vec<(usize, Vec<Fp2>, VerifierKey)>; INSTANCES] =
        std::array::from_fn(|_| Vec::new());
    let mut phase_outputs = Vec::with_capacity(phases.len());
    let mut bridge_points = Vec::with_capacity(phases.len() + 1);
    let mut bridge_claims = Vec::with_capacity(phases.len() + 1);

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
        let strict_key = verify_scalar(proof.phase_strict_corrs[index], &mut cx);
        bridge_points.push(point.clone());
        bridge_claims.push(strict_key);
        let c_key = open_fp_vec_k(&prepared.selected_row_keys, &point[ARGMAX_COL_BITS..]);
        let vocab_weight = eq_vec(&point[..ARGMAX_COL_BITS])[..VOCAB]
            .iter()
            .copied()
            .fold(Fp2::ZERO, |sum, value| sum + value);
        cx.kzero.push(
            c_key
                .scale(vocab_weight)
                .sub(strict_key)
                .sub(VerifierKey::from_public(eval_after(public_tokens, &point), cx.ctx.delta))
                .sub(logit_key),
        );
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
    bridge_points.push(is_max_point);
    bridge_claims.push(d_key);
    verify_packed_bridge(&bridge_points, &bridge_claims, &proof.packed_bridge, &mut aux, &mut cx)?;

    if aux.iter().any(|claims| claims.len() != aux[0].len()) {
        return None;
    }
    let plan = range_batch_plan(&mut cx.doms, aux[0].len());
    let alpha = cx.bank.alpha(TableKey::Range(16))?;
    let shifts = [Some(0)];
    let jobs = (0..INSTANCES)
        .map(|instance| {
            let (_, job) = instance_limb_job(instance);
            VerifyLogupBatchJob {
                site: plan.sites()[instance].id,
                n_bits: job_entries(job).trailing_zeros() as usize,
                shifts: &shifts,
                alpha,
                proof: &proof.limb_instances[instance],
                aux_claims: &aux[instance],
            }
        })
        .collect();
    let outputs =
        blind_instance_verify_batch(&plan, jobs, cx.ctx, cx.tx, &mut cx.kprod, &mut cx.kzero)
            .ok()?;
    for output in outputs {
        cx.bank.push_kroots(TableKey::Range(16), output.output.kroots);
    }

    Some(PrivateArgmaxOutV { phases: phase_outputs, prod: cx.kprod, zero: cx.kzero })
}

pub(crate) fn phase_layout_from_lengths(
    lengths: &[usize],
) -> Option<(Vec<Vec<usize>>, Vec<usize>)> {
    let total: usize = lengths.iter().sum();
    if total == 0 || total > ARGMAX_PACKED_ROWS {
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
    fn crafted_tie_golden_uses_last_maximum() {
        let mut row = vec![-7i64; VOCAB];
        row[11] = 9;
        row[37] = 9;
        assert_eq!(validate_argmax_row(&row, 37), Some(9));
    }

    #[test]
    fn forged_tie_selecting_earlier_maximum_rejects() {
        let mut row = vec![-7i64; VOCAB];
        row[11] = 9;
        row[37] = 9;
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
    fn packed_domain_matches_preregistered_geometry() {
        assert_eq!(LIMBS, 3);
        assert_eq!(PACKED_JOBS, 2);
        assert_eq!(FIRST_JOB_ENTRIES, 8 * SEGMENT_ENTRIES);
        assert_eq!(SECOND_JOB_ENTRIES, 2 * SEGMENT_ENTRIES);
        assert_eq!(ARGMAX_PACKED_ENTRIES_PER_LIMB, 2_621_440);
        assert_eq!(ARGMAX_REAL_COMPARISONS, 2_512_850);
        assert!(
            100 * ARGMAX_PACKED_ENTRIES_PER_LIMB <= 115 * ARGMAX_REAL_COMPARISONS,
            "padding exceeds the binding 1.15x gate"
        );
        assert_eq!(LIMBS * ARGMAX_PACKED_ENTRIES_PER_LIMB, 7_864_320);
    }

    #[test]
    fn phase_rows_are_global_and_bounded() {
        let (phases, rows) = phase_layout_from_lengths(&[1, 16, 16, 16, 1]).unwrap();
        assert_eq!(phases[0], vec![0]);
        assert_eq!(phases[4], vec![49]);
        assert_eq!(rows, (0..50).collect::<Vec<_>>());
        assert!(phase_layout_from_lengths(&[1, 50]).is_none());
        assert!(phase_layout_from_lengths(&[1, 64]).is_none());
        assert!(phase_layout_from_lengths(&[0, 1]).is_none());
    }
}

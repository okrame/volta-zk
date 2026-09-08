//! Fixed-shape C71 matrix certificate. Counts come from the verifier config.

use super::*;
use crate::c61_whir_reference::{
    c61_max_pruned_binary_siblings, C61MultiProof, C61Reader, C61WhirReferenceError, C61Writer,
    ReferenceResult,
};
use p3_whir_c61::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir_c61::pcs::zk::{BaseCaseZkProof, BlindedMask, MaskOpeningPair, ZkRoundProof};
use p3_whir_c61::ClaimlessZkSumcheckData;

const MAGIC: &[u8; 8] = b"C71MX1\0\0";
pub(super) const MAX_BYTES: usize = 8 << 20;

fn require(ok: bool, message: &str) -> ReferenceResult<()> {
    if ok {
        Ok(())
    } else {
        Err(C61WhirReferenceError::new(message))
    }
}
fn put_e(w: &mut C61Writer, x: E) {
    w.bytes.extend_from_slice(&from_p3(x).to_bytes());
}
fn get_fp3(r: &mut C61Reader<'_>) -> ReferenceResult<Fp3> {
    Fp3::from_bytes(r.take(24)?).map_err(|e| C61WhirReferenceError::new(e.to_string()))
}
fn get_e(r: &mut C61Reader<'_>) -> ReferenceResult<E> {
    get_fp3(r).map(to_p3)
}
fn put_leaf_e(w: &mut C61Writer, x: E) {
    let words: &[Goldilocks] = x.as_basis_coefficients_slice();
    for &x in words {
        w.fp(x);
    }
}
fn get_leaf_e(r: &mut C61Reader<'_>) -> ReferenceResult<E> {
    Ok(E::new([r.fp()?, r.fp()?, r.fp()?]))
}

fn put_open<V: Copy>(
    w: &mut C61Writer,
    opening: &SharedProofOpening<V, C61MultiProof>,
    domain: usize,
    requested: usize,
    width: usize,
    scalar: fn(&mut C61Writer, V),
) -> ReferenceResult<()> {
    let q = domain.min(requested);
    require(
        opening.rows.len() == q && opening.rows.iter().all(|row| row.len() == width),
        "C71 opening shape mismatch",
    )?;
    for row in &opening.rows {
        for &value in row {
            scalar(w, value);
        }
    }
    w.multiproof(&opening.proof, c61_max_pruned_binary_siblings(domain, q))
}
fn get_open<V>(
    r: &mut C61Reader<'_>,
    domain: usize,
    requested: usize,
    width: usize,
    scalar: fn(&mut C61Reader<'_>) -> ReferenceResult<V>,
) -> ReferenceResult<SharedProofOpening<V, C61MultiProof>> {
    let q = domain.min(requested);
    let rows =
        (0..q).map(|_| (0..width).map(|_| scalar(r)).collect()).collect::<ReferenceResult<_>>()?;
    let proof = r.multiproof(c61_max_pruned_binary_siblings(domain, q))?;
    Ok(SharedProofOpening { rows, proof })
}

pub(super) fn header(
    n: usize,
    root: &C61Commitment,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
) -> ReferenceResult<C61Writer> {
    let config = matrix_config(n).map_err(C61WhirReferenceError::new)?;
    matrix_statement(n, root, input, output, attempt, &config)
        .map_err(C61WhirReferenceError::new)?;
    let mut w = C61Writer::default();
    w.bytes.extend_from_slice(MAGIC);
    w.u16(1);
    w.u16(n as u16);
    w.bytes.extend_from_slice(blake3::hash(&gamma(&config)).as_bytes());
    w.commitment(root)?;
    w.bytes.extend_from_slice(&attempt.encode());
    for x in input {
        w.bytes.extend_from_slice(&x.to_le_bytes());
    }
    for y in output {
        w.bytes.extend_from_slice(&y.to_le_bytes());
    }
    Ok(w)
}

pub(super) fn encode(
    n: usize,
    root: &C61Commitment,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
    matrix: &MatrixProof,
) -> ReferenceResult<Vec<u8>> {
    let config = matrix_config(n).map_err(C61WhirReferenceError::new)?;
    let mut w = header(n, root, input, output, attempt)?;
    require(matrix.rounds.len() == config.num_variables / 2, "C71 matrix round count mismatch")?;
    for row in &matrix.rounds {
        for x in row {
            w.bytes.extend_from_slice(&x.to_bytes());
        }
    }
    for x in &matrix.terminal {
        w.bytes.extend_from_slice(&x.to_bytes());
    }
    let proof = &matrix.pcs;
    let batches = config.n_rounds() + 1;
    require(
        proof.sumchecks.len() == batches
            && proof.sumcheck_mask_commitments.len() == batches
            && proof.rounds.len() == config.n_rounds(),
        "C71 PCS batch count mismatch",
    )?;
    for (i, batch) in proof.sumchecks.iter().enumerate() {
        require(
            batch.ell_zk == config.zk.ell_zk
                && batch.pow_witnesses.is_empty()
                && batch.round_coefficients.len() == config.round_folding_factor(i)
                && batch.round_coefficients.iter().all(|r| r.len() == config.zk.ell_zk - 1),
            "C71 PCS sumcheck shape mismatch",
        )?;
        put_e(&mut w, batch.mu_tilde);
        for row in &batch.round_coefficients {
            for &x in row {
                put_e(&mut w, x);
            }
        }
    }
    for root in &proof.sumcheck_mask_commitments {
        w.commitment(root)?;
    }
    for (i, (round, p)) in proof.rounds.iter().zip(&config.round_parameters).enumerate() {
        let width = 1 << config.round_folding_factor(i);
        let domain = p.domain_size / width;
        require(
            round.ood_answers.len() == p.ood_samples && round.pow_witness == Goldilocks::ZERO,
            "C71 PCS round shape mismatch",
        )?;
        w.commitment(&round.commitment)?;
        w.commitment(&round.mask_commitment)?;
        for &x in &round.ood_answers {
            put_e(&mut w, x);
        }
        match &round.openings {
            QueryOpenings::Base(o) if i == 0 => {
                put_open(&mut w, o, domain, p.num_queries, width, C61Writer::fp)?
            }
            QueryOpenings::Extension(o) if i > 0 => {
                put_open(&mut w, o, domain, p.num_queries, width, put_leaf_e)?
            }
            _ => return Err(C61WhirReferenceError::new("C71 PCS opening field mismatch")),
        }
    }
    let b = &proof.base_case;
    let groups = config.mask_groups();
    let last = config.final_round_config();
    require(
        b.fresh_mask_commitments.len() == groups.len()
            && b.mask_openings.len() == groups.len()
            && b.blinded_masks.len() == groups.iter().map(|g| g.width).sum::<usize>()
            && b.blinded_message.len() == 1 << last.num_variables
            && b.blinded_randomness.len() == config.oracle_randomness[config.n_rounds()]
            && b.pow_witness == Goldilocks::ZERO,
        "C71 base-case shape mismatch",
    )?;
    w.commitment(&b.fresh_main_commitment)?;
    for root in &b.fresh_mask_commitments {
        w.commitment(root)?;
    }
    put_e(&mut w, b.masked_claim);
    for &x in b.blinded_message.iter().chain(&b.blinded_randomness) {
        put_e(&mut w, x);
    }
    let mut masks = b.blinded_masks.iter();
    for group in &groups {
        for _ in 0..group.width {
            let mask = masks.next().unwrap();
            require(
                mask.message.len() == group.shape.message_len
                    && mask.randomness.len() == group.shape.randomness_len,
                "C71 blinded mask shape mismatch",
            )?;
            for &x in mask.message.iter().chain(&mask.randomness) {
                put_e(&mut w, x);
            }
        }
    }
    let width = 1 << last.folding_factor;
    let domain = last.domain_size / width;
    match &b.source_openings {
        QueryOpenings::Extension(o) => {
            put_open(&mut w, o, domain, config.final_queries, width, put_leaf_e)?
        }
        _ => return Err(C61WhirReferenceError::new("C71 final oracle must be cubic")),
    }
    put_open(&mut w, &b.fresh_main_openings, domain, config.final_queries, 1, put_leaf_e)?;
    for (pair, group) in b.mask_openings.iter().zip(groups) {
        put_open(
            &mut w,
            &pair.carried,
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            put_leaf_e,
        )?;
        put_open(
            &mut w,
            &pair.fresh,
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            put_leaf_e,
        )?;
    }
    w.bytes.extend_from_slice(&matrix.close_tag.to_bytes());
    require(w.bytes.len() <= MAX_BYTES, "C71 certificate exceeds local byte cap")?;
    Ok(w.bytes)
}

pub(super) fn decode(
    n: usize,
    root: &C61Commitment,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
    bytes: &[u8],
) -> ReferenceResult<MatrixProof> {
    require(bytes.len() <= MAX_BYTES, "C71 certificate exceeds local byte cap")?;
    let config = matrix_config(n).map_err(C61WhirReferenceError::new)?;
    let expected = header(n, root, input, output, attempt)?.bytes;
    let mut r = C61Reader::new(bytes);
    require(r.take(expected.len())? == expected, "C71 statement/header mismatch")?;
    let mut rounds = Vec::new();
    for _ in 0..config.num_variables / 2 {
        rounds.push([get_fp3(&mut r)?, get_fp3(&mut r)?, get_fp3(&mut r)?, get_fp3(&mut r)?]);
    }
    let terminal = [get_fp3(&mut r)?, get_fp3(&mut r)?];
    let mut sumchecks = Vec::new();
    for batch in 0..=config.n_rounds() {
        let mu_tilde = get_e(&mut r)?;
        let round_coefficients = (0..config.round_folding_factor(batch))
            .map(|_| (0..config.zk.ell_zk - 1).map(|_| get_e(&mut r)).collect())
            .collect::<ReferenceResult<_>>()?;
        sumchecks.push(ClaimlessZkSumcheckData {
            mu_tilde,
            ell_zk: config.zk.ell_zk,
            round_coefficients,
            pow_witnesses: Vec::new(),
        });
    }
    let sumcheck_mask_commitments =
        (0..=config.n_rounds()).map(|_| r.commitment()).collect::<ReferenceResult<_>>()?;
    let mut pcs_rounds = Vec::new();
    for (i, p) in config.round_parameters.iter().enumerate() {
        let commitment = r.commitment()?;
        let mask_commitment = r.commitment()?;
        let ood_answers =
            (0..p.ood_samples).map(|_| get_e(&mut r)).collect::<ReferenceResult<_>>()?;
        let width = 1 << config.round_folding_factor(i);
        let domain = p.domain_size / width;
        let openings = if i == 0 {
            QueryOpenings::Base(get_open(&mut r, domain, p.num_queries, width, |r| r.fp())?)
        } else {
            QueryOpenings::Extension(get_open(&mut r, domain, p.num_queries, width, get_leaf_e)?)
        };
        pcs_rounds.push(ZkRoundProof {
            commitment,
            mask_commitment,
            ood_answers,
            pow_witness: Goldilocks::ZERO,
            openings,
        });
    }
    let groups = config.mask_groups();
    let last = config.final_round_config();
    let fresh_main_commitment = r.commitment()?;
    let fresh_mask_commitments =
        (0..groups.len()).map(|_| r.commitment()).collect::<ReferenceResult<_>>()?;
    let masked_claim = get_e(&mut r)?;
    let blinded_message =
        (0..1 << last.num_variables).map(|_| get_e(&mut r)).collect::<ReferenceResult<_>>()?;
    let blinded_randomness = (0..config.oracle_randomness[config.n_rounds()])
        .map(|_| get_e(&mut r))
        .collect::<ReferenceResult<_>>()?;
    let mut blinded_masks = Vec::new();
    for group in &groups {
        for _ in 0..group.width {
            let message = (0..group.shape.message_len)
                .map(|_| get_e(&mut r))
                .collect::<ReferenceResult<_>>()?;
            let randomness = (0..group.shape.randomness_len)
                .map(|_| get_e(&mut r))
                .collect::<ReferenceResult<_>>()?;
            blinded_masks.push(BlindedMask { message, randomness });
        }
    }
    let width = 1 << last.folding_factor;
    let domain = last.domain_size / width;
    let source_openings = QueryOpenings::Extension(get_open(
        &mut r,
        domain,
        config.final_queries,
        width,
        get_leaf_e,
    )?);
    let fresh_main_openings = get_open(&mut r, domain, config.final_queries, 1, get_leaf_e)?;
    let mut mask_openings = Vec::new();
    for group in groups {
        let carried = get_open(
            &mut r,
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            get_leaf_e,
        )?;
        let fresh = get_open(
            &mut r,
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            get_leaf_e,
        )?;
        mask_openings.push(MaskOpeningPair { carried, fresh });
    }
    let close_tag = get_fp3(&mut r)?;
    r.finish()?;
    let base_case = BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness: Goldilocks::ZERO,
        source_openings,
        fresh_main_openings,
        mask_openings,
    };
    Ok(MatrixProof {
        rounds,
        terminal,
        close_tag,
        pcs: ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds: pcs_rounds, base_case },
    })
}

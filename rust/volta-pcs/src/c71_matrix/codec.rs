//! Fixed-shape C71 matrix certificate. Counts come from the verifier config.

use super::*;
use crate::c61_whir_reference::{
    c61_max_pruned_binary_siblings, C61Reader, C61WhirReferenceError, C61Writer, ReferenceResult,
};
use p3_whir_c61::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir_c61::pcs::zk::{BaseCaseZkProof, BlindedMask, MaskOpeningPair, ZkRoundProof};
use p3_whir_c61::ClaimlessZkSumcheckData;

#[cfg(not(feature = "c71-b12-pcs"))]
const MAGIC: &[u8; 8] = b"C71MX1\0\0";
#[cfg(feature = "c71-b12-pcs")]
const MAGIC: &[u8; 8] = b"C71MX2\0\0";
pub(super) const MAX_BYTES: usize = 8 << 20;

pub(super) fn max_bytes(variables: usize) -> usize {
    if cfg!(feature = "c71-b12-pcs") && matches!(variables, 34 | 35) {
        16 << 20
    } else {
        MAX_BYTES
    }
}

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
    opening: &SharedProofOpening<V, MatrixMultiProof>,
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
    #[cfg(feature = "c71-b12-pcs")]
    let proof = {
        require(opening.proof.0.len() == q, "C71 salt query count mismatch")?;
        for matrices in &opening.proof.0 {
            require(matrices.len() == 1 && matrices[0].len() == 4, "C71 salt shape mismatch")?;
            for &salt in &matrices[0] {
                w.fp(salt);
            }
        }
        &opening.proof.1
    };
    #[cfg(not(feature = "c71-b12-pcs"))]
    let proof = &opening.proof;
    w.multiproof(proof, c61_max_pruned_binary_siblings(domain, q))
}
fn get_open<V>(
    r: &mut C61Reader<'_>,
    domain: usize,
    requested: usize,
    width: usize,
    scalar: fn(&mut C61Reader<'_>) -> ReferenceResult<V>,
) -> ReferenceResult<SharedProofOpening<V, MatrixMultiProof>> {
    let q = domain.min(requested);
    let rows =
        (0..q).map(|_| (0..width).map(|_| scalar(r)).collect()).collect::<ReferenceResult<_>>()?;
    #[cfg(feature = "c71-b12-pcs")]
    let salts = (0..q)
        .map(|_| (0..4).map(|_| r.fp()).collect::<ReferenceResult<Vec<_>>>().map(|row| vec![row]))
        .collect::<ReferenceResult<Vec<_>>>()?;
    let proof = r.multiproof(c61_max_pruned_binary_siblings(domain, q))?;
    #[cfg(feature = "c71-b12-pcs")]
    let proof = (salts, proof);
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
    w.u16(if cfg!(feature = "c71-b12-pcs") { 2 } else { 1 });
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
    let w = header(n, root, input, output, attempt)?;
    encode_body(&config, config.num_variables / 2, matrix, w)
}

#[cfg(feature = "c71-b12-pcs")]
pub(super) fn encode_linear(domain: Domain, proof: &MatrixProof) -> ReferenceResult<Vec<u8>> {
    let config = domain.config().map_err(C61WhirReferenceError::new)?;
    encode_body(&config, config.num_variables, proof, C61Writer::default())
}

fn encode_body(
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    rounds: usize,
    matrix: &MatrixProof,
    mut w: C61Writer,
) -> ReferenceResult<Vec<u8>> {
    require(matrix.rounds.len() == rounds, "C71 matrix round count mismatch")?;
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
    require(
        w.bytes.len() <= max_bytes(config.num_variables),
        "C71 certificate exceeds local byte cap",
    )?;
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
    decode_body(&config, config.num_variables / 2, r)
}

#[cfg(feature = "c71-b12-pcs")]
pub(super) fn decode_linear(domain: Domain, bytes: &[u8]) -> ReferenceResult<MatrixProof> {
    let config = domain.config().map_err(C61WhirReferenceError::new)?;
    require(
        bytes.len() <= max_bytes(config.num_variables),
        "C71 certificate exceeds local byte cap",
    )?;
    decode_body(&config, config.num_variables, C61Reader::new(bytes))
}

fn decode_body(
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    round_count: usize,
    mut r: C61Reader<'_>,
) -> ReferenceResult<MatrixProof> {
    let mut rounds = Vec::new();
    for _ in 0..round_count {
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

#[cfg(all(test, feature = "c71-b12-pcs"))]
pub(super) mod tests {
    use super::*;

    // Codec fixtures only: zero fields/roots are not cryptographic proofs.
    fn set_frontiers(
        c: &ZkWhirConfig<E, Goldilocks, Fs>,
        p: &mut MatrixProof,
        mut budget: usize,
    ) -> usize {
        let mut total = 0;
        let mut fill = |hashes: &mut Vec<[u8; 32]>, domain: usize, queries: usize| {
            let count = budget.min(c61_max_pruned_binary_siblings(domain, domain.min(queries)));
            hashes.resize(count, [0; 32]);
            budget -= count;
            total += count;
        };
        for (round, config) in p.pcs.rounds.iter_mut().zip(&c.round_parameters) {
            let hashes = match &mut round.openings {
                QueryOpenings::Base(o) => &mut o.proof.1.sibling_hashes,
                QueryOpenings::Extension(o) => &mut o.proof.1.sibling_hashes,
            };
            fill(hashes, config.domain_size >> config.folding_factor, config.num_queries);
        }
        let last = c.final_round_config();
        let base = &mut p.pcs.base_case;
        let QueryOpenings::Extension(source) = &mut base.source_openings else {
            panic!("final field")
        };
        fill(
            &mut source.proof.1.sibling_hashes,
            last.domain_size >> last.folding_factor,
            c.final_queries,
        );
        fill(
            &mut base.fresh_main_openings.proof.1.sibling_hashes,
            last.domain_size >> last.folding_factor,
            c.final_queries,
        );
        for (pair, group) in base.mask_openings.iter_mut().zip(c.mask_groups()) {
            fill(&mut pair.carried.proof.1.sibling_hashes, group.shape.domain_size, c.mask_queries);
            fill(&mut pair.fresh.proof.1.sibling_hashes, group.shape.domain_size, c.mask_queries);
        }
        total
    }

    #[test]
    fn c71_b12_canonical_pcs_codec_geometry_and_byte_cap() {
        for (h, fixed, upper) in [(35, 6_929_180, 13_941_532), (34, 6_928_316, 13_776_828)] {
            let domain = Domain::Flat(h);
            let c = domain.config().unwrap();
            assert_eq!(gamma(&c).len(), 2_277);
            let bytes = vec![0; fixed];
            let mut p = decode_linear(domain, &bytes).unwrap();
            assert_eq!(encode_linear(domain, &p).unwrap(), bytes);
            assert!(decode_linear(domain, &bytes[..fixed - 1]).is_err());
            assert_eq!(fixed + 32 * set_frontiers(&c, &mut p, usize::MAX), upper);
            let maximal = encode_linear(domain, &p).unwrap();
            assert_eq!(maximal.len(), upper);
            assert!(upper < max_bytes(h));
            assert_eq!(
                encode_linear(domain, &decode_linear(domain, &maximal).unwrap()).unwrap(),
                maximal
            );

            let fits = (MAX_BYTES - fixed) / 32;
            assert_eq!(set_frontiers(&c, &mut p, fits), fits);
            let bounded = encode_linear(domain, &p).unwrap();
            assert_eq!(bounded.len(), fixed + 32 * fits);
            assert_eq!(
                encode_linear(domain, &decode_linear(domain, &bounded).unwrap()).unwrap(),
                bounded
            );
            assert_eq!(set_frontiers(&c, &mut p, fits + 1), fits + 1);
            assert_eq!(encode_linear(domain, &p).unwrap().len(), fixed + 32 * (fits + 1));
            assert!(decode_linear(domain, &vec![0; max_bytes(h) + 1]).is_err());
            set_frontiers(&c, &mut p, usize::MAX);
            let QueryOpenings::Base(first) = &mut p.pcs.rounds[0].openings else {
                panic!("first field")
            };
            first.proof.1.sibling_hashes.push([0; 32]);
            assert!(encode_linear(domain, &p).unwrap_err().to_string().contains("frontier bound"));
        }
        assert_eq!(max_bytes(12), MAX_BYTES);
        assert_eq!(max_bytes(14), MAX_BYTES);
    }

    pub(in crate::c71_matrix) fn maximal_linear_fixture(h: usize) -> Vec<u8> {
        let fixed = match h {
            35 => 6_929_180,
            34 => 6_928_316,
            _ => panic!("canonical fixture domain"),
        };
        let domain = Domain::Flat(h);
        let mut proof = decode_linear(domain, &vec![0; fixed]).unwrap();
        set_frontiers(&domain.config().unwrap(), &mut proof, usize::MAX);
        encode_linear(domain, &proof).unwrap()
    }
}

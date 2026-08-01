//! In-memory CPU differential for the C6.1 claimless-affine WHIR fork.
//!
//! This feature-gated module connects the reviewed fork boundary to C6AWH1
//! without implementing a production backend or codec.  The opening target
//! is authenticated before the native proof, never serialized, propagated as
//! a public affine form by both roles, and closed by one designated ZeroOpen.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir_c61::pcs::zk::{
    BaseCaseClaimlessClosure, HidingWhirProver, HidingWhirVerifier, ZkParameters, ZkWhirConfig,
    ZkWhirProof,
};
use p3_whir_c61::ClaimlessAffineClaim;
use rand_010::rngs::StdRng;
use rand_010::SeedableRng;
use volta_field::{Fp2, P};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

use crate::c61_authenticated_whir::{
    finish_c61_authenticated_whir_base, prepare_c61_authenticated_whir_mask,
    verify_c61_authenticated_whir_base, C61AuthenticatedWhirAffineClaim,
    C61AuthenticatedWhirMaskRange, C61AuthenticatedWhirProverClosure,
    C61AuthenticatedWhirProverFinishInput, C61AuthenticatedWhirVerifierInput,
};
use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};
use crate::c61_whir_reference::{
    c61_p3_fp2_from_volta, c61_reference_mmcs, c61_volta_fp2_from_p3, C61Commitment,
    C61InteractiveChallenger, C61Mmcs, C61P3Fp2, C61_WHIRA1_ELL_ZK, C61_WHIRA1_INITIAL_FOLD,
    C61_WHIRA1_LATER_FOLD, C61_WHIRA1_MASK_LOG_INV_RATE, C61_WHIRA1_STARTING_LOG_INV_RATE,
};

pub const C61_AUTHENTICATED_P3_SECURITY_BITS: usize = 75;
pub const C61_AUTHENTICATED_P3_REVISION: &str =
    "66e290615de1858f2f2f6a804158064c406cda1c+c61-claimless-affine-v1";

type C61AuthenticatedP3Proof = ZkWhirProof<Goldilocks, C61P3Fp2, C61Mmcs>;

#[derive(Debug)]
pub struct C61AuthenticatedP3Diagnostic {
    pub num_variables: usize,
    pub provider_affine: C61AuthenticatedWhirAffineClaim,
    pub verifier_affine: C61AuthenticatedWhirAffineClaim,
    pub provider_transcript_bytes: u64,
    pub verifier_transcript_bytes: u64,
    pub provider_ledger: BTreeMap<&'static str, u64>,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub proof_has_clear_evaluation_field: bool,
    pub full_correlations: u64,
}

#[derive(Clone)]
struct C61AuthenticatedP3Artifact {
    commitment: C61Commitment,
    proof: C61AuthenticatedP3Proof,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    provider_closure: C61AuthenticatedWhirProverClosure,
    provider_transcript_bytes: u64,
    provider_ledger: BTreeMap<&'static str, u64>,
}

fn c61_authenticated_config<Challenger>(
    num_variables: usize,
) -> Result<ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>, String>
where
    Challenger: FieldChallenger<Goldilocks> + GrindingChallenger<Witness = Goldilocks>,
{
    ZkWhirConfig::new(
        num_variables,
        ProtocolParameters {
            security_level: C61_AUTHENTICATED_P3_SECURITY_BITS,
            pow_bits: 0,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::ConstantFromSecondRound(
                C61_WHIRA1_INITIAL_FOLD,
                C61_WHIRA1_LATER_FOLD,
            ),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: C61_WHIRA1_STARTING_LOG_INV_RATE,
        },
        ZkParameters { ell_zk: C61_WHIRA1_ELL_ZK, mask_log_inv_rate: C61_WHIRA1_MASK_LOG_INV_RATE },
    )
    .map_err(|error| error.to_string())
}

fn affine_from_p3(claim: ClaimlessAffineClaim<C61P3Fp2>) -> C61AuthenticatedWhirAffineClaim {
    C61AuthenticatedWhirAffineClaim {
        coefficient: c61_volta_fp2_from_p3(claim.coefficient),
        constant: c61_volta_fp2_from_p3(claim.constant),
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedP3Artifact, u64), String> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err("C6AWH1-P3 witness/point dimension mismatch".to_owned());
    }
    let evaluation_p3 = witness.eval_base(&point);
    let evaluation = c61_volta_fp2_from_p3(evaluation_p3);
    let target = ProverAuthed::new(evaluation, target_tag);
    let target_key = VerifierKey::new(target_tag + delta * evaluation);

    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = StdRng::seed_from_u64(prover_rng_seed);
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);

    // The low-level fork deliberately has no target-revealing PCS adapter.
    // Reproduce its load-bearing statement order explicitly: root first,
    // then the verifier-owned opening point, then the first native challenge.
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    let mut correlations = CorrelationStream::new(pcg_seed);
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
        .map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), evaluation_p3)],
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
    drop(challenger);

    let provider_affine = affine_from_p3(output.target);
    let final_target = provider_affine.authenticate_prover(target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;

    Ok((
        C61AuthenticatedP3Artifact {
            commitment,
            proof: output.proof,
            point,
            target_key,
            provider_affine,
            provider_base_case: output.base_case,
            provider_closure,
            provider_transcript_bytes: transcript.total_bytes(),
            provider_ledger: transcript.ledger().clone(),
        },
        correlations.counters.full_corrs,
    ))
}

fn verify_diagnostic(
    artifact: &C61AuthenticatedP3Artifact,
    verifier_seed: [u8; 32],
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedWhirAffineClaim, Transcript), String> {
    let num_variables = artifact.point.num_variables();
    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(artifact.commitment.clone());
    challenger.observe_public_point(&artifact.point).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(
            &artifact.proof,
            &artifact.commitment,
            std::slice::from_ref(&artifact.point),
            &mut challenger,
        )
    }))
    .map_err(|_| "C6AWH1-P3 fork verifier panicked".to_owned())?
    .map_err(|error| format!("C6AWH1-P3 verification failed: {error}"))?;
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
    drop(challenger);

    let verifier_affine = affine_from_p3(result.target);
    if verifier_affine != artifact.provider_affine {
        return Err("C6AWH1-P3 provider/verifier affine replay mismatch".to_owned());
    }
    if result.base_case != artifact.provider_base_case {
        return Err("C6AWH1-P3 provider/verifier base closure mismatch".to_owned());
    }
    let final_key = verifier_affine.derive_verifier_key(artifact.target_key, delta);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        artifact.provider_closure.proof,
        &mut context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok((verifier_affine, transcript))
}

/// Run one reference-only end-to-end differential.  Small dimensions are
/// diagnostic; D27/D28 remain the only production-profile shapes.
pub fn run_c61_authenticated_whir_p3_diagnostic(
    num_variables: usize,
) -> Result<C61AuthenticatedP3Diagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWH1-P3 diagnostic dimension must be in 4..=28".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(17).wrapping_add(3)))
            .collect(),
    );
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(19).wrapping_add(5)))
            .collect(),
    );
    let verifier_seed = [0x61; 32];
    let pcg_seed = [0xA7; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 17), volta_field::Fp::new(0x1234_5678));
    let target_tag = Fp2::new(volta_field::Fp::new(41), volta_field::Fp::new(43));
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 1, range_start: 40_000 };
    let (artifact, full_correlations) = prove_diagnostic(
        witness,
        point,
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
    )?;
    let (verifier_affine, verifier_transcript) =
        verify_diagnostic(&artifact, verifier_seed, pcg_seed, delta, id, mask_range)?;
    if artifact.provider_ledger != *verifier_transcript.ledger() {
        return Err("C6AWH1-P3 provider/verifier transcript ledger mismatch".to_owned());
    }
    Ok(C61AuthenticatedP3Diagnostic {
        num_variables,
        provider_affine: artifact.provider_affine,
        verifier_affine,
        provider_transcript_bytes: artifact.provider_transcript_bytes,
        verifier_transcript_bytes: verifier_transcript.total_bytes(),
        provider_ledger: artifact.provider_ledger,
        verifier_ledger: verifier_transcript.ledger().clone(),
        proof_has_clear_evaluation_field: false,
        full_correlations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_claimless_affine_whir_closes_through_designated_mac() {
        let report = run_c61_authenticated_whir_p3_diagnostic(14).unwrap();
        assert_eq!(report.provider_affine, report.verifier_affine);
        assert_eq!(report.provider_ledger, report.verifier_ledger);
        assert_eq!(report.provider_transcript_bytes, report.verifier_transcript_bytes);
        assert!(!report.proof_has_clear_evaluation_field);
        assert_eq!(report.full_correlations, 1);
    }

    #[test]
    fn fork_source_guard_has_no_eval_field_or_clear_claim_replay() {
        let proof = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/proof.rs");
        let prover = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs");
        let verifier = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/verifier/mod.rs");
        let sumcheck = include_str!("../../third_party/p3-sumcheck-c61/src/zk/prover/residual.rs");
        let adapter = include_str!("c61_authenticated_whir_p3.rs");
        let production_adapter = adapter.split("#[cfg(test)]").next().unwrap();
        assert!(!proof.contains("pub evals:"));
        assert_eq!(prover.matches("into_zk_sumcheck_claimless(").count(), 2);
        assert!(verifier.contains("verify_affine_claim"));
        assert!(sumcheck.contains("into_zk_sumcheck_claimless"));
        assert!(sumcheck.contains("aux_claim,\n            false,"));
        assert_eq!(
            production_adapter.matches("C61InteractiveChallenger::new_claimless(").count(),
            2
        );
        assert_eq!(production_adapter.matches(".observe_public_point(").count(), 2);
        assert_eq!(production_adapter.matches(".ensure_public_statement_bound()").count(), 2);

        let mut transcript = Transcript::new([0x31; 32]);
        let challenger = C61InteractiveChallenger::new_claimless(&mut transcript, 4);
        assert!(challenger.ensure_public_statement_bound().is_err());
    }

    fn mutation_fixture() -> (
        C61AuthenticatedP3Artifact,
        [u8; 32],
        [u8; 32],
        Fp2,
        C61NativeChainId,
        C61AuthenticatedWhirMaskRange,
    ) {
        let num_variables = 14;
        let witness = Poly::new(
            (0..(1usize << num_variables))
                .map(|index| Goldilocks::from_u64((index as u64) * 13 + 7))
                .collect(),
        );
        let point = Point::new(
            (0..num_variables).map(|index| C61P3Fp2::from_u64(index as u64 * 23 + 11)).collect(),
        );
        let verifier_seed = [0x72; 32];
        let pcg_seed = [0xB8; 32];
        let delta = Fp2::new(volta_field::Fp::new(P - 29), volta_field::Fp::new(991));
        let id = C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 };
        let mask_range =
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 9, range_start: 50_000 };
        let (artifact, _) = prove_diagnostic(
            witness,
            point,
            verifier_seed,
            0xC6_2002,
            pcg_seed,
            delta,
            Fp2::new(volta_field::Fp::new(47), volta_field::Fp::new(53)),
            id,
            mask_range,
        )
        .unwrap();
        (artifact, verifier_seed, pcg_seed, delta, id, mask_range)
    }

    #[test]
    fn target_key_transcript_point_and_base_mutations_fail_closed() {
        let (artifact, verifier_seed, pcg_seed, delta, id, mask_range) = mutation_fixture();

        let mut bad_key = artifact.clone();
        bad_key.target_key.k += Fp2::ONE;
        assert!(
            verify_diagnostic(&bad_key, verifier_seed, pcg_seed, delta, id, mask_range,).is_err()
        );

        let mut bad_base = artifact.clone();
        bad_base.proof.base_case.masked_claim += C61P3Fp2::ONE;
        assert!(
            verify_diagnostic(&bad_base, verifier_seed, pcg_seed, delta, id, mask_range,).is_err()
        );

        let mut bad_point = artifact.clone();
        let mut coordinates = bad_point.point.as_slice().to_vec();
        coordinates[0] += C61P3Fp2::ONE;
        bad_point.point = Point::new(coordinates);
        assert!(
            verify_diagnostic(&bad_point, verifier_seed, pcg_seed, delta, id, mask_range,).is_err()
        );

        let mut wrong_seed = verifier_seed;
        wrong_seed[0] ^= 1;
        assert!(verify_diagnostic(&artifact, wrong_seed, pcg_seed, delta, id, mask_range,).is_err());

        let mut wrong_range = mask_range;
        wrong_range.range_start += 3;
        assert!(
            verify_diagnostic(&artifact, verifier_seed, pcg_seed, delta, id, wrong_range,).is_err()
        );
    }
}

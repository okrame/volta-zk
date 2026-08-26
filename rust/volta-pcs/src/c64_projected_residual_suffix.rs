//! C6.4 pre-challenge commitment boundary for the compact residual PCS.

use volta_field::Fp2;
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use volta_mac::ProverAuthed;
use volta_mac::Transcript;
use volta_proto::mle::eq_vec;

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c64_joint_residual_sketch::C64ProjectedResidualGpuOwner;
use crate::c64_joint_residual_sketch::{C64_RESIDUAL_AUXILIARY_TABLES, C64_RESIDUAL_LEAF_TABLES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64ProjectedResidualWeights {
    leaf: [Fp2; C64_RESIDUAL_LEAF_TABLES],
    auxiliary: [Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
}

impl C64ProjectedResidualWeights {
    pub fn leaf(&self) -> &[Fp2; C64_RESIDUAL_LEAF_TABLES] {
        &self.leaf
    }

    pub fn auxiliary(&self) -> &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES] {
        &self.auxiliary
    }
}

pub fn draw_c64_projected_residual_weights(
    binding_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<C64ProjectedResidualWeights, String> {
    if binding_digest == [0; 32] || !transcript.is_fiat_shamir() {
        return Err("C6.4 projected residual binding or transcript differs".to_owned());
    }
    transcript.absorb_public_message("c64_projected_residual_binding", &binding_digest);
    let leaf_point: [Fp2; 3] = std::array::from_fn(|_| transcript.challenge_fp2());
    let auxiliary_point: [Fp2; 4] = std::array::from_fn(|_| transcript.challenge_fp2());
    Ok(C64ProjectedResidualWeights {
        leaf: eq_vec(&leaf_point)
            .try_into()
            .map_err(|_| "C6.4 leaf-column weight census differs".to_owned())?,
        auxiliary: eq_vec(&auxiliary_point)
            .try_into()
            .map_err(|_| "C6.4 auxiliary-column weight census differs".to_owned())?,
    })
}

pub fn replay_c64_projected_residual_precommit(
    binding_digest: [u8; 32],
    roots: [[u8; 32]; 6],
    transcript: &mut Transcript,
) -> Result<C64ProjectedResidualWeights, String> {
    if roots.contains(&[0; 32]) {
        return Err("C6.4 projected residual root is empty".to_owned());
    }
    let weights = draw_c64_projected_residual_weights(binding_digest, transcript)?;
    transcript.absorb_public_message(
        "c64_projected_residual_roots",
        &roots.iter().flatten().copied().collect::<Vec<_>>(),
    );
    Ok(weights)
}

pub(crate) fn draw_c64_projected_residual_postclaim_challenges(
    roots: [[u8; 32]; 6],
    pending_digest: [u8; 32],
    source_statement_digest: [u8; 32],
    transcript: &mut Transcript,
) -> Result<(Fp2, [Fp2; 3]), String> {
    if !transcript.is_fiat_shamir()
        || [pending_digest, source_statement_digest].contains(&[0; 32])
        || roots.contains(&[0; 32])
    {
        return Err("C6.4 projected residual postclaim binding differs".to_owned());
    }
    let mut binding = Vec::with_capacity(6 * 32 + 64);
    for root in roots {
        binding.extend_from_slice(&root);
    }
    binding.extend_from_slice(&pending_digest);
    binding.extend_from_slice(&source_statement_digest);
    transcript.absorb_public_message("c64_projected_residual_postclaim", &binding);
    let correction_beta = transcript.challenge_fp2();
    let batch_alphas = std::array::from_fn(|_| transcript.challenge_fp2());
    if correction_beta == Fp2::ZERO || batch_alphas.contains(&Fp2::ZERO) {
        return Err("C6.4 projected residual batching challenge is zero".to_owned());
    }
    Ok((correction_beta, batch_alphas))
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C64ProjectedResidualPrecommit {
    pub(crate) backend: std::sync::Arc<std::sync::Mutex<volta_accel::Backend>>,
    pub(crate) weights: C64ProjectedResidualWeights,
    pub(crate) roots: [[u8; 32]; 6],
    pub(crate) lanes: [[Option<crate::c63_preencoded_whir::C63ResidentSystematicPrepared>; 2]; 3],
    pub(crate) correction_message: Option<volta_accel::DeviceBuffer<volta_accel::Fp2Repr>>,
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
impl Drop for C64ProjectedResidualPrecommit {
    fn drop(&mut self) {
        if let Some(message) = self.correction_message.take() {
            if let Ok(mut backend) = self.backend.lock() {
                let _ = backend.free_device(message);
            }
        }
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub(crate) struct C64ProjectedResidualProverOutput {
    pub(crate) artifacts: [[Vec<u8>; 2]; 3],
    pub(crate) mask_corrections: [[[Fp2; 2]; 2]; 3],
    pub(crate) terminal_proofs:
        [[crate::c61_authenticated_whir::C61AuthenticatedWhirBaseProof; 2]; 3],
    pub(crate) correction_link: crate::c63_sparse_h_closure::C63SparseHClosureProof,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub(crate) struct C64ProjectedResidualVerifierOutput {
    pub(crate) correction_audit: crate::c63_sparse_h_closure::C63SparseHTapeClosureReferenceAudit,
}

pub fn c64_projected_residual_binding_digest(
    fixed_roots_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
    relation_digest: [u8; 32],
    source_binding_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if [fixed_roots_digest, outer_statement_digest, relation_digest, source_binding_digest]
        .contains(&[0; 32])
    {
        return Err("C6.4 projected residual public binding is empty".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/projected-residual-binding/v1");
    hasher.update(&fixed_roots_digest);
    hasher.update(&outer_statement_digest);
    hasher.update(&relation_digest);
    hasher.update(&source_binding_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c64_projected_residual_precommit<R: rand_010::Rng>(
    mmcs: &crate::c62_gpu_whir::C62GpuMmcs,
    binding_digest: [u8; 32],
    leaf: &volta_proto::C6PairedResidualLeafWitness,
    closure: &volta_proto::C6PairedResidualClosureWitness,
    auxiliary: &volta_proto::C6PairedResidualAuxiliaryWitness,
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<C64ProjectedResidualPrecommit, String> {
    use crate::c63_preencoded_whir::prepare_c63_resident_systematic_limb;
    use crate::c64_whir_profile::{
        c64_projected_residual_whir_config, C64_AUXILIARY_VARIABLES, C64_CORRECTION_VARIABLES,
        C64_INPUT_VARIABLES,
    };

    let weights = draw_c64_projected_residual_weights(binding_digest, transcript)?;
    let backend = mmcs.backend();
    let mut owner = C64ProjectedResidualGpuOwner::build_production(
        mmcs,
        weights.leaf(),
        weights.auxiliary(),
        leaf,
        closure,
        auxiliary,
    )?;
    let leaf_config = c64_projected_residual_whir_config(C64_INPUT_VARIABLES)?;
    let correction_config = c64_projected_residual_whir_config(C64_CORRECTION_VARIABLES)?;
    let auxiliary_config = c64_projected_residual_whir_config(C64_AUXILIARY_VARIABLES)?;
    let leaf_folding = leaf_config.round_folding_factor(0);
    let correction_folding = correction_config.round_folding_factor(0);
    let auxiliary_folding = auxiliary_config.round_folding_factor(0);
    let leaf_mmcs = mmcs
        .sequential_fresh_lane(
            C64_INPUT_VARIABLES,
            leaf_folding,
            leaf_config.starting_log_inv_rate,
            3,
        )
        .map_err(|error| error.to_string())?;
    let auxiliary_mmcs = mmcs
        .sequential_fresh_lane(
            C64_AUXILIARY_VARIABLES,
            auxiliary_folding,
            auxiliary_config.starting_log_inv_rate,
            2,
        )
        .map_err(|error| error.to_string())?;
    let correction_mmcs = mmcs
        .sequential_fresh_lane(
            C64_CORRECTION_VARIABLES,
            correction_folding,
            correction_config.starting_log_inv_rate,
            5,
        )
        .map_err(|error| error.to_string())?;
    let contexts: [[[u8; 32]; 2]; 3] = std::array::from_fn(|family| {
        std::array::from_fn(|limb| {
            c64_residual_limb_context(binding_digest, &weights, family, limb)
        })
    });
    let mut lanes = std::array::from_fn(|_| std::array::from_fn(|_| None));
    let mut roots = [[0u8; 32]; 6];
    for family in 0..3 {
        for limb in 0..2 {
            let (lane_mmcs, config, message) = match family {
                0 => (leaf_mmcs.clone(), &leaf_config, owner.take_leaf_other_limb(limb)?),
                1 => (
                    correction_mmcs.clone(),
                    &correction_config,
                    owner.take_leaf_correction_limb(limb)?,
                ),
                _ => (auxiliary_mmcs.clone(), &auxiliary_config, owner.take_auxiliary_limb(limb)?),
            };
            let prepared = prepare_c63_resident_systematic_limb(
                lane_mmcs,
                config,
                message,
                contexts[family][limb],
                rng,
            )?;
            roots[family * 2 + limb] = prepared.root();
            lanes[family][limb] = Some(prepared);
        }
    }
    transcript.absorb_public_message(
        "c64_projected_residual_roots",
        &roots.iter().flatten().copied().collect::<Vec<_>>(),
    );
    let correction_message = owner.take_correction_message()?;
    Ok(C64ProjectedResidualPrecommit {
        backend,
        weights,
        roots,
        lanes,
        correction_message: Some(correction_message),
    })
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_c64_projected_residual_precommit<R: rand_010::Rng>(
    mut precommit: C64ProjectedResidualPrecommit,
    projected_pending: [[[ProverAuthed; 2]; 2]; 3],
    correction_pending: [[[ProverAuthed; 2]; 2]; 2],
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    correction_link_point: &[Fp2],
    correction_link_targets: [ProverAuthed; 2],
    correction_link: crate::c63_sparse_h_closure::C63SparseHClosureProof,
    batch_alphas: [Fp2; 3],
    mask_range: crate::c61_authenticated_whir::C64AuthenticatedWhirMaskRange,
    streams: &mut [volta_mac::CorrelationStream; 2],
    rng: &mut R,
) -> Result<C64ProjectedResidualProverOutput, String> {
    use crate::c61_authenticated_whir::{
        finish_c64_shared_authenticated_whir_limb_pair,
        prepare_c64_shared_authenticated_whir_limb_pair, C64ProjectedResidualFamily,
    };

    if leaf_points.iter().any(|point| point.len() != 23)
        || auxiliary_points.iter().any(|point| point.len() != 15)
        || correction_link_point.len() != 24
    {
        return Err("C6.4 projected residual opening points differ".to_owned());
    }
    let families = [
        C64ProjectedResidualFamily::LeafOther,
        C64ProjectedResidualFamily::LeafCorrection,
        C64ProjectedResidualFamily::Auxiliary,
    ];
    let mut artifacts: [[Option<Vec<u8>>; 2]; 3] =
        std::array::from_fn(|_| std::array::from_fn(|_| None));
    let mut mask_corrections = [[[Fp2::ZERO; 2]; 2]; 3];
    let mut terminal_proofs =
        [[crate::c61_authenticated_whir::C61AuthenticatedWhirBaseProof::decode(&[0; 16])
            .map_err(|error| error.to_string())?; 2]; 3];

    for (family_index, family) in families.into_iter().enumerate() {
        let mut owned_points = match family {
            C64ProjectedResidualFamily::LeafOther => {
                leaf_points.iter().map(|point| point.to_vec()).collect::<Vec<_>>()
            }
            C64ProjectedResidualFamily::Auxiliary => {
                auxiliary_points.iter().map(|point| point.to_vec()).collect::<Vec<_>>()
            }
            C64ProjectedResidualFamily::LeafCorrection => {
                let mut points = Vec::with_capacity(5);
                for point in leaf_points {
                    for selector in [Fp2::ZERO, Fp2::ONE] {
                        let mut point = point.to_vec();
                        point.push(selector);
                        points.push(point);
                    }
                }
                points.push(correction_link_point.to_vec());
                points
            }
        };
        let shared = prepare_c64_shared_authenticated_whir_limb_pair(family, mask_range, streams)
            .map_err(|error| error.to_string())?;
        mask_corrections[family_index] = shared.corrections();
        let masks = shared.values();
        let mut limb_outputs = Vec::with_capacity(2);
        for limb in 0..2 {
            let lane = precommit.lanes[family_index][limb]
                .take()
                .ok_or_else(|| "C6.4 projected residual lane is absent".to_owned())?;
            let values = owned_points
                .iter()
                .map(|point| lane.evaluate(point))
                .collect::<Result<Vec<_>, _>>()?;
            let claims = owned_points
                .iter()
                .zip(&values)
                .map(|(point, &value)| (point.as_slice(), value))
                .collect::<Vec<_>>();
            limb_outputs.push(lane.finish_many_with_batch_alpha(
                &claims,
                masks[limb],
                batch_alphas[family_index],
                rng,
            )?);
        }
        if limb_outputs[0].claim_weights != limb_outputs[1].claim_weights {
            return Err("C6.4 projected residual limb batch weights differ".to_owned());
        }
        let weights = &limb_outputs[0].claim_weights;
        let expected_targets: [volta_mac::ProverAuthed; 2] =
            std::array::from_fn(|tape| match family {
                C64ProjectedResidualFamily::LeafOther | C64ProjectedResidualFamily::Auxiliary => {
                    projected_pending[family_index][0][tape]
                        .scale(weights[0])
                        .add(projected_pending[family_index][1][tape].scale(weights[1]))
                }
                C64ProjectedResidualFamily::LeafCorrection => correction_pending[0][0][tape]
                    .scale(precommit.weights.leaf[3] * weights[0])
                    .add(
                        correction_pending[0][1][tape]
                            .scale(precommit.weights.leaf[6] * weights[1]),
                    )
                    .add(
                        correction_pending[1][0][tape]
                            .scale(precommit.weights.leaf[3] * weights[2]),
                    )
                    .add(
                        correction_pending[1][1][tape]
                            .scale(precommit.weights.leaf[6] * weights[3]),
                    )
                    .add(correction_link_targets[tape].scale(weights[4])),
            });
        let mut transcripts = std::array::from_fn(|tape| {
            Transcript::new_fiat_shamir(c64_residual_auth_context(
                precommit.roots,
                family_index,
                tape,
                batch_alphas[family_index],
            ))
            .expect("nonzero C6.4 residual authentication context")
        });
        let normalized = [limb_outputs[0].normalized, limb_outputs[1].normalized];
        let closures = finish_c64_shared_authenticated_whir_limb_pair(
            shared,
            normalized,
            expected_targets,
            &mut transcripts,
        )
        .map_err(|error| error.to_string())?;
        for limb in 0..2 {
            artifacts[family_index][limb] = Some(std::mem::take(&mut limb_outputs[limb].artifact));
        }
        terminal_proofs[family_index] = closures.map(|closure| closure.proof);
        owned_points.clear();
    }
    Ok(C64ProjectedResidualProverOutput {
        artifacts: artifacts.map(|family| family.map(|artifact| artifact.expect("C6.4 artifact"))),
        mask_corrections,
        terminal_proofs,
        correction_link,
    })
}

fn c64_residual_auth_context(
    roots: [[u8; 32]; 6],
    family: usize,
    tape: usize,
    batch_alpha: Fp2,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/residual-auth-context/v1");
    for root in roots {
        hasher.update(&root);
    }
    hasher.update(&[family as u8, tape as u8]);
    hasher.update(&batch_alpha.c0.value().to_le_bytes());
    hasher.update(&batch_alpha.c1.value().to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "c61-p3-authenticated-reference")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c64_projected_residual(
    frame: &crate::c64_projected_residual_codec::C64ProjectedResidualFrame,
    precommit_binding_digest: [u8; 32],
    fixed_roots_digest: [u8; 32],
    nbr2_statement_digest: [u8; 32],
    weights: C64ProjectedResidualWeights,
    pending: &crate::c6_residual_sumcheck_blind::C6BlindResidualPendingClaimsVerifier,
    leaf_points: [&[Fp2]; 2],
    auxiliary_points: [&[Fp2]; 2],
    source_claims: &crate::c6_authenticated_output_link::C63ResidualSourceFunctionalVerifierClaims,
    correction_beta: Fp2,
    batch_alphas: [Fp2; 3],
    mask_range: crate::c61_authenticated_whir::C64AuthenticatedWhirMaskRange,
    contexts: &mut [volta_mac::VerifierCtx; 2],
    transcript: &mut Transcript,
) -> Result<C64ProjectedResidualVerifierOutput, String> {
    use crate::c61_authenticated_whir::{
        verify_c64_shared_authenticated_whir_limb_pair, C64ProjectedResidualFamily,
    };
    use crate::c63_preencoded_whir::verify_c64_whir_ordinary_artifact_with_config_at_many_points_with_batch_alpha_and_root;
    use crate::c64_whir_profile::{
        c64_projected_residual_whir_config, C64_AUXILIARY_VARIABLES, C64_CORRECTION_VARIABLES,
        C64_INPUT_VARIABLES,
    };

    let pending_digest =
        crate::c64_joint_residual_sketch::c64_projected_pending_digest_verifier(pending)?;
    let coefficients = [
        source_claims.statement().coefficients(0).map_err(|error| error.to_string())?,
        source_claims.statement().coefficients(1).map_err(|error| error.to_string())?,
    ];
    let coefficient_digest = crate::c63_sparse_h_closure::c64_correction_link_coefficient_digest(
        coefficients,
        correction_beta,
        1 << 23,
    )
    .map_err(|error| error.to_string())?;
    let mut binding = blake3::Hasher::new_derive_key("volta-zk/c64/correction-link-binding/v1");
    binding.update(&fixed_roots_digest);
    binding.update(&nbr2_statement_digest);
    binding.update(&source_claims.statement().digest());
    for root in frame.roots {
        binding.update(&root);
    }
    let correction_binding_digest = *binding.finalize().as_bytes();
    if frame.binding_digest != correction_binding_digest {
        return Err("C6.4 projected residual correction binding differs".to_owned());
    }
    let correction_statement = crate::c63_sparse_h_closure::C64TerminalLinkStatement::new(
        correction_binding_digest,
        coefficient_digest,
        pending_digest,
        24,
    )
    .map_err(|error| error.to_string())?;
    let initial_keys = std::array::from_fn(|tape| {
        source_claims.keys()[0][tape].add(source_claims.keys()[1][tape].scale(correction_beta))
    });
    let correction_audit = crate::c63_sparse_h_closure::verify_c64_correction_link(
        coefficients,
        correction_beta,
        1 << 23,
        initial_keys,
        &correction_statement,
        &frame.correction_link,
        contexts,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let projected_pending = crate::c64_joint_residual_sketch::fold_c64_projected_pending_verifier(
        pending,
        weights.leaf(),
        weights.auxiliary(),
    )?;
    let correction_pending =
        crate::c64_joint_residual_sketch::c64_correction_pending_verifier(pending)?;
    let families = [
        C64ProjectedResidualFamily::LeafOther,
        C64ProjectedResidualFamily::LeafCorrection,
        C64ProjectedResidualFamily::Auxiliary,
    ];
    for (family_index, family) in families.into_iter().enumerate() {
        let owned_points = match family {
            C64ProjectedResidualFamily::LeafOther => {
                leaf_points.iter().map(|point| point.to_vec()).collect::<Vec<_>>()
            }
            C64ProjectedResidualFamily::Auxiliary => {
                auxiliary_points.iter().map(|point| point.to_vec()).collect::<Vec<_>>()
            }
            C64ProjectedResidualFamily::LeafCorrection => {
                let mut points = Vec::with_capacity(5);
                for point in leaf_points {
                    for selector in [Fp2::ZERO, Fp2::ONE] {
                        let mut point = point.to_vec();
                        point.push(selector);
                        points.push(point);
                    }
                }
                points.push(correction_audit.sumcheck_point.clone());
                points
            }
        };
        let (variables, config) = match family {
            C64ProjectedResidualFamily::LeafOther => {
                (C64_INPUT_VARIABLES, c64_projected_residual_whir_config(C64_INPUT_VARIABLES)?)
            }
            C64ProjectedResidualFamily::LeafCorrection => (
                C64_CORRECTION_VARIABLES,
                c64_projected_residual_whir_config(C64_CORRECTION_VARIABLES)?,
            ),
            C64ProjectedResidualFamily::Auxiliary => (
                C64_AUXILIARY_VARIABLES,
                c64_projected_residual_whir_config(C64_AUXILIARY_VARIABLES)?,
            ),
        };
        let points = owned_points.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut closures = Vec::with_capacity(2);
        let mut claim_weights = None;
        for limb in 0..2 {
            let (closure, limb_weights) =
                verify_c64_whir_ordinary_artifact_with_config_at_many_points_with_batch_alpha_and_root(
                    &frame.artifacts[family_index][limb],
                    variables,
                    &config,
                    &points,
                    c64_residual_limb_context(precommit_binding_digest, &weights, family_index, limb),
                    batch_alphas[family_index],
                    frame.roots[family_index * 2 + limb],
                )?;
            if claim_weights.as_ref().is_some_and(|weights| weights != &limb_weights) {
                return Err("C6.4 verifier limb batch weights differ".to_owned());
            }
            claim_weights = Some(limb_weights);
            closures.push(crate::c61_authenticated_whir::C63AuthenticatedWhirNormalizedLimb {
                combined: closure.combined,
                shifted_masked_claim: closure.shifted_masked_claim,
                gamma: closure.gamma,
                affine: closure.target,
                claim_weight: Fp2::ONE,
            });
        }
        let claim_weights = claim_weights.expect("two C6.4 limbs");
        let expected_targets: [volta_mac::VerifierKey; 2] =
            std::array::from_fn(|tape| match family {
                C64ProjectedResidualFamily::LeafOther | C64ProjectedResidualFamily::Auxiliary => {
                    projected_pending[family_index][0][tape]
                        .scale(claim_weights[0])
                        .add(projected_pending[family_index][1][tape].scale(claim_weights[1]))
                }
                C64ProjectedResidualFamily::LeafCorrection => correction_pending[0][0][tape]
                    .scale(weights.leaf[3] * claim_weights[0])
                    .add(correction_pending[0][1][tape].scale(weights.leaf[6] * claim_weights[1]))
                    .add(correction_pending[1][0][tape].scale(weights.leaf[3] * claim_weights[2]))
                    .add(correction_pending[1][1][tape].scale(weights.leaf[6] * claim_weights[3]))
                    .add(correction_audit.terminal_m_keys[tape].scale(claim_weights[4])),
            });
        let normalized: [crate::c61_authenticated_whir::C63AuthenticatedWhirNormalizedLimb; 2] =
            closures.try_into().map_err(|_| "C6.4 verifier limb census differs".to_owned())?;
        for tape in 0..2 {
            let mut auth_transcript = Transcript::new_fiat_shamir(c64_residual_auth_context(
                frame.roots,
                family_index,
                tape,
                batch_alphas[family_index],
            ))?;
            verify_c64_shared_authenticated_whir_limb_pair(
                normalized,
                expected_targets[tape],
                frame.terminal_proofs[family_index][tape],
                frame.mask_corrections[family_index][tape],
                &mut contexts[tape],
                family,
                mask_range,
                &mut auth_transcript,
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(C64ProjectedResidualVerifierOutput { correction_audit })
}

fn c64_residual_limb_context(
    binding_digest: [u8; 32],
    weights: &C64ProjectedResidualWeights,
    family: usize,
    limb: usize,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/projected-residual-limb/v1");
    hasher.update(&binding_digest);
    hasher.update(&[family as u8, limb as u8]);
    for value in weights.leaf.iter().chain(&weights.auxiliary) {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_mac::Transcript;

    #[test]
    fn projected_weights_are_binding_and_transcript_deterministic() {
        let mut left = Transcript::new_fiat_shamir([0x64; 32]).unwrap();
        let mut right = Transcript::new_fiat_shamir([0x64; 32]).unwrap();
        let weights = draw_c64_projected_residual_weights([0xA4; 32], &mut left).unwrap();
        assert_eq!(weights, draw_c64_projected_residual_weights([0xA4; 32], &mut right).unwrap());
        assert_eq!(left.ledger(), right.ledger());
        let mut changed = Transcript::new_fiat_shamir([0x64; 32]).unwrap();
        assert_ne!(weights, draw_c64_projected_residual_weights([0xA5; 32], &mut changed).unwrap());
    }
}

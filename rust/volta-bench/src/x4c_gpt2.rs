//! Frozen GPT-2-small inventory and real-weight materialization for X4c.
//!
//! This module is orchestration only. It maps the already-authenticated
//! T=100+50 model claims onto the five schema-4 cohorts. It does not alter
//! the X4 profile, codec, transcript frames, rate, query count or soundness
//! accounting.

use rayon::prelude::*;
use std::time::Instant;
use volta_field::{Fp, Fp2, P};
use volta_gpt2::{Gpt2Model, D, DFF, L, NPOS, VOCAB};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::x4::{
    authenticate_pending_aux_prover_v4, authenticate_pending_aux_verifier_v4,
    evaluate_multilinear_table, hash_descriptor_v4, manifest_id_digest_v4,
    multilinear_coefficients_in_place, multilinear_evaluations_in_place, profile_digest_v4,
    prove_authenticated_output_link_x4c_v4, prove_bound_response_zero_batch_v4,
    transfer_template_digest_v4, verify_authenticated_output_link_x4c_v4,
    verify_bound_response_zero_batch_v4, verify_response_manifest_v4,
    AuthenticatedOutputBlockProverV4, AuthenticatedOutputBlockVerifierV4,
    AuthenticatedOutputLinkMetricsV4, AuthenticatedOutputLinkPrefixV4,
    AuthenticatedOutputLinkProofV4, BlockKind, CohortIdentityV4, CohortVerifierConfigV4,
    DescriptorFrameV4, Digest, FrameV4, InitialOpeningScheduleV4, LinkPolynomialProverV4,
    LinkPolynomialVerifierV4, ManifestLeafFrame, ManifestTreeV4, ModelGlobalOpeningSourceV4,
    NamespaceKind, OracleKindV4, PackedOpeningScheduleV4, Phase, ReducedClaimFrame,
    ResponseEnvelopeFrameV4, X4OpeningRegistryV4, X4cArenaRuntimeV4, X4cRamModelGlobalCohortV4,
    X4cResponseMetricsV4, X4cSealConfigV4, X4cSelectedQueryTapeV4,
};
use volta_pcs::{batch_reduce_prover, batch_reduce_verifier, BlockClaim};
use volta_proto::sumcheck_blind::BlindSumcheckProof;
use volta_proto::{cattn_permuted, ModelOut, ModelOutV, WeightClaimP};

pub const X4C_GPT2_PHYSICAL_BLOCKS: usize = 51;
pub const X4C_GPT2_REDUCED_CLAIMS: usize = 102;
pub const X4C_GPT2_COHORTS: usize = 5;
pub const X4C_GPT2_CLAIM_REDUCTION_FULL_CORRELATIONS: u64 = 2_208;
pub const X4C_GPT2_SEAM_FULL_CORRELATIONS: u64 = 106;
pub const X4C_GPT2_FULL_CORRELATIONS: u64 = 2_314;
pub const X4C_GPT2_DURABLE_COEFFICIENT_BYTES: u64 = 9_618_587_648;
pub const X4C_GPT2_DURABLE_ROOT_BYTES: u64 = 160;
pub const X4C_GPT2_DURABLE_TIER_BYTES: u64 =
    X4C_GPT2_DURABLE_COEFFICIENT_BYTES + X4C_GPT2_DURABLE_ROOT_BYTES;
pub const X4C_GPT2_HOST_ORACLE_BYTES: u64 = 76_948_701_184;
pub const X4C_GPT2_HOST_OUTER_CACHE_BYTES: u64 = 37_094_424_416;
pub const X4C_GPT2_PCS_BYTES: u64 = 2_683_236;
pub const X4C_GPT2_RESPONSE_BYTES: u64 = 43_953_700;

pub const X4C_WEXT_MU26_COHORT_ID: u32 = 0xA500_0001;
pub const X4C_WEXT_MU22_COHORT_ID: u32 = 0xA500_0002;
pub const X4C_WEXT_MU20_COHORT_ID: u32 = 0xA500_0003;
pub const X4C_AUX_ELL17_COHORT_ID: u32 = 0xA500_0100;
pub const X4C_AUX_ELL16_COHORT_ID: u32 = 0xA500_0101;

pub const X4C_CLAIM_REDUCTION_DOMAIN_BASE: u64 = 0x1000_0000_0000_0000;
pub const X4C_M9_DOMAIN_BASE: u64 = 0x1000_0000_0001_0000;
pub const X4C_LINK_DOMAIN_BASE: u64 = 0x1000_0000_0002_0000;
pub const X4C_ZERO_DOMAIN: u64 = 0x1000_0000_0003_0000;

const X4C_RATE_LOG2: u8 = 3;
const X4C_LINK_ROUNDS: usize = 27;
const MASK_XOF_CONTEXT: &str = "volta-zk/x4c/gpt2-real-weight-mask/v1";
const MASK_SEED_COMMITMENT_CONTEXT: &str = "volta-zk/x4c/gpt2-real-weight-mask-seed-commitment/v1";
const PARENT_CLAIM_CONTEXT: &str = "volta-zk/x4c/gpt2-parent-claim/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpt2WeightSource {
    TokenEmbeddingLogits,
    TokenEmbeddingSelection,
    PositionEmbedding,
    CAttn { layer: usize },
    AttentionProjection { layer: usize },
    FfnUp { layer: usize },
    FfnDown { layer: usize },
}

#[derive(Clone, Debug)]
pub struct X4cGpt2Block {
    pub source: Gpt2WeightSource,
    pub descriptor: DescriptorFrameV4,
    pub descriptor_digest: Digest,
    pub weight_slot: u16,
    pub auxiliary_slot: u16,
    pub prover_claim_indices: [usize; 2],
    pub claim_reduction_domain_base: u64,
    pub m9_domain: u64,
}

impl X4cGpt2Block {
    pub fn mu(&self) -> usize {
        usize::from(self.descriptor.mu)
    }

    pub fn ell(&self) -> usize {
        usize::from(self.descriptor.ell)
    }

    pub fn claims<'a>(&self, output: &'a ModelOut) -> Result<[&'a WeightClaimP; 2], String> {
        let first = output
            .weight_claims
            .get(self.prover_claim_indices[0])
            .or_else(|| {
                self.prover_claim_indices[0]
                    .checked_sub(2 * 4 * L)
                    .and_then(|index| output.embed_claims.get(index))
            })
            .ok_or_else(|| "missing first GPT-2 parent claim".to_owned())?;
        let second = output
            .weight_claims
            .get(self.prover_claim_indices[1])
            .or_else(|| {
                self.prover_claim_indices[1]
                    .checked_sub(2 * 4 * L)
                    .and_then(|index| output.embed_claims.get(index))
            })
            .ok_or_else(|| "missing second GPT-2 parent claim".to_owned())?;
        if first.point.len() != self.mu() || second.point.len() != self.mu() {
            return Err("GPT-2 parent-claim dimension does not match its X4c descriptor".to_owned());
        }
        Ok([first, second])
    }

    fn verifier_claims<'a>(
        &self,
        output: &'a ModelOutV,
    ) -> Result<[&'a (Vec<Fp2>, VerifierKey); 2], String> {
        let first = output
            .weight_keys
            .get(self.prover_claim_indices[0])
            .or_else(|| {
                self.prover_claim_indices[0]
                    .checked_sub(2 * 4 * L)
                    .and_then(|index| output.embed_keys.get(index))
            })
            .ok_or_else(|| "missing first GPT-2 verifier parent claim".to_owned())?;
        let second = output
            .weight_keys
            .get(self.prover_claim_indices[1])
            .or_else(|| {
                self.prover_claim_indices[1]
                    .checked_sub(2 * 4 * L)
                    .and_then(|index| output.embed_keys.get(index))
            })
            .ok_or_else(|| "missing second GPT-2 verifier parent claim".to_owned())?;
        Ok([first, second])
    }
}

#[derive(Clone, Debug)]
pub struct X4cGpt2Inventory {
    pub model_config_digest: Digest,
    pub weights_digest: Digest,
    pub blocks: Vec<X4cGpt2Block>,
    pub cohort_configs: Vec<CohortVerifierConfigV4>,
    pub link_round_domains: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct X4cGpt2CohortMaterial {
    pub name: &'static str,
    pub config: CohortVerifierConfigV4,
    pub coefficients: Vec<Option<Vec<Fp2>>>,
}

#[derive(Clone, Debug)]
pub struct X4cGpt2EvaluationTables {
    /// Same five-cohort order and structural slots as the inventory configs.
    pub slots: Vec<Vec<Option<Vec<Fp2>>>>,
}

#[derive(Debug)]
pub struct X4cGpt2ReducedClaims {
    pub frames: Vec<ReducedClaimFrame>,
    pub proofs: Vec<BlindSumcheckProof>,
    pub points: Vec<Vec<Fp2>>,
    pub prover_values: Vec<ProverAuthed>,
    pub verifier_keys: Vec<VerifierKey>,
}

#[derive(Debug)]
pub struct X4cGpt2OnlineResult {
    pub model_root: Digest,
    pub manifest_frames: Vec<volta_pcs::x4::ManifestFrameV4>,
    pub reduced: X4cGpt2ReducedClaims,
    pub link_proof: AuthenticatedOutputLinkProofV4,
    pub link_metrics: AuthenticatedOutputLinkMetricsV4,
    pub x4c_metrics: X4cResponseMetricsV4,
    pub seal_wall_ns: u64,
    pub open_wall_ns: u64,
    pub verify_wall_ns: u64,
    pub response: ResponseEnvelopeFrameV4,
    pub encoded_pcs: Vec<u8>,
}

fn expected_ell(mu: u8) -> u8 {
    let target = 111u32 * u32::from(mu) * u32::from(mu) + 1;
    (u32::BITS - (target - 1).leading_zeros()) as u8
}

fn claim_index_weight(phase: usize, layer: usize, tensor: usize) -> usize {
    phase * 4 * L + layer * 4 + tensor
}

fn claim_index_embed(phase: usize, tensor: usize) -> usize {
    2 * 4 * L + phase * 3 + tensor
}

#[derive(Clone, Copy)]
struct BlockShape {
    source_rows: usize,
    source_cols: usize,
    padded_rows: usize,
    padded_cols: usize,
    mu: u8,
    weight_cohort_id: u32,
    weight_slot: u16,
    weight_slot_count: u16,
    auxiliary_slot: u16,
    tensor_id: u16,
    namespace_kind: NamespaceKind,
    namespace_index: u8,
    block_kind: BlockKind,
    split_prefix: u8,
    claim_indices: [usize; 2],
}

fn descriptor_for(
    shape: BlockShape,
    model_config_digest: Digest,
    weights_digest: Digest,
    transfer_domains: [u64; 2],
) -> Result<DescriptorFrameV4, String> {
    let mut ordered_domains = transfer_domains;
    ordered_domains.sort_unstable();
    if ordered_domains[0] == ordered_domains[1] {
        return Err("a GPT-2 block reuses its parent-claim correlation domain".to_owned());
    }
    let logical_coeffs = shape
        .source_rows
        .checked_mul(shape.source_cols)
        .ok_or_else(|| "logical coefficient count overflows".to_owned())?;
    let padded_coeffs = shape
        .padded_rows
        .checked_mul(shape.padded_cols)
        .ok_or_else(|| "padded coefficient count overflows".to_owned())?;
    let mu = padded_coeffs.ilog2() as u8;
    if mu != shape.mu || !padded_coeffs.is_power_of_two() {
        return Err("GPT-2 block shape does not match its frozen mu".to_owned());
    }
    let descriptor = DescriptorFrameV4 {
        profile_digest: profile_digest_v4(),
        model_config_digest,
        weights_digest,
        namespace_kind: shape.namespace_kind,
        namespace_index: shape.namespace_index,
        tensor_id: shape.tensor_id,
        block_kind: shape.block_kind,
        block_ordinal: 0,
        split_prefix: shape.split_prefix,
        mu,
        ell: expected_ell(mu),
        rate_log2: X4C_RATE_LOG2,
        source_rows: u32::try_from(shape.source_rows)
            .map_err(|_| "source row count overflows".to_owned())?,
        source_cols: u32::try_from(shape.source_cols)
            .map_err(|_| "source column count overflows".to_owned())?,
        padded_rows: u32::try_from(shape.padded_rows)
            .map_err(|_| "padded row count overflows".to_owned())?,
        padded_cols: u32::try_from(shape.padded_cols)
            .map_err(|_| "padded column count overflows".to_owned())?,
        logical_coeffs: u64::try_from(logical_coeffs)
            .map_err(|_| "logical coefficient count overflows".to_owned())?,
        padded_coeffs: u64::try_from(padded_coeffs)
            .map_err(|_| "padded coefficient count overflows".to_owned())?,
        cohort_id: shape.weight_cohort_id,
        slot: shape.weight_slot,
        slot_count: shape.weight_slot_count,
        n_w: 1u64 << (u32::from(mu) + 4),
        n_g: 1u64 << (u32::from(expected_ell(mu)) + 3),
        transfer_template_digest: transfer_template_digest_v4(&ordered_domains)
            .map_err(|error| format!("transfer template: {error:?}"))?,
    };
    descriptor.validate().map_err(|error| format!("GPT-2 descriptor validation: {error:?}"))?;
    Ok(descriptor)
}

fn shapes() -> Vec<(Gpt2WeightSource, BlockShape)> {
    let mut shapes = Vec::with_capacity(X4C_GPT2_PHYSICAL_BLOCKS);
    // The tied matrix is represented by two independently claimed roles.
    for (source, kind, tensor_id, embed_tensor, slot) in [
        (Gpt2WeightSource::TokenEmbeddingLogits, BlockKind::UnembeddingHalf, 1, 0, 0),
        (Gpt2WeightSource::TokenEmbeddingSelection, BlockKind::EmbeddingHalf, 2, 1, 1),
    ] {
        shapes.push((
            source,
            BlockShape {
                source_rows: VOCAB,
                source_cols: D,
                padded_rows: 1 << 16,
                padded_cols: 1 << 10,
                mu: 26,
                weight_cohort_id: X4C_WEXT_MU26_COHORT_ID,
                weight_slot: slot,
                weight_slot_count: 2,
                auxiliary_slot: slot,
                tensor_id,
                namespace_kind: NamespaceKind::Global,
                namespace_index: 255,
                block_kind: kind,
                split_prefix: 0,
                claim_indices: [
                    claim_index_embed(0, embed_tensor),
                    claim_index_embed(1, embed_tensor),
                ],
            },
        ));
    }

    // Frozen mu=22 slot order: layer-major c_attn, ffn_up, ffn_down.
    let mut auxiliary_slot = 0u16;
    for layer in 0..L {
        for (source, tensor_id, source_rows, source_cols, padded_rows, padded_cols, tensor) in [
            (Gpt2WeightSource::CAttn { layer }, 0x100, D, 3 * D, 1 << 10, 1 << 12, 0),
            (Gpt2WeightSource::FfnUp { layer }, 0x102, D, DFF, 1 << 10, 1 << 12, 2),
            (Gpt2WeightSource::FfnDown { layer }, 0x103, DFF, D, 1 << 12, 1 << 10, 3),
        ] {
            // `tensor` is the model-proof tensor index; weight slot is
            // explicitly layer-major among the three mu=22 tensors.
            let weight_slot = u16::try_from(
                3 * layer
                    + match tensor {
                        0 => 0,
                        2 => 1,
                        3 => 2,
                        _ => unreachable!(),
                    },
            )
            .expect("small slot");
            shapes.push((
                source,
                BlockShape {
                    source_rows,
                    source_cols,
                    padded_rows,
                    padded_cols,
                    mu: 22,
                    weight_cohort_id: X4C_WEXT_MU22_COHORT_ID,
                    weight_slot,
                    weight_slot_count: 64,
                    auxiliary_slot,
                    tensor_id,
                    namespace_kind: NamespaceKind::Layer,
                    namespace_index: layer as u8,
                    block_kind: BlockKind::Fixed,
                    split_prefix: 255,
                    claim_indices: [
                        claim_index_weight(0, layer, tensor),
                        claim_index_weight(1, layer, tensor),
                    ],
                },
            ));
            auxiliary_slot += 1;
        }
    }

    // Frozen mu=20 slot order: twelve attention projections, then wpe.
    for layer in 0..L {
        shapes.push((
            Gpt2WeightSource::AttentionProjection { layer },
            BlockShape {
                source_rows: D,
                source_cols: D,
                padded_rows: 1 << 10,
                padded_cols: 1 << 10,
                mu: 20,
                weight_cohort_id: X4C_WEXT_MU20_COHORT_ID,
                weight_slot: layer as u16,
                weight_slot_count: 16,
                auxiliary_slot,
                tensor_id: 0x101,
                namespace_kind: NamespaceKind::Layer,
                namespace_index: layer as u8,
                block_kind: BlockKind::AttentionO,
                split_prefix: 255,
                claim_indices: [claim_index_weight(0, layer, 1), claim_index_weight(1, layer, 1)],
            },
        ));
        auxiliary_slot += 1;
    }
    shapes.push((
        Gpt2WeightSource::PositionEmbedding,
        BlockShape {
            source_rows: NPOS,
            source_cols: D,
            padded_rows: 1 << 10,
            padded_cols: 1 << 10,
            mu: 20,
            weight_cohort_id: X4C_WEXT_MU20_COHORT_ID,
            weight_slot: 12,
            weight_slot_count: 16,
            auxiliary_slot,
            tensor_id: 3,
            namespace_kind: NamespaceKind::Global,
            namespace_index: 255,
            block_kind: BlockKind::Fixed,
            split_prefix: 255,
            claim_indices: [claim_index_embed(0, 2), claim_index_embed(1, 2)],
        },
    ));
    shapes
}

impl X4cGpt2Inventory {
    /// Construct the frozen 51-block inventory after a mock model-proof
    /// prepass has exposed the two deterministic parent correlation domains
    /// for every block. Online real-PCG runs must reproduce them exactly.
    pub fn new(
        model_config_digest: Digest,
        weights_digest: Digest,
        parent_domains: &[[u64; 2]],
    ) -> Result<Self, String> {
        let shapes = shapes();
        if shapes.len() != X4C_GPT2_PHYSICAL_BLOCKS
            || parent_domains.len() != X4C_GPT2_PHYSICAL_BLOCKS
        {
            return Err("X4c GPT-2 inventory must contain exactly 51 blocks".to_owned());
        }
        let mut next_reduction_domain = X4C_CLAIM_REDUCTION_DOMAIN_BASE;
        let mut blocks = Vec::with_capacity(shapes.len());
        for (index, ((source, shape), domains)) in
            shapes.into_iter().zip(parent_domains.iter().copied()).enumerate()
        {
            let descriptor = descriptor_for(shape, model_config_digest, weights_digest, domains)?;
            let descriptor_digest = hash_descriptor_v4(&descriptor)
                .map_err(|error| format!("descriptor digest: {error:?}"))?;
            blocks.push(X4cGpt2Block {
                source,
                descriptor,
                descriptor_digest,
                weight_slot: shape.weight_slot,
                auxiliary_slot: shape.auxiliary_slot,
                prover_claim_indices: shape.claim_indices,
                claim_reduction_domain_base: next_reduction_domain,
                m9_domain: X4C_M9_DOMAIN_BASE + index as u64,
            });
            next_reduction_domain += u64::from(shape.mu);
        }
        let descriptors = |cohort_id: u32, slots: usize| {
            let mut values = vec![None; slots];
            for block in &blocks {
                if block.descriptor.cohort_id == cohort_id {
                    values[usize::from(block.weight_slot)] = Some(block.descriptor_digest);
                }
            }
            values
        };
        let auxiliary_descriptors = |ell: usize, slots: usize| {
            let mut values = vec![None; slots];
            for block in &blocks {
                if block.ell() == ell {
                    values[usize::from(block.auxiliary_slot)] = Some(block.descriptor_digest);
                }
            }
            values
        };
        let cohort_configs = vec![
            cohort_config(
                X4C_WEXT_MU26_COHORT_ID,
                OracleKindV4::WeightExtension,
                30,
                descriptors(X4C_WEXT_MU26_COHORT_ID, 2),
            )?,
            cohort_config(
                X4C_WEXT_MU22_COHORT_ID,
                OracleKindV4::WeightExtension,
                26,
                descriptors(X4C_WEXT_MU22_COHORT_ID, 64),
            )?,
            cohort_config(
                X4C_WEXT_MU20_COHORT_ID,
                OracleKindV4::WeightExtension,
                24,
                descriptors(X4C_WEXT_MU20_COHORT_ID, 16),
            )?,
            cohort_config(
                X4C_AUX_ELL17_COHORT_ID,
                OracleKindV4::Auxiliary,
                20,
                auxiliary_descriptors(17, 2),
            )?,
            cohort_config(
                X4C_AUX_ELL16_COHORT_ID,
                OracleKindV4::Auxiliary,
                19,
                auxiliary_descriptors(16, 64),
            )?,
        ];
        let link_round_domains =
            (0..2 * X4C_LINK_ROUNDS).map(|i| X4C_LINK_DOMAIN_BASE + i as u64).collect();
        let inventory = Self {
            model_config_digest,
            weights_digest,
            blocks,
            cohort_configs,
            link_round_domains,
        };
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn parent_domains_from_output(output: &ModelOut) -> Result<Vec<[u64; 2]>, String> {
        if output.weight_claims.len() != 2 * 4 * L || output.embed_claims.len() != 6 {
            return Err("X4c requires exactly 96 weight and 6 embedding claims".to_owned());
        }
        shapes()
            .into_iter()
            .map(|(_, shape)| {
                let lookup = |index: usize| {
                    output
                        .weight_claims
                        .get(index)
                        .or_else(|| {
                            index
                                .checked_sub(2 * 4 * L)
                                .and_then(|embed| output.embed_claims.get(embed))
                        })
                        .map(|claim| claim.auth_domain)
                        .ok_or_else(|| "missing parent claim while deriving domains".to_owned())
                };
                Ok([lookup(shape.claim_indices[0])?, lookup(shape.claim_indices[1])?])
            })
            .collect()
    }

    pub fn validate_parent_domains(&self, output: &ModelOut) -> Result<(), String> {
        let observed = Self::parent_domains_from_output(output)?;
        for (block, domains) in self.blocks.iter().zip(observed) {
            let expected = block.descriptor.transfer_template_digest;
            let mut domains = domains;
            domains.sort_unstable();
            let actual = transfer_template_digest_v4(&domains)
                .map_err(|error| format!("parent transfer template: {error:?}"))?;
            if actual != expected {
                return Err(
                    "online parent-claim domain schedule differs from onboarding".to_owned()
                );
            }
        }
        Ok(())
    }

    pub fn claim_frames(&self, output: &ModelOut) -> Result<Vec<ReducedClaimFrame>, String> {
        self.validate_parent_domains(output)?;
        let mut frames = Vec::with_capacity(X4C_GPT2_REDUCED_CLAIMS);
        for block in &self.blocks {
            for (phase_ordinal, claim) in block.claims(output)?.into_iter().enumerate() {
                frames.push(ReducedClaimFrame {
                    descriptor_digest: block.descriptor_digest,
                    parent_claim_digest: parent_claim_digest(
                        block.descriptor_digest,
                        phase_ordinal,
                        claim,
                    ),
                    phase: if phase_ordinal == 0 { Phase::Prefill } else { Phase::Decode },
                    phase_ordinal: phase_ordinal as u16,
                    point: claim.point.clone(),
                    affine_scale: Fp2::ONE,
                    auth_domain: claim.auth_domain,
                });
            }
        }
        if frames.len() != X4C_GPT2_REDUCED_CLAIMS {
            return Err("X4c reduced-claim frame count changed".to_owned());
        }
        Ok(frames)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.blocks.len() != X4C_GPT2_PHYSICAL_BLOCKS
            || self.cohort_configs.len() != X4C_GPT2_COHORTS
            || self.link_round_domains.len() != 2 * X4C_LINK_ROUNDS
            || !self.link_round_domains.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err("X4c GPT-2 inventory cardinality changed".to_owned());
        }
        let mut descriptor_set = std::collections::BTreeSet::new();
        let mut parent_domain_set = std::collections::BTreeSet::new();
        let mut claim_reduction_fulls = 0u64;
        for block in &self.blocks {
            block.descriptor.validate().map_err(|error| format!("descriptor: {error:?}"))?;
            if !descriptor_set.insert(block.descriptor_digest) {
                return Err("duplicate X4c GPT-2 descriptor".to_owned());
            }
            claim_reduction_fulls += 2 * block.descriptor.mu as u64;
            for domain in block.claim_reduction_domain_base
                ..block.claim_reduction_domain_base + u64::from(block.descriptor.mu)
            {
                if !parent_domain_set.insert(domain) {
                    return Err("claim-reduction correlation domain overlaps".to_owned());
                }
            }
            if !parent_domain_set.insert(block.m9_domain) {
                return Err("M9 correlation domain overlaps".to_owned());
            }
        }
        for domain in &self.link_round_domains {
            if !parent_domain_set.insert(*domain) {
                return Err("link correlation domain overlaps".to_owned());
            }
        }
        if !parent_domain_set.insert(X4C_ZERO_DOMAIN)
            || claim_reduction_fulls != X4C_GPT2_CLAIM_REDUCTION_FULL_CORRELATIONS
            || claim_reduction_fulls + X4C_GPT2_SEAM_FULL_CORRELATIONS != X4C_GPT2_FULL_CORRELATIONS
        {
            return Err("X4c GPT-2 correlation census changed".to_owned());
        }
        let present = self
            .cohort_configs
            .iter()
            .map(|config| config.slot_descriptors.iter().flatten().count())
            .collect::<Vec<_>>();
        if present != [2, 36, 13, 2, 49] {
            return Err("X4c GPT-2 cohort occupancy changed".to_owned());
        }
        Ok(())
    }
}

fn cohort_config(
    cohort_id: u32,
    oracle_kind: OracleKindV4,
    domain_log2: u8,
    slot_descriptors: Vec<Option<Digest>>,
) -> Result<CohortVerifierConfigV4, String> {
    let config = CohortVerifierConfigV4 {
        identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round: 0 },
        slot_descriptors,
        outer_len: 1usize << domain_log2,
        expected_symbol_count: 1,
    };
    config.validate().map_err(|error| format!("GPT-2 cohort config: {error:?}"))?;
    Ok(config)
}

fn parent_claim_digest(
    descriptor_digest: Digest,
    phase_ordinal: usize,
    claim: &WeightClaimP,
) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(PARENT_CLAIM_CONTEXT);
    hasher.update(&descriptor_digest);
    hasher.update(&[phase_ordinal as u8]);
    hasher.update(&claim.auth_domain.to_le_bytes());
    hasher.update(&(claim.point.len() as u64).to_le_bytes());
    for coordinate in &claim.point {
        hasher.update(&coordinate.c0.value().to_le_bytes());
        hasher.update(&coordinate.c1.value().to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub fn mask_seed_commitment(seed: [u8; 32]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(MASK_SEED_COMMITMENT_CONTEXT);
    hasher.update(&seed);
    *hasher.finalize().as_bytes()
}

struct UniformFp2Xof {
    reader: blake3::OutputReader,
    buffer: [u8; 65_536],
    cursor: usize,
}

impl UniformFp2Xof {
    fn new(seed: [u8; 32], descriptor: Digest, oracle_kind: OracleKindV4) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(MASK_XOF_CONTEXT);
        hasher.update(&seed);
        hasher.update(&descriptor);
        hasher.update(&[oracle_kind as u8]);
        let mut value = Self { reader: hasher.finalize_xof(), buffer: [0; 65_536], cursor: 65_536 };
        value.refill();
        value
    }

    fn refill(&mut self) {
        self.reader.fill(&mut self.buffer);
        self.cursor = 0;
    }

    fn word(&mut self) -> u64 {
        if self.cursor + 8 > self.buffer.len() {
            self.refill();
        }
        let word = u64::from_le_bytes(
            self.buffer[self.cursor..self.cursor + 8].try_into().expect("eight-byte XOF word"),
        );
        self.cursor += 8;
        word
    }

    fn fp(&mut self) -> Fp {
        loop {
            let candidate = self.word();
            if candidate < P {
                return Fp::new(candidate);
            }
        }
    }

    fn fp2(&mut self) -> Fp2 {
        Fp2::new(self.fp(), self.fp())
    }
}

fn fill_padded_matrix(
    destination: &mut [Fp2],
    source: &[i16],
    source_rows: usize,
    source_cols: usize,
    padded_cols: usize,
) -> Result<(), String> {
    if source.len() != source_rows * source_cols
        || destination.len() % padded_cols != 0
        || destination.len() / padded_cols < source_rows
        || padded_cols < source_cols
    {
        return Err("invalid padded GPT-2 matrix geometry".to_owned());
    }
    destination.par_chunks_mut(padded_cols).take(source_rows).enumerate().for_each(
        |(row, target)| {
            for (slot, value) in target[..source_cols]
                .iter_mut()
                .zip(&source[row * source_cols..(row + 1) * source_cols])
            {
                *slot = Fp2::from_base(Fp::from_i64(i64::from(*value)));
            }
        },
    );
    Ok(())
}

fn fill_source(
    model: &Gpt2Model,
    block: &X4cGpt2Block,
    destination: &mut [Fp2],
) -> Result<(), String> {
    let shape = &block.descriptor;
    let padded_cols = shape.padded_cols as usize;
    match block.source {
        Gpt2WeightSource::TokenEmbeddingLogits | Gpt2WeightSource::TokenEmbeddingSelection => {
            fill_padded_matrix(destination, &model.wte, VOCAB, D, padded_cols)
        }
        Gpt2WeightSource::PositionEmbedding => {
            fill_padded_matrix(destination, &model.wpe, NPOS, D, padded_cols)
        }
        Gpt2WeightSource::CAttn { layer } => {
            let permuted = cattn_permuted(&model.layers[layer].0.c_attn);
            fill_padded_matrix(destination, &permuted, D, 4096, padded_cols)
        }
        Gpt2WeightSource::AttentionProjection { layer } => {
            fill_padded_matrix(destination, &model.layers[layer].0.attn_proj, D, D, padded_cols)
        }
        Gpt2WeightSource::FfnUp { layer } => {
            fill_padded_matrix(destination, &model.layers[layer].0.ffn_up, D, DFF, padded_cols)
        }
        Gpt2WeightSource::FfnDown { layer } => {
            fill_padded_matrix(destination, &model.layers[layer].0.ffn_down, DFF, D, padded_cols)
        }
    }
}

/// Materialize the exact five real-weight coefficient cohorts.
///
/// `seed` is secret onboarding randomness. Only
/// [`mask_seed_commitment`] belongs in a record. Coefficients are transformed
/// in place so the exporter never owns a second production-sized table.
pub fn materialize_real_weight_cohorts(
    model: &Gpt2Model,
    inventory: &X4cGpt2Inventory,
    seed: [u8; 32],
) -> Result<Vec<X4cGpt2CohortMaterial>, String> {
    model.validate_layout()?;
    inventory.validate()?;
    let mut materials = inventory
        .cohort_configs
        .iter()
        .map(|config| X4cGpt2CohortMaterial {
            name: match config.identity.cohort_id {
                X4C_WEXT_MU26_COHORT_ID => "Wext-mu26-global-tied-roles",
                X4C_WEXT_MU22_COHORT_ID => "Wext-mu22-all-layers",
                X4C_WEXT_MU20_COHORT_ID => "Wext-mu20-layers-and-position",
                X4C_AUX_ELL17_COHORT_ID => "auxiliary-ell17",
                X4C_AUX_ELL16_COHORT_ID => "auxiliary-ell16",
                _ => unreachable!("validated five-cohort inventory"),
            },
            config: config.clone(),
            coefficients: vec![None; config.slot_descriptors.len()],
        })
        .collect::<Vec<_>>();
    for block in &inventory.blocks {
        let weight_index = match block.descriptor.cohort_id {
            X4C_WEXT_MU26_COHORT_ID => 0,
            X4C_WEXT_MU22_COHORT_ID => 1,
            X4C_WEXT_MU20_COHORT_ID => 2,
            _ => return Err("unknown weight cohort in GPT-2 descriptor".to_owned()),
        };
        let weight_len = 1usize << (block.mu() + 1);
        let mut weight = vec![Fp2::ZERO; weight_len];
        let (original, twin) = weight.split_at_mut(weight_len / 2);
        fill_source(model, block, original)?;
        let mut xof =
            UniformFp2Xof::new(seed, block.descriptor_digest, OracleKindV4::WeightExtension);
        for value in twin {
            *value = xof.fp2();
        }
        multilinear_coefficients_in_place(&mut weight)
            .map_err(|error| format!("weight coefficient transform: {error:?}"))?;
        materials[weight_index].coefficients[usize::from(block.weight_slot)] = Some(weight);

        let auxiliary_index = if block.ell() == 17 { 3 } else { 4 };
        let mut auxiliary = vec![Fp2::ZERO; 1usize << block.ell()];
        let mut xof = UniformFp2Xof::new(seed, block.descriptor_digest, OracleKindV4::Auxiliary);
        for value in &mut auxiliary {
            *value = xof.fp2();
        }
        multilinear_coefficients_in_place(&mut auxiliary)
            .map_err(|error| format!("auxiliary coefficient transform: {error:?}"))?;
        materials[auxiliary_index].coefficients[usize::from(block.auxiliary_slot)] =
            Some(auxiliary);
    }
    let coefficient_bytes = materials
        .iter()
        .flat_map(|material| material.coefficients.iter().flatten())
        .try_fold(0u64, |sum, coefficients| {
            sum.checked_add(coefficients.len() as u64 * 16)
                .ok_or_else(|| "coefficient byte census overflows".to_owned())
        })?;
    if coefficient_bytes != X4C_GPT2_DURABLE_COEFFICIENT_BYTES {
        return Err("real-weight coefficient byte census changed".to_owned());
    }
    Ok(materials)
}

/// Reconstruct Boolean-hypercube evaluation tables from a second
/// pre-response coefficient load. This work is deliberately outside the
/// measured response I/O window; the live opening remains file-free.
pub fn rebuild_evaluation_tables(
    inventory: &X4cGpt2Inventory,
    coefficients: &[X4cGpt2CohortMaterial],
) -> Result<X4cGpt2EvaluationTables, String> {
    if coefficients.len() != X4C_GPT2_COHORTS {
        return Err("evaluation rebuild requires exactly five cohorts".to_owned());
    }
    let mut slots = Vec::with_capacity(coefficients.len());
    let mut bytes = 0u64;
    for (expected, material) in inventory.cohort_configs.iter().zip(coefficients) {
        if &material.config != expected
            || material.coefficients.len() != expected.slot_descriptors.len()
        {
            return Err("evaluation rebuild coefficient/config mismatch".to_owned());
        }
        let mut cohort = material.coefficients.clone();
        for values in cohort.iter_mut().flatten() {
            multilinear_evaluations_in_place(values)
                .map_err(|error| format!("evaluation inverse transform: {error:?}"))?;
            bytes = bytes
                .checked_add(values.len() as u64 * 16)
                .ok_or_else(|| "evaluation-table byte census overflows".to_owned())?;
        }
        slots.push(cohort);
    }
    if bytes != X4C_GPT2_DURABLE_COEFFICIENT_BYTES {
        return Err("evaluation-table byte census changed".to_owned());
    }
    Ok(X4cGpt2EvaluationTables { slots })
}

fn padded_source_i16(model: &Gpt2Model, block: &X4cGpt2Block) -> Result<Vec<i16>, String> {
    let rows = block.descriptor.padded_rows as usize;
    let cols = block.descriptor.padded_cols as usize;
    let mut padded = vec![0i16; rows * cols];
    let place = |target: &mut [i16], source: &[i16], source_rows: usize, source_cols: usize| {
        if source.len() != source_rows * source_cols || source_rows > rows || source_cols > cols {
            return Err("invalid X4c claim-reduction source geometry".to_owned());
        }
        target.par_chunks_mut(cols).take(source_rows).enumerate().for_each(|(row, destination)| {
            destination[..source_cols]
                .copy_from_slice(&source[row * source_cols..(row + 1) * source_cols]);
        });
        Ok(())
    };
    match block.source {
        Gpt2WeightSource::TokenEmbeddingLogits | Gpt2WeightSource::TokenEmbeddingSelection => {
            place(&mut padded, &model.wte, VOCAB, D)?
        }
        Gpt2WeightSource::PositionEmbedding => place(&mut padded, &model.wpe, NPOS, D)?,
        Gpt2WeightSource::CAttn { layer } => {
            let permuted = cattn_permuted(&model.layers[layer].0.c_attn);
            place(&mut padded, &permuted, D, 4096)?
        }
        Gpt2WeightSource::AttentionProjection { layer } => {
            place(&mut padded, &model.layers[layer].0.attn_proj, D, D)?
        }
        Gpt2WeightSource::FfnUp { layer } => {
            place(&mut padded, &model.layers[layer].0.ffn_up, D, DFF)?
        }
        Gpt2WeightSource::FfnDown { layer } => {
            place(&mut padded, &model.layers[layer].0.ffn_down, DFF, D)?
        }
    }
    Ok(padded)
}

/// Reduce the 102 already-authenticated model claims to one authenticated
/// point per physical block using the existing blind batch reducer.
///
/// Prover and verifier advance together. Any point, key, transcript or
/// correlation-domain divergence stops before the X4c link begins.
#[allow(clippy::too_many_arguments)]
pub fn reduce_real_weight_claims(
    model: &Gpt2Model,
    inventory: &X4cGpt2Inventory,
    prover_output: &ModelOut,
    verifier_output: &ModelOutV,
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
) -> Result<X4cGpt2ReducedClaims, String> {
    inventory.validate_parent_domains(prover_output)?;
    if verifier_output.weight_keys.len() != prover_output.weight_claims.len()
        || verifier_output.embed_keys.len() != prover_output.embed_claims.len()
    {
        return Err("prover/verifier GPT-2 claim cardinality differs".to_owned());
    }
    let frames = inventory.claim_frames(prover_output)?;
    let fulls_before = stream.counters.full_corrs;
    let mut proofs = Vec::with_capacity(X4C_GPT2_PHYSICAL_BLOCKS);
    let mut points = Vec::with_capacity(X4C_GPT2_PHYSICAL_BLOCKS);
    let mut prover_values = Vec::with_capacity(X4C_GPT2_PHYSICAL_BLOCKS);
    let mut verifier_keys = Vec::with_capacity(X4C_GPT2_PHYSICAL_BLOCKS);
    for (block_index, block) in inventory.blocks.iter().enumerate() {
        let block_frames = &frames[2 * block_index..2 * block_index + 2];
        for frame in block_frames {
            let bytes = FrameV4::ReducedClaim(frame.clone())
                .encode()
                .map_err(|error| format!("encode reduced claim: {error:?}"))?;
            let byte_len = u64::try_from(bytes.len())
                .map_err(|_| "reduced-claim frame length overflows".to_owned())?;
            prover_tx.append("x4_v4_reduced_claim", byte_len);
            verifier_tx.append("x4_v4_reduced_claim", byte_len);
        }
        let parent = block.claims(prover_output)?;
        let verifier_parent = block.verifier_claims(verifier_output)?;
        for ((claim, (point, _)), frame) in
            parent.iter().zip(verifier_parent.iter()).zip(block_frames)
        {
            if claim.point != *point
                || claim.auth_domain != frame.auth_domain
                || claim.point != frame.point
            {
                return Err("X4c parent-claim statement mismatch".to_owned());
            }
        }
        let padded = padded_source_i16(model, block)?;
        let prover_claims = parent
            .iter()
            .map(|claim| (BlockClaim { offset: 0, point: claim.point.clone() }, claim.value))
            .collect::<Vec<_>>();
        let verifier_claims = verifier_parent
            .iter()
            .map(|(point, key)| (BlockClaim { offset: 0, point: point.clone() }, *key))
            .collect::<Vec<_>>();
        let (proof, point, value, _) = batch_reduce_prover(
            &padded,
            block.mu(),
            &prover_claims,
            stream,
            block.claim_reduction_domain_base,
            prover_tx,
        );
        let (verifier_point, key) = batch_reduce_verifier(
            block.mu(),
            &verifier_claims,
            &proof,
            verifier,
            block.claim_reduction_domain_base,
            verifier_tx,
        )
        .ok_or_else(|| "X4c verifier rejected a claim reduction".to_owned())?;
        if verifier_point != point {
            return Err("X4c claim-reduction point differs across roles".to_owned());
        }
        proofs.push(proof);
        points.push(point);
        prover_values.push(value);
        verifier_keys.push(key);
    }
    if stream.counters.full_corrs.checked_sub(fulls_before)
        != Some(X4C_GPT2_CLAIM_REDUCTION_FULL_CORRELATIONS)
        || prover_tx.total_bytes() != verifier_tx.total_bytes()
    {
        return Err("X4c claim-reduction accounting diverged".to_owned());
    }
    Ok(X4cGpt2ReducedClaims { frames, proofs, points, prover_values, verifier_keys })
}

fn cohort_index_for_weight(cohort_id: u32) -> Result<usize, String> {
    match cohort_id {
        X4C_WEXT_MU26_COHORT_ID => Ok(0),
        X4C_WEXT_MU22_COHORT_ID => Ok(1),
        X4C_WEXT_MU20_COHORT_ID => Ok(2),
        _ => Err("unknown GPT-2 weight cohort".to_owned()),
    }
}

fn cohort_index_for_auxiliary(ell: usize) -> Result<usize, String> {
    match ell {
        17 => Ok(3),
        16 => Ok(4),
        _ => Err("unknown GPT-2 auxiliary cohort".to_owned()),
    }
}

/// Execute the complete real-weight X4c PCS seam after the model proof has
/// produced and verified its 102 authenticated parent claims.
///
/// The caller must obtain `freshness_record_digest` from
/// `ProductionFaseDConnection::begin_x4_response` before making either the
/// PCG pools or selected draw tape available.
#[allow(clippy::too_many_arguments)]
pub fn execute_real_weight_x4c<R: X4cArenaRuntimeV4>(
    model: &Gpt2Model,
    inventory: &X4cGpt2Inventory,
    cohorts: &[X4cRamModelGlobalCohortV4],
    evaluations: &X4cGpt2EvaluationTables,
    epoch: u64,
    freshness_record_digest: Digest,
    selected_tape: X4cSelectedQueryTapeV4,
    prover_output: &ModelOut,
    verifier_output: &ModelOutV,
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
    runtime: &mut R,
    seal_config: X4cSealConfigV4,
) -> Result<X4cGpt2OnlineResult, String> {
    if epoch == 0
        || freshness_record_digest == [0; 32]
        || cohorts.len() != X4C_GPT2_COHORTS
        || evaluations.slots.len() != X4C_GPT2_COHORTS
        || selected_tape.draw_count() != 111
    {
        return Err("X4c online prerequisite is missing".to_owned());
    }
    inventory.validate()?;
    for ((expected, cohort), tables) in
        inventory.cohort_configs.iter().zip(cohorts).zip(&evaluations.slots)
    {
        if cohort.commitment().config != *expected
            || tables.len() != expected.slot_descriptors.len()
        {
            return Err("X4c online cohort/evaluation identity mismatch".to_owned());
        }
    }
    let leaves = inventory
        .blocks
        .iter()
        .map(|block| {
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            Ok(ManifestLeafFrame {
                descriptor_digest: block.descriptor_digest,
                ordered_roots: vec![cohorts[weight_index].root(), cohorts[auxiliary_index].root()],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let manifest = ManifestTreeV4::build(
        manifest_id_digest_v4(inventory.model_config_digest, inventory.weights_digest, epoch),
        leaves,
    )
    .map_err(|error| format!("X4c manifest: {error:?}"))?;
    let model_root = manifest.root();
    let descriptor_digests =
        inventory.blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let manifest_frames = manifest
        .open(&descriptor_digests)
        .map_err(|error| format!("X4c manifest opening: {error:?}"))?;

    let fulls_before = stream.counters.full_corrs;
    let verifier_fulls_before = verifier.counters.full_corrs;
    let reduced = reduce_real_weight_claims(
        model,
        inventory,
        prover_output,
        verifier_output,
        stream,
        verifier,
        prover_tx,
        verifier_tx,
    )?;
    let mut weight_points = Vec::with_capacity(inventory.blocks.len());
    let mut auxiliary_points = Vec::with_capacity(inventory.blocks.len());
    let mut auxiliary_values = Vec::with_capacity(inventory.blocks.len());
    let mut public_h = Vec::with_capacity(inventory.blocks.len());
    for (index, block) in inventory.blocks.iter().enumerate() {
        let mut weight_point = reduced.points[index].clone();
        weight_point.push(Fp2::ZERO);
        let auxiliary_point = canonical_auxiliary_point(&reduced.points[index], block.ell())?;
        let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
        let table = evaluations.slots[auxiliary_index]
            .get(usize::from(block.auxiliary_slot))
            .and_then(Option::as_ref)
            .ok_or_else(|| "missing X4c auxiliary evaluation table".to_owned())?;
        let auxiliary_value = evaluate_multilinear_table(table, &auxiliary_point)
            .map_err(|error| format!("X4c auxiliary evaluation: {error:?}"))?;
        public_h.push(reduced.prover_values[index].x + auxiliary_value);
        weight_points.push(weight_point);
        auxiliary_points.push(auxiliary_point);
        auxiliary_values.push(auxiliary_value);
    }

    let mut pending_prover = Vec::with_capacity(inventory.blocks.len());
    let mut pending_verifier = Vec::with_capacity(inventory.blocks.len());
    let mut m9_frames = Vec::with_capacity(inventory.blocks.len());
    for (index, block) in inventory.blocks.iter().enumerate() {
        let (pending, frame) = authenticate_pending_aux_prover_v4(
            block.descriptor_digest,
            auxiliary_values[index],
            stream,
            block.m9_domain,
            prover_tx,
        )
        .map_err(|error| format!("X4c M9 prover: {error:?}"))?;
        let verifier_pending =
            authenticate_pending_aux_verifier_v4(&frame, verifier, block.m9_domain, verifier_tx)
                .map_err(|error| format!("X4c M9 verifier: {error:?}"))?;
        pending_prover.push(pending);
        pending_verifier.push(verifier_pending);
        m9_frames.push(frame);
    }
    let prover_blocks = pending_prover
        .into_iter()
        .enumerate()
        .map(|(index, pending_aux)| {
            let block = &inventory.blocks[index];
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            let weight_evaluations = evaluations.slots[weight_index]
                .get(usize::from(block.weight_slot))
                .and_then(Option::as_ref)
                .ok_or_else(|| "missing X4c weight evaluation table".to_owned())?;
            let auxiliary_evaluations = evaluations.slots[auxiliary_index]
                .get(usize::from(block.auxiliary_slot))
                .and_then(Option::as_ref)
                .ok_or_else(|| "missing X4c auxiliary evaluation table".to_owned())?;
            Ok(AuthenticatedOutputBlockProverV4 {
                descriptor_digest: block.descriptor_digest,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialProverV4 {
                    cohort: &cohorts[weight_index],
                    slot: block.weight_slot,
                    evaluations: weight_evaluations,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialProverV4 {
                    cohort: &cohorts[auxiliary_index],
                    slot: block.auxiliary_slot,
                    evaluations: auxiliary_evaluations,
                    target_point: &auxiliary_points[index],
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let verifier_blocks = pending_verifier
        .into_iter()
        .enumerate()
        .map(|(index, pending_aux)| {
            let block = &inventory.blocks[index];
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            Ok(AuthenticatedOutputBlockVerifierV4 {
                descriptor_digest: block.descriptor_digest,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialVerifierV4 {
                    commitment: cohorts[weight_index].commitment(),
                    slot: block.weight_slot,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialVerifierV4 {
                    commitment: cohorts[auxiliary_index].commitment(),
                    slot: block.auxiliary_slot,
                    target_point: &auxiliary_points[index],
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let prefix = AuthenticatedOutputLinkPrefixV4 {
        epoch,
        claim_frames: &reduced.frames,
        descriptor_digests: &descriptor_digests,
        ordered_h_symbols: &public_h,
        m9_frames: &m9_frames,
        round_correlation_domain_ids: &inventory.link_round_domains,
    };
    let prover_permit = X4OpeningRegistryV4::default()
        .authorize_after_persistent_freshness(model_root, epoch, freshness_record_digest)
        .map_err(|error| format!("X4c prover permit: {error:?}"))?;
    let (link_proof, bound_prover, link_metrics, x4c_metrics, phase_walls, selected_draws) =
        prove_authenticated_output_link_x4c_v4(
            prover_permit,
            model_root,
            prover_blocks,
            prefix,
            stream,
            prover_tx,
            selected_tape,
            runtime,
            seal_config,
        )
        .map_err(|error| format!("X4c link prover: {error:?}"))?;
    let verifier_permit = X4OpeningRegistryV4::default()
        .authorize_after_persistent_freshness(model_root, epoch, freshness_record_digest)
        .map_err(|error| format!("X4c verifier permit: {error:?}"))?;
    let verify_started = Instant::now();
    let bound_verifier = verify_authenticated_output_link_x4c_v4(
        verifier_permit,
        model_root,
        verifier_blocks,
        prefix,
        &link_proof,
        &selected_draws,
        verifier,
        verifier_tx,
    )
    .map_err(|error| format!("X4c link verifier: {error:?}"))?;
    let verify_wall_ns = u64::try_from(verify_started.elapsed().as_nanos())
        .map(|value| value.max(1))
        .map_err(|_| "X4c verifier wall overflows u64".to_owned())?;
    let zero_batch = prove_bound_response_zero_batch_v4(
        &reduced.prover_values,
        &bound_prover,
        &public_h,
        stream,
        X4C_ZERO_DOMAIN,
        prover_tx,
    )
    .map_err(|error| format!("X4c response ZeroBatch prover: {error:?}"))?;
    verify_bound_response_zero_batch_v4(
        &reduced.verifier_keys,
        &bound_verifier,
        &public_h,
        &zero_batch,
        verifier,
        X4C_ZERO_DOMAIN,
        verifier_tx,
    )
    .map_err(|error| format!("X4c response ZeroBatch verifier: {error:?}"))?;

    let initial_groups = inventory
        .cohort_configs
        .iter()
        .zip(cohorts)
        .map(|(config, cohort)| InitialOpeningScheduleV4 {
            cohort_id: config.identity.cohort_id,
            domain_log2: config.outer_depth(),
            slot_count: config.slot_descriptors.len() as u16,
            touched_slots: config
                .slot_descriptors
                .iter()
                .enumerate()
                .filter_map(|(slot, descriptor)| descriptor.map(|_| slot as u16))
                .collect(),
            root_digest: cohort.root(),
        })
        .collect::<Vec<_>>();
    let schedule = PackedOpeningScheduleV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        initial_groups,
        fold_frames: link_proof.global_folding.fold_frames.clone(),
        draw_width: 30,
        query_draws: selected_draws,
    };
    schedule.validate().map_err(|error| format!("X4c packed schedule: {error:?}"))?;
    let response = ResponseEnvelopeFrameV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        descriptor_digests: descriptor_digests.clone(),
        manifest_frames: manifest_frames.clone(),
        claim_frames: reduced.frames.clone(),
        ordered_h_symbols: public_h,
        m9_frames,
        authenticated_output_link_frame: link_proof.frame.clone(),
        fold_frames: link_proof.global_folding.fold_frames.clone(),
        packed_opening_frame: link_proof.global_folding.packed_opening.clone(),
        zero_batch_frame: zero_batch,
    };
    response
        .validate_statement(
            model_root,
            epoch,
            &descriptor_digests,
            &reduced.frames,
            &inventory.link_round_domains,
            &schedule,
        )
        .map_err(|error| format!("X4c response statement: {error:?}"))?;
    verify_response_manifest_v4(
        &response,
        inventory.model_config_digest,
        inventory.weights_digest,
        &descriptor_digests,
    )
    .map_err(|error| format!("X4c response manifest: {error:?}"))?;
    let encoded_pcs = FrameV4::ResponseEnvelope(response.clone())
        .encode()
        .map_err(|error| format!("X4c response encode: {error:?}"))?;
    if encoded_pcs.len() as u64 != X4C_GPT2_PCS_BYTES
        || stream.counters.full_corrs.checked_sub(fulls_before) != Some(X4C_GPT2_FULL_CORRELATIONS)
        || verifier.counters.full_corrs.checked_sub(verifier_fulls_before)
            != Some(X4C_GPT2_FULL_CORRELATIONS)
        || prover_tx.total_bytes() != verifier_tx.total_bytes()
        || x4c_metrics.io != Default::default()
        || x4c_metrics.execution.query_gather_calls != 1
        || x4c_metrics.sampling_soundness_credit_bits != 0
    {
        return Err("X4c exact byte/correlation/I/O/gather invariant failed".to_owned());
    }
    Ok(X4cGpt2OnlineResult {
        model_root,
        manifest_frames,
        reduced,
        link_proof,
        link_metrics,
        x4c_metrics,
        seal_wall_ns: phase_walls.seal_wall_ns,
        open_wall_ns: phase_walls.open_wall_ns,
        verify_wall_ns,
        response,
        encoded_pcs,
    })
}

/// Canonical auxiliary point `suffix(z, ell-1) || 0`.
pub fn canonical_auxiliary_point(z: &[Fp2], ell: usize) -> Result<Vec<Fp2>, String> {
    if ell == 0 || ell > z.len() + 1 {
        return Err("invalid canonical auxiliary-point geometry".to_owned());
    }
    let suffix = ell - 1;
    let mut point = z[z.len() - suffix..].to_vec();
    point.push(Fp2::ZERO);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_mac::ProverAuthed;

    fn fake_output() -> ModelOut {
        let claim = |point_len: usize, auth_domain: u64| WeightClaimP {
            point: vec![Fp2::from_base(Fp::new(auth_domain)); point_len],
            value: ProverAuthed::from_public(Fp2::from_base(Fp::new(auth_domain + 1))),
            auth_domain,
        };
        let weight_claims = (0..2 * 4 * L)
            .map(|index| {
                let tensor = index % 4;
                claim(if tensor == 1 { 20 } else { 22 }, 0x5000 + index as u64)
            })
            .collect();
        let embed_claims = (0..6)
            .map(|index| claim(if index % 3 == 2 { 20 } else { 26 }, 0x6000 + index as u64))
            .collect();
        ModelOut {
            weight_claims,
            chunk_p1_s: Vec::new(),
            chunk_p2_s: Vec::new(),
            embed_claims,
            bytes: Default::default(),
            ctr_instances: Default::default(),
            ctr_other: Default::default(),
            lookups: Vec::new(),
            corr_counters: Default::default(),
        }
    }

    #[test]
    fn production_inventory_has_exact_frozen_geometry_and_correlations() {
        let output = fake_output();
        let domains = X4cGpt2Inventory::parent_domains_from_output(&output).unwrap();
        let inventory = X4cGpt2Inventory::new([0x11; 32], [0x22; 32], &domains).unwrap();
        inventory.validate().unwrap();
        assert_eq!(inventory.blocks.len(), 51);
        assert_eq!(
            inventory.blocks.iter().map(|block| block.mu()).collect::<Vec<_>>(),
            std::iter::repeat_n(26, 2)
                .chain(std::iter::repeat_n(22, 36))
                .chain(std::iter::repeat_n(20, 13))
                .collect::<Vec<_>>()
        );
        assert_eq!(inventory.claim_frames(&output).unwrap().len(), 102);
        assert_eq!(X4C_GPT2_FULL_CORRELATIONS, 2_314);
        assert_eq!(X4C_GPT2_DURABLE_TIER_BYTES, 9_618_587_808);
    }

    #[test]
    fn parent_domain_change_is_fail_closed() {
        let mut output = fake_output();
        let domains = X4cGpt2Inventory::parent_domains_from_output(&output).unwrap();
        let inventory = X4cGpt2Inventory::new([0x11; 32], [0x22; 32], &domains).unwrap();
        output.embed_claims[0].auth_domain += 1;
        assert!(inventory.validate_parent_domains(&output).is_err());
    }

    #[test]
    fn padded_matrix_and_uniform_xof_are_exact_and_deterministic() {
        let mut padded = vec![Fp2::ZERO; 16];
        fill_padded_matrix(&mut padded, &[1, -2, 3, -4, 5, -6], 2, 3, 4).unwrap();
        assert_eq!(padded[0], Fp2::from_base(Fp::new(1)));
        assert_eq!(padded[1], Fp2::from_base(Fp::from_i64(-2)));
        assert_eq!(padded[3], Fp2::ZERO);
        assert_eq!(padded[4], Fp2::from_base(Fp::from_i64(-4)));
        assert_eq!(padded[7], Fp2::ZERO);
        assert!(padded[8..].iter().all(|value| *value == Fp2::ZERO));

        let mut first = UniformFp2Xof::new([7; 32], [8; 32], OracleKindV4::WeightExtension);
        let mut second = UniformFp2Xof::new([7; 32], [8; 32], OracleKindV4::WeightExtension);
        for _ in 0..128 {
            assert_eq!(first.fp2(), second.fp2());
        }
    }

    #[test]
    fn canonical_auxiliary_point_uses_suffix_and_zero() {
        let z = (0..26).map(|value| Fp2::from_base(Fp::new(value))).collect::<Vec<_>>();
        let point = canonical_auxiliary_point(&z, 17).unwrap();
        assert_eq!(&point[..16], &z[10..]);
        assert_eq!(point[16], Fp2::ZERO);
    }

    #[test]
    fn seed_commitment_is_domain_separated() {
        assert_eq!(mask_seed_commitment([1; 32]), mask_seed_commitment([1; 32]));
        assert_ne!(mask_seed_commitment([1; 32]), mask_seed_commitment([2; 32]));
    }
}

//! C6SPR1 scaled differential over the generic weighted fraction-tree GKR.
//!
//! The clear CPU/reference seam proves all seven preregistered rational sums.
//! Its blind counterpart reuses the installed authenticated LogUp grammar and
//! leaves fourteen authenticated MLE claims for the joint PCS boundary.

use super::*;
use crate::logup::{
    blind_prove_weighted_frac_tree, blind_verify_frac_tree, prove_weighted_frac_tree,
    verify_frac_tree, BlindFracProof, BlindLayerProof, Counters, Doms, FracProof, ProdKeyTriples,
    ProdTriples,
};
use volta_field::P;
use volta_mac::{CorrelationStream, VerifierCtx};

mod joint_leaf;
pub use joint_leaf::*;

const C6_SPARSE_RATIONAL_SUBCHECKS: usize = 7;
const C6_SPARSE_RATIONAL_GKR_STREAM_DOMAINS: [u64; C6_SPARSE_RATIONAL_SUBCHECKS] = [
    0xC6_53_50_52_01,
    0xC6_53_50_52_02,
    0xC6_53_50_52_03,
    0xC6_53_50_52_04,
    0xC6_53_50_52_05,
    0xC6_53_50_52_06,
    0xC6_53_50_52_07,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum C6SparseRationalSubcheck {
    RecurrenceAnchor = 0,
    RecurrenceLinear = 1,
    RecurrenceScale = 2,
    RuntimePlan = 3,
    RuntimeTable = 4,
    SourceBoundary = 5,
    SourcePlan = 6,
}

impl C6SparseRationalSubcheck {
    const ALL: [Self; C6_SPARSE_RATIONAL_SUBCHECKS] = [
        Self::RecurrenceAnchor,
        Self::RecurrenceLinear,
        Self::RecurrenceScale,
        Self::RuntimePlan,
        Self::RuntimeTable,
        Self::SourceBoundary,
        Self::SourcePlan,
    ];

    fn index(self) -> usize {
        self as usize
    }
}

const C6_SPARSE_RESPONSE_BLOCKS: usize = 4;
const C6_SPARSE_PLAN_BLOCKS: usize = 4;
const C6_SPARSE_RESPONSE_OPENINGS: usize = 6;
const C6_SPARSE_PLAN_OPENINGS: usize = 3;
const C6_SPARSE_PHYSICAL_RESPONSE_OPENINGS: usize = 2 * C6_SPARSE_RESPONSE_OPENINGS;
const C6_SPARSE_PACKING_MAX_SCALED_LOG2: u8 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalPackedOracleReference {
    base_domain_log2: u8,
    operation_plan_digest: C6ResidualDigest,
    lane_digests: [C6ResidualDigest; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    runtime_instance: C6OperationPlanInstanceIdentity,
    response_values: Vec<Fp2>,
    plan_values: Vec<Fp2>,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
}

impl C6SparseRationalPackedOracleReference {
    pub fn base_domain_log2(&self) -> u8 {
        self.base_domain_log2
    }

    pub fn response_domain_log2(&self) -> u8 {
        self.base_domain_log2 + 2
    }

    pub fn physical_response_domain_log2(&self) -> u8 {
        self.base_domain_log2 + 3
    }

    pub fn plan_domain_log2(&self) -> u8 {
        self.base_domain_log2 + 2
    }

    pub fn response_digest(&self) -> C6ResidualDigest {
        self.response_digest
    }

    pub fn plan_digest(&self) -> C6ResidualDigest {
        self.plan_digest
    }

    pub fn opening_points(
        &self,
        input_point: &[Fp2],
    ) -> C6ResidualResult<C6SparseRationalPackedOpeningPoints> {
        C6SparseRationalPackedOpeningPoints::new(
            self.base_domain_log2,
            self.response_digest,
            self.plan_digest,
            input_point,
        )
    }

    pub fn physical_opening_points(
        &self,
        input_point: &[Fp2],
    ) -> C6ResidualResult<C6SparseRationalPhysicalOpeningPoints> {
        C6SparseRationalPhysicalOpeningPoints::new(
            self.base_domain_log2,
            self.response_digest,
            self.plan_digest,
            input_point,
        )
    }

    /// Base-field physical response polynomial: all `c0` coefficients,
    /// followed by all `c1` coefficients under one final limb variable.
    pub fn physical_response_values(&self) -> Vec<Fp> {
        self.response_values
            .iter()
            .map(|value| value.c0)
            .chain(self.response_values.iter().map(|value| value.c1))
            .collect()
    }

    /// The fixed plan is base-valued and needs no limb selector.
    pub fn physical_plan_values(&self) -> C6ResidualResult<Vec<Fp>> {
        if self.plan_values.iter().any(|value| value.c1 != Fp::ZERO) {
            return Err(C6ResidualError::new("C6SPR3 fixed plan contains a non-base coefficient"));
        }
        Ok(self.plan_values.iter().map(|value| value.c0).collect())
    }

    pub fn evaluate_physical_response_openings(
        &self,
        points: &C6SparseRationalPhysicalOpeningPoints,
    ) -> C6ResidualResult<[Fp2; C6_SPARSE_PHYSICAL_RESPONSE_OPENINGS]> {
        points.validate(self)?;
        let values =
            self.physical_response_values().into_iter().map(Fp2::from_base).collect::<Vec<_>>();
        Ok(std::array::from_fn(|index| crate::mle::eval_mle(&values, &points.response[index])))
    }

    pub fn evaluate_physical_plan_openings(
        &self,
        points: &C6SparseRationalPhysicalOpeningPoints,
    ) -> C6ResidualResult<[Fp2; C6_SPARSE_PLAN_OPENINGS]> {
        points.validate(self)?;
        let values =
            self.physical_plan_values()?.into_iter().map(Fp2::from_base).collect::<Vec<_>>();
        Ok(std::array::from_fn(|index| crate::mle::eval_mle(&values, &points.plan[index])))
    }

    pub fn evaluate_response_openings(
        &self,
        points: &C6SparseRationalPackedOpeningPoints,
    ) -> C6ResidualResult<[Fp2; C6_SPARSE_RESPONSE_OPENINGS]> {
        points.validate(self)?;
        Ok(std::array::from_fn(|index| {
            crate::mle::eval_mle(&self.response_values, &points.response[index])
        }))
    }

    pub fn evaluate_plan_openings(
        &self,
        points: &C6SparseRationalPackedOpeningPoints,
    ) -> C6ResidualResult<[Fp2; C6_SPARSE_PLAN_OPENINGS]> {
        points.validate(self)?;
        Ok(std::array::from_fn(|index| {
            crate::mle::eval_mle(&self.plan_values, &points.plan[index])
        }))
    }

    pub fn validate(
        &self,
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        lanes: [&C6ResidualFoldedTerminalAdjointLaneReference;
            C6_RESIDUAL_PROOF_REPETITIONS as usize],
    ) -> C6ResidualResult<()> {
        let expected = compile_c6_sparse_rational_packed_oracle_reference(
            operation_plan,
            extraction,
            runtime,
            lanes,
        )?;
        if *self != expected {
            return Err(C6ResidualError::new(
                "C6SPR2 packed oracle differs from the canonical prechallenge layout",
            ));
        }
        Ok(())
    }

    pub fn validate_relation(
        &self,
        relation: &C6ResidualSparseRationalRelationReference,
    ) -> C6ResidualResult<()> {
        let base_rows = 1usize << self.base_domain_log2;
        let lane_0 = &self.response_values[..base_rows];
        let lane_1 = &self.response_values[base_rows..2 * base_rows];
        let packed_runtime_and_boundaries = &self.response_values[2 * base_rows..3 * base_rows];
        let mu = &self.response_values[3 * base_rows..4 * base_rows];
        let node_count = relation.combined_nodes.len();
        let source_count = relation.combined_sources.len();
        let source_capacity = base_rows / 4;
        if node_count > base_rows
            || source_count > source_capacity
            || relation.node_scale_values.len() != node_count
            || relation.combined_injection.len() != node_count
        {
            return Err(C6ResidualError::new(
                "C6SPR2 relation exceeds its packed oracle capacities",
            ));
        }
        let zeta = relation.sparse_challenges.lane_batch;
        if (0..node_count).any(|index| {
            relation.combined_nodes[index] != lane_0[index] + zeta * lane_1[index]
                || relation.node_scale_values[index] != mu[index]
        }) {
            return Err(C6ResidualError::new(
                "C6SPR2 committed lanes or mu differ from the postchallenge relation",
            ));
        }
        let g0_start = base_rows / 2;
        let g1_start = g0_start + source_capacity;
        if (0..source_count).any(|source| {
            relation.combined_sources[source]
                != packed_runtime_and_boundaries[g0_start + source]
                    + zeta * packed_runtime_and_boundaries[g1_start + source]
        }) {
            return Err(C6ResidualError::new(
                "C6SPR2 committed source boundaries differ from the postchallenge relation",
            ));
        }
        Ok(())
    }
}

/// Physical base-field points for the corrected C6SPR3 backend boundary.
/// Response order is semantic opening major, then limb `(c0, c1)`; the plan
/// retains its three base-valued points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalPhysicalOpeningPoints {
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    input_point: Vec<Fp2>,
    response: [Vec<Fp2>; C6_SPARSE_PHYSICAL_RESPONSE_OPENINGS],
    plan: [Vec<Fp2>; C6_SPARSE_PLAN_OPENINGS],
    digest: C6ResidualDigest,
}

impl C6SparseRationalPhysicalOpeningPoints {
    pub fn new(
        base_domain_log2: u8,
        response_digest: C6ResidualDigest,
        plan_digest: C6ResidualDigest,
        input_point: &[Fp2],
    ) -> C6ResidualResult<Self> {
        let semantic = C6SparseRationalPackedOpeningPoints::new(
            base_domain_log2,
            response_digest,
            plan_digest,
            input_point,
        )?;
        let response = semantic
            .response
            .iter()
            .flat_map(|point| {
                [Fp2::ZERO, Fp2::ONE].into_iter().map(move |limb| {
                    point.iter().copied().chain(std::iter::once(limb)).collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| C6ResidualError::new("C6SPR3 physical response-point census mismatch"))?;
        let mut points = Self {
            base_domain_log2,
            response_digest,
            plan_digest,
            input_point: input_point.to_vec(),
            response,
            plan: semantic.plan,
            digest: [0; 32],
        };
        points.digest = points.recompute_digest();
        Ok(points)
    }

    pub fn response(&self) -> &[Vec<Fp2>; C6_SPARSE_PHYSICAL_RESPONSE_OPENINGS] {
        &self.response
    }

    pub fn plan(&self) -> &[Vec<Fp2>; C6_SPARSE_PLAN_OPENINGS] {
        &self.plan
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn validate(&self, packed: &C6SparseRationalPackedOracleReference) -> C6ResidualResult<()> {
        let expected = Self::new(
            packed.base_domain_log2,
            packed.response_digest,
            packed.plan_digest,
            &self.input_point,
        )?;
        if *self != expected {
            return Err(C6ResidualError::new("C6SPR3 physical opening points are noncanonical"));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> C6ResidualDigest {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6/sparse-rational-physical-points/v1");
        hasher.update(&[self.base_domain_log2]);
        hasher.update(&self.response_digest);
        hasher.update(&self.plan_digest);
        for (role, points) in [(0u8, self.response.as_slice()), (1u8, self.plan.as_slice())] {
            hasher.update(&[role]);
            hasher.update(&(points.len() as u64).to_le_bytes());
            for (ordinal, point) in points.iter().enumerate() {
                hasher.update(&(ordinal as u64).to_le_bytes());
                hasher.update(&(point.len() as u64).to_le_bytes());
                for &coordinate in point {
                    hash_fp2(&mut hasher, coordinate);
                }
            }
        }
        *hasher.finalize().as_bytes()
    }
}

pub fn fold_c6_sparse_physical_response_openings(
    physical: &[Fp2; C6_SPARSE_PHYSICAL_RESPONSE_OPENINGS],
) -> [Fp2; C6_SPARSE_RESPONSE_OPENINGS] {
    let extension_generator = Fp2::new(Fp::ZERO, Fp::ONE);
    std::array::from_fn(|index| physical[2 * index] + extension_generator * physical[2 * index + 1])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalPackedOpeningPoints {
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    input_point: Vec<Fp2>,
    response: [Vec<Fp2>; C6_SPARSE_RESPONSE_OPENINGS],
    plan: [Vec<Fp2>; C6_SPARSE_PLAN_OPENINGS],
    digest: C6ResidualDigest,
}

impl C6SparseRationalPackedOpeningPoints {
    pub fn new(
        base_domain_log2: u8,
        response_digest: C6ResidualDigest,
        plan_digest: C6ResidualDigest,
        input_point: &[Fp2],
    ) -> C6ResidualResult<Self> {
        let base_dimension = usize::from(base_domain_log2);
        if input_point.len() != base_dimension || base_dimension < 2 {
            return Err(C6ResidualError::new("C6SPR2 packed input point has the wrong dimension"));
        }
        let append = |prefix: &[Fp2], suffix: &[Fp2]| {
            prefix.iter().chain(suffix).copied().collect::<Vec<_>>()
        };
        let response = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ONE]),
            append(&input_point[..base_dimension - 1], &[Fp2::ZERO, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..base_dimension - 2], &[Fp2::ZERO, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..base_dimension - 2], &[Fp2::ONE, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
        ];
        let plan = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ZERO, Fp2::ONE]),
        ];
        let mut points = Self {
            base_domain_log2,
            response_digest,
            plan_digest,
            input_point: input_point.to_vec(),
            response,
            plan,
            digest: [0; 32],
        };
        points.digest = points.recompute_digest();
        Ok(points)
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn input_point(&self) -> &[Fp2] {
        &self.input_point
    }

    pub fn response(&self) -> &[Vec<Fp2>; C6_SPARSE_RESPONSE_OPENINGS] {
        &self.response
    }

    pub fn plan(&self) -> &[Vec<Fp2>; C6_SPARSE_PLAN_OPENINGS] {
        &self.plan
    }

    pub fn validate(&self, packed: &C6SparseRationalPackedOracleReference) -> C6ResidualResult<()> {
        let expected = Self::new(
            packed.base_domain_log2,
            packed.response_digest,
            packed.plan_digest,
            &self.input_point,
        )?;
        if *self != expected {
            return Err(C6ResidualError::new(
                "C6SPR2 ordered packed opening points are noncanonical",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> C6ResidualDigest {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6/sparse-rational-packed-points/v1");
        hasher.update(&[self.base_domain_log2]);
        hasher.update(&self.response_digest);
        hasher.update(&self.plan_digest);
        for (role, points) in [(0u8, self.response.as_slice()), (1u8, self.plan.as_slice())] {
            hasher.update(&[role]);
            hasher.update(&(points.len() as u64).to_le_bytes());
            for (ordinal, point) in points.iter().enumerate() {
                hasher.update(&(ordinal as u64).to_le_bytes());
                hasher.update(&(point.len() as u64).to_le_bytes());
                for &coordinate in point {
                    hash_fp2(&mut hasher, coordinate);
                }
            }
        }
        *hasher.finalize().as_bytes()
    }
}

fn sparse_plan_opcode(kind: C6InstalledOperationKind) -> Fp2 {
    let code = match kind {
        C6InstalledOperationKind::Source => 1,
        C6InstalledOperationKind::StructuralZero => 2,
        C6InstalledOperationKind::PublicInput => 3,
        C6InstalledOperationKind::Add => 4,
        C6InstalledOperationKind::Sub => 5,
        C6InstalledOperationKind::Scale => 6,
    };
    Fp2::from_base(Fp::new(code))
}

/// Lagrange selector for one of the six canonical operation codes.
///
/// The fixed plan uses only the base-field points `1..=6` on active rows.
/// Padding must therefore use one of those canonical codes before this
/// selector is used by a virtual-polynomial terminal equation.
fn c6_sparse_opcode_selector(kind: C6InstalledOperationKind, opcode: Fp2) -> Fp2 {
    let selected = kind as u8;
    let mut numerator = Fp2::ONE;
    let mut denominator = Fp::ONE;
    for code in 1u8..=6 {
        if code == selected {
            continue;
        }
        numerator = numerator * (opcode - Fp2::from_base(Fp::new(u64::from(code))));
        denominator = denominator * Fp::from_i64(i64::from(selected) - i64::from(code));
    }
    numerator.mul_base(denominator.inv())
}

/// Evaluate the MLEs of `[row < active_rows]` and
/// `[row < active_rows] * row` at one LSB-first point without materializing
/// either public column.
///
/// `[0, active_rows)` is split into aligned dyadic blocks.  Each block fixes
/// only its high bits; summing over its free low bits gives the block weight,
/// while their conditional index is `offset + sum_j 2^j point[j]`.
fn c6_sparse_range_mle_moments(active_rows: usize, point: &[Fp2]) -> C6ResidualResult<(Fp2, Fp2)> {
    if point.len() >= usize::BITS as usize || point.len() >= u64::BITS as usize {
        return Err(C6ResidualError::new("C6SPR2 public range dimension exceeds machine index"));
    }
    let capacity = 1usize << point.len();
    if active_rows > capacity {
        return Err(C6ResidualError::new("C6SPR2 public range exceeds its MLE domain"));
    }

    let mut active = Fp2::ZERO;
    let mut active_index = Fp2::ZERO;
    let mut offset = 0usize;
    let mut remaining = active_rows;
    while remaining != 0 {
        let block_log2 = (usize::BITS - 1 - remaining.leading_zeros()) as usize;
        let block_rows = 1usize << block_log2;
        debug_assert_eq!(offset % block_rows, 0);

        let mut block_weight = Fp2::ONE;
        for (bit, &coordinate) in point.iter().enumerate().skip(block_log2) {
            block_weight = block_weight
                * if (offset >> bit) & 1 == 1 { coordinate } else { Fp2::ONE - coordinate };
        }
        let offset_u64 = u64::try_from(offset)
            .map_err(|_| C6ResidualError::new("C6SPR2 public range offset exceeds u64"))?;
        let mut conditional_index = Fp2::from_base(Fp::new(offset_u64));
        for (bit, &coordinate) in point.iter().enumerate().take(block_log2) {
            conditional_index += coordinate * Fp2::from_base(Fp::new(1u64 << bit));
        }
        active += block_weight;
        active_index += block_weight * conditional_index;
        offset += block_rows;
        remaining -= block_rows;
    }
    Ok((active, active_index))
}

fn hash_packed_oracle(
    domain: &'static str,
    base_domain_log2: u8,
    operation_plan_digest: C6ResidualDigest,
    lane_digests: &[C6ResidualDigest],
    runtime_instance: C6OperationPlanInstanceIdentity,
    values: &[Fp2],
) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&[base_domain_log2]);
    hasher.update(&operation_plan_digest);
    for digest in lane_digests {
        hasher.update(digest);
    }
    hasher.update(&runtime_instance.version.to_le_bytes());
    hasher.update(&runtime_instance.topology_digest);
    hasher.update(&runtime_instance.public_input_count.to_le_bytes());
    hasher.update(&runtime_instance.scalar_input_count.to_le_bytes());
    hasher.update(&runtime_instance.instance_digest);
    hasher.update(&(values.len() as u64).to_le_bytes());
    for &value in values {
        hash_fp2(&mut hasher, value);
    }
    *hasher.finalize().as_bytes()
}

/// Materialize the exact C6SPR2 response and fixed-plan packings before any
/// sparse lane-batch or rational challenge is supplied.
pub fn compile_c6_sparse_rational_packed_oracle_reference(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    lanes: [&C6ResidualFoldedTerminalAdjointLaneReference; C6_RESIDUAL_PROOF_REPETITIONS as usize],
) -> C6ResidualResult<C6SparseRationalPackedOracleReference> {
    compile_c6_sparse_rational_packed_oracle_materialized(
        operation_plan,
        extraction,
        runtime,
        lanes,
        false,
    )
}

/// Materialize the frozen physical D28 response and D27 public plan inputs.
///
/// This entry point is reserved for a resource-instrumented production
/// campaign.  It does not grant PCS, memory, timing or GPU credit by itself.
pub fn compile_c6_sparse_rational_packed_oracle_production(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    lanes: [&C6ResidualFoldedTerminalAdjointLaneReference; C6_RESIDUAL_PROOF_REPETITIONS as usize],
) -> C6ResidualResult<C6SparseRationalPackedOracleReference> {
    compile_c6_sparse_rational_packed_oracle_materialized(
        operation_plan,
        extraction,
        runtime,
        lanes,
        true,
    )
}

fn compile_c6_sparse_rational_packed_oracle_materialized(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    lanes: [&C6ResidualFoldedTerminalAdjointLaneReference; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    require_production: bool,
) -> C6ResidualResult<C6SparseRationalPackedOracleReference> {
    let topology = operation_plan.topology();
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 source count exceeds usize"))?;
    let base_rows = node_count
        .max(
            scalar_count
                .checked_mul(2)
                .ok_or_else(|| C6ResidualError::new("C6SPR2 Scale-runtime packing overflows"))?,
        )
        .max(
            source_count
                .checked_mul(4)
                .ok_or_else(|| C6ResidualError::new("C6SPR2 source packing overflows"))?,
        )
        .max(2)
        .checked_next_power_of_two()
        .ok_or_else(|| C6ResidualError::new("C6SPR2 base domain overflows"))?;
    let base_domain_log2 = u8::try_from(base_rows.trailing_zeros())
        .map_err(|_| C6ResidualError::new("C6SPR2 base dimension exceeds u8"))?;
    let production_geometry = base_domain_log2 == 25
        && topology.source_count == 4_975_525
        && topology.canonical_node_count == 28_845_631
        && topology.scalar_input_count == 10_828_852;
    if (require_production && !production_geometry)
        || (!require_production && base_domain_log2 >= C6_SPARSE_PACKING_MAX_SCALED_LOG2)
        || operation_plan.operation_kinds().len() != node_count
        || scalar_count > base_rows / 2
        || source_count > base_rows / 4
        || lanes[0].proof_repetition != 0
        || lanes[1].proof_repetition != 1
        || lanes[0].terminal_metadata_digest != lanes[1].terminal_metadata_digest
        || lanes[0].relation_challenges_digest != lanes[1].relation_challenges_digest
        || lanes[0].output_beta != lanes[1].output_beta
        || lanes.iter().any(|lane| {
            lane.node_coefficients.len() != node_count
                || lane.source_coefficients.len() != source_count
        })
    {
        return Err(C6ResidualError::new(format!(
            "C6SPR2 {} packing geometry or lane boundary mismatch: base_log2={base_domain_log2}, base_rows={base_rows}, runtime={}, sources={source_count}, lane_nodes={}/{}, lane_sources={}/{}",
            if require_production { "production" } else { "scaled" },
            scalar_count,
            lanes[0].node_coefficients.len(),
            lanes[1].node_coefficients.len(),
            lanes[0].source_coefficients.len(),
            lanes[1].source_coefficients.len(),
        )));
    }
    runtime
        .validate_extraction_binding(extraction)
        .map_err(|error| C6ResidualError::new(error.to_string()))?;

    let response_len = base_rows
        .checked_mul(C6_SPARSE_RESPONSE_BLOCKS)
        .ok_or_else(|| C6ResidualError::new("C6SPR2 response packing length overflows"))?;
    let mut response_values = try_zeroed_fp2_vec(response_len, "C6SPR2 response packing")?;
    response_values[..node_count].copy_from_slice(&lanes[0].node_coefficients);
    response_values[base_rows..base_rows + node_count].copy_from_slice(&lanes[1].node_coefficients);
    let boundary_block = 2 * base_rows;
    // Only Scale operands enter the sparse rational relation. They are
    // indexed from zero by the fixed plan, so this D(base-1) sub-block must
    // be `scalar_runtime || zero`. Packing verifier-owned public inputs ahead
    // of them would create a non-dyadic shifted slice that one MLE opening
    // cannot authenticate.
    for scalar in 0..scalar_count {
        response_values[boundary_block + scalar] = runtime
            .scalar_value(
                extraction,
                u32::try_from(scalar)
                    .map_err(|_| C6ResidualError::new("C6SPR2 scalar index exceeds u32"))?,
            )
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
    }
    let g0_start = boundary_block + base_rows / 2;
    let g1_start = g0_start + base_rows / 4;
    response_values[g0_start..g0_start + source_count]
        .copy_from_slice(&lanes[0].source_coefficients);
    response_values[g1_start..g1_start + source_count]
        .copy_from_slice(&lanes[1].source_coefficients);

    let mu_block = 3 * base_rows;
    let plan_len = base_rows
        .checked_mul(C6_SPARSE_PLAN_BLOCKS)
        .ok_or_else(|| C6ResidualError::new("C6SPR2 plan packing length overflows"))?;
    let mut plan_values = try_zeroed_fp2_vec(plan_len, "C6SPR2 plan packing")?;
    let lhs_block = base_rows;
    let rhs_block = 2 * base_rows;
    // The virtual terminal relation uses degree-five selectors on the six
    // canonical opcode values.  Neutral plan padding is therefore encoded as
    // StructuralZero rather than the non-opcode value zero.
    plan_values[..base_rows].fill(sparse_plan_opcode(C6InstalledOperationKind::StructuralZero));
    let mut source_cursor = 0usize;
    let mut operand_cursor = 0usize;
    let mut scalar_cursor = 0u32;
    for (canonical, &kind) in operation_plan.operation_kinds().iter().enumerate() {
        plan_values[canonical] = sparse_plan_opcode(kind);
        match kind {
            C6InstalledOperationKind::Source => {
                let source = *operation_plan
                    .source_ordinals()
                    .get(source_cursor)
                    .ok_or_else(|| C6ResidualError::new("C6SPR2 source stream is truncated"))?;
                source_cursor += 1;
                plan_values[lhs_block + canonical] = Fp2::from_base(Fp::new(u64::from(source)));
            }
            C6InstalledOperationKind::StructuralZero | C6InstalledOperationKind::PublicInput => {}
            C6InstalledOperationKind::Add | C6InstalledOperationKind::Sub => {
                let operands = operation_plan
                    .operands()
                    .get(operand_cursor..operand_cursor + 2)
                    .ok_or_else(|| C6ResidualError::new("C6SPR2 operand stream is truncated"))?;
                operand_cursor += 2;
                plan_values[lhs_block + canonical] =
                    Fp2::from_base(Fp::new(u64::from(operands[0])));
                plan_values[rhs_block + canonical] =
                    Fp2::from_base(Fp::new(u64::from(operands[1])));
            }
            C6InstalledOperationKind::Scale => {
                let operand = *operation_plan.operands().get(operand_cursor).ok_or_else(|| {
                    C6ResidualError::new("C6SPR2 Scale operand stream is truncated")
                })?;
                operand_cursor += 1;
                plan_values[lhs_block + canonical] = Fp2::from_base(Fp::new(u64::from(operand)));
                plan_values[rhs_block + canonical] =
                    Fp2::from_base(Fp::new(u64::from(scalar_cursor)));
                response_values[mu_block + canonical] = runtime
                    .scalar_value(extraction, scalar_cursor)
                    .map_err(|error| C6ResidualError::new(error.to_string()))?;
                scalar_cursor = scalar_cursor
                    .checked_add(1)
                    .ok_or_else(|| C6ResidualError::new("C6SPR2 scalar cursor overflows"))?;
            }
        }
    }
    if source_cursor != operation_plan.source_ordinals().len()
        || operand_cursor != operation_plan.operands().len()
        || usize::try_from(scalar_cursor).ok() != Some(scalar_count)
    {
        return Err(C6ResidualError::new("C6SPR2 packed plan cursors do not close"));
    }

    let lane_digests = [lanes[0].digest(), lanes[1].digest()];
    let runtime_instance = runtime.instance_identity();
    let operation_plan_digest = operation_plan.artifact_digest();
    let response_digest = hash_packed_oracle(
        "volta-zk/c6/sparse-rational-packed-response/v1",
        base_domain_log2,
        operation_plan_digest,
        &lane_digests,
        runtime_instance,
        &response_values,
    );
    let plan_digest = hash_packed_oracle(
        "volta-zk/c6/sparse-rational-packed-plan/v1",
        base_domain_log2,
        operation_plan_digest,
        &[],
        C6OperationPlanInstanceIdentity {
            version: runtime_instance.version,
            topology_digest: runtime_instance.topology_digest,
            public_input_count: runtime_instance.public_input_count,
            scalar_input_count: runtime_instance.scalar_input_count,
            instance_digest: [0; 32],
        },
        &plan_values,
    );
    Ok(C6SparseRationalPackedOracleReference {
        base_domain_log2,
        operation_plan_digest,
        lane_digests,
        runtime_instance,
        response_values,
        plan_values,
        response_digest,
        plan_digest,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6SparseRationalLeaves {
    active_rows: usize,
    numerator: Vec<Fp2>,
    denominator: Vec<Fp2>,
    expected_sum: Fp2,
}

fn neutral_fraction_leaves(
    active_rows: usize,
    label: &'static str,
) -> C6ResidualResult<(Vec<Fp2>, Vec<Fp2>)> {
    let domain_rows = active_rows
        .max(2)
        .checked_next_power_of_two()
        .ok_or_else(|| C6ResidualError::new(format!("C6SPR1 {label} domain overflows")))?;
    let numerator = try_zeroed_fp2_vec(domain_rows, label)?;
    let mut denominator = try_zeroed_fp2_vec(domain_rows, label)?;
    denominator.fill(Fp2::ONE);
    Ok((numerator, denominator))
}

fn checked_fraction_sum(leaves: &C6SparseRationalLeaves) -> C6ResidualResult<Fp2> {
    if leaves.numerator.len() != leaves.denominator.len()
        || !leaves.numerator.len().is_power_of_two()
        || leaves.numerator.len() < 2
        || leaves.active_rows > leaves.numerator.len()
        || leaves.denominator.iter().any(|value| *value == Fp2::ZERO)
        || leaves.numerator[leaves.active_rows..].iter().any(|value| *value != Fp2::ZERO)
        || leaves.denominator[leaves.active_rows..].iter().any(|value| *value != Fp2::ONE)
    {
        return Err(C6ResidualError::new(
            "C6SPR1 weighted fraction leaves or neutral padding are malformed",
        ));
    }
    Ok(leaves
        .numerator
        .iter()
        .zip(&leaves.denominator)
        .fold(Fp2::ZERO, |sum, (&numerator, &denominator)| sum + numerator * denominator.inv()))
}

fn materialize_sparse_rational_leaves(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    relation: &C6ResidualSparseRationalRelationReference,
) -> C6ResidualResult<[C6SparseRationalLeaves; C6_SPARSE_RATIONAL_SUBCHECKS]> {
    let topology = operation_plan.topology();
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR1 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR1 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR1 source count exceeds usize"))?;
    if operation_plan.operation_kinds().len() != node_count
        || relation.combined_nodes.len() != node_count
        || relation.combined_injection.len() != node_count
        || relation.node_scale_values.len() != node_count
        || relation.combined_sources.len() != source_count
        || relation.recurrence_residual() != Fp2::ZERO
        || relation.runtime_gather_residual() != Fp2::ZERO
        || relation.source_gather_residual() != Fp2::ZERO
    {
        return Err(C6ResidualError::new(
            "C6SPR1 rational reference has an incompatible topology or residual",
        ));
    }

    let gamma = relation.sparse_challenges.recurrence;
    let tau = relation.sparse_challenges.runtime_gather;
    let delta = relation.sparse_challenges.source_gather;
    let (mut anchor_p, mut anchor_q) =
        neutral_fraction_leaves(node_count, "recurrence-anchor leaves")?;
    let (mut linear_p, mut linear_q) =
        neutral_fraction_leaves(node_count, "recurrence-linear leaves")?;
    let (mut scale_p, mut scale_q) =
        neutral_fraction_leaves(node_count, "recurrence-scale leaves")?;
    let (mut runtime_plan_p, mut runtime_plan_q) =
        neutral_fraction_leaves(node_count, "runtime-plan leaves")?;
    let (mut runtime_table_p, mut runtime_table_q) =
        neutral_fraction_leaves(scalar_count, "runtime-table leaves")?;
    let (mut source_boundary_p, mut source_boundary_q) =
        neutral_fraction_leaves(source_count, "source-boundary leaves")?;
    let (mut source_plan_p, mut source_plan_q) =
        neutral_fraction_leaves(node_count, "source-plan leaves")?;

    for index in 0..node_count {
        anchor_p[index] = relation.combined_nodes[index] - relation.combined_injection[index];
        anchor_q[index] = c6_sparse_rational_denominator(
            gamma,
            u32::try_from(index)
                .map_err(|_| C6ResidualError::new("C6SPR1 node index exceeds u32"))?,
        );
    }
    for scalar in 0..scalar_count {
        let scalar = u32::try_from(scalar)
            .map_err(|_| C6ResidualError::new("C6SPR1 scalar index exceeds u32"))?;
        runtime_table_p[scalar as usize] = runtime
            .scalar_value(extraction, scalar)
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        runtime_table_q[scalar as usize] = c6_sparse_rational_denominator(tau, scalar);
    }
    for source in 0..source_count {
        source_boundary_p[source] = relation.combined_sources[source];
        source_boundary_q[source] = c6_sparse_rational_denominator(
            delta,
            u32::try_from(source)
                .map_err(|_| C6ResidualError::new("C6SPR1 source index exceeds u32"))?,
        );
    }

    let mut source_cursor = 0usize;
    let mut operand_cursor = 0usize;
    let mut scalar_cursor = 0u32;
    for (canonical, &kind) in operation_plan.operation_kinds().iter().enumerate() {
        let coefficient = relation.combined_nodes[canonical];
        match kind {
            C6InstalledOperationKind::Source => {
                let source = *operation_plan
                    .source_ordinals()
                    .get(source_cursor)
                    .ok_or_else(|| C6ResidualError::new("C6SPR1 source stream is truncated"))?;
                source_cursor += 1;
                source_plan_p[canonical] = coefficient;
                source_plan_q[canonical] = c6_sparse_rational_denominator(delta, source);
            }
            C6InstalledOperationKind::StructuralZero | C6InstalledOperationKind::PublicInput => {
                if relation.node_scale_values[canonical] != Fp2::ZERO {
                    return Err(C6ResidualError::new(
                        "C6SPR1 non-Scale row carries a runtime value",
                    ));
                }
            }
            C6InstalledOperationKind::Add | C6InstalledOperationKind::Sub => {
                if relation.node_scale_values[canonical] != Fp2::ZERO {
                    return Err(C6ResidualError::new(
                        "C6SPR1 non-Scale row carries a runtime value",
                    ));
                }
                let operands = operation_plan
                    .operands()
                    .get(operand_cursor..operand_cursor + 2)
                    .ok_or_else(|| C6ResidualError::new("C6SPR1 operand stream is truncated"))?;
                operand_cursor += 2;
                let lhs = c6_sparse_rational_denominator(gamma, operands[0]);
                let rhs = c6_sparse_rational_denominator(gamma, operands[1]);
                linear_q[canonical] = lhs * rhs;
                linear_p[canonical] = coefficient
                    * if kind == C6InstalledOperationKind::Add { rhs + lhs } else { rhs - lhs };
            }
            C6InstalledOperationKind::Scale => {
                let operand = *operation_plan.operands().get(operand_cursor).ok_or_else(|| {
                    C6ResidualError::new("C6SPR1 Scale operand stream is truncated")
                })?;
                operand_cursor += 1;
                let mu = relation.node_scale_values[canonical];
                scale_p[canonical] = coefficient * mu;
                scale_q[canonical] = c6_sparse_rational_denominator(gamma, operand);
                runtime_plan_p[canonical] = mu;
                runtime_plan_q[canonical] = c6_sparse_rational_denominator(tau, scalar_cursor);
                scalar_cursor = scalar_cursor
                    .checked_add(1)
                    .ok_or_else(|| C6ResidualError::new("C6SPR1 scalar cursor overflows"))?;
            }
        }
    }
    if source_cursor != operation_plan.source_ordinals().len()
        || operand_cursor != operation_plan.operands().len()
        || usize::try_from(scalar_cursor).ok() != Some(scalar_count)
    {
        return Err(C6ResidualError::new("C6SPR1 weighted leaf plan cursors do not close"));
    }

    let leaves = vec![
        C6SparseRationalLeaves {
            active_rows: node_count,
            numerator: anchor_p,
            denominator: anchor_q,
            expected_sum: relation.recurrence_terms[0],
        },
        C6SparseRationalLeaves {
            active_rows: node_count,
            numerator: linear_p,
            denominator: linear_q,
            expected_sum: relation.recurrence_terms[1],
        },
        C6SparseRationalLeaves {
            active_rows: node_count,
            numerator: scale_p,
            denominator: scale_q,
            expected_sum: relation.recurrence_terms[2],
        },
        C6SparseRationalLeaves {
            active_rows: node_count,
            numerator: runtime_plan_p,
            denominator: runtime_plan_q,
            expected_sum: relation.runtime_gather_terms[0],
        },
        C6SparseRationalLeaves {
            active_rows: scalar_count,
            numerator: runtime_table_p,
            denominator: runtime_table_q,
            expected_sum: relation.runtime_gather_terms[1],
        },
        C6SparseRationalLeaves {
            active_rows: source_count,
            numerator: source_boundary_p,
            denominator: source_boundary_q,
            expected_sum: relation.source_gather_terms[0],
        },
        C6SparseRationalLeaves {
            active_rows: node_count,
            numerator: source_plan_p,
            denominator: source_plan_q,
            expected_sum: relation.source_gather_terms[1],
        },
    ];
    let leaves: [C6SparseRationalLeaves; C6_SPARSE_RATIONAL_SUBCHECKS] = leaves
        .try_into()
        .map_err(|_| C6ResidualError::new("C6SPR1 weighted leaf census differs from seven"))?;
    for (subcheck, leaves) in C6SparseRationalSubcheck::ALL.into_iter().zip(&leaves) {
        if checked_fraction_sum(leaves)? != leaves.expected_sum {
            return Err(C6ResidualError::new(format!(
                "C6SPR1 {subcheck:?} weighted leaves differ from the exact rational reference"
            )));
        }
    }
    Ok(leaves)
}

fn sparse_rational_gkr_seed_digest(seed: [u8; 32]) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/sparse-rational-gkr-seed/v1");
    hasher.update(&seed);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, PartialEq, Eq)]
pub struct C6ResidualSparseRationalGkrReferenceProof {
    relation_digest: C6ResidualDigest,
    gkr_seed_digest: C6ResidualDigest,
    subchecks: [FracProof; C6_SPARSE_RATIONAL_SUBCHECKS],
}

impl C6ResidualSparseRationalGkrReferenceProof {
    pub fn bytes(&self) -> u64 {
        self.subchecks.iter().map(FracProof::bytes).sum()
    }

    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn subcheck(&self, subcheck: C6SparseRationalSubcheck) -> &FracProof {
        &self.subchecks[subcheck.index()]
    }
}

/// Prove all seven C6SPR1 rational sums on the scaled CPU/reference path.
/// `gkr_seed` stands for transcript challenges sampled after every response
/// input commitment and after the rational challenges.
pub fn prove_c6_residual_sparse_rational_gkr_reference(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    relation: &C6ResidualSparseRationalRelationReference,
    gkr_seed: [u8; 32],
) -> C6ResidualResult<(C6ResidualSparseRationalGkrReferenceProof, Counters)> {
    let leaves = materialize_sparse_rational_leaves(operation_plan, extraction, runtime, relation)?;
    let mut counters = Counters::default();
    let mut proofs = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    for (index, leaves) in leaves.iter().enumerate() {
        let mut stream =
            FpStream::domain_separated(gkr_seed, C6_SPARSE_RATIONAL_GKR_STREAM_DOMAINS[index]);
        let proof = prove_weighted_frac_tree(
            &leaves.numerator,
            &leaves.denominator,
            &mut stream,
            &mut counters,
        );
        if proof.root_q == Fp2::ZERO || proof.root_p != leaves.expected_sum * proof.root_q {
            return Err(C6ResidualError::new(
                "C6SPR1 weighted fraction root does not equal its exact rational sum",
            ));
        }
        proofs.push(proof);
    }
    let subchecks = proofs
        .try_into()
        .map_err(|_| C6ResidualError::new("C6SPR1 fraction proof census differs from seven"))?;
    Ok((
        C6ResidualSparseRationalGkrReferenceProof {
            relation_digest: relation.digest(),
            gkr_seed_digest: sparse_rational_gkr_seed_digest(gkr_seed),
            subchecks,
        },
        counters,
    ))
}

/// Verify the seven clear GKR proofs against their exact materialized leaf
/// polynomials.  This is a differential verifier, not a PCS opening verifier.
pub fn verify_c6_residual_sparse_rational_gkr_reference(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    relation: &C6ResidualSparseRationalRelationReference,
    gkr_seed: [u8; 32],
    proof: &C6ResidualSparseRationalGkrReferenceProof,
) -> C6ResidualResult<bool> {
    if proof.relation_digest != relation.digest()
        || proof.gkr_seed_digest != sparse_rational_gkr_seed_digest(gkr_seed)
    {
        return Ok(false);
    }
    let leaves = materialize_sparse_rational_leaves(operation_plan, extraction, runtime, relation)?;
    let mut counters = Counters::default();
    let mut sums = [Fp2::ZERO; C6_SPARSE_RATIONAL_SUBCHECKS];
    for (index, (proof, leaves)) in proof.subchecks.iter().zip(&leaves).enumerate() {
        if proof.root_q == Fp2::ZERO {
            return Ok(false);
        }
        sums[index] = proof.root_p * proof.root_q.inv();
        if sums[index] != leaves.expected_sum {
            return Ok(false);
        }
        let mut stream =
            FpStream::domain_separated(gkr_seed, C6_SPARSE_RATIONAL_GKR_STREAM_DOMAINS[index]);
        if !verify_frac_tree(
            proof,
            |point, counters| crate::logup::eval_mle_counted(&leaves.numerator, point, counters),
            |point, counters| crate::logup::eval_mle_counted(&leaves.denominator, point, counters),
            &mut stream,
            &mut counters,
        ) {
            return Ok(false);
        }
    }
    Ok(sums[C6SparseRationalSubcheck::RecurrenceAnchor.index()]
        == sums[C6SparseRationalSubcheck::RecurrenceLinear.index()]
            + sums[C6SparseRationalSubcheck::RecurrenceScale.index()]
        && sums[C6SparseRationalSubcheck::RuntimePlan.index()]
            == sums[C6SparseRationalSubcheck::RuntimeTable.index()]
        && sums[C6SparseRationalSubcheck::SourceBoundary.index()]
            == sums[C6SparseRationalSubcheck::SourcePlan.index()])
}

fn sparse_rational_subcheck_depths(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<[usize; C6_SPARSE_RATIONAL_SUBCHECKS]> {
    let topology = operation_plan.topology();
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR3 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR3 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR3 source count exceeds usize"))?;
    let depth = |active_rows: usize| -> C6ResidualResult<usize> {
        let rows = active_rows
            .max(2)
            .checked_next_power_of_two()
            .ok_or_else(|| C6ResidualError::new("C6SPR3 fraction domain overflows"))?;
        Ok(rows.trailing_zeros() as usize)
    };
    Ok([
        depth(node_count)?,
        depth(node_count)?,
        depth(node_count)?,
        depth(node_count)?,
        depth(scalar_count)?,
        depth(source_count)?,
        depth(node_count)?,
    ])
}

/// Canonical fraction-tree dimensions in the seven registered subcheck
/// slots.  Wire codecs use this instead of trusting provider-supplied vector
/// lengths.
pub fn c6_sparse_rational_subcheck_depths(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<[usize; C6_SPARSE_RATIONAL_SUBCHECKS]> {
    sparse_rational_subcheck_depths(operation_plan)
}

fn sparse_blind_frac_correction_scalars(depth: usize) -> C6ResidualResult<u64> {
    let depth = u64::try_from(depth)
        .map_err(|_| C6ResidualError::new("C6SPR3 fraction depth exceeds u64"))?;
    depth
        .checked_mul(depth)
        .and_then(|value| value.checked_add(6 * depth))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| C6ResidualError::new("C6SPR3 fraction correction census overflows"))
}

fn encode_sparse_blind_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

struct SparseBlindCorrectionReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SparseBlindCorrectionReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fp2(&mut self) -> C6ResidualResult<Fp2> {
        let end = self
            .offset
            .checked_add(16)
            .ok_or_else(|| C6ResidualError::new("C6SPR3 correction cursor overflows"))?;
        if end > self.bytes.len() {
            return Err(C6ResidualError::new("truncated C6SPR3 correction body"));
        }
        let c0 = u64::from_le_bytes(
            self.bytes[self.offset..self.offset + 8]
                .try_into()
                .expect("fixed C6SPR3 base-field slice"),
        );
        let c1 = u64::from_le_bytes(
            self.bytes[self.offset + 8..end].try_into().expect("fixed C6SPR3 base-field slice"),
        );
        if c0 >= P || c1 >= P {
            return Err(C6ResidualError::new(
                "C6SPR3 correction contains a noncanonical base-field limb",
            ));
        }
        self.offset = end;
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn finish(self) -> C6ResidualResult<()> {
        if self.offset != self.bytes.len() {
            return Err(C6ResidualError::new("trailing C6SPR3 correction bytes"));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct C6ResidualSparseRationalBlindGkrProof {
    relation_digest: C6ResidualDigest,
    subchecks: [BlindFracProof; C6_SPARSE_RATIONAL_SUBCHECKS],
    root_inverse_corrections: [Fp2; C6_SPARSE_RATIONAL_SUBCHECKS],
    root_ratio_corrections: [Fp2; C6_SPARSE_RATIONAL_SUBCHECKS],
}

impl C6ResidualSparseRationalBlindGkrProof {
    pub fn bytes(&self) -> u64 {
        self.subchecks.iter().map(BlindFracProof::bytes).sum::<u64>()
            + 32 * C6_SPARSE_RATIONAL_SUBCHECKS as u64
    }

    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn correction_bytes(operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<u64> {
        c6_sparse_rational_subcheck_depths(operation_plan)?
            .into_iter()
            .try_fold(0u64, |total, depth| {
                total
                    .checked_add(sparse_blind_frac_correction_scalars(depth)?)
                    .ok_or_else(|| C6ResidualError::new("C6SPR3 correction byte count overflows"))
            })?
            .checked_mul(16)
            .ok_or_else(|| C6ResidualError::new("C6SPR3 correction byte count overflows"))
    }

    /// Encode only transcript-visible corrections.  Dimensions and relation
    /// ownership are supplied by the enclosing typed C6.1 frame.
    pub fn encode_corrections(
        &self,
        operation_plan: &C6InstalledOperationPlan,
    ) -> C6ResidualResult<Vec<u8>> {
        let depths = c6_sparse_rational_subcheck_depths(operation_plan)?;
        let expected_bytes = Self::correction_bytes(operation_plan)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected_bytes)
                .map_err(|_| C6ResidualError::new("C6SPR3 correction body exceeds usize"))?,
        );
        for (index, (&depth, proof)) in depths.iter().zip(&self.subchecks).enumerate() {
            if proof.layers.len() != depth || proof.aux.is_some() {
                return Err(C6ResidualError::new(
                    "C6SPR3 weighted fraction proof has noncanonical layer shape",
                ));
            }
            for correction in proof.root_corrs {
                encode_sparse_blind_fp2(&mut bytes, correction);
            }
            for (layer_index, layer) in proof.layers.iter().enumerate() {
                if layer.round_corrs.len() != layer_index {
                    return Err(C6ResidualError::new(
                        "C6SPR3 weighted fraction round census is noncanonical",
                    ));
                }
                for corrections in &layer.round_corrs {
                    for correction in corrections {
                        encode_sparse_blind_fp2(&mut bytes, *correction);
                    }
                }
                for correction in layer.split_corrs {
                    encode_sparse_blind_fp2(&mut bytes, correction);
                }
                for correction in layer.z_corrs {
                    encode_sparse_blind_fp2(&mut bytes, correction);
                }
            }
            encode_sparse_blind_fp2(&mut bytes, self.root_inverse_corrections[index]);
            encode_sparse_blind_fp2(&mut bytes, self.root_ratio_corrections[index]);
        }
        if bytes.len() as u64 != expected_bytes || self.bytes() != expected_bytes {
            return Err(C6ResidualError::new(
                "C6SPR3 correction encoder disagrees with the exact census",
            ));
        }
        Ok(bytes)
    }

    pub fn decode_corrections(
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: C6ResidualDigest,
        bytes: &[u8],
    ) -> C6ResidualResult<Self> {
        if bytes.len() as u64 != Self::correction_bytes(operation_plan)? {
            return Err(C6ResidualError::new("C6SPR3 strict correction length mismatch"));
        }
        let depths = c6_sparse_rational_subcheck_depths(operation_plan)?;
        let mut reader = SparseBlindCorrectionReader::new(bytes);
        let mut subchecks = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
        let mut root_inverse_corrections = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
        let mut root_ratio_corrections = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
        for depth in depths {
            let root_corrs = [reader.fp2()?, reader.fp2()?];
            let mut layers = Vec::with_capacity(depth);
            for layer_index in 0..depth {
                let mut round_corrs = Vec::with_capacity(layer_index);
                for _ in 0..layer_index {
                    round_corrs.push([reader.fp2()?, reader.fp2()?]);
                }
                layers.push(BlindLayerProof {
                    round_corrs,
                    split_corrs: [reader.fp2()?, reader.fp2()?, reader.fp2()?, reader.fp2()?],
                    z_corrs: [reader.fp2()?, reader.fp2()?, reader.fp2()?],
                });
            }
            subchecks.push(BlindFracProof { root_corrs, layers, aux: None });
            root_inverse_corrections.push(reader.fp2()?);
            root_ratio_corrections.push(reader.fp2()?);
        }
        reader.finish()?;
        let proof = Self {
            relation_digest,
            subchecks: subchecks.try_into().map_err(|_| {
                C6ResidualError::new("C6SPR3 decoded fraction-proof census differs from seven")
            })?,
            root_inverse_corrections: root_inverse_corrections.try_into().map_err(|_| {
                C6ResidualError::new("C6SPR3 decoded inverse census differs from seven")
            })?,
            root_ratio_corrections: root_ratio_corrections.try_into().map_err(|_| {
                C6ResidualError::new("C6SPR3 decoded ratio census differs from seven")
            })?,
        };
        if proof.bytes() != bytes.len() as u64 {
            return Err(C6ResidualError::new(
                "C6SPR3 decoded correction census differs from the wire",
            ));
        }
        Ok(proof)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalBlindLeafClaim {
    point: Vec<Fp2>,
    numerator: ProverAuthed,
    denominator: ProverAuthed,
}

impl C6SparseRationalBlindLeafClaim {
    pub fn point(&self) -> &[Fp2] {
        &self.point
    }

    pub fn numerator(&self) -> ProverAuthed {
        self.numerator
    }

    pub fn denominator(&self) -> ProverAuthed {
        self.denominator
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalBlindLeafKey {
    point: Vec<Fp2>,
    numerator: VerifierKey,
    denominator: VerifierKey,
}

impl C6SparseRationalBlindLeafKey {
    pub fn point(&self) -> &[Fp2] {
        &self.point
    }

    pub fn numerator(&self) -> VerifierKey {
        self.numerator
    }

    pub fn denominator(&self) -> VerifierKey {
        self.denominator
    }
}

/// Blind seven-tree prover.  Every fraction-tree message is a correction;
/// the returned fourteen authenticated leaf claims are the only leaf values
/// handed to the joint reducer.  Each root gets an authenticated inverse and
/// ratio product; the seven ratios close through exactly three linear rows.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn prove_c6_residual_sparse_rational_gkr_blind_reference(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    relation: &C6ResidualSparseRationalRelationReference,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    counters: &mut Counters,
    products: &mut ProdTriples,
    zeros: &mut Vec<ProverAuthed>,
) -> C6ResidualResult<(
    C6ResidualSparseRationalBlindGkrProof,
    [C6SparseRationalBlindLeafClaim; C6_SPARSE_RATIONAL_SUBCHECKS],
)> {
    public_relation.validate_operation_plan(operation_plan)?;
    relation.validate_public_relation(public_relation)?;
    let leaves = materialize_sparse_rational_leaves(operation_plan, extraction, runtime, relation)?;
    let mut subchecks = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut root_inverse_corrections = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut root_ratio_corrections = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut root_ratios = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut claims = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    for leaves in &leaves {
        let (proof, point, numerator, denominator, roots) = blind_prove_weighted_frac_tree(
            &leaves.numerator,
            &leaves.denominator,
            stream,
            doms,
            tx,
            counters,
            products,
            zeros,
        );
        if roots.1.x == Fp2::ZERO || roots.0.x != leaves.expected_sum * roots.1.x {
            return Err(C6ResidualError::new(
                "C6SPR3 blind fraction root differs from its exact rational sum",
            ));
        }
        let inverse = roots.1.x.inv();
        let inverse_domain = doms.take(1);
        let inverse_mask = stream
            .draw_fulls(inverse_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C6ResidualError::new("C6SPR3 missing root-inverse correlation"))?;
        stream
            .record_c6_fullfield_plaintexts(inverse_domain, &[inverse])
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        root_inverse_corrections.push(inverse - inverse_mask.x);
        tx.append("c6_sparse_root_inverse_correction", 16);
        let inverse = inverse_mask.authenticate(inverse);
        products.push((roots.1, inverse, ProverAuthed::from_public(Fp2::ONE)));
        let ratio_value = roots.0.x * inverse.x;
        let ratio_domain = doms.take(1);
        let ratio_mask = stream
            .draw_fulls(ratio_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C6ResidualError::new("C6SPR3 missing root-ratio correlation"))?;
        stream
            .record_c6_fullfield_plaintexts(ratio_domain, &[ratio_value])
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        root_ratio_corrections.push(ratio_value - ratio_mask.x);
        tx.append("c6_sparse_root_ratio_correction", 16);
        let ratio = ratio_mask.authenticate(ratio_value);
        products.push((roots.0, inverse, ratio));
        root_ratios.push(ratio);
        subchecks.push(proof);
        claims.push(C6SparseRationalBlindLeafClaim { point, numerator, denominator });
    }
    zeros.push(root_ratios[0].sub(root_ratios[1]).sub(root_ratios[2]));
    zeros.push(root_ratios[3].sub(root_ratios[4]));
    zeros.push(root_ratios[5].sub(root_ratios[6]));
    if zeros[zeros.len() - 3..].iter().any(|row| row.x != Fp2::ZERO) {
        return Err(C6ResidualError::new(
            "C6SPR3 blind fraction roots do not satisfy the three rational identities",
        ));
    }
    Ok((
        C6ResidualSparseRationalBlindGkrProof {
            relation_digest: public_relation.digest(),
            subchecks: subchecks.try_into().map_err(|_| {
                C6ResidualError::new("C6SPR3 blind fraction-proof census differs from seven")
            })?,
            root_inverse_corrections: root_inverse_corrections.try_into().map_err(|_| {
                C6ResidualError::new("C6SPR3 root-inverse census differs from seven")
            })?,
            root_ratio_corrections: root_ratio_corrections
                .try_into()
                .map_err(|_| C6ResidualError::new("C6SPR3 root-ratio census differs from seven"))?,
        },
        claims.try_into().map_err(|_| {
            C6ResidualError::new("C6SPR3 blind leaf-claim census differs from seven")
        })?,
    ))
}

/// Verifier mirror of
/// [`prove_c6_residual_sparse_rational_gkr_blind_reference`].
pub fn verify_c6_residual_sparse_rational_gkr_blind_reference(
    operation_plan: &C6InstalledOperationPlan,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    proof: &C6ResidualSparseRationalBlindGkrProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    products: &mut ProdKeyTriples,
    zeros: &mut Vec<VerifierKey>,
) -> C6ResidualResult<Option<[C6SparseRationalBlindLeafKey; C6_SPARSE_RATIONAL_SUBCHECKS]>> {
    public_relation.validate_operation_plan(operation_plan)?;
    if proof.relation_digest != public_relation.digest() {
        return Ok(None);
    }
    let depths = sparse_rational_subcheck_depths(operation_plan)?;
    let mut claims = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut root_ratios = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    for index in 0..C6_SPARSE_RATIONAL_SUBCHECKS {
        let Some((point, numerator, denominator, roots)) = blind_verify_frac_tree(
            depths[index],
            &proof.subchecks[index],
            ctx,
            doms,
            tx,
            products,
            zeros,
        ) else {
            return Ok(None);
        };
        let inverse =
            ctx.correct_full_verifier_key(doms.take(1), proof.root_inverse_corrections[index]);
        tx.append("c6_sparse_root_inverse_correction", 16);
        products.push((roots.1, inverse, VerifierKey::from_public(Fp2::ONE, ctx.delta)));
        let ratio =
            ctx.correct_full_verifier_key(doms.take(1), proof.root_ratio_corrections[index]);
        tx.append("c6_sparse_root_ratio_correction", 16);
        products.push((roots.0, inverse, ratio));
        root_ratios.push(ratio);
        claims.push(C6SparseRationalBlindLeafKey { point, numerator, denominator });
    }
    zeros.push(root_ratios[0].sub(root_ratios[1]).sub(root_ratios[2]));
    zeros.push(root_ratios[3].sub(root_ratios[4]));
    zeros.push(root_ratios[5].sub(root_ratios[6]));
    Ok(Some(
        claims
            .try_into()
            .map_err(|_| C6ResidualError::new("C6SPR3 blind leaf-key census differs from seven"))?,
    ))
}

#[cfg(all(test, feature = "c6-trace"))]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use volta_mac::{zero_batch_exchange, C6TraceSourceManifest};

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(fp(value))
    }

    #[test]
    fn public_range_moments_and_opcode_selectors_are_exact() {
        const KINDS: [C6InstalledOperationKind; 6] = [
            C6InstalledOperationKind::Source,
            C6InstalledOperationKind::StructuralZero,
            C6InstalledOperationKind::PublicInput,
            C6InstalledOperationKind::Add,
            C6InstalledOperationKind::Sub,
            C6InstalledOperationKind::Scale,
        ];
        for selected in KINDS {
            for row_kind in KINDS {
                assert_eq!(
                    c6_sparse_opcode_selector(selected, sparse_plan_opcode(row_kind)),
                    if selected == row_kind { Fp2::ONE } else { Fp2::ZERO },
                );
            }
        }
        let arbitrary_opcode = Fp2::new(fp(37), fp(9));
        assert_eq!(
            KINDS.into_iter().fold(Fp2::ZERO, |sum, kind| {
                sum + c6_sparse_opcode_selector(kind, arbitrary_opcode)
            }),
            Fp2::ONE,
        );

        for dimension in 1usize..=8 {
            let point = (0..dimension)
                .map(|bit| Fp2::new(fp(41 + bit as u64), fp(3 + bit as u64)))
                .collect::<Vec<_>>();
            let capacity = 1usize << dimension;
            for active_rows in 0..=capacity {
                let mut indicator = vec![Fp2::ZERO; capacity];
                let mut indexed = vec![Fp2::ZERO; capacity];
                for row in 0..active_rows {
                    indicator[row] = Fp2::ONE;
                    indexed[row] = fp2(row as u64);
                }
                let (active, active_index) =
                    c6_sparse_range_mle_moments(active_rows, &point).unwrap();
                assert_eq!(active, crate::mle::eval_mle(&indicator, &point));
                assert_eq!(active_index, crate::mle::eval_mle(&indexed, &point));
            }
            assert!(c6_sparse_range_mle_moments(capacity + 1, &point).is_err());
        }
    }

    #[test]
    fn seven_sparse_rational_gkr_subchecks_reject_role_and_padding_mutations() {
        let direct = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let topology = direct.operation_plan().topology();
        let source_manifest = C6TraceSourceManifest::new(
            topology.source_count,
            topology.source_schedule_digest,
            direct.manifest().product_mask_sources().to_vec(),
        )
        .unwrap();
        let terminal_metadata = C6OperationPlanTerminalMetadata::from_installed(
            direct.operation_plan(),
            &source_manifest,
        )
        .unwrap();
        let leaf_point = [
            Fp2::new(fp(0), fp(1)),
            Fp2::new(fp(1), fp(2)),
            Fp2::new(fp(2), fp(3)),
            Fp2::new(fp(3), fp(5)),
            Fp2::new(fp(5), fp(7)),
            Fp2::new(fp(7), fp(11)),
            Fp2::new(fp(11), fp(13)),
        ];
        let output_beta = Fp2::new(fp(191), fp(17));
        let lanes: [C6ResidualFoldedTerminalAdjointLaneReference;
            C6_RESIDUAL_PROOF_REPETITIONS as usize] = std::array::from_fn(|repetition| {
            compile_c6_residual_folded_terminal_adjoint_lane_reference(
                direct.operation_plan(),
                &terminal_metadata,
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                repetition as u8,
                &leaf_point,
                output_beta,
            )
            .unwrap()
        });
        let sparse_challenges = C6ResidualSparseRationalChallenges::new(
            topology,
            Fp2::new(fp(197), fp(1)),
            Fp2::new(fp(199), fp(2)),
            Fp2::new(fp(211), fp(3)),
            Fp2::new(fp(223), fp(4)),
        )
        .unwrap();
        let relation = compile_c6_residual_sparse_rational_relation_reference(
            direct.operation_plan(),
            &terminal_metadata,
            direct.extraction(),
            direct.runtime(),
            direct.relation(),
            [&lanes[0], &lanes[1]],
            sparse_challenges,
            output_beta,
        )
        .unwrap();
        let public_relation = C6ResidualSparseRationalPublicRelation::new(
            direct.operation_plan(),
            &terminal_metadata,
            direct.relation(),
            sparse_challenges,
            output_beta,
        )
        .unwrap();
        let packed = compile_c6_sparse_rational_packed_oracle_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            [&lanes[0], &lanes[1]],
        )
        .unwrap();
        assert!(compile_c6_sparse_rational_packed_oracle_production(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            [&lanes[0], &lanes[1]],
        )
        .is_err());
        packed
            .validate(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                [&lanes[0], &lanes[1]],
            )
            .unwrap();
        packed.validate_relation(&relation).unwrap();
        let base_rows = 1usize << packed.base_domain_log2();
        assert_eq!(packed.response_values.len(), C6_SPARSE_RESPONSE_BLOCKS * base_rows);
        assert_eq!(packed.plan_values.len(), C6_SPARSE_PLAN_BLOCKS * base_rows);
        let input_point: Vec<Fp2> = (0..packed.base_domain_log2())
            .map(|coordinate| fp2(307 + u64::from(coordinate) * 2))
            .collect();
        let opening_points = packed.opening_points(&input_point).unwrap();
        opening_points.validate(&packed).unwrap();
        let response_openings = packed.evaluate_response_openings(&opening_points).unwrap();
        let plan_openings = packed.evaluate_plan_openings(&opening_points).unwrap();
        let physical_points = packed.physical_opening_points(&input_point).unwrap();
        physical_points.validate(&packed).unwrap();
        assert_eq!(physical_points.response().len(), 2 * response_openings.len());
        assert!(physical_points
            .response()
            .iter()
            .all(|point| point.len() == packed.physical_response_domain_log2() as usize));
        assert!(physical_points
            .plan()
            .iter()
            .all(|point| point.len() == packed.plan_domain_log2() as usize));
        let physical_response =
            packed.evaluate_physical_response_openings(&physical_points).unwrap();
        let physical_plan = packed.evaluate_physical_plan_openings(&physical_points).unwrap();
        assert_eq!(
            fold_c6_sparse_physical_response_openings(&physical_response),
            response_openings,
        );
        assert_eq!(physical_plan, plan_openings);
        let physical_response_values = packed.physical_response_values();
        assert_eq!(physical_response_values.len(), 2 * packed.response_values.len());
        assert!(physical_response_values[packed.response_values.len()..]
            .iter()
            .any(|value| *value != Fp::ZERO));
        let extension_generator = Fp2::new(Fp::ZERO, Fp::ONE);
        for (index, &semantic) in packed.response_values.iter().enumerate() {
            assert_eq!(
                semantic,
                Fp2::from_base(physical_response_values[index])
                    + extension_generator
                        * Fp2::from_base(
                            physical_response_values[packed.response_values.len() + index],
                        ),
            );
        }
        assert_eq!(
            packed.physical_plan_values().unwrap(),
            packed.plan_values.iter().map(|value| value.c0).collect::<Vec<_>>(),
        );
        assert_eq!(
            response_openings[0],
            crate::mle::eval_mle(&packed.response_values[..base_rows], &input_point)
        );
        assert_eq!(
            response_openings[1],
            crate::mle::eval_mle(&packed.response_values[base_rows..2 * base_rows], &input_point)
        );
        assert_eq!(
            response_openings[2],
            crate::mle::eval_mle(
                &packed.response_values[3 * base_rows..4 * base_rows],
                &input_point
            )
        );
        let packed_middle = &packed.response_values[2 * base_rows..3 * base_rows];
        let mut expected_scale_runtime = vec![Fp2::ZERO; base_rows / 2];
        for (scalar, expected) in
            expected_scale_runtime.iter_mut().take(topology.scalar_input_count as usize).enumerate()
        {
            *expected = direct.runtime().scalar_value(direct.extraction(), scalar as u32).unwrap();
        }
        assert_eq!(
            response_openings[3],
            crate::mle::eval_mle(&expected_scale_runtime, &input_point[..input_point.len() - 1])
        );
        assert_eq!(&packed_middle[..base_rows / 2], expected_scale_runtime);
        assert_eq!(
            response_openings[4],
            crate::mle::eval_mle(
                &packed_middle[base_rows / 2..3 * base_rows / 4],
                &input_point[..input_point.len() - 2],
            )
        );
        assert_eq!(
            response_openings[5],
            crate::mle::eval_mle(
                &packed_middle[3 * base_rows / 4..],
                &input_point[..input_point.len() - 2],
            )
        );
        for (opening, block) in plan_openings.iter().zip(0..C6_SPARSE_PLAN_OPENINGS) {
            assert_eq!(
                *opening,
                crate::mle::eval_mle(
                    &packed.plan_values[block * base_rows..(block + 1) * base_rows],
                    &input_point,
                )
            );
        }
        assert!(packed.plan_values[topology.canonical_node_count as usize..base_rows].iter().all(
            |&opcode| { opcode == sparse_plan_opcode(C6InstalledOperationKind::StructuralZero) }
        ));
        let non_scale = direct
            .operation_plan()
            .operation_kinds()
            .iter()
            .position(|kind| *kind != C6InstalledOperationKind::Scale)
            .unwrap();
        let mut changed_packed_response = packed.clone();
        changed_packed_response.response_values[3 * base_rows + non_scale] += Fp2::ONE;
        assert!(changed_packed_response
            .validate(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                [&lanes[0], &lanes[1]],
            )
            .is_err());
        let mut changed_response_digest = packed.clone();
        changed_response_digest.response_digest[0] ^= 1;
        assert!(changed_response_digest
            .validate(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                [&lanes[0], &lanes[1]],
            )
            .is_err());
        let mut changed_packed_plan = packed.clone();
        changed_packed_plan.plan_values[0] += Fp2::ONE;
        assert!(changed_packed_plan
            .validate(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                [&lanes[0], &lanes[1]],
            )
            .is_err());
        let mut changed_opening_points = opening_points.clone();
        changed_opening_points.response[0][0] += Fp2::ONE;
        assert!(changed_opening_points.validate(&packed).is_err());
        let mut changed_physical_points = physical_points.clone();
        changed_physical_points.response.swap(0, 1);
        assert!(changed_physical_points.validate(&packed).is_err());
        let seed = [0x61; 32];
        let (mut proof, counters) = prove_c6_residual_sparse_rational_gkr_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
            seed,
        )
        .unwrap();
        assert!(counters.fp2_mults > 0);
        assert!(proof.bytes() > 0);
        assert!(verify_c6_residual_sparse_rational_gkr_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
            seed,
            &proof,
        )
        .unwrap());

        let correlation_seed = [0x72; 32];
        let transcript_seed = [0x73; 32];
        let delta = Fp2::new(fp(313), fp(317));
        let mut prover_stream = CorrelationStream::new(correlation_seed);
        let mut prover_doms = Doms::new(10_000);
        let mut prover_transcript = Transcript::new(transcript_seed);
        let mut prover_products = Vec::new();
        let mut prover_zeros = Vec::new();
        let (mut blind_proof, blind_claims) =
            prove_c6_residual_sparse_rational_gkr_blind_reference(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                &relation,
                &public_relation,
                &mut prover_stream,
                &mut prover_doms,
                &mut prover_transcript,
                &mut Counters::default(),
                &mut prover_products,
                &mut prover_zeros,
            )
            .unwrap();
        assert!(blind_proof.bytes() > 0);
        let mut verifier = VerifierCtx::new(correlation_seed, delta);
        let mut verifier_doms = Doms::new(10_000);
        let mut verifier_transcript = Transcript::new(transcript_seed);
        let mut verifier_products = Vec::new();
        let mut verifier_zeros = Vec::new();
        let blind_keys = verify_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            &public_relation,
            &blind_proof,
            &mut verifier,
            &mut verifier_doms,
            &mut verifier_transcript,
            &mut verifier_products,
            &mut verifier_zeros,
        )
        .unwrap()
        .unwrap();
        assert_eq!(prover_doms.cursor(), verifier_doms.cursor());
        assert_eq!(prover_products.len(), verifier_products.len());
        assert_eq!(prover_zeros.len(), verifier_zeros.len());
        let depth_sum: usize =
            c6_sparse_rational_subcheck_depths(direct.operation_plan()).unwrap().into_iter().sum();
        assert_eq!(prover_products.len(), 3 * depth_sum + 2 * C6_SPARSE_RATIONAL_SUBCHECKS);
        assert_eq!(prover_zeros.len(), depth_sum + 3);
        assert_eq!(prover_stream.counters.full_corrs, blind_proof.bytes() / 16);
        for (claim, key) in blind_claims.iter().zip(&blind_keys) {
            assert_eq!(claim.point(), key.point());
            assert_eq!(key.numerator().k, claim.numerator().m + delta * claim.numerator().x,);
            assert_eq!(key.denominator().k, claim.denominator().m + delta * claim.denominator().x,);
        }
        let product_challenge = prover_transcript.challenge_fp2();
        assert_eq!(product_challenge, verifier_transcript.challenge_fp2());
        let product_mask = prover_stream.draw_product_mask(20_000, prover_products.len());
        let product_mask_key =
            verifier.expand_product_mask_verifier_key(20_000, verifier_products.len());
        let product_proof = prod_batch_prover(
            &prover_products,
            product_challenge,
            product_mask,
            &mut prover_transcript,
        );
        assert!(prod_batch_verify(
            &verifier_products,
            product_mask_key,
            delta,
            product_challenge,
            &product_proof,
        ));
        assert!(zero_batch_exchange(
            &prover_zeros,
            &verifier_zeros,
            &mut prover_stream,
            &mut verifier,
            20_001,
            &mut prover_transcript,
        ));
        blind_proof.root_inverse_corrections[0] += Fp2::ONE;
        let mut changed_verifier = VerifierCtx::new(correlation_seed, delta);
        let mut changed_doms = Doms::new(10_000);
        let mut changed_transcript = Transcript::new(transcript_seed);
        let mut changed_products = Vec::new();
        let mut changed_zeros = Vec::new();
        assert!(verify_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            &public_relation,
            &blind_proof,
            &mut changed_verifier,
            &mut changed_doms,
            &mut changed_transcript,
            &mut changed_products,
            &mut changed_zeros,
        )
        .unwrap()
        .is_some());
        assert_eq!(product_challenge, changed_transcript.challenge_fp2());
        let changed_product_mask_key =
            changed_verifier.expand_product_mask_verifier_key(20_000, changed_products.len());
        assert!(!prod_batch_verify(
            &changed_products,
            changed_product_mask_key,
            delta,
            product_challenge,
            &product_proof,
        ));

        for subcheck in C6SparseRationalSubcheck::ALL {
            proof.subchecks[subcheck.index()].root_p += Fp2::ONE;
            assert!(!verify_c6_residual_sparse_rational_gkr_reference(
                direct.operation_plan(),
                direct.extraction(),
                direct.runtime(),
                &relation,
                seed,
                &proof,
            )
            .unwrap());
            proof.subchecks[subcheck.index()].root_p =
                proof.subchecks[subcheck.index()].root_p - Fp2::ONE;
        }

        let changed_batch = C6ResidualSparseRationalChallenges::new(
            topology,
            Fp2::new(fp(227), fp(5)),
            sparse_challenges.recurrence,
            sparse_challenges.runtime_gather,
            sparse_challenges.source_gather,
        )
        .unwrap();
        let changed_relation = compile_c6_residual_sparse_rational_relation_reference(
            direct.operation_plan(),
            &terminal_metadata,
            direct.extraction(),
            direct.runtime(),
            direct.relation(),
            [&lanes[0], &lanes[1]],
            changed_batch,
            output_beta,
        )
        .unwrap();
        packed.validate_relation(&changed_relation).unwrap();
        assert!(!verify_c6_residual_sparse_rational_gkr_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &changed_relation,
            seed,
            &proof,
        )
        .unwrap());

        let mut leaves = materialize_sparse_rational_leaves(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
        )
        .unwrap();
        let mut padded_subchecks = 0usize;
        for (index, padded) in leaves.iter_mut().enumerate() {
            if padded.active_rows == padded.numerator.len() {
                continue;
            }
            padded_subchecks += 1;
            padded.numerator[padded.active_rows] = Fp2::ONE;
            assert!(checked_fraction_sum(padded).is_err());
            let mut stream =
                FpStream::domain_separated(seed, C6_SPARSE_RATIONAL_GKR_STREAM_DOMAINS[index]);
            assert!(!verify_frac_tree(
                &proof.subchecks[index],
                |point, counters| {
                    crate::logup::eval_mle_counted(&padded.numerator, point, counters)
                },
                |point, counters| {
                    crate::logup::eval_mle_counted(&padded.denominator, point, counters)
                },
                &mut stream,
                &mut Counters::default(),
            ));
            padded.numerator[padded.active_rows] = Fp2::ZERO;
        }
        assert_eq!(padded_subchecks, C6_SPARSE_RATIONAL_SUBCHECKS);
    }
}

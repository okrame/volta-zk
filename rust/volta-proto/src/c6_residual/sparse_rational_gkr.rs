//! C6SPR1 scaled differential over the generic weighted fraction-tree GKR.
//!
//! This module is intentionally a clear CPU/reference seam.  It proves all
//! seven preregistered rational sums and exposes the final leaf claims through
//! the underlying fraction-tree proof, but it does not yet authenticate those
//! claims against PCS commitments.  The latter is the next typed boundary.

use super::*;
use crate::logup::{prove_weighted_frac_tree, verify_frac_tree, Counters, FracProof};

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
    fn new(
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
    let topology = operation_plan.topology();
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 node count exceeds usize"))?;
    let public_count = usize::try_from(topology.public_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 public count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 source count exceeds usize"))?;
    let runtime_count = public_count
        .checked_add(scalar_count)
        .ok_or_else(|| C6ResidualError::new("C6SPR2 runtime count overflows"))?;
    let base_rows = node_count
        .max(
            runtime_count
                .checked_mul(2)
                .ok_or_else(|| C6ResidualError::new("C6SPR2 runtime packing overflows"))?,
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
    if base_domain_log2 >= C6_SPARSE_PACKING_MAX_SCALED_LOG2
        || operation_plan.operation_kinds().len() != node_count
        || runtime_count > base_rows / 2
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
            "C6SPR2 scaled packing geometry or lane boundary mismatch: base_log2={base_domain_log2}, base_rows={base_rows}, runtime={}, sources={source_count}, lane_nodes={}/{}, lane_sources={}/{}",
            runtime_count,
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
    for public in 0..public_count {
        response_values[boundary_block + public] = runtime
            .public_value(
                extraction,
                u32::try_from(public)
                    .map_err(|_| C6ResidualError::new("C6SPR2 public index exceeds u32"))?,
            )
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
    }
    for scalar in 0..scalar_count {
        response_values[boundary_block + public_count + scalar] = runtime
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

#[cfg(all(test, feature = "c6-trace"))]
mod tests {
    use super::*;
    use volta_mac::C6TraceSourceManifest;

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(fp(value))
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
        let leaf_point = [Fp2::ZERO, Fp2::ONE, fp2(2), fp2(3), fp2(5), fp2(7), fp2(11)];
        let output_beta = fp2(191);
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
        let packed = compile_c6_sparse_rational_packed_oracle_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            [&lanes[0], &lanes[1]],
        )
        .unwrap();
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
        assert_eq!(
            response_openings[3],
            crate::mle::eval_mle(
                &packed_middle[..base_rows / 2],
                &input_point[..input_point.len() - 1]
            )
        );
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

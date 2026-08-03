//! Joint terminal reduction for the seven C6SPR2 weighted-fraction trees.
//!
//! The fourteen leaf claims are batched after the fraction proofs and reduced
//! to one point on the packed base domain.  The terminal expression is
//! linearized into six response openings, one authenticated `lambda * mu`
//! product, and three clear fixed-plan evaluations which must equal their
//! authenticated plan-opening targets.  No leaf polynomial is evaluated by
//! the core verifier.

use super::*;
use crate::logup::{reduce_frac_tree, FracLeafClaims};

const C6_SPARSE_JOINT_DEGREE: usize = 8;
const C6_SPARSE_JOINT_SENT_VALUES: usize = C6_SPARSE_JOINT_DEGREE;
const C6_SPARSE_JOINT_STREAM_DOMAIN: u64 = 0xC6_53_50_52_4A_4C_01;

fn joint_seed_digest(seed: [u8; 32]) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/sparse-joint-leaf-seed/v1");
    hasher.update(&seed);
    *hasher.finalize().as_bytes()
}

fn expected_subcheck_sums(
    relation: &C6ResidualSparseRationalRelationReference,
) -> [Fp2; C6_SPARSE_RATIONAL_SUBCHECKS] {
    [
        relation.recurrence_terms[0],
        relation.recurrence_terms[1],
        relation.recurrence_terms[2],
        relation.runtime_gather_terms[0],
        relation.runtime_gather_terms[1],
        relation.source_gather_terms[0],
        relation.source_gather_terms[1],
    ]
}

fn reduce_sparse_fraction_claims(
    relation: &C6ResidualSparseRationalRelationReference,
    gkr_seed: [u8; 32],
    proof: &C6ResidualSparseRationalGkrReferenceProof,
) -> C6ResidualResult<Option<[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS]>> {
    if proof.relation_digest != relation.digest()
        || proof.gkr_seed_digest != sparse_rational_gkr_seed_digest(gkr_seed)
        || relation.recurrence_residual() != Fp2::ZERO
        || relation.runtime_gather_residual() != Fp2::ZERO
        || relation.source_gather_residual() != Fp2::ZERO
    {
        return Ok(None);
    }
    let expected = expected_subcheck_sums(relation);
    let mut reduced = Vec::with_capacity(C6_SPARSE_RATIONAL_SUBCHECKS);
    let mut counters = Counters::default();
    for (index, subproof) in proof.subchecks.iter().enumerate() {
        if subproof.root_q == Fp2::ZERO || subproof.root_p != expected[index] * subproof.root_q {
            return Ok(None);
        }
        let mut stream =
            FpStream::domain_separated(gkr_seed, C6_SPARSE_RATIONAL_GKR_STREAM_DOMAINS[index]);
        let Some(claims) = reduce_frac_tree(subproof, &mut stream, &mut counters) else {
            return Ok(None);
        };
        reduced.push(claims);
    }
    Ok(Some(reduced.try_into().map_err(|_| {
        C6ResidualError::new("C6SPR2 reduced fraction-claim census differs from seven")
    })?))
}

fn canonical_base_domain_log2_from_topology(
    topology: C6OperationPlanTopologyIdentity,
) -> C6ResidualResult<u8> {
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 source count exceeds usize"))?;
    let rows = node_count
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
    u8::try_from(rows.trailing_zeros())
        .map_err(|_| C6ResidualError::new("C6SPR2 base dimension exceeds u8"))
}

fn canonical_base_domain_log2(operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<u8> {
    canonical_base_domain_log2_from_topology(operation_plan.topology())
}

/// Canonical common dimension used by the joint leaf reduction and all
/// response/plan opening points.
pub fn c6_sparse_rational_base_domain_log2(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<u8> {
    canonical_base_domain_log2(operation_plan)
}

pub fn c6_sparse_rational_base_domain_log2_compact(
    topology: C6OperationPlanTopologyIdentity,
) -> C6ResidualResult<u8> {
    canonical_base_domain_log2_from_topology(topology)
}

fn eq_lifted(leaf_point: &[Fp2], base_point: &[Fp2]) -> C6ResidualResult<Fp2> {
    if leaf_point.len() > base_point.len() {
        return Err(C6ResidualError::new(
            "C6SPR2 fraction leaf point exceeds the packed base dimension",
        ));
    }
    Ok(base_point.iter().enumerate().fold(Fp2::ONE, |acc, (bit, &coordinate)| {
        let leaf = leaf_point.get(bit).copied().unwrap_or(Fp2::ZERO);
        let product = leaf * coordinate;
        acc * (product + product - leaf - coordinate + Fp2::ONE)
    }))
}

fn range_denominator_mle(
    active_rows: usize,
    challenge: Fp2,
    leaf_point: &[Fp2],
    base_point: &[Fp2],
) -> C6ResidualResult<Fp2> {
    if leaf_point.len() > base_point.len() {
        return Err(C6ResidualError::new(
            "C6SPR2 range denominator exceeds the packed base dimension",
        ));
    }
    let (active, active_index) =
        c6_sparse_range_mle_moments(active_rows, &base_point[..leaf_point.len()])?;
    Ok(Fp2::ONE + active * (challenge - Fp2::ONE) - active_index)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminalLinearization {
    leaf_coefficients: [[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS],
    response_coefficients: [Fp2; C6_SPARSE_RESPONSE_OPENINGS],
    lambda_mu_coefficient: Fp2,
    public_constant: Fp2,
}

impl TerminalLinearization {
    fn evaluate(
        &self,
        leaf_values: &[[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS],
        response: &[Fp2; C6_SPARSE_RESPONSE_OPENINGS],
        lane_batch: Fp2,
    ) -> Fp2 {
        let leaf_linear = self.leaf_coefficients.iter().zip(leaf_values).fold(
            self.public_constant,
            |sum, (coefficients, values)| {
                sum + coefficients[0] * values[0] + coefficients[1] * values[1]
            },
        );
        let linear = self
            .response_coefficients
            .iter()
            .zip(response)
            .fold(leaf_linear, |sum, (&coefficient, &value)| sum + coefficient * value);
        let lambda = response[0] + lane_batch * response[1];
        linear + self.lambda_mu_coefficient * lambda * response[2]
    }
}

#[cfg(all(test, feature = "c6-trace"))]
fn terminal_leaf_values(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    claims: &[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS],
    base_point: &[Fp2],
    response: &[Fp2; C6_SPARSE_RESPONSE_OPENINGS],
    plan: &[Fp2; C6_SPARSE_PLAN_OPENINGS],
    injection: Fp2,
) -> C6ResidualResult<[[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS]> {
    let topology = operation_plan.topology();
    let node_count = topology.canonical_node_count as usize;
    let scalar_count = topology.scalar_input_count as usize;
    let source_count = topology.source_count as usize;
    let opcode = plan[0];
    let lhs = plan[1];
    let rhs = plan[2];
    let select_source = c6_sparse_opcode_selector(C6InstalledOperationKind::Source, opcode);
    let select_add = c6_sparse_opcode_selector(C6InstalledOperationKind::Add, opcode);
    let select_sub = c6_sparse_opcode_selector(C6InstalledOperationKind::Sub, opcode);
    let select_scale = c6_sparse_opcode_selector(C6InstalledOperationKind::Scale, opcode);
    let gamma = relation.sparse_challenges.recurrence;
    let tau = relation.sparse_challenges.runtime_gather;
    let delta = relation.sparse_challenges.source_gather;
    let zeta = relation.sparse_challenges.lane_batch;
    let lambda = response[0] + zeta * response[1];
    let lhs_denominator = gamma - lhs;
    let rhs_denominator = gamma - rhs;

    Ok([
        [
            lambda - injection,
            range_denominator_mle(
                node_count,
                gamma,
                &claims[C6SparseRationalSubcheck::RecurrenceAnchor.index()].point,
                base_point,
            )?,
        ],
        [
            lambda
                * (select_add * (rhs_denominator + lhs_denominator)
                    + select_sub * (rhs_denominator - lhs_denominator)),
            Fp2::ONE + (select_add + select_sub) * (lhs_denominator * rhs_denominator - Fp2::ONE),
        ],
        [select_scale * lambda * response[2], Fp2::ONE + select_scale * (gamma - lhs - Fp2::ONE)],
        [select_scale * response[2], Fp2::ONE + select_scale * (tau - rhs - Fp2::ONE)],
        [
            response[3],
            range_denominator_mle(
                scalar_count,
                tau,
                &claims[C6SparseRationalSubcheck::RuntimeTable.index()].point,
                base_point,
            )?,
        ],
        [
            response[4] + zeta * response[5],
            range_denominator_mle(
                source_count,
                delta,
                &claims[C6SparseRationalSubcheck::SourceBoundary.index()].point,
                base_point,
            )?,
        ],
        [select_source * lambda, Fp2::ONE + select_source * (delta - lhs - Fp2::ONE)],
    ])
}

fn terminal_linearization(
    operation_plan: &C6InstalledOperationPlan,
    sparse_challenges: C6ResidualSparseRationalChallenges,
    claim_points: &[Vec<Fp2>; C6_SPARSE_RATIONAL_SUBCHECKS],
    theta: Fp2,
    base_point: &[Fp2],
    plan: &[Fp2; C6_SPARSE_PLAN_OPENINGS],
    injection: Fp2,
) -> C6ResidualResult<TerminalLinearization> {
    terminal_linearization_from_topology(
        operation_plan.topology(),
        sparse_challenges,
        claim_points,
        theta,
        base_point,
        plan,
        injection,
    )
}

#[allow(clippy::too_many_arguments)]
fn terminal_linearization_from_topology(
    topology: C6OperationPlanTopologyIdentity,
    sparse_challenges: C6ResidualSparseRationalChallenges,
    claim_points: &[Vec<Fp2>; C6_SPARSE_RATIONAL_SUBCHECKS],
    theta: Fp2,
    base_point: &[Fp2],
    plan: &[Fp2; C6_SPARSE_PLAN_OPENINGS],
    injection: Fp2,
) -> C6ResidualResult<TerminalLinearization> {
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 source count exceeds usize"))?;
    if claim_points.iter().any(|point| point.len() > base_point.len()) {
        return Err(C6ResidualError::new(
            "C6SPR2 reduced leaf point exceeds the common terminal point",
        ));
    }

    let mut powers = [Fp2::ONE; 2 * C6_SPARSE_RATIONAL_SUBCHECKS];
    for index in 1..powers.len() {
        powers[index] = powers[index - 1] * theta;
    }
    let eq: [Fp2; C6_SPARSE_RATIONAL_SUBCHECKS] = claim_points
        .iter()
        .map(|point| eq_lifted(point, base_point))
        .collect::<C6ResidualResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| C6ResidualError::new("C6SPR2 equality-weight census differs from seven"))?;
    let weighted = |subcheck: C6SparseRationalSubcheck, numerator: bool| {
        let index = subcheck.index();
        eq[index] * powers[2 * index + usize::from(!numerator)]
    };
    let leaf_coefficients = std::array::from_fn(|index| {
        [Fp2::ZERO - eq[index] * powers[2 * index], Fp2::ZERO - eq[index] * powers[2 * index + 1]]
    });
    let mut response_coefficients = [Fp2::ZERO; C6_SPARSE_RESPONSE_OPENINGS];
    let mut lambda_mu_coefficient = Fp2::ZERO;
    let mut public_constant = Fp2::ZERO;

    let opcode = plan[0];
    let lhs = plan[1];
    let rhs = plan[2];
    let select_source = c6_sparse_opcode_selector(C6InstalledOperationKind::Source, opcode);
    let select_add = c6_sparse_opcode_selector(C6InstalledOperationKind::Add, opcode);
    let select_sub = c6_sparse_opcode_selector(C6InstalledOperationKind::Sub, opcode);
    let select_scale = c6_sparse_opcode_selector(C6InstalledOperationKind::Scale, opcode);
    let gamma = sparse_challenges.recurrence;
    let tau = sparse_challenges.runtime_gather;
    let delta = sparse_challenges.source_gather;
    let zeta = sparse_challenges.lane_batch;
    let anchor_p = weighted(C6SparseRationalSubcheck::RecurrenceAnchor, true);
    response_coefficients[0] += anchor_p;
    response_coefficients[1] += anchor_p * zeta;
    public_constant = public_constant - anchor_p * injection;
    public_constant += weighted(C6SparseRationalSubcheck::RecurrenceAnchor, false)
        * range_denominator_mle(
            node_count,
            gamma,
            &claim_points[C6SparseRationalSubcheck::RecurrenceAnchor.index()],
            base_point,
        )?;

    let lhs_denominator = gamma - lhs;
    let rhs_denominator = gamma - rhs;
    let linear_factor = select_add * (rhs_denominator + lhs_denominator)
        + select_sub * (rhs_denominator - lhs_denominator);
    let linear_p = weighted(C6SparseRationalSubcheck::RecurrenceLinear, true) * linear_factor;
    response_coefficients[0] += linear_p;
    response_coefficients[1] += linear_p * zeta;
    public_constant += weighted(C6SparseRationalSubcheck::RecurrenceLinear, false)
        * (Fp2::ONE + (select_add + select_sub) * (lhs_denominator * rhs_denominator - Fp2::ONE));

    lambda_mu_coefficient +=
        weighted(C6SparseRationalSubcheck::RecurrenceScale, true) * select_scale;
    public_constant += weighted(C6SparseRationalSubcheck::RecurrenceScale, false)
        * (Fp2::ONE + select_scale * (gamma - lhs - Fp2::ONE));

    response_coefficients[2] +=
        weighted(C6SparseRationalSubcheck::RuntimePlan, true) * select_scale;
    public_constant += weighted(C6SparseRationalSubcheck::RuntimePlan, false)
        * (Fp2::ONE + select_scale * (tau - rhs - Fp2::ONE));

    response_coefficients[3] += weighted(C6SparseRationalSubcheck::RuntimeTable, true);
    public_constant += weighted(C6SparseRationalSubcheck::RuntimeTable, false)
        * range_denominator_mle(
            scalar_count,
            tau,
            &claim_points[C6SparseRationalSubcheck::RuntimeTable.index()],
            base_point,
        )?;

    let source_boundary = weighted(C6SparseRationalSubcheck::SourceBoundary, true);
    response_coefficients[4] += source_boundary;
    response_coefficients[5] += source_boundary * zeta;
    public_constant += weighted(C6SparseRationalSubcheck::SourceBoundary, false)
        * range_denominator_mle(
            source_count,
            delta,
            &claim_points[C6SparseRationalSubcheck::SourceBoundary.index()],
            base_point,
        )?;

    let source_plan = weighted(C6SparseRationalSubcheck::SourcePlan, true) * select_source;
    response_coefficients[0] += source_plan;
    response_coefficients[1] += source_plan * zeta;
    public_constant += weighted(C6SparseRationalSubcheck::SourcePlan, false)
        * (Fp2::ONE + select_source * (delta - lhs - Fp2::ONE));

    Ok(TerminalLinearization {
        leaf_coefficients,
        response_coefficients,
        lambda_mu_coefficient,
        public_constant,
    })
}

fn fraction_leaf_values(
    claims: &[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS],
) -> [[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS] {
    std::array::from_fn(|index| [claims[index].p, claims[index].q])
}

fn fraction_leaf_points(
    claims: &[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS],
) -> [Vec<Fp2>; C6_SPARSE_RATIONAL_SUBCHECKS] {
    std::array::from_fn(|index| claims[index].point.clone())
}

#[derive(Clone, Debug)]
struct FoldedColumn {
    dimension: usize,
    values: Vec<Fp2>,
}

impl FoldedColumn {
    fn exact(values: &[Fp2], dimension: usize) -> C6ResidualResult<Self> {
        if dimension >= usize::BITS as usize || values.len() != 1usize << dimension {
            return Err(C6ResidualError::new("C6SPR2 folded column geometry is noncanonical"));
        }
        Ok(Self { dimension, values: values.to_vec() })
    }

    fn padded(values: &[Fp2], dimension: usize) -> C6ResidualResult<Self> {
        if dimension >= usize::BITS as usize || values.len() > 1usize << dimension {
            return Err(C6ResidualError::new("C6SPR2 padded column exceeds its domain"));
        }
        let mut padded = values.to_vec();
        padded.resize(1usize << dimension, Fp2::ZERO);
        Ok(Self { dimension, values: padded })
    }

    fn evaluate_current(&self, round: usize, value: Fp2, suffix: usize) -> Fp2 {
        if round >= self.dimension {
            return self.values[0];
        }
        let remaining_after = self.dimension - round - 1;
        let pair =
            if remaining_after == 0 { 0 } else { suffix & ((1usize << remaining_after) - 1) };
        let low = self.values[2 * pair];
        low + (self.values[2 * pair + 1] - low) * value
    }

    fn fold(&mut self, round: usize, challenge: Fp2) {
        if round < self.dimension {
            crate::mle::fold_low(&mut self.values, challenge);
        }
    }
}

struct JointWitnessState {
    response: [FoldedColumn; C6_SPARSE_RESPONSE_OPENINGS],
    plan: [FoldedColumn; C6_SPARSE_PLAN_OPENINGS],
    injection: FoldedColumn,
}

impl JointWitnessState {
    fn new(
        packed: &C6SparseRationalPackedOracleReference,
        relation: &C6ResidualSparseRationalRelationReference,
    ) -> C6ResidualResult<Self> {
        let dimension = usize::from(packed.base_domain_log2);
        let base_rows = 1usize << dimension;
        if packed.response_values.len() != C6_SPARSE_RESPONSE_BLOCKS * base_rows
            || packed.plan_values.len() != C6_SPARSE_PLAN_BLOCKS * base_rows
        {
            return Err(C6ResidualError::new("C6SPR2 packed oracle geometry is malformed"));
        }
        let response = [
            FoldedColumn::exact(&packed.response_values[..base_rows], dimension)?,
            FoldedColumn::exact(&packed.response_values[base_rows..2 * base_rows], dimension)?,
            FoldedColumn::exact(&packed.response_values[3 * base_rows..4 * base_rows], dimension)?,
            FoldedColumn::exact(
                &packed.response_values[2 * base_rows..2 * base_rows + base_rows / 2],
                dimension - 1,
            )?,
            FoldedColumn::exact(
                &packed.response_values
                    [2 * base_rows + base_rows / 2..2 * base_rows + 3 * base_rows / 4],
                dimension - 2,
            )?,
            FoldedColumn::exact(
                &packed.response_values[2 * base_rows + 3 * base_rows / 4..3 * base_rows],
                dimension - 2,
            )?,
        ];
        let plan: [FoldedColumn; C6_SPARSE_PLAN_OPENINGS] = (0..C6_SPARSE_PLAN_OPENINGS)
            .map(|block| {
                FoldedColumn::exact(
                    &packed.plan_values[block * base_rows..(block + 1) * base_rows],
                    dimension,
                )
            })
            .collect::<C6ResidualResult<Vec<_>>>()?
            .try_into()
            .map_err(|_| C6ResidualError::new("C6SPR2 folded plan census differs from three"))?;
        Ok(Self {
            response,
            plan,
            injection: FoldedColumn::padded(&relation.combined_injection, dimension)?,
        })
    }

    fn evaluate(
        &self,
        round: usize,
        value: Fp2,
        suffix: usize,
    ) -> ([Fp2; C6_SPARSE_RESPONSE_OPENINGS], [Fp2; C6_SPARSE_PLAN_OPENINGS], Fp2) {
        (
            std::array::from_fn(|index| {
                self.response[index].evaluate_current(round, value, suffix)
            }),
            std::array::from_fn(|index| self.plan[index].evaluate_current(round, value, suffix)),
            self.injection.evaluate_current(round, value, suffix),
        )
    }

    fn fold(&mut self, round: usize, challenge: Fp2) {
        for column in &mut self.response {
            column.fold(round, challenge);
        }
        for column in &mut self.plan {
            column.fold(round, challenge);
        }
        self.injection.fold(round, challenge);
    }
}

fn point_with_suffix(dimension: usize, prefix: &[Fp2], value: Fp2, suffix: usize) -> Vec<Fp2> {
    let mut point = Vec::with_capacity(dimension);
    point.extend_from_slice(prefix);
    point.push(value);
    for bit in 0..dimension - prefix.len() - 1 {
        point.push(if (suffix >> bit) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO });
    }
    point
}

fn joint_round_evaluations(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    claims: &[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS],
    theta: Fp2,
    dimension: usize,
    prefix: &[Fp2],
    state: &JointWitnessState,
) -> C6ResidualResult<[Fp2; C6_SPARSE_JOINT_DEGREE + 1]> {
    let round = prefix.len();
    let leaf_values = fraction_leaf_values(claims);
    let leaf_points = fraction_leaf_points(claims);
    let suffix_rows = 1usize << (dimension - round - 1);
    let mut evaluations = [Fp2::ZERO; C6_SPARSE_JOINT_DEGREE + 1];
    for (integer, evaluation) in evaluations.iter_mut().enumerate() {
        let value = Fp2::from_base(Fp::new(integer as u64));
        for suffix in 0..suffix_rows {
            let point = point_with_suffix(dimension, prefix, value, suffix);
            let (response, plan, injection) = state.evaluate(round, value, suffix);
            let linearization = terminal_linearization(
                operation_plan,
                relation.sparse_challenges,
                &leaf_points,
                theta,
                &point,
                &plan,
                injection,
            )?;
            *evaluation += linearization.evaluate(
                &leaf_values,
                &response,
                relation.sparse_challenges.lane_batch,
            );
        }
    }
    Ok(evaluations)
}

fn degree_eight_lagrange_weights(point: Fp2) -> [Fp2; C6_SPARSE_JOINT_DEGREE + 1] {
    std::array::from_fn(|index| {
        let mut numerator = Fp2::ONE;
        let mut denominator = Fp::ONE;
        for other in 0..=C6_SPARSE_JOINT_DEGREE {
            if other == index {
                continue;
            }
            numerator = numerator * (point - Fp2::from_base(Fp::new(other as u64)));
            denominator = denominator * Fp::from_i64(index as i64 - other as i64);
        }
        numerator.mul_base(denominator.inv())
    })
}

fn interpolate_degree_eight(evaluations: &[Fp2; C6_SPARSE_JOINT_DEGREE + 1], point: Fp2) -> Fp2 {
    evaluations
        .iter()
        .zip(degree_eight_lagrange_weights(point))
        .fold(Fp2::ZERO, |sum, (&evaluation, weight)| sum + evaluation * weight)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSparseRationalBlindJointRoundsProof {
    relation_digest: C6ResidualDigest,
    clear_plan_values: [Fp2; C6_SPARSE_PLAN_OPENINGS],
    round_corrections: Vec<[Fp2; C6_SPARSE_JOINT_SENT_VALUES]>,
}

impl C6ResidualSparseRationalBlindJointRoundsProof {
    pub fn bytes(&self) -> u64 {
        16 * (C6_SPARSE_PLAN_OPENINGS as u64
            + self.round_corrections.len() as u64 * C6_SPARSE_JOINT_SENT_VALUES as u64)
    }

    pub fn clear_plan_values(&self) -> &[Fp2; C6_SPARSE_PLAN_OPENINGS] {
        &self.clear_plan_values
    }

    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn correction_bytes(base_domain_log2: u8) -> C6ResidualResult<u64> {
        16u64
            .checked_mul(
                C6_SPARSE_PLAN_OPENINGS as u64
                    + u64::from(base_domain_log2) * C6_SPARSE_JOINT_SENT_VALUES as u64,
            )
            .ok_or_else(|| C6ResidualError::new("C6SPR3 joint correction byte count overflows"))
    }

    /// Encode transcript-visible plan evaluations and degree-eight round
    /// corrections.  The enclosing frame owns the relation digest and D25
    /// dimension.
    pub fn encode_corrections(&self, base_domain_log2: u8) -> C6ResidualResult<Vec<u8>> {
        if self.round_corrections.len() != usize::from(base_domain_log2) {
            return Err(C6ResidualError::new(
                "C6SPR3 joint correction round census is noncanonical",
            ));
        }
        let expected_bytes = Self::correction_bytes(base_domain_log2)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected_bytes)
                .map_err(|_| C6ResidualError::new("C6SPR3 joint body exceeds usize"))?,
        );
        for value in self.clear_plan_values {
            encode_sparse_blind_fp2(&mut bytes, value);
        }
        for round in &self.round_corrections {
            for correction in round {
                encode_sparse_blind_fp2(&mut bytes, *correction);
            }
        }
        if bytes.len() as u64 != expected_bytes || self.bytes() != expected_bytes {
            return Err(C6ResidualError::new(
                "C6SPR3 joint encoder disagrees with the exact census",
            ));
        }
        Ok(bytes)
    }

    pub fn decode_corrections(
        relation_digest: C6ResidualDigest,
        base_domain_log2: u8,
        bytes: &[u8],
    ) -> C6ResidualResult<Self> {
        if bytes.len() as u64 != Self::correction_bytes(base_domain_log2)? {
            return Err(C6ResidualError::new("C6SPR3 strict joint correction length mismatch"));
        }
        let mut reader = SparseBlindCorrectionReader::new(bytes);
        let clear_plan_values = [reader.fp2()?, reader.fp2()?, reader.fp2()?];
        let mut round_corrections = Vec::with_capacity(usize::from(base_domain_log2));
        for _ in 0..base_domain_log2 {
            let mut round = [Fp2::ZERO; C6_SPARSE_JOINT_SENT_VALUES];
            for correction in &mut round {
                *correction = reader.fp2()?;
            }
            round_corrections.push(round);
        }
        reader.finish()?;
        Ok(Self { relation_digest, clear_plan_values, round_corrections })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSparseRationalBlindJointTerminalProof {
    product_correction: Fp2,
}

impl C6ResidualSparseRationalBlindJointTerminalProof {
    pub const fn bytes(&self) -> u64 {
        16
    }

    pub fn product_correction(&self) -> Fp2 {
        self.product_correction
    }

    pub fn from_product_correction(product_correction: Fp2) -> Self {
        Self { product_correction }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalBlindJointProverTerminal {
    relation_digest: C6ResidualDigest,
    points: C6SparseRationalPackedOpeningPoints,
    expected_response: [Fp2; C6_SPARSE_RESPONSE_OPENINGS],
    clear_plan_values: [Fp2; C6_SPARSE_PLAN_OPENINGS],
    linearization: TerminalLinearization,
    leaf_claims: [C6SparseRationalBlindLeafClaim; C6_SPARSE_RATIONAL_SUBCHECKS],
    sumcheck_claim: ProverAuthed,
    lane_batch: Fp2,
}

impl C6SparseRationalBlindJointProverTerminal {
    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn points(&self) -> &C6SparseRationalPackedOpeningPoints {
        &self.points
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalBlindJointVerifierTerminal {
    relation_digest: C6ResidualDigest,
    points: C6SparseRationalPackedOpeningPoints,
    clear_plan_values: [Fp2; C6_SPARSE_PLAN_OPENINGS],
    linearization: TerminalLinearization,
    leaf_keys: [C6SparseRationalBlindLeafKey; C6_SPARSE_RATIONAL_SUBCHECKS],
    sumcheck_claim: VerifierKey,
    lane_batch: Fp2,
}

impl C6SparseRationalBlindJointVerifierTerminal {
    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn points(&self) -> &C6SparseRationalPackedOpeningPoints {
        &self.points
    }

    /// The three clear plan evaluations are carried by the strict joint
    /// proof and authenticated later by the shared D27 opening.  Exposing
    /// them lets a compact verifier avoid materializing the plan oracle.
    pub fn clear_plan_values(&self) -> &[Fp2; C6_SPARSE_PLAN_OPENINGS] {
        &self.clear_plan_values
    }
}

fn blind_leaf_claims_as_clear(
    claims: &[C6SparseRationalBlindLeafClaim; C6_SPARSE_RATIONAL_SUBCHECKS],
) -> [FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS] {
    std::array::from_fn(|index| FracLeafClaims {
        point: claims[index].point.clone(),
        p: claims[index].numerator.x,
        q: claims[index].denominator.x,
    })
}

/// Authenticate the degree-8 joint sumcheck rounds.  The response and plan
/// PCS targets are deliberately absent here: they become available only at
/// the returned common point and are connected by the terminal finish step.
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    packed: &C6SparseRationalPackedOracleReference,
    leaf_claims: &[C6SparseRationalBlindLeafClaim; C6_SPARSE_RATIONAL_SUBCHECKS],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
) -> C6ResidualResult<(
    C6ResidualSparseRationalBlindJointRoundsProof,
    C6SparseRationalBlindJointProverTerminal,
)> {
    public_relation.validate_operation_plan(operation_plan)?;
    relation.validate_public_relation(public_relation)?;
    if packed.base_domain_log2 != canonical_base_domain_log2(operation_plan)? {
        return Err(C6ResidualError::new(
            "C6SPR3 blind joint reduction base dimension is noncanonical",
        ));
    }
    packed.validate_relation(relation)?;
    let depths = sparse_rational_subcheck_depths(operation_plan)?;
    if leaf_claims.iter().zip(depths).any(|(claim, depth)| claim.point.len() != depth) {
        return Err(C6ResidualError::new("C6SPR3 blind leaf-claim point is noncanonical"));
    }
    let clear_claims = blind_leaf_claims_as_clear(leaf_claims);
    let dimension = usize::from(packed.base_domain_log2);
    let mut state = JointWitnessState::new(packed, relation)?;
    let theta = tx.challenge_fp2();
    let mut claim = ProverAuthed::ZERO;
    let mut point = Vec::with_capacity(dimension);
    let mut round_corrections = Vec::with_capacity(dimension);
    for round in 0..dimension {
        let evaluations = joint_round_evaluations(
            operation_plan,
            relation,
            &clear_claims,
            theta,
            dimension,
            &point,
            &state,
        )?;
        if evaluations[0] + evaluations[1] != claim.x {
            return Err(C6ResidualError::new(
                "C6SPR3 blind joint polynomial differs from its authenticated claim",
            ));
        }
        let sent: [Fp2; C6_SPARSE_JOINT_SENT_VALUES] =
            std::array::from_fn(
                |index| {
                    if index == 0 {
                        evaluations[0]
                    } else {
                        evaluations[index + 1]
                    }
                },
            );
        let domain = doms.take(1);
        let masks = stream.draw_fulls(domain, C6_SPARSE_JOINT_SENT_VALUES);
        stream
            .record_c6_fullfield_plaintexts(domain, &sent)
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        round_corrections.push(std::array::from_fn(|index| sent[index] - masks[index].x));
        tx.append("c6_sparse_joint_round_corrections", 16 * C6_SPARSE_JOINT_SENT_VALUES as u64);
        let authenticated_sent: [ProverAuthed; C6_SPARSE_JOINT_SENT_VALUES] = masks
            .into_iter()
            .zip(sent)
            .map(|(mask, value)| mask.authenticate(value))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| C6ResidualError::new("C6SPR3 authenticated round census mismatch"))?;
        let authenticated_evaluations: [ProverAuthed; C6_SPARSE_JOINT_DEGREE + 1] =
            std::array::from_fn(|index| match index {
                0 => authenticated_sent[0],
                1 => claim.sub(authenticated_sent[0]),
                _ => authenticated_sent[index - 1],
            });
        let challenge = tx.challenge_fp2();
        claim = authenticated_evaluations
            .iter()
            .zip(degree_eight_lagrange_weights(challenge))
            .fold(ProverAuthed::ZERO, |sum, (&evaluation, weight)| {
                sum.add(evaluation.scale(weight))
            });
        state.fold(round, challenge);
        point.push(challenge);
    }
    let points = packed.opening_points(&point)?;
    let expected_response = packed.evaluate_response_openings(&points)?;
    let clear_plan_values = packed.evaluate_plan_openings(&points)?;
    tx.append("c6_sparse_joint_plan_values", 16 * C6_SPARSE_PLAN_OPENINGS as u64);
    let injection = crate::mle::eval_mle(&relation.combined_injection, &point);
    let linearization = terminal_linearization(
        operation_plan,
        relation.sparse_challenges,
        &fraction_leaf_points(&clear_claims),
        theta,
        &point,
        &clear_plan_values,
        injection,
    )?;
    Ok((
        C6ResidualSparseRationalBlindJointRoundsProof {
            relation_digest: public_relation.digest(),
            clear_plan_values,
            round_corrections,
        },
        C6SparseRationalBlindJointProverTerminal {
            relation_digest: public_relation.digest(),
            points,
            expected_response,
            clear_plan_values,
            linearization,
            leaf_claims: leaf_claims.clone(),
            sumcheck_claim: claim,
            lane_batch: relation.sparse_challenges.lane_batch,
        },
    ))
}

/// Verifier mirror of the blind degree-8 round reduction.
#[allow(clippy::too_many_arguments)]
pub fn verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: &C6OperationPlanTerminalMetadata,
    relation_challenges: &C6ResidualRelationChallenges,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    leaf_keys: &[C6SparseRationalBlindLeafKey; C6_SPARSE_RATIONAL_SUBCHECKS],
    proof: &C6ResidualSparseRationalBlindJointRoundsProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
) -> C6ResidualResult<Option<C6SparseRationalBlindJointVerifierTerminal>> {
    public_relation.validate(operation_plan, terminal_metadata, relation_challenges)?;
    verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_with_topology(
        operation_plan.topology(),
        terminal_metadata,
        relation_challenges,
        public_relation,
        base_domain_log2,
        response_digest,
        plan_digest,
        leaf_keys,
        proof,
        ctx,
        doms,
        tx,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_compact(
    operation_plan_digest: C6ResidualDigest,
    topology: C6OperationPlanTopologyIdentity,
    terminal_metadata: &C6OperationPlanTerminalMetadata,
    relation_challenges: &C6ResidualRelationChallenges,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    leaf_keys: &[C6SparseRationalBlindLeafKey; C6_SPARSE_RATIONAL_SUBCHECKS],
    proof: &C6ResidualSparseRationalBlindJointRoundsProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
) -> C6ResidualResult<Option<C6SparseRationalBlindJointVerifierTerminal>> {
    public_relation.validate_compact(
        operation_plan_digest,
        topology,
        terminal_metadata,
        relation_challenges,
    )?;
    verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_with_topology(
        topology,
        terminal_metadata,
        relation_challenges,
        public_relation,
        base_domain_log2,
        response_digest,
        plan_digest,
        leaf_keys,
        proof,
        ctx,
        doms,
        tx,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_with_topology(
    topology: C6OperationPlanTopologyIdentity,
    terminal_metadata: &C6OperationPlanTerminalMetadata,
    relation_challenges: &C6ResidualRelationChallenges,
    public_relation: &C6ResidualSparseRationalPublicRelation,
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    leaf_keys: &[C6SparseRationalBlindLeafKey; C6_SPARSE_RATIONAL_SUBCHECKS],
    proof: &C6ResidualSparseRationalBlindJointRoundsProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
) -> C6ResidualResult<Option<C6SparseRationalBlindJointVerifierTerminal>> {
    if base_domain_log2 != canonical_base_domain_log2_from_topology(topology)?
        || proof.relation_digest != public_relation.digest()
        || proof.round_corrections.len() != usize::from(base_domain_log2)
    {
        return Ok(None);
    }
    let depths = sparse_rational_subcheck_depths_from_topology(topology)?;
    if leaf_keys.iter().zip(depths).any(|(claim, depth)| claim.point.len() != depth) {
        return Ok(None);
    }
    let theta = tx.challenge_fp2();
    let mut claim = VerifierKey::ZERO;
    let mut point = Vec::with_capacity(usize::from(base_domain_log2));
    for corrections in &proof.round_corrections {
        let authenticated_sent: [VerifierKey; C6_SPARSE_JOINT_SENT_VALUES] = ctx
            .correct_full_verifier_keys(doms.take(1), corrections)
            .try_into()
            .map_err(|_| C6ResidualError::new("C6SPR3 authenticated key census mismatch"))?;
        tx.append("c6_sparse_joint_round_corrections", 16 * C6_SPARSE_JOINT_SENT_VALUES as u64);
        let authenticated_evaluations: [VerifierKey; C6_SPARSE_JOINT_DEGREE + 1] =
            std::array::from_fn(|index| match index {
                0 => authenticated_sent[0],
                1 => claim.sub(authenticated_sent[0]),
                _ => authenticated_sent[index - 1],
            });
        let challenge = tx.challenge_fp2();
        claim = authenticated_evaluations
            .iter()
            .zip(degree_eight_lagrange_weights(challenge))
            .fold(VerifierKey::ZERO, |sum, (&evaluation, weight)| {
                sum.add(evaluation.scale(weight))
            });
        point.push(challenge);
    }
    tx.append("c6_sparse_joint_plan_values", 16 * C6_SPARSE_PLAN_OPENINGS as u64);
    let sparse_challenges = public_relation.sparse_challenges();
    let injection = evaluate_c6_residual_folded_terminal_injection_sparse(
        terminal_metadata,
        relation_challenges,
        sparse_challenges.lane_batch(),
        public_relation.output_beta(),
        &point,
    )?;
    let claim_points = std::array::from_fn(|index| leaf_keys[index].point.clone());
    let linearization = terminal_linearization_from_topology(
        topology,
        sparse_challenges,
        &claim_points,
        theta,
        &point,
        &proof.clear_plan_values,
        injection,
    )?;
    Ok(Some(C6SparseRationalBlindJointVerifierTerminal {
        relation_digest: public_relation.digest(),
        points: C6SparseRationalPackedOpeningPoints::new(
            base_domain_log2,
            response_digest,
            plan_digest,
            &point,
        )?,
        clear_plan_values: proof.clear_plan_values,
        linearization,
        leaf_keys: leaf_keys.clone(),
        sumcheck_claim: claim,
        lane_batch: sparse_challenges.lane_batch,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn finish_c6_residual_sparse_rational_joint_leaf_blind_prover(
    terminal: C6SparseRationalBlindJointProverTerminal,
    response_targets: &[ProverAuthed; C6_SPARSE_RESPONSE_OPENINGS],
    plan_targets: &[ProverAuthed; C6_SPARSE_PLAN_OPENINGS],
    stream: &mut CorrelationStream,
    doms: &mut Doms,
    tx: &mut Transcript,
    products: &mut ProdTriples,
    zeros: &mut Vec<ProverAuthed>,
) -> C6ResidualResult<C6ResidualSparseRationalBlindJointTerminalProof> {
    if response_targets
        .iter()
        .zip(terminal.expected_response)
        .any(|(target, expected)| target.x != expected)
        || plan_targets
            .iter()
            .zip(terminal.clear_plan_values)
            .any(|(target, expected)| target.x != expected)
    {
        return Err(C6ResidualError::new("C6SPR3 PCS target plaintext mismatch"));
    }
    let lambda = response_targets[0].add(response_targets[1].scale(terminal.lane_batch));
    let mu = response_targets[2];
    let product_value = lambda.x * mu.x;
    let domain = doms.take(1);
    let product_mask = stream
        .draw_fulls(domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C6ResidualError::new("C6SPR3 missing terminal-product correlation"))?;
    stream
        .record_c6_fullfield_plaintexts(domain, &[product_value])
        .map_err(|error| C6ResidualError::new(error.to_string()))?;
    let product_correction = product_value - product_mask.x;
    tx.append("c6_sparse_joint_product_correction", 16);
    let product = product_mask.authenticate(product_value);
    products.push((lambda, mu, product));

    for (target, clear) in plan_targets.iter().zip(terminal.clear_plan_values) {
        zeros.push(target.sub(ProverAuthed::from_public(clear)));
    }
    let mut residual = ProverAuthed::from_public(terminal.linearization.public_constant)
        .sub(terminal.sumcheck_claim);
    for (coefficients, claim) in
        terminal.linearization.leaf_coefficients.iter().zip(&terminal.leaf_claims)
    {
        residual = residual
            .add(claim.numerator.scale(coefficients[0]))
            .add(claim.denominator.scale(coefficients[1]));
    }
    for (&coefficient, target) in
        terminal.linearization.response_coefficients.iter().zip(response_targets)
    {
        residual = residual.add(target.scale(coefficient));
    }
    residual = residual.add(product.scale(terminal.linearization.lambda_mu_coefficient));
    if residual.x != Fp2::ZERO {
        return Err(C6ResidualError::new("C6SPR3 honest blind terminal residual is nonzero"));
    }
    zeros.push(residual);
    Ok(C6ResidualSparseRationalBlindJointTerminalProof { product_correction })
}

#[allow(clippy::too_many_arguments)]
pub fn finish_c6_residual_sparse_rational_joint_leaf_blind_verifier(
    terminal: C6SparseRationalBlindJointVerifierTerminal,
    response_keys: &[VerifierKey; C6_SPARSE_RESPONSE_OPENINGS],
    plan_keys: &[VerifierKey; C6_SPARSE_PLAN_OPENINGS],
    proof: &C6ResidualSparseRationalBlindJointTerminalProof,
    ctx: &mut VerifierCtx,
    doms: &mut Doms,
    tx: &mut Transcript,
    products: &mut ProdKeyTriples,
    zeros: &mut Vec<VerifierKey>,
) -> C6ResidualResult<()> {
    let lambda = response_keys[0].add(response_keys[1].scale(terminal.lane_batch));
    let mu = response_keys[2];
    let product = ctx.correct_full_verifier_key(doms.take(1), proof.product_correction);
    tx.append("c6_sparse_joint_product_correction", 16);
    products.push((lambda, mu, product));

    for (target, clear) in plan_keys.iter().zip(terminal.clear_plan_values) {
        zeros.push(target.sub(VerifierKey::from_public(clear, ctx.delta)));
    }
    let mut residual = VerifierKey::from_public(terminal.linearization.public_constant, ctx.delta)
        .sub(terminal.sumcheck_claim);
    for (coefficients, claim) in
        terminal.linearization.leaf_coefficients.iter().zip(&terminal.leaf_keys)
    {
        residual = residual
            .add(claim.numerator.scale(coefficients[0]))
            .add(claim.denominator.scale(coefficients[1]));
    }
    for (&coefficient, target) in
        terminal.linearization.response_coefficients.iter().zip(response_keys)
    {
        residual = residual.add(target.scale(coefficient));
    }
    residual = residual.add(product.scale(terminal.linearization.lambda_mu_coefficient));
    zeros.push(residual);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSparseRationalJointLeafProof {
    relation_digest: C6ResidualDigest,
    gkr_seed_digest: C6ResidualDigest,
    joint_seed_digest: C6ResidualDigest,
    clear_plan_values: [Fp2; C6_SPARSE_PLAN_OPENINGS],
    rounds: Vec<[Fp2; C6_SPARSE_JOINT_SENT_VALUES]>,
}

impl C6ResidualSparseRationalJointLeafProof {
    pub fn bytes(&self) -> u64 {
        16 * (C6_SPARSE_PLAN_OPENINGS as u64
            + self.rounds.len() as u64 * C6_SPARSE_JOINT_SENT_VALUES as u64)
    }

    pub fn clear_plan_values(&self) -> &[Fp2; C6_SPARSE_PLAN_OPENINGS] {
        &self.clear_plan_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalJointOpeningValues {
    points: C6SparseRationalPackedOpeningPoints,
    response: [Fp2; C6_SPARSE_RESPONSE_OPENINGS],
    plan: [Fp2; C6_SPARSE_PLAN_OPENINGS],
}

impl C6SparseRationalJointOpeningValues {
    pub fn points(&self) -> &C6SparseRationalPackedOpeningPoints {
        &self.points
    }

    pub fn response(&self) -> &[Fp2; C6_SPARSE_RESPONSE_OPENINGS] {
        &self.response
    }

    pub fn plan(&self) -> &[Fp2; C6_SPARSE_PLAN_OPENINGS] {
        &self.plan
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SparseRationalJointTerminalRelation {
    relation_digest: C6ResidualDigest,
    points: C6SparseRationalPackedOpeningPoints,
    clear_plan_values: [Fp2; C6_SPARSE_PLAN_OPENINGS],
    clear_leaf_values: [[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS],
    leaf_coefficients: [[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS],
    response_coefficients: [Fp2; C6_SPARSE_RESPONSE_OPENINGS],
    lambda_mu_coefficient: Fp2,
    public_constant: Fp2,
    sumcheck_claim: Fp2,
    lane_batch: Fp2,
}

impl C6SparseRationalJointTerminalRelation {
    pub fn points(&self) -> &C6SparseRationalPackedOpeningPoints {
        &self.points
    }

    pub fn relation_digest(&self) -> C6ResidualDigest {
        self.relation_digest
    }

    pub fn clear_plan_values(&self) -> &[Fp2; C6_SPARSE_PLAN_OPENINGS] {
        &self.clear_plan_values
    }

    pub fn response_coefficients(&self) -> &[Fp2; C6_SPARSE_RESPONSE_OPENINGS] {
        &self.response_coefficients
    }

    pub fn leaf_coefficients(&self) -> &[[Fp2; 2]; C6_SPARSE_RATIONAL_SUBCHECKS] {
        &self.leaf_coefficients
    }

    pub fn lambda_mu_coefficient(&self) -> Fp2 {
        self.lambda_mu_coefficient
    }

    pub fn public_constant(&self) -> Fp2 {
        self.public_constant
    }

    pub fn sumcheck_claim(&self) -> Fp2 {
        self.sumcheck_claim
    }

    pub fn lane_batch(&self) -> Fp2 {
        self.lane_batch
    }

    pub fn clear_residual(&self, response: &[Fp2; C6_SPARSE_RESPONSE_OPENINGS]) -> Fp2 {
        let linearization = TerminalLinearization {
            leaf_coefficients: self.leaf_coefficients,
            response_coefficients: self.response_coefficients,
            lambda_mu_coefficient: self.lambda_mu_coefficient,
            public_constant: self.public_constant,
        };
        linearization.evaluate(&self.clear_leaf_values, response, self.lane_batch)
            - self.sumcheck_claim
    }
}

pub fn prove_c6_residual_sparse_rational_joint_leaf_reference(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    packed: &C6SparseRationalPackedOracleReference,
    gkr_seed: [u8; 32],
    gkr_proof: &C6ResidualSparseRationalGkrReferenceProof,
    joint_seed: [u8; 32],
) -> C6ResidualResult<(C6ResidualSparseRationalJointLeafProof, C6SparseRationalJointOpeningValues)>
{
    if packed.base_domain_log2 != canonical_base_domain_log2(operation_plan)? {
        return Err(C6ResidualError::new("C6SPR2 joint reduction base dimension is noncanonical"));
    }
    packed.validate_relation(relation)?;
    let Some(claims) = reduce_sparse_fraction_claims(relation, gkr_seed, gkr_proof)? else {
        return Err(C6ResidualError::new("C6SPR2 fraction proof does not reduce to valid claims"));
    };
    let dimension = usize::from(packed.base_domain_log2);
    let mut state = JointWitnessState::new(packed, relation)?;
    let mut stream = FpStream::domain_separated(joint_seed, C6_SPARSE_JOINT_STREAM_DOMAIN);
    let theta = stream.next_fp2();
    let mut claim = Fp2::ZERO;
    let mut point = Vec::with_capacity(dimension);
    let mut rounds = Vec::with_capacity(dimension);
    for round in 0..dimension {
        let evaluations = joint_round_evaluations(
            operation_plan,
            relation,
            &claims,
            theta,
            dimension,
            &point,
            &state,
        )?;
        if evaluations[0] + evaluations[1] != claim {
            return Err(C6ResidualError::new(
                "C6SPR2 joint leaf polynomial does not match its running sumcheck claim",
            ));
        }
        rounds.push(std::array::from_fn(|index| {
            if index == 0 {
                evaluations[0]
            } else {
                evaluations[index + 1]
            }
        }));
        let challenge = stream.next_fp2();
        claim = interpolate_degree_eight(&evaluations, challenge);
        state.fold(round, challenge);
        point.push(challenge);
    }
    let points = packed.opening_points(&point)?;
    let opening_values = C6SparseRationalJointOpeningValues {
        response: packed.evaluate_response_openings(&points)?,
        plan: packed.evaluate_plan_openings(&points)?,
        points,
    };
    let proof = C6ResidualSparseRationalJointLeafProof {
        relation_digest: relation.digest(),
        gkr_seed_digest: sparse_rational_gkr_seed_digest(gkr_seed),
        joint_seed_digest: joint_seed_digest(joint_seed),
        clear_plan_values: opening_values.plan,
        rounds,
    };
    let Some(terminal) = reduce_c6_residual_sparse_rational_joint_leaf_reference(
        operation_plan,
        relation,
        packed.base_domain_log2,
        packed.response_digest,
        packed.plan_digest,
        gkr_seed,
        gkr_proof,
        joint_seed,
        &proof,
    )?
    else {
        return Err(C6ResidualError::new("C6SPR2 honest joint leaf proof did not reduce"));
    };
    if terminal.points != opening_values.points
        || terminal.clear_plan_values != opening_values.plan
        || terminal.clear_residual(&opening_values.response) != Fp2::ZERO
    {
        return Err(C6ResidualError::new(
            "C6SPR2 joint terminal relation differs from its nine packed openings",
        ));
    }
    Ok((proof, opening_values))
}

#[allow(clippy::too_many_arguments)]
pub fn reduce_c6_residual_sparse_rational_joint_leaf_reference(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    base_domain_log2: u8,
    response_digest: C6ResidualDigest,
    plan_digest: C6ResidualDigest,
    gkr_seed: [u8; 32],
    gkr_proof: &C6ResidualSparseRationalGkrReferenceProof,
    joint_seed: [u8; 32],
    proof: &C6ResidualSparseRationalJointLeafProof,
) -> C6ResidualResult<Option<C6SparseRationalJointTerminalRelation>> {
    if base_domain_log2 != canonical_base_domain_log2(operation_plan)?
        || proof.relation_digest != relation.digest()
        || proof.gkr_seed_digest != sparse_rational_gkr_seed_digest(gkr_seed)
        || proof.joint_seed_digest != joint_seed_digest(joint_seed)
        || proof.rounds.len() != usize::from(base_domain_log2)
    {
        return Ok(None);
    }
    let Some(claims) = reduce_sparse_fraction_claims(relation, gkr_seed, gkr_proof)? else {
        return Ok(None);
    };
    let mut stream = FpStream::domain_separated(joint_seed, C6_SPARSE_JOINT_STREAM_DOMAIN);
    let theta = stream.next_fp2();
    let mut claim = Fp2::ZERO;
    let mut point = Vec::with_capacity(usize::from(base_domain_log2));
    for sent in &proof.rounds {
        let mut evaluations = [Fp2::ZERO; C6_SPARSE_JOINT_DEGREE + 1];
        evaluations[0] = sent[0];
        evaluations[1] = claim - sent[0];
        evaluations[2..].copy_from_slice(&sent[1..]);
        let challenge = stream.next_fp2();
        claim = interpolate_degree_eight(&evaluations, challenge);
        point.push(challenge);
    }
    let injection = crate::mle::eval_mle(&relation.combined_injection, &point);
    let linearization = terminal_linearization(
        operation_plan,
        relation.sparse_challenges,
        &fraction_leaf_points(&claims),
        theta,
        &point,
        &proof.clear_plan_values,
        injection,
    )?;
    let points = C6SparseRationalPackedOpeningPoints::new(
        base_domain_log2,
        response_digest,
        plan_digest,
        &point,
    )?;
    Ok(Some(C6SparseRationalJointTerminalRelation {
        relation_digest: relation.digest(),
        points,
        clear_plan_values: proof.clear_plan_values,
        clear_leaf_values: fraction_leaf_values(&claims),
        leaf_coefficients: linearization.leaf_coefficients,
        response_coefficients: linearization.response_coefficients,
        lambda_mu_coefficient: linearization.lambda_mu_coefficient,
        public_constant: linearization.public_constant,
        sumcheck_claim: claim,
        lane_batch: relation.sparse_challenges.lane_batch,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
    operation_plan: &C6InstalledOperationPlan,
    relation: &C6ResidualSparseRationalRelationReference,
    packed: &C6SparseRationalPackedOracleReference,
    gkr_seed: [u8; 32],
    gkr_proof: &C6ResidualSparseRationalGkrReferenceProof,
    joint_seed: [u8; 32],
    proof: &C6ResidualSparseRationalJointLeafProof,
    openings: &C6SparseRationalJointOpeningValues,
) -> C6ResidualResult<bool> {
    let Some(terminal) = reduce_c6_residual_sparse_rational_joint_leaf_reference(
        operation_plan,
        relation,
        packed.base_domain_log2,
        packed.response_digest,
        packed.plan_digest,
        gkr_seed,
        gkr_proof,
        joint_seed,
        proof,
    )?
    else {
        return Ok(false);
    };
    Ok(openings.points == terminal.points
        && openings.plan == terminal.clear_plan_values
        && terminal.clear_residual(&openings.response) == Fp2::ZERO)
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
    fn joint_leaf_reduction_closes_clear_and_blind_exact_openings() {
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
        let gkr_seed = [0x61; 32];
        let (gkr_proof, _) = prove_c6_residual_sparse_rational_gkr_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
            gkr_seed,
        )
        .unwrap();
        let joint_seed = [0x6a; 32];
        let (mut proof, openings) = prove_c6_residual_sparse_rational_joint_leaf_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
        )
        .unwrap();
        assert_eq!(
            proof.bytes(),
            16 * (C6_SPARSE_PLAN_OPENINGS as u64
                + u64::from(packed.base_domain_log2()) * C6_SPARSE_JOINT_SENT_VALUES as u64),
        );
        assert!(verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
            &openings,
        )
        .unwrap());
        let terminal = reduce_c6_residual_sparse_rational_joint_leaf_reference(
            direct.operation_plan(),
            &relation,
            packed.base_domain_log2(),
            packed.response_digest(),
            packed.plan_digest(),
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
        )
        .unwrap()
        .unwrap();
        assert_eq!(terminal.points(), openings.points());
        assert_eq!(terminal.relation_digest(), relation.digest());
        assert_eq!(terminal.clear_plan_values(), openings.plan());
        assert_eq!(terminal.clear_residual(openings.response()), Fp2::ZERO);
        assert_ne!(terminal.lambda_mu_coefficient(), Fp2::ZERO);
        assert!(terminal.response_coefficients().iter().any(|value| *value != Fp2::ZERO));

        let correlation_seed = [0x74; 32];
        let transcript_seed = [0x75; 32];
        let delta = Fp2::new(fp(331), fp(337));
        let mut prover_stream = CorrelationStream::new(correlation_seed);
        let mut prover_doms = Doms::new(30_000);
        let mut prover_transcript = Transcript::new(transcript_seed);
        let mut prover_products = Vec::new();
        let mut prover_zeros = Vec::new();
        let (blind_gkr_proof, blind_leaf_claims) =
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
        let mut verifier = VerifierCtx::new(correlation_seed, delta);
        let mut verifier_doms = Doms::new(30_000);
        let mut verifier_transcript = Transcript::new(transcript_seed);
        let mut verifier_products = Vec::new();
        let mut verifier_zeros = Vec::new();
        let blind_leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            &public_relation,
            &blind_gkr_proof,
            &mut verifier,
            &mut verifier_doms,
            &mut verifier_transcript,
            &mut verifier_products,
            &mut verifier_zeros,
        )
        .unwrap()
        .unwrap();
        let mut compact_verifier = VerifierCtx::new(correlation_seed, delta);
        let mut compact_doms = Doms::new(30_000);
        let mut compact_transcript = Transcript::new(transcript_seed);
        let mut compact_products = Vec::new();
        let mut compact_zeros = Vec::new();
        let compact_leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_compact(
            direct.operation_plan().artifact_digest(),
            direct.operation_plan().topology(),
            &terminal_metadata,
            direct.relation(),
            &public_relation,
            &blind_gkr_proof,
            &mut compact_verifier,
            &mut compact_doms,
            &mut compact_transcript,
            &mut compact_products,
            &mut compact_zeros,
        )
        .unwrap()
        .unwrap();
        assert_eq!(compact_leaf_keys, blind_leaf_keys);
        assert_eq!(compact_products, verifier_products);
        assert_eq!(compact_zeros, verifier_zeros);
        assert_eq!(compact_doms.cursor(), verifier_doms.cursor());
        assert_eq!(compact_transcript.ledger(), verifier_transcript.ledger());
        let (blind_rounds, prover_terminal) =
            prove_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
                direct.operation_plan(),
                &relation,
                &public_relation,
                &packed,
                &blind_leaf_claims,
                &mut prover_stream,
                &mut prover_doms,
                &mut prover_transcript,
            )
            .unwrap();
        let verifier_terminal =
            verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
                direct.operation_plan(),
                &terminal_metadata,
                direct.relation(),
                &public_relation,
                packed.base_domain_log2(),
                packed.response_digest(),
                packed.plan_digest(),
                &blind_leaf_keys,
                &blind_rounds,
                &mut verifier,
                &mut verifier_doms,
                &mut verifier_transcript,
            )
            .unwrap()
            .unwrap();
        let compact_terminal = verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_compact(
            direct.operation_plan().artifact_digest(),
            direct.operation_plan().topology(),
            &terminal_metadata,
            direct.relation(),
            &public_relation,
            packed.base_domain_log2(),
            packed.response_digest(),
            packed.plan_digest(),
            &compact_leaf_keys,
            &blind_rounds,
            &mut compact_verifier,
            &mut compact_doms,
            &mut compact_transcript,
        )
        .unwrap()
        .unwrap();
        assert_eq!(prover_terminal.points(), verifier_terminal.points());
        assert_eq!(compact_terminal.points(), verifier_terminal.points());
        assert_eq!(compact_products, verifier_products);
        assert_eq!(compact_zeros, verifier_zeros);
        assert_eq!(compact_doms.cursor(), verifier_doms.cursor());
        assert_eq!(compact_transcript.ledger(), verifier_transcript.ledger());
        assert_eq!(
            blind_rounds.bytes(),
            16 * (C6_SPARSE_PLAN_OPENINGS as u64
                + u64::from(packed.base_domain_log2()) * C6_SPARSE_JOINT_SENT_VALUES as u64),
        );
        let response_values = packed.evaluate_response_openings(prover_terminal.points()).unwrap();
        let plan_values = packed.evaluate_plan_openings(prover_terminal.points()).unwrap();
        let target_domain = prover_doms.take(1);
        assert_eq!(target_domain, verifier_doms.take(1));
        let target_values = response_values.iter().chain(&plan_values).copied().collect::<Vec<_>>();
        let target_masks = prover_stream.draw_fulls(target_domain, target_values.len());
        prover_stream.record_c6_fullfield_plaintexts(target_domain, &target_values).unwrap();
        let target_corrections = target_values
            .iter()
            .zip(&target_masks)
            .map(|(&value, mask)| value - mask.x)
            .collect::<Vec<_>>();
        prover_transcript.append("c6_sparse_joint_test_pcs_targets", 16 * 9);
        verifier_transcript.append("c6_sparse_joint_test_pcs_targets", 16 * 9);
        let target_keys = verifier.correct_full_verifier_keys(target_domain, &target_corrections);
        let response_targets: [ProverAuthed; C6_SPARSE_RESPONSE_OPENINGS] = target_masks
            [..C6_SPARSE_RESPONSE_OPENINGS]
            .iter()
            .zip(response_values)
            .map(|(mask, value)| mask.authenticate(value))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let plan_targets: [ProverAuthed; C6_SPARSE_PLAN_OPENINGS] = target_masks
            [C6_SPARSE_RESPONSE_OPENINGS..]
            .iter()
            .zip(plan_values)
            .map(|(mask, value)| mask.authenticate(value))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let response_keys: [VerifierKey; C6_SPARSE_RESPONSE_OPENINGS] =
            target_keys[..C6_SPARSE_RESPONSE_OPENINGS].try_into().unwrap();
        let plan_keys: [VerifierKey; C6_SPARSE_PLAN_OPENINGS] =
            target_keys[C6_SPARSE_RESPONSE_OPENINGS..].try_into().unwrap();
        let products_before_terminal = prover_products.len();
        let zeros_before_terminal = prover_zeros.len();
        let blind_terminal = finish_c6_residual_sparse_rational_joint_leaf_blind_prover(
            prover_terminal,
            &response_targets,
            &plan_targets,
            &mut prover_stream,
            &mut prover_doms,
            &mut prover_transcript,
            &mut prover_products,
            &mut prover_zeros,
        )
        .unwrap();
        finish_c6_residual_sparse_rational_joint_leaf_blind_verifier(
            verifier_terminal,
            &response_keys,
            &plan_keys,
            &blind_terminal,
            &mut verifier,
            &mut verifier_doms,
            &mut verifier_transcript,
            &mut verifier_products,
            &mut verifier_zeros,
        )
        .unwrap();
        assert_eq!(blind_terminal.bytes(), 16);
        assert_eq!(prover_products.len(), products_before_terminal + 1);
        assert_eq!(prover_zeros.len(), zeros_before_terminal + 4);
        assert_eq!(prover_products.len(), verifier_products.len());
        assert_eq!(prover_zeros.len(), verifier_zeros.len());
        assert_eq!(prover_doms.cursor(), verifier_doms.cursor());
        let product_challenge = prover_transcript.challenge_fp2();
        assert_eq!(product_challenge, verifier_transcript.challenge_fp2());
        let product_mask = prover_stream.draw_product_mask(40_000, prover_products.len());
        let product_mask_key =
            verifier.expand_product_mask_verifier_key(40_000, verifier_products.len());
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
            40_001,
            &mut prover_transcript,
        ));
        let mut changed_terminal_proof = blind_terminal.clone();
        changed_terminal_proof.product_correction += Fp2::ONE;
        let mut changed_verifier = VerifierCtx::new(correlation_seed, delta);
        let mut changed_doms = Doms::new(30_000);
        let mut changed_transcript = Transcript::new(transcript_seed);
        let mut changed_products = Vec::new();
        let mut changed_zeros = Vec::new();
        let changed_leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            &public_relation,
            &blind_gkr_proof,
            &mut changed_verifier,
            &mut changed_doms,
            &mut changed_transcript,
            &mut changed_products,
            &mut changed_zeros,
        )
        .unwrap()
        .unwrap();
        let changed_terminal =
            verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
                direct.operation_plan(),
                &terminal_metadata,
                direct.relation(),
                &public_relation,
                packed.base_domain_log2(),
                packed.response_digest(),
                packed.plan_digest(),
                &changed_leaf_keys,
                &blind_rounds,
                &mut changed_verifier,
                &mut changed_doms,
                &mut changed_transcript,
            )
            .unwrap()
            .unwrap();
        assert_eq!(changed_doms.take(1), target_domain);
        changed_transcript.append("c6_sparse_joint_test_pcs_targets", 16 * 9);
        let changed_target_keys =
            changed_verifier.correct_full_verifier_keys(target_domain, &target_corrections);
        let changed_response_keys: [VerifierKey; C6_SPARSE_RESPONSE_OPENINGS] =
            changed_target_keys[..C6_SPARSE_RESPONSE_OPENINGS].try_into().unwrap();
        let changed_plan_keys: [VerifierKey; C6_SPARSE_PLAN_OPENINGS] =
            changed_target_keys[C6_SPARSE_RESPONSE_OPENINGS..].try_into().unwrap();
        finish_c6_residual_sparse_rational_joint_leaf_blind_verifier(
            changed_terminal,
            &changed_response_keys,
            &changed_plan_keys,
            &changed_terminal_proof,
            &mut changed_verifier,
            &mut changed_doms,
            &mut changed_transcript,
            &mut changed_products,
            &mut changed_zeros,
        )
        .unwrap();
        assert_eq!(product_challenge, changed_transcript.challenge_fp2());
        let changed_product_mask_key =
            changed_verifier.expand_product_mask_verifier_key(40_000, changed_products.len());
        assert!(!prod_batch_verify(
            &changed_products,
            changed_product_mask_key,
            delta,
            product_challenge,
            &product_proof,
        ));

        let claims =
            reduce_sparse_fraction_claims(&relation, gkr_seed, &gkr_proof).unwrap().unwrap();
        let leaves = materialize_sparse_rational_leaves(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
        )
        .unwrap();
        let base_rows = 1usize << packed.base_domain_log2();
        let boundary = 2 * base_rows;
        for (subcheck, expected) in leaves.iter().enumerate() {
            for row in 0..expected.numerator.len() {
                let point = (0..packed.base_domain_log2())
                    .map(|bit| if (row >> bit) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO })
                    .collect::<Vec<_>>();
                let response = [
                    packed.response_values[row],
                    packed.response_values[base_rows + row],
                    packed.response_values[3 * base_rows + row],
                    packed.response_values[boundary + (row & (base_rows / 2 - 1))],
                    packed.response_values[boundary + base_rows / 2 + (row & (base_rows / 4 - 1))],
                    packed.response_values
                        [boundary + 3 * base_rows / 4 + (row & (base_rows / 4 - 1))],
                ];
                let plan = [
                    packed.plan_values[row],
                    packed.plan_values[base_rows + row],
                    packed.plan_values[2 * base_rows + row],
                ];
                let injection = relation.combined_injection.get(row).copied().unwrap_or(Fp2::ZERO);
                let actual = terminal_leaf_values(
                    direct.operation_plan(),
                    &relation,
                    &claims,
                    &point,
                    &response,
                    &plan,
                    injection,
                )
                .unwrap();
                assert_eq!(actual[subcheck][0], expected.numerator[row]);
                assert_eq!(actual[subcheck][1], expected.denominator[row]);
            }
        }

        let common_point = terminal.points.input_point.as_slice();
        let injection = crate::mle::eval_mle(&relation.combined_injection, common_point);
        let direct_terminal = terminal_leaf_values(
            direct.operation_plan(),
            &relation,
            &claims,
            common_point,
            openings.response(),
            openings.plan(),
            injection,
        )
        .unwrap();
        let mut stream = FpStream::domain_separated(joint_seed, C6_SPARSE_JOINT_STREAM_DOMAIN);
        let theta = stream.next_fp2();
        let mut theta_power = Fp2::ONE;
        let mut direct_batched = Fp2::ZERO;
        for (index, values) in direct_terminal.iter().enumerate() {
            let equality = eq_lifted(&claims[index].point, common_point).unwrap();
            direct_batched += equality * theta_power * (values[0] - claims[index].p);
            theta_power = theta_power * theta;
            direct_batched += equality * theta_power * (values[1] - claims[index].q);
            theta_power = theta_power * theta;
        }
        assert_eq!(direct_batched, terminal.sumcheck_claim());

        proof.rounds[0][0] += Fp2::ONE;
        assert!(!verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
            &openings,
        )
        .unwrap());
        proof.rounds[0][0] = proof.rounds[0][0] - Fp2::ONE;

        proof.clear_plan_values[0] += Fp2::ONE;
        assert!(!verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
            &openings,
        )
        .unwrap());
        proof.clear_plan_values[0] = proof.clear_plan_values[0] - Fp2::ONE;

        let mut changed_response = openings.clone();
        let changed_index =
            terminal.response_coefficients().iter().position(|value| *value != Fp2::ZERO).unwrap();
        changed_response.response[changed_index] += Fp2::ONE;
        assert!(!verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
            &changed_response,
        )
        .unwrap());

        let mut changed_plan = openings.clone();
        changed_plan.plan[0] += Fp2::ONE;
        assert!(!verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            joint_seed,
            &proof,
            &changed_plan,
        )
        .unwrap());
        assert!(!verify_c6_residual_sparse_rational_joint_leaf_clear_reference(
            direct.operation_plan(),
            &relation,
            &packed,
            gkr_seed,
            &gkr_proof,
            [0x6b; 32],
            &proof,
            &openings,
        )
        .unwrap());
    }
}

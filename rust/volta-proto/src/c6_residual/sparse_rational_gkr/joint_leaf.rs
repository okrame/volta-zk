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

fn canonical_base_domain_log2(operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<u8> {
    let topology = operation_plan.topology();
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
    relation: &C6ResidualSparseRationalRelationReference,
    claims: &[FracLeafClaims; C6_SPARSE_RATIONAL_SUBCHECKS],
    theta: Fp2,
    base_point: &[Fp2],
    plan: &[Fp2; C6_SPARSE_PLAN_OPENINGS],
    injection: Fp2,
) -> C6ResidualResult<TerminalLinearization> {
    let topology = operation_plan.topology();
    let node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 node count exceeds usize"))?;
    let scalar_count = usize::try_from(topology.scalar_input_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 scalar count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6SPR2 source count exceeds usize"))?;
    if claims.iter().any(|claim| claim.point.len() > base_point.len()) {
        return Err(C6ResidualError::new(
            "C6SPR2 reduced leaf point exceeds the common terminal point",
        ));
    }

    let mut powers = [Fp2::ONE; 2 * C6_SPARSE_RATIONAL_SUBCHECKS];
    for index in 1..powers.len() {
        powers[index] = powers[index - 1] * theta;
    }
    let eq: [Fp2; C6_SPARSE_RATIONAL_SUBCHECKS] = claims
        .iter()
        .map(|claim| eq_lifted(&claim.point, base_point))
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
    let gamma = relation.sparse_challenges.recurrence;
    let tau = relation.sparse_challenges.runtime_gather;
    let delta = relation.sparse_challenges.source_gather;
    let zeta = relation.sparse_challenges.lane_batch;
    let anchor_p = weighted(C6SparseRationalSubcheck::RecurrenceAnchor, true);
    response_coefficients[0] += anchor_p;
    response_coefficients[1] += anchor_p * zeta;
    public_constant = public_constant - anchor_p * injection;
    public_constant += weighted(C6SparseRationalSubcheck::RecurrenceAnchor, false)
        * range_denominator_mle(
            node_count,
            gamma,
            &claims[C6SparseRationalSubcheck::RecurrenceAnchor.index()].point,
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
            &claims[C6SparseRationalSubcheck::RuntimeTable.index()].point,
            base_point,
        )?;

    let source_boundary = weighted(C6SparseRationalSubcheck::SourceBoundary, true);
    response_coefficients[4] += source_boundary;
    response_coefficients[5] += source_boundary * zeta;
    public_constant += weighted(C6SparseRationalSubcheck::SourceBoundary, false)
        * range_denominator_mle(
            source_count,
            delta,
            &claims[C6SparseRationalSubcheck::SourceBoundary.index()].point,
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
    let suffix_rows = 1usize << (dimension - round - 1);
    let mut evaluations = [Fp2::ZERO; C6_SPARSE_JOINT_DEGREE + 1];
    for (integer, evaluation) in evaluations.iter_mut().enumerate() {
        let value = Fp2::from_base(Fp::new(integer as u64));
        for suffix in 0..suffix_rows {
            let point = point_with_suffix(dimension, prefix, value, suffix);
            let (response, plan, injection) = state.evaluate(round, value, suffix);
            let linearization = terminal_linearization(
                operation_plan,
                relation,
                claims,
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

fn interpolate_degree_eight(evaluations: &[Fp2; C6_SPARSE_JOINT_DEGREE + 1], point: Fp2) -> Fp2 {
    let mut result = Fp2::ZERO;
    for (index, &evaluation) in evaluations.iter().enumerate() {
        let mut numerator = Fp2::ONE;
        let mut denominator = Fp::ONE;
        for other in 0..=C6_SPARSE_JOINT_DEGREE {
            if other == index {
                continue;
            }
            numerator = numerator * (point - Fp2::from_base(Fp::new(other as u64)));
            denominator = denominator * Fp::from_i64(index as i64 - other as i64);
        }
        result += evaluation * numerator.mul_base(denominator.inv());
    }
    result
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
        relation,
        &claims,
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
    use volta_mac::C6TraceSourceManifest;

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(fp(value))
    }

    #[test]
    fn joint_leaf_reduction_closes_only_through_the_exact_nine_openings() {
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

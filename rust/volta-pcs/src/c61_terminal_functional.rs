//! Typed C6.1 native-chain statements for the exact C6TFR1 relation.
//!
//! These types deliberately stop before a native backend implementation.
//! Public commitments, ordered points and compiler bindings are hashed into
//! one role-independent statement digest.  Authenticated target shares stay
//! in the provider statement and target keys stay in the verifier statement;
//! neither role-local vector is serialized into, or hashed by, the public
//! statement.

use std::fmt;

use volta_field::Fp2;
use volta_mac::{ProverAuthed, Transcript, VerifierKey};

use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent, C61_TERMINAL_CLAIMS};
use crate::c6_residual_sumcheck::{C6_RESIDUAL_AUXILIARY_ROUNDS, C6_RESIDUAL_LEAF_ROUNDS};

pub const C61_MODEL_OPENING_TARGETS: usize = 96;
pub const C61_EMBEDDING_OPENING_TARGETS: usize = 6;
pub const C61_COMPILER_TERMINAL_TARGETS: usize = C61_TERMINAL_CLAIMS;
pub const C61_TERMINAL_FUNCTIONAL_RELATION_LOG2: u8 = 28;
pub const C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS: usize = 2;
pub const C61_SPARSE_RATIONAL_INPUT_LOG2: u8 = 25;
pub const C61_SPARSE_RATIONAL_PACKED_LOG2: u8 = 27;
pub const C61_SPARSE_RATIONAL_RESPONSE_OPENINGS: usize = 6;
pub const C61_SPARSE_RATIONAL_PLAN_OPENINGS: usize = 3;

const PUBLIC_STATEMENT_DOMAIN: &str = "volta-zk/c6.1/typed-native-chain-statement/v1";
const COMMITTED_OPENINGS_DOMAIN: &str = "volta-zk/c6.1/typed-committed-openings/v1";
const COMPILER_RELATION_DOMAIN: &str = "volta-zk/c6.1/typed-terminal-functional-compiler/v1";
const TERMINAL_CLAIMS_DOMAIN: &str = "volta-zk/c6.1/ordered-terminal-claims/v1";
const SPARSE_RESPONSE_LAYOUT_DOMAIN: &str = "volta-zk/c6.1/sparse-response-layout/v1";
const SPARSE_PLAN_LAYOUT_DOMAIN: &str = "volta-zk/c6.1/sparse-plan-layout/v1";
const SPARSE_ORACLES_DOMAIN: &str = "volta-zk/c6.1/sparse-compiler-oracles/v1";
const SPARSE_OPENING_STATEMENT_DOMAIN: &str = "volta-zk/c6.1/sparse-compiler-opening-statement/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalStatementError(String);

impl C61TerminalFunctionalStatementError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61TerminalFunctionalStatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61TerminalFunctionalStatementError {}

type Result<T> = std::result::Result<T, C61TerminalFunctionalStatementError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61NativeCommitmentDescriptor {
    pub parameter_digest: [u8; 32],
    pub commitment_root: [u8; 32],
    pub polynomial_domain_log2: u8,
}

impl C61NativeCommitmentDescriptor {
    fn validate(self) -> Result<()> {
        if self.parameter_digest == [0; 32] || self.commitment_root == [0; 32] {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native commitment contains a zero digest",
            ));
        }
        if self.polynomial_domain_log2 == 0 || self.polynomial_domain_log2 > 63 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native commitment dimension is out of range",
            ));
        }
        Ok(())
    }
}

fn sparse_layout_digest(domain: &'static str, blocks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&[C61_SPARSE_RATIONAL_INPUT_LOG2, C61_SPARSE_RATIONAL_PACKED_LOG2]);
    hasher.update(&(blocks.len() as u64).to_le_bytes());
    for (ordinal, block) in blocks.iter().enumerate() {
        hasher.update(&(ordinal as u64).to_le_bytes());
        hasher.update(&(block.len() as u64).to_le_bytes());
        hasher.update(block);
    }
    *hasher.finalize().as_bytes()
}

pub fn c61_sparse_response_layout_digest() -> [u8; 32] {
    sparse_layout_digest(
        SPARSE_RESPONSE_LAYOUT_DOMAIN,
        &[b"lambda_0_D25", b"lambda_1_D25", b"runtime_D24_g0_D23_g1_D23", b"mu_D25"],
    )
}

pub fn c61_sparse_plan_layout_digest() -> [u8; 32] {
    sparse_layout_digest(
        SPARSE_PLAN_LAYOUT_DOMAIN,
        &[b"opcode_D25", b"lhs_D25", b"rhs_D25", b"zero_D25"],
    )
}

/// The two commitment roots fixed before C6SPR2's lane/rational challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOracles {
    pub response: C61NativeCommitmentDescriptor,
    pub plan: C61NativeCommitmentDescriptor,
    pub response_layout_digest: [u8; 32],
    pub plan_layout_digest: [u8; 32],
}

impl C61SparseRationalCompilerOracles {
    pub fn new(
        response: C61NativeCommitmentDescriptor,
        plan: C61NativeCommitmentDescriptor,
    ) -> Result<Self> {
        let oracles = Self {
            response,
            plan,
            response_layout_digest: c61_sparse_response_layout_digest(),
            plan_layout_digest: c61_sparse_plan_layout_digest(),
        };
        oracles.validate()?;
        Ok(oracles)
    }

    pub fn validate(&self) -> Result<()> {
        self.response.validate()?;
        self.plan.validate()?;
        if self.response.polynomial_domain_log2 != C61_SPARSE_RATIONAL_PACKED_LOG2
            || self.plan.polynomial_domain_log2 != C61_SPARSE_RATIONAL_PACKED_LOG2
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 response and plan commitments must both use D27",
            ));
        }
        if self.response_layout_digest != c61_sparse_response_layout_digest()
            || self.plan_layout_digest != c61_sparse_plan_layout_digest()
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 compiler oracle layout digest is noncanonical",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(SPARSE_ORACLES_DOMAIN);
        for descriptor in [self.response, self.plan] {
            hasher.update(&descriptor.parameter_digest);
            hasher.update(&descriptor.commitment_root);
            hasher.update(&[descriptor.polynomial_domain_log2]);
        }
        hasher.update(&self.response_layout_digest);
        hasher.update(&self.plan_layout_digest);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Nine ordered points derived after the joint GKR leaf reduction.  The
/// order is response `(lambda_0, lambda_1, mu, runtime, g_0, g_1)` followed
/// by fixed plan `(opcode, lhs, rhs)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOpeningPoints {
    input_point: Vec<Fp2>,
    response: [Vec<Fp2>; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    plan: [Vec<Fp2>; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    digest: [u8; 32],
}

impl C61SparseRationalCompilerOpeningPoints {
    pub fn new(input_point: &[Fp2]) -> Result<Self> {
        if input_point.len() != usize::from(C61_SPARSE_RATIONAL_INPUT_LOG2) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 GKR input point must be D25",
            ));
        }
        let dimension = input_point.len();
        let append = |prefix: &[Fp2], suffix: &[Fp2]| {
            prefix.iter().chain(suffix).copied().collect::<Vec<_>>()
        };
        let response = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ONE]),
            append(&input_point[..dimension - 1], &[Fp2::ZERO, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..dimension - 2], &[Fp2::ZERO, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..dimension - 2], &[Fp2::ONE, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
        ];
        let plan = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ZERO, Fp2::ONE]),
        ];
        let mut points =
            Self { input_point: input_point.to_vec(), response, plan, digest: [0; 32] };
        points.digest = points.recompute_digest();
        Ok(points)
    }

    pub fn input_point(&self) -> &[Fp2] {
        &self.input_point
    }

    pub fn response(&self) -> &[Vec<Fp2>; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] {
        &self.response
    }

    pub fn plan(&self) -> &[Vec<Fp2>; C61_SPARSE_RATIONAL_PLAN_OPENINGS] {
        &self.plan
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if *self != Self::new(&self.input_point)? {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 compiler opening points are noncanonical",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.1/sparse-compiler-opening-points/v1");
        for (role, points) in [(0u8, self.response.as_slice()), (1u8, self.plan.as_slice())] {
            hasher.update(&[role]);
            hasher.update(&(points.len() as u64).to_le_bytes());
            for (ordinal, point) in points.iter().enumerate() {
                hasher.update(&(ordinal as u64).to_le_bytes());
                hash_point(&mut hasher, point);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOpeningStatement {
    pub compiler_statement_digest: [u8; 32],
    pub sparse_relation_digest: [u8; 32],
    pub gkr_transcript_digest: [u8; 32],
    pub oracles: C61SparseRationalCompilerOracles,
    pub points: C61SparseRationalCompilerOpeningPoints,
    digest: [u8; 32],
}

impl C61SparseRationalCompilerOpeningStatement {
    pub fn new(
        compiler_statement_digest: [u8; 32],
        sparse_relation_digest: [u8; 32],
        gkr_transcript_digest: [u8; 32],
        oracles: C61SparseRationalCompilerOracles,
        input_point: &[Fp2],
    ) -> Result<Self> {
        if [compiler_statement_digest, sparse_relation_digest, gkr_transcript_digest]
            .contains(&[0; 32])
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 opening statement contains a zero binding digest",
            ));
        }
        oracles.validate()?;
        let points = C61SparseRationalCompilerOpeningPoints::new(input_point)?;
        let mut statement = Self {
            compiler_statement_digest,
            sparse_relation_digest,
            gkr_transcript_digest,
            oracles,
            points,
            digest: [0; 32],
        };
        statement.digest = statement.recompute_digest()?;
        Ok(statement)
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn validate(&self) -> Result<()> {
        self.oracles.validate()?;
        self.points.validate()?;
        if [self.compiler_statement_digest, self.sparse_relation_digest, self.gkr_transcript_digest]
            .contains(&[0; 32])
            || self.digest != self.recompute_digest()?
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 opening statement binding is inconsistent",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new_derive_key(SPARSE_OPENING_STATEMENT_DOMAIN);
        hasher.update(&self.compiler_statement_digest);
        hasher.update(&self.sparse_relation_digest);
        hasher.update(&self.gkr_transcript_digest);
        hasher.update(&self.oracles.digest()?);
        hasher.update(&self.points.digest());
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalProverOpeningStatement {
    pub public: C61SparseRationalCompilerOpeningStatement,
    pub response_targets: [ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    pub plan_targets: [ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
}

impl C61SparseRationalProverOpeningStatement {
    pub fn new(
        public: C61SparseRationalCompilerOpeningStatement,
        response_targets: [ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
        plan_targets: [ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    ) -> Result<Self> {
        public.validate()?;
        Ok(Self { public, response_targets, plan_targets })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalVerifierOpeningStatement {
    pub public: C61SparseRationalCompilerOpeningStatement,
    pub response_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    pub plan_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
}

impl C61SparseRationalVerifierOpeningStatement {
    pub fn new(
        public: C61SparseRationalCompilerOpeningStatement,
        response_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
        plan_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    ) -> Result<Self> {
        public.validate()?;
        Ok(Self { public, response_target_keys, plan_target_keys })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61CommittedOpeningStatement {
    pub commitment: C61NativeCommitmentDescriptor,
    pub ordered_points: Vec<Vec<Fp2>>,
}

impl C61CommittedOpeningStatement {
    fn validate(&self, expected_targets: usize) -> Result<()> {
        self.commitment.validate()?;
        if self.ordered_points.len() != expected_targets {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 committed-opening statement has the wrong target census",
            ));
        }
        let point_dimension = usize::from(self.commitment.polynomial_domain_log2);
        if self.ordered_points.iter().any(|point| point.len() != point_dimension) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 committed-opening statement has a malformed point",
            ));
        }
        Ok(())
    }

    fn digest(&self, component: C61NativeComponent) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(COMMITTED_OPENINGS_DOMAIN);
        hasher.update(&(component as u16).to_le_bytes());
        hasher.update(&self.commitment.parameter_digest);
        hasher.update(&self.commitment.commitment_root);
        hasher.update(&[self.commitment.polynomial_domain_log2]);
        hasher.update(&(self.ordered_points.len() as u64).to_le_bytes());
        for (ordinal, point) in self.ordered_points.iter().enumerate() {
            hasher.update(&(ordinal as u64).to_le_bytes());
            hash_point(&mut hasher, point);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Complete public input of each of the two compiler chains.  The two chains
/// use independent native-proof randomness/MAC coordinates but bind the same
/// exact two-repetition C6TFR1 relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalCompilerBinding {
    pub operation_plan_digest: [u8; 32],
    pub operation_topology_digest: [u8; 32],
    pub terminal_metadata_digest: [u8; 32],
    pub extraction_map_digest: [u8; 32],
    pub runtime_root: [u8; 32],
    pub residual_manifest_digest: [u8; 32],
    pub residual_public_claims_digest: [u8; 32],
    pub relation_challenges_digest: [u8; 32],
    pub sparse_oracles: C61SparseRationalCompilerOracles,
    pub leaf_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub auxiliary_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    pub output_beta: Fp2,
    pub relation_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalCompilerStatement {
    pub operation_plan_digest: [u8; 32],
    pub operation_topology_digest: [u8; 32],
    pub terminal_metadata_digest: [u8; 32],
    pub extraction_map_digest: [u8; 32],
    pub runtime_root: [u8; 32],
    pub residual_manifest_digest: [u8; 32],
    pub residual_public_claims_digest: [u8; 32],
    pub relation_challenges_digest: [u8; 32],
    pub sparse_oracles: C61SparseRationalCompilerOracles,
    pub leaf_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub auxiliary_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    pub terminal_claims_digest: [u8; 32],
    pub output_beta: Fp2,
    pub relation_root: [u8; 32],
    pub functional_fold: Fp2,
}

impl C61TerminalFunctionalCompilerStatement {
    pub fn new(binding: C61TerminalFunctionalCompilerBinding) -> Result<Self> {
        let C61TerminalFunctionalCompilerBinding {
            operation_plan_digest,
            operation_topology_digest,
            terminal_metadata_digest,
            extraction_map_digest,
            runtime_root,
            residual_manifest_digest,
            residual_public_claims_digest,
            relation_challenges_digest,
            sparse_oracles,
            leaf_points,
            auxiliary_points,
            terminal_claims,
            output_beta,
            relation_root,
        } = binding;
        let terminal_claims_digest = terminal_claims_digest(&terminal_claims);
        let functional_fold = fold_terminal_claims(&terminal_claims, output_beta);
        let statement = Self {
            operation_plan_digest,
            operation_topology_digest,
            terminal_metadata_digest,
            extraction_map_digest,
            runtime_root,
            residual_manifest_digest,
            residual_public_claims_digest,
            relation_challenges_digest,
            sparse_oracles,
            leaf_points,
            auxiliary_points,
            terminal_claims,
            terminal_claims_digest,
            output_beta,
            relation_root,
            functional_fold,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn validate(&self) -> Result<()> {
        let required_digests = [
            self.operation_plan_digest,
            self.operation_topology_digest,
            self.terminal_metadata_digest,
            self.extraction_map_digest,
            self.runtime_root,
            self.residual_manifest_digest,
            self.residual_public_claims_digest,
            self.relation_challenges_digest,
            self.relation_root,
        ];
        if required_digests.contains(&[0; 32]) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement contains a zero binding digest",
            ));
        }
        self.sparse_oracles.validate()?;
        if self.leaf_points.iter().any(|point| point.len() != C6_RESIDUAL_LEAF_ROUNDS) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement has a malformed leaf point",
            ));
        }
        if self.auxiliary_points.iter().any(|point| point.len() != C6_RESIDUAL_AUXILIARY_ROUNDS) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement has a malformed auxiliary point",
            ));
        }
        if self.terminal_claims_digest != terminal_claims_digest(&self.terminal_claims) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler terminal digest is inconsistent",
            ));
        }
        if self.functional_fold != fold_terminal_claims(&self.terminal_claims, self.output_beta) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler functional fold is inconsistent",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(COMPILER_RELATION_DOMAIN);
        hasher.update(&[C61_TERMINAL_FUNCTIONAL_RELATION_LOG2]);
        for digest in [
            self.operation_plan_digest,
            self.operation_topology_digest,
            self.terminal_metadata_digest,
            self.extraction_map_digest,
            self.runtime_root,
            self.residual_manifest_digest,
            self.residual_public_claims_digest,
            self.relation_challenges_digest,
        ] {
            hasher.update(&digest);
        }
        hasher.update(&self.sparse_oracles.digest()?);
        for (repetition, point) in self.leaf_points.iter().enumerate() {
            hasher.update(&[repetition as u8, 0]);
            hash_point(&mut hasher, point);
        }
        for (repetition, point) in self.auxiliary_points.iter().enumerate() {
            hasher.update(&[repetition as u8, 1]);
            hash_point(&mut hasher, point);
        }
        hasher.update(&self.terminal_claims_digest);
        hash_fp2(&mut hasher, self.output_beta);
        hasher.update(&self.relation_root);
        hash_fp2(&mut hasher, self.functional_fold);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C61TypedNativeRelationStatement {
    Model(C61CommittedOpeningStatement),
    Embedding(C61CommittedOpeningStatement),
    Compiler(Box<C61TerminalFunctionalCompilerStatement>),
}

impl C61TypedNativeRelationStatement {
    fn component(&self) -> C61NativeComponent {
        match self {
            Self::Model(_) => C61NativeComponent::Model,
            Self::Embedding(_) => C61NativeComponent::Embedding,
            Self::Compiler(_) => C61NativeComponent::Compiler,
        }
    }

    fn target_count(&self) -> usize {
        match self {
            Self::Model(_) => C61_MODEL_OPENING_TARGETS,
            Self::Embedding(_) => C61_EMBEDDING_OPENING_TARGETS,
            Self::Compiler(_) => C61_COMPILER_TERMINAL_TARGETS,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Model(statement) => statement.validate(C61_MODEL_OPENING_TARGETS),
            Self::Embedding(statement) => statement.validate(C61_EMBEDDING_OPENING_TARGETS),
            Self::Compiler(statement) => statement.validate(),
        }
    }

    fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        match self {
            Self::Model(statement) => Ok(statement.digest(C61NativeComponent::Model)),
            Self::Embedding(statement) => Ok(statement.digest(C61NativeComponent::Embedding)),
            Self::Compiler(statement) => statement.digest(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TypedNativeChainPublicStatement {
    id: C61NativeChainId,
    relation: C61TypedNativeRelationStatement,
    digest: [u8; 32],
}

impl C61TypedNativeChainPublicStatement {
    pub fn new(id: C61NativeChainId, relation: C61TypedNativeRelationStatement) -> Result<Self> {
        if id.repetition >= 2 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native chain repetition is out of range",
            ));
        }
        if id.component != relation.component() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native chain component does not match its typed relation",
            ));
        }
        relation.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(PUBLIC_STATEMENT_DOMAIN);
        hasher.update(&(id.component as u16).to_le_bytes());
        hasher.update(&[id.repetition]);
        hasher.update(&relation.digest()?);
        let digest = *hasher.finalize().as_bytes();
        Ok(Self { id, relation, digest })
    }

    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    pub fn relation(&self) -> &C61TypedNativeRelationStatement {
        &self.relation
    }

    pub fn target_count(&self) -> usize {
        self.relation.target_count()
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn validate(&self) -> Result<()> {
        if self.id.component != self.relation.component() || self.id.repetition >= 2 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 typed native chain identity is inconsistent",
            ));
        }
        if self.digest
            != C61TypedNativeChainPublicStatement::new(self.id, self.relation.clone())?.digest
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 typed native chain digest is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeProverChainStatement {
    public: C61TypedNativeChainPublicStatement,
    targets: Vec<ProverAuthed>,
}

impl C61NativeProverChainStatement {
    pub fn new(
        public: C61TypedNativeChainPublicStatement,
        targets: Vec<ProverAuthed>,
    ) -> Result<Self> {
        public.validate()?;
        if targets.len() != public.target_count() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 provider target census does not match the typed statement",
            ));
        }
        if let C61TypedNativeRelationStatement::Compiler(compiler) = public.relation() {
            if targets.iter().zip(compiler.terminal_claims).any(|(target, claim)| target.x != claim)
            {
                return Err(C61TerminalFunctionalStatementError::new(
                    "C6TFR1 provider target plaintext differs from its terminal claim",
                ));
            }
        }
        Ok(Self { public, targets })
    }

    pub fn public(&self) -> &C61TypedNativeChainPublicStatement {
        &self.public
    }

    pub fn targets(&self) -> &[ProverAuthed] {
        &self.targets
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeVerifierChainStatement {
    public: C61TypedNativeChainPublicStatement,
    target_keys: Vec<VerifierKey>,
}

impl C61NativeVerifierChainStatement {
    pub fn new(
        public: C61TypedNativeChainPublicStatement,
        target_keys: Vec<VerifierKey>,
    ) -> Result<Self> {
        public.validate()?;
        if target_keys.len() != public.target_count() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 verifier target census does not match the typed statement",
            ));
        }
        Ok(Self { public, target_keys })
    }

    pub fn public(&self) -> &C61TypedNativeChainPublicStatement {
        &self.public
    }

    pub fn target_keys(&self) -> &[VerifierKey] {
        &self.target_keys
    }
}

/// Future production backends must consume the structured verifier
/// statement.  The historical opaque digest/payload adapter does not
/// implement this trait and remains ineligible for C6TFR1 credit.
pub trait C61TypedNativeBackendVerifier {
    fn verify_typed_chain(
        &self,
        statement: &C61NativeVerifierChainStatement,
        payload: &[u8],
        transcript: &mut Transcript,
    ) -> Result<()>;
}

pub fn fold_terminal_claims(claims: &[Fp2; C61_TERMINAL_CLAIMS], output_beta: Fp2) -> Fp2 {
    claims
        .iter()
        .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
            (sum + power * *claim, power * output_beta)
        })
        .0
}

pub fn terminal_claims_digest(claims: &[Fp2; C61_TERMINAL_CLAIMS]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TERMINAL_CLAIMS_DOMAIN);
    hasher.update(&(claims.len() as u64).to_le_bytes());
    for (ordinal, claim) in claims.iter().enumerate() {
        hasher.update(&(ordinal as u64).to_le_bytes());
        hash_fp2(&mut hasher, *claim);
    }
    *hasher.finalize().as_bytes()
}

fn hash_point(hasher: &mut blake3::Hasher, point: &[Fp2]) {
    hasher.update(&(point.len() as u64).to_le_bytes());
    for coordinate in point {
        hash_fp2(hasher, *coordinate);
    }
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, P};

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(17).wrapping_add(3)))
    }

    fn commitment(marker: u8, dimension: u8) -> C61NativeCommitmentDescriptor {
        C61NativeCommitmentDescriptor {
            parameter_digest: [marker; 32],
            commitment_root: [marker.wrapping_add(1); 32],
            polynomial_domain_log2: dimension,
        }
    }

    fn opening_statement(marker: u8, dimension: u8, claims: usize) -> C61CommittedOpeningStatement {
        C61CommittedOpeningStatement {
            commitment: commitment(marker, dimension),
            ordered_points: (0..claims)
                .map(|claim| {
                    (0..dimension)
                        .map(|coordinate| {
                            fp2(u64::from(marker) + claim as u64 + u64::from(coordinate))
                        })
                        .collect()
                })
                .collect(),
        }
    }

    fn compiler_statement() -> C61TerminalFunctionalCompilerStatement {
        let terminal_claims = std::array::from_fn(|index| fp2(index as u64 + 101));
        C61TerminalFunctionalCompilerStatement::new(C61TerminalFunctionalCompilerBinding {
            operation_plan_digest: [1; 32],
            operation_topology_digest: [2; 32],
            terminal_metadata_digest: [3; 32],
            extraction_map_digest: [4; 32],
            runtime_root: [5; 32],
            residual_manifest_digest: [6; 32],
            residual_public_claims_digest: [7; 32],
            relation_challenges_digest: [8; 32],
            sparse_oracles: C61SparseRationalCompilerOracles::new(
                commitment(41, C61_SPARSE_RATIONAL_PACKED_LOG2),
                commitment(51, C61_SPARSE_RATIONAL_PACKED_LOG2),
            )
            .unwrap(),
            leaf_points: std::array::from_fn(|repetition| {
                (0..C6_RESIDUAL_LEAF_ROUNDS)
                    .map(|coordinate| fp2(200 + (repetition * 31 + coordinate) as u64))
                    .collect()
            }),
            auxiliary_points: std::array::from_fn(|repetition| {
                (0..C6_RESIDUAL_AUXILIARY_ROUNDS)
                    .map(|coordinate| fp2(400 + (repetition * 31 + coordinate) as u64))
                    .collect()
            }),
            terminal_claims,
            output_beta: fp2(509),
            relation_root: [9; 32],
        })
        .unwrap()
    }

    fn role_targets(values: &[Fp2]) -> (Vec<ProverAuthed>, Vec<VerifierKey>) {
        let delta = fp2(P - 91);
        let provider = values
            .iter()
            .enumerate()
            .map(|(index, value)| ProverAuthed::new(*value, fp2(index as u64 + 601)))
            .collect::<Vec<_>>();
        let verifier =
            provider.iter().map(|target| VerifierKey::new(target.m + delta * target.x)).collect();
        (provider, verifier)
    }

    #[test]
    fn all_six_role_typed_statements_bind_exact_censuses_without_hashing_keys() {
        for (component, relation, values) in [
            (
                C61NativeComponent::Model,
                C61TypedNativeRelationStatement::Model(opening_statement(
                    11,
                    14,
                    C61_MODEL_OPENING_TARGETS,
                )),
                (0..C61_MODEL_OPENING_TARGETS).map(|index| fp2(index as u64 + 1)).collect(),
            ),
            (
                C61NativeComponent::Embedding,
                C61TypedNativeRelationStatement::Embedding(opening_statement(
                    21,
                    14,
                    C61_EMBEDDING_OPENING_TARGETS,
                )),
                (0..C61_EMBEDDING_OPENING_TARGETS).map(|index| fp2(index as u64 + 301)).collect(),
            ),
            {
                let compiler = compiler_statement();
                (
                    C61NativeComponent::Compiler,
                    C61TypedNativeRelationStatement::Compiler(Box::new(compiler.clone())),
                    compiler.terminal_claims.to_vec(),
                )
            },
        ] {
            for repetition in 0..2 {
                let public = C61TypedNativeChainPublicStatement::new(
                    C61NativeChainId { component, repetition },
                    relation.clone(),
                )
                .unwrap();
                let (provider_targets, verifier_keys) = role_targets(&values);
                let provider =
                    C61NativeProverChainStatement::new(public.clone(), provider_targets).unwrap();
                let verifier =
                    C61NativeVerifierChainStatement::new(public.clone(), verifier_keys).unwrap();
                assert_eq!(provider.public().digest(), verifier.public().digest());
                assert_eq!(provider.targets().len(), public.target_count());
                assert_eq!(verifier.target_keys().len(), public.target_count());

                let changed_keys = verifier
                    .target_keys()
                    .iter()
                    .enumerate()
                    .map(|(index, key)| VerifierKey::new(key.k + fp2(index as u64 + 701)))
                    .collect();
                let changed_verifier =
                    C61NativeVerifierChainStatement::new(public.clone(), changed_keys).unwrap();
                assert_eq!(changed_verifier.public().digest(), public.digest());
            }
        }
    }

    #[test]
    fn compiler_statement_rejects_terminal_point_order_binding_and_target_mutations() {
        let compiler = compiler_statement();
        compiler.validate().unwrap();
        assert_eq!(
            compiler.functional_fold,
            fold_terminal_claims(&compiler.terminal_claims, compiler.output_beta)
        );
        assert_eq!(
            compiler.terminal_claims_digest,
            terminal_claims_digest(&compiler.terminal_claims)
        );

        let mut changed_terminal = compiler.clone();
        changed_terminal.terminal_claims[0] += Fp2::ONE;
        assert!(changed_terminal.validate().is_err());

        let mut changed_fold = compiler.clone();
        changed_fold.functional_fold += Fp2::ONE;
        assert!(changed_fold.validate().is_err());

        let mut changed_point = compiler.clone();
        changed_point.leaf_points[0][0] += Fp2::ONE;
        assert_ne!(compiler.digest().unwrap(), changed_point.digest().unwrap());

        let mut swapped_points = compiler.clone();
        swapped_points.leaf_points.swap(0, 1);
        assert_ne!(compiler.digest().unwrap(), swapped_points.digest().unwrap());

        let mut changed_relation_root = compiler.clone();
        changed_relation_root.relation_root[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_relation_root.digest().unwrap());

        let mut changed_terminal_metadata = compiler.clone();
        changed_terminal_metadata.terminal_metadata_digest[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_terminal_metadata.digest().unwrap());

        let public = C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
            C61TypedNativeRelationStatement::Compiler(Box::new(compiler.clone())),
        )
        .unwrap();
        let (mut provider_targets, verifier_keys) = role_targets(&compiler.terminal_claims);
        provider_targets[3].x += Fp2::ONE;
        assert!(C61NativeProverChainStatement::new(public.clone(), provider_targets).is_err());
        assert!(C61NativeVerifierChainStatement::new(
            public.clone(),
            verifier_keys[..C61_COMPILER_TERMINAL_TARGETS - 1].to_vec(),
        )
        .is_err());
        assert!(C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
            C61TypedNativeRelationStatement::Compiler(Box::new(compiler)),
        )
        .is_err());
    }

    #[test]
    fn sparse_compiler_oracles_points_and_role_targets_are_exact_and_typed() {
        let compiler = compiler_statement();
        let compiler_digest = compiler.digest().unwrap();
        let input_point: Vec<Fp2> = (0..C61_SPARSE_RATIONAL_INPUT_LOG2)
            .map(|coordinate| fp2(900 + u64::from(coordinate)))
            .collect();
        let public = C61SparseRationalCompilerOpeningStatement::new(
            compiler_digest,
            [61; 32],
            [62; 32],
            compiler.sparse_oracles,
            &input_point,
        )
        .unwrap();
        public.validate().unwrap();
        assert_eq!(public.points.response().len(), C61_SPARSE_RATIONAL_RESPONSE_OPENINGS);
        assert_eq!(public.points.plan().len(), C61_SPARSE_RATIONAL_PLAN_OPENINGS);

        let proto_points = volta_proto::c6_residual::C6SparseRationalPackedOpeningPoints::new(
            C61_SPARSE_RATIONAL_INPUT_LOG2,
            compiler.sparse_oracles.response.commitment_root,
            compiler.sparse_oracles.plan.commitment_root,
            &input_point,
        )
        .unwrap();
        assert_eq!(public.points.response(), proto_points.response());
        assert_eq!(public.points.plan(), proto_points.plan());

        let response_values: [Fp2; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] =
            std::array::from_fn(|index| fp2(1_000 + index as u64));
        let plan_values: [Fp2; C61_SPARSE_RATIONAL_PLAN_OPENINGS] =
            std::array::from_fn(|index| fp2(1_100 + index as u64));
        let (response_targets, response_keys) = {
            let (targets, keys) = role_targets(&response_values);
            (targets.try_into().unwrap(), keys.try_into().unwrap())
        };
        let (plan_targets, plan_keys) = {
            let (targets, keys) = role_targets(&plan_values);
            (targets.try_into().unwrap(), keys.try_into().unwrap())
        };
        let prover = C61SparseRationalProverOpeningStatement::new(
            public.clone(),
            response_targets,
            plan_targets,
        )
        .unwrap();
        let verifier = C61SparseRationalVerifierOpeningStatement::new(
            public.clone(),
            response_keys,
            plan_keys,
        )
        .unwrap();
        assert_eq!(prover.public.digest(), verifier.public.digest());

        let mut changed_key_verifier = verifier.clone();
        changed_key_verifier.response_target_keys[0] =
            VerifierKey::new(changed_key_verifier.response_target_keys[0].k + Fp2::ONE);
        assert_eq!(changed_key_verifier.public.digest(), public.digest());

        let mut changed_layout = compiler.sparse_oracles;
        changed_layout.response_layout_digest[0] ^= 1;
        assert!(changed_layout.validate().is_err());
        let mut changed_points = public.clone();
        changed_points.points.response.swap(0, 1);
        assert!(changed_points.validate().is_err());
        let mut changed_root = compiler.clone();
        changed_root.sparse_oracles.response.commitment_root[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_root.digest().unwrap());
    }

    #[test]
    fn committed_openings_bind_commitment_point_order_and_component() {
        let model = opening_statement(31, 14, C61_MODEL_OPENING_TARGETS);
        let public = C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            C61TypedNativeRelationStatement::Model(model.clone()),
        )
        .unwrap();

        let mut changed_commitment = model.clone();
        changed_commitment.commitment.commitment_root[0] ^= 1;
        let changed_commitment = C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(changed_commitment),
        )
        .unwrap();
        assert_ne!(public.digest(), changed_commitment.digest());

        let mut reordered = model.clone();
        reordered.ordered_points.swap(0, 1);
        let reordered = C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(reordered),
        )
        .unwrap();
        assert_ne!(public.digest(), reordered.digest());

        let mut malformed = model;
        malformed.ordered_points.pop();
        assert!(C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(malformed),
        )
        .is_err());
    }
}

//! Typed C6 authenticated-value DAG and affine residual compiler.
//!
//! The historical verifier is not globally linear: QuickSilver contains
//! `k_a * k_b - Delta * k_c`.  This module therefore exposes only linear
//! authenticated-value nodes and a separate, terminal `ProductClosure`.
//! A key multiplication requested as an ordinary node is rejected.
//!
//! Protocol order is represented by the API:
//!
//! 1. build the static value DAG and closure shapes;
//! 2. compare its exact census with the independently expected census;
//! 3. bind a nonzero pre-query witness commitment;
//! 4. only then supply independent base-share RLC coefficients, zero-closure
//!    weights, and the existing QuickSilver `(chi, M0, M1)` values.
//!
//! The compiler emits one grand affine equation.  It combines reverse
//! accumulation of every linear zero closure with base-share binding for
//! every direct correlation and every uncorrected product mask:
//!
//! `K_base + Delta * D_corr = M_public`.

use crate::c6::{C6DeltaResidual, C6PairedDeltaResidual};
use crate::c6_census::{
    C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES, C6_RESIDUAL_LEAF_ALIGNED_SLOTS, C6_RESIDUAL_SLOT_ENTRIES,
    C6_RESIDUAL_SLOT_LOG2, C6_T1_TOTAL_PRODUCT_CLOSURES, C6_T1_TOTAL_PRODUCT_TRIPLES,
    C6_T1_ZERO_CLOSURES,
};
use crate::c6_source::C6PairedSourceWitness;
use crate::prod_check::{prod_batch_verify, ProdProof};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{
    C6DecodedInstanceExtractionPlan, C6InstalledOperationKind, C6InstalledOperationPlan,
    C6OperationPlanInstanceIdentity, C6OperationPlanTopologyIdentity, C6RuntimeInstanceValues,
    CorrScheduleAudit, CorrScheduleKind, CorrScheduleRole, ProverAuthed, Transcript, VerifierKey,
};

#[cfg(feature = "c6-trace")]
mod fused_fixture;
#[cfg(feature = "c6-trace")]
pub use fused_fixture::{build_c6_residual_fused_scaled_fixture, C6ResidualFusedScaledFixture};

#[cfg(feature = "c6-trace")]
pub(crate) static C6_RESIDUAL_TRACE_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

pub type C6ResidualDigest = [u8; 32];

const CENSUS_DOMAIN: &[u8] = b"volta-zk/c6/residual-census/v1";
const PROGRAM_DOMAIN: &[u8] = b"volta-zk/c6/residual-program/v1";
const PREQUERY_DOMAIN: &[u8] = b"volta-zk/c6/residual-prequery/v1";
const RESPONSE_DOMAIN: &[u8] = b"volta-zk/c6/residual-response/v1";
const COMPILED_LINEAR_FORM_DOMAIN: &[u8] = b"volta-zk/c6/compiled-linear-form/v1";
const COMPILED_COEFFICIENT_DOMAIN: &[u8] = b"volta-zk/c6/compiled-coefficients/v1";
const PAIRED_COMPILED_COEFFICIENT_DOMAIN: &[u8] = b"volta-zk/c6/paired-compiled-coefficients/v2";
const PAIRED_COEFFICIENT_STREAM_DOMAINS: [u64; 2] =
    [0xC6_52_45_53_49_44_01, 0xC6_52_45_53_49_44_02];
const PAIRED_LEAF_WRAPPER_DOMAIN: &str = "volta-zk/c6/paired-residual-leaf-wrapper/v1";
const PAIRED_CLOSURE_WRAPPER_DOMAIN: &str = "volta-zk/c6/paired-residual-closure-wrapper/v1";
const PAIRED_INSTALLED_CLOSURE_WRAPPER_DOMAIN: &str =
    "volta-zk/c6/paired-installed-residual-closure-wrapper/v1";
const PAIRED_AUXILIARY_WRAPPER_DOMAIN: &str = "volta-zk/c6/paired-residual-auxiliary-wrapper/v1";
const TERMINAL_WEIGHT_SCHEDULE_DOMAIN_V2: &str = "volta-zk/c6/residual-terminal-weight-schedule/v2";
const TERMINAL_WEIGHT_SCHEDULE_DOMAIN_V3: &str = "volta-zk/c6/residual-terminal-weight-schedule/v3";
const TERMINAL_LINEAR_FORM_DOMAIN_V2: &str = "volta-zk/c6/residual-terminal-linear-form/v2";
const TERMINAL_LINEAR_FORM_DOMAIN_V3: &str = "volta-zk/c6/residual-terminal-linear-form/v3";
const POST_ROOT_CONTEXT_SEED_DOMAIN: &str = "volta-zk/c6/residual-post-root-context-seed/v2";
const POST_ROOT_CHALLENGES_DOMAIN: &str = "volta-zk/c6/residual-post-root-challenges/v2";
const POST_ROOT_SEED_COMMITMENT_DOMAIN: &str = "volta-zk/c6/residual-post-root-seed-commitment/v2";
const RELATION_MANIFEST_DOMAIN: &str = "volta-zk/c6/t1-residual-relation-manifest/v1";
const RELATION_MANIFEST_MAGIC: [u8; 8] = *b"C6RLM1\0\0";
const RELATION_ROOT_BINDING_DOMAIN: &str = "volta-zk/c6/residual-root-binding/v3";
const BASE_SHARE_CONTEXT_DOMAIN: &str = "volta-zk/c6/residual-base-share-context/v3";
const VERIFIER_SEED_COMMITMENT_DOMAIN: &str = "volta-zk/c6/residual-verifier-seed-commitment/v1";
const PUBLIC_CLAIMS_DOMAIN: &str = "volta-zk/c6/residual-public-claims/v1";
const RELATION_CONTEXT_DOMAIN: &str = "volta-zk/c6/residual-relation-context/v3";
const RELATION_CHALLENGES_DOMAIN: &str = "volta-zk/c6/residual-relation-challenges/v3";
const ATOMIC_WEIGHT_SCHEDULE_DOMAIN: &str = "volta-zk/c6/residual-atomic-weight-schedule/v1";
const ATOMIC_EVENT_COMPLETION_DOMAIN: &str = "volta-zk/c6/residual-atomic-event-completion/v1";
const ATOMIC_EVENT_AUDIT_DOMAIN: &str = "volta-zk/c6/residual-atomic-event-audit/v1";
const FUSED_FOLDED_COEFFICIENT_DOMAIN: &str = "volta-zk/c6/residual-fused-folded-coefficients/v1";
const FUSED_TERMINAL_COEFFICIENT_DOMAIN: &str =
    "volta-zk/c6/residual-fused-terminal-coefficients/v1";
const TERMINAL_WEIGHT_STREAM_DOMAINS: [[[u64; 2]; 2]; 2] = [
    [
        [0xC6_54_45_52_4D_00_00_01, 0xC6_54_45_52_4D_00_00_02],
        [0xC6_54_45_52_4D_00_01_01, 0xC6_54_45_52_4D_00_01_02],
    ],
    [
        [0xC6_54_45_52_4D_01_00_01, 0xC6_54_45_52_4D_01_00_02],
        [0xC6_54_45_52_4D_01_01_01, 0xC6_54_45_52_4D_01_01_02],
    ],
];
const ATOMIC_WEIGHT_STREAM_DOMAINS: [u64; 2] =
    [0xC6_41_54_4F_4D_00_00_01, 0xC6_41_54_4F_4D_01_00_01];
const RESIDUAL_RELATION_PROTOCOL_V2: u8 = 2;
const RESIDUAL_RELATION_PROTOCOL_V3: u8 = 3;
pub const C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS: [(u8, u8); 8] =
    [(0, 2), (0, 3), (1, 2), (1, 3), (6, 8), (6, 9), (7, 8), (7, 9)];
const RESIDUAL_RELATION_SOURCE_FORMULAS: [&[u8]; 3] =
    [b"dir*(L0-L1-L3)+pm*L3", b"dir*(L0-L4-L6)+pm*L6", b"pm*L0"];

pub const C6_RESIDUAL_PROOF_REPETITIONS: u8 = 2;
pub const C6_RESIDUAL_MAC_COORDINATES: u8 = 2;
pub const C6_RESIDUAL_TERMINAL_FORM_KINDS: usize = 2;
pub const C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS: usize = C6_RESIDUAL_PROOF_REPETITIONS as usize
    * C6_RESIDUAL_MAC_COORDINATES as usize
    * C6_RESIDUAL_TERMINAL_FORM_KINDS;
pub const C6_RESIDUAL_AUXILIARY_LANES: u32 = 16;
pub const C6_RESIDUAL_AUXILIARY_PRODUCT_LANES: u32 = 12;
pub const C6_RESIDUAL_AUXILIARY_ZERO_LANES: u32 = 4;
pub const C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2: u32 = 15;
pub const C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES: u64 = 1 << C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2;
pub const C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS: u64 =
    C6_RESIDUAL_RELATION_LEAF_TABLES as u64 * (C6_RESIDUAL_SLOT_ENTRIES / 2);
pub const C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_BYTES: u64 =
    C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS * std::mem::size_of::<Fp2>() as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualError(String);

impl C6ResidualError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6ResidualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6ResidualError {}

type C6ResidualResult<T> = Result<T, C6ResidualError>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6LeafKind {
    Subfield = 1,
    FullField = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6LeafRole {
    Direct = 1,
    ProductMask = 2,
}

/// Canonical connection-local identity of one correlation leaf.
///
/// `schedule_index` is the exact transcript/correlation ordinal.  The
/// physical tuple is independently unique, so renumbering or swapping leaves
/// changes the census instead of silently canonicalizing the mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct C6LeafId {
    pub schedule_index: u32,
    pub stage: u8,
    pub domain: u64,
    pub offset: u32,
    pub kind: C6LeafKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PhysicalLeafId {
    stage: u8,
    domain: u64,
    offset: u32,
    kind: C6LeafKind,
}

impl C6LeafId {
    fn physical(self) -> PhysicalLeafId {
        PhysicalLeafId {
            stage: self.stage,
            domain: self.domain,
            offset: self.offset,
            kind: self.kind,
        }
    }
}

/// Provider witness at one direct base-correlation leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6SourceWitness {
    Subfield { r: Fp, correction: Fp, tag: Fp2 },
    FullField { r: Fp2, correction: Fp2, tag: Fp2 },
}

impl C6SourceWitness {
    fn kind(self) -> C6LeafKind {
        match self {
            Self::Subfield { .. } => C6LeafKind::Subfield,
            Self::FullField { .. } => C6LeafKind::FullField,
        }
    }

    fn base_plaintext(self) -> Fp2 {
        match self {
            Self::Subfield { r, .. } => Fp2::from_base(r),
            Self::FullField { r, .. } => r,
        }
    }

    fn correction(self) -> Fp2 {
        match self {
            Self::Subfield { correction, .. } => Fp2::from_base(correction),
            Self::FullField { correction, .. } => correction,
        }
    }

    fn tag(self) -> Fp2 {
        match self {
            Self::Subfield { tag, .. } | Self::FullField { tag, .. } => tag,
        }
    }

    fn prover_value(self) -> ProverAuthed {
        ProverAuthed::new(self.base_plaintext() + self.correction(), self.tag())
    }

    fn is_uncorrected_full(self) -> bool {
        matches!(self, Self::FullField { correction: Fp2::ZERO, .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceNode {
    id: C6LeafId,
    role: C6LeafRole,
    witness: C6SourceWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct C6ValueId(u32);

impl C6ValueId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueNode {
    Source(usize),
    Public(Fp2),
    Add(C6ValueId, C6ValueId),
    Sub(C6ValueId, C6ValueId),
    Scale(C6ValueId, Fp2),
}

/// The only operations accepted by the authenticated-value DAG.  The
/// explicit forbidden variant gives migration code a fail-closed path when a
/// census discovers an old verifier key multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ValueOperation {
    Add { lhs: C6ValueId, rhs: C6ValueId },
    Sub { lhs: C6ValueId, rhs: C6ValueId },
    Scale { value: C6ValueId, scalar: Fp2 },
    ForbiddenKeyMultiply { lhs: C6ValueId, rhs: C6ValueId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductShape {
    triples: Vec<[C6ValueId; 3]>,
    mask: C6ValueId,
}

/// Exact static census that the client can derive independently of hidden
/// witness values and post-commit challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualCensus {
    pub leaf_count: u32,
    pub node_count: u32,
    pub zero_closure_count: u32,
    pub product_closure_count: u32,
    pub leaf_digest: C6ResidualDigest,
    pub program_digest: C6ResidualDigest,
}

#[derive(Default)]
pub struct C6ResidualBuilder {
    sources: Vec<SourceNode>,
    nodes: Vec<ValueNode>,
    physical_leaves: BTreeSet<PhysicalLeafId>,
    zero_closures: Vec<C6ValueId>,
    products: Vec<ProductShape>,
    used_product_masks: BTreeSet<usize>,
}

impl C6ResidualBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_value_id(&self) -> C6ResidualResult<C6ValueId> {
        let index = u32::try_from(self.nodes.len())
            .map_err(|_| C6ResidualError::new("C6 residual node count exceeds u32"))?;
        Ok(C6ValueId(index))
    }

    fn validate_value(&self, value: C6ValueId) -> C6ResidualResult<()> {
        if value.index() >= self.nodes.len() {
            return Err(C6ResidualError::new("C6 residual references an unknown/future value"));
        }
        Ok(())
    }

    pub fn add_source(
        &mut self,
        id: C6LeafId,
        role: C6LeafRole,
        witness: C6SourceWitness,
    ) -> C6ResidualResult<C6ValueId> {
        let expected_index = u32::try_from(self.sources.len())
            .map_err(|_| C6ResidualError::new("C6 source count exceeds u32"))?;
        if id.schedule_index != expected_index {
            return Err(C6ResidualError::new(format!(
                "C6 source schedule index {} is not canonical next index {expected_index}",
                id.schedule_index
            )));
        }
        if id.kind != witness.kind() {
            return Err(C6ResidualError::new("C6 leaf kind/witness mismatch"));
        }
        if role == C6LeafRole::ProductMask && !witness.is_uncorrected_full() {
            return Err(C6ResidualError::new(
                "C6 ProductClosure mask must be an uncorrected full correlation",
            ));
        }
        if !self.physical_leaves.insert(id.physical()) {
            return Err(C6ResidualError::new("duplicate C6 physical correlation leaf"));
        }

        let value = self.next_value_id()?;
        let source_index = self.sources.len();
        self.sources.push(SourceNode { id, role, witness });
        self.nodes.push(ValueNode::Source(source_index));
        Ok(value)
    }

    pub fn add_public(&mut self, value: Fp2) -> C6ResidualResult<C6ValueId> {
        let id = self.next_value_id()?;
        self.nodes.push(ValueNode::Public(value));
        Ok(id)
    }

    pub fn add_operation(&mut self, operation: C6ValueOperation) -> C6ResidualResult<C6ValueId> {
        let node = match operation {
            C6ValueOperation::Add { lhs, rhs } => {
                self.validate_value(lhs)?;
                self.validate_value(rhs)?;
                ValueNode::Add(lhs, rhs)
            }
            C6ValueOperation::Sub { lhs, rhs } => {
                self.validate_value(lhs)?;
                self.validate_value(rhs)?;
                ValueNode::Sub(lhs, rhs)
            }
            C6ValueOperation::Scale { value, scalar } => {
                self.validate_value(value)?;
                ValueNode::Scale(value, scalar)
            }
            C6ValueOperation::ForbiddenKeyMultiply { lhs, rhs } => {
                self.validate_value(lhs)?;
                self.validate_value(rhs)?;
                return Err(C6ResidualError::new(
                    "nonlinear key multiplication requires an explicit C6 ProductClosure",
                ));
            }
        };
        let id = self.next_value_id()?;
        self.nodes.push(node);
        Ok(id)
    }

    pub fn add(&mut self, lhs: C6ValueId, rhs: C6ValueId) -> C6ResidualResult<C6ValueId> {
        self.add_operation(C6ValueOperation::Add { lhs, rhs })
    }

    pub fn sub(&mut self, lhs: C6ValueId, rhs: C6ValueId) -> C6ResidualResult<C6ValueId> {
        self.add_operation(C6ValueOperation::Sub { lhs, rhs })
    }

    pub fn scale(&mut self, value: C6ValueId, scalar: Fp2) -> C6ResidualResult<C6ValueId> {
        self.add_operation(C6ValueOperation::Scale { value, scalar })
    }

    pub fn add_zero_closure(&mut self, value: C6ValueId) -> C6ResidualResult<()> {
        self.validate_value(value)?;
        self.zero_closures.push(value);
        Ok(())
    }

    pub fn add_product_closure(
        &mut self,
        triples: Vec<[C6ValueId; 3]>,
        mask: C6ValueId,
    ) -> C6ResidualResult<()> {
        if triples.is_empty() {
            return Err(C6ResidualError::new("empty C6 ProductClosure"));
        }
        self.validate_value(mask)?;
        for triple in &triples {
            for value in triple {
                self.validate_value(*value)?;
            }
        }
        let source_index = match self.nodes[mask.index()] {
            ValueNode::Source(index) => index,
            _ => {
                return Err(C6ResidualError::new(
                    "C6 ProductClosure mask is not a direct correlation leaf",
                ));
            }
        };
        if self.sources[source_index].role != C6LeafRole::ProductMask {
            return Err(C6ResidualError::new("C6 ProductClosure mask leaf has the wrong role"));
        }
        if !self.used_product_masks.insert(source_index) {
            return Err(C6ResidualError::new("C6 ProductClosure mask correlation reused"));
        }
        self.products.push(ProductShape { triples, mask });
        Ok(())
    }

    fn mark_reachable(&self, value: C6ValueId, reachable: &mut [bool]) {
        let index = value.index();
        if reachable[index] {
            return;
        }
        reachable[index] = true;
        match self.nodes[index] {
            ValueNode::Source(_) | ValueNode::Public(_) => {}
            ValueNode::Add(lhs, rhs) | ValueNode::Sub(lhs, rhs) => {
                self.mark_reachable(lhs, reachable);
                self.mark_reachable(rhs, reachable);
            }
            ValueNode::Scale(input, _) => self.mark_reachable(input, reachable),
        }
    }

    fn validate_graph(&self) -> C6ResidualResult<()> {
        if self.nodes.is_empty() {
            return Err(C6ResidualError::new("empty C6 residual DAG"));
        }
        let mut reachable = vec![false; self.nodes.len()];
        for value in &self.zero_closures {
            self.mark_reachable(*value, &mut reachable);
        }
        for product in &self.products {
            self.mark_reachable(product.mask, &mut reachable);
            for triple in &product.triples {
                for value in triple {
                    self.mark_reachable(*value, &mut reachable);
                }
            }
        }
        if let Some(index) = reachable.iter().position(|is_reachable| !is_reachable) {
            return Err(C6ResidualError::new(format!(
                "dead C6 residual node {index} is outside every closure"
            )));
        }

        let declared_mask_nodes: BTreeSet<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(node_index, node)| match node {
                ValueNode::Source(source_index)
                    if self.sources[*source_index].role == C6LeafRole::ProductMask =>
                {
                    Some(node_index)
                }
                _ => None,
            })
            .collect();
        let used_mask_nodes: BTreeSet<usize> =
            self.products.iter().map(|product| product.mask.index()).collect();
        if declared_mask_nodes != used_mask_nodes {
            return Err(C6ResidualError::new(
                "every C6 product-mask leaf must close exactly one ProductClosure",
            ));
        }
        let mask_nodes = declared_mask_nodes;
        for (index, node) in self.nodes.iter().enumerate() {
            match node {
                ValueNode::Add(lhs, rhs) | ValueNode::Sub(lhs, rhs) => {
                    if mask_nodes.contains(&lhs.index()) || mask_nodes.contains(&rhs.index()) {
                        return Err(C6ResidualError::new(
                            "product-mask leaf used by a linear value node",
                        ));
                    }
                }
                ValueNode::Scale(value, _) => {
                    if mask_nodes.contains(&value.index()) {
                        return Err(C6ResidualError::new(
                            "product-mask leaf used by a linear scale node",
                        ));
                    }
                }
                ValueNode::Source(_) | ValueNode::Public(_) => {}
            }
            if mask_nodes.contains(&index)
                && self.zero_closures.iter().any(|value| value.index() == index)
            {
                return Err(C6ResidualError::new("product-mask leaf used by a zero closure"));
            }
        }
        for product in &self.products {
            for triple in &product.triples {
                if triple.iter().any(|value| mask_nodes.contains(&value.index())) {
                    return Err(C6ResidualError::new(
                        "product-mask leaf reused as a product operand",
                    ));
                }
            }
        }
        Ok(())
    }

    fn evaluate_values(&self) -> Vec<ProverAuthed> {
        let mut values: Vec<ProverAuthed> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let value = match *node {
                ValueNode::Source(index) => self.sources[index].witness.prover_value(),
                ValueNode::Public(value) => ProverAuthed::from_public(value),
                ValueNode::Add(lhs, rhs) => values[lhs.index()].add(values[rhs.index()]),
                ValueNode::Sub(lhs, rhs) => values[lhs.index()].sub(values[rhs.index()]),
                ValueNode::Scale(input, scalar) => values[input.index()].scale(scalar),
            };
            values.push(value);
        }
        values
    }

    pub fn census(&self) -> C6ResidualResult<C6ResidualCensus> {
        self.validate_graph()?;
        let leaf_count = count_u32(self.sources.len(), "C6 leaf count")?;
        let node_count = count_u32(self.nodes.len(), "C6 node count")?;
        let zero_closure_count = count_u32(self.zero_closures.len(), "C6 zero-closure count")?;
        let product_closure_count = count_u32(self.products.len(), "C6 product-closure count")?;

        let mut leaf_hasher = blake3::Hasher::new();
        leaf_hasher.update(CENSUS_DOMAIN);
        leaf_hasher.update(&leaf_count.to_le_bytes());
        for source in &self.sources {
            hash_leaf(&mut leaf_hasher, source);
        }
        let leaf_digest = *leaf_hasher.finalize().as_bytes();

        let mut program_hasher = blake3::Hasher::new();
        program_hasher.update(PROGRAM_DOMAIN);
        program_hasher.update(&leaf_digest);
        program_hasher.update(&node_count.to_le_bytes());
        program_hasher.update(&zero_closure_count.to_le_bytes());
        program_hasher.update(&product_closure_count.to_le_bytes());
        for node in &self.nodes {
            hash_node(&mut program_hasher, node);
        }
        for closure in &self.zero_closures {
            program_hasher.update(&closure.0.to_le_bytes());
        }
        for product in &self.products {
            program_hasher.update(&(product.triples.len() as u64).to_le_bytes());
            for triple in &product.triples {
                for value in triple {
                    program_hasher.update(&value.0.to_le_bytes());
                }
            }
            program_hasher.update(&product.mask.0.to_le_bytes());
        }
        let program_digest = *program_hasher.finalize().as_bytes();

        Ok(C6ResidualCensus {
            leaf_count,
            node_count,
            zero_closure_count,
            product_closure_count,
            leaf_digest,
            program_digest,
        })
    }

    pub fn commit(
        self,
        witness_commitment: C6ResidualDigest,
        expected_census: C6ResidualCensus,
    ) -> C6ResidualResult<C6CommittedResidualProgram> {
        if witness_commitment == [0; 32] {
            return Err(C6ResidualError::new("zero C6 residual witness commitment"));
        }
        let actual_census = self.census()?;
        if actual_census != expected_census {
            return Err(C6ResidualError::new(
                "C6 residual census differs from the independently expected schedule",
            ));
        }
        let values = self.evaluate_values();
        let prequery_statement_digest = hash_digest_parts(
            PREQUERY_DOMAIN,
            &[&witness_commitment, &actual_census.program_digest],
        );
        Ok(C6CommittedResidualProgram {
            sources: self.sources,
            nodes: self.nodes,
            zero_closures: self.zero_closures,
            products: self.products,
            values,
            census: actual_census,
            witness_commitment,
            prequery_statement_digest,
        })
    }
}

fn count_u32(value: usize, label: &str) -> C6ResidualResult<u32> {
    u32::try_from(value).map_err(|_| C6ResidualError::new(format!("{label} exceeds u32")))
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

fn hash_leaf(hasher: &mut blake3::Hasher, source: &SourceNode) {
    hasher.update(&source.id.schedule_index.to_le_bytes());
    hasher.update(&[source.id.stage]);
    hasher.update(&source.id.domain.to_le_bytes());
    hasher.update(&source.id.offset.to_le_bytes());
    hasher.update(&[source.id.kind as u8, source.role as u8]);
}

fn hash_node(hasher: &mut blake3::Hasher, node: &ValueNode) {
    match *node {
        ValueNode::Source(index) => {
            hasher.update(&[1]);
            hasher.update(&(index as u64).to_le_bytes());
        }
        ValueNode::Public(value) => {
            hasher.update(&[2]);
            hash_fp2(hasher, value);
        }
        ValueNode::Add(lhs, rhs) => {
            hasher.update(&[3]);
            hasher.update(&lhs.0.to_le_bytes());
            hasher.update(&rhs.0.to_le_bytes());
        }
        ValueNode::Sub(lhs, rhs) => {
            hasher.update(&[4]);
            hasher.update(&lhs.0.to_le_bytes());
            hasher.update(&rhs.0.to_le_bytes());
        }
        ValueNode::Scale(value, scalar) => {
            hasher.update(&[5]);
            hasher.update(&value.0.to_le_bytes());
            hash_fp2(hasher, scalar);
        }
    }
}

fn hash_digest_parts(domain: &[u8], parts: &[&[u8]]) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn installed_product_mask_sources(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<Vec<u32>> {
    let mut source_cursor = 0usize;
    let mut source_by_node = BTreeMap::new();
    for (canonical, kind) in operation_plan.operation_kinds().iter().copied().enumerate() {
        if kind == C6InstalledOperationKind::Source {
            let source = *operation_plan.source_ordinals().get(source_cursor).ok_or_else(|| {
                C6ResidualError::new("C6 installed source-ordinal stream is truncated")
            })?;
            source_cursor += 1;
            source_by_node.insert(canonical as u32, source);
        }
    }
    if source_cursor != operation_plan.source_ordinals().len()
        || source_cursor != operation_plan.topology().source_count as usize
    {
        return Err(C6ResidualError::new(
            "C6 installed source-ordinal stream differs from topology",
        ));
    }

    let mut seen = BTreeSet::new();
    let mut masks = Vec::with_capacity(operation_plan.products().len());
    for product in operation_plan.products() {
        let source = *source_by_node.get(&product.mask()).ok_or_else(|| {
            C6ResidualError::new("C6 installed ProductClosure mask is not a source node")
        })?;
        if source >= operation_plan.topology().source_count || !seen.insert(source) {
            return Err(C6ResidualError::new(
                "C6 installed ProductClosure masks are reused or out of range",
            ));
        }
        masks.push(source);
    }
    Ok(masks)
}

fn checked_relation_entries(log2: u8, label: &str) -> C6ResidualResult<u64> {
    1u64.checked_shl(u32::from(log2))
        .ok_or_else(|| C6ResidualError::new(format!("C6 residual {label} capacity overflows")))
}

fn residual_relation_atomic_outputs(
    source_count: u64,
    product_closures: u64,
    product_triples: u64,
    zero_roots: u64,
    leaf_entries: u64,
    auxiliary_entries: u64,
) -> C6ResidualResult<(u64, u64, u64)> {
    let raw_copy_entries = product_triples
        .checked_mul(12)
        .and_then(|value| value.checked_add(zero_roots.checked_mul(4)?))
        .ok_or_else(|| C6ResidualError::new("C6 residual raw-copy census overflows"))?;
    let leaf_tails = leaf_entries
        .checked_sub(source_count)
        .and_then(|tail| tail.checked_mul(7))
        .and_then(|tail| tail.checked_add(leaf_entries.checked_sub(raw_copy_entries)?))
        .ok_or_else(|| C6ResidualError::new("C6 residual leaf-tail census is invalid"))?;
    let auxiliary_tails = auxiliary_entries
        .checked_sub(product_triples)
        .and_then(|tail| tail.checked_mul(12))
        .and_then(|tail| {
            tail.checked_add(auxiliary_entries.checked_sub(zero_roots)?.checked_mul(4)?)
        })
        .ok_or_else(|| C6ResidualError::new("C6 residual auxiliary-tail census is invalid"))?;
    let atomic_outputs = source_count
        .checked_mul(3)
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(raw_copy_entries))
        .and_then(|value| value.checked_add(product_closures.checked_mul(6)?))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(leaf_tails))
        .and_then(|value| value.checked_add(auxiliary_tails))
        .ok_or_else(|| C6ResidualError::new("C6 residual atomic-output census overflows"))?;
    Ok((raw_copy_entries, leaf_tails, atomic_outputs))
}

/// Canonical C6RLM1 binding for one installed residual relation.
///
/// The production constructor fixes the exact T1 capacities.  Tests use the
/// private scaled constructor below; a scaled digest can never satisfy
/// [`Self::is_production_geometry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualRelationManifest {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology: C6OperationPlanTopologyIdentity,
    instance: C6OperationPlanInstanceIdentity,
    product_mask_sources: Vec<u32>,
    leaf_log2: u8,
    auxiliary_log2: u8,
    leaf_entries: u64,
    auxiliary_entries: u64,
    raw_copy_entries: u64,
    leaf_tail_outputs: u64,
    auxiliary_tail_outputs: u64,
    atomic_outputs_per_repetition: u64,
    production_geometry: bool,
    digest: C6ResidualDigest,
}

impl C6ResidualRelationManifest {
    pub fn new(
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
    ) -> C6ResidualResult<Self> {
        Self::new_with_geometry(
            operation_plan,
            extraction,
            runtime,
            C6_RESIDUAL_SLOT_LOG2 as u8,
            C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2 as u8,
            true,
        )
    }

    fn new_with_geometry(
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        leaf_log2: u8,
        auxiliary_log2: u8,
        require_production: bool,
    ) -> C6ResidualResult<Self> {
        runtime
            .validate_extraction_binding(extraction)
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        let topology = operation_plan.topology();
        let instance = runtime.instance_identity();
        let extraction_census = extraction.census();
        if runtime.role() != extraction.role()
            || extraction.topology_digest() != topology.topology_digest
            || instance.version != topology.version
            || instance.topology_digest != topology.topology_digest
            || instance.public_input_count != topology.public_input_count
            || instance.scalar_input_count != topology.scalar_input_count
            || extraction_census.canonical_public_input_count != topology.public_input_count
            || extraction_census.canonical_scalar_input_count != topology.scalar_input_count
        {
            return Err(C6ResidualError::new(
                "C6 relation manifest instance/extraction binding mismatch",
            ));
        }

        let product_mask_sources = installed_product_mask_sources(operation_plan)?;
        let product_triples = installed_product_triple_count(operation_plan)?;
        let leaf_entries = checked_relation_entries(leaf_log2, "leaf")?;
        let auxiliary_entries = checked_relation_entries(auxiliary_log2, "auxiliary")?;
        let source_count = u64::from(topology.source_count);
        let product_closures = u64::from(topology.product_closure_count);
        let zero_roots = u64::from(topology.zero_root_count);
        let (raw_copy_entries, leaf_tail_outputs, atomic_outputs_per_repetition) =
            residual_relation_atomic_outputs(
                source_count,
                product_closures,
                product_triples,
                zero_roots,
                leaf_entries,
                auxiliary_entries,
            )?;
        let auxiliary_tail_outputs = auxiliary_entries
            .checked_sub(product_triples)
            .and_then(|tail| tail.checked_mul(12))
            .and_then(|tail| {
                tail.checked_add(auxiliary_entries.checked_sub(zero_roots)?.checked_mul(4)?)
            })
            .ok_or_else(|| C6ResidualError::new("C6 residual auxiliary-tail census is invalid"))?;
        let closure_live_entries = raw_copy_entries
            .checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES)
            .ok_or_else(|| C6ResidualError::new("C6 residual closure live census overflows"))?;
        if topology.product_closure_count as usize != operation_plan.products().len()
            || topology.product_closure_count as usize != product_mask_sources.len()
            || topology.product_triple_count != product_triples
            || topology.zero_root_count as usize != operation_plan.zero_roots().len()
            || source_count > leaf_entries
            || closure_live_entries > leaf_entries
            || product_triples > auxiliary_entries
            || zero_roots > auxiliary_entries
        {
            return Err(C6ResidualError::new(
                "C6 relation manifest geometry differs from installed plan/capacity",
            ));
        }

        let production_geometry = topology.source_count == 4_975_525
            && topology.product_closure_count == C6_T1_TOTAL_PRODUCT_CLOSURES as u32
            && topology.product_triple_count == C6_T1_TOTAL_PRODUCT_TRIPLES
            && topology.zero_root_count == C6_T1_ZERO_CLOSURES as u32
            && leaf_log2 == C6_RESIDUAL_SLOT_LOG2 as u8
            && auxiliary_log2 == C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2 as u8;
        if require_production && !production_geometry {
            return Err(C6ResidualError::new(
                "C6RLM1 production manifest does not have the frozen T1 geometry",
            ));
        }

        let mut manifest = Self {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology,
            instance,
            product_mask_sources,
            leaf_log2,
            auxiliary_log2,
            leaf_entries,
            auxiliary_entries,
            raw_copy_entries,
            leaf_tail_outputs,
            auxiliary_tail_outputs,
            atomic_outputs_per_repetition,
            production_geometry,
            digest: [0; 32],
        };
        manifest.digest = residual_relation_manifest_digest(&manifest);
        manifest.validate(operation_plan)?;
        Ok(manifest)
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn topology(&self) -> C6OperationPlanTopologyIdentity {
        self.topology
    }

    pub fn instance(&self) -> C6OperationPlanInstanceIdentity {
        self.instance
    }

    pub fn product_mask_sources(&self) -> &[u32] {
        &self.product_mask_sources
    }

    pub fn leaf_log2(&self) -> u8 {
        self.leaf_log2
    }

    pub fn auxiliary_log2(&self) -> u8 {
        self.auxiliary_log2
    }

    pub fn leaf_entries(&self) -> u64 {
        self.leaf_entries
    }

    pub fn auxiliary_entries(&self) -> u64 {
        self.auxiliary_entries
    }

    pub fn raw_copy_entries(&self) -> u64 {
        self.raw_copy_entries
    }

    pub fn atomic_outputs_per_repetition(&self) -> u64 {
        self.atomic_outputs_per_repetition
    }

    pub fn is_production_geometry(&self) -> bool {
        self.production_geometry
    }

    fn validate(&self, operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<()> {
        if self.operation_plan_artifact_digest != operation_plan.artifact_digest()
            || self.topology != operation_plan.topology()
            || self.product_mask_sources != installed_product_mask_sources(operation_plan)?
            || self.digest == [0; 32]
            || self.digest != residual_relation_manifest_digest(self)
        {
            return Err(C6ResidualError::new("C6 residual relation manifest binding mismatch"));
        }
        Ok(())
    }
}

fn residual_relation_manifest_digest(manifest: &C6ResidualRelationManifest) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(RELATION_MANIFEST_DOMAIN);
    hasher.update(&RELATION_MANIFEST_MAGIC);
    hasher.update(&manifest.operation_plan_artifact_digest);
    hasher.update(&manifest.topology.version.to_le_bytes());
    hasher.update(&manifest.topology.source_count.to_le_bytes());
    hasher.update(&manifest.topology.source_schedule_digest);
    hasher.update(&manifest.topology.canonical_node_count.to_le_bytes());
    hasher.update(&manifest.topology.public_input_count.to_le_bytes());
    hasher.update(&manifest.topology.scalar_input_count.to_le_bytes());
    hasher.update(&manifest.topology.product_closure_count.to_le_bytes());
    hasher.update(&manifest.topology.product_triple_count.to_le_bytes());
    hasher.update(&manifest.topology.zero_root_count.to_le_bytes());
    hasher.update(&manifest.topology.topology_digest);
    hasher.update(&manifest.instance.version.to_le_bytes());
    hasher.update(&manifest.instance.topology_digest);
    hasher.update(&manifest.instance.public_input_count.to_le_bytes());
    hasher.update(&manifest.instance.scalar_input_count.to_le_bytes());
    hasher.update(&manifest.instance.instance_digest);
    hasher.update(&[manifest.leaf_log2, manifest.auxiliary_log2]);
    hasher.update(&manifest.leaf_entries.to_le_bytes());
    hasher.update(&manifest.auxiliary_entries.to_le_bytes());
    hasher.update(&manifest.raw_copy_entries.to_le_bytes());
    hasher.update(&manifest.leaf_tail_outputs.to_le_bytes());
    hasher.update(&manifest.auxiliary_tail_outputs.to_le_bytes());
    hasher.update(&manifest.atomic_outputs_per_repetition.to_le_bytes());
    hasher.update(&(manifest.product_mask_sources.len() as u64).to_le_bytes());
    for (closure, source) in manifest.product_mask_sources.iter().enumerate() {
        hasher.update(&(closure as u64).to_le_bytes());
        hasher.update(&source.to_le_bytes());
    }
    for formula in RESIDUAL_RELATION_SOURCE_FORMULAS {
        hasher.update(&(formula.len() as u64).to_le_bytes());
        hasher.update(formula);
    }
    hasher.update(b"R_D=P+sum(ell*d)-sum(alpha*r)-D");
    hasher.update(b"R_M=sum((ell+alpha)*m)-M");
    hasher.update(b"raw=12*t+6*b+k;zero=12*T+4*z+2*b+k");
    hasher.update(b"product=Q,M0,M1;zero=sum(zeta*A_zero_x)");
    for (lhs, rhs) in C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS {
        hasher.update(&[lhs, rhs]);
    }
    for domains in TERMINAL_WEIGHT_STREAM_DOMAINS {
        for coordinate in domains {
            for domain in coordinate {
                hasher.update(&domain.to_le_bytes());
            }
        }
    }
    for domain in ATOMIC_WEIGHT_STREAM_DOMAINS {
        hasher.update(&domain.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Retained ProductClosure and response-wide ZeroBatch challenges fixed
/// after the roots and before provider public claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualRetainedChallenges {
    manifest_digest: C6ResidualDigest,
    product_challenges: Vec<Fp2>,
    zero_challenge: Fp2,
    digest: C6ResidualDigest,
}

impl C6ResidualRetainedChallenges {
    pub fn new(
        manifest: &C6ResidualRelationManifest,
        product_challenges: Vec<Fp2>,
        zero_challenge: Fp2,
    ) -> C6ResidualResult<Self> {
        if product_challenges.len() != manifest.topology.product_closure_count as usize {
            return Err(C6ResidualError::new(
                "C6 retained ProductClosure challenge census mismatch",
            ));
        }
        let mut retained = Self {
            manifest_digest: manifest.digest,
            product_challenges,
            zero_challenge,
            digest: [0; 32],
        };
        retained.digest = retained_challenges_digest(&retained);
        Ok(retained)
    }

    pub fn product_challenges(&self) -> &[Fp2] {
        &self.product_challenges
    }

    pub fn zero_challenge(&self) -> Fp2 {
        self.zero_challenge
    }

    pub fn zero_weights(&self, zero_roots: usize) -> Vec<Fp2> {
        let mut power = Fp2::ONE;
        (0..zero_roots)
            .map(|_| {
                power = power * self.zero_challenge;
                power
            })
            .collect()
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }
}

fn retained_challenges_digest(retained: &C6ResidualRetainedChallenges) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(BASE_SHARE_CONTEXT_DOMAIN);
    hasher.update(b"retained-challenges");
    hasher.update(&retained.manifest_digest);
    hasher.update(&(retained.product_challenges.len() as u64).to_le_bytes());
    for challenge in &retained.product_challenges {
        hash_fp2(&mut hasher, *challenge);
    }
    hash_fp2(&mut hasher, retained.zero_challenge);
    *hasher.finalize().as_bytes()
}

/// Private typestate after the wrapper statement and roots are fixed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualRelationRootBound {
    manifest: C6ResidualRelationManifest,
    wrapper_statement_digest: C6ResidualDigest,
    fixed_roots_digest: C6ResidualDigest,
    digest: C6ResidualDigest,
}

impl C6ResidualRelationRootBound {
    /// Low-level join used by the PCS crate after it has produced its private
    /// fixed-root token.  Production callers must not substitute a raw
    /// provider digest for that token.
    #[doc(hidden)]
    pub fn bind_fixed_roots(
        manifest: C6ResidualRelationManifest,
        wrapper_statement_digest: C6ResidualDigest,
        fixed_roots_digest: C6ResidualDigest,
    ) -> C6ResidualResult<Self> {
        if wrapper_statement_digest == [0; 32]
            || fixed_roots_digest == [0; 32]
            || manifest.digest == [0; 32]
        {
            return Err(C6ResidualError::new("C6 residual v3 root binding contains a zero digest"));
        }
        let mut root =
            Self { manifest, wrapper_statement_digest, fixed_roots_digest, digest: [0; 32] };
        root.digest = relation_root_binding_digest(&root);
        Ok(root)
    }

    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        &self.manifest
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn release_base_share_seed(
        self,
        retained: C6ResidualRetainedChallenges,
        base_share_seed: [u8; 32],
    ) -> C6ResidualResult<C6ResidualBaseShareContext> {
        if base_share_seed == [0; 32]
            || retained.manifest_digest != self.manifest.digest
            || retained.digest == [0; 32]
            || retained.digest != retained_challenges_digest(&retained)
        {
            return Err(C6ResidualError::new(
                "C6 residual base-share transition has an invalid seed/challenge binding",
            ));
        }
        let mut commitment_hasher = blake3::Hasher::new_derive_key(VERIFIER_SEED_COMMITMENT_DOMAIN);
        commitment_hasher.update(&base_share_seed);
        let base_share_seed_commitment = *commitment_hasher.finalize().as_bytes();

        let mut alpha_hasher = blake3::Hasher::new_derive_key(BASE_SHARE_CONTEXT_DOMAIN);
        alpha_hasher.update(b"alpha-seed");
        alpha_hasher.update(&self.digest);
        alpha_hasher.update(&retained.digest);
        alpha_hasher.update(&base_share_seed);
        let alpha_seed = *alpha_hasher.finalize().as_bytes();

        let mut context = C6ResidualBaseShareContext {
            root: self,
            retained,
            base_share_seed_commitment,
            alpha_seed,
            digest: [0; 32],
        };
        context.digest = base_share_context_digest(&context);
        Ok(context)
    }
}

fn relation_root_binding_digest(root: &C6ResidualRelationRootBound) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(RELATION_ROOT_BINDING_DOMAIN);
    hasher.update(&root.manifest.digest);
    hasher.update(&root.wrapper_statement_digest);
    hasher.update(&root.fixed_roots_digest);
    *hasher.finalize().as_bytes()
}

/// Typestate after the first verifier seed and retained challenges, but
/// before provider public outputs are committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualBaseShareContext {
    root: C6ResidualRelationRootBound,
    retained: C6ResidualRetainedChallenges,
    base_share_seed_commitment: C6ResidualDigest,
    alpha_seed: [u8; 32],
    digest: C6ResidualDigest,
}

impl C6ResidualBaseShareContext {
    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        &self.root.manifest
    }

    pub fn retained(&self) -> &C6ResidualRetainedChallenges {
        &self.retained
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn base_share_seed_commitment(&self) -> C6ResidualDigest {
        self.base_share_seed_commitment
    }

    pub fn alpha_stream(&self, coordinate: u8) -> C6ResidualResult<FpStream> {
        let domain = *PAIRED_COEFFICIENT_STREAM_DOMAINS
            .get(usize::from(coordinate))
            .ok_or_else(|| C6ResidualError::new("C6 residual alpha coordinate is out of range"))?;
        Ok(FpStream::domain_separated(self.alpha_seed, domain))
    }

    pub fn commit_public_claims(
        self,
        linear_form_digest: C6ResidualDigest,
        products: Vec<C6ResidualProductPublicClaim>,
        residual: C6PairedDeltaResidual,
    ) -> C6ResidualResult<C6ResidualClaimsBoundContext> {
        if linear_form_digest == [0; 32]
            || products.len() != self.root.manifest.topology.product_closure_count as usize
        {
            return Err(C6ResidualError::new(
                "C6 residual public-claims frame has an invalid digest/census",
            ));
        }
        let mut frame = C6ResidualPublicClaimsFrame {
            manifest_digest: self.root.manifest.digest,
            base_share_context_digest: self.digest,
            retained_challenges_digest: self.retained.digest,
            linear_form_digest,
            products,
            residual,
            digest: [0; 32],
        };
        frame.digest = public_claims_digest(&frame);
        Ok(C6ResidualClaimsBoundContext { base: self, claims: frame })
    }
}

fn base_share_context_digest(context: &C6ResidualBaseShareContext) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(BASE_SHARE_CONTEXT_DOMAIN);
    hasher.update(&context.root.digest);
    hasher.update(&context.retained.digest);
    hasher.update(&context.base_share_seed_commitment);
    hasher.update(&context.alpha_seed);
    *hasher.finalize().as_bytes()
}

/// Ordered `(M0,M1)` provider outputs for both MAC coordinates of one
/// installed ProductClosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualProductPublicClaim {
    pub messages: [[Fp2; 2]; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualPublicClaimsFrame {
    manifest_digest: C6ResidualDigest,
    base_share_context_digest: C6ResidualDigest,
    retained_challenges_digest: C6ResidualDigest,
    linear_form_digest: C6ResidualDigest,
    products: Vec<C6ResidualProductPublicClaim>,
    residual: C6PairedDeltaResidual,
    digest: C6ResidualDigest,
}

impl C6ResidualPublicClaimsFrame {
    pub fn products(&self) -> &[C6ResidualProductPublicClaim] {
        &self.products
    }

    pub fn residual(&self) -> C6PairedDeltaResidual {
        self.residual
    }

    pub fn linear_form_digest(&self) -> C6ResidualDigest {
        self.linear_form_digest
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }
}

fn public_claims_digest(frame: &C6ResidualPublicClaimsFrame) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(PUBLIC_CLAIMS_DOMAIN);
    hasher.update(&frame.manifest_digest);
    hasher.update(&frame.base_share_context_digest);
    hasher.update(&frame.retained_challenges_digest);
    hasher.update(&frame.linear_form_digest);
    hasher.update(&(frame.products.len() as u64).to_le_bytes());
    for (closure, product) in frame.products.iter().enumerate() {
        hasher.update(&(closure as u64).to_le_bytes());
        for coordinate in 0..2 {
            hasher.update(&[coordinate as u8]);
            hash_fp2(&mut hasher, product.messages[coordinate][0]);
            hash_fp2(&mut hasher, product.messages[coordinate][1]);
        }
    }
    for (coordinate, residual) in frame.residual.coordinates.iter().enumerate() {
        hasher.update(&[coordinate as u8]);
        hash_fp2(&mut hasher, residual.correction_rlc);
        hash_fp2(&mut hasher, residual.public_tag_rlc);
    }
    *hasher.finalize().as_bytes()
}

/// Typestate proving that all provider-controlled public outputs were fixed
/// before the independent relation seed exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualClaimsBoundContext {
    base: C6ResidualBaseShareContext,
    claims: C6ResidualPublicClaimsFrame,
}

impl C6ResidualClaimsBoundContext {
    pub fn claims(&self) -> &C6ResidualPublicClaimsFrame {
        &self.claims
    }

    pub fn release_relation_seed(
        self,
        operation_plan: &C6InstalledOperationPlan,
        relation_seed: [u8; 32],
    ) -> C6ResidualResult<C6ResidualRelationChallenges> {
        self.base.root.manifest.validate(operation_plan)?;
        if relation_seed == [0; 32] {
            return Err(C6ResidualError::new("C6 residual relation seed is zero"));
        }
        let mut commitment_hasher = blake3::Hasher::new_derive_key(VERIFIER_SEED_COMMITMENT_DOMAIN);
        commitment_hasher.update(&relation_seed);
        let relation_seed_commitment = *commitment_hasher.finalize().as_bytes();
        if relation_seed_commitment == self.base.base_share_seed_commitment {
            return Err(C6ResidualError::new(
                "C6 residual relation seed reuses the base-share seed",
            ));
        }

        let mut context_hasher = blake3::Hasher::new_derive_key(RELATION_CONTEXT_DOMAIN);
        context_hasher.update(&self.base.digest);
        context_hasher.update(&self.claims.digest);
        context_hasher.update(&relation_seed);
        let context_seed = *context_hasher.finalize().as_bytes();

        let mut terminal_schedules = Vec::with_capacity(C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS);
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    terminal_schedules.push(derive_terminal_weight_schedule(
                        operation_plan,
                        RESIDUAL_RELATION_PROTOCOL_V3,
                        proof_repetition,
                        mac_coordinate,
                        kind,
                        context_seed,
                    )?);
                }
            }
        }
        let terminal_schedules: [C6ResidualTerminalWeightSchedule;
            C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS] =
            terminal_schedules.try_into().map_err(|_| {
                C6ResidualError::new("C6 residual v3 terminal expansion lost a schedule")
            })?;
        let atomic_schedules = std::array::from_fn(|repetition| {
            C6ResidualAtomicWeightSchedule::new(
                self.base.root.manifest.digest,
                self.claims.digest,
                context_seed,
                repetition as u8,
                self.base.root.manifest.atomic_outputs_per_repetition,
            )
        });
        let mut challenges = C6ResidualRelationChallenges {
            claims_bound: self,
            relation_seed_commitment,
            context_seed,
            terminal_schedules,
            atomic_schedules,
            digest: [0; 32],
        };
        challenges.digest = relation_challenges_digest(&challenges);
        challenges.validate(operation_plan)?;
        Ok(challenges)
    }
}

/// Non-materialized atomic-weight stream for one complete relation
/// repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicWeightSchedule {
    manifest_digest: C6ResidualDigest,
    public_claims_digest: C6ResidualDigest,
    context_seed: [u8; 32],
    proof_repetition: u8,
    stream_domain: u64,
    output_count: u64,
    digest: C6ResidualDigest,
}

impl C6ResidualAtomicWeightSchedule {
    fn new(
        manifest_digest: C6ResidualDigest,
        public_claims_digest: C6ResidualDigest,
        context_seed: [u8; 32],
        proof_repetition: u8,
        output_count: u64,
    ) -> Self {
        let stream_domain = ATOMIC_WEIGHT_STREAM_DOMAINS[usize::from(proof_repetition)];
        let mut schedule = Self {
            manifest_digest,
            public_claims_digest,
            context_seed,
            proof_repetition,
            stream_domain,
            output_count,
            digest: [0; 32],
        };
        schedule.digest = atomic_weight_schedule_digest(&schedule);
        schedule
    }

    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn stream_domain(&self) -> u64 {
        self.stream_domain
    }

    pub fn output_count(&self) -> u64 {
        self.output_count
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn stream(&self) -> FpStream {
        FpStream::domain_separated(self.context_seed, self.stream_domain)
    }
}

fn atomic_weight_schedule_digest(schedule: &C6ResidualAtomicWeightSchedule) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(ATOMIC_WEIGHT_SCHEDULE_DOMAIN);
    hasher.update(&schedule.manifest_digest);
    hasher.update(&schedule.public_claims_digest);
    hasher.update(&[schedule.proof_repetition]);
    hasher.update(&schedule.stream_domain.to_le_bytes());
    hasher.update(&schedule.output_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualRelationChallenges {
    claims_bound: C6ResidualClaimsBoundContext,
    relation_seed_commitment: C6ResidualDigest,
    context_seed: [u8; 32],
    terminal_schedules: [C6ResidualTerminalWeightSchedule; C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS],
    atomic_schedules: [C6ResidualAtomicWeightSchedule; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    digest: C6ResidualDigest,
}

impl C6ResidualRelationChallenges {
    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        &self.claims_bound.base.root.manifest
    }

    pub fn base_share_context(&self) -> &C6ResidualBaseShareContext {
        &self.claims_bound.base
    }

    pub fn claims(&self) -> &C6ResidualPublicClaimsFrame {
        &self.claims_bound.claims
    }

    pub fn relation_seed_commitment(&self) -> C6ResidualDigest {
        self.relation_seed_commitment
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn terminal_schedule(
        &self,
        proof_repetition: u8,
        mac_coordinate: u8,
        kind: C6ResidualTerminalFormKind,
    ) -> C6ResidualResult<&C6ResidualTerminalWeightSchedule> {
        if proof_repetition >= C6_RESIDUAL_PROOF_REPETITIONS
            || mac_coordinate >= C6_RESIDUAL_MAC_COORDINATES
        {
            return Err(C6ResidualError::new(
                "C6 residual v3 terminal schedule index is out of range",
            ));
        }
        let index = usize::from(proof_repetition)
            .checked_mul(usize::from(C6_RESIDUAL_MAC_COORDINATES))
            .and_then(|base| base.checked_add(usize::from(mac_coordinate)))
            .and_then(|base| base.checked_mul(C6_RESIDUAL_TERMINAL_FORM_KINDS))
            .and_then(|base| base.checked_add(kind.stream_index()))
            .ok_or_else(|| C6ResidualError::new("C6 residual v3 schedule index overflows"))?;
        self.terminal_schedules
            .get(index)
            .ok_or_else(|| C6ResidualError::new("C6 residual v3 schedule is missing"))
    }

    pub fn atomic_schedule(
        &self,
        proof_repetition: u8,
    ) -> C6ResidualResult<&C6ResidualAtomicWeightSchedule> {
        self.atomic_schedules
            .get(usize::from(proof_repetition))
            .ok_or_else(|| C6ResidualError::new("C6 residual atomic repetition is out of range"))
    }

    fn validate(&self, operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<()> {
        self.manifest().validate(operation_plan)?;
        if self.relation_seed_commitment == [0; 32]
            || self.context_seed == [0; 32]
            || self.claims().digest == [0; 32]
            || self.claims().digest != public_claims_digest(self.claims())
            || self.digest == [0; 32]
            || self.digest != relation_challenges_digest(self)
        {
            return Err(C6ResidualError::new("C6 residual relation-challenge binding mismatch"));
        }
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            let atomic = self.atomic_schedule(proof_repetition)?;
            if atomic.proof_repetition != proof_repetition
                || atomic.stream_domain
                    != ATOMIC_WEIGHT_STREAM_DOMAINS[usize::from(proof_repetition)]
                || atomic.output_count != self.manifest().atomic_outputs_per_repetition
                || atomic.digest != atomic_weight_schedule_digest(atomic)
            {
                return Err(C6ResidualError::new(
                    "C6 residual atomic-weight schedule binding mismatch",
                ));
            }
            for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    let schedule =
                        self.terminal_schedule(proof_repetition, mac_coordinate, kind)?;
                    if schedule.protocol_version != RESIDUAL_RELATION_PROTOCOL_V3
                        || schedule.proof_repetition != proof_repetition
                        || schedule.mac_coordinate != mac_coordinate
                        || schedule.kind != kind
                    {
                        return Err(C6ResidualError::new(
                            "C6 residual v3 terminal streams are swapped",
                        ));
                    }
                    schedule.validate(operation_plan)?;
                }
            }
        }
        Ok(())
    }
}

fn relation_challenges_digest(challenges: &C6ResidualRelationChallenges) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(RELATION_CHALLENGES_DOMAIN);
    hasher.update(&challenges.claims_bound.base.root.manifest.digest);
    hasher.update(&challenges.claims_bound.base.digest);
    hasher.update(&challenges.claims_bound.claims.digest);
    hasher.update(&challenges.relation_seed_commitment);
    hasher.update(&challenges.context_seed);
    for schedule in &challenges.terminal_schedules {
        hasher.update(&[schedule.proof_repetition, schedule.mac_coordinate, schedule.kind as u8]);
        hasher.update(&schedule.digest);
    }
    for schedule in &challenges.atomic_schedules {
        hasher.update(&[schedule.proof_repetition]);
        hasher.update(&schedule.digest);
    }
    *hasher.finalize().as_bytes()
}

pub const C6_RESIDUAL_RELATION_LEAF_TABLES: usize = 8;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualAtomicFamily {
    SourceGrammar = 0,
    Affine = 1,
    Reverse = 2,
    RawCopy = 3,
    Product = 4,
    Zero = 5,
    LeafTail = 6,
    AuxiliaryTail = 7,
}

impl C6ResidualAtomicFamily {
    pub const ALL: [Self; 8] = [
        Self::SourceGrammar,
        Self::Affine,
        Self::Reverse,
        Self::RawCopy,
        Self::Product,
        Self::Zero,
        Self::LeafTail,
        Self::AuxiliaryTail,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualAtomicCoefficientTarget {
    LeafLinear { table: u8, row: u32 },
    AuxiliaryLinear { table: u8, row: u32 },
    AuxiliaryQuadratic { lhs: u8, rhs: u8, row: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicOutputEvent {
    pub proof_repetition: u8,
    pub output_ordinal: u64,
    pub family: C6ResidualAtomicFamily,
    pub weight: Fp2,
    pub weighted_public_constant: Fp2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicCoefficientEvent {
    pub proof_repetition: u8,
    pub output_ordinal: u64,
    pub family: C6ResidualAtomicFamily,
    pub target: C6ResidualAtomicCoefficientTarget,
    pub coefficient: Fp2,
}

pub trait C6ResidualAtomicEventSink {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError>;

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicReplaySummary {
    proof_repetition: u8,
    target: Fp2,
    family_outputs: [u64; 8],
    family_coefficient_writes: [u64; 8],
    atomic_outputs: u64,
    coefficient_writes: u64,
    semantic_digest: C6ResidualDigest,
}

impl C6ResidualAtomicReplaySummary {
    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn family_outputs(&self) -> &[u64; 8] {
        &self.family_outputs
    }

    pub fn family_coefficient_writes(&self) -> &[u64; 8] {
        &self.family_coefficient_writes
    }

    pub fn atomic_outputs(&self) -> u64 {
        self.atomic_outputs
    }

    pub fn coefficient_writes(&self) -> u64 {
        self.coefficient_writes
    }

    pub fn semantic_digest(&self) -> C6ResidualDigest {
        self.semantic_digest
    }
}

/// Full scaled witness used only by the differential reference compiler.
///
/// Production code must stream the same coefficients against committed
/// wrapper tables and must never materialize these arrays at T1 capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualRelationReferenceWitness {
    manifest_digest: C6ResidualDigest,
    leaf_tables: [Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_tables: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize],
    digest: C6ResidualDigest,
}

impl C6ResidualRelationReferenceWitness {
    pub fn from_live(
        manifest: &C6ResidualRelationManifest,
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> C6ResidualResult<Self> {
        if manifest.production_geometry {
            return Err(C6ResidualError::new(
                "C6 production relation witness must use the fused streaming compiler",
            ));
        }
        let leaf_entries = usize::try_from(manifest.leaf_entries)
            .map_err(|_| C6ResidualError::new("C6 reference leaf capacity exceeds usize"))?;
        let auxiliary_entries = usize::try_from(manifest.auxiliary_entries)
            .map_err(|_| C6ResidualError::new("C6 reference auxiliary capacity exceeds usize"))?;
        if leaf.source_schedule_digest != manifest.topology.source_schedule_digest
            || leaf.source_count != manifest.topology.source_count
            || leaf.product_mask_count as usize != manifest.product_mask_sources.len()
            || closure.census.product_closures != manifest.topology.product_closure_count
            || closure.census.product_triples != manifest.topology.product_triple_count
            || closure.census.zero_roots != manifest.topology.zero_root_count
            || closure.values.len()
                != usize::try_from(
                    manifest
                        .raw_copy_entries
                        .checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES)
                        .ok_or_else(|| {
                            C6ResidualError::new("C6 reference closure length overflows")
                        })?,
                )
                .map_err(|_| C6ResidualError::new("C6 reference closure length exceeds usize"))?
            || auxiliary.closure_witness_digest != closure.witness_digest
            || auxiliary.census.product_rows != manifest.topology.product_triple_count
            || auxiliary.census.zero_rows != u64::from(manifest.topology.zero_root_count)
        {
            return Err(C6ResidualError::new("C6 reference witness bindings differ from C6RLM1"));
        }

        let mut leaf_tables = std::array::from_fn(|_| vec![Fp2::ZERO; leaf_entries]);
        for column in C6ResidualLeafColumn::ALL {
            leaf_tables[column.index()][..leaf.source_count as usize]
                .copy_from_slice(leaf.column(column));
        }
        leaf_tables[7][..closure.values.len()].copy_from_slice(&closure.values);

        let mut auxiliary_tables = std::array::from_fn(|_| vec![Fp2::ZERO; auxiliary_entries]);
        for lane in C6ResidualAuxiliaryLane::ALL {
            let live = auxiliary.lane(lane);
            if live.len() > auxiliary_entries {
                return Err(C6ResidualError::new(
                    "C6 reference auxiliary lane exceeds scaled capacity",
                ));
            }
            auxiliary_tables[lane.index()][..live.len()].copy_from_slice(live);
        }

        let mut witness = Self {
            manifest_digest: manifest.digest,
            leaf_tables,
            auxiliary_tables,
            digest: [0; 32],
        };
        witness.digest = relation_reference_witness_digest(&witness);
        Ok(witness)
    }

    pub fn leaf_tables(&self) -> &[Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES] {
        &self.leaf_tables
    }

    pub fn auxiliary_tables(&self) -> &[Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize] {
        &self.auxiliary_tables
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    fn validate(&self, manifest: &C6ResidualRelationManifest) -> C6ResidualResult<()> {
        let leaf_entries = usize::try_from(manifest.leaf_entries)
            .map_err(|_| C6ResidualError::new("C6 reference leaf capacity exceeds usize"))?;
        let auxiliary_entries = usize::try_from(manifest.auxiliary_entries)
            .map_err(|_| C6ResidualError::new("C6 reference auxiliary capacity exceeds usize"))?;
        if self.manifest_digest != manifest.digest
            || self.leaf_tables.iter().any(|table| table.len() != leaf_entries)
            || self.auxiliary_tables.iter().any(|table| table.len() != auxiliary_entries)
            || self.digest == [0; 32]
            || self.digest != relation_reference_witness_digest(self)
        {
            return Err(C6ResidualError::new(
                "C6 residual reference witness digest/geometry mismatch",
            ));
        }
        Ok(())
    }
}

fn relation_reference_witness_digest(
    witness: &C6ResidualRelationReferenceWitness,
) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/residual-reference-witness/v1");
    hasher.update(&witness.manifest_digest);
    for (table, values) in witness.leaf_tables.iter().enumerate() {
        hasher.update(&[0, table as u8]);
        hasher.update(&(values.len() as u64).to_le_bytes());
        for value in values {
            hash_fp2(&mut hasher, *value);
        }
    }
    for (table, values) in witness.auxiliary_tables.iter().enumerate() {
        hasher.update(&[1, table as u8]);
        hasher.update(&(values.len() as u64).to_le_bytes());
        for value in values {
            hash_fp2(&mut hasher, *value);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Canonical coefficient MLEs for one complete residual repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicRelationStatement {
    proof_repetition: u8,
    manifest_digest: C6ResidualDigest,
    relation_challenges_digest: C6ResidualDigest,
    target: Fp2,
    leaf_linear: [Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_linear: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize],
    auxiliary_quadratic: Vec<((u8, u8), Vec<Fp2>)>,
    atomic_outputs_consumed: u64,
    digest: C6ResidualDigest,
}

impl C6ResidualAtomicRelationStatement {
    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn leaf_linear(&self) -> &[Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES] {
        &self.leaf_linear
    }

    pub fn auxiliary_linear(&self) -> &[Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize] {
        &self.auxiliary_linear
    }

    pub fn auxiliary_quadratic(&self) -> &[((u8, u8), Vec<Fp2>)] {
        &self.auxiliary_quadratic
    }

    pub fn atomic_outputs_consumed(&self) -> u64 {
        self.atomic_outputs_consumed
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn evaluate(&self, witness: &C6ResidualRelationReferenceWitness) -> C6ResidualResult<Fp2> {
        if self.manifest_digest != witness.manifest_digest {
            return Err(C6ResidualError::new(
                "C6 atomic statement and reference witness use different manifests",
            ));
        }
        let mut value = Fp2::ZERO;
        for (coefficients, table) in self.leaf_linear.iter().zip(&witness.leaf_tables) {
            value += coefficients
                .iter()
                .zip(table)
                .fold(Fp2::ZERO, |sum, (&coefficient, &entry)| sum + coefficient * entry);
        }
        for (coefficients, table) in self.auxiliary_linear.iter().zip(&witness.auxiliary_tables) {
            value += coefficients
                .iter()
                .zip(table)
                .fold(Fp2::ZERO, |sum, (&coefficient, &entry)| sum + coefficient * entry);
        }
        for ((lhs, rhs), coefficients) in &self.auxiliary_quadratic {
            value += coefficients
                .iter()
                .zip(&witness.auxiliary_tables[usize::from(*lhs)])
                .zip(&witness.auxiliary_tables[usize::from(*rhs)])
                .fold(Fp2::ZERO, |sum, ((&coefficient, &lhs), &rhs)| sum + coefficient * lhs * rhs);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualAtomicReferenceCompilation {
    statements: [C6ResidualAtomicRelationStatement; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    family_outputs: [[u64; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    family_weighted_residuals: [[Fp2; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    expression_evaluations: [Fp2; C6_RESIDUAL_PROOF_REPETITIONS as usize],
    digest: C6ResidualDigest,
}

impl C6ResidualAtomicReferenceCompilation {
    pub fn statements(
        &self,
    ) -> &[C6ResidualAtomicRelationStatement; C6_RESIDUAL_PROOF_REPETITIONS as usize] {
        &self.statements
    }

    pub fn family_outputs(&self) -> &[[u64; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] {
        &self.family_outputs
    }

    pub fn family_weighted_residuals(&self) -> &[[Fp2; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] {
        &self.family_weighted_residuals
    }

    pub fn expression_evaluations(&self) -> &[Fp2; C6_RESIDUAL_PROOF_REPETITIONS as usize] {
        &self.expression_evaluations
    }

    pub fn is_satisfied(&self) -> bool {
        self.statements.iter().enumerate().all(|(repetition, statement)| {
            self.expression_evaluations[repetition] == statement.target
                && self.family_weighted_residuals[repetition]
                    .iter()
                    .all(|residual| *residual == Fp2::ZERO)
        })
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }
}

struct C6AtomicEventAudit {
    hasher: blake3::Hasher,
}

impl C6AtomicEventAudit {
    fn new(proof_repetition: u8) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(ATOMIC_EVENT_AUDIT_DOMAIN);
        hasher.update(&[proof_repetition]);
        Self { hasher }
    }

    fn output(&mut self, event: C6ResidualAtomicOutputEvent) {
        self.hasher.update(&[0, event.proof_repetition, event.family as u8]);
        self.hasher.update(&event.output_ordinal.to_le_bytes());
        hash_fp2(&mut self.hasher, event.weight);
        hash_fp2(&mut self.hasher, event.weighted_public_constant);
    }

    fn coefficient(&mut self, event: C6ResidualAtomicCoefficientEvent) {
        self.hasher.update(&[1, event.proof_repetition, event.family as u8]);
        self.hasher.update(&event.output_ordinal.to_le_bytes());
        match event.target {
            C6ResidualAtomicCoefficientTarget::LeafLinear { table, row } => {
                self.hasher.update(&[0, table, 0]);
                self.hasher.update(&row.to_le_bytes());
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryLinear { table, row } => {
                self.hasher.update(&[1, table, 0]);
                self.hasher.update(&row.to_le_bytes());
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic { lhs, rhs, row } => {
                self.hasher.update(&[2, lhs, rhs]);
                self.hasher.update(&row.to_le_bytes());
            }
        }
        hash_fp2(&mut self.hasher, event.coefficient);
    }

    fn digest(&self) -> C6ResidualDigest {
        *self.hasher.finalize().as_bytes()
    }
}

pub struct C6ResidualAtomicEventAuditSink {
    proof_repetition: u8,
    audit: C6AtomicEventAudit,
}

impl C6ResidualAtomicEventAuditSink {
    pub fn new(proof_repetition: u8) -> Self {
        Self { proof_repetition, audit: C6AtomicEventAudit::new(proof_repetition) }
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.audit.digest()
    }
}

impl C6ResidualAtomicEventSink for C6ResidualAtomicEventAuditSink {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new("C6 atomic audit sink received a swapped repetition"));
        }
        self.audit.output(event);
        Ok(())
    }

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new(
                "C6 atomic audit coefficient has a swapped repetition",
            ));
        }
        self.audit.coefficient(event);
        Ok(())
    }
}

struct C6AtomicReferenceSink<'a> {
    witness: &'a C6ResidualRelationReferenceWitness,
    family_residuals: [Fp2; 8],
    leaf_linear: [Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_linear: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize],
    auxiliary_quadratic: BTreeMap<(u8, u8), Vec<Fp2>>,
    audit: C6AtomicEventAudit,
}

impl<'a> C6AtomicReferenceSink<'a> {
    fn new(
        proof_repetition: u8,
        witness: &'a C6ResidualRelationReferenceWitness,
        leaf_entries: usize,
        auxiliary_entries: usize,
    ) -> Self {
        Self {
            witness,
            family_residuals: [Fp2::ZERO; 8],
            leaf_linear: std::array::from_fn(|_| vec![Fp2::ZERO; leaf_entries]),
            auxiliary_linear: std::array::from_fn(|_| vec![Fp2::ZERO; auxiliary_entries]),
            auxiliary_quadratic: C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
                .into_iter()
                .map(|factors| (factors, vec![Fp2::ZERO; auxiliary_entries]))
                .collect(),
            audit: C6AtomicEventAudit::new(proof_repetition),
        }
    }
}

impl C6ResidualAtomicEventSink for C6AtomicReferenceSink<'_> {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError> {
        self.family_residuals[event.family.index()] += event.weighted_public_constant;
        self.audit.output(event);
        Ok(())
    }

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError> {
        let witness_value = match event.target {
            C6ResidualAtomicCoefficientTarget::LeafLinear { table, row } => {
                let table = usize::from(table);
                let row = row as usize;
                let coefficient = self
                    .leaf_linear
                    .get_mut(table)
                    .and_then(|values| values.get_mut(row))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 atomic reference leaf event is out of range")
                    })?;
                *coefficient += event.coefficient;
                *self.witness.leaf_tables.get(table).and_then(|values| values.get(row)).ok_or_else(
                    || C6ResidualError::new("C6 atomic reference leaf witness is out of range"),
                )?
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryLinear { table, row } => {
                let table = usize::from(table);
                let row = row as usize;
                let coefficient = self
                    .auxiliary_linear
                    .get_mut(table)
                    .and_then(|values| values.get_mut(row))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 atomic reference auxiliary event is out of range")
                    })?;
                *coefficient += event.coefficient;
                *self
                    .witness
                    .auxiliary_tables
                    .get(table)
                    .and_then(|values| values.get(row))
                    .ok_or_else(|| {
                        C6ResidualError::new(
                            "C6 atomic reference auxiliary witness is out of range",
                        )
                    })?
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic { lhs, rhs, row } => {
                let row = row as usize;
                let coefficient = self
                    .auxiliary_quadratic
                    .get_mut(&(lhs, rhs))
                    .and_then(|values| values.get_mut(row))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 atomic reference quadratic event is out of range")
                    })?;
                *coefficient += event.coefficient;
                let lhs = *self
                    .witness
                    .auxiliary_tables
                    .get(usize::from(lhs))
                    .and_then(|values| values.get(row))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 atomic reference quadratic lhs is out of range")
                    })?;
                let rhs = *self
                    .witness
                    .auxiliary_tables
                    .get(usize::from(rhs))
                    .and_then(|values| values.get(row))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 atomic reference quadratic rhs is out of range")
                    })?;
                lhs * rhs
            }
        };
        self.family_residuals[event.family.index()] += event.coefficient * witness_value;
        self.audit.coefficient(event);
        Ok(())
    }
}

struct C6AtomicEventEmitter<'a, S: C6ResidualAtomicEventSink> {
    proof_repetition: u8,
    leaf_entries: u64,
    auxiliary_entries: u64,
    stream: FpStream,
    sink: &'a mut S,
    family_outputs: [u64; 8],
    family_coefficient_writes: [u64; 8],
    atomic_outputs: u64,
    coefficient_writes: u64,
    weighted_public_constant: Fp2,
    current_output: Option<(u64, C6ResidualAtomicFamily)>,
}

impl<'a, S: C6ResidualAtomicEventSink> C6AtomicEventEmitter<'a, S> {
    fn new(
        proof_repetition: u8,
        manifest: &C6ResidualRelationManifest,
        schedule: &C6ResidualAtomicWeightSchedule,
        sink: &'a mut S,
    ) -> Self {
        Self {
            proof_repetition,
            leaf_entries: manifest.leaf_entries,
            auxiliary_entries: manifest.auxiliary_entries,
            stream: schedule.stream(),
            sink,
            family_outputs: [0; 8],
            family_coefficient_writes: [0; 8],
            atomic_outputs: 0,
            coefficient_writes: 0,
            weighted_public_constant: Fp2::ZERO,
            current_output: None,
        }
    }

    fn next(
        &mut self,
        family: C6ResidualAtomicFamily,
        public_constant: Fp2,
    ) -> C6ResidualResult<Fp2> {
        let weight = self.stream.next_fp2();
        let output_ordinal = self.atomic_outputs;
        let weighted_public_constant = weight * public_constant;
        self.sink.output(C6ResidualAtomicOutputEvent {
            proof_repetition: self.proof_repetition,
            output_ordinal,
            family,
            weight,
            weighted_public_constant,
        })?;
        self.atomic_outputs = self
            .atomic_outputs
            .checked_add(1)
            .ok_or_else(|| C6ResidualError::new("C6 atomic output census overflows"))?;
        self.family_outputs[family.index()] = self.family_outputs[family.index()]
            .checked_add(1)
            .ok_or_else(|| C6ResidualError::new("C6 atomic family output census overflows"))?;
        self.weighted_public_constant += weighted_public_constant;
        self.current_output = Some((output_ordinal, family));
        Ok(weight)
    }

    fn add_leaf(&mut self, table: usize, row: usize, coefficient: Fp2) -> C6ResidualResult<()> {
        if table >= C6_RESIDUAL_RELATION_LEAF_TABLES || row as u64 >= self.leaf_entries {
            return Err(C6ResidualError::new("C6 atomic leaf coefficient target is out of range"));
        }
        self.write(
            C6ResidualAtomicCoefficientTarget::LeafLinear {
                table: table as u8,
                row: u32::try_from(row)
                    .map_err(|_| C6ResidualError::new("C6 atomic leaf row exceeds u32"))?,
            },
            coefficient,
        )
    }

    fn add_auxiliary(
        &mut self,
        table: usize,
        row: usize,
        coefficient: Fp2,
    ) -> C6ResidualResult<()> {
        if table >= C6_RESIDUAL_AUXILIARY_LANES as usize || row as u64 >= self.auxiliary_entries {
            return Err(C6ResidualError::new(
                "C6 atomic auxiliary coefficient target is out of range",
            ));
        }
        self.write(
            C6ResidualAtomicCoefficientTarget::AuxiliaryLinear {
                table: table as u8,
                row: u32::try_from(row)
                    .map_err(|_| C6ResidualError::new("C6 atomic auxiliary row exceeds u32"))?,
            },
            coefficient,
        )
    }

    fn add_quadratic(
        &mut self,
        lhs: u8,
        rhs: u8,
        row: usize,
        coefficient: Fp2,
    ) -> C6ResidualResult<()> {
        if !C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.contains(&(lhs, rhs))
            || row as u64 >= self.auxiliary_entries
        {
            return Err(C6ResidualError::new(
                "C6 atomic quadratic coefficient target is out of range",
            ));
        }
        self.write(
            C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic {
                lhs,
                rhs,
                row: u32::try_from(row)
                    .map_err(|_| C6ResidualError::new("C6 atomic quadratic row exceeds u32"))?,
            },
            coefficient,
        )
    }

    fn write(
        &mut self,
        target: C6ResidualAtomicCoefficientTarget,
        coefficient: Fp2,
    ) -> C6ResidualResult<()> {
        let (output_ordinal, family) = self
            .current_output
            .ok_or_else(|| C6ResidualError::new("C6 coefficient precedes its atomic output"))?;
        self.sink.coefficient(C6ResidualAtomicCoefficientEvent {
            proof_repetition: self.proof_repetition,
            output_ordinal,
            family,
            target,
            coefficient,
        })?;
        self.coefficient_writes = self
            .coefficient_writes
            .checked_add(1)
            .ok_or_else(|| C6ResidualError::new("C6 coefficient-write census overflows"))?;
        self.family_coefficient_writes[family.index()] = self.family_coefficient_writes
            [family.index()]
        .checked_add(1)
        .ok_or_else(|| C6ResidualError::new("C6 family coefficient-write census overflows"))?;
        Ok(())
    }
}

fn expected_atomic_family_outputs(
    manifest: &C6ResidualRelationManifest,
) -> C6ResidualResult<[u64; 8]> {
    Ok([
        u64::from(manifest.topology.source_count)
            .checked_mul(3)
            .ok_or_else(|| C6ResidualError::new("C6 SourceGrammar output census overflows"))?,
        4,
        4,
        manifest.raw_copy_entries,
        u64::from(manifest.topology.product_closure_count)
            .checked_mul(6)
            .ok_or_else(|| C6ResidualError::new("C6 Product output census overflows"))?,
        2,
        manifest.leaf_tail_outputs,
        manifest.auxiliary_tail_outputs,
    ])
}

fn expected_atomic_family_coefficient_writes(
    manifest: &C6ResidualRelationManifest,
) -> C6ResidualResult<[u64; 8]> {
    let sources = u64::from(manifest.topology.source_count);
    let masks = u64::try_from(manifest.product_mask_sources.len())
        .map_err(|_| C6ResidualError::new("C6 ProductMask census exceeds u64"))?;
    let direct = sources
        .checked_sub(masks)
        .ok_or_else(|| C6ResidualError::new("C6 direct-source census underflows"))?;
    let triples = manifest.topology.product_triple_count;
    let closures = u64::from(manifest.topology.product_closure_count);
    let zeros = u64::from(manifest.topology.zero_root_count);
    let checked_sum = |terms: &[u64], label: &str| {
        terms.iter().try_fold(0u64, |sum, term| {
            sum.checked_add(*term)
                .ok_or_else(|| C6ResidualError::new(format!("{label} write census overflows")))
        })
    };
    let checked_mul = |value: u64, factor: u64, label: &str| {
        value
            .checked_mul(factor)
            .ok_or_else(|| C6ResidualError::new(format!("{label} write census overflows")))
    };
    Ok([
        checked_sum(
            &[
                checked_mul(direct, 6, "C6 SourceGrammar")?,
                checked_mul(masks, 3, "C6 SourceGrammar")?,
            ],
            "C6 SourceGrammar",
        )?,
        checked_mul(sources, 6, "C6 Affine")?,
        checked_sum(
            &[
                checked_mul(sources, 4, "C6 Reverse")?,
                checked_mul(triples, 12, "C6 Reverse")?,
                checked_mul(zeros, 4, "C6 Reverse")?,
            ],
            "C6 Reverse",
        )?,
        checked_mul(manifest.raw_copy_entries, 2, "C6 RawCopy")?,
        checked_sum(
            &[checked_mul(triples, 12, "C6 Product")?, checked_mul(closures, 4, "C6 Product")?],
            "C6 Product",
        )?,
        checked_mul(zeros, 2, "C6 Zero")?,
        manifest.leaf_tail_outputs,
        manifest.auxiliary_tail_outputs,
    ])
}

/// Replay the exact v3 atomic compiler grammar into a caller-owned sink.
///
/// The replay is witness-independent.  It accepts production geometry, owns
/// every atomic weight and emits no materialized coefficient array.
#[allow(clippy::too_many_arguments)]
pub fn replay_c6_residual_atomic_events<S: C6ResidualAtomicEventSink>(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    proof_repetition: u8,
    sink: &mut S,
) -> C6ResidualResult<C6ResidualAtomicReplaySummary> {
    challenges.validate(operation_plan)?;
    let manifest = challenges.manifest();
    if linear.operation_plan_artifact_digest != manifest.operation_plan_artifact_digest
        || linear.topology != manifest.topology
        || linear.instance != manifest.instance
        || linear.product_mask_sources != manifest.product_mask_sources
        || linear.linear_form_digest != challenges.claims().linear_form_digest
    {
        return Err(C6ResidualError::new(
            "C6 atomic event replay linear form differs from manifest/public claims",
        ));
    }
    let atomic_schedule = challenges.atomic_schedule(proof_repetition)?;
    if atomic_schedule.output_count != manifest.atomic_outputs_per_repetition {
        return Err(C6ResidualError::new(
            "C6 atomic event replay schedule differs from the manifest",
        ));
    }

    let source_count = usize::try_from(manifest.topology.source_count)
        .map_err(|_| C6ResidualError::new("C6 source census exceeds usize"))?;
    let leaf_entries = usize::try_from(manifest.leaf_entries)
        .map_err(|_| C6ResidualError::new("C6 leaf entry census exceeds usize"))?;
    let auxiliary_entries = usize::try_from(manifest.auxiliary_entries)
        .map_err(|_| C6ResidualError::new("C6 auxiliary entry census exceeds usize"))?;
    let product_triples = usize::try_from(manifest.topology.product_triple_count)
        .map_err(|_| C6ResidualError::new("C6 product-triple census exceeds usize"))?;
    let zero_roots = usize::try_from(manifest.topology.zero_root_count)
        .map_err(|_| C6ResidualError::new("C6 zero-root census exceeds usize"))?;
    let mut emitter = C6AtomicEventEmitter::new(proof_repetition, manifest, atomic_schedule, sink);

    for source in 0..source_count {
        let is_mask = manifest.product_mask_sources.binary_search(&(source as u32)).is_ok();
        let direct = !is_mask;

        let weight = emitter.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO)?;
        if direct {
            emitter.add_leaf(0, source, weight)?;
            emitter.add_leaf(1, source, Fp2::ZERO - weight)?;
            emitter.add_leaf(3, source, Fp2::ZERO - weight)?;
        } else {
            emitter.add_leaf(3, source, weight)?;
        }

        let weight = emitter.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO)?;
        if direct {
            emitter.add_leaf(0, source, weight)?;
            emitter.add_leaf(4, source, Fp2::ZERO - weight)?;
            emitter.add_leaf(6, source, Fp2::ZERO - weight)?;
        } else {
            emitter.add_leaf(6, source, weight)?;
        }

        let weight = emitter.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO)?;
        if is_mask {
            emitter.add_leaf(0, source, weight)?;
        }
    }

    for coordinate in 0..2u8 {
        let (r_table, m_table, d_table) =
            if coordinate == 0 { (1usize, 2usize, 3usize) } else { (4, 5, 6) };
        let residual = challenges.claims().residual.coordinates[usize::from(coordinate)];

        let weight = emitter.next(
            C6ResidualAtomicFamily::Affine,
            linear.public_plaintext - residual.correction_rlc,
        )?;
        let mut alphas = challenges.base_share_context().alpha_stream(coordinate)?;
        for (source, &linear_coefficient) in linear.leaf_coefficients.iter().enumerate() {
            let alpha = alphas.next_fp2();
            emitter.add_leaf(d_table, source, weight * linear_coefficient)?;
            emitter.add_leaf(r_table, source, Fp2::ZERO - weight * alpha)?;
        }

        let weight =
            emitter.next(C6ResidualAtomicFamily::Affine, Fp2::ZERO - residual.public_tag_rlc)?;
        let mut alphas = challenges.base_share_context().alpha_stream(coordinate)?;
        for (source, &linear_coefficient) in linear.leaf_coefficients.iter().enumerate() {
            let alpha = alphas.next_fp2();
            emitter.add_leaf(m_table, source, weight * (linear_coefficient + alpha))?;
        }
    }

    for coordinate in 0..2u8 {
        for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag] {
            let schedule = challenges.terminal_schedule(proof_repetition, coordinate, kind)?;
            let form = C6CompiledTerminalLinearForm::compile(
                operation_plan,
                extraction,
                runtime,
                schedule,
            )?;
            if form.protocol_version != RESIDUAL_RELATION_PROTOCOL_V3
                || form.topology != manifest.topology
                || form.instance != manifest.instance
                || form.leaf_coefficients.len() != source_count
            {
                return Err(C6ResidualError::new(
                    "C6 atomic event replay terminal form differs from C6RLM1",
                ));
            }
            let outer = emitter.next(C6ResidualAtomicFamily::Reverse, form.public_plaintext)?;
            for (source, &coefficient) in form.leaf_coefficients.iter().enumerate() {
                let is_mask = manifest.product_mask_sources.binary_search(&(source as u32)).is_ok();
                let table = match kind {
                    C6ResidualTerminalFormKind::Plaintext => {
                        if is_mask {
                            if coordinate == 0 {
                                1
                            } else {
                                4
                            }
                        } else {
                            0
                        }
                    }
                    C6ResidualTerminalFormKind::Tag => {
                        if coordinate == 0 {
                            2
                        } else {
                            5
                        }
                    }
                };
                emitter.add_leaf(table, source, outer * coefficient)?;
            }
            let lane_base = usize::from(coordinate) * 6;
            for (triple, weights) in schedule.product_weights.iter().enumerate() {
                let lanes = match kind {
                    C6ResidualTerminalFormKind::Plaintext => {
                        [lane_base, lane_base + 2, lane_base + 4]
                    }
                    C6ResidualTerminalFormKind::Tag => {
                        [lane_base + 1, lane_base + 3, lane_base + 5]
                    }
                };
                for (lane, terminal_weight) in lanes.into_iter().zip(weights) {
                    emitter.add_auxiliary(lane, triple, Fp2::ZERO - outer * *terminal_weight)?;
                }
            }
            let zero_lane = 12
                + 2 * usize::from(coordinate)
                + usize::from(kind == C6ResidualTerminalFormKind::Tag);
            for (zero, terminal_weight) in schedule.zero_weights.iter().enumerate() {
                emitter.add_auxiliary(zero_lane, zero, Fp2::ZERO - outer * *terminal_weight)?;
            }
        }
    }

    let mut raw_position = 0usize;
    for triple in 0..product_triples {
        for coordinate in 0..2usize {
            for component in 0..6usize {
                let lane = 6 * coordinate + component;
                let weight = emitter.next(C6ResidualAtomicFamily::RawCopy, Fp2::ZERO)?;
                emitter.add_leaf(7, raw_position, weight)?;
                emitter.add_auxiliary(lane, triple, Fp2::ZERO - weight)?;
                raw_position += 1;
            }
        }
    }
    for zero in 0..zero_roots {
        for coordinate in 0..2usize {
            for component in 0..2usize {
                let lane = 12 + 2 * coordinate + component;
                let weight = emitter.next(C6ResidualAtomicFamily::RawCopy, Fp2::ZERO)?;
                emitter.add_leaf(7, raw_position, weight)?;
                emitter.add_auxiliary(lane, zero, Fp2::ZERO - weight)?;
                raw_position += 1;
            }
        }
    }
    if raw_position as u64 != manifest.raw_copy_entries {
        return Err(C6ResidualError::new(
            "C6 atomic event replay raw-copy cursor differs from C6RLM1",
        ));
    }

    let mut triple_cursor = 0usize;
    for (closure, product) in operation_plan.products().iter().enumerate() {
        let chi = challenges.base_share_context().retained.product_challenges[closure];
        let mask_source = manifest.product_mask_sources[closure] as usize;
        for coordinate in 0..2usize {
            let lane_base = 6 * coordinate;
            let r_table = if coordinate == 0 { 1 } else { 4 };
            let m_table = if coordinate == 0 { 2 } else { 5 };
            let messages = challenges.claims().products[closure].messages[coordinate];

            let outer = emitter.next(C6ResidualAtomicFamily::Product, Fp2::ZERO)?;
            let mut power = Fp2::ONE;
            for triple in 0..product.triples().len() {
                power = power * chi;
                let row = triple_cursor + triple;
                emitter.add_quadratic(
                    lane_base as u8,
                    (lane_base + 2) as u8,
                    row,
                    outer * power,
                )?;
                emitter.add_auxiliary(lane_base + 4, row, Fp2::ZERO - outer * power)?;
            }

            let outer = emitter.next(C6ResidualAtomicFamily::Product, Fp2::ZERO - messages[0])?;
            emitter.add_leaf(m_table, mask_source, outer)?;
            let mut power = Fp2::ONE;
            for triple in 0..product.triples().len() {
                power = power * chi;
                let row = triple_cursor + triple;
                emitter.add_quadratic(
                    (lane_base + 1) as u8,
                    (lane_base + 3) as u8,
                    row,
                    outer * power,
                )?;
            }

            let outer = emitter.next(C6ResidualAtomicFamily::Product, Fp2::ZERO - messages[1])?;
            emitter.add_leaf(r_table, mask_source, outer)?;
            let mut power = Fp2::ONE;
            for triple in 0..product.triples().len() {
                power = power * chi;
                let row = triple_cursor + triple;
                emitter.add_quadratic(
                    lane_base as u8,
                    (lane_base + 3) as u8,
                    row,
                    outer * power,
                )?;
                emitter.add_quadratic(
                    (lane_base + 1) as u8,
                    (lane_base + 2) as u8,
                    row,
                    outer * power,
                )?;
                emitter.add_auxiliary(lane_base + 5, row, Fp2::ZERO - outer * power)?;
            }
        }
        triple_cursor += product.triples().len();
    }
    if triple_cursor != product_triples {
        return Err(C6ResidualError::new("C6 atomic event replay ProductClosure cursor mismatch"));
    }

    let zero_weights = challenges.base_share_context().retained.zero_weights(zero_roots);
    for coordinate in 0..2usize {
        let lane = 12 + 2 * coordinate;
        let outer = emitter.next(C6ResidualAtomicFamily::Zero, Fp2::ZERO)?;
        for (zero, weight) in zero_weights.iter().enumerate() {
            emitter.add_auxiliary(lane, zero, outer * *weight)?;
        }
    }

    for table in 0..7usize {
        for row in source_count..leaf_entries {
            let weight = emitter.next(C6ResidualAtomicFamily::LeafTail, Fp2::ZERO)?;
            emitter.add_leaf(table, row, weight)?;
        }
    }
    for row in raw_position..leaf_entries {
        let weight = emitter.next(C6ResidualAtomicFamily::LeafTail, Fp2::ZERO)?;
        emitter.add_leaf(7, row, weight)?;
    }
    for lane in 0..12usize {
        for row in product_triples..auxiliary_entries {
            let weight = emitter.next(C6ResidualAtomicFamily::AuxiliaryTail, Fp2::ZERO)?;
            emitter.add_auxiliary(lane, row, weight)?;
        }
    }
    for lane in 12..16usize {
        for row in zero_roots..auxiliary_entries {
            let weight = emitter.next(C6ResidualAtomicFamily::AuxiliaryTail, Fp2::ZERO)?;
            emitter.add_auxiliary(lane, row, weight)?;
        }
    }

    let expected_outputs = expected_atomic_family_outputs(manifest)?;
    let expected_writes = expected_atomic_family_coefficient_writes(manifest)?;
    if emitter.family_outputs != expected_outputs
        || emitter.family_coefficient_writes != expected_writes
        || emitter.atomic_outputs != manifest.atomic_outputs_per_repetition
        || emitter.atomic_outputs != atomic_schedule.output_count
    {
        return Err(C6ResidualError::new("C6 atomic event replay census differs from C6RLM1"));
    }
    let expected_total_writes = expected_writes.iter().try_fold(0u64, |sum, writes| {
        sum.checked_add(*writes)
            .ok_or_else(|| C6ResidualError::new("C6 atomic total write census overflows"))
    })?;
    if emitter.coefficient_writes != expected_total_writes {
        return Err(C6ResidualError::new("C6 atomic event replay total write census mismatch"));
    }

    let target = Fp2::ZERO - emitter.weighted_public_constant;
    let mut summary = C6ResidualAtomicReplaySummary {
        proof_repetition,
        target,
        family_outputs: emitter.family_outputs,
        family_coefficient_writes: emitter.family_coefficient_writes,
        atomic_outputs: emitter.atomic_outputs,
        coefficient_writes: emitter.coefficient_writes,
        semantic_digest: [0; 32],
    };
    let mut hasher = blake3::Hasher::new_derive_key(ATOMIC_EVENT_COMPLETION_DOMAIN);
    hasher.update(&[1, proof_repetition]);
    hasher.update(&manifest.digest);
    hasher.update(&challenges.digest);
    hasher.update(&linear.linear_form_digest);
    hasher.update(&atomic_schedule.digest);
    hash_fp2(&mut hasher, summary.target);
    for family in C6ResidualAtomicFamily::ALL {
        hasher.update(&[family as u8]);
        hasher.update(&summary.family_outputs[family.index()].to_le_bytes());
        hasher.update(&summary.family_coefficient_writes[family.index()].to_le_bytes());
    }
    hasher.update(&summary.atomic_outputs.to_le_bytes());
    hasher.update(&summary.coefficient_writes.to_le_bytes());
    summary.semantic_digest = *hasher.finalize().as_bytes();
    Ok(summary)
}

/// Materializing scaled differential over the same event replay used by the
/// fused provider/client sinks.  Production geometry is deliberately
/// rejected here; production callers use [`replay_c6_residual_atomic_events`]
/// directly.
#[allow(clippy::too_many_arguments)]
pub fn compile_c6_residual_atomic_relation_reference(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    witness: &C6ResidualRelationReferenceWitness,
) -> C6ResidualResult<C6ResidualAtomicReferenceCompilation> {
    challenges.validate(operation_plan)?;
    let manifest = challenges.manifest();
    if manifest.production_geometry {
        return Err(C6ResidualError::new(
            "C6 atomic reference compiler cannot materialize production coefficient tables",
        ));
    }
    if manifest.leaf_entries > (1 << 20) || manifest.auxiliary_entries > (1 << 16) {
        return Err(C6ResidualError::new(
            "C6 atomic reference compiler exceeds its scaled allocation guard",
        ));
    }
    witness.validate(manifest)?;

    let leaf_entries = usize::try_from(manifest.leaf_entries)
        .map_err(|_| C6ResidualError::new("C6 reference leaf entries exceed usize"))?;
    let auxiliary_entries = usize::try_from(manifest.auxiliary_entries)
        .map_err(|_| C6ResidualError::new("C6 reference auxiliary entries exceed usize"))?;
    let mut statements = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut family_outputs = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut family_residuals = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut expression_evaluations = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);

    for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
        let mut sink =
            C6AtomicReferenceSink::new(proof_repetition, witness, leaf_entries, auxiliary_entries);
        let summary = replay_c6_residual_atomic_events(
            operation_plan,
            extraction,
            runtime,
            linear,
            challenges,
            proof_repetition,
            &mut sink,
        )?;
        if summary.semantic_digest == [0; 32] || sink.audit.digest() == [0; 32] {
            return Err(C6ResidualError::new(
                "C6 atomic event replay produced an empty semantic/audit binding",
            ));
        }
        let auxiliary_quadratic = sink.auxiliary_quadratic.into_iter().collect::<Vec<_>>();
        if auxiliary_quadratic
            .iter()
            .map(|(factors, _)| *factors)
            .ne(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS)
        {
            return Err(C6ResidualError::new(
                "C6 atomic event replay emitted a noncanonical quadratic tuple",
            ));
        }
        let mut statement = C6ResidualAtomicRelationStatement {
            proof_repetition,
            manifest_digest: manifest.digest,
            relation_challenges_digest: challenges.digest,
            target: summary.target,
            leaf_linear: sink.leaf_linear,
            auxiliary_linear: sink.auxiliary_linear,
            auxiliary_quadratic,
            atomic_outputs_consumed: summary.atomic_outputs,
            digest: [0; 32],
        };
        statement.digest = atomic_relation_statement_digest(&statement);
        let expression = statement.evaluate(witness)?;
        let direct = sink.family_residuals.iter().fold(Fp2::ZERO, |sum, residual| sum + *residual);
        if expression - statement.target != direct {
            return Err(C6ResidualError::new(
                "C6 atomic event replay coefficient/source differential mismatch",
            ));
        }
        statements.push(statement);
        family_outputs.push(summary.family_outputs);
        family_residuals.push(sink.family_residuals);
        expression_evaluations.push(expression);
    }

    let statements: [C6ResidualAtomicRelationStatement; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        statements
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic event replay lost a repetition"))?;
    let family_outputs: [[u64; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] = family_outputs
        .try_into()
        .map_err(|_| C6ResidualError::new("C6 atomic event replay lost a family census"))?;
    let family_weighted_residuals: [[Fp2; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        family_residuals
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic event replay lost a differential"))?;
    let expression_evaluations: [Fp2; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        expression_evaluations
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic event replay lost an evaluation"))?;
    let mut compilation = C6ResidualAtomicReferenceCompilation {
        statements,
        family_outputs,
        family_weighted_residuals,
        expression_evaluations,
        digest: [0; 32],
    };
    compilation.digest = atomic_reference_compilation_digest(&compilation);
    Ok(compilation)
}

#[cfg(all(test, feature = "c6-trace"))]
struct C6AtomicReferenceAccumulator {
    stream: FpStream,
    consumed: u64,
    family_outputs: [u64; 8],
    family_residuals: [Fp2; 8],
    constant: Fp2,
    leaf_linear: [Vec<Fp2>; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_linear: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize],
    auxiliary_quadratic: BTreeMap<(u8, u8), Vec<Fp2>>,
}

#[cfg(all(test, feature = "c6-trace"))]
impl C6AtomicReferenceAccumulator {
    fn new(
        schedule: &C6ResidualAtomicWeightSchedule,
        leaf_entries: usize,
        auxiliary_entries: usize,
    ) -> Self {
        Self {
            stream: schedule.stream(),
            consumed: 0,
            family_outputs: [0; 8],
            family_residuals: [Fp2::ZERO; 8],
            constant: Fp2::ZERO,
            leaf_linear: std::array::from_fn(|_| vec![Fp2::ZERO; leaf_entries]),
            auxiliary_linear: std::array::from_fn(|_| vec![Fp2::ZERO; auxiliary_entries]),
            auxiliary_quadratic: C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
                .into_iter()
                .map(|factors| (factors, vec![Fp2::ZERO; auxiliary_entries]))
                .collect(),
        }
    }

    fn next(&mut self, family: C6ResidualAtomicFamily, constant: Fp2, witness: Fp2) -> Fp2 {
        let weight = self.stream.next_fp2();
        self.consumed += 1;
        self.family_outputs[family.index()] += 1;
        self.family_residuals[family.index()] += weight * (constant + witness);
        self.constant += weight * constant;
        weight
    }

    fn add_leaf(&mut self, table: usize, row: usize, value: Fp2) {
        self.leaf_linear[table][row] += value;
    }

    fn add_auxiliary(&mut self, table: usize, row: usize, value: Fp2) {
        self.auxiliary_linear[table][row] += value;
    }

    fn add_quadratic(&mut self, lhs: u8, rhs: u8, row: usize, value: Fp2) {
        self.auxiliary_quadratic
            .get_mut(&(lhs, rhs))
            .expect("frozen C6 auxiliary quadratic tuple")[row] += value;
    }
}

/// Compile and independently evaluate every C6RLM1 family on a scaled
/// installed relation.  This path deliberately rejects production geometry:
/// it is retained under `cfg(test)` only as the independent pre-refactor
/// oracle for the event replay.
#[cfg(all(test, feature = "c6-trace"))]
#[allow(clippy::too_many_arguments)]
fn compile_c6_residual_atomic_relation_reference_legacy(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    witness: &C6ResidualRelationReferenceWitness,
) -> C6ResidualResult<C6ResidualAtomicReferenceCompilation> {
    challenges.validate(operation_plan)?;
    let manifest = challenges.manifest();
    if manifest.production_geometry {
        return Err(C6ResidualError::new(
            "C6 atomic reference compiler cannot materialize production coefficient tables",
        ));
    }
    if manifest.leaf_entries > (1 << 20) || manifest.auxiliary_entries > (1 << 16) {
        return Err(C6ResidualError::new(
            "C6 atomic reference compiler exceeds its scaled allocation guard",
        ));
    }
    witness.validate(manifest)?;
    if linear.operation_plan_artifact_digest != manifest.operation_plan_artifact_digest
        || linear.topology != manifest.topology
        || linear.instance != manifest.instance
        || linear.product_mask_sources != manifest.product_mask_sources
        || linear.linear_form_digest != challenges.claims().linear_form_digest
    {
        return Err(C6ResidualError::new(
            "C6 atomic compiler linear form differs from manifest/public claims",
        ));
    }

    let source_count = manifest.topology.source_count as usize;
    let leaf_entries = manifest.leaf_entries as usize;
    let auxiliary_entries = manifest.auxiliary_entries as usize;
    let product_triples = manifest.topology.product_triple_count as usize;
    let zero_roots = manifest.topology.zero_root_count as usize;
    let mask_sources = manifest.product_mask_sources.iter().copied().collect::<BTreeSet<_>>();
    let mut alphas: [Vec<Fp2>; 2] = std::array::from_fn(|_| Vec::with_capacity(source_count));
    for coordinate in 0..2u8 {
        let mut stream = challenges.base_share_context().alpha_stream(coordinate)?;
        for _ in 0..source_count {
            alphas[usize::from(coordinate)].push(stream.next_fp2());
        }
    }

    let mut terminal_forms = Vec::with_capacity(C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS);
    for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
        for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
            for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag] {
                let schedule =
                    challenges.terminal_schedule(proof_repetition, mac_coordinate, kind)?;
                let form = C6CompiledTerminalLinearForm::compile(
                    operation_plan,
                    extraction,
                    runtime,
                    schedule,
                )?;
                if form.protocol_version != RESIDUAL_RELATION_PROTOCOL_V3
                    || form.topology != manifest.topology
                    || form.instance != manifest.instance
                    || form.leaf_coefficients.len() != source_count
                {
                    return Err(C6ResidualError::new(
                        "C6 atomic compiler terminal form differs from C6RLM1",
                    ));
                }
                terminal_forms.push(form);
            }
        }
    }

    let mut statements = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut family_outputs = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut family_residuals = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);
    let mut expression_evaluations = Vec::with_capacity(C6_RESIDUAL_PROOF_REPETITIONS as usize);

    for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
        let atomic_schedule = challenges.atomic_schedule(proof_repetition)?;
        let mut accumulator =
            C6AtomicReferenceAccumulator::new(atomic_schedule, leaf_entries, auxiliary_entries);

        for source in 0..source_count {
            let is_mask = mask_sources.contains(&(source as u32));
            let direct = !is_mask;
            let l = &witness.leaf_tables;

            let source0 =
                if direct { l[0][source] - l[1][source] - l[3][source] } else { l[3][source] };
            let weight =
                accumulator.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO, source0);
            if direct {
                accumulator.add_leaf(0, source, weight);
                accumulator.add_leaf(1, source, Fp2::ZERO - weight);
                accumulator.add_leaf(3, source, Fp2::ZERO - weight);
            } else {
                accumulator.add_leaf(3, source, weight);
            }

            let source1 =
                if direct { l[0][source] - l[4][source] - l[6][source] } else { l[6][source] };
            let weight =
                accumulator.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO, source1);
            if direct {
                accumulator.add_leaf(0, source, weight);
                accumulator.add_leaf(4, source, Fp2::ZERO - weight);
                accumulator.add_leaf(6, source, Fp2::ZERO - weight);
            } else {
                accumulator.add_leaf(6, source, weight);
            }

            let source_x = if is_mask { l[0][source] } else { Fp2::ZERO };
            let weight =
                accumulator.next(C6ResidualAtomicFamily::SourceGrammar, Fp2::ZERO, source_x);
            if is_mask {
                accumulator.add_leaf(0, source, weight);
            }
        }

        for (coordinate, coordinate_alphas) in alphas.iter().enumerate() {
            let (r_table, m_table, d_table) = if coordinate == 0 { (1, 2, 3) } else { (4, 5, 6) };
            let residual = challenges.claims().residual.coordinates[coordinate];
            let mut d_witness = Fp2::ZERO;
            let mut m_witness = Fp2::ZERO;
            for (source, (&linear_coefficient, &alpha)) in
                linear.leaf_coefficients.iter().zip(coordinate_alphas).enumerate()
            {
                d_witness += linear_coefficient * witness.leaf_tables[d_table][source]
                    - alpha * witness.leaf_tables[r_table][source];
                m_witness += (linear_coefficient + alpha) * witness.leaf_tables[m_table][source];
            }
            let d_constant = linear.public_plaintext - residual.correction_rlc;
            let weight = accumulator.next(C6ResidualAtomicFamily::Affine, d_constant, d_witness);
            for (source, (&linear_coefficient, &alpha)) in
                linear.leaf_coefficients.iter().zip(coordinate_alphas).enumerate()
            {
                accumulator.add_leaf(d_table, source, weight * linear_coefficient);
                accumulator.add_leaf(r_table, source, Fp2::ZERO - weight * alpha);
            }
            let m_constant = Fp2::ZERO - residual.public_tag_rlc;
            let weight = accumulator.next(C6ResidualAtomicFamily::Affine, m_constant, m_witness);
            for (source, (&linear_coefficient, &alpha)) in
                linear.leaf_coefficients.iter().zip(coordinate_alphas).enumerate()
            {
                accumulator.add_leaf(m_table, source, weight * (linear_coefficient + alpha));
            }
        }

        for coordinate in 0..2usize {
            for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag] {
                let form_index =
                    usize::from(proof_repetition) * 4 + coordinate * 2 + kind.stream_index();
                let form = &terminal_forms[form_index];
                let schedule =
                    challenges.terminal_schedule(proof_repetition, coordinate as u8, kind)?;
                let mut witness_value = Fp2::ZERO;
                for source in 0..source_count {
                    let is_mask = mask_sources.contains(&(source as u32));
                    let table = match kind {
                        C6ResidualTerminalFormKind::Plaintext => {
                            if is_mask {
                                if coordinate == 0 {
                                    1
                                } else {
                                    4
                                }
                            } else {
                                0
                            }
                        }
                        C6ResidualTerminalFormKind::Tag => {
                            if coordinate == 0 {
                                2
                            } else {
                                5
                            }
                        }
                    };
                    witness_value +=
                        form.leaf_coefficients[source] * witness.leaf_tables[table][source];
                }
                let lane_base = coordinate * 6;
                for (triple, weights) in schedule.product_weights.iter().enumerate() {
                    let lanes = match kind {
                        C6ResidualTerminalFormKind::Plaintext => {
                            [lane_base, lane_base + 2, lane_base + 4]
                        }
                        C6ResidualTerminalFormKind::Tag => {
                            [lane_base + 1, lane_base + 3, lane_base + 5]
                        }
                    };
                    for (lane, terminal_weight) in lanes.into_iter().zip(weights) {
                        witness_value = witness_value
                            - *terminal_weight * witness.auxiliary_tables[lane][triple];
                    }
                }
                let zero_lane =
                    12 + 2 * coordinate + usize::from(kind == C6ResidualTerminalFormKind::Tag);
                for (zero, terminal_weight) in schedule.zero_weights.iter().enumerate() {
                    witness_value = witness_value
                        - *terminal_weight * witness.auxiliary_tables[zero_lane][zero];
                }
                let constant = form.public_plaintext;
                let outer =
                    accumulator.next(C6ResidualAtomicFamily::Reverse, constant, witness_value);
                for source in 0..source_count {
                    let is_mask = mask_sources.contains(&(source as u32));
                    let table = match kind {
                        C6ResidualTerminalFormKind::Plaintext => {
                            if is_mask {
                                if coordinate == 0 {
                                    1
                                } else {
                                    4
                                }
                            } else {
                                0
                            }
                        }
                        C6ResidualTerminalFormKind::Tag => {
                            if coordinate == 0 {
                                2
                            } else {
                                5
                            }
                        }
                    };
                    accumulator.add_leaf(table, source, outer * form.leaf_coefficients[source]);
                }
                for (triple, weights) in schedule.product_weights.iter().enumerate() {
                    let lanes = match kind {
                        C6ResidualTerminalFormKind::Plaintext => {
                            [lane_base, lane_base + 2, lane_base + 4]
                        }
                        C6ResidualTerminalFormKind::Tag => {
                            [lane_base + 1, lane_base + 3, lane_base + 5]
                        }
                    };
                    for (lane, terminal_weight) in lanes.into_iter().zip(weights) {
                        accumulator.add_auxiliary(
                            lane,
                            triple,
                            Fp2::ZERO - outer * *terminal_weight,
                        );
                    }
                }
                for (zero, terminal_weight) in schedule.zero_weights.iter().enumerate() {
                    accumulator.add_auxiliary(
                        zero_lane,
                        zero,
                        Fp2::ZERO - outer * *terminal_weight,
                    );
                }
            }
        }

        let mut raw_position = 0usize;
        for triple in 0..product_triples {
            for coordinate in 0..2usize {
                for component in 0..6usize {
                    let lane = 6 * coordinate + component;
                    let relation = witness.leaf_tables[7][raw_position]
                        - witness.auxiliary_tables[lane][triple];
                    let weight =
                        accumulator.next(C6ResidualAtomicFamily::RawCopy, Fp2::ZERO, relation);
                    accumulator.add_leaf(7, raw_position, weight);
                    accumulator.add_auxiliary(lane, triple, Fp2::ZERO - weight);
                    raw_position += 1;
                }
            }
        }
        for zero in 0..zero_roots {
            for coordinate in 0..2usize {
                for component in 0..2usize {
                    let lane = 12 + 2 * coordinate + component;
                    let relation =
                        witness.leaf_tables[7][raw_position] - witness.auxiliary_tables[lane][zero];
                    let weight =
                        accumulator.next(C6ResidualAtomicFamily::RawCopy, Fp2::ZERO, relation);
                    accumulator.add_leaf(7, raw_position, weight);
                    accumulator.add_auxiliary(lane, zero, Fp2::ZERO - weight);
                    raw_position += 1;
                }
            }
        }
        if raw_position as u64 != manifest.raw_copy_entries {
            return Err(C6ResidualError::new(
                "C6 atomic compiler raw-copy cursor differs from C6RLM1",
            ));
        }

        let mut triple_cursor = 0usize;
        for (closure, product) in operation_plan.products().iter().enumerate() {
            let chi = challenges.base_share_context().retained.product_challenges[closure];
            let mask_source = manifest.product_mask_sources[closure] as usize;
            for coordinate in 0..2usize {
                let lane_base = 6 * coordinate;
                let r_table = if coordinate == 0 { 1 } else { 4 };
                let m_table = if coordinate == 0 { 2 } else { 5 };
                let messages = challenges.claims().products[closure].messages[coordinate];

                let mut power = Fp2::ONE;
                let mut q_witness = Fp2::ZERO;
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    q_witness += power
                        * (witness.auxiliary_tables[lane_base][row]
                            * witness.auxiliary_tables[lane_base + 2][row]
                            - witness.auxiliary_tables[lane_base + 4][row]);
                }
                let outer = accumulator.next(C6ResidualAtomicFamily::Product, Fp2::ZERO, q_witness);
                power = Fp2::ONE;
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    accumulator.add_quadratic(
                        lane_base as u8,
                        (lane_base + 2) as u8,
                        row,
                        outer * power,
                    );
                    accumulator.add_auxiliary(lane_base + 4, row, Fp2::ZERO - outer * power);
                }

                power = Fp2::ONE;
                let mut m0_witness = witness.leaf_tables[m_table][mask_source];
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    m0_witness += power
                        * witness.auxiliary_tables[lane_base + 1][row]
                        * witness.auxiliary_tables[lane_base + 3][row];
                }
                let outer = accumulator.next(
                    C6ResidualAtomicFamily::Product,
                    Fp2::ZERO - messages[0],
                    m0_witness,
                );
                accumulator.add_leaf(m_table, mask_source, outer);
                power = Fp2::ONE;
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    accumulator.add_quadratic(
                        (lane_base + 1) as u8,
                        (lane_base + 3) as u8,
                        row,
                        outer * power,
                    );
                }

                power = Fp2::ONE;
                let mut m1_witness = witness.leaf_tables[r_table][mask_source];
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    m1_witness += power
                        * (witness.auxiliary_tables[lane_base][row]
                            * witness.auxiliary_tables[lane_base + 3][row]
                            + witness.auxiliary_tables[lane_base + 1][row]
                                * witness.auxiliary_tables[lane_base + 2][row]
                            - witness.auxiliary_tables[lane_base + 5][row]);
                }
                let outer = accumulator.next(
                    C6ResidualAtomicFamily::Product,
                    Fp2::ZERO - messages[1],
                    m1_witness,
                );
                accumulator.add_leaf(r_table, mask_source, outer);
                power = Fp2::ONE;
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    accumulator.add_quadratic(
                        lane_base as u8,
                        (lane_base + 3) as u8,
                        row,
                        outer * power,
                    );
                    accumulator.add_quadratic(
                        (lane_base + 1) as u8,
                        (lane_base + 2) as u8,
                        row,
                        outer * power,
                    );
                    accumulator.add_auxiliary(lane_base + 5, row, Fp2::ZERO - outer * power);
                }
            }
            triple_cursor += product.triples().len();
        }
        if triple_cursor != product_triples {
            return Err(C6ResidualError::new(
                "C6 atomic compiler ProductClosure triple cursor mismatch",
            ));
        }

        let zero_weights = challenges.base_share_context().retained.zero_weights(zero_roots);
        for coordinate in 0..2usize {
            let lane = 12 + 2 * coordinate;
            let witness_value = zero_weights
                .iter()
                .zip(&witness.auxiliary_tables[lane][..zero_roots])
                .fold(Fp2::ZERO, |sum, (&weight, &value)| sum + weight * value);
            let outer = accumulator.next(C6ResidualAtomicFamily::Zero, Fp2::ZERO, witness_value);
            for (zero, weight) in zero_weights.iter().enumerate() {
                accumulator.add_auxiliary(lane, zero, outer * *weight);
            }
        }

        for table in 0..7usize {
            for row in source_count..leaf_entries {
                let value = witness.leaf_tables[table][row];
                let weight = accumulator.next(C6ResidualAtomicFamily::LeafTail, Fp2::ZERO, value);
                accumulator.add_leaf(table, row, weight);
            }
        }
        for row in raw_position..leaf_entries {
            let value = witness.leaf_tables[7][row];
            let weight = accumulator.next(C6ResidualAtomicFamily::LeafTail, Fp2::ZERO, value);
            accumulator.add_leaf(7, row, weight);
        }
        for lane in 0..12usize {
            for row in product_triples..auxiliary_entries {
                let value = witness.auxiliary_tables[lane][row];
                let weight =
                    accumulator.next(C6ResidualAtomicFamily::AuxiliaryTail, Fp2::ZERO, value);
                accumulator.add_auxiliary(lane, row, weight);
            }
        }
        for lane in 12..16usize {
            for row in zero_roots..auxiliary_entries {
                let value = witness.auxiliary_tables[lane][row];
                let weight =
                    accumulator.next(C6ResidualAtomicFamily::AuxiliaryTail, Fp2::ZERO, value);
                accumulator.add_auxiliary(lane, row, weight);
            }
        }

        let expected_family_outputs = [
            u64::from(manifest.topology.source_count) * 3,
            4,
            4,
            manifest.raw_copy_entries,
            u64::from(manifest.topology.product_closure_count) * 6,
            2,
            manifest.leaf_tail_outputs,
            manifest.auxiliary_tail_outputs,
        ];
        if accumulator.family_outputs != expected_family_outputs
            || accumulator.consumed != manifest.atomic_outputs_per_repetition
            || accumulator.consumed != atomic_schedule.output_count
        {
            return Err(C6ResidualError::new(
                "C6 atomic compiler stream consumption differs from C6RLM1",
            ));
        }

        let target = Fp2::ZERO - accumulator.constant;
        let auxiliary_quadratic = accumulator.auxiliary_quadratic.into_iter().collect::<Vec<_>>();
        if auxiliary_quadratic
            .iter()
            .map(|(factors, _)| *factors)
            .ne(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS)
        {
            return Err(C6ResidualError::new(
                "C6 atomic compiler emitted a noncanonical quadratic tuple",
            ));
        }
        let mut statement = C6ResidualAtomicRelationStatement {
            proof_repetition,
            manifest_digest: manifest.digest,
            relation_challenges_digest: challenges.digest,
            target,
            leaf_linear: accumulator.leaf_linear,
            auxiliary_linear: accumulator.auxiliary_linear,
            auxiliary_quadratic,
            atomic_outputs_consumed: accumulator.consumed,
            digest: [0; 32],
        };
        statement.digest = atomic_relation_statement_digest(&statement);
        let expression = statement.evaluate(witness)?;
        let direct =
            accumulator.family_residuals.iter().fold(Fp2::ZERO, |sum, residual| sum + *residual);
        if expression - statement.target != direct {
            return Err(C6ResidualError::new(
                "C6 atomic compiler coefficient/source differential mismatch",
            ));
        }
        statements.push(statement);
        family_outputs.push(accumulator.family_outputs);
        family_residuals.push(accumulator.family_residuals);
        expression_evaluations.push(expression);
    }

    let statements: [C6ResidualAtomicRelationStatement; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        statements
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic compiler lost a repetition"))?;
    let family_outputs: [[u64; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] = family_outputs
        .try_into()
        .map_err(|_| C6ResidualError::new("C6 atomic compiler lost a family census"))?;
    let family_weighted_residuals: [[Fp2; 8]; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        family_residuals
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic compiler lost a differential"))?;
    let expression_evaluations: [Fp2; C6_RESIDUAL_PROOF_REPETITIONS as usize] =
        expression_evaluations
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 atomic compiler lost an evaluation"))?;
    let mut compilation = C6ResidualAtomicReferenceCompilation {
        statements,
        family_outputs,
        family_weighted_residuals,
        expression_evaluations,
        digest: [0; 32],
    };
    compilation.digest = atomic_reference_compilation_digest(&compilation);
    Ok(compilation)
}

fn atomic_relation_statement_digest(
    statement: &C6ResidualAtomicRelationStatement,
) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/residual-atomic-statement/v1");
    hasher.update(&[statement.proof_repetition]);
    hasher.update(&statement.manifest_digest);
    hasher.update(&statement.relation_challenges_digest);
    hash_fp2(&mut hasher, statement.target);
    hasher.update(&statement.atomic_outputs_consumed.to_le_bytes());
    for (table, coefficients) in statement.leaf_linear.iter().enumerate() {
        hasher.update(&[0, table as u8]);
        for coefficient in coefficients {
            hash_fp2(&mut hasher, *coefficient);
        }
    }
    for (table, coefficients) in statement.auxiliary_linear.iter().enumerate() {
        hasher.update(&[1, table as u8]);
        for coefficient in coefficients {
            hash_fp2(&mut hasher, *coefficient);
        }
    }
    for ((lhs, rhs), coefficients) in &statement.auxiliary_quadratic {
        hasher.update(&[2, *lhs, *rhs]);
        for coefficient in coefficients {
            hash_fp2(&mut hasher, *coefficient);
        }
    }
    *hasher.finalize().as_bytes()
}

fn atomic_reference_compilation_digest(
    compilation: &C6ResidualAtomicReferenceCompilation,
) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/residual-atomic-reference/v1");
    for repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS as usize {
        hasher.update(&compilation.statements[repetition].digest);
        for family in C6ResidualAtomicFamily::ALL {
            hasher.update(&compilation.family_outputs[repetition][family.index()].to_le_bytes());
            hash_fp2(
                &mut hasher,
                compilation.family_weighted_residuals[repetition][family.index()],
            );
        }
        hash_fp2(&mut hasher, compilation.expression_evaluations[repetition]);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ProductPostCommit {
    pub chi: Fp2,
    pub m0: Fp2,
    pub m1: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualPostCommit {
    /// One independent field coefficient per canonical base-correlation leaf.
    pub base_share_alphas: Vec<Fp2>,
    /// Existing verifier weights for the declared linear zero closures.
    pub zero_weights: Vec<Fp2>,
    /// Existing QuickSilver challenge and retained messages per closure.
    pub products: Vec<C6ProductPostCommit>,
}

/// Response-independent binding of the compact reverse accumulator.
///
/// The two response sides reconstruct this value independently from their
/// installed setup artifact, role-local instance map and the same public
/// zero-closure weights. No leaf coefficient vector is serialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CompiledResidualBinding {
    pub operation_plan_artifact_digest: C6ResidualDigest,
    pub topology_digest: C6ResidualDigest,
    pub instance_digest: C6ResidualDigest,
    pub linear_form_digest: C6ResidualDigest,
    pub coefficient_digest: C6ResidualDigest,
    pub source_count: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6CompiledLinearResidualMemoryCensus {
    pub node_workspace_elements: u64,
    pub node_workspace_bytes: u64,
    pub leaf_coefficient_elements: u64,
    pub leaf_coefficient_capacity: u64,
    pub leaf_coefficient_heap_bytes: u64,
    pub product_mask_elements: u64,
    pub product_mask_capacity: u64,
    pub product_mask_heap_bytes: u64,
    pub inline_bytes: u64,
    pub retained_resident_bytes: u64,
    pub peak_compile_resident_bytes: u64,
}

/// Canonical order of the seven leaf-aligned residual witness slots.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualLeafColumn {
    CommonPlaintext = 0,
    Coordinate0Mask = 1,
    Coordinate0Tag = 2,
    Coordinate0Correction = 3,
    Coordinate1Mask = 4,
    Coordinate1Tag = 5,
    Coordinate1Correction = 6,
}

impl C6ResidualLeafColumn {
    pub const ALL: [Self; 7] = [
        Self::CommonPlaintext,
        Self::Coordinate0Mask,
        Self::Coordinate0Tag,
        Self::Coordinate0Correction,
        Self::Coordinate1Mask,
        Self::Coordinate1Tag,
        Self::Coordinate1Correction,
    ];

    fn index(self) -> usize {
        self as usize
    }
}

/// Prover-only live prefixes for the seven source-aligned residual slots.
///
/// ProductMask rows deliberately place zero in `CommonPlaintext`; their two
/// independent plaintext masks remain in the coordinate-specific `r`
/// columns.  This object contains no padded capacity and is never a response
/// field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedResidualLeafWitness {
    source_schedule_digest: C6ResidualDigest,
    paired_source_digest: C6ResidualDigest,
    source_count: u32,
    product_mask_count: u32,
    columns: [Vec<Fp2>; C6_RESIDUAL_LEAF_ALIGNED_SLOTS as usize],
    witness_digest: C6ResidualDigest,
}

impl C6PairedResidualLeafWitness {
    pub fn source_schedule_digest(&self) -> C6ResidualDigest {
        self.source_schedule_digest
    }

    pub fn paired_source_digest(&self) -> C6ResidualDigest {
        self.paired_source_digest
    }

    pub fn source_count(&self) -> u32 {
        self.source_count
    }

    pub fn product_mask_count(&self) -> u32 {
        self.product_mask_count
    }

    pub fn witness_digest(&self) -> C6ResidualDigest {
        self.witness_digest
    }

    pub fn column(&self, column: C6ResidualLeafColumn) -> &[Fp2] {
        &self.columns[column.index()]
    }

    pub fn live_elements(&self) -> u64 {
        u64::from(self.source_count) * C6_RESIDUAL_LEAF_ALIGNED_SLOTS
    }

    /// CPU/reference padding seam.  The production fused backend consumes
    /// live prefixes directly and must not allocate these eight-million-row
    /// vectors merely to satisfy an in-memory API.
    pub fn materialize_padded_columns(
        &self,
        slot_log2: u32,
    ) -> C6ResidualResult<[Vec<Fp2>; C6_RESIDUAL_LEAF_ALIGNED_SLOTS as usize]> {
        let slot_entries = 1usize
            .checked_shl(slot_log2)
            .ok_or_else(|| C6ResidualError::new("C6 residual slot length overflows usize"))?;
        if slot_entries < self.source_count as usize
            || (slot_log2 == C6_RESIDUAL_SLOT_LOG2
                && slot_entries as u64 != C6_RESIDUAL_SLOT_ENTRIES)
        {
            return Err(C6ResidualError::new(
                "C6 residual live source prefix exceeds its padded slot",
            ));
        }
        let mut padded = std::array::from_fn(|_| vec![Fp2::ZERO; slot_entries]);
        for column in C6ResidualLeafColumn::ALL {
            padded[column.index()][..self.source_count as usize]
                .copy_from_slice(self.column(column));
        }
        Ok(padded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualClosureWitnessCensus {
    pub product_closures: u32,
    pub product_triples: u64,
    pub zero_roots: u32,
    pub product_operand_values: u64,
    pub zero_root_values: u64,
    pub footer_values: u64,
    pub live_values: u64,
}

/// Exact heap census for installed-plan terminal evaluation.
///
/// The two `u32` node arrays replace a dense pair of authenticated values for
/// every canonical node.  `peak_live_node_values` is measured by the
/// evaluator; it is deliberately not projected from topology alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6InstalledClosureEvaluationMemoryCensus {
    pub canonical_nodes: u64,
    pub reference_count_heap_bytes: u64,
    pub node_slot_heap_bytes: u64,
    pub source_draw_index_heap_bytes: u64,
    pub peak_live_node_values: u64,
    pub node_value_capacity: u64,
    pub node_value_heap_bytes: u64,
    pub free_slot_heap_bytes: u64,
    pub closure_value_heap_bytes: u64,
    pub peak_working_heap_bytes: u64,
    pub dense_paired_node_baseline_bytes: u64,
}

/// Result of evaluating only installed terminal ownership on both MAC tapes.
///
/// The evaluation and its census are provider-local.  Neither is a response
/// object; the closure live prefix is consumed by the sealed residual PCS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6InstalledPairedClosureEvaluation {
    closure: C6PairedResidualClosureWitness,
    memory_census: C6InstalledClosureEvaluationMemoryCensus,
}

impl C6InstalledPairedClosureEvaluation {
    pub fn closure(&self) -> &C6PairedResidualClosureWitness {
        &self.closure
    }

    pub fn into_closure(self) -> C6PairedResidualClosureWitness {
        self.closure
    }

    pub fn memory_census(&self) -> C6InstalledClosureEvaluationMemoryCensus {
        self.memory_census
    }
}

/// Canonical live prefix of residual slot 7.  The footer is currently the
/// frozen zero reserve; later envelope fields may consume it only through a
/// separately versioned layout change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C6InstalledClosureBinding {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology_digest: C6ResidualDigest,
    instance_digest: C6ResidualDigest,
    source_schedule_digest: C6ResidualDigest,
    paired_source_digest: C6ResidualDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedResidualClosureWitness {
    program_digest: C6ResidualDigest,
    installed_binding: Option<C6InstalledClosureBinding>,
    census: C6ResidualClosureWitnessCensus,
    values: Vec<Fp2>,
    witness_digest: C6ResidualDigest,
}

impl C6PairedResidualClosureWitness {
    pub fn program_digest(&self) -> C6ResidualDigest {
        self.program_digest
    }

    pub fn census(&self) -> C6ResidualClosureWitnessCensus {
        self.census
    }

    pub fn values(&self) -> &[Fp2] {
        &self.values
    }

    pub fn witness_digest(&self) -> C6ResidualDigest {
        self.witness_digest
    }

    pub fn materialize_padded(&self, slot_log2: u32) -> C6ResidualResult<Vec<Fp2>> {
        let slot_entries = 1usize
            .checked_shl(slot_log2)
            .ok_or_else(|| C6ResidualError::new("C6 closure slot length overflows usize"))?;
        if slot_entries < self.values.len()
            || (slot_log2 == C6_RESIDUAL_SLOT_LOG2
                && slot_entries as u64 != C6_RESIDUAL_SLOT_ENTRIES)
        {
            return Err(C6ResidualError::new(
                "C6 residual closure workspace exceeds its padded slot",
            ));
        }
        let mut padded = vec![Fp2::ZERO; slot_entries];
        padded[..self.values.len()].copy_from_slice(&self.values);
        Ok(padded)
    }

    /// Deterministically transpose the canonical slot-7 live prefix into the
    /// sixteen residual auxiliary semantic lanes.
    ///
    /// This remains a prover-only witness adapter.  In particular, it does
    /// not construct the independent upper-half ZK masks and does not create
    /// a PCS obligation.
    pub fn transpose_auxiliary_lanes(&self) -> C6ResidualResult<C6PairedResidualAuxiliaryWitness> {
        let expected_product_values = self
            .census
            .product_triples
            .checked_mul(u64::from(C6_RESIDUAL_AUXILIARY_PRODUCT_LANES))
            .ok_or_else(|| C6ResidualError::new("C6 auxiliary product census overflows"))?;
        let expected_zero_values = u64::from(self.census.zero_roots)
            .checked_mul(u64::from(C6_RESIDUAL_AUXILIARY_ZERO_LANES))
            .ok_or_else(|| C6ResidualError::new("C6 auxiliary zero census overflows"))?;
        let expected_live_values = expected_product_values
            .checked_add(expected_zero_values)
            .and_then(|values| values.checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES))
            .ok_or_else(|| C6ResidualError::new("C6 auxiliary live census overflows"))?;
        let actual_values = u64::try_from(self.values.len())
            .map_err(|_| C6ResidualError::new("C6 auxiliary source length exceeds u64"))?;
        if self.census.product_operand_values != expected_product_values
            || self.census.zero_root_values != expected_zero_values
            || self.census.footer_values != C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES
            || self.census.live_values != expected_live_values
            || actual_values != expected_live_values
        {
            return Err(C6ResidualError::new(
                "C6 auxiliary source does not match the frozen slot-7 census",
            ));
        }
        if self.census.product_triples > C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES
            || u64::from(self.census.zero_roots) > C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES
        {
            return Err(C6ResidualError::new(
                "C6 auxiliary live rows exceed their semantic halves",
            ));
        }

        let product_end = usize::try_from(expected_product_values)
            .map_err(|_| C6ResidualError::new("C6 auxiliary product prefix exceeds usize"))?;
        let footer_start = usize::try_from(
            expected_product_values
                .checked_add(expected_zero_values)
                .ok_or_else(|| C6ResidualError::new("C6 auxiliary footer offset overflows"))?,
        )
        .map_err(|_| C6ResidualError::new("C6 auxiliary footer offset exceeds usize"))?;
        let footer = self
            .values
            .get(footer_start..)
            .ok_or_else(|| C6ResidualError::new("C6 auxiliary footer is truncated"))?;
        if footer.len() != C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES as usize
            || footer.iter().any(|value| *value != Fp2::ZERO)
        {
            return Err(C6ResidualError::new(
                "C6 auxiliary source footer is not the frozen zero reserve",
            ));
        }

        let product_rows = usize::try_from(self.census.product_triples)
            .map_err(|_| C6ResidualError::new("C6 auxiliary product rows exceed usize"))?;
        let zero_rows = usize::try_from(self.census.zero_roots)
            .map_err(|_| C6ResidualError::new("C6 auxiliary zero rows exceed usize"))?;
        let mut lanes: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize] =
            std::array::from_fn(|lane| {
                Vec::with_capacity(if lane < C6_RESIDUAL_AUXILIARY_PRODUCT_LANES as usize {
                    product_rows
                } else {
                    zero_rows
                })
            });

        let mut product_chunks =
            self.values[..product_end].chunks_exact(C6_RESIDUAL_AUXILIARY_PRODUCT_LANES as usize);
        for row in &mut product_chunks {
            for (lane, value) in row.iter().copied().enumerate() {
                lanes[lane].push(value);
            }
        }
        if !product_chunks.remainder().is_empty() {
            return Err(C6ResidualError::new("C6 auxiliary product prefix is not lane-aligned"));
        }

        let mut zero_chunks = self.values[product_end..footer_start]
            .chunks_exact(C6_RESIDUAL_AUXILIARY_ZERO_LANES as usize);
        for row in &mut zero_chunks {
            for (lane, value) in row.iter().copied().enumerate() {
                lanes[C6_RESIDUAL_AUXILIARY_PRODUCT_LANES as usize + lane].push(value);
            }
        }
        if !zero_chunks.remainder().is_empty()
            || lanes[..C6_RESIDUAL_AUXILIARY_PRODUCT_LANES as usize]
                .iter()
                .any(|lane| lane.len() != product_rows)
            || lanes[C6_RESIDUAL_AUXILIARY_PRODUCT_LANES as usize..]
                .iter()
                .any(|lane| lane.len() != zero_rows)
        {
            return Err(C6ResidualError::new(
                "C6 auxiliary transpose does not match its row census",
            ));
        }

        let transposed_live_values = expected_product_values
            .checked_add(expected_zero_values)
            .ok_or_else(|| C6ResidualError::new("C6 auxiliary transpose census overflows"))?;
        let census = C6ResidualAuxiliaryWitnessCensus {
            product_rows: self.census.product_triples,
            zero_rows: u64::from(self.census.zero_roots),
            product_lanes: C6_RESIDUAL_AUXILIARY_PRODUCT_LANES,
            zero_lanes: C6_RESIDUAL_AUXILIARY_ZERO_LANES,
            semantic_entries_per_lane: C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES,
            transposed_live_values,
        };
        let mut hasher = blake3::Hasher::new_derive_key(PAIRED_AUXILIARY_WRAPPER_DOMAIN);
        hasher.update(&self.program_digest);
        hasher.update(&self.witness_digest);
        hasher.update(&u64::from(self.census.product_closures).to_le_bytes());
        hasher.update(&self.census.product_triples.to_le_bytes());
        hasher.update(&u64::from(self.census.zero_roots).to_le_bytes());
        hasher.update(&self.census.product_operand_values.to_le_bytes());
        hasher.update(&self.census.zero_root_values.to_le_bytes());
        hasher.update(&self.census.footer_values.to_le_bytes());
        hasher.update(&self.census.live_values.to_le_bytes());
        hasher.update(&census.product_rows.to_le_bytes());
        hasher.update(&census.zero_rows.to_le_bytes());
        hasher.update(&u64::from(census.product_lanes).to_le_bytes());
        hasher.update(&u64::from(census.zero_lanes).to_le_bytes());
        hasher.update(&census.semantic_entries_per_lane.to_le_bytes());
        hasher.update(&census.transposed_live_values.to_le_bytes());
        for lane in C6ResidualAuxiliaryLane::ALL {
            hasher.update(&[lane as u8]);
            hasher.update(&(lanes[lane.index()].len() as u64).to_le_bytes());
            for value in &lanes[lane.index()] {
                hash_fp2(&mut hasher, *value);
            }
        }

        Ok(C6PairedResidualAuxiliaryWitness {
            program_digest: self.program_digest,
            closure_witness_digest: self.witness_digest,
            closure_census: self.census,
            census,
            lanes,
            witness_digest: *hasher.finalize().as_bytes(),
        })
    }
}

/// Frozen order of the sixteen residual auxiliary semantic lanes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualAuxiliaryLane {
    Coordinate0ProductXa = 0,
    Coordinate0ProductMa = 1,
    Coordinate0ProductXb = 2,
    Coordinate0ProductMb = 3,
    Coordinate0ProductXc = 4,
    Coordinate0ProductMc = 5,
    Coordinate1ProductXa = 6,
    Coordinate1ProductMa = 7,
    Coordinate1ProductXb = 8,
    Coordinate1ProductMb = 9,
    Coordinate1ProductXc = 10,
    Coordinate1ProductMc = 11,
    Coordinate0ZeroX = 12,
    Coordinate0ZeroM = 13,
    Coordinate1ZeroX = 14,
    Coordinate1ZeroM = 15,
}

impl C6ResidualAuxiliaryLane {
    pub const ALL: [Self; C6_RESIDUAL_AUXILIARY_LANES as usize] = [
        Self::Coordinate0ProductXa,
        Self::Coordinate0ProductMa,
        Self::Coordinate0ProductXb,
        Self::Coordinate0ProductMb,
        Self::Coordinate0ProductXc,
        Self::Coordinate0ProductMc,
        Self::Coordinate1ProductXa,
        Self::Coordinate1ProductMa,
        Self::Coordinate1ProductXb,
        Self::Coordinate1ProductMb,
        Self::Coordinate1ProductXc,
        Self::Coordinate1ProductMc,
        Self::Coordinate0ZeroX,
        Self::Coordinate0ZeroM,
        Self::Coordinate1ZeroX,
        Self::Coordinate1ZeroM,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualAuxiliaryWitnessCensus {
    pub product_rows: u64,
    pub zero_rows: u64,
    pub product_lanes: u32,
    pub zero_lanes: u32,
    pub semantic_entries_per_lane: u64,
    pub transposed_live_values: u64,
}

/// Prover-only live prefixes for residual auxiliary slots 0--15.
///
/// The vectors contain only semantic rows.  The independent upper-half ZK
/// masks are intentionally absent and must be supplied by the later sealed
/// wrapper source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedResidualAuxiliaryWitness {
    program_digest: C6ResidualDigest,
    closure_witness_digest: C6ResidualDigest,
    closure_census: C6ResidualClosureWitnessCensus,
    census: C6ResidualAuxiliaryWitnessCensus,
    lanes: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize],
    witness_digest: C6ResidualDigest,
}

impl C6PairedResidualAuxiliaryWitness {
    pub fn program_digest(&self) -> C6ResidualDigest {
        self.program_digest
    }

    pub fn closure_witness_digest(&self) -> C6ResidualDigest {
        self.closure_witness_digest
    }

    pub fn closure_census(&self) -> C6ResidualClosureWitnessCensus {
        self.closure_census
    }

    pub fn census(&self) -> C6ResidualAuxiliaryWitnessCensus {
        self.census
    }

    pub fn witness_digest(&self) -> C6ResidualDigest {
        self.witness_digest
    }

    pub fn lane(&self, lane: C6ResidualAuxiliaryLane) -> &[Fp2] {
        &self.lanes[lane.index()]
    }

    /// Materialize exactly the semantic halves for CPU/reference tests.
    ///
    /// This method deliberately returns `2^15`, not `2^16`, entries per
    /// lane.  It therefore cannot silently stand in for the independently
    /// masked auxiliary PCS coefficients.
    pub fn materialize_semantic_halves(
        &self,
    ) -> C6ResidualResult<[Vec<Fp2>; C6_RESIDUAL_AUXILIARY_LANES as usize]> {
        let semantic_entries = usize::try_from(C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES)
            .map_err(|_| C6ResidualError::new("C6 auxiliary semantic length exceeds usize"))?;
        let mut semantic = std::array::from_fn(|_| vec![Fp2::ZERO; semantic_entries]);
        for lane in C6ResidualAuxiliaryLane::ALL {
            let live = self.lane(lane);
            if live.len() > semantic_entries {
                return Err(C6ResidualError::new(
                    "C6 auxiliary live lane exceeds its semantic half",
                ));
            }
            semantic[lane.index()][..live.len()].copy_from_slice(live);
        }
        Ok(semantic)
    }
}

/// Bound live-prefix view used by fused provider sinks.
///
/// Missing semantic rows are canonical zero padding.  Constructing this view
/// never allocates a padded witness table.
#[derive(Clone, Copy)]
pub struct C6ResidualFusedWitnessView<'a> {
    manifest_digest: C6ResidualDigest,
    leaf: &'a C6PairedResidualLeafWitness,
    closure: &'a C6PairedResidualClosureWitness,
    auxiliary: &'a C6PairedResidualAuxiliaryWitness,
    digest: C6ResidualDigest,
}

impl<'a> C6ResidualFusedWitnessView<'a> {
    pub fn new(
        manifest: &C6ResidualRelationManifest,
        leaf: &'a C6PairedResidualLeafWitness,
        closure: &'a C6PairedResidualClosureWitness,
        auxiliary: &'a C6PairedResidualAuxiliaryWitness,
    ) -> C6ResidualResult<Self> {
        let expected_closure_values = manifest
            .raw_copy_entries
            .checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES)
            .ok_or_else(|| C6ResidualError::new("C6 fused closure length overflows"))?;
        let closure_values = u64::try_from(closure.values.len())
            .map_err(|_| C6ResidualError::new("C6 fused closure length exceeds u64"))?;
        if leaf.source_schedule_digest != manifest.topology.source_schedule_digest
            || leaf.source_count != manifest.topology.source_count
            || leaf.product_mask_count as usize != manifest.product_mask_sources.len()
            || closure.census.product_closures != manifest.topology.product_closure_count
            || closure.census.product_triples != manifest.topology.product_triple_count
            || closure.census.zero_roots != manifest.topology.zero_root_count
            || closure_values != expected_closure_values
            || auxiliary.closure_witness_digest != closure.witness_digest
            || auxiliary.census.product_rows != manifest.topology.product_triple_count
            || auxiliary.census.zero_rows != u64::from(manifest.topology.zero_root_count)
        {
            return Err(C6ResidualError::new(
                "C6 fused witness view differs from C6RLM1 ownership",
            ));
        }
        match closure.installed_binding {
            Some(binding)
                if binding.operation_plan_artifact_digest
                    == manifest.operation_plan_artifact_digest
                    && binding.topology_digest == manifest.topology.topology_digest
                    && binding.instance_digest == manifest.instance.instance_digest
                    && binding.source_schedule_digest == leaf.source_schedule_digest
                    && binding.paired_source_digest == leaf.paired_source_digest
                    && closure.program_digest == manifest.operation_plan_artifact_digest => {}
            Some(_) => {
                return Err(C6ResidualError::new(
                    "C6 installed closure binding differs from C6RLM1/leaf ownership",
                ));
            }
            None if manifest.production_geometry => {
                return Err(C6ResidualError::new(
                    "C6 production fused witness requires an installed closure binding",
                ));
            }
            None => {}
        }
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6/residual-fused-witness-view/v1");
        hasher.update(&manifest.digest);
        hasher.update(&leaf.witness_digest);
        hasher.update(&closure.witness_digest);
        hasher.update(&auxiliary.witness_digest);
        let view = Self {
            manifest_digest: manifest.digest,
            leaf,
            closure,
            auxiliary,
            digest: *hasher.finalize().as_bytes(),
        };
        if view.digest == [0; 32] {
            return Err(C6ResidualError::new("C6 fused witness view digest is zero"));
        }
        Ok(view)
    }

    pub fn manifest_digest(&self) -> C6ResidualDigest {
        self.manifest_digest
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    /// Return one logical leaf-table value, including canonical zero padding.
    ///
    /// This is intentionally a scalar provider interface: fused consumers may
    /// fold the installed witness directly without materializing the padded
    /// semantic tables.
    pub fn leaf_value(&self, table: usize, row: usize) -> C6ResidualResult<Fp2> {
        match table {
            0..=6 => Ok(self
                .leaf
                .columns
                .get(table)
                .and_then(|values| values.get(row))
                .copied()
                .unwrap_or(Fp2::ZERO)),
            7 => Ok(self.closure.values.get(row).copied().unwrap_or(Fp2::ZERO)),
            _ => Err(C6ResidualError::new("C6 fused witness leaf table is out of range")),
        }
    }

    /// Return one logical auxiliary-table value, including canonical zero
    /// padding, without allocating the semantic table.
    pub fn auxiliary_value(&self, table: usize, row: usize) -> C6ResidualResult<Fp2> {
        self.auxiliary
            .lanes
            .get(table)
            .map(|values| values.get(row).copied().unwrap_or(Fp2::ZERO))
            .ok_or_else(|| C6ResidualError::new("C6 fused witness auxiliary table is out of range"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualFusedFirstRound {
    proof_repetition: u8,
    target: Fp2,
    leaf_message: [Fp2; 3],
    auxiliary_message: [Fp2; 4],
    semantic_digest: C6ResidualDigest,
    witness_view_digest: C6ResidualDigest,
    digest: C6ResidualDigest,
}

impl C6ResidualFusedFirstRound {
    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn leaf_message(&self) -> &[Fp2; 3] {
        &self.leaf_message
    }

    pub fn auxiliary_message(&self) -> &[Fp2; 4] {
        &self.auxiliary_message
    }

    pub fn semantic_digest(&self) -> C6ResidualDigest {
        self.semantic_digest
    }

    pub fn witness_view_digest(&self) -> C6ResidualDigest {
        self.witness_view_digest
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }
}

struct C6ResidualFusedFirstRoundSink<'a> {
    proof_repetition: u8,
    witness: C6ResidualFusedWitnessView<'a>,
    leaf_message: [Fp2; 3],
    auxiliary_message: [Fp2; 4],
}

impl C6ResidualFusedFirstRoundSink<'_> {
    fn interpolation_point(index: usize) -> Fp2 {
        Fp2::new(Fp::new(index as u64), Fp::ZERO)
    }

    fn selector(bit: usize, point: Fp2) -> Fp2 {
        if bit == 0 {
            Fp2::ONE - point
        } else {
            point
        }
    }

    fn linear_at(
        &self,
        table: usize,
        row: usize,
        point: Fp2,
        auxiliary: bool,
    ) -> C6ResidualResult<Fp2> {
        let base = row & !1;
        let (zero, one) = if auxiliary {
            (
                self.witness.auxiliary_value(table, base)?,
                self.witness.auxiliary_value(table, base + 1)?,
            )
        } else {
            (self.witness.leaf_value(table, base)?, self.witness.leaf_value(table, base + 1)?)
        };
        Ok(zero * (Fp2::ONE - point) + one * point)
    }
}

impl C6ResidualAtomicEventSink for C6ResidualFusedFirstRoundSink<'_> {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new("C6 first-round sink received a swapped repetition"));
        }
        Ok(())
    }

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new(
                "C6 first-round coefficient has a swapped repetition",
            ));
        }
        match event.target {
            C6ResidualAtomicCoefficientTarget::LeafLinear { table, row } => {
                let row = row as usize;
                for index in 0..self.leaf_message.len() {
                    let point = Self::interpolation_point(index);
                    let selector = Self::selector(row & 1, point);
                    let witness = self.linear_at(usize::from(table), row, point, false)?;
                    self.leaf_message[index] += event.coefficient * selector * witness;
                }
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryLinear { table, row } => {
                let row = row as usize;
                for index in 0..self.auxiliary_message.len() {
                    let point = Self::interpolation_point(index);
                    let selector = Self::selector(row & 1, point);
                    let witness = self.linear_at(usize::from(table), row, point, true)?;
                    self.auxiliary_message[index] += event.coefficient * selector * witness;
                }
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic { lhs, rhs, row } => {
                let row = row as usize;
                for index in 0..self.auxiliary_message.len() {
                    let point = Self::interpolation_point(index);
                    let selector = Self::selector(row & 1, point);
                    let lhs = self.linear_at(usize::from(lhs), row, point, true)?;
                    let rhs = self.linear_at(usize::from(rhs), row, point, true)?;
                    self.auxiliary_message[index] += event.coefficient * selector * lhs * rhs;
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compile_c6_residual_fused_first_round(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    proof_repetition: u8,
    witness: C6ResidualFusedWitnessView<'_>,
) -> C6ResidualResult<C6ResidualFusedFirstRound> {
    if witness.manifest_digest != challenges.manifest().digest {
        return Err(C6ResidualError::new("C6 first-round witness view uses a different manifest"));
    }
    let mut sink = C6ResidualFusedFirstRoundSink {
        proof_repetition,
        witness,
        leaf_message: [Fp2::ZERO; 3],
        auxiliary_message: [Fp2::ZERO; 4],
    };
    let summary = replay_c6_residual_atomic_events(
        operation_plan,
        extraction,
        runtime,
        linear,
        challenges,
        proof_repetition,
        &mut sink,
    )?;
    let mut round = C6ResidualFusedFirstRound {
        proof_repetition,
        target: summary.target,
        leaf_message: sink.leaf_message,
        auxiliary_message: sink.auxiliary_message,
        semantic_digest: summary.semantic_digest,
        witness_view_digest: witness.digest,
        digest: [0; 32],
    };
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6/residual-fused-first-round/v1");
    hasher.update(&[proof_repetition]);
    hasher.update(&round.semantic_digest);
    hasher.update(&round.witness_view_digest);
    hash_fp2(&mut hasher, round.target);
    for value in round.leaf_message.iter().chain(&round.auxiliary_message) {
        hash_fp2(&mut hasher, *value);
    }
    round.digest = *hasher.finalize().as_bytes();
    Ok(round)
}

/// Coefficient family retained after the first fused sumcheck challenge.
///
/// The leaf family is replayed first and owns the production peak.  The much
/// smaller auxiliary family may join only after leaf has reached the shared
/// suffix admission length.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualFusedCoefficientFamily {
    Leaf = 0,
    Auxiliary = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualFusedCoefficientMemoryCensus {
    family: C6ResidualFusedCoefficientFamily,
    input_entries_per_table: u64,
    folded_entries_per_table: u64,
    linear_tables: u64,
    quadratic_tables: u64,
    state_elements: u64,
    state_bytes: u64,
}

impl C6ResidualFusedCoefficientMemoryCensus {
    pub fn family(&self) -> C6ResidualFusedCoefficientFamily {
        self.family
    }

    pub fn input_entries_per_table(&self) -> u64 {
        self.input_entries_per_table
    }

    pub fn folded_entries_per_table(&self) -> u64 {
        self.folded_entries_per_table
    }

    pub fn linear_tables(&self) -> u64 {
        self.linear_tables
    }

    pub fn quadratic_tables(&self) -> u64 {
        self.quadratic_tables
    }

    pub fn state_elements(&self) -> u64 {
        self.state_elements
    }

    pub fn state_bytes(&self) -> u64 {
        self.state_bytes
    }
}

pub fn c6_residual_fused_coefficient_memory_census(
    manifest: &C6ResidualRelationManifest,
    family: C6ResidualFusedCoefficientFamily,
) -> C6ResidualResult<C6ResidualFusedCoefficientMemoryCensus> {
    let (input_entries_per_table, linear_tables, quadratic_tables) = match family {
        C6ResidualFusedCoefficientFamily::Leaf => {
            (manifest.leaf_entries, C6_RESIDUAL_RELATION_LEAF_TABLES as u64, 0)
        }
        C6ResidualFusedCoefficientFamily::Auxiliary => (
            manifest.auxiliary_entries,
            u64::from(C6_RESIDUAL_AUXILIARY_LANES),
            C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len() as u64,
        ),
    };
    if input_entries_per_table < 2 || !input_entries_per_table.is_power_of_two() {
        return Err(C6ResidualError::new(
            "C6 fused coefficient input length is not a nontrivial power of two",
        ));
    }
    let folded_entries_per_table = input_entries_per_table / 2;
    let tables = linear_tables
        .checked_add(quadratic_tables)
        .ok_or_else(|| C6ResidualError::new("C6 fused coefficient table census overflows"))?;
    let state_elements = folded_entries_per_table
        .checked_mul(tables)
        .ok_or_else(|| C6ResidualError::new("C6 fused coefficient element census overflows"))?;
    let element_bytes = u64::try_from(std::mem::size_of::<Fp2>())
        .map_err(|_| C6ResidualError::new("C6 Fp2 size exceeds u64"))?;
    let state_bytes = state_elements
        .checked_mul(element_bytes)
        .ok_or_else(|| C6ResidualError::new("C6 fused coefficient byte census overflows"))?;
    if state_elements > C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS
        || state_bytes > C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_BYTES
    {
        return Err(C6ResidualError::new(
            "C6 fused coefficient state exceeds the frozen production memory cap",
        ));
    }
    Ok(C6ResidualFusedCoefficientMemoryCensus {
        family,
        input_entries_per_table,
        folded_entries_per_table,
        linear_tables,
        quadratic_tables,
        state_elements,
        state_bytes,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C6ResidualFusedCoefficientArenaLayout {
    offset: usize,
    entries_per_table: usize,
    table_stride: usize,
    tables: usize,
}

impl C6ResidualFusedCoefficientArenaLayout {
    fn elements(self) -> C6ResidualResult<u64> {
        u64::try_from(self.entries_per_table)
            .ok()
            .and_then(|entries| {
                u64::try_from(self.tables).ok().and_then(|tables| entries.checked_mul(tables))
            })
            .ok_or_else(|| C6ResidualError::new("C6 fused arena layout census overflows"))
    }

    fn table_range(self, table: usize) -> C6ResidualResult<std::ops::Range<usize>> {
        if table >= self.tables {
            return Err(C6ResidualError::new("C6 fused arena table is out of range"));
        }
        let start = table
            .checked_mul(self.table_stride)
            .and_then(|delta| self.offset.checked_add(delta))
            .ok_or_else(|| C6ResidualError::new("C6 fused arena table offset overflows"))?;
        let end = start
            .checked_add(self.entries_per_table)
            .ok_or_else(|| C6ResidualError::new("C6 fused arena table end overflows"))?;
        Ok(start..end)
    }
}

#[derive(Debug, Default)]
struct C6ResidualFusedCoefficientArenaState {
    active_repetition: Option<u8>,
    leaf_admitted: bool,
    auxiliary_admitted: bool,
    leaf: Option<C6ResidualFusedCoefficientArenaLayout>,
    auxiliary: Option<C6ResidualFusedCoefficientArenaLayout>,
    backing: Vec<Fp2>,
    peak_logical_elements: u64,
    peak_reserved_elements: u64,
    faulted: bool,
}

impl C6ResidualFusedCoefficientArenaState {
    fn layout(
        &self,
        family: C6ResidualFusedCoefficientFamily,
    ) -> Option<C6ResidualFusedCoefficientArenaLayout> {
        match family {
            C6ResidualFusedCoefficientFamily::Leaf => self.leaf,
            C6ResidualFusedCoefficientFamily::Auxiliary => self.auxiliary,
        }
    }

    fn layout_mut(
        &mut self,
        family: C6ResidualFusedCoefficientFamily,
    ) -> &mut Option<C6ResidualFusedCoefficientArenaLayout> {
        match family {
            C6ResidualFusedCoefficientFamily::Leaf => &mut self.leaf,
            C6ResidualFusedCoefficientFamily::Auxiliary => &mut self.auxiliary,
        }
    }

    fn active_family_elements(&self, family: C6ResidualFusedCoefficientFamily) -> u64 {
        self.layout(family).and_then(|layout| layout.elements().ok()).unwrap_or(0)
    }

    fn active_elements(&self) -> u64 {
        self.active_family_elements(C6ResidualFusedCoefficientFamily::Leaf).saturating_add(
            self.active_family_elements(C6ResidualFusedCoefficientFamily::Auxiliary),
        )
    }

    fn reserved_elements(&self) -> u64 {
        u64::try_from(self.backing.capacity()).unwrap_or(u64::MAX)
    }

    fn fold_family(
        &mut self,
        proof_repetition: u8,
        family: C6ResidualFusedCoefficientFamily,
        expected_entries_per_table: u64,
        challenge: Fp2,
    ) -> C6ResidualResult<u64> {
        if self.faulted || self.active_repetition != Some(proof_repetition) {
            return Err(C6ResidualError::new(
                "C6 fused coefficient arena lost its active repetition",
            ));
        }
        let layout = self
            .layout(family)
            .ok_or_else(|| C6ResidualError::new("C6 fused coefficient family is not live"))?;
        let expected_entries = usize::try_from(expected_entries_per_table)
            .map_err(|_| C6ResidualError::new("C6 fused coefficient length exceeds usize"))?;
        if layout.entries_per_table != expected_entries
            || layout.entries_per_table <= 1
            || layout.entries_per_table & 1 != 0
        {
            return Err(C6ResidualError::new(
                "C6 fused coefficient state has no legal binary fold",
            ));
        }
        let next_entries = layout.entries_per_table / 2;
        for table in 0..layout.tables {
            let range = layout.table_range(table)?;
            if range.end > self.backing.len() {
                return Err(C6ResidualError::new(
                    "C6 fused coefficient table exceeds its single backing allocation",
                ));
            }
            for row in 0..next_entries {
                let even = self.backing[range.start + 2 * row];
                let odd = self.backing[range.start + 2 * row + 1];
                self.backing[range.start + row] = even + (odd - even) * challenge;
            }
        }
        let mut next = layout;
        next.entries_per_table = next_entries;
        *self.layout_mut(family) = Some(next);
        u64::try_from(next_entries)
            .map_err(|_| C6ResidualError::new("C6 fused folded length exceeds u64"))
    }

    fn release(
        &mut self,
        proof_repetition: u8,
        family: C6ResidualFusedCoefficientFamily,
        expected_entries_per_table: u64,
    ) {
        if self.active_repetition != Some(proof_repetition) {
            self.faulted = true;
            return;
        }
        let Some(layout) = self.layout(family) else {
            self.faulted = true;
            return;
        };
        if u64::try_from(layout.entries_per_table).ok() != Some(expected_entries_per_table) {
            self.faulted = true;
            return;
        }
        *self.layout_mut(family) = None;
        if self.leaf.is_none() && self.auxiliary.is_none() {
            self.active_repetition = None;
            self.leaf_admitted = false;
            self.auxiliary_admitted = false;
            self.backing = Vec::new();
        }
    }
}

/// Response-local owner of the single legal fused coefficient backing.
///
/// Leaf state is admitted first and allocates the only coefficient buffer.
/// Auxiliary may join the same proof repetition only after leaf reaches the
/// shared suffix; its tables reuse the compacted leaf buffer's tail.
pub struct C6ResidualFusedCoefficientAllocationTracker {
    manifest_digest: C6ResidualDigest,
    state: Arc<Mutex<C6ResidualFusedCoefficientArenaState>>,
}

/// Canonical name for the round-synchronous single-backing owner.
///
/// The original longer type remains source-compatible with the first scaled
/// checkpoint.
pub type C6ResidualFusedCoefficientArena = C6ResidualFusedCoefficientAllocationTracker;

impl C6ResidualFusedCoefficientAllocationTracker {
    pub fn new(manifest: &C6ResidualRelationManifest) -> Self {
        Self {
            manifest_digest: manifest.digest,
            state: Arc::new(Mutex::new(C6ResidualFusedCoefficientArenaState::default())),
        }
    }

    pub fn manifest_digest(&self) -> C6ResidualDigest {
        self.manifest_digest
    }

    fn with_snapshot<R>(&self, read: impl FnOnce(&C6ResidualFusedCoefficientArenaState) -> R) -> R {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        read(&state)
    }

    pub fn active_repetition(&self) -> Option<u8> {
        self.with_snapshot(|state| state.active_repetition)
    }

    pub fn active_elements(&self) -> u64 {
        self.with_snapshot(C6ResidualFusedCoefficientArenaState::active_elements)
    }

    pub fn active_bytes(&self) -> u64 {
        self.active_elements() * std::mem::size_of::<Fp2>() as u64
    }

    pub fn active_leaf_elements(&self) -> u64 {
        self.with_snapshot(|state| {
            state.active_family_elements(C6ResidualFusedCoefficientFamily::Leaf)
        })
    }

    pub fn active_auxiliary_elements(&self) -> u64 {
        self.with_snapshot(|state| {
            state.active_family_elements(C6ResidualFusedCoefficientFamily::Auxiliary)
        })
    }

    pub fn reserved_elements(&self) -> u64 {
        self.with_snapshot(C6ResidualFusedCoefficientArenaState::reserved_elements)
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_elements() * std::mem::size_of::<Fp2>() as u64
    }

    pub fn peak_elements(&self) -> u64 {
        self.with_snapshot(|state| state.peak_logical_elements)
    }

    pub fn peak_bytes(&self) -> u64 {
        self.peak_elements() * std::mem::size_of::<Fp2>() as u64
    }

    pub fn peak_reserved_elements(&self) -> u64 {
        self.with_snapshot(|state| state.peak_reserved_elements)
    }

    pub fn peak_reserved_bytes(&self) -> u64 {
        self.peak_reserved_elements() * std::mem::size_of::<Fp2>() as u64
    }

    pub fn is_faulted(&self) -> bool {
        self.with_snapshot(|state| state.faulted)
    }

    fn reserve(
        &self,
        manifest: &C6ResidualRelationManifest,
        proof_repetition: u8,
        census: C6ResidualFusedCoefficientMemoryCensus,
    ) -> C6ResidualResult<C6ResidualFusedCoefficientAllocationLease> {
        if self.manifest_digest != manifest.digest {
            return Err(C6ResidualError::new(
                "C6 fused allocation tracker uses a different manifest",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| C6ResidualError::new("C6 fused coefficient arena is poisoned"))?;
        if state.faulted {
            return Err(C6ResidualError::new("C6 fused coefficient arena is faulted"));
        }
        let entries = usize::try_from(census.folded_entries_per_table)
            .map_err(|_| C6ResidualError::new("C6 fused coefficient length exceeds usize"))?;
        match census.family {
            C6ResidualFusedCoefficientFamily::Leaf => {
                if state.active_repetition.is_some()
                    || state.leaf_admitted
                    || state.auxiliary_admitted
                    || state.leaf.is_some()
                    || state.auxiliary.is_some()
                    || !state.backing.is_empty()
                {
                    return Err(C6ResidualError::new(
                        "C6 fused leaf state requires an empty coefficient arena",
                    ));
                }
                let required = usize::try_from(census.state_elements).map_err(|_| {
                    C6ResidualError::new("C6 fused leaf backing length exceeds usize")
                })?;
                let mut backing = Vec::new();
                backing.try_reserve_exact(required).map_err(|_| {
                    C6ResidualError::new("C6 fused coefficient backing allocation failed")
                })?;
                if backing.capacity() != required {
                    return Err(C6ResidualError::new(
                        "C6 fused coefficient backing capacity is not exact",
                    ));
                }
                backing.resize(required, Fp2::ZERO);
                state.backing = backing;
                state.active_repetition = Some(proof_repetition);
                state.leaf_admitted = true;
                state.leaf = Some(C6ResidualFusedCoefficientArenaLayout {
                    offset: 0,
                    entries_per_table: entries,
                    table_stride: entries,
                    tables: C6_RESIDUAL_RELATION_LEAF_TABLES,
                });
            }
            C6ResidualFusedCoefficientFamily::Auxiliary => {
                if state.active_repetition != Some(proof_repetition) {
                    return Err(C6ResidualError::new(
                        "C6 fused auxiliary state uses a different or inactive repetition",
                    ));
                }
                if !state.leaf_admitted || state.auxiliary_admitted || state.auxiliary.is_some() {
                    return Err(C6ResidualError::new(
                        "C6 fused auxiliary state is duplicate or lacks its leaf predecessor",
                    ));
                }
                let leaf = state.leaf.ok_or_else(|| {
                    C6ResidualError::new("C6 fused auxiliary state lacks a live leaf layout")
                })?;
                if leaf.entries_per_table != entries {
                    return Err(C6ResidualError::new(
                        "C6 fused auxiliary state was admitted before the shared suffix",
                    ));
                }
                let leaf_elements =
                    leaf.entries_per_table.checked_mul(leaf.tables).ok_or_else(|| {
                        C6ResidualError::new("C6 fused compacted leaf census overflows")
                    })?;
                let auxiliary_linear_tables = usize::try_from(C6_RESIDUAL_AUXILIARY_LANES)
                    .map_err(|_| {
                        C6ResidualError::new("C6 fused auxiliary lane count exceeds usize")
                    })?;
                let auxiliary_tables = auxiliary_linear_tables
                    .checked_add(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len())
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 fused auxiliary table census overflows")
                    })?;
                let auxiliary_elements =
                    entries.checked_mul(auxiliary_tables).ok_or_else(|| {
                        C6ResidualError::new("C6 fused auxiliary state census overflows")
                    })?;
                let combined = leaf_elements
                    .checked_add(auxiliary_elements)
                    .ok_or_else(|| C6ResidualError::new("C6 fused activation census overflows"))?;
                if combined > state.backing.len() {
                    return Err(C6ResidualError::new(
                        "C6 fused activation state does not fit the single leaf backing",
                    ));
                }
                for table in 0..leaf.tables {
                    let source = leaf.table_range(table)?;
                    let destination_start =
                        table.checked_mul(leaf.entries_per_table).ok_or_else(|| {
                            C6ResidualError::new("C6 fused leaf compaction offset overflows")
                        })?;
                    state.backing.copy_within(source, destination_start);
                }
                let auxiliary_end = leaf_elements
                    .checked_add(auxiliary_elements)
                    .ok_or_else(|| C6ResidualError::new("C6 fused auxiliary tail end overflows"))?;
                state.backing[leaf_elements..auxiliary_end].fill(Fp2::ZERO);
                state.leaf = Some(C6ResidualFusedCoefficientArenaLayout {
                    offset: 0,
                    entries_per_table: leaf.entries_per_table,
                    table_stride: leaf.entries_per_table,
                    tables: leaf.tables,
                });
                state.auxiliary = Some(C6ResidualFusedCoefficientArenaLayout {
                    offset: leaf_elements,
                    entries_per_table: entries,
                    table_stride: entries,
                    tables: auxiliary_tables,
                });
                state.auxiliary_admitted = true;
            }
        }
        let active_elements = state.active_elements();
        let reserved_elements = state.reserved_elements();
        if active_elements > C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS
            || reserved_elements > C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS
        {
            state.faulted = true;
            return Err(C6ResidualError::new(
                "C6 fused coefficient arena exceeds the frozen production memory cap",
            ));
        }
        state.peak_logical_elements = state.peak_logical_elements.max(active_elements);
        state.peak_reserved_elements = state.peak_reserved_elements.max(reserved_elements);
        Ok(C6ResidualFusedCoefficientAllocationLease {
            state: Arc::clone(&self.state),
            proof_repetition,
            family: census.family,
            entries_per_table: census.folded_entries_per_table,
        })
    }
}

struct C6ResidualFusedCoefficientAllocationLease {
    state: Arc<Mutex<C6ResidualFusedCoefficientArenaState>>,
    proof_repetition: u8,
    family: C6ResidualFusedCoefficientFamily,
    entries_per_table: u64,
}

impl C6ResidualFusedCoefficientAllocationLease {
    fn fold_next(&mut self, challenge: Fp2) -> C6ResidualResult<u64> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| C6ResidualError::new("C6 fused coefficient arena is poisoned"))?;
        let next = state.fold_family(
            self.proof_repetition,
            self.family,
            self.entries_per_table,
            challenge,
        )?;
        self.entries_per_table = next;
        Ok(next)
    }
}

impl Drop for C6ResidualFusedCoefficientAllocationLease {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.release(self.proof_repetition, self.family, self.entries_per_table);
    }
}

pub struct C6ResidualFusedFoldedCoefficients {
    proof_repetition: u8,
    family: C6ResidualFusedCoefficientFamily,
    challenge: Fp2,
    point: Vec<Fp2>,
    entries_per_table: u64,
    target: Fp2,
    selected_coefficient_writes: u64,
    memory_census: C6ResidualFusedCoefficientMemoryCensus,
    semantic_digest: C6ResidualDigest,
    completion_digest: C6ResidualDigest,
    _allocation_lease: C6ResidualFusedCoefficientAllocationLease,
}

impl C6ResidualFusedFoldedCoefficients {
    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn family(&self) -> C6ResidualFusedCoefficientFamily {
        self.family
    }

    pub fn challenge(&self) -> Fp2 {
        self.challenge
    }

    pub fn point(&self) -> &[Fp2] {
        &self.point
    }

    pub fn entries_per_table(&self) -> u64 {
        self.entries_per_table
    }

    pub fn active_elements(&self) -> u64 {
        let tables =
            self.memory_census.linear_tables.saturating_add(self.memory_census.quadratic_tables);
        self.entries_per_table.saturating_mul(tables)
    }

    pub fn active_bytes(&self) -> u64 {
        self.active_elements() * std::mem::size_of::<Fp2>() as u64
    }

    pub fn is_terminal(&self) -> bool {
        self.entries_per_table == 1
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn selected_coefficient_writes(&self) -> u64 {
        self.selected_coefficient_writes
    }

    pub fn memory_census(&self) -> C6ResidualFusedCoefficientMemoryCensus {
        self.memory_census
    }

    pub fn semantic_digest(&self) -> C6ResidualDigest {
        self.semantic_digest
    }

    /// Metadata-only completion binding.
    ///
    /// The private coefficient arrays are deliberately not hashed: a
    /// production-sized leaf state is 512 MiB and is consumed immediately by
    /// the remaining sumcheck rounds.
    pub fn completion_digest(&self) -> C6ResidualDigest {
        self.completion_digest
    }

    pub fn with_leaf_linear<R>(
        &self,
        read: impl FnOnce([&[Fp2]; C6_RESIDUAL_RELATION_LEAF_TABLES]) -> R,
    ) -> C6ResidualResult<R> {
        if self.family != C6ResidualFusedCoefficientFamily::Leaf {
            return Err(C6ResidualError::new(
                "C6 fused auxiliary state cannot expose leaf coefficient views",
            ));
        }
        let state = self
            ._allocation_lease
            .state
            .lock()
            .map_err(|_| C6ResidualError::new("C6 fused coefficient arena is poisoned"))?;
        let layout =
            state.leaf.ok_or_else(|| C6ResidualError::new("C6 fused leaf layout is not live"))?;
        if layout.tables != C6_RESIDUAL_RELATION_LEAF_TABLES
            || u64::try_from(layout.entries_per_table).ok() != Some(self.entries_per_table)
        {
            return Err(C6ResidualError::new("C6 fused leaf view geometry diverged"));
        }
        let last = layout.table_range(C6_RESIDUAL_RELATION_LEAF_TABLES - 1)?;
        if last.end > state.backing.len() {
            return Err(C6ResidualError::new(
                "C6 fused leaf views exceed their single backing allocation",
            ));
        }
        let tables = std::array::from_fn(|table| {
            let start = layout.offset + table * layout.table_stride;
            &state.backing[start..start + layout.entries_per_table]
        });
        Ok(read(tables))
    }

    pub fn with_auxiliary_tables<R>(
        &self,
        read: impl FnOnce(
            [&[Fp2]; C6_RESIDUAL_AUXILIARY_LANES as usize],
            [&[Fp2]; C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len()],
        ) -> R,
    ) -> C6ResidualResult<R> {
        if self.family != C6ResidualFusedCoefficientFamily::Auxiliary {
            return Err(C6ResidualError::new(
                "C6 fused leaf state cannot expose auxiliary coefficient views",
            ));
        }
        let state = self
            ._allocation_lease
            .state
            .lock()
            .map_err(|_| C6ResidualError::new("C6 fused coefficient arena is poisoned"))?;
        let layout = state
            .auxiliary
            .ok_or_else(|| C6ResidualError::new("C6 fused auxiliary layout is not live"))?;
        let linear_tables = usize::try_from(C6_RESIDUAL_AUXILIARY_LANES)
            .map_err(|_| C6ResidualError::new("C6 fused auxiliary lane count exceeds usize"))?;
        let expected_tables = linear_tables
            .checked_add(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len())
            .ok_or_else(|| C6ResidualError::new("C6 fused auxiliary table census overflows"))?;
        if layout.tables != expected_tables
            || u64::try_from(layout.entries_per_table).ok() != Some(self.entries_per_table)
        {
            return Err(C6ResidualError::new("C6 fused auxiliary view geometry diverged"));
        }
        let last = layout.table_range(expected_tables - 1)?;
        if last.end > state.backing.len() {
            return Err(C6ResidualError::new(
                "C6 fused auxiliary views exceed their single backing allocation",
            ));
        }
        let linear = std::array::from_fn(|table| {
            let start = layout.offset + table * layout.table_stride;
            &state.backing[start..start + layout.entries_per_table]
        });
        let quadratic = std::array::from_fn(|table| {
            let table = linear_tables + table;
            let start = layout.offset + table * layout.table_stride;
            &state.backing[start..start + layout.entries_per_table]
        });
        Ok(read(linear, quadratic))
    }

    /// Bind the next shared sumcheck challenge in place.
    ///
    /// The single backing allocation is folded in place; its physical
    /// capacity never changes.
    pub fn fold_next(&mut self, challenge: Fp2) -> C6ResidualResult<()> {
        if self.entries_per_table <= 1 || self.entries_per_table & 1 != 0 {
            return Err(C6ResidualError::new(
                "C6 fused coefficient state has no legal binary fold",
            ));
        }
        self.point
            .try_reserve(1)
            .map_err(|_| C6ResidualError::new("C6 fused coefficient point allocation failed"))?;
        self.entries_per_table = self._allocation_lease.fold_next(challenge)?;
        self.point.push(challenge);
        Ok(())
    }
}

fn expected_fused_selected_coefficient_writes(
    manifest: &C6ResidualRelationManifest,
    family: C6ResidualFusedCoefficientFamily,
) -> C6ResidualResult<u64> {
    let all = expected_atomic_family_coefficient_writes(manifest)?;
    let sources = u64::from(manifest.topology.source_count);
    let reverse_leaf = sources
        .checked_mul(4)
        .ok_or_else(|| C6ResidualError::new("C6 fused reverse leaf census overflows"))?;
    let reverse_auxiliary = all[C6ResidualAtomicFamily::Reverse.index()]
        .checked_sub(reverse_leaf)
        .ok_or_else(|| C6ResidualError::new("C6 fused reverse auxiliary census underflows"))?;
    let product_leaf = u64::from(manifest.topology.product_closure_count)
        .checked_mul(4)
        .ok_or_else(|| C6ResidualError::new("C6 fused product leaf census overflows"))?;
    let product_auxiliary = all[C6ResidualAtomicFamily::Product.index()]
        .checked_sub(product_leaf)
        .ok_or_else(|| C6ResidualError::new("C6 fused product auxiliary census underflows"))?;
    let selected = match family {
        C6ResidualFusedCoefficientFamily::Leaf => [
            all[C6ResidualAtomicFamily::SourceGrammar.index()],
            all[C6ResidualAtomicFamily::Affine.index()],
            reverse_leaf,
            manifest.raw_copy_entries,
            all[C6ResidualAtomicFamily::LeafTail.index()]
                .checked_add(product_leaf)
                .ok_or_else(|| C6ResidualError::new("C6 fused leaf census overflows"))?,
        ],
        C6ResidualFusedCoefficientFamily::Auxiliary => [
            reverse_auxiliary,
            product_auxiliary,
            all[C6ResidualAtomicFamily::Zero.index()],
            all[C6ResidualAtomicFamily::AuxiliaryTail.index()],
            manifest.raw_copy_entries,
        ],
    };
    selected.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| C6ResidualError::new("C6 fused selected-write census overflows"))
    })
}

struct C6ResidualFusedFoldedCoefficientSink<'a> {
    proof_repetition: u8,
    family: C6ResidualFusedCoefficientFamily,
    challenge: Fp2,
    selected_coefficient_writes: u64,
    arena: std::sync::MutexGuard<'a, C6ResidualFusedCoefficientArenaState>,
}

impl<'a> C6ResidualFusedFoldedCoefficientSink<'a> {
    fn new(
        proof_repetition: u8,
        family: C6ResidualFusedCoefficientFamily,
        challenge: Fp2,
        census: C6ResidualFusedCoefficientMemoryCensus,
        arena: std::sync::MutexGuard<'a, C6ResidualFusedCoefficientArenaState>,
    ) -> C6ResidualResult<Self> {
        if census.family != family {
            return Err(C6ResidualError::new(
                "C6 fused coefficient allocation uses a different family census",
            ));
        }
        if arena.active_repetition != Some(proof_repetition) {
            return Err(C6ResidualError::new(
                "C6 fused coefficient sink uses an inactive repetition",
            ));
        }
        let layout = arena
            .layout(family)
            .ok_or_else(|| C6ResidualError::new("C6 fused coefficient sink lacks its layout"))?;
        let expected_tables =
            usize::try_from(census.linear_tables.checked_add(census.quadratic_tables).ok_or_else(
                || C6ResidualError::new("C6 fused coefficient table census overflows"),
            )?)
            .map_err(|_| C6ResidualError::new("C6 fused coefficient table count exceeds usize"))?;
        if u64::try_from(layout.entries_per_table).ok() != Some(census.folded_entries_per_table)
            || layout.tables != expected_tables
        {
            return Err(C6ResidualError::new(
                "C6 fused coefficient sink layout differs from its census",
            ));
        }
        Ok(Self { proof_repetition, family, challenge, selected_coefficient_writes: 0, arena })
    }

    fn add(&mut self, table: usize, row: u32, coefficient: Fp2) -> C6ResidualResult<()> {
        let selector = if row & 1 == 0 { Fp2::ONE - self.challenge } else { self.challenge };
        let folded_row = usize::try_from(row / 2)
            .map_err(|_| C6ResidualError::new("C6 fused folded row exceeds usize"))?;
        let layout = self
            .arena
            .layout(self.family)
            .ok_or_else(|| C6ResidualError::new("C6 fused coefficient sink lost its layout"))?;
        let range = layout.table_range(table)?;
        let index = range
            .start
            .checked_add(folded_row)
            .ok_or_else(|| C6ResidualError::new("C6 fused folded row index overflows"))?;
        if index >= range.end {
            return Err(C6ResidualError::new("C6 fused folded row is out of range"));
        }
        let entry = self
            .arena
            .backing
            .get_mut(index)
            .ok_or_else(|| C6ResidualError::new("C6 fused folded row is out of range"))?;
        *entry += coefficient * selector;
        Ok(())
    }
}

impl C6ResidualAtomicEventSink for C6ResidualFusedFoldedCoefficientSink<'_> {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new("C6 fused folded sink received a swapped repetition"));
        }
        Ok(())
    }

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new(
                "C6 fused folded coefficient has a swapped repetition",
            ));
        }
        let selected = match (self.family, event.target) {
            (
                C6ResidualFusedCoefficientFamily::Leaf,
                C6ResidualAtomicCoefficientTarget::LeafLinear { table, row },
            ) => {
                self.add(usize::from(table), row, event.coefficient)?;
                true
            }
            (
                C6ResidualFusedCoefficientFamily::Auxiliary,
                C6ResidualAtomicCoefficientTarget::AuxiliaryLinear { table, row },
            ) => {
                self.add(usize::from(table), row, event.coefficient)?;
                true
            }
            (
                C6ResidualFusedCoefficientFamily::Auxiliary,
                C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic { lhs, rhs, row },
            ) => {
                let table = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
                    .iter()
                    .position(|factors| *factors == (lhs, rhs))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 fused folded quadratic tuple is not canonical")
                    })?;
                let linear_tables = usize::try_from(C6_RESIDUAL_AUXILIARY_LANES).map_err(|_| {
                    C6ResidualError::new("C6 fused auxiliary lane count exceeds usize")
                })?;
                self.add(linear_tables + table, row, event.coefficient)?;
                true
            }
            _ => false,
        };
        if selected {
            self.selected_coefficient_writes = self
                .selected_coefficient_writes
                .checked_add(1)
                .ok_or_else(|| C6ResidualError::new("C6 fused selected-write census overflows"))?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compile_c6_residual_fused_folded_coefficients(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    allocation_tracker: &C6ResidualFusedCoefficientAllocationTracker,
    proof_repetition: u8,
    family: C6ResidualFusedCoefficientFamily,
    challenge: Fp2,
) -> C6ResidualResult<C6ResidualFusedFoldedCoefficients> {
    challenges.atomic_schedule(proof_repetition)?;
    let memory_census = c6_residual_fused_coefficient_memory_census(challenges.manifest(), family)?;
    let allocation_lease =
        allocation_tracker.reserve(challenges.manifest(), proof_repetition, memory_census)?;
    let expected_writes =
        expected_fused_selected_coefficient_writes(challenges.manifest(), family)?;
    let arena = allocation_tracker
        .state
        .lock()
        .map_err(|_| C6ResidualError::new("C6 fused coefficient arena is poisoned"))?;
    let mut sink = C6ResidualFusedFoldedCoefficientSink::new(
        proof_repetition,
        family,
        challenge,
        memory_census,
        arena,
    )?;
    let summary = replay_c6_residual_atomic_events(
        operation_plan,
        extraction,
        runtime,
        linear,
        challenges,
        proof_repetition,
        &mut sink,
    )?;
    if sink.selected_coefficient_writes != expected_writes {
        return Err(C6ResidualError::new(format!(
            "C6 fused folded selected-write census differs from the manifest: got {}, expected {}",
            sink.selected_coefficient_writes, expected_writes
        )));
    }
    let selected_coefficient_writes = sink.selected_coefficient_writes;
    drop(sink);
    let mut hasher = blake3::Hasher::new_derive_key(FUSED_FOLDED_COEFFICIENT_DOMAIN);
    hasher.update(&[proof_repetition, family as u8]);
    hasher.update(&summary.semantic_digest);
    hash_fp2(&mut hasher, challenge);
    hasher.update(&memory_census.input_entries_per_table.to_le_bytes());
    hasher.update(&memory_census.folded_entries_per_table.to_le_bytes());
    hasher.update(&memory_census.linear_tables.to_le_bytes());
    hasher.update(&memory_census.quadratic_tables.to_le_bytes());
    hasher.update(&memory_census.state_elements.to_le_bytes());
    hasher.update(&memory_census.state_bytes.to_le_bytes());
    hasher.update(&selected_coefficient_writes.to_le_bytes());
    Ok(C6ResidualFusedFoldedCoefficients {
        proof_repetition,
        family,
        challenge,
        point: vec![challenge],
        entries_per_table: memory_census.folded_entries_per_table,
        target: summary.target,
        selected_coefficient_writes,
        memory_census,
        semantic_digest: summary.semantic_digest,
        completion_digest: *hasher.finalize().as_bytes(),
        _allocation_lease: allocation_lease,
    })
}

/// Constant-memory cursor for `eq(point, row)` in LSB-first order.
///
/// Sequential rows update only the toggled binary digits.  Nonzero factor
/// inverses are precomputed once; zero factors are counted separately, so
/// transcript challenges equal to zero or one require no exceptional path
/// and never invert zero.
struct C6ResidualEqPointCursor {
    entries: u64,
    factors: Vec<[Fp2; 2]>,
    inverses: Vec<[Option<Fp2>; 2]>,
    current_row: Option<u32>,
    nonzero_product: Fp2,
    zero_factors: u32,
}

impl C6ResidualEqPointCursor {
    fn new(point: &[Fp2], entries: u64, label: &str) -> C6ResidualResult<Self> {
        if entries == 0 || !entries.is_power_of_two() {
            return Err(C6ResidualError::new(format!(
                "C6 {label} terminal entries are not a power of two"
            )));
        }
        let expected_point_len = usize::try_from(entries.trailing_zeros())
            .map_err(|_| C6ResidualError::new(format!("C6 {label} point length exceeds usize")))?;
        if point.len() != expected_point_len || point.len() > u32::BITS as usize {
            return Err(C6ResidualError::new(format!(
                "C6 {label} terminal point has the wrong length"
            )));
        }
        let factors =
            point.iter().map(|&coordinate| [Fp2::ONE - coordinate, coordinate]).collect::<Vec<_>>();
        let inverses = factors
            .iter()
            .map(|pair| {
                pair.map(|factor| if factor == Fp2::ZERO { None } else { Some(factor.inv()) })
            })
            .collect();
        Ok(Self {
            entries,
            factors,
            inverses,
            current_row: None,
            nonzero_product: Fp2::ONE,
            zero_factors: 0,
        })
    }

    fn reset(&mut self, row: u32) -> C6ResidualResult<Fp2> {
        if u64::from(row) >= self.entries {
            return Err(C6ResidualError::new("C6 terminal coefficient row is out of range"));
        }
        self.nonzero_product = Fp2::ONE;
        self.zero_factors = 0;
        for (bit, factors) in self.factors.iter().enumerate() {
            let factor = factors[((row >> bit) & 1) as usize];
            if factor == Fp2::ZERO {
                self.zero_factors = self
                    .zero_factors
                    .checked_add(1)
                    .ok_or_else(|| C6ResidualError::new("C6 terminal zero census overflows"))?;
            } else {
                self.nonzero_product = self.nonzero_product * factor;
            }
        }
        self.current_row = Some(row);
        Ok(self.current_value())
    }

    fn replace_factor(&mut self, bit: usize, old: usize, new: usize) -> C6ResidualResult<()> {
        let old_factor = self.factors[bit][old];
        if old_factor == Fp2::ZERO {
            self.zero_factors = self
                .zero_factors
                .checked_sub(1)
                .ok_or_else(|| C6ResidualError::new("C6 terminal zero census underflows"))?;
        } else {
            let inverse = self.inverses[bit][old].ok_or_else(|| {
                C6ResidualError::new("C6 terminal nonzero factor lost its inverse")
            })?;
            self.nonzero_product = self.nonzero_product * inverse;
        }
        let new_factor = self.factors[bit][new];
        if new_factor == Fp2::ZERO {
            self.zero_factors = self
                .zero_factors
                .checked_add(1)
                .ok_or_else(|| C6ResidualError::new("C6 terminal zero census overflows"))?;
        } else {
            self.nonzero_product = self.nonzero_product * new_factor;
        }
        Ok(())
    }

    fn current_value(&self) -> Fp2 {
        if self.zero_factors == 0 {
            self.nonzero_product
        } else {
            Fp2::ZERO
        }
    }

    fn at(&mut self, row: u32) -> C6ResidualResult<Fp2> {
        if u64::from(row) >= self.entries {
            return Err(C6ResidualError::new("C6 terminal coefficient row is out of range"));
        }
        let Some(current) = self.current_row else {
            return self.reset(row);
        };
        if current == row {
            return Ok(self.current_value());
        }
        if current.checked_add(1) != Some(row) {
            return self.reset(row);
        }
        let changed = current ^ row;
        for bit in 0..self.factors.len() {
            if changed & (1u32 << bit) != 0 {
                self.replace_factor(
                    bit,
                    ((current >> bit) & 1) as usize,
                    ((row >> bit) & 1) as usize,
                )?;
            }
        }
        self.current_row = Some(row);
        Ok(self.current_value())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualFusedTerminalCoefficients {
    proof_repetition: u8,
    target: Fp2,
    leaf_point: Vec<Fp2>,
    auxiliary_point: Vec<Fp2>,
    leaf_linear: [Fp2; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_linear: [Fp2; C6_RESIDUAL_AUXILIARY_LANES as usize],
    auxiliary_quadratic: [Fp2; C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len()],
    coefficient_writes: u64,
    semantic_digest: C6ResidualDigest,
    digest: C6ResidualDigest,
}

impl C6ResidualFusedTerminalCoefficients {
    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn leaf_point(&self) -> &[Fp2] {
        &self.leaf_point
    }

    pub fn auxiliary_point(&self) -> &[Fp2] {
        &self.auxiliary_point
    }

    pub fn leaf_linear(&self) -> &[Fp2; C6_RESIDUAL_RELATION_LEAF_TABLES] {
        &self.leaf_linear
    }

    pub fn auxiliary_linear(&self) -> &[Fp2; C6_RESIDUAL_AUXILIARY_LANES as usize] {
        &self.auxiliary_linear
    }

    pub fn auxiliary_quadratic(&self) -> &[Fp2; C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len()] {
        &self.auxiliary_quadratic
    }

    pub fn coefficient_writes(&self) -> u64 {
        self.coefficient_writes
    }

    pub fn semantic_digest(&self) -> C6ResidualDigest {
        self.semantic_digest
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }
}

struct C6ResidualFusedTerminalCoefficientSink {
    proof_repetition: u8,
    leaf_cursor: C6ResidualEqPointCursor,
    auxiliary_cursor: C6ResidualEqPointCursor,
    leaf_linear: [Fp2; C6_RESIDUAL_RELATION_LEAF_TABLES],
    auxiliary_linear: [Fp2; C6_RESIDUAL_AUXILIARY_LANES as usize],
    auxiliary_quadratic: [Fp2; C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len()],
    coefficient_writes: u64,
}

impl C6ResidualAtomicEventSink for C6ResidualFusedTerminalCoefficientSink {
    fn output(&mut self, event: C6ResidualAtomicOutputEvent) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new(
                "C6 fused terminal sink received a swapped repetition",
            ));
        }
        Ok(())
    }

    fn coefficient(
        &mut self,
        event: C6ResidualAtomicCoefficientEvent,
    ) -> Result<(), C6ResidualError> {
        if event.proof_repetition != self.proof_repetition {
            return Err(C6ResidualError::new(
                "C6 fused terminal coefficient has a swapped repetition",
            ));
        }
        match event.target {
            C6ResidualAtomicCoefficientTarget::LeafLinear { table, row } => {
                let equality = self.leaf_cursor.at(row)?;
                let value = self.leaf_linear.get_mut(usize::from(table)).ok_or_else(|| {
                    C6ResidualError::new("C6 fused terminal leaf table is out of range")
                })?;
                *value += event.coefficient * equality;
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryLinear { table, row } => {
                let equality = self.auxiliary_cursor.at(row)?;
                let value = self.auxiliary_linear.get_mut(usize::from(table)).ok_or_else(|| {
                    C6ResidualError::new("C6 fused terminal auxiliary table is out of range")
                })?;
                *value += event.coefficient * equality;
            }
            C6ResidualAtomicCoefficientTarget::AuxiliaryQuadratic { lhs, rhs, row } => {
                let equality = self.auxiliary_cursor.at(row)?;
                let table = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
                    .iter()
                    .position(|factors| *factors == (lhs, rhs))
                    .ok_or_else(|| {
                        C6ResidualError::new("C6 fused terminal quadratic tuple is not canonical")
                    })?;
                self.auxiliary_quadratic[table] += event.coefficient * equality;
            }
        }
        self.coefficient_writes = self
            .coefficient_writes
            .checked_add(1)
            .ok_or_else(|| C6ResidualError::new("C6 terminal coefficient census overflows"))?;
        Ok(())
    }
}

/// Replay the atomic grammar directly into its 8 + 16 + 8 terminal
/// coefficient evaluations.
///
/// This path allocates only the two challenge points and cursor metadata.  It
/// never materializes an equality vector or a coefficient MLE.
#[allow(clippy::too_many_arguments)]
pub fn compile_c6_residual_fused_terminal_coefficients(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    linear: &C6CompiledLinearResidual,
    challenges: &C6ResidualRelationChallenges,
    proof_repetition: u8,
    leaf_point: &[Fp2],
    auxiliary_point: &[Fp2],
) -> C6ResidualResult<C6ResidualFusedTerminalCoefficients> {
    challenges.atomic_schedule(proof_repetition)?;
    let mut sink = C6ResidualFusedTerminalCoefficientSink {
        proof_repetition,
        leaf_cursor: C6ResidualEqPointCursor::new(
            leaf_point,
            challenges.manifest().leaf_entries,
            "leaf",
        )?,
        auxiliary_cursor: C6ResidualEqPointCursor::new(
            auxiliary_point,
            challenges.manifest().auxiliary_entries,
            "auxiliary",
        )?,
        leaf_linear: [Fp2::ZERO; C6_RESIDUAL_RELATION_LEAF_TABLES],
        auxiliary_linear: [Fp2::ZERO; C6_RESIDUAL_AUXILIARY_LANES as usize],
        auxiliary_quadratic: [Fp2::ZERO; C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len()],
        coefficient_writes: 0,
    };
    let summary = replay_c6_residual_atomic_events(
        operation_plan,
        extraction,
        runtime,
        linear,
        challenges,
        proof_repetition,
        &mut sink,
    )?;
    if sink.coefficient_writes != summary.coefficient_writes {
        return Err(C6ResidualError::new(
            "C6 fused terminal coefficient census differs from atomic replay",
        ));
    }
    let mut terminal = C6ResidualFusedTerminalCoefficients {
        proof_repetition,
        target: summary.target,
        leaf_point: leaf_point.to_vec(),
        auxiliary_point: auxiliary_point.to_vec(),
        leaf_linear: sink.leaf_linear,
        auxiliary_linear: sink.auxiliary_linear,
        auxiliary_quadratic: sink.auxiliary_quadratic,
        coefficient_writes: sink.coefficient_writes,
        semantic_digest: summary.semantic_digest,
        digest: [0; 32],
    };
    let mut hasher = blake3::Hasher::new_derive_key(FUSED_TERMINAL_COEFFICIENT_DOMAIN);
    hasher.update(&[proof_repetition]);
    hasher.update(&terminal.semantic_digest);
    hash_fp2(&mut hasher, terminal.target);
    hasher.update(&(terminal.leaf_point.len() as u64).to_le_bytes());
    for value in &terminal.leaf_point {
        hash_fp2(&mut hasher, *value);
    }
    hasher.update(&(terminal.auxiliary_point.len() as u64).to_le_bytes());
    for value in &terminal.auxiliary_point {
        hash_fp2(&mut hasher, *value);
    }
    for value in terminal
        .leaf_linear
        .iter()
        .chain(&terminal.auxiliary_linear)
        .chain(&terminal.auxiliary_quadratic)
    {
        hash_fp2(&mut hasher, *value);
    }
    hasher.update(&terminal.coefficient_writes.to_le_bytes());
    terminal.digest = *hasher.finalize().as_bytes();
    Ok(terminal)
}

/// Provider output of one compiled affine residual coordinate.
///
/// This is constant-size. `leaf_coefficients` remain private to
/// [`C6CompiledLinearResidual`] and are dropped after the response-local
/// provider/client folds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CompiledResidualPlan {
    pub binding: C6CompiledResidualBinding,
    pub residual: C6DeltaResidual,
}

/// Client-local fold of verifier-only base keys under the same coefficient
/// stream used by the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CompiledBaseKeyRlc {
    pub binding: C6CompiledResidualBinding,
    pub base_key_rlc: Fp2,
}

/// Constant-size provider output for the two independent MAC coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CompiledPairedResidualPlan {
    pub binding: C6CompiledResidualBinding,
    pub residual: C6PairedDeltaResidual,
}

/// Client-local verifier-key folds for the two independent MAC coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CompiledPairedBaseKeyRlc {
    pub binding: C6CompiledResidualBinding,
    pub base_key_rlcs: [Fp2; 2],
}

impl C6CompiledResidualPlan {
    pub fn verify(self, client: C6CompiledBaseKeyRlc, delta: Fp2) -> C6ResidualResult<bool> {
        if self.binding != client.binding {
            return Err(C6ResidualError::new(
                "C6 provider/client compiled residual bindings differ",
            ));
        }
        Ok(self.residual.verify(client.base_key_rlc, delta))
    }
}

impl C6CompiledPairedResidualPlan {
    pub fn verify(
        self,
        client: C6CompiledPairedBaseKeyRlc,
        deltas: [Fp2; 2],
    ) -> C6ResidualResult<bool> {
        if self.binding != client.binding {
            return Err(C6ResidualError::new("C6 provider/client paired residual bindings differ"));
        }
        Ok(self.residual.verify(client.base_key_rlcs, deltas))
    }
}

/// Whether one reverse terminal form follows authenticated plaintexts or
/// tags.  Public authenticated constants contribute their value only to the
/// plaintext form; their tag is canonically zero.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6ResidualTerminalFormKind {
    Plaintext = 1,
    Tag = 2,
}

impl C6ResidualTerminalFormKind {
    fn stream_index(self) -> usize {
        match self {
            Self::Plaintext => 0,
            Self::Tag => 1,
        }
    }
}

/// Exact reference schedule for batching installed ProductClosure operands
/// and zero roots into one reverse linear form.
///
/// `product_weights` is flat in installed ProductClosure order, triple
/// order, then `(a,b,c)` component order.  It is local compiler input, never
/// a response field.  A later checkpoint derives these weights from the
/// post-root verifier challenge; this type deliberately does not choose that
/// expansion domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualTerminalWeightSchedule {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology_digest: C6ResidualDigest,
    protocol_version: u8,
    proof_repetition: u8,
    mac_coordinate: u8,
    kind: C6ResidualTerminalFormKind,
    product_weights: Vec<[Fp2; 3]>,
    zero_weights: Vec<Fp2>,
    digest: C6ResidualDigest,
}

impl C6ResidualTerminalWeightSchedule {
    pub fn new(
        operation_plan: &C6InstalledOperationPlan,
        proof_repetition: u8,
        mac_coordinate: u8,
        kind: C6ResidualTerminalFormKind,
        product_weights: Vec<[Fp2; 3]>,
        zero_weights: Vec<Fp2>,
    ) -> C6ResidualResult<Self> {
        Self::new_for_version(
            operation_plan,
            RESIDUAL_RELATION_PROTOCOL_V2,
            proof_repetition,
            mac_coordinate,
            kind,
            product_weights,
            zero_weights,
        )
    }

    fn new_for_version(
        operation_plan: &C6InstalledOperationPlan,
        protocol_version: u8,
        proof_repetition: u8,
        mac_coordinate: u8,
        kind: C6ResidualTerminalFormKind,
        product_weights: Vec<[Fp2; 3]>,
        zero_weights: Vec<Fp2>,
    ) -> C6ResidualResult<Self> {
        if proof_repetition >= C6_RESIDUAL_PROOF_REPETITIONS
            || mac_coordinate >= C6_RESIDUAL_MAC_COORDINATES
            || !matches!(
                protocol_version,
                RESIDUAL_RELATION_PROTOCOL_V2 | RESIDUAL_RELATION_PROTOCOL_V3
            )
        {
            return Err(C6ResidualError::new(
                "C6 residual terminal version/repetition/MAC coordinate is out of range",
            ));
        }
        let product_triples = installed_product_triple_count(operation_plan)?;
        if product_weights.len() as u64 != product_triples
            || zero_weights.len() != operation_plan.zero_roots().len()
        {
            return Err(C6ResidualError::new(
                "C6 residual terminal-weight census differs from installed terminals",
            ));
        }
        let mut schedule = Self {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology_digest: operation_plan.topology().topology_digest,
            protocol_version,
            proof_repetition,
            mac_coordinate,
            kind,
            product_weights,
            zero_weights,
            digest: [0; 32],
        };
        schedule.digest = terminal_weight_schedule_digest(&schedule);
        schedule.validate(operation_plan)?;
        Ok(schedule)
    }

    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn mac_coordinate(&self) -> u8 {
        self.mac_coordinate
    }

    pub fn kind(&self) -> C6ResidualTerminalFormKind {
        self.kind
    }

    pub fn product_weights(&self) -> &[[Fp2; 3]] {
        &self.product_weights
    }

    pub fn zero_weights(&self) -> &[Fp2] {
        &self.zero_weights
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    fn validate(&self, operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<()> {
        if self.proof_repetition >= C6_RESIDUAL_PROOF_REPETITIONS
            || self.mac_coordinate >= C6_RESIDUAL_MAC_COORDINATES
            || !matches!(
                self.protocol_version,
                RESIDUAL_RELATION_PROTOCOL_V2 | RESIDUAL_RELATION_PROTOCOL_V3
            )
            || self.operation_plan_artifact_digest != operation_plan.artifact_digest()
            || self.topology_digest != operation_plan.topology().topology_digest
            || self.product_weights.len() as u64 != installed_product_triple_count(operation_plan)?
            || self.zero_weights.len() != operation_plan.zero_roots().len()
            || self.digest == [0; 32]
            || self.digest != terminal_weight_schedule_digest(self)
        {
            return Err(C6ResidualError::new(
                "C6 residual terminal-weight schedule binding mismatch",
            ));
        }
        Ok(())
    }
}

/// Reference materialization of every residual challenge derived after the
/// five wrapper roots are fixed.
///
/// The outer PCS orchestrator remains responsible for the temporal
/// transition: it must release the fresh client seed only after obtaining a
/// validated fixed-root token.  This bundle binds that root context and
/// prevents downstream code from accepting provider-selected terminal
/// weights.  Its eight materialized schedules are a CPU/reference seam; the
/// production compiler must eventually stream the same expansion.
#[derive(Clone, PartialEq, Eq)]
pub struct C6ResidualPostRootChallenges {
    fixed_roots_digest: C6ResidualDigest,
    operation_plan_artifact_digest: C6ResidualDigest,
    topology_digest: C6ResidualDigest,
    batching_seed_commitment: C6ResidualDigest,
    context_seed: [u8; 32],
    terminal_schedules: [C6ResidualTerminalWeightSchedule; C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS],
    digest: C6ResidualDigest,
}

impl fmt::Debug for C6ResidualPostRootChallenges {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let terminal_schedule_digests =
            self.terminal_schedules.iter().map(|schedule| schedule.digest()).collect::<Vec<_>>();
        formatter
            .debug_struct("C6ResidualPostRootChallenges")
            .field("fixed_roots_digest", &self.fixed_roots_digest)
            .field("operation_plan_artifact_digest", &self.operation_plan_artifact_digest)
            .field("topology_digest", &self.topology_digest)
            .field("batching_seed_commitment", &self.batching_seed_commitment)
            .field("terminal_schedule_digests", &terminal_schedule_digests)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl C6ResidualPostRootChallenges {
    /// Expand the one already-budgeted client batching seed under the fixed
    /// root/plan context.  This method adds no transcript or certificate
    /// field.
    pub fn derive(
        operation_plan: &C6InstalledOperationPlan,
        fixed_roots_digest: C6ResidualDigest,
        batching_seed: [u8; 32],
    ) -> C6ResidualResult<Self> {
        if fixed_roots_digest == [0; 32] {
            return Err(C6ResidualError::new(
                "C6 residual post-root challenges require a nonzero fixed-root binding",
            ));
        }
        let operation_plan_artifact_digest = operation_plan.artifact_digest();
        let topology_digest = operation_plan.topology().topology_digest;

        let mut seed_commitment_hasher =
            blake3::Hasher::new_derive_key(POST_ROOT_SEED_COMMITMENT_DOMAIN);
        seed_commitment_hasher.update(&batching_seed);
        let batching_seed_commitment = *seed_commitment_hasher.finalize().as_bytes();

        let mut context_hasher = blake3::Hasher::new_derive_key(POST_ROOT_CONTEXT_SEED_DOMAIN);
        context_hasher.update(&fixed_roots_digest);
        context_hasher.update(&operation_plan_artifact_digest);
        context_hasher.update(&topology_digest);
        context_hasher.update(&batching_seed);
        let context_seed = *context_hasher.finalize().as_bytes();

        let mut schedules = Vec::with_capacity(C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS);
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    schedules.push(derive_terminal_weight_schedule(
                        operation_plan,
                        RESIDUAL_RELATION_PROTOCOL_V2,
                        proof_repetition,
                        mac_coordinate,
                        kind,
                        context_seed,
                    )?);
                }
            }
        }
        let terminal_schedules: [C6ResidualTerminalWeightSchedule;
            C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS] = schedules
            .try_into()
            .map_err(|_| C6ResidualError::new("C6 residual terminal expansion lost a schedule"))?;
        let mut bundle = Self {
            fixed_roots_digest,
            operation_plan_artifact_digest,
            topology_digest,
            batching_seed_commitment,
            context_seed,
            terminal_schedules,
            digest: [0; 32],
        };
        bundle.digest = post_root_challenges_digest(&bundle);
        bundle.validate(operation_plan)?;
        Ok(bundle)
    }

    pub fn fixed_roots_digest(&self) -> C6ResidualDigest {
        self.fixed_roots_digest
    }

    pub fn batching_seed_commitment(&self) -> C6ResidualDigest {
        self.batching_seed_commitment
    }

    pub fn digest(&self) -> C6ResidualDigest {
        self.digest
    }

    pub fn terminal_schedule(
        &self,
        proof_repetition: u8,
        mac_coordinate: u8,
        kind: C6ResidualTerminalFormKind,
    ) -> C6ResidualResult<&C6ResidualTerminalWeightSchedule> {
        if proof_repetition >= C6_RESIDUAL_PROOF_REPETITIONS
            || mac_coordinate >= C6_RESIDUAL_MAC_COORDINATES
        {
            return Err(C6ResidualError::new(
                "C6 residual terminal schedule proof repetition or MAC coordinate is out of range",
            ));
        }
        let index = usize::from(proof_repetition)
            .checked_mul(usize::from(C6_RESIDUAL_MAC_COORDINATES))
            .and_then(|base| base.checked_add(usize::from(mac_coordinate)))
            .and_then(|base| base.checked_mul(C6_RESIDUAL_TERMINAL_FORM_KINDS))
            .and_then(|base| base.checked_add(kind.stream_index()))
            .ok_or_else(|| C6ResidualError::new("C6 residual terminal schedule index overflows"))?;
        self.terminal_schedules.get(index).ok_or_else(|| {
            C6ResidualError::new(
                "C6 residual terminal schedule proof repetition or MAC coordinate is out of range",
            )
        })
    }

    fn validate(&self, operation_plan: &C6InstalledOperationPlan) -> C6ResidualResult<()> {
        if self.fixed_roots_digest == [0; 32]
            || self.operation_plan_artifact_digest != operation_plan.artifact_digest()
            || self.topology_digest != operation_plan.topology().topology_digest
            || self.batching_seed_commitment == [0; 32]
            || self.context_seed == [0; 32]
            || self.digest == [0; 32]
            || self.digest != post_root_challenges_digest(self)
        {
            return Err(C6ResidualError::new("C6 residual post-root challenge binding mismatch"));
        }
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    let schedule =
                        self.terminal_schedule(proof_repetition, mac_coordinate, kind)?;
                    if schedule.proof_repetition() != proof_repetition
                        || schedule.mac_coordinate() != mac_coordinate
                        || schedule.kind() != kind
                        || schedule.protocol_version() != RESIDUAL_RELATION_PROTOCOL_V2
                    {
                        return Err(C6ResidualError::new(
                            "C6 residual terminal challenge streams are swapped",
                        ));
                    }
                    schedule.validate(operation_plan)?;
                }
            }
        }
        Ok(())
    }

    fn validate_compiled_binding(
        &self,
        operation_plan_artifact_digest: C6ResidualDigest,
        topology: C6OperationPlanTopologyIdentity,
    ) -> C6ResidualResult<()> {
        if self.fixed_roots_digest == [0; 32]
            || self.operation_plan_artifact_digest != operation_plan_artifact_digest
            || self.topology_digest != topology.topology_digest
            || self.batching_seed_commitment == [0; 32]
            || self.context_seed == [0; 32]
            || self.digest == [0; 32]
            || self.digest != post_root_challenges_digest(self)
        {
            return Err(C6ResidualError::new(
                "C6 compiled residual differs from its post-root challenge bundle",
            ));
        }
        Ok(())
    }
}

/// Materialized reference output of one installed terminal reverse form.
///
/// The leaf coefficients remain local and may be consumed by the later
/// sumcheck-statement compiler.  Production credit requires a fused path
/// that does not retain another full source-length vector.
pub struct C6CompiledTerminalLinearForm {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology: C6OperationPlanTopologyIdentity,
    instance: C6OperationPlanInstanceIdentity,
    protocol_version: u8,
    proof_repetition: u8,
    mac_coordinate: u8,
    kind: C6ResidualTerminalFormKind,
    schedule_digest: C6ResidualDigest,
    leaf_coefficients: Vec<Fp2>,
    public_plaintext: Fp2,
    linear_form_digest: C6ResidualDigest,
}

impl fmt::Debug for C6CompiledTerminalLinearForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6CompiledTerminalLinearForm")
            .field("operation_plan_artifact_digest", &self.operation_plan_artifact_digest)
            .field("topology", &self.topology)
            .field("instance", &self.instance)
            .field("protocol_version", &self.protocol_version)
            .field("proof_repetition", &self.proof_repetition)
            .field("mac_coordinate", &self.mac_coordinate)
            .field("kind", &self.kind)
            .field("schedule_digest", &self.schedule_digest)
            .field("leaf_coefficients", &self.leaf_coefficients.len())
            .field("public_plaintext", &self.public_plaintext)
            .field("linear_form_digest", &self.linear_form_digest)
            .finish_non_exhaustive()
    }
}

impl C6CompiledTerminalLinearForm {
    /// Compile one terminal form from the sealed post-root expansion instead
    /// of accepting a caller-provided weight vector.
    pub fn compile_post_root(
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        challenges: &C6ResidualPostRootChallenges,
        proof_repetition: u8,
        mac_coordinate: u8,
        kind: C6ResidualTerminalFormKind,
    ) -> C6ResidualResult<Self> {
        challenges.validate(operation_plan)?;
        Self::compile(
            operation_plan,
            extraction,
            runtime,
            challenges.terminal_schedule(proof_repetition, mac_coordinate, kind)?,
        )
    }

    /// Reference-only entry point for an explicitly supplied schedule.
    /// Production statement assembly must use [`Self::compile_post_root`].
    #[doc(hidden)]
    pub fn compile(
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        schedule: &C6ResidualTerminalWeightSchedule,
    ) -> C6ResidualResult<Self> {
        schedule.validate(operation_plan)?;
        let include_public = schedule.kind == C6ResidualTerminalFormKind::Plaintext;
        let reverse = reverse_installed_linear_form(
            operation_plan,
            extraction,
            runtime,
            include_public,
            |node_coefficients| {
                let mut product_cursor = 0usize;
                for product in operation_plan.products() {
                    for triple in product.triples() {
                        let weights = schedule.product_weights[product_cursor];
                        product_cursor += 1;
                        for (node, weight) in triple.iter().zip(weights) {
                            let coefficient =
                                node_coefficients.get_mut(*node as usize).ok_or_else(|| {
                                    C6ResidualError::new(
                                        "C6 terminal ProductClosure operand is outside the plan",
                                    )
                                })?;
                            *coefficient += weight;
                        }
                    }
                }
                if product_cursor != schedule.product_weights.len() {
                    return Err(C6ResidualError::new(
                        "C6 terminal ProductClosure cursor differs from its schedule",
                    ));
                }
                for (&root, &weight) in
                    operation_plan.zero_roots().iter().zip(&schedule.zero_weights)
                {
                    let coefficient =
                        node_coefficients.get_mut(root as usize).ok_or_else(|| {
                            C6ResidualError::new("C6 terminal zero root is outside the plan")
                        })?;
                    *coefficient += weight;
                }
                Ok(())
            },
        )?;
        if schedule.kind == C6ResidualTerminalFormKind::Tag && reverse.public_plaintext != Fp2::ZERO
        {
            return Err(C6ResidualError::new("C6 tag terminal form acquired a public plaintext"));
        }
        let linear_form_domain = match schedule.protocol_version {
            RESIDUAL_RELATION_PROTOCOL_V2 => TERMINAL_LINEAR_FORM_DOMAIN_V2,
            RESIDUAL_RELATION_PROTOCOL_V3 => TERMINAL_LINEAR_FORM_DOMAIN_V3,
            _ => {
                return Err(C6ResidualError::new(
                    "C6 residual terminal linear form has an unknown protocol version",
                ));
            }
        };
        let mut hasher = blake3::Hasher::new_derive_key(linear_form_domain);
        hasher.update(&operation_plan.artifact_digest());
        hasher.update(&reverse.topology.topology_digest);
        hasher.update(&reverse.instance.instance_digest);
        hasher.update(&[schedule.proof_repetition, schedule.mac_coordinate, schedule.kind as u8]);
        hasher.update(&schedule.digest);
        hash_fp2(&mut hasher, reverse.public_plaintext);
        hasher.update(&(reverse.leaf_coefficients.len() as u64).to_le_bytes());
        for (source, coefficient) in reverse.leaf_coefficients.iter().enumerate() {
            hasher.update(&(source as u32).to_le_bytes());
            hash_fp2(&mut hasher, *coefficient);
        }
        Ok(Self {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology: reverse.topology,
            instance: reverse.instance,
            protocol_version: schedule.protocol_version,
            proof_repetition: schedule.proof_repetition,
            mac_coordinate: schedule.mac_coordinate,
            kind: schedule.kind,
            schedule_digest: schedule.digest,
            leaf_coefficients: reverse.leaf_coefficients,
            public_plaintext: reverse.public_plaintext,
            linear_form_digest: *hasher.finalize().as_bytes(),
        })
    }

    pub fn topology(&self) -> C6OperationPlanTopologyIdentity {
        self.topology
    }

    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    pub fn instance(&self) -> C6OperationPlanInstanceIdentity {
        self.instance
    }

    pub fn proof_repetition(&self) -> u8 {
        self.proof_repetition
    }

    pub fn mac_coordinate(&self) -> u8 {
        self.mac_coordinate
    }

    pub fn kind(&self) -> C6ResidualTerminalFormKind {
        self.kind
    }

    pub fn schedule_digest(&self) -> C6ResidualDigest {
        self.schedule_digest
    }

    pub fn leaf_coefficients(&self) -> &[Fp2] {
        &self.leaf_coefficients
    }

    pub fn public_plaintext(&self) -> Fp2 {
        self.public_plaintext
    }

    pub fn linear_form_digest(&self) -> C6ResidualDigest {
        self.linear_form_digest
    }
}

fn installed_product_triple_count(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<u64> {
    operation_plan.products().iter().try_fold(0u64, |total, product| {
        total
            .checked_add(product.triples().len() as u64)
            .ok_or_else(|| C6ResidualError::new("C6 ProductClosure census overflows"))
    })
}

fn terminal_weight_schedule_digest(
    schedule: &C6ResidualTerminalWeightSchedule,
) -> C6ResidualDigest {
    let domain = match schedule.protocol_version {
        RESIDUAL_RELATION_PROTOCOL_V2 => TERMINAL_WEIGHT_SCHEDULE_DOMAIN_V2,
        RESIDUAL_RELATION_PROTOCOL_V3 => TERMINAL_WEIGHT_SCHEDULE_DOMAIN_V3,
        _ => return [0; 32],
    };
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&schedule.operation_plan_artifact_digest);
    hasher.update(&schedule.topology_digest);
    hasher.update(&[schedule.proof_repetition, schedule.mac_coordinate, schedule.kind as u8]);
    hasher.update(&(schedule.product_weights.len() as u64).to_le_bytes());
    for (triple, weights) in schedule.product_weights.iter().enumerate() {
        hasher.update(&(triple as u64).to_le_bytes());
        for weight in weights {
            hash_fp2(&mut hasher, *weight);
        }
    }
    hasher.update(&(schedule.zero_weights.len() as u64).to_le_bytes());
    for (root, weight) in schedule.zero_weights.iter().enumerate() {
        hasher.update(&(root as u64).to_le_bytes());
        hash_fp2(&mut hasher, *weight);
    }
    *hasher.finalize().as_bytes()
}

fn derive_terminal_weight_schedule(
    operation_plan: &C6InstalledOperationPlan,
    protocol_version: u8,
    proof_repetition: u8,
    mac_coordinate: u8,
    kind: C6ResidualTerminalFormKind,
    context_seed: [u8; 32],
) -> C6ResidualResult<C6ResidualTerminalWeightSchedule> {
    let domain = *TERMINAL_WEIGHT_STREAM_DOMAINS
        .get(usize::from(proof_repetition))
        .and_then(|coordinates| coordinates.get(usize::from(mac_coordinate)))
        .and_then(|kinds| kinds.get(kind.stream_index()))
        .ok_or_else(|| C6ResidualError::new("C6 residual terminal stream domain is missing"))?;
    let product_triples = usize::try_from(installed_product_triple_count(operation_plan)?)
        .map_err(|_| {
            C6ResidualError::new("C6 residual ProductClosure triple count exceeds usize")
        })?;
    let mut stream = FpStream::domain_separated(context_seed, domain);
    let mut product_weights = Vec::new();
    product_weights.try_reserve_exact(product_triples).map_err(|_| {
        C6ResidualError::new("C6 residual terminal product-weight allocation failed")
    })?;
    for _ in 0..product_triples {
        product_weights.push([stream.next_fp2(), stream.next_fp2(), stream.next_fp2()]);
    }
    let mut zero_weights = Vec::new();
    zero_weights
        .try_reserve_exact(operation_plan.zero_roots().len())
        .map_err(|_| C6ResidualError::new("C6 residual terminal zero-weight allocation failed"))?;
    for _ in operation_plan.zero_roots() {
        zero_weights.push(stream.next_fp2());
    }
    C6ResidualTerminalWeightSchedule::new_for_version(
        operation_plan,
        protocol_version,
        proof_repetition,
        mac_coordinate,
        kind,
        product_weights,
        zero_weights,
    )
}

fn post_root_challenges_digest(challenges: &C6ResidualPostRootChallenges) -> C6ResidualDigest {
    let mut hasher = blake3::Hasher::new_derive_key(POST_ROOT_CHALLENGES_DOMAIN);
    hasher.update(&challenges.fixed_roots_digest);
    hasher.update(&challenges.operation_plan_artifact_digest);
    hasher.update(&challenges.topology_digest);
    hasher.update(&challenges.batching_seed_commitment);
    hasher.update(&challenges.context_seed);
    hasher.update(&(challenges.terminal_schedules.len() as u64).to_le_bytes());
    for schedule in &challenges.terminal_schedules {
        hasher.update(&[
            schedule.proof_repetition(),
            schedule.mac_coordinate(),
            schedule.kind() as u8,
        ]);
        hasher.update(&schedule.digest());
    }
    *hasher.finalize().as_bytes()
}

struct C6ReverseInstalledLinearForm {
    topology: C6OperationPlanTopologyIdentity,
    instance: C6OperationPlanInstanceIdentity,
    leaf_coefficients: Vec<Fp2>,
    product_mask_sources: Vec<u32>,
    public_plaintext: Fp2,
}

fn reverse_installed_linear_form(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    include_public_inputs: bool,
    seed_terminals: impl FnOnce(&mut [Fp2]) -> C6ResidualResult<()>,
) -> C6ResidualResult<C6ReverseInstalledLinearForm> {
    let decoded = operation_plan.decoded();
    let topology = decoded.topology;
    let instance = runtime.instance_identity();
    let extraction_census = extraction.census();
    runtime
        .validate_extraction_binding(extraction)
        .map_err(|error| C6ResidualError::new(error.to_string()))?;
    if runtime.role() != extraction.role()
        || extraction.topology_digest() != topology.topology_digest
        || instance.version != topology.version
        || instance.topology_digest != topology.topology_digest
        || instance.public_input_count != topology.public_input_count
        || instance.scalar_input_count != topology.scalar_input_count
        || extraction_census.canonical_public_input_count != topology.public_input_count
        || extraction_census.canonical_scalar_input_count != topology.scalar_input_count
    {
        return Err(C6ResidualError::new(
            "C6 installed plan, runtime instance and extraction map differ",
        ));
    }
    let canonical_node_count = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6 canonical node count exceeds usize"))?;
    let source_count = usize::try_from(topology.source_count)
        .map_err(|_| C6ResidualError::new("C6 source count exceeds usize"))?;
    if operation_plan.operation_kinds().len() != canonical_node_count
        || operation_plan.source_ordinals().len() as u64 != decoded.node_kinds.source
        || operation_plan.operands().len() as u64 != decoded.encoding.operand_count
        || operation_plan.products().len() != topology.product_closure_count as usize
        || operation_plan.zero_roots().len() != topology.zero_root_count as usize
        || installed_product_triple_count(operation_plan)? != topology.product_triple_count
    {
        return Err(C6ResidualError::new(
            "C6 installed reverse arrays differ from their decoded census",
        ));
    }

    let mut node_coefficients =
        try_zeroed_fp2_vec(canonical_node_count, "C6 reverse node workspace")?;
    seed_terminals(&mut node_coefficients)?;
    let mut leaf_coefficients = try_zeroed_fp2_vec(source_count, "C6 reverse leaf coefficients")?;

    let mut product_mask_nodes = Vec::with_capacity(operation_plan.products().len());
    product_mask_nodes.extend(operation_plan.products().iter().map(|product| product.mask()));
    product_mask_nodes.sort_unstable();
    if product_mask_nodes.windows(2).any(|window| window[0] == window[1]) {
        return Err(C6ResidualError::new("C6 installed ProductClosure mask node is reused"));
    }

    let mut source_cursor = operation_plan.source_ordinals().len();
    let mut operand_cursor = operation_plan.operands().len();
    let mut public_cursor = topology.public_input_count as usize;
    let mut scalar_cursor = topology.scalar_input_count as usize;
    let mut product_mask_sources = Vec::with_capacity(product_mask_nodes.len());
    let mut public_plaintext = Fp2::ZERO;

    for (canonical, &kind) in operation_plan.operation_kinds().iter().enumerate().rev() {
        let coefficient = node_coefficients[canonical];
        match kind {
            C6InstalledOperationKind::Source => {
                source_cursor = source_cursor
                    .checked_sub(1)
                    .ok_or_else(|| C6ResidualError::new("C6 installed source cursor underflows"))?;
                let source = operation_plan.source_ordinals()[source_cursor] as usize;
                let leaf = leaf_coefficients.get_mut(source).ok_or_else(|| {
                    C6ResidualError::new("C6 installed source is outside its manifest")
                })?;
                *leaf += coefficient;
                if product_mask_nodes.binary_search(&(canonical as u32)).is_ok() {
                    if coefficient != Fp2::ZERO {
                        return Err(C6ResidualError::new(
                            "C6 ProductClosure mask acquired a linear coefficient",
                        ));
                    }
                    product_mask_sources.push(source as u32);
                }
            }
            C6InstalledOperationKind::StructuralZero => {}
            C6InstalledOperationKind::PublicInput => {
                public_cursor = public_cursor.checked_sub(1).ok_or_else(|| {
                    C6ResidualError::new("C6 installed public-input cursor underflows")
                })?;
                if include_public_inputs && coefficient != Fp2::ZERO {
                    let value = runtime
                        .public_value(extraction, public_cursor as u32)
                        .map_err(|error| C6ResidualError::new(error.to_string()))?;
                    public_plaintext += coefficient * value;
                }
            }
            C6InstalledOperationKind::Add | C6InstalledOperationKind::Sub => {
                operand_cursor = operand_cursor.checked_sub(2).ok_or_else(|| {
                    C6ResidualError::new("C6 installed binary-operand cursor underflows")
                })?;
                let lhs = operation_plan.operands()[operand_cursor] as usize;
                let rhs = operation_plan.operands()[operand_cursor + 1] as usize;
                if lhs >= canonical || rhs >= canonical {
                    return Err(C6ResidualError::new(
                        "C6 installed binary operation is not topological",
                    ));
                }
                if coefficient != Fp2::ZERO {
                    node_coefficients[lhs] += coefficient;
                    if kind == C6InstalledOperationKind::Add {
                        node_coefficients[rhs] += coefficient;
                    } else {
                        node_coefficients[rhs] = node_coefficients[rhs] - coefficient;
                    }
                }
            }
            C6InstalledOperationKind::Scale => {
                operand_cursor = operand_cursor.checked_sub(1).ok_or_else(|| {
                    C6ResidualError::new("C6 installed scale-operand cursor underflows")
                })?;
                scalar_cursor = scalar_cursor.checked_sub(1).ok_or_else(|| {
                    C6ResidualError::new("C6 installed scalar-input cursor underflows")
                })?;
                let input = operation_plan.operands()[operand_cursor] as usize;
                if input >= canonical {
                    return Err(C6ResidualError::new(
                        "C6 installed scale operation is not topological",
                    ));
                }
                if coefficient != Fp2::ZERO {
                    let scalar = runtime
                        .scalar_value(extraction, scalar_cursor as u32)
                        .map_err(|error| C6ResidualError::new(error.to_string()))?;
                    node_coefficients[input] += coefficient * scalar;
                }
            }
        }
    }
    if source_cursor != 0
        || operand_cursor != 0
        || public_cursor != 0
        || scalar_cursor != 0
        || product_mask_sources.len() != topology.product_closure_count as usize
    {
        return Err(C6ResidualError::new(
            "C6 installed reverse cursors differ from their exact census",
        ));
    }
    product_mask_sources.sort_unstable();
    Ok(C6ReverseInstalledLinearForm {
        topology,
        instance,
        leaf_coefficients,
        product_mask_sources,
        public_plaintext,
    })
}

/// Response-local reverse accumulation over the strictly installed
/// parameterized operation plan.
///
/// The dense node workspace is local scratch. The retained leaf vector has
/// one `Fp2` per canonical source schedule entry and never crosses the setup
/// or response wire.
pub struct C6CompiledLinearResidual {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology: C6OperationPlanTopologyIdentity,
    instance: C6OperationPlanInstanceIdentity,
    leaf_coefficients: Vec<Fp2>,
    product_mask_sources: Vec<u32>,
    public_plaintext: Fp2,
    linear_form_digest: C6ResidualDigest,
}

impl fmt::Debug for C6CompiledLinearResidual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6CompiledLinearResidual")
            .field("operation_plan_artifact_digest", &self.operation_plan_artifact_digest)
            .field("topology", &self.topology)
            .field("instance", &self.instance)
            .field("leaf_coefficients", &self.leaf_coefficients.len())
            .field("product_mask_sources", &self.product_mask_sources.len())
            .field("public_plaintext", &self.public_plaintext)
            .field("linear_form_digest", &self.linear_form_digest)
            .finish_non_exhaustive()
    }
}

impl C6CompiledLinearResidual {
    pub fn compile(
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        zero_weights: &[Fp2],
    ) -> C6ResidualResult<Self> {
        if zero_weights.len() != operation_plan.zero_roots().len() {
            return Err(C6ResidualError::new(
                "C6 zero-closure weight count differs from installed terminals",
            ));
        }
        let reverse = reverse_installed_linear_form(
            operation_plan,
            extraction,
            runtime,
            true,
            |node_coefficients| {
                for (&root, &weight) in operation_plan.zero_roots().iter().zip(zero_weights) {
                    let coefficient =
                        node_coefficients.get_mut(root as usize).ok_or_else(|| {
                            C6ResidualError::new("C6 zero root is outside the installed plan")
                        })?;
                    *coefficient += weight;
                }
                Ok(())
            },
        )?;

        let mut linear_hasher = blake3::Hasher::new();
        linear_hasher.update(COMPILED_LINEAR_FORM_DOMAIN);
        linear_hasher.update(&operation_plan.artifact_digest());
        linear_hasher.update(&reverse.topology.topology_digest);
        linear_hasher.update(&reverse.instance.instance_digest);
        linear_hasher.update(&reverse.topology.source_count.to_le_bytes());
        linear_hasher.update(&(zero_weights.len() as u64).to_le_bytes());
        for weight in zero_weights {
            hash_fp2(&mut linear_hasher, *weight);
        }
        hash_fp2(&mut linear_hasher, reverse.public_plaintext);
        for (source, coefficient) in reverse.leaf_coefficients.iter().enumerate() {
            linear_hasher.update(&(source as u32).to_le_bytes());
            hash_fp2(&mut linear_hasher, *coefficient);
        }
        let linear_form_digest = *linear_hasher.finalize().as_bytes();

        Ok(Self {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology: reverse.topology,
            instance: reverse.instance,
            leaf_coefficients: reverse.leaf_coefficients,
            product_mask_sources: reverse.product_mask_sources,
            public_plaintext: reverse.public_plaintext,
            linear_form_digest,
        })
    }

    pub fn topology(&self) -> C6OperationPlanTopologyIdentity {
        self.topology
    }

    pub fn operation_plan_artifact_digest(&self) -> C6ResidualDigest {
        self.operation_plan_artifact_digest
    }

    pub fn instance(&self) -> C6OperationPlanInstanceIdentity {
        self.instance
    }

    pub fn source_count(&self) -> usize {
        self.leaf_coefficients.len()
    }

    /// Local coefficient view for the residual-sumcheck statement compiler.
    /// The slice is reconstructed independently by both response roles and
    /// is never serialized as setup or certificate data.
    pub fn leaf_coefficients(&self) -> &[Fp2] {
        &self.leaf_coefficients
    }

    pub fn product_mask_sources(&self) -> &[u32] {
        &self.product_mask_sources
    }

    pub fn public_plaintext(&self) -> Fp2 {
        self.public_plaintext
    }

    pub fn linear_form_digest(&self) -> C6ResidualDigest {
        self.linear_form_digest
    }

    pub fn memory_census(&self) -> C6ResidualResult<C6CompiledLinearResidualMemoryCensus> {
        let bytes = |capacity: usize, element_bytes: usize, label: &str| {
            let capacity = u64::try_from(capacity)
                .map_err(|_| C6ResidualError::new(format!("{label} capacity exceeds u64")))?;
            let element_bytes = u64::try_from(element_bytes)
                .map_err(|_| C6ResidualError::new(format!("{label} element size exceeds u64")))?;
            let bytes = capacity
                .checked_mul(element_bytes)
                .ok_or_else(|| C6ResidualError::new(format!("{label} byte count overflows")))?;
            Ok((capacity, bytes))
        };
        let node_workspace_elements = u64::from(self.topology.canonical_node_count);
        let node_workspace_bytes = node_workspace_elements
            .checked_mul(std::mem::size_of::<Fp2>() as u64)
            .ok_or_else(|| C6ResidualError::new("C6 reverse node workspace bytes overflow"))?;
        let (leaf_coefficient_capacity, leaf_coefficient_heap_bytes) = bytes(
            self.leaf_coefficients.capacity(),
            std::mem::size_of::<Fp2>(),
            "C6 leaf coefficient",
        )?;
        let (product_mask_capacity, product_mask_heap_bytes) = bytes(
            self.product_mask_sources.capacity(),
            std::mem::size_of::<u32>(),
            "C6 ProductMask source",
        )?;
        let inline_bytes = std::mem::size_of::<Self>() as u64;
        let retained_resident_bytes = inline_bytes
            .checked_add(leaf_coefficient_heap_bytes)
            .and_then(|total| total.checked_add(product_mask_heap_bytes))
            .ok_or_else(|| C6ResidualError::new("C6 compiled residual residency overflows"))?;
        let peak_compile_resident_bytes = retained_resident_bytes
            .checked_add(node_workspace_bytes)
            .ok_or_else(|| C6ResidualError::new("C6 compiled residual peak residency overflows"))?;
        Ok(C6CompiledLinearResidualMemoryCensus {
            node_workspace_elements,
            node_workspace_bytes,
            leaf_coefficient_elements: self.leaf_coefficients.len() as u64,
            leaf_coefficient_capacity,
            leaf_coefficient_heap_bytes,
            product_mask_elements: self.product_mask_sources.len() as u64,
            product_mask_capacity,
            product_mask_heap_bytes,
            inline_bytes,
            retained_resident_bytes,
            peak_compile_resident_bytes,
        })
    }

    fn fold_coefficients(
        &self,
        transcript: &mut Transcript,
        mut fold: impl FnMut(u32, Fp2, Fp2, Fp2) -> C6ResidualResult<()>,
    ) -> C6ResidualResult<C6ResidualDigest> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMPILED_COEFFICIENT_DOMAIN);
        hasher.update(&self.linear_form_digest);
        hasher.update(&self.topology.source_count.to_le_bytes());
        for (source, &linear) in self.leaf_coefficients.iter().enumerate() {
            let source = source as u32;
            let alpha = transcript.challenge_fp2();
            let coefficient = linear + alpha;
            hasher.update(&source.to_le_bytes());
            hash_fp2(&mut hasher, coefficient);
            fold(source, linear, alpha, coefficient)?;
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn fold_paired_coefficients(
        &self,
        batching_seed: [u8; 32],
        mut fold: impl FnMut(u32, Fp2, [Fp2; 2], [Fp2; 2]) -> C6ResidualResult<()>,
    ) -> C6ResidualResult<C6ResidualDigest> {
        let mut streams = PAIRED_COEFFICIENT_STREAM_DOMAINS
            .map(|domain| FpStream::domain_separated(batching_seed, domain));
        let mut hasher = blake3::Hasher::new();
        hasher.update(PAIRED_COMPILED_COEFFICIENT_DOMAIN);
        hasher.update(&self.linear_form_digest);
        hasher.update(&self.topology.source_count.to_le_bytes());
        hasher.update(&batching_seed);
        for (source, &linear) in self.leaf_coefficients.iter().enumerate() {
            let source = source as u32;
            let alphas = [streams[0].next_fp2(), streams[1].next_fp2()];
            let coefficients = [linear + alphas[0], linear + alphas[1]];
            hasher.update(&source.to_le_bytes());
            for coordinate in 0..2 {
                hasher.update(&[coordinate as u8]);
                hash_fp2(&mut hasher, alphas[coordinate]);
                hash_fp2(&mut hasher, coefficients[coordinate]);
            }
            fold(source, linear, alphas, coefficients)?;
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn binding(&self, coefficient_digest: C6ResidualDigest) -> C6CompiledResidualBinding {
        C6CompiledResidualBinding {
            operation_plan_artifact_digest: self.operation_plan_artifact_digest,
            topology_digest: self.topology.topology_digest,
            instance_digest: self.instance.instance_digest,
            linear_form_digest: self.linear_form_digest,
            coefficient_digest,
            source_count: self.topology.source_count,
        }
    }

    /// Reference provider fold over an already materialized canonical source
    /// slice. Production callers use the paired witness streaming seam, so
    /// this method never implies a response serialization.
    pub fn respond_sources(
        &self,
        sources: &[C6SourceWitness],
        transcript: &mut Transcript,
    ) -> C6ResidualResult<C6CompiledResidualPlan> {
        if sources.len() != self.leaf_coefficients.len() {
            return Err(C6ResidualError::new(
                "C6 provider source vector differs from installed source census",
            ));
        }
        for &source in &self.product_mask_sources {
            if !sources[source as usize].is_uncorrected_full() {
                return Err(C6ResidualError::new(
                    "C6 installed ProductClosure mask witness is not full and uncorrected",
                ));
            }
        }

        let mut correction_rlc = self.public_plaintext;
        let mut public_tag_rlc = Fp2::ZERO;
        let coefficient_digest =
            self.fold_coefficients(transcript, |source, linear, alpha, coefficient| {
                let witness = sources[source as usize];
                correction_rlc += linear * witness.correction();
                correction_rlc = correction_rlc - alpha * witness.base_plaintext();
                public_tag_rlc += coefficient * witness.tag();
                Ok(())
            })?;
        Ok(C6CompiledResidualPlan {
            binding: self.binding(coefficient_digest),
            residual: C6DeltaResidual { correction_rlc, public_tag_rlc },
        })
    }

    fn validate_paired_source_schedule(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
    ) -> C6ResidualResult<()> {
        if !schedule.is_canonical()
            || sources.schedule_digest() != schedule.digest
            || sources.source_schedule_digest() != self.topology.source_schedule_digest
        {
            return Err(C6ResidualError::new(
                "C6 paired source witness differs from the canonical allocation schedule",
            ));
        }
        for coordinate in sources.coordinates() {
            coordinate.subfield().validate_against(schedule).map_err(C6ResidualError::new)?;
            coordinate.fullfield().validate_against(schedule).map_err(C6ResidualError::new)?;
        }
        if sources.subfield_leaf_count() as u64 != schedule.counters.sub_corrs
            || sources.fullfield_leaf_count() as u64 != schedule.counters.full_corrs
        {
            return Err(C6ResidualError::new(
                "C6 paired source witness counts differ from the allocation schedule",
            ));
        }

        let mut next_source = 0u64;
        let mut product_mask_sources = Vec::new();
        for draw in &schedule.draws {
            if draw.role == CorrScheduleRole::ProductMask {
                if draw.kind != CorrScheduleKind::FullField || draw.count != 1 {
                    return Err(C6ResidualError::new(
                        "C6 source schedule contains a noncanonical ProductMask draw",
                    ));
                }
                product_mask_sources.push(u32::try_from(next_source).map_err(|_| {
                    C6ResidualError::new("C6 ProductMask source ordinal exceeds u32")
                })?);
            }
            next_source = next_source.checked_add(draw.count).ok_or_else(|| {
                C6ResidualError::new("C6 flattened source schedule count overflows")
            })?;
        }
        if next_source != self.topology.source_count as u64
            || product_mask_sources != self.product_mask_sources
        {
            return Err(C6ResidualError::new(
                "C6 paired source schedule differs from the installed operation plan",
            ));
        }
        Ok(())
    }

    /// Build the exact seven live residual source columns from the two
    /// independently backed tapes.  The installed plan supplies the
    /// authoritative ProductMask ordinals and source-schedule binding.
    pub fn build_paired_residual_leaf_witness(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
    ) -> C6ResidualResult<C6PairedResidualLeafWitness> {
        self.validate_paired_source_schedule(sources, schedule)?;
        if u64::from(self.topology.source_count) > C6_RESIDUAL_SLOT_ENTRIES {
            return Err(C6ResidualError::new(
                "C6 paired residual leaves exceed the frozen slot capacity",
            ));
        }

        let source_count = self.topology.source_count as usize;
        let mut columns: [Vec<Fp2>; C6_RESIDUAL_LEAF_ALIGNED_SLOTS as usize] =
            std::array::from_fn(|_| Vec::new());
        for column in &mut columns {
            column
                .try_reserve_exact(source_count)
                .map_err(|_| C6ResidualError::new("C6 residual leaf-column allocation failed"))?;
        }

        let mut hasher = blake3::Hasher::new_derive_key(PAIRED_LEAF_WRAPPER_DOMAIN);
        hasher.update(&self.topology.source_schedule_digest);
        hasher.update(&sources.pair_digest());
        hasher.update(&self.topology.source_count.to_le_bytes());
        hasher.update(&(self.product_mask_sources.len() as u64).to_le_bytes());

        let mut cursor = C6PairedSourceCursor::new(sources, schedule);
        for source in 0..self.topology.source_count {
            let witnesses = cursor.next(source)?;
            let is_product_mask = self.product_mask_sources.binary_search(&source).is_ok();
            let x = [
                witnesses[0].base_plaintext() + witnesses[0].correction(),
                witnesses[1].base_plaintext() + witnesses[1].correction(),
            ];
            let common_plaintext = if is_product_mask {
                if witnesses.iter().any(|witness| witness.correction() != Fp2::ZERO) {
                    return Err(C6ResidualError::new(
                        "C6 ProductMask acquired a correction in the wrapper source bridge",
                    ));
                }
                Fp2::ZERO
            } else {
                if x[0] != x[1] {
                    return Err(C6ResidualError::new(
                        "C6 direct source plaintext differs across residual coordinates",
                    ));
                }
                x[0]
            };
            let row = [
                common_plaintext,
                witnesses[0].base_plaintext(),
                witnesses[0].tag(),
                witnesses[0].correction(),
                witnesses[1].base_plaintext(),
                witnesses[1].tag(),
                witnesses[1].correction(),
            ];
            for (column, value) in columns.iter_mut().zip(row) {
                column.push(value);
            }
            hasher.update(&source.to_le_bytes());
            hasher.update(&[u8::from(is_product_mask)]);
            for value in row {
                hash_fp2(&mut hasher, value);
            }
        }
        cursor.finish(self.topology.source_count)?;
        if columns.iter().any(|column| column.len() != source_count) {
            return Err(C6ResidualError::new(
                "C6 paired residual leaf columns have different lengths",
            ));
        }

        let product_mask_count = u32::try_from(self.product_mask_sources.len())
            .map_err(|_| C6ResidualError::new("C6 ProductMask count exceeds u32"))?;
        Ok(C6PairedResidualLeafWitness {
            source_schedule_digest: self.topology.source_schedule_digest,
            paired_source_digest: sources.pair_digest(),
            source_count: self.topology.source_count,
            product_mask_count,
            columns,
            witness_digest: *hasher.finalize().as_bytes(),
        })
    }

    /// Evaluate the installed response DAG on both authenticated source
    /// tapes and retain only ProductClosure operands and zero roots.
    ///
    /// Node values are released after their last operation/terminal use.  A
    /// dense pair of authenticated values for every canonical node is never
    /// allocated.  This is the production-shape bridge from typed response
    /// roots to residual slot 7; it remains provider-local and serializes
    /// neither the operation plan nor its scratch state.
    pub fn evaluate_installed_paired_closure(
        &self,
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
    ) -> C6ResidualResult<C6InstalledPairedClosureEvaluation> {
        self.validate_paired_source_schedule(sources, schedule)?;
        runtime
            .validate_extraction_binding(extraction)
            .map_err(|error| C6ResidualError::new(error.to_string()))?;
        if self.operation_plan_artifact_digest != operation_plan.artifact_digest()
            || self.topology != operation_plan.topology()
            || self.instance != runtime.instance_identity()
            || extraction.topology_digest() != self.topology.topology_digest
            || runtime.role() != extraction.role()
        {
            return Err(C6ResidualError::new(
                "C6 installed closure inputs differ from the compiled response identity",
            ));
        }
        evaluate_installed_paired_closure(operation_plan, extraction, runtime, sources, schedule)
    }

    /// Production-shape provider fold over both source coordinates in the
    /// canonical interleaved allocation order. The paired witness remains a
    /// prover-only sidecar and is streamed once.
    pub fn respond_paired_sources_post_root(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
        challenges: &C6ResidualPostRootChallenges,
    ) -> C6ResidualResult<C6CompiledPairedResidualPlan> {
        challenges.validate_compiled_binding(self.operation_plan_artifact_digest, self.topology)?;
        self.respond_paired_sources(sources, schedule, challenges.context_seed)
    }

    /// Diagnostic/raw-seed seam retained for frozen records and scaled
    /// differentials.  Production wrapper integration uses
    /// [`Self::respond_paired_sources_post_root`].
    #[doc(hidden)]
    pub fn respond_paired_sources(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
        batching_seed: [u8; 32],
    ) -> C6ResidualResult<C6CompiledPairedResidualPlan> {
        self.validate_paired_source_schedule(sources, schedule)?;
        let mut cursor = C6PairedSourceCursor::new(sources, schedule);
        let mut correction_rlcs = [self.public_plaintext; 2];
        let mut public_tag_rlcs = [Fp2::ZERO; 2];
        let coefficient_digest = self.fold_paired_coefficients(
            batching_seed,
            |source, linear, alphas, coefficients| {
                let witnesses = cursor.next(source)?;
                for coordinate in 0..2 {
                    correction_rlcs[coordinate] += linear * witnesses[coordinate].correction();
                    correction_rlcs[coordinate] = correction_rlcs[coordinate]
                        - alphas[coordinate] * witnesses[coordinate].base_plaintext();
                    public_tag_rlcs[coordinate] +=
                        coefficients[coordinate] * witnesses[coordinate].tag();
                }
                Ok(())
            },
        )?;
        cursor.finish(self.topology.source_count)?;
        Ok(C6CompiledPairedResidualPlan {
            binding: self.binding(coefficient_digest),
            residual: C6PairedDeltaResidual {
                coordinates: [
                    C6DeltaResidual {
                        correction_rlc: correction_rlcs[0],
                        public_tag_rlc: public_tag_rlcs[0],
                    },
                    C6DeltaResidual {
                        correction_rlc: correction_rlcs[1],
                        public_tag_rlc: public_tag_rlcs[1],
                    },
                ],
            },
        })
    }

    /// Client-only streaming fold of verifier base keys. The transcript must
    /// be positioned at the same post-commit challenge boundary as the
    /// provider transcript; the coefficient digest detects divergence.
    pub fn fold_base_keys(
        &self,
        base_keys: &[Fp2],
        transcript: &mut Transcript,
    ) -> C6ResidualResult<C6CompiledBaseKeyRlc> {
        if base_keys.len() != self.leaf_coefficients.len() {
            return Err(C6ResidualError::new(
                "C6 verifier base-key vector differs from installed source census",
            ));
        }
        let mut base_key_rlc = Fp2::ZERO;
        let coefficient_digest =
            self.fold_coefficients(transcript, |source, _, _, coefficient| {
                base_key_rlc += coefficient * base_keys[source as usize];
                Ok(())
            })?;
        Ok(C6CompiledBaseKeyRlc { binding: self.binding(coefficient_digest), base_key_rlc })
    }

    /// Client-only paired base-key fold. The two vectors are local
    /// verifier-tape views; neither vector nor the derived coefficients is a
    /// certificate field.
    pub fn fold_paired_base_keys_post_root(
        &self,
        base_keys: [&[Fp2]; 2],
        challenges: &C6ResidualPostRootChallenges,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        challenges.validate_compiled_binding(self.operation_plan_artifact_digest, self.topology)?;
        self.fold_paired_base_keys(base_keys, challenges.context_seed)
    }

    /// Diagnostic/raw-seed seam retained for frozen records and scaled
    /// differentials.
    #[doc(hidden)]
    pub fn fold_paired_base_keys(
        &self,
        base_keys: [&[Fp2]; 2],
        batching_seed: [u8; 32],
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        if base_keys.iter().any(|keys| keys.len() != self.leaf_coefficients.len()) {
            return Err(C6ResidualError::new(
                "C6 paired verifier base-key vectors differ from installed source census",
            ));
        }
        self.fold_paired_base_keys_stream(batching_seed, |source| {
            Ok([base_keys[0][source as usize], base_keys[1][source as usize]])
        })
    }

    /// Streaming client seam for a local paired key tape. Exactly one
    /// callback is made per canonical source ordinal.
    pub fn fold_paired_base_keys_stream_post_root(
        &self,
        challenges: &C6ResidualPostRootChallenges,
        base_keys: impl FnMut(u32) -> C6ResidualResult<[Fp2; 2]>,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        challenges.validate_compiled_binding(self.operation_plan_artifact_digest, self.topology)?;
        self.fold_paired_base_keys_stream(challenges.context_seed, base_keys)
    }

    /// Diagnostic/raw-seed seam retained for frozen records and scaled
    /// differentials.
    #[doc(hidden)]
    pub fn fold_paired_base_keys_stream(
        &self,
        batching_seed: [u8; 32],
        mut base_keys: impl FnMut(u32) -> C6ResidualResult<[Fp2; 2]>,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        let mut base_key_rlcs = [Fp2::ZERO; 2];
        let coefficient_digest =
            self.fold_paired_coefficients(batching_seed, |source, _, _, coefficients| {
                let keys = base_keys(source)?;
                for coordinate in 0..2 {
                    base_key_rlcs[coordinate] += coefficients[coordinate] * keys[coordinate];
                }
                Ok(())
            })?;
        Ok(C6CompiledPairedBaseKeyRlc { binding: self.binding(coefficient_digest), base_key_rlcs })
    }

    /// Local differential oracle only. A deployed client never receives
    /// provider source witnesses; it supplies its verifier-tape key stream to
    /// [`Self::fold_paired_base_keys_stream`] instead.
    #[doc(hidden)]
    pub fn fold_paired_base_keys_from_sources_diagnostic(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
        deltas: [Fp2; 2],
        batching_seed: [u8; 32],
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        self.validate_paired_source_schedule(sources, schedule)?;
        let mut cursor = C6PairedSourceCursor::new(sources, schedule);
        let folded = self.fold_paired_base_keys_stream(batching_seed, |source| {
            let witnesses = cursor.next(source)?;
            Ok([
                witnesses[0].tag() + deltas[0] * witnesses[0].base_plaintext(),
                witnesses[1].tag() + deltas[1] * witnesses[1].base_plaintext(),
            ])
        })?;
        cursor.finish(self.topology.source_count)?;
        Ok(folded)
    }
}

struct C6PairedSourceCursor<'a> {
    sources: &'a C6PairedSourceWitness,
    schedule: &'a CorrScheduleAudit,
    draw_index: usize,
    draw_offset: u64,
    source: u32,
}

impl<'a> C6PairedSourceCursor<'a> {
    fn new(sources: &'a C6PairedSourceWitness, schedule: &'a CorrScheduleAudit) -> Self {
        Self { sources, schedule, draw_index: 0, draw_offset: 0, source: 0 }
    }

    fn next(&mut self, expected_source: u32) -> C6ResidualResult<[C6SourceWitness; 2]> {
        if self.source != expected_source {
            return Err(C6ResidualError::new(
                "C6 paired source cursor differs from the coefficient schedule",
            ));
        }
        let draw = *self
            .schedule
            .draws
            .get(self.draw_index)
            .ok_or_else(|| C6ResidualError::new("C6 paired source schedule ended early"))?;
        if self.draw_offset >= draw.count {
            return Err(C6ResidualError::new("C6 paired source cursor exceeded its current draw"));
        }
        let witness_index = draw
            .global_offset
            .checked_add(self.draw_offset)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| C6ResidualError::new("C6 paired witness offset exceeds usize"))?;
        let mut witnesses =
            [C6SourceWitness::FullField { r: Fp2::ZERO, correction: Fp2::ZERO, tag: Fp2::ZERO }; 2];
        for (coordinate, output) in witnesses.iter_mut().enumerate() {
            *output = match draw.kind {
                CorrScheduleKind::Subfield => {
                    if draw.role != CorrScheduleRole::DirectCorrection {
                        return Err(C6ResidualError::new(
                            "C6 subfield source cannot be a ProductMask",
                        ));
                    }
                    let audit = self.sources.coordinates()[coordinate].subfield();
                    let r = *audit.masks().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 subfield source mask is missing")
                    })?;
                    let correction = *audit.corrections().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 subfield source correction is missing")
                    })?;
                    let tag = *audit
                        .tags()
                        .get(witness_index)
                        .ok_or_else(|| C6ResidualError::new("C6 subfield source tag is missing"))?;
                    C6SourceWitness::Subfield { r, correction, tag }
                }
                CorrScheduleKind::FullField => {
                    let audit = self.sources.coordinates()[coordinate].fullfield();
                    let r = *audit.masks().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 full-field source mask is missing")
                    })?;
                    let correction = *audit.corrections().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 full-field source correction is missing")
                    })?;
                    let tag = *audit.tags().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 full-field source tag is missing")
                    })?;
                    if draw.role == CorrScheduleRole::ProductMask && correction != Fp2::ZERO {
                        return Err(C6ResidualError::new(
                            "C6 ProductMask source has a nonzero correction",
                        ));
                    }
                    C6SourceWitness::FullField { r, correction, tag }
                }
            };
        }

        self.source = self
            .source
            .checked_add(1)
            .ok_or_else(|| C6ResidualError::new("C6 paired source ordinal overflows"))?;
        self.draw_offset += 1;
        if self.draw_offset == draw.count {
            self.draw_index += 1;
            self.draw_offset = 0;
        }
        Ok(witnesses)
    }

    fn finish(&self, expected_sources: u32) -> C6ResidualResult<()> {
        if self.source != expected_sources
            || self.draw_index != self.schedule.draws.len()
            || self.draw_offset != 0
        {
            return Err(C6ResidualError::new(
                "C6 paired source cursor did not consume the exact schedule",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct C6PairedInstalledNodeValue {
    x: [Fp2; 2],
    m: [Fp2; 2],
}

impl C6PairedInstalledNodeValue {
    fn from_sources(sources: [C6SourceWitness; 2]) -> Self {
        Self {
            x: sources.map(C6SourceWitness::prover_value).map(|value| value.x),
            m: sources.map(C6SourceWitness::prover_value).map(|value| value.m),
        }
    }

    fn public(value: Fp2) -> Self {
        Self { x: [value; 2], m: [Fp2::ZERO; 2] }
    }

    fn add(self, rhs: Self) -> Self {
        Self {
            x: [self.x[0] + rhs.x[0], self.x[1] + rhs.x[1]],
            m: [self.m[0] + rhs.m[0], self.m[1] + rhs.m[1]],
        }
    }

    fn sub(self, rhs: Self) -> Self {
        Self {
            x: [self.x[0] - rhs.x[0], self.x[1] - rhs.x[1]],
            m: [self.m[0] - rhs.m[0], self.m[1] - rhs.m[1]],
        }
    }

    fn scale(self, scalar: Fp2) -> Self {
        Self {
            x: [self.x[0] * scalar, self.x[1] * scalar],
            m: [self.m[0] * scalar, self.m[1] * scalar],
        }
    }
}

struct C6PairedSourceLookup<'a> {
    sources: &'a C6PairedSourceWitness,
    schedule: &'a CorrScheduleAudit,
    flattened_draw_starts: Vec<u64>,
    source_count: u64,
}

impl<'a> C6PairedSourceLookup<'a> {
    fn new(
        sources: &'a C6PairedSourceWitness,
        schedule: &'a CorrScheduleAudit,
    ) -> C6ResidualResult<Self> {
        let mut flattened_draw_starts = Vec::new();
        flattened_draw_starts
            .try_reserve_exact(schedule.draws.len())
            .map_err(|_| C6ResidualError::new("C6 source draw index allocation failed"))?;
        let mut source_count = 0u64;
        for draw in &schedule.draws {
            flattened_draw_starts.push(source_count);
            source_count = source_count
                .checked_add(draw.count)
                .ok_or_else(|| C6ResidualError::new("C6 flattened source count overflows"))?;
        }
        Ok(Self { sources, schedule, flattened_draw_starts, source_count })
    }

    fn source_count(&self) -> u64 {
        self.source_count
    }

    fn draw_index_heap_bytes(&self) -> C6ResidualResult<u64> {
        u64::try_from(self.flattened_draw_starts.capacity())
            .ok()
            .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<u64>() as u64))
            .ok_or_else(|| C6ResidualError::new("C6 source draw index byte count overflows"))
    }

    fn get(&self, source: u32) -> C6ResidualResult<[C6SourceWitness; 2]> {
        let source = u64::from(source);
        if source >= self.source_count {
            return Err(C6ResidualError::new(
                "C6 installed source ordinal exceeds the paired schedule",
            ));
        }
        let draw_index = self
            .flattened_draw_starts
            .partition_point(|&start| start <= source)
            .checked_sub(1)
            .ok_or_else(|| C6ResidualError::new("C6 paired source draw lookup underflows"))?;
        let draw = *self
            .schedule
            .draws
            .get(draw_index)
            .ok_or_else(|| C6ResidualError::new("C6 paired source draw lookup is missing"))?;
        let draw_offset = source
            .checked_sub(self.flattened_draw_starts[draw_index])
            .ok_or_else(|| C6ResidualError::new("C6 paired source draw offset underflows"))?;
        if draw_offset >= draw.count {
            return Err(C6ResidualError::new(
                "C6 paired source ordinal crossed its canonical draw",
            ));
        }
        let witness_index = draw
            .global_offset
            .checked_add(draw_offset)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| C6ResidualError::new("C6 paired witness offset exceeds usize"))?;
        let mut witnesses =
            [C6SourceWitness::FullField { r: Fp2::ZERO, correction: Fp2::ZERO, tag: Fp2::ZERO }; 2];
        for (coordinate, output) in witnesses.iter_mut().enumerate() {
            *output = match draw.kind {
                CorrScheduleKind::Subfield => {
                    if draw.role != CorrScheduleRole::DirectCorrection {
                        return Err(C6ResidualError::new(
                            "C6 subfield installed source cannot be a ProductMask",
                        ));
                    }
                    let audit = self.sources.coordinates()[coordinate].subfield();
                    C6SourceWitness::Subfield {
                        r: *audit.masks().get(witness_index).ok_or_else(|| {
                            C6ResidualError::new("C6 installed subfield source mask is missing")
                        })?,
                        correction: *audit.corrections().get(witness_index).ok_or_else(|| {
                            C6ResidualError::new(
                                "C6 installed subfield source correction is missing",
                            )
                        })?,
                        tag: *audit.tags().get(witness_index).ok_or_else(|| {
                            C6ResidualError::new("C6 installed subfield source tag is missing")
                        })?,
                    }
                }
                CorrScheduleKind::FullField => {
                    let audit = self.sources.coordinates()[coordinate].fullfield();
                    let correction = *audit.corrections().get(witness_index).ok_or_else(|| {
                        C6ResidualError::new("C6 installed full-field correction is missing")
                    })?;
                    if draw.role == CorrScheduleRole::ProductMask && correction != Fp2::ZERO {
                        return Err(C6ResidualError::new(
                            "C6 installed ProductMask source has a correction",
                        ));
                    }
                    C6SourceWitness::FullField {
                        r: *audit.masks().get(witness_index).ok_or_else(|| {
                            C6ResidualError::new("C6 installed full-field mask is missing")
                        })?,
                        correction,
                        tag: *audit.tags().get(witness_index).ok_or_else(|| {
                            C6ResidualError::new("C6 installed full-field tag is missing")
                        })?,
                    }
                }
            };
        }
        Ok(witnesses)
    }
}

const C6_UNUSED_NODE_SLOT: u32 = u32::MAX;

fn try_filled_u32_vec(length: usize, value: u32, label: &str) -> C6ResidualResult<Vec<u32>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| C6ResidualError::new(format!("{label} allocation failed")))?;
    values.resize(length, value);
    Ok(values)
}

fn increment_installed_node_use(
    use_counts: &mut [u32],
    node: u32,
    upper_bound: u32,
    label: &str,
) -> C6ResidualResult<()> {
    if node >= upper_bound {
        return Err(C6ResidualError::new(format!(
            "{label} is outside the installed topological prefix"
        )));
    }
    let count = use_counts
        .get_mut(node as usize)
        .ok_or_else(|| C6ResidualError::new(format!("{label} is outside the installed plan")))?;
    *count = count
        .checked_add(1)
        .ok_or_else(|| C6ResidualError::new(format!("{label} reference count overflows")))?;
    Ok(())
}

fn installed_closure_census(
    operation_plan: &C6InstalledOperationPlan,
) -> C6ResidualResult<C6ResidualClosureWitnessCensus> {
    let product_triples = installed_product_triple_count(operation_plan)?;
    let product_operand_values = product_triples
        .checked_mul(12)
        .ok_or_else(|| C6ResidualError::new("C6 installed closure product values overflow"))?;
    let zero_roots = u32::try_from(operation_plan.zero_roots().len())
        .map_err(|_| C6ResidualError::new("C6 installed zero-root count exceeds u32"))?;
    let zero_root_values = u64::from(zero_roots)
        .checked_mul(4)
        .ok_or_else(|| C6ResidualError::new("C6 installed closure zero values overflow"))?;
    let live_values = product_operand_values
        .checked_add(zero_root_values)
        .and_then(|values| values.checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES))
        .ok_or_else(|| C6ResidualError::new("C6 installed closure live values overflow"))?;
    if live_values > C6_RESIDUAL_SLOT_ENTRIES {
        return Err(C6ResidualError::new(
            "C6 installed closure live prefix exceeds the frozen residual slot",
        ));
    }
    Ok(C6ResidualClosureWitnessCensus {
        product_closures: u32::try_from(operation_plan.products().len())
            .map_err(|_| C6ResidualError::new("C6 installed ProductClosure count exceeds u32"))?,
        product_triples,
        zero_roots,
        product_operand_values,
        zero_root_values,
        footer_values: C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES,
        live_values,
    })
}

fn installed_node_value(
    node: u32,
    node_slots: &[u32],
    node_values: &[C6PairedInstalledNodeValue],
) -> C6ResidualResult<C6PairedInstalledNodeValue> {
    let slot = *node_slots
        .get(node as usize)
        .ok_or_else(|| C6ResidualError::new("C6 installed live node is outside the slot map"))?;
    if slot == C6_UNUSED_NODE_SLOT {
        return Err(C6ResidualError::new("C6 installed node was released before its final use"));
    }
    node_values
        .get(slot as usize)
        .copied()
        .ok_or_else(|| C6ResidualError::new("C6 installed node slot is outside the value arena"))
}

fn retain_installed_node_value(
    canonical: u32,
    value: C6PairedInstalledNodeValue,
    use_counts: &[u32],
    node_slots: &mut [u32],
    node_values: &mut Vec<C6PairedInstalledNodeValue>,
    free_slots: &mut Vec<u32>,
    active_values: &mut u64,
    peak_live_values: &mut u64,
) -> C6ResidualResult<()> {
    if use_counts[canonical as usize] == 0 {
        return Ok(());
    }
    if node_slots[canonical as usize] != C6_UNUSED_NODE_SLOT {
        return Err(C6ResidualError::new("C6 installed node slot was assigned twice"));
    }
    let slot = if let Some(slot) = free_slots.pop() {
        *node_values
            .get_mut(slot as usize)
            .ok_or_else(|| C6ResidualError::new("C6 installed free slot is out of range"))? = value;
        slot
    } else {
        node_values
            .try_reserve(1)
            .map_err(|_| C6ResidualError::new("C6 installed node-value arena growth failed"))?;
        let slot = u32::try_from(node_values.len())
            .map_err(|_| C6ResidualError::new("C6 installed node-value slot exceeds u32"))?;
        node_values.push(value);
        slot
    };
    node_slots[canonical as usize] = slot;
    *active_values = active_values
        .checked_add(1)
        .ok_or_else(|| C6ResidualError::new("C6 installed active-value census overflows"))?;
    *peak_live_values = (*peak_live_values).max(*active_values);
    Ok(())
}

fn release_installed_node_use(
    node: u32,
    use_counts: &mut [u32],
    node_slots: &mut [u32],
    free_slots: &mut Vec<u32>,
    active_values: &mut u64,
) -> C6ResidualResult<()> {
    let count = use_counts
        .get_mut(node as usize)
        .ok_or_else(|| C6ResidualError::new("C6 released installed node is out of range"))?;
    if *count == 0 {
        return Err(C6ResidualError::new("C6 installed node reference count underflows"));
    }
    *count -= 1;
    if *count != 0 {
        return Ok(());
    }
    let slot = std::mem::replace(
        node_slots
            .get_mut(node as usize)
            .ok_or_else(|| C6ResidualError::new("C6 released node lacks a slot-map entry"))?,
        C6_UNUSED_NODE_SLOT,
    );
    if slot == C6_UNUSED_NODE_SLOT {
        return Err(C6ResidualError::new("C6 installed node has no live slot to release"));
    }
    free_slots
        .try_reserve(1)
        .map_err(|_| C6ResidualError::new("C6 installed free-slot arena growth failed"))?;
    free_slots.push(slot);
    *active_values = active_values
        .checked_sub(1)
        .ok_or_else(|| C6ResidualError::new("C6 installed active-value census underflows"))?;
    Ok(())
}

fn evaluate_installed_paired_closure(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    sources: &C6PairedSourceWitness,
    schedule: &CorrScheduleAudit,
) -> C6ResidualResult<C6InstalledPairedClosureEvaluation> {
    let topology = operation_plan.topology();
    let canonical_nodes = usize::try_from(topology.canonical_node_count)
        .map_err(|_| C6ResidualError::new("C6 canonical node count exceeds usize"))?;
    if operation_plan.operation_kinds().len() != canonical_nodes {
        return Err(C6ResidualError::new(
            "C6 installed opcode count differs from canonical topology",
        ));
    }
    let source_lookup = C6PairedSourceLookup::new(sources, schedule)?;
    if source_lookup.source_count() != u64::from(topology.source_count) {
        return Err(C6ResidualError::new(
            "C6 installed paired source lookup differs from topology",
        ));
    }
    let census = installed_closure_census(operation_plan)?;

    let mut use_counts = try_filled_u32_vec(canonical_nodes, 0, "C6 node reference-count")?;
    let mut operand_cursor = 0usize;
    let mut source_nodes = 0usize;
    let mut public_nodes = 0usize;
    let mut scalar_nodes = 0usize;
    for (canonical, &kind) in operation_plan.operation_kinds().iter().enumerate() {
        let canonical = u32::try_from(canonical)
            .map_err(|_| C6ResidualError::new("C6 canonical node ordinal exceeds u32"))?;
        match kind {
            C6InstalledOperationKind::Source => source_nodes += 1,
            C6InstalledOperationKind::StructuralZero => {}
            C6InstalledOperationKind::PublicInput => public_nodes += 1,
            C6InstalledOperationKind::Add | C6InstalledOperationKind::Sub => {
                let operands =
                    operation_plan.operands().get(operand_cursor..operand_cursor + 2).ok_or_else(
                        || C6ResidualError::new("C6 installed binary operands are truncated"),
                    )?;
                increment_installed_node_use(
                    &mut use_counts,
                    operands[0],
                    canonical,
                    "C6 installed binary lhs",
                )?;
                increment_installed_node_use(
                    &mut use_counts,
                    operands[1],
                    canonical,
                    "C6 installed binary rhs",
                )?;
                operand_cursor += 2;
            }
            C6InstalledOperationKind::Scale => {
                let input = *operation_plan.operands().get(operand_cursor).ok_or_else(|| {
                    C6ResidualError::new("C6 installed scale operand is truncated")
                })?;
                increment_installed_node_use(
                    &mut use_counts,
                    input,
                    canonical,
                    "C6 installed scale input",
                )?;
                operand_cursor += 1;
                scalar_nodes += 1;
            }
        }
    }
    if operand_cursor != operation_plan.operands().len()
        || source_nodes != operation_plan.source_ordinals().len()
        || source_nodes > topology.source_count as usize
        || public_nodes != topology.public_input_count as usize
        || scalar_nodes != topology.scalar_input_count as usize
    {
        return Err(C6ResidualError::new(format!(
            "C6 installed operation streams differ from topology: operands {operand_cursor}/{}, sources {source_nodes}/{}/{}, public {public_nodes}/{}, scalar {scalar_nodes}/{}",
            operation_plan.operands().len(),
            operation_plan.source_ordinals().len(),
            topology.source_count,
            topology.public_input_count,
            topology.scalar_input_count,
        )));
    }
    let canonical_limit = topology.canonical_node_count;
    let mut product_triples = 0u64;
    for product in operation_plan.products() {
        product_triples = product_triples
            .checked_add(product.triples().len() as u64)
            .ok_or_else(|| C6ResidualError::new("C6 installed terminal triple count overflows"))?;
        for triple in product.triples() {
            for &node in triple {
                increment_installed_node_use(
                    &mut use_counts,
                    node,
                    canonical_limit,
                    "C6 installed ProductClosure operand",
                )?;
            }
        }
    }
    for &root in operation_plan.zero_roots() {
        increment_installed_node_use(
            &mut use_counts,
            root,
            canonical_limit,
            "C6 installed zero root",
        )?;
    }
    if product_triples != census.product_triples
        || operation_plan.products().len() != census.product_closures as usize
        || operation_plan.zero_roots().len() != census.zero_roots as usize
    {
        return Err(C6ResidualError::new(
            "C6 installed terminal references differ from closure census",
        ));
    }

    let mut node_slots =
        try_filled_u32_vec(canonical_nodes, C6_UNUSED_NODE_SLOT, "C6 node-slot map")?;
    let mut node_values = Vec::<C6PairedInstalledNodeValue>::new();
    let mut free_slots = Vec::<u32>::new();
    let mut active_values = 0u64;
    let mut peak_live_values = 0u64;
    operand_cursor = 0;
    let mut source_cursor = 0usize;
    let mut public_cursor = 0u32;
    let mut scalar_cursor = 0u32;
    for (canonical, &kind) in operation_plan.operation_kinds().iter().enumerate() {
        let canonical_u32 = canonical as u32;
        let value = match kind {
            C6InstalledOperationKind::Source => {
                let source =
                    *operation_plan.source_ordinals().get(source_cursor).ok_or_else(|| {
                        C6ResidualError::new("C6 installed source-ordinal stream is truncated")
                    })?;
                source_cursor += 1;
                C6PairedInstalledNodeValue::from_sources(source_lookup.get(source)?)
            }
            C6InstalledOperationKind::StructuralZero => C6PairedInstalledNodeValue::default(),
            C6InstalledOperationKind::PublicInput => {
                let public = runtime
                    .public_value(extraction, public_cursor)
                    .map_err(|error| C6ResidualError::new(error.to_string()))?;
                public_cursor = public_cursor.checked_add(1).ok_or_else(|| {
                    C6ResidualError::new("C6 installed public-input cursor overflows")
                })?;
                C6PairedInstalledNodeValue::public(public)
            }
            C6InstalledOperationKind::Add | C6InstalledOperationKind::Sub => {
                let operands =
                    operation_plan.operands().get(operand_cursor..operand_cursor + 2).ok_or_else(
                        || C6ResidualError::new("C6 installed binary operands are truncated"),
                    )?;
                let lhs = installed_node_value(operands[0], &node_slots, &node_values)?;
                let rhs = installed_node_value(operands[1], &node_slots, &node_values)?;
                let value =
                    if kind == C6InstalledOperationKind::Add { lhs.add(rhs) } else { lhs.sub(rhs) };
                release_installed_node_use(
                    operands[0],
                    &mut use_counts,
                    &mut node_slots,
                    &mut free_slots,
                    &mut active_values,
                )?;
                release_installed_node_use(
                    operands[1],
                    &mut use_counts,
                    &mut node_slots,
                    &mut free_slots,
                    &mut active_values,
                )?;
                operand_cursor += 2;
                value
            }
            C6InstalledOperationKind::Scale => {
                let input = *operation_plan.operands().get(operand_cursor).ok_or_else(|| {
                    C6ResidualError::new("C6 installed scale operand is truncated")
                })?;
                let scalar = runtime
                    .scalar_value(extraction, scalar_cursor)
                    .map_err(|error| C6ResidualError::new(error.to_string()))?;
                scalar_cursor = scalar_cursor.checked_add(1).ok_or_else(|| {
                    C6ResidualError::new("C6 installed scalar-input cursor overflows")
                })?;
                let value = installed_node_value(input, &node_slots, &node_values)?.scale(scalar);
                release_installed_node_use(
                    input,
                    &mut use_counts,
                    &mut node_slots,
                    &mut free_slots,
                    &mut active_values,
                )?;
                operand_cursor += 1;
                value
            }
        };
        retain_installed_node_value(
            canonical_u32,
            value,
            &use_counts,
            &mut node_slots,
            &mut node_values,
            &mut free_slots,
            &mut active_values,
            &mut peak_live_values,
        )?;
    }
    if operand_cursor != operation_plan.operands().len()
        || source_cursor != operation_plan.source_ordinals().len()
        || public_cursor != topology.public_input_count
        || scalar_cursor != topology.scalar_input_count
    {
        return Err(C6ResidualError::new(
            "C6 installed forward cursors differ from their exact census",
        ));
    }

    let live_values = usize::try_from(census.live_values)
        .map_err(|_| C6ResidualError::new("C6 installed closure length exceeds usize"))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(live_values)
        .map_err(|_| C6ResidualError::new("C6 installed closure allocation failed"))?;
    for product in operation_plan.products() {
        for triple in product.triples() {
            for coordinate in 0..2 {
                for &node in triple {
                    let value = installed_node_value(node, &node_slots, &node_values)?;
                    values.extend([value.x[coordinate], value.m[coordinate]]);
                }
            }
            for &node in triple {
                release_installed_node_use(
                    node,
                    &mut use_counts,
                    &mut node_slots,
                    &mut free_slots,
                    &mut active_values,
                )?;
            }
        }
    }
    for &root in operation_plan.zero_roots() {
        let value = installed_node_value(root, &node_slots, &node_values)?;
        if value.x[0] != value.x[1] {
            return Err(C6ResidualError::new(
                "C6 installed zero-root plaintext differs across coordinates",
            ));
        }
        values.extend([value.x[0], value.m[0], value.x[1], value.m[1]]);
        release_installed_node_use(
            root,
            &mut use_counts,
            &mut node_slots,
            &mut free_slots,
            &mut active_values,
        )?;
    }
    values.resize(live_values, Fp2::ZERO);
    if active_values != 0
        || use_counts.iter().any(|&count| count != 0)
        || node_slots.iter().any(|&slot| slot != C6_UNUSED_NODE_SLOT)
        || values.len() as u64 != census.live_values
    {
        return Err(C6ResidualError::new(
            "C6 installed closure evaluation left a live or unconsumed node",
        ));
    }

    let capacity_bytes = |capacity: usize, element_bytes: usize, label: &str| {
        u64::try_from(capacity)
            .ok()
            .and_then(|capacity| capacity.checked_mul(element_bytes as u64))
            .ok_or_else(|| C6ResidualError::new(format!("{label} byte count overflows")))
    };
    let reference_count_heap_bytes =
        capacity_bytes(use_counts.capacity(), std::mem::size_of::<u32>(), "C6 reference-count")?;
    let node_slot_heap_bytes =
        capacity_bytes(node_slots.capacity(), std::mem::size_of::<u32>(), "C6 node-slot")?;
    let source_draw_index_heap_bytes = source_lookup.draw_index_heap_bytes()?;
    let node_value_heap_bytes = capacity_bytes(
        node_values.capacity(),
        std::mem::size_of::<C6PairedInstalledNodeValue>(),
        "C6 node-value arena",
    )?;
    let free_slot_heap_bytes =
        capacity_bytes(free_slots.capacity(), std::mem::size_of::<u32>(), "C6 free-slot arena")?;
    let closure_value_heap_bytes =
        capacity_bytes(values.capacity(), std::mem::size_of::<Fp2>(), "C6 closure value")?;
    let peak_working_heap_bytes = [
        reference_count_heap_bytes,
        node_slot_heap_bytes,
        source_draw_index_heap_bytes,
        node_value_heap_bytes,
        free_slot_heap_bytes,
        closure_value_heap_bytes,
    ]
    .into_iter()
    .try_fold(0u64, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or_else(|| C6ResidualError::new("C6 installed working heap census overflows"))
    })?;
    let dense_paired_node_baseline_bytes = (topology.canonical_node_count as u64)
        .checked_mul(std::mem::size_of::<C6PairedInstalledNodeValue>() as u64)
        .ok_or_else(|| C6ResidualError::new("C6 dense node baseline bytes overflow"))?;
    let memory_census = C6InstalledClosureEvaluationMemoryCensus {
        canonical_nodes: topology.canonical_node_count as u64,
        reference_count_heap_bytes,
        node_slot_heap_bytes,
        source_draw_index_heap_bytes,
        peak_live_node_values: peak_live_values,
        node_value_capacity: node_values.capacity() as u64,
        node_value_heap_bytes,
        free_slot_heap_bytes,
        closure_value_heap_bytes,
        peak_working_heap_bytes,
        dense_paired_node_baseline_bytes,
    };

    let mut hasher = blake3::Hasher::new_derive_key(PAIRED_INSTALLED_CLOSURE_WRAPPER_DOMAIN);
    hasher.update(&operation_plan.artifact_digest());
    hasher.update(&topology.topology_digest);
    hasher.update(&runtime.instance_identity().instance_digest);
    hasher.update(&schedule.digest);
    hasher.update(&sources.pair_digest());
    hasher.update(&u64::from(census.product_closures).to_le_bytes());
    hasher.update(&census.product_triples.to_le_bytes());
    hasher.update(&u64::from(census.zero_roots).to_le_bytes());
    hasher.update(&census.live_values.to_le_bytes());
    for value in &values {
        hash_fp2(&mut hasher, *value);
    }
    let closure = C6PairedResidualClosureWitness {
        program_digest: operation_plan.artifact_digest(),
        installed_binding: Some(C6InstalledClosureBinding {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology_digest: topology.topology_digest,
            instance_digest: runtime.instance_identity().instance_digest,
            source_schedule_digest: topology.source_schedule_digest,
            paired_source_digest: sources.pair_digest(),
        }),
        census,
        values,
        witness_digest: *hasher.finalize().as_bytes(),
    };
    Ok(C6InstalledPairedClosureEvaluation { closure, memory_census })
}

fn try_zeroed_fp2_vec(length: usize, label: &str) -> C6ResidualResult<Vec<Fp2>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| C6ResidualError::new(format!("{label} allocation failed")))?;
    values.resize(length, Fp2::ZERO);
    Ok(values)
}

pub struct C6CommittedResidualProgram {
    sources: Vec<SourceNode>,
    nodes: Vec<ValueNode>,
    zero_closures: Vec<C6ValueId>,
    products: Vec<ProductShape>,
    values: Vec<ProverAuthed>,
    census: C6ResidualCensus,
    witness_commitment: C6ResidualDigest,
    prequery_statement_digest: C6ResidualDigest,
}

impl C6CommittedResidualProgram {
    pub fn census(&self) -> C6ResidualCensus {
        self.census
    }

    pub fn witness_commitment(&self) -> C6ResidualDigest {
        self.witness_commitment
    }

    pub fn prequery_statement_digest(&self) -> C6ResidualDigest {
        self.prequery_statement_digest
    }

    pub fn leaf_order(&self) -> Vec<C6LeafId> {
        self.sources.iter().map(|source| source.id).collect()
    }

    /// Scaled/reference construction of the canonical slot-7 live prefix for
    /// two independently committed executions of the same typed DAG.
    ///
    /// Production uses the installed-plan/capture seam; this method freezes
    /// its value order against the already-audited reference builder.
    pub fn build_paired_closure_witness(
        &self,
        secondary: &C6CommittedResidualProgram,
    ) -> C6ResidualResult<C6PairedResidualClosureWitness> {
        if self.witness_commitment == secondary.witness_commitment
            || self.census != secondary.census
            || self.nodes != secondary.nodes
            || self.zero_closures != secondary.zero_closures
            || self.products != secondary.products
            || self.sources.len() != secondary.sources.len()
            || self.values.len() != secondary.values.len()
        {
            return Err(C6ResidualError::new(
                "C6 paired closure witnesses do not use one DAG and two commitments",
            ));
        }
        for (primary, secondary) in self.sources.iter().zip(&secondary.sources) {
            if primary.id != secondary.id
                || primary.role != secondary.role
                || (primary.role == C6LeafRole::Direct
                    && primary.witness.prover_value().x != secondary.witness.prover_value().x)
            {
                return Err(C6ResidualError::new(
                    "C6 paired closure source identity/plaintext mismatch",
                ));
            }
        }

        let product_triples = self.products.iter().try_fold(0u64, |total, product| {
            total
                .checked_add(product.triples.len() as u64)
                .ok_or_else(|| C6ResidualError::new("C6 closure triple count overflows"))
        })?;
        let product_operand_values = product_triples
            .checked_mul(12)
            .ok_or_else(|| C6ResidualError::new("C6 closure product values overflow"))?;
        let zero_root_values = (self.zero_closures.len() as u64)
            .checked_mul(4)
            .ok_or_else(|| C6ResidualError::new("C6 closure zero values overflow"))?;
        let live_values = product_operand_values
            .checked_add(zero_root_values)
            .and_then(|values| values.checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES))
            .ok_or_else(|| C6ResidualError::new("C6 closure live values overflow"))?;
        if live_values > C6_RESIDUAL_SLOT_ENTRIES {
            return Err(C6ResidualError::new(
                "C6 closure live prefix exceeds the frozen residual slot",
            ));
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(
                usize::try_from(live_values)
                    .map_err(|_| C6ResidualError::new("C6 closure live values exceed usize"))?,
            )
            .map_err(|_| C6ResidualError::new("C6 closure witness allocation failed"))?;

        for product in &self.products {
            for triple in &product.triples {
                for coordinate_values in [&self.values, &secondary.values] {
                    for node in triple {
                        let value = coordinate_values[node.index()];
                        values.extend([value.x, value.m]);
                    }
                }
            }
        }
        for root in &self.zero_closures {
            let primary = self.values[root.index()];
            let secondary = secondary.values[root.index()];
            if primary.x != secondary.x {
                return Err(C6ResidualError::new(
                    "C6 paired zero-root plaintext differs across coordinates",
                ));
            }
            values.extend([primary.x, primary.m, secondary.x, secondary.m]);
        }
        values.resize(
            values
                .len()
                .checked_add(C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES as usize)
                .ok_or_else(|| C6ResidualError::new("C6 closure footer length overflows"))?,
            Fp2::ZERO,
        );
        if values.len() as u64 != live_values {
            return Err(C6ResidualError::new("C6 closure workspace census mismatch"));
        }

        let census = C6ResidualClosureWitnessCensus {
            product_closures: u32::try_from(self.products.len())
                .map_err(|_| C6ResidualError::new("C6 ProductClosure count exceeds u32"))?,
            product_triples,
            zero_roots: u32::try_from(self.zero_closures.len())
                .map_err(|_| C6ResidualError::new("C6 zero-root count exceeds u32"))?,
            product_operand_values,
            zero_root_values,
            footer_values: C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES,
            live_values,
        };
        let mut hasher = blake3::Hasher::new_derive_key(PAIRED_CLOSURE_WRAPPER_DOMAIN);
        hasher.update(&self.census.program_digest);
        hasher.update(&self.witness_commitment);
        hasher.update(&secondary.witness_commitment);
        hasher.update(&u64::from(census.product_closures).to_le_bytes());
        hasher.update(&census.product_triples.to_le_bytes());
        hasher.update(&u64::from(census.zero_roots).to_le_bytes());
        hasher.update(&census.live_values.to_le_bytes());
        for value in &values {
            hash_fp2(&mut hasher, *value);
        }
        Ok(C6PairedResidualClosureWitness {
            program_digest: self.census.program_digest,
            installed_binding: None,
            census,
            values,
            witness_digest: *hasher.finalize().as_bytes(),
        })
    }

    fn compute_product(&self, shape: &ProductShape, chi: Fp2) -> (Fp2, Fp2, Fp2) {
        let mask = self.values[shape.mask.index()];
        let mut q = Fp2::ZERO;
        let mut m0 = mask.m;
        let mut m1 = mask.x;
        let mut weight = Fp2::ONE;
        for [a, b, c] in &shape.triples {
            weight = weight * chi;
            let a = self.values[a.index()];
            let b = self.values[b.index()];
            let c = self.values[c.index()];
            q += weight * (a.x * b.x - c.x);
            m0 += weight * (a.m * b.m);
            m1 += weight * (a.x * b.m + b.x * a.m - c.m);
        }
        (q, m0, m1)
    }

    /// Provider-side formation of the exact retained QuickSilver messages,
    /// called only after the client supplies the existing post-commit `chi`
    /// values.
    pub fn product_openings(&self, chis: &[Fp2]) -> C6ResidualResult<Vec<C6ProductPostCommit>> {
        if chis.len() != self.products.len() {
            return Err(C6ResidualError::new("wrong C6 ProductClosure challenge count"));
        }
        self.products
            .iter()
            .zip(chis)
            .enumerate()
            .map(|(index, (shape, &chi))| {
                let (q, m0, m1) = self.compute_product(shape, chi);
                if q != Fp2::ZERO {
                    return Err(C6ResidualError::new(format!(
                        "C6 ProductClosure {index} has nonzero quadratic coefficient"
                    )));
                }
                Ok(C6ProductPostCommit { chi, m0, m1 })
            })
            .collect()
    }

    fn validate_post_commit(&self, post: &C6ResidualPostCommit) -> C6ResidualResult<()> {
        if post.base_share_alphas.len() != self.sources.len() {
            return Err(C6ResidualError::new(
                "C6 base-share coefficient count differs from leaf census",
            ));
        }
        if post.zero_weights.len() != self.zero_closures.len() {
            return Err(C6ResidualError::new("C6 zero-closure weight count differs from census"));
        }
        if post.products.len() != self.products.len() {
            return Err(C6ResidualError::new(
                "C6 ProductClosure response count differs from census",
            ));
        }
        Ok(())
    }

    fn validate_wrapper_relations(&self, post: &C6ResidualPostCommit) -> C6ResidualResult<()> {
        self.validate_post_commit(post)?;
        for (index, value) in self.zero_closures.iter().enumerate() {
            if self.values[value.index()].x != Fp2::ZERO {
                return Err(C6ResidualError::new(format!(
                    "C6 zero closure {index} has nonzero plaintext"
                )));
            }
        }
        for (index, (shape, response)) in self.products.iter().zip(&post.products).enumerate() {
            let (q, m0, m1) = self.compute_product(shape, response.chi);
            if q != Fp2::ZERO {
                return Err(C6ResidualError::new(format!(
                    "C6 ProductClosure {index} has nonzero Q"
                )));
            }
            if response.m0 != m0 || response.m1 != m1 {
                return Err(C6ResidualError::new(format!(
                    "C6 ProductClosure {index} has malformed M0/M1"
                )));
            }
        }
        Ok(())
    }

    fn reverse_linear_coefficients(&self, zero_weights: &[Fp2]) -> (Vec<Fp2>, Fp2) {
        let mut node_coefficients = vec![Fp2::ZERO; self.nodes.len()];
        for (&value, &weight) in self.zero_closures.iter().zip(zero_weights) {
            node_coefficients[value.index()] += weight;
        }

        let mut leaf_coefficients = vec![Fp2::ZERO; self.sources.len()];
        let mut public_plaintext = Fp2::ZERO;
        for index in (0..self.nodes.len()).rev() {
            let coefficient = node_coefficients[index];
            match self.nodes[index] {
                ValueNode::Source(source) => leaf_coefficients[source] += coefficient,
                ValueNode::Public(value) => public_plaintext += coefficient * value,
                ValueNode::Add(lhs, rhs) => {
                    node_coefficients[lhs.index()] += coefficient;
                    node_coefficients[rhs.index()] += coefficient;
                }
                ValueNode::Sub(lhs, rhs) => {
                    node_coefficients[lhs.index()] += coefficient;
                    node_coefficients[rhs.index()] = node_coefficients[rhs.index()] - coefficient;
                }
                ValueNode::Scale(input, scalar) => {
                    node_coefficients[input.index()] += coefficient * scalar;
                }
            }
        }
        (leaf_coefficients, public_plaintext)
    }

    pub fn respond(&self, post: C6ResidualPostCommit) -> C6ResidualResult<C6ResidualPlan> {
        self.validate_wrapper_relations(&post)?;
        let (linear_coefficients, public_plaintext) =
            self.reverse_linear_coefficients(&post.zero_weights);

        let mut base_key_coefficients = Vec::with_capacity(self.sources.len());
        let mut correction_rlc = public_plaintext;
        let mut public_tag_rlc = Fp2::ZERO;
        for (index, ((source, &linear), &alpha)) in
            self.sources.iter().zip(&linear_coefficients).zip(&post.base_share_alphas).enumerate()
        {
            debug_assert_eq!(source.id.schedule_index as usize, index);
            let coefficient = linear + alpha;
            base_key_coefficients.push(coefficient);
            correction_rlc += linear * source.witness.correction();
            correction_rlc = correction_rlc - alpha * source.witness.base_plaintext();
            public_tag_rlc += coefficient * source.witness.tag();
        }

        let residual = C6DeltaResidual { correction_rlc, public_tag_rlc };
        let response_digest = self.response_digest(&post, residual);
        Ok(C6ResidualPlan {
            census: self.census,
            prequery_statement_digest: self.prequery_statement_digest,
            response_digest,
            leaf_order: self.leaf_order(),
            base_key_coefficients,
            residual,
        })
    }

    fn response_digest(
        &self,
        post: &C6ResidualPostCommit,
        residual: C6DeltaResidual,
    ) -> C6ResidualDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RESPONSE_DOMAIN);
        hasher.update(&self.prequery_statement_digest);
        for alpha in &post.base_share_alphas {
            hash_fp2(&mut hasher, *alpha);
        }
        for weight in &post.zero_weights {
            hash_fp2(&mut hasher, *weight);
        }
        for product in &post.products {
            hash_fp2(&mut hasher, product.chi);
            hash_fp2(&mut hasher, product.m0);
            hash_fp2(&mut hasher, product.m1);
        }
        hash_fp2(&mut hasher, residual.correction_rlc);
        hash_fp2(&mut hasher, residual.public_tag_rlc);
        *hasher.finalize().as_bytes()
    }

    fn evaluate_verifier_keys(
        &self,
        base_keys: &[Fp2],
        delta: Fp2,
    ) -> C6ResidualResult<Vec<VerifierKey>> {
        if base_keys.len() != self.sources.len() {
            return Err(C6ResidualError::new("wrong C6 verifier base-key count"));
        }
        let mut keys: Vec<VerifierKey> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let key = match *node {
                ValueNode::Source(source) => VerifierKey::new(
                    base_keys[source] + delta * self.sources[source].witness.correction(),
                ),
                ValueNode::Public(value) => VerifierKey::from_public(value, delta),
                ValueNode::Add(lhs, rhs) => keys[lhs.index()].add(keys[rhs.index()]),
                ValueNode::Sub(lhs, rhs) => keys[lhs.index()].sub(keys[rhs.index()]),
                ValueNode::Scale(input, scalar) => keys[input.index()].scale(scalar),
            };
            keys.push(key);
        }
        Ok(keys)
    }

    /// Reference execution of the unchanged old verifier over the same scaled
    /// fixture.  This is a parity oracle, not the compact C6 verification
    /// path.
    pub fn old_verifier_accepts(
        &self,
        post: &C6ResidualPostCommit,
        base_keys: &[Fp2],
        delta: Fp2,
    ) -> C6ResidualResult<bool> {
        self.validate_post_commit(post)?;
        let keys = self.evaluate_verifier_keys(base_keys, delta)?;

        let mut zero_residual = Fp2::ZERO;
        for (&value, &weight) in self.zero_closures.iter().zip(&post.zero_weights) {
            zero_residual += weight * (keys[value.index()].k - self.values[value.index()].m);
        }
        if zero_residual != Fp2::ZERO {
            return Ok(false);
        }

        for (shape, response) in self.products.iter().zip(&post.products) {
            let triples: Vec<_> = shape
                .triples
                .iter()
                .map(|[a, b, c]| (keys[a.index()], keys[b.index()], keys[c.index()]))
                .collect();
            let proof = ProdProof { m0: response.m0, m1: response.m1 };
            if !prod_batch_verify(&triples, keys[shape.mask.index()], delta, response.chi, &proof) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualPlan {
    pub census: C6ResidualCensus,
    pub prequery_statement_digest: C6ResidualDigest,
    pub response_digest: C6ResidualDigest,
    pub leaf_order: Vec<C6LeafId>,
    pub base_key_coefficients: Vec<Fp2>,
    pub residual: C6DeltaResidual,
}

impl C6ResidualPlan {
    pub fn base_key_rlc(&self, base_keys: &[Fp2]) -> C6ResidualResult<Fp2> {
        if base_keys.len() != self.base_key_coefficients.len() {
            return Err(C6ResidualError::new(
                "C6 verifier base-key vector differs from residual leaf census",
            ));
        }
        Ok(self
            .base_key_coefficients
            .iter()
            .zip(base_keys)
            .fold(Fp2::ZERO, |acc, (&coefficient, &key)| acc + coefficient * key))
    }

    pub fn verify(&self, base_keys: &[Fp2], delta: Fp2) -> C6ResidualResult<bool> {
        Ok(self.residual.verify(self.base_key_rlc(base_keys)?, delta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "c6-trace")]
    use crate::c6_source::{replay_c6_source_coordinate, C6SourceCoordinate};
    #[cfg(feature = "c6-trace")]
    use volta_mac::{
        begin_c6_prover_trace, compile_c6_operation_trace_for_role,
        derive_c6_runtime_instance_from_trace_diagnostic, finish_c6_prover_trace,
        record_c6_product_closure, record_c6_zero_roots, C6InstanceExtractionRole,
        C6TraceSourceManifest, CorrelationStream,
    };

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(fp(value))
    }

    #[cfg(feature = "c6-trace")]
    fn fold_once(values: &[Fp2], challenge: Fp2) -> Vec<Fp2> {
        values
            .chunks_exact(2)
            .map(|pair| pair[0] * (Fp2::ONE - challenge) + pair[1] * challenge)
            .collect()
    }

    fn hex_digest(value: C6ResidualDigest) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn leaf(index: u32, domain: u64, kind: C6LeafKind) -> C6LeafId {
        C6LeafId { schedule_index: index, stage: 1, domain, offset: 0, kind }
    }

    fn source_full(r: u64, x: u64, tag: u64) -> C6SourceWitness {
        C6SourceWitness::FullField { r: fp2(r), correction: fp2(x) - fp2(r), tag: fp2(tag) }
    }

    fn base_key(witness: C6SourceWitness, delta: Fp2) -> Fp2 {
        witness.tag() + delta * witness.base_plaintext()
    }

    struct Fixture {
        builder: C6ResidualBuilder,
        witnesses: Vec<C6SourceWitness>,
        chi: Fp2,
    }

    fn fixture(tag_delta: Fp2, changed_leaf_domain: bool) -> Fixture {
        let mut builder = C6ResidualBuilder::new();
        let a_witness = match source_full(1, 3, 19) {
            C6SourceWitness::FullField { r, correction, tag } => {
                C6SourceWitness::FullField { r, correction, tag: tag + tag_delta }
            }
            _ => unreachable!(),
        };
        let b_witness = source_full(2, 4, 23);
        let c_witness = source_full(5, 12, 29);
        let mask_witness =
            C6SourceWitness::FullField { r: fp2(7), correction: Fp2::ZERO, tag: fp2(31) };
        let witnesses = vec![a_witness, b_witness, c_witness, mask_witness];

        let a = builder
            .add_source(
                leaf(0, if changed_leaf_domain { 0x101 } else { 0x100 }, C6LeafKind::FullField),
                C6LeafRole::Direct,
                a_witness,
            )
            .unwrap();
        let b = builder
            .add_source(leaf(1, 0x200, C6LeafKind::FullField), C6LeafRole::Direct, b_witness)
            .unwrap();
        let c = builder
            .add_source(leaf(2, 0x300, C6LeafKind::FullField), C6LeafRole::Direct, c_witness)
            .unwrap();
        let mask = builder
            .add_source(
                leaf(3, 0x400, C6LeafKind::FullField),
                C6LeafRole::ProductMask,
                mask_witness,
            )
            .unwrap();

        let seven = builder.add_public(fp2(7)).unwrap();
        let sum = builder.add(a, b).unwrap();
        let zero = builder.sub(sum, seven).unwrap();
        builder.add_zero_closure(zero).unwrap();
        let six = builder.add_public(fp2(6)).unwrap();
        let twice_a = builder.scale(a, fp2(2)).unwrap();
        let scaled_zero = builder.sub(twice_a, six).unwrap();
        builder.add_zero_closure(scaled_zero).unwrap();
        builder.add_product_closure(vec![[a, b, c], [b, a, c]], mask).unwrap();
        Fixture { builder, witnesses, chi: fp2(37) }
    }

    fn post_for(program: &C6CommittedResidualProgram, chi: Fp2) -> C6ResidualPostCommit {
        C6ResidualPostCommit {
            base_share_alphas: vec![fp2(41), fp2(43), fp2(47), fp2(53)],
            zero_weights: vec![fp2(59), fp2(61)],
            products: program.product_openings(&[chi]).unwrap(),
        }
    }

    #[cfg(feature = "c6-trace")]
    fn installed_fixture(
        _witnesses: &[C6SourceWitness],
    ) -> (C6InstalledOperationPlan, C6DecodedInstanceExtractionPlan, C6RuntimeInstanceValues) {
        begin_c6_prover_trace().unwrap();
        let mut correlations = CorrelationStream::new([0xC6; 32]);
        correlations.enable_c6_operation_trace().unwrap();
        let direct = correlations.draw_fulls(0x100, 3);
        let mask = correlations.draw_product_mask(0x200, 2);
        let a = direct[0].authenticate(fp2(3));
        let b = direct[1].authenticate(fp2(4));
        let c = direct[2].authenticate(fp2(12));
        let seven = ProverAuthed::from_public(fp2(7));
        let sum = a.add(b);
        let zero = sum.sub(seven);
        let six = ProverAuthed::from_public(fp2(6));
        let twice_a = a.scale(fp2(2));
        let scaled_zero = twice_a.sub(six);
        record_c6_zero_roots(&[zero.c6_trace_token(), scaled_zero.c6_trace_token()]).unwrap();
        record_c6_product_closure(
            &[
                [a.c6_trace_token(), b.c6_trace_token(), c.c6_trace_token()],
                [b.c6_trace_token(), a.c6_trace_token(), c.c6_trace_token()],
            ],
            mask.c6_trace_token(),
        )
        .unwrap();
        let snapshot = finish_c6_prover_trace().unwrap();
        let manifest = C6TraceSourceManifest::new(4, [0x5A; 32], vec![3]).unwrap();
        let compiled = compile_c6_operation_trace_for_role(
            &snapshot,
            &manifest,
            C6InstanceExtractionRole::Prover,
        )
        .unwrap();
        let extraction = compiled.instance_extraction.decode(compiled.plan.topology).unwrap();
        let runtime = derive_c6_runtime_instance_from_trace_diagnostic(
            &snapshot,
            &compiled.artifact,
            &extraction,
            compiled.plan.instance,
        )
        .unwrap();
        let installed = compiled.artifact.install(&manifest).unwrap();
        (installed, extraction, runtime)
    }

    #[cfg(feature = "c6-trace")]
    fn paired_leaf_witness_from_programs(
        primary: &C6CommittedResidualProgram,
        secondary: &C6CommittedResidualProgram,
        source_schedule_digest: C6ResidualDigest,
    ) -> C6PairedResidualLeafWitness {
        assert_eq!(primary.sources.len(), secondary.sources.len());
        let mut columns: [Vec<Fp2>; C6_RESIDUAL_LEAF_ALIGNED_SLOTS as usize] =
            std::array::from_fn(|_| Vec::with_capacity(primary.sources.len()));
        let mut product_mask_count = 0u32;
        for (left, right) in primary.sources.iter().zip(&secondary.sources) {
            assert_eq!(left.id, right.id);
            assert_eq!(left.role, right.role);
            let is_mask = left.role == C6LeafRole::ProductMask;
            if is_mask {
                product_mask_count += 1;
                assert_eq!(left.witness.correction(), Fp2::ZERO);
                assert_eq!(right.witness.correction(), Fp2::ZERO);
            }
            let common = if is_mask {
                Fp2::ZERO
            } else {
                let left_x = left.witness.base_plaintext() + left.witness.correction();
                let right_x = right.witness.base_plaintext() + right.witness.correction();
                assert_eq!(left_x, right_x);
                left_x
            };
            let row = [
                common,
                left.witness.base_plaintext(),
                left.witness.tag(),
                left.witness.correction(),
                right.witness.base_plaintext(),
                right.witness.tag(),
                right.witness.correction(),
            ];
            for (column, value) in columns.iter_mut().zip(row) {
                column.push(value);
            }
        }
        C6PairedResidualLeafWitness {
            source_schedule_digest,
            paired_source_digest: [0xA1; 32],
            source_count: primary.sources.len() as u32,
            product_mask_count,
            columns,
            witness_digest: [0xA2; 32],
        }
    }

    #[cfg(feature = "c6-trace")]
    fn installed_paired_fixture() -> (
        C6InstalledOperationPlan,
        C6DecodedInstanceExtractionPlan,
        C6RuntimeInstanceValues,
        CorrScheduleAudit,
        C6PairedSourceWitness,
    ) {
        let source_schedule_digest = [0x6A; 32];

        let mut primary_stream = CorrelationStream::new([0xD0; 32]);
        primary_stream.enable_c6_source_witness_collection().unwrap();
        let sub = primary_stream.draw_subs(0x90, 1);
        primary_stream.record_c6_subfield_corrections(0x90, &[(fp(9) - sub[0].r).value()]).unwrap();
        let _direct = primary_stream.draw_fulls(0x100, 3);
        primary_stream.record_c6_fullfield_plaintexts(0x100, &[fp2(3), fp2(4), fp2(12)]).unwrap();
        let _mask = primary_stream.draw_product_mask(0x200, 2);
        let schedule = primary_stream.schedule_audit().unwrap();
        let primary = C6SourceCoordinate::new(
            primary_stream.finish_c6_subfield_witness_collection().unwrap(),
            primary_stream.finish_c6_fullfield_witness_collection().unwrap(),
            &schedule,
        )
        .unwrap();
        let mut secondary_stream = CorrelationStream::new([0xD1; 32]);
        let secondary =
            replay_c6_source_coordinate(&primary, &schedule, &mut secondary_stream).unwrap();
        let paired = C6PairedSourceWitness::new(
            [[0xE0; 32], [0xE1; 32]],
            [primary, secondary],
            &schedule,
            source_schedule_digest,
        )
        .unwrap();

        begin_c6_prover_trace().unwrap();
        let mut trace_stream = CorrelationStream::new([0xD2; 32]);
        trace_stream.enable_c6_operation_trace().unwrap();
        let sub = trace_stream.draw_subs(0x90, 1)[0].authenticate(fp(9)).embed();
        let direct = trace_stream.draw_fulls(0x100, 3);
        let mask = trace_stream.draw_product_mask(0x200, 2);
        let a = direct[0].authenticate(fp2(3));
        let b = direct[1].authenticate(fp2(4));
        let c = direct[2].authenticate(fp2(12));
        let seven = ProverAuthed::from_public(fp2(7));
        let zero = a.add(b).sub(seven);
        let six = ProverAuthed::from_public(fp2(6));
        let scaled_zero = a.scale(fp2(2)).sub(six);
        let nine = ProverAuthed::from_public(fp2(9));
        let sub_zero = sub.sub(nine);
        record_c6_zero_roots(&[
            zero.c6_trace_token(),
            scaled_zero.c6_trace_token(),
            sub_zero.c6_trace_token(),
        ])
        .unwrap();
        record_c6_product_closure(
            &[
                [a.c6_trace_token(), b.c6_trace_token(), c.c6_trace_token()],
                [b.c6_trace_token(), a.c6_trace_token(), c.c6_trace_token()],
            ],
            mask.c6_trace_token(),
        )
        .unwrap();
        let snapshot = finish_c6_prover_trace().unwrap();
        let manifest = C6TraceSourceManifest::new(5, source_schedule_digest, vec![4]).unwrap();
        let compiled = compile_c6_operation_trace_for_role(
            &snapshot,
            &manifest,
            C6InstanceExtractionRole::Prover,
        )
        .unwrap();
        let extraction = compiled.instance_extraction.decode(compiled.plan.topology).unwrap();
        let runtime = derive_c6_runtime_instance_from_trace_diagnostic(
            &snapshot,
            &compiled.artifact,
            &extraction,
            compiled.plan.instance,
        )
        .unwrap();
        let installed = compiled.artifact.install(&manifest).unwrap();

        (installed, extraction, runtime, schedule, paired)
    }

    #[test]
    fn scaled_product_fixture_matches_old_verifier_and_compact_residual() {
        let fixture = fixture(Fp2::ZERO, false);
        let witnesses = fixture.witnesses.clone();
        let census = fixture.builder.census().unwrap();
        let program = fixture.builder.commit([7; 32], census).unwrap();
        let post = post_for(&program, fixture.chi);
        let delta = fp2(61);
        let base_keys: Vec<_> = witnesses.iter().map(|witness| base_key(*witness, delta)).collect();

        assert!(program.old_verifier_accepts(&post, &base_keys, delta).unwrap());
        let plan = program.respond(post).unwrap();
        assert!(plan.verify(&base_keys, delta).unwrap());
        assert_eq!(plan.census, census);
        assert_eq!(plan.leaf_order.len(), 4);
        assert_eq!(
            hex_digest(census.leaf_digest),
            "cf5071e1e8567a605b20812e4fe2709b34b3da5fc02675d5e72657221dd11364"
        );
        assert_eq!(
            hex_digest(census.program_digest),
            "b550fca9364f143625d7851aeead98c1a10e4dd7f3f73f9f94cd41f0bab746aa"
        );
        assert_eq!(
            hex_digest(plan.prequery_statement_digest),
            "d9451338b533e5c78dbbf6c320d13889a8bca4cb9ad4aaf5b5cb3c507721b7c1"
        );
        assert_eq!(
            hex_digest(plan.response_digest),
            "bc3f201ff93a1c88e4d61c568b4a18b68460159ef4a35b5ebf025b950c96968d"
        );
        assert_ne!(plan.prequery_statement_digest, [0; 32]);
        assert_ne!(plan.response_digest, [0; 32]);
    }

    #[test]
    fn t1_auxiliary_lane_geometry_is_exact_and_fits_semantic_halves() {
        use crate::c6_census::{C6_T1_TOTAL_PRODUCT_TRIPLES, C6_T1_ZERO_CLOSURES};

        assert_eq!(C6_RESIDUAL_AUXILIARY_PRODUCT_LANES, 12);
        assert_eq!(C6_RESIDUAL_AUXILIARY_ZERO_LANES, 4);
        assert_eq!(
            C6_RESIDUAL_AUXILIARY_PRODUCT_LANES + C6_RESIDUAL_AUXILIARY_ZERO_LANES,
            C6_RESIDUAL_AUXILIARY_LANES
        );
        assert_eq!(C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2, 15);
        assert_eq!(C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES, 32_768);
        assert_eq!(C6_T1_TOTAL_PRODUCT_TRIPLES, 22_339);
        assert_eq!(C6_T1_ZERO_CLOSURES, 8_170);
        const {
            assert!(C6_T1_TOTAL_PRODUCT_TRIPLES <= C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES);
            assert!(C6_T1_ZERO_CLOSURES <= C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES);
        }
        for (index, lane) in C6ResidualAuxiliaryLane::ALL.into_iter().enumerate() {
            assert_eq!(lane.index(), index);
        }
    }

    #[test]
    fn paired_closure_and_auxiliary_workspaces_have_the_frozen_order() {
        let primary_fixture = fixture(Fp2::ZERO, false);
        let primary_census = primary_fixture.builder.census().unwrap();
        let primary = primary_fixture.builder.commit([0x71; 32], primary_census).unwrap();
        let secondary_fixture = fixture(fp2(1), false);
        let secondary_census = secondary_fixture.builder.census().unwrap();
        let secondary = secondary_fixture.builder.commit([0x72; 32], secondary_census).unwrap();

        let witness = primary.build_paired_closure_witness(&secondary).unwrap();
        assert_eq!(witness.program_digest(), primary_census.program_digest);
        assert_ne!(witness.witness_digest(), [0; 32]);
        assert_eq!(
            witness.census(),
            C6ResidualClosureWitnessCensus {
                product_closures: 1,
                product_triples: 2,
                zero_roots: 2,
                product_operand_values: 24,
                zero_root_values: 8,
                footer_values: 64,
                live_values: 96,
            }
        );
        assert_eq!(
            &witness.values()[..12],
            &[
                fp2(3),
                fp2(19),
                fp2(4),
                fp2(23),
                fp2(12),
                fp2(29),
                fp2(3),
                fp2(20),
                fp2(4),
                fp2(23),
                fp2(12),
                fp2(29),
            ]
        );
        assert_eq!(
            &witness.values()[24..32],
            &[Fp2::ZERO, fp2(42), Fp2::ZERO, fp2(43), Fp2::ZERO, fp2(38), Fp2::ZERO, fp2(40),]
        );
        assert!(witness.values()[32..].iter().all(|value| *value == Fp2::ZERO));
        assert!(witness.materialize_padded(6).is_err());
        let padded = witness.materialize_padded(7).unwrap();
        assert_eq!(padded.len(), 128);
        assert_eq!(&padded[..96], witness.values());
        assert!(padded[96..].iter().all(|value| *value == Fp2::ZERO));

        let auxiliary = witness.transpose_auxiliary_lanes().unwrap();
        assert_eq!(auxiliary.program_digest(), witness.program_digest());
        assert_eq!(auxiliary.closure_witness_digest(), witness.witness_digest());
        assert_eq!(auxiliary.closure_census(), witness.census());
        assert_eq!(
            auxiliary.census(),
            C6ResidualAuxiliaryWitnessCensus {
                product_rows: 2,
                zero_rows: 2,
                product_lanes: 12,
                zero_lanes: 4,
                semantic_entries_per_lane: 1 << 15,
                transposed_live_values: 32,
            }
        );
        assert_ne!(auxiliary.witness_digest(), [0; 32]);
        let expected_lanes = [
            (C6ResidualAuxiliaryLane::Coordinate0ProductXa, [fp2(3), fp2(4)]),
            (C6ResidualAuxiliaryLane::Coordinate0ProductMa, [fp2(19), fp2(23)]),
            (C6ResidualAuxiliaryLane::Coordinate0ProductXb, [fp2(4), fp2(3)]),
            (C6ResidualAuxiliaryLane::Coordinate0ProductMb, [fp2(23), fp2(19)]),
            (C6ResidualAuxiliaryLane::Coordinate0ProductXc, [fp2(12), fp2(12)]),
            (C6ResidualAuxiliaryLane::Coordinate0ProductMc, [fp2(29), fp2(29)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductXa, [fp2(3), fp2(4)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductMa, [fp2(20), fp2(23)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductXb, [fp2(4), fp2(3)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductMb, [fp2(23), fp2(20)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductXc, [fp2(12), fp2(12)]),
            (C6ResidualAuxiliaryLane::Coordinate1ProductMc, [fp2(29), fp2(29)]),
            (C6ResidualAuxiliaryLane::Coordinate0ZeroX, [Fp2::ZERO, Fp2::ZERO]),
            (C6ResidualAuxiliaryLane::Coordinate0ZeroM, [fp2(42), fp2(38)]),
            (C6ResidualAuxiliaryLane::Coordinate1ZeroX, [Fp2::ZERO, Fp2::ZERO]),
            (C6ResidualAuxiliaryLane::Coordinate1ZeroM, [fp2(43), fp2(40)]),
        ];
        for (lane, expected) in expected_lanes {
            assert_eq!(auxiliary.lane(lane), expected);
        }

        let semantic = auxiliary.materialize_semantic_halves().unwrap();
        for lane in C6ResidualAuxiliaryLane::ALL {
            let live = auxiliary.lane(lane);
            assert_eq!(
                semantic[lane.index()].len(),
                C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES as usize
            );
            assert_eq!(&semantic[lane.index()][..live.len()], live);
            assert!(semantic[lane.index()][live.len()..].iter().all(|value| *value == Fp2::ZERO));
        }

        let mut changed_value = witness.clone();
        changed_value.values[0] += Fp2::ONE;
        let changed_auxiliary = changed_value.transpose_auxiliary_lanes().unwrap();
        assert_ne!(changed_auxiliary.witness_digest(), auxiliary.witness_digest());

        let mut malformed_layout = witness.clone();
        malformed_layout.census.product_operand_values -= 1;
        assert!(malformed_layout.transpose_auxiliary_lanes().is_err());

        let mut malformed_footer = witness.clone();
        let footer_index = malformed_footer.values.len() - 1;
        malformed_footer.values[footer_index] = Fp2::ONE;
        assert!(malformed_footer.transpose_auxiliary_lanes().is_err());

        let mut truncated = witness.clone();
        truncated.values.pop();
        assert!(truncated.transpose_auxiliary_lanes().is_err());

        let changed_fixture = fixture(Fp2::ZERO, true);
        let changed_census = changed_fixture.builder.census().unwrap();
        let changed = changed_fixture.builder.commit([0x73; 32], changed_census).unwrap();
        assert!(primary.build_paired_closure_witness(&changed).is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn installed_reverse_accumulator_matches_reference_without_leaf_vectors_on_wire() {
        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();
        let fixture = fixture(Fp2::ZERO, false);
        let witnesses = fixture.witnesses.clone();
        let census = fixture.builder.census().unwrap();
        let program = fixture.builder.commit([0xC6; 32], census).unwrap();
        let zero_weights = [fp2(59), fp2(61)];
        let alpha_seed = [0xA7; 32];
        let mut alpha_reference = Transcript::new(alpha_seed);
        let alphas =
            (0..witnesses.len()).map(|_| alpha_reference.challenge_fp2()).collect::<Vec<_>>();
        let reference_post = C6ResidualPostCommit {
            base_share_alphas: alphas,
            zero_weights: zero_weights.to_vec(),
            products: program.product_openings(&[fixture.chi]).unwrap(),
        };
        let reference = program.respond(reference_post).unwrap();

        let (installed, extraction, runtime) = installed_fixture(&witnesses);
        let compiled =
            C6CompiledLinearResidual::compile(&installed, &extraction, &runtime, &zero_weights)
                .unwrap();
        assert_eq!(compiled.source_count(), witnesses.len());
        assert_eq!(compiled.product_mask_sources(), &[3]);
        let memory = compiled.memory_census().unwrap();
        assert_eq!(memory.leaf_coefficient_elements, 4);
        assert_eq!(memory.product_mask_elements, 1);
        assert_eq!(
            memory.peak_compile_resident_bytes,
            memory.retained_resident_bytes + memory.node_workspace_bytes
        );

        let delta = fp2(61);
        let base_keys =
            witnesses.iter().map(|witness| base_key(*witness, delta)).collect::<Vec<_>>();
        let mut provider_transcript = Transcript::new(alpha_seed);
        let response = compiled.respond_sources(&witnesses, &mut provider_transcript).unwrap();
        let mut client_transcript = Transcript::new(alpha_seed);
        let client = compiled.fold_base_keys(&base_keys, &mut client_transcript).unwrap();

        assert_eq!(response.residual, reference.residual);
        assert_eq!(response.binding, client.binding);
        assert!(response.verify(client, delta).unwrap());
        assert_ne!(response.binding.linear_form_digest, [0; 32]);
        assert_ne!(response.binding.coefficient_digest, [0; 32]);
        assert!(std::mem::size_of_val(&response) <= 256);
        assert_installed_terminal_forms_reuse_the_residual_reverse_walker_exactly(
            &installed,
            &extraction,
            &runtime,
            &witnesses,
            &compiled,
        );
    }

    #[cfg(feature = "c6-trace")]
    fn assert_installed_terminal_forms_reuse_the_residual_reverse_walker_exactly(
        installed: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
        runtime: &C6RuntimeInstanceValues,
        witnesses: &[C6SourceWitness],
        compiled: &C6CompiledLinearResidual,
    ) {
        let zero_weights = [fp2(59), fp2(61)];

        let zero_only = C6ResidualTerminalWeightSchedule::new(
            installed,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
            vec![[Fp2::ZERO; 3]; 2],
            zero_weights.to_vec(),
        )
        .unwrap();
        let zero_form =
            C6CompiledTerminalLinearForm::compile(installed, extraction, runtime, &zero_only)
                .unwrap();
        assert_eq!(zero_form.leaf_coefficients(), compiled.leaf_coefficients());
        assert_eq!(zero_form.public_plaintext(), compiled.public_plaintext());
        assert_eq!(zero_form.topology(), compiled.topology());
        assert_eq!(zero_form.instance(), compiled.instance());

        let product_weights = vec![[fp2(2), fp2(3), fp2(5)], [fp2(7), fp2(11), fp2(13)]];
        let terminal_zero_weights = vec![fp2(17), fp2(19)];
        let plaintext_schedule = C6ResidualTerminalWeightSchedule::new(
            installed,
            1,
            1,
            C6ResidualTerminalFormKind::Plaintext,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        let tag_schedule = C6ResidualTerminalWeightSchedule::new(
            installed,
            1,
            1,
            C6ResidualTerminalFormKind::Tag,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        let other_coordinate_schedule = C6ResidualTerminalWeightSchedule::new(
            installed,
            1,
            0,
            C6ResidualTerminalFormKind::Plaintext,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        let other_repetition_schedule = C6ResidualTerminalWeightSchedule::new(
            installed,
            0,
            1,
            C6ResidualTerminalFormKind::Plaintext,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        assert_ne!(plaintext_schedule.digest(), tag_schedule.digest());
        assert_ne!(plaintext_schedule.digest(), other_coordinate_schedule.digest());
        assert_ne!(plaintext_schedule.digest(), other_repetition_schedule.digest());
        let plaintext = C6CompiledTerminalLinearForm::compile(
            installed,
            extraction,
            runtime,
            &plaintext_schedule,
        )
        .unwrap();
        let tag =
            C6CompiledTerminalLinearForm::compile(installed, extraction, runtime, &tag_schedule)
                .unwrap();
        let other_coordinate = C6CompiledTerminalLinearForm::compile(
            installed,
            extraction,
            runtime,
            &other_coordinate_schedule,
        )
        .unwrap();
        assert_eq!(plaintext.leaf_coefficients(), tag.leaf_coefficients());
        assert_eq!(plaintext.leaf_coefficients(), other_coordinate.leaf_coefficients());
        assert_eq!(tag.public_plaintext(), Fp2::ZERO);
        assert_ne!(plaintext.linear_form_digest(), tag.linear_form_digest());
        assert_ne!(plaintext.linear_form_digest(), other_coordinate.linear_form_digest());
        assert_eq!(plaintext.proof_repetition(), 1);
        assert_eq!(plaintext.mac_coordinate(), 1);
        assert_eq!(plaintext.kind(), C6ResidualTerminalFormKind::Plaintext);
        assert_eq!(plaintext.schedule_digest(), plaintext_schedule.digest());
        assert_eq!(plaintext.leaf_coefficients()[3], Fp2::ZERO);

        let values = witnesses.iter().map(|witness| witness.prover_value()).collect::<Vec<_>>();
        let zero = values[0].add(values[1]).sub(ProverAuthed::from_public(fp2(7)));
        let scaled_zero = values[0].scale(fp2(2)).sub(ProverAuthed::from_public(fp2(6)));
        let terminal_values =
            [[values[0], values[1], values[2]], [values[1], values[0], values[2]]];
        let expected_plaintext = terminal_values.iter().zip(&product_weights).fold(
            Fp2::ZERO,
            |sum, (triple, weights)| {
                sum + triple
                    .iter()
                    .zip(weights)
                    .fold(Fp2::ZERO, |row, (value, weight)| row + value.x * *weight)
            },
        ) + terminal_zero_weights[0] * zero.x
            + terminal_zero_weights[1] * scaled_zero.x;
        let expected_tag = terminal_values.iter().zip(&product_weights).fold(
            Fp2::ZERO,
            |sum, (triple, weights)| {
                sum + triple
                    .iter()
                    .zip(weights)
                    .fold(Fp2::ZERO, |row, (value, weight)| row + value.m * *weight)
            },
        ) + terminal_zero_weights[0] * zero.m
            + terminal_zero_weights[1] * scaled_zero.m;
        let source_plaintext = plaintext
            .leaf_coefficients()
            .iter()
            .zip(&values)
            .fold(plaintext.public_plaintext(), |sum, (coefficient, value)| {
                sum + *coefficient * value.x
            });
        let source_tag = tag
            .leaf_coefficients()
            .iter()
            .zip(&values)
            .fold(tag.public_plaintext(), |sum, (coefficient, value)| sum + *coefficient * value.m);
        assert_eq!(source_plaintext, expected_plaintext);
        assert_eq!(source_tag, expected_tag);

        let fixed_roots_digest = [0xB7; 32];
        let batching_seed = [0xB8; 32];
        let post_root =
            C6ResidualPostRootChallenges::derive(installed, fixed_roots_digest, batching_seed)
                .unwrap();
        assert_eq!(post_root.fixed_roots_digest(), fixed_roots_digest);
        assert_ne!(post_root.batching_seed_commitment(), [0; 32]);
        assert_ne!(post_root.digest(), [0; 32]);
        assert_eq!(
            post_root,
            C6ResidualPostRootChallenges::derive(installed, fixed_roots_digest, batching_seed,)
                .unwrap()
        );
        let terminal_domains = TERMINAL_WEIGHT_STREAM_DOMAINS
            .iter()
            .flat_map(|coordinates| coordinates.iter())
            .flat_map(|kinds| kinds.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let alpha_domains = PAIRED_COEFFICIENT_STREAM_DOMAINS.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(terminal_domains.len(), C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS);
        assert!(terminal_domains.is_disjoint(&alpha_domains));
        let mut schedule_digests = Vec::new();
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            for mac_coordinate in 0..C6_RESIDUAL_MAC_COORDINATES {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    let schedule = post_root
                        .terminal_schedule(proof_repetition, mac_coordinate, kind)
                        .unwrap();
                    assert_eq!(schedule.proof_repetition(), proof_repetition);
                    assert_eq!(schedule.mac_coordinate(), mac_coordinate);
                    assert_eq!(schedule.kind(), kind);
                    assert_eq!(schedule.product_weights().len(), 2);
                    assert_eq!(schedule.zero_weights().len(), 2);
                    schedule_digests.push(schedule.digest());

                    let compiled_post_root = C6CompiledTerminalLinearForm::compile_post_root(
                        installed,
                        extraction,
                        runtime,
                        &post_root,
                        proof_repetition,
                        mac_coordinate,
                        kind,
                    )
                    .unwrap();
                    let compiled_reference = C6CompiledTerminalLinearForm::compile(
                        installed, extraction, runtime, schedule,
                    )
                    .unwrap();
                    assert_eq!(
                        compiled_post_root.linear_form_digest(),
                        compiled_reference.linear_form_digest()
                    );

                    let mut reference_stream = FpStream::domain_separated(
                        post_root.context_seed,
                        TERMINAL_WEIGHT_STREAM_DOMAINS[usize::from(proof_repetition)]
                            [usize::from(mac_coordinate)][kind.stream_index()],
                    );
                    for weights in schedule.product_weights() {
                        assert_eq!(
                            *weights,
                            [
                                reference_stream.next_fp2(),
                                reference_stream.next_fp2(),
                                reference_stream.next_fp2(),
                            ]
                        );
                    }
                    for weight in schedule.zero_weights() {
                        assert_eq!(*weight, reference_stream.next_fp2());
                    }
                }
            }
        }
        let unique_schedule_digests = schedule_digests.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(unique_schedule_digests.len(), C6_RESIDUAL_POST_ROOT_TERMINAL_STREAMS);

        let changed_root =
            C6ResidualPostRootChallenges::derive(installed, [0xB9; 32], batching_seed).unwrap();
        let changed_seed =
            C6ResidualPostRootChallenges::derive(installed, fixed_roots_digest, [0xBA; 32])
                .unwrap();
        assert_ne!(changed_root.digest(), post_root.digest());
        assert_ne!(changed_seed.digest(), post_root.digest());
        assert_ne!(changed_root.context_seed, post_root.context_seed);
        assert_ne!(changed_seed.context_seed, post_root.context_seed);
        assert!(C6ResidualPostRootChallenges::derive(installed, [0; 32], batching_seed).is_err());
        assert!(post_root.terminal_schedule(2, 0, C6ResidualTerminalFormKind::Plaintext).is_err());
        assert!(post_root.terminal_schedule(0, 2, C6ResidualTerminalFormKind::Plaintext).is_err());

        let mut swapped_kinds = post_root.clone();
        swapped_kinds.terminal_schedules.swap(0, 1);
        assert!(C6CompiledTerminalLinearForm::compile_post_root(
            installed,
            extraction,
            runtime,
            &swapped_kinds,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
        )
        .is_err());
        let mut swapped_coordinates = post_root.clone();
        swapped_coordinates.terminal_schedules.swap(0, 2);
        assert!(C6CompiledTerminalLinearForm::compile_post_root(
            installed,
            extraction,
            runtime,
            &swapped_coordinates,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
        )
        .is_err());
        let mut swapped_repetitions = post_root.clone();
        swapped_repetitions.terminal_schedules.swap(0, 4);
        assert!(C6CompiledTerminalLinearForm::compile_post_root(
            installed,
            extraction,
            runtime,
            &swapped_repetitions,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
        )
        .is_err());
        let mut changed_weight = post_root.clone();
        changed_weight.terminal_schedules[0].product_weights[0][0] += Fp2::ONE;
        assert!(C6CompiledTerminalLinearForm::compile_post_root(
            installed,
            extraction,
            runtime,
            &changed_weight,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
        )
        .is_err());

        assert!(C6ResidualTerminalWeightSchedule::new(
            installed,
            0,
            0,
            C6ResidualTerminalFormKind::Plaintext,
            vec![[Fp2::ZERO; 3]; 1],
            zero_weights.to_vec(),
        )
        .is_err());
        assert!(C6ResidualTerminalWeightSchedule::new(
            installed,
            2,
            0,
            C6ResidualTerminalFormKind::Plaintext,
            vec![[Fp2::ZERO; 3]; 2],
            zero_weights.to_vec(),
        )
        .is_err());
        assert!(C6ResidualTerminalWeightSchedule::new(
            installed,
            0,
            2,
            C6ResidualTerminalFormKind::Plaintext,
            vec![[Fp2::ZERO; 3]; 2],
            zero_weights.to_vec(),
        )
        .is_err());
        let mut malformed = plaintext_schedule.clone();
        malformed.product_weights[0][0] += Fp2::ONE;
        assert!(C6CompiledTerminalLinearForm::compile(installed, extraction, runtime, &malformed,)
            .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn v3_atomic_relation_typestate_and_all_families_are_differentially_bound() {
        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();

        let primary_fixture = fixture(Fp2::ZERO, false);
        let installed_witnesses = primary_fixture.witnesses.clone();
        let chi = primary_fixture.chi;
        let primary_census = primary_fixture.builder.census().unwrap();
        let primary = primary_fixture.builder.commit([0xC1; 32], primary_census).unwrap();
        let secondary_fixture = fixture(fp2(1), false);
        let secondary_census = secondary_fixture.builder.census().unwrap();
        let secondary = secondary_fixture.builder.commit([0xC2; 32], secondary_census).unwrap();
        let leaf = paired_leaf_witness_from_programs(&primary, &secondary, [0x5A; 32]);
        let closure = primary.build_paired_closure_witness(&secondary).unwrap();
        let auxiliary = closure.transpose_auxiliary_lanes().unwrap();

        let (installed, extraction, runtime) = installed_fixture(&installed_witnesses);
        assert!(C6ResidualRelationManifest::new(&installed, &extraction, &runtime).is_err());
        let manifest = C6ResidualRelationManifest::new_with_geometry(
            &installed,
            &extraction,
            &runtime,
            7,
            2,
            false,
        )
        .unwrap();
        assert!(!manifest.is_production_geometry());
        assert_eq!(manifest.product_mask_sources(), &[3]);
        assert_eq!(manifest.leaf_entries(), 128);
        assert_eq!(manifest.auxiliary_entries(), 4);
        assert_eq!(manifest.raw_copy_entries(), 32);
        assert_eq!(manifest.atomic_outputs_per_repetition(), 1_056);

        let reference =
            C6ResidualRelationReferenceWitness::from_live(&manifest, &leaf, &closure, &auxiliary)
                .unwrap();
        let retained = C6ResidualRetainedChallenges::new(&manifest, vec![chi], fp2(79)).unwrap();
        let zero_weights = retained.zero_weights(installed.zero_roots().len());
        let linear =
            C6CompiledLinearResidual::compile(&installed, &extraction, &runtime, &zero_weights)
                .unwrap();

        let root =
            C6ResidualRelationRootBound::bind_fixed_roots(manifest.clone(), [0xD1; 32], [0xD2; 32])
                .unwrap();
        assert!(C6ResidualRelationRootBound::bind_fixed_roots(
            manifest.clone(),
            [0; 32],
            [0xD2; 32],
        )
        .is_err());
        let base_seed = [0xD3; 32];
        let base = root.release_base_share_seed(retained, base_seed).unwrap();
        assert_ne!(base.digest(), [0; 32]);
        assert_ne!(base.base_share_seed_commitment(), [0; 32]);
        assert_ne!(
            base.alpha_stream(0).unwrap().next_fp2(),
            base.alpha_stream(1).unwrap().next_fp2()
        );
        assert!(base.alpha_stream(2).is_err());

        let mut alphas: [Vec<Fp2>; 2] =
            std::array::from_fn(|_| Vec::with_capacity(linear.source_count()));
        for coordinate in 0..2u8 {
            let mut stream = base.alpha_stream(coordinate).unwrap();
            for _ in 0..linear.source_count() {
                alphas[usize::from(coordinate)].push(stream.next_fp2());
            }
        }
        let mut residuals =
            [C6DeltaResidual { correction_rlc: Fp2::ZERO, public_tag_rlc: Fp2::ZERO }; 2];
        for (coordinate, (coordinate_alphas, residual)) in
            alphas.iter().zip(&mut residuals).enumerate()
        {
            let (r_table, m_table, d_table) = if coordinate == 0 { (1, 2, 3) } else { (4, 5, 6) };
            let mut correction = linear.public_plaintext();
            let mut message = Fp2::ZERO;
            for (source, &alpha) in coordinate_alphas.iter().enumerate() {
                correction +=
                    linear.leaf_coefficients()[source] * reference.leaf_tables[d_table][source];
                correction = correction - alpha * reference.leaf_tables[r_table][source];
                message += (linear.leaf_coefficients()[source] + alpha)
                    * reference.leaf_tables[m_table][source];
            }
            *residual = C6DeltaResidual { correction_rlc: correction, public_tag_rlc: message };
        }

        let mut product_claims = Vec::new();
        let mut triple_cursor = 0usize;
        for (closure_index, product) in installed.products().iter().enumerate() {
            let mask_source = manifest.product_mask_sources()[closure_index] as usize;
            let mut messages = [[Fp2::ZERO; 2]; 2];
            for (coordinate, message) in messages.iter_mut().enumerate() {
                let lane = 6 * coordinate;
                let r_table = if coordinate == 0 { 1 } else { 4 };
                let m_table = if coordinate == 0 { 2 } else { 5 };
                let mut q = Fp2::ZERO;
                let mut m0 = reference.leaf_tables[m_table][mask_source];
                let mut m1 = reference.leaf_tables[r_table][mask_source];
                let mut power = Fp2::ONE;
                for triple in 0..product.triples().len() {
                    power = power * chi;
                    let row = triple_cursor + triple;
                    q += power
                        * (reference.auxiliary_tables[lane][row]
                            * reference.auxiliary_tables[lane + 2][row]
                            - reference.auxiliary_tables[lane + 4][row]);
                    m0 += power
                        * reference.auxiliary_tables[lane + 1][row]
                        * reference.auxiliary_tables[lane + 3][row];
                    m1 += power
                        * (reference.auxiliary_tables[lane][row]
                            * reference.auxiliary_tables[lane + 3][row]
                            + reference.auxiliary_tables[lane + 1][row]
                                * reference.auxiliary_tables[lane + 2][row]
                            - reference.auxiliary_tables[lane + 5][row]);
                }
                assert_eq!(q, Fp2::ZERO);
                *message = [m0, m1];
            }
            triple_cursor += product.triples().len();
            product_claims.push(C6ResidualProductPublicClaim { messages });
        }
        assert_eq!(triple_cursor, 2);

        let residual = C6PairedDeltaResidual { coordinates: residuals };
        let claims_bound = base
            .clone()
            .commit_public_claims(linear.linear_form_digest(), product_claims.clone(), residual)
            .unwrap();
        let relation_seed = [0xD4; 32];
        let relation = claims_bound.release_relation_seed(&installed, relation_seed).unwrap();
        assert_ne!(relation.digest(), [0; 32]);
        assert_ne!(relation.relation_seed_commitment(), base.base_share_seed_commitment());
        assert!(base
            .clone()
            .commit_public_claims(linear.linear_form_digest(), product_claims.clone(), residual,)
            .unwrap()
            .release_relation_seed(&installed, base_seed)
            .is_err());

        let mut terminal_digests = BTreeSet::new();
        for proof_repetition in 0..2u8 {
            let atomic = relation.atomic_schedule(proof_repetition).unwrap();
            assert_eq!(atomic.output_count(), 1_056);
            assert_eq!(
                atomic.stream_domain(),
                ATOMIC_WEIGHT_STREAM_DOMAINS[usize::from(proof_repetition)]
            );
            assert_ne!(atomic.digest(), [0; 32]);
            for coordinate in 0..2u8 {
                for kind in [C6ResidualTerminalFormKind::Plaintext, C6ResidualTerminalFormKind::Tag]
                {
                    let schedule =
                        relation.terminal_schedule(proof_repetition, coordinate, kind).unwrap();
                    assert_eq!(schedule.protocol_version(), RESIDUAL_RELATION_PROTOCOL_V3);
                    terminal_digests.insert(schedule.digest());
                }
            }
        }
        assert_eq!(terminal_digests.len(), 8);
        let diagnostic_v2 =
            C6ResidualPostRootChallenges::derive(&installed, [0xD2; 32], base_seed).unwrap();
        assert_eq!(
            diagnostic_v2
                .terminal_schedule(0, 0, C6ResidualTerminalFormKind::Plaintext)
                .unwrap()
                .protocol_version(),
            RESIDUAL_RELATION_PROTOCOL_V2
        );
        assert_ne!(
            diagnostic_v2
                .terminal_schedule(0, 0, C6ResidualTerminalFormKind::Plaintext)
                .unwrap()
                .digest(),
            relation
                .terminal_schedule(0, 0, C6ResidualTerminalFormKind::Plaintext)
                .unwrap()
                .digest()
        );

        let compiled = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &reference,
        )
        .unwrap();
        let legacy = compile_c6_residual_atomic_relation_reference_legacy(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &reference,
        )
        .unwrap();
        assert_eq!(compiled, legacy);
        assert!(compiled.is_satisfied());
        assert_ne!(compiled.digest(), [0; 32]);
        assert_eq!(compiled.family_outputs()[0], [12, 4, 4, 32, 6, 2, 964, 32]);
        assert_eq!(compiled.family_outputs()[0], compiled.family_outputs()[1]);
        assert!(compiled
            .family_weighted_residuals()
            .iter()
            .flatten()
            .all(|residual| *residual == Fp2::ZERO));
        assert_ne!(compiled.statements()[0].digest(), compiled.statements()[1].digest());
        for statement in compiled.statements() {
            assert_eq!(statement.atomic_outputs_consumed(), 1_056);
            assert_eq!(statement.auxiliary_quadratic().len(), 8);
            assert_eq!(
                statement
                    .auxiliary_quadratic()
                    .iter()
                    .map(|(factors, _)| *factors)
                    .collect::<Vec<_>>(),
                C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            );
            assert_eq!(statement.evaluate(&reference).unwrap(), statement.target());
        }
        let mut production_requires_installed = manifest.clone();
        production_requires_installed.production_geometry = true;
        assert!(C6ResidualFusedWitnessView::new(
            &production_requires_installed,
            &leaf,
            &closure,
            &auxiliary,
        )
        .is_err());
        let fused_witness =
            C6ResidualFusedWitnessView::new(&manifest, &leaf, &closure, &auxiliary).unwrap();
        assert_eq!(fused_witness.manifest_digest(), manifest.digest());
        assert_ne!(fused_witness.digest(), [0; 32]);
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            let statement = &compiled.statements()[usize::from(proof_repetition)];
            let first_round = compile_c6_residual_fused_first_round(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                fused_witness,
            )
            .unwrap();
            assert_eq!(first_round.proof_repetition(), proof_repetition);
            assert_eq!(first_round.target(), statement.target());
            assert_eq!(first_round.witness_view_digest(), fused_witness.digest());
            assert_ne!(first_round.digest(), [0; 32]);

            let mut expected_leaf = [Fp2::ZERO; 3];
            for (coefficients, witness) in
                statement.leaf_linear().iter().zip(reference.leaf_tables())
            {
                for pair in 0..coefficients.len() / 2 {
                    for (index, expected) in expected_leaf.iter_mut().enumerate() {
                        let point = fp2(index as u64);
                        let coefficient = coefficients[2 * pair] * (Fp2::ONE - point)
                            + coefficients[2 * pair + 1] * point;
                        let value =
                            witness[2 * pair] * (Fp2::ONE - point) + witness[2 * pair + 1] * point;
                        *expected += coefficient * value;
                    }
                }
            }
            let mut expected_auxiliary = [Fp2::ZERO; 4];
            for (coefficients, witness) in
                statement.auxiliary_linear().iter().zip(reference.auxiliary_tables())
            {
                for pair in 0..coefficients.len() / 2 {
                    for (index, expected) in expected_auxiliary.iter_mut().enumerate() {
                        let point = fp2(index as u64);
                        let coefficient = coefficients[2 * pair] * (Fp2::ONE - point)
                            + coefficients[2 * pair + 1] * point;
                        let value =
                            witness[2 * pair] * (Fp2::ONE - point) + witness[2 * pair + 1] * point;
                        *expected += coefficient * value;
                    }
                }
            }
            for ((lhs, rhs), coefficients) in statement.auxiliary_quadratic() {
                let lhs = &reference.auxiliary_tables()[usize::from(*lhs)];
                let rhs = &reference.auxiliary_tables()[usize::from(*rhs)];
                for pair in 0..coefficients.len() / 2 {
                    for (index, expected) in expected_auxiliary.iter_mut().enumerate() {
                        let point = fp2(index as u64);
                        let coefficient = coefficients[2 * pair] * (Fp2::ONE - point)
                            + coefficients[2 * pair + 1] * point;
                        let lhs = lhs[2 * pair] * (Fp2::ONE - point) + lhs[2 * pair + 1] * point;
                        let rhs = rhs[2 * pair] * (Fp2::ONE - point) + rhs[2 * pair + 1] * point;
                        *expected += coefficient * lhs * rhs;
                    }
                }
            }
            assert_eq!(first_round.leaf_message(), &expected_leaf);
            assert_eq!(first_round.auxiliary_message(), &expected_auxiliary);
            assert_eq!(
                first_round.leaf_message()[0]
                    + first_round.leaf_message()[1]
                    + first_round.auxiliary_message()[0]
                    + first_round.auxiliary_message()[1],
                first_round.target()
            );

            let mut audit = C6ResidualAtomicEventAuditSink::new(proof_repetition);
            let summary = replay_c6_residual_atomic_events(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                &mut audit,
            )
            .unwrap();
            assert_eq!(first_round.semantic_digest(), summary.semantic_digest());
        }
        let mut malformed_auxiliary = auxiliary.clone();
        malformed_auxiliary.closure_witness_digest = [0; 32];
        assert!(C6ResidualFusedWitnessView::new(&manifest, &leaf, &closure, &malformed_auxiliary)
            .is_err());

        assert_eq!(std::mem::size_of::<Fp2>(), 16);
        assert_eq!(C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_ELEMENTS, 33_554_432);
        assert_eq!(C6_RESIDUAL_FUSED_MAX_COEFFICIENT_STATE_BYTES, 536_870_912);
        let leaf_memory = c6_residual_fused_coefficient_memory_census(
            &manifest,
            C6ResidualFusedCoefficientFamily::Leaf,
        )
        .unwrap();
        assert_eq!(leaf_memory.input_entries_per_table(), 128);
        assert_eq!(leaf_memory.folded_entries_per_table(), 64);
        assert_eq!(leaf_memory.linear_tables(), 8);
        assert_eq!(leaf_memory.quadratic_tables(), 0);
        assert_eq!(leaf_memory.state_elements(), 512);
        assert_eq!(leaf_memory.state_bytes(), 8_192);
        let auxiliary_memory = c6_residual_fused_coefficient_memory_census(
            &manifest,
            C6ResidualFusedCoefficientFamily::Auxiliary,
        )
        .unwrap();
        assert_eq!(auxiliary_memory.input_entries_per_table(), 4);
        assert_eq!(auxiliary_memory.folded_entries_per_table(), 2);
        assert_eq!(auxiliary_memory.linear_tables(), 16);
        assert_eq!(auxiliary_memory.quadratic_tables(), 8);
        assert_eq!(auxiliary_memory.state_elements(), 48);
        assert_eq!(auxiliary_memory.state_bytes(), 768);

        let allocation_tracker = C6ResidualFusedCoefficientAllocationTracker::new(&manifest);
        assert_eq!(allocation_tracker.manifest_digest(), manifest.digest());
        assert_eq!(allocation_tracker.active_repetition(), None);
        assert_eq!(allocation_tracker.active_elements(), 0);
        assert_eq!(allocation_tracker.active_bytes(), 0);
        assert!(!allocation_tracker.is_faulted());
        assert!(compile_c6_residual_fused_folded_coefficients(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &allocation_tracker,
            0,
            C6ResidualFusedCoefficientFamily::Auxiliary,
            fp2(79),
        )
        .is_err());
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            let challenge = fp2(83 + u64::from(proof_repetition));
            let statement = &compiled.statements()[usize::from(proof_repetition)];
            let mut leaf_folded = compile_c6_residual_fused_folded_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                &allocation_tracker,
                proof_repetition,
                C6ResidualFusedCoefficientFamily::Leaf,
                challenge,
            )
            .unwrap();
            assert_eq!(leaf_folded.proof_repetition(), proof_repetition);
            assert_eq!(leaf_folded.family(), C6ResidualFusedCoefficientFamily::Leaf);
            assert_eq!(leaf_folded.challenge(), challenge);
            assert_eq!(leaf_folded.point(), &[challenge]);
            assert_eq!(leaf_folded.entries_per_table(), 64);
            assert_eq!(leaf_folded.active_elements(), 512);
            assert_eq!(leaf_folded.target(), statement.target());
            assert_eq!(leaf_folded.selected_coefficient_writes(), 1_061);
            assert_eq!(leaf_folded.memory_census(), leaf_memory);
            assert!(leaf_folded.with_auxiliary_tables(|_, _| ()).is_err());
            leaf_folded
                .with_leaf_linear(|actual| {
                    for (actual, coefficients) in actual.iter().zip(statement.leaf_linear()) {
                        assert_eq!(*actual, fold_once(coefficients, challenge));
                    }
                })
                .unwrap();
            assert_eq!(allocation_tracker.active_repetition(), Some(proof_repetition));
            assert_eq!(allocation_tracker.active_elements(), 512);
            assert_eq!(allocation_tracker.active_leaf_elements(), 512);
            assert_eq!(allocation_tracker.active_auxiliary_elements(), 0);
            assert_eq!(allocation_tracker.active_bytes(), 8_192);
            assert_eq!(allocation_tracker.reserved_elements(), 512);
            assert_eq!(allocation_tracker.reserved_bytes(), 8_192);
            let backing_pointer =
                allocation_tracker.with_snapshot(|state| state.backing.as_ptr() as usize);
            assert!(compile_c6_residual_fused_folded_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                &allocation_tracker,
                proof_repetition,
                C6ResidualFusedCoefficientFamily::Auxiliary,
                challenge,
            )
            .is_err());
            assert!(compile_c6_residual_fused_folded_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                &allocation_tracker,
                1 - proof_repetition,
                C6ResidualFusedCoefficientFamily::Leaf,
                challenge,
            )
            .is_err());

            let shared_prefix: [Fp2; 5] = std::array::from_fn(|index| {
                fp2(101 + 8 * u64::from(proof_repetition) + index as u64)
            });
            for next_challenge in shared_prefix {
                leaf_folded.fold_next(next_challenge).unwrap();
                leaf_folded
                    .with_leaf_linear(|actual| {
                        for (actual, coefficients) in actual.iter().zip(statement.leaf_linear()) {
                            let mut expected = coefficients.clone();
                            for point in leaf_folded.point() {
                                crate::mle::fold_low(&mut expected, *point);
                            }
                            assert_eq!(*actual, expected);
                        }
                    })
                    .unwrap();
            }
            assert_eq!(leaf_folded.entries_per_table(), 2);
            assert_eq!(leaf_folded.active_elements(), 16);
            assert_eq!(allocation_tracker.active_leaf_elements(), 16);
            assert_eq!(allocation_tracker.active_elements(), 16);

            let leaf_semantic_digest = leaf_folded.semantic_digest();
            let leaf_completion_digest = leaf_folded.completion_digest();
            let activation_challenge = *shared_prefix.last().unwrap();
            let mut auxiliary_folded = compile_c6_residual_fused_folded_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                &allocation_tracker,
                proof_repetition,
                C6ResidualFusedCoefficientFamily::Auxiliary,
                activation_challenge,
            )
            .unwrap();
            assert_eq!(auxiliary_folded.family(), C6ResidualFusedCoefficientFamily::Auxiliary);
            assert_eq!(auxiliary_folded.point(), &[activation_challenge]);
            assert_eq!(auxiliary_folded.entries_per_table(), 2);
            assert_eq!(auxiliary_folded.target(), statement.target());
            assert_eq!(auxiliary_folded.selected_coefficient_writes(), 124);
            assert_eq!(auxiliary_folded.memory_census(), auxiliary_memory);
            assert!(auxiliary_folded.with_leaf_linear(|_| ()).is_err());
            auxiliary_folded
                .with_auxiliary_tables(|linear, quadratic| {
                    for (actual, coefficients) in linear.iter().zip(statement.auxiliary_linear()) {
                        assert_eq!(*actual, fold_once(coefficients, activation_challenge));
                    }
                    for (actual, (_, coefficients)) in
                        quadratic.iter().zip(statement.auxiliary_quadratic())
                    {
                        assert_eq!(*actual, fold_once(coefficients, activation_challenge));
                    }
                })
                .unwrap();
            assert_eq!(allocation_tracker.active_leaf_elements(), 16);
            assert_eq!(allocation_tracker.active_auxiliary_elements(), 48);
            assert_eq!(allocation_tracker.active_elements(), 64);
            assert_eq!(allocation_tracker.reserved_elements(), 512);
            assert_eq!(allocation_tracker.reserved_bytes(), 8_192);
            assert_eq!(
                allocation_tracker.with_snapshot(|state| state.backing.as_ptr() as usize),
                backing_pointer
            );
            leaf_folded
                .with_leaf_linear(|actual| {
                    for (actual, coefficients) in actual.iter().zip(statement.leaf_linear()) {
                        let mut expected = coefficients.clone();
                        for point in leaf_folded.point() {
                            crate::mle::fold_low(&mut expected, *point);
                        }
                        assert_eq!(*actual, expected);
                    }
                })
                .unwrap();
            assert!(compile_c6_residual_fused_folded_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                &allocation_tracker,
                proof_repetition,
                C6ResidualFusedCoefficientFamily::Auxiliary,
                activation_challenge,
            )
            .is_err());
            assert_eq!(leaf_semantic_digest, auxiliary_folded.semantic_digest());
            assert_ne!(leaf_completion_digest, [0; 32]);
            assert_ne!(auxiliary_folded.completion_digest(), [0; 32]);
            assert_ne!(leaf_completion_digest, auxiliary_folded.completion_digest());

            let terminal_challenge = fp2(151 + u64::from(proof_repetition));
            leaf_folded.fold_next(terminal_challenge).unwrap();
            auxiliary_folded.fold_next(terminal_challenge).unwrap();
            assert!(leaf_folded.is_terminal());
            assert!(auxiliary_folded.is_terminal());
            assert_eq!(leaf_folded.entries_per_table(), 1);
            assert_eq!(auxiliary_folded.entries_per_table(), 1);
            assert_eq!(allocation_tracker.active_leaf_elements(), 8);
            assert_eq!(allocation_tracker.active_auxiliary_elements(), 24);
            assert_eq!(allocation_tracker.active_elements(), 32);
            assert_eq!(allocation_tracker.reserved_elements(), 512);
            leaf_folded
                .with_leaf_linear(|actual| {
                    for (actual, coefficients) in actual.iter().zip(statement.leaf_linear()) {
                        assert_eq!(
                            actual[0],
                            crate::mle::eval_mle(coefficients, leaf_folded.point())
                        );
                    }
                })
                .unwrap();
            auxiliary_folded
                .with_auxiliary_tables(|linear, quadratic| {
                    for (actual, coefficients) in linear.iter().zip(statement.auxiliary_linear()) {
                        assert_eq!(
                            actual[0],
                            crate::mle::eval_mle(coefficients, auxiliary_folded.point())
                        );
                    }
                    for (actual, (_, coefficients)) in
                        quadratic.iter().zip(statement.auxiliary_quadratic())
                    {
                        assert_eq!(
                            actual[0],
                            crate::mle::eval_mle(coefficients, auxiliary_folded.point())
                        );
                    }
                })
                .unwrap();
            assert!(leaf_folded.fold_next(fp2(173)).is_err());
            assert!(auxiliary_folded.fold_next(fp2(179)).is_err());

            drop(auxiliary_folded);
            assert_eq!(allocation_tracker.active_elements(), 8);
            assert_eq!(allocation_tracker.reserved_elements(), 512);
            assert_eq!(allocation_tracker.active_repetition(), Some(proof_repetition));
            drop(leaf_folded);
            assert_eq!(allocation_tracker.active_elements(), 0);
            assert_eq!(allocation_tracker.reserved_elements(), 0);
            assert_eq!(allocation_tracker.active_repetition(), None);
            assert!(!allocation_tracker.is_faulted());
        }
        assert_eq!(allocation_tracker.peak_elements(), 512);
        assert_eq!(allocation_tracker.peak_bytes(), 8_192);
        assert_eq!(allocation_tracker.peak_reserved_elements(), 512);
        assert_eq!(allocation_tracker.peak_reserved_bytes(), 8_192);

        // Re-sum the exact production arena lifecycle without allocating its
        // 512 MiB backing buffer in a unit test.
        let mut production_manifest = manifest.clone();
        production_manifest.leaf_entries = 1 << 23;
        production_manifest.auxiliary_entries = 1 << 15;
        production_manifest.digest = [0xA5; 32];
        let production_leaf = c6_residual_fused_coefficient_memory_census(
            &production_manifest,
            C6ResidualFusedCoefficientFamily::Leaf,
        )
        .unwrap();
        let production_auxiliary = c6_residual_fused_coefficient_memory_census(
            &production_manifest,
            C6ResidualFusedCoefficientFamily::Auxiliary,
        )
        .unwrap();
        assert_eq!(production_leaf.state_elements(), 33_554_432);
        assert_eq!(production_leaf.state_bytes(), 536_870_912);
        assert_eq!(production_auxiliary.state_elements(), 393_216);
        assert_eq!(production_auxiliary.state_bytes(), 6_291_456);
        let production_leaf_at_activation = u64::from(C6_RESIDUAL_RELATION_LEAF_TABLES as u32)
            * production_auxiliary.folded_entries_per_table();
        let production_combined =
            production_leaf_at_activation + production_auxiliary.state_elements();
        assert_eq!(production_leaf_at_activation, 131_072);
        assert_eq!(production_combined, 524_288);
        assert_eq!(production_combined * std::mem::size_of::<Fp2>() as u64, 8_388_608);
        assert!(production_combined <= production_leaf.state_elements());

        let mut undersized_backing_manifest = manifest.clone();
        undersized_backing_manifest.leaf_entries = 8;
        undersized_backing_manifest.auxiliary_entries = 4;
        undersized_backing_manifest.digest = [0xA6; 32];
        let undersized_tracker = C6ResidualFusedCoefficientArena::new(&undersized_backing_manifest);
        let undersized_leaf = c6_residual_fused_coefficient_memory_census(
            &undersized_backing_manifest,
            C6ResidualFusedCoefficientFamily::Leaf,
        )
        .unwrap();
        let undersized_auxiliary = c6_residual_fused_coefficient_memory_census(
            &undersized_backing_manifest,
            C6ResidualFusedCoefficientFamily::Auxiliary,
        )
        .unwrap();
        let mut undersized_leaf_lease =
            undersized_tracker.reserve(&undersized_backing_manifest, 0, undersized_leaf).unwrap();
        undersized_leaf_lease.fold_next(fp2(181)).unwrap();
        assert_eq!(undersized_tracker.active_leaf_elements(), 16);
        assert_eq!(undersized_tracker.reserved_elements(), 32);
        assert!(undersized_tracker
            .reserve(&undersized_backing_manifest, 0, undersized_auxiliary)
            .is_err());
        assert_eq!(undersized_tracker.reserved_elements(), 32);
        drop(undersized_leaf_lease);
        assert_eq!(undersized_tracker.reserved_elements(), 0);
        assert!(!undersized_tracker.is_faulted());

        let leaf_point = [Fp2::ZERO, Fp2::ONE, fp2(2), fp2(3), Fp2::ZERO, fp2(5), Fp2::ONE];
        let auxiliary_point = [Fp2::ONE, Fp2::ZERO];
        let mut cursor = C6ResidualEqPointCursor::new(&leaf_point, 128, "test").unwrap();
        for row in (0..128u32).chain([63, 64, 127, 0]) {
            let expected = leaf_point.iter().enumerate().fold(Fp2::ONE, |product, (bit, point)| {
                product * if row & (1 << bit) == 0 { Fp2::ONE - *point } else { *point }
            });
            assert_eq!(cursor.at(row).unwrap(), expected);
        }
        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            let statement = &compiled.statements()[usize::from(proof_repetition)];
            let terminal = compile_c6_residual_fused_terminal_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                &leaf_point,
                &auxiliary_point,
            )
            .unwrap();
            assert_eq!(terminal.proof_repetition(), proof_repetition);
            assert_eq!(terminal.target(), statement.target());
            assert_eq!(terminal.leaf_point(), &leaf_point);
            assert_eq!(terminal.auxiliary_point(), &auxiliary_point);
            assert_eq!(terminal.coefficient_writes(), 1_185);
            assert_ne!(terminal.semantic_digest(), [0; 32]);
            assert_ne!(terminal.digest(), [0; 32]);
            for (actual, coefficients) in terminal.leaf_linear().iter().zip(statement.leaf_linear())
            {
                assert_eq!(*actual, crate::mle::eval_mle(coefficients, &leaf_point));
            }
            for (actual, coefficients) in
                terminal.auxiliary_linear().iter().zip(statement.auxiliary_linear())
            {
                assert_eq!(*actual, crate::mle::eval_mle(coefficients, &auxiliary_point));
            }
            for (actual, (_, coefficients)) in
                terminal.auxiliary_quadratic().iter().zip(statement.auxiliary_quadratic())
            {
                assert_eq!(*actual, crate::mle::eval_mle(coefficients, &auxiliary_point));
            }
            let changed_leaf_point = [fp2(7), fp2(11), fp2(13), fp2(17), fp2(19), fp2(23), fp2(29)];
            let changed = compile_c6_residual_fused_terminal_coefficients(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                &changed_leaf_point,
                &auxiliary_point,
            )
            .unwrap();
            assert_ne!(terminal.digest(), changed.digest());
        }
        assert!(compile_c6_residual_fused_terminal_coefficients(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            0,
            &leaf_point[..6],
            &auxiliary_point,
        )
        .is_err());
        assert!(compile_c6_residual_fused_terminal_coefficients(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            0,
            &leaf_point,
            &auxiliary_point[..1],
        )
        .is_err());
        assert!(compile_c6_residual_fused_folded_coefficients(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &allocation_tracker,
            C6_RESIDUAL_PROOF_REPETITIONS,
            C6ResidualFusedCoefficientFamily::Leaf,
            fp2(89),
        )
        .is_err());
        let mut oversized_manifest = manifest.clone();
        oversized_manifest.leaf_entries = C6_RESIDUAL_SLOT_ENTRIES * 2;
        assert!(c6_residual_fused_coefficient_memory_census(
            &oversized_manifest,
            C6ResidualFusedCoefficientFamily::Leaf,
        )
        .is_err());
        let mut wrong_tracker_manifest = manifest.clone();
        wrong_tracker_manifest.digest[0] ^= 1;
        let wrong_tracker =
            C6ResidualFusedCoefficientAllocationTracker::new(&wrong_tracker_manifest);
        assert!(compile_c6_residual_fused_folded_coefficients(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &wrong_tracker,
            0,
            C6ResidualFusedCoefficientFamily::Leaf,
            fp2(97),
        )
        .is_err());
        assert_eq!(wrong_tracker.active_elements(), 0);

        let mut swapped_audit = C6ResidualAtomicEventAuditSink::new(0);
        assert!(swapped_audit
            .output(C6ResidualAtomicOutputEvent {
                proof_repetition: 1,
                output_ordinal: 0,
                family: C6ResidualAtomicFamily::SourceGrammar,
                weight: Fp2::ONE,
                weighted_public_constant: Fp2::ZERO,
            })
            .is_err());
        assert!(swapped_audit
            .coefficient(C6ResidualAtomicCoefficientEvent {
                proof_repetition: 1,
                output_ordinal: 0,
                family: C6ResidualAtomicFamily::SourceGrammar,
                target: C6ResidualAtomicCoefficientTarget::LeafLinear { table: 0, row: 0 },
                coefficient: Fp2::ONE,
            })
            .is_err());

        for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
            let mut provider_audit = C6ResidualAtomicEventAuditSink::new(proof_repetition);
            let provider_summary = replay_c6_residual_atomic_events(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                &mut provider_audit,
            )
            .unwrap();
            let mut client_audit = C6ResidualAtomicEventAuditSink::new(proof_repetition);
            let client_summary = replay_c6_residual_atomic_events(
                &installed,
                &extraction,
                &runtime,
                &linear,
                &relation,
                proof_repetition,
                &mut client_audit,
            )
            .unwrap();
            assert_eq!(provider_summary, client_summary);
            assert_eq!(provider_audit.digest(), client_audit.digest());
            assert_ne!(provider_audit.digest(), [0; 32]);
            assert_eq!(provider_summary.atomic_outputs(), 1_056);
            assert_eq!(provider_summary.coefficient_writes(), 1_185);
            assert_eq!(
                provider_summary.family_coefficient_writes(),
                &[21, 24, 48, 64, 28, 4, 964, 32]
            );
            assert_eq!(
                provider_summary.target(),
                compiled.statements()[usize::from(proof_repetition)].target()
            );
        }

        let mut changed_claims = product_claims.clone();
        changed_claims[0].messages[0][0] += Fp2::ONE;
        let changed_relation = base
            .clone()
            .commit_public_claims(linear.linear_form_digest(), changed_claims, residual)
            .unwrap()
            .release_relation_seed(&installed, relation_seed)
            .unwrap();
        let changed = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &changed_relation,
            &reference,
        )
        .unwrap();
        assert!(!changed.is_satisfied());
        for repetition in 0..2usize {
            assert_ne!(
                changed.statements()[repetition].digest(),
                compiled.statements()[repetition].digest()
            );
            assert_ne!(
                changed.family_weighted_residuals()[repetition]
                    [C6ResidualAtomicFamily::Product.index()],
                Fp2::ZERO
            );
        }

        let mut post_seed_mutation = relation.clone();
        post_seed_mutation.claims_bound.claims.residual.coordinates[0].correction_rlc += Fp2::ONE;
        assert!(compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &post_seed_mutation,
            &reference,
        )
        .is_err());

        let mut source_mutation = reference.clone();
        source_mutation.leaf_tables[0][0] += Fp2::ONE;
        source_mutation.digest = relation_reference_witness_digest(&source_mutation);
        let source_reject = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &source_mutation,
        )
        .unwrap();
        assert!(!source_reject.is_satisfied());
        assert!(source_reject.family_weighted_residuals().iter().all(|families| {
            families[C6ResidualAtomicFamily::SourceGrammar.index()] != Fp2::ZERO
        }));

        let mut raw_mutation = reference.clone();
        raw_mutation.leaf_tables[7].swap(0, 1);
        raw_mutation.digest = relation_reference_witness_digest(&raw_mutation);
        let raw_reject = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &raw_mutation,
        )
        .unwrap();
        assert!(!raw_reject.is_satisfied());
        assert!(raw_reject
            .family_weighted_residuals()
            .iter()
            .all(|families| { families[C6ResidualAtomicFamily::RawCopy.index()] != Fp2::ZERO }));

        let mut leaf_tail_mutation = reference.clone();
        leaf_tail_mutation.leaf_tables[0][manifest.topology.source_count as usize] = Fp2::ONE;
        leaf_tail_mutation.digest = relation_reference_witness_digest(&leaf_tail_mutation);
        let leaf_tail_reject = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &leaf_tail_mutation,
        )
        .unwrap();
        assert!(!leaf_tail_reject.is_satisfied());
        assert!(leaf_tail_reject
            .family_weighted_residuals()
            .iter()
            .all(|families| { families[C6ResidualAtomicFamily::LeafTail.index()] != Fp2::ZERO }));

        let mut auxiliary_tail_mutation = reference.clone();
        auxiliary_tail_mutation.auxiliary_tables[0]
            [manifest.topology.product_triple_count as usize] = Fp2::ONE;
        auxiliary_tail_mutation.digest =
            relation_reference_witness_digest(&auxiliary_tail_mutation);
        let auxiliary_tail_reject = compile_c6_residual_atomic_relation_reference(
            &installed,
            &extraction,
            &runtime,
            &linear,
            &relation,
            &auxiliary_tail_mutation,
        )
        .unwrap();
        assert!(!auxiliary_tail_reject.is_satisfied());
        assert!(auxiliary_tail_reject.family_weighted_residuals().iter().all(|families| {
            families[C6ResidualAtomicFamily::AuxiliaryTail.index()] != Fp2::ZERO
        }));
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn paired_source_fold_is_interleaved_bound_and_fail_closed() {
        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();
        let (installed, extraction, runtime, schedule, paired) = installed_paired_fixture();
        let zero_weights = [fp2(59), fp2(61), fp2(67)];
        let compiled =
            C6CompiledLinearResidual::compile(&installed, &extraction, &runtime, &zero_weights)
                .unwrap();
        assert_eq!(compiled.source_count(), 5);
        assert_eq!(compiled.product_mask_sources(), &[4]);
        let leaf_witness = compiled.build_paired_residual_leaf_witness(&paired, &schedule).unwrap();
        assert_eq!(leaf_witness.source_count(), 5);
        assert_eq!(leaf_witness.product_mask_count(), 1);
        assert_eq!(leaf_witness.live_elements(), 35);
        assert_eq!(leaf_witness.source_schedule_digest(), [0x6A; 32]);
        assert_eq!(leaf_witness.paired_source_digest(), paired.pair_digest());
        assert_ne!(leaf_witness.witness_digest(), [0; 32]);
        assert!(leaf_witness.materialize_padded_columns(2).is_err());
        let padded = leaf_witness.materialize_padded_columns(3).unwrap();
        assert!(padded.iter().all(|column| column.len() == 8));
        assert!(padded.iter().all(|column| column[5..] == [Fp2::ZERO; 3]));

        let deltas = [fp2(71), fp2(73)];
        let mut cursor = C6PairedSourceCursor::new(&paired, &schedule);
        let mut base_keys = [Vec::with_capacity(5), Vec::with_capacity(5)];
        for source in 0..5 {
            let witnesses = cursor.next(source).unwrap();
            let is_product_mask = source == 4;
            let expected_common = if is_product_mask {
                Fp2::ZERO
            } else {
                witnesses[0].base_plaintext() + witnesses[0].correction()
            };
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::CommonPlaintext)[source as usize],
                expected_common
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate0Mask)[source as usize],
                witnesses[0].base_plaintext()
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate0Tag)[source as usize],
                witnesses[0].tag()
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate0Correction)[source as usize],
                witnesses[0].correction()
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate1Mask)[source as usize],
                witnesses[1].base_plaintext()
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate1Tag)[source as usize],
                witnesses[1].tag()
            );
            assert_eq!(
                leaf_witness.column(C6ResidualLeafColumn::Coordinate1Correction)[source as usize],
                witnesses[1].correction()
            );
            if !is_product_mask {
                assert_eq!(
                    expected_common,
                    witnesses[1].base_plaintext() + witnesses[1].correction()
                );
            }
            for coordinate in 0..2 {
                base_keys[coordinate].push(base_key(witnesses[coordinate], deltas[coordinate]));
            }
        }
        cursor.finish(5).unwrap();

        let alpha_seed = [0xA8; 32];
        let mut observed_alphas = [Vec::new(), Vec::new()];
        let observed_digest = compiled
            .fold_paired_coefficients(alpha_seed, |_, _, alphas, _| {
                for coordinate in 0..2 {
                    observed_alphas[coordinate].push(alphas[coordinate]);
                }
                Ok(())
            })
            .unwrap();
        assert!(observed_alphas[0]
            .iter()
            .zip(&observed_alphas[1])
            .any(|(left, right)| left != right));
        assert_ne!(
            observed_digest,
            compiled.fold_paired_coefficients([0xA9; 32], |_, _, _, _| Ok(())).unwrap()
        );

        let response = compiled.respond_paired_sources(&paired, &schedule, alpha_seed).unwrap();
        let client = compiled
            .fold_paired_base_keys([base_keys[0].as_slice(), base_keys[1].as_slice()], alpha_seed)
            .unwrap();
        assert!(response.verify(client, deltas).unwrap());
        assert_eq!(response.binding.source_count, 5);
        assert!(std::mem::size_of_val(&response) <= 288);

        let post_root =
            C6ResidualPostRootChallenges::derive(&installed, [0xBB; 32], alpha_seed).unwrap();
        let post_root_response =
            compiled.respond_paired_sources_post_root(&paired, &schedule, &post_root).unwrap();
        let post_root_client = compiled
            .fold_paired_base_keys_post_root(
                [base_keys[0].as_slice(), base_keys[1].as_slice()],
                &post_root,
            )
            .unwrap();
        assert!(post_root_response.verify(post_root_client, deltas).unwrap());
        assert_ne!(
            post_root_response.binding.coefficient_digest,
            response.binding.coefficient_digest
        );

        let changed_root =
            C6ResidualPostRootChallenges::derive(&installed, [0xBC; 32], alpha_seed).unwrap();
        let changed_root_client = compiled
            .fold_paired_base_keys_post_root(
                [base_keys[0].as_slice(), base_keys[1].as_slice()],
                &changed_root,
            )
            .unwrap();
        assert!(post_root_response.verify(changed_root_client, deltas).is_err());
        let mut malformed_post_root = post_root.clone();
        malformed_post_root.context_seed[0] ^= 1;
        assert!(compiled
            .respond_paired_sources_post_root(&paired, &schedule, &malformed_post_root)
            .is_err());

        let divergent_client = compiled
            .fold_paired_base_keys([base_keys[0].as_slice(), base_keys[1].as_slice()], [0xA9; 32])
            .unwrap();
        assert!(response.verify(divergent_client, deltas).is_err());

        let wrong_schedule_pair = C6PairedSourceWitness::new(
            paired.tape_ids(),
            paired.coordinates().clone(),
            &schedule,
            [0xFF; 32],
        )
        .unwrap();
        assert!(compiled
            .respond_paired_sources(&wrong_schedule_pair, &schedule, alpha_seed)
            .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn installed_paired_closure_is_liveness_bounded_and_fused_view_ready() {
        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();
        let (installed, extraction, runtime, schedule, paired) = installed_paired_fixture();
        let zero_weights = [fp2(59), fp2(61), fp2(67)];
        let compiled =
            C6CompiledLinearResidual::compile(&installed, &extraction, &runtime, &zero_weights)
                .unwrap();
        let leaf = compiled.build_paired_residual_leaf_witness(&paired, &schedule).unwrap();
        let evaluation = compiled
            .evaluate_installed_paired_closure(
                &installed,
                &extraction,
                &runtime,
                &paired,
                &schedule,
            )
            .unwrap();
        let closure = evaluation.closure();
        assert_eq!(closure.program_digest(), installed.artifact_digest());
        assert_eq!(closure.census().product_closures, 1);
        assert_eq!(closure.census().product_triples, 2);
        assert_eq!(closure.census().zero_roots, 3);
        assert_eq!(closure.census().product_operand_values, 24);
        assert_eq!(closure.census().zero_root_values, 12);
        assert_eq!(closure.census().live_values, 100);
        assert_ne!(closure.witness_digest(), [0; 32]);

        let mut cursor = C6PairedSourceCursor::new(&paired, &schedule);
        let sources: Vec<_> = (0..5).map(|source| cursor.next(source).unwrap()).collect();
        cursor.finish(5).unwrap();
        let a = sources[1].map(C6SourceWitness::prover_value);
        let b = sources[2].map(C6SourceWitness::prover_value);
        let c = sources[3].map(C6SourceWitness::prover_value);
        let triples = [[a, b, c], [b, a, c]];
        let mut expected = Vec::new();
        for triple in triples {
            for coordinate in 0..2 {
                for node in triple {
                    expected.extend([node[coordinate].x, node[coordinate].m]);
                }
            }
        }
        let sub = sources[0].map(C6SourceWitness::prover_value);
        for coordinate in 0..2 {
            let zero = a[coordinate].add(b[coordinate]).sub(ProverAuthed::from_public(fp2(7)));
            expected.extend([zero.x, zero.m]);
        }
        for coordinate in 0..2 {
            let zero = a[coordinate].scale(fp2(2)).sub(ProverAuthed::from_public(fp2(6)));
            expected.extend([zero.x, zero.m]);
        }
        for coordinate in 0..2 {
            let zero = sub[coordinate].sub(ProverAuthed::from_public(fp2(9)));
            expected.extend([zero.x, zero.m]);
        }
        assert_eq!(&closure.values()[..expected.len()], expected);
        assert!(closure.values()[expected.len()..].iter().all(|value| *value == Fp2::ZERO));
        for zero in closure.values()[24..36].chunks_exact(4) {
            assert_eq!(zero[0], Fp2::ZERO);
            assert_eq!(zero[2], Fp2::ZERO);
        }

        let memory = evaluation.memory_census();
        assert_eq!(memory.canonical_nodes, installed.topology().canonical_node_count as u64);
        assert!(memory.peak_live_node_values > 0);
        assert!(memory.peak_live_node_values < memory.canonical_nodes);
        assert!(memory.node_value_capacity >= memory.peak_live_node_values);
        assert_eq!(
            memory.dense_paired_node_baseline_bytes,
            memory.canonical_nodes * std::mem::size_of::<C6PairedInstalledNodeValue>() as u64
        );
        assert!(memory.peak_working_heap_bytes > memory.closure_value_heap_bytes);

        let auxiliary = closure.transpose_auxiliary_lanes().unwrap();
        let manifest = C6ResidualRelationManifest::new_with_geometry(
            &installed,
            &extraction,
            &runtime,
            7,
            2,
            false,
        )
        .unwrap();
        let view = C6ResidualFusedWitnessView::new(&manifest, &leaf, closure, &auxiliary).unwrap();
        assert_eq!(view.manifest_digest(), manifest.digest());
        assert_ne!(view.digest(), [0; 32]);
        let mut wrong_installed_binding = closure.clone();
        wrong_installed_binding.installed_binding.as_mut().unwrap().paired_source_digest[0] ^= 1;
        assert!(C6ResidualFusedWitnessView::new(
            &manifest,
            &leaf,
            &wrong_installed_binding,
            &auxiliary,
        )
        .is_err());

        let wrong_source_schedule = C6PairedSourceWitness::new(
            paired.tape_ids(),
            paired.coordinates().clone(),
            &schedule,
            [0xFF; 32],
        )
        .unwrap();
        assert!(compiled
            .evaluate_installed_paired_closure(
                &installed,
                &extraction,
                &runtime,
                &wrong_source_schedule,
                &schedule,
            )
            .is_err());
        let mut noncanonical_schedule = schedule.clone();
        noncanonical_schedule.digest[0] ^= 1;
        assert!(compiled
            .evaluate_installed_paired_closure(
                &installed,
                &extraction,
                &runtime,
                &paired,
                &noncanonical_schedule,
            )
            .is_err());
    }

    #[test]
    fn nonlinear_key_node_and_product_mask_reuse_fail_closed() {
        let mut builder = C6ResidualBuilder::new();
        let a = builder
            .add_source(leaf(0, 1, C6LeafKind::FullField), C6LeafRole::Direct, source_full(1, 2, 3))
            .unwrap();
        let b = builder
            .add_source(leaf(1, 2, C6LeafKind::FullField), C6LeafRole::Direct, source_full(2, 3, 4))
            .unwrap();
        assert!(builder
            .add_operation(C6ValueOperation::ForbiddenKeyMultiply { lhs: a, rhs: b })
            .is_err());

        let c = builder.add_public(fp2(6)).unwrap();
        let mask = builder
            .add_source(
                leaf(2, 3, C6LeafKind::FullField),
                C6LeafRole::ProductMask,
                C6SourceWitness::FullField { r: fp2(5), correction: Fp2::ZERO, tag: fp2(7) },
            )
            .unwrap();
        builder.add_product_closure(vec![[a, b, c]], mask).unwrap();
        assert!(builder.add_product_closure(vec![[a, b, c]], mask).is_err());
    }

    #[test]
    fn product_mask_must_be_full_uncorrected_and_is_not_a_linear_value() {
        let mut builder = C6ResidualBuilder::new();
        assert!(builder
            .add_source(
                leaf(0, 9, C6LeafKind::FullField),
                C6LeafRole::ProductMask,
                source_full(1, 2, 3),
            )
            .is_err());

        let a = builder
            .add_source(
                leaf(0, 10, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(1, 2, 3),
            )
            .unwrap();
        let mask = builder
            .add_source(
                leaf(1, 11, C6LeafKind::FullField),
                C6LeafRole::ProductMask,
                C6SourceWitness::FullField { r: fp2(4), correction: Fp2::ZERO, tag: fp2(5) },
            )
            .unwrap();
        let mixed = builder.add(a, mask).unwrap();
        builder.add_zero_closure(mixed).unwrap();
        assert!(builder.census().is_err());
    }

    #[test]
    fn duplicate_reordered_deleted_and_changed_leaf_censuses_reject() {
        let honest = fixture(Fp2::ZERO, false);
        let expected = honest.builder.census().unwrap();

        let changed = fixture(Fp2::ZERO, true);
        assert!(changed.builder.commit([8; 32], expected).is_err());

        let mut reordered = C6ResidualBuilder::new();
        assert!(reordered
            .add_source(
                leaf(1, 0x200, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(2, 4, 23),
            )
            .is_err());

        let mut duplicate = C6ResidualBuilder::new();
        duplicate
            .add_source(
                leaf(0, 77, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(1, 2, 3),
            )
            .unwrap();
        assert!(duplicate
            .add_source(
                leaf(1, 77, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(1, 2, 3),
            )
            .is_err());

        let mut deleted = C6ResidualBuilder::new();
        let a = deleted
            .add_source(
                leaf(0, 0x100, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(1, 3, 19),
            )
            .unwrap();
        let b = deleted
            .add_source(
                leaf(1, 0x200, C6LeafKind::FullField),
                C6LeafRole::Direct,
                source_full(2, 4, 23),
            )
            .unwrap();
        let c = deleted.add_public(fp2(12)).unwrap();
        let mask = deleted
            .add_source(
                leaf(2, 0x400, C6LeafKind::FullField),
                C6LeafRole::ProductMask,
                C6SourceWitness::FullField { r: fp2(7), correction: Fp2::ZERO, tag: fp2(31) },
            )
            .unwrap();
        let seven = deleted.add_public(fp2(7)).unwrap();
        let sum = deleted.add(a, b).unwrap();
        let zero = deleted.sub(sum, seven).unwrap();
        deleted.add_zero_closure(zero).unwrap();
        deleted.add_product_closure(vec![[a, b, c]], mask).unwrap();
        assert!(deleted.commit([9; 32], expected).is_err());
    }

    #[test]
    fn changed_hidden_tag_is_caught_by_base_share_binding() {
        let honest = fixture(Fp2::ZERO, false);
        let expected = honest.builder.census().unwrap();
        let honest_witnesses = honest.witnesses.clone();

        let changed = fixture(fp2(1), false);
        assert_eq!(changed.builder.census().unwrap(), expected);
        let program = changed.builder.commit([10; 32], expected).unwrap();
        let post = post_for(&program, changed.chi);
        let delta = fp2(67);
        let actual_base_keys: Vec<_> =
            honest_witnesses.iter().map(|witness| base_key(*witness, delta)).collect();
        assert!(!program.old_verifier_accepts(&post, &actual_base_keys, delta).unwrap());
        let plan = program.respond(post).unwrap();
        assert!(!plan.verify(&actual_base_keys, delta).unwrap());
    }

    #[test]
    fn post_commit_counts_and_product_messages_are_exact() {
        let fixture = fixture(Fp2::ZERO, false);
        let census = fixture.builder.census().unwrap();
        let program = fixture.builder.commit([11; 32], census).unwrap();
        let mut post = post_for(&program, fixture.chi);

        post.base_share_alphas.pop();
        assert!(program.respond(post.clone()).is_err());
        post.base_share_alphas.push(fp2(71));
        post.products[0].m0 += Fp2::ONE;
        assert!(program.respond(post).is_err());
        assert!(program.product_openings(&[]).is_err());
    }

    #[test]
    fn nonzero_zero_closure_and_dead_node_reject() {
        let mut builder = C6ResidualBuilder::new();
        let source = builder
            .add_source(
                leaf(0, 90, C6LeafKind::Subfield),
                C6LeafRole::Direct,
                C6SourceWitness::Subfield { r: fp(1), correction: fp(1), tag: fp2(3) },
            )
            .unwrap();
        builder.add_zero_closure(source).unwrap();
        let census = builder.census().unwrap();
        let program = builder.commit([12; 32], census).unwrap();
        let post = C6ResidualPostCommit {
            base_share_alphas: vec![fp2(5)],
            zero_weights: vec![fp2(7)],
            products: Vec::new(),
        };
        assert!(program.respond(post).is_err());

        let mut dead = C6ResidualBuilder::new();
        let live = dead.add_public(Fp2::ZERO).unwrap();
        let _unused = dead.add_public(Fp2::ONE).unwrap();
        dead.add_zero_closure(live).unwrap();
        assert!(dead.census().is_err());
    }
}

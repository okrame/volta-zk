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
    C6_RESIDUAL_SLOT_LOG2,
};
use crate::c6_source::C6PairedSourceWitness;
use crate::prod_check::{prod_batch_verify, ProdProof};
use std::collections::BTreeSet;
use std::fmt;
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{
    C6DecodedInstanceExtractionPlan, C6InstalledOperationKind, C6InstalledOperationPlan,
    C6OperationPlanInstanceIdentity, C6OperationPlanTopologyIdentity, C6RuntimeInstanceValues,
    CorrScheduleAudit, CorrScheduleKind, CorrScheduleRole, ProverAuthed, Transcript, VerifierKey,
};

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
const PAIRED_AUXILIARY_WRAPPER_DOMAIN: &str = "volta-zk/c6/paired-residual-auxiliary-wrapper/v1";
const TERMINAL_WEIGHT_SCHEDULE_DOMAIN: &str = "volta-zk/c6/residual-terminal-weight-schedule/v1";
const TERMINAL_LINEAR_FORM_DOMAIN: &str = "volta-zk/c6/residual-terminal-linear-form/v1";

pub const C6_RESIDUAL_AUXILIARY_LANES: u32 = 16;
pub const C6_RESIDUAL_AUXILIARY_PRODUCT_LANES: u32 = 12;
pub const C6_RESIDUAL_AUXILIARY_ZERO_LANES: u32 = 4;
pub const C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2: u32 = 15;
pub const C6_RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES: u64 = 1 << C6_RESIDUAL_AUXILIARY_SEMANTIC_LOG2;

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

/// Canonical live prefix of residual slot 7.  The footer is currently the
/// frozen zero reserve; later envelope fields may consume it only through a
/// separately versioned layout change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedResidualClosureWitness {
    program_digest: C6ResidualDigest,
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
    repetition: u8,
    kind: C6ResidualTerminalFormKind,
    product_weights: Vec<[Fp2; 3]>,
    zero_weights: Vec<Fp2>,
    digest: C6ResidualDigest,
}

impl C6ResidualTerminalWeightSchedule {
    pub fn new(
        operation_plan: &C6InstalledOperationPlan,
        repetition: u8,
        kind: C6ResidualTerminalFormKind,
        product_weights: Vec<[Fp2; 3]>,
        zero_weights: Vec<Fp2>,
    ) -> C6ResidualResult<Self> {
        if repetition >= 2 {
            return Err(C6ResidualError::new("C6 residual terminal repetition is out of range"));
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
            repetition,
            kind,
            product_weights,
            zero_weights,
            digest: [0; 32],
        };
        schedule.digest = terminal_weight_schedule_digest(&schedule);
        schedule.validate(operation_plan)?;
        Ok(schedule)
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
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
        if self.repetition >= 2
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

/// Materialized reference output of one installed terminal reverse form.
///
/// The leaf coefficients remain local and may be consumed by the later
/// sumcheck-statement compiler.  Production credit requires a fused path
/// that does not retain another full source-length vector.
pub struct C6CompiledTerminalLinearForm {
    operation_plan_artifact_digest: C6ResidualDigest,
    topology: C6OperationPlanTopologyIdentity,
    instance: C6OperationPlanInstanceIdentity,
    repetition: u8,
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
            .field("repetition", &self.repetition)
            .field("kind", &self.kind)
            .field("schedule_digest", &self.schedule_digest)
            .field("leaf_coefficients", &self.leaf_coefficients.len())
            .field("public_plaintext", &self.public_plaintext)
            .field("linear_form_digest", &self.linear_form_digest)
            .finish_non_exhaustive()
    }
}

impl C6CompiledTerminalLinearForm {
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
        let mut hasher = blake3::Hasher::new_derive_key(TERMINAL_LINEAR_FORM_DOMAIN);
        hasher.update(&operation_plan.artifact_digest());
        hasher.update(&reverse.topology.topology_digest);
        hasher.update(&reverse.instance.instance_digest);
        hasher.update(&[schedule.repetition, schedule.kind as u8]);
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
            repetition: schedule.repetition,
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

    pub fn instance(&self) -> C6OperationPlanInstanceIdentity {
        self.instance
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
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
    let mut hasher = blake3::Hasher::new_derive_key(TERMINAL_WEIGHT_SCHEDULE_DOMAIN);
    hasher.update(&schedule.operation_plan_artifact_digest);
    hasher.update(&schedule.topology_digest);
    hasher.update(&[schedule.repetition, schedule.kind as u8]);
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

    /// Production-shape provider fold over both source coordinates in the
    /// canonical interleaved allocation order. The paired witness remains a
    /// prover-only sidecar and is streamed once.
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
        begin_c6_prover_trace, begin_c6_runtime_instance_capture,
        compile_c6_operation_trace_for_role, finish_c6_prover_trace, record_c6_product_closure,
        record_c6_zero_roots, C6InstanceExtractionRole, C6TraceSourceManifest, CorrelationStream,
    };

    #[cfg(feature = "c6-trace")]
    static INSTALLED_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_base(fp(value))
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
        witnesses: &[C6SourceWitness],
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
        let installed = compiled.artifact.install(&manifest).unwrap();

        let capture = begin_c6_runtime_instance_capture(&extraction).unwrap();
        let a = witnesses[0].prover_value();
        let b = witnesses[1].prover_value();
        let seven = ProverAuthed::from_public(fp2(7));
        let _zero = a.add(b).sub(seven);
        let six = ProverAuthed::from_public(fp2(6));
        let _scaled_zero = a.scale(fp2(2)).sub(six);
        let runtime = capture.finish_installed(&installed, &extraction).unwrap();
        (installed, extraction, runtime)
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
        let installed = compiled.artifact.install(&manifest).unwrap();

        let capture = begin_c6_runtime_instance_capture(&extraction).unwrap();
        let sub = ProverAuthed::new(fp2(9), fp2(101));
        let a = ProverAuthed::new(fp2(3), fp2(103));
        let b = ProverAuthed::new(fp2(4), fp2(107));
        let seven = ProverAuthed::from_public(fp2(7));
        let _zero = a.add(b).sub(seven);
        let six = ProverAuthed::from_public(fp2(6));
        let _scaled_zero = a.scale(fp2(2)).sub(six);
        let nine = ProverAuthed::from_public(fp2(9));
        let _sub_zero = sub.sub(nine);
        let runtime = capture.finish_installed(&installed, &extraction).unwrap();

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
        let _fixture_guard = INSTALLED_FIXTURE_LOCK.lock().unwrap();
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
            C6ResidualTerminalFormKind::Plaintext,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        let tag_schedule = C6ResidualTerminalWeightSchedule::new(
            installed,
            1,
            C6ResidualTerminalFormKind::Tag,
            product_weights.clone(),
            terminal_zero_weights.clone(),
        )
        .unwrap();
        assert_ne!(plaintext_schedule.digest(), tag_schedule.digest());
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
        assert_eq!(plaintext.leaf_coefficients(), tag.leaf_coefficients());
        assert_eq!(tag.public_plaintext(), Fp2::ZERO);
        assert_ne!(plaintext.linear_form_digest(), tag.linear_form_digest());
        assert_eq!(plaintext.repetition(), 1);
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

        assert!(C6ResidualTerminalWeightSchedule::new(
            installed,
            0,
            C6ResidualTerminalFormKind::Plaintext,
            vec![[Fp2::ZERO; 3]; 1],
            zero_weights.to_vec(),
        )
        .is_err());
        assert!(C6ResidualTerminalWeightSchedule::new(
            installed,
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
    fn paired_source_fold_is_interleaved_bound_and_fail_closed() {
        let _fixture_guard = INSTALLED_FIXTURE_LOCK.lock().unwrap();
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

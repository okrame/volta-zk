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
use crate::c6_source::C6PairedSourceWitness;
use crate::prod_check::{prod_batch_verify, ProdProof};
use std::collections::BTreeSet;
use std::fmt;
use volta_field::{Fp, Fp2};
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
        let decoded = operation_plan.decoded();
        let topology = decoded.topology;
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
            || zero_weights.len() != topology.zero_root_count as usize
        {
            return Err(C6ResidualError::new(
                "C6 installed reverse arrays differ from their decoded census",
            ));
        }
        let product_triple_count =
            operation_plan.products().iter().try_fold(0u64, |total, product| {
                total
                    .checked_add(product.triples().len() as u64)
                    .ok_or_else(|| C6ResidualError::new("C6 ProductClosure census overflows"))
            })?;
        if product_triple_count != topology.product_triple_count {
            return Err(C6ResidualError::new(
                "C6 installed ProductClosure triples differ from topology",
            ));
        }

        let mut node_coefficients =
            try_zeroed_fp2_vec(canonical_node_count, "C6 reverse node workspace")?;
        for (&root, &weight) in operation_plan.zero_roots().iter().zip(zero_weights) {
            let coefficient = node_coefficients.get_mut(root as usize).ok_or_else(|| {
                C6ResidualError::new("C6 zero root is outside the installed plan")
            })?;
            *coefficient += weight;
        }
        let mut leaf_coefficients =
            try_zeroed_fp2_vec(source_count, "C6 reverse leaf coefficients")?;

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
                    source_cursor = source_cursor.checked_sub(1).ok_or_else(|| {
                        C6ResidualError::new("C6 installed source cursor underflows")
                    })?;
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
                    if coefficient != Fp2::ZERO {
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

        let mut linear_hasher = blake3::Hasher::new();
        linear_hasher.update(COMPILED_LINEAR_FORM_DOMAIN);
        linear_hasher.update(&operation_plan.artifact_digest());
        linear_hasher.update(&topology.topology_digest);
        linear_hasher.update(&instance.instance_digest);
        linear_hasher.update(&topology.source_count.to_le_bytes());
        linear_hasher.update(&(zero_weights.len() as u64).to_le_bytes());
        for weight in zero_weights {
            hash_fp2(&mut linear_hasher, *weight);
        }
        hash_fp2(&mut linear_hasher, public_plaintext);
        for (source, coefficient) in leaf_coefficients.iter().enumerate() {
            linear_hasher.update(&(source as u32).to_le_bytes());
            hash_fp2(&mut linear_hasher, *coefficient);
        }
        let linear_form_digest = *linear_hasher.finalize().as_bytes();

        Ok(Self {
            operation_plan_artifact_digest: operation_plan.artifact_digest(),
            topology,
            instance,
            leaf_coefficients,
            product_mask_sources,
            public_plaintext,
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

    /// Production-shape provider fold over both source coordinates in the
    /// canonical interleaved allocation order. The paired witness remains a
    /// prover-only sidecar and is streamed once.
    pub fn respond_paired_sources(
        &self,
        sources: &C6PairedSourceWitness,
        schedule: &CorrScheduleAudit,
        transcript: &mut Transcript,
    ) -> C6ResidualResult<C6CompiledPairedResidualPlan> {
        self.validate_paired_source_schedule(sources, schedule)?;
        let mut cursor = C6PairedSourceCursor::new(sources, schedule);
        let mut correction_rlcs = [self.public_plaintext; 2];
        let mut public_tag_rlcs = [Fp2::ZERO; 2];
        let coefficient_digest =
            self.fold_coefficients(transcript, |source, linear, alpha, coefficient| {
                let witnesses = cursor.next(source)?;
                for coordinate in 0..2 {
                    correction_rlcs[coordinate] += linear * witnesses[coordinate].correction();
                    correction_rlcs[coordinate] = correction_rlcs[coordinate]
                        - alpha * witnesses[coordinate].base_plaintext();
                    public_tag_rlcs[coordinate] += coefficient * witnesses[coordinate].tag();
                }
                Ok(())
            })?;
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
        transcript: &mut Transcript,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        if base_keys.iter().any(|keys| keys.len() != self.leaf_coefficients.len()) {
            return Err(C6ResidualError::new(
                "C6 paired verifier base-key vectors differ from installed source census",
            ));
        }
        self.fold_paired_base_keys_stream(transcript, |source| {
            Ok([base_keys[0][source as usize], base_keys[1][source as usize]])
        })
    }

    /// Streaming client seam for a local paired key tape. Exactly one
    /// callback is made per canonical source ordinal.
    pub fn fold_paired_base_keys_stream(
        &self,
        transcript: &mut Transcript,
        mut base_keys: impl FnMut(u32) -> C6ResidualResult<[Fp2; 2]>,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        let mut base_key_rlcs = [Fp2::ZERO; 2];
        let coefficient_digest =
            self.fold_coefficients(transcript, |source, _, _, coefficient| {
                let keys = base_keys(source)?;
                for coordinate in 0..2 {
                    base_key_rlcs[coordinate] += coefficient * keys[coordinate];
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
        transcript: &mut Transcript,
    ) -> C6ResidualResult<C6CompiledPairedBaseKeyRlc> {
        self.validate_paired_source_schedule(sources, schedule)?;
        let mut cursor = C6PairedSourceCursor::new(sources, schedule);
        let folded = self.fold_paired_base_keys_stream(transcript, |source| {
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

    #[cfg(feature = "c6-trace")]
    #[test]
    fn installed_reverse_accumulator_matches_reference_without_leaf_vectors_on_wire() {
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
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn paired_source_fold_is_interleaved_bound_and_fail_closed() {
        let (installed, extraction, runtime, schedule, paired) = installed_paired_fixture();
        let zero_weights = [fp2(59), fp2(61), fp2(67)];
        let compiled =
            C6CompiledLinearResidual::compile(&installed, &extraction, &runtime, &zero_weights)
                .unwrap();
        assert_eq!(compiled.source_count(), 5);
        assert_eq!(compiled.product_mask_sources(), &[4]);

        let deltas = [fp2(71), fp2(73)];
        let mut cursor = C6PairedSourceCursor::new(&paired, &schedule);
        let mut base_keys = [Vec::with_capacity(5), Vec::with_capacity(5)];
        for source in 0..5 {
            let witnesses = cursor.next(source).unwrap();
            for coordinate in 0..2 {
                base_keys[coordinate].push(base_key(witnesses[coordinate], deltas[coordinate]));
            }
        }
        cursor.finish(5).unwrap();

        let alpha_seed = [0xA8; 32];
        let mut provider_transcript = Transcript::new(alpha_seed);
        let response =
            compiled.respond_paired_sources(&paired, &schedule, &mut provider_transcript).unwrap();
        let mut client_transcript = Transcript::new(alpha_seed);
        let client = compiled
            .fold_paired_base_keys(
                [base_keys[0].as_slice(), base_keys[1].as_slice()],
                &mut client_transcript,
            )
            .unwrap();
        assert!(response.verify(client, deltas).unwrap());
        assert_eq!(response.binding.source_count, 5);
        assert!(std::mem::size_of_val(&response) <= 288);

        let mut divergent_transcript = Transcript::new([0xA9; 32]);
        let divergent_client = compiled
            .fold_paired_base_keys(
                [base_keys[0].as_slice(), base_keys[1].as_slice()],
                &mut divergent_transcript,
            )
            .unwrap();
        assert!(response.verify(divergent_client, deltas).is_err());

        let wrong_schedule_pair = C6PairedSourceWitness::new(
            paired.tape_ids(),
            paired.coordinates().clone(),
            &schedule,
            [0xFF; 32],
        )
        .unwrap();
        let mut wrong_schedule_transcript = Transcript::new(alpha_seed);
        assert!(
            compiled
                .respond_paired_sources(
                    &wrong_schedule_pair,
                    &schedule,
                    &mut wrong_schedule_transcript,
                )
                .is_err()
        );
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

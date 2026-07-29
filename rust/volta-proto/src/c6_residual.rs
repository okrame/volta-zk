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

use crate::c6::C6DeltaResidual;
use crate::prod_check::{prod_batch_verify, ProdProof};
use std::collections::BTreeSet;
use std::fmt;
use volta_field::{Fp, Fp2};
use volta_mac::{ProverAuthed, VerifierKey};

pub type C6ResidualDigest = [u8; 32];

const CENSUS_DOMAIN: &[u8] = b"volta-zk/c6/residual-census/v1";
const PROGRAM_DOMAIN: &[u8] = b"volta-zk/c6/residual-program/v1";
const PREQUERY_DOMAIN: &[u8] = b"volta-zk/c6/residual-prequery/v1";
const RESPONSE_DOMAIN: &[u8] = b"volta-zk/c6/residual-response/v1";

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
        ProverAuthed { x: self.base_plaintext() + self.correction(), m: self.tag() }
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
                ValueNode::Source(source) => VerifierKey {
                    k: base_keys[source] + delta * self.sources[source].witness.correction(),
                },
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
            if !prod_batch_verify(&triples, keys[shape.mask.index()].k, delta, response.chi, &proof)
            {
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

//! Diagnostic-only C6 authenticated-value provenance recorder.
//!
//! The ordinary build uses a zero-sized token and records nothing.  The
//! `c6-trace` feature turns the token into a compact handle and enables one
//! process-local, fail-closed prover trace.  This module deliberately does
//! not infer provenance from plaintexts, tags, keys, or addresses.

use std::fmt;
use volta_field::Fp2;

pub const C6_OPERATION_PLAN_VERSION: u32 = 1;

#[cfg(feature = "c6-trace")]
const C6_OPERATION_NODE_DOMAIN: &str = "volta/proto/c6/operation-plan/nodes/v1";
#[cfg(feature = "c6-trace")]
const C6_OPERATION_ROOT_DOMAIN: &str = "volta/proto/c6/operation-plan/roots/v1";
#[cfg(feature = "c6-trace")]
const C6_OPERATION_PLAN_DOMAIN: &str = "volta/proto/c6/operation-plan/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6TraceError(String);

impl C6TraceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6TraceError {}

/// Copyable ghost provenance attached only by a `c6-trace` build.
#[cfg(not(feature = "c6-trace"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct C6TraceToken;

/// Copyable ghost provenance attached only by a `c6-trace` build.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct C6TraceToken(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6TraceNode {
    Public(Fp2),
    Add { lhs: C6TraceToken, rhs: C6TraceToken },
    Sub { lhs: C6TraceToken, rhs: C6TraceToken },
    Scale { value: C6TraceToken, scalar: Fp2 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6TraceProductClosure {
    pub triples: Vec<[C6TraceToken; 3]>,
    pub mask: C6TraceToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ProverTraceSnapshot {
    pub source_count: u32,
    pub nodes: Vec<C6TraceNode>,
    pub zero_roots: Vec<C6TraceToken>,
    pub products: Vec<C6TraceProductClosure>,
}

/// Public source identity consumed by the operation-plan normalizer.
///
/// The schedule digest binds the complete source metadata.  The explicit
/// mask ordinals let the normalizer enforce the only exceptional leaf role
/// without copying the multi-million-entry manifest into the trace artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6TraceSourceManifest {
    pub source_count: u32,
    pub source_schedule_digest: [u8; 32],
    pub product_mask_sources: Vec<u32>,
}

impl C6TraceSourceManifest {
    pub fn new(
        source_count: u32,
        source_schedule_digest: [u8; 32],
        product_mask_sources: Vec<u32>,
    ) -> Result<Self, C6TraceError> {
        if source_schedule_digest == [0; 32] {
            return Err(C6TraceError::new("C6 trace source-schedule digest is zero"));
        }
        let mut previous = None;
        for &source in &product_mask_sources {
            if source >= source_count {
                return Err(C6TraceError::new(
                    "C6 trace ProductMask source is outside the source manifest",
                ));
            }
            if previous.is_some_and(|value| source <= value) {
                return Err(C6TraceError::new(
                    "C6 trace ProductMask sources are not strictly ordered",
                ));
            }
            previous = Some(source);
        }
        Ok(Self { source_count, source_schedule_digest, product_mask_sources })
    }

    #[cfg(feature = "c6-trace")]
    fn is_product_mask(&self, source: u32) -> bool {
        self.product_mask_sources.binary_search(&source).is_ok()
    }
}

/// Fields that define equality of independently normalized prover and
/// verifier programs.  Allocation-order diagnostics deliberately live
/// outside this structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6OperationPlanIdentity {
    pub version: u32,
    pub source_count: u32,
    pub source_schedule_digest: [u8; 32],
    pub canonical_node_count: u32,
    pub product_closure_count: u32,
    pub product_triple_count: u64,
    pub zero_root_count: u32,
    pub program_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6OperationPlanDiagnostics {
    pub raw_operation_count: u64,
    pub reachable_operation_count: u64,
    pub omitted_operation_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CanonicalOperationPlan {
    pub identity: C6OperationPlanIdentity,
    pub diagnostics: C6OperationPlanDiagnostics,
}

#[cfg(feature = "c6-trace")]
const PUBLIC_ZERO_TOKEN: u32 = 1;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_BIT: u32 = 1 << 31;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_MASK: u32 = SOURCE_TOKEN_BIT - 1;

#[cfg(feature = "c6-trace")]
#[derive(Default)]
struct C6TraceRuntime {
    active: bool,
    source_count: u32,
    nodes: Vec<C6TraceNode>,
    zero_roots: Vec<C6TraceToken>,
    products: Vec<C6TraceProductClosure>,
}

#[cfg(feature = "c6-trace")]
fn runtime() -> &'static std::sync::Mutex<C6TraceRuntime> {
    static RUNTIME: std::sync::OnceLock<std::sync::Mutex<C6TraceRuntime>> =
        std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| std::sync::Mutex::new(C6TraceRuntime::default()))
}

#[cfg(feature = "c6-trace")]
fn with_runtime<T>(
    operation: impl FnOnce(&mut C6TraceRuntime) -> Result<T, C6TraceError>,
) -> Result<T, C6TraceError> {
    let mut runtime =
        runtime().lock().map_err(|_| C6TraceError::new("C6 trace mutex is poisoned"))?;
    operation(&mut runtime)
}

pub fn begin_c6_prover_trace() -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if runtime.active {
                return Err(C6TraceError::new("a C6 prover trace is already active"));
            }
            runtime.active = true;
            runtime.source_count = 0;
            runtime.nodes.clear();
            runtime.zero_roots.clear();
            runtime.products.clear();
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

pub fn finish_c6_prover_trace() -> Result<C6ProverTraceSnapshot, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Err(C6TraceError::new("no C6 prover trace is active"));
            }
            runtime.active = false;
            Ok(C6ProverTraceSnapshot {
                source_count: runtime.source_count,
                nodes: std::mem::take(&mut runtime.nodes),
                zero_roots: std::mem::take(&mut runtime.zero_roots),
                products: std::mem::take(&mut runtime.products),
            })
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

#[cfg(feature = "c6-trace")]
const UNASSIGNED_CANONICAL_NODE: u32 = u32::MAX;

#[cfg(feature = "c6-trace")]
struct C6TraceNormalizer<'a> {
    trace: &'a C6ProverTraceSnapshot,
    manifest: &'a C6TraceSourceManifest,
    raw_to_canonical: Vec<u32>,
    source_to_canonical: Vec<u32>,
    public_zero_canonical: u32,
    canonical_node_count: u32,
    reachable_operation_count: u64,
    node_hasher: blake3::Hasher,
}

#[cfg(feature = "c6-trace")]
impl<'a> C6TraceNormalizer<'a> {
    fn new(
        trace: &'a C6ProverTraceSnapshot,
        manifest: &'a C6TraceSourceManifest,
    ) -> Result<Self, C6TraceError> {
        if trace.source_count != manifest.source_count {
            return Err(C6TraceError::new(format!(
                "C6 trace source count {} differs from manifest {}",
                trace.source_count, manifest.source_count
            )));
        }
        if trace.nodes.len() >= (SOURCE_TOKEN_BIT - 2) as usize {
            return Err(C6TraceError::new("C6 trace operation count exceeds token capacity"));
        }
        Ok(Self {
            trace,
            manifest,
            raw_to_canonical: vec![UNASSIGNED_CANONICAL_NODE; trace.nodes.len()],
            source_to_canonical: vec![UNASSIGNED_CANONICAL_NODE; manifest.source_count as usize],
            public_zero_canonical: UNASSIGNED_CANONICAL_NODE,
            canonical_node_count: 0,
            reachable_operation_count: 0,
            node_hasher: blake3::Hasher::new_derive_key(C6_OPERATION_NODE_DOMAIN),
        })
    }

    fn raw_index(&self, token: C6TraceToken) -> Result<Option<usize>, C6TraceError> {
        if token.is_untracked() {
            return Err(C6TraceError::new("C6 canonical terminal lacks provenance"));
        }
        if token == C6TraceToken::public_zero() || token.is_source() {
            return Ok(None);
        }
        let index = token
            .0
            .checked_sub(2)
            .ok_or_else(|| C6TraceError::new("C6 trace token encoding is invalid"))?
            as usize;
        if index >= self.trace.nodes.len() {
            return Err(C6TraceError::new("C6 trace token references an unknown operation"));
        }
        Ok(Some(index))
    }

    fn existing_canonical(&self, token: C6TraceToken) -> Result<Option<u32>, C6TraceError> {
        if token == C6TraceToken::public_zero() {
            return Ok((self.public_zero_canonical != UNASSIGNED_CANONICAL_NODE)
                .then_some(self.public_zero_canonical));
        }
        if let Some(source) = token.source_index() {
            if source >= self.manifest.source_count {
                return Err(C6TraceError::new(
                    "C6 trace source token is outside the source manifest",
                ));
            }
            let canonical = self.source_to_canonical[source as usize];
            return Ok((canonical != UNASSIGNED_CANONICAL_NODE).then_some(canonical));
        }
        let index = self
            .raw_index(token)?
            .ok_or_else(|| C6TraceError::new("C6 trace leaf token classification failed"))?;
        let canonical = self.raw_to_canonical[index];
        Ok((canonical != UNASSIGNED_CANONICAL_NODE).then_some(canonical))
    }

    fn next_canonical(&mut self) -> Result<u32, C6TraceError> {
        let canonical = self.canonical_node_count;
        self.canonical_node_count = canonical
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 canonical node count overflows u32"))?;
        Ok(canonical)
    }

    fn hash_node_prefix(&mut self, canonical: u32, tag: u8) {
        self.node_hasher.update(&canonical.to_le_bytes());
        self.node_hasher.update(&[tag]);
    }

    fn assign_leaf(
        &mut self,
        token: C6TraceToken,
        reject_product_mask: bool,
    ) -> Result<u32, C6TraceError> {
        if token == C6TraceToken::public_zero() {
            if self.public_zero_canonical == UNASSIGNED_CANONICAL_NODE {
                let canonical = self.next_canonical()?;
                self.hash_node_prefix(canonical, 2);
                hash_trace_fp2(&mut self.node_hasher, Fp2::ZERO);
                self.public_zero_canonical = canonical;
            }
            return Ok(self.public_zero_canonical);
        }
        let source = token
            .source_index()
            .ok_or_else(|| C6TraceError::new("C6 trace leaf is not a source or public zero"))?;
        if source >= self.manifest.source_count {
            return Err(C6TraceError::new("C6 trace source token is outside the source manifest"));
        }
        if reject_product_mask && self.manifest.is_product_mask(source) {
            return Err(C6TraceError::new(
                "C6 ProductMask source occurs outside its direct closure-mask position",
            ));
        }
        let existing = self.source_to_canonical[source as usize];
        if existing != UNASSIGNED_CANONICAL_NODE {
            return Ok(existing);
        }
        let canonical = self.next_canonical()?;
        self.hash_node_prefix(canonical, 1);
        self.node_hasher.update(&source.to_le_bytes());
        self.source_to_canonical[source as usize] = canonical;
        Ok(canonical)
    }

    fn child_tokens(&self, raw_index: usize) -> Result<[Option<C6TraceToken>; 2], C6TraceError> {
        let child = |token: C6TraceToken| -> Result<C6TraceToken, C6TraceError> {
            if let Some(child_index) = self.raw_index(token)? {
                if child_index >= raw_index {
                    return Err(C6TraceError::new(
                        "C6 trace operation references a future or cyclic operation",
                    ));
                }
            }
            Ok(token)
        };
        match self.trace.nodes[raw_index] {
            C6TraceNode::Public(value) => {
                if value == Fp2::ZERO {
                    return Err(C6TraceError::new(
                        "C6 trace contains a noncanonical allocated public zero",
                    ));
                }
                Ok([None, None])
            }
            C6TraceNode::Add { lhs, rhs } | C6TraceNode::Sub { lhs, rhs } => {
                Ok([Some(child(lhs)?), Some(child(rhs)?)])
            }
            C6TraceNode::Scale { value, .. } => Ok([Some(child(value)?), None]),
        }
    }

    fn assign_operation(&mut self, raw_index: usize) -> Result<u32, C6TraceError> {
        let canonical = self.next_canonical()?;
        match self.trace.nodes[raw_index] {
            C6TraceNode::Public(value) => {
                self.hash_node_prefix(canonical, 2);
                hash_trace_fp2(&mut self.node_hasher, value);
            }
            C6TraceNode::Add { lhs, rhs } => {
                self.hash_node_prefix(canonical, 3);
                let lhs = self.existing_canonical(lhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Add lhs was not normalized first")
                })?;
                let rhs = self.existing_canonical(rhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Add rhs was not normalized first")
                })?;
                self.node_hasher.update(&lhs.to_le_bytes());
                self.node_hasher.update(&rhs.to_le_bytes());
            }
            C6TraceNode::Sub { lhs, rhs } => {
                self.hash_node_prefix(canonical, 4);
                let lhs = self.existing_canonical(lhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Sub lhs was not normalized first")
                })?;
                let rhs = self.existing_canonical(rhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Sub rhs was not normalized first")
                })?;
                self.node_hasher.update(&lhs.to_le_bytes());
                self.node_hasher.update(&rhs.to_le_bytes());
            }
            C6TraceNode::Scale { value, scalar } => {
                self.hash_node_prefix(canonical, 5);
                let value = self.existing_canonical(value)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Scale operand was not normalized first")
                })?;
                self.node_hasher.update(&value.to_le_bytes());
                hash_trace_fp2(&mut self.node_hasher, scalar);
            }
        }
        self.raw_to_canonical[raw_index] = canonical;
        self.reachable_operation_count = self
            .reachable_operation_count
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 reachable operation count overflows"))?;
        Ok(canonical)
    }

    fn normalize_root(
        &mut self,
        root: C6TraceToken,
        reject_product_mask: bool,
    ) -> Result<u32, C6TraceError> {
        if let Some(canonical) = self.existing_canonical(root)? {
            if reject_product_mask
                && root.source_index().is_some_and(|source| self.manifest.is_product_mask(source))
            {
                return Err(C6TraceError::new(
                    "C6 ProductMask source occurs outside its direct closure-mask position",
                ));
            }
            return Ok(canonical);
        }

        let mut stack = vec![(root, false)];
        while let Some((token, expanded)) = stack.pop() {
            if self.existing_canonical(token)?.is_some() {
                if reject_product_mask
                    && token
                        .source_index()
                        .is_some_and(|source| self.manifest.is_product_mask(source))
                {
                    return Err(C6TraceError::new(
                        "C6 ProductMask source occurs outside its direct closure-mask position",
                    ));
                }
                continue;
            }
            let Some(raw_index) = self.raw_index(token)? else {
                self.assign_leaf(token, reject_product_mask)?;
                continue;
            };
            if expanded {
                self.assign_operation(raw_index)?;
                continue;
            }
            stack.push((token, true));
            let children = self.child_tokens(raw_index)?;
            if let Some(rhs) = children[1] {
                stack.push((rhs, false));
            }
            if let Some(lhs) = children[0] {
                stack.push((lhs, false));
            }
        }
        self.existing_canonical(root)?
            .ok_or_else(|| C6TraceError::new("C6 trace root failed to normalize"))
    }
}

#[cfg(feature = "c6-trace")]
fn hash_trace_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

/// Normalize one diagnostic trace without consulting authenticated values.
///
/// Product closures precede zero roots exactly as frozen in the C6 design.
/// Only [`C6OperationPlanIdentity`] participates in prover/verifier equality;
/// allocation-order counts remain diagnostic.
pub fn normalize_c6_operation_trace(
    trace: &C6ProverTraceSnapshot,
    manifest: &C6TraceSourceManifest,
) -> Result<C6CanonicalOperationPlan, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        if trace.products.len() != manifest.product_mask_sources.len() {
            return Err(C6TraceError::new(
                "C6 ProductClosure count differs from ProductMask manifest",
            ));
        }
        let product_closure_count = u32::try_from(trace.products.len())
            .map_err(|_| C6TraceError::new("C6 ProductClosure count exceeds u32"))?;
        let zero_root_count = u32::try_from(trace.zero_roots.len())
            .map_err(|_| C6TraceError::new("C6 zero-root count exceeds u32"))?;
        let mut product_triple_count = 0u64;
        let mut normalizer = C6TraceNormalizer::new(trace, manifest)?;
        let mut root_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_ROOT_DOMAIN);
        root_hasher.update(&product_closure_count.to_le_bytes());

        for (closure_index, closure) in trace.products.iter().enumerate() {
            if closure.triples.is_empty() {
                return Err(C6TraceError::new("empty C6 ProductClosure trace"));
            }
            let expected_mask = manifest.product_mask_sources[closure_index];
            if closure.mask.source_index() != Some(expected_mask) {
                return Err(C6TraceError::new(format!(
                    "C6 ProductClosure {closure_index} mask differs from canonical source manifest"
                )));
            }
            let triple_count = u64::try_from(closure.triples.len())
                .map_err(|_| C6TraceError::new("C6 product triple count exceeds u64"))?;
            product_triple_count = product_triple_count
                .checked_add(triple_count)
                .ok_or_else(|| C6TraceError::new("C6 product triple count overflows"))?;
            root_hasher.update(&(closure_index as u64).to_le_bytes());
            root_hasher.update(&triple_count.to_le_bytes());
            for triple in &closure.triples {
                for &operand in triple {
                    let canonical = normalizer.normalize_root(operand, true)?;
                    root_hasher.update(&canonical.to_le_bytes());
                }
            }
            let canonical_mask = normalizer.normalize_root(closure.mask, false)?;
            root_hasher.update(&canonical_mask.to_le_bytes());
        }

        root_hasher.update(&zero_root_count.to_le_bytes());
        for &root in &trace.zero_roots {
            let canonical = normalizer.normalize_root(root, true)?;
            root_hasher.update(&canonical.to_le_bytes());
        }

        let raw_operation_count = u64::try_from(trace.nodes.len())
            .map_err(|_| C6TraceError::new("C6 raw operation count exceeds u64"))?;
        let omitted_operation_count = raw_operation_count
            .checked_sub(normalizer.reachable_operation_count)
            .ok_or_else(|| C6TraceError::new("C6 reachable operation count exceeds raw count"))?;
        let node_digest = *normalizer.node_hasher.finalize().as_bytes();
        let root_digest = *root_hasher.finalize().as_bytes();
        let mut plan_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_PLAN_DOMAIN);
        plan_hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        plan_hasher.update(&manifest.source_count.to_le_bytes());
        plan_hasher.update(&manifest.source_schedule_digest);
        plan_hasher.update(&normalizer.canonical_node_count.to_le_bytes());
        plan_hasher.update(&product_closure_count.to_le_bytes());
        plan_hasher.update(&product_triple_count.to_le_bytes());
        plan_hasher.update(&zero_root_count.to_le_bytes());
        plan_hasher.update(&node_digest);
        plan_hasher.update(&root_digest);
        let program_digest = *plan_hasher.finalize().as_bytes();

        return Ok(C6CanonicalOperationPlan {
            identity: C6OperationPlanIdentity {
                version: C6_OPERATION_PLAN_VERSION,
                source_count: manifest.source_count,
                source_schedule_digest: manifest.source_schedule_digest,
                canonical_node_count: normalizer.canonical_node_count,
                product_closure_count,
                product_triple_count,
                zero_root_count,
                program_digest,
            },
            diagnostics: C6OperationPlanDiagnostics {
                raw_operation_count,
                reachable_operation_count: normalizer.reachable_operation_count,
                omitted_operation_count,
            },
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (trace, manifest);
        Err(C6TraceError::new(
            "C6 operation-plan normalization requires the diagnostic c6-trace feature",
        ))
    }
}

impl C6TraceToken {
    pub(crate) const fn untracked() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self(0)
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    pub(crate) const fn public_zero() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self(PUBLIC_ZERO_TOKEN)
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    #[cfg(feature = "c6-trace")]
    fn is_untracked(self) -> bool {
        self.0 == 0
    }

    #[cfg(feature = "c6-trace")]
    fn is_source(self) -> bool {
        self.0 & SOURCE_TOKEN_BIT != 0
    }

    pub fn source_index(self) -> Option<u32> {
        #[cfg(feature = "c6-trace")]
        {
            return self.is_source().then_some((self.0 & SOURCE_TOKEN_MASK).checked_sub(1)?);
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            None
        }
    }

    pub fn is_tracked(self) -> bool {
        #[cfg(feature = "c6-trace")]
        {
            return !self.is_untracked();
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            false
        }
    }

    #[cfg(feature = "c6-trace")]
    pub(crate) fn source(index: u32) -> Result<Self, C6TraceError> {
        if index >= SOURCE_TOKEN_MASK - 1 {
            return Err(C6TraceError::new("C6 trace source index exceeds token capacity"));
        }
        with_runtime(|runtime| {
            if !runtime.active {
                return Err(C6TraceError::new("C6 trace source allocated without an active trace"));
            }
            if index != runtime.source_count {
                return Err(C6TraceError::new(format!(
                    "C6 trace source index {index} is not canonical next index {}",
                    runtime.source_count
                )));
            }
            runtime.source_count = runtime
                .source_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 trace source count overflows"))?;
            Ok(Self(SOURCE_TOKEN_BIT | (index + 1)))
        })
    }

    pub(crate) fn public(value: Fp2) -> Self {
        #[cfg(feature = "c6-trace")]
        {
            if value == Fp2::ZERO {
                return Self::public_zero();
            }
            return record_node(C6TraceNode::Public(value));
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            let _ = value;
            Self
        }
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        record_binary(self, rhs, |lhs, rhs| C6TraceNode::Add { lhs, rhs })
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        record_binary(self, rhs, |lhs, rhs| C6TraceNode::Sub { lhs, rhs })
    }

    pub(crate) fn scale(self, scalar: Fp2) -> Self {
        #[cfg(feature = "c6-trace")]
        {
            if self.is_untracked() {
                return Self::untracked();
            }
            return record_node(C6TraceNode::Scale { value: self, scalar });
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            let _ = scalar;
            Self
        }
    }
}

fn record_binary(
    lhs: C6TraceToken,
    rhs: C6TraceToken,
    node: impl FnOnce(C6TraceToken, C6TraceToken) -> C6TraceNode,
) -> C6TraceToken {
    #[cfg(feature = "c6-trace")]
    {
        if lhs.is_untracked() || rhs.is_untracked() {
            return C6TraceToken::untracked();
        }
        return record_node(node(lhs, rhs));
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (lhs, rhs, node);
        C6TraceToken
    }
}

#[cfg(feature = "c6-trace")]
fn record_node(node: C6TraceNode) -> C6TraceToken {
    with_runtime(|runtime| {
        if !runtime.active {
            return Ok(C6TraceToken::untracked());
        }
        let index = u32::try_from(runtime.nodes.len())
            .map_err(|_| C6TraceError::new("C6 trace operation count exceeds u32"))?;
        if index >= SOURCE_TOKEN_BIT - 2 {
            return Err(C6TraceError::new("C6 trace operation token capacity exhausted"));
        }
        runtime.nodes.push(node);
        Ok(C6TraceToken(index + 2))
    })
    .unwrap_or_else(|error| panic!("C6 trace node HARD STOP: {error}"))
}

#[doc(hidden)]
pub fn record_c6_zero_roots(values: &[C6TraceToken]) -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Ok(());
            }
            if let Some(index) = values.iter().position(|token| !token.is_tracked()) {
                return Err(C6TraceError::new(format!("C6 zero root {index} lacks provenance")));
            }
            runtime.zero_roots.extend_from_slice(values);
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = values;
        Ok(())
    }
}

#[doc(hidden)]
pub fn record_c6_product_closure(
    triples: &[[C6TraceToken; 3]],
    mask: C6TraceToken,
) -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Ok(());
            }
            if !mask.is_tracked() {
                return Err(C6TraceError::new("C6 ProductClosure mask lacks provenance"));
            }
            if mask.source_index().is_none() {
                return Err(C6TraceError::new(
                    "C6 ProductClosure mask is not a source provenance token",
                ));
            }
            for (triple_index, triple) in triples.iter().enumerate() {
                if let Some(operand) = triple.iter().position(|token| !token.is_tracked()) {
                    return Err(C6TraceError::new(format!(
                        "C6 ProductClosure triple {triple_index} operand {operand} lacks provenance"
                    )));
                }
            }
            runtime.products.push(C6TraceProductClosure { triples: triples.to_vec(), mask });
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (triples, mask);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "c6-trace")]
    fn source(index: u32) -> C6TraceToken {
        C6TraceToken(SOURCE_TOKEN_BIT | (index + 1))
    }

    #[cfg(feature = "c6-trace")]
    fn operation(index: u32) -> C6TraceToken {
        C6TraceToken(index + 2)
    }

    #[cfg(feature = "c6-trace")]
    fn manifest(source_count: u32, product_masks: Vec<u32>) -> C6TraceSourceManifest {
        C6TraceSourceManifest::new(source_count, [0xA5; 32], product_masks).unwrap()
    }

    #[cfg(feature = "c6-trace")]
    fn allocation_trace(with_dead_prefix: bool) -> C6ProverTraceSnapshot {
        let mut nodes = Vec::new();
        if with_dead_prefix {
            nodes.push(C6TraceNode::Public(Fp2::new(
                volta_field::Fp::new(99),
                volta_field::Fp::new(7),
            )));
        }
        let offset = u32::from(with_dead_prefix);
        nodes.push(C6TraceNode::Public(Fp2::ONE));
        nodes.push(C6TraceNode::Add { lhs: source(0), rhs: operation(offset) });
        nodes.push(C6TraceNode::Scale {
            value: operation(offset + 1),
            scalar: Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3)),
        });
        let root = operation(offset + 2);
        C6ProverTraceSnapshot {
            source_count: 3,
            nodes,
            zero_roots: vec![root],
            products: vec![C6TraceProductClosure {
                triples: vec![[root, source(1), source(0)]],
                mask: source(2),
            }],
        }
    }

    #[test]
    fn ordinary_trace_token_is_zero_sized() {
        #[cfg(not(feature = "c6-trace"))]
        assert_eq!(std::mem::size_of::<C6TraceToken>(), 0);
        #[cfg(feature = "c6-trace")]
        assert_eq!(std::mem::size_of::<C6TraceToken>(), 4);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn trace_rejects_missing_provenance_and_censuses_sources() {
        begin_c6_prover_trace().unwrap();
        let source = C6TraceToken::source(0).unwrap();
        let public = C6TraceToken::public(Fp2::ONE);
        let sum = source.add(public);
        record_c6_product_closure(&[[source, public, sum]], source).unwrap();
        let error = record_c6_zero_roots(&[C6TraceToken::untracked()]).unwrap_err();
        assert!(error.to_string().contains("lacks provenance"));
        record_c6_zero_roots(&[sum]).unwrap();
        let snapshot = finish_c6_prover_trace().unwrap();
        assert_eq!(snapshot.source_count, 1);
        assert_eq!(snapshot.products.len(), 1);
        assert_eq!(snapshot.zero_roots, vec![sum]);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_ignores_raw_ids_and_unreachable_operations() {
        let manifest = manifest(3, vec![2]);
        let compact = normalize_c6_operation_trace(&allocation_trace(false), &manifest).unwrap();
        let shifted = normalize_c6_operation_trace(&allocation_trace(true), &manifest).unwrap();
        assert_eq!(compact.identity, shifted.identity);
        assert_eq!(compact.diagnostics.raw_operation_count, 3);
        assert_eq!(compact.diagnostics.reachable_operation_count, 3);
        assert_eq!(compact.diagnostics.omitted_operation_count, 0);
        assert_eq!(shifted.diagnostics.raw_operation_count, 4);
        assert_eq!(shifted.diagnostics.reachable_operation_count, 3);
        assert_eq!(shifted.diagnostics.omitted_operation_count, 1);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_binds_operand_root_and_schedule_order() {
        let manifest = manifest(3, vec![2]);
        let baseline = normalize_c6_operation_trace(&allocation_trace(false), &manifest).unwrap();

        let mut swapped_operand = allocation_trace(false);
        swapped_operand.nodes[1] = C6TraceNode::Add { lhs: operation(0), rhs: source(0) };
        let swapped_operand = normalize_c6_operation_trace(&swapped_operand, &manifest).unwrap();
        assert_ne!(baseline.identity.program_digest, swapped_operand.identity.program_digest);

        let mut swapped_roots = allocation_trace(false);
        swapped_roots.zero_roots = vec![source(1), operation(2)];
        let swapped_roots = normalize_c6_operation_trace(&swapped_roots, &manifest).unwrap();
        assert_ne!(baseline.identity.program_digest, swapped_roots.identity.program_digest);

        let changed_manifest = C6TraceSourceManifest::new(3, [0x5A; 32], vec![2]).unwrap();
        let changed_schedule =
            normalize_c6_operation_trace(&allocation_trace(false), &changed_manifest).unwrap();
        assert_ne!(baseline.identity.program_digest, changed_schedule.identity.program_digest);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_preserves_declared_graph_sharing() {
        let manifest = manifest(2, vec![]);
        let shared = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![C6TraceNode::Add { lhs: source(0), rhs: source(1) }],
            zero_roots: vec![operation(0), operation(0)],
            products: vec![],
        };
        let duplicated = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![
                C6TraceNode::Add { lhs: source(0), rhs: source(1) },
                C6TraceNode::Add { lhs: source(0), rhs: source(1) },
            ],
            zero_roots: vec![operation(0), operation(1)],
            products: vec![],
        };
        let shared = normalize_c6_operation_trace(&shared, &manifest).unwrap();
        let duplicated = normalize_c6_operation_trace(&duplicated, &manifest).unwrap();
        assert_ne!(shared.identity.canonical_node_count, duplicated.identity.canonical_node_count);
        assert_ne!(shared.identity.program_digest, duplicated.identity.program_digest);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_rejects_mask_role_reuse_and_linear_use() {
        let manifest = manifest(3, vec![2]);

        let mut wrong_mask = allocation_trace(false);
        wrong_mask.products[0].mask = source(1);
        let error = normalize_c6_operation_trace(&wrong_mask, &manifest).unwrap_err();
        assert!(error.to_string().contains("canonical source manifest"));

        let mut mask_operand = allocation_trace(false);
        mask_operand.products[0].triples[0][1] = source(2);
        let error = normalize_c6_operation_trace(&mask_operand, &manifest).unwrap_err();
        assert!(error.to_string().contains("outside its direct closure-mask"));

        let duplicate_manifest = C6TraceSourceManifest::new(3, [0xA5; 32], vec![2, 2]).unwrap_err();
        assert!(duplicate_manifest.to_string().contains("strictly ordered"));
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_rejects_invalid_operation_tokens() {
        let manifest = manifest(2, vec![]);
        let future = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![
                C6TraceNode::Add { lhs: operation(1), rhs: source(0) },
                C6TraceNode::Public(Fp2::ONE),
            ],
            zero_roots: vec![operation(0)],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&future, &manifest).unwrap_err();
        assert!(error.to_string().contains("future or cyclic"));

        let out_of_range = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![],
            zero_roots: vec![source(2)],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&out_of_range, &manifest).unwrap_err();
        assert!(error.to_string().contains("outside the source manifest"));

        let allocated_zero = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![C6TraceNode::Public(Fp2::ZERO)],
            zero_roots: vec![operation(0)],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&allocated_zero, &manifest).unwrap_err();
        assert!(error.to_string().contains("noncanonical allocated public zero"));

        let untracked = C6ProverTraceSnapshot {
            source_count: 2,
            nodes: vec![],
            zero_roots: vec![C6TraceToken::untracked()],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&untracked, &manifest).unwrap_err();
        assert!(error.to_string().contains("lacks provenance"));
    }
}

//! Diagnostic-only C6 authenticated-value provenance recorder.
//!
//! The ordinary build uses a zero-sized token and records nothing.  The
//! `c6-trace` feature turns the token into a compact handle and enables one
//! process-local, fail-closed prover trace.  This module deliberately does
//! not infer provenance from plaintexts, tags, keys, or addresses.

use std::cell::RefCell;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use volta_field::Fp2;

pub const C6_OPERATION_PLAN_VERSION: u32 = 2;

#[cfg(feature = "c6-trace")]
const C6_OPERATION_NODE_DOMAIN: &str = "volta/proto/c6/operation-plan/nodes/v2";
#[cfg(feature = "c6-trace")]
const C6_OPERATION_NODE_BLOCK_DOMAIN: &str =
    "volta/proto/c6/operation-plan/node-block-diagnostic/v2";
const C6_OPERATION_ROOT_DOMAIN: &str = "volta/proto/c6/operation-plan/roots/v2";
#[cfg(feature = "c6-trace")]
const C6_OPERATION_PLAN_DOMAIN: &str = "volta/proto/c6/operation-plan/v2";
const C6_OPERATION_TOPOLOGY_NODE_DOMAIN: &str = "volta/proto/c6/operation-plan/topology-nodes/v2";
const C6_OPERATION_TOPOLOGY_PLAN_DOMAIN: &str = "volta/proto/c6/operation-plan/topology/v2";
const C6_OPERATION_INSTANCE_VALUE_DOMAIN: &str = "volta/proto/c6/operation-plan/instance-values/v2";
const C6_OPERATION_INSTANCE_DOMAIN: &str = "volta/proto/c6/operation-plan/instance/v2";

const C6_OPERATION_PLAN_CODEC_MAGIC: &[u8; 8] = b"VC6PLN2\0";
const C6_OPERATION_PLAN_CODEC_VERSION: u32 = 1;
const C6_OPERATION_PARAMETERIZED_HEADER_BYTES: u64 = 152;
const C6_INSTANCE_EXTRACTION_CODEC_MAGIC: &[u8; 8] = b"VC6INS1\0";
const C6_INSTANCE_EXTRACTION_CODEC_VERSION: u32 = 1;
const C6_INSTANCE_EXTRACTION_HEADER_BYTES: u64 = 120;
const C6_INSTANCE_EXTRACTION_MAP_DOMAIN: &str =
    "volta/proto/c6/operation-plan/instance-extraction-map/v1";

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
pub struct C6TraceToken {
    namespace: u32,
    handle: u32,
}

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
    pub namespace: u32,
    pub source_count: u32,
    pub nodes: Vec<C6TraceNode>,
    pub zero_roots: Vec<C6TraceToken>,
    pub products: Vec<C6TraceProductClosure>,
}

pub type C6VerifierTraceSnapshot = C6ProverTraceSnapshot;

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

/// Response-independent identity of the parameterized authenticated-value
/// program. Public constants and scale coefficients are canonical input
/// slots here; their response-specific values are bound separately by
/// [`C6OperationPlanInstanceIdentity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6OperationPlanTopologyIdentity {
    pub version: u32,
    pub source_count: u32,
    pub source_schedule_digest: [u8; 32],
    pub canonical_node_count: u32,
    pub public_input_count: u32,
    pub scalar_input_count: u32,
    pub product_closure_count: u32,
    pub product_triple_count: u64,
    pub zero_root_count: u32,
    pub topology_digest: [u8; 32],
}

/// Per-response binding of all public-node and scale-scalar slot values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6OperationPlanInstanceIdentity {
    pub version: u32,
    pub topology_digest: [u8; 32],
    pub public_input_count: u32,
    pub scalar_input_count: u32,
    pub instance_digest: [u8; 32],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6InstanceExtractionRole {
    Prover = 1,
    Verifier = 2,
}

impl C6InstanceExtractionRole {
    fn decode(value: u8) -> Result<Self, C6TraceError> {
        match value {
            1 => Ok(Self::Prover),
            2 => Ok(Self::Verifier),
            _ => Err(C6TraceError::new("unknown C6 instance-extraction role")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6InstanceExtractionCensus {
    pub raw_public_input_count: u32,
    pub raw_scalar_input_count: u32,
    pub canonical_public_input_count: u32,
    pub canonical_scalar_input_count: u32,
    pub public_run_count: u32,
    pub scalar_run_count: u32,
    pub header_bytes: u64,
    pub public_map_bytes: u64,
    pub scalar_map_bytes: u64,
    pub total_bytes: u64,
    pub map_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6CanonicalNodeKindCensus {
    pub source: u64,
    pub structural_zero: u64,
    pub public_input: u64,
    pub add: u64,
    pub sub: u64,
    pub scale: u64,
}

impl C6CanonicalNodeKindCensus {
    pub fn total(self) -> u64 {
        self.source + self.structural_zero + self.public_input + self.add + self.sub + self.scale
    }
}

/// Exact byte census for the preregistered uncompressed v2 candidate.
///
/// This is not setup credit: no production decoder or materialized artifact
/// is claimed by the diagnostic normalizer. Nodes use packed 3-bit opcodes;
/// sources use absolute ULEB128 ordinals; linear operands use positive
/// backward-distance ULEB128 values; public/scalar slot ordinals are implicit
/// in canonical order; terminal roots use absolute ULEB128 node ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6OperationPlanEncodingCensus {
    pub header_bytes: u64,
    pub packed_opcode_bytes: u64,
    pub source_payload_bytes: u64,
    pub linear_operand_payload_bytes: u64,
    pub terminal_payload_bytes: u64,
    pub total_bytes: u64,
}

/// Exact census for the specialized canonical v2 operand/source coding.
///
/// A normalizer-only value is a projection and receives no setup credit.
/// [`compile_c6_operation_trace`] materializes the sections and requires
/// their measured census to equal this value exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6OperationPlanSpecializedEncodingCensus {
    pub header_bytes: u64,
    pub packed_opcode_bytes: u64,
    pub source_delta_payload_bytes: u64,
    pub operand_unit_flag_bytes: u64,
    pub nonunit_operand_payload_bytes: u64,
    pub terminal_payload_bytes: u64,
    pub total_bytes: u64,
    pub source_successor_count: u64,
    pub operand_count: u64,
    pub unit_operand_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6OperationPlanDiagnostics {
    pub raw_operation_count: u64,
    pub reachable_operation_count: u64,
    pub omitted_operation_count: u64,
    pub node_digest: [u8; 32],
    pub root_digest: [u8; 32],
    /// Diagnostic-only independent hashes over consecutive canonical node
    /// records. These do not participate in program identity.
    pub canonical_node_block_digests: Vec<[u8; 32]>,
    /// Empty unless an explicit diagnostic normalization requested one
    /// canonical block.
    pub captured_canonical_nodes: Vec<C6CanonicalNodeDebug>,
    pub node_kinds: C6CanonicalNodeKindCensus,
    /// Number of canonical nodes assigned after all ProductClosure terminals
    /// and before the first ZeroBatch root.
    pub product_phase_node_count: u64,
    pub topology_node_digest: [u8; 32],
    pub instance_value_digest: [u8; 32],
    pub candidate_encoding: C6OperationPlanEncodingCensus,
    pub specialized_encoding_projection: C6OperationPlanSpecializedEncodingCensus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CanonicalNodeDebug {
    pub canonical: u32,
    pub terminal: Option<C6CanonicalTerminalDebug>,
    pub node: C6CanonicalNodeDebugKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6CanonicalTerminalDebug {
    ProductOperand { closure: u64, triple: u64, operand: u8 },
    ProductMask { closure: u64 },
    ZeroRoot { index: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6CanonicalNodeDebugKind {
    Source(u32),
    Public(Fp2),
    Add { lhs: u32, rhs: u32 },
    Sub { lhs: u32, rhs: u32 },
    Scale { value: u32, scalar: Fp2 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CanonicalOperationPlan {
    /// Exact-instance identity retained as a prover/verifier parity oracle.
    pub identity: C6OperationPlanIdentity,
    pub topology: C6OperationPlanTopologyIdentity,
    pub instance: C6OperationPlanInstanceIdentity,
    pub diagnostics: C6OperationPlanDiagnostics,
}

pub struct C6CompiledOperationPlan {
    pub plan: C6CanonicalOperationPlan,
    pub artifact: C6OperationPlanArtifact,
    pub instance_extraction: C6InstanceExtractionArtifact,
}

#[derive(Clone, PartialEq, Eq)]
pub struct C6OperationPlanArtifact {
    bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct C6InstanceExtractionArtifact {
    bytes: Vec<u8>,
}

impl fmt::Debug for C6InstanceExtractionArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6InstanceExtractionArtifact")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl C6InstanceExtractionArtifact {
    pub fn parse(
        bytes: Vec<u8>,
        topology: C6OperationPlanTopologyIdentity,
    ) -> Result<Self, C6TraceError> {
        decode_c6_instance_extraction_artifact(&bytes, topology)?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn decode(
        &self,
        topology: C6OperationPlanTopologyIdentity,
    ) -> Result<C6DecodedInstanceExtractionPlan, C6TraceError> {
        decode_c6_instance_extraction_artifact(&self.bytes, topology)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6DecodedInstanceExtractionPlan {
    role: C6InstanceExtractionRole,
    topology_digest: [u8; 32],
    public_raw_ordinals: Vec<u32>,
    scalar_raw_ordinals: Vec<u32>,
    census: C6InstanceExtractionCensus,
}

impl C6DecodedInstanceExtractionPlan {
    pub fn role(&self) -> C6InstanceExtractionRole {
        self.role
    }

    pub fn topology_digest(&self) -> [u8; 32] {
        self.topology_digest
    }

    pub fn public_raw_ordinals(&self) -> &[u32] {
        &self.public_raw_ordinals
    }

    pub fn scalar_raw_ordinals(&self) -> &[u32] {
        &self.scalar_raw_ordinals
    }

    pub fn census(&self) -> C6InstanceExtractionCensus {
        self.census
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C6RuntimeInstanceCaptureSpec {
    role: C6InstanceExtractionRole,
    topology_digest: [u8; 32],
    map_digest: [u8; 32],
    raw_public_input_count: u32,
    raw_scalar_input_count: u32,
    canonical_public_input_count: u32,
    canonical_scalar_input_count: u32,
}

impl C6RuntimeInstanceCaptureSpec {
    fn from_extraction(extraction: &C6DecodedInstanceExtractionPlan) -> Self {
        Self {
            role: extraction.role,
            topology_digest: extraction.topology_digest,
            map_digest: extraction.census.map_digest,
            raw_public_input_count: extraction.census.raw_public_input_count,
            raw_scalar_input_count: extraction.census.raw_scalar_input_count,
            canonical_public_input_count: extraction.census.canonical_public_input_count,
            canonical_scalar_input_count: extraction.census.canonical_scalar_input_count,
        }
    }
}

struct C6RuntimeInstanceCaptureState {
    role: C6InstanceExtractionRole,
    expected_spec: Option<C6RuntimeInstanceCaptureSpec>,
    public_values: Vec<Fp2>,
    scalar_values: Vec<Fp2>,
    public_overflow: bool,
    scalar_overflow: bool,
}

thread_local! {
    static C6_RUNTIME_INSTANCE_CAPTURE: RefCell<Option<C6RuntimeInstanceCaptureState>> =
        const { RefCell::new(None) };
}

/// Response-local raw public/scalar recorder.
///
/// The guard is deliberately thread-affine. If authenticated-value work
/// migrates to another thread, that thread has no active recorder and the
/// exact installed raw census fails at [`Self::finish`].
pub struct C6RuntimeInstanceCaptureGuard {
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl fmt::Debug for C6RuntimeInstanceCaptureGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6RuntimeInstanceCaptureGuard")
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// Captured response values in the role's raw construction order.
///
/// Canonical slot access always goes through the installed extraction map;
/// no response-linear value vector is serialized.
pub struct C6RuntimeInstanceValues {
    spec: C6RuntimeInstanceCaptureSpec,
    public_values: Vec<Fp2>,
    scalar_values: Vec<Fp2>,
    instance: C6OperationPlanInstanceIdentity,
}

impl fmt::Debug for C6RuntimeInstanceValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6RuntimeInstanceValues")
            .field("role", &self.spec.role)
            .field("raw_public_values", &self.public_values.len())
            .field("raw_scalar_values", &self.scalar_values.len())
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl C6RuntimeInstanceValues {
    pub fn role(&self) -> C6InstanceExtractionRole {
        self.spec.role
    }

    pub fn instance_identity(&self) -> C6OperationPlanInstanceIdentity {
        self.instance
    }

    pub fn raw_public_input_count(&self) -> usize {
        self.public_values.len()
    }

    pub fn raw_scalar_input_count(&self) -> usize {
        self.scalar_values.len()
    }

    fn validate_extraction(
        &self,
        extraction: &C6DecodedInstanceExtractionPlan,
    ) -> Result<(), C6TraceError> {
        if self.spec != C6RuntimeInstanceCaptureSpec::from_extraction(extraction) {
            return Err(C6TraceError::new(
                "C6 runtime instance values differ from the installed extraction map",
            ));
        }
        Ok(())
    }

    /// Fail-closed binding check for consumers whose algebra may not read a
    /// public/scalar slot (for example an all-zero or tag-only reverse form).
    pub fn validate_extraction_binding(
        &self,
        extraction: &C6DecodedInstanceExtractionPlan,
    ) -> Result<(), C6TraceError> {
        self.validate_extraction(extraction)
    }

    pub fn public_value(
        &self,
        extraction: &C6DecodedInstanceExtractionPlan,
        canonical_slot: u32,
    ) -> Result<Fp2, C6TraceError> {
        self.validate_extraction(extraction)?;
        let raw = *extraction
            .public_raw_ordinals
            .get(canonical_slot as usize)
            .ok_or_else(|| C6TraceError::new("C6 canonical public slot is out of range"))?;
        self.public_values
            .get(raw as usize)
            .copied()
            .ok_or_else(|| C6TraceError::new("C6 mapped raw public slot is out of range"))
    }

    pub fn scalar_value(
        &self,
        extraction: &C6DecodedInstanceExtractionPlan,
        canonical_slot: u32,
    ) -> Result<Fp2, C6TraceError> {
        self.validate_extraction(extraction)?;
        let raw = *extraction
            .scalar_raw_ordinals
            .get(canonical_slot as usize)
            .ok_or_else(|| C6TraceError::new("C6 canonical scalar slot is out of range"))?;
        self.scalar_values
            .get(raw as usize)
            .copied()
            .ok_or_else(|| C6TraceError::new("C6 mapped raw scalar slot is out of range"))
    }
}

/// Begin one exact response-local instance capture on the current thread.
///
/// The installed role map supplies exact capacities and censuses. Nested
/// captures on the same thread are rejected.
pub fn begin_c6_runtime_instance_capture(
    extraction: &C6DecodedInstanceExtractionPlan,
) -> Result<C6RuntimeInstanceCaptureGuard, C6TraceError> {
    let spec = C6RuntimeInstanceCaptureSpec::from_extraction(extraction);
    let public_capacity = usize::try_from(spec.raw_public_input_count)
        .map_err(|_| C6TraceError::new("C6 raw public capture count exceeds usize"))?;
    let scalar_capacity = usize::try_from(spec.raw_scalar_input_count)
        .map_err(|_| C6TraceError::new("C6 raw scalar capture count exceeds usize"))?;
    begin_c6_runtime_instance_capture_impl(
        extraction.role,
        Some(spec),
        public_capacity,
        scalar_capacity,
    )
}

/// Diagnostic-only first-pass capture used to validate a newly compiled map.
///
/// Production callers must use [`begin_c6_runtime_instance_capture`] with an
/// already installed and decoded extraction artifact.
#[doc(hidden)]
pub fn begin_c6_runtime_instance_capture_diagnostic(
    role: C6InstanceExtractionRole,
) -> Result<C6RuntimeInstanceCaptureGuard, C6TraceError> {
    begin_c6_runtime_instance_capture_impl(role, None, 0, 0)
}

/// Reconstruct response-instance values from the immutable diagnostic trace.
///
/// This is the first-pass companion to operation-plan compilation.  It is
/// intentionally unavailable as a production capture seam: deployed callers
/// use an installed extraction map and [`begin_c6_runtime_instance_capture`].
/// Reading the snapshot is nevertheless necessary for parallel test harnesses
/// because the process-global operation recorder may contain dead nodes from
/// unrelated threads, while a thread-local first-pass capture correctly does
/// not.  The extraction map selects only canonical reachable values and the
/// expected instance identity binds their exact positions.
#[doc(hidden)]
pub fn derive_c6_runtime_instance_from_trace_diagnostic(
    snapshot: &C6ProverTraceSnapshot,
    operation_plan: &C6OperationPlanArtifact,
    extraction: &C6DecodedInstanceExtractionPlan,
    expected_instance: C6OperationPlanInstanceIdentity,
) -> Result<C6RuntimeInstanceValues, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        let spec = C6RuntimeInstanceCaptureSpec::from_extraction(extraction);
        let mut public_values = Vec::new();
        public_values
            .try_reserve_exact(spec.raw_public_input_count as usize)
            .map_err(|_| C6TraceError::new("C6 diagnostic public-value allocation failed"))?;
        let mut scalar_values = Vec::new();
        scalar_values
            .try_reserve_exact(spec.raw_scalar_input_count as usize)
            .map_err(|_| C6TraceError::new("C6 diagnostic scalar-value allocation failed"))?;
        for node in &snapshot.nodes {
            match *node {
                C6TraceNode::Public(value) => public_values.push(value),
                C6TraceNode::Scale { scalar, .. } => scalar_values.push(scalar),
                C6TraceNode::Add { .. } | C6TraceNode::Sub { .. } => {}
            }
        }
        if public_values.len() != spec.raw_public_input_count as usize
            || scalar_values.len() != spec.raw_scalar_input_count as usize
        {
            return Err(C6TraceError::new(
                "C6 diagnostic trace values differ from the extraction raw census",
            ));
        }
        let instance = reconstruct_c6_runtime_instance_identity(
            operation_plan,
            extraction,
            &public_values,
            &scalar_values,
        )?;
        if instance != expected_instance {
            return Err(C6TraceError::new(
                "C6 diagnostic trace values differ from the compiled instance identity",
            ));
        }
        Ok(C6RuntimeInstanceValues { spec, public_values, scalar_values, instance })
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (snapshot, operation_plan, extraction, expected_instance);
        Err(C6TraceError::new(
            "C6 trace-derived runtime instances require the diagnostic c6-trace feature",
        ))
    }
}

fn begin_c6_runtime_instance_capture_impl(
    role: C6InstanceExtractionRole,
    expected_spec: Option<C6RuntimeInstanceCaptureSpec>,
    public_capacity: usize,
    scalar_capacity: usize,
) -> Result<C6RuntimeInstanceCaptureGuard, C6TraceError> {
    let mut public_values = Vec::new();
    public_values
        .try_reserve_exact(public_capacity)
        .map_err(|_| C6TraceError::new("C6 raw public capture allocation failed"))?;
    let mut scalar_values = Vec::new();
    scalar_values
        .try_reserve_exact(scalar_capacity)
        .map_err(|_| C6TraceError::new("C6 raw scalar capture allocation failed"))?;

    C6_RUNTIME_INSTANCE_CAPTURE
        .try_with(|capture| {
            let mut capture = capture
                .try_borrow_mut()
                .map_err(|_| C6TraceError::new("C6 runtime instance capture is borrowed"))?;
            if capture.is_some() {
                return Err(C6TraceError::new(
                    "a C6 runtime instance capture is already active on this thread",
                ));
            }
            *capture = Some(C6RuntimeInstanceCaptureState {
                role,
                expected_spec,
                public_values,
                scalar_values,
                public_overflow: false,
                scalar_overflow: false,
            });
            Ok(())
        })
        .map_err(|_| C6TraceError::new("C6 runtime instance TLS is unavailable"))??;
    Ok(C6RuntimeInstanceCaptureGuard { active: true, _not_send: PhantomData })
}

impl C6RuntimeInstanceCaptureGuard {
    pub fn finish(
        mut self,
        operation_plan: &C6OperationPlanArtifact,
        extraction: &C6DecodedInstanceExtractionPlan,
    ) -> Result<C6RuntimeInstanceValues, C6TraceError> {
        let result = finish_c6_runtime_instance_capture(operation_plan, extraction);
        self.active = false;
        result
    }

    pub fn finish_installed(
        mut self,
        operation_plan: &C6InstalledOperationPlan,
        extraction: &C6DecodedInstanceExtractionPlan,
    ) -> Result<C6RuntimeInstanceValues, C6TraceError> {
        let result = finish_c6_runtime_instance_capture_installed(operation_plan, extraction);
        self.active = false;
        result
    }
}

impl Drop for C6RuntimeInstanceCaptureGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = C6_RUNTIME_INSTANCE_CAPTURE.try_with(|capture| {
                if let Ok(mut capture) = capture.try_borrow_mut() {
                    *capture = None;
                }
            });
        }
    }
}

#[inline]
fn record_c6_runtime_public(value: Fp2) {
    let _ = C6_RUNTIME_INSTANCE_CAPTURE.try_with(|capture| {
        let mut capture = capture.borrow_mut();
        let Some(capture) = capture.as_mut() else {
            return;
        };
        let limit = capture
            .expected_spec
            .map_or(u32::MAX as usize, |spec| spec.raw_public_input_count as usize);
        if capture.public_values.len() >= limit {
            capture.public_overflow = true;
            return;
        }
        capture.public_values.push(value);
    });
}

#[inline]
fn record_c6_runtime_scalar(value: Fp2) {
    let _ = C6_RUNTIME_INSTANCE_CAPTURE.try_with(|capture| {
        let mut capture = capture.borrow_mut();
        let Some(capture) = capture.as_mut() else {
            return;
        };
        let limit = capture
            .expected_spec
            .map_or(u32::MAX as usize, |spec| spec.raw_scalar_input_count as usize);
        if capture.scalar_values.len() >= limit {
            capture.scalar_overflow = true;
            return;
        }
        capture.scalar_values.push(value);
    });
}

fn finish_c6_runtime_instance_capture(
    operation_plan: &C6OperationPlanArtifact,
    extraction: &C6DecodedInstanceExtractionPlan,
) -> Result<C6RuntimeInstanceValues, C6TraceError> {
    let (spec, public_values, scalar_values) = take_c6_runtime_instance_capture(extraction)?;
    let instance = reconstruct_c6_runtime_instance_identity(
        operation_plan,
        extraction,
        &public_values,
        &scalar_values,
    )?;
    Ok(C6RuntimeInstanceValues { spec, public_values, scalar_values, instance })
}

fn finish_c6_runtime_instance_capture_installed(
    operation_plan: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
) -> Result<C6RuntimeInstanceValues, C6TraceError> {
    let (spec, public_values, scalar_values) = take_c6_runtime_instance_capture(extraction)?;
    let instance = operation_plan.reconstruct_runtime_instance_identity(
        extraction,
        &public_values,
        &scalar_values,
    )?;
    Ok(C6RuntimeInstanceValues { spec, public_values, scalar_values, instance })
}

fn take_c6_runtime_instance_capture(
    extraction: &C6DecodedInstanceExtractionPlan,
) -> Result<(C6RuntimeInstanceCaptureSpec, Vec<Fp2>, Vec<Fp2>), C6TraceError> {
    let capture = C6_RUNTIME_INSTANCE_CAPTURE
        .try_with(|capture| {
            capture
                .try_borrow_mut()
                .map_err(|_| C6TraceError::new("C6 runtime instance capture is borrowed"))?
                .take()
                .ok_or_else(|| C6TraceError::new("no C6 runtime instance capture is active"))
        })
        .map_err(|_| C6TraceError::new("C6 runtime instance TLS is unavailable"))??;
    let expected_spec = C6RuntimeInstanceCaptureSpec::from_extraction(extraction);
    if capture.role != expected_spec.role
        || capture.expected_spec.is_some_and(|spec| spec != expected_spec)
    {
        return Err(C6TraceError::new(
            "C6 runtime instance capture finished against a different extraction map",
        ));
    }
    if capture.public_overflow || capture.scalar_overflow {
        return Err(C6TraceError::new(
            "C6 runtime instance stream exceeds the installed raw census",
        ));
    }
    if capture.public_values.len() != expected_spec.raw_public_input_count as usize
        || capture.scalar_values.len() != expected_spec.raw_scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 runtime instance stream differs from the installed raw census",
        ));
    }
    Ok((expected_spec, capture.public_values, capture.scalar_values))
}

impl fmt::Debug for C6OperationPlanArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6OperationPlanArtifact")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl C6OperationPlanArtifact {
    /// Parse client-received setup bytes with the strict ordinary-build
    /// decoder before admitting them as an installed artifact.
    pub fn parse(bytes: Vec<u8>, manifest: &C6TraceSourceManifest) -> Result<Self, C6TraceError> {
        decode_c6_operation_plan_artifact(&bytes, manifest)?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn decode(
        &self,
        manifest: &C6TraceSourceManifest,
    ) -> Result<C6DecodedOperationPlan, C6TraceError> {
        decode_c6_operation_plan_artifact(&self.bytes, manifest)
    }

    /// Consume one admitted setup artifact and materialize its compact local
    /// reverse-execution arrays using the same strict decoder.
    pub fn install(
        self,
        manifest: &C6TraceSourceManifest,
    ) -> Result<C6InstalledOperationPlan, C6TraceError> {
        let artifact_digest = *blake3::hash(&self.bytes).as_bytes();
        let (decoded, data) = decode_c6_operation_plan_artifact_impl(&self.bytes, manifest, true)?;
        let data = data
            .ok_or_else(|| C6TraceError::new("C6 operation-plan installation emitted no data"))?;
        Ok(C6InstalledOperationPlan {
            decoded,
            artifact_digest,
            opcodes: data.opcodes,
            source_ordinals: data.source_ordinals,
            operands: data.operands,
            products: data.products,
            zero_roots: data.zero_roots,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6DecodedOperationPlan {
    pub topology: C6OperationPlanTopologyIdentity,
    pub node_kinds: C6CanonicalNodeKindCensus,
    pub product_phase_node_count: u64,
    pub encoding: C6OperationPlanSpecializedEncodingCensus,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6InstalledOperationKind {
    Source = 1,
    StructuralZero = 2,
    PublicInput = 3,
    Add = 4,
    Sub = 5,
    Scale = 6,
}

impl C6InstalledOperationKind {
    fn decode(value: u8) -> Result<Self, C6TraceError> {
        match value {
            1 => Ok(Self::Source),
            2 => Ok(Self::StructuralZero),
            3 => Ok(Self::PublicInput),
            4 => Ok(Self::Add),
            5 => Ok(Self::Sub),
            6 => Ok(Self::Scale),
            _ => Err(C6TraceError::new("unknown installed C6 operation kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6InstalledProductClosure {
    triples: Vec<[u32; 3]>,
    mask: u32,
}

impl C6InstalledProductClosure {
    pub fn triples(&self) -> &[[u32; 3]] {
        &self.triples
    }

    pub fn mask(&self) -> u32 {
        self.mask
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6InstalledOperationPlanMemoryCensus {
    pub opcode_elements: u64,
    pub opcode_capacity: u64,
    pub opcode_heap_bytes: u64,
    pub source_elements: u64,
    pub source_capacity: u64,
    pub source_heap_bytes: u64,
    pub operand_elements: u64,
    pub operand_capacity: u64,
    pub operand_heap_bytes: u64,
    pub product_closure_elements: u64,
    pub product_closure_capacity: u64,
    pub product_closure_heap_bytes: u64,
    pub product_triple_elements: u64,
    pub product_triple_capacity: u64,
    pub product_triple_heap_bytes: u64,
    pub zero_root_elements: u64,
    pub zero_root_capacity: u64,
    pub zero_root_heap_bytes: u64,
    pub inline_bytes: u64,
    pub total_heap_bytes: u64,
    pub total_resident_bytes: u64,
}

/// Strictly decoded, response-independent operation plan held in local
/// session memory.
///
/// This is constructed once from the canonical setup artifact. Its vectors
/// are never serialized as response data.
pub struct C6InstalledOperationPlan {
    decoded: C6DecodedOperationPlan,
    artifact_digest: [u8; 32],
    opcodes: Vec<C6InstalledOperationKind>,
    source_ordinals: Vec<u32>,
    operands: Vec<u32>,
    products: Vec<C6InstalledProductClosure>,
    zero_roots: Vec<u32>,
}

impl fmt::Debug for C6InstalledOperationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("C6InstalledOperationPlan")
            .field("topology", &self.decoded.topology)
            .field("artifact_digest", &self.artifact_digest)
            .field("opcodes", &self.opcodes.len())
            .field("source_ordinals", &self.source_ordinals.len())
            .field("operands", &self.operands.len())
            .field("products", &self.products.len())
            .field("zero_roots", &self.zero_roots.len())
            .finish_non_exhaustive()
    }
}

impl C6InstalledOperationPlan {
    pub fn decoded(&self) -> C6DecodedOperationPlan {
        self.decoded
    }

    pub fn topology(&self) -> C6OperationPlanTopologyIdentity {
        self.decoded.topology
    }

    pub fn artifact_digest(&self) -> [u8; 32] {
        self.artifact_digest
    }

    pub fn operation_kind(&self, canonical: u32) -> Result<C6InstalledOperationKind, C6TraceError> {
        self.opcodes
            .get(canonical as usize)
            .copied()
            .ok_or_else(|| C6TraceError::new("installed C6 canonical node is out of range"))
    }

    pub fn operation_kinds(&self) -> &[C6InstalledOperationKind] {
        &self.opcodes
    }

    pub fn source_ordinals(&self) -> &[u32] {
        &self.source_ordinals
    }

    pub fn operands(&self) -> &[u32] {
        &self.operands
    }

    pub fn products(&self) -> &[C6InstalledProductClosure] {
        &self.products
    }

    pub fn zero_roots(&self) -> &[u32] {
        &self.zero_roots
    }

    pub fn memory_census(&self) -> Result<C6InstalledOperationPlanMemoryCensus, C6TraceError> {
        let allocation = |capacity: usize, element_bytes: usize, label: &str| {
            let capacity = u64::try_from(capacity)
                .map_err(|_| C6TraceError::new(format!("C6 {label} capacity exceeds u64")))?;
            let element_bytes = u64::try_from(element_bytes)
                .map_err(|_| C6TraceError::new(format!("C6 {label} element size exceeds u64")))?;
            let bytes = capacity
                .checked_mul(element_bytes)
                .ok_or_else(|| C6TraceError::new(format!("C6 {label} allocation overflows")))?;
            Ok((capacity, bytes))
        };
        let elements = |length: usize, label: &str| {
            u64::try_from(length)
                .map_err(|_| C6TraceError::new(format!("C6 {label} length exceeds u64")))
        };

        let (opcode_capacity, opcode_heap_bytes) = allocation(
            self.opcodes.capacity(),
            std::mem::size_of::<C6InstalledOperationKind>(),
            "installed opcode",
        )?;
        let (source_capacity, source_heap_bytes) = allocation(
            self.source_ordinals.capacity(),
            std::mem::size_of::<u32>(),
            "installed source",
        )?;
        let (operand_capacity, operand_heap_bytes) =
            allocation(self.operands.capacity(), std::mem::size_of::<u32>(), "installed operand")?;
        let (product_closure_capacity, product_closure_heap_bytes) = allocation(
            self.products.capacity(),
            std::mem::size_of::<C6InstalledProductClosure>(),
            "installed ProductClosure",
        )?;
        let mut product_triple_elements = 0u64;
        let mut product_triple_capacity = 0u64;
        let mut product_triple_heap_bytes = 0u64;
        for product in &self.products {
            product_triple_elements = product_triple_elements
                .checked_add(elements(product.triples.len(), "installed ProductClosure triple")?)
                .ok_or_else(|| {
                    C6TraceError::new("C6 installed ProductClosure triple count overflows")
                })?;
            let (capacity, bytes) = allocation(
                product.triples.capacity(),
                std::mem::size_of::<[u32; 3]>(),
                "installed ProductClosure triple",
            )?;
            product_triple_capacity =
                product_triple_capacity.checked_add(capacity).ok_or_else(|| {
                    C6TraceError::new("C6 installed ProductClosure triple capacity overflows")
                })?;
            product_triple_heap_bytes =
                product_triple_heap_bytes.checked_add(bytes).ok_or_else(|| {
                    C6TraceError::new("C6 installed ProductClosure triple bytes overflow")
                })?;
        }
        let (zero_root_capacity, zero_root_heap_bytes) = allocation(
            self.zero_roots.capacity(),
            std::mem::size_of::<u32>(),
            "installed zero root",
        )?;
        let total_heap_bytes = [
            opcode_heap_bytes,
            source_heap_bytes,
            operand_heap_bytes,
            product_closure_heap_bytes,
            product_triple_heap_bytes,
            zero_root_heap_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |total, bytes| {
            total.checked_add(bytes).ok_or_else(|| {
                C6TraceError::new("C6 installed operation-plan heap census overflows")
            })
        })?;
        let inline_bytes = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            C6TraceError::new("C6 installed operation-plan inline size exceeds u64")
        })?;
        let total_resident_bytes = inline_bytes
            .checked_add(total_heap_bytes)
            .ok_or_else(|| C6TraceError::new("C6 installed operation-plan residency overflows"))?;

        Ok(C6InstalledOperationPlanMemoryCensus {
            opcode_elements: elements(self.opcodes.len(), "installed opcode")?,
            opcode_capacity,
            opcode_heap_bytes,
            source_elements: elements(self.source_ordinals.len(), "installed source")?,
            source_capacity,
            source_heap_bytes,
            operand_elements: elements(self.operands.len(), "installed operand")?,
            operand_capacity,
            operand_heap_bytes,
            product_closure_elements: elements(self.products.len(), "installed ProductClosure")?,
            product_closure_capacity,
            product_closure_heap_bytes,
            product_triple_elements,
            product_triple_capacity,
            product_triple_heap_bytes,
            zero_root_elements: elements(self.zero_roots.len(), "installed zero root")?,
            zero_root_capacity,
            zero_root_heap_bytes,
            inline_bytes,
            total_heap_bytes,
            total_resident_bytes,
        })
    }

    fn reconstruct_runtime_instance_identity(
        &self,
        extraction: &C6DecodedInstanceExtractionPlan,
        raw_public_values: &[Fp2],
        raw_scalar_values: &[Fp2],
    ) -> Result<C6OperationPlanInstanceIdentity, C6TraceError> {
        let topology = self.decoded.topology;
        reconstruct_c6_runtime_instance_identity_from_opcodes(
            topology.version,
            topology.topology_digest,
            topology.canonical_node_count,
            topology.public_input_count,
            topology.scalar_input_count,
            extraction,
            raw_public_values,
            raw_scalar_values,
            |canonical| {
                self.opcodes
                    .get(canonical as usize)
                    .map(|kind| *kind as u8)
                    .ok_or_else(|| C6TraceError::new("installed C6 opcode is out of range"))
            },
        )
    }
}

struct C6OperationPlanInstallData {
    opcodes: Vec<C6InstalledOperationKind>,
    source_ordinals: Vec<u32>,
    operands: Vec<u32>,
    products: Vec<C6InstalledProductClosure>,
    zero_roots: Vec<u32>,
}

#[cfg(feature = "c6-trace")]
const PUBLIC_ZERO_TOKEN: u32 = 1;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_BIT: u32 = 1 << 31;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_MASK: u32 = SOURCE_TOKEN_BIT - 1;

#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C6TraceParty {
    Prover,
    Verifier,
}

#[cfg(feature = "c6-trace")]
#[derive(Default)]
struct C6TraceRuntime {
    party: Option<C6TraceParty>,
    /// Product/zero terminal calls are response-coordinator actions.  The
    /// owner lets an active diagnostic trace coexist with unrelated Rust
    /// tests on other harness threads without accepting an untracked
    /// terminal from the traced response itself.
    owner_thread: Option<std::thread::ThreadId>,
    namespace: u32,
    next_namespace: u32,
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
        return begin_c6_trace(C6TraceParty::Prover);
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

pub fn finish_c6_prover_trace() -> Result<C6ProverTraceSnapshot, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return finish_c6_trace(C6TraceParty::Prover);
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

pub fn begin_c6_verifier_trace() -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return begin_c6_trace(C6TraceParty::Verifier);
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 verifier tracing requires the diagnostic c6-trace feature"))
    }
}

pub fn finish_c6_verifier_trace() -> Result<C6VerifierTraceSnapshot, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return finish_c6_trace(C6TraceParty::Verifier);
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 verifier tracing requires the diagnostic c6-trace feature"))
    }
}

#[cfg(feature = "c6-trace")]
fn begin_c6_trace(party: C6TraceParty) -> Result<(), C6TraceError> {
    with_runtime(|runtime| {
        if runtime.party.is_some() {
            return Err(C6TraceError::new("a C6 operation trace is already active"));
        }
        runtime.next_namespace = runtime
            .next_namespace
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 trace namespace counter exhausted"))?;
        runtime.party = Some(party);
        runtime.owner_thread = Some(std::thread::current().id());
        runtime.namespace = runtime.next_namespace;
        runtime.source_count = 0;
        runtime.nodes.clear();
        runtime.zero_roots.clear();
        runtime.products.clear();
        Ok(())
    })
}

#[cfg(feature = "c6-trace")]
fn finish_c6_trace(expected_party: C6TraceParty) -> Result<C6ProverTraceSnapshot, C6TraceError> {
    with_runtime(|runtime| {
        if runtime.party != Some(expected_party)
            || runtime.owner_thread != Some(std::thread::current().id())
        {
            return Err(C6TraceError::new(
                "C6 operation trace finished by the wrong or inactive party",
            ));
        }
        let namespace = runtime.namespace;
        runtime.party = None;
        runtime.owner_thread = None;
        runtime.namespace = 0;
        Ok(C6ProverTraceSnapshot {
            namespace,
            source_count: runtime.source_count,
            nodes: std::mem::take(&mut runtime.nodes),
            zero_roots: std::mem::take(&mut runtime.zero_roots),
            products: std::mem::take(&mut runtime.products),
        })
    })
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
    topology_node_hasher: blake3::Hasher,
    instance_value_hasher: blake3::Hasher,
    public_input_count: u32,
    scalar_input_count: u32,
    node_kinds: C6CanonicalNodeKindCensus,
    source_payload_bytes: u64,
    source_delta_payload_bytes: u64,
    previous_source: Option<u32>,
    source_successor_count: u64,
    linear_operand_payload_bytes: u64,
    operand_count: u64,
    unit_operand_count: u64,
    nonunit_operand_payload_bytes: u64,
    node_block_hasher: blake3::Hasher,
    node_block_len: u32,
    node_block_digests: Vec<[u8; 32]>,
    capture_block: Option<u64>,
    captured_nodes: Vec<C6CanonicalNodeDebug>,
    current_terminal: Option<C6CanonicalTerminalDebug>,
    encoder: Option<C6PlanEncodingBuilder>,
}

#[cfg(feature = "c6-trace")]
const C6_OPERATION_DIAGNOSTIC_BLOCK_NODES: u32 = 64;

#[cfg(feature = "c6-trace")]
fn new_node_block_hasher(block_index: u64) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key(C6_OPERATION_NODE_BLOCK_DOMAIN);
    hasher.update(&block_index.to_le_bytes());
    hasher
}

#[cfg(feature = "c6-trace")]
fn uleb128_u32_len(value: u32) -> u64 {
    uleb128_u64_len(u64::from(value))
}

fn uleb128_u64_len(mut value: u64) -> u64 {
    let mut bytes = 1;
    while value >= 0x80 {
        value >>= 7;
        bytes += 1;
    }
    bytes
}

#[cfg(feature = "c6-trace")]
fn zigzag_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

#[cfg(feature = "c6-trace")]
#[derive(Default)]
struct C6BitWriter {
    bytes: Vec<u8>,
    bits: u64,
}

#[cfg(feature = "c6-trace")]
impl C6BitWriter {
    fn push(&mut self, value: u8, width: u8) -> Result<(), C6TraceError> {
        if width == 0 || width > 8 || value >> width != 0 {
            return Err(C6TraceError::new("invalid C6 packed-bit value"));
        }
        for shift in 0..width {
            let bit_index = self.bits;
            if bit_index % 8 == 0 {
                self.bytes.push(0);
            }
            if value & (1 << shift) != 0 {
                let byte = self
                    .bytes
                    .last_mut()
                    .ok_or_else(|| C6TraceError::new("missing C6 packed-bit output byte"))?;
                *byte |= 1 << (bit_index % 8);
            }
            self.bits = self
                .bits
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 packed-bit count overflows"))?;
        }
        Ok(())
    }
}

#[cfg(feature = "c6-trace")]
#[derive(Default)]
struct C6PlanEncodingBuilder {
    opcodes: C6BitWriter,
    source_payload: Vec<u8>,
    operand_flags: C6BitWriter,
    operand_payload: Vec<u8>,
    terminal_payload: Vec<u8>,
    previous_source: Option<u32>,
    source_successor_count: u64,
    unit_operand_count: u64,
}

#[cfg(feature = "c6-trace")]
impl C6PlanEncodingBuilder {
    fn push_uleb(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn source(&mut self, source: u32) -> Result<(), C6TraceError> {
        self.opcodes.push(1, 3)?;
        let previous = self.previous_source.map_or(-1, i64::from);
        let delta = i64::from(source) - previous;
        Self::push_uleb(&mut self.source_payload, zigzag_i64(delta));
        if delta == 1 {
            self.source_successor_count = self
                .source_successor_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 encoded source-successor count overflows"))?;
        }
        self.previous_source = Some(source);
        Ok(())
    }

    fn structural_zero(&mut self) -> Result<(), C6TraceError> {
        self.opcodes.push(2, 3)
    }

    fn public_input(&mut self) -> Result<(), C6TraceError> {
        self.opcodes.push(3, 3)
    }

    fn operand(&mut self, canonical: u32, operand: u32) -> Result<(), C6TraceError> {
        let distance = canonical.checked_sub(operand).ok_or_else(|| {
            C6TraceError::new("C6 encoded operand is not before its canonical node")
        })?;
        if distance == 0 {
            return Err(C6TraceError::new("C6 encoded operand has zero backward distance"));
        }
        if distance == 1 {
            self.operand_flags.push(0, 1)?;
            self.unit_operand_count = self
                .unit_operand_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 encoded unit-operand count overflows"))?;
        } else {
            self.operand_flags.push(1, 1)?;
            Self::push_uleb(&mut self.operand_payload, u64::from(distance - 2));
        }
        Ok(())
    }

    fn add(&mut self, canonical: u32, lhs: u32, rhs: u32) -> Result<(), C6TraceError> {
        self.opcodes.push(4, 3)?;
        self.operand(canonical, lhs)?;
        self.operand(canonical, rhs)
    }

    fn sub(&mut self, canonical: u32, lhs: u32, rhs: u32) -> Result<(), C6TraceError> {
        self.opcodes.push(5, 3)?;
        self.operand(canonical, lhs)?;
        self.operand(canonical, rhs)
    }

    fn scale(&mut self, canonical: u32, value: u32) -> Result<(), C6TraceError> {
        self.opcodes.push(6, 3)?;
        self.operand(canonical, value)
    }

    fn terminal_count(&mut self, count: u64) {
        Self::push_uleb(&mut self.terminal_payload, count);
    }

    fn terminal_node(&mut self, canonical: u32) {
        Self::push_uleb(&mut self.terminal_payload, u64::from(canonical));
    }

    fn finish(
        self,
        topology: C6OperationPlanTopologyIdentity,
        expected: C6OperationPlanSpecializedEncodingCensus,
    ) -> Result<C6OperationPlanArtifact, C6TraceError> {
        let section_lengths = [
            self.opcodes.bytes.len(),
            self.source_payload.len(),
            self.operand_flags.bytes.len(),
            self.operand_payload.len(),
            self.terminal_payload.len(),
        ];
        let actual = C6OperationPlanSpecializedEncodingCensus {
            header_bytes: C6_OPERATION_PARAMETERIZED_HEADER_BYTES,
            packed_opcode_bytes: section_lengths[0] as u64,
            source_delta_payload_bytes: section_lengths[1] as u64,
            operand_unit_flag_bytes: section_lengths[2] as u64,
            nonunit_operand_payload_bytes: section_lengths[3] as u64,
            terminal_payload_bytes: section_lengths[4] as u64,
            total_bytes: C6_OPERATION_PARAMETERIZED_HEADER_BYTES
                + section_lengths.iter().map(|&length| length as u64).sum::<u64>(),
            source_successor_count: self.source_successor_count,
            operand_count: self.operand_flags.bits,
            unit_operand_count: self.unit_operand_count,
        };
        if actual != expected {
            return Err(C6TraceError::new(format!(
                "materialized C6 plan encoding differs from projection: {actual:?} != {expected:?}"
            )));
        }
        let capacity = usize::try_from(actual.total_bytes)
            .map_err(|_| C6TraceError::new("C6 encoded plan length exceeds usize"))?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(C6_OPERATION_PLAN_CODEC_MAGIC);
        bytes.extend_from_slice(&C6_OPERATION_PLAN_CODEC_VERSION.to_le_bytes());
        bytes.extend_from_slice(&topology.version.to_le_bytes());
        bytes.extend_from_slice(&topology.source_count.to_le_bytes());
        bytes.extend_from_slice(&topology.source_schedule_digest);
        bytes.extend_from_slice(&topology.canonical_node_count.to_le_bytes());
        bytes.extend_from_slice(&topology.public_input_count.to_le_bytes());
        bytes.extend_from_slice(&topology.scalar_input_count.to_le_bytes());
        bytes.extend_from_slice(&topology.product_closure_count.to_le_bytes());
        bytes.extend_from_slice(&topology.product_triple_count.to_le_bytes());
        bytes.extend_from_slice(&topology.zero_root_count.to_le_bytes());
        bytes.extend_from_slice(&topology.topology_digest);
        for length in section_lengths {
            bytes.extend_from_slice(&(length as u64).to_le_bytes());
        }
        if bytes.len() as u64 != C6_OPERATION_PARAMETERIZED_HEADER_BYTES {
            return Err(C6TraceError::new("C6 operation-plan header length changed"));
        }
        bytes.extend_from_slice(&self.opcodes.bytes);
        bytes.extend_from_slice(&self.source_payload);
        bytes.extend_from_slice(&self.operand_flags.bytes);
        bytes.extend_from_slice(&self.operand_payload);
        bytes.extend_from_slice(&self.terminal_payload);
        if bytes.len() != capacity {
            return Err(C6TraceError::new("C6 operation-plan artifact length changed"));
        }
        Ok(C6OperationPlanArtifact { bytes })
    }
}

fn c6_instance_extraction_map_digest(
    role: C6InstanceExtractionRole,
    topology: C6OperationPlanTopologyIdentity,
    raw_public_input_count: u32,
    raw_scalar_input_count: u32,
    public_raw_ordinals: &[u32],
    scalar_raw_ordinals: &[u32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(C6_INSTANCE_EXTRACTION_MAP_DOMAIN);
    hasher.update(&C6_INSTANCE_EXTRACTION_CODEC_VERSION.to_le_bytes());
    hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
    hasher.update(&[role as u8]);
    hasher.update(&topology.topology_digest);
    hasher.update(&raw_public_input_count.to_le_bytes());
    hasher.update(&raw_scalar_input_count.to_le_bytes());
    hasher.update(&topology.public_input_count.to_le_bytes());
    hasher.update(&topology.scalar_input_count.to_le_bytes());
    for (kind, ordinals) in [(1u8, public_raw_ordinals), (2u8, scalar_raw_ordinals)] {
        hasher.update(&[kind]);
        hasher.update(&(ordinals.len() as u64).to_le_bytes());
        for (slot, &raw) in ordinals.iter().enumerate() {
            hasher.update(&(slot as u64).to_le_bytes());
            hasher.update(&raw.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "c6-trace")]
fn c6_instance_map_runs(ordinals: &[u32]) -> Result<Vec<(u32, u32)>, C6TraceError> {
    let mut runs = Vec::new();
    let mut index = 0usize;
    while index < ordinals.len() {
        let start = ordinals[index];
        let mut length = 1usize;
        while index + length < ordinals.len()
            && ordinals[index + length - 1]
                .checked_add(1)
                .is_some_and(|next| next == ordinals[index + length])
        {
            length += 1;
        }
        runs.push((
            start,
            u32::try_from(length)
                .map_err(|_| C6TraceError::new("C6 instance-extraction run exceeds u32"))?,
        ));
        index += length;
    }
    Ok(runs)
}

#[cfg(feature = "c6-trace")]
fn encode_c6_instance_map_section(ordinals: &[u32]) -> Result<(Vec<u8>, u32), C6TraceError> {
    let runs = c6_instance_map_runs(ordinals)?;
    let run_count = u32::try_from(runs.len())
        .map_err(|_| C6TraceError::new("C6 instance-extraction run count exceeds u32"))?;
    let mut bytes = Vec::new();
    C6PlanEncodingBuilder::push_uleb(&mut bytes, u64::from(run_count));
    let mut expected_next = 0i64;
    for (start, length) in runs {
        let delta = i64::from(start) - expected_next;
        C6PlanEncodingBuilder::push_uleb(&mut bytes, zigzag_i64(delta));
        C6PlanEncodingBuilder::push_uleb(&mut bytes, u64::from(length - 1));
        expected_next = i64::from(start)
            .checked_add(i64::from(length))
            .ok_or_else(|| C6TraceError::new("C6 instance-extraction run end overflows"))?;
    }
    Ok((bytes, run_count))
}

#[cfg(feature = "c6-trace")]
fn encode_c6_instance_extraction_artifact(
    role: C6InstanceExtractionRole,
    topology: C6OperationPlanTopologyIdentity,
    raw_public_input_count: u32,
    raw_scalar_input_count: u32,
    public_raw_ordinals: &[u32],
    scalar_raw_ordinals: &[u32],
) -> Result<(C6InstanceExtractionArtifact, C6InstanceExtractionCensus), C6TraceError> {
    if public_raw_ordinals.len() != topology.public_input_count as usize
        || scalar_raw_ordinals.len() != topology.scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 instance-extraction map differs from canonical slot census",
        ));
    }
    let (public_map, public_run_count) = encode_c6_instance_map_section(public_raw_ordinals)?;
    let (scalar_map, scalar_run_count) = encode_c6_instance_map_section(scalar_raw_ordinals)?;
    let map_digest = c6_instance_extraction_map_digest(
        role,
        topology,
        raw_public_input_count,
        raw_scalar_input_count,
        public_raw_ordinals,
        scalar_raw_ordinals,
    );
    let public_map_bytes = u64::try_from(public_map.len())
        .map_err(|_| C6TraceError::new("C6 public instance map exceeds u64"))?;
    let scalar_map_bytes = u64::try_from(scalar_map.len())
        .map_err(|_| C6TraceError::new("C6 scalar instance map exceeds u64"))?;
    let total_bytes = C6_INSTANCE_EXTRACTION_HEADER_BYTES
        .checked_add(public_map_bytes)
        .and_then(|bytes| bytes.checked_add(scalar_map_bytes))
        .ok_or_else(|| C6TraceError::new("C6 instance-extraction artifact length overflows"))?;
    let capacity = usize::try_from(total_bytes)
        .map_err(|_| C6TraceError::new("C6 instance-extraction artifact exceeds usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(C6_INSTANCE_EXTRACTION_CODEC_MAGIC);
    bytes.extend_from_slice(&C6_INSTANCE_EXTRACTION_CODEC_VERSION.to_le_bytes());
    bytes.extend_from_slice(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
    bytes.push(role as u8);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&topology.topology_digest);
    bytes.extend_from_slice(&raw_public_input_count.to_le_bytes());
    bytes.extend_from_slice(&raw_scalar_input_count.to_le_bytes());
    bytes.extend_from_slice(&topology.public_input_count.to_le_bytes());
    bytes.extend_from_slice(&topology.scalar_input_count.to_le_bytes());
    bytes.extend_from_slice(&map_digest);
    bytes.extend_from_slice(&public_map_bytes.to_le_bytes());
    bytes.extend_from_slice(&scalar_map_bytes.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    if bytes.len() as u64 != C6_INSTANCE_EXTRACTION_HEADER_BYTES {
        return Err(C6TraceError::new("C6 instance-extraction header length changed"));
    }
    bytes.extend_from_slice(&public_map);
    bytes.extend_from_slice(&scalar_map);
    if bytes.len() != capacity {
        return Err(C6TraceError::new("C6 instance-extraction artifact length changed"));
    }
    let census = C6InstanceExtractionCensus {
        raw_public_input_count,
        raw_scalar_input_count,
        canonical_public_input_count: topology.public_input_count,
        canonical_scalar_input_count: topology.scalar_input_count,
        public_run_count,
        scalar_run_count,
        header_bytes: C6_INSTANCE_EXTRACTION_HEADER_BYTES,
        public_map_bytes,
        scalar_map_bytes,
        total_bytes,
        map_digest,
    };
    Ok((C6InstanceExtractionArtifact { bytes }, census))
}

#[cfg(feature = "c6-trace")]
impl<'a> C6TraceNormalizer<'a> {
    fn new(
        trace: &'a C6ProverTraceSnapshot,
        manifest: &'a C6TraceSourceManifest,
        capture_block: Option<u64>,
        compile: bool,
    ) -> Result<Self, C6TraceError> {
        if trace.namespace == 0 {
            return Err(C6TraceError::new("C6 trace snapshot has no namespace"));
        }
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
            topology_node_hasher: blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_NODE_DOMAIN),
            instance_value_hasher: blake3::Hasher::new_derive_key(
                C6_OPERATION_INSTANCE_VALUE_DOMAIN,
            ),
            public_input_count: 0,
            scalar_input_count: 0,
            node_kinds: C6CanonicalNodeKindCensus::default(),
            source_payload_bytes: 0,
            source_delta_payload_bytes: 0,
            previous_source: None,
            source_successor_count: 0,
            linear_operand_payload_bytes: 0,
            operand_count: 0,
            unit_operand_count: 0,
            nonunit_operand_payload_bytes: 0,
            node_block_hasher: new_node_block_hasher(0),
            node_block_len: 0,
            node_block_digests: Vec::new(),
            capture_block,
            captured_nodes: Vec::new(),
            current_terminal: None,
            encoder: compile.then(C6PlanEncodingBuilder::default),
        })
    }

    fn raw_index(&self, token: C6TraceToken) -> Result<Option<usize>, C6TraceError> {
        if token.is_untracked() {
            return Err(C6TraceError::new("C6 canonical terminal lacks provenance"));
        }
        if !token.belongs_to(self.trace.namespace) {
            return Err(C6TraceError::new("C6 trace token belongs to a different namespace"));
        }
        if token == C6TraceToken::public_zero() || token.is_source() {
            return Ok(None);
        }
        let index = token
            .handle
            .checked_sub(2)
            .ok_or_else(|| C6TraceError::new("C6 trace token encoding is invalid"))?
            as usize;
        if index >= self.trace.nodes.len() {
            return Err(C6TraceError::new("C6 trace token references an unknown operation"));
        }
        Ok(Some(index))
    }

    fn existing_canonical(&self, token: C6TraceToken) -> Result<Option<u32>, C6TraceError> {
        if !token.is_untracked() && !token.belongs_to(self.trace.namespace) {
            return Err(C6TraceError::new("C6 trace token belongs to a different namespace"));
        }
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

    fn hash_node_bytes(&mut self, bytes: &[u8]) {
        self.node_hasher.update(bytes);
        self.node_block_hasher.update(bytes);
    }

    fn hash_node_prefix(&mut self, canonical: u32, tag: u8) {
        self.hash_node_bytes(&canonical.to_le_bytes());
        self.hash_node_bytes(&[tag]);
    }

    fn hash_topology_node_prefix(&mut self, canonical: u32, tag: u8) {
        self.topology_node_hasher.update(&canonical.to_le_bytes());
        self.topology_node_hasher.update(&[tag]);
    }

    fn hash_instance_value(&mut self, canonical: u32, kind: u8, slot: u32, value: Fp2) {
        self.instance_value_hasher.update(&canonical.to_le_bytes());
        self.instance_value_hasher.update(&[kind]);
        self.instance_value_hasher.update(&slot.to_le_bytes());
        self.instance_value_hasher.update(&value.c0.value().to_le_bytes());
        self.instance_value_hasher.update(&value.c1.value().to_le_bytes());
    }

    fn next_public_input(&mut self) -> Result<u32, C6TraceError> {
        let slot = self.public_input_count;
        self.public_input_count = slot
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 public-input slot count overflows u32"))?;
        Ok(slot)
    }

    fn next_scalar_input(&mut self) -> Result<u32, C6TraceError> {
        let slot = self.scalar_input_count;
        self.scalar_input_count = slot
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 scalar-input slot count overflows u32"))?;
        Ok(slot)
    }

    fn add_source_payload(&mut self, source: u32) -> Result<(), C6TraceError> {
        self.source_payload_bytes = self
            .source_payload_bytes
            .checked_add(uleb128_u32_len(source))
            .ok_or_else(|| C6TraceError::new("C6 source encoding byte count overflows"))?;
        let previous = self.previous_source.map_or(-1, i64::from);
        let delta = i64::from(source) - previous;
        self.source_delta_payload_bytes = self
            .source_delta_payload_bytes
            .checked_add(uleb128_u64_len(zigzag_i64(delta)))
            .ok_or_else(|| C6TraceError::new("C6 source-delta byte count overflows"))?;
        if delta == 1 {
            self.source_successor_count = self
                .source_successor_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 source-successor count overflows"))?;
        }
        self.previous_source = Some(source);
        Ok(())
    }

    fn add_operand_payload(&mut self, canonical: u32, operand: u32) -> Result<(), C6TraceError> {
        let distance = canonical.checked_sub(operand).ok_or_else(|| {
            C6TraceError::new("C6 parameterized operand is not before its canonical node")
        })?;
        if distance == 0 {
            return Err(C6TraceError::new("C6 parameterized operand has zero backward distance"));
        }
        self.linear_operand_payload_bytes = self
            .linear_operand_payload_bytes
            .checked_add(uleb128_u32_len(distance))
            .ok_or_else(|| C6TraceError::new("C6 operand encoding byte count overflows"))?;
        self.operand_count = self
            .operand_count
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("C6 operand count overflows"))?;
        if distance == 1 {
            self.unit_operand_count = self
                .unit_operand_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 unit-operand count overflows"))?;
        } else {
            self.nonunit_operand_payload_bytes = self
                .nonunit_operand_payload_bytes
                .checked_add(uleb128_u32_len(distance - 2))
                .ok_or_else(|| C6TraceError::new("C6 nonunit operand byte count overflows"))?;
        }
        Ok(())
    }

    fn finish_node_record(&mut self) {
        self.node_block_len += 1;
        if self.node_block_len == C6_OPERATION_DIAGNOSTIC_BLOCK_NODES {
            self.node_block_digests.push(*self.node_block_hasher.finalize().as_bytes());
            self.node_block_len = 0;
            self.node_block_hasher = new_node_block_hasher(self.node_block_digests.len() as u64);
        }
    }

    fn finish_node_blocks(&mut self) {
        if self.node_block_len != 0 {
            self.node_block_digests.push(*self.node_block_hasher.finalize().as_bytes());
            self.node_block_len = 0;
        }
    }

    fn capture_node(&mut self, canonical: u32, node: C6CanonicalNodeDebugKind) {
        if self.capture_block
            == Some(u64::from(canonical) / u64::from(C6_OPERATION_DIAGNOSTIC_BLOCK_NODES))
        {
            self.captured_nodes.push(C6CanonicalNodeDebug {
                canonical,
                terminal: self.current_terminal,
                node,
            });
        }
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
                self.hash_node_fp2(Fp2::ZERO);
                self.hash_topology_node_prefix(canonical, 2);
                self.node_kinds.structural_zero += 1;
                if let Some(encoder) = &mut self.encoder {
                    encoder.structural_zero()?;
                }
                self.capture_node(canonical, C6CanonicalNodeDebugKind::Public(Fp2::ZERO));
                self.finish_node_record();
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
        self.hash_node_bytes(&source.to_le_bytes());
        self.hash_topology_node_prefix(canonical, 1);
        self.topology_node_hasher.update(&source.to_le_bytes());
        self.node_kinds.source += 1;
        self.add_source_payload(source)?;
        if let Some(encoder) = &mut self.encoder {
            encoder.source(source)?;
        }
        self.capture_node(canonical, C6CanonicalNodeDebugKind::Source(source));
        self.finish_node_record();
        self.source_to_canonical[source as usize] = canonical;
        Ok(canonical)
    }

    fn hash_node_fp2(&mut self, value: Fp2) {
        self.hash_node_bytes(&value.c0.value().to_le_bytes());
        self.hash_node_bytes(&value.c1.value().to_le_bytes());
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
            C6TraceNode::Public(_) => Ok([None, None]),
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
                self.hash_node_fp2(value);
                let slot = self.next_public_input()?;
                self.hash_topology_node_prefix(canonical, 3);
                self.topology_node_hasher.update(&slot.to_le_bytes());
                self.hash_instance_value(canonical, 1, slot, value);
                self.node_kinds.public_input += 1;
                if let Some(encoder) = &mut self.encoder {
                    encoder.public_input()?;
                }
                self.capture_node(canonical, C6CanonicalNodeDebugKind::Public(value));
            }
            C6TraceNode::Add { lhs, rhs } => {
                self.hash_node_prefix(canonical, 3);
                let lhs = self.existing_canonical(lhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Add lhs was not normalized first")
                })?;
                let rhs = self.existing_canonical(rhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Add rhs was not normalized first")
                })?;
                self.hash_node_bytes(&lhs.to_le_bytes());
                self.hash_node_bytes(&rhs.to_le_bytes());
                self.hash_topology_node_prefix(canonical, 4);
                self.topology_node_hasher.update(&lhs.to_le_bytes());
                self.topology_node_hasher.update(&rhs.to_le_bytes());
                self.node_kinds.add += 1;
                self.add_operand_payload(canonical, lhs)?;
                self.add_operand_payload(canonical, rhs)?;
                if let Some(encoder) = &mut self.encoder {
                    encoder.add(canonical, lhs, rhs)?;
                }
                self.capture_node(canonical, C6CanonicalNodeDebugKind::Add { lhs, rhs });
            }
            C6TraceNode::Sub { lhs, rhs } => {
                self.hash_node_prefix(canonical, 4);
                let lhs = self.existing_canonical(lhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Sub lhs was not normalized first")
                })?;
                let rhs = self.existing_canonical(rhs)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Sub rhs was not normalized first")
                })?;
                self.hash_node_bytes(&lhs.to_le_bytes());
                self.hash_node_bytes(&rhs.to_le_bytes());
                self.hash_topology_node_prefix(canonical, 5);
                self.topology_node_hasher.update(&lhs.to_le_bytes());
                self.topology_node_hasher.update(&rhs.to_le_bytes());
                self.node_kinds.sub += 1;
                self.add_operand_payload(canonical, lhs)?;
                self.add_operand_payload(canonical, rhs)?;
                if let Some(encoder) = &mut self.encoder {
                    encoder.sub(canonical, lhs, rhs)?;
                }
                self.capture_node(canonical, C6CanonicalNodeDebugKind::Sub { lhs, rhs });
            }
            C6TraceNode::Scale { value, scalar } => {
                self.hash_node_prefix(canonical, 5);
                let value = self.existing_canonical(value)?.ok_or_else(|| {
                    C6TraceError::new("C6 trace Scale operand was not normalized first")
                })?;
                self.hash_node_bytes(&value.to_le_bytes());
                self.hash_node_fp2(scalar);
                let slot = self.next_scalar_input()?;
                self.hash_topology_node_prefix(canonical, 6);
                self.topology_node_hasher.update(&value.to_le_bytes());
                self.topology_node_hasher.update(&slot.to_le_bytes());
                self.hash_instance_value(canonical, 2, slot, scalar);
                self.node_kinds.scale += 1;
                self.add_operand_payload(canonical, value)?;
                if let Some(encoder) = &mut self.encoder {
                    encoder.scale(canonical, value)?;
                }
                self.capture_node(canonical, C6CanonicalNodeDebugKind::Scale { value, scalar });
            }
        }
        self.finish_node_record();
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
fn compile_c6_instance_extraction(
    normalizer: &C6TraceNormalizer<'_>,
    role: C6InstanceExtractionRole,
    topology: C6OperationPlanTopologyIdentity,
    expected_instance: C6OperationPlanInstanceIdentity,
) -> Result<C6InstanceExtractionArtifact, C6TraceError> {
    let mut raw_public_values = Vec::new();
    let mut raw_scalar_values = Vec::new();
    let mut public_map = Vec::<(u32, u32)>::new();
    let mut scalar_map = Vec::<(u32, u32)>::new();
    for (raw_index, node) in normalizer.trace.nodes.iter().enumerate() {
        let canonical = normalizer.raw_to_canonical[raw_index];
        match *node {
            C6TraceNode::Public(value) => {
                let raw_slot = u32::try_from(raw_public_values.len())
                    .map_err(|_| C6TraceError::new("C6 raw public slot count exceeds u32"))?;
                raw_public_values.push(value);
                if canonical != UNASSIGNED_CANONICAL_NODE {
                    public_map.push((canonical, raw_slot));
                }
            }
            C6TraceNode::Scale { scalar, .. } => {
                let raw_slot = u32::try_from(raw_scalar_values.len())
                    .map_err(|_| C6TraceError::new("C6 raw scalar slot count exceeds u32"))?;
                raw_scalar_values.push(scalar);
                if canonical != UNASSIGNED_CANONICAL_NODE {
                    scalar_map.push((canonical, raw_slot));
                }
            }
            C6TraceNode::Add { .. } | C6TraceNode::Sub { .. } => {}
        }
    }
    public_map.sort_unstable_by_key(|&(canonical, _)| canonical);
    scalar_map.sort_unstable_by_key(|&(canonical, _)| canonical);
    if public_map.len() != topology.public_input_count as usize
        || scalar_map.len() != topology.scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 reachable raw instance events differ from canonical slot census",
        ));
    }
    if public_map.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || scalar_map.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(C6TraceError::new(
            "C6 canonical instance-node order is duplicate or nonmonotone",
        ));
    }

    let mut value_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_INSTANCE_VALUE_DOMAIN);
    let mut public_index = 0usize;
    let mut scalar_index = 0usize;
    while public_index < public_map.len() || scalar_index < scalar_map.len() {
        let take_public = scalar_index == scalar_map.len()
            || (public_index < public_map.len()
                && public_map[public_index].0 < scalar_map[scalar_index].0);
        if take_public {
            let (canonical, raw_slot) = public_map[public_index];
            let value = raw_public_values[raw_slot as usize];
            value_hasher.update(&canonical.to_le_bytes());
            value_hasher.update(&[1]);
            value_hasher.update(&(public_index as u32).to_le_bytes());
            value_hasher.update(&value.c0.value().to_le_bytes());
            value_hasher.update(&value.c1.value().to_le_bytes());
            public_index += 1;
        } else {
            let (canonical, raw_slot) = scalar_map[scalar_index];
            let value = raw_scalar_values[raw_slot as usize];
            value_hasher.update(&canonical.to_le_bytes());
            value_hasher.update(&[2]);
            value_hasher.update(&(scalar_index as u32).to_le_bytes());
            value_hasher.update(&value.c0.value().to_le_bytes());
            value_hasher.update(&value.c1.value().to_le_bytes());
            scalar_index += 1;
        }
    }
    let instance_value_digest = *value_hasher.finalize().as_bytes();
    let mut instance_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_INSTANCE_DOMAIN);
    instance_hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
    instance_hasher.update(&topology.topology_digest);
    instance_hasher.update(&topology.public_input_count.to_le_bytes());
    instance_hasher.update(&topology.scalar_input_count.to_le_bytes());
    instance_hasher.update(&instance_value_digest);
    let reconstructed_instance = C6OperationPlanInstanceIdentity {
        version: C6_OPERATION_PLAN_VERSION,
        topology_digest: topology.topology_digest,
        public_input_count: topology.public_input_count,
        scalar_input_count: topology.scalar_input_count,
        instance_digest: *instance_hasher.finalize().as_bytes(),
    };
    if reconstructed_instance != expected_instance {
        return Err(C6TraceError::new(
            "C6 raw instance extraction does not reconstruct canonical instance identity",
        ));
    }

    let public_raw_ordinals: Vec<_> = public_map.iter().map(|&(_, raw)| raw).collect();
    let scalar_raw_ordinals: Vec<_> = scalar_map.iter().map(|&(_, raw)| raw).collect();
    let raw_public_input_count = u32::try_from(raw_public_values.len())
        .map_err(|_| C6TraceError::new("C6 raw public slot count exceeds u32"))?;
    let raw_scalar_input_count = u32::try_from(raw_scalar_values.len())
        .map_err(|_| C6TraceError::new("C6 raw scalar slot count exceeds u32"))?;
    let (artifact, expected_census) = encode_c6_instance_extraction_artifact(
        role,
        topology,
        raw_public_input_count,
        raw_scalar_input_count,
        &public_raw_ordinals,
        &scalar_raw_ordinals,
    )?;
    let decoded = artifact.decode(topology)?;
    if decoded.role != role
        || decoded.public_raw_ordinals != public_raw_ordinals
        || decoded.scalar_raw_ordinals != scalar_raw_ordinals
        || decoded.census != expected_census
    {
        return Err(C6TraceError::new(
            "C6 instance-extraction artifact roundtrip differs from compilation",
        ));
    }
    Ok(artifact)
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
    normalize_c6_operation_trace_impl(trace, manifest, None, None).map(|(plan, _, _)| plan)
}

/// Compile one canonical parameterized topology artifact while producing the
/// same exact-instance diagnostics as [`normalize_c6_operation_trace`].
///
/// The compiler remains a `c6-trace` development path. The artifact decoder
/// itself is available to ordinary client builds.
pub fn compile_c6_operation_trace(
    trace: &C6ProverTraceSnapshot,
    manifest: &C6TraceSourceManifest,
) -> Result<C6CompiledOperationPlan, C6TraceError> {
    compile_c6_operation_trace_for_role(trace, manifest, C6InstanceExtractionRole::Prover)
}

pub fn compile_c6_operation_trace_for_role(
    trace: &C6ProverTraceSnapshot,
    manifest: &C6TraceSourceManifest,
    role: C6InstanceExtractionRole,
) -> Result<C6CompiledOperationPlan, C6TraceError> {
    let (plan, artifact, instance_extraction) =
        normalize_c6_operation_trace_impl(trace, manifest, None, Some(role))?;
    Ok(C6CompiledOperationPlan {
        plan,
        artifact: artifact
            .ok_or_else(|| C6TraceError::new("C6 operation-plan compiler emitted no artifact"))?,
        instance_extraction: instance_extraction.ok_or_else(|| {
            C6TraceError::new("C6 operation-plan compiler emitted no instance-extraction artifact")
        })?,
    })
}

/// Targeted diagnostic twin of [`normalize_c6_operation_trace`]. The
/// captured block is informative only and cannot affect program identity.
#[doc(hidden)]
pub fn normalize_c6_operation_trace_debug_block(
    trace: &C6ProverTraceSnapshot,
    manifest: &C6TraceSourceManifest,
    block: u64,
) -> Result<C6CanonicalOperationPlan, C6TraceError> {
    normalize_c6_operation_trace_impl(trace, manifest, Some(block), None).map(|(plan, _, _)| plan)
}

fn normalize_c6_operation_trace_impl(
    trace: &C6ProverTraceSnapshot,
    manifest: &C6TraceSourceManifest,
    capture_block: Option<u64>,
    compile_role: Option<C6InstanceExtractionRole>,
) -> Result<
    (
        C6CanonicalOperationPlan,
        Option<C6OperationPlanArtifact>,
        Option<C6InstanceExtractionArtifact>,
    ),
    C6TraceError,
> {
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
        let mut terminal_payload_bytes = 0u64;
        let mut normalizer =
            C6TraceNormalizer::new(trace, manifest, capture_block, compile_role.is_some())?;
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
            terminal_payload_bytes = terminal_payload_bytes
                .checked_add(uleb128_u64_len(triple_count))
                .ok_or_else(|| C6TraceError::new("C6 terminal encoding byte count overflows"))?;
            if let Some(encoder) = &mut normalizer.encoder {
                encoder.terminal_count(triple_count);
            }
            root_hasher.update(&(closure_index as u64).to_le_bytes());
            root_hasher.update(&triple_count.to_le_bytes());
            for (triple_index, triple) in closure.triples.iter().enumerate() {
                for (operand_index, &operand) in triple.iter().enumerate() {
                    normalizer.current_terminal = Some(C6CanonicalTerminalDebug::ProductOperand {
                        closure: closure_index as u64,
                        triple: triple_index as u64,
                        operand: operand_index as u8,
                    });
                    let canonical = normalizer.normalize_root(operand, true)?;
                    root_hasher.update(&canonical.to_le_bytes());
                    terminal_payload_bytes =
                        terminal_payload_bytes.checked_add(uleb128_u32_len(canonical)).ok_or_else(
                            || C6TraceError::new("C6 terminal encoding byte count overflows"),
                        )?;
                    if let Some(encoder) = &mut normalizer.encoder {
                        encoder.terminal_node(canonical);
                    }
                }
            }
            normalizer.current_terminal =
                Some(C6CanonicalTerminalDebug::ProductMask { closure: closure_index as u64 });
            let canonical_mask = normalizer.normalize_root(closure.mask, false)?;
            root_hasher.update(&canonical_mask.to_le_bytes());
            terminal_payload_bytes = terminal_payload_bytes
                .checked_add(uleb128_u32_len(canonical_mask))
                .ok_or_else(|| C6TraceError::new("C6 terminal encoding byte count overflows"))?;
            if let Some(encoder) = &mut normalizer.encoder {
                encoder.terminal_node(canonical_mask);
            }
        }
        let product_phase_node_count = u64::from(normalizer.canonical_node_count);

        root_hasher.update(&zero_root_count.to_le_bytes());
        for (index, &root) in trace.zero_roots.iter().enumerate() {
            normalizer.current_terminal =
                Some(C6CanonicalTerminalDebug::ZeroRoot { index: index as u64 });
            let canonical = normalizer.normalize_root(root, true)?;
            root_hasher.update(&canonical.to_le_bytes());
            terminal_payload_bytes = terminal_payload_bytes
                .checked_add(uleb128_u32_len(canonical))
                .ok_or_else(|| C6TraceError::new("C6 terminal encoding byte count overflows"))?;
            if let Some(encoder) = &mut normalizer.encoder {
                encoder.terminal_node(canonical);
            }
        }
        normalizer.current_terminal = None;

        let raw_operation_count = u64::try_from(trace.nodes.len())
            .map_err(|_| C6TraceError::new("C6 raw operation count exceeds u64"))?;
        let omitted_operation_count = raw_operation_count
            .checked_sub(normalizer.reachable_operation_count)
            .ok_or_else(|| C6TraceError::new("C6 reachable operation count exceeds raw count"))?;
        normalizer.finish_node_blocks();
        let node_digest = *normalizer.node_hasher.finalize().as_bytes();
        let topology_node_digest = *normalizer.topology_node_hasher.finalize().as_bytes();
        let instance_value_digest = *normalizer.instance_value_hasher.finalize().as_bytes();
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

        if normalizer.node_kinds.total() != u64::from(normalizer.canonical_node_count) {
            return Err(C6TraceError::new("C6 canonical node-kind census differs from node count"));
        }
        let mut topology_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_PLAN_DOMAIN);
        topology_hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        topology_hasher.update(&manifest.source_count.to_le_bytes());
        topology_hasher.update(&manifest.source_schedule_digest);
        topology_hasher.update(&normalizer.canonical_node_count.to_le_bytes());
        topology_hasher.update(&normalizer.public_input_count.to_le_bytes());
        topology_hasher.update(&normalizer.scalar_input_count.to_le_bytes());
        topology_hasher.update(&product_closure_count.to_le_bytes());
        topology_hasher.update(&product_triple_count.to_le_bytes());
        topology_hasher.update(&zero_root_count.to_le_bytes());
        topology_hasher.update(&topology_node_digest);
        topology_hasher.update(&root_digest);
        let topology_digest = *topology_hasher.finalize().as_bytes();

        let mut instance_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_INSTANCE_DOMAIN);
        instance_hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        instance_hasher.update(&topology_digest);
        instance_hasher.update(&normalizer.public_input_count.to_le_bytes());
        instance_hasher.update(&normalizer.scalar_input_count.to_le_bytes());
        instance_hasher.update(&instance_value_digest);
        let instance_digest = *instance_hasher.finalize().as_bytes();

        let packed_opcode_bits = u64::from(normalizer.canonical_node_count)
            .checked_mul(3)
            .ok_or_else(|| C6TraceError::new("C6 packed opcode bit count overflows"))?;
        let packed_opcode_bytes = packed_opcode_bits
            .checked_add(7)
            .ok_or_else(|| C6TraceError::new("C6 packed opcode byte count overflows"))?
            / 8;
        let candidate_total_bytes = C6_OPERATION_PARAMETERIZED_HEADER_BYTES
            .checked_add(packed_opcode_bytes)
            .and_then(|bytes| bytes.checked_add(normalizer.source_payload_bytes))
            .and_then(|bytes| bytes.checked_add(normalizer.linear_operand_payload_bytes))
            .and_then(|bytes| bytes.checked_add(terminal_payload_bytes))
            .ok_or_else(|| C6TraceError::new("C6 candidate plan byte count overflows"))?;
        let candidate_encoding = C6OperationPlanEncodingCensus {
            header_bytes: C6_OPERATION_PARAMETERIZED_HEADER_BYTES,
            packed_opcode_bytes,
            source_payload_bytes: normalizer.source_payload_bytes,
            linear_operand_payload_bytes: normalizer.linear_operand_payload_bytes,
            terminal_payload_bytes,
            total_bytes: candidate_total_bytes,
        };
        let operand_unit_flag_bytes = normalizer
            .operand_count
            .checked_add(7)
            .ok_or_else(|| C6TraceError::new("C6 operand-flag byte count overflows"))?
            / 8;
        let specialized_total_bytes = C6_OPERATION_PARAMETERIZED_HEADER_BYTES
            .checked_add(packed_opcode_bytes)
            .and_then(|bytes| bytes.checked_add(normalizer.source_delta_payload_bytes))
            .and_then(|bytes| bytes.checked_add(operand_unit_flag_bytes))
            .and_then(|bytes| bytes.checked_add(normalizer.nonunit_operand_payload_bytes))
            .and_then(|bytes| bytes.checked_add(terminal_payload_bytes))
            .ok_or_else(|| C6TraceError::new("C6 specialized plan byte count overflows"))?;
        let specialized_encoding_projection = C6OperationPlanSpecializedEncodingCensus {
            header_bytes: C6_OPERATION_PARAMETERIZED_HEADER_BYTES,
            packed_opcode_bytes,
            source_delta_payload_bytes: normalizer.source_delta_payload_bytes,
            operand_unit_flag_bytes,
            nonunit_operand_payload_bytes: normalizer.nonunit_operand_payload_bytes,
            terminal_payload_bytes,
            total_bytes: specialized_total_bytes,
            source_successor_count: normalizer.source_successor_count,
            operand_count: normalizer.operand_count,
            unit_operand_count: normalizer.unit_operand_count,
        };

        let topology = C6OperationPlanTopologyIdentity {
            version: C6_OPERATION_PLAN_VERSION,
            source_count: manifest.source_count,
            source_schedule_digest: manifest.source_schedule_digest,
            canonical_node_count: normalizer.canonical_node_count,
            public_input_count: normalizer.public_input_count,
            scalar_input_count: normalizer.scalar_input_count,
            product_closure_count,
            product_triple_count,
            zero_root_count,
            topology_digest,
        };
        let instance = C6OperationPlanInstanceIdentity {
            version: C6_OPERATION_PLAN_VERSION,
            topology_digest,
            public_input_count: normalizer.public_input_count,
            scalar_input_count: normalizer.scalar_input_count,
            instance_digest,
        };
        let instance_extraction = compile_role
            .map(|role| compile_c6_instance_extraction(&normalizer, role, topology, instance))
            .transpose()?;
        let artifact = normalizer
            .encoder
            .take()
            .map(|encoder| encoder.finish(topology, specialized_encoding_projection))
            .transpose()?;
        let plan = C6CanonicalOperationPlan {
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
            topology,
            instance,
            diagnostics: C6OperationPlanDiagnostics {
                raw_operation_count,
                reachable_operation_count: normalizer.reachable_operation_count,
                omitted_operation_count,
                node_digest,
                root_digest,
                canonical_node_block_digests: normalizer.node_block_digests,
                captured_canonical_nodes: normalizer.captured_nodes,
                node_kinds: normalizer.node_kinds,
                product_phase_node_count,
                topology_node_digest,
                instance_value_digest,
                candidate_encoding,
                specialized_encoding_projection,
            },
        };
        return Ok((plan, artifact, instance_extraction));
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (trace, manifest, capture_block, compile_role);
        Err(C6TraceError::new(
            "C6 operation-plan normalization requires the diagnostic c6-trace feature",
        ))
    }
}

struct C6ByteCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> C6ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], C6TraceError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| C6TraceError::new("C6 operation-plan cursor overflows"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| C6TraceError::new("truncated C6 operation-plan artifact"))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, C6TraceError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, C6TraceError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| C6TraceError::new("truncated C6 u32"))?,
        ))
    }

    fn u64(&mut self) -> Result<u64, C6TraceError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| C6TraceError::new("truncated C6 u64"))?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], C6TraceError> {
        self.take(32)?.try_into().map_err(|_| C6TraceError::new("truncated C6 digest"))
    }
}

struct C6BitReader<'a> {
    bytes: &'a [u8],
    bits: u64,
}

impl<'a> C6BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bits: 0 }
    }

    fn read(&mut self, width: u8) -> Result<u8, C6TraceError> {
        if width == 0 || width > 8 {
            return Err(C6TraceError::new("invalid C6 packed-bit width"));
        }
        let end = self
            .bits
            .checked_add(u64::from(width))
            .ok_or_else(|| C6TraceError::new("C6 packed-bit cursor overflows"))?;
        if end
            > u64::try_from(self.bytes.len())
                .map_err(|_| C6TraceError::new("C6 packed section exceeds u64"))?
                .saturating_mul(8)
        {
            return Err(C6TraceError::new("truncated C6 packed-bit section"));
        }
        let mut value = 0u8;
        for shift in 0..width {
            let bit = self.bits + u64::from(shift);
            let byte_index = usize::try_from(bit / 8)
                .map_err(|_| C6TraceError::new("C6 packed-bit index exceeds usize"))?;
            value |= ((self.bytes[byte_index] >> (bit % 8)) & 1) << shift;
        }
        self.bits = end;
        Ok(value)
    }

    fn finish(&self, expected_bits: u64, label: &str) -> Result<(), C6TraceError> {
        if self.bits != expected_bits {
            return Err(C6TraceError::new(format!(
                "C6 {label} bit count differs from decoded program"
            )));
        }
        let expected_bytes = expected_bits
            .checked_add(7)
            .ok_or_else(|| C6TraceError::new(format!("C6 {label} byte count overflows")))?
            / 8;
        if u64::try_from(self.bytes.len())
            .map_err(|_| C6TraceError::new(format!("C6 {label} length exceeds u64")))?
            != expected_bytes
        {
            return Err(C6TraceError::new(format!("C6 {label} section has noncanonical length")));
        }
        if expected_bits % 8 != 0 {
            let used = (expected_bits % 8) as u8;
            let padding_mask = !((1u8 << used) - 1);
            if self.bytes.last().is_some_and(|byte| byte & padding_mask != 0) {
                return Err(C6TraceError::new(format!("C6 {label} section has nonzero padding")));
            }
        }
        Ok(())
    }
}

struct C6UlebReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> C6UlebReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, label: &str) -> Result<u64, C6TraceError> {
        let start = self.position;
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or_else(|| C6TraceError::new(format!("truncated C6 {label} ULEB128")))?;
            self.position += 1;
            let payload = u64::from(byte & 0x7f);
            if shift >= 64 || payload > (u64::MAX >> shift) {
                return Err(C6TraceError::new(format!("C6 {label} ULEB128 overflows")));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                let consumed = self.position - start;
                if u64::try_from(consumed)
                    .map_err(|_| C6TraceError::new("C6 ULEB128 length exceeds u64"))?
                    != uleb128_u64_len(value)
                {
                    return Err(C6TraceError::new(format!("C6 {label} ULEB128 is nonminimal")));
                }
                return Ok(value);
            }
            shift = shift
                .checked_add(7)
                .ok_or_else(|| C6TraceError::new(format!("C6 {label} ULEB128 shift overflows")))?;
            if self.position - start >= 10 {
                return Err(C6TraceError::new(format!("C6 {label} ULEB128 is too long")));
            }
        }
    }

    fn finish(&self, label: &str) -> Result<(), C6TraceError> {
        if self.position != self.bytes.len() {
            return Err(C6TraceError::new(format!("C6 {label} section has trailing bytes")));
        }
        Ok(())
    }
}

fn c6_bitset_len(bits: u32) -> Result<usize, C6TraceError> {
    let bytes = u64::from(bits)
        .checked_add(7)
        .ok_or_else(|| C6TraceError::new("C6 bitset length overflows"))?
        / 8;
    usize::try_from(bytes).map_err(|_| C6TraceError::new("C6 bitset length exceeds usize"))
}

fn c6_try_vec_with_capacity<T>(capacity: u64, label: &str) -> Result<Vec<T>, C6TraceError> {
    let capacity = usize::try_from(capacity)
        .map_err(|_| C6TraceError::new(format!("C6 {label} capacity exceeds usize")))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| C6TraceError::new(format!("C6 {label} allocation failed")))?;
    Ok(values)
}

fn c6_bitset_get(bits: &[u8], index: u32) -> bool {
    bits[index as usize / 8] & (1 << (index % 8)) != 0
}

fn c6_bitset_insert(bits: &mut [u8], index: u32) -> bool {
    let byte = &mut bits[index as usize / 8];
    let mask = 1 << (index % 8);
    let fresh = *byte & mask == 0;
    *byte |= mask;
    fresh
}

fn c6_unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn c6_section<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: u64,
) -> Result<&'a [u8], C6TraceError> {
    let length = usize::try_from(length)
        .map_err(|_| C6TraceError::new("C6 operation-plan section exceeds usize"))?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| C6TraceError::new("C6 operation-plan section offset overflows"))?;
    let section = bytes
        .get(*offset..end)
        .ok_or_else(|| C6TraceError::new("truncated C6 operation-plan section"))?;
    *offset = end;
    Ok(section)
}

fn decode_c6_instance_map_section(
    bytes: &[u8],
    raw_count: u32,
    canonical_count: u32,
    label: &str,
) -> Result<(Vec<u32>, u32), C6TraceError> {
    let mut input = C6UlebReader::new(bytes);
    let run_count = input.read(label)?;
    let run_count = u32::try_from(run_count)
        .map_err(|_| C6TraceError::new(format!("C6 {label} run count exceeds u32")))?;
    if (canonical_count == 0 && run_count != 0)
        || (canonical_count != 0 && (run_count == 0 || run_count > canonical_count))
    {
        return Err(C6TraceError::new(format!(
            "C6 {label} run count differs from canonical slot census"
        )));
    }
    let mut ordinals = Vec::with_capacity(canonical_count as usize);
    let mut seen = vec![0u8; c6_bitset_len(raw_count)?];
    let mut expected_next = 0i64;
    for run_index in 0..run_count {
        let delta = c6_unzigzag(input.read(label)?);
        if run_index != 0 && delta == 0 {
            return Err(C6TraceError::new(format!("C6 {label} contains adjacent mergeable runs")));
        }
        let start = expected_next
            .checked_add(delta)
            .ok_or_else(|| C6TraceError::new(format!("C6 {label} run start overflows")))?;
        if start < 0 || start >= i64::from(raw_count) {
            return Err(C6TraceError::new(format!(
                "C6 {label} run starts outside the raw slot census"
            )));
        }
        let length = input
            .read(label)?
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new(format!("C6 {label} run length overflows")))?;
        let length = u32::try_from(length)
            .map_err(|_| C6TraceError::new(format!("C6 {label} run length exceeds u32")))?;
        let start = start as u32;
        let end = start
            .checked_add(length)
            .ok_or_else(|| C6TraceError::new(format!("C6 {label} run end overflows")))?;
        if end > raw_count
            || ordinals
                .len()
                .checked_add(length as usize)
                .is_none_or(|count| count > canonical_count as usize)
        {
            return Err(C6TraceError::new(format!(
                "C6 {label} run exceeds its raw or canonical census"
            )));
        }
        for raw in start..end {
            if !c6_bitset_insert(&mut seen, raw) {
                return Err(C6TraceError::new(format!(
                    "C6 {label} maps one raw slot more than once"
                )));
            }
            ordinals.push(raw);
        }
        expected_next = i64::from(end);
    }
    input.finish(label)?;
    if ordinals.len() != canonical_count as usize {
        return Err(C6TraceError::new(format!("C6 {label} does not cover every canonical slot")));
    }
    Ok((ordinals, run_count))
}

fn decode_c6_instance_extraction_artifact(
    bytes: &[u8],
    topology: C6OperationPlanTopologyIdentity,
) -> Result<C6DecodedInstanceExtractionPlan, C6TraceError> {
    let header_len = usize::try_from(C6_INSTANCE_EXTRACTION_HEADER_BYTES)
        .map_err(|_| C6TraceError::new("C6 instance-extraction header exceeds usize"))?;
    let header_bytes = bytes
        .get(..header_len)
        .ok_or_else(|| C6TraceError::new("truncated C6 instance-extraction header"))?;
    let mut header = C6ByteCursor::new(header_bytes);
    if header.take(8)? != C6_INSTANCE_EXTRACTION_CODEC_MAGIC {
        return Err(C6TraceError::new("wrong C6 instance-extraction codec magic"));
    }
    if header.u32()? != C6_INSTANCE_EXTRACTION_CODEC_VERSION {
        return Err(C6TraceError::new("wrong C6 instance-extraction codec version"));
    }
    if header.u32()? != C6_OPERATION_PLAN_VERSION || topology.version != C6_OPERATION_PLAN_VERSION {
        return Err(C6TraceError::new("wrong C6 instance-extraction operation-plan version"));
    }
    let role = C6InstanceExtractionRole::decode(header.u8()?)?;
    if header.take(3)? != [0; 3] {
        return Err(C6TraceError::new("nonzero C6 instance-extraction reserved header bytes"));
    }
    let topology_digest = header.digest()?;
    let raw_public_input_count = header.u32()?;
    let raw_scalar_input_count = header.u32()?;
    let canonical_public_input_count = header.u32()?;
    let canonical_scalar_input_count = header.u32()?;
    let claimed_map_digest = header.digest()?;
    let public_map_bytes = header.u64()?;
    let scalar_map_bytes = header.u64()?;
    if header.u32()? != 0 || header.position != header_len {
        return Err(C6TraceError::new("nonzero or trailing C6 instance-extraction header bytes"));
    }
    if topology_digest != topology.topology_digest
        || canonical_public_input_count != topology.public_input_count
        || canonical_scalar_input_count != topology.scalar_input_count
    {
        return Err(C6TraceError::new(
            "C6 instance-extraction header differs from topology identity",
        ));
    }
    if raw_public_input_count < canonical_public_input_count
        || raw_scalar_input_count < canonical_scalar_input_count
        || raw_public_input_count > topology.canonical_node_count
        || raw_scalar_input_count > topology.canonical_node_count
        || raw_public_input_count
            .checked_add(raw_scalar_input_count)
            .is_none_or(|count| count > topology.canonical_node_count)
    {
        return Err(C6TraceError::new(
            "C6 instance-extraction raw census is outside topology bounds",
        ));
    }
    let total_bytes = C6_INSTANCE_EXTRACTION_HEADER_BYTES
        .checked_add(public_map_bytes)
        .and_then(|value| value.checked_add(scalar_map_bytes))
        .ok_or_else(|| C6TraceError::new("C6 instance-extraction length overflows"))?;
    if total_bytes
        != u64::try_from(bytes.len())
            .map_err(|_| C6TraceError::new("C6 instance-extraction length exceeds u64"))?
    {
        return Err(C6TraceError::new(
            "C6 instance-extraction header length differs from artifact",
        ));
    }
    let mut offset = header_len;
    let public_section = c6_section(bytes, &mut offset, public_map_bytes)?;
    let scalar_section = c6_section(bytes, &mut offset, scalar_map_bytes)?;
    if offset != bytes.len() {
        return Err(C6TraceError::new("C6 instance-extraction artifact has trailing bytes"));
    }
    let (public_raw_ordinals, public_run_count) = decode_c6_instance_map_section(
        public_section,
        raw_public_input_count,
        canonical_public_input_count,
        "public instance map",
    )?;
    let (scalar_raw_ordinals, scalar_run_count) = decode_c6_instance_map_section(
        scalar_section,
        raw_scalar_input_count,
        canonical_scalar_input_count,
        "scalar instance map",
    )?;
    let map_digest = c6_instance_extraction_map_digest(
        role,
        topology,
        raw_public_input_count,
        raw_scalar_input_count,
        &public_raw_ordinals,
        &scalar_raw_ordinals,
    );
    if map_digest != claimed_map_digest {
        return Err(C6TraceError::new("C6 instance-extraction map digest mismatch"));
    }
    let census = C6InstanceExtractionCensus {
        raw_public_input_count,
        raw_scalar_input_count,
        canonical_public_input_count,
        canonical_scalar_input_count,
        public_run_count,
        scalar_run_count,
        header_bytes: C6_INSTANCE_EXTRACTION_HEADER_BYTES,
        public_map_bytes,
        scalar_map_bytes,
        total_bytes,
        map_digest,
    };
    Ok(C6DecodedInstanceExtractionPlan {
        role,
        topology_digest,
        public_raw_ordinals,
        scalar_raw_ordinals,
        census,
    })
}

fn reconstruct_c6_runtime_instance_identity(
    operation_plan: &C6OperationPlanArtifact,
    extraction: &C6DecodedInstanceExtractionPlan,
    raw_public_values: &[Fp2],
    raw_scalar_values: &[Fp2],
) -> Result<C6OperationPlanInstanceIdentity, C6TraceError> {
    if raw_public_values.len() != extraction.census.raw_public_input_count as usize
        || raw_scalar_values.len() != extraction.census.raw_scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 runtime instance values differ from the extraction raw census",
        ));
    }
    let header_len = usize::try_from(C6_OPERATION_PARAMETERIZED_HEADER_BYTES)
        .map_err(|_| C6TraceError::new("C6 operation-plan header exceeds usize"))?;
    let header_bytes = operation_plan
        .bytes
        .get(..header_len)
        .ok_or_else(|| C6TraceError::new("truncated C6 operation-plan header"))?;
    let mut header = C6ByteCursor::new(header_bytes);
    if header.take(8)? != C6_OPERATION_PLAN_CODEC_MAGIC
        || header.u32()? != C6_OPERATION_PLAN_CODEC_VERSION
    {
        return Err(C6TraceError::new(
            "C6 runtime instance received the wrong operation-plan codec",
        ));
    }
    let version = header.u32()?;
    if version != C6_OPERATION_PLAN_VERSION {
        return Err(C6TraceError::new(
            "C6 runtime instance received the wrong operation-plan version",
        ));
    }
    let _source_count = header.u32()?;
    let _source_schedule_digest = header.digest()?;
    let canonical_node_count = header.u32()?;
    let public_input_count = header.u32()?;
    let scalar_input_count = header.u32()?;
    let _product_closure_count = header.u32()?;
    let _product_triple_count = header.u64()?;
    let _zero_root_count = header.u32()?;
    let topology_digest = header.digest()?;
    let section_lengths =
        [header.u64()?, header.u64()?, header.u64()?, header.u64()?, header.u64()?];
    if header.position != header_len {
        return Err(C6TraceError::new(
            "C6 runtime instance operation-plan header has trailing bytes",
        ));
    }
    if topology_digest != extraction.topology_digest
        || public_input_count != extraction.census.canonical_public_input_count
        || scalar_input_count != extraction.census.canonical_scalar_input_count
        || extraction.public_raw_ordinals.len() != public_input_count as usize
        || extraction.scalar_raw_ordinals.len() != scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 runtime instance operation plan differs from the extraction map",
        ));
    }
    let expected_opcode_bytes = u64::from(canonical_node_count)
        .checked_mul(3)
        .and_then(|bits| bits.checked_add(7))
        .ok_or_else(|| C6TraceError::new("C6 runtime instance opcode length overflows"))?
        / 8;
    if section_lengths[0] != expected_opcode_bytes {
        return Err(C6TraceError::new(
            "C6 runtime instance opcode section differs from the node census",
        ));
    }
    let total_bytes = C6_OPERATION_PARAMETERIZED_HEADER_BYTES
        .checked_add(
            section_lengths
                .iter()
                .try_fold(0u64, |sum, &length| sum.checked_add(length))
                .ok_or_else(|| {
                    C6TraceError::new("C6 runtime instance operation-plan lengths overflow")
                })?,
        )
        .ok_or_else(|| {
            C6TraceError::new("C6 runtime instance operation-plan total length overflows")
        })?;
    let artifact_bytes = u64::try_from(operation_plan.bytes.len())
        .map_err(|_| C6TraceError::new("C6 runtime operation-plan length exceeds u64"))?;
    if total_bytes != artifact_bytes {
        return Err(C6TraceError::new(
            "C6 runtime instance operation-plan length differs from its header",
        ));
    }
    let mut offset = header_len;
    let opcode_section = c6_section(&operation_plan.bytes, &mut offset, section_lengths[0])?;
    let mut opcodes = C6BitReader::new(opcode_section);
    let instance = reconstruct_c6_runtime_instance_identity_from_opcodes(
        version,
        topology_digest,
        canonical_node_count,
        public_input_count,
        scalar_input_count,
        extraction,
        raw_public_values,
        raw_scalar_values,
        |_| opcodes.read(3),
    )?;
    let opcode_bits = u64::from(canonical_node_count)
        .checked_mul(3)
        .ok_or_else(|| C6TraceError::new("C6 runtime opcode bit count overflows"))?;
    opcodes.finish(opcode_bits, "runtime instance opcode")?;
    Ok(instance)
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_c6_runtime_instance_identity_from_opcodes(
    version: u32,
    topology_digest: [u8; 32],
    canonical_node_count: u32,
    public_input_count: u32,
    scalar_input_count: u32,
    extraction: &C6DecodedInstanceExtractionPlan,
    raw_public_values: &[Fp2],
    raw_scalar_values: &[Fp2],
    mut opcode_at: impl FnMut(u32) -> Result<u8, C6TraceError>,
) -> Result<C6OperationPlanInstanceIdentity, C6TraceError> {
    if version != C6_OPERATION_PLAN_VERSION
        || topology_digest != extraction.topology_digest
        || public_input_count != extraction.census.canonical_public_input_count
        || scalar_input_count != extraction.census.canonical_scalar_input_count
        || extraction.public_raw_ordinals.len() != public_input_count as usize
        || extraction.scalar_raw_ordinals.len() != scalar_input_count as usize
        || raw_public_values.len() != extraction.census.raw_public_input_count as usize
        || raw_scalar_values.len() != extraction.census.raw_scalar_input_count as usize
    {
        return Err(C6TraceError::new(
            "C6 runtime instance inputs differ from the installed plan and extraction map",
        ));
    }
    let mut public_slot = 0u32;
    let mut scalar_slot = 0u32;
    let mut value_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_INSTANCE_VALUE_DOMAIN);
    for canonical in 0..canonical_node_count {
        match opcode_at(canonical)? {
            1 | 2 | 4 | 5 => {}
            3 => {
                let raw = *extraction
                    .public_raw_ordinals
                    .get(public_slot as usize)
                    .ok_or_else(|| C6TraceError::new("C6 runtime public slot count overflows"))?;
                let value = *raw_public_values.get(raw as usize).ok_or_else(|| {
                    C6TraceError::new("C6 runtime public map points outside the raw stream")
                })?;
                value_hasher.update(&canonical.to_le_bytes());
                value_hasher.update(&[1]);
                value_hasher.update(&public_slot.to_le_bytes());
                value_hasher.update(&value.c0.value().to_le_bytes());
                value_hasher.update(&value.c1.value().to_le_bytes());
                public_slot = public_slot
                    .checked_add(1)
                    .ok_or_else(|| C6TraceError::new("C6 runtime public slot count overflows"))?;
            }
            6 => {
                let raw = *extraction
                    .scalar_raw_ordinals
                    .get(scalar_slot as usize)
                    .ok_or_else(|| C6TraceError::new("C6 runtime scalar slot count overflows"))?;
                let value = *raw_scalar_values.get(raw as usize).ok_or_else(|| {
                    C6TraceError::new("C6 runtime scalar map points outside the raw stream")
                })?;
                value_hasher.update(&canonical.to_le_bytes());
                value_hasher.update(&[2]);
                value_hasher.update(&scalar_slot.to_le_bytes());
                value_hasher.update(&value.c0.value().to_le_bytes());
                value_hasher.update(&value.c1.value().to_le_bytes());
                scalar_slot = scalar_slot
                    .checked_add(1)
                    .ok_or_else(|| C6TraceError::new("C6 runtime scalar slot count overflows"))?;
            }
            _ => {
                return Err(C6TraceError::new(
                    "C6 runtime instance encountered a reserved operation-plan opcode",
                ));
            }
        }
    }
    if public_slot != public_input_count || scalar_slot != scalar_input_count {
        return Err(C6TraceError::new(
            "C6 runtime instance slot counts differ from the operation plan",
        ));
    }
    let instance_value_digest = *value_hasher.finalize().as_bytes();
    let mut instance_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_INSTANCE_DOMAIN);
    instance_hasher.update(&version.to_le_bytes());
    instance_hasher.update(&topology_digest);
    instance_hasher.update(&public_input_count.to_le_bytes());
    instance_hasher.update(&scalar_input_count.to_le_bytes());
    instance_hasher.update(&instance_value_digest);
    Ok(C6OperationPlanInstanceIdentity {
        version,
        topology_digest,
        public_input_count,
        scalar_input_count,
        instance_digest: *instance_hasher.finalize().as_bytes(),
    })
}

fn decode_c6_operation_plan_artifact(
    bytes: &[u8],
    manifest: &C6TraceSourceManifest,
) -> Result<C6DecodedOperationPlan, C6TraceError> {
    decode_c6_operation_plan_artifact_impl(bytes, manifest, false).map(|(decoded, _)| decoded)
}

fn decode_c6_operation_plan_artifact_impl(
    bytes: &[u8],
    manifest: &C6TraceSourceManifest,
    install: bool,
) -> Result<(C6DecodedOperationPlan, Option<C6OperationPlanInstallData>), C6TraceError> {
    let header_len = usize::try_from(C6_OPERATION_PARAMETERIZED_HEADER_BYTES)
        .map_err(|_| C6TraceError::new("C6 operation-plan header exceeds usize"))?;
    let header_bytes = bytes
        .get(..header_len)
        .ok_or_else(|| C6TraceError::new("truncated C6 operation-plan header"))?;
    let mut header = C6ByteCursor::new(header_bytes);
    if header.take(8)? != C6_OPERATION_PLAN_CODEC_MAGIC {
        return Err(C6TraceError::new("wrong C6 operation-plan codec magic"));
    }
    if header.u32()? != C6_OPERATION_PLAN_CODEC_VERSION {
        return Err(C6TraceError::new("wrong C6 operation-plan codec version"));
    }
    let version = header.u32()?;
    if version != C6_OPERATION_PLAN_VERSION {
        return Err(C6TraceError::new("wrong C6 operation-plan topology version"));
    }
    let source_count = header.u32()?;
    let source_schedule_digest = header.digest()?;
    let canonical_node_count = header.u32()?;
    let public_input_count = header.u32()?;
    let scalar_input_count = header.u32()?;
    let product_closure_count = header.u32()?;
    let product_triple_count = header.u64()?;
    let zero_root_count = header.u32()?;
    let claimed_topology_digest = header.digest()?;
    let section_lengths =
        [header.u64()?, header.u64()?, header.u64()?, header.u64()?, header.u64()?];
    if header.position != header_len {
        return Err(C6TraceError::new("C6 operation-plan header has trailing bytes"));
    }
    if source_count != manifest.source_count
        || source_schedule_digest != manifest.source_schedule_digest
    {
        return Err(C6TraceError::new("C6 operation-plan header differs from source manifest"));
    }
    if usize::try_from(product_closure_count)
        .map_err(|_| C6TraceError::new("C6 ProductClosure count exceeds usize"))?
        != manifest.product_mask_sources.len()
    {
        return Err(C6TraceError::new(
            "C6 operation-plan ProductClosure count differs from mask manifest",
        ));
    }
    let expected_opcode_bytes = u64::from(canonical_node_count)
        .checked_mul(3)
        .and_then(|bits| bits.checked_add(7))
        .ok_or_else(|| C6TraceError::new("C6 operation-plan opcode length overflows"))?
        / 8;
    if section_lengths[0] != expected_opcode_bytes {
        return Err(C6TraceError::new(
            "C6 operation-plan opcode section length differs from node census",
        ));
    }
    let claimed_total = C6_OPERATION_PARAMETERIZED_HEADER_BYTES
        .checked_add(
            section_lengths
                .iter()
                .try_fold(0u64, |sum, &length| sum.checked_add(length))
                .ok_or_else(|| C6TraceError::new("C6 operation-plan section lengths overflow"))?,
        )
        .ok_or_else(|| C6TraceError::new("C6 operation-plan total length overflows"))?;
    if claimed_total
        != u64::try_from(bytes.len())
            .map_err(|_| C6TraceError::new("C6 operation-plan length exceeds u64"))?
    {
        return Err(C6TraceError::new("C6 operation-plan header length differs from artifact"));
    }

    let mut offset = header_len;
    let opcode_section = c6_section(bytes, &mut offset, section_lengths[0])?;
    let source_section = c6_section(bytes, &mut offset, section_lengths[1])?;
    let operand_flag_section = c6_section(bytes, &mut offset, section_lengths[2])?;
    let operand_section = c6_section(bytes, &mut offset, section_lengths[3])?;
    let terminal_section = c6_section(bytes, &mut offset, section_lengths[4])?;
    if offset != bytes.len() {
        return Err(C6TraceError::new("C6 operation-plan artifact has trailing bytes"));
    }

    let mut opcodes = C6BitReader::new(opcode_section);
    let mut sources = C6UlebReader::new(source_section);
    let mut operand_flags = C6BitReader::new(operand_flag_section);
    let mut operands = C6UlebReader::new(operand_section);
    let mut node_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_NODE_DOMAIN);
    let mut node_kinds = C6CanonicalNodeKindCensus::default();
    let mut source_seen = vec![0u8; c6_bitset_len(source_count)?];
    let mut product_mask_nodes = vec![None; manifest.product_mask_sources.len()];
    let mut node_is_product_mask = vec![0u8; c6_bitset_len(canonical_node_count)?];
    let mut previous_source = -1i64;
    let mut source_successor_count = 0u64;
    let mut decoded_public_inputs = 0u32;
    let mut decoded_scalar_inputs = 0u32;
    let mut operand_count = 0u64;
    let mut unit_operand_count = 0u64;
    let mut installed = if install {
        Some(C6OperationPlanInstallData {
            opcodes: c6_try_vec_with_capacity(u64::from(canonical_node_count), "installed opcode")?,
            source_ordinals: c6_try_vec_with_capacity(u64::from(source_count), "installed source")?,
            operands: c6_try_vec_with_capacity(
                section_lengths[2]
                    .checked_mul(8)
                    .ok_or_else(|| C6TraceError::new("installed operand capacity overflows"))?,
                "installed operand",
            )?,
            products: c6_try_vec_with_capacity(
                u64::from(product_closure_count),
                "installed ProductClosure",
            )?,
            zero_roots: c6_try_vec_with_capacity(
                u64::from(zero_root_count),
                "installed zero root",
            )?,
        })
    } else {
        None
    };

    let decode_operand = |canonical: u32,
                          operand_flags: &mut C6BitReader<'_>,
                          operands: &mut C6UlebReader<'_>,
                          operand_count: &mut u64,
                          unit_operand_count: &mut u64|
     -> Result<u32, C6TraceError> {
        *operand_count = operand_count
            .checked_add(1)
            .ok_or_else(|| C6TraceError::new("decoded C6 operand count overflows"))?;
        let distance = if operand_flags.read(1)? == 0 {
            *unit_operand_count = unit_operand_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("decoded C6 unit-operand count overflows"))?;
            1u64
        } else {
            operands
                .read("operand")?
                .checked_add(2)
                .ok_or_else(|| C6TraceError::new("decoded C6 operand distance overflows"))?
        };
        let distance = u32::try_from(distance)
            .map_err(|_| C6TraceError::new("decoded C6 operand distance exceeds u32"))?;
        canonical
            .checked_sub(distance)
            .ok_or_else(|| C6TraceError::new("decoded C6 operand is not a prior node"))
    };

    for canonical in 0..canonical_node_count {
        let tag = opcodes.read(3)?;
        if let Some(installed) = installed.as_mut() {
            installed.opcodes.push(C6InstalledOperationKind::decode(tag)?);
        }
        node_hasher.update(&canonical.to_le_bytes());
        node_hasher.update(&[tag]);
        match tag {
            1 => {
                let delta = c6_unzigzag(sources.read("source delta")?);
                let source = previous_source
                    .checked_add(delta)
                    .ok_or_else(|| C6TraceError::new("decoded C6 source delta overflows"))?;
                if source < 0 || source >= i64::from(source_count) {
                    return Err(C6TraceError::new(
                        "decoded C6 source is outside the source manifest",
                    ));
                }
                let source = source as u32;
                if !c6_bitset_insert(&mut source_seen, source) {
                    return Err(C6TraceError::new("duplicate decoded C6 source node"));
                }
                if delta == 1 {
                    source_successor_count =
                        source_successor_count.checked_add(1).ok_or_else(|| {
                            C6TraceError::new("decoded C6 source-successor count overflows")
                        })?;
                }
                previous_source = i64::from(source);
                if let Some(installed) = installed.as_mut() {
                    installed.source_ordinals.push(source);
                }
                node_hasher.update(&source.to_le_bytes());
                node_kinds.source += 1;
                if let Ok(mask_index) = manifest.product_mask_sources.binary_search(&source) {
                    if product_mask_nodes[mask_index].replace(canonical).is_some() {
                        return Err(C6TraceError::new("duplicate decoded C6 ProductMask source"));
                    }
                    c6_bitset_insert(&mut node_is_product_mask, canonical);
                }
            }
            2 => {
                node_kinds.structural_zero += 1;
                if node_kinds.structural_zero > 1 {
                    return Err(C6TraceError::new(
                        "decoded C6 plan contains multiple structural zeros",
                    ));
                }
            }
            3 => {
                node_hasher.update(&decoded_public_inputs.to_le_bytes());
                decoded_public_inputs = decoded_public_inputs
                    .checked_add(1)
                    .ok_or_else(|| C6TraceError::new("decoded C6 public slots overflow"))?;
                node_kinds.public_input += 1;
            }
            4 | 5 => {
                let lhs = decode_operand(
                    canonical,
                    &mut operand_flags,
                    &mut operands,
                    &mut operand_count,
                    &mut unit_operand_count,
                )?;
                let rhs = decode_operand(
                    canonical,
                    &mut operand_flags,
                    &mut operands,
                    &mut operand_count,
                    &mut unit_operand_count,
                )?;
                if let Some(installed) = installed.as_mut() {
                    installed.operands.extend_from_slice(&[lhs, rhs]);
                }
                if c6_bitset_get(&node_is_product_mask, lhs)
                    || c6_bitset_get(&node_is_product_mask, rhs)
                {
                    return Err(C6TraceError::new(
                        "decoded C6 ProductMask reaches a linear operation",
                    ));
                }
                node_hasher.update(&lhs.to_le_bytes());
                node_hasher.update(&rhs.to_le_bytes());
                if tag == 4 {
                    node_kinds.add += 1;
                } else {
                    node_kinds.sub += 1;
                }
            }
            6 => {
                let value = decode_operand(
                    canonical,
                    &mut operand_flags,
                    &mut operands,
                    &mut operand_count,
                    &mut unit_operand_count,
                )?;
                if let Some(installed) = installed.as_mut() {
                    installed.operands.push(value);
                }
                if c6_bitset_get(&node_is_product_mask, value) {
                    return Err(C6TraceError::new("decoded C6 ProductMask reaches a linear scale"));
                }
                node_hasher.update(&value.to_le_bytes());
                node_hasher.update(&decoded_scalar_inputs.to_le_bytes());
                decoded_scalar_inputs = decoded_scalar_inputs
                    .checked_add(1)
                    .ok_or_else(|| C6TraceError::new("decoded C6 scalar slots overflow"))?;
                node_kinds.scale += 1;
            }
            _ => return Err(C6TraceError::new("decoded C6 operation-plan opcode is reserved")),
        }
    }
    let opcode_bits = u64::from(canonical_node_count)
        .checked_mul(3)
        .ok_or_else(|| C6TraceError::new("decoded C6 opcode bit count overflows"))?;
    opcodes.finish(opcode_bits, "opcode")?;
    sources.finish("source-delta")?;
    operand_flags.finish(operand_count, "operand-flag")?;
    operands.finish("operand")?;
    if decoded_public_inputs != public_input_count
        || decoded_scalar_inputs != scalar_input_count
        || node_kinds.total() != u64::from(canonical_node_count)
    {
        return Err(C6TraceError::new(
            "decoded C6 node or instance-slot census differs from header",
        ));
    }
    let topology_node_digest = *node_hasher.finalize().as_bytes();

    let mut terminals = C6UlebReader::new(terminal_section);
    let mut root_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_ROOT_DOMAIN);
    root_hasher.update(&product_closure_count.to_le_bytes());
    let mut decoded_product_triples = 0u64;
    let mut product_max_node = None::<u32>;
    let read_terminal_node = |terminals: &mut C6UlebReader<'_>| -> Result<u32, C6TraceError> {
        let node = terminals.read("terminal node")?;
        let node = u32::try_from(node)
            .map_err(|_| C6TraceError::new("decoded C6 terminal node exceeds u32"))?;
        if node >= canonical_node_count {
            return Err(C6TraceError::new(
                "decoded C6 terminal node is outside the canonical plan",
            ));
        }
        Ok(node)
    };
    for closure_index in 0..product_closure_count {
        let triple_count = terminals.read("ProductClosure triple count")?;
        if triple_count == 0 {
            return Err(C6TraceError::new("decoded C6 ProductClosure is empty"));
        }
        decoded_product_triples = decoded_product_triples
            .checked_add(triple_count)
            .ok_or_else(|| C6TraceError::new("decoded C6 product triple count overflows"))?;
        root_hasher.update(&u64::from(closure_index).to_le_bytes());
        root_hasher.update(&triple_count.to_le_bytes());
        let mut installed_triples = install
            .then(|| c6_try_vec_with_capacity(triple_count, "installed product triple"))
            .transpose()?;
        for _ in 0..triple_count {
            let mut triple = [0u32; 3];
            for operand in &mut triple {
                let node = read_terminal_node(&mut terminals)?;
                if c6_bitset_get(&node_is_product_mask, node) {
                    return Err(C6TraceError::new("decoded C6 ProductMask is a product operand"));
                }
                *operand = node;
                product_max_node = Some(product_max_node.map_or(node, |value| value.max(node)));
                root_hasher.update(&node.to_le_bytes());
            }
            if let Some(installed_triples) = installed_triples.as_mut() {
                installed_triples.push(triple);
            }
        }
        let mask_node = read_terminal_node(&mut terminals)?;
        let mask_index = usize::try_from(closure_index)
            .map_err(|_| C6TraceError::new("C6 closure index exceeds usize"))?;
        if product_mask_nodes.get(mask_index).copied().flatten() != Some(mask_node) {
            return Err(C6TraceError::new(
                "decoded C6 ProductClosure mask differs from canonical manifest",
            ));
        }
        product_max_node = Some(product_max_node.map_or(mask_node, |value| value.max(mask_node)));
        root_hasher.update(&mask_node.to_le_bytes());
        if let Some(installed) = installed.as_mut() {
            installed.products.push(C6InstalledProductClosure {
                triples: installed_triples.ok_or_else(|| {
                    C6TraceError::new("installed C6 ProductClosure lost its triples")
                })?,
                mask: mask_node,
            });
        }
    }
    if decoded_product_triples != product_triple_count {
        return Err(C6TraceError::new("decoded C6 product triple count differs from header"));
    }
    if product_mask_nodes.iter().any(Option::is_none) {
        return Err(C6TraceError::new("decoded C6 plan omits a ProductMask source"));
    }
    let product_phase_node_count = product_max_node
        .and_then(|node| node.checked_add(1))
        .map(u64::from)
        .ok_or_else(|| C6TraceError::new("decoded C6 product phase is empty or overflows"))?;

    root_hasher.update(&zero_root_count.to_le_bytes());
    for _ in 0..zero_root_count {
        let node = read_terminal_node(&mut terminals)?;
        if c6_bitset_get(&node_is_product_mask, node) {
            return Err(C6TraceError::new("decoded C6 ProductMask is a zero root"));
        }
        root_hasher.update(&node.to_le_bytes());
        if let Some(installed) = installed.as_mut() {
            installed.zero_roots.push(node);
        }
    }
    terminals.finish("terminal")?;
    let root_digest = *root_hasher.finalize().as_bytes();

    let mut topology_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_PLAN_DOMAIN);
    topology_hasher.update(&version.to_le_bytes());
    topology_hasher.update(&source_count.to_le_bytes());
    topology_hasher.update(&source_schedule_digest);
    topology_hasher.update(&canonical_node_count.to_le_bytes());
    topology_hasher.update(&public_input_count.to_le_bytes());
    topology_hasher.update(&scalar_input_count.to_le_bytes());
    topology_hasher.update(&product_closure_count.to_le_bytes());
    topology_hasher.update(&product_triple_count.to_le_bytes());
    topology_hasher.update(&zero_root_count.to_le_bytes());
    topology_hasher.update(&topology_node_digest);
    topology_hasher.update(&root_digest);
    let topology_digest = *topology_hasher.finalize().as_bytes();
    if topology_digest != claimed_topology_digest {
        return Err(C6TraceError::new("decoded C6 topology digest mismatch"));
    }
    let topology = C6OperationPlanTopologyIdentity {
        version,
        source_count,
        source_schedule_digest,
        canonical_node_count,
        public_input_count,
        scalar_input_count,
        product_closure_count,
        product_triple_count,
        zero_root_count,
        topology_digest,
    };
    let encoding = C6OperationPlanSpecializedEncodingCensus {
        header_bytes: C6_OPERATION_PARAMETERIZED_HEADER_BYTES,
        packed_opcode_bytes: section_lengths[0],
        source_delta_payload_bytes: section_lengths[1],
        operand_unit_flag_bytes: section_lengths[2],
        nonunit_operand_payload_bytes: section_lengths[3],
        terminal_payload_bytes: section_lengths[4],
        total_bytes: claimed_total,
        source_successor_count,
        operand_count,
        unit_operand_count,
    };
    if let Some(data) = installed.as_ref() {
        if data.opcodes.len() != canonical_node_count as usize
            || data.source_ordinals.len() as u64 != node_kinds.source
            || data.operands.len() as u64 != operand_count
            || data.products.len() != product_closure_count as usize
            || data.zero_roots.len() != zero_root_count as usize
        {
            return Err(C6TraceError::new(
                "installed C6 operation-plan arrays differ from the decoded census",
            ));
        }
    }
    Ok((
        C6DecodedOperationPlan { topology, node_kinds, product_phase_node_count, encoding },
        installed,
    ))
}

impl C6TraceToken {
    pub(crate) const fn untracked() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self { namespace: 0, handle: 0 }
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    pub(crate) const fn public_zero() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self { namespace: 0, handle: PUBLIC_ZERO_TOKEN }
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    #[cfg(feature = "c6-trace")]
    fn is_untracked(self) -> bool {
        self.handle == 0
    }

    #[cfg(feature = "c6-trace")]
    fn is_source(self) -> bool {
        self.handle & SOURCE_TOKEN_BIT != 0
    }

    #[cfg(feature = "c6-trace")]
    fn belongs_to(self, namespace: u32) -> bool {
        self == Self::public_zero() || self.namespace == namespace
    }

    pub fn source_index(self) -> Option<u32> {
        #[cfg(feature = "c6-trace")]
        {
            return self.is_source().then_some((self.handle & SOURCE_TOKEN_MASK).checked_sub(1)?);
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
            if runtime.party.is_none() {
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
            Ok(Self { namespace: runtime.namespace, handle: SOURCE_TOKEN_BIT | (index + 1) })
        })
    }

    pub(crate) fn public(value: Fp2) -> Self {
        record_c6_runtime_public(value);
        #[cfg(feature = "c6-trace")]
        {
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
        record_c6_runtime_scalar(scalar);
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
        if runtime.party.is_none() {
            return Ok(match node {
                // A fixed zero may be constructed before the response trace
                // begins and later participate in the authenticated-value
                // graph. Preserve its explicit structural identity. Any
                // public zero constructed while a trace is active is instead
                // allocated as a distinct response-instance input node.
                C6TraceNode::Public(value) if value == Fp2::ZERO => C6TraceToken::public_zero(),
                _ => C6TraceToken::untracked(),
            });
        }
        let operands = match node {
            C6TraceNode::Public(_) => [None, None],
            C6TraceNode::Add { lhs, rhs } | C6TraceNode::Sub { lhs, rhs } => [Some(lhs), Some(rhs)],
            C6TraceNode::Scale { value, .. } => [Some(value), None],
        };
        if operands.into_iter().flatten().any(|token| !token.belongs_to(runtime.namespace)) {
            return Err(C6TraceError::new(
                "C6 operation mixes tokens from different trace namespaces",
            ));
        }
        let index = u32::try_from(runtime.nodes.len())
            .map_err(|_| C6TraceError::new("C6 trace operation count exceeds u32"))?;
        if index >= SOURCE_TOKEN_BIT - 2 {
            return Err(C6TraceError::new("C6 trace operation token capacity exhausted"));
        }
        runtime.nodes.push(node);
        Ok(C6TraceToken { namespace: runtime.namespace, handle: index + 2 })
    })
    .unwrap_or_else(|error| panic!("C6 trace node HARD STOP: {error}"))
}

#[doc(hidden)]
pub fn record_c6_zero_roots(values: &[C6TraceToken]) -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if runtime.party.is_none() {
                return Ok(());
            }
            // The operation recorder is process-global because C6 linear
            // arithmetic may run on Rayon workers.  ZeroBatch terminals,
            // however, are coordinator-thread actions.  Ignore an unrelated
            // test's terminal while preserving the strict provenance checks
            // on the response thread that owns this trace.
            if runtime.owner_thread != Some(std::thread::current().id()) {
                return Ok(());
            }
            if let Some(index) = values.iter().position(|token| !token.is_tracked()) {
                return Err(C6TraceError::new(format!("C6 zero root {index} lacks provenance")));
            }
            if let Some(index) =
                values.iter().position(|token| !token.belongs_to(runtime.namespace))
            {
                return Err(C6TraceError::new(format!(
                    "C6 zero root {index} belongs to a different trace namespace"
                )));
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
            if runtime.party.is_none() {
                return Ok(());
            }
            // See `record_c6_zero_roots`: ProductClosure terminals are also
            // coordinator-thread actions.  A tracked mask on another thread
            // is still a traced-response bug; an untracked mask belongs to
            // unrelated concurrent harness work and is ignored.
            if runtime.owner_thread != Some(std::thread::current().id()) {
                if mask.is_tracked() && mask.belongs_to(runtime.namespace) {
                    return Err(C6TraceError::new(
                        "C6 ProductClosure terminal emitted outside the trace owner thread",
                    ));
                }
                return Ok(());
            }
            if !mask.is_tracked() {
                return Err(C6TraceError::new("C6 ProductClosure mask lacks provenance"));
            }
            if !mask.belongs_to(runtime.namespace) {
                return Err(C6TraceError::new(
                    "C6 ProductClosure mask belongs to a different trace namespace",
                ));
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
                if let Some(operand) =
                    triple.iter().position(|token| !token.belongs_to(runtime.namespace))
                {
                    return Err(C6TraceError::new(format!(
                        "C6 ProductClosure triple {triple_index} operand {operand} belongs to a different trace namespace"
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
    const TEST_NAMESPACE: u32 = 7;

    #[cfg(feature = "c6-trace")]
    fn source(index: u32) -> C6TraceToken {
        C6TraceToken { namespace: TEST_NAMESPACE, handle: SOURCE_TOKEN_BIT | (index + 1) }
    }

    #[cfg(feature = "c6-trace")]
    fn operation(index: u32) -> C6TraceToken {
        C6TraceToken { namespace: TEST_NAMESPACE, handle: index + 2 }
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
            namespace: TEST_NAMESPACE,
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
        assert_eq!(std::mem::size_of::<C6TraceToken>(), 8);
    }

    #[test]
    fn ordinary_build_can_parse_a_canonical_plan_artifact() {
        let manifest = C6TraceSourceManifest::new(2, [0xA5; 32], vec![1]).unwrap();
        let mut node_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_NODE_DOMAIN);
        for (canonical, source) in [(0u32, 0u32), (1, 1)] {
            node_hasher.update(&canonical.to_le_bytes());
            node_hasher.update(&[1]);
            node_hasher.update(&source.to_le_bytes());
        }
        let topology_node_digest = *node_hasher.finalize().as_bytes();

        let mut root_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_ROOT_DOMAIN);
        root_hasher.update(&1u32.to_le_bytes());
        root_hasher.update(&0u64.to_le_bytes());
        root_hasher.update(&1u64.to_le_bytes());
        for node in [0u32, 0, 0, 1] {
            root_hasher.update(&node.to_le_bytes());
        }
        root_hasher.update(&0u32.to_le_bytes());
        let root_digest = *root_hasher.finalize().as_bytes();

        let mut topology_hasher = blake3::Hasher::new_derive_key(C6_OPERATION_TOPOLOGY_PLAN_DOMAIN);
        topology_hasher.update(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        topology_hasher.update(&2u32.to_le_bytes());
        topology_hasher.update(&manifest.source_schedule_digest);
        topology_hasher.update(&2u32.to_le_bytes());
        topology_hasher.update(&0u32.to_le_bytes());
        topology_hasher.update(&0u32.to_le_bytes());
        topology_hasher.update(&1u32.to_le_bytes());
        topology_hasher.update(&1u64.to_le_bytes());
        topology_hasher.update(&0u32.to_le_bytes());
        topology_hasher.update(&topology_node_digest);
        topology_hasher.update(&root_digest);
        let topology_digest = *topology_hasher.finalize().as_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(C6_OPERATION_PLAN_CODEC_MAGIC);
        bytes.extend_from_slice(&C6_OPERATION_PLAN_CODEC_VERSION.to_le_bytes());
        bytes.extend_from_slice(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&manifest.source_schedule_digest);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&topology_digest);
        for length in [1u64, 2, 0, 0, 5] {
            bytes.extend_from_slice(&length.to_le_bytes());
        }
        bytes.push(0b00_001_001);
        bytes.extend_from_slice(&[2, 2]);
        bytes.extend_from_slice(&[1, 0, 0, 0, 1]);
        assert_eq!(bytes.len(), 160);

        let artifact = C6OperationPlanArtifact::parse(bytes, &manifest).unwrap();
        let decoded = artifact.decode(&manifest).unwrap();
        assert_eq!(decoded.topology.topology_digest, topology_digest);
        assert_eq!(decoded.node_kinds.source, 2);
        assert_eq!(decoded.product_phase_node_count, 2);
        assert_eq!(decoded.encoding.total_bytes, 160);
        let installed = artifact.clone().install(&manifest).unwrap();
        assert_eq!(installed.topology(), decoded.topology);
        assert_eq!(installed.source_ordinals(), &[0, 1]);
        assert!(installed.operands().is_empty());
        assert_eq!(installed.products().len(), 1);
        assert_eq!(installed.products()[0].triples(), &[[0, 0, 0]]);
        assert_eq!(installed.products()[0].mask(), 1);
        assert!(installed.zero_roots().is_empty());
        assert_eq!(installed.artifact_digest(), *blake3::hash(artifact.as_bytes()).as_bytes());
        let memory = installed.memory_census().unwrap();
        assert_eq!(memory.opcode_elements, 2);
        assert_eq!(memory.source_elements, 2);
        assert_eq!(memory.operand_elements, 0);
        assert_eq!(memory.product_closure_elements, 1);
        assert_eq!(memory.product_triple_elements, 1);
        assert_eq!(memory.zero_root_elements, 0);
        assert_eq!(memory.total_resident_bytes, memory.inline_bytes + memory.total_heap_bytes);

        let map_digest = c6_instance_extraction_map_digest(
            C6InstanceExtractionRole::Verifier,
            decoded.topology,
            0,
            0,
            &[],
            &[],
        );
        let mut extraction = Vec::new();
        extraction.extend_from_slice(C6_INSTANCE_EXTRACTION_CODEC_MAGIC);
        extraction.extend_from_slice(&C6_INSTANCE_EXTRACTION_CODEC_VERSION.to_le_bytes());
        extraction.extend_from_slice(&C6_OPERATION_PLAN_VERSION.to_le_bytes());
        extraction.push(C6InstanceExtractionRole::Verifier as u8);
        extraction.extend_from_slice(&[0; 3]);
        extraction.extend_from_slice(&topology_digest);
        extraction.extend_from_slice(&0u32.to_le_bytes());
        extraction.extend_from_slice(&0u32.to_le_bytes());
        extraction.extend_from_slice(&0u32.to_le_bytes());
        extraction.extend_from_slice(&0u32.to_le_bytes());
        extraction.extend_from_slice(&map_digest);
        extraction.extend_from_slice(&1u64.to_le_bytes());
        extraction.extend_from_slice(&1u64.to_le_bytes());
        extraction.extend_from_slice(&0u32.to_le_bytes());
        extraction.extend_from_slice(&[0, 0]);
        assert_eq!(extraction.len(), 122);
        let extraction = C6InstanceExtractionArtifact::parse(extraction, decoded.topology).unwrap();
        let extraction = extraction.decode(decoded.topology).unwrap();
        assert_eq!(extraction.role, C6InstanceExtractionRole::Verifier);
        assert!(extraction.public_raw_ordinals.is_empty());
        assert!(extraction.scalar_raw_ordinals.is_empty());
        assert_eq!(extraction.census.total_bytes, 122);
        #[cfg(not(feature = "c6-trace"))]
        {
            let capture = begin_c6_runtime_instance_capture(&extraction).unwrap();
            assert!(begin_c6_runtime_instance_capture(&extraction).is_err());
            let runtime = capture.finish(&artifact, &extraction).unwrap();
            assert_eq!(runtime.role(), C6InstanceExtractionRole::Verifier);
            assert_eq!(runtime.raw_public_input_count(), 0);
            assert_eq!(runtime.raw_scalar_input_count(), 0);

            let overflow = begin_c6_runtime_instance_capture(&extraction).unwrap();
            let _unexpected = crate::ProverAuthed::from_public(Fp2::ONE);
            assert!(overflow.finish(&artifact, &extraction).is_err());
        }
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn trace_rejects_missing_provenance_and_censuses_sources() {
        let _trace_guard = crate::C6_OPERATION_TRACE_TEST_LOCK.lock().unwrap();
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
    fn trace_ignores_untracked_terminals_from_unrelated_harness_threads() {
        let _trace_guard = crate::C6_OPERATION_TRACE_TEST_LOCK.lock().unwrap();
        begin_c6_prover_trace().unwrap();
        std::thread::spawn(|| {
            let untracked = C6TraceToken::untracked();
            record_c6_product_closure(&[[untracked; 3]], untracked).unwrap();
            record_c6_zero_roots(&[untracked]).unwrap();
        })
        .join()
        .unwrap();

        let untracked = C6TraceToken::untracked();
        assert!(record_c6_product_closure(&[[untracked; 3]], untracked).is_err());
        assert!(record_c6_zero_roots(&[untracked]).is_err());
        let snapshot = finish_c6_prover_trace().unwrap();
        assert!(snapshot.products.is_empty());
        assert!(snapshot.zero_roots.is_empty());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn prover_and_verifier_trace_lifecycles_are_sequential_and_independent() {
        let _trace_guard = crate::C6_OPERATION_TRACE_TEST_LOCK.lock().unwrap();
        let record = || {
            let value = C6TraceToken::source(0).unwrap();
            let mask = C6TraceToken::source(1).unwrap();
            let public = C6TraceToken::public(Fp2::ONE);
            let sum = value.add(public);
            record_c6_product_closure(&[[value, public, sum]], mask).unwrap();
            record_c6_zero_roots(&[sum]).unwrap();
        };

        begin_c6_prover_trace().unwrap();
        assert!(begin_c6_verifier_trace().is_err());
        record();
        let prover = finish_c6_prover_trace().unwrap();

        begin_c6_verifier_trace().unwrap();
        assert!(finish_c6_prover_trace().is_err());
        let stale = record_c6_zero_roots(&[prover.zero_roots[0]]).unwrap_err();
        assert!(stale.to_string().contains("different trace namespace"));
        record();
        let verifier = finish_c6_verifier_trace().unwrap();
        assert_ne!(prover.namespace, verifier.namespace);

        let manifest = manifest(2, vec![1]);
        let prover = normalize_c6_operation_trace(&prover, &manifest).unwrap();
        let verifier = normalize_c6_operation_trace(&verifier, &manifest).unwrap();
        assert_eq!(prover.identity, verifier.identity);
        assert_eq!(prover.topology, verifier.topology);
        assert_eq!(prover.instance, verifier.instance);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_ignores_raw_ids_and_unreachable_operations() {
        let manifest = manifest(3, vec![2]);
        let compact = normalize_c6_operation_trace(&allocation_trace(false), &manifest).unwrap();
        let captured =
            normalize_c6_operation_trace_debug_block(&allocation_trace(false), &manifest, 0)
                .unwrap();
        let shifted = normalize_c6_operation_trace(&allocation_trace(true), &manifest).unwrap();
        assert_eq!(compact.identity, captured.identity);
        assert!(!captured.diagnostics.captured_canonical_nodes.is_empty());
        assert_eq!(compact.identity, shifted.identity);
        assert_eq!(compact.diagnostics.raw_operation_count, 3);
        assert_eq!(compact.diagnostics.reachable_operation_count, 3);
        assert_eq!(compact.diagnostics.omitted_operation_count, 0);
        assert_eq!(shifted.diagnostics.raw_operation_count, 4);
        assert_eq!(shifted.diagnostics.reachable_operation_count, 3);
        assert_eq!(shifted.diagnostics.omitted_operation_count, 1);
        assert_eq!(
            compact.diagnostics.node_kinds,
            C6CanonicalNodeKindCensus {
                source: 3,
                structural_zero: 0,
                public_input: 1,
                add: 1,
                sub: 0,
                scale: 1,
            }
        );
        assert_eq!(
            compact.diagnostics.candidate_encoding,
            C6OperationPlanEncodingCensus {
                header_bytes: 152,
                packed_opcode_bytes: 3,
                source_payload_bytes: 3,
                linear_operand_payload_bytes: 3,
                terminal_payload_bytes: 6,
                total_bytes: 167,
            }
        );
        assert_eq!(
            compact.diagnostics.specialized_encoding_projection,
            C6OperationPlanSpecializedEncodingCensus {
                header_bytes: 152,
                packed_opcode_bytes: 3,
                source_delta_payload_bytes: 3,
                operand_unit_flag_bytes: 1,
                nonunit_operand_payload_bytes: 1,
                terminal_payload_bytes: 6,
                total_bytes: 166,
                source_successor_count: 3,
                operand_count: 3,
                unit_operand_count: 2,
            }
        );
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
        assert_ne!(baseline.topology.topology_digest, changed_schedule.topology.topology_digest);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn parameterized_plan_separates_topology_from_instance_values() {
        let manifest = manifest(3, vec![2]);
        let baseline_trace = allocation_trace(false);
        let baseline = normalize_c6_operation_trace(&baseline_trace, &manifest).unwrap();
        let baseline_compiled = compile_c6_operation_trace_for_role(
            &baseline_trace,
            &manifest,
            C6InstanceExtractionRole::Verifier,
        )
        .unwrap();
        let mut changed_trace = allocation_trace(false);
        changed_trace.nodes[0] =
            C6TraceNode::Public(Fp2::new(volta_field::Fp::new(123), volta_field::Fp::new(456)));
        changed_trace.nodes[2] = C6TraceNode::Scale {
            value: operation(1),
            scalar: Fp2::new(volta_field::Fp::new(789), volta_field::Fp::new(321)),
        };
        let changed = normalize_c6_operation_trace(&changed_trace, &manifest).unwrap();
        let changed_compiled = compile_c6_operation_trace_for_role(
            &changed_trace,
            &manifest,
            C6InstanceExtractionRole::Verifier,
        )
        .unwrap();

        assert_ne!(baseline.identity.program_digest, changed.identity.program_digest);
        assert_eq!(baseline.topology, changed.topology);
        assert_ne!(baseline.instance.instance_digest, changed.instance.instance_digest);
        assert_eq!(baseline.instance.topology_digest, baseline.topology.topology_digest);
        assert_eq!(changed.instance.topology_digest, changed.topology.topology_digest);
        assert_eq!(baseline_compiled.artifact, changed_compiled.artifact);
        assert_eq!(baseline_compiled.instance_extraction, changed_compiled.instance_extraction);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn parameterized_plan_codec_roundtrips_and_rejects_noncanonical_mutations() {
        let manifest = manifest(3, vec![2]);
        let trace = allocation_trace(false);
        let normalized = normalize_c6_operation_trace(&trace, &manifest).unwrap();
        let compiled = compile_c6_operation_trace(&trace, &manifest).unwrap();
        assert_eq!(compiled.plan, normalized);
        assert_eq!(
            compiled.artifact.len() as u64,
            compiled.plan.diagnostics.specialized_encoding_projection.total_bytes
        );
        let decoded = compiled.artifact.decode(&manifest).unwrap();
        assert_eq!(decoded.topology, normalized.topology);
        assert_eq!(decoded.node_kinds, normalized.diagnostics.node_kinds);
        assert_eq!(
            decoded.product_phase_node_count,
            normalized.diagnostics.product_phase_node_count
        );
        assert_eq!(decoded.encoding, normalized.diagnostics.specialized_encoding_projection);
        let installed = compiled.artifact.clone().install(&manifest).unwrap();
        assert_eq!(installed.topology(), normalized.topology);
        assert_eq!(installed.operation_kind(0).unwrap(), C6InstalledOperationKind::Source);
        assert_eq!(installed.source_ordinals(), &[0, 1, 2]);
        assert_eq!(installed.operands(), &[0, 1, 2]);
        assert_eq!(installed.products()[0].triples(), &[[3, 4, 0]]);
        assert_eq!(installed.products()[0].mask(), 5);
        assert_eq!(installed.zero_roots(), &[3]);
        let memory = installed.memory_census().unwrap();
        assert_eq!(memory.opcode_elements, u64::from(normalized.topology.canonical_node_count));
        assert_eq!(memory.source_elements, 3);
        assert_eq!(memory.operand_elements, 3);
        assert_eq!(memory.product_triple_elements, 1);
        assert_eq!(memory.zero_root_elements, 1);
        assert!(memory.total_heap_bytes > 0);
        let extraction = compiled.instance_extraction.decode(normalized.topology).unwrap();
        let trace_runtime = derive_c6_runtime_instance_from_trace_diagnostic(
            &trace,
            &compiled.artifact,
            &extraction,
            compiled.plan.instance,
        )
        .unwrap();
        assert_eq!(trace_runtime.instance_identity(), compiled.plan.instance);
        assert_eq!(extraction.role, C6InstanceExtractionRole::Prover);
        assert_eq!(extraction.public_raw_ordinals, vec![0]);
        assert_eq!(extraction.scalar_raw_ordinals, vec![0]);
        assert_eq!(
            extraction.census,
            C6InstanceExtractionCensus {
                raw_public_input_count: 1,
                raw_scalar_input_count: 1,
                canonical_public_input_count: 1,
                canonical_scalar_input_count: 1,
                public_run_count: 1,
                scalar_run_count: 1,
                header_bytes: 120,
                public_map_bytes: 3,
                scalar_map_bytes: 3,
                total_bytes: 126,
                map_digest: extraction.census.map_digest,
            }
        );
        let capture = begin_c6_runtime_instance_capture(&extraction).unwrap();
        let public = C6TraceToken::public(Fp2::ONE);
        let _scaled = public.scale(Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3)));
        let runtime = capture.finish(&compiled.artifact, &extraction).unwrap();
        assert_eq!(runtime.role(), C6InstanceExtractionRole::Prover);
        assert_eq!(runtime.raw_public_input_count(), 1);
        assert_eq!(runtime.raw_scalar_input_count(), 1);
        assert_eq!(runtime.instance_identity(), compiled.plan.instance);
        assert_eq!(runtime.public_value(&extraction, 0).unwrap(), Fp2::ONE);
        assert_eq!(
            runtime.scalar_value(&extraction, 0).unwrap(),
            Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3))
        );
        let installed_capture = begin_c6_runtime_instance_capture(&extraction).unwrap();
        let public = C6TraceToken::public(Fp2::ONE);
        let _scaled = public.scale(Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3)));
        let installed_runtime =
            installed_capture.finish_installed(&installed, &extraction).unwrap();
        assert_eq!(installed_runtime.instance_identity(), compiled.plan.instance);
        let migrated = begin_c6_runtime_instance_capture(&extraction).unwrap();
        std::thread::spawn(|| {
            let public = C6TraceToken::public(Fp2::ONE);
            let _scaled = public.scale(Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3)));
        })
        .join()
        .unwrap();
        assert!(migrated.finish(&compiled.artifact, &extraction).is_err());

        let shifted_trace = allocation_trace(true);
        let shifted = compile_c6_operation_trace(&shifted_trace, &manifest).unwrap();
        assert_eq!(compiled.artifact, shifted.artifact);
        assert_ne!(compiled.instance_extraction, shifted.instance_extraction);
        let shifted_extraction = shifted.instance_extraction.decode(shifted.plan.topology).unwrap();
        assert_eq!(shifted_extraction.public_raw_ordinals, vec![1]);
        assert_eq!(shifted_extraction.scalar_raw_ordinals, vec![0]);
        assert_eq!(shifted_extraction.census.raw_public_input_count, 2);
        let shifted_runtime = derive_c6_runtime_instance_from_trace_diagnostic(
            &shifted_trace,
            &shifted.artifact,
            &shifted_extraction,
            shifted.plan.instance,
        )
        .unwrap();
        assert_eq!(shifted_runtime.instance_identity(), shifted.plan.instance);

        let verifier = compile_c6_operation_trace_for_role(
            &allocation_trace(false),
            &manifest,
            C6InstanceExtractionRole::Verifier,
        )
        .unwrap();
        assert_eq!(compiled.artifact, verifier.artifact);
        assert_ne!(compiled.instance_extraction, verifier.instance_extraction);
        let verifier_extraction =
            verifier.instance_extraction.decode(verifier.plan.topology).unwrap();
        assert_eq!(verifier_extraction.role, C6InstanceExtractionRole::Verifier);
        let wrong_role = begin_c6_runtime_instance_capture(&extraction).unwrap();
        let public = C6TraceToken::public(Fp2::ONE);
        let _scaled = public.scale(Fp2::new(volta_field::Fp::new(2), volta_field::Fp::new(3)));
        assert!(wrong_role.finish(&compiled.artifact, &verifier_extraction).is_err());

        let reject = |mut bytes: Vec<u8>, mutate: fn(&mut Vec<u8>)| {
            mutate(&mut bytes);
            assert!(C6OperationPlanArtifact::parse(bytes, &manifest).is_err());
        };
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| bytes[0] ^= 1);
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| bytes[12] ^= 1);
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| bytes[80] ^= 1);
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| {
            bytes[C6_OPERATION_PARAMETERIZED_HEADER_BYTES as usize] |= 7;
        });
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| {
            let opcode_len = u64::from_le_bytes(bytes[112..120].try_into().unwrap()) as usize;
            let source_len = u64::from_le_bytes(bytes[120..128].try_into().unwrap()) as usize;
            let source_start = C6_OPERATION_PARAMETERIZED_HEADER_BYTES as usize + opcode_len;
            bytes[source_start] |= 0x80;
            bytes.insert(source_start + 1, 0);
            bytes[120..128].copy_from_slice(&((source_len + 1) as u64).to_le_bytes());
        });
        reject(compiled.artifact.as_bytes().to_vec(), |bytes| bytes.push(0));

        let parsed =
            C6OperationPlanArtifact::parse(compiled.artifact.as_bytes().to_vec(), &manifest)
                .unwrap();
        assert_eq!(parsed, compiled.artifact);

        let reject_extraction = |mut bytes: Vec<u8>, mutate: fn(&mut Vec<u8>)| {
            mutate(&mut bytes);
            assert!(C6InstanceExtractionArtifact::parse(bytes, compiled.plan.topology).is_err());
        };
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            bytes[0] ^= 1;
        });
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            bytes[16] = 3;
        });
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            bytes[17] = 1;
        });
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            bytes[68] ^= 1;
        });
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            let public_len = u64::from_le_bytes(bytes[100..108].try_into().unwrap());
            bytes[C6_INSTANCE_EXTRACTION_HEADER_BYTES as usize] |= 0x80;
            bytes.insert(C6_INSTANCE_EXTRACTION_HEADER_BYTES as usize + 1, 0);
            bytes[100..108].copy_from_slice(&(public_len + 1).to_le_bytes());
        });
        reject_extraction(compiled.instance_extraction.as_bytes().to_vec(), |bytes| {
            bytes.push(0);
        });

        let wrong_manifest = C6TraceSourceManifest::new(3, [0x5A; 32], vec![2]).unwrap();
        assert!(C6OperationPlanArtifact::parse(
            compiled.artifact.as_bytes().to_vec(),
            &wrong_manifest
        )
        .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn zero_public_input_does_not_alias_structural_zero() {
        let trace = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 0,
            nodes: vec![C6TraceNode::Public(Fp2::ZERO)],
            zero_roots: vec![operation(0), C6TraceToken::public_zero()],
            products: vec![],
        };
        let plan = normalize_c6_operation_trace(&trace, &manifest(0, vec![])).unwrap();
        assert_eq!(plan.identity.canonical_node_count, 2);
        assert_eq!(plan.topology.public_input_count, 1);
        assert_eq!(plan.topology.scalar_input_count, 0);
        assert_eq!(plan.diagnostics.node_kinds.public_input, 1);
        assert_eq!(plan.diagnostics.node_kinds.structural_zero, 1);

        let aliased = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 0,
            nodes: vec![],
            zero_roots: vec![C6TraceToken::public_zero(), C6TraceToken::public_zero()],
            products: vec![],
        };
        let aliased = normalize_c6_operation_trace(&aliased, &manifest(0, vec![])).unwrap();
        assert_ne!(plan.topology.topology_digest, aliased.topology.topology_digest);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn public_zero_lifecycle_distinguishes_pretrace_structure_from_active_input() {
        let _trace_guard = crate::C6_OPERATION_TRACE_TEST_LOCK.lock().unwrap();
        let structural = C6TraceToken::public(Fp2::ZERO);
        assert_eq!(structural, C6TraceToken::public_zero());

        begin_c6_prover_trace().unwrap();
        let input = C6TraceToken::public(Fp2::ZERO);
        assert_ne!(input, C6TraceToken::public_zero());
        record_c6_zero_roots(&[input, structural]).unwrap();
        let snapshot = finish_c6_prover_trace().unwrap();
        let plan = normalize_c6_operation_trace(&snapshot, &manifest(0, vec![])).unwrap();
        assert_eq!(plan.topology.public_input_count, 1);
        assert_eq!(plan.diagnostics.node_kinds.public_input, 1);
        assert_eq!(plan.diagnostics.node_kinds.structural_zero, 1);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn canonical_plan_preserves_declared_graph_sharing() {
        let manifest = manifest(2, vec![]);
        let shared = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 2,
            nodes: vec![C6TraceNode::Add { lhs: source(0), rhs: source(1) }],
            zero_roots: vec![operation(0), operation(0)],
            products: vec![],
        };
        let duplicated = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
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
            namespace: TEST_NAMESPACE,
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
            namespace: TEST_NAMESPACE,
            source_count: 2,
            nodes: vec![],
            zero_roots: vec![source(2)],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&out_of_range, &manifest).unwrap_err();
        assert!(error.to_string().contains("outside the source manifest"));

        let allocated_zero = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 2,
            nodes: vec![C6TraceNode::Public(Fp2::ZERO)],
            zero_roots: vec![operation(0)],
            products: vec![],
        };
        let allocated_zero = normalize_c6_operation_trace(&allocated_zero, &manifest).unwrap();
        assert_eq!(allocated_zero.topology.public_input_count, 1);
        assert_eq!(allocated_zero.diagnostics.node_kinds.structural_zero, 0);

        let untracked = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 2,
            nodes: vec![],
            zero_roots: vec![C6TraceToken::untracked()],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&untracked, &manifest).unwrap_err();
        assert!(error.to_string().contains("lacks provenance"));

        let mixed_namespace = C6ProverTraceSnapshot {
            namespace: TEST_NAMESPACE,
            source_count: 2,
            nodes: vec![],
            zero_roots: vec![C6TraceToken {
                namespace: TEST_NAMESPACE + 1,
                handle: SOURCE_TOKEN_BIT | 1,
            }],
            products: vec![],
        };
        let error = normalize_c6_operation_trace(&mixed_namespace, &manifest).unwrap_err();
        assert!(error.to_string().contains("different namespace"));
    }
}

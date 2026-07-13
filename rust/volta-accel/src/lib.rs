//! Internal accelerator seam for P7.
//!
//! CPU remains the default.  The optional `cuda` feature enables a dynamic
//! loader for `libvolta_cuda_backend.so`; requesting CUDA without the feature,
//! shared object, compatible ABI, or device is an explicit error.  Hybrid
//! mode may run named residual work on the CPU and accounts it.  Resident mode
//! rejects residual work, which prevents an accidental staged path from being
//! reported as the resident gate.

use std::fmt;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::AtomicU64;
#[cfg(feature = "cuda")]
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use volta_field::{Fp, Fp2};

pub const CUDA_ABI_VERSION: u32 = 19;
pub const OPERATION_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Operation {
    Gemm = 0,
    Logup = 1,
    PcsRows = 2,
    PcsNtt = 3,
    PcsMerkle = 4,
}

impl Operation {
    pub const ALL: [Operation; OPERATION_COUNT] = [
        Operation::Gemm,
        Operation::Logup,
        Operation::PcsRows,
        Operation::PcsNtt,
        Operation::PcsMerkle,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Operation::Gemm => "gemm",
            Operation::Logup => "logup",
            Operation::PcsRows => "pcs_rows",
            Operation::PcsNtt => "pcs_ntt",
            Operation::PcsMerkle => "pcs_merkle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Cpu,
    CudaHybrid,
    CudaResident,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum MatrixFoldAxis {
    Rows = 0,
    Columns = 1,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeviceTimingMode {
    /// CPU/default stats have no device timing source.
    #[default]
    None,
    /// Asynchronous phase timing from CUDA events; one final stream barrier
    /// per staged operation.
    CudaEvents,
    /// Fallback for runtimes where event elapsed-time is unavailable: each
    /// H2D/kernel/D2H phase is delimited by a timed host stream barrier.
    /// These are phase wall times (including launch overhead), and the three
    /// barriers per operation are counted explicitly.
    HostBarrierWall,
}

impl DeviceTimingMode {
    pub const fn name(self) -> &'static str {
        match self {
            DeviceTimingMode::None => "none",
            DeviceTimingMode::CudaEvents => "cuda-events",
            DeviceTimingMode::HostBarrierWall => "host-barrier-wall",
        }
    }
}

impl BackendKind {
    pub const fn name(self) -> &'static str {
        match self {
            BackendKind::Cpu => "cpu",
            BackendKind::CudaHybrid => "cuda-hybrid",
            BackendKind::CudaResident => "cuda-resident",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationStats {
    pub calls: u64,
    pub kernel_ns: u64,
    pub cpu_residual_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendStats {
    pub operations: [OperationStats; OPERATION_COUNT],
    pub timing_mode: DeviceTimingMode,
    pub measurement_wall_ns: u64,
    pub unattributed_cpu_residual_ns: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub h2d_ns: u64,
    pub d2h_ns: u64,
    pub synchronizations: u64,
    pub synchronization_ns: u64,
    /// Barriers required before protocol-visible device-to-host output.
    pub sync_host_output: u64,
    /// Legacy barriers retaining pageable host upload lifetime. P7b removes
    /// these only after the CUDA staging contract is differentially tested.
    pub sync_upload_lifetime: u64,
    /// Coarse flushes of deferred timing records (zero in legacy mode).
    pub sync_timing_flush: u64,
    /// Barriers whose only purpose is per-call profiling.
    pub sync_profiling_legacy: u64,
    /// Barriers before workspace/cache physical reclamation.
    pub sync_allocator_flush: u64,
    /// Successful physical `cudaMalloc` calls observed in this measurement
    /// window (workspace plus resident arena misses), not logical resident
    /// allocation requests.
    pub allocation_calls: u64,
    pub resident_alloc_requests: u64,
    pub resident_reuse_hits: u64,
    pub resident_free_requests: u64,
    /// Successful physical `cudaFree` calls observed in this measurement
    /// window. This need not balance [`Self::allocation_calls`]: a persistent
    /// context may free workspace or cached arena storage allocated before the
    /// most recent stats reset.
    pub physical_free_calls: u64,
    pub live_device_bytes: u64,
    pub peak_device_bytes: u64,
}

/// Physical allocations owned by a CUDA context. Active resident storage is
/// reported by capacity rather than logical length so these three categories
/// sum exactly to [`BackendStats::live_device_bytes`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceMemoryBreakdown {
    pub workspace_bytes: u64,
    /// Physical capacity backing live opaque buffers returned to Rust.
    pub resident_bytes: u64,
    /// Physical capacity retained by the resident best-fit arena for reuse.
    pub cached_resident_bytes: u64,
}

impl BackendStats {
    pub fn operation(&self, op: Operation) -> OperationStats {
        self.operations[op as usize]
    }

    pub fn kernel_ns(&self) -> u64 {
        self.operations.iter().map(|x| x.kernel_ns).sum()
    }

    pub fn operation_cpu_residual_ns(&self) -> u64 {
        self.operations.iter().map(|x| x.cpu_residual_ns).sum()
    }

    pub fn cpu_residual_ns(&self) -> u64 {
        self.operation_cpu_residual_ns() + self.unattributed_cpu_residual_ns
    }

    pub fn synchronization_reason_total(&self) -> u64 {
        self.sync_host_output
            + self.sync_upload_lifetime
            + self.sync_timing_flush
            + self.sync_profiling_legacy
            + self.sync_allocator_flush
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccelError {
    FeatureDisabled,
    InvalidInput(&'static str),
    LibraryLoad(String),
    MissingSymbol(String),
    AbiMismatch { expected: u32, found: u32 },
    Cuda(String),
    ResidualForbidden(Operation),
    MeasurementAlreadyActive,
    MeasurementNotActive,
    AttributionInconsistent { wall_ns: u64, attributed_ns: u64 },
}

impl fmt::Display for AccelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccelError::FeatureDisabled => {
                write!(f, "CUDA requested but volta-accel was built without feature `cuda`")
            }
            AccelError::InvalidInput(s) => write!(f, "invalid accelerator input: {s}"),
            AccelError::LibraryLoad(s) => write!(f, "cannot load CUDA backend: {s}"),
            AccelError::MissingSymbol(s) => write!(f, "CUDA backend is missing symbol {s}"),
            AccelError::AbiMismatch { expected, found } => {
                write!(f, "CUDA backend ABI mismatch: expected {expected}, found {found}")
            }
            AccelError::Cuda(s) => write!(f, "CUDA backend error: {s}"),
            AccelError::ResidualForbidden(op) => {
                write!(f, "{} CPU residual is forbidden by the cuda-resident gate", op.name())
            }
            AccelError::MeasurementAlreadyActive => {
                write!(f, "accelerator measurement already active")
            }
            AccelError::MeasurementNotActive => write!(f, "accelerator measurement is not active"),
            AccelError::AttributionInconsistent { wall_ns, attributed_ns } => write!(
                f,
                "accelerator attribution exceeds measurement wall: {attributed_ns} ns > {wall_ns} ns"
            ),
        }
    }
}

impl std::error::Error for AccelError {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp2Repr {
    pub c0: u64,
    pub c1: u64,
}

mod device_element {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for i16 {}
    impl Sealed for i64 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for super::Fp2Repr {}
}

/// Plain-old-data values supported by the internal resident-buffer ABI.
/// This trait is sealed so a type with padding or drop glue cannot cross the
/// C boundary accidentally.
pub trait DeviceElement: device_element::Sealed + Copy + Default + 'static {}
impl DeviceElement for u8 {}
impl DeviceElement for i16 {}
impl DeviceElement for i64 {}
impl DeviceElement for u32 {}
impl DeviceElement for u64 {}
impl DeviceElement for Fp2Repr {}

mod resident_matrix_element {
    pub trait Sealed {}
    impl Sealed for i16 {}
    impl Sealed for i64 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for super::Fp2Repr {}
}

/// Scalar types accepted by the generic resident matrix-fold kernels.
/// The trait is sealed so its CUDA ABI kind tag cannot be forged downstream.
pub trait ResidentMatrixElement: DeviceElement + resident_matrix_element::Sealed {
    #[doc(hidden)]
    const CUDA_KIND: i32;
}

impl ResidentMatrixElement for i16 {
    const CUDA_KIND: i32 = 0;
}
impl ResidentMatrixElement for i64 {
    const CUDA_KIND: i32 = 1;
}
impl ResidentMatrixElement for u32 {
    const CUDA_KIND: i32 = 4;
}
impl ResidentMatrixElement for u64 {
    const CUDA_KIND: i32 = 2;
}
impl ResidentMatrixElement for Fp2Repr {
    const CUDA_KIND: i32 = 3;
}

pub trait ResidentBaseElement: ResidentMatrixElement {}
impl ResidentBaseElement for i16 {}
impl ResidentBaseElement for i64 {}
impl ResidentBaseElement for u32 {}
impl ResidentBaseElement for u64 {}

mod resident_signed_element {
    pub trait Sealed {}
    impl Sealed for i16 {}
    impl Sealed for i64 {}
}

/// Signed integer sources accepted by resident requant-column builders.
pub trait ResidentSignedElement: ResidentBaseElement + resident_signed_element::Sealed {}
impl ResidentSignedElement for i16 {}
impl ResidentSignedElement for i64 {}

/// Opaque allocation owned by one [`Backend`] CUDA context.  It exposes no
/// device pointer, is deliberately non-`Clone`, and can only be freed by
/// moving it back into the context that created it.  Dropping the context
/// releases every still-live allocation.
#[derive(Debug)]
pub struct DeviceBuffer<T: DeviceElement> {
    #[cfg_attr(not(feature = "cuda"), allow(dead_code))]
    id: u64,
    len: usize,
    context_id: u64,
    _element: PhantomData<T>,
}

/// Borrowed typed region of an opaque resident allocation.  This is the
/// internal cross-crate view used by the forward/prover seam: it carries only
/// an element offset and length, never a raw device pointer.
#[derive(Clone, Copy, Debug)]
pub struct DeviceSlice<'a, T: DeviceElement> {
    buffer: &'a DeviceBuffer<T>,
    offset: usize,
    len: usize,
}

impl<'a, T: DeviceElement> DeviceSlice<'a, T> {
    pub fn new(buffer: &'a DeviceBuffer<T>, offset: usize, len: usize) -> Result<Self, AccelError> {
        validate_region(buffer.len, offset, len)?;
        Ok(DeviceSlice { buffer, offset, len })
    }

    pub fn buffer(self) -> &'a DeviceBuffer<T> {
        self.buffer
    }

    pub fn offset(self) -> usize {
        self.offset
    }

    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Opaque leaves-to-root BLAKE3 Merkle tree in resident device storage.
#[derive(Debug)]
pub struct DeviceMerkleTree {
    storage: DeviceBuffer<u8>,
    leaves: usize,
}

/// Column-major resident proof columns: `columns` consecutive vectors, each
/// of the same power-of-two `entries` length. This is an internal ownership
/// boundary shared by range/pair builders and resident LogUp.
#[derive(Debug)]
pub struct DeviceLookupColumns {
    storage: DeviceBuffer<u64>,
    columns: usize,
    entries: usize,
}

/// Shape-parametric proof-only attention materialization. The four
/// allocations are column-major base-field vectors; they deliberately carry
/// no model configuration or raw pointer. Layout access is through checked
/// views so the protocol layer can share columns across LogUp, authentication
/// and sumcheck without duplicating them.
#[derive(Debug)]
pub struct DeviceAttentionProofWires {
    rect: DeviceBuffer<u64>,
    rect_entries: usize,
    rows: DeviceBuffer<u64>,
    row_entries: usize,
    above: DeviceBuffer<u64>,
    qkv: DeviceBuffer<u64>,
    qkv_entries: usize,
}

impl DeviceAttentionProofWires {
    pub fn rect_entries(&self) -> usize {
        self.rect_entries
    }

    /// `[softmax_norm remainder, softmax weight]`.
    pub fn softmax_norm_columns(&self) -> DeviceSlice<'_, u64> {
        DeviceSlice::new(&self.rect, 0, 2 * self.rect_entries).expect("valid attention rect layout")
    }

    /// `[scores remainder, row-shifted score]`.
    pub fn scores_columns(&self) -> DeviceSlice<'_, u64> {
        DeviceSlice::new(&self.rect, 2 * self.rect_entries, 2 * self.rect_entries)
            .expect("valid attention rect layout")
    }

    /// `[row-shifted score, exp output, is-max]`.
    pub fn exp_columns(&self) -> DeviceSlice<'_, u64> {
        DeviceSlice::new(&self.rect, 3 * self.rect_entries, 3 * self.rect_entries)
            .expect("valid attention rect layout")
    }

    pub fn rect_column(&self, index: usize) -> Result<DeviceSlice<'_, u64>, AccelError> {
        if index >= 7 {
            return Err(AccelError::InvalidInput("attention rect column out of bounds"));
        }
        DeviceSlice::new(&self.rect, index * self.rect_entries, self.rect_entries)
    }

    pub fn full_scores(&self) -> DeviceSlice<'_, u64> {
        self.rect_column(6).expect("valid full-score column")
    }

    pub fn row_entries(&self) -> usize {
        self.row_entries
    }

    /// Row columns: denoms, reciprocal inputs, reciprocals, row shifts.
    pub fn row_column(&self, index: usize) -> Result<DeviceSlice<'_, u64>, AccelError> {
        if index >= 4 {
            return Err(AccelError::InvalidInput("attention row column out of bounds"));
        }
        DeviceSlice::new(&self.rows, index * self.row_entries, self.row_entries)
    }

    pub fn above(&self) -> DeviceSlice<'_, u64> {
        DeviceSlice::new(&self.above, 0, self.above.len()).expect("whole above-score vector")
    }

    pub fn qkv_entries(&self) -> usize {
        self.qkv_entries
    }

    pub fn qkv_columns(&self) -> DeviceSlice<'_, u64> {
        DeviceSlice::new(&self.qkv, 0, 2 * self.qkv_entries).expect("valid QKV proof layout")
    }

    pub fn qkv_column(&self, index: usize) -> Result<DeviceSlice<'_, u64>, AccelError> {
        if index >= 2 {
            return Err(AccelError::InvalidInput("attention QKV column out of bounds"));
        }
        DeviceSlice::new(&self.qkv, index * self.qkv_entries, self.qkv_entries)
    }
}

impl DeviceLookupColumns {
    pub fn columns(&self) -> usize {
        self.columns
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn view(&self, first: usize, count: usize) -> Result<DeviceSlice<'_, u64>, AccelError> {
        if count == 0 || first > self.columns || count > self.columns - first {
            return Err(AccelError::InvalidInput("lookup-column view is out of bounds"));
        }
        DeviceSlice::new(&self.storage, first * self.entries, count * self.entries)
    }

    pub fn column(&self, index: usize) -> Result<DeviceSlice<'_, u64>, AccelError> {
        self.view(index, 1)
    }
}

impl DeviceMerkleTree {
    pub fn leaves(&self) -> usize {
        self.leaves
    }

    pub fn is_owned_by(&self, backend: &Backend) -> bool {
        self.storage.is_owned_by(backend)
    }
}

impl<T: DeviceElement> DeviceBuffer<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pure ownership preflight. This performs no CUDA call and lets compound
    /// owners reject a wrong context before consuming any of their handles.
    pub fn is_owned_by(&self, backend: &Backend) -> bool {
        backend.kind == BackendKind::CudaResident && self.context_id == backend.context_id
    }
}

#[cfg_attr(not(feature = "cuda"), allow(dead_code))]
static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);

impl From<Fp2> for Fp2Repr {
    fn from(x: Fp2) -> Self {
        Fp2Repr { c0: x.c0.value(), c1: x.c1.value() }
    }
}

impl From<Fp2Repr> for Fp2 {
    fn from(x: Fp2Repr) -> Self {
        Fp2::new(Fp::new(x.c0), Fp::new(x.c1))
    }
}

pub struct Backend {
    kind: BackendKind,
    context_id: u64,
    #[cfg(feature = "cuda")]
    cuda: Option<cuda::CudaContext>,
    cpu_residual_ns: [u64; OPERATION_COUNT],
    measurement_active: bool,
    measurement_started: Option<Instant>,
}

impl Backend {
    pub fn cpu() -> Backend {
        Backend {
            kind: BackendKind::Cpu,
            context_id: 0,
            #[cfg(feature = "cuda")]
            cuda: None,
            cpu_residual_ns: [0; OPERATION_COUNT],
            measurement_active: false,
            measurement_started: None,
        }
    }

    pub fn cuda_hybrid() -> Result<Backend, AccelError> {
        Self::load_cuda(BackendKind::CudaHybrid)
    }

    pub fn cuda_resident() -> Result<Backend, AccelError> {
        Self::load_cuda(BackendKind::CudaResident)
    }

    #[cfg(feature = "cuda")]
    fn load_cuda(kind: BackendKind) -> Result<Backend, AccelError> {
        let cuda = cuda::CudaContext::load()?;
        Ok(Backend {
            kind,
            context_id: NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed),
            cuda: Some(cuda),
            cpu_residual_ns: [0; OPERATION_COUNT],
            measurement_active: false,
            measurement_started: None,
        })
    }

    #[cfg(not(feature = "cuda"))]
    fn load_cuda(_kind: BackendKind) -> Result<Backend, AccelError> {
        Err(AccelError::FeatureDisabled)
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn is_cpu(&self) -> bool {
        self.kind == BackendKind::Cpu
    }

    pub fn begin_measurement(&mut self) -> Result<(), AccelError> {
        if self.measurement_active {
            return Err(AccelError::MeasurementAlreadyActive);
        }
        self.cpu_residual_ns = [0; OPERATION_COUNT];
        #[cfg(feature = "cuda")]
        if let Some(cuda) = &mut self.cuda {
            cuda.reset_stats()?;
        }
        self.measurement_started = Some(Instant::now());
        self.measurement_active = true;
        Ok(())
    }

    pub fn finish_measurement(&mut self) -> Result<BackendStats, AccelError> {
        if !self.measurement_active {
            return Err(AccelError::MeasurementNotActive);
        }
        let wall_ns = self
            .measurement_started
            .expect("active measurement without start time")
            .elapsed()
            .as_nanos() as u64;
        let mut stats = self.stats()?;
        let phase_ns = stats.h2d_ns + stats.d2h_ns + stats.kernel_ns();
        let operation_cpu_ns = stats.operation_cpu_residual_ns();
        let attributed_ns = phase_ns
            .checked_add(operation_cpu_ns)
            .ok_or(AccelError::AttributionInconsistent { wall_ns, attributed_ns: u64::MAX })?;
        if attributed_ns > wall_ns {
            return Err(AccelError::AttributionInconsistent { wall_ns, attributed_ns });
        }
        stats.measurement_wall_ns = wall_ns;
        stats.unattributed_cpu_residual_ns = wall_ns - attributed_ns;
        self.measurement_active = false;
        self.measurement_started = None;
        Ok(stats)
    }

    pub fn stats(&self) -> Result<BackendStats, AccelError> {
        let mut out = BackendStats::default();
        #[cfg(feature = "cuda")]
        if let Some(cuda) = &self.cuda {
            out = cuda.stats()?;
        }
        for (dst, &ns) in out.operations.iter_mut().zip(&self.cpu_residual_ns) {
            dst.cpu_residual_ns = ns;
        }
        Ok(out)
    }

    pub fn device_memory_breakdown(&self) -> Result<DeviceMemoryBreakdown, AccelError> {
        #[cfg(feature = "cuda")]
        if let Some(cuda) = &self.cuda {
            return cuda.memory_breakdown();
        }
        Err(AccelError::FeatureDisabled)
    }

    /// Physically release inactive resident-arena storage. Active buffers and
    /// primitive workspaces remain valid; normal `free_device` stays a cheap
    /// logical free so hot sessions retain reuse.
    pub fn trim_device_cache(&mut self) -> Result<(), AccelError> {
        self.require_resident()?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").trim_resident_cache();
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    fn require_resident(&self) -> Result<(), AccelError> {
        if self.kind != BackendKind::CudaResident {
            return Err(AccelError::InvalidInput(
                "resident buffers require the cuda-resident backend",
            ));
        }
        Ok(())
    }

    fn validate_buffer<T: DeviceElement>(
        &self,
        buffer: &DeviceBuffer<T>,
    ) -> Result<(), AccelError> {
        self.require_resident()?;
        if buffer.context_id != self.context_id {
            return Err(AccelError::InvalidInput(
                "device buffer belongs to a different CUDA context",
            ));
        }
        Ok(())
    }

    /// Allocate a persistent typed device buffer. Allocation is intentionally
    /// separate from upload so setup and online transfers remain attributable.
    pub fn alloc_device<T: DeviceElement>(
        &mut self,
        len: usize,
    ) -> Result<DeviceBuffer<T>, AccelError> {
        self.require_resident()?;
        let bytes = len
            .checked_mul(size_of::<T>())
            .filter(|&n| n > 0)
            .ok_or(AccelError::InvalidInput("zero or overflowing device allocation"))?;
        #[cfg(not(feature = "cuda"))]
        let _ = bytes;
        #[cfg(feature = "cuda")]
        {
            let id =
                self.cuda.as_mut().expect("CUDA kind without context").resident_alloc(bytes)?;
            return Ok(DeviceBuffer {
                id,
                len,
                context_id: self.context_id,
                _element: PhantomData,
            });
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn free_device<T: DeviceElement>(
        &mut self,
        buffer: DeviceBuffer<T>,
    ) -> Result<(), AccelError> {
        self.validate_buffer(&buffer)?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").resident_free(buffer.id);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn upload_device<T: DeviceElement>(
        &mut self,
        buffer: &DeviceBuffer<T>,
        offset: usize,
        values: &[T],
    ) -> Result<(), AccelError> {
        self.validate_buffer(buffer)?;
        validate_region(buffer.len, offset, values.len())?;
        if values.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").resident_upload(
                buffer.id,
                offset * size_of::<T>(),
                values.as_ptr().cast(),
                values.len() * size_of::<T>(),
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Explicit device-to-host boundary. Resident proving code must call this
    /// only for protocol messages; tests also use it for differential checks.
    pub fn download_device<T: DeviceElement>(
        &mut self,
        buffer: &DeviceBuffer<T>,
        offset: usize,
        len: usize,
    ) -> Result<Vec<T>, AccelError> {
        self.validate_buffer(buffer)?;
        validate_region(buffer.len, offset, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }
        #[cfg(feature = "cuda")]
        {
            let mut out = vec![T::default(); len];
            self.cuda.as_mut().expect("CUDA kind without context").resident_download(
                buffer.id,
                offset * size_of::<T>(),
                out.as_mut_ptr().cast(),
                len * size_of::<T>(),
            )?;
            return Ok(out);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn upload_new_device<T: DeviceElement>(
        &mut self,
        values: &[T],
    ) -> Result<DeviceBuffer<T>, AccelError> {
        let buffer = self.alloc_device(values.len())?;
        if let Err(error) = self.upload_device(&buffer, 0, values) {
            let _ = self.free_device(buffer);
            return Err(error);
        }
        Ok(buffer)
    }

    /// Resident GEMM: inputs and output stay in the same CUDA context.
    pub fn gemm_i64_device(
        &mut self,
        a: &DeviceBuffer<i16>,
        a_offset: usize,
        b: &DeviceBuffer<i16>,
        b_offset: usize,
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<DeviceBuffer<i64>, AccelError> {
        self.validate_buffer(a)?;
        self.validate_buffer(b)?;
        validate_region(a.len, a_offset, checked_product(m, k)?)?;
        validate_region(b.len, b_offset, checked_product(k, n)?)?;
        let out = self.alloc_device(checked_product(m, n)?)?;
        #[cfg(feature = "cuda")]
        let result = self
            .cuda
            .as_mut()
            .expect("CUDA kind without context")
            .gemm_i64_device(a.id, a_offset, b.id, b_offset, out.id, 0, m, k, n);
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(out);
            return Err(error);
        }
        Ok(out)
    }

    /// Resident fused GEMM/requant/MAC-correction primitive. Only the final
    /// corrections need cross the protocol boundary.
    pub fn gemm_requant_auth_device(
        &mut self,
        a: &DeviceBuffer<i16>,
        a_offset: usize,
        b: &DeviceBuffer<i16>,
        b_offset: usize,
        masks: &DeviceBuffer<u64>,
        masks_offset: usize,
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(DeviceBuffer<i16>, DeviceBuffer<u64>), AccelError> {
        self.validate_buffer(a)?;
        self.validate_buffer(b)?;
        self.validate_buffer(masks)?;
        let mn = checked_product(m, n)?;
        validate_region(a.len, a_offset, checked_product(m, k)?)?;
        validate_region(b.len, b_offset, checked_product(k, n)?)?;
        validate_region(masks.len, masks_offset, mn)?;
        if shift == 0 || shift >= 63 {
            return Err(AccelError::InvalidInput("requant shift must be in 1..63"));
        }
        let out = self.alloc_device(mn)?;
        let corr = match self.alloc_device(mn) {
            Ok(corr) => corr,
            Err(error) => {
                let _ = self.free_device(out);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").gemm_requant_auth_device(
                a.id,
                a_offset,
                b.id,
                b_offset,
                masks.id,
                masks_offset,
                out.id,
                0,
                corr.id,
                0,
                m,
                k,
                n,
                shift,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(corr);
            let _ = self.free_device(out);
            return Err(error);
        }
        Ok((out, corr))
    }

    fn validate_device_slice<T: DeviceElement>(
        &self,
        slice: DeviceSlice<'_, T>,
        required: usize,
    ) -> Result<(), AccelError> {
        self.validate_buffer(slice.buffer)?;
        if slice.len < required {
            return Err(AccelError::InvalidInput(
                "resident device slice is shorter than its shape",
            ));
        }
        Ok(())
    }

    /// Shape-parametric fixed-point embedding. All witness outputs remain in
    /// resident buffers; `error` is a sticky one-word no-clamp/domain flag.
    #[allow(clippy::too_many_arguments)]
    pub fn fixed_embed_device(
        &mut self,
        tokens: DeviceSlice<'_, u32>,
        wte: DeviceSlice<'_, i16>,
        wpe: DeviceSlice<'_, i16>,
        acc: DeviceSlice<'_, i64>,
        out: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        d: usize,
        vocab: usize,
        positions: usize,
        pos0: usize,
        shift: i32,
    ) -> Result<(), AccelError> {
        let rd = checked_product(rows, d)?;
        self.validate_device_slice(tokens, rows)?;
        self.validate_device_slice(wte, checked_product(vocab, d)?)?;
        self.validate_device_slice(wpe, checked_product(positions, d)?)?;
        self.validate_device_slice(acc, rd)?;
        self.validate_device_slice(out, rd)?;
        self.validate_device_slice(error, 1)?;
        if rows == 0
            || d == 0
            || vocab == 0
            || pos0.checked_add(rows).filter(|&end| end <= positions).is_none()
            || !(-62..=62).contains(&shift)
        {
            return Err(AccelError::InvalidInput("invalid resident embedding geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_embed_device(
                tokens.buffer.id,
                tokens.offset,
                wte.buffer.id,
                wte.offset,
                wpe.buffer.id,
                wpe.offset,
                acc.buffer.id,
                acc.offset,
                out.buffer.id,
                out.offset,
                error.buffer.id,
                error.offset,
                rows,
                d,
                vocab,
                positions,
                pos0,
                shift,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fixed_layer_norm_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        gain: DeviceSlice<'_, i16>,
        bias: DeviceSlice<'_, i16>,
        rsqrt_lut: DeviceSlice<'_, i16>,
        mean: DeviceSlice<'_, i64>,
        var: DeviceSlice<'_, i64>,
        rsqrt_input: DeviceSlice<'_, i64>,
        rsqrt_output: DeviceSlice<'_, i16>,
        accumulators: DeviceSlice<'_, i64>,
        output: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        d: usize,
        var_shift: u32,
        norm_shift: u32,
    ) -> Result<(), AccelError> {
        let rd = checked_product(rows, d)?;
        for slice in [input, output] {
            self.validate_device_slice(slice, rd)?;
        }
        self.validate_device_slice(accumulators, rd)?;
        for slice in [gain, bias] {
            self.validate_device_slice(slice, d)?;
        }
        self.validate_device_slice(rsqrt_lut, 1 << 16)?;
        for slice in [mean, var, rsqrt_input] {
            self.validate_device_slice(slice, rows)?;
        }
        self.validate_device_slice(rsqrt_output, rows)?;
        self.validate_device_slice(error, 1)?;
        if rows == 0 || d == 0 || norm_shift == 0 || norm_shift >= 63 || var_shift >= 63 {
            return Err(AccelError::InvalidInput("invalid resident layer-norm geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_layer_norm_device(
                input.buffer.id,
                input.offset,
                gain.buffer.id,
                gain.offset,
                bias.buffer.id,
                bias.offset,
                rsqrt_lut.buffer.id,
                rsqrt_lut.offset,
                mean.buffer.id,
                mean.offset,
                var.buffer.id,
                var.offset,
                rsqrt_input.buffer.id,
                rsqrt_input.offset,
                rsqrt_output.buffer.id,
                rsqrt_output.offset,
                accumulators.buffer.id,
                accumulators.offset,
                output.buffer.id,
                output.offset,
                error.buffer.id,
                error.offset,
                rows,
                d,
                var_shift,
                norm_shift,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Fixed GEMM with optional public bias and residual. The original i64
    /// accumulators, requantized wire, and residual boundary are distinct
    /// outputs so the prover can consume each without reconstructing it.
    #[allow(clippy::too_many_arguments)]
    pub fn fixed_gemm_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        weights: DeviceSlice<'_, i16>,
        bias: Option<DeviceSlice<'_, i16>>,
        residual: Option<DeviceSlice<'_, i16>>,
        accumulators: DeviceSlice<'_, i64>,
        requantized: DeviceSlice<'_, i16>,
        residual_output: Option<DeviceSlice<'_, i16>>,
        error: DeviceSlice<'_, u32>,
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        let mk = checked_product(m, k)?;
        let kn = checked_product(k, n)?;
        let mn = checked_product(m, n)?;
        self.validate_device_slice(input, mk)?;
        self.validate_device_slice(weights, kn)?;
        if let Some(slice) = bias {
            self.validate_device_slice(slice, n)?;
        }
        if let Some(slice) = residual {
            self.validate_device_slice(slice, mn)?;
        }
        self.validate_device_slice(accumulators, mn)?;
        self.validate_device_slice(requantized, mn)?;
        if let Some(slice) = residual_output {
            self.validate_device_slice(slice, mn)?;
        }
        self.validate_device_slice(error, 1)?;
        if m == 0
            || k == 0
            || n == 0
            || shift == 0
            || shift >= 63
            || residual.is_some() != residual_output.is_some()
        {
            return Err(AccelError::InvalidInput("invalid resident fixed GEMM geometry"));
        }
        #[cfg(feature = "cuda")]
        let raw = |slice: DeviceSlice<'_, i16>| (slice.buffer.id, slice.offset);
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_gemm_device(
                input.buffer.id,
                input.offset,
                weights.buffer.id,
                weights.offset,
                bias.map(raw),
                residual.map(raw),
                accumulators.buffer.id,
                accumulators.offset,
                requantized.buffer.id,
                requantized.offset,
                residual_output.map(raw),
                error.buffer.id,
                error.offset,
                m,
                k,
                n,
                shift,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fixed_qkv_split_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        q: DeviceSlice<'_, i16>,
        k: DeviceSlice<'_, i16>,
        v: DeviceSlice<'_, i16>,
        rows: usize,
        d: usize,
    ) -> Result<(), AccelError> {
        let rd = checked_product(rows, d)?;
        self.validate_device_slice(input, checked_product(rd, 3)?)?;
        for slice in [q, k, v] {
            self.validate_device_slice(slice, rd)?;
        }
        if rows == 0 || d == 0 {
            return Err(AccelError::InvalidInput("invalid resident QKV split geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_qkv_split_device(
                input.buffer.id,
                input.offset,
                q.buffer.id,
                q.offset,
                k.buffer.id,
                k.offset,
                v.buffer.id,
                v.offset,
                rows,
                d,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fixed_attention_scores_device(
        &mut self,
        q: DeviceSlice<'_, i16>,
        k: DeviceSlice<'_, i16>,
        accumulators: DeviceSlice<'_, i64>,
        outputs: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_dim: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        let d = checked_product(heads, head_dim)?;
        let packed_per_head = rows
            .checked_mul(pos0)
            .and_then(|x| rows.checked_mul(rows + 1).and_then(|tri2| x.checked_add(tri2 / 2)))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let packed = checked_product(heads, packed_per_head)?;
        self.validate_device_slice(q, checked_product(rows, d)?)?;
        self.validate_device_slice(k, checked_product(seq, d)?)?;
        self.validate_device_slice(accumulators, packed)?;
        self.validate_device_slice(outputs, packed)?;
        self.validate_device_slice(error, 1)?;
        if rows == 0
            || seq == 0
            || heads == 0
            || head_dim == 0
            || shift == 0
            || shift >= 63
            || pos0.checked_add(rows).filter(|&end| end <= seq).is_none()
        {
            return Err(AccelError::InvalidInput("invalid resident attention-score geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .fixed_attention_scores_device(
                    q.buffer.id,
                    q.offset,
                    k.buffer.id,
                    k.offset,
                    accumulators.buffer.id,
                    accumulators.offset,
                    outputs.buffer.id,
                    outputs.offset,
                    error.buffer.id,
                    error.offset,
                    rows,
                    seq,
                    pos0,
                    heads,
                    head_dim,
                    shift,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fixed_softmax_device(
        &mut self,
        scores: DeviceSlice<'_, i16>,
        exp_lut: DeviceSlice<'_, i16>,
        recip_lut: DeviceSlice<'_, i16>,
        row_shifts: DeviceSlice<'_, i16>,
        exp_outputs: DeviceSlice<'_, i16>,
        denoms: DeviceSlice<'_, i64>,
        recips: DeviceSlice<'_, i16>,
        weights: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        recip_den_shift: u32,
        norm_shift: u32,
        use_row_shift: bool,
    ) -> Result<(), AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = use_row_shift;
        let packed_per_head = rows
            .checked_mul(pos0)
            .and_then(|x| rows.checked_mul(rows + 1).and_then(|tri2| x.checked_add(tri2 / 2)))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let packed = checked_product(heads, packed_per_head)?;
        let row_count = checked_product(heads, rows)?;
        for slice in [scores, exp_outputs, weights] {
            self.validate_device_slice(slice, packed)?;
        }
        for slice in [row_shifts, recips] {
            self.validate_device_slice(slice, row_count)?;
        }
        self.validate_device_slice(denoms, row_count)?;
        self.validate_device_slice(exp_lut, 1 << 16)?;
        self.validate_device_slice(recip_lut, 1 << 16)?;
        self.validate_device_slice(error, 1)?;
        if rows == 0
            || seq == 0
            || heads == 0
            || norm_shift == 0
            || norm_shift >= 63
            || recip_den_shift >= 63
            || pos0.checked_add(rows).filter(|&end| end <= seq).is_none()
        {
            return Err(AccelError::InvalidInput("invalid resident softmax geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_softmax_device(
                scores.buffer.id,
                scores.offset,
                exp_lut.buffer.id,
                exp_lut.offset,
                recip_lut.buffer.id,
                recip_lut.offset,
                row_shifts.buffer.id,
                row_shifts.offset,
                exp_outputs.buffer.id,
                exp_outputs.offset,
                denoms.buffer.id,
                denoms.offset,
                recips.buffer.id,
                recips.offset,
                weights.buffer.id,
                weights.offset,
                error.buffer.id,
                error.offset,
                rows,
                seq,
                pos0,
                heads,
                recip_den_shift,
                norm_shift,
                use_row_shift,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fixed_av_device(
        &mut self,
        weights: DeviceSlice<'_, i16>,
        values: DeviceSlice<'_, i16>,
        accumulators: DeviceSlice<'_, i64>,
        outputs: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        seq: usize,
        pos0: usize,
        d: usize,
        heads: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        let packed_per_head = rows
            .checked_mul(pos0)
            .and_then(|x| rows.checked_mul(rows + 1).and_then(|tri2| x.checked_add(tri2 / 2)))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        self.validate_device_slice(weights, checked_product(heads, packed_per_head)?)?;
        self.validate_device_slice(values, checked_product(seq, d)?)?;
        let rd = checked_product(rows, d)?;
        self.validate_device_slice(accumulators, rd)?;
        self.validate_device_slice(outputs, rd)?;
        self.validate_device_slice(error, 1)?;
        if rows == 0
            || seq == 0
            || d == 0
            || heads == 0
            || d % heads != 0
            || shift == 0
            || shift >= 63
            || pos0.checked_add(rows).filter(|&end| end <= seq).is_none()
        {
            return Err(AccelError::InvalidInput("invalid resident AV geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_av_device(
                weights.buffer.id,
                weights.offset,
                values.buffer.id,
                values.offset,
                accumulators.buffer.id,
                accumulators.offset,
                outputs.buffer.id,
                outputs.offset,
                error.buffer.id,
                error.offset,
                rows,
                seq,
                pos0,
                d,
                heads,
                shift,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn fixed_lookup_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        lut: DeviceSlice<'_, i16>,
        output: DeviceSlice<'_, i16>,
    ) -> Result<(), AccelError> {
        if input.is_empty() || output.len() < input.len() {
            return Err(AccelError::InvalidInput("invalid resident lookup geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        self.validate_device_slice(lut, 1 << 16)?;
        self.validate_device_slice(output, input.len())?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_lookup_device(
                input.buffer.id,
                input.offset,
                lut.buffer.id,
                lut.offset,
                output.buffer.id,
                output.offset,
                input.len,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn fixed_requant_i16_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        output: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        shift: u32,
    ) -> Result<(), AccelError> {
        if input.is_empty() || output.len() < input.len() || shift >= 63 {
            return Err(AccelError::InvalidInput("invalid resident i16 requant geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        self.validate_device_slice(output, input.len())?;
        self.validate_device_slice(error, 1)?;
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .fixed_requant_i16_device(
                    input.buffer.id,
                    input.offset,
                    output.buffer.id,
                    output.offset,
                    error.buffer.id,
                    error.offset,
                    input.len,
                    shift,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn fixed_logits_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        weights: DeviceSlice<'_, i16>,
        output: DeviceSlice<'_, i64>,
        rows: usize,
        d: usize,
        vocab: usize,
    ) -> Result<(), AccelError> {
        self.validate_device_slice(input, checked_product(rows, d)?)?;
        self.validate_device_slice(weights, checked_product(vocab, d)?)?;
        self.validate_device_slice(output, checked_product(rows, vocab)?)?;
        if rows == 0 || d == 0 || vocab == 0 {
            return Err(AccelError::InvalidInput("invalid resident logits geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fixed_logits_device(
                input.buffer.id,
                input.offset,
                weights.buffer.id,
                weights.offset,
                output.buffer.id,
                output.offset,
                rows,
                d,
                vocab,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Compute subfield Π_Auth corrections from a resident base-field source
    /// and resident canonical masks. The correction vector remains resident
    /// until the caller explicitly emits it as a protocol message.
    pub fn subfield_corrections_device<T: ResidentBaseElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        masks: DeviceSlice<'_, u64>,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        if input.is_empty() || masks.len() < input.len() {
            return Err(AccelError::InvalidInput("invalid resident subfield-correction geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        self.validate_device_slice(masks, input.len())?;
        let output = self.alloc_device(input.len())?;
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").subfield_corrections_device(
                input.buffer.id,
                input.offset,
                masks.buffer.id,
                masks.offset,
                output.id,
                0,
                input.len,
                T::CUDA_KIND,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Canonically lift and pad a resident base vector into an Fp/u64
    /// allocation. This is used for authenticated vectors whose protocol
    /// domain is the next power of two, including nonzero public pad values.
    pub fn pad_base_vector_device<T: ResidentBaseElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        padded_len: usize,
        pad: Fp,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = pad;
        if input.is_empty() || padded_len < input.len() || !padded_len.is_power_of_two() {
            return Err(AccelError::InvalidInput("invalid resident base-vector padding"));
        }
        self.validate_device_slice(input, input.len())?;
        let output = self.alloc_device(padded_len)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").pad_base_vector_device(
            input.buffer.id,
            input.offset,
            output.id,
            0,
            input.len,
            padded_len,
            pad,
            T::CUDA_KIND,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Fold one axis of a resident row-major matrix with public Fp2 weights.
    /// The untouched axis is zero-padded to its next power of two.
    pub fn matrix_fold_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        weights: DeviceSlice<'_, Fp2Repr>,
        rows: usize,
        cols: usize,
        axis: MatrixFoldAxis,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        self.matrix_window_fold_device(input, weights, rows, cols, 0, cols, axis)
    }

    /// Fold one axis of a column window in a resident row-major matrix.
    /// `stride` is the physical row width and `[column_offset, column_offset
    /// + cols)` is the logical matrix. This keeps head/tensor slices resident
    /// without allocating a gathered copy. The untouched axis is padded to a
    /// power of two exactly as in [`Self::matrix_fold_device`].
    #[allow(clippy::too_many_arguments)]
    pub fn matrix_window_fold_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        weights: DeviceSlice<'_, Fp2Repr>,
        rows: usize,
        stride: usize,
        column_offset: usize,
        cols: usize,
        axis: MatrixFoldAxis,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        if rows == 0
            || cols == 0
            || stride == 0
            || column_offset.checked_add(cols).filter(|&end| end <= stride).is_none()
        {
            return Err(AccelError::InvalidInput("invalid resident matrix-window fold geometry"));
        }
        self.validate_device_slice(input, checked_product(rows, stride)?)?;
        let (terms, real_outputs) = match axis {
            MatrixFoldAxis::Rows => (rows, cols),
            MatrixFoldAxis::Columns => (cols, rows),
        };
        self.validate_device_slice(weights, terms)?;
        let out_pad = real_outputs
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let output = self.alloc_device(out_pad)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").matrix_fold_device(
            input.buffer.id,
            input.offset,
            weights.buffer.id,
            weights.offset,
            output.id,
            0,
            rows,
            stride,
            column_offset,
            cols,
            out_pad,
            T::CUDA_KIND,
            axis as i32,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    pub fn equality_weights_device(
        &mut self,
        point: &[Fp2],
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        let point_raw: Vec<Fp2Repr> = point.iter().copied().map(Into::into).collect();
        let points =
            if point_raw.is_empty() { None } else { Some(self.upload_new_device(&point_raw)?) };
        let weights = self.logup_eq_rows_device(points.as_ref(), 1, point.len());
        let free_result = if let Some(points) = points { self.free_device(points) } else { Ok(()) };
        match (weights, free_result) {
            (Ok(weights), Ok(())) => Ok(weights),
            (Ok(weights), Err(error)) => {
                let _ = self.free_device(weights);
                Err(error)
            }
            (Err(error), _) => Err(error),
        }
    }

    /// Evaluate a power-of-two resident base/Fp2 vector at an LSB-first MLE
    /// point. Only the transcript-sized point is uploaded and the resulting
    /// scalar is downloaded; the equality row and fold stay device-resident.
    pub fn mle_eval_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        point: &[Fp2],
    ) -> Result<Fp2, AccelError> {
        let expected = 1usize
            .checked_shl(point.len() as u32)
            .ok_or(AccelError::InvalidInput("resident MLE dimension overflow"))?;
        if input.len() != expected {
            return Err(AccelError::InvalidInput("resident MLE point does not match vector"));
        }
        self.validate_device_slice(input, expected)?;

        let weights = self.equality_weights_device(point)?;

        let folded = match self.matrix_fold_device(
            input,
            DeviceSlice::new(&weights, 0, weights.len()).expect("whole equality row"),
            1,
            expected,
            MatrixFoldAxis::Columns,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(weights);
                return Err(error);
            }
        };
        if let Err(error) = self.free_device(weights) {
            let _ = self.free_device(folded);
            return Err(error);
        }
        let value = self.download_device(&folded, 0, 1).map(|values| Fp2::from(values[0]));
        let free_result = self.free_device(folded);
        match (value, free_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    /// Evaluate the zero-padded multilinear extension of a real row-major
    /// matrix. Point order is padded columns (LSB) followed by padded rows.
    /// Equality tables and both folds stay resident; only the scalar result
    /// crosses D2H.
    pub fn matrix_mle_eval_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        rows: usize,
        cols: usize,
        point: &[Fp2],
    ) -> Result<Fp2, AccelError> {
        if rows == 0 || cols == 0 {
            return Err(AccelError::InvalidInput("invalid resident matrix MLE geometry"));
        }
        self.validate_device_slice(input, checked_product(rows, cols)?)?;
        let col_bits = cols
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("shape overflow"))?
            .trailing_zeros() as usize;
        let row_bits = rows
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("shape overflow"))?
            .trailing_zeros() as usize;
        if point.len() != col_bits + row_bits {
            return Err(AccelError::InvalidInput("resident matrix MLE point mismatch"));
        }
        let col_weights = self.equality_weights_device(&point[..col_bits])?;
        let row_weights = match self.equality_weights_device(&point[col_bits..]) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(col_weights);
                return Err(error);
            }
        };
        let folded = match self.matrix_fold_device(
            input,
            DeviceSlice::new(&col_weights, 0, cols).expect("real column equality prefix"),
            rows,
            cols,
            MatrixFoldAxis::Columns,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(row_weights);
                let _ = self.free_device(col_weights);
                return Err(error);
            }
        };
        let first_free = self.free_device(col_weights).err();
        if let Some(error) = first_free {
            let _ = self.free_device(folded);
            let _ = self.free_device(row_weights);
            return Err(error);
        }
        let value = self.fp2_dot_device(
            DeviceSlice::new(&folded, 0, folded.len()).expect("whole row fold"),
            DeviceSlice::new(&row_weights, 0, row_weights.len()).expect("whole row equality"),
        );
        let folded_free = self.free_device(folded).err();
        let weights_free = self.free_device(row_weights).err();
        match (value, folded_free.or(weights_free)) {
            (Ok(value), None) => Ok(value),
            (Err(error), _) | (_, Some(error)) => Err(error),
        }
    }

    /// MLE of a logical column window inside a wider row-major matrix.
    /// Point order is padded window columns followed by padded rows.
    #[allow(clippy::too_many_arguments)]
    pub fn matrix_window_mle_eval_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        rows: usize,
        stride: usize,
        column_offset: usize,
        cols: usize,
        point: &[Fp2],
    ) -> Result<Fp2, AccelError> {
        let col_bits = cols
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("shape overflow"))?
            .trailing_zeros() as usize;
        let row_bits = rows
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("shape overflow"))?
            .trailing_zeros() as usize;
        if point.len() != col_bits + row_bits {
            return Err(AccelError::InvalidInput("resident matrix-window MLE point mismatch"));
        }
        let col_weights = self.equality_weights_device(&point[..col_bits])?;
        let row_weights = match self.equality_weights_device(&point[col_bits..]) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(col_weights);
                return Err(error);
            }
        };
        let folded = match self.matrix_window_fold_device(
            input,
            DeviceSlice::new(&col_weights, 0, cols).expect("real window equality prefix"),
            rows,
            stride,
            column_offset,
            cols,
            MatrixFoldAxis::Columns,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(row_weights);
                let _ = self.free_device(col_weights);
                return Err(error);
            }
        };
        let first_free = self.free_device(col_weights).err();
        if let Some(error) = first_free {
            let _ = self.free_device(folded);
            let _ = self.free_device(row_weights);
            return Err(error);
        }
        let value = self.fp2_dot_device(
            DeviceSlice::new(&folded, 0, folded.len()).expect("whole window row fold"),
            DeviceSlice::new(&row_weights, 0, row_weights.len()).expect("whole row equality"),
        );
        let folded_free = self.free_device(folded).err();
        let weights_free = self.free_device(row_weights).err();
        match (value, folded_free.or(weights_free)) {
            (Ok(value), None) => Ok(value),
            (Err(error), _) | (_, Some(error)) => Err(error),
        }
    }

    /// Weighted sum of an arbitrary resident base/Fp2 vector. Public weights
    /// are protocol data and are uploaded once; only the scalar crosses D2H.
    pub fn weighted_sum_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        weights: &[Fp2],
    ) -> Result<Fp2, AccelError> {
        if input.is_empty() || input.len() != weights.len() {
            return Err(AccelError::InvalidInput("resident weighted-sum geometry mismatch"));
        }
        let raw: Vec<Fp2Repr> = weights.iter().copied().map(Into::into).collect();
        let device_weights = self.upload_new_device(&raw)?;
        let folded = match self.matrix_fold_device(
            input,
            DeviceSlice::new(&device_weights, 0, raw.len()).expect("whole weighted-sum row"),
            1,
            input.len(),
            MatrixFoldAxis::Columns,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(device_weights);
                return Err(error);
            }
        };
        if let Err(error) = self.free_device(device_weights) {
            let _ = self.free_device(folded);
            return Err(error);
        }
        let value = self.download_device(&folded, 0, 1).map(|values| Fp2::from(values[0]));
        let free_result = self.free_device(folded);
        match (value, free_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    /// Dot product of two resident Fp2 vectors. The returned scalar is a
    /// protocol-sized host message; neither input crosses D2H.
    pub fn fp2_dot_device(
        &mut self,
        a: DeviceSlice<'_, Fp2Repr>,
        b: DeviceSlice<'_, Fp2Repr>,
    ) -> Result<Fp2, AccelError> {
        if a.is_empty() || a.len() != b.len() {
            return Err(AccelError::InvalidInput("invalid resident Fp2 dot geometry"));
        }
        self.validate_device_slice(a, a.len())?;
        self.validate_device_slice(b, b.len())?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fp2_dot_device(
                a.buffer.id,
                a.offset,
                b.buffer.id,
                b.offset,
                a.len,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Compressed `[g(0), g(2)]` product-sumcheck round over two resident
    /// Fp2 vectors. Folding remains a separate D2D operation so Rust retains
    /// transcript/challenge orchestration.
    pub fn fp2_product_round_device(
        &mut self,
        a: DeviceSlice<'_, Fp2Repr>,
        b: DeviceSlice<'_, Fp2Repr>,
    ) -> Result<[Fp2; 2], AccelError> {
        if a.len() != b.len() || a.len() < 2 || a.len() % 2 != 0 {
            return Err(AccelError::InvalidInput(
                "invalid resident product-sumcheck round geometry",
            ));
        }
        self.validate_device_slice(a, a.len())?;
        self.validate_device_slice(b, b.len())?;
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .fp2_product_round_device(a.buffer.id, a.offset, b.buffer.id, b.offset, a.len / 2);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn fp2_triple_product_round_device(
        &mut self,
        a: DeviceSlice<'_, Fp2Repr>,
        b: DeviceSlice<'_, Fp2Repr>,
        c: DeviceSlice<'_, Fp2Repr>,
    ) -> Result<[Fp2; 3], AccelError> {
        if a.len() != b.len() || a.len() != c.len() || a.len() < 2 || a.len() % 2 != 0 {
            return Err(AccelError::InvalidInput("invalid resident triple-product round geometry"));
        }
        for input in [a, b, c] {
            self.validate_device_slice(input, input.len())?;
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .fp2_triple_product_round_device(
                    a.buffer.id,
                    a.offset,
                    b.buffer.id,
                    b.offset,
                    c.buffer.id,
                    c.offset,
                    a.len / 2,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Construct the two full-domain factors used by the broadcast
    /// LayerNorm Hadamard relation: `(x-mean)` and `(rsqrt*gain)`.
    #[allow(clippy::too_many_arguments)]
    pub fn ln_hadamard_factors_device(
        &mut self,
        input: DeviceSlice<'_, i16>,
        mean: DeviceSlice<'_, u64>,
        rsqrt: DeviceSlice<'_, u64>,
        gain: DeviceSlice<'_, i16>,
        rows: usize,
        cols: usize,
    ) -> Result<(DeviceBuffer<Fp2Repr>, DeviceBuffer<Fp2Repr>), AccelError> {
        if rows == 0 || cols == 0 {
            return Err(AccelError::InvalidInput("invalid resident LN Hadamard geometry"));
        }
        self.validate_device_slice(input, checked_product(rows, cols)?)?;
        self.validate_device_slice(gain, cols)?;
        let row_pad =
            rows.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let col_pad =
            cols.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        self.validate_device_slice(mean, row_pad)?;
        self.validate_device_slice(rsqrt, row_pad)?;
        let total = checked_product(row_pad, col_pad)?;
        let centered = self.alloc_device(total)?;
        let scaled = match self.alloc_device(total) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(centered);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").ln_hadamard_factors_device(
                input.buffer.id,
                input.offset,
                mean.buffer.id,
                mean.offset,
                rsqrt.buffer.id,
                rsqrt.offset,
                gain.buffer.id,
                gain.offset,
                centered.id,
                0,
                scaled.id,
                0,
                rows,
                cols,
                row_pad,
                col_pad,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(scaled);
            let _ = self.free_device(centered);
            return Err(error);
        }
        Ok((centered, scaled))
    }

    /// Canonically lift a resident base vector to Fp2 and repeat each input
    /// element `repeat` times. `repeat = 1` is the ordinary lift; larger
    /// values implement row-table broadcasts without a host materialization.
    pub fn base_to_fp2_broadcast_device<T: ResidentBaseElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        repeat: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        if input.is_empty() || repeat == 0 {
            return Err(AccelError::InvalidInput("invalid resident base broadcast geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        let output_len = checked_product(input.len(), repeat)?;
        let output = self.alloc_device(output_len)?;
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").base_broadcast_fp2_device(
                input.buffer.id,
                input.offset,
                output.id,
                0,
                input.len(),
                repeat,
                T::CUDA_KIND,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Repeat a typed resident vector contiguously without changing its
    /// scalar representation. Used for protocol batch padding/duplication.
    pub fn repeat_vector_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        repeat: usize,
    ) -> Result<DeviceBuffer<T>, AccelError> {
        if input.is_empty() || repeat == 0 {
            return Err(AccelError::InvalidInput("invalid resident vector repeat geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        let output_len = checked_product(input.len(), repeat)?;
        let output = self.alloc_device(output_len)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").repeat_vector_device(
            input.buffer.id,
            input.offset,
            output.id,
            0,
            input.len(),
            repeat,
            T::CUDA_KIND,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Copy the same contiguous column window from each physical source row
    /// into a compact resident matrix. This is the shape-parametric D2D
    /// primitive used to view suffix/band data without a host staging copy.
    pub fn compact_strided_rows_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        rows: usize,
        source_stride: usize,
        width: usize,
    ) -> Result<DeviceBuffer<T>, AccelError> {
        if rows == 0 || width == 0 || source_stride < width {
            return Err(AccelError::InvalidInput("invalid resident strided-copy geometry"));
        }
        let source_len = rows
            .checked_sub(1)
            .and_then(|n| n.checked_mul(source_stride))
            .and_then(|n| n.checked_add(width))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        self.validate_device_slice(input, source_len)?;
        let output_len = checked_product(rows, width)?;
        let output = self.alloc_device(output_len)?;
        let result = self.compact_strided_rows_into_device(
            input,
            DeviceSlice::new(&output, 0, output_len).expect("whole compact output"),
            rows,
            source_stride,
            width,
        );
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// In-place destination form of [`Backend::compact_strided_rows_device`]
    /// for callers that pack several derived views into one owned allocation.
    pub fn compact_strided_rows_into_device<T: ResidentMatrixElement>(
        &mut self,
        input: DeviceSlice<'_, T>,
        output: DeviceSlice<'_, T>,
        rows: usize,
        source_stride: usize,
        width: usize,
    ) -> Result<(), AccelError> {
        if rows == 0 || width == 0 || source_stride < width {
            return Err(AccelError::InvalidInput("invalid resident strided-copy geometry"));
        }
        let source_len = rows
            .checked_sub(1)
            .and_then(|n| n.checked_mul(source_stride))
            .and_then(|n| n.checked_add(width))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let output_len = checked_product(rows, width)?;
        self.validate_device_slice(input, source_len)?;
        self.validate_device_slice(output, output_len)?;
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .compact_strided_rows_device(
                    input.buffer.id,
                    input.offset,
                    output.buffer.id,
                    output.offset,
                    rows,
                    source_stride,
                    width,
                    T::CUDA_KIND,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Zero an equality row outside the real above-causal attention cells.
    /// The buffer is modified in place and retains the same ownership.
    #[allow(clippy::too_many_arguments)]
    pub fn attention_above_mask_device(
        &mut self,
        equality: &DeviceBuffer<Fp2Repr>,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_pad: usize,
    ) -> Result<(), AccelError> {
        if rows == 0
            || seq == 0
            || heads == 0
            || head_pad < heads
            || !head_pad.is_power_of_two()
            || pos0.checked_add(rows).filter(|&end| end == seq).is_none()
        {
            return Err(AccelError::InvalidInput("invalid resident above-causal mask geometry"));
        }
        let q_pad =
            rows.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let s_pad =
            seq.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let entries = checked_product(head_pad, checked_product(q_pad, s_pad)?)?;
        if equality.len() != entries {
            return Err(AccelError::InvalidInput("above-causal equality dimension mismatch"));
        }
        self.validate_device_slice(
            DeviceSlice::new(equality, 0, equality.len()).expect("whole above-mask equality"),
            entries,
        )?;
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .attention_above_mask_device(
                    equality.id,
                    0,
                    entries,
                    rows,
                    seq,
                    pos0,
                    heads,
                    head_pad,
                    q_pad,
                    s_pad,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Materialize the attention columns consumed by the proof from the
    /// causal-packed forward witness. All dimensions are runtime parameters;
    /// `own_k`/`v` contain the current band's rows while `k_cache` may include
    /// a prefix. Returned values are canonical Goldilocks elements.
    #[allow(clippy::too_many_arguments)]
    pub fn attention_proof_wires_device(
        &mut self,
        q: DeviceSlice<'_, i16>,
        k_cache: DeviceSlice<'_, i16>,
        own_k: DeviceSlice<'_, i16>,
        v: DeviceSlice<'_, i16>,
        scores_acc: DeviceSlice<'_, i64>,
        scores_q: DeviceSlice<'_, i16>,
        row_shifts: DeviceSlice<'_, i16>,
        exp_outputs: DeviceSlice<'_, i16>,
        denoms: DeviceSlice<'_, i64>,
        recips: DeviceSlice<'_, i16>,
        softmax_weights: DeviceSlice<'_, i16>,
        recip_lut: DeviceSlice<'_, i16>,
        qkv_acc: DeviceSlice<'_, i64>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_pad: usize,
        head_dim: usize,
        shift_scores: u32,
        shift_softmax_norm: u32,
        shift_qkv: u32,
        recip_den_shift: u32,
        exp_pad_input: i16,
        recip_pad_output: i16,
        use_row_shift: bool,
    ) -> Result<DeviceAttentionProofWires, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = (exp_pad_input, recip_pad_output, use_row_shift);
        if rows < 2
            || seq == 0
            || heads == 0
            || head_dim == 0
            || head_pad < heads
            || !head_pad.is_power_of_two()
            || pos0.checked_add(rows).filter(|&end| end == seq).is_none()
            || !(1..=16).contains(&shift_scores)
            || !(1..=16).contains(&shift_softmax_norm)
            || !(1..=16).contains(&shift_qkv)
            || recip_den_shift >= 63
        {
            return Err(AccelError::InvalidInput("invalid resident attention-proof geometry"));
        }
        let d = checked_product(heads, head_dim)?;
        let packed_per_head = rows
            .checked_mul(pos0)
            .and_then(|prefix| {
                rows.checked_mul(rows + 1)
                    .and_then(|twice_triangle| prefix.checked_add(twice_triangle / 2))
            })
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let packed = checked_product(heads, packed_per_head)?;
        let real_rows = checked_product(heads, rows)?;
        for slice in [q, own_k, v] {
            self.validate_device_slice(slice, checked_product(rows, d)?)?;
        }
        self.validate_device_slice(k_cache, checked_product(seq, d)?)?;
        self.validate_device_slice(scores_acc, packed)?;
        self.validate_device_slice(scores_q, packed)?;
        self.validate_device_slice(row_shifts, real_rows)?;
        self.validate_device_slice(exp_outputs, packed)?;
        self.validate_device_slice(denoms, real_rows)?;
        self.validate_device_slice(recips, real_rows)?;
        self.validate_device_slice(softmax_weights, packed)?;
        self.validate_device_slice(recip_lut, 1 << 16)?;
        self.validate_device_slice(qkv_acc, checked_product(rows, checked_product(3, d)?)?)?;
        self.validate_device_slice(error, 1)?;

        let q_pad =
            rows.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let s_pad =
            seq.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let d_pad =
            d.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let rect_entries = checked_product(head_pad, checked_product(q_pad, s_pad)?)?;
        let row_entries = checked_product(head_pad, q_pad)?;
        let above_per_head =
            rows.checked_mul(rows - 1).ok_or(AccelError::InvalidInput("shape overflow"))? / 2;
        let above_entries = checked_product(heads, above_per_head)?;
        let qkv_entries = checked_product(q_pad, checked_product(4, d_pad)?)?;

        let rect = self.alloc_device(checked_product(7, rect_entries)?)?;
        let row_values = match self.alloc_device(checked_product(4, row_entries)?) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(rect);
                return Err(error);
            }
        };
        let above = match self.alloc_device(above_entries) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(row_values);
                let _ = self.free_device(rect);
                return Err(error);
            }
        };
        let qkv = match self.alloc_device(checked_product(2, qkv_entries)?) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(above);
                let _ = self.free_device(row_values);
                let _ = self.free_device(rect);
                return Err(error);
            }
        };

        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").attention_proof_wires_device(
                q.buffer.id,
                q.offset,
                k_cache.buffer.id,
                k_cache.offset,
                own_k.buffer.id,
                own_k.offset,
                v.buffer.id,
                v.offset,
                scores_acc.buffer.id,
                scores_acc.offset,
                scores_q.buffer.id,
                scores_q.offset,
                row_shifts.buffer.id,
                row_shifts.offset,
                exp_outputs.buffer.id,
                exp_outputs.offset,
                denoms.buffer.id,
                denoms.offset,
                recips.buffer.id,
                recips.offset,
                softmax_weights.buffer.id,
                softmax_weights.offset,
                recip_lut.buffer.id,
                recip_lut.offset,
                qkv_acc.buffer.id,
                qkv_acc.offset,
                error.buffer.id,
                error.offset,
                rect.id,
                0,
                row_values.id,
                0,
                above.id,
                0,
                qkv.id,
                0,
                rows,
                seq,
                pos0,
                heads,
                head_pad,
                head_dim,
                q_pad,
                s_pad,
                d_pad,
                shift_scores,
                shift_softmax_norm,
                shift_qkv,
                recip_den_shift,
                exp_pad_input,
                recip_pad_output,
                use_row_shift,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(qkv);
            let _ = self.free_device(above);
            let _ = self.free_device(row_values);
            let _ = self.free_device(rect);
            return Err(error);
        }
        Ok(DeviceAttentionProofWires {
            rect,
            rect_entries,
            rows: row_values,
            row_entries,
            above,
            qkv,
            qkv_entries,
        })
    }

    pub fn free_attention_proof_wires(
        &mut self,
        wires: DeviceAttentionProofWires,
    ) -> Result<(), AccelError> {
        let first = self.free_device(wires.qkv).err();
        let second = self.free_device(wires.above).err();
        let third = self.free_device(wires.rows).err();
        let fourth = self.free_device(wires.rect).err();
        first.or(second).or(third).or(fourth).map_or(Ok(()), Err)
    }

    /// Build padded requant lookup columns. Single-stage order is
    /// `[remainder, output]`; chained order is
    /// `[stage1_remainder, stage1_output, stage2_remainder, final_output]`.
    #[allow(clippy::too_many_arguments)]
    pub fn requant_lookup_columns_device<A: ResidentSignedElement>(
        &mut self,
        accumulators: DeviceSlice<'_, A>,
        outputs: DeviceSlice<'_, i16>,
        error: DeviceSlice<'_, u32>,
        rows: usize,
        cols: usize,
        shift: u32,
    ) -> Result<DeviceLookupColumns, AccelError> {
        if rows == 0 || cols == 0 || shift == 0 || shift >= 63 {
            return Err(AccelError::InvalidInput("invalid resident requant-column geometry"));
        }
        let real = checked_product(rows, cols)?;
        self.validate_device_slice(accumulators, real)?;
        self.validate_device_slice(outputs, real)?;
        self.validate_device_slice(error, 1)?;
        let row_pad =
            rows.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let col_pad =
            cols.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let entries = checked_product(row_pad, col_pad)?;
        let columns = if shift > 16 { 4 } else { 2 };
        let storage = self.alloc_device(checked_product(columns, entries)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").requant_columns_device(
            accumulators.buffer.id,
            accumulators.offset,
            outputs.buffer.id,
            outputs.offset,
            storage.id,
            0,
            error.buffer.id,
            error.offset,
            rows,
            cols,
            row_pad,
            col_pad,
            A::CUDA_KIND,
            shift,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(storage);
            return Err(error);
        }
        Ok(DeviceLookupColumns { storage, columns, entries })
    }

    pub fn pair_lookup_columns_device(
        &mut self,
        inputs: DeviceSlice<'_, i16>,
        outputs: DeviceSlice<'_, i16>,
        rows: usize,
        cols: usize,
        pad_input: i16,
        pad_output: i16,
    ) -> Result<DeviceLookupColumns, AccelError> {
        self.pair_lookup_columns_base_device(
            inputs,
            outputs,
            rows,
            cols,
            Fp::from_i64(pad_input as i64),
            Fp::from_i64(pad_output as i64),
        )
    }

    pub fn pair_lookup_columns_base_device<A: ResidentBaseElement, B: ResidentBaseElement>(
        &mut self,
        inputs: DeviceSlice<'_, A>,
        outputs: DeviceSlice<'_, B>,
        rows: usize,
        cols: usize,
        pad_input: Fp,
        pad_output: Fp,
    ) -> Result<DeviceLookupColumns, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = (pad_input, pad_output);
        if rows == 0 || cols == 0 {
            return Err(AccelError::InvalidInput("invalid resident pair-column geometry"));
        }
        let real = checked_product(rows, cols)?;
        self.validate_device_slice(inputs, real)?;
        self.validate_device_slice(outputs, real)?;
        let row_pad =
            rows.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let col_pad =
            cols.checked_next_power_of_two().ok_or(AccelError::InvalidInput("shape overflow"))?;
        let entries = checked_product(row_pad, col_pad)?;
        let storage = self.alloc_device(checked_product(2, entries)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").pair_columns_device(
            inputs.buffer.id,
            inputs.offset,
            outputs.buffer.id,
            outputs.offset,
            storage.id,
            0,
            rows,
            cols,
            row_pad,
            col_pad,
            pad_input,
            pad_output,
            A::CUDA_KIND,
            B::CUDA_KIND,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(storage);
            return Err(error);
        }
        Ok(DeviceLookupColumns { storage, columns: 2, entries })
    }

    /// Histogram a padded pair-LUT input column in the table's canonical
    /// u16 index order. Signed LUTs map negative field representatives back
    /// to their two's-complement indices; nonnegative LUTs require <2^16.
    pub fn histogram_lut_device(
        &mut self,
        input: DeviceSlice<'_, u64>,
        signed_input: bool,
    ) -> Result<DeviceBuffer<u32>, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = signed_input;
        if input.is_empty() {
            return Err(AccelError::InvalidInput("invalid resident LUT histogram geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        let output = self.alloc_device(1 << 16)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").histogram_lut_device(
            input.buffer.id,
            input.offset,
            output.id,
            0,
            input.len,
            signed_input,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    pub fn histogram_fp_device(
        &mut self,
        input: DeviceSlice<'_, u64>,
        bins: usize,
    ) -> Result<DeviceBuffer<u32>, AccelError> {
        if input.is_empty() || bins == 0 {
            return Err(AccelError::InvalidInput("invalid resident histogram geometry"));
        }
        self.validate_device_slice(input, input.len())?;
        let output = self.alloc_device(bins)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").histogram_fp_device(
            input.buffer.id,
            input.offset,
            output.id,
            0,
            input.len,
            bins,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    pub fn u32_add_inplace_device(
        &mut self,
        target: DeviceSlice<'_, u32>,
        add: DeviceSlice<'_, u32>,
    ) -> Result<(), AccelError> {
        if target.is_empty() || target.len() != add.len() {
            return Err(AccelError::InvalidInput("invalid resident u32-add geometry"));
        }
        self.validate_device_slice(target, target.len())?;
        self.validate_device_slice(add, add.len())?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").u32_add_inplace_device(
                target.buffer.id,
                target.offset,
                add.buffer.id,
                add.offset,
                target.len,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn pack_lookup_leaf_device(
        &mut self,
        columns: DeviceSlice<'_, u64>,
        column_count: usize,
        entries: usize,
        shifts: &[Option<u32>],
        alpha0: Fp,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = alpha0;
        if column_count == 0
            || shifts.len() != column_count
            || entries < 2
            || !entries.is_power_of_two()
            || shifts.iter().flatten().any(|&shift| shift >= 63)
            || !shifts.iter().any(Option::is_some)
        {
            return Err(AccelError::InvalidInput("invalid resident lookup-leaf geometry"));
        }
        self.validate_device_slice(columns, checked_product(column_count, entries)?)?;
        let raw_shifts: Vec<u32> = shifts.iter().map(|shift| shift.unwrap_or(u32::MAX)).collect();
        let dshifts = self.upload_new_device(&raw_shifts)?;
        let leaf = match self.alloc_device(entries) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.free_device(dshifts);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").pack_lookup_leaf_device(
                columns.buffer.id,
                columns.offset,
                dshifts.id,
                0,
                leaf.id,
                0,
                column_count,
                entries,
                alpha0,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        let free_result = self.free_device(dshifts);
        if let Err(error) = result {
            let _ = self.free_device(leaf);
            return Err(error);
        }
        free_result?;
        Ok(leaf)
    }

    pub fn deinterleave_base_columns_device(
        &mut self,
        columns: DeviceSlice<'_, u64>,
        column_count: usize,
        entries: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        if column_count == 0 || entries < 2 || entries % 2 != 0 {
            return Err(AccelError::InvalidInput(
                "invalid resident base-column deinterleave geometry",
            ));
        }
        let total = checked_product(column_count, entries)?;
        self.validate_device_slice(columns, total)?;
        let output = self.alloc_device(total)?;
        #[cfg(feature = "cuda")]
        let result = self
            .cuda
            .as_mut()
            .expect("CUDA kind without context")
            .deinterleave_base_columns_device(
                columns.buffer.id,
                columns.offset,
                output.id,
                0,
                column_count,
                entries,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    pub fn free_lookup_columns(&mut self, columns: DeviceLookupColumns) -> Result<(), AccelError> {
        self.free_device(columns.storage)
    }

    /// Run explicitly residual host work. Hybrid accounting is deliberate;
    /// resident mode rejects it instead of silently falling back.
    pub fn cpu_residual<T>(
        &mut self,
        op: Operation,
        f: impl FnOnce() -> T,
    ) -> Result<T, AccelError> {
        if self.kind == BackendKind::CudaResident {
            return Err(AccelError::ResidualForbidden(op));
        }
        let t0 = Instant::now();
        let value = f();
        if self.kind == BackendKind::CudaHybrid {
            self.cpu_residual_ns[op as usize] += t0.elapsed().as_nanos() as u64;
        }
        Ok(value)
    }

    /// Attribute the host portion of a staged operation from its wall time
    /// and a stats snapshot taken immediately before it. Device event time is
    /// removed; the remainder includes host computation and launch overhead.
    pub fn account_staged_wall(
        &mut self,
        op: Operation,
        wall: Duration,
        before: BackendStats,
    ) -> Result<(), AccelError> {
        if self.kind == BackendKind::Cpu {
            return Ok(());
        }
        if self.kind == BackendKind::CudaResident {
            return Err(AccelError::ResidualForbidden(op));
        }
        let after = self.stats()?;
        let device_before = before.h2d_ns
            + before.d2h_ns
            + before.operations.iter().map(|x| x.kernel_ns).sum::<u64>();
        let device_after =
            after.h2d_ns + after.d2h_ns + after.operations.iter().map(|x| x.kernel_ns).sum::<u64>();
        self.cpu_residual_ns[op as usize] +=
            (wall.as_nanos() as u64).saturating_sub(device_after.saturating_sub(device_before));
        Ok(())
    }

    pub fn gemm_i64(
        &mut self,
        a: &[i16],
        b: &[i16],
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<Vec<i64>, AccelError> {
        validate_gemm(a, b, m, k, n)?;
        if self.kind == BackendKind::Cpu {
            return Err(AccelError::InvalidInput("gemm_i64 called on the CPU backend"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").gemm_i64(a, b, m, k, n);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn gemm_requant_auth(
        &mut self,
        a: &[i16],
        b: &[i16],
        masks: &[Fp],
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(Vec<i16>, Vec<u64>), AccelError> {
        validate_gemm(a, b, m, k, n)?;
        if masks.len() != m.checked_mul(n).ok_or(AccelError::InvalidInput("shape overflow"))? {
            return Err(AccelError::InvalidInput("mask length does not match GEMM output"));
        }
        if shift == 0 || shift >= 63 {
            return Err(AccelError::InvalidInput("requant shift must be in 1..63"));
        }
        if self.kind == BackendKind::Cpu {
            return Err(AccelError::InvalidInput("gemm_requant_auth called on the CPU backend"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .gemm_requant_auth(a, b, masks, m, k, n, shift);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn ntt_fp(&mut self, msg: &[Fp], size: usize) -> Result<Vec<Fp>, AccelError> {
        validate_ntt(msg.len(), size)?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().ok_or(AccelError::FeatureDisabled)?.ntt_fp(msg, size);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn ntt_fp_batch(
        &mut self,
        messages: &[Fp],
        rows: usize,
        msg_len: usize,
        size: usize,
    ) -> Result<Vec<Fp>, AccelError> {
        validate_ntt(msg_len, size)?;
        if rows == 0
            || messages.len()
                != rows.checked_mul(msg_len).ok_or(AccelError::InvalidInput("shape overflow"))?
        {
            return Err(AccelError::InvalidInput("invalid batched NTT geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .ntt_fp_batch(messages, rows, msg_len, size);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn ntt_fp2(&mut self, msg: &[Fp2], size: usize) -> Result<Vec<Fp2>, AccelError> {
        validate_ntt(msg.len(), size)?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().ok_or(AccelError::FeatureDisabled)?.ntt_fp2(msg, size);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Batched NTT over already padded resident base-field rows.
    pub fn ntt_fp_batch_device(
        &mut self,
        input: &DeviceBuffer<u64>,
        input_offset: usize,
        rows: usize,
        size: usize,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        self.validate_buffer(input)?;
        validate_ntt(size, size)?;
        let total = checked_product(rows, size)?;
        validate_region(input.len, input_offset, total)?;
        let output = self.alloc_device(total)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").ntt_fp_batch_device(
            input.id,
            input_offset,
            rows,
            size,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Batched NTT over already padded resident extension-field rows.
    pub fn ntt_fp2_batch_device(
        &mut self,
        input: &DeviceBuffer<Fp2Repr>,
        input_offset: usize,
        rows: usize,
        size: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        self.validate_buffer(input)?;
        validate_ntt(size, size)?;
        let total = checked_product(rows, size)?;
        validate_region(input.len, input_offset, total)?;
        let output = self.alloc_device(total)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").ntt_fp2_batch_device(
            input.id,
            input_offset,
            rows,
            size,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Return internal fraction-tree layers in root-to-leaf order.  Each
    /// outer vector has lengths 1,2,...,n/2.
    pub fn logup_tree(
        &mut self,
        leaf_a: &[Fp],
        alpha1: Fp,
        mult: Option<&[u32]>,
    ) -> Result<(Vec<Vec<Fp2>>, Vec<Vec<Fp2>>), AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = alpha1;
        let n = leaf_a.len();
        if n < 2 || !n.is_power_of_two() {
            return Err(AccelError::InvalidInput("LogUp leaf count must be a power of two >= 2"));
        }
        if let Some(m) = mult {
            if m.len() != n {
                return Err(AccelError::InvalidInput("LogUp multiplicity length mismatch"));
            }
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .logup_tree(leaf_a, alpha1, mult);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Build a complete LogUp fraction tree in resident buffers. The outputs
    /// are flattened root-to-leaf (level offsets 0, 1, 3, ...); no tree node
    /// crosses the host boundary.
    pub fn logup_tree_device(
        &mut self,
        leaf_a: &DeviceBuffer<u64>,
        leaf_offset: usize,
        alpha1: Fp,
        mult: Option<(&DeviceBuffer<u32>, usize)>,
        n: usize,
    ) -> Result<(DeviceBuffer<Fp2Repr>, DeviceBuffer<Fp2Repr>), AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = alpha1;
        self.validate_buffer(leaf_a)?;
        if n < 2 || !n.is_power_of_two() {
            return Err(AccelError::InvalidInput("LogUp leaf count must be a power of two >= 2"));
        }
        validate_region(leaf_a.len, leaf_offset, n)?;
        if let Some((m, offset)) = mult {
            self.validate_buffer(m)?;
            validate_region(m.len, offset, n)?;
        }
        let p = self.alloc_device(n - 1)?;
        let q = match self.alloc_device(n - 1) {
            Ok(q) => q,
            Err(error) => {
                let _ = self.free_device(p);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").logup_tree_device(
            leaf_a.id,
            leaf_offset,
            mult.map(|(m, offset)| (m.id, offset)),
            n,
            alpha1,
            p.id,
            0,
            q.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(q);
            let _ = self.free_device(p);
            return Err(error);
        }
        Ok((p, q))
    }

    /// Materialize structured base-field leaves as full resident Fp2 `(p,q)`
    /// vectors for the leaf-layer round engine.
    pub fn logup_materialize_leaves_device(
        &mut self,
        leaf_a: &DeviceBuffer<u64>,
        leaf_offset: usize,
        alpha1: Fp,
        mult: Option<(&DeviceBuffer<u32>, usize)>,
        n: usize,
    ) -> Result<(DeviceBuffer<Fp2Repr>, DeviceBuffer<Fp2Repr>), AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = alpha1;
        self.validate_buffer(leaf_a)?;
        validate_region(leaf_a.len, leaf_offset, n)?;
        if n == 0 {
            return Err(AccelError::InvalidInput("zero LogUp leaf count"));
        }
        if let Some((m, offset)) = mult {
            self.validate_buffer(m)?;
            validate_region(m.len, offset, n)?;
        }
        let p = self.alloc_device(n)?;
        let q = match self.alloc_device(n) {
            Ok(q) => q,
            Err(error) => {
                let _ = self.free_device(p);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").logup_materialize_leaves_device(
                leaf_a.id,
                leaf_offset,
                mult.map(|(m, offset)| (m.id, offset)),
                n,
                alpha1,
                p.id,
                0,
                q.id,
                0,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(q);
            let _ = self.free_device(p);
            return Err(error);
        }
        Ok((p, q))
    }

    pub fn logup_general_round(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        suffix_eq: &[Fp2],
    ) -> Result<[Fp2; 4], AccelError> {
        let len = p0.len();
        if len < 2
            || len % 2 != 0
            || p1.len() != len
            || q0.len() != len
            || q1.len() != len
            || suffix_eq.len() != len / 2
        {
            return Err(AccelError::InvalidInput("invalid LogUp general-round geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .logup_general_round(p0, p1, q0, q1, suffix_eq);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Evaluate one resident LogUp round. Exactly four Fp2 protocol values
    /// are returned to Rust; all polynomial vectors remain on device.
    #[allow(clippy::too_many_arguments)]
    pub fn logup_general_round_device(
        &mut self,
        p0: &DeviceBuffer<Fp2Repr>,
        p0_offset: usize,
        p1: &DeviceBuffer<Fp2Repr>,
        p1_offset: usize,
        q0: &DeviceBuffer<Fp2Repr>,
        q0_offset: usize,
        q1: &DeviceBuffer<Fp2Repr>,
        q1_offset: usize,
        suffix_eq: &DeviceBuffer<Fp2Repr>,
        suffix_offset: usize,
        pairs: usize,
    ) -> Result<[Fp2; 4], AccelError> {
        for buffer in [p0, p1, q0, q1, suffix_eq] {
            self.validate_buffer(buffer)?;
        }
        let values = checked_product(2, pairs)?;
        for (buffer, offset) in [(p0, p0_offset), (p1, p1_offset), (q0, q0_offset), (q1, q1_offset)]
        {
            validate_region(buffer.len, offset, values)?;
        }
        validate_region(suffix_eq.len, suffix_offset, pairs)?;
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .expect("CUDA kind without context")
                .logup_general_round_device(
                    p0.id,
                    p0_offset,
                    p1.id,
                    p1_offset,
                    q0.id,
                    q0_offset,
                    q1.id,
                    q1_offset,
                    suffix_eq.id,
                    suffix_offset,
                    pairs,
                );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn logup_fold4(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        r: Fp2,
    ) -> Result<[Vec<Fp2>; 4], AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = r;
        let len = p0.len();
        if len < 2 || len % 2 != 0 || p1.len() != len || q0.len() != len || q1.len() != len {
            return Err(AccelError::InvalidInput("invalid LogUp fold geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .logup_fold4(p0, p1, q0, q1, r);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Fold four resident Fp2 vectors and keep all four outputs resident.
    #[allow(clippy::too_many_arguments)]
    pub fn logup_fold4_device(
        &mut self,
        p0: &DeviceBuffer<Fp2Repr>,
        p0_offset: usize,
        p1: &DeviceBuffer<Fp2Repr>,
        p1_offset: usize,
        q0: &DeviceBuffer<Fp2Repr>,
        q0_offset: usize,
        q1: &DeviceBuffer<Fp2Repr>,
        q1_offset: usize,
        pairs: usize,
        r: Fp2,
    ) -> Result<[DeviceBuffer<Fp2Repr>; 4], AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = r;
        for buffer in [p0, p1, q0, q1] {
            self.validate_buffer(buffer)?;
        }
        let values = checked_product(2, pairs)?;
        for (buffer, offset) in [(p0, p0_offset), (p1, p1_offset), (q0, q0_offset), (q1, q1_offset)]
        {
            validate_region(buffer.len, offset, values)?;
        }
        let o0 = self.alloc_device(pairs)?;
        let o1 = match self.alloc_device(pairs) {
            Ok(x) => x,
            Err(e) => {
                let _ = self.free_device(o0);
                return Err(e);
            }
        };
        let o2 = match self.alloc_device(pairs) {
            Ok(x) => x,
            Err(e) => {
                let _ = self.free_device(o1);
                let _ = self.free_device(o0);
                return Err(e);
            }
        };
        let o3 = match self.alloc_device(pairs) {
            Ok(x) => x,
            Err(e) => {
                let _ = self.free_device(o2);
                let _ = self.free_device(o1);
                let _ = self.free_device(o0);
                return Err(e);
            }
        };
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").logup_fold4_device(
            p0.id, p0_offset, p1.id, p1_offset, q0.id, q0_offset, q1.id, q1_offset, pairs, r,
            o0.id, 0, o1.id, 0, o2.id, 0, o3.id, 0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(o3);
            let _ = self.free_device(o2);
            let _ = self.free_device(o1);
            let _ = self.free_device(o0);
            return Err(error);
        }
        Ok([o0, o1, o2, o3])
    }

    /// Split an interleaved resident Fp2 vector into its even and odd halves.
    pub fn fp2_deinterleave_device(
        &mut self,
        input: &DeviceBuffer<Fp2Repr>,
        input_offset: usize,
        pairs: usize,
    ) -> Result<(DeviceBuffer<Fp2Repr>, DeviceBuffer<Fp2Repr>), AccelError> {
        self.validate_buffer(input)?;
        validate_region(input.len, input_offset, checked_product(2, pairs)?)?;
        let even = self.alloc_device(pairs)?;
        let odd = match self.alloc_device(pairs) {
            Ok(odd) => odd,
            Err(error) => {
                let _ = self.free_device(even);
                return Err(error);
            }
        };
        #[cfg(feature = "cuda")]
        let result = self
            .cuda
            .as_mut()
            .expect("CUDA kind without context")
            .fp2_deinterleave_device(input.id, input_offset, pairs, even.id, 0, odd.id, 0);
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(odd);
            let _ = self.free_device(even);
            return Err(error);
        }
        Ok((even, odd))
    }

    /// Construct every suffix-equality table from resident transcript
    /// challenges. Table `j` starts at `2^(point_len-1-j)-1`.
    pub fn logup_suffix_eq_device(
        &mut self,
        points: &DeviceBuffer<Fp2Repr>,
        points_offset: usize,
        point_len: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        self.validate_buffer(points)?;
        if point_len == 0 || point_len >= usize::BITS as usize {
            return Err(AccelError::InvalidInput("invalid LogUp suffix-eq dimension"));
        }
        validate_region(points.len, points_offset, point_len)?;
        let total = (1usize << point_len) - 1;
        let output = self.alloc_device(total)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").logup_suffix_eq_device(
            points.id,
            points_offset,
            point_len,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Fold `rows` independent resident Fp2 vectors of equal even length.
    pub fn fp2_fold_rows_device(
        &mut self,
        input: &DeviceBuffer<Fp2Repr>,
        input_offset: usize,
        rows: usize,
        len: usize,
        r: Fp2,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = r;
        self.validate_buffer(input)?;
        if rows == 0 || len < 2 || len % 2 != 0 {
            return Err(AccelError::InvalidInput("invalid resident row-fold geometry"));
        }
        validate_region(input.len, input_offset, checked_product(rows, len)?)?;
        let output = self.alloc_device(checked_product(rows, len / 2)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").fp2_fold_rows_device(
            input.id,
            input_offset,
            rows,
            len,
            r,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Build `rows` full equality tables from row-major resident points.
    pub fn logup_eq_rows_device(
        &mut self,
        points: Option<&DeviceBuffer<Fp2Repr>>,
        rows: usize,
        dims: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        if rows == 0 || dims >= usize::BITS as usize {
            return Err(AccelError::InvalidInput("invalid resident eq-row geometry"));
        }
        match (dims, points) {
            (0, None) => {}
            (0, Some(points)) => self.validate_buffer(points)?,
            (_, Some(points)) => {
                self.validate_buffer(points)?;
                validate_region(points.len, 0, checked_product(rows, dims)?)?;
            }
            (_, None) => {
                return Err(AccelError::InvalidInput(
                    "non-empty equality rows require resident points",
                ));
            }
        }
        let width = 1usize << dims;
        let output = self.alloc_device(checked_product(rows, width)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").logup_eq_rows_device(
            points.map_or(0, |p| p.id),
            0,
            rows,
            dims,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Evaluate one aux leaf round while q vectors, aux columns and equality
    /// rows stay resident. Only `[g(0), g(2), g(3)]` is returned.
    #[allow(clippy::too_many_arguments)]
    pub fn logup_aux_round_device(
        &mut self,
        q0: &DeviceBuffer<Fp2Repr>,
        q1: &DeviceBuffer<Fp2Repr>,
        suffix: &DeviceBuffer<Fp2Repr>,
        suffix_offset: usize,
        columns: &DeviceBuffer<Fp2Repr>,
        eq_rows: Option<&DeviceBuffer<Fp2Repr>>,
        claim_cols: Option<&DeviceBuffer<u32>>,
        weights: Option<&DeviceBuffer<Fp2Repr>>,
        column_count: usize,
        claim_count: usize,
        vector_len: usize,
        lambda: Fp2,
        cpref: Fp2,
        point: Fp2,
    ) -> Result<[Fp2; 3], AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = (lambda, cpref, point);
        for buffer in [q0, q1, columns] {
            self.validate_buffer(buffer)?;
        }
        self.validate_buffer(suffix)?;
        if column_count == 0 || vector_len < 2 || vector_len % 2 != 0 {
            return Err(AccelError::InvalidInput("invalid resident aux-round geometry"));
        }
        validate_region(q0.len, 0, vector_len)?;
        validate_region(q1.len, 0, vector_len)?;
        validate_region(suffix.len, suffix_offset, vector_len / 2)?;
        validate_region(columns.len, 0, checked_product(2 * column_count, vector_len)?)?;
        let optional_ids = if claim_count == 0 {
            (0, 0, 0)
        } else {
            let eq_rows =
                eq_rows.ok_or(AccelError::InvalidInput("missing resident aux eq rows"))?;
            let claim_cols =
                claim_cols.ok_or(AccelError::InvalidInput("missing resident aux column ids"))?;
            let weights =
                weights.ok_or(AccelError::InvalidInput("missing resident aux weights"))?;
            self.validate_buffer(eq_rows)?;
            self.validate_buffer(claim_cols)?;
            self.validate_buffer(weights)?;
            validate_region(eq_rows.len, 0, checked_product(claim_count, vector_len)?)?;
            validate_region(claim_cols.len, 0, claim_count)?;
            validate_region(weights.len, 0, checked_product(2, claim_count)?)?;
            (eq_rows.id, claim_cols.id, weights.id)
        };
        #[cfg(not(feature = "cuda"))]
        let _ = optional_ids;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").logup_aux_round_device(
                q0.id,
                0,
                q1.id,
                0,
                suffix.id,
                suffix_offset,
                columns.id,
                0,
                optional_ids.0,
                0,
                optional_ids.1,
                0,
                optional_ids.2,
                0,
                column_count,
                claim_count,
                vector_len,
                lambda,
                cpref,
                point,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn hash_fp_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
    ) -> Result<Vec<[u8; 32]>, AccelError> {
        if rows < 8
            || rows % 8 != 0
            || cols == 0
            || !cols.is_power_of_two()
            || matrix.len()
                != rows.checked_mul(cols).ok_or(AccelError::InvalidInput("shape overflow"))?
        {
            return Err(AccelError::InvalidInput("invalid PCS hash matrix geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .hash_fp_columns(matrix, rows, cols);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn pcs_combine_rows(
        &mut self,
        weights: &[i16],
        pads: &[Fp],
        coeffs: &[Fp2],
        rows: usize,
        cols: usize,
        pad: usize,
        combinations: usize,
    ) -> Result<Vec<Vec<Fp2>>, AccelError> {
        if rows == 0
            || cols == 0
            || combinations == 0
            || weights.len()
                != rows.checked_mul(cols).ok_or(AccelError::InvalidInput("shape overflow"))?
            || pads.len()
                != rows.checked_mul(pad).ok_or(AccelError::InvalidInput("shape overflow"))?
            || coeffs.len()
                != combinations
                    .checked_mul(rows)
                    .ok_or(AccelError::InvalidInput("shape overflow"))?
        {
            return Err(AccelError::InvalidInput("invalid PCS row-combination geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().ok_or(AccelError::FeatureDisabled)?.pcs_combine_rows(
                weights,
                pads,
                coeffs,
                rows,
                cols,
                pad,
                combinations,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn pcs_gather_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
        indices: &[u32],
    ) -> Result<Vec<Vec<Fp>>, AccelError> {
        if rows == 0
            || cols == 0
            || indices.is_empty()
            || matrix.len()
                != rows.checked_mul(cols).ok_or(AccelError::InvalidInput("shape overflow"))?
            || indices.iter().any(|&j| j as usize >= cols)
        {
            return Err(AccelError::InvalidInput("invalid PCS column-gather geometry"));
        }
        #[cfg(feature = "cuda")]
        {
            return self
                .cuda
                .as_mut()
                .ok_or(AccelError::FeatureDisabled)?
                .pcs_gather_columns(matrix, rows, cols, indices);
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    /// Construct padded PCS message rows from resident i16 weights and Fp
    /// pad tails. The output is base-field canonical u64 row-major storage.
    #[allow(clippy::too_many_arguments)]
    pub fn pcs_messages_device(
        &mut self,
        weights: &DeviceBuffer<i16>,
        weights_offset: usize,
        pads: &DeviceBuffer<u64>,
        pads_offset: usize,
        rows: usize,
        cols: usize,
        pad: usize,
        code_len: usize,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        self.validate_buffer(weights)?;
        self.validate_buffer(pads)?;
        if rows == 0 || cols == 0 || cols.checked_add(pad).is_none_or(|n| n > code_len) {
            return Err(AccelError::InvalidInput("invalid resident PCS message geometry"));
        }
        validate_region(weights.len, weights_offset, checked_product(rows, cols)?)?;
        validate_region(pads.len, pads_offset, checked_product(rows, pad)?)?;
        let output = self.alloc_device(checked_product(rows, code_len)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").pcs_messages_device(
            weights.id,
            weights_offset,
            pads.id,
            pads_offset,
            rows,
            cols,
            pad,
            code_len,
            output.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    /// Resident PCS row combinations. Coefficients are row-major
    /// `combinations × rows`; outputs remain resident Fp2 message rows.
    #[allow(clippy::too_many_arguments)]
    pub fn pcs_combine_rows_device(
        &mut self,
        weights: &DeviceBuffer<i16>,
        weights_offset: usize,
        pads: &DeviceBuffer<u64>,
        pads_offset: usize,
        coeffs: &DeviceBuffer<Fp2Repr>,
        coeffs_offset: usize,
        rows: usize,
        cols: usize,
        pad: usize,
        combinations: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        self.validate_buffer(weights)?;
        self.validate_buffer(pads)?;
        self.validate_buffer(coeffs)?;
        if rows == 0 || cols == 0 || combinations == 0 {
            return Err(AccelError::InvalidInput("invalid resident PCS combination geometry"));
        }
        validate_region(weights.len, weights_offset, checked_product(rows, cols)?)?;
        validate_region(pads.len, pads_offset, checked_product(rows, pad)?)?;
        validate_region(coeffs.len, coeffs_offset, checked_product(combinations, rows)?)?;
        let msg_len = cols.checked_add(pad).ok_or(AccelError::InvalidInput("shape overflow"))?;
        let output = self.alloc_device(checked_product(combinations, msg_len)?)?;
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").pcs_combine_rows_device(
                weights.id,
                weights_offset,
                pads.id,
                pads_offset,
                coeffs.id,
                coeffs_offset,
                rows,
                cols,
                pad,
                combinations,
                output.id,
                0,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }

    pub fn fp2_add_inplace_device(
        &mut self,
        target: &DeviceBuffer<Fp2Repr>,
        target_offset: usize,
        add: &DeviceBuffer<Fp2Repr>,
        add_offset: usize,
        len: usize,
    ) -> Result<(), AccelError> {
        self.validate_buffer(target)?;
        self.validate_buffer(add)?;
        validate_region(target.len, target_offset, len)?;
        validate_region(add.len, add_offset, len)?;
        #[cfg(feature = "cuda")]
        {
            return self.cuda.as_mut().expect("CUDA kind without context").fp2_add_inplace_device(
                target.id,
                target_offset,
                add.id,
                add_offset,
                len,
            );
        }
        #[cfg(not(feature = "cuda"))]
        Err(AccelError::FeatureDisabled)
    }

    pub fn hash_fp_tree_device(
        &mut self,
        matrix: &DeviceBuffer<u64>,
        rows: usize,
        cols: usize,
    ) -> Result<DeviceMerkleTree, AccelError> {
        self.hash_tree_device_impl(matrix, rows, cols, false)
    }

    pub fn hash_fp2_tree_device(
        &mut self,
        matrix: &DeviceBuffer<Fp2Repr>,
        rows: usize,
        cols: usize,
    ) -> Result<DeviceMerkleTree, AccelError> {
        self.hash_tree_device_impl(matrix, rows, cols, true)
    }

    fn hash_tree_device_impl<T: DeviceElement>(
        &mut self,
        matrix: &DeviceBuffer<T>,
        rows: usize,
        cols: usize,
        fp2: bool,
    ) -> Result<DeviceMerkleTree, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = fp2;
        self.validate_buffer(matrix)?;
        if rows == 0 || cols == 0 || !cols.is_power_of_two() {
            return Err(AccelError::InvalidInput("invalid resident Merkle matrix geometry"));
        }
        validate_region(matrix.len, 0, checked_product(rows, cols)?)?;
        let hashes = cols
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(AccelError::InvalidInput("shape overflow"))?;
        let storage = self.alloc_device(checked_product(hashes, 32)?)?;
        #[cfg(feature = "cuda")]
        let result = self
            .cuda
            .as_mut()
            .expect("CUDA kind without context")
            .hash_tree_device(fp2, matrix.id, 0, rows, cols, storage.id, 0);
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(storage);
            return Err(error);
        }
        Ok(DeviceMerkleTree { storage, leaves: cols })
    }

    pub fn merkle_root_device(&mut self, tree: &DeviceMerkleTree) -> Result<[u8; 32], AccelError> {
        self.validate_buffer(&tree.storage)?;
        let offset = (2 * tree.leaves - 2) * 32;
        Ok(self.download_device(&tree.storage, offset, 32)?.try_into().unwrap())
    }

    pub fn merkle_paths_device(
        &mut self,
        tree: &DeviceMerkleTree,
        indices: &DeviceBuffer<u32>,
        queries: usize,
    ) -> Result<DeviceBuffer<u8>, AccelError> {
        self.validate_buffer(&tree.storage)?;
        self.validate_buffer(indices)?;
        validate_region(indices.len, 0, queries)?;
        if queries == 0 {
            return Err(AccelError::InvalidInput("empty resident Merkle query set"));
        }
        let bits = tree.leaves.trailing_zeros() as usize;
        let paths = self.alloc_device(checked_product(checked_product(queries, bits)?, 32)?)?;
        #[cfg(feature = "cuda")]
        let result = self.cuda.as_mut().expect("CUDA kind without context").merkle_paths_device(
            tree.storage.id,
            0,
            tree.leaves,
            indices.id,
            0,
            queries,
            paths.id,
            0,
        );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(paths);
            return Err(error);
        }
        Ok(paths)
    }

    pub fn free_device_merkle_tree(&mut self, tree: DeviceMerkleTree) -> Result<(), AccelError> {
        self.free_device(tree.storage)
    }

    pub fn pcs_gather_fp_device(
        &mut self,
        matrix: &DeviceBuffer<u64>,
        rows: usize,
        cols: usize,
        indices: &DeviceBuffer<u32>,
        queries: usize,
    ) -> Result<DeviceBuffer<u64>, AccelError> {
        self.pcs_gather_device_impl(matrix, rows, cols, indices, queries, false)
    }

    pub fn pcs_gather_fp2_device(
        &mut self,
        matrix: &DeviceBuffer<Fp2Repr>,
        rows: usize,
        cols: usize,
        indices: &DeviceBuffer<u32>,
        queries: usize,
    ) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
        self.pcs_gather_device_impl(matrix, rows, cols, indices, queries, true)
    }

    fn pcs_gather_device_impl<T: DeviceElement>(
        &mut self,
        matrix: &DeviceBuffer<T>,
        rows: usize,
        cols: usize,
        indices: &DeviceBuffer<u32>,
        queries: usize,
        fp2: bool,
    ) -> Result<DeviceBuffer<T>, AccelError> {
        #[cfg(not(feature = "cuda"))]
        let _ = fp2;
        self.validate_buffer(matrix)?;
        self.validate_buffer(indices)?;
        validate_region(matrix.len, 0, checked_product(rows, cols)?)?;
        validate_region(indices.len, 0, queries)?;
        if rows == 0 || cols == 0 || queries == 0 {
            return Err(AccelError::InvalidInput("invalid resident PCS gather geometry"));
        }
        let output = self.alloc_device(checked_product(rows, queries)?)?;
        #[cfg(feature = "cuda")]
        let result =
            self.cuda.as_mut().expect("CUDA kind without context").pcs_gather_columns_device(
                fp2, matrix.id, 0, rows, cols, indices.id, 0, queries, output.id, 0,
            );
        #[cfg(not(feature = "cuda"))]
        let result: Result<(), AccelError> = Err(AccelError::FeatureDisabled);
        if let Err(error) = result {
            let _ = self.free_device(output);
            return Err(error);
        }
        Ok(output)
    }
}

fn validate_gemm(a: &[i16], b: &[i16], m: usize, k: usize, n: usize) -> Result<(), AccelError> {
    if m == 0 || k == 0 || n == 0 {
        return Err(AccelError::InvalidInput("zero GEMM dimension"));
    }
    if a.len() != m.checked_mul(k).ok_or(AccelError::InvalidInput("shape overflow"))?
        || b.len() != k.checked_mul(n).ok_or(AccelError::InvalidInput("shape overflow"))?
    {
        return Err(AccelError::InvalidInput("GEMM input length mismatch"));
    }
    Ok(())
}

fn checked_product(a: usize, b: usize) -> Result<usize, AccelError> {
    a.checked_mul(b).ok_or(AccelError::InvalidInput("shape overflow"))
}

fn validate_region(total: usize, offset: usize, len: usize) -> Result<(), AccelError> {
    if offset > total || len > total - offset {
        return Err(AccelError::InvalidInput("device buffer region is out of bounds"));
    }
    Ok(())
}

fn validate_ntt(msg_len: usize, size: usize) -> Result<(), AccelError> {
    if size < 2 || !size.is_power_of_two() || msg_len > size {
        return Err(AccelError::InvalidInput("invalid NTT geometry"));
    }
    Ok(())
}

#[cfg(feature = "cuda")]
mod cuda;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_is_default_and_residual_runs() {
        let mut b = Backend::cpu();
        assert_eq!(b.kind(), BackendKind::Cpu);
        b.begin_measurement().unwrap();
        assert_eq!(b.cpu_residual(Operation::Logup, || 7).unwrap(), 7);
        let stats = b.finish_measurement().unwrap();
        assert_eq!(stats.operation_cpu_residual_ns(), 0);
        assert_eq!(stats.cpu_residual_ns(), stats.measurement_wall_ns);
    }

    #[test]
    fn measurement_state_is_explicit() {
        let mut b = Backend::cpu();
        assert_eq!(b.finish_measurement(), Err(AccelError::MeasurementNotActive));
        b.begin_measurement().unwrap();
        assert_eq!(b.begin_measurement(), Err(AccelError::MeasurementAlreadyActive));
        b.finish_measurement().unwrap();
    }

    #[cfg(not(feature = "cuda"))]
    #[test]
    fn cuda_request_never_falls_back_without_feature() {
        assert!(matches!(Backend::cuda_hybrid(), Err(AccelError::FeatureDisabled)));
        assert!(matches!(Backend::cuda_resident(), Err(AccelError::FeatureDisabled)));
    }
}

#[cfg(all(test, feature = "cuda"))]
mod cuda_tests {
    use super::*;

    fn cuda(kind: BackendKind) -> Option<Backend> {
        let loaded = match kind {
            BackendKind::CudaHybrid => Backend::cuda_hybrid(),
            BackendKind::CudaResident => Backend::cuda_resident(),
            BackendKind::Cpu => unreachable!(),
        };
        match loaded {
            Ok(b) => Some(b),
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA differential test: {e}");
                None
            }
            Err(e) => panic!("CUDA is required for this test run: {e}"),
        }
    }

    fn cpu_gemm(a: &[i16], b: &[i16], m: usize, k: usize, n: usize) -> Vec<i64> {
        let mut out = vec![0; m * n];
        for i in 0..m {
            for q in 0..k {
                for j in 0..n {
                    out[i * n + j] += a[i * k + q] as i64 * b[q * n + j] as i64;
                }
            }
        }
        out
    }

    /// Deliberately violates the public move-only ownership rule so negative
    /// tests can present a stale opaque id to the C ABI.
    fn duplicate_device_buffer_for_test<T: DeviceElement>(
        buffer: &DeviceBuffer<T>,
    ) -> DeviceBuffer<T> {
        DeviceBuffer {
            id: buffer.id,
            len: buffer.len,
            context_id: buffer.context_id,
            _element: PhantomData,
        }
    }

    fn cpu_ntt(mut v: Vec<Fp>) -> Vec<Fp> {
        let n = v.len();
        let bits = n.trailing_zeros();
        for i in 0..n {
            let j = (i as u64).reverse_bits() as usize >> (64 - bits);
            if i < j {
                v.swap(i, j);
            }
        }
        let root = Fp::new(7).pow((volta_field::P - 1) >> bits);
        let mut tw = vec![Fp::ONE; n / 2];
        for i in 1..n / 2 {
            tw[i] = tw[i - 1] * root;
        }
        let mut len = 2;
        while len <= n {
            let step = n / len;
            for start in (0..n).step_by(len) {
                for k in 0..len / 2 {
                    let u = v[start + k];
                    let w = v[start + k + len / 2] * tw[k * step];
                    v[start + k] = u + w;
                    v[start + k + len / 2] = u - w;
                }
            }
            len *= 2;
        }
        v
    }

    fn cpu_tree(a: &[Fp], alpha1: Fp, mult: Option<&[u32]>) -> (Vec<Vec<Fp2>>, Vec<Vec<Fp2>>) {
        let a1sq7 = Fp::new(7) * alpha1 * alpha1;
        let mut p: Vec<Fp2> = (0..a.len() / 2)
            .map(|i| match mult {
                None => Fp2::new(a[2 * i] + a[2 * i + 1], alpha1 + alpha1),
                Some(m) => Fp2::new(
                    -(Fp::new(m[2 * i] as u64) * a[2 * i + 1]
                        + Fp::new(m[2 * i + 1] as u64) * a[2 * i]),
                    -((Fp::new(m[2 * i] as u64) + Fp::new(m[2 * i + 1] as u64)) * alpha1),
                ),
            })
            .collect();
        let mut q: Vec<Fp2> = (0..a.len() / 2)
            .map(|i| Fp2::new(a[2 * i] * a[2 * i + 1] + a1sq7, (a[2 * i] + a[2 * i + 1]) * alpha1))
            .collect();
        let mut ps = vec![p.clone()];
        let mut qs = vec![q.clone()];
        while p.len() > 1 {
            let pn: Vec<Fp2> = (0..p.len() / 2)
                .map(|i| p[2 * i] * q[2 * i + 1] + p[2 * i + 1] * q[2 * i])
                .collect();
            let qn: Vec<Fp2> = (0..q.len() / 2).map(|i| q[2 * i] * q[2 * i + 1]).collect();
            p = pn;
            q = qn;
            ps.push(p.clone());
            qs.push(q.clone());
        }
        ps.reverse();
        qs.reverse();
        (ps, qs)
    }

    fn at2(a: Fp2, b: Fp2) -> Fp2 {
        let d = b - a;
        a + d + d
    }

    fn cpu_merkle_levels(mut leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
        let mut levels = vec![leaves.clone()];
        while leaves.len() > 1 {
            leaves = leaves
                .chunks_exact(2)
                .map(|pair| {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&pair[0]);
                    hasher.update(&pair[1]);
                    *hasher.finalize().as_bytes()
                })
                .collect();
            levels.push(leaves.clone());
        }
        levels
    }

    #[test]
    fn gemm_and_fused_auth_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        gpu.begin_measurement().unwrap();
        for (m, k, n) in [(7, 33, 12), (3, 5, 7), (1, 64, 65)] {
            let a: Vec<i16> = (0..m * k).map(|i| ((37 * i + 11) % 401) as i16 - 200).collect();
            let b: Vec<i16> = (0..k * n).map(|i| ((53 * i + 5) % 401) as i16 - 200).collect();
            let expected = cpu_gemm(&a, &b, m, k, n);
            assert_eq!(gpu.gemm_i64(&a, &b, m, k, n).unwrap(), expected);
            let masks: Vec<Fp> =
                (0..m * n).map(|i| Fp::new((i as u64 * 97 + 13) % volta_field::P)).collect();
            let (out, corr) = gpu.gemm_requant_auth(&a, &b, &masks, m, k, n, 8).unwrap();
            for z in 0..m * n {
                let rounded = ((expected[z] + 128) >> 8).clamp(-32768, 32767) as i16;
                assert_eq!(out[z], rounded);
                assert_eq!(
                    Fp::new(corr[z]) + masks[z],
                    Fp::from_i64(rounded as i64),
                    "correction {z}"
                );
            }
        }
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(Operation::Gemm).calls, 6);
        assert!(stats.h2d_bytes > 0 && stats.d2h_bytes > 0);
        assert!(stats.h2d_ns > 0 && stats.d2h_ns > 0);
        assert!(stats.operation(Operation::Gemm).kernel_ns > 0);
        assert_eq!(
            stats.measurement_wall_ns,
            stats.h2d_ns + stats.d2h_ns + stats.kernel_ns() + stats.cpu_residual_ns()
        );
        assert_eq!(stats.synchronization_reason_total(), stats.synchronizations);
        assert_eq!(stats.sync_allocator_flush, 1, "one workspace growth must reclaim storage");
        match stats.timing_mode {
            DeviceTimingMode::CudaEvents => {
                assert_eq!(stats.sync_host_output, 6);
                assert_eq!(stats.sync_profiling_legacy, 0);
                assert_eq!(stats.synchronizations, 7);
            }
            DeviceTimingMode::HostBarrierWall => {
                assert_eq!(stats.sync_host_output, 6);
                assert_eq!(stats.sync_upload_lifetime, 6);
                assert_eq!(stats.sync_profiling_legacy, 6);
                assert_eq!(stats.synchronizations, 19);
            }
            DeviceTimingMode::None => panic!("CUDA stats have no timing mode"),
        }
    }

    #[test]
    fn ntt_fp_and_fp2_are_bit_exact_with_padding() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        for (msg_len, n) in [(3, 8), (17, 32), (513, 1024)] {
            let msg: Vec<Fp> = (0..msg_len).map(|i| Fp::new(i as u64 * 0x9E37_79B9 + 17)).collect();
            let mut padded = vec![Fp::ZERO; n];
            padded[..msg_len].copy_from_slice(&msg);
            assert_eq!(gpu.ntt_fp(&msg, n).unwrap(), cpu_ntt(padded.clone()));
            let msg2: Vec<Fp2> = msg
                .iter()
                .enumerate()
                .map(|(i, &x)| Fp2::new(x, Fp::new(i as u64 * 71 + 9)))
                .collect();
            let got = gpu.ntt_fp2(&msg2, n).unwrap();
            let mut c0 = vec![Fp::ZERO; n];
            let mut c1 = vec![Fp::ZERO; n];
            for (i, x) in msg2.iter().enumerate() {
                c0[i] = x.c0;
                c1[i] = x.c1;
            }
            let (c0, c1) = (cpu_ntt(c0), cpu_ntt(c1));
            let expected: Vec<Fp2> = c0.into_iter().zip(c1).map(|(a, b)| Fp2::new(a, b)).collect();
            assert_eq!(got, expected);
        }

        let rows = 3;
        let msg_len = 17;
        let n = 32;
        let messages: Vec<Fp> =
            (0..rows * msg_len).map(|i| Fp::new(i as u64 * 0x85EB_CA6B + 29)).collect();
        let got = gpu.ntt_fp_batch(&messages, rows, msg_len, n).unwrap();
        for row in 0..rows {
            let mut padded = vec![Fp::ZERO; n];
            padded[..msg_len].copy_from_slice(&messages[row * msg_len..(row + 1) * msg_len]);
            assert_eq!(&got[row * n..(row + 1) * n], cpu_ntt(padded));
        }
    }

    #[test]
    fn logup_tree_round_and_fold_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        for log_n in [1, 4, 10] {
            let n = 1usize << log_n;
            let a: Vec<Fp> = (0..n).map(|i| Fp::new(i as u64 * 0x85EB_CA6B + 29)).collect();
            let mult: Vec<u32> = (0..n).map(|i| ((i * 17 + 3) % 41) as u32).collect();
            let alpha1 = Fp::new(991);
            assert_eq!(gpu.logup_tree(&a, alpha1, None).unwrap(), cpu_tree(&a, alpha1, None));
            assert_eq!(
                gpu.logup_tree(&a, alpha1, Some(&mult)).unwrap(),
                cpu_tree(&a, alpha1, Some(&mult))
            );
        }

        let n = 256;
        let make = |tag: u64| {
            (0..n)
                .map(|i| Fp2::new(Fp::new(i as u64 * 37 + tag), Fp::new(i as u64 * 53 + tag + 1)))
                .collect::<Vec<_>>()
        };
        let p0 = make(1);
        let p1 = make(2);
        let q0 = make(3);
        let q1 = make(4);
        let suffix: Vec<Fp2> = (0..n / 2)
            .map(|i| Fp2::new(Fp::new(i as u64 * 71 + 7), Fp::new(i as u64 * 97 + 13)))
            .collect();
        let mut expected = [Fp2::ZERO; 4];
        for i in 0..n / 2 {
            let (a0, a2) = (p0[2 * i], at2(p0[2 * i], p0[2 * i + 1]));
            let (b0, b2) = (p1[2 * i], at2(p1[2 * i], p1[2 * i + 1]));
            let (c0, c2) = (q0[2 * i], at2(q0[2 * i], q0[2 * i + 1]));
            let (d0, d2) = (q1[2 * i], at2(q1[2 * i], q1[2 * i + 1]));
            expected[0] += suffix[i] * (a0 * d0 + b0 * c0);
            expected[1] += suffix[i] * (a2 * d2 + b2 * c2);
            expected[2] += suffix[i] * (c0 * d0);
            expected[3] += suffix[i] * (c2 * d2);
        }
        assert_eq!(gpu.logup_general_round(&p0, &p1, &q0, &q1, &suffix).unwrap(), expected);
        let r = Fp2::new(Fp::new(123), Fp::new(456));
        let got = gpu.logup_fold4(&p0, &p1, &q0, &q1, r).unwrap();
        for (src, folded) in [&p0, &p1, &q0, &q1].into_iter().zip(got) {
            for i in 0..n / 2 {
                assert_eq!(folded[i], src[2 * i] + (src[2 * i + 1] - src[2 * i]) * r);
            }
        }
    }

    #[test]
    fn resident_logup_tree_round_and_fold_keep_vectors_on_device() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let n = 1024usize;
        let leaf: Vec<Fp> = (0..n).map(|i| Fp::new(i as u64 * 0x85EB_CA6B + 29)).collect();
        let leaf_raw: Vec<u64> = leaf.iter().map(|x| x.value()).collect();
        let mult: Vec<u32> = (0..n).map(|i| ((i * 17 + 3) % 41) as u32).collect();
        let alpha1 = Fp::new(991);
        let dleaf = gpu.upload_new_device(&leaf_raw).unwrap();
        let dmult = gpu.upload_new_device(&mult).unwrap();

        let values = 256usize;
        let pairs = values / 2;
        let make = |tag: u64| {
            (0..values)
                .map(|i| Fp2::new(Fp::new(i as u64 * 37 + tag), Fp::new(i as u64 * 53 + tag + 1)))
                .collect::<Vec<_>>()
        };
        let p0 = make(1);
        let p1 = make(2);
        let q0 = make(3);
        let q1 = make(4);
        let suffix: Vec<Fp2> = (0..pairs)
            .map(|i| Fp2::new(Fp::new(i as u64 * 71 + 7), Fp::new(i as u64 * 97 + 13)))
            .collect();
        let repr = |v: &[Fp2]| v.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let dp0 = gpu.upload_new_device(&repr(&p0)).unwrap();
        let dp1 = gpu.upload_new_device(&repr(&p1)).unwrap();
        let dq0 = gpu.upload_new_device(&repr(&q0)).unwrap();
        let dq1 = gpu.upload_new_device(&repr(&q1)).unwrap();
        let ds = gpu.upload_new_device(&repr(&suffix)).unwrap();
        let points: Vec<Fp2> = (0..8)
            .map(|i| Fp2::new(Fp::new(i as u64 * 101 + 17), Fp::new(i as u64 * 127 + 23)))
            .collect();
        let dpoints = gpu.upload_new_device(&repr(&points)).unwrap();

        let mut expected_round = [Fp2::ZERO; 4];
        for i in 0..pairs {
            let (a0, a2) = (p0[2 * i], at2(p0[2 * i], p0[2 * i + 1]));
            let (b0, b2) = (p1[2 * i], at2(p1[2 * i], p1[2 * i + 1]));
            let (c0, c2) = (q0[2 * i], at2(q0[2 * i], q0[2 * i + 1]));
            let (d0, d2) = (q1[2 * i], at2(q1[2 * i], q1[2 * i + 1]));
            expected_round[0] += suffix[i] * (a0 * d0 + b0 * c0);
            expected_round[1] += suffix[i] * (a2 * d2 + b2 * c2);
            expected_round[2] += suffix[i] * (c0 * d0);
            expected_round[3] += suffix[i] * (c2 * d2);
        }
        let r = Fp2::new(Fp::new(123), Fp::new(456));

        gpu.begin_measurement().unwrap();
        let (dtp, dtq) = gpu.logup_tree_device(&dleaf, 0, alpha1, Some((&dmult, 0)), n).unwrap();
        let got_round = gpu
            .logup_general_round_device(&dp0, 0, &dp1, 0, &dq0, 0, &dq1, 0, &ds, 0, pairs)
            .unwrap();
        assert_eq!(got_round, expected_round);
        let folded = gpu.logup_fold4_device(&dp0, 0, &dp1, 0, &dq0, 0, &dq1, 0, pairs, r).unwrap();
        let (deven, dodd) = gpu.fp2_deinterleave_device(&dp0, 0, pairs).unwrap();
        let dsuffix = gpu.logup_suffix_eq_device(&dpoints, 0, points.len()).unwrap();
        let resident_stats = gpu.stats().unwrap();
        assert_eq!(resident_stats.h2d_bytes, 0);
        assert_eq!(resident_stats.d2h_bytes, 4 * size_of::<Fp2Repr>() as u64);
        assert_eq!(resident_stats.operation(Operation::Logup).calls, 5);

        // Differential downloads are outside the resident-path assertion.
        let expected_tree = cpu_tree(&leaf, alpha1, Some(&mult));
        let flat = |layers: Vec<Vec<Fp2>>| layers.into_iter().flatten().collect::<Vec<_>>();
        let got_p: Vec<Fp2> =
            gpu.download_device(&dtp, 0, n - 1).unwrap().into_iter().map(Into::into).collect();
        let got_q: Vec<Fp2> =
            gpu.download_device(&dtq, 0, n - 1).unwrap().into_iter().map(Into::into).collect();
        assert_eq!(got_p, flat(expected_tree.0));
        assert_eq!(got_q, flat(expected_tree.1));
        let got_even: Vec<Fp2> =
            gpu.download_device(&deven, 0, pairs).unwrap().into_iter().map(Into::into).collect();
        let got_odd: Vec<Fp2> =
            gpu.download_device(&dodd, 0, pairs).unwrap().into_iter().map(Into::into).collect();
        assert_eq!(got_even, (0..pairs).map(|i| p0[2 * i]).collect::<Vec<_>>());
        assert_eq!(got_odd, (0..pairs).map(|i| p0[2 * i + 1]).collect::<Vec<_>>());

        let mut expected_suffix = vec![Fp2::ONE];
        let mut current = vec![Fp2::ONE];
        for j in (1..points.len()).rev() {
            let mut next = Vec::with_capacity(current.len() * 2);
            for &v in &current {
                let v1 = v * points[j];
                next.push(v - v1);
                next.push(v1);
            }
            expected_suffix.extend_from_slice(&next);
            current = next;
        }
        let got_suffix: Vec<Fp2> = gpu
            .download_device(&dsuffix, 0, expected_suffix.len())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        assert_eq!(got_suffix, expected_suffix);
        for ((src, device), label) in
            [(&p0, &folded[0]), (&p1, &folded[1]), (&q0, &folded[2]), (&q1, &folded[3])]
                .into_iter()
                .zip(["p0", "p1", "q0", "q1"])
        {
            let got: Vec<Fp2> = gpu
                .download_device(device, 0, pairs)
                .unwrap()
                .into_iter()
                .map(Into::into)
                .collect();
            for i in 0..pairs {
                assert_eq!(got[i], src[2 * i] + (src[2 * i + 1] - src[2 * i]) * r, "{label}[{i}]");
            }
        }
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(
            stats.measurement_wall_ns,
            stats.h2d_ns + stats.d2h_ns + stats.kernel_ns() + stats.cpu_residual_ns()
        );

        for output in folded {
            gpu.free_device(output).unwrap();
        }
        gpu.free_device(dsuffix).unwrap();
        gpu.free_device(dodd).unwrap();
        gpu.free_device(deven).unwrap();
        gpu.free_device(dtq).unwrap();
        gpu.free_device(dtp).unwrap();
        gpu.free_device(dpoints).unwrap();
        gpu.free_device(ds).unwrap();
        gpu.free_device(dq1).unwrap();
        gpu.free_device(dq0).unwrap();
        gpu.free_device(dp1).unwrap();
        gpu.free_device(dp0).unwrap();
        gpu.free_device(dmult).unwrap();
        gpu.free_device(dleaf).unwrap();
    }

    #[test]
    fn resident_pcs_ntt_gather_and_merkle_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let (rows, cols, pad, code_len) = (5usize, 11usize, 3usize, 16usize);
        let weights: Vec<i16> =
            (0..rows * cols).map(|i| ((i * 37 + 9) % 1001) as i16 - 500).collect();
        let pads: Vec<Fp> = (0..rows * pad).map(|i| Fp::new(i as u64 * 53 + 5)).collect();
        let pads_raw: Vec<u64> = pads.iter().map(|x| x.value()).collect();
        let dweights = gpu.upload_new_device(&weights).unwrap();
        let dpads = gpu.upload_new_device(&pads_raw).unwrap();

        let combinations = 2usize;
        let mask_rows = 3usize; // 48-byte leaves: exercises a partial BLAKE3 block.
        let mask_messages: Vec<Fp2> = (0..mask_rows * code_len)
            .map(|i| {
                if i % code_len < cols + pad {
                    Fp2::new(Fp::new(i as u64 * 71 + 7), Fp::new(i as u64 * 97 + 13))
                } else {
                    Fp2::ZERO
                }
            })
            .collect();
        let mask_raw: Vec<Fp2Repr> = mask_messages.iter().copied().map(Fp2Repr::from).collect();
        let dmasks = gpu.upload_new_device(&mask_raw).unwrap();
        let mask_compact: Vec<Fp2Repr> = (0..combinations)
            .flat_map(|row| {
                mask_messages[row * code_len..row * code_len + cols + pad]
                    .iter()
                    .copied()
                    .map(Fp2Repr::from)
            })
            .collect();
        let dmask_compact = gpu.upload_new_device(&mask_compact).unwrap();
        let indices = [0u32, 7, 15];
        let dindices = gpu.upload_new_device(&indices).unwrap();

        let coeffs: Vec<Fp2> = (0..combinations * rows)
            .map(|i| Fp2::new(Fp::new(i as u64 * 109 + 17), Fp::new(i as u64 * 131 + 19)))
            .collect();
        let coeff_raw: Vec<Fp2Repr> = coeffs.iter().copied().map(Into::into).collect();
        let dcoeffs = gpu.upload_new_device(&coeff_raw).unwrap();

        gpu.begin_measurement().unwrap();
        let dmessages =
            gpu.pcs_messages_device(&dweights, 0, &dpads, 0, rows, cols, pad, code_len).unwrap();
        let dencoded = gpu.ntt_fp_batch_device(&dmessages, 0, rows, code_len).unwrap();
        let dmask_encoded = gpu.ntt_fp2_batch_device(&dmasks, 0, mask_rows, code_len).unwrap();
        let weight_tree = gpu.hash_fp_tree_device(&dencoded, rows, code_len).unwrap();
        let mask_tree = gpu.hash_fp2_tree_device(&dmask_encoded, mask_rows, code_len).unwrap();
        let weight_root = gpu.merkle_root_device(&weight_tree).unwrap();
        let mask_root = gpu.merkle_root_device(&mask_tree).unwrap();
        let weight_paths = gpu.merkle_paths_device(&weight_tree, &dindices, indices.len()).unwrap();
        let mask_paths = gpu.merkle_paths_device(&mask_tree, &dindices, indices.len()).unwrap();
        let gathered =
            gpu.pcs_gather_fp_device(&dencoded, rows, code_len, &dindices, indices.len()).unwrap();
        let mask_gathered = gpu
            .pcs_gather_fp2_device(&dmask_encoded, mask_rows, code_len, &dindices, indices.len())
            .unwrap();
        let combined = gpu
            .pcs_combine_rows_device(
                &dweights,
                0,
                &dpads,
                0,
                &dcoeffs,
                0,
                rows,
                cols,
                pad,
                combinations,
            )
            .unwrap();
        gpu.fp2_add_inplace_device(&combined, 0, &dmask_compact, 0, combinations * (cols + pad))
            .unwrap();
        let resident_stats = gpu.stats().unwrap();
        assert_eq!(resident_stats.d2h_bytes, 64, "only two Merkle roots cross D2H");

        let messages: Vec<Fp> = gpu
            .download_device(&dmessages, 0, rows * code_len)
            .unwrap()
            .into_iter()
            .map(Fp::new)
            .collect();
        let encoded: Vec<Fp> = gpu
            .download_device(&dencoded, 0, rows * code_len)
            .unwrap()
            .into_iter()
            .map(Fp::new)
            .collect();
        for row in 0..rows {
            let mut expected = vec![Fp::ZERO; code_len];
            for j in 0..cols {
                expected[j] = Fp::from_i64(weights[row * cols + j] as i64);
            }
            expected[cols..cols + pad].copy_from_slice(&pads[row * pad..(row + 1) * pad]);
            assert_eq!(&messages[row * code_len..(row + 1) * code_len], &expected);
            assert_eq!(&encoded[row * code_len..(row + 1) * code_len], cpu_ntt(expected));
        }
        let mask_encoded: Vec<Fp2> = gpu
            .download_device(&dmask_encoded, 0, mask_rows * code_len)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for row in 0..mask_rows {
            let src = &mask_messages[row * code_len..(row + 1) * code_len];
            let c0 = cpu_ntt(src.iter().map(|x| x.c0).collect());
            let c1 = cpu_ntt(src.iter().map(|x| x.c1).collect());
            let expected: Vec<Fp2> = c0.into_iter().zip(c1).map(|(a, b)| Fp2::new(a, b)).collect();
            assert_eq!(&mask_encoded[row * code_len..(row + 1) * code_len], &expected);
        }

        let weight_leaves: Vec<[u8; 32]> = (0..code_len)
            .map(|j| {
                let mut bytes = Vec::with_capacity(rows * 8);
                for i in 0..rows {
                    bytes.extend_from_slice(&encoded[i * code_len + j].value().to_le_bytes());
                }
                *blake3::hash(&bytes).as_bytes()
            })
            .collect();
        let mask_leaves: Vec<[u8; 32]> = (0..code_len)
            .map(|j| {
                let mut bytes = Vec::with_capacity(mask_rows * 16);
                for i in 0..mask_rows {
                    let x = mask_encoded[i * code_len + j];
                    bytes.extend_from_slice(&x.c0.value().to_le_bytes());
                    bytes.extend_from_slice(&x.c1.value().to_le_bytes());
                }
                *blake3::hash(&bytes).as_bytes()
            })
            .collect();
        let weight_levels = cpu_merkle_levels(weight_leaves);
        let mask_levels = cpu_merkle_levels(mask_leaves);
        assert_eq!(weight_root, weight_levels.last().unwrap()[0]);
        assert_eq!(mask_root, mask_levels.last().unwrap()[0]);

        let path_bytes = gpu.download_device(&weight_paths, 0, indices.len() * 4 * 32).unwrap();
        let mask_path_bytes = gpu.download_device(&mask_paths, 0, indices.len() * 4 * 32).unwrap();
        for (q, &index) in indices.iter().enumerate() {
            let mut idx = index as usize;
            for level in 0..4 {
                let off = (q * 4 + level) * 32;
                assert_eq!(&path_bytes[off..off + 32], &weight_levels[level][idx ^ 1]);
                assert_eq!(&mask_path_bytes[off..off + 32], &mask_levels[level][idx ^ 1]);
                idx >>= 1;
            }
        }
        let gathered_host: Vec<Fp> = gpu
            .download_device(&gathered, 0, rows * indices.len())
            .unwrap()
            .into_iter()
            .map(Fp::new)
            .collect();
        let mask_gathered_host: Vec<Fp2> = gpu
            .download_device(&mask_gathered, 0, mask_rows * indices.len())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for (q, &j) in indices.iter().enumerate() {
            assert_eq!(
                &gathered_host[q * rows..(q + 1) * rows],
                &(0..rows).map(|i| encoded[i * code_len + j as usize]).collect::<Vec<_>>()
            );
            assert_eq!(
                &mask_gathered_host[q * mask_rows..(q + 1) * mask_rows],
                &(0..mask_rows)
                    .map(|i| mask_encoded[i * code_len + j as usize])
                    .collect::<Vec<_>>()
            );
        }
        let combined_host: Vec<Fp2> = gpu
            .download_device(&combined, 0, combinations * (cols + pad))
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for combo in 0..combinations {
            for j in 0..cols + pad {
                let expected = (0..rows).fold(Fp2::ZERO, |acc, i| {
                    let x = if j < cols {
                        Fp::from_i64(weights[i * cols + j] as i64)
                    } else {
                        pads[i * pad + j - cols]
                    };
                    acc + coeffs[combo * rows + i].mul_base(x)
                }) + mask_messages[combo * code_len + j];
                assert_eq!(combined_host[combo * (cols + pad) + j], expected);
            }
        }
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(
            stats.measurement_wall_ns,
            stats.h2d_ns + stats.d2h_ns + stats.kernel_ns() + stats.cpu_residual_ns()
        );

        gpu.free_device(combined).unwrap();
        gpu.free_device(mask_gathered).unwrap();
        gpu.free_device(gathered).unwrap();
        gpu.free_device(mask_paths).unwrap();
        gpu.free_device(weight_paths).unwrap();
        gpu.free_device_merkle_tree(mask_tree).unwrap();
        gpu.free_device_merkle_tree(weight_tree).unwrap();
        gpu.free_device(dmask_encoded).unwrap();
        gpu.free_device(dencoded).unwrap();
        gpu.free_device(dmessages).unwrap();
        gpu.free_device(dcoeffs).unwrap();
        gpu.free_device(dindices).unwrap();
        gpu.free_device(dmask_compact).unwrap();
        gpu.free_device(dmasks).unwrap();
        gpu.free_device(dpads).unwrap();
        gpu.free_device(dweights).unwrap();
    }

    #[test]
    fn blake3_column_leaves_match_for_padded_and_non_power_rows() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        for (rows, cols) in [(8, 16), (24, 8), (128, 16), (1024, 32)] {
            let matrix: Vec<Fp> = (0..rows * cols)
                .map(|i| Fp::new((i as u64 * 0x9E37_79B9 + 17) % volta_field::P))
                .collect();
            let got = gpu.hash_fp_columns(&matrix, rows, cols).unwrap();
            for j in 0..cols {
                let mut bytes = Vec::with_capacity(rows * 8);
                for i in 0..rows {
                    bytes.extend_from_slice(&matrix[i * cols + j].value().to_le_bytes());
                }
                assert_eq!(got[j], *blake3::hash(&bytes).as_bytes(), "rows={rows}, col={j}");
            }
        }
    }

    #[test]
    fn context_reuse_is_deterministic_and_resident_rejects_residual() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        let a = vec![3i16; 3 * 5];
        let b = vec![-2i16; 5 * 7];
        let first = gpu.gemm_i64(&a, &b, 3, 5, 7).unwrap();
        for _ in 0..8 {
            assert_eq!(gpu.gemm_i64(&a, &b, 3, 5, 7).unwrap(), first);
        }
        let Some(mut resident) = cuda(BackendKind::CudaResident) else { return };
        assert_eq!(
            resident.cpu_residual(Operation::PcsRows, || ()),
            Err(AccelError::ResidualForbidden(Operation::PcsRows))
        );
    }

    #[test]
    fn resident_arena_reuses_best_fit_without_aliasing_and_rejects_stale_ids() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        gpu.begin_measurement().unwrap();

        let large = gpu.alloc_device::<u8>(128).unwrap();
        let small = gpu.alloc_device::<u8>(64).unwrap();
        let large_id = large.id;
        let small_id = small.id;
        let stale_small_read = duplicate_device_buffer_for_test(&small);
        let stale_small_free = duplicate_device_buffer_for_test(&small);
        let cold = gpu.stats().unwrap();
        assert_eq!(cold.allocation_calls, 2);
        assert_eq!(cold.resident_alloc_requests, 2);
        assert_eq!(cold.resident_reuse_hits, 0);

        gpu.free_device(large).unwrap();
        gpu.free_device(small).unwrap();
        let cached = gpu.device_memory_breakdown().unwrap();
        assert_eq!(cached.workspace_bytes, 0);
        assert_eq!(cached.resident_bytes, 0);
        assert_eq!(cached.cached_resident_bytes, 192);
        assert_eq!(gpu.stats().unwrap().live_device_bytes, 192);

        // 48 bytes fit both cached allocations; best-fit must choose the
        // former 64-byte slot and issue a new generation, not a cudaMalloc.
        let reused = gpu.alloc_device::<u8>(48).unwrap();
        assert_ne!(reused.id, small_id);
        assert_eq!(reused.id as u32, small_id as u32);
        let oversized_view = DeviceBuffer {
            id: reused.id,
            len: 64,
            context_id: reused.context_id,
            _element: PhantomData::<u8>,
        };
        assert!(matches!(
            gpu.download_device(&oversized_view, 48, 1),
            Err(AccelError::Cuda(message)) if message.contains("out of bounds")
        ));

        // The only remaining cached allocation is the former 128-byte slot.
        // Keeping both leases live must never alias their physical storage.
        let second = gpu.alloc_device::<u8>(48).unwrap();
        assert_ne!(second.id as u32, reused.id as u32);
        assert_eq!(second.id as u32, large_id as u32);
        gpu.upload_device(&reused, 0, &[0x11; 48]).unwrap();
        gpu.upload_device(&second, 0, &[0x22; 48]).unwrap();
        assert_eq!(gpu.download_device(&reused, 0, 48).unwrap(), vec![0x11; 48]);
        assert_eq!(gpu.download_device(&second, 0, 48).unwrap(), vec![0x22; 48]);

        let warm = gpu.stats().unwrap();
        assert_eq!(warm.allocation_calls, 2);
        assert_eq!(warm.resident_alloc_requests, 4);
        assert_eq!(warm.resident_reuse_hits, 2);
        assert_eq!(warm.resident_free_requests, 2);
        assert_eq!(warm.physical_free_calls, 0);
        let active = gpu.device_memory_breakdown().unwrap();
        assert_eq!(active.workspace_bytes, 0);
        assert_eq!(active.resident_bytes, 192);
        assert_eq!(active.cached_resident_bytes, 0);
        assert_eq!(
            active.workspace_bytes + active.resident_bytes + active.cached_resident_bytes,
            warm.live_device_bytes
        );

        assert!(matches!(
            gpu.download_device(&stale_small_read, 0, 1),
            Err(AccelError::Cuda(message)) if message.contains("unknown resident buffer id")
        ));
        assert!(matches!(
            gpu.free_device(stale_small_free),
            Err(AccelError::Cuda(message)) if message.contains("stale resident buffer id")
        ));

        let double_free = duplicate_device_buffer_for_test(&second);
        gpu.free_device(second).unwrap();
        assert!(matches!(
            gpu.free_device(double_free),
            Err(AccelError::Cuda(message)) if message.contains("stale resident buffer id")
        ));
        gpu.free_device(reused).unwrap();
        let final_stats = gpu.finish_measurement().unwrap();
        assert_eq!(final_stats.synchronization_reason_total(), final_stats.synchronizations);
        assert_eq!(final_stats.resident_alloc_requests, 4);
        assert_eq!(final_stats.resident_reuse_hits, 2);
        assert_eq!(final_stats.resident_free_requests, 6);
        assert_eq!(final_stats.physical_free_calls, 0);
        let final_memory = gpu.device_memory_breakdown().unwrap();
        assert_eq!(final_memory.resident_bytes, 0);
        assert_eq!(final_memory.cached_resident_bytes, 192);
        assert_eq!(
            final_memory.workspace_bytes
                + final_memory.resident_bytes
                + final_memory.cached_resident_bytes,
            final_stats.live_device_bytes
        );

        gpu.trim_device_cache().unwrap();
        let trimmed = gpu.device_memory_breakdown().unwrap();
        assert_eq!(trimmed.resident_bytes, 0);
        assert_eq!(trimmed.cached_resident_bytes, 0);
        let trimmed_stats = gpu.stats().unwrap();
        assert_eq!(trimmed_stats.live_device_bytes, trimmed.workspace_bytes);
        assert_eq!(trimmed_stats.physical_free_calls, 2);
        assert_eq!(trimmed_stats.sync_allocator_flush, 1);
        assert_eq!(trimmed_stats.synchronization_reason_total(), trimmed_stats.synchronizations);
    }

    #[test]
    fn resident_buffers_and_device_gemm_are_bit_exact_and_attributed() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let (m, k, n) = (3usize, 5usize, 7usize);
        let a: Vec<i16> = (0..m * k).map(|i| ((37 * i + 11) % 401) as i16 - 200).collect();
        let b: Vec<i16> = (0..k * n).map(|i| ((53 * i + 5) % 401) as i16 - 200).collect();
        let expected = cpu_gemm(&a, &b, m, k, n);
        let masks: Vec<Fp> =
            (0..m * n).map(|i| Fp::new((i as u64 * 97 + 13) % volta_field::P)).collect();
        let raw_masks: Vec<u64> = masks.iter().map(|x| x.value()).collect();

        // Exercise non-zero typed offsets: padding must never enter a kernel.
        let da = gpu.alloc_device::<i16>(2 + a.len() + 3).unwrap();
        let db = gpu.alloc_device::<i16>(4 + b.len() + 1).unwrap();
        let dm = gpu.alloc_device::<u64>(1 + masks.len() + 2).unwrap();
        gpu.begin_measurement().unwrap();
        gpu.upload_device(&da, 2, &a).unwrap();
        gpu.upload_device(&db, 4, &b).unwrap();
        gpu.upload_device(&dm, 1, &raw_masks).unwrap();
        let after_upload = gpu.stats().unwrap();

        let dacc = gpu.gemm_i64_device(&da, 2, &db, 4, m, k, n).unwrap();
        let (dout, dcorr) =
            gpu.gemm_requant_auth_device(&da, 2, &db, 4, &dm, 1, m, k, n, 8).unwrap();
        let after_kernels = gpu.stats().unwrap();
        assert_eq!(after_kernels.h2d_bytes, after_upload.h2d_bytes);
        assert_eq!(after_kernels.d2h_bytes, after_upload.d2h_bytes);
        assert_eq!(
            after_kernels.operation(Operation::Gemm).calls,
            after_upload.operation(Operation::Gemm).calls + 2
        );

        assert_eq!(gpu.download_device(&dacc, 0, m * n).unwrap(), expected);
        let out = gpu.download_device(&dout, 0, m * n).unwrap();
        let corr = gpu.download_device(&dcorr, 0, m * n).unwrap();
        for z in 0..m * n {
            let rounded = ((expected[z] + 128) >> 8).clamp(-32768, 32767) as i16;
            assert_eq!(out[z], rounded);
            assert_eq!(Fp::new(corr[z]) + masks[z], Fp::from_i64(rounded as i64), "correction {z}");
        }
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.h2d_bytes, (a.len() + b.len()) as u64 * 2 + masks.len() as u64 * 8);
        assert_eq!(stats.d2h_bytes, m as u64 * n as u64 * (8 + 2 + 8));
        assert!(stats.operation(Operation::Gemm).kernel_ns > 0);
        assert_eq!(
            stats.measurement_wall_ns,
            stats.h2d_ns + stats.d2h_ns + stats.kernel_ns() + stats.cpu_residual_ns()
        );

        gpu.free_device(dcorr).unwrap();
        gpu.free_device(dout).unwrap();
        gpu.free_device(dacc).unwrap();
        gpu.free_device(dm).unwrap();
        gpu.free_device(db).unwrap();
        gpu.free_device(da).unwrap();
        let memory = gpu.device_memory_breakdown().unwrap();
        assert_eq!(memory.resident_bytes, 0);
        assert_eq!(
            memory.workspace_bytes + memory.cached_resident_bytes,
            gpu.stats().unwrap().live_device_bytes
        );
    }

    #[test]
    fn resident_protocol_field_algebra_is_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let (rows, cols) = (3usize, 5usize);
        let input: Vec<i16> = (0..rows * cols).map(|i| ((i * 41 + 7) % 211) as i16 - 105).collect();
        let masks: Vec<Fp> = (0..input.len()).map(|i| Fp::new(i as u64 * 0x1021 + 19)).collect();
        let raw_masks: Vec<u64> = masks.iter().map(|x| x.value()).collect();
        let row_weights: Vec<Fp2> = (0..rows.next_power_of_two())
            .map(|i| Fp2::new(Fp::new(i as u64 * 17 + 3), Fp::new(i as u64 * 29 + 5)))
            .collect();
        let col_weights: Vec<Fp2> = (0..cols.next_power_of_two())
            .map(|i| Fp2::new(Fp::new(i as u64 * 31 + 11), Fp::new(i as u64 * 43 + 13)))
            .collect();
        let dinput = gpu.upload_new_device(&input).unwrap();
        let dmasks = gpu.upload_new_device(&raw_masks).unwrap();
        let drow_weights = gpu
            .upload_new_device(&row_weights.iter().copied().map(Into::into).collect::<Vec<_>>())
            .unwrap();
        let dcol_weights = gpu
            .upload_new_device(&col_weights.iter().copied().map(Into::into).collect::<Vec<_>>())
            .unwrap();

        let dcorr = gpu
            .subfield_corrections_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                DeviceSlice::new(&dmasks, 0, masks.len()).unwrap(),
            )
            .unwrap();
        let corrections = gpu.download_device(&dcorr, 0, input.len()).unwrap();
        for i in 0..input.len() {
            assert_eq!(
                Fp::new(corrections[i]) + masks[i],
                Fp::from_i64(input[i] as i64),
                "subfield correction {i}"
            );
        }

        let padded = gpu
            .pad_base_vector_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                32,
                Fp::new(17),
            )
            .unwrap();
        let padded_host = gpu.download_device(&padded, 0, 32).unwrap();
        for (got, expected) in padded_host[..input.len()]
            .iter()
            .zip(input.iter().map(|&value| Fp::from_i64(value as i64).value()))
        {
            assert_eq!(*got, expected);
        }
        assert!(padded_host[input.len()..].iter().all(|&value| value == 17));

        let point: Vec<Fp2> =
            (0..5).map(|i| Fp2::new(Fp::new(i * 71 + 9), Fp::new(i * 83 + 15))).collect();
        let matrix_eval = gpu
            .matrix_mle_eval_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                rows,
                cols,
                &point,
            )
            .unwrap();
        let mut padded_matrix =
            vec![Fp2::ZERO; rows.next_power_of_two() * cols.next_power_of_two()];
        for i in 0..rows {
            for j in 0..cols {
                padded_matrix[i * cols.next_power_of_two() + j] =
                    Fp2::from_base(Fp::from_i64(input[i * cols + j] as i64));
            }
        }
        for &challenge in &point {
            let half = padded_matrix.len() / 2;
            for i in 0..half {
                padded_matrix[i] = padded_matrix[2 * i]
                    + (padded_matrix[2 * i + 1] - padded_matrix[2 * i]) * challenge;
            }
            padded_matrix.truncate(half);
        }
        assert_eq!(matrix_eval, padded_matrix[0]);

        let folded_rows = gpu
            .matrix_fold_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                DeviceSlice::new(&drow_weights, 0, row_weights.len()).unwrap(),
                rows,
                cols,
                MatrixFoldAxis::Rows,
            )
            .unwrap();
        let got_rows: Vec<Fp2> = gpu
            .download_device(&folded_rows, 0, cols.next_power_of_two())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for j in 0..cols.next_power_of_two() {
            let expected = if j < cols {
                (0..rows).fold(Fp2::ZERO, |sum, i| {
                    sum + row_weights[i].mul_base(Fp::from_i64(input[i * cols + j] as i64))
                })
            } else {
                Fp2::ZERO
            };
            assert_eq!(got_rows[j], expected, "row fold output {j}");
        }

        let folded_cols = gpu
            .matrix_fold_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                DeviceSlice::new(&dcol_weights, 0, col_weights.len()).unwrap(),
                rows,
                cols,
                MatrixFoldAxis::Columns,
            )
            .unwrap();
        let got_cols: Vec<Fp2> = gpu
            .download_device(&folded_cols, 0, rows.next_power_of_two())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for i in 0..rows.next_power_of_two() {
            let expected = if i < rows {
                (0..cols).fold(Fp2::ZERO, |sum, j| {
                    sum + col_weights[j].mul_base(Fp::from_i64(input[i * cols + j] as i64))
                })
            } else {
                Fp2::ZERO
            };
            assert_eq!(got_cols[i], expected, "column fold output {i}");
        }

        // Per-head proof paths use a logical matrix window inside a wider
        // row stride. It must fold directly without a gathered host mirror.
        let window_offset = 1usize;
        let window_cols = 3usize;
        let window_weights = &col_weights[..window_cols];
        let window_weights_raw: Vec<Fp2Repr> =
            window_weights.iter().copied().map(Into::into).collect();
        let dwindow_weights = gpu.upload_new_device(&window_weights_raw).unwrap();
        let folded_window = gpu
            .matrix_window_fold_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                DeviceSlice::new(&dwindow_weights, 0, window_cols).unwrap(),
                rows,
                cols,
                window_offset,
                window_cols,
                MatrixFoldAxis::Columns,
            )
            .unwrap();
        let got_window: Vec<Fp2> = gpu
            .download_device(&folded_window, 0, rows.next_power_of_two())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for i in 0..rows.next_power_of_two() {
            let expected = if i < rows {
                (0..window_cols).fold(Fp2::ZERO, |sum, j| {
                    sum + window_weights[j]
                        .mul_base(Fp::from_i64(input[i * cols + window_offset + j] as i64))
                })
            } else {
                Fp2::ZERO
            };
            assert_eq!(got_window[i], expected, "window fold output {i}");
        }
        gpu.free_device(folded_window).unwrap();
        gpu.free_device(dwindow_weights).unwrap();

        let window_point = &point[..4];
        let window_eval = gpu
            .matrix_window_mle_eval_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                rows,
                cols,
                window_offset,
                window_cols,
                window_point,
            )
            .unwrap();
        let mut padded_window = vec![Fp2::ZERO; rows.next_power_of_two() * 4];
        for i in 0..rows {
            for j in 0..window_cols {
                padded_window[i * 4 + j] =
                    Fp2::from_base(Fp::from_i64(input[i * cols + window_offset + j] as i64));
            }
        }
        for &challenge in window_point {
            let half = padded_window.len() / 2;
            for i in 0..half {
                padded_window[i] = padded_window[2 * i]
                    + (padded_window[2 * i + 1] - padded_window[2 * i]) * challenge;
            }
            padded_window.truncate(half);
        }
        assert_eq!(window_eval, padded_window[0]);

        let public_weights: Vec<Fp2> = (0..input.len())
            .map(|i| Fp2::new(Fp::new(7 + i as u64 * 11), Fp::new(13 + i as u64 * 17)))
            .collect();
        let weighted = gpu
            .weighted_sum_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                &public_weights,
            )
            .unwrap();
        let expected_weighted =
            input.iter().zip(&public_weights).fold(Fp2::ZERO, |sum, (&value, &weight)| {
                sum + weight.mul_base(Fp::from_i64(value as i64))
            });
        assert_eq!(weighted, expected_weighted);

        let broadcast = gpu
            .base_to_fp2_broadcast_device(DeviceSlice::new(&dinput, 0, input.len()).unwrap(), 2)
            .unwrap();
        let broadcast_values: Vec<Fp2> = gpu
            .download_device(&broadcast, 0, 2 * input.len())
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for (i, pair) in broadcast_values.chunks_exact(2).enumerate() {
            assert_eq!(pair, [Fp2::from_base(Fp::from_i64(input[i] as i64)); 2]);
        }
        gpu.free_device(broadcast).unwrap();

        let repeated = gpu
            .repeat_vector_device(DeviceSlice::new(&dinput, 0, input.len()).unwrap(), 3)
            .unwrap();
        let repeated_values = gpu.download_device(&repeated, 0, 3 * input.len()).unwrap();
        assert_eq!(repeated_values, input.repeat(3));
        gpu.free_device(repeated).unwrap();

        let compact = gpu
            .compact_strided_rows_device(
                DeviceSlice::new(&dinput, window_offset, input.len() - window_offset).unwrap(),
                rows,
                cols,
                window_cols,
            )
            .unwrap();
        let compact_values = gpu.download_device(&compact, 0, rows * window_cols).unwrap();
        let expected_compact: Vec<i16> = (0..rows)
            .flat_map(|row| {
                input[row * cols + window_offset..row * cols + window_offset + window_cols]
                    .iter()
                    .copied()
            })
            .collect();
        assert_eq!(compact_values, expected_compact);
        gpu.free_device(compact).unwrap();

        let mask_entries = 4 * 4 * 4;
        let mask_source: Vec<Fp2> = (0..mask_entries)
            .map(|i| Fp2::new(Fp::new(101 + i as u64), Fp::new(401 + i as u64)))
            .collect();
        let mask_raw: Vec<Fp2Repr> = mask_source.iter().copied().map(Into::into).collect();
        let mask = gpu.upload_new_device(&mask_raw).unwrap();
        gpu.attention_above_mask_device(&mask, 3, 3, 0, 2, 4).unwrap();
        let masked: Vec<Fp2> = gpu
            .download_device(&mask, 0, mask_entries)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for h in 0..4 {
            for i in 0..4 {
                for j in 0..4 {
                    let z = h * 16 + i * 4 + j;
                    let expected =
                        if h < 2 && i < 3 && j < 3 && j > i { mask_source[z] } else { Fp2::ZERO };
                    assert_eq!(masked[z], expected);
                }
            }
        }
        gpu.free_device(mask).unwrap();

        let av: Vec<Fp2> =
            (0..8).map(|i| Fp2::new(Fp::new(i * 47 + 2), Fp::new(i * 53 + 7))).collect();
        let bv: Vec<Fp2> =
            (0..8).map(|i| Fp2::new(Fp::new(i * 59 + 3), Fp::new(i * 61 + 11))).collect();
        let cv: Vec<Fp2> =
            (0..8).map(|i| Fp2::new(Fp::new(i * 67 + 5), Fp::new(i * 71 + 13))).collect();
        let da =
            gpu.upload_new_device(&av.iter().copied().map(Into::into).collect::<Vec<_>>()).unwrap();
        let db =
            gpu.upload_new_device(&bv.iter().copied().map(Into::into).collect::<Vec<_>>()).unwrap();
        let dc =
            gpu.upload_new_device(&cv.iter().copied().map(Into::into).collect::<Vec<_>>()).unwrap();
        let dot = gpu
            .fp2_dot_device(
                DeviceSlice::new(&da, 0, av.len()).unwrap(),
                DeviceSlice::new(&db, 0, bv.len()).unwrap(),
            )
            .unwrap();
        assert_eq!(dot, av.iter().zip(&bv).fold(Fp2::ZERO, |sum, (&a, &b)| sum + a * b));
        let round = gpu
            .fp2_product_round_device(
                DeviceSlice::new(&da, 0, av.len()).unwrap(),
                DeviceSlice::new(&db, 0, bv.len()).unwrap(),
            )
            .unwrap();
        let expected_round = (0..4).fold([Fp2::ZERO; 2], |mut out, i| {
            let (a0, a1) = (av[2 * i], av[2 * i + 1]);
            let (b0, b1) = (bv[2 * i], bv[2 * i + 1]);
            out[0] += a0 * b0;
            out[1] += (a0 + (a1 - a0) + (a1 - a0)) * (b0 + (b1 - b0) + (b1 - b0));
            out
        });
        assert_eq!(round, expected_round);
        let triple_round = gpu
            .fp2_triple_product_round_device(
                DeviceSlice::new(&da, 0, av.len()).unwrap(),
                DeviceSlice::new(&db, 0, bv.len()).unwrap(),
                DeviceSlice::new(&dc, 0, cv.len()).unwrap(),
            )
            .unwrap();
        let expected_triple = (0..4).fold([Fp2::ZERO; 3], |mut out, i| {
            let values = |source: &[Fp2], at: u64| {
                let v0 = source[2 * i];
                v0 + (source[2 * i + 1] - v0) * Fp2::from_base(Fp::new(at))
            };
            for (slot, at) in [0u64, 2, 3].into_iter().enumerate() {
                out[slot] += values(&av, at) * values(&bv, at) * values(&cv, at);
            }
            out
        });
        assert_eq!(triple_round, expected_triple);

        let means: Vec<u64> =
            [-3i64, 7, 2, 0].into_iter().map(|value| Fp::from_i64(value).value()).collect();
        let rsqrt = vec![2u64, 3, 4, 5];
        let gain = vec![-2i16, 3, 5, -7, 11];
        let dmeans = gpu.upload_new_device(&means).unwrap();
        let drsqrt = gpu.upload_new_device(&rsqrt).unwrap();
        let dgain = gpu.upload_new_device(&gain).unwrap();
        let (centered, scaled) = gpu
            .ln_hadamard_factors_device(
                DeviceSlice::new(&dinput, 0, input.len()).unwrap(),
                DeviceSlice::new(&dmeans, 0, means.len()).unwrap(),
                DeviceSlice::new(&drsqrt, 0, rsqrt.len()).unwrap(),
                DeviceSlice::new(&dgain, 0, gain.len()).unwrap(),
                rows,
                cols,
            )
            .unwrap();
        let centered_host: Vec<Fp2> =
            gpu.download_device(&centered, 0, 32).unwrap().into_iter().map(Into::into).collect();
        let scaled_host: Vec<Fp2> =
            gpu.download_device(&scaled, 0, 32).unwrap().into_iter().map(Into::into).collect();
        for row in 0..4 {
            for col in 0..8 {
                let z = row * 8 + col;
                let expected_centered = if row < rows {
                    let value = if col < cols { input[row * cols + col] as i64 } else { 0 };
                    Fp2::from_base(Fp::from_i64(value) - Fp::new(means[row]))
                } else {
                    Fp2::ZERO
                };
                let expected_scaled = if col < cols {
                    Fp2::from_base(Fp::new(rsqrt[row]) * Fp::from_i64(gain[col] as i64))
                } else {
                    Fp2::ZERO
                };
                assert_eq!(centered_host[z], expected_centered);
                assert_eq!(scaled_host[z], expected_scaled);
            }
        }
        let challenge = Fp2::new(Fp::new(123), Fp::new(456));
        let folded_a = gpu.fp2_fold_rows_device(&da, 0, 1, av.len(), challenge).unwrap();
        let got_fold: Vec<Fp2> = gpu
            .download_device(&folded_a, 0, av.len() / 2)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        let expected_fold: Vec<Fp2> = (0..av.len() / 2)
            .map(|i| av[2 * i] + (av[2 * i + 1] - av[2 * i]) * challenge)
            .collect();
        assert_eq!(got_fold, expected_fold);

        gpu.free_device(folded_a).unwrap();
        gpu.free_device(scaled).unwrap();
        gpu.free_device(centered).unwrap();
        gpu.free_device(dgain).unwrap();
        gpu.free_device(drsqrt).unwrap();
        gpu.free_device(dmeans).unwrap();
        gpu.free_device(dc).unwrap();
        gpu.free_device(db).unwrap();
        gpu.free_device(da).unwrap();
        gpu.free_device(folded_cols).unwrap();
        gpu.free_device(folded_rows).unwrap();
        gpu.free_device(padded).unwrap();
        gpu.free_device(dcorr).unwrap();
        gpu.free_device(dcol_weights).unwrap();
        gpu.free_device(drow_weights).unwrap();
        gpu.free_device(dmasks).unwrap();
        gpu.free_device(dinput).unwrap();
    }

    #[test]
    fn resident_lookup_columns_histograms_and_packing_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let (rows, cols) = (3usize, 5usize);
        let entries = rows.next_power_of_two() * cols.next_power_of_two();
        let shift = 8u32;
        let outputs: Vec<i16> = (0..rows * cols).map(|i| ((i * 13 + 5) % 81) as i16 - 40).collect();
        let remainders: Vec<i64> = (0..rows * cols).map(|i| (i % (1 << shift)) as i64).collect();
        let accumulators: Vec<i64> = outputs
            .iter()
            .zip(&remainders)
            .map(|(&out, &rem)| ((out as i64) << shift) + rem - (1 << (shift - 1)))
            .collect();
        let dacc = gpu.upload_new_device(&accumulators).unwrap();
        let dout = gpu.upload_new_device(&outputs).unwrap();
        let error = gpu.upload_new_device(&[0u32]).unwrap();
        let columns = gpu
            .requant_lookup_columns_device(
                DeviceSlice::new(&dacc, 0, accumulators.len()).unwrap(),
                DeviceSlice::new(&dout, 0, outputs.len()).unwrap(),
                DeviceSlice::new(&error, 0, 1).unwrap(),
                rows,
                cols,
                shift,
            )
            .unwrap();
        assert_eq!(columns.columns(), 2);
        assert_eq!(columns.entries(), entries);
        let raw =
            gpu.download_device(columns.view(0, 2).unwrap().buffer(), 0, 2 * entries).unwrap();
        for row in 0..rows.next_power_of_two() {
            for col in 0..cols.next_power_of_two() {
                let z = row * cols.next_power_of_two() + col;
                if row < rows && col < cols {
                    let source = row * cols + col;
                    assert_eq!(raw[z], remainders[source] as u64);
                    assert_eq!(Fp::new(raw[entries + z]), Fp::from_i64(outputs[source] as i64));
                } else {
                    assert_eq!(raw[z], 1 << (shift - 1));
                    assert_eq!(raw[entries + z], 0);
                }
            }
        }
        let accumulators_i16: Vec<i16> =
            accumulators.iter().map(|&value| i16::try_from(value).unwrap()).collect();
        let dacc_i16 = gpu.upload_new_device(&accumulators_i16).unwrap();
        let columns_i16 = gpu
            .requant_lookup_columns_device(
                DeviceSlice::new(&dacc_i16, 0, accumulators_i16.len()).unwrap(),
                DeviceSlice::new(&dout, 0, outputs.len()).unwrap(),
                DeviceSlice::new(&error, 0, 1).unwrap(),
                rows,
                cols,
                shift,
            )
            .unwrap();
        let raw_i16 =
            gpu.download_device(columns_i16.view(0, 2).unwrap().buffer(), 0, 2 * entries).unwrap();
        assert_eq!(raw_i16, raw, "i16/i64 requant sources diverged");
        gpu.free_lookup_columns(columns_i16).unwrap();
        gpu.free_device(dacc_i16).unwrap();
        let histogram = gpu.histogram_fp_device(columns.column(0).unwrap(), 1 << shift).unwrap();
        let expected_hist = {
            let mut values = vec![0u32; 1 << shift];
            for &value in &raw[..entries] {
                values[value as usize] += 1;
            }
            values
        };
        assert_eq!(gpu.download_device(&histogram, 0, 1 << shift).unwrap(), expected_hist);
        let histogram2 = gpu.histogram_fp_device(columns.column(0).unwrap(), 1 << shift).unwrap();
        gpu.u32_add_inplace_device(
            DeviceSlice::new(&histogram, 0, 1 << shift).unwrap(),
            DeviceSlice::new(&histogram2, 0, 1 << shift).unwrap(),
        )
        .unwrap();
        assert_eq!(
            gpu.download_device(&histogram, 0, 1 << shift).unwrap(),
            expected_hist.iter().map(|x| x * 2).collect::<Vec<_>>()
        );

        let alpha0 = Fp::new(0xCAFE_BABE);
        let leaf = gpu
            .pack_lookup_leaf_device(
                columns.view(0, 2).unwrap(),
                2,
                entries,
                &[Some(0), None],
                alpha0,
            )
            .unwrap();
        let leaf_host: Vec<Fp> =
            gpu.download_device(&leaf, 0, entries).unwrap().into_iter().map(Fp::new).collect();
        for z in 0..entries {
            assert_eq!(leaf_host[z], alpha0 - Fp::new(raw[z]));
        }
        let aux =
            gpu.deinterleave_base_columns_device(columns.view(0, 2).unwrap(), 2, entries).unwrap();
        let aux_host: Vec<Fp2> = gpu
            .download_device(&aux, 0, 2 * entries)
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        for column in 0..2 {
            for i in 0..entries / 2 {
                assert_eq!(
                    aux_host[column * entries + i],
                    Fp2::from_base(Fp::new(raw[column * entries + 2 * i]))
                );
                assert_eq!(
                    aux_host[column * entries + entries / 2 + i],
                    Fp2::from_base(Fp::new(raw[column * entries + 2 * i + 1]))
                );
            }
        }

        let pair_outputs: Vec<i16> = outputs.iter().map(|&x| -x).collect();
        let dpair_out = gpu.upload_new_device(&pair_outputs).unwrap();
        let pair = gpu
            .pair_lookup_columns_device(
                DeviceSlice::new(&dout, 0, outputs.len()).unwrap(),
                DeviceSlice::new(&dpair_out, 0, pair_outputs.len()).unwrap(),
                rows,
                cols,
                -123,
                77,
            )
            .unwrap();
        let pair_raw =
            gpu.download_device(pair.view(0, 2).unwrap().buffer(), 0, 2 * entries).unwrap();
        for row in 0..rows.next_power_of_two() {
            for col in 0..cols.next_power_of_two() {
                let z = row * cols.next_power_of_two() + col;
                let (input, output) = if row < rows && col < cols {
                    let source = row * cols + col;
                    (outputs[source], pair_outputs[source])
                } else {
                    (-123, 77)
                };
                assert_eq!(Fp::new(pair_raw[z]), Fp::from_i64(input as i64));
                assert_eq!(Fp::new(pair_raw[entries + z]), Fp::from_i64(output as i64));
            }
        }
        let signed_hist = gpu.histogram_lut_device(pair.column(0).unwrap(), true).unwrap();
        let mut expected_signed = vec![0u32; 1 << 16];
        for row in 0..rows.next_power_of_two() {
            for col in 0..cols.next_power_of_two() {
                let input = if row < rows && col < cols { outputs[row * cols + col] } else { -123 };
                expected_signed[input as u16 as usize] += 1;
            }
        }
        assert_eq!(gpu.download_device(&signed_hist, 0, 1 << 16).unwrap(), expected_signed);

        let nonnegative_inputs: Vec<i64> =
            (0..rows * cols).map(|i| 40_000 + (i * 997 % 20_000) as i64).collect();
        let dnonnegative = gpu.upload_new_device(&nonnegative_inputs).unwrap();
        let nonnegative_pair = gpu
            .pair_lookup_columns_base_device(
                DeviceSlice::new(&dnonnegative, 0, nonnegative_inputs.len()).unwrap(),
                DeviceSlice::new(&dpair_out, 0, pair_outputs.len()).unwrap(),
                rows,
                cols,
                Fp::new(0),
                Fp::new(77),
            )
            .unwrap();
        let nonnegative_raw = gpu
            .download_device(nonnegative_pair.view(0, 2).unwrap().buffer(), 0, 2 * entries)
            .unwrap();
        for row in 0..rows.next_power_of_two() {
            for col in 0..cols.next_power_of_two() {
                let z = row * cols.next_power_of_two() + col;
                let expected = if row < rows && col < cols {
                    nonnegative_inputs[row * cols + col] as u64
                } else {
                    0
                };
                assert_eq!(nonnegative_raw[z], expected);
            }
        }
        let nonnegative_hist =
            gpu.histogram_lut_device(nonnegative_pair.column(0).unwrap(), false).unwrap();
        assert_eq!(
            gpu.download_device(&nonnegative_hist, 0, 1 << 16).unwrap().iter().sum::<u32>(),
            entries as u32
        );

        let chain_shift = 20u32;
        let chain_acc: Vec<i64> = (0..rows * cols).map(|i| i as i64 * 91_337 - 500_000).collect();
        let chain_out: Vec<i16> = chain_acc
            .iter()
            .map(|&a| {
                let y1 = (a + (1 << 3)) >> 4;
                ((y1 + (1 << 15)) >> 16) as i16
            })
            .collect();
        let dchain_acc = gpu.upload_new_device(&chain_acc).unwrap();
        let dchain_out = gpu.upload_new_device(&chain_out).unwrap();
        let chained = gpu
            .requant_lookup_columns_device(
                DeviceSlice::new(&dchain_acc, 0, chain_acc.len()).unwrap(),
                DeviceSlice::new(&dchain_out, 0, chain_out.len()).unwrap(),
                DeviceSlice::new(&error, 0, 1).unwrap(),
                rows,
                cols,
                chain_shift,
            )
            .unwrap();
        assert_eq!(chained.columns(), 4);
        let chained_raw =
            gpu.download_device(chained.view(0, 4).unwrap().buffer(), 0, 4 * entries).unwrap();
        for row in 0..rows {
            for col in 0..cols {
                let source = row * cols + col;
                let z = row * cols.next_power_of_two() + col;
                let y1 = (chain_acc[source] + 8) >> 4;
                assert_eq!(chained_raw[z] as i64, chain_acc[source] + 8 - (y1 << 4));
                assert_eq!(Fp::new(chained_raw[entries + z]), Fp::from_i64(y1));
                assert_eq!(
                    chained_raw[2 * entries + z] as i64,
                    y1 + (1 << 15) - ((chain_out[source] as i64) << 16)
                );
                assert_eq!(
                    Fp::new(chained_raw[3 * entries + z]),
                    Fp::from_i64(chain_out[source] as i64)
                );
            }
        }
        assert_eq!(gpu.download_device(&error, 0, 1).unwrap(), vec![0]);

        gpu.free_lookup_columns(chained).unwrap();
        gpu.free_device(dchain_out).unwrap();
        gpu.free_device(dchain_acc).unwrap();
        gpu.free_device(nonnegative_hist).unwrap();
        gpu.free_lookup_columns(nonnegative_pair).unwrap();
        gpu.free_device(dnonnegative).unwrap();
        gpu.free_device(signed_hist).unwrap();
        gpu.free_lookup_columns(pair).unwrap();
        gpu.free_device(dpair_out).unwrap();
        gpu.free_device(aux).unwrap();
        gpu.free_device(leaf).unwrap();
        gpu.free_device(histogram2).unwrap();
        gpu.free_device(histogram).unwrap();
        gpu.free_lookup_columns(columns).unwrap();
        gpu.free_device(error).unwrap();
        gpu.free_device(dout).unwrap();
        gpu.free_device(dacc).unwrap();
    }

    #[test]
    fn resident_attention_proof_wires_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaResident) else { return };
        let (query_rows, seq, pos0) = (3usize, 3usize, 0usize);
        let (heads, head_pad, head_dim) = (2usize, 4usize, 2usize);
        let d = heads * head_dim;
        let (shift_scores, shift_norm, shift_qkv) = (4u32, 4u32, 4u32);
        let q: Vec<i16> = (0..query_rows * d).map(|i| (i as i16 % 7) - 3).collect();
        let k: Vec<i16> = (0..seq * d).map(|i| ((i * 3) as i16 % 9) - 4).collect();
        let v: Vec<i16> = (0..query_rows * d).map(|i| ((i * 5) as i16 % 11) - 5).collect();
        let per_head = query_rows * (query_rows + 1) / 2;
        let mut scores_acc = vec![0i64; heads * per_head];
        let mut scores_q = vec![0i16; heads * per_head];
        let mut row_shifts = vec![0i16; heads * query_rows];
        let mut exp_outputs = vec![2i16; heads * per_head];
        let mut denoms = vec![0i64; heads * query_rows];
        let recips = vec![3i16; heads * query_rows];
        let softmax_weights = vec![0i16; heads * per_head];
        for h in 0..heads {
            for i in 0..query_rows {
                let start = h * per_head + i * (i + 1) / 2;
                let mut maximum = i16::MIN;
                for j in 0..=i {
                    let acc = (0..head_dim).fold(0i64, |sum, l| {
                        sum + q[i * d + h * head_dim + l] as i64
                            * k[j * d + h * head_dim + l] as i64
                    });
                    scores_acc[start + j] = acc;
                    scores_q[start + j] = ((acc + 8) >> shift_scores) as i16;
                    maximum = maximum.max(scores_q[start + j]);
                }
                row_shifts[h * query_rows + i] = maximum;
                denoms[h * query_rows + i] = 2 * (i + 1) as i64;
            }
        }
        // Keep ownership distinct even where the values are simple constants.
        exp_outputs.iter_mut().for_each(|value| *value = 2);
        let mut recip_lut = vec![0i16; 1 << 16];
        recip_lut[0] = 7;
        for &denom in &denoms {
            recip_lut[denom as usize] = 3;
        }
        let mut qkv_acc = vec![0i64; query_rows * 3 * d];
        for i in 0..query_rows {
            for third in 0..3 {
                for j in 0..d {
                    let output = match third {
                        0 => q[i * d + j],
                        1 => k[i * d + j],
                        _ => v[i * d + j],
                    };
                    qkv_acc[i * 3 * d + third * d + j] = (output as i64) << shift_qkv;
                }
            }
        }

        let dq = gpu.upload_new_device(&q).unwrap();
        let dk = gpu.upload_new_device(&k).unwrap();
        let dv = gpu.upload_new_device(&v).unwrap();
        let d_scores_acc = gpu.upload_new_device(&scores_acc).unwrap();
        let d_scores_q = gpu.upload_new_device(&scores_q).unwrap();
        let d_row_shifts = gpu.upload_new_device(&row_shifts).unwrap();
        let d_exp = gpu.upload_new_device(&exp_outputs).unwrap();
        let d_denoms = gpu.upload_new_device(&denoms).unwrap();
        let d_recips = gpu.upload_new_device(&recips).unwrap();
        let d_weights = gpu.upload_new_device(&softmax_weights).unwrap();
        let d_recip_lut = gpu.upload_new_device(&recip_lut).unwrap();
        let d_qkv_acc = gpu.upload_new_device(&qkv_acc).unwrap();
        let error = gpu.upload_new_device(&[0u32]).unwrap();
        let exp_pad = i16::MIN;
        let wires = gpu
            .attention_proof_wires_device(
                DeviceSlice::new(&dq, 0, q.len()).unwrap(),
                DeviceSlice::new(&dk, 0, k.len()).unwrap(),
                DeviceSlice::new(&dk, 0, k.len()).unwrap(),
                DeviceSlice::new(&dv, 0, v.len()).unwrap(),
                DeviceSlice::new(&d_scores_acc, 0, scores_acc.len()).unwrap(),
                DeviceSlice::new(&d_scores_q, 0, scores_q.len()).unwrap(),
                DeviceSlice::new(&d_row_shifts, 0, row_shifts.len()).unwrap(),
                DeviceSlice::new(&d_exp, 0, exp_outputs.len()).unwrap(),
                DeviceSlice::new(&d_denoms, 0, denoms.len()).unwrap(),
                DeviceSlice::new(&d_recips, 0, recips.len()).unwrap(),
                DeviceSlice::new(&d_weights, 0, softmax_weights.len()).unwrap(),
                DeviceSlice::new(&d_recip_lut, 0, recip_lut.len()).unwrap(),
                DeviceSlice::new(&d_qkv_acc, 0, qkv_acc.len()).unwrap(),
                DeviceSlice::new(&error, 0, 1).unwrap(),
                query_rows,
                seq,
                pos0,
                heads,
                head_pad,
                head_dim,
                shift_scores,
                shift_norm,
                shift_qkv,
                0,
                exp_pad,
                recip_lut[0],
                true,
            )
            .unwrap();
        assert_eq!(gpu.download_device(&error, 0, 1).unwrap(), vec![0]);

        let q_pad = query_rows.next_power_of_two();
        let s_pad = seq.next_power_of_two();
        let sp2 = q_pad * s_pad;
        let rect_entries = head_pad * sp2;
        assert_eq!(wires.rect_entries(), rect_entries);
        let rect = gpu
            .download_device(wires.rect_column(0).unwrap().buffer(), 0, 7 * rect_entries)
            .unwrap();
        let mut expected = vec![0u64; 7 * rect_entries];
        for h in 0..head_pad {
            for i in 0..q_pad {
                for j in 0..s_pad {
                    let z = h * sp2 + i * s_pad + j;
                    let mut norm_rem = 8i64;
                    let mut weight = 0i64;
                    let mut score_rem = 8i64;
                    let mut sprime = exp_pad as i64;
                    let mut exp_value = 0i64;
                    let mut is_max = 0i64;
                    let mut full = 0i64;
                    if h < heads && i < query_rows && j < seq {
                        full = (0..head_dim).fold(0i64, |sum, l| {
                            sum + q[i * d + h * head_dim + l] as i64
                                * k[j * d + h * head_dim + l] as i64
                        });
                        if j <= i {
                            let packed = h * per_head + i * (i + 1) / 2 + j;
                            sprime =
                                scores_q[packed] as i64 - row_shifts[h * query_rows + i] as i64;
                            score_rem = scores_acc[packed] + 8 - ((scores_q[packed] as i64) << 4);
                            exp_value = 2;
                            weight = 0;
                            norm_rem = 14;
                            is_max = i64::from(
                                sprime == 0
                                    && (0..j).all(|prior| {
                                        let p = h * per_head + i * (i + 1) / 2 + prior;
                                        scores_q[p] != row_shifts[h * query_rows + i]
                                    }),
                            );
                        }
                    }
                    expected[z] = norm_rem as u64;
                    expected[rect_entries + z] = Fp::from_i64(weight).value();
                    expected[2 * rect_entries + z] = score_rem as u64;
                    expected[3 * rect_entries + z] = Fp::from_i64(sprime).value();
                    expected[4 * rect_entries + z] = Fp::from_i64(exp_value).value();
                    expected[5 * rect_entries + z] = is_max as u64;
                    expected[6 * rect_entries + z] = Fp::from_i64(full).value();
                }
            }
        }
        assert_eq!(rect, expected);

        let row_entries = head_pad * q_pad;
        let row_values =
            gpu.download_device(wires.row_column(0).unwrap().buffer(), 0, 4 * row_entries).unwrap();
        for h in 0..head_pad {
            for i in 0..q_pad {
                let z = h * q_pad + i;
                if h < heads && i < query_rows {
                    assert_eq!(Fp::new(row_values[z]), Fp::from_i64(denoms[h * query_rows + i]));
                    assert_eq!(row_values[row_entries + z], denoms[h * query_rows + i] as u64);
                    assert_eq!(Fp::new(row_values[2 * row_entries + z]), Fp::from_i64(3));
                    assert_eq!(
                        Fp::new(row_values[3 * row_entries + z]),
                        Fp::from_i64(row_shifts[h * query_rows + i] as i64)
                    );
                } else {
                    assert_eq!(row_values[z], 0);
                    assert_eq!(row_values[row_entries + z], 0);
                    assert_eq!(Fp::new(row_values[2 * row_entries + z]), Fp::from_i64(7));
                    assert_eq!(row_values[3 * row_entries + z], 0);
                }
            }
        }
        let above = gpu
            .download_device(wires.above().buffer(), wires.above().offset(), wires.above().len())
            .unwrap();
        let mut expected_above = Vec::new();
        for h in 0..heads {
            for i in 0..query_rows {
                for j in i + 1..seq {
                    let full = (0..head_dim).fold(0i64, |sum, l| {
                        sum + q[i * d + h * head_dim + l] as i64
                            * k[j * d + h * head_dim + l] as i64
                    });
                    expected_above.push(Fp::from_i64(full).value());
                }
            }
        }
        assert_eq!(above, expected_above);

        let d_pad = d.next_power_of_two();
        let qkv_entries = q_pad * 4 * d_pad;
        let qkv_columns =
            gpu.download_device(wires.qkv_column(0).unwrap().buffer(), 0, 2 * qkv_entries).unwrap();
        for i in 0..q_pad {
            for col in 0..4 * d_pad {
                let z = i * 4 * d_pad + col;
                let third = col / d_pad;
                let rest = col % d_pad;
                let output = if i < query_rows && third < 3 && rest < d {
                    match third {
                        0 => q[i * d + rest],
                        1 => k[i * d + rest],
                        _ => v[i * d + rest],
                    }
                } else {
                    0
                };
                assert_eq!(qkv_columns[z], 8);
                assert_eq!(Fp::new(qkv_columns[qkv_entries + z]), Fp::from_i64(output as i64));
            }
        }

        gpu.free_attention_proof_wires(wires).unwrap();
        gpu.free_device(error).unwrap();
        gpu.free_device(d_qkv_acc).unwrap();
        gpu.free_device(d_recip_lut).unwrap();
        gpu.free_device(d_weights).unwrap();
        gpu.free_device(d_recips).unwrap();
        gpu.free_device(d_denoms).unwrap();
        gpu.free_device(d_exp).unwrap();
        gpu.free_device(d_row_shifts).unwrap();
        gpu.free_device(d_scores_q).unwrap();
        gpu.free_device(d_scores_acc).unwrap();
        gpu.free_device(dv).unwrap();
        gpu.free_device(dk).unwrap();
        gpu.free_device(dq).unwrap();
    }

    #[test]
    fn resident_buffer_context_ownership_is_enforced() {
        let Some(mut owner) = cuda(BackendKind::CudaResident) else { return };
        let Some(mut other) = cuda(BackendKind::CudaResident) else { return };
        let buffer = owner.upload_new_device(&[1u64, 2, 3, 4]).unwrap();
        assert!(matches!(
            other.download_device(&buffer, 0, buffer.len()),
            Err(AccelError::InvalidInput("device buffer belongs to a different CUDA context"))
        ));
        owner.free_device(buffer).unwrap();
    }

    #[test]
    fn pcs_row_combinations_and_column_gather_are_bit_exact() {
        let Some(mut gpu) = cuda(BackendKind::CudaHybrid) else { return };
        let (rows, cols, pad, combinations) = (7, 11, 3, 4);
        let weights: Vec<i16> =
            (0..rows * cols).map(|i| ((i * 37 + 9) % 1001) as i16 - 500).collect();
        let pads: Vec<Fp> = (0..rows * pad).map(|i| Fp::new(i as u64 * 53 + 5)).collect();
        let coeffs: Vec<Fp2> = (0..combinations * rows)
            .map(|i| Fp2::new(Fp::new(i as u64 * 71 + 7), Fp::new(i as u64 * 97 + 13)))
            .collect();
        let got =
            gpu.pcs_combine_rows(&weights, &pads, &coeffs, rows, cols, pad, combinations).unwrap();
        for combo in 0..combinations {
            for j in 0..cols + pad {
                let expected = (0..rows).fold(Fp2::ZERO, |acc, i| {
                    let x = if j < cols {
                        Fp::from_i64(weights[i * cols + j] as i64)
                    } else {
                        pads[i * pad + j - cols]
                    };
                    acc + coeffs[combo * rows + i].mul_base(x)
                });
                assert_eq!(got[combo][j], expected, "combo={combo}, col={j}");
            }
        }

        let (grows, gcols) = (13, 16);
        let matrix: Vec<Fp> = (0..grows * gcols).map(|i| Fp::new(i as u64 * 131 + 17)).collect();
        let indices = [0u32, 7, 15, 3];
        let gathered = gpu.pcs_gather_columns(&matrix, grows, gcols, &indices).unwrap();
        for (q, &j) in indices.iter().enumerate() {
            let expected: Vec<Fp> = (0..grows).map(|i| matrix[i * gcols + j as usize]).collect();
            assert_eq!(gathered[q], expected);
        }
    }
}

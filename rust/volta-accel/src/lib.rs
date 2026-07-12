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

pub const CUDA_ABI_VERSION: u32 = 3;
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
    pub allocation_calls: u64,
    pub live_device_bytes: u64,
    pub peak_device_bytes: u64,
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

impl<T: DeviceElement> DeviceBuffer<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
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
        assert_eq!(
            stats.synchronizations,
            match stats.timing_mode {
                DeviceTimingMode::CudaEvents => 6,
                DeviceTimingMode::HostBarrierWall => 18,
                DeviceTimingMode::None => panic!("CUDA stats have no timing mode"),
            }
        );
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
        assert_eq!(gpu.stats().unwrap().live_device_bytes, 0);
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

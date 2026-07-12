use super::{
    AccelError, BackendStats, DeviceTimingMode, Fp2Repr, OperationStats, CUDA_ABI_VERSION,
    OPERATION_COUNT,
};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use volta_field::{Fp, Fp2};

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
    fn dlclose(handle: *mut c_void) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawStats {
    calls: [u64; OPERATION_COUNT],
    kernel_ns: [u64; OPERATION_COUNT],
    h2d_bytes: u64,
    d2h_bytes: u64,
    h2d_ns: u64,
    d2h_ns: u64,
    synchronizations: u64,
    synchronization_ns: u64,
    allocation_calls: u64,
    live_device_bytes: u64,
    peak_device_bytes: u64,
    timing_mode: u32,
    reserved: u32,
}

const _: () = assert!(std::mem::size_of::<RawStats>() == 160);

type AbiVersion = unsafe extern "C" fn() -> u32;
type Create = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
type Destroy = unsafe extern "C" fn(*mut c_void);
type LastError = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type ResetStats = unsafe extern "C" fn(*mut c_void) -> c_int;
type GetStats = unsafe extern "C" fn(*mut c_void, *mut RawStats) -> c_int;
type ResidentAlloc = unsafe extern "C" fn(*mut c_void, usize, *mut u64) -> c_int;
type ResidentFree = unsafe extern "C" fn(*mut c_void, u64) -> c_int;
type ResidentUpload = unsafe extern "C" fn(*mut c_void, u64, usize, *const c_void, usize) -> c_int;
type ResidentDownload = unsafe extern "C" fn(*mut c_void, u64, usize, *mut c_void, usize) -> c_int;
type GemmI64 = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const i16,
    *mut i64,
    usize,
    usize,
    usize,
) -> c_int;
type GemmI64Device = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
) -> c_int;
type GemmRequantAuth = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const i16,
    *const u64,
    *mut i16,
    *mut u64,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type GemmRequantAuthDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type NttFp = unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, *mut u64) -> c_int;
type NttFpBatch =
    unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, usize, *mut u64) -> c_int;
type NttFp2 =
    unsafe extern "C" fn(*mut c_void, *const Fp2Repr, usize, usize, *mut Fp2Repr) -> c_int;
type LogupTree = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    *const u32,
    usize,
    u64,
    c_int,
    *mut Fp2Repr,
    *mut Fp2Repr,
) -> c_int;
type LogupTreeDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    usize,
    u64,
    c_int,
    u64,
    usize,
    u64,
    usize,
) -> c_int;
type LogupMaterializeLeavesDevice = LogupTreeDevice;
type LogupGeneralRound = unsafe extern "C" fn(
    *mut c_void,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    usize,
    *mut Fp2Repr,
) -> c_int;
type LogupGeneralRoundDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    *mut Fp2Repr,
) -> c_int;
type LogupFold4 = unsafe extern "C" fn(
    *mut c_void,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    usize,
    Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
) -> c_int;
type LogupFold4Device = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    Fp2Repr,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
) -> c_int;
type Fp2DeinterleaveDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize, u64, usize) -> c_int;
type LogupSuffixEqDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize) -> c_int;
type HashFpColumns = unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, *mut u8) -> c_int;
type PcsCombineRows = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const u64,
    *const Fp2Repr,
    usize,
    usize,
    usize,
    usize,
    *mut Fp2Repr,
) -> c_int;
type PcsGatherColumns = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    usize,
    usize,
    *const u32,
    usize,
    *mut u64,
) -> c_int;

struct Api {
    handle: *mut c_void,
    create: Create,
    destroy: Destroy,
    last_error: LastError,
    reset_stats: ResetStats,
    get_stats: GetStats,
    resident_alloc: ResidentAlloc,
    resident_free: ResidentFree,
    resident_upload: ResidentUpload,
    resident_download: ResidentDownload,
    gemm_i64: GemmI64,
    gemm_i64_device: GemmI64Device,
    gemm_requant_auth: GemmRequantAuth,
    gemm_requant_auth_device: GemmRequantAuthDevice,
    ntt_fp: NttFp,
    ntt_fp_batch: NttFpBatch,
    ntt_fp2: NttFp2,
    logup_tree: LogupTree,
    logup_tree_device: LogupTreeDevice,
    logup_materialize_leaves_device: LogupMaterializeLeavesDevice,
    logup_general_round: LogupGeneralRound,
    logup_general_round_device: LogupGeneralRoundDevice,
    logup_fold4: LogupFold4,
    logup_fold4_device: LogupFold4Device,
    fp2_deinterleave_device: Fp2DeinterleaveDevice,
    logup_suffix_eq_device: LogupSuffixEqDevice,
    pcs_combine_rows: PcsCombineRows,
    pcs_gather_columns: PcsGatherColumns,
    hash_fp_columns: HashFpColumns,
}

pub(super) struct CudaContext {
    raw: *mut c_void,
    api: Api,
}

impl CudaContext {
    pub(super) fn load() -> Result<CudaContext, AccelError> {
        let path = std::env::var("VOLTA_CUDA_LIBRARY")
            .unwrap_or_else(|_| "libvolta_cuda_backend.so".to_owned());
        let cpath = CString::new(path.clone())
            .map_err(|_| AccelError::LibraryLoad("library path contains NUL".to_owned()))?;
        // SAFETY: cpath is NUL terminated and remains alive for this call.
        let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if handle.is_null() {
            return Err(AccelError::LibraryLoad(format!("{path}: {}", dl_error())));
        }
        let api_result = unsafe { Self::load_api(handle) };
        let api = match api_result {
            Ok(api) => api,
            Err(e) => {
                // SAFETY: handle was returned by dlopen and is not otherwise owned.
                unsafe { dlclose(handle) };
                return Err(e);
            }
        };
        let mut raw = ptr::null_mut();
        // SAFETY: function pointer and out parameter follow the versioned C ABI.
        let rc = unsafe { (api.create)(&mut raw) };
        if rc != 0 || raw.is_null() {
            let msg = if raw.is_null() {
                format!("initialization failed with status {rc}")
            } else {
                // SAFETY: raw came from the backend and last_error accepts it.
                unsafe { c_error((api.last_error)(raw), rc) }
            };
            if !raw.is_null() {
                // SAFETY: partially initialized context is owned here.
                unsafe { (api.destroy)(raw) };
            }
            // SAFETY: api.handle remains live and is owned here.
            unsafe { dlclose(api.handle) };
            return Err(AccelError::Cuda(msg));
        }
        Ok(CudaContext { raw, api })
    }

    unsafe fn load_api(handle: *mut c_void) -> Result<Api, AccelError> {
        let abi: AbiVersion = unsafe { load_symbol(handle, b"volta_cuda_abi_version\0")? };
        // SAFETY: loaded symbol has the declared ABI by contract.
        let found = unsafe { abi() };
        if found != CUDA_ABI_VERSION {
            return Err(AccelError::AbiMismatch { expected: CUDA_ABI_VERSION, found });
        }
        Ok(Api {
            handle,
            create: unsafe { load_symbol(handle, b"volta_cuda_create\0")? },
            destroy: unsafe { load_symbol(handle, b"volta_cuda_destroy\0")? },
            last_error: unsafe { load_symbol(handle, b"volta_cuda_last_error\0")? },
            reset_stats: unsafe { load_symbol(handle, b"volta_cuda_reset_stats\0")? },
            get_stats: unsafe { load_symbol(handle, b"volta_cuda_get_stats\0")? },
            resident_alloc: unsafe { load_symbol(handle, b"volta_cuda_resident_alloc\0")? },
            resident_free: unsafe { load_symbol(handle, b"volta_cuda_resident_free\0")? },
            resident_upload: unsafe { load_symbol(handle, b"volta_cuda_resident_upload\0")? },
            resident_download: unsafe { load_symbol(handle, b"volta_cuda_resident_download\0")? },
            gemm_i64: unsafe { load_symbol(handle, b"volta_cuda_gemm_i64\0")? },
            gemm_i64_device: unsafe { load_symbol(handle, b"volta_cuda_gemm_i64_device\0")? },
            gemm_requant_auth: unsafe { load_symbol(handle, b"volta_cuda_gemm_requant_auth\0")? },
            gemm_requant_auth_device: unsafe {
                load_symbol(handle, b"volta_cuda_gemm_requant_auth_device\0")?
            },
            ntt_fp: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp\0")? },
            ntt_fp_batch: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp_batch\0")? },
            ntt_fp2: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp2\0")? },
            logup_tree: unsafe { load_symbol(handle, b"volta_cuda_logup_tree\0")? },
            logup_tree_device: unsafe { load_symbol(handle, b"volta_cuda_logup_tree_device\0")? },
            logup_materialize_leaves_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_materialize_leaves_device\0")?
            },
            logup_general_round: unsafe {
                load_symbol(handle, b"volta_cuda_logup_general_round\0")?
            },
            logup_general_round_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_general_round_device\0")?
            },
            logup_fold4: unsafe { load_symbol(handle, b"volta_cuda_logup_fold4\0")? },
            logup_fold4_device: unsafe { load_symbol(handle, b"volta_cuda_logup_fold4_device\0")? },
            fp2_deinterleave_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_deinterleave_device\0")?
            },
            logup_suffix_eq_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_suffix_eq_device\0")?
            },
            pcs_combine_rows: unsafe { load_symbol(handle, b"volta_cuda_pcs_combine_rows\0")? },
            pcs_gather_columns: unsafe { load_symbol(handle, b"volta_cuda_pcs_gather_columns\0")? },
            hash_fp_columns: unsafe { load_symbol(handle, b"volta_cuda_hash_fp_columns\0")? },
        })
    }

    fn check(&self, rc: c_int) -> Result<(), AccelError> {
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: context is live for the lifetime of self.
            Err(AccelError::Cuda(unsafe { c_error((self.api.last_error)(self.raw), rc) }))
        }
    }

    pub(super) fn reset_stats(&mut self) -> Result<(), AccelError> {
        // SAFETY: context is live and exclusively borrowed.
        self.check(unsafe { (self.api.reset_stats)(self.raw) })
    }

    pub(super) fn stats(&self) -> Result<BackendStats, AccelError> {
        let mut raw = RawStats::default();
        // SAFETY: output points to a correctly sized C representation.
        self.check(unsafe { (self.api.get_stats)(self.raw, &mut raw) })?;
        let mut out = BackendStats {
            timing_mode: match raw.timing_mode {
                1 => DeviceTimingMode::CudaEvents,
                2 => DeviceTimingMode::HostBarrierWall,
                value => {
                    return Err(AccelError::Cuda(format!(
                        "CUDA backend returned unknown timing mode {value}"
                    )));
                }
            },
            h2d_bytes: raw.h2d_bytes,
            d2h_bytes: raw.d2h_bytes,
            h2d_ns: raw.h2d_ns,
            d2h_ns: raw.d2h_ns,
            synchronizations: raw.synchronizations,
            synchronization_ns: raw.synchronization_ns,
            allocation_calls: raw.allocation_calls,
            live_device_bytes: raw.live_device_bytes,
            peak_device_bytes: raw.peak_device_bytes,
            ..Default::default()
        };
        for i in 0..OPERATION_COUNT {
            out.operations[i] = OperationStats {
                calls: raw.calls[i],
                kernel_ns: raw.kernel_ns[i],
                cpu_residual_ns: 0,
            };
        }
        Ok(out)
    }

    pub(super) fn resident_alloc(&mut self, bytes: usize) -> Result<u64, AccelError> {
        let mut id = 0;
        // SAFETY: context is live and id points to one u64 result.
        self.check(unsafe { (self.api.resident_alloc)(self.raw, bytes, &mut id) })?;
        Ok(id)
    }

    pub(super) fn resident_free(&mut self, id: u64) -> Result<(), AccelError> {
        // SAFETY: context validates the opaque allocation id.
        self.check(unsafe { (self.api.resident_free)(self.raw, id) })
    }

    pub(super) fn resident_upload(
        &mut self,
        id: u64,
        offset_bytes: usize,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: safe caller retains the typed input slice for the synchronous ABI call.
        self.check(unsafe { (self.api.resident_upload)(self.raw, id, offset_bytes, src, bytes) })
    }

    pub(super) fn resident_download(
        &mut self,
        id: u64,
        offset_bytes: usize,
        dst: *mut c_void,
        bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: safe caller allocated the typed output slice and the ABI synchronizes.
        self.check(unsafe { (self.api.resident_download)(self.raw, id, offset_bytes, dst, bytes) })
    }

    pub(super) fn gemm_i64(
        &mut self,
        a: &[i16],
        b: &[i16],
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<Vec<i64>, AccelError> {
        let mut out = vec![0i64; m * n];
        // SAFETY: slice lengths were validated by the safe caller.
        self.check(unsafe {
            (self.api.gemm_i64)(self.raw, a.as_ptr(), b.as_ptr(), out.as_mut_ptr(), m, k, n)
        })?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gemm_i64_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        out: u64,
        out_offset: usize,
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: context owns every opaque id; Rust validated typed regions.
        self.check(unsafe {
            (self.api.gemm_i64_device)(self.raw, a, a_offset, b, b_offset, out, out_offset, m, k, n)
        })
    }

    pub(super) fn gemm_requant_auth(
        &mut self,
        a: &[i16],
        b: &[i16],
        masks: &[Fp],
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(Vec<i16>, Vec<u64>), AccelError> {
        let raw_masks: Vec<u64> = masks.iter().map(|x| x.value()).collect();
        let mut out = vec![0i16; m * n];
        let mut corr = vec![0u64; m * n];
        // SAFETY: all buffers have the dimensions supplied to the C ABI.
        self.check(unsafe {
            (self.api.gemm_requant_auth)(
                self.raw,
                a.as_ptr(),
                b.as_ptr(),
                raw_masks.as_ptr(),
                out.as_mut_ptr(),
                corr.as_mut_ptr(),
                m,
                k,
                n,
                shift,
            )
        })?;
        Ok((out, corr))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gemm_requant_auth_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        masks: u64,
        masks_offset: usize,
        out: u64,
        out_offset: usize,
        corr: u64,
        corr_offset: usize,
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: context owns every opaque id; Rust validated typed regions.
        self.check(unsafe {
            (self.api.gemm_requant_auth_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                masks,
                masks_offset,
                out,
                out_offset,
                corr,
                corr_offset,
                m,
                k,
                n,
                shift,
            )
        })
    }

    pub(super) fn ntt_fp(&mut self, msg: &[Fp], size: usize) -> Result<Vec<Fp>, AccelError> {
        let input: Vec<u64> = msg.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; size];
        // SAFETY: input/output lengths match the supplied geometry.
        self.check(unsafe {
            (self.api.ntt_fp)(self.raw, input.as_ptr(), input.len(), size, output.as_mut_ptr())
        })?;
        Ok(output.into_iter().map(Fp::new).collect())
    }

    pub(super) fn ntt_fp_batch(
        &mut self,
        messages: &[Fp],
        rows: usize,
        msg_len: usize,
        size: usize,
    ) -> Result<Vec<Fp>, AccelError> {
        let input: Vec<u64> = messages.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; rows * size];
        // SAFETY: compact input and padded output geometries were validated.
        self.check(unsafe {
            (self.api.ntt_fp_batch)(
                self.raw,
                input.as_ptr(),
                rows,
                msg_len,
                size,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output.into_iter().map(Fp::new).collect())
    }

    pub(super) fn ntt_fp2(&mut self, msg: &[Fp2], size: usize) -> Result<Vec<Fp2>, AccelError> {
        let input: Vec<Fp2Repr> = msg.iter().copied().map(Into::into).collect();
        let mut output = vec![Fp2Repr::default(); size];
        // SAFETY: input/output lengths match the supplied geometry.
        self.check(unsafe {
            (self.api.ntt_fp2)(self.raw, input.as_ptr(), input.len(), size, output.as_mut_ptr())
        })?;
        Ok(output.into_iter().map(Into::into).collect())
    }

    pub(super) fn logup_tree(
        &mut self,
        leaf_a: &[Fp],
        alpha1: Fp,
        mult: Option<&[u32]>,
    ) -> Result<(Vec<Vec<Fp2>>, Vec<Vec<Fp2>>), AccelError> {
        let n = leaf_a.len();
        let input: Vec<u64> = leaf_a.iter().map(|x| x.value()).collect();
        let mut p = vec![Fp2Repr::default(); n - 1];
        let mut q = vec![Fp2Repr::default(); n - 1];
        let (mp, kind) = mult.map_or((ptr::null(), 0), |m| (m.as_ptr(), 1));
        // SAFETY: all vectors have n or n-1 entries as required by the ABI.
        self.check(unsafe {
            (self.api.logup_tree)(
                self.raw,
                input.as_ptr(),
                mp,
                n,
                alpha1.value(),
                kind,
                p.as_mut_ptr(),
                q.as_mut_ptr(),
            )
        })?;
        Ok((unflatten_tree(p, n), unflatten_tree(q, n)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_tree_device(
        &mut self,
        leaf: u64,
        leaf_offset: usize,
        mult: Option<(u64, usize)>,
        n: usize,
        alpha1: Fp,
        p: u64,
        p_offset: usize,
        q: u64,
        q_offset: usize,
    ) -> Result<(), AccelError> {
        let (mult_id, mult_offset, kind) = mult.map_or((0, 0, 0), |(id, offset)| (id, offset, 1));
        // SAFETY: opaque ids and typed ranges were validated by Backend.
        self.check(unsafe {
            (self.api.logup_tree_device)(
                self.raw,
                leaf,
                leaf_offset,
                mult_id,
                mult_offset,
                n,
                alpha1.value(),
                kind,
                p,
                p_offset,
                q,
                q_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_materialize_leaves_device(
        &mut self,
        leaf: u64,
        leaf_offset: usize,
        mult: Option<(u64, usize)>,
        n: usize,
        alpha1: Fp,
        p: u64,
        p_offset: usize,
        q: u64,
        q_offset: usize,
    ) -> Result<(), AccelError> {
        let (mult_id, mult_offset, kind) = mult.map_or((0, 0, 0), |(id, offset)| (id, offset, 1));
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.logup_materialize_leaves_device)(
                self.raw,
                leaf,
                leaf_offset,
                mult_id,
                mult_offset,
                n,
                alpha1.value(),
                kind,
                p,
                p_offset,
                q,
                q_offset,
            )
        })
    }

    pub(super) fn logup_general_round(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        suffix_eq: &[Fp2],
    ) -> Result<[Fp2; 4], AccelError> {
        let cvt = |v: &[Fp2]| v.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let (p0, p1, q0, q1, suffix) = (cvt(p0), cvt(p1), cvt(q0), cvt(q1), cvt(suffix_eq));
        let mut out = [Fp2Repr::default(); 4];
        // SAFETY: every vector geometry was validated by the safe caller.
        self.check(unsafe {
            (self.api.logup_general_round)(
                self.raw,
                p0.as_ptr(),
                p1.as_ptr(),
                q0.as_ptr(),
                q1.as_ptr(),
                suffix.as_ptr(),
                suffix.len(),
                out.as_mut_ptr(),
            )
        })?;
        Ok(out.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_general_round_device(
        &mut self,
        p0: u64,
        p0_offset: usize,
        p1: u64,
        p1_offset: usize,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        suffix: u64,
        suffix_offset: usize,
        pairs: usize,
    ) -> Result<[Fp2; 4], AccelError> {
        let mut out = [Fp2Repr::default(); 4];
        // SAFETY: opaque ids and typed ranges were validated by Backend; the
        // output is one protocol round message and the ABI synchronizes it.
        self.check(unsafe {
            (self.api.logup_general_round_device)(
                self.raw,
                p0,
                p0_offset,
                p1,
                p1_offset,
                q0,
                q0_offset,
                q1,
                q1_offset,
                suffix,
                suffix_offset,
                pairs,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out.map(Into::into))
    }

    pub(super) fn logup_fold4(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        r: Fp2,
    ) -> Result<[Vec<Fp2>; 4], AccelError> {
        let cvt = |v: &[Fp2]| v.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let input = [cvt(p0), cvt(p1), cvt(q0), cvt(q1)];
        let half = p0.len() / 2;
        let mut output: [Vec<Fp2Repr>; 4] = std::array::from_fn(|_| vec![Fp2Repr::default(); half]);
        // SAFETY: inputs have 2*half entries and outputs half entries.
        self.check(unsafe {
            (self.api.logup_fold4)(
                self.raw,
                input[0].as_ptr(),
                input[1].as_ptr(),
                input[2].as_ptr(),
                input[3].as_ptr(),
                half,
                r.into(),
                output[0].as_mut_ptr(),
                output[1].as_mut_ptr(),
                output[2].as_mut_ptr(),
                output[3].as_mut_ptr(),
            )
        })?;
        Ok(output.map(|v| v.into_iter().map(Into::into).collect()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_fold4_device(
        &mut self,
        p0: u64,
        p0_offset: usize,
        p1: u64,
        p1_offset: usize,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        pairs: usize,
        r: Fp2,
        o0: u64,
        o0_offset: usize,
        o1: u64,
        o1_offset: usize,
        o2: u64,
        o2_offset: usize,
        o3: u64,
        o3_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: opaque ids and typed ranges were validated by Backend.
        self.check(unsafe {
            (self.api.logup_fold4_device)(
                self.raw,
                p0,
                p0_offset,
                p1,
                p1_offset,
                q0,
                q0_offset,
                q1,
                q1_offset,
                pairs,
                r.into(),
                o0,
                o0_offset,
                o1,
                o1_offset,
                o2,
                o2_offset,
                o3,
                o3_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_deinterleave_device(
        &mut self,
        input: u64,
        input_offset: usize,
        pairs: usize,
        even: u64,
        even_offset: usize,
        odd: u64,
        odd_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.fp2_deinterleave_device)(
                self.raw,
                input,
                input_offset,
                pairs,
                even,
                even_offset,
                odd,
                odd_offset,
            )
        })
    }

    pub(super) fn logup_suffix_eq_device(
        &mut self,
        points: u64,
        points_offset: usize,
        point_len: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.logup_suffix_eq_device)(
                self.raw,
                points,
                points_offset,
                point_len,
                output,
                output_offset,
            )
        })
    }

    pub(super) fn hash_fp_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
    ) -> Result<Vec<[u8; 32]>, AccelError> {
        let input: Vec<u64> = matrix.iter().map(|x| x.value()).collect();
        let mut bytes = vec![0u8; cols * 32];
        // SAFETY: matrix and output geometries were checked by the safe caller.
        self.check(unsafe {
            (self.api.hash_fp_columns)(self.raw, input.as_ptr(), rows, cols, bytes.as_mut_ptr())
        })?;
        Ok(bytes.chunks_exact(32).map(|x| x.try_into().unwrap()).collect())
    }

    pub(super) fn pcs_combine_rows(
        &mut self,
        weights: &[i16],
        pads: &[Fp],
        coeffs: &[Fp2],
        rows: usize,
        cols: usize,
        pad: usize,
        combinations: usize,
    ) -> Result<Vec<Vec<Fp2>>, AccelError> {
        let raw_pads: Vec<u64> = pads.iter().map(|x| x.value()).collect();
        let raw_coeffs: Vec<Fp2Repr> = coeffs.iter().copied().map(Into::into).collect();
        let msg_len = cols + pad;
        let mut output = vec![Fp2Repr::default(); combinations * msg_len];
        // SAFETY: every buffer follows the checked matrix geometry.
        self.check(unsafe {
            (self.api.pcs_combine_rows)(
                self.raw,
                weights.as_ptr(),
                raw_pads.as_ptr(),
                raw_coeffs.as_ptr(),
                rows,
                cols,
                pad,
                combinations,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output
            .chunks_exact(msg_len)
            .map(|row| row.iter().copied().map(Into::into).collect())
            .collect())
    }

    pub(super) fn pcs_gather_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
        indices: &[u32],
    ) -> Result<Vec<Vec<Fp>>, AccelError> {
        let raw: Vec<u64> = matrix.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; rows * indices.len()];
        // SAFETY: matrix, index and output lengths follow the checked geometry.
        self.check(unsafe {
            (self.api.pcs_gather_columns)(
                self.raw,
                raw.as_ptr(),
                rows,
                cols,
                indices.as_ptr(),
                indices.len(),
                output.as_mut_ptr(),
            )
        })?;
        Ok(output
            .chunks_exact(rows)
            .map(|col| col.iter().copied().map(Fp::new).collect())
            .collect())
    }
}

impl Drop for CudaContext {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns both the context and dlopen handle.
        unsafe {
            (self.api.destroy)(self.raw);
            dlclose(self.api.handle);
        }
    }
}

fn unflatten_tree(flat: Vec<Fp2Repr>, n: usize) -> Vec<Vec<Fp2>> {
    let depth = n.trailing_zeros() as usize;
    let mut out = Vec::with_capacity(depth);
    let mut off = 0;
    for level in 0..depth {
        let len = 1usize << level;
        out.push(flat[off..off + len].iter().copied().map(Into::into).collect());
        off += len;
    }
    debug_assert_eq!(off, n - 1);
    out
}

unsafe fn load_symbol<T: Copy>(handle: *mut c_void, name: &'static [u8]) -> Result<T, AccelError> {
    debug_assert_eq!(name.last(), Some(&0));
    // Clear an old loader error, then resolve the NUL-terminated static name.
    unsafe { dlerror() };
    let p = unsafe { dlsym(handle, name.as_ptr().cast()) };
    let error = unsafe { dlerror() };
    if p.is_null() || !error.is_null() {
        let label = String::from_utf8_lossy(&name[..name.len() - 1]).into_owned();
        return Err(AccelError::MissingSymbol(label));
    }
    // POSIX specifies conversion between dlsym's void pointer and a function
    // pointer. transmute_copy avoids imposing a generic-size proof on T.
    Ok(unsafe { std::mem::transmute_copy(&p) })
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a process-owned NUL string.
    unsafe {
        let p = dlerror();
        if p.is_null() {
            "unknown dynamic-loader error".to_owned()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

unsafe fn c_error(p: *const c_char, rc: c_int) -> String {
    if p.is_null() {
        format!("status {rc}")
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

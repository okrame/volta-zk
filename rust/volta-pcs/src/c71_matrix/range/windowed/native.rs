//! Explicit native range backend. The library is trusted executable code;
//! never load a path from the proof/transcript. No environment-selected backend.
use super::*;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::{size_of, size_of_val};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, MutexGuard};

pub(in crate::c71_matrix) type ResidentReader =
    Arc<dyn Fn(&mut Runtime, usize, usize, usize, usize) -> Result<Buffer, String> + Send + Sync>;

#[derive(Clone)]
struct Resident {
    runtime: Arc<Mutex<Runtime>>,
    read: ResidentReader,
}

#[derive(Clone)]
pub(in crate::c71_matrix) struct Config {
    pub library: PathBuf,
    pub device: i32,
    pub arena_bytes: u64,
    pub reserve_bytes: u64,
    pub window_words: usize,
    pub buckets: u32,
    resident: Option<Resident>,
}

impl Config {
    pub(in crate::c71_matrix) fn new(
        library: PathBuf,
        device: i32,
        arena_bytes: u64,
        reserve_bytes: u64,
        window_words: usize,
        buckets: u32,
    ) -> Self {
        Self { library, device, arena_bytes, reserve_bytes, window_words, buckets, resident: None }
    }
    pub(in crate::c71_matrix) fn with_resident(
        mut self,
        runtime: Arc<Mutex<Runtime>>,
        read: ResidentReader,
    ) -> Result<Self, String> {
        {
            let mut owner = runtime.lock().map_err(|_| "native owner poisoned")?;
            owner.require_configuration(&self)?;
            if self.resident.is_some() {
                return owner.abort("native resident reader replacement");
            }
        }
        self.resident = Some(Resident { runtime, read });
        Ok(self)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, serde::Serialize)]
pub(in crate::c71_matrix) struct Stats {
    pub arena_bytes: u64,
    pub live_capacity_bytes: u64,
    pub peak_capacity_bytes: u64,
    pub logical_bytes: u64,
    pub allocations: u64,
    pub releases: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub zeroed_bytes: u64,
    pub launches: u64,
    pub fences: u64,
    pub host_owner_bytes: u64,
    pub stopped: u64,
    pub cleanup_failed: u64,
    pub weights_bytes: u64,
    pub weights_loaded_bytes: u64,
    pub weights_sealed: u64,
    pub peak_reserved_bytes: u64,
    pub d2d_bytes: u64,
}

// Fp3 itself has Rust layout. Marshal canonical limbs, never transmute it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Field {
    limbs: [u64; 3],
}
impl From<Fp3> for Field {
    fn from(x: Fp3) -> Self {
        Self { limbs: [x.c0.value(), x.c1.value(), x.c2.value()] }
    }
}
impl Field {
    fn decode(self) -> Result<Fp3, String> {
        if self.limbs.iter().any(|&x| x >= volta_field::P) {
            return Err("native noncanonical output".into());
        }
        Ok(Fp3::new(Fp::new(self.limbs[0]), Fp::new(self.limbs[1]), Fp::new(self.limbs[2])))
    }
}
#[repr(C)]
struct Group {
    alpha: Field,
    lambda: Field,
    prefix: [Field; 35],
    tail_point: [Field; 35],
    first_tail: u64,
    bottom: u32,
    prefix_bits: u32,
    width: u32,
    tail_bits: u32,
    buckets: u32,
}
#[repr(C)]
struct Round {
    lambda: Field,
    prefix_equality: Field,
    point: [Field; 35],
    bits: u32,
}
const _: () =
    assert!(size_of::<Stats>() == 152 && size_of::<Group>() == 1760 && size_of::<Round>() == 896);

// Same POSIX loader pattern as volta-accel's existing CUDA backend, but a
// separate ABI: the legacy accelerator uses Fp2, never this native Fp3.
#[cfg(unix)]
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}
struct Library(*mut c_void);
impl Library {
    fn open(path: &std::path::Path) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| "native library path contains NUL")?;
            // SAFETY: trusted local executable, explicit path, owned NUL string.
            let raw = unsafe { dlopen(path.as_ptr(), 2) }; // RTLD_NOW | RTLD_LOCAL
            if raw.is_null() {
                return Err("native range library unavailable".into());
            }
            Ok(Self(raw))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err("native range requires POSIX".into())
        }
    }
    unsafe fn symbol<T: Copy>(&self, name: &'static [u8]) -> Result<T, String> {
        #[cfg(unix)]
        {
            // SAFETY: caller fixes function type to the versioned native header.
            let p = unsafe { dlsym(self.0, name.as_ptr().cast()) };
            if p.is_null() {
                return Err(format!(
                    "native range symbol missing: {}",
                    String::from_utf8_lossy(name)
                ));
            }
            assert_eq!(size_of::<T>(), size_of::<*mut c_void>());
            Ok(unsafe { std::mem::transmute_copy(&p) })
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err("native range requires POSIX".into())
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            dlclose(self.0);
        }
    }
}
type Raw = *mut c_void;
#[repr(C)]
pub(in crate::c71_matrix) struct DenseShape {
    pub m: u32,
    pub n: u32,
    pub k: u32,
}
const _: () = assert!(size_of::<DenseShape>() == 12);
#[repr(C)]
pub(in crate::c71_matrix) struct Pointwise {
    pub a: i64,
    pub b: i64,
    pub multiply: u32,
}
const _: () = assert!(size_of::<Pointwise>() == 24);
#[repr(C)]
pub(in crate::c71_matrix) struct RopeShape {
    pub rows: u32,
    pub heads: u32,
    pub width: u32,
    pub pairs: u32,
}
const _: () = assert!(size_of::<RopeShape>() == 16);
#[repr(C)]
pub(in crate::c71_matrix) struct RmsShape {
    pub rows: u32,
    pub heads: u32,
    pub columns: u32,
    pub weighted: u32,
    pub coefficients: [u64; 6],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(in crate::c71_matrix) struct AttentionShape {
    pub rows: u32,
    pub first: u32,
    pub head: u32,
    pub old: u32,
    pub groups: u32,
    pub lanes: u32,
}
impl AttentionShape {
    fn valid(&self) -> bool {
        (1..=150).contains(&self.rows)
            && self.first < 150
            && self.rows <= 150 - self.first
            && self.head < 32
            && [0, 150, 300].contains(&self.old)
            && (1..=32).contains(&self.groups)
            && 32 % self.groups == 0
            && (1..=512).contains(&self.lanes)
    }
}
const _: () = assert!(size_of::<RmsShape>() == 64 && size_of::<AttentionShape>() == 24);
#[repr(C)]
pub(in crate::c71_matrix) struct ByteTile {
    pub input_first: u64,
    pub input_stride: u64,
    pub rows: u64,
    pub columns: u64,
    pub original_first: u64,
    pub window_first: u64,
    pub window_length: u64,
    pub byte_first: u32,
    pub width: u32,
    pub signed_width: u32,
    pub dimension: u32,
    pub suffix: u32,
    pub bottom: u32,
}
const _: () = assert!(size_of::<ByteTile>() == 80);
/// Opaque, non-cloneable resident allocation. Release through its runtime;
/// dropping this descriptor alone does not release device capacity.
pub(in crate::c71_matrix) struct Buffer {
    id: u64,
    kind: u32,
    count: usize,
    owner: Arc<()>,
}
macro_rules! api {
    ($($field:ident: $ty:ty => $name:literal),* $(,)?) => {
        struct Api { $($field: $ty,)* _library: Library }
        impl Api {
            fn load(path: &std::path::Path) -> Result<Self, String> {
                let library = Library::open(path)?;
                // SAFETY: fixed C ABI types below mirror c71_range_runtime.h.
                unsafe {
                    let abi: unsafe extern "C" fn() -> u32 = library.symbol(b"c71_range_runtime_abi\0")?;
                    if abi() != 4 { return Err("native range ABI differs".into()); }
                    Ok(Self { $($field: library.symbol(concat!($name, "\0").as_bytes())?,)* _library: library })
                }
            }
        }
    }
}
api! {
    create: unsafe extern "C" fn(i32,u64,u64,extern "C" fn(i64)->i32,*mut Raw)->i32 => "c71_range_create",
    close: unsafe extern "C" fn(Raw,*mut Stats)->i32 => "c71_range_close",
    error: unsafe extern "C" fn(Raw)->*const c_char => "c71_range_error",
    abort: unsafe extern "C" fn(Raw)->i32 => "c71_range_abort",
    stats: unsafe extern "C" fn(Raw,*mut Stats)->i32 => "c71_range_stats",
    alloc: unsafe extern "C" fn(Raw,u32,u64,*mut u64)->i32 => "c71_range_alloc",
    release: unsafe extern "C" fn(Raw,u64)->i32 => "c71_range_release",
    upload: unsafe extern "C" fn(Raw,u64,*const c_void,u64)->i32 => "c71_range_upload",
    zero: unsafe extern "C" fn(Raw,u64)->i32 => "c71_range_zero",
    roots: unsafe extern "C" fn(Raw,u64,u32,Field,u64,u64)->i32 => "c71_range_roots",
    canopy: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_range_runtime_canopy",
    children: unsafe extern "C" fn(Raw,u64)->i32 => "c71_range_as_children",
    groups: unsafe extern "C" fn(Raw,u64,*const Group,u64)->i32 => "c71_range_groups",
    h_sum: unsafe extern "C" fn(Raw,u64,u64,u32)->i32 => "c71_range_runtime_h_sum",
    h_fold: unsafe extern "C" fn(Raw,u64,u64,Field)->i32 => "c71_range_runtime_h_fold",
    child_fold: unsafe extern "C" fn(Raw,u64,Field)->i32 => "c71_range_runtime_child_fold",
    coefficients: unsafe extern "C" fn(Raw,u64,*const Round,*mut Field)->i32 => "c71_range_runtime_coefficients",
    h_coefficients: unsafe extern "C" fn(Raw,u64,*const Round,*mut Field)->i32 => "c71_range_runtime_h_coefficients",
    read: unsafe extern "C" fn(Raw,u64,*mut u64,u32)->i32 => "c71_range_read",
    weights_begin: unsafe extern "C" fn(Raw,u64)->i32 => "c71_dense_weights_begin",
    weights_upload: unsafe extern "C" fn(Raw,u64,*const i16,u64)->i32 => "c71_dense_weights_upload",
    weights_seal: unsafe extern "C" fn(Raw)->i32 => "c71_dense_weights_seal",
    embedding: unsafe extern "C" fn(Raw,u64,u32,u32,*const u32,u32,u64)->i32 => "c71_dense_embedding",
    product: unsafe extern "C" fn(Raw,u64,u64,u64,DenseShape,u64)->i32 => "c71_dense_product_rows",
    quantize: unsafe extern "C" fn(Raw,u64,i32,u64)->i32 => "c71_dense_quantize",
    pointwise: unsafe extern "C" fn(Raw,u64,u64,u64,u64,Pointwise,u64)->i32 => "c71_dense_pointwise",
    histogram_begin: unsafe extern "C" fn(Raw,u64)->i32 => "c71_histogram_begin",
    histogram_seal: unsafe extern "C" fn(Raw,u64)->i32 => "c71_histogram_seal",
    histogram_padding: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_histogram_padding",
    signed_append: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64)->i32 => "c71_signed_append_at",
    original_read: unsafe extern "C" fn(Raw,u64,u32,u64,u64,*mut c_void)->i32 => "c71_original_read",
    rms: unsafe extern "C" fn(Raw,u64,u64,u64,RmsShape,u64,u64,u64)->i32 => "c71_dense_rms",
    qk: unsafe extern "C" fn(Raw,u64,u64,u64,AttentionShape,u64)->i32 => "c71_dense_qk",
    pv: unsafe extern "C" fn(Raw,*const u64,*const u64,u64,AttentionShape,u64)->i32 => "c71_dense_pv",
    softmax: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,AttentionShape,*const u64)->i32 => "c71_dense_softmax",
    lookup: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64)->i32 => "c71_dense_lookup",
    rope: unsafe extern "C" fn(Raw,u64,u64,u64,u64,RopeShape,u64)->i32 => "c71_dense_rope",
    argmax: unsafe extern "C" fn(Raw,u64,u64,u32,u32,u64,*mut u32)->i32 => "c71_dense_argmax",
    byte_begin: unsafe extern "C" fn(Raw,u64)->i32 => "c71_byte_begin",
    byte_scatter: unsafe extern "C" fn(Raw,u64,*const ByteTile,u64)->i32 => "c71_byte_scatter",
    byte_seal: unsafe extern "C" fn(Raw,u64)->i32 => "c71_byte_seal",
}
pub(in crate::c71_matrix) struct Runtime {
    api: Api,
    raw: Raw,
    stopped: bool,
    weights: Option<(Arc<Vec<i16>>, [u8; 32])>,
    owner: Arc<()>,
    configuration: (PathBuf, i32, u64, u64),
}

unsafe impl Send for Runtime {}

impl Runtime {
    pub(in crate::c71_matrix) fn new(config: &Config) -> Result<Self, String> {
        if config.resident.is_some() {
            return Err("resident configuration cannot create a second native owner".into());
        }
        let api = Api::load(&config.library)?;
        let mut s = Self {
            api,
            raw: ptr::null_mut(),
            stopped: false,
            weights: None,
            owner: Arc::new(()),
            configuration: (
                config.library.clone(),
                config.device,
                config.arena_bytes,
                config.reserve_bytes,
            ),
        };
        // SAFETY: owned pointer output; on error Drop also closes partial owners.
        let status = unsafe {
            (s.api.create)(config.device, config.arena_bytes, config.reserve_bytes,
                crate::c71_matrix::census::external, &mut s.raw)
        };
        s.check(status)?;
        if s.raw.is_null() {
            return Err("native range returned null owner".into());
        }
        Ok(s)
    }
    fn ready(&self) -> Result<(), String> {
        if self.stopped || self.raw.is_null() {
            Err("native runtime stopped or closed".into())
        } else {
            Ok(())
        }
    }
    fn require_configuration(&mut self, config: &Config) -> Result<(), String> {
        self.ready()?;
        if self.configuration
            != (config.library.clone(), config.device, config.arena_bytes, config.reserve_bytes)
        {
            return self.abort("native shared configuration differs");
        }
        Ok(())
    }
    fn require_buffer(&mut self, buffer: &Buffer) -> Result<(), String> {
        self.ready()?;
        if !Arc::ptr_eq(&self.owner, &buffer.owner) {
            return self.abort("native buffer belongs to another runtime");
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn abort<T>(
        &mut self,
        message: impl Into<String>,
    ) -> Result<T, String> {
        if !self.raw.is_null() {
            unsafe {
                (self.api.abort)(self.raw);
            }
        }
        self.stopped = true;
        Err(message.into())
    }
    pub(in crate::c71_matrix) fn stats(&self) -> Result<Stats, String> {
        let mut stats = Stats::default();
        let status = unsafe { (self.api.stats)(self.raw, &mut stats) };
        if status != 0 {
            return Err("native stats unavailable".into());
        }
        Ok(stats)
    }
    pub(in crate::c71_matrix) fn install_weights(
        &mut self,
        weights: Arc<Vec<i16>>,
        layout: [u8; 32],
    ) -> Result<(), String> {
        self.ready()?;
        if self.weights.is_some() || layout == [0; 32] {
            return self.abort("native W identity or replacement");
        }
        let status = unsafe { (self.api.weights_begin)(self.raw, weights.len() as u64) };
        self.check(status)?;
        for (i, chunk) in weights.chunks(1 << 27).enumerate() {
            let status = unsafe {
                (self.api.weights_upload)(
                    self.raw,
                    (i as u64) << 27,
                    chunk.as_ptr(),
                    chunk.len() as u64,
                )
            };
            self.check(status)?;
        }
        let status = unsafe { (self.api.weights_seal)(self.raw) };
        self.check(status)?;
        self.weights = Some((weights, layout));
        Ok(())
    }
    pub(in crate::c71_matrix) fn require_weights(
        &mut self,
        weights: &Arc<Vec<i16>>,
        layout: [u8; 32],
    ) -> Result<(), String> {
        self.ready()?;
        if !self.weights.as_ref().is_some_and(|(w, l)| Arc::ptr_eq(w, weights) && *l == layout) {
            return self.abort("native W owner or layout differs");
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn embedding(
        &mut self,
        weight_offset: usize,
        vocabulary: usize,
        columns: usize,
        tokens: &[u32],
    ) -> Result<Buffer, String> {
        self.ready()?;
        if tokens.is_empty()
            || tokens.len() > 150
            || !(1..=262144).contains(&vocabulary)
            || !(1..=21504).contains(&columns)
            || tokens.iter().any(|&t| t as usize >= vocabulary)
        {
            return self.abort("native embedding geometry or token differs");
        }
        let count = tokens.len() * columns;
        let id = self.alloc(1, count)?;
        let status = unsafe {
            (self.api.embedding)(
                self.raw,
                weight_offset as u64,
                vocabulary as u32,
                columns as u32,
                tokens.as_ptr(),
                tokens.len() as u32,
                id,
            )
        };
        self.check(status)?;
        Ok(Buffer { id, kind: 1, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn upload_signed(
        &mut self,
        values: &[i16],
    ) -> Result<Buffer, String> {
        let id = self.alloc(1, values.len())?;
        let status = unsafe {
            (self.api.upload)(self.raw, id, values.as_ptr().cast(), size_of_val(values) as u64)
        };
        self.check(status)?;
        Ok(Buffer { id, kind: 1, count: values.len(), owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn product(
        &mut self,
        input: &Buffer,
        first_row: usize,
        weight_offset: usize,
        shape: DenseShape,
    ) -> Result<Buffer, String> {
        self.ready()?;
        self.require_buffer(input)?;
        if input.kind != 1
            || shape.m == 0
            || shape.m > 150
            || shape.n == 0
            || shape.n > 262144
            || shape.k == 0
            || shape.k > 21504
        {
            return self.abort("native dense shape or input kind");
        }
        let count = shape.m as usize * shape.n as usize;
        let id = self.alloc(6, count)?;
        let status = unsafe {
            (self.api.product)(
                self.raw,
                input.id,
                first_row as u64,
                weight_offset as u64,
                shape,
                id,
            )
        };
        self.check(status)?;
        Ok(Buffer { id, kind: 6, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn quantize(
        &mut self,
        raw: &Buffer,
        shift: i32,
    ) -> Result<Buffer, String> {
        self.ready()?;
        self.require_buffer(raw)?;
        if raw.kind != 6 {
            return self.abort("native RNE requires raw i64");
        }
        let id = self.alloc(1, raw.count)?;
        let status = unsafe { (self.api.quantize)(self.raw, raw.id, shift, id) };
        self.check(status)?;
        Ok(Buffer { id, kind: 1, count: raw.count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pointwise(
        &mut self,
        inputs: [Option<(&Buffer, usize)>; 2],
        count: usize,
        op: Pointwise,
    ) -> Result<Buffer, String> {
        self.ready()?;
        for (buffer, _) in inputs.iter().flatten() {
            self.require_buffer(buffer)?;
        }
        let id = self.alloc(6, count)?;
        let [x, y] = inputs.map(|input| input.map_or((0, 0), |(b, first)| (b.id, first as u64)));
        let status = unsafe { (self.api.pointwise)(self.raw, x.0, x.1, y.0, y.1, op, id) };
        self.check(status)?;
        Ok(Buffer { id, kind: 6, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn upload_table(&mut self, bytes: &[u8]) -> Result<Buffer, String> {
        let id = self.alloc(0, bytes.len())?;
        let status =
            unsafe { (self.api.upload)(self.raw, id, bytes.as_ptr().cast(), bytes.len() as u64) };
        self.check(status)?;
        Ok(Buffer { id, kind: 0, count: bytes.len(), owner: self.owner.clone() })
    }
    fn allocate_buffer(&mut self, kind: u32, count: usize) -> Result<Buffer, String> {
        Ok(Buffer { id: self.alloc(kind, count)?, kind, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn signed_capacity(
        &mut self,
        count: usize,
    ) -> Result<Buffer, String> {
        self.allocate_buffer(1, count)
    }
    pub(in crate::c71_matrix) fn append_signed(
        &mut self,
        input: &Buffer,
        first: usize,
        count: usize,
        output: &Buffer,
        output_first: usize,
    ) -> Result<(), String> {
        self.require_buffer(input)?;
        self.require_buffer(output)?;
        let status = unsafe {
            (self.api.signed_append)(
                self.raw,
                input.id,
                first as u64,
                count as u64,
                output.id,
                output_first as u64,
            )
        };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn download_bytes(
        &mut self,
        input: &Buffer,
        first: usize,
        output: &mut [u8],
    ) -> Result<(), String> {
        self.require_buffer(input)?;
        let status = unsafe {
            (self.api.original_read)(
                self.raw,
                input.id,
                0,
                first as u64,
                output.len() as u64,
                output.as_mut_ptr().cast(),
            )
        };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn download_words(
        &mut self,
        input: &Buffer,
        first: usize,
        output: &mut [i64],
    ) -> Result<(), String> {
        self.require_buffer(input)?;
        if output.is_empty() || output.len() > 262144 {
            return self.abort("original row staging size differs");
        }
        match input.kind {
            1 => {
                let mut words = vec![0i16; output.len()];
                let status = unsafe {
                    (self.api.original_read)(
                        self.raw,
                        input.id,
                        1,
                        first as u64,
                        words.len() as u64,
                        words.as_mut_ptr().cast(),
                    )
                };
                self.check(status)?;
                for (out, value) in output.iter_mut().zip(words) {
                    *out = i64::from(value);
                }
                Ok(())
            }
            6 => {
                let status = unsafe {
                    (self.api.original_read)(
                        self.raw,
                        input.id,
                        6,
                        first as u64,
                        output.len() as u64,
                        output.as_mut_ptr().cast(),
                    )
                };
                self.check(status)
            }
            _ => self.abort("original row staging kind differs"),
        }
    }
    pub(in crate::c71_matrix) fn rms(
        &mut self,
        input: &Buffer,
        first: usize,
        weight_offset: usize,
        shape: RmsShape,
    ) -> Result<(Option<Buffer>, Buffer, Buffer), String> {
        self.require_buffer(input)?;
        if !(1..=150).contains(&shape.rows)
            || !(1..=32).contains(&shape.heads)
            || !(1..=5376).contains(&shape.columns)
            || shape.weighted > 1
        {
            return self.abort("native RMS geometry differs");
        }
        let count = shape.rows as usize * shape.heads as usize * shape.columns as usize;
        let product =
            if shape.weighted != 0 { Some(self.allocate_buffer(6, count)?) } else { None };
        let statistic = self.allocate_buffer(6, shape.rows as usize * shape.heads as usize)?;
        let output = self.allocate_buffer(1, count)?;
        let status = unsafe {
            (self.api.rms)(
                self.raw,
                input.id,
                first as u64,
                weight_offset as u64,
                shape,
                product.as_ref().map_or(0, |buffer| buffer.id),
                statistic.id,
                output.id,
            )
        };
        self.check(status)?;
        Ok((product, statistic, output))
    }
    pub(in crate::c71_matrix) fn qk(
        &mut self,
        query: &Buffer,
        first: usize,
        keys: &Buffer,
        shape: AttentionShape,
    ) -> Result<Buffer, String> {
        self.require_buffer(query)?;
        self.require_buffer(keys)?;
        if !shape.valid() {
            return self.abort("native QK geometry differs");
        }
        let output = self.allocate_buffer(6, shape.rows as usize * (shape.old as usize + 150))?;
        let status =
            unsafe { (self.api.qk)(self.raw, query.id, first as u64, keys.id, shape, output.id) };
        self.check(status)?;
        Ok(output)
    }
    pub(in crate::c71_matrix) fn pv(
        &mut self,
        probabilities: &[(&Buffer, usize); 32],
        values: &Buffer,
        shape: AttentionShape,
    ) -> Result<Buffer, String> {
        self.require_buffer(values)?;
        for (buffer, _) in probabilities {
            self.require_buffer(buffer)?;
        }
        if !shape.valid() {
            return self.abort("native PV geometry differs");
        }
        let output = self.allocate_buffer(6, shape.rows as usize * 32 * shape.lanes as usize)?;
        let ids = probabilities.map(|(buffer, _)| buffer.id);
        let starts = probabilities.map(|(_, first)| first as u64);
        let status = unsafe {
            (self.api.pv)(self.raw, ids.as_ptr(), starts.as_ptr(), values.id, shape, output.id)
        };
        self.check(status)?;
        Ok(output)
    }
    pub(in crate::c71_matrix) fn softmax(
        &mut self,
        input: &Buffer,
        first: usize,
        table: &Buffer,
        offset: usize,
        histogram: &Buffer,
        shape: AttentionShape,
    ) -> Result<[Buffer; 5], String> {
        for buffer in [input, table, histogram] {
            self.require_buffer(buffer)?;
        }
        if !shape.valid() {
            return self.abort("native softmax geometry differs");
        }
        let rows = shape.rows as usize;
        let count = rows * (shape.old as usize + 150);
        let outputs = [
            self.allocate_buffer(1, rows)?,
            self.allocate_buffer(1, count)?,
            self.allocate_buffer(6, count)?,
            self.allocate_buffer(6, rows)?,
            self.allocate_buffer(1, count)?,
        ];
        let ids = outputs.each_ref().map(|buffer| buffer.id);
        let status = unsafe {
            (self.api.softmax)(
                self.raw,
                input.id,
                first as u64,
                table.id,
                offset as u64,
                histogram.id,
                shape,
                ids.as_ptr(),
            )
        };
        self.check(status)?;
        Ok(outputs)
    }
    pub(in crate::c71_matrix) fn histogram_padding(
        &mut self,
        histogram: &Buffer,
        count: usize,
    ) -> Result<(), String> {
        self.require_buffer(histogram)?;
        let status = unsafe { (self.api.histogram_padding)(self.raw, histogram.id, count as u64) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn histogram(&mut self) -> Result<Buffer, String> {
        let id = self.alloc(8, 65535)?;
        let status = unsafe { (self.api.histogram_begin)(self.raw, id) };
        self.check(status)?;
        Ok(Buffer { id, kind: 8, count: 65535, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn seal_histogram(
        &mut self,
        mut buffer: Buffer,
    ) -> Result<Buffer, String> {
        self.require_buffer(&buffer)?;
        let status = unsafe { (self.api.histogram_seal)(self.raw, buffer.id) };
        self.check(status)?;
        buffer.kind = 6;
        Ok(buffer)
    }
    pub(in crate::c71_matrix) fn lookup(
        &mut self,
        input: &Buffer,
        first: usize,
        count: usize,
        table: &Buffer,
        offset: usize,
        histogram: &Buffer,
    ) -> Result<Buffer, String> {
        self.ready()?;
        for buffer in [input, table, histogram] {
            self.require_buffer(buffer)?;
        }
        let id = self.alloc(1, count)?;
        let status = unsafe {
            (self.api.lookup)(
                self.raw,
                input.id,
                first as u64,
                table.id,
                offset as u64,
                histogram.id,
                id,
            )
        };
        self.check(status)?;
        Ok(Buffer { id, kind: 1, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn rope(
        &mut self,
        input: &Buffer,
        first: usize,
        table: &Buffer,
        offset: usize,
        shape: RopeShape,
    ) -> Result<Buffer, String> {
        self.ready()?;
        self.require_buffer(input)?;
        self.require_buffer(table)?;
        if !(1..=150).contains(&shape.rows)
            || !(1..=32).contains(&shape.heads)
            || !(2..=512).contains(&shape.width)
            || shape.width % 2 != 0
            || shape.pairs == 0
            || shape.pairs > shape.width / 2
        {
            return self.abort("native RoPE geometry differs");
        }
        let count = shape.rows as usize * shape.heads as usize * shape.width as usize;
        let id = self.alloc(6, count)?;
        let status = unsafe {
            (self.api.rope)(self.raw, input.id, first as u64, table.id, offset as u64, shape, id)
        };
        self.check(status)?;
        Ok(Buffer { id, kind: 6, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn argmax(
        &mut self,
        input: &Buffer,
        first: usize,
        rows: usize,
        columns: usize,
    ) -> Result<(Buffer, Vec<u32>), String> {
        self.require_buffer(input)?;
        if !(1..=150).contains(&rows) || !(1..=262144).contains(&columns) {
            return self.abort("native argmax geometry differs");
        }
        let count = rows * columns;
        let id = self.alloc(1, count)?;
        let mut tokens = vec![0; rows];
        let status = unsafe {
            (self.api.argmax)(
                self.raw,
                input.id,
                first as u64,
                rows as u32,
                columns as u32,
                id,
                tokens.as_mut_ptr(),
            )
        };
        self.check(status)?;
        Ok((Buffer { id, kind: 1, count, owner: self.owner.clone() }, tokens))
    }
    pub(in crate::c71_matrix) fn release_buffer(&mut self, buffer: Buffer) -> Result<(), String> {
        self.require_buffer(&buffer)?;
        self.release(buffer.id)
    }
    pub(in crate::c71_matrix) fn share_buffer(
        &mut self,
        buffer: &Arc<Buffer>,
    ) -> Result<Arc<Buffer>, String> {
        self.require_buffer(buffer)?;
        Ok(buffer.clone())
    }
    pub(in crate::c71_matrix) fn release_shared_buffer(
        &mut self,
        buffer: Arc<Buffer>,
    ) -> Result<(), String> {
        self.require_buffer(&buffer)?;
        match Arc::try_unwrap(buffer) {
            Ok(buffer) => self.release_buffer(buffer),
            Err(_) => Ok(()),
        }
    }
    pub(in crate::c71_matrix) fn byte_window(&mut self, count: usize) -> Result<Buffer, String> {
        let id = self.alloc(7, count)?;
        let status = unsafe { (self.api.byte_begin)(self.raw, id) };
        self.check(status)?;
        Ok(Buffer { id, kind: 7, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn scatter_bytes(
        &mut self,
        input: &Buffer,
        tile: &ByteTile,
        output: &Buffer,
    ) -> Result<(), String> {
        self.require_buffer(input)?;
        self.require_buffer(output)?;
        let status = unsafe { (self.api.byte_scatter)(self.raw, input.id, tile, output.id) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn seal_bytes(
        &mut self,
        mut output: Buffer,
    ) -> Result<Buffer, String> {
        self.require_buffer(&output)?;
        let status = unsafe { (self.api.byte_seal)(self.raw, output.id) };
        self.check(status)?;
        output.kind = 0;
        Ok(output)
    }
    #[cfg(test)]
    pub(in crate::c71_matrix) fn root_check(
        &mut self,
        input: &Buffer,
        alpha: Fp3,
    ) -> Result<[Fp3; 2], String> {
        self.require_buffer(input)?;
        if input.kind > 1 || !input.count.is_power_of_two() || !(2..=2048).contains(&input.count) {
            return self.abort("test root requires a small power-of-two original block");
        }
        let id = self.alloc(2, 1)?;
        let status = unsafe {
            (self.api.roots)(self.raw, input.id, input.count.ilog2(), alpha.into(), id, 0)
        };
        self.check(status)?;
        let value = self.read::<2>(id)?;
        self.release(id)?;
        Ok(value)
    }
    fn check(&mut self, status: i32) -> Result<(), String> {
        if status == 0 && !self.stopped {
            return Ok(());
        }
        self.stopped = true;
        // SAFETY: live context (or null, allowed by error ABI); string is copied.
        let error = unsafe { (self.api.error)(self.raw) };
        let message = if error.is_null() {
            "unknown error".into()
        } else {
            unsafe { CStr::from_ptr(error) }.to_string_lossy()
        };
        Err(format!("native range stopped: {message}"))
    }
    fn alloc(&mut self, kind: u32, count: usize) -> Result<u64, String> {
        self.ready()?;
        let mut id = 0;
        let status = unsafe { (self.api.alloc)(self.raw, kind, count as u64, &mut id) };
        self.check(status)?;
        Ok(id)
    }
    fn release(&mut self, id: u64) -> Result<(), String> {
        self.ready()?;
        let status = unsafe { (self.api.release)(self.raw, id) };
        self.check(status)
    }
    fn read<const N: usize>(&mut self, id: u64) -> Result<[Fp3; N], String> {
        self.ready()?;
        assert!(N == 2 || N == 4);
        let mut raw = [Field::default(); N];
        let status =
            unsafe { (self.api.read)(self.raw, id, raw.as_mut_ptr().cast(), (N * 3) as u32) };
        self.check(status)?;
        let mut out = [Fp3::ZERO; N];
        for (out, value) in out.iter_mut().zip(raw) {
            *out = value.decode()?;
        }
        Ok(out)
    }
    pub(in crate::c71_matrix) fn close(&mut self) -> Result<Stats, String> {
        let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
        if raw.is_null() {
            return Ok(Stats::default());
        }
        let mut stats = Stats::default();
        let status = unsafe { (self.api.close)(raw, &mut stats) };
        self.weights = None;
        if status != 0 || stats.cleanup_failed != 0 {
            return Err(format!(
                "native cleanup failed, arena bytes: {}, W bytes: {}",
                stats.arena_bytes, stats.weights_bytes
            ));
        }
        Ok(stats)
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("{error}");
        }
    }
}

enum Owner<'a> {
    Owned(Runtime),
    Shared { runtime: MutexGuard<'a, Runtime>, capacity: u64, finished: bool },
}

impl Deref for Owner<'_> {
    type Target = Runtime;
    fn deref(&self) -> &Runtime {
        match self {
            Self::Owned(runtime) => runtime,
            Self::Shared { runtime, .. } => runtime,
        }
    }
}

impl DerefMut for Owner<'_> {
    fn deref_mut(&mut self) -> &mut Runtime {
        match self {
            Self::Owned(runtime) => runtime,
            Self::Shared { runtime, .. } => runtime,
        }
    }
}

impl<'a> Owner<'a> {
    fn new(config: &'a Config) -> Result<Self, String> {
        match &config.resident {
            None => Ok(Self::Owned(Runtime::new(config)?)),
            Some(resident) => {
                let mut runtime = resident.runtime.lock().map_err(|_| "native owner poisoned")?;
                runtime.require_configuration(config)?;
                let capacity = runtime.stats()?.live_capacity_bytes;
                Ok(Self::Shared { runtime, capacity, finished: false })
            }
        }
    }

    fn finish(&mut self) -> Result<Stats, String> {
        match self {
            Self::Owned(runtime) => runtime.close(),
            Self::Shared { runtime, capacity, finished } => {
                let stats = runtime.stats()?;
                if stats.stopped != 0 || stats.live_capacity_bytes != *capacity {
                    return runtime.abort("shared range changed retained source capacity");
                }
                *finished = true;
                Ok(stats)
            }
        }
    }
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if let Self::Shared { runtime, finished: false, .. } = self {
            let _ = runtime.abort::<()>("shared range did not finish");
        }
    }
}

pub(super) struct Evaluator<'a, T> {
    source: &'a Source<T>,
    runtime: Owner<'a>,
    resident_read: Option<ResidentReader>,
    bits: usize,
    retained: usize,
    window: usize,
    buckets: u32,
    alpha: Fp3,
    canopy: Vec<u64>,
    layer: Option<usize>,
    children: Option<u64>,
    gram: Option<u64>,
    gram_end: usize,
    folded: usize,
    work: Work,
}
impl<'a, T: Word> Evaluator<'a, T> {
    pub(super) fn new(
        source: &'a Source<T>,
        bits: usize,
        alpha: Fp3,
        config: &'a Config,
    ) -> Result<Self, String> {
        if !(1..=35).contains(&bits) {
            return Err("native range dimension differs".into());
        }
        let (retained, cap, _) = source.geometry(bits);
        let window = config.window_words;
        if !window.is_power_of_two()
            || window < 1 << (bits - retained)
            || window > cap.min(1 << bits)
            || !(1..=256).contains(&config.buckets)
            || (bits >= 34 && config.reserve_bytes < 256 * 1024 * 1024)
            || (T::KIND == 0) != (source.alphabet == Alphabet::Byte)
        {
            return Err("native range configuration differs".into());
        }
        let mut e = Self {
            source,
            runtime: Owner::new(config)?,
            resident_read: config.resident.as_ref().map(|resident| resident.read.clone()),
            bits,
            retained,
            window,
            buckets: config.buckets,
            alpha,
            canopy: Vec::new(),
            layer: None,
            children: None,
            gram: None,
            gram_end: 0,
            folded: 0,
            work: Work { native_shared: config.resident.is_some(), ..Work::default() },
        };
        let mut n = 1 << retained;
        let level = e.runtime.alloc(2, n)?;
        e.scan(0, 0, |runtime, input, first| {
            let status = unsafe {
                (runtime.api.roots)(
                    runtime.raw,
                    input,
                    (bits - retained) as u32,
                    alpha.into(),
                    level,
                    (first >> (bits - retained)) as u64,
                )
            };
            runtime.check(status)
        })?;
        e.work.fraction_merges += (1u64 << bits) - n as u64;
        e.canopy.push(level);
        while n > 1 {
            n /= 2;
            let upper = e.runtime.alloc(2, n)?;
            let status =
                unsafe { (e.runtime.api.canopy)(e.runtime.raw, *e.canopy.last().unwrap(), upper) };
            e.runtime.check(status)?;
            e.canopy.push(upper);
            e.work.fraction_merges += n as u64;
        }
        Ok(e)
    }
    // Host originals stay bounded; upload fences before the reader reuses them.
    // SAFETY of upload: Word is sealed to u8/i16, with native POD representation.
    fn scan(
        &mut self,
        suffix: usize,
        bottom: usize,
        mut emit: impl FnMut(&mut Runtime, u64, usize) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(read) = self.resident_read.clone() {
            self.work.named_evaluator_heap_peak_bytes = self
                .work
                .named_evaluator_heap_peak_bytes
                .max(self.canopy.capacity() * size_of::<u64>() + size_of::<Self>());
            self.work.source_passes += 1;
            for first in (0..1usize << self.bits).step_by(self.window) {
                let input = read(&mut self.runtime, suffix, bottom, first, self.window)?;
                self.runtime.require_buffer(&input)?;
                if input.kind != T::KIND || input.count != self.window {
                    return self.runtime.abort("resident range window kind or size differs");
                }
                self.work.byte_windows += 1;
                self.work.requested_bytes += (self.window * size_of::<T>()) as u64;
                emit(&mut self.runtime, input.id, first)?;
                self.runtime.release_buffer(input)?;
            }
            return Ok(());
        }
        let mut words = allocate(self.window, T::default())?;
        let id = self.runtime.alloc(T::KIND, self.window)?;
        self.work.named_evaluator_heap_peak_bytes = self.work.named_evaluator_heap_peak_bytes.max(
            words.capacity() * size_of::<T>()
                + self.canopy.capacity() * size_of::<u64>()
                + size_of::<Self>(),
        );
        self.work.source_passes += 1;
        for first in (0..1usize << self.bits).step_by(self.window) {
            (self.source.read)(suffix, bottom, first, &mut words)?;
            self.work.byte_windows += 1;
            self.work.requested_bytes += size_of_val(&words[..]) as u64;
            let status = unsafe {
                (self.runtime.api.upload)(
                    self.runtime.raw,
                    id,
                    words.as_ptr().cast(),
                    size_of_val(&words[..]) as u64,
                )
            };
            self.runtime.check(status)?;
            emit(&mut self.runtime, id, first)?;
        }
        self.runtime.release(id)
    }
    pub(super) fn root(&mut self) -> Result<[Fp3; 2], String> {
        let id = self.canopy.pop().ok_or("native range root missing")?;
        let out = self.runtime.read(id)?;
        self.runtime.release(id)?;
        Ok(out)
    }
    fn start_layer(&mut self, layer: usize) -> Result<(), String> {
        if self.layer == Some(layer) {
            return Ok(());
        }
        if self.layer.map_or(layer != 0, |l| layer != l + 1) || layer >= self.bits {
            return Err("native range layer order differs".into());
        }
        if let Some(id) = self.children.take() {
            self.runtime.release(id)?;
        }
        if let Some(id) = self.gram.take() {
            self.runtime.release(id)?;
        }
        self.folded = 0;
        self.gram_end = 0;
        self.layer = Some(layer);
        if layer < self.retained {
            let id = self.canopy.pop().ok_or("native range canopy exhausted")?;
            let status = unsafe { (self.runtime.api.children)(self.runtime.raw, id) };
            self.runtime.check(status)?;
            self.children = Some(id);
        }
        Ok(())
    }
    fn groups(
        &mut self,
        layer: usize,
        prefix: &[Fp3],
        width: usize,
        point: &[Fp3],
        lambda: Fp3,
        output: u64,
    ) -> Result<(), String> {
        let bottom = self.bits - layer;
        let suffix = layer - prefix.len() - width;
        let mut g = Group {
            alpha: self.alpha.into(),
            lambda: lambda.into(),
            prefix: [Field::default(); 35],
            tail_point: [Field::default(); 35],
            first_tail: 0,
            bottom: bottom as u32,
            prefix_bits: prefix.len() as u32,
            width: width as u32,
            tail_bits: suffix as u32,
            buckets: self.buckets,
        };
        for (out, &r) in g.prefix.iter_mut().zip(prefix) {
            *out = r.into();
        }
        if width > 0 {
            for (out, &r) in g.tail_point.iter_mut().zip(&point[prefix.len() + width..]) {
                *out = r.into();
            }
        }
        let group_bits = bottom + prefix.len() + width;
        if self.window < 1 << group_bits {
            return Err("native range window splits group".into());
        }
        self.scan(suffix, bottom, |runtime, input, first| {
            g.first_tail = (first >> group_bits) as u64;
            let status = unsafe { (runtime.api.groups)(runtime.raw, input, &g, output) };
            runtime.check(status)
        })?;
        self.work.fraction_merges += (1u64 << self.bits) - (1u64 << (layer + 1));
        Ok(())
    }
    fn retain(&mut self, layer: usize, prefix: &[Fp3]) -> Result<(), String> {
        if let Some(id) = self.gram.take() {
            self.runtime.release(id)?;
        }
        let id = self.runtime.alloc(3, 1 << (layer - prefix.len()))?;
        self.groups(layer, prefix, 0, &[], Fp3::ZERO, id)?;
        self.children = Some(id);
        self.folded = prefix.len();
        self.work.retained_levels += 1;
        Ok(())
    }
    fn fold_children(&mut self, prefix: &[Fp3]) -> Result<(), String> {
        for &r in &prefix[self.folded..] {
            let status = unsafe {
                (self.runtime.api.child_fold)(self.runtime.raw, self.children.unwrap(), r.into())
            };
            self.runtime.check(status)?;
        }
        self.folded = prefix.len();
        Ok(())
    }
    pub(super) fn coefficients(
        &mut self,
        layer: usize,
        point: &[Fp3],
        lambda: Fp3,
        prefix: &[Fp3],
    ) -> Result<[Fp3; 4], String> {
        if point.len() != layer || prefix.len() >= layer {
            return Err("native range round shape differs".into());
        }
        self.start_layer(layer)?;
        let gap = layer.saturating_sub(self.retained);
        let (id, end, operation) = if prefix.len() >= gap {
            if self.children.is_none() {
                self.retain(layer, prefix)?;
            }
            self.fold_children(prefix)?;
            (self.children.unwrap(), layer, self.runtime.api.coefficients)
        } else {
            if self.gram.is_none() || prefix.len() == self.gram_end {
                if let Some(id) = self.gram.take() {
                    self.runtime.release(id)?;
                }
                let mut start = 0;
                let width = *self.source.geometry(self.bits).2[gap]
                    .iter()
                    .find(|&&w| {
                        let here = start == prefix.len();
                        start += w;
                        here
                    })
                    .ok_or("native range Gram order differs")?;
                let cells = 1 << (2 * width);
                let buckets = self.runtime.alloc(4, cells * self.buckets as usize)?;
                let status = unsafe { (self.runtime.api.zero)(self.runtime.raw, buckets) };
                self.runtime.check(status)?;
                self.groups(layer, prefix, width, point, lambda, buckets)?;
                let id = self.runtime.alloc(4, cells)?;
                let status = unsafe {
                    (self.runtime.api.h_sum)(self.runtime.raw, buckets, id, self.buckets)
                };
                self.runtime.check(status)?;
                self.runtime.release(buckets)?;
                self.gram = Some(id);
                self.gram_end = prefix.len() + width;
                self.folded = prefix.len();
                self.work.gram_windows += 1;
            }
            for &r in &prefix[self.folded..] {
                let old = self.gram.unwrap();
                let next = self.runtime.alloc(4, 1 << (2 * (self.gram_end - self.folded - 1)))?;
                let status =
                    unsafe { (self.runtime.api.h_fold)(self.runtime.raw, old, next, r.into()) };
                self.runtime.check(status)?;
                self.runtime.release(old)?;
                self.gram = Some(next);
                self.folded += 1;
            }
            (self.gram.unwrap(), self.gram_end, self.runtime.api.h_coefficients)
        };
        let equality = point
            .iter()
            .zip(prefix)
            .fold(Fp3::ONE, |e, (&x, &r)| e * ((Fp3::ONE - x) * (Fp3::ONE - r) + x * r));
        let mut round = Round {
            lambda: lambda.into(),
            prefix_equality: equality.into(),
            point: [Field::default(); 35],
            bits: (end - prefix.len()) as u32,
        };
        for (out, &r) in round.point.iter_mut().zip(&point[prefix.len()..end]) {
            *out = r.into();
        }
        let mut raw = [Field::default(); 4];
        // Native operation fences its fixed-size output BEFORE the GKR caller
        // can authenticate it or derive the next Fiat-Shamir coin.
        let status = unsafe { operation(self.runtime.raw, id, &round, raw.as_mut_ptr()) };
        self.runtime.check(status)?;
        let mut out = [Fp3::ZERO; 4];
        for (out, r) in out.iter_mut().zip(raw) {
            *out = r.decode()?;
        }
        Ok(out)
    }
    pub(super) fn terminal(&mut self, layer: usize, prefix: &[Fp3]) -> Result<[Fp3; 4], String> {
        if prefix.len() != layer {
            return Err("native range terminal shape differs".into());
        }
        self.start_layer(layer)?;
        if self.children.is_none() {
            self.retain(layer, prefix)?;
        }
        self.fold_children(prefix)?;
        self.runtime.read(self.children.unwrap())
    }
    pub(super) fn finish(mut self) -> Result<Work, String> {
        for id in self.canopy.drain(..).chain(self.children.take()).chain(self.gram.take()) {
            self.runtime.release(id)?;
        }
        self.work.native = Some(self.runtime.finish()?);
        Ok(self.work)
    }
}

#[cfg(test)]
pub(in crate::c71_matrix) mod tests {
    use super::*;
    #[test]
    fn c71_b12_windowed_native_abi4_rejects_legacy_stats() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let f = fixture(512);
        let path = f.directory.join("abi2-only.so");
        let mut compiler = Command::new("g++")
            .args(["-shared", "-fPIC", "-x", "c++", "-", "-o"])
            .arg(&path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(b"extern \"C\" unsigned c71_range_runtime_abi() { return 2; }\n")
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        let mut config = f.config.clone();
        config.library = path;
        assert_eq!(Runtime::new(&config).err().unwrap(), "native range ABI differs");
        std::fs::remove_file(&config.library).unwrap();
        let mut runtime = Runtime::new(&f.config).unwrap();
        assert_eq!(runtime.stats().unwrap().d2d_bytes, 0);
        runtime.close().unwrap();
    }
    #[test]
    fn c71_b12_windowed_native_dense_chain() {
        #[repr(C)]
        struct Shape {
            m: u32,
            n: u32,
            k: u32,
        }
        let fixture = fixture(512);
        for shift in [i32::MIN, -15, -14, -1, 0, 1, 2, 3, 15, 31, 47, 48, i32::MAX] {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            // Test the real C owner via the same loader as the range prover.
            // Only the device driver/launch algebra is simulated, not the ABI.
            unsafe {
                let library = &runtime.api._library;
                let begin: unsafe extern "C" fn(Raw, u64) -> i32 =
                    library.symbol(b"c71_dense_weights_begin\0").unwrap();
                let upload: unsafe extern "C" fn(Raw, u64, *const i16, u64) -> i32 =
                    library.symbol(b"c71_dense_weights_upload\0").unwrap();
                let seal: unsafe extern "C" fn(Raw) -> i32 =
                    library.symbol(b"c71_dense_weights_seal\0").unwrap();
                let product: unsafe extern "C" fn(Raw, u64, u64, Shape, u64) -> i32 =
                    library.symbol(b"c71_dense_product\0").unwrap();
                let quantize: unsafe extern "C" fn(Raw, u64, i32, u64) -> i32 =
                    library.symbol(b"c71_dense_quantize\0").unwrap();
                let weights: [i16; 8] = [1, 2, 3, 4, 4, 3, 2, 1];
                assert_eq!(begin(runtime.raw, 8), 0);
                assert_eq!(upload(runtime.raw, 0, weights.as_ptr(), 8), 0);
                assert_eq!(seal(runtime.raw), 0);
                let x = runtime.alloc(1, 8).unwrap();
                let input: [i16; 8] = [1, 2, 3, 4, -1, -2, -3, -4];
                assert_eq!((runtime.api.upload)(runtime.raw, x, input.as_ptr().cast(), 16), 0);
                let raw = runtime.alloc(6, 4).unwrap();
                let y = runtime.alloc(1, 4).unwrap();
                assert_eq!(product(runtime.raw, x, 0, Shape { m: 2, n: 2, k: 4 }, raw), 0);
                let expected: Result<Vec<_>, _> = [30, 20, -30, -20]
                    .into_iter()
                    .map(|raw| crate::c71_matrix::rne::integer(raw, shift))
                    .collect();
                let status = quantize(runtime.raw, raw, shift, y);
                if let Ok(expected) = expected {
                    runtime.check(status).unwrap();
                    let root = runtime.alloc(2, 1).unwrap();
                    let alpha = Fp3::new(Fp::new(19), Fp::new(2), Fp::new(3));
                    assert_eq!((runtime.api.roots)(runtime.raw, y, 2, alpha.into(), root, 0), 0);
                    let [p, q] = runtime.read::<2>(root).unwrap();
                    let denominators: Vec<_> = expected
                        .iter()
                        .map(|&v| alpha - crate::c71_matrix::signed(i64::from(v)))
                        .collect();
                    let product = denominators.iter().fold(Fp3::ONE, |a, &b| a * b);
                    let numerator = (0..4)
                        .map(|i| {
                            denominators
                                .iter()
                                .enumerate()
                                .filter(|(j, _)| *j != i)
                                .map(|(_, v)| *v)
                                .fold(Fp3::ONE, |a, b| a * b)
                        })
                        .fold(Fp3::ZERO, |a, b| a + b);
                    assert_eq!([p, q], [numerator, product]);
                } else {
                    assert!(runtime.check(status).is_err());
                    assert!(runtime.alloc(1, 1).is_err());
                }
            }
            let stats = runtime.close().unwrap();
            assert_eq!(stats.weights_bytes, 0);
            assert_eq!(stats.arena_bytes, 0);
            assert_eq!(stats.weights_loaded_bytes, 16);
            assert_eq!(stats.weights_sealed, 1);
            assert_eq!(stats.peak_reserved_bytes, stats.peak_capacity_bytes + 16);
            assert_eq!(stats.h2d_bytes, 32);
        }
    }
    pub(in crate::c71_matrix) struct Fixture {
        pub config: Config,
        directory: PathBuf,
    }
    #[test]
    fn c71_b12_windowed_native_nonlinear_rejections_are_terminal() {
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 2 << 20;
        let injection = Injection::new(&fixture.config);
        for case in 0..12 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let input = runtime.upload_signed(&[0, 1, 2, 3]).unwrap();
            let table_values = vec![if case == 2 { i16::MIN } else { 0 }; 65535];
            let table = runtime
                .upload_table(
                    &table_values.iter().flat_map(|value| value.to_le_bytes()).collect::<Vec<_>>(),
                )
                .unwrap();
            let mut histogram = runtime.histogram().unwrap();
            if case == 3 {
                histogram = runtime.seal_histogram(histogram).unwrap();
            }
            let result = match case {
                0..=3 => runtime
                    .lookup(
                        &input,
                        if case == 0 { usize::MAX } else { 0 },
                        4,
                        &table,
                        usize::from(case == 1),
                        &histogram,
                    )
                    .map(|_| ()),
                4 | 5 => {
                    let coefficients = runtime
                        .upload_table(
                            &[i32::MAX, 0]
                                .into_iter()
                                .flat_map(|value| value.to_le_bytes())
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();
                    runtime
                        .rope(
                            &input,
                            0,
                            &coefficients,
                            0,
                            RopeShape {
                                rows: 1,
                                heads: 1,
                                width: if case == 5 { u32::MAX } else { 4 },
                                pairs: 1,
                            },
                        )
                        .map(|_| ())
                }
                6 => {
                    let (slack, _) = runtime.argmax(&input, 0, 1, 4).unwrap();
                    runtime.argmax(&slack, 0, 1, 4).map(|_| ())
                }
                _ => {
                    injection.set([1, 2, 4, 7, 8][case - 7]);
                    runtime.argmax(&input, 0, 1, 4).map(|_| ())
                }
            };
            injection.set(0);
            assert!(result.is_err(), "nonlinear rejection {case}");
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            assert!(runtime.upload_signed(&[0]).is_err());
            runtime.close().unwrap();
        }
        eprintln!("C71_NONLINEAR_REJECTIONS count=12 terminal=true gpu=false");
    }
    #[test]
    fn c71_b12_windowed_native_distinct_libraries_reject_colliding_handles() {
        let first = fixture(512);
        let second = fixture(512);
        for release in [false, true] {
            let mut owner = Runtime::new(&first.config).unwrap();
            let mut foreign = Runtime::new(&second.config).unwrap();
            let original = owner.upload_signed(&[1, 2]).unwrap();
            let other = foreign.upload_signed(&[3, 4]).unwrap();
            assert_eq!(original.id, other.id);
            let before = foreign.stats().unwrap();
            if release {
                assert!(foreign.release_buffer(original).is_err());
            } else {
                assert!(foreign.argmax(&original, 0, 1, 2).is_err());
                owner.release_buffer(original).unwrap();
            }
            let after = foreign.stats().unwrap();
            assert_eq!(after.stopped, 1);
            assert_eq!(
                (after.allocations, after.releases, after.launches),
                (before.allocations, before.releases, before.launches)
            );
            owner.close().unwrap();
            foreign.close().unwrap();
        }
    }
    #[test]
    fn c71_b12_windowed_native_attention_rejections_are_terminal() {
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 2 << 20;
        let injection = Injection::new(&fixture.config);
        for case in 0..10 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let input = runtime.upload_signed(&[1; 32]).unwrap();
            let tail = runtime.signed_capacity(150).unwrap();
            if case != 2 {
                runtime.append_signed(&input, 0, 2, &tail, 0).unwrap();
            }
            let shape = AttentionShape { rows: 1, first: 1, head: 31, old: 0, groups: 1, lanes: 1 };
            let result = match case {
                0 | 1 => runtime
                    .rms(
                        &input,
                        0,
                        0,
                        RmsShape {
                            rows: 1,
                            heads: 1,
                            columns: 32,
                            weighted: 0,
                            coefficients: if case == 0 {
                                [u64::MAX; 6]
                            } else {
                                [1_000_000_000_000, 0, 1, 0, 1, 0]
                            },
                        },
                    )
                    .map(|_| ()),
                2 => runtime.qk(&input, 0, &tail, shape).map(|_| ()),
                3 => {
                    let (invalid, _) = runtime.argmax(&input, 0, 1, 32).unwrap();
                    runtime.qk(&invalid, 0, &tail, shape).map(|_| ())
                }
                4..=5 | 8..=9 => {
                    let mut scores = vec![0i16; 150];
                    if case == 5 {
                        scores[3] = 1;
                    }
                    let scores = runtime.upload_signed(&scores).unwrap();
                    let table = vec![if case == 4 { 0i32 } else { 1 << 30 }; 65535];
                    let table = runtime
                        .upload_table(
                            &table.iter().flat_map(|value| value.to_le_bytes()).collect::<Vec<_>>(),
                        )
                        .unwrap();
                    let histogram = runtime.histogram().unwrap();
                    if case >= 8 {
                        injection.set(if case == 8 { 1 } else { 2 });
                    }
                    runtime.softmax(&scores, 0, &table, 0, &histogram, shape).map(|_| ())
                }
                6 => {
                    let negative = runtime.upload_signed(&[-1; 150]).unwrap();
                    runtime.pv(&[(&negative, 0); 32], &tail, shape).map(|_| ())
                }
                7 => {
                    let histogram = runtime.histogram().unwrap();
                    runtime.histogram_padding(&histogram, 100).unwrap();
                    runtime.histogram_padding(&histogram, 100)
                }
                _ => unreachable!(),
            };
            injection.set(0);
            assert!(result.is_err(), "attention rejection {case}");
            assert_eq!(runtime.stats().unwrap().stopped, 1);
            runtime.close().unwrap();
        }
    }
    #[test]
    fn c71_b12_windowed_native_descriptor_capacity_is_bounded() {
        let fixture = fixture(512);
        let mut runtime = Runtime::new(&fixture.config).unwrap();
        let buffers = (0..512).map(|_| runtime.alloc(0, 1).unwrap()).collect::<Vec<_>>();
        let stats = runtime.stats().unwrap();
        assert_eq!((stats.logical_bytes, stats.live_capacity_bytes), (512, 512 * 256));
        assert!(stats.host_owner_bytes >= 512 * 64);
        for buffer in buffers {
            runtime.release(buffer).unwrap();
        }
        for _ in 0..512 {
            runtime.alloc(0, 1).unwrap();
        }
        assert!(runtime.alloc(0, 1).is_err());
        assert_eq!(runtime.stats().unwrap().stopped, 1);
        runtime.close().unwrap();
    }
    #[test]
    fn c71_b12_windowed_native_original_staging_is_bounded_and_fenced() {
        let fixture = fixture(512);
        let injection = Injection::new(&fixture.config);
        for fault in 0..5 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let input = runtime.upload_signed(&[1, -2, 3, -4]).unwrap();
            let tail = runtime.signed_capacity(12).unwrap();
            runtime.append_signed(&input, 0, 4, &tail, 0).unwrap();
            let mut words = [0i64; 4];
            if fault == 0 {
                let before = runtime.stats().unwrap();
                runtime.download_words(&tail, 0, &mut words).unwrap();
                assert_eq!(words, [1, -2, 3, -4]);
                assert_eq!(runtime.stats().unwrap().d2h_bytes - before.d2h_bytes, 8);
                let raw = runtime
                    .pointwise(
                        [Some((&input, 0)), None],
                        4,
                        Pointwise { a: 1 << 30, b: 0, multiply: 0 },
                    )
                    .unwrap();
                runtime.download_words(&raw, 0, &mut words).unwrap();
                assert_eq!(words, [1 << 30, -2 << 30, 3 << 30, -4 << 30]);
            } else {
                if fault >= 3 {
                    injection.set(if fault == 3 { 2 } else { 7 });
                }
                let result = if fault == 1 {
                    runtime.download_words(&tail, 1, &mut words)
                } else if fault == 2 {
                    runtime.download_bytes(&tail, 0, &mut [0; 8])
                } else {
                    runtime.download_words(&tail, 0, &mut words)
                };
                injection.set(0);
                assert!(result.is_err());
                assert_eq!(runtime.stats().unwrap().stopped, 1);
            }
            runtime.close().unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                std::fs::remove_file(&self.config.library).unwrap();
                std::fs::remove_dir(&self.directory).unwrap();
            }
        }
    }
    pub(in crate::c71_matrix) fn fixture(window_words: usize) -> Fixture {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory =
            std::env::temp_dir().join(format!("c71-range-ffi-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let library = directory.join("range-host-fixture.so");
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let result = std::process::Command::new("g++")
            .current_dir(root)
            .args([
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                "-DC71_RANGE_FFI_TEST",
                "-I",
                "tests/cuda_stub",
                "-I",
                "cuda",
                "cuda/c71_range_runtime.cpp",
                "tests/c71_range_runtime_host.cpp",
                "-o",
            ])
            .arg(&library)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        Fixture {
            config: Config {
                library,
                device: 0,
                arena_bytes: 262144,
                reserve_bytes: 256,
                window_words,
                buckets: 3,
                resident: None,
            },
            directory,
        }
    }
    pub(in crate::c71_matrix) struct Injection {
        api: Library,
        call: unsafe extern "C" fn(u32),
    }
    impl Injection {
        pub(in crate::c71_matrix) fn new(config: &Config) -> Self {
            let api = Library::open(&config.library).unwrap();
            let call = unsafe { api.symbol(b"c71_range_test_failure\0") }.unwrap();
            Self { api, call }
        }
        pub(in crate::c71_matrix) fn set(&self, kind: u32) {
            let _ = &self.api;
            unsafe {
                (self.call)(kind);
            }
        }
        pub(in crate::c71_matrix) fn expect_bytes(&self, bytes: &[u8]) {
            // Fake driver observes exact byte ORDER when roots consumes it.
            // Production exports no array download or this assertion hook.
            let call: unsafe extern "C" fn(*const u8, u64) =
                unsafe { self.api.symbol(b"c71_range_test_expect_bytes\0") }.unwrap();
            unsafe {
                call(bytes.as_ptr(), bytes.len() as u64);
            }
        }
        pub(in crate::c71_matrix) fn expect_raw(&self, values: &[i64]) {
            let call: unsafe extern "C" fn(*const i64, u64) =
                unsafe { self.api.symbol(b"c71_range_test_expect_raw\0") }.unwrap();
            unsafe {
                call(values.as_ptr(), values.len() as u64);
            }
        }
    }
}

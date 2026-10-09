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
pub(in crate::c71_matrix) struct Field {
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
#[derive(Clone, Copy, Default)]
pub(in crate::c71_matrix) struct LinearShape {
    pub live: u64,
    pub dimension: u32,
    pub remaining: u32,
    pub chunks: u32,
    pub groups: u32,
    pub intervals: u32,
    pub points: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::c71_matrix) struct LinearChunk {
    pub shift: u32,
    pub bits: u32,
    pub first: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::c71_matrix) struct LinearGroup {
    pub bits: u32,
    pub first: u32,
    pub count: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::c71_matrix) struct LinearInterval {
    pub index: u64,
    pub first: u32,
    pub bits: u32,
    pub lower: Field,
    pub upper: Field,
}
/// The sole canonical upload copy of the borrowed public residual points.
/// begin fences its copies before this packet may be dropped.
pub(in crate::c71_matrix) struct LinearPacket {
    pub shape: LinearShape,
    pub chunks: Vec<LinearChunk>,
    pub tables: Vec<Field>,
    pub groups: Vec<LinearGroup>,
    pub intervals: Vec<LinearInterval>,
    pub points: Vec<Field>,
}
impl LinearPacket {
    pub(in crate::c71_matrix) fn host_capacity_bytes(&self) -> usize {
        size_of::<Self>() + self.chunks.capacity() * size_of::<LinearChunk>()
            + self.tables.capacity() * size_of::<Field>()
            + self.groups.capacity() * size_of::<LinearGroup>()
            + self.intervals.capacity() * size_of::<LinearInterval>()
            + self.points.capacity() * size_of::<Field>()
    }
}
const _: () = assert!(size_of::<Field>() == 24 && size_of::<LinearShape>() == 32
    && size_of::<LinearChunk>() == 16 && size_of::<LinearGroup>() == 16
    && size_of::<LinearInterval>() == 64 && size_of::<[Field; 5]>() == 120);
// PCS v^3=v+1 basis. MAC Field is deliberately a different Rust type.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::c71_matrix) struct PcsField { limbs:[u64;3] }
impl From<E> for PcsField {
    fn from(value:E)->Self {
        let basis=<E as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
        Self {limbs:[basis[0].as_canonical_u64(),basis[1].as_canonical_u64(),basis[2].as_canonical_u64()]}
    }
}
impl PcsField {
    fn decode(self)->Result<E,String> {
        if self.limbs.iter().any(|&value|value>=volta_field::P) {return Err("native PCS noncanonical limb".into());}
        <E as BasedVectorSpace<Goldilocks>>::from_basis_coefficients_slice(
            &self.limbs.map(Goldilocks::new)).ok_or("native PCS basis dimension differs".into())
    }
}
#[repr(C)]
#[derive(Clone,Copy,Default)]
pub(in crate::c71_matrix) struct ResidualChunk {pub shift:u32,pub bits:u32,pub first:u32,pub reserved:u32}
#[repr(C)]
#[derive(Clone,Copy,Default)]
pub(in crate::c71_matrix) struct ResidualEq {pub bits:u32,pub chunks:u32,pub entries:u32,pub reserved:u32}
#[repr(C)]
#[derive(Clone,Copy,Default)]
pub(in crate::c71_matrix) struct ResidualShape {pub live:u64,pub dimension:u32,pub remaining:u32,pub equality:ResidualEq}
#[repr(u32)]
#[derive(Clone,Copy,Eq,PartialEq)]
pub(in crate::c71_matrix) enum ResidualPhase {Singleton=0,Retention=1,Cosets=2,Ood=3}
#[repr(C)]
#[derive(Clone,Copy,Default)]
pub(in crate::c71_matrix) struct ResidualCosets {pub rows:u64,pub pad_rows:u32,pub cosets:u32,pub first_coset:u32,pub reserved:u32}
#[repr(C)]
#[derive(Clone,Copy,Default)]
struct RawPlanes {c0:u64,c1:u64,c2:u64,count:u64}
#[repr(C)]
struct RawResidual {planes:RawPlanes,ring:u64,reduced_count:u32,reserved:u32,reduced:[PcsField;128]}
impl Default for RawResidual {
    fn default()->Self {Self {planes:RawPlanes::default(),ring:0,reduced_count:0,reserved:0,reduced:[PcsField::default();128]}}
}
pub(in crate::c71_matrix) struct ResidualPacket {pub shape:ResidualShape,pub chunks:Vec<ResidualChunk>,pub tables:Vec<PcsField>}
impl ResidualPacket {
    pub(in crate::c71_matrix) fn host_capacity_bytes(&self)->usize {
        size_of::<Self>()+self.chunks.capacity()*size_of::<ResidualChunk>()+self.tables.capacity()*size_of::<PcsField>()
    }
}
pub(in crate::c71_matrix) struct ResidualToken {id:u64,owner:Arc<()>,phase:ResidualPhase,count:u64}
pub(in crate::c71_matrix) struct ResidualContract {id:u64,owner:Arc<()>,kind:u32}
pub(in crate::c71_matrix) struct ResidualQuery {id:u64,owner:Arc<()>,capacity:usize}
// Descriptors do not free device capacity on drop. Their typed runtime
// retirement is required after the last oracle lease has been consumed.
pub(in crate::c71_matrix) struct ResidualPlanes {raw:RawPlanes,owner:Arc<()>}
impl ResidualPlanes {pub(in crate::c71_matrix) fn count(&self)->usize {self.raw.count as usize}}
pub(in crate::c71_matrix) struct ResidualRing {id:u64,count:usize,owner:Arc<()>}
pub(in crate::c71_matrix) enum ResidualResult {Reduced(Vec<E>),Planes(ResidualPlanes),Ring(ResidualRing)}
const _:()=assert!(size_of::<PcsField>()==24 && size_of::<ResidualChunk>()==16 && size_of::<ResidualEq>()==16
    && size_of::<ResidualShape>()==32 && size_of::<ResidualCosets>()==24 && size_of::<RawPlanes>()==32 && size_of::<RawResidual>()==3120);

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
/// Original biased bytes of a resident scalar tile. Unlike ByteTile this
/// has no range permutation/window: PCS consumes the original flat layout.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(in crate::c71_matrix) struct PcsSourceTile {
    pub input_first: u64,
    pub input_stride: u64,
    pub rows: u64,
    pub columns: u64,
    pub original_first: u64,
    pub byte_first: u32,
    pub width: u32,
    pub signed_width: u32,
}
const _: () = assert!(size_of::<PcsSourceTile>() == 56);
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(in crate::c71_matrix) struct PcsSourceShape {
    pub message_rows: u64, pub rows: u64, pub live: u64,
    pub pad_rows: u32, pub cosets: u32, pub first_coset: u32,
}
const _: () = assert!(size_of::<PcsSourceShape>() == 40);
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(in crate::c71_matrix) struct PcsQueryBlock {
    pub first: u64, pub source_rows: u64, pub message_rows: u64, pub active: u64,
    pub byte_first: u64, pub window_first: u64, pub pad_first: u64, pub pad_rows: u64,
    pub pad_only: u32,
}
const _: () = assert!(size_of::<PcsQueryBlock>() == 72);
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(in crate::c71_matrix) struct WeightTile {
    pub first: u64, pub count: u64, pub packed_first: u64, pub packed_stride: u64, pub columns: u64,
}
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(in crate::c71_matrix) struct WeightShape {
    pub message_rows: u64, pub rows: u64, pub pad_rows: u32, pub cosets: u32,
    pub first_coset: u32, pub first_column: u32, pub slots: u32,
}
const _: () = assert!(size_of::<WeightTile>() == 40 && size_of::<WeightShape>() == 40);
#[derive(Clone, Copy)]
#[repr(C)]
pub(in crate::c71_matrix) struct SaltGeometry {
    pub rows: u64, pub origin: u64, pub cosets: u32, pub cut: u32,
}
#[derive(Default)]
#[repr(C)]
struct SaltProgress {
    cursor: u64, accepted: u64, logical_bytes: u64, physical_blocks: u64,
    failed: u32, complete: u32,
}
const _: () = assert!(size_of::<SaltGeometry>() == 24 && size_of::<SaltProgress>() == 40);
/// Proof-consumer capability, never a numeric source Buffer or public coin.
pub(in crate::c71_matrix) struct PrivateSalts { id: u64, owner: Arc<()> }
/// One proof consumer; its capability never reaches a numerical producer.
pub(in crate::c71_matrix) struct LinearToken { id: u64, owner: Arc<()> }
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
    pcs_upload: unsafe extern "C" fn(Raw,u64,u64,*const u64,u64)->i32 => "c71_pcs_words_upload",
    pcs_start: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_pcs_leaf_start",
    pcs_step: unsafe extern "C" fn(Raw,u64,u64,u32)->i32 => "c71_pcs_leaf_step",
    pcs_finish: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64)->i32 => "c71_pcs_leaf_finish",
    pcs_nodes: unsafe extern "C" fn(Raw,u64,u64,u64)->i32 => "c71_pcs_nodes",
    pcs_frontier: unsafe extern "C" fn(Raw,u64,u64,u32)->i32 => "c71_pcs_frontier_begin",
    pcs_merge: unsafe extern "C" fn(Raw,u64,u64,u32)->i32 => "c71_pcs_merge_group",
    pcs_read: unsafe extern "C" fn(Raw,u64,u64,u64,*mut c_void)->i32 => "c71_pcs_read_digests",
    pcs_tiles: unsafe extern "C" fn(Raw,u64,*const WeightTile,u64)->i32 => "c71_pcs_tiles_upload",
    pcs_powers: unsafe extern "C" fn(Raw,u64,u64,WeightShape)->i32 => "c71_pcs_powers",
    pcs_twiddles: unsafe extern "C" fn(Raw,u64,u32)->i32 => "c71_pcs_twiddles",
    transform_twiddles: unsafe extern "C" fn(Raw,u64,u32,u32)->i32 => "c71_pcs_transform_twiddles",
    transform: unsafe extern "C" fn(Raw,u64,u64,u64,u32,u32,u32)->i32 => "c71_pcs_transform",
    pcs_words_read: unsafe extern "C" fn(Raw,u64,u64,u64,*mut u64)->i32 => "c71_pcs_read_words",
    query_low: unsafe extern "C" fn(Raw,u64,u64,u64,PcsQueryBlock)->i32 => "c71_pcs_query_low",
    query_weight_low: unsafe extern "C" fn(Raw,u64,u64,u64,PcsQueryBlock)->i32 => "c71_pcs_query_weight_low",
    query_remainder: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u32)->i32 => "c71_pcs_query_remainder",
    query_shift: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64,u64,u64)->i32 => "c71_pcs_query_shift",
    query_add: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_pcs_query_add",
    pcs_zero: unsafe extern "C" fn(Raw,u64)->i32 => "c71_pcs_ring_zero",
    pcs_weight: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64,WeightShape)->i32 => "c71_pcs_weight",
    pcs_weight_tensor: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64,WeightShape)->i32 => "c71_pcs_weight_tensor",
    pcs_compare_words: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_pcs_compare_words",
    pcs_source_powers: unsafe extern "C" fn(Raw,u64,u64,PcsSourceShape)->i32 => "c71_pcs_source_powers",
    pcs_source_begin: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,PcsSourceShape)->i32 => "c71_pcs_source_begin",
    pcs_source_tile: unsafe extern "C" fn(Raw,u64,*const PcsSourceTile)->i32 => "c71_pcs_source_tile",
    pcs_source_finish: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64)->i32 => "c71_pcs_source_finish",
    pcs_full_leaves: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u64,u64)->i32 => "c71_pcs_full_leaves",
    salts_begin: unsafe extern "C" fn(Raw,*const u8,SaltGeometry,u32,u32,*mut u64)->i32 => "c71_pcs_salts_begin",
    salts_prescan: unsafe extern "C" fn(Raw,u64,*mut SaltProgress)->i32 => "c71_pcs_salts_prescan",
    salts_indices: unsafe extern "C" fn(Raw,u64,*mut u64,u64,*mut u64,u64)->i32 => "c71_pcs_salts_indices",
    private_finish: unsafe extern "C" fn(Raw,u64,u64,u64,u32,u64,u64,*mut u64)->i32 => "c71_pcs_leaf_finish_private",
    private_full: unsafe extern "C" fn(Raw,u64,u64,u64,u64,u32,u64,u64,*mut u64)->i32 => "c71_pcs_full_leaves_private",
    salts_complete: unsafe extern "C" fn(Raw,u64,*mut u64,u64,*mut u64)->i32 => "c71_pcs_salts_complete",
    linear_begin: unsafe extern "C" fn(Raw,LinearShape,*const LinearChunk,*const Field,u32,
        *const LinearGroup,*const LinearInterval,*const Field,*mut u64)->i32 => "c71_linear_begin",
    linear_source: unsafe extern "C" fn(Raw,u64,u64,PcsSourceTile)->i32 => "c71_linear_source_tile",
    linear_weights: unsafe extern "C" fn(Raw,u64,u64)->i32 => "c71_linear_weights",
    linear_finish: unsafe extern "C" fn(Raw,u64,*mut Field)->i32 => "c71_linear_finish",
    residual_begin:unsafe extern "C" fn(Raw,ResidualShape,ResidualPhase,*const ResidualChunk,*const PcsField,ResidualCosets,*const PcsField,u32,PcsField,*mut u64)->i32=>"c71_pcs_residual_begin",
    residual_source:unsafe extern "C" fn(Raw,u64,u64,PcsSourceTile)->i32=>"c71_pcs_residual_source_tile",
    residual_weights:unsafe extern "C" fn(Raw,u64,u64)->i32=>"c71_pcs_residual_weights",
    residual_resident:unsafe extern "C" fn(Raw,u64,RawPlanes)->i32=>"c71_pcs_residual_resident",
    residual_finish:unsafe extern "C" fn(Raw,u64,*mut RawResidual)->i32=>"c71_pcs_residual_finish",
    residual_fold:unsafe extern "C" fn(Raw,RawPlanes,u32,PcsField,PcsField,*mut RawPlanes)->i32=>"c71_pcs_residual_fold",
    residual_retire_planes:unsafe extern "C" fn(Raw,RawPlanes)->i32=>"c71_pcs_residual_retire_planes",
    residual_retire_ring:unsafe extern "C" fn(Raw,u64)->i32=>"c71_pcs_residual_retire_ring",
    residual_final:unsafe extern "C" fn(Raw,RawPlanes,*mut PcsField,u32)->i32=>"c71_pcs_residual_final_read",
    contract_begin:unsafe extern "C" fn(Raw,ResidualShape,*const ResidualChunk,*const PcsField,u32,u32,*mut u64)->i32=>"c71_pcs_residual_contract_begin",
    contract_weights:unsafe extern "C" fn(Raw,u64,u64,u64,u32,*const PcsField,*const PcsField)->i32=>"c71_pcs_residual_contract_weights_band",
    contract_resident:unsafe extern "C" fn(Raw,u64,RawPlanes,u64,u32,*const PcsField,*const PcsField)->i32=>"c71_pcs_residual_contract_resident_band",
    contract_finish:unsafe extern "C" fn(Raw,u64,*mut PcsField)->i32=>"c71_pcs_residual_contract_finish",
    residual_query_begin:unsafe extern "C" fn(Raw,ResidualShape,*const ResidualChunk,*const PcsField,*const PcsField,u32,u32,u32,*mut u64)->i32=>"c71_pcs_residual_query_begin",
    residual_query_weights:unsafe extern "C" fn(Raw,u64,u64,PcsQueryBlock)->i32=>"c71_pcs_residual_query_weights",
    residual_query_resident:unsafe extern "C" fn(Raw,u64,RawPlanes,PcsQueryBlock)->i32=>"c71_pcs_residual_query_resident",
    residual_query_root:unsafe extern "C" fn(Raw,u64,u32,u64,u64,u64,u64,u64,u64,u64,u64)->i32=>"c71_pcs_residual_query_root",
    residual_query_finish:unsafe extern "C" fn(Raw,u64,*const u64,u32,*mut u64)->i32=>"c71_pcs_residual_query_finish",
    short_private:unsafe extern "C" fn(Raw,u64,u64,u64,u32,u64,u64,*mut u64)->i32=>"c71_pcs_short_leaves_private",

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
    pub(in crate::c71_matrix) fn residual_query_begin(&mut self,packet:&ResidualPacket,pads:&[PcsField],
        capacity:usize,column:usize)->Result<ResidualQuery,String> {
        self.require_residual_packet(packet)?;
        if !capacity.is_power_of_two() || capacity>1<<20 || column>=4 || pads.is_empty() || pads.len()%4!=0 || pads.len()>4*1536 {
            return self.abort("native E query geometry or pads differ");
        }
        let mut id=0;
        let status=unsafe {(self.api.residual_query_begin)(self.raw,packet.shape,packet.chunks.as_ptr(),packet.tables.as_ptr(),
            pads.as_ptr(),pads.len() as u32,capacity as u32,column as u32,&mut id)};
        self.check(status)?;if id==0 {return self.abort("native E query null capability");}
        Ok(ResidualQuery {id,owner:self.owner.clone(),capacity})
    }
    fn require_residual_query(&mut self,token:&ResidualQuery)->Result<(),String> {
        self.ready()?;if token.id==0 || !Arc::ptr_eq(&self.owner,&token.owner) {return self.abort("native E query capability owner differs");}
        Ok(())
    }
    pub(in crate::c71_matrix) fn residual_query_weights(&mut self,token:&ResidualQuery,tiles:&Buffer,
        block:PcsQueryBlock)->Result<(),String> {
        self.require_residual_query(token)?;self.require_buffer(tiles)?;
        let status=unsafe {(self.api.residual_query_weights)(self.raw,token.id,tiles.id,block)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_query_resident(&mut self,token:&ResidualQuery,planes:&ResidualPlanes,
        block:PcsQueryBlock)->Result<(),String> {
        self.require_residual_query(token)?;self.require_planes(planes)?;
        let status=unsafe {(self.api.residual_query_resident)(self.raw,token.id,planes.raw,block)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_query_root(&mut self,token:&ResidualQuery,limb:usize,high:Option<&Buffer>,
        inverse:&Buffer,modulus:&Buffer,forward:&Buffer,backward:&Buffer,work:&Buffer,scratch:&Buffer,output:&Buffer)->Result<(),String> {
        self.require_residual_query(token)?;if limb>=3 {return self.abort("native E query limb differs");}
        for buffer in high.into_iter().chain([inverse,modulus,forward,backward,work,scratch,output]) {self.require_buffer(buffer)?;}
        let status=unsafe {(self.api.residual_query_root)(self.raw,token.id,limb as u32,high.map_or(0,|b|b.id),
            inverse.id,modulus.id,forward.id,backward.id,work.id,scratch.id,output.id)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_query_finish(&mut self,token:ResidualQuery,finals:[&Buffer;3],
        count:usize)->Result<Vec<u64>,String> {
        self.require_residual_query(&token)?;
        if count==0 || count>token.capacity {return self.abort("native E query output exceeds cap");}
        for buffer in finals {self.require_buffer(buffer)?;}
        let ids=finals.map(|b|b.id);
        let mut output=vec![0;3*count];
        let status=unsafe {(self.api.residual_query_finish)(self.raw,token.id,ids.as_ptr(),count as u32,output.as_mut_ptr())};
        self.check(status)?;if output.iter().any(|&x|x>=volta_field::P){return self.abort("native E query noncanonical output");}
        Ok(output)
    }
    fn require_residual_packet(&mut self,packet:&ResidualPacket)->Result<(),String> {
        self.ready()?;
        if packet.shape.equality.chunks as usize!=packet.chunks.len() || packet.shape.equality.entries as usize!=packet.tables.len() {
            return self.abort("native PCS EQ packet lengths differ");
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn residual_begin(&mut self,packet:&ResidualPacket,phase:ResidualPhase,
        cosets:ResidualCosets,pads:&[PcsField],point:E)->Result<ResidualToken,String> {
        self.require_residual_packet(packet)?;
        if pads.len()>4*1536 {return self.abort("native PCS pad packet exceeds cap");}
        let mut id=0;
        let status=unsafe {(self.api.residual_begin)(self.raw,packet.shape,phase,packet.chunks.as_ptr(),packet.tables.as_ptr(),
            cosets,pads.as_ptr(),pads.len() as u32,point.into(),&mut id)};
        self.check(status)?;
        if id==0 {return self.abort("native PCS null capability");}
        let count=match phase {ResidualPhase::Singleton=>1u64<<(packet.shape.dimension-packet.shape.remaining),
            ResidualPhase::Retention=>1u64<<packet.shape.remaining,ResidualPhase::Cosets=>24*cosets.rows,ResidualPhase::Ood=>1};
        Ok(ResidualToken {id,owner:self.owner.clone(),phase,count})
    }
    fn require_residual(&mut self,token:&ResidualToken)->Result<(),String> {
        self.ready()?;
        if token.id==0 || !Arc::ptr_eq(&self.owner,&token.owner) {return self.abort("native PCS capability owner differs");}
        Ok(())
    }
    fn require_planes(&mut self,planes:&ResidualPlanes)->Result<(),String> {
        self.ready()?;
        if !Arc::ptr_eq(&self.owner,&planes.owner) {return self.abort("native PCS planes owner differs");}
        Ok(())
    }
    pub(in crate::c71_matrix) fn residual_source_tile(&mut self,token:&ResidualToken,input:&Buffer,tile:PcsSourceTile)->Result<(),String> {
        self.require_residual(token)?;self.require_buffer(input)?;
        let status=unsafe {(self.api.residual_source)(self.raw,token.id,input.id,tile)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_weights(&mut self,token:&ResidualToken,tiles:&Buffer)->Result<(),String> {
        self.require_residual(token)?;self.require_buffer(tiles)?;
        let status=unsafe {(self.api.residual_weights)(self.raw,token.id,tiles.id)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_resident(&mut self,token:&ResidualToken,planes:&ResidualPlanes)->Result<(),String> {
        self.require_residual(token)?;self.require_planes(planes)?;
        let status=unsafe {(self.api.residual_resident)(self.raw,token.id,planes.raw)};self.check(status)
    }
    fn wrap_planes(&mut self,raw:RawPlanes,count:u64)->Result<ResidualPlanes,String> {
        if raw.count!=count || raw.c0==0 || raw.c1==0 || raw.c2==0 || raw.c0==raw.c1 || raw.c0==raw.c2 || raw.c1==raw.c2 {
            return self.abort("native PCS planes publication differs");
        }
        Ok(ResidualPlanes {raw,owner:self.owner.clone()})
    }
    pub(in crate::c71_matrix) fn residual_finish(&mut self,token:ResidualToken)->Result<ResidualResult,String> {
        self.require_residual(&token)?;
        let mut raw=RawResidual::default();
        let status=unsafe {(self.api.residual_finish)(self.raw,token.id,&mut raw)};self.check(status)?;
        if raw.reserved!=0 {return self.abort("native PCS reserved publication differs");}
        let empty_planes=raw.planes.c0==0 && raw.planes.c1==0 && raw.planes.c2==0 && raw.planes.count==0;
        match token.phase {
            ResidualPhase::Singleton|ResidualPhase::Ood=>{
                if !empty_planes || raw.ring!=0 || u64::from(raw.reduced_count)!=token.count || token.count>128 {
                    return self.abort("native PCS reduction publication differs");
                }
                let mut values=Vec::with_capacity(token.count as usize);
                for field in &raw.reduced[..token.count as usize] {
                    values.push(match field.decode() {Ok(value)=>value,Err(error)=>return self.abort(error)});
                }
                Ok(ResidualResult::Reduced(values))
            }
            ResidualPhase::Retention=>{
                if raw.ring!=0 || raw.reduced_count!=0 {return self.abort("native PCS retention publication differs");}
                self.wrap_planes(raw.planes,token.count).map(ResidualResult::Planes)
            }
            ResidualPhase::Cosets=>{
                if !empty_planes || raw.ring==0 || raw.reduced_count!=0 {return self.abort("native PCS coset publication differs");}
                Ok(ResidualResult::Ring(ResidualRing {id:raw.ring,count:token.count as usize,owner:self.owner.clone()}))
            }
        }
    }
    pub(in crate::c71_matrix) fn residual_fold(&mut self,input:&ResidualPlanes,point:&[E])->Result<ResidualPlanes,String> {
        self.require_planes(input)?;
        if !(1..=2).contains(&point.len()) {return self.abort("native PCS fold width differs");}
        let mut output=RawPlanes::default();
        let status=unsafe {(self.api.residual_fold)(self.raw,input.raw,point.len() as u32,point[0].into(),
            point.get(1).copied().unwrap_or(E::ZERO).into(),&mut output)};self.check(status)?;
        self.wrap_planes(output,input.raw.count>>point.len())
    }
    pub(in crate::c71_matrix) fn residual_retire_planes(&mut self,input:&ResidualPlanes)->Result<(),String> {
        self.require_planes(input)?;
        let status=unsafe {(self.api.residual_retire_planes)(self.raw,input.raw)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_retire_ring(&mut self,input:ResidualRing)->Result<(),String> {
        self.ready()?;
        if !Arc::ptr_eq(&self.owner,&input.owner) {return self.abort("native PCS ring owner differs");}
        let status=unsafe {(self.api.residual_retire_ring)(self.raw,input.id)};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_final_read(&mut self,input:ResidualPlanes)->Result<Vec<E>,String> {
        self.require_planes(&input)?;
        if input.count()==0 || input.count()>128 {return self.abort("native PCS final read exceeds bound");}
        let mut fields=vec![PcsField::default();input.count()];
        let status=unsafe {(self.api.residual_final)(self.raw,input.raw,fields.as_mut_ptr(),fields.len() as u32)};self.check(status)?;
        fields.into_iter().map(PcsField::decode).collect::<Result<Vec<_>,_>>().or_else(|error|self.abort(error))
    }
    pub(in crate::c71_matrix) fn residual_contract_begin(&mut self,packet:&ResidualPacket,kind:u32,capacity:usize)->Result<ResidualContract,String> {
        self.require_residual_packet(packet)?;
        if kind>1 || capacity==0 || capacity>1<<21 {return self.abort("native PCS contraction kind or band exceeds cap");}
        let mut id=0;
        let status=unsafe {(self.api.contract_begin)(self.raw,packet.shape,packet.chunks.as_ptr(),packet.tables.as_ptr(),kind,capacity as u32,&mut id)};
        self.check(status)?;if id==0 {return self.abort("native PCS contraction null capability");}
        Ok(ResidualContract {id,owner:self.owner.clone(),kind})
    }
    fn require_contract(&mut self,token:&ResidualContract,left:&[PcsField],right:&[PcsField])->Result<(),String> {
        self.ready()?;
        if token.id==0 || !Arc::ptr_eq(&self.owner,&token.owner) || left.is_empty() || left.len()>1<<21 ||
            (token.kind==0 && !right.is_empty()) || (token.kind==1 && right.len()!=left.len()) {
            return self.abort("native PCS contraction owner or public band differs");
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn residual_contract_weights(&mut self,token:&ResidualContract,tiles:&Buffer,
        first:usize,left:&[PcsField],right:&[PcsField])->Result<(),String> {
        self.require_contract(token,left,right)?;self.require_buffer(tiles)?;
        let status=unsafe {(self.api.contract_weights)(self.raw,token.id,tiles.id,first as u64,left.len() as u32,
            left.as_ptr(),if right.is_empty(){ptr::null()}else{right.as_ptr()})};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_contract_resident(&mut self,token:&ResidualContract,input:&ResidualPlanes,
        first:usize,left:&[PcsField],right:&[PcsField])->Result<(),String> {
        self.require_contract(token,left,right)?;self.require_planes(input)?;
        let status=unsafe {(self.api.contract_resident)(self.raw,token.id,input.raw,first as u64,left.len() as u32,
            left.as_ptr(),if right.is_empty(){ptr::null()}else{right.as_ptr()})};self.check(status)
    }
    pub(in crate::c71_matrix) fn residual_contract_finish(&mut self,token:ResidualContract)->Result<[E;2],String> {
        self.ready()?;if !Arc::ptr_eq(&self.owner,&token.owner) {return self.abort("native PCS contraction owner differs");}
        let mut fields=[PcsField::default();2];
        let status=unsafe {(self.api.contract_finish)(self.raw,token.id,fields.as_mut_ptr())};self.check(status)?;
        let left=fields[0].decode().or_else(|error|self.abort(error))?;
        let right=fields[1].decode().or_else(|error|self.abort(error))?;Ok([left,right])
    }
    pub(in crate::c71_matrix) fn residual_short_leaves(&mut self,private:&PrivateSalts,ring:&ResidualRing,
        output:&mut Buffer,group:usize,first:usize,count:usize)->Result<u64,String> {
        self.ready()?;self.require_buffer(output)?;
        if !Arc::ptr_eq(&self.owner,&private.owner) || !Arc::ptr_eq(&self.owner,&ring.owner) || ring.count==0 || group>u32::MAX as usize {
            return self.abort("native PCS short leaf owner or group differs");
        }
        let mut completed=0;
        let status=unsafe {(self.api.short_private)(self.raw,private.id,ring.id,output.id,group as u32,first as u64,count as u64,&mut completed)};
        self.check(status)?;if first.checked_add(count)==output.count.checked_mul(2){output.kind=11;}Ok(completed)
    }
    pub(in crate::c71_matrix) fn linear_begin(&mut self, packet: &LinearPacket) -> Result<LinearToken, String> {
        self.ready()?;
        let s=packet.shape;
        if s.chunks as usize != packet.chunks.len() || s.groups as usize != packet.groups.len()
            || s.intervals as usize != packet.intervals.len() || s.points as usize != packet.points.len()
            || packet.tables.len()>1280 {
            return self.abort("native linear packet lengths differ");
        }
        let mut id=0;
        let status=unsafe { (self.api.linear_begin)(self.raw,s,packet.chunks.as_ptr(),packet.tables.as_ptr(),
            packet.tables.len() as u32,packet.groups.as_ptr(),packet.intervals.as_ptr(),packet.points.as_ptr(),&mut id) };
        self.check(status)?;
        if id==0 { return self.abort("native linear returned null capability"); }
        Ok(LinearToken { id,owner:self.owner.clone() })
    }
    fn require_linear(&mut self, token: &LinearToken) -> Result<(),String> {
        self.ready()?;
        if token.id==0 || !Arc::ptr_eq(&self.owner,&token.owner) {
            return self.abort("native linear capability belongs to another owner");
        }
        Ok(())
    }
    pub(in crate::c71_matrix) fn linear_source_tile(&mut self, token: &LinearToken,
        input: &Buffer, tile: PcsSourceTile) -> Result<(),String> {
        self.require_linear(token)?; self.require_buffer(input)?;
        let status=unsafe { (self.api.linear_source)(self.raw,token.id,input.id,tile) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn linear_weights(&mut self, token: &LinearToken,
        sealed_tiles: &Buffer) -> Result<(),String> {
        self.require_linear(token)?; self.require_buffer(sealed_tiles)?;
        let status=unsafe { (self.api.linear_weights)(self.raw,token.id,sealed_tiles.id) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn linear_finish(&mut self, token: LinearToken) -> Result<[Fp3;5],String> {
        self.require_linear(&token)?;
        let mut fields=[Field::default();5];
        let status=unsafe { (self.api.linear_finish)(self.raw,token.id,fields.as_mut_ptr()) };
        self.check(status)?;
        let mut values=[Fp3::ZERO;5];
        for (value,field) in values.iter_mut().zip(fields) {
            *value=match field.decode() { Ok(value)=>value,Err(error)=>return self.abort(error) };
        }
        Ok(values)
    }
    pub(in crate::c71_matrix) fn pcs_salts_prepare(&mut self, seed: &[u8; 32], geometry: SaltGeometry,
        group: u32, starts: &mut [u64], offsets: &mut [u64]) -> Result<(u64, PrivateSalts), String> {
        let result: Result<(u64, PrivateSalts), String> = (|| {
            self.ready()?;
            let target = geometry.rows.checked_mul(u64::from(geometry.cosets))
                .and_then(|n| n.checked_mul(4)).ok_or("private PCS salt target overflow")?;
            let capacity = target.clamp(8, 1 << 24).next_power_of_two() as u32;
            let before = self.stats()?;
            let mut phase = crate::c71_matrix::progress::Span::start("pcs_salts_prescan_gpu",
                serde_json::json!({"rows": geometry.rows,"cosets": geometry.cosets,"cut": geometry.cut,
                    "samples": target,"candidate_capacity": capacity}))?;
            let mut id = 0;
            let status = unsafe { (self.api.salts_begin)(self.raw, seed.as_ptr(), geometry, group, capacity, &mut id) };
            self.check(status)?;
            let private = PrivateSalts { id, owner: self.owner.clone() };
            let mut progress = SaltProgress::default();
            let mut chunks = 0u64;
            let mut blocks = 0u64;
            loop {
                let status = unsafe { (self.api.salts_prescan)(self.raw, id, &mut progress) };
                self.check(status)?;
                chunks += 1; blocks += progress.physical_blocks;
                phase.checkpoint(|| serde_json::json!({"completed_samples":progress.accepted,
                    "logical_candidate_bytes":progress.logical_bytes,"computed_xof_blocks":blocks,
                    "chunks":chunks,"native":self.stats().ok()}))?;
                if progress.complete != 0 { break; }
            }
            let status = unsafe { (self.api.salts_indices)(self.raw, id, starts.as_mut_ptr(), starts.len() as u64,
                offsets.as_mut_ptr(), offsets.len() as u64) };
            self.check(status)?;
            let after = self.stats()?;
            phase.finish(serde_json::json!({"completed_samples":progress.accepted,
                "logical_candidate_bytes":progress.logical_bytes,"computed_xof_blocks":blocks,"chunks":chunks,
                "native_h2d_bytes":after.h2d_bytes-before.h2d_bytes,"native_d2h_bytes":after.d2h_bytes-before.d2h_bytes,
                "native_launches":after.launches-before.launches,"native_fences":after.fences-before.fences,
                "native":after}))?;
            Ok((progress.cursor, private))
        })();
        if let Err(error) = &result { return self.abort(error.clone()); }
        result
    }
    fn require_private(&mut self, salts: &PrivateSalts) -> Result<(), String> {
        self.ready()?;
        if !Arc::ptr_eq(&self.owner, &salts.owner) { return self.abort("private PCS capability belongs to another owner"); }
        Ok(())
    }
    pub(in crate::c71_matrix) fn pcs_private_hash_finish(&mut self, salts: &PrivateSalts, ring: &Buffer,
        states: &mut Buffer, group: usize, first: usize) -> Result<u64, String> {
        self.require_private(salts)?; self.require_buffer(ring)?; self.require_buffer(states)?;
        let Ok(group) = u32::try_from(group) else { return self.abort("private PCS group overflow"); };
        let count = states.count.min(65536);
        let mut completed = 0;
        let status = unsafe { (self.api.private_finish)(self.raw, salts.id, ring.id, states.id, group,
            first as u64, count as u64, &mut completed) };
        self.check(status)?;
        if first.checked_add(count) == Some(states.count) { states.kind = 11; }
        Ok(completed)
    }
    pub(in crate::c71_matrix) fn pcs_private_full_hash_band(&mut self, salts: &PrivateSalts, values: &[Buffer; 2],
        states: &mut Buffer, group: usize, first: usize) -> Result<u64, String> {
        self.require_private(salts)?;
        for input in [&values[0], &values[1], states] { self.require_buffer(input)?; }
        let Ok(group) = u32::try_from(group) else { return self.abort("private PCS group overflow"); };
        let count = states.count.min(65536);
        let mut completed = 0;
        let status = unsafe { (self.api.private_full)(self.raw, salts.id, values[0].id, values[1].id, states.id, group,
            first as u64, count as u64, &mut completed) };
        self.check(status)?;
        if first.checked_add(count) == Some(states.count) { states.kind = 11; }
        Ok(completed)
    }
    pub(in crate::c71_matrix) fn pcs_salts_complete(&mut self, salts: PrivateSalts, current: &mut [u64]) -> Result<u64, String> {
        self.require_private(&salts)?;
        let mut consumed = 0;
        let status = unsafe { (self.api.salts_complete)(self.raw, salts.id, current.as_mut_ptr(), current.len() as u64, &mut consumed) };
        self.check(status)?;
        Ok(consumed)
    }
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
    pub(in crate::c71_matrix) fn pcs_words(&mut self, count: usize) -> Result<Buffer, String> {
        let id = self.alloc(9, count)?;
        Ok(Buffer { id, kind: 9, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pcs_weight_tiles(&mut self, weights: &Arc<Vec<i16>>, layout: [u8; 32], tiles: &[WeightTile]) -> Result<Buffer, String> {
        self.require_weights(weights, layout)?;
        let id = self.alloc(13, tiles.len())?;
        let status = unsafe { (self.api.pcs_tiles)(self.raw, id, tiles.as_ptr(), tiles.len() as u64) };
        self.check(status)?;
        Ok(Buffer { id, kind: 13, count: tiles.len(), owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pcs_coset_powers(&mut self, shape: WeightShape) -> Result<(Buffer, Buffer), String> {
        // C validates the shape before kernels. Bound counts before host math.
        if shape.rows < 4 || shape.rows > 1 << 20 || shape.message_rows > 1 << 28 || shape.pad_rows > 1536 {
            return self.abort("native PCS power capacity differs");
        }
        let low_count = 32 * shape.rows as usize;
        let high_count = 32 * (shape.message_rows + u64::from(shape.pad_rows)).div_ceil(shape.rows) as usize;
        let low = self.allocate_buffer(14, low_count)?;
        let high = self.allocate_buffer(14, high_count)?;
        let status = unsafe { (self.api.pcs_powers)(self.raw, low.id, high.id, shape) };
        self.check(status)?;
        Ok((low, high))
    }
    pub(in crate::c71_matrix) fn pcs_fft_twiddles(&mut self, log_rows: usize) -> Result<Buffer, String> {
        if !(2..=20).contains(&log_rows) || log_rows % 2 != 0 { return self.abort("native PCS FFT shape differs"); }
        let output = self.allocate_buffer(14, 1 << log_rows)?;
        let status = unsafe { (self.api.pcs_twiddles)(self.raw, output.id, log_rows as u32) };
        self.check(status)?;
        Ok(output)
    }
    pub(in crate::c71_matrix) fn pcs_transform_twiddles(&mut self, log_rows: usize, inverse: bool) -> Result<Buffer,String> {
        if !(1..=24).contains(&log_rows) { return self.abort("native PCS transform shape differs"); }
        let output=self.allocate_buffer(14,1<<log_rows)?;
        let status=unsafe { (self.api.transform_twiddles)(self.raw,output.id,log_rows as u32,u32::from(inverse)) };
        self.check(status)?; Ok(output)
    }
    pub(in crate::c71_matrix) fn pcs_transform(&mut self, values: &Buffer, scratch: &Buffer,
        twiddles: &Buffer, log_rows: usize, batch: usize, inverse: bool) -> Result<(),String> {
        for b in [values,scratch,twiddles] { self.require_buffer(b)?; }
        if !(1..=24).contains(&log_rows) || !(1..=1<<20).contains(&batch) {
            return self.abort("native PCS transform geometry differs");
        }
        let status=unsafe { (self.api.transform)(self.raw,values.id,scratch.id,twiddles.id,
            log_rows as u32,batch as u32,u32::from(inverse)) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_download_words(&mut self, values: &Buffer, first: usize, output: &mut [u64])
        -> Result<(),String> {
        self.require_buffer(values)?;
        let status=unsafe { (self.api.pcs_words_read)(self.raw,values.id,first as u64,output.len() as u64,output.as_mut_ptr()) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_query_low(&mut self, bytes: Option<&Buffer>, pads: &Buffer,
        low: &Buffer, block: PcsQueryBlock) -> Result<(),String> {
        for b in bytes.into_iter().chain([pads,low]) { self.require_buffer(b)?; }
        let status=unsafe { (self.api.query_low)(self.raw,bytes.map_or(0,|b|b.id),pads.id,low.id,block) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_query_weight_low(&mut self, tiles: &Buffer, pads: &Buffer,
        low: &Buffer, block: PcsQueryBlock) -> Result<(),String> {
        for b in [tiles,pads,low] {self.require_buffer(b)?;}
        let status=unsafe {(self.api.query_weight_low)(self.raw,tiles.id,pads.id,low.id,block)};
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_query_remainder(&mut self, high: &Buffer, low: &Buffer,
        inverse: &Buffer, modulus: &Buffer, forward: &Buffer, backward: &Buffer,
        work: &Buffer, scratch: &Buffer, output: &Buffer, degree: usize, children: bool) -> Result<(),String> {
        for b in [high,low,inverse,modulus,forward,backward,work,scratch,output] { self.require_buffer(b)?; }
        let status=unsafe { (self.api.query_remainder)(self.raw,high.id,low.id,inverse.id,modulus.id,
            forward.id,backward.id,work.id,scratch.id,output.id,degree as u64,u32::from(children)) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_query_shift(&mut self, values: &Buffer, shift: &Buffer,
        forward: &Buffer, backward: &Buffer, work: &Buffer, scratch: &Buffer,
        low: &Buffer, high: &Buffer) -> Result<(),String> {
        for b in [values,shift,forward,backward,work,scratch,low,high] { self.require_buffer(b)?; }
        let status=unsafe { (self.api.query_shift)(self.raw,values.id,shift.id,forward.id,backward.id,
            work.id,scratch.id,low.id,high.id) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_query_add(&mut self, values: &Buffer, correction: &Buffer) -> Result<(),String> {
        self.require_buffer(values)?; self.require_buffer(correction)?;
        let status=unsafe { (self.api.query_add)(self.raw,values.id,correction.id) }; self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_ring(&mut self, rows: usize) -> Result<Buffer, String> {
        if rows == 0 || rows > 1 << 20 { return self.abort("native PCS ring capacity differs"); }
        let output = self.pcs_words(8 * 32 * rows)?;
        let status = unsafe { (self.api.pcs_zero)(self.raw, output.id) };
        self.check(status)?;
        Ok(output)
    }
    pub(in crate::c71_matrix) fn pcs_weight_columns(&mut self, tiles: &Buffer, pads: &Buffer,
        low: &Buffer, high: &Buffer, twiddles: &Buffer, ring: &Buffer, shape: WeightShape) -> Result<(), String> {
        for input in [tiles, pads, low, high, twiddles, ring] { self.require_buffer(input)?; }
        let status = unsafe { (self.api.pcs_weight)(self.raw, tiles.id, pads.id, low.id, high.id, twiddles.id, ring.id, shape) };
        self.check(status)
    }
    /// Explicit comparison only; the runner keeps ordinary accumulation.
    /// Same owner, source/powers, finite FFT and publication guard in C.
    pub(in crate::c71_matrix) fn pcs_weight_columns_tensor(&mut self, tiles: &Buffer, pads: &Buffer,
        low: &Buffer, high: &Buffer, twiddles: &Buffer, ring: &Buffer, shape: WeightShape) -> Result<(), String> {
        for input in [tiles, pads, low, high, twiddles, ring] { self.require_buffer(input)?; }
        let status = unsafe { (self.api.pcs_weight_tensor)(self.raw, tiles.id, pads.id, low.id, high.id, twiddles.id, ring.id, shape) };
        self.check(status)
    }
    /// Diagnostic bitwise comparison; no source words are downloaded.
    pub(in crate::c71_matrix) fn pcs_compare_words(&mut self, left: &Buffer, right: &Buffer) -> Result<(), String> {
        self.require_buffer(left)?; self.require_buffer(right)?;
        let status = unsafe { (self.api.pcs_compare_words)(self.raw, left.id, right.id) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_upload(
        &mut self, output: &Buffer, first: usize, values: &[u64],
    ) -> Result<(), String> {
        self.require_buffer(output)?;
        let status = unsafe { (self.api.pcs_upload)(self.raw, output.id, first as u64, values.as_ptr(), values.len() as u64) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_source_powers(&mut self, shape: PcsSourceShape) -> Result<(Buffer, Buffer), String> {
        if shape.rows < 4 || shape.rows > 1 << 20 || shape.message_rows > 1 << 27 || shape.pad_rows > 1536 {
            return self.abort("native PCS source power capacity differs");
        }
        let low = self.allocate_buffer(14, 4 * shape.rows as usize)?;
        let high = self.allocate_buffer(14, 4 * (shape.message_rows + u64::from(shape.pad_rows)).div_ceil(shape.rows) as usize)?;
        let status = unsafe { (self.api.pcs_source_powers)(self.raw, low.id, high.id, shape) };
        self.check(status)?;
        Ok((low, high))
    }
    pub(in crate::c71_matrix) fn pcs_source_begin(&mut self, low: &Buffer, high: &Buffer,
        shape: PcsSourceShape, with_histogram: bool) -> Result<([Buffer; 2], Option<Buffer>), String> {
        self.require_buffer(low)?; self.require_buffer(high)?;
        if shape.rows < 4 || shape.rows > 1 << 20 { return self.abort("native PCS source capacity differs"); }
        let values = [self.allocate_buffer(15, 256 * shape.rows as usize)?, self.allocate_buffer(15, 256 * shape.rows as usize)?];
        let histogram = if with_histogram { Some(self.allocate_buffer(16, 256)?) } else { None };
        let status = unsafe { (self.api.pcs_source_begin)(self.raw, values[0].id, values[1].id, low.id, high.id,
            histogram.as_ref().map_or(0, |h| h.id), shape) };
        self.check(status)?;
        Ok((values, histogram))
    }
    pub(in crate::c71_matrix) fn pcs_source_tile(&mut self, input: &Buffer, tile: PcsSourceTile) -> Result<(), String> {
        self.require_buffer(input)?;
        let status = unsafe { (self.api.pcs_source_tile)(self.raw, input.id, &tile) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_source_finish(&mut self, values: &mut [Buffer; 2], histogram: Option<&mut Buffer>,
        pads: &Buffer, twiddles: &Buffer) -> Result<(), String> {
        for input in [pads, twiddles, &values[0], &values[1]] { self.require_buffer(input)?; }
        if let Some(h) = histogram.as_ref() { self.require_buffer(h)?; }
        let status = unsafe { (self.api.pcs_source_finish)(self.raw, values[0].id, values[1].id,
            histogram.as_ref().map_or(0, |h| h.id), pads.id, twiddles.id) };
        self.check(status)?;
        for value in values { value.kind = 9; }
        if let Some(h) = histogram { h.kind = 6; }
        Ok(())
    }
    pub(in crate::c71_matrix) fn pcs_full_hash_begin(&mut self, rows: usize) -> Result<Buffer, String> {
        self.allocate_buffer(10, rows)
    }
    pub(in crate::c71_matrix) fn pcs_full_hash_band(&mut self, values: &[Buffer; 2], salts: &Buffer,
        states: &mut Buffer, first: usize) -> Result<(), String> {
        for input in [salts, states, &values[0], &values[1]] { self.require_buffer(input)?; }
        if salts.kind != 9 || salts.count % 4 != 0 { return self.abort("native PCS full leaf salt shape differs"); }
        let count = salts.count / 4;
        let status = unsafe { (self.api.pcs_full_leaves)(self.raw, values[0].id, values[1].id, salts.id, states.id, first as u64, count as u64) };
        self.check(status)?;
        if first.checked_add(count) == Some(states.count) { states.kind = 11; }
        Ok(())
    }
    pub(in crate::c71_matrix) fn pcs_hash_start(&mut self, ring: &Buffer) -> Result<Buffer, String> {
        self.require_buffer(ring)?;
        if ring.kind != 9 || ring.count % 8 != 0 {
            return self.abort("native PCS ring shape differs");
        }
        let count = ring.count / 8;
        let id = self.alloc(10, count)?;
        let status = unsafe { (self.api.pcs_start)(self.raw, ring.id, id) };
        self.check(status)?;
        Ok(Buffer { id, kind: 10, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pcs_hash_step(
        &mut self, ring: &Buffer, states: &Buffer, first_column: usize,
    ) -> Result<(), String> {
        self.require_buffer(ring)?;
        self.require_buffer(states)?;
        let Ok(first) = u32::try_from(first_column) else {
            return self.abort("native PCS column overflow");
        };
        let status = unsafe { (self.api.pcs_step)(self.raw, ring.id, states.id, first) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_hash_finish(
        &mut self, ring: &Buffer, salts: &Buffer, states: &mut Buffer, first_row: usize,
    ) -> Result<(), String> {
        self.require_buffer(ring)?;
        self.require_buffer(salts)?;
        self.require_buffer(states)?;
        if salts.kind != 9 || salts.count % 4 != 0 {
            return self.abort("native PCS salt band differs");
        }
        let count = salts.count / 4;
        let status = unsafe { (self.api.pcs_finish)(self.raw, ring.id, salts.id, states.id, first_row as u64, count as u64) };
        self.check(status)?;
        if first_row + count == states.count { states.kind = 11; }
        Ok(())
    }
    pub(in crate::c71_matrix) fn pcs_nodes(&mut self, input: &Buffer) -> Result<Buffer, String> {
        self.pcs_nodes_strided(input, 1)
    }
    pub(in crate::c71_matrix) fn pcs_nodes_strided(&mut self, input: &Buffer, rows: usize) -> Result<Buffer, String> {
        self.require_buffer(input)?;
        if input.kind != 11 || input.count < 2 || input.count % 2 != 0 {
            return self.abort("native PCS Merkle input differs");
        }
        let count = input.count / 2;
        let id = self.alloc(11, count)?;
        let status = unsafe { (self.api.pcs_nodes)(self.raw, input.id, id, rows as u64) };
        self.check(status)?;
        Ok(Buffer { id, kind: 11, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pcs_frontier(&mut self, rows: usize, groups: usize) -> Result<Buffer, String> {
        if !rows.is_power_of_two() || rows > 1 << 25 || !groups.is_power_of_two() || !(2..=4096).contains(&groups) {
            return self.abort("native PCS frontier geometry differs");
        }
        let count = rows * groups.ilog2() as usize;
        let id = self.alloc(12, count)?;
        let status = unsafe { (self.api.pcs_frontier)(self.raw, id, rows as u64, groups as u32) };
        self.check(status)?;
        Ok(Buffer { id, kind: 12, count, owner: self.owner.clone() })
    }
    pub(in crate::c71_matrix) fn pcs_merge_group(&mut self, frontier: &Buffer, roots: &Buffer, group: usize) -> Result<(), String> {
        self.require_buffer(frontier)?;
        self.require_buffer(roots)?;
        let Ok(group) = u32::try_from(group) else { return self.abort("native PCS group overflow"); };
        let status = unsafe { (self.api.pcs_merge)(self.raw, frontier.id, roots.id, group) };
        self.check(status)
    }
    pub(in crate::c71_matrix) fn pcs_digests(
        &mut self, input: &Buffer, first: usize, count: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.require_buffer(input)?;
        if input.kind != 11 || count == 0 || count > 1 << 21 || first > input.count || count > input.count - first {
            return self.abort("native PCS digest read differs");
        }
        let mut output = vec![[0; 32]; count];
        let status = unsafe { (self.api.pcs_read)(self.raw, input.id, first as u64, count as u64, output.as_mut_ptr().cast()) };
        self.check(status)?;
        Ok(output)
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
    fn c71_b12_native_residual_pcs_basis_is_distinct_and_canonical() {
        let v=E::new([Goldilocks::ZERO,Goldilocks::ONE,Goldilocks::ZERO]);
        assert_eq!(v*v*v,v+E::ONE);
        let field=PcsField::from(v);assert_eq!(field.limbs,[0,1,0]);assert_eq!(field.decode().unwrap(),v);
        let value=E::new([Goldilocks::new(3),Goldilocks::new(5),Goldilocks::new(7)]);
        assert_eq!(PcsField::from(value).decode().unwrap(),value);
        assert_ne!(PcsField::from(crate::c71_matrix::to_p3(Fp3::new(Fp::ZERO,Fp::ONE,Fp::ZERO))).limbs,[0,1,0]);
        for limb in 0..3 {let mut field=PcsField::from(value);field.limbs[limb]=volta_field::P;assert!(field.decode().is_err());}
    }
    fn residual_missing_symbols(symbols:&[&str]) {
        assert!(symbols.len()<=4);
        for symbol in symbols {
            let fixture=fixture_library(512,Some(symbol));assert!(Runtime::new(&fixture.config).is_err(),"{symbol}");
        }
    }
    #[test]
    fn c71_b12_native_residual_symbols_1() {
        residual_missing_symbols(&["c71_pcs_residual_begin","c71_pcs_residual_source_tile","c71_pcs_residual_weights","c71_pcs_residual_resident"]);
    }
    #[test]
    fn c71_b12_native_residual_symbols_2() {
        residual_missing_symbols(&["c71_pcs_residual_finish","c71_pcs_residual_fold","c71_pcs_residual_retire_planes","c71_pcs_residual_retire_ring"]);
    }
    #[test]
    fn c71_b12_native_residual_symbols_3() {
        residual_missing_symbols(&["c71_pcs_residual_final_read","c71_pcs_residual_contract_begin","c71_pcs_residual_contract_weights_band","c71_pcs_residual_contract_resident_band"]);
    }
    #[test]
    fn c71_b12_native_residual_symbols_4() {
        residual_missing_symbols(&["c71_pcs_residual_contract_finish","c71_pcs_short_leaves_private"]);
    }
    fn residual_fixture_packet(remaining:usize,point:&[E])->ResidualPacket {
        let tables=Poly::new_from_point(point,E::ONE).as_slice().iter().copied().map(PcsField::from).collect();
        ResidualPacket {shape:ResidualShape {live:8,dimension:3,remaining:remaining as u32,
            equality:ResidualEq {bits:point.len() as u32,chunks:1,entries:1<<point.len(),reserved:0}},
            chunks:vec![ResidualChunk {shift:0,bits:point.len() as u32,first:0,reserved:0}],tables}
    }
    #[test]
    fn c71_b12_native_residual_owner_coverage_private_tokens_and_faults() {
        let fixture=fixture(512);let injection=Injection::new(&fixture.config);
        for fault in 0..27 {
            let mut runtime=Runtime::new(&fixture.config).unwrap();
            let input=runtime.upload_signed(&[-32767,-1,0,1,32767,17,-13,9]).unwrap();
            let tile=PcsSourceTile {input_first:0,input_stride:1,rows:8,columns:1,original_first:0,
                byte_first:0,width:1,signed_width:2};
            let mut packet=residual_fixture_packet(2,&[E::ZERO,E::ONE]);
            let result:Result<(),String>=if fault<=6 {
                match fault {0=>packet.shape.equality.entries+=1,1=>packet.tables[0].limbs[2]=volta_field::P,
                    3=>injection.set(2),4=>packet.shape.equality.bits+=1,5=>injection.set(10),6=>injection.set(11),_=>()}
                if fault==2 {runtime.allocate_buffer(19,8).map(|_|())}
                else {runtime.residual_begin(&packet,ResidualPhase::Singleton,ResidualCosets::default(),&[],E::ZERO).map(|_|())}
            } else {
                let token=runtime.residual_begin(&packet,ResidualPhase::Singleton,ResidualCosets::default(),&[],E::ZERO).unwrap();
                match fault {
                    7=>runtime.residual_begin(&packet,ResidualPhase::Singleton,ResidualCosets::default(),&[],E::ZERO).map(|_|()),
                    8=>runtime.residual_source_tile(&ResidualToken {id:0,owner:token.owner.clone(),phase:token.phase,count:token.count},&input,tile),
                    9=>{let other=Runtime::new(&fixture.config).unwrap();runtime.residual_source_tile(&ResidualToken {id:token.id,owner:other.owner.clone(),phase:token.phase,count:token.count},&input,tile)},
                    10=>{let pending=runtime.allocate_buffer(1,8).unwrap();runtime.residual_source_tile(&token,&pending,tile)},
                    11=>{runtime.residual_source_tile(&token,&input,PcsSourceTile {rows:7,..tile}).unwrap();runtime.residual_finish(token).map(|_|())},
                    12=>{runtime.residual_source_tile(&token,&input,tile).unwrap();runtime.residual_source_tile(&token,&input,tile)},
                    13=>runtime.residual_source_tile(&token,&input,PcsSourceTile {original_first:8,..tile}),
                    14=>{let wrong=runtime.pcs_words(8).unwrap();runtime.residual_weights(&token,&wrong)},
                    15=>{injection.set(1);runtime.residual_source_tile(&token,&input,tile)},
                    16..=21=>{
                        if fault==16 {injection.set(9);}
                        runtime.residual_source_tile(&token,&input,tile).unwrap();
                        if fault!=16 {injection.set(match fault {17=>7,18=>8,19=>3,20=>4,21=>2,_=>unreachable!()});}
                        runtime.residual_finish(token).map(|_|())
                    },
                    22=>{let stale=ResidualToken {id:token.id,owner:token.owner.clone(),phase:token.phase,count:token.count};
                        runtime.residual_source_tile(&token,&input,tile).unwrap();runtime.residual_finish(token).unwrap();runtime.residual_finish(stale).map(|_|())},
                    23=>{let private=Buffer {id:token.id,kind:17,count:8,owner:token.owner.clone()};
                        let before=runtime.stats().unwrap().d2h_bytes;let result=runtime.download_bytes(&private,0,&mut [0;8]);
                        assert_eq!(runtime.stats().unwrap().d2h_bytes,before);result},
                    24=>runtime.release_buffer(Buffer {id:token.id,kind:17,count:8,owner:token.owner.clone()}),
                    25=>{let mut other=Runtime::new(&fixture.config).unwrap();let foreign=other.upload_signed(&[1;8]).unwrap();runtime.residual_source_tile(&token,&foreign,tile)},
                    26=>{let wrong=runtime.upload_table(&[0;8]).unwrap();runtime.residual_source_tile(&token,&wrong,tile)},
                    _=>unreachable!(),
                }
            };
            injection.set(0);assert!(result.is_err(),"residual fault {fault}");
            assert_eq!(runtime.stats().unwrap().stopped,1);assert!(runtime.pcs_words(1).is_err());
            if fault==19 {assert!(runtime.close().is_err());}else{runtime.close().unwrap();}
        }
        println!("C71_NATIVE_RESIDUAL_OWNER_FAILURE {{\"terminal_rejections\":27,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_residual_query_symbols_1() {
        residual_missing_symbols(&["c71_pcs_residual_query_begin","c71_pcs_residual_query_weights","c71_pcs_residual_query_resident"]);
    }
    #[test]
    fn c71_b12_native_residual_query_symbols_2() {
        residual_missing_symbols(&["c71_pcs_residual_query_root","c71_pcs_residual_query_finish"]);
    }
    #[test]
    fn c71_b12_native_residual_query_owner_final_values_and_faults() {
        let fixture=fixture(512);let injection=Injection::new(&fixture.config);
        for fault in 0..28 {
            let mut runtime=Runtime::new(&fixture.config).unwrap();
            let weights=Arc::new(vec![2i16,-3,5,-7,11,-13,17,-19]);runtime.install_weights(weights.clone(),[53;32]).unwrap();
            let tiles=runtime.pcs_weight_tiles(&weights,[53;32],&[WeightTile {first:0,count:8,packed_first:0,packed_stride:1,columns:1}]).unwrap();
            let mut packet=ResidualPacket {shape:ResidualShape {live:8,dimension:3,remaining:3,equality:ResidualEq::default()},chunks:vec![],tables:vec![]};
            let pads=[PcsField::from(E::ONE);4];
            let inverse=runtime.pcs_words(2).unwrap();runtime.pcs_upload(&inverse,0,&[1,1]).unwrap();
            let modulus=runtime.pcs_words(2).unwrap();runtime.pcs_upload(&modulus,0,&[1,volta_field::P-1]).unwrap();
            let forward=runtime.pcs_transform_twiddles(1,false).unwrap();let backward=runtime.pcs_transform_twiddles(1,true).unwrap();
            let work=runtime.pcs_words(2).unwrap();let scratch=runtime.pcs_words(2).unwrap();
            let remainders=[runtime.pcs_words(1).unwrap(),runtime.pcs_words(1).unwrap(),runtime.pcs_words(1).unwrap(),runtime.pcs_words(1).unwrap()];
            let mut current=[0,1,2];let mut spare=3;
            let block=PcsQueryBlock {first:2,source_rows:3,message_rows:2,active:2,byte_first:0,window_first:0,pad_first:0,pad_rows:1,pad_only:0};
            let result:Result<Vec<u64>,String>=if (1..=6).contains(&fault) {
                match fault {3=>injection.set(2),4=>packet.shape.remaining=1,5=>injection.set(10),6=>injection.set(11),_=>()}
                runtime.residual_query_begin(&packet,if fault==2 {&pads[..3]}else{&pads},if fault==1 {3}else{1},0).map(|_|Vec::new())
            } else {
                let token=runtime.residual_query_begin(&packet,&pads,1,0).unwrap();
                match fault {
                    7=>runtime.residual_query_begin(&packet,&pads,1,0).map(|_|Vec::new()),
                    8=>runtime.residual_query_weights(&ResidualQuery {id:0,owner:token.owner.clone(),capacity:1},&tiles,block).map(|_|Vec::new()),
                    9=>{let other=Runtime::new(&fixture.config).unwrap();runtime.residual_query_weights(&ResidualQuery {id:token.id,owner:other.owner.clone(),capacity:1},&tiles,block).map(|_|Vec::new())},
                    10=>runtime.residual_query_weights(&token,&inverse,block).map(|_|Vec::new()),
                    11=>runtime.residual_query_weights(&token,&tiles,PcsQueryBlock {first:0,..block}).map(|_|Vec::new()),
                    12=>runtime.residual_query_weights(&token,&tiles,PcsQueryBlock {active:1,..block}).map(|_|Vec::new()),
                    13=>runtime.residual_query_weights(&token,&tiles,PcsQueryBlock {byte_first:2,..block}).map(|_|Vec::new()),
                    14=>{runtime.residual_query_weights(&token,&tiles,block).unwrap();runtime.residual_query_weights(&token,&tiles,block).map(|_|Vec::new())},
                    15=>{let private=Buffer {id:token.id,kind:17,count:1,owner:token.owner.clone()};let before=runtime.stats().unwrap().d2h_bytes;
                        let result=runtime.download_bytes(&private,0,&mut [0;8]).map(|_|Vec::new());assert_eq!(runtime.stats().unwrap().d2h_bytes,before);result},
                    16=>{injection.set(1);runtime.residual_query_weights(&token,&tiles,block).map(|_|Vec::new())},
                    _=>{
                        if fault==17 {injection.set(9);}
                        let mut error=None;
                        for b in (0..3).rev() {
                            runtime.residual_query_weights(&token,&tiles,PcsQueryBlock {first:b,..block}).unwrap();
                            for limb in 0..3 {
                                if fault==18 && b==2 && limb==0 {injection.set(5);}
                                let high=(b!=2).then_some(&remainders[current[limb]]);
                                let high=if fault==19 && b==1 && limb==0 {None}else{high};
                                let operation=runtime.residual_query_root(&token,if fault==20 && b==2 && limb==1 {0}else{limb},high,
                                    &inverse,&modulus,&forward,&backward,&work,&scratch,&remainders[spare]);
                                if let Err(failure)=operation {error=Some(failure);break;}
                                std::mem::swap(&mut current[limb],&mut spare);
                            }
                            if error.is_some(){break;}
                        }
                        if let Some(error)=error {Err(error)}else{
                            if (21..=24).contains(&fault){injection.set([7,8,3,4][fault-21]);}
                            if fault==27 {injection.set(12);}
                            let finals=if fault==25 {[&remainders[current[0]];3]}else{current.map(|i|&remainders[i])};
                            runtime.residual_query_finish(token,finals,if fault==26 {0}else{1})
                        }
                    }
                }
            };
            injection.set(0);
            if fault==0 {
                assert_eq!(result.unwrap(),[2,0,0]);
                for buffer in remainders {runtime.release_buffer(buffer).unwrap();}
                for buffer in [inverse,modulus,forward,backward,work,scratch,tiles]{runtime.release_buffer(buffer).unwrap();}
                let stats=runtime.stats().unwrap();assert_eq!(stats.d2h_bytes,28);assert_eq!(stats.arena_bytes,0);
            } else {assert!(result.is_err(),"query E fault {fault}");assert_eq!(runtime.stats().unwrap().stopped,1);assert!(runtime.pcs_words(1).is_err());}
            if fault==23 {assert!(runtime.close().is_err());}else{runtime.close().unwrap();}
        }
        println!("C71_NATIVE_QUERY_E_OWNER_FAILURE {{\"terminal_rejections\":27,\"canonical_decode_rejection\":true,\"gpu_execution\":false,\"credit\":false}}");
    }

    fn linear_fixture_packet() -> LinearPacket {
        LinearPacket {shape:LinearShape {live:8,dimension:3,remaining:3,chunks:0,groups:1,intervals:1,points:2},
            chunks:vec![],tables:vec![],groups:vec![LinearGroup {bits:2,first:0,count:1,reserved:0}],
            intervals:vec![LinearInterval {index:0,first:0,bits:2,
                lower:Fp3::ONE.into(),upper:Fp3::new(Fp::new(2),Fp::new(3),Fp::new(5)).into()}],
            points:vec![Fp3::ZERO.into(),Fp3::new(Fp::new(7),Fp::new(11),Fp::new(13)).into()]}
    }
    #[test]
    fn c71_b12_native_linear_owner_token_coverage_and_fail_closed() {
        let fixture=fixture(512); let injection=Injection::new(&fixture.config);
        for fault in 0..30 {
            let mut runtime=Runtime::new(&fixture.config).unwrap();
            let weights=Arc::new(vec![1i16;8]); runtime.install_weights(weights.clone(),[17;32]).unwrap();
            let sealed=runtime.pcs_weight_tiles(&weights,[17;32],&[WeightTile {
                first:0,count:8,packed_first:0,packed_stride:1,columns:1}]).unwrap();
            let input=runtime.upload_signed(&[-32767,0,1,32767]).unwrap();
            let tile=PcsSourceTile {input_first:0,input_stride:2,rows:2,columns:2,
                original_first:0,byte_first:0,width:2,signed_width:2};
            let mut packet=linear_fixture_packet();
            let result:Result<(),String>=if fault<=5 || fault==27 {
                match fault {
                    0=>packet.shape.points+=1,
                    1=>packet.points[0].limbs[0]=volta_field::P,
                    3=>injection.set(2),4=>injection.set(10),5=>injection.set(11),
                    27=>packet.shape.remaining=2,
                    _=>(),
                }
                if fault==2 {runtime.allocate_buffer(18,1).map(|_|())}
                else {runtime.linear_begin(&packet).map(|_|())}
            } else {
                let token=runtime.linear_begin(&packet).unwrap();
                match fault {
                    6=>runtime.linear_begin(&packet).map(|_|()),
                    7=>runtime.linear_source_tile(&LinearToken {id:0,owner:runtime.owner.clone()},&input,tile),
                    8=>{
                        let other=Runtime::new(&fixture.config).unwrap();
                        runtime.linear_source_tile(&LinearToken {id:token.id,owner:other.owner.clone()},&input,tile)
                    },
                    9=>{
                        let mut other=Runtime::new(&fixture.config).unwrap();
                        let foreign=other.upload_signed(&[1;4]).unwrap();
                        runtime.linear_source_tile(&token,&foreign,tile)
                    },
                    10=>{let pending=runtime.allocate_buffer(1,4).unwrap();runtime.linear_source_tile(&token,&pending,tile)},
                    11=>{let bytes=runtime.upload_table(&[1;4]).unwrap();runtime.linear_source_tile(&token,&bytes,tile)},
                    12=>{
                        runtime.linear_source_tile(&token,&input,PcsSourceTile {rows:1,..tile}).unwrap();
                        runtime.linear_finish(token).map(|_|())
                    },
                    13=>{
                        runtime.linear_source_tile(&token,&input,tile).unwrap();
                        runtime.linear_source_tile(&token,&input,tile)
                    },
                    14=>runtime.linear_source_tile(&token,&input,PcsSourceTile {original_first:8,..tile}),
                    15=>{let wrong=runtime.pcs_words(8).unwrap();runtime.linear_weights(&token,&wrong)},
                    16=>{runtime.linear_weights(&token,&sealed).unwrap();runtime.linear_weights(&token,&sealed)},
                    17=>{runtime.linear_source_tile(&token,&input,tile).unwrap();runtime.linear_weights(&token,&sealed)},
                    18=>{injection.set(1);runtime.linear_source_tile(&token,&input,tile)},
                    19..=24=>{
                        if fault==19 {injection.set(9);}
                        runtime.linear_source_tile(&token,&input,tile).unwrap();
                        if fault!=19 {injection.set(match fault {20=>7,21=>8,22=>3,23=>4,24=>2,_=>unreachable!()});}
                        runtime.linear_finish(token).map(|_|())
                    },
                    25=>{
                        let stale=LinearToken {id:token.id,owner:token.owner.clone()};
                        runtime.linear_source_tile(&token,&input,tile).unwrap();runtime.linear_finish(token).unwrap();
                        runtime.linear_finish(stale).map(|_|())
                    },
                    26=>runtime.require_weights(&Arc::new(vec![1i16;8]),[17;32]),
                    28=>{
                        let private=Buffer {id:token.id,kind:18,count:1,owner:runtime.owner.clone()};
                        let before=runtime.stats().unwrap().d2h_bytes;
                        let result=runtime.download_bytes(&private,0,&mut [0;8]);
                        assert_eq!(runtime.stats().unwrap().d2h_bytes,before); result
                    },
                    29=>{
                        let private=Buffer {id:token.id,kind:18,count:1,owner:runtime.owner.clone()};
                        runtime.release_buffer(private)
                    },
                    _=>unreachable!(),
                }
            };
            injection.set(0);
            assert!(result.is_err(),"linear owner fault {fault}");
            assert_eq!(runtime.stats().unwrap().stopped,1);assert!(runtime.pcs_words(1).is_err());
            let closed=runtime.close();
            if fault==22 {assert!(closed.is_err());} else {closed.unwrap();}
        }
        println!("C71_NATIVE_LINEAR_OWNER_FAILURE {{\"terminal_rejections\":30,\"gpu_execution\":false,\"credit\":false}}");
    }
    #[test]
    fn c71_b12_native_linear_symbols_are_required() {
        for symbol in ["c71_linear_begin","c71_linear_source_tile","c71_linear_weights","c71_linear_finish"] {
            let fixture=fixture_library(512,Some(symbol));
            assert!(Runtime::new(&fixture.config).is_err(),"missing linear symbol {symbol}");
        }
    }
    #[test]
    fn c71_b12_native_transform_natural_forward_inverse_and_work() {
        use p3_dft::{Radix2DFTSmallBatch,TwoAdicSubgroupDft};
        use p3_field::PrimeField64;
        use p3_goldilocks::Goldilocks;
        let mut fixture=fixture(512); fixture.config.arena_bytes=16<<20;
        let weights=Arc::new(Vec::new());
        let _budget=crate::c71_matrix::census::Budget::new(&weights).unwrap();
        let mut runtime=Runtime::new(&fixture.config).unwrap();
        let dft=Radix2DFTSmallBatch::<Goldilocks>::default();
        let cases=(1..=10).flat_map(|log| [1usize,3,4].map(move |batch|(log,batch)))
            .chain([(3,32767),(3,32768),(3,65530),(3,65536),(16,3),(17,3)]);
        for (log,batch) in cases {
            let rows=1usize<<log;
                let original: Vec<u64>=(0..rows*batch).map(|i| match i%5 {
                    0=>0,1=>1,2=>Goldilocks::ORDER_U64-1,_=>(i*1237+19) as u64 }).collect();
                let values=runtime.pcs_words(original.len()).unwrap();
                runtime.pcs_upload(&values,0,&original).unwrap();
                let scratch=runtime.pcs_words(original.len()).unwrap();
                let forward=runtime.pcs_transform_twiddles(log,false).unwrap();
                let inverse=runtime.pcs_transform_twiddles(log,true).unwrap();
                let before=runtime.stats().unwrap();
                let started=std::time::Instant::now();
                runtime.pcs_transform(&values,&scratch,&forward,log,batch,false).unwrap();
                let mut actual=vec![0;original.len()];
                runtime.pcs_download_words(&values,0,&mut actual).unwrap();
                let forward_s=started.elapsed().as_secs_f64();
                let expected: Vec<_>=original.chunks_exact(rows).flat_map(|c|
                    dft.dft(c.iter().copied().map(Goldilocks::new).collect()).into_iter()
                        .map(|x| x.as_canonical_u64())).collect();
                assert_eq!(actual,expected,"forward log {log} batch {batch}");
                let started=std::time::Instant::now();
                runtime.pcs_transform(&values,&scratch,&inverse,log,batch,true).unwrap();
                runtime.pcs_download_words(&values,0,&mut actual).unwrap();
                let inverse_s=started.elapsed().as_secs_f64();
                assert_eq!(actual,original,"roundtrip log {log} batch {batch}");
                let after=runtime.stats().unwrap();
                assert_eq!(after.h2d_bytes,before.h2d_bytes);
                assert_eq!(after.d2h_bytes-before.d2h_bytes,(16*original.len()) as u64);
                assert_eq!(after.fences-before.fences,2);
                let launches=(if log==1 {1} else if log%2==0 {5} else {6})*batch.div_ceil(32767)
                    + usize::from(log%2!=0 && log>1);
                assert_eq!(after.launches-before.launches,(2*launches) as u64);
                assert_eq!(after.d2d_bytes-before.d2d_bytes,if log%2!=0 && log>1 {(16*original.len()) as u64} else {0});
                for buffer in [values,scratch,forward,inverse] { runtime.release_buffer(buffer).unwrap(); }
                if batch>4 || log>10 { println!("C71_NATIVE_TRANSFORM_BENCH {}",serde_json::json!({
                    "log_length":log,"batch":batch,"forward_owner_host_s":forward_s,"inverse_owner_host_s":inverse_s,
                    "launches_per_transform":launches,"gpu_execution":false,"credit":false})); }
        }
        let stats=runtime.close().unwrap(); assert_eq!(stats.arena_bytes,0);
        println!("C71_NATIVE_TRANSFORM {}",serde_json::json!({"cases":36,"log_lengths":[1,17],
            "natural_forward_and_inverse":true,"host_owner_bytes":stats.host_owner_bytes,
            "capacity_peak_bytes":stats.peak_capacity_bytes,"census":crate::c71_matrix::census::simultaneous(),
            "gpu_execution":false,"credit":false}));
    }

    #[test]
    fn c71_b12_native_transform_rejections_and_fail_closed() {
        let fixture=fixture(512); let injection=Injection::new(&fixture.config);
        for fault in 0..18 {
            let mut runtime=Runtime::new(&fixture.config).unwrap();
            let values=runtime.pcs_words(8).unwrap();
            if fault!=7 { runtime.pcs_upload(&values,0,&[1;8]).unwrap(); }
            let scratch=runtime.pcs_words(if fault==4 {4} else {8}).unwrap();
            let twiddles=runtime.pcs_transform_twiddles(3,fault==5).unwrap();
            let result=match fault {
                0=>runtime.pcs_transform_twiddles(0,false).map(|_|()),
                1=>runtime.pcs_transform_twiddles(25,false).map(|_|()),
                2=>runtime.pcs_transform(&values,&scratch,&twiddles,3,0,false),
                3=>runtime.pcs_transform(&values,&scratch,&twiddles,25,1,false),
                4..=5|7=>runtime.pcs_transform(&values,&scratch,&twiddles,3,1,false),
                6=>runtime.pcs_transform(&values,&values,&twiddles,3,1,false),
                8=>runtime.pcs_transform(&twiddles,&scratch,&twiddles,3,1,false),
                9=>runtime.pcs_download_words(&twiddles,0,&mut[0]),
                10=>runtime.pcs_download_words(&values,8,&mut[0]),
                11=>runtime.pcs_download_words(&values,0,&mut[]),
                12=>{
                    let status=unsafe{(runtime.api.pcs_words_read)(runtime.raw,values.id,0,(1<<20)+1,&mut 0)};
                    runtime.check(status)
                },
                13=>{ injection.set(1); runtime.pcs_transform(&values,&scratch,&twiddles,3,1,false) },
                14..=15=>{
                    runtime.pcs_transform(&values,&scratch,&twiddles,3,1,false).unwrap();
                    injection.set(if fault==14 {2} else {4});
                    runtime.pcs_download_words(&values,0,&mut[0;8])
                },
                16=>{
                    let mut other=Runtime::new(&fixture.config).unwrap();
                    let foreign=other.pcs_words(8).unwrap();
                    runtime.pcs_transform(&values,&foreign,&twiddles,3,1,false)
                },
                17=>runtime.pcs_transform(&values,&scratch,&twiddles,3,2,false),
                _=>unreachable!(),
            };
            assert!(result.is_err(),"fault {fault}"); injection.set(0);
            assert_eq!(runtime.stats().unwrap().stopped,1); assert!(runtime.pcs_words(1).is_err());
            runtime.close().unwrap();
        }
        println!("C71_NATIVE_TRANSFORM_FAILURE {{\"terminal_rejections\":18,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_transform_symbols_are_mandatory() {
        for symbol in ["c71_pcs_transform_twiddles","c71_pcs_transform","c71_pcs_read_words"] {
            let legacy=fixture_library(512,Some(symbol));
            let error=Runtime::new(&legacy.config).err().unwrap(); assert!(error.contains(symbol),"{error}");
        }
    }

    #[test]
    fn c71_b12_native_weight_query_symbol_is_mandatory() {
        let legacy=fixture_library(512,Some("c71_pcs_query_weight_low"));
        let error=Runtime::new(&legacy.config).err().unwrap();
        assert!(error.contains("c71_pcs_query_weight_low"),"{error}");
    }

    #[test]
    fn c71_b12_native_query_private_phase_read_and_mandatory_symbols() {
        for symbol in ["c71_pcs_query_low","c71_pcs_query_remainder","c71_pcs_query_shift","c71_pcs_query_add"] {
            let legacy=fixture_library(512,Some(symbol));
            let error=Runtime::new(&legacy.config).err().unwrap(); assert!(error.contains(symbol),"{error}");
        }
        let fixture=fixture(512);
        let weights=Arc::new(Vec::new());
        let _budget=crate::c71_matrix::census::Budget::new(&weights).unwrap();
        let mut runtime=Runtime::new(&fixture.config).unwrap();
        let values=runtime.pcs_words(4).unwrap(); runtime.pcs_upload(&values,0,&[1,2,3,4]).unwrap();
        let (_,private)=runtime.pcs_salts_prepare(&[31;32],SaltGeometry { rows:4,origin:0,cosets:4,cut:4 },
            4,&mut [0;4],&mut [0;4]).unwrap();
        let before=runtime.stats().unwrap();
        let mut words=[73;4];
        assert!(runtime.pcs_download_words(&values,0,&mut words).is_err());
        assert_eq!(words,[73;4]);
        let after=runtime.stats().unwrap();
        assert_eq!(after.d2h_bytes,before.d2h_bytes);
        assert_eq!(after.launches,before.launches); assert_eq!(after.fences,before.fences);
        assert_eq!(after.stopped,1);
        drop(private); runtime.close().unwrap();
    }

    #[test]
    fn c71_b12_native_query_rejections_and_fail_closed() {
        let fixture=fixture(512); let injection=Injection::new(&fixture.config);
        let weights=Arc::new(Vec::new());
        let _budget=crate::c71_matrix::census::Budget::new(&weights).unwrap();
        for fault in 0..25 {
            let mut runtime=Runtime::new(&fixture.config).unwrap();
            let bytes=runtime.upload_table(&[3;8]).unwrap();
            let pads=runtime.pcs_words(4).unwrap(); runtime.pcs_upload(&pads,0,&[1;4]).unwrap();
            let high=runtime.pcs_words(4).unwrap();
            if fault!=15 { runtime.pcs_upload(&high,0,&[1;4]).unwrap(); }
            let low=runtime.pcs_words(4).unwrap(); runtime.pcs_upload(&low,0,&[1;4]).unwrap();
            let inverse=runtime.pcs_words(8).unwrap(); runtime.pcs_upload(&inverse,0,&[1;8]).unwrap();
            let modulus=runtime.pcs_words(8).unwrap(); runtime.pcs_upload(&modulus,0,&[2;8]).unwrap();
            let forward=runtime.pcs_transform_twiddles(3,false).unwrap();
            let backward=runtime.pcs_transform_twiddles(3,true).unwrap();
            let work=runtime.pcs_words(8).unwrap(); let scratch=runtime.pcs_words(8).unwrap();
            let output=runtime.pcs_words(4).unwrap();
            let block=PcsQueryBlock { first:0,source_rows:12,message_rows:8,active:8,byte_first:0,
                window_first:0,pad_first:0,pad_rows:4,pad_only:0 };
            let result=match fault {
                0=>runtime.pcs_query_low(None,&pads,&low,block),
                1=>{ let pending=runtime.byte_window(8).unwrap(); runtime.pcs_query_low(Some(&pending),&pads,&low,block) },
                2=>runtime.pcs_query_low(Some(&bytes),&pads,&low,PcsQueryBlock { window_first:1,..block }),
                3=>runtime.pcs_query_low(Some(&bytes),&pads,&low,PcsQueryBlock { source_rows:9,..block }),
                4=>runtime.pcs_query_low(Some(&bytes),&pads,&low,PcsQueryBlock { pad_only:2,..block }),
                5=>runtime.pcs_query_low(Some(&bytes),&pads,&low,PcsQueryBlock { pad_rows:0,..block }),
                6=>runtime.pcs_query_low(Some(&bytes),&pads,&low,PcsQueryBlock { pad_first:1,..block }),
                7=>runtime.pcs_query_low(Some(&high),&pads,&low,block),
                8=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,0,false),
                9=>runtime.pcs_query_remainder(&high,&high,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,4,true),
                10=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,2,false),
                11=>runtime.pcs_query_remainder(&high,&low,&pads,&modulus,&forward,&backward,&work,&scratch,&output,4,false),
                12=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&high,4,false),
                13=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&work,&output,4,false),
                14=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&backward,&forward,&work,&scratch,&output,4,false),
                15=>runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,4,false),
                16=>{
                    let mut other=Runtime::new(&fixture.config).unwrap(); let foreign=other.pcs_words(4).unwrap();
                    runtime.pcs_query_remainder(&foreign,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,4,false)
                },
                17..=21=>{
                    if fault==17 { injection.set(1); }
                    let submitted=runtime.pcs_query_remainder(&high,&low,&inverse,&modulus,&forward,&backward,&work,&scratch,&output,4,false);
                    if fault==17 { submitted } else {
                        submitted.unwrap();
                        injection.set(match fault { 18=>2,19=>7,20=>3,21=>4,_=>unreachable!() });
                        if fault==20 { runtime.release_buffer(output) }
                        else { runtime.pcs_download_words(&output,0,&mut [0;4]) }
                    }
                },
                22=>runtime.pcs_query_shift(&high,&modulus,&forward,&backward,&work,&work,&low,&output),
                23=>runtime.pcs_query_shift(&high,&modulus,&forward,&backward,&work,&scratch,&low,&low),
                24=>runtime.pcs_query_add(&high,&high),
                _=>unreachable!(),
            };
            assert!(result.is_err(),"query fault {fault}"); injection.set(0);
            assert_eq!(runtime.stats().unwrap().stopped,1); assert!(runtime.pcs_words(1).is_err());
            let closed=runtime.close();
            if fault==20 { assert!(closed.is_err()); } else { closed.unwrap(); }
        }
        println!("C71_NATIVE_QUERY_FAILURE {{\"terminal_rejections\":25,\"gpu_execution\":false,\"credit\":false}}");
    }

    fn salt_values(runtime: &mut Runtime, rows: usize, column: usize, count: usize, bias: u64) -> Buffer {
        let values = runtime.pcs_words(rows * count).unwrap();
        let words: Vec<_> = (0..rows * count).map(|i| ((column + i / rows) * 17) as u64 + bias).collect();
        runtime.pcs_upload(&values, 0, &words).unwrap();
        values
    }
    fn private_w_prefix(runtime: &mut Runtime, rows: usize, bias: u64) -> (Buffer, Buffer) {
        let ring = runtime.pcs_words(8 * rows).unwrap();
        let put = |runtime: &mut Runtime, column: usize, slots: usize| {
            let words: Vec<_> = (0..4 * rows).map(|i| ((column + i / rows) * 17) as u64 + bias).collect();
            runtime.pcs_upload(&ring, slots * rows, &words).unwrap();
        };
        put(runtime, 0, 0); put(runtime, 4, 4);
        let state = runtime.pcs_hash_start(&ring).unwrap();
        for first in (4..=116).step_by(8) {
            put(runtime, first + 4, 0); runtime.pcs_hash_step(&ring, &state, first).unwrap();
            if first < 116 { put(runtime, first + 8, 4); }
        }
        put(runtime, 124, 0);
        (ring, state)
    }
    #[test]
    fn c71_b12_native_private_salts_owner_exact_stream_hash_and_work() {
        use std::time::Instant;
        let mut fixture = fixture(512); fixture.config.arena_bytes = 16 << 20;
        for (case, (rows, cosets, group, origin)) in [
            (16usize, 32usize, 4usize, 7u64),
            (4, 64, 32, 32),
            (4096, 32, 32, 63),
            (4, 32, 32, (1u64 << 40) - 8 * 4 * 4 * 32),
        ].into_iter().enumerate() {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let height = rows * cosets;
            let seed = [case as u8 + 23; 32];
            let mut hash = blake3::Hasher::new();
            hash.update(b"volta-zk/c71/b12/private-coins/v1\0"); hash.update(&seed);
            let mut reader = hash.finalize_xof(); reader.set_position(origin);
            let mut expected_starts = vec![0; rows];
            let mut expected_offsets = vec![0; height / cosets];
            let mut expected_ends = vec![0; rows];
            let mut samples = Vec::with_capacity(4 * height);
            for leaf in 0..height {
                if leaf % cosets == 0 { expected_starts[leaf / cosets] = reader.position(); }
                if leaf % cosets == 0 { expected_offsets[leaf / cosets] = reader.position(); }
                for _ in 0..4 {
                    loop {
                        let mut bytes = [0; 8]; reader.fill(&mut bytes);
                        let candidate = u64::from_le_bytes(bytes);
                        if candidate < 0xffffffff00000001 { samples.push(candidate); break; }
                    }
                }
                if (leaf + 1) % cosets == 0 { expected_ends[leaf / cosets] = reader.position(); }
            }
            let mut starts = vec![0; rows]; let mut offsets = vec![0; height / cosets];
            let geometry = SaltGeometry { rows: rows as u64, origin, cosets: cosets as u32, cut: cosets as u32 };
            let prepared = Instant::now();
            let (end, private) = runtime.pcs_salts_prepare(&seed, geometry, group as u32, &mut starts, &mut offsets).unwrap();
            let prescan_s = prepared.elapsed().as_secs_f64();
            assert_eq!(end, reader.position()); assert_eq!(starts, expected_starts); assert_eq!(offsets, expected_offsets);
            let before = runtime.stats().unwrap();
            let mut leaves = Vec::new(); let mut hash_fences = 0;
            let hashed = Instant::now();
            for g in 0..cosets / group {
                let count = rows * group;
                let mut states;
                if group == 4 {
                    let values = [salt_values(&mut runtime, count, 0, 64, case as u64),
                        salt_values(&mut runtime, count, 64, 64, case as u64)];
                    states = runtime.pcs_full_hash_begin(count).unwrap();
                    let band_before = runtime.stats().unwrap();
                    for first in (0..count).step_by(count.min(65536)) {
                        let done = runtime.pcs_private_full_hash_band(&private, &values, &mut states, g, first).unwrap();
                        assert_eq!(done == 0, g == 0 && first + count.min(65536) < count);
                    }
                    hash_fences += runtime.stats().unwrap().fences - band_before.fences;
                    for v in values { runtime.release_buffer(v).unwrap(); }
                } else {
                    let (ring, state) = private_w_prefix(&mut runtime, count, case as u64);
                    states = state;
                    let band_before = runtime.stats().unwrap();
                    for first in (0..count).step_by(count.min(65536)) {
                        let done = runtime.pcs_private_hash_finish(&private, &ring, &mut states, g, first).unwrap();
                        assert_eq!(done == 0, g == 0 && first + count.min(65536) < count);
                    }
                    hash_fences += runtime.stats().unwrap().fences - band_before.fences;
                    runtime.release_buffer(ring).unwrap();
                }
                leaves.push(states);
            }
            let replay_bytes = runtime.pcs_salts_complete(private, &mut starts).unwrap();
            assert_eq!(starts, expected_ends); assert_eq!(replay_bytes, end - origin);
            assert_eq!(hash_fences, (cosets / group) as u64);
            let hash_s = hashed.elapsed().as_secs_f64();
            let mut prefix = blake3::Hasher::new(); prefix.update(b"volta-zk/c71/b12/merkle/leaf/v1\0");
            for col in 0..128 { prefix.update(&(col * 17 + case as u64).to_le_bytes()); }
            for (g, buffer) in leaves.into_iter().enumerate() {
                let actual = runtime.pcs_digests(&buffer, 0, rows * group).unwrap();
                for (local, digest) in actual.into_iter().enumerate() {
                    let natural = (local % rows) * cosets + g * group + local / rows;
                    let mut expected = prefix.clone();
                    for value in &samples[4 * natural..4 * natural + 4] { expected.update(&value.to_le_bytes()); }
                    assert_eq!(digest, *expected.finalize().as_bytes(), "case {case} group {g} leaf {local}");
                }
                runtime.release_buffer(buffer).unwrap();
            }
            let after = runtime.stats().unwrap();
            assert_eq!(after.arena_bytes, 0);
            println!("C71_PRIVATE_SALTS_OWNER {}", serde_json::json!({"case":case,"rows":rows,"cosets":cosets,
                "group_cosets":group,"leaves":height,"candidate_bytes":replay_bytes,"prescan_host_s":prescan_s,
                "hash_replay_host_s":hash_s,"hash_bands":(height/count_band(rows*group)),"hash_fences":hash_fences,
                "native_peak_capacity_bytes":after.peak_capacity_bytes,"host_owner_bytes":after.host_owner_bytes,
                "native_h2d_bytes_after_prescan":after.h2d_bytes-before.h2d_bytes,
                "native_d2h_bytes_after_prescan":after.d2h_bytes-before.d2h_bytes,
                "reference_samples_capacity_bytes":samples.capacity()*8,"host_indices_capacity_bytes":
                    8*(starts.capacity()+offsets.capacity()+expected_starts.capacity()+expected_offsets.capacity()+expected_ends.capacity()),
                "salt_band_uploads":0,"gpu_execution":false,"credit":false}));
            runtime.close().unwrap();
        }
        fn count_band(rows: usize) -> usize { rows.min(65536) }
    }

    #[test]
    fn c71_b12_native_private_salts_owner_rejections_and_fail_closed() {
        let fixture = fixture(512); let injection = Injection::new(&fixture.config);
        for fault in 0..24 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let mut starts = [0; 4]; let mut offsets = [0; 4];
            let mut geometry = SaltGeometry { rows:4,origin:32,cosets:8,cut:8 };
            if fault == 0 { geometry.rows=3; }
            if fault == 1 { geometry.cosets=3; }
            if fault == 2 { geometry.cut=4; }
            if fault == 3 { geometry.origin=(1 << 40)-8; }
            if (4..=7).contains(&fault) { injection.set([1,2,4,9][fault-4]); }
            let prepared = runtime.pcs_salts_prepare(&[31;32], geometry, 4, &mut starts,
                if fault == 8 { &mut offsets[..3] } else { &mut offsets });
            let result = if fault <= 8 { prepared.map(|_| ()) } else {
                let (_, private) = prepared.unwrap();
                let values = [salt_values(&mut runtime, 16, 0, 64, 1), salt_values(&mut runtime, 16, 64, 64, 1)];
                let mut states = runtime.pcs_full_hash_begin(16).unwrap();
                match fault {
                    9 => runtime.pcs_salts_prepare(&[31;32],geometry,4,&mut starts,&mut offsets).map(|_| ()),
                    10 => runtime.pcs_salts_complete(private,&mut starts).map(|_| ()),
                    11 => runtime.pcs_private_full_hash_band(&private,&values,&mut states,1,0).map(|_| ()),
                    12 => runtime.pcs_private_full_hash_band(&private,&values,&mut states,0,1).map(|_| ()),
                    13 => runtime.pcs_digests(&states,0,1).map(|_| ()),
                    14..=16 => {
                        let fake = Buffer { id:private.id,kind:if fault==14 {6} else {9},count:1,owner:runtime.owner.clone() };
                        if fault==14 { runtime.download_words(&fake,0,&mut [0]).map(|_| ()) }
                        else if fault==15 { runtime.pcs_upload(&fake,0,&[1]) }
                        else { runtime.release_buffer(fake) }
                    },
                    17 => runtime.allocate_buffer(17,8).map(|_| ()),
                    18 => {
                        let mut other=Runtime::new(&fixture.config).unwrap();
                        other.pcs_private_full_hash_band(&private,&values,&mut states,0,0).map(|_| ())
                    },
                    19 => {
                        runtime.pcs_private_full_hash_band(&private,&values,&mut states,0,0).unwrap();
                        runtime.pcs_private_full_hash_band(&private,&values,&mut states,0,0).map(|_| ())
                    },
                    20..=23 => {
                        injection.set([1,2,3,9][fault-20]);
                        runtime.pcs_private_full_hash_band(&private,&values,&mut states,0,0).map(|_| ())
                    },
                    _ => unreachable!(),
                }
            };
            assert!(result.is_err(),"fault {fault}");
            injection.set(0);
            if fault != 18 {
                assert!(runtime.pcs_words(1).is_err(),"ordinary retry accepted fault {fault}");
                assert_eq!(runtime.stats().unwrap().stopped,1);
            }
            if fault==22 { assert!(runtime.close().is_err()); } else { runtime.close().unwrap(); }
        }
        println!("C71_PRIVATE_SALTS_FAILURE {{\"terminal_rejections\":24,\"generic_private_reads\":0,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_private_salts_owner_metadata_alias_and_stale_capability() {
        let fixture = fixture(512);
        let geometry = SaltGeometry { rows:4,origin:32,cosets:8,cut:8 };
        for fault in 0..7 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let mut indices = [0u64; 8];
            let mut consumed = 0;
            let status = if fault < 3 {
                let mut id = 0; let mut progress = SaltProgress::default();
                let begin = unsafe { (runtime.api.salts_begin)(runtime.raw,[31u8;32].as_ptr(),geometry,4,128,&mut id) };
                runtime.check(begin).unwrap();
                let scan = unsafe { (runtime.api.salts_prescan)(runtime.raw,id,&mut progress) };
                runtime.check(scan).unwrap(); assert_eq!(progress.complete,1);
                let starts = match fault {
                    1 => indices.as_mut_ptr().cast::<u8>().wrapping_add(1).cast(),
                    2 => (usize::MAX - 7) as *mut u64,
                    _ => indices.as_mut_ptr(),
                };
                let offsets = if fault==0 { indices.as_mut_ptr().wrapping_add(1) }
                    else { indices.as_mut_ptr().wrapping_add(4) };
                unsafe { (runtime.api.salts_indices)(runtime.raw,id,starts,4,offsets,4) }
            } else {
                let (starts, offsets) = indices.split_at_mut(4);
                let (_, private) = runtime.pcs_salts_prepare(&[31;32],geometry,4,starts,offsets).unwrap();
                let values = [salt_values(&mut runtime,16,0,64,1),salt_values(&mut runtime,16,64,64,1)];
                for group in 0..2 {
                    let mut states = runtime.pcs_full_hash_begin(16).unwrap();
                    runtime.pcs_private_full_hash_band(&private,&values,&mut states,group,0).unwrap();
                    runtime.release_buffer(states).unwrap();
                }
                let id = private.id;
                if fault==6 {
                    runtime.pcs_salts_complete(private,starts).unwrap();
                    let (_, _fresh) = runtime.pcs_salts_prepare(&[32;32],geometry,4,starts,offsets).unwrap();
                    assert_ne!(id,_fresh.id);
                    unsafe { (runtime.api.salts_prescan)(runtime.raw,id,&mut SaltProgress::default()) }
                } else {
                    let current = match fault {
                        4 => starts.as_mut_ptr().cast::<u8>().wrapping_add(1).cast(),
                        5 => (usize::MAX - 7) as *mut u64,
                        _ => starts.as_mut_ptr(),
                    };
                    let output = if fault==3 { starts.as_mut_ptr().wrapping_add(1) } else { &mut consumed };
                    unsafe { (runtime.api.salts_complete)(runtime.raw,id,current,4,output) }
                }
            };
            assert!(runtime.check(status).is_err(),"fault {fault}");
            assert!(runtime.pcs_words(1).is_err()); assert_eq!(runtime.stats().unwrap().stopped,1);
            runtime.close().unwrap();
        }
        println!("C71_PRIVATE_SALTS_METADATA_FAILURE {{\"terminal_rejections\":7,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_private_salts_owner_symbols_are_mandatory() {
        for symbol in ["c71_pcs_salts_begin","c71_pcs_salts_prescan","c71_pcs_salts_indices",
            "c71_pcs_leaf_finish_private","c71_pcs_full_leaves_private","c71_pcs_salts_complete"] {
            let legacy = fixture_library(512,Some(symbol));
            let error = Runtime::new(&legacy.config).err().unwrap();
            assert!(error.contains(symbol),"{error}");
        }
    }

    #[test]
    fn c71_b12_native_source_pending_coverage_owner_and_failure() {
        let fixture = fixture(128);
        let injection = Injection::new(&fixture.config);
        for fault in 0..28 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let input = runtime.upload_signed(&[32767; 64]).unwrap();
            let shape = PcsSourceShape { message_rows: 4, rows: 4, live: 128, pad_rows: 3, cosets: 16, first_coset: 0 };
            let tile = PcsSourceTile { input_first: 0, input_stride: 8, rows: 8, columns: 8,
                original_first: 0, byte_first: 0, width: 2, signed_width: 2 };
            let pads = runtime.pcs_words(128 * 3).unwrap();
            runtime.pcs_upload(&pads, 0, &[7; 128 * 3]).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(2).unwrap();
            let (low, high) = runtime.pcs_source_powers(shape).unwrap();
            let result = match fault {
                0 => runtime.pcs_source_begin(&low, &low, shape, true).map(|_| ()),
                1 => runtime.pcs_source_powers(PcsSourceShape { rows: 3, ..shape }).map(|_| ()),
                19 => runtime.pcs_source_begin(&low, &high, PcsSourceShape { first_coset: 4, ..shape }, false).map(|_| ()),
                // Larger rates are needed by reduced original PCS profiles
                // with fixed pads; a rate below sixteen is still excluded.
                23 => runtime.pcs_source_powers(PcsSourceShape { cosets: 8, ..shape }).map(|_| ()),
                _ => {
                    let (mut values, mut histogram) = runtime.pcs_source_begin(&low, &high, shape, true).unwrap();
                    match fault {
                        2 => runtime.pcs_source_tile(&input, PcsSourceTile { signed_width: 6, ..tile }),
                        3 => runtime.pcs_source_tile(&input, PcsSourceTile { width: 3, ..tile }),
                        4 => runtime.pcs_source_tile(&input, PcsSourceTile { byte_first: 3, ..tile }),
                        5 => runtime.pcs_source_tile(&input, PcsSourceTile { original_first: u64::MAX, ..tile }),
                        6 => runtime.pcs_source_tile(&input, PcsSourceTile { input_stride: 0, ..tile }),
                        7 => runtime.pcs_source_tile(&input, PcsSourceTile { input_first: u64::MAX, ..tile }),
                        8 => runtime.pcs_source_tile(&input, PcsSourceTile { rows: u64::MAX, ..tile }),
                        9 => { runtime.pcs_source_tile(&input, tile).unwrap(); runtime.pcs_source_tile(&input, tile) },
                        10 => runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pads, &twiddles),
                        11 => runtime.download_words(&values[0], 0, &mut [0; 1]),
                        12 => {
                            let salts = runtime.pcs_words(32).unwrap(); runtime.pcs_upload(&salts, 0, &[1; 32]).unwrap();
                            let mut states = runtime.pcs_full_hash_begin(16).unwrap();
                            runtime.pcs_full_hash_band(&values, &salts, &mut states, 0)
                        },
                        13 => {
                            runtime.pcs_source_tile(&input, tile).unwrap(); values.swap(0, 1);
                            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pads, &twiddles)
                        },
                        14 => {
                            runtime.pcs_source_tile(&input, tile).unwrap();
                            runtime.pcs_source_finish(&mut values, None, &pads, &twiddles)
                        },
                        15 => {
                            let mut other = Runtime::new(&fixture.config).unwrap();
                            let foreign = other.upload_signed(&[1; 64]).unwrap();
                            runtime.pcs_source_tile(&foreign, tile)
                        },
                        16 | 18 => {
                            runtime.pcs_source_tile(&input, tile).unwrap();
                            injection.set(if fault == 16 { 9 } else { 2 });
                            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pads, &twiddles)
                        },
                        17 => { injection.set(1); runtime.pcs_source_tile(&input, tile) },
                        20 => {
                            runtime.pcs_source_tile(&input, tile).unwrap();
                            let wrong = runtime.pcs_words(1).unwrap(); runtime.pcs_upload(&wrong, 0, &[1]).unwrap();
                            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &wrong, &twiddles)
                        },
                        21 => { let pending = runtime.allocate_buffer(1, 64).unwrap(); runtime.pcs_source_tile(&pending, tile) },
                        22 => runtime.pcs_source_begin(&low, &high, shape, false).map(|_| ()),
                        24..=26 => {
                            runtime.pcs_source_tile(&input, tile).unwrap();
                            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pads, &twiddles).unwrap();
                            let band = if fault == 26 {16} else {8};
                            let salts = runtime.pcs_words(4 * band).unwrap(); runtime.pcs_upload(&salts, 0, &vec![1; 4 * band]).unwrap();
                            let mut states = runtime.pcs_full_hash_begin(16).unwrap();
                            if fault == 26 { injection.set(9); }
                            let status = runtime.pcs_full_hash_band(&values, &salts, &mut states, 0);
                            if fault == 26 { status } else {
                                status.unwrap();
                                if fault == 24 { runtime.pcs_full_hash_band(&values, &salts, &mut states, 0) }
                                else { runtime.pcs_digests(&states, 0, 1).map(|_| ()) }
                            }
                        },
                        27 => {
                            let raw = runtime.pointwise([Some((&input, 0)), None], 64,
                                Pointwise { a: 1 << 30, b: 0, multiply: 0 }).unwrap();
                            runtime.pcs_source_tile(&raw, PcsSourceTile { signed_width: 4, ..tile }).unwrap();
                            runtime.pcs_source_finish(&mut values, histogram.as_mut(), &pads, &twiddles)
                        },
                        _ => unreachable!(),
                    }
                }
            };
            assert!(result.is_err(), "fault {fault} published a source");
            let before = runtime.stats().unwrap();
            assert_eq!(before.stopped, 1);
            assert!(runtime.pcs_source_tile(&input, tile).is_err());
            let after = runtime.stats().unwrap();
            assert_eq!(after.launches, before.launches);
            assert_eq!(after.allocations, before.allocations);
            assert_eq!(after.h2d_bytes, before.h2d_bytes);
            injection.set(0);
            assert_eq!(runtime.close().unwrap().arena_bytes, 0);
        }
        println!("C71_PCS_SOURCE_REJECTIONS {{\"cases\":28,\"terminal\":true,\"gpu_execution\":false,\"credit\":false}}");
    }

    #[test]
    fn c71_b12_native_incremental_hash_rejections_and_fail_closed() {
        let f = fixture(512);
        let injection = Injection::new(&f.config);
        for fault in 0..27 {
            let mut runtime = Runtime::new(&f.config).unwrap();
            let ring = runtime.pcs_words(16).unwrap();
            runtime.pcs_upload(&ring, 0, &[0; 16]).unwrap();
            let mut state = runtime.pcs_hash_start(&ring).unwrap();
            let salts = runtime.pcs_words(4).unwrap();
            runtime.pcs_upload(&salts, 0, &[0; 4]).unwrap();
            if (8..=9).contains(&fault) || (13..=14).contains(&fault) || fault >= 19 {
                for first in (4..=116).step_by(8) {
                    runtime.pcs_hash_step(&ring, &state, first).unwrap();
                }
            }
            if fault >= 19 {
                runtime.pcs_hash_finish(&ring, &salts, &mut state, 0).unwrap();
                runtime.pcs_hash_finish(&ring, &salts, &mut state, 1).unwrap();
            }
            let failed = match fault {
                0 => runtime.pcs_hash_step(&ring, &state, 12).is_err(),
                1 => runtime.pcs_hash_finish(&ring, &salts, &mut state, 0).is_err(),
                2 => {
                    let status = unsafe { (runtime.api.pcs_start)(runtime.raw, ring.id, state.id) };
                    runtime.check(status).is_err()
                }
                3 => {
                    let mut out = [0u8; 32];
                    let status = unsafe { (runtime.api.pcs_read)(runtime.raw, state.id, 0, 1, out.as_mut_ptr().cast()) };
                    runtime.check(status).is_err()
                }
                4 => {
                    let signed = runtime.upload_signed(&[1; 16]).unwrap();
                    let status = unsafe { (runtime.api.pcs_step)(runtime.raw, signed.id, state.id, 4) };
                    runtime.check(status).is_err()
                }
                5 => runtime.pcs_upload(&ring, 0, &[u64::MAX]).is_err(),
                6 => {
                    let incomplete = runtime.pcs_words(8).unwrap();
                    runtime.pcs_upload(&incomplete, 1, &[0]).is_err()
                }
                7 => {
                    let out = runtime.alloc(11, 1).unwrap();
                    let status = unsafe { (runtime.api.pcs_nodes)(runtime.raw, state.id, out, 1) };
                    runtime.check(status).is_err()
                }
                8 => runtime.pcs_hash_finish(&ring, &salts, &mut state, 1).is_err(),
                9 => {
                    runtime.pcs_hash_finish(&ring, &salts, &mut state, 0).unwrap();
                    // Partially finalized bands still cannot be published.
                    let mut out = [0u8; 32];
                    let status = unsafe { (runtime.api.pcs_read)(runtime.raw, state.id, 0, 1, out.as_mut_ptr().cast()) };
                    runtime.check(status).is_err()
                }
                10 => runtime.pcs_hash_step(&ring, &state, usize::MAX).is_err(),
                11 => { injection.set(2); runtime.pcs_upload(&ring, 0, &[0]).is_err() },
                12 => { injection.set(1); runtime.pcs_hash_step(&ring, &state, 4).is_err() },
                13 => {
                    injection.set(9);
                    runtime.pcs_hash_finish(&ring, &salts, &mut state, 0).unwrap();
                    runtime.pcs_hash_finish(&ring, &salts, &mut state, 1).is_err()
                }
                14 => {
                    runtime.pcs_hash_finish(&ring, &salts, &mut state, 0).unwrap();
                    runtime.pcs_hash_finish(&ring, &salts, &mut state, 1).unwrap();
                    injection.set(7); runtime.pcs_digests(&state, 0, 1).is_err()
                }
                15 => {
                    let mut other = Runtime::new(&f.config).unwrap();
                    let foreign = other.pcs_words(16).unwrap();
                    runtime.pcs_hash_step(&foreign, &state, 4).is_err()
                }
                16 => runtime.pcs_words(1 << 28).is_err(),
                17 => runtime.pcs_words((1 << 28) + 1).is_err(),
                18 => {
                    let mut out = [0u8; 1];
                    let status = unsafe { (runtime.api.original_read)(runtime.raw, ring.id, 0, 0, 1, out.as_mut_ptr().cast()) };
                    runtime.check(status).is_err()
                }
                19 => runtime.pcs_frontier(3, 2).is_err(),
                20 => {
                    let frontier = runtime.pcs_frontier(2, 2).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 1).is_err()
                }
                21 => {
                    let frontier = runtime.pcs_frontier(2, 2).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 0).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 0).is_err()
                }
                22 => {
                    let frontier = runtime.pcs_frontier(2, 2).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 0).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 1).unwrap();
                    runtime.pcs_merge_group(&frontier, &state, 2).is_err()
                }
                23 => {
                    let frontier = runtime.pcs_frontier(2, 2).unwrap();
                    let mut out = [0u8; 32];
                    let status = unsafe { (runtime.api.pcs_read)(runtime.raw, frontier.id, 0, 1, out.as_mut_ptr().cast()) };
                    runtime.check(status).is_err()
                }
                24 => runtime.pcs_nodes_strided(&state, 0).is_err(),
                25 => {
                    let mut other = Runtime::new(&f.config).unwrap();
                    let foreign = other.pcs_frontier(2, 2).unwrap();
                    runtime.pcs_merge_group(&foreign, &state, 0).is_err()
                }
                26 => {
                    let frontier = runtime.pcs_frontier(2, 2).unwrap();
                    injection.set(1); runtime.pcs_merge_group(&frontier, &state, 0).is_err()
                }
                _ => unreachable!(),
            };
            assert!(failed, "fault {fault}");
            assert_eq!(runtime.stats().unwrap().stopped, 1, "fault {fault}");
            assert!(runtime.pcs_hash_step(&ring, &state, 4).is_err());
            injection.set(0);
            let stats = runtime.close().unwrap();
            assert_eq!(stats.live_capacity_bytes, 0);
            assert_eq!(stats.cleanup_failed, 0);
        }
        println!("C71_INCREMENTAL_HASH_REJECTIONS {{\"cases\":27,\"gpu_execution\":false,\"credit\":false}}");
    }
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
    fn c71_b12_native_weight_tensor_owner_fft_hash_parity() {
        let mut fixture = fixture(512);
        fixture.config.arena_bytes = 8 << 20;
        let injection = Injection::new(&fixture.config);
        for (n, rows, pad) in [(4usize, 4usize, 11usize), (64, 16, 17), (1024, 4, 1536)] {
            let weights = Arc::new((0..96 * n).map(|i| match i % 7 {
                0 => 0, 1 => 32767, 2 => -32767, 3 => 1, 4 => -1,
                _ => ((i * 179 % 65535) as i32 - 32767) as i16,
            }).collect::<Vec<_>>());
            let _budget = census::Budget::new(&weights).unwrap();
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            runtime.install_weights(weights.clone(), [27; 32]).unwrap();
            let tiles = runtime.pcs_weight_tiles(&weights, [27; 32], &[
                WeightTile { first: 0, count: (64 * n) as u64, packed_first: 0, packed_stride: 96, columns: 64 },
                WeightTile { first: (64 * n) as u64, count: (32 * n) as u64, packed_first: 64, packed_stride: 96, columns: 32 },
            ]).unwrap();
            let pads = runtime.pcs_words(128 * pad).unwrap();
            let words: Vec<_> = (0..128 * pad).map(|i| if i % 4 == 0 { Goldilocks::ORDER_U64 - 1 }
                else { (i * 1231 + 13) as u64 }).collect();
            runtime.pcs_upload(&pads, 0, &words).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(rows.ilog2() as usize).unwrap();
            let ring = runtime.pcs_ring(rows).unwrap();
            let shape = WeightShape { message_rows: n as u64, rows: rows as u64,
                pad_rows: pad as u32, cosets: 64, first_coset: 32, first_column: 0, slots: 0 };
            let (low, high) = runtime.pcs_coset_powers(shape).unwrap();
            let group_rows = 32 * rows;
            let salts = runtime.pcs_words(4 * group_rows).unwrap();
            let salt_words: Vec<_> = (0..4 * group_rows).map(|i| (i * 9871 + 71) as u64).collect();
            runtime.pcs_upload(&salts, 0, &salt_words).unwrap();
            let mut ordinary = Vec::new();
            let mut ordinary_work = None;
            let mut elapsed = [0.0; 2];
            for tensor in [false, true] {
                // The observer is PRIVATE TEST memory. It records ordinary
                // post-FFT fields and compares the tensor submission in order;
                // production has no such field download/cache. Existing Rust
                // polynomial parity checks independently cover ordinary W.
                injection.pcs_record(u32::from(tensor));
                let before = runtime.stats().unwrap();
                let started = std::time::Instant::now();
                let fill = |runtime: &mut Runtime, column: usize, slots| {
                    let shape = WeightShape { first_column: column as u32, slots, ..shape };
                    if tensor { runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &ring, shape) }
                    else { runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &ring, shape) }.unwrap();
                };
                fill(&mut runtime, 0, 0);
                fill(&mut runtime, 4, 4);
                let mut states = runtime.pcs_hash_start(&ring).unwrap();
                for first in (4..=116).step_by(8) {
                    fill(&mut runtime, first + 4, 0);
                    runtime.pcs_hash_step(&ring, &states, first).unwrap();
                    if first < 116 { fill(&mut runtime, first + 8, 4); }
                }
                fill(&mut runtime, 124, 0);
                runtime.pcs_hash_finish(&ring, &salts, &mut states, 0).unwrap();
                let after_hash = runtime.stats().unwrap();
                assert_eq!(after_hash.d2h_bytes - before.d2h_bytes, 132); // flags only
                let mut levels = vec![runtime.pcs_digests(&states, 0, group_rows).unwrap()];
                let mut current = states;
                while current.count > 1 {
                    let stride = if current.count > rows { rows } else { 1 };
                    let next = runtime.pcs_nodes_strided(&current, stride).unwrap();
                    levels.push(runtime.pcs_digests(&next, 0, next.count).unwrap());
                    runtime.release_buffer(current).unwrap(); current = next;
                }
                runtime.release_buffer(current).unwrap();
                let after = runtime.stats().unwrap();
                elapsed[usize::from(tensor)] = started.elapsed().as_secs_f64();
                let work = (after.launches - before.launches, after.fences - before.fences,
                    after.d2h_bytes - before.d2h_bytes, after.live_capacity_bytes,
                    after.host_owner_bytes, after.peak_capacity_bytes);
                assert_eq!(after.stopped, 0);
                if tensor { assert_eq!(levels, ordinary); assert_eq!(Some(work), ordinary_work); injection.pcs_record(2); }
                else { ordinary = levels; ordinary_work = Some(work); }
            }
            for buffer in [tiles, pads, twiddles, ring, low, high, salts] { runtime.release_buffer(buffer).unwrap(); }
            assert_eq!(runtime.stats().unwrap().live_capacity_bytes, 0);
            let stats = runtime.close().unwrap();
            assert_eq!(stats.cleanup_failed, 0);
            println!("C71_PCS_TENSOR_OWNER {}", serde_json::json!({"message_rows":n,"coset_rows":rows,
                "pad_rows":pad,"cosets":32,"columns":128,"original_w_bytes":weights.len()*2,
                "fixture_post_fft_observer_bytes":128*32*rows*8,"all_fft_values_equal":true,
                "all_leaf_node_digests_equal":true,"ordinary_host_s":elapsed[0],"tensor_host_s":elapsed[1],
                "native_capacity_peak_bytes":stats.peak_capacity_bytes,"host_owner_bytes":stats.host_owner_bytes,
                "gpu_execution":false,"tensor_core_execution":false,"credit":false}));
        }
    }
    #[test]
    fn c71_b12_native_weight_tensor_owner_rejections_and_fail_closed() {
        let fixture = fixture(512);
        let injection = Injection::new(&fixture.config);
        let weights = Arc::new(vec![2i16; 1024]);
        let _budget = census::Budget::new(&weights).unwrap();
        for fault in 0..12 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            runtime.install_weights(weights.clone(), [17; 32]).unwrap();
            let tiles = runtime.pcs_weight_tiles(&weights, [17; 32], &[
                WeightTile { first: 0, count: 1024, packed_first: 0, packed_stride: 1, columns: 1 },
            ]).unwrap();
            let pads = runtime.pcs_words(1024).unwrap(); runtime.pcs_upload(&pads, 0, &[3; 1024]).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(2).unwrap();
            let ring = runtime.pcs_ring(4).unwrap();
            let mut shape = WeightShape { message_rows: 8, rows: 4, pad_rows: 8, cosets: 256,
                first_coset: 0, first_column: 0, slots: 0 };
            let (low, high) = runtime.pcs_coset_powers(shape).unwrap();
            let result = match fault {
                0 => {
                    let mut other = Runtime::new(&fixture.config).unwrap(); let foreign = other.pcs_ring(4).unwrap();
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &foreign, shape)
                }
                1 => {
                    let wrong = runtime.upload_signed(&[3; 1024]).unwrap();
                    runtime.pcs_weight_columns_tensor(&tiles, &wrong, &low, &high, &twiddles, &ring, shape)
                }
                2 => runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &low, &twiddles, &ring, shape),
                3 => runtime.pcs_weight_columns_tensor(&tiles, &ring, &low, &high, &twiddles, &ring, shape),
                4 => { shape.first_coset=32;
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &ring, shape) }
                5 => {
                    let incomplete = runtime.pcs_words(1024).unwrap();
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &incomplete, shape)
                }
                6 => {
                    let incomplete = runtime.pcs_words(1024).unwrap();
                    runtime.pcs_weight_columns_tensor(&tiles, &incomplete, &low, &high, &twiddles, &ring, shape)
                }
                7 => { shape.message_rows=2048;
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &ring, shape) }
                8..=10 => { injection.set([1,2,9][fault-8]);
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &ring, shape) }
                11 => {
                    let retired = runtime.pcs_words(1).unwrap(); let id = retired.id; runtime.release_buffer(retired).unwrap();
                    let stale = Buffer { id, kind:9, count:1, owner:runtime.owner.clone() };
                    runtime.pcs_weight_columns_tensor(&tiles, &pads, &low, &high, &twiddles, &stale, shape)
                }
                _ => unreachable!(),
            };
            assert!(result.is_err(), "tensor fault {fault}");
            let stopped = runtime.stats().unwrap(); assert_eq!(stopped.stopped, 1);
            assert!(runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &ring, shape).is_err());
            assert_eq!(runtime.stats().unwrap().launches, stopped.launches);
            injection.set(0);
            let stats = runtime.close().unwrap(); assert_eq!(stats.live_capacity_bytes, 0); assert_eq!(stats.cleanup_failed, 0);
        }
        println!("C71_PCS_TENSOR_OWNER_REJECTIONS {{\"cases\":12,\"gpu_execution\":false,\"tensor_core_execution\":false,\"credit\":false}}");
    }
    #[test]
    fn c71_b12_native_weight_tensor_symbol_is_mandatory() {
        let legacy = fixture_library(512, Some("c71_pcs_weight_tensor"));
        let error = Runtime::new(&legacy.config).err().unwrap();
        assert!(error.contains("c71_pcs_weight_tensor"), "{error}");
    }
    #[test]
    fn c71_b12_native_pcs_compare_words_exact_and_terminal() {
        let fixture = fixture(128);
        let injection = Injection::new(&fixture.config);
        for fault in 0..11 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            let words = [0,1,Goldilocks::ORDER_U64-1,Goldilocks::ORDER_U64-2,256,1<<32,19,31];
            let left = runtime.pcs_words(8).unwrap(); runtime.pcs_upload(&left,0,&words).unwrap();
            let right = runtime.pcs_words(8).unwrap();
            let mut rhs = words; if fault==1 { rhs[7]+=1; }
            runtime.pcs_upload(&right,0,&rhs).unwrap();
            let before = runtime.stats().unwrap();
            let result = match fault {
                0 | 1 => runtime.pcs_compare_words(&left,&right),
                2 => runtime.pcs_compare_words(&left,&left),
                3 => {
                    let mut other=Runtime::new(&fixture.config).unwrap(); let foreign=other.pcs_words(8).unwrap();
                    other.pcs_upload(&foreign,0,&words).unwrap(); runtime.pcs_compare_words(&left,&foreign)
                }
                4 => { let wrong=runtime.upload_signed(&[1;8]).unwrap(); runtime.pcs_compare_words(&left,&wrong) }
                5 => { let incomplete=runtime.pcs_words(8).unwrap(); runtime.pcs_compare_words(&left,&incomplete) }
                6 => {
                    let short=runtime.pcs_words(7).unwrap(); runtime.pcs_upload(&short,0,&words[..7]).unwrap();
                    runtime.pcs_compare_words(&left,&short)
                }
                7..=9 => { injection.set([1,2,9][fault-7]); runtime.pcs_compare_words(&left,&right) }
                10 => runtime.pcs_upload(&right,0,&[Goldilocks::ORDER_U64]),
                _ => unreachable!(),
            };
            let after=runtime.stats().unwrap();
            if fault==0 {
                result.unwrap(); assert_eq!(after.d2h_bytes-before.d2h_bytes,4);
                assert_eq!(after.launches-before.launches,1); assert_eq!(after.live_capacity_bytes,before.live_capacity_bytes);
                runtime.pcs_compare_words(&right,&left).unwrap(); // both arrays remained unchanged/full
                runtime.release_buffer(left).unwrap(); runtime.release_buffer(right).unwrap();
            } else {
                assert!(result.is_err(),"comparison fault {fault}"); assert_eq!(after.stopped,1);
                assert!(runtime.pcs_compare_words(&left,&right).is_err());
                assert_eq!(runtime.stats().unwrap().launches,after.launches);
            }
            injection.set(0); let final_stats=runtime.close().unwrap();
            assert_eq!(final_stats.arena_bytes,0); assert_eq!(final_stats.cleanup_failed,0);
        }
        println!("C71_PCS_COMPARE_WORDS {{\"positive\":1,\"terminal_rejections\":10,\"field_downloads\":0,\"gpu_execution\":false,\"credit\":false}}");
    }
    #[test]
    fn c71_b12_native_pcs_compare_words_symbol_is_mandatory() {
        let legacy=fixture_library(128,Some("c71_pcs_compare_words"));
        let error=Runtime::new(&legacy.config).err().unwrap(); assert!(error.contains("c71_pcs_compare_words"),"{error}");
    }
    #[test]
    fn c71_b12_native_weight_rejections_and_fail_closed() {
        let fixture = fixture(512);
        let injection = Injection::new(&fixture.config);
        let weights = Arc::new(vec![2i16; 1024]);
        let _budget = census::Budget::new(&weights).unwrap();
        let tile = WeightTile { first: 0, count: 1024, packed_first: 0, packed_stride: 1, columns: 1 };
        for fault in 0..24 {
            let mut runtime = Runtime::new(&fixture.config).unwrap();
            runtime.install_weights(weights.clone(), [17; 32]).unwrap();
            let tiles = runtime.pcs_weight_tiles(&weights, [17; 32], &[tile]).unwrap();
            let pads = runtime.pcs_words(1024).unwrap();
            runtime.pcs_upload(&pads, 0, &vec![3; 1024]).unwrap();
            let twiddles = runtime.pcs_fft_twiddles(2).unwrap();
            let ring = runtime.pcs_ring(4).unwrap();
            let mut shape = WeightShape { message_rows: 8, rows: 4, pad_rows: 8, cosets: 256,
                first_coset: 0, first_column: 0, slots: 0 };
            let (low, high) = runtime.pcs_coset_powers(shape).unwrap();
            let failed = match fault {
                0..=9 | 18 => {
                    match fault {
                        0 => shape.message_rows = 3, 1 => shape.rows = 8, 2 => shape.rows = 0,
                        3 => shape.slots = 8, 4 => shape.first_column = 126, 5 => shape.cosets = 16,
                        6 => shape.first_coset = 1, 7 => shape.first_coset = 256,
                        8 => shape.pad_rows = 1537, 9 => shape.message_rows = 4,
                        18 => shape.first_coset = 32, _ => unreachable!(),
                    }
                    runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &ring, shape).is_err()
                }
                10 => runtime.pcs_weight_columns(&tiles, &pads, &low, &low, &twiddles, &ring, shape).is_err(),
                11 => runtime.pcs_weight_columns(&tiles, &ring, &low, &high, &twiddles, &ring, shape).is_err(),
                12 => runtime.pcs_weight_tiles(&Arc::new(weights.as_ref().clone()), [17; 32], &[tile]).is_err(),
                13 => runtime.pcs_weight_tiles(&weights, [18; 32], &[tile]).is_err(),
                14 => runtime.pcs_weight_tiles(&weights, [17; 32], &[WeightTile { first: 1, ..tile }]).is_err(),
                15 => runtime.pcs_weight_tiles(&weights, [17; 32], &[WeightTile { packed_stride: 2, ..tile }]).is_err(),
                16 => {
                    let incomplete = runtime.pcs_words(1024).unwrap();
                    runtime.pcs_weight_columns(&tiles, &incomplete, &low, &high, &twiddles, &ring, shape).is_err()
                }
                17 => {
                    let incomplete = runtime.pcs_words(1024).unwrap();
                    runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &incomplete, shape).is_err()
                }
                19..=21 => {
                    injection.set([1, 2, 9][fault - 19]);
                    runtime.pcs_weight_columns(&tiles, &pads, &low, &high, &twiddles, &ring, shape).is_err()
                }
                22 => runtime.pcs_fft_twiddles(3).is_err(),
                23 => runtime.pcs_upload(&pads, 0, &[Goldilocks::ORDER_U64]).is_err(),
                _ => unreachable!(),
            };
            assert!(failed, "fault {fault}");
            assert_eq!(runtime.stats().unwrap().stopped, 1, "fault {fault}");
            assert!(runtime.pcs_ring(4).is_err());
            injection.set(0);
            let stats = runtime.close().unwrap();
            assert_eq!(stats.live_capacity_bytes, 0);
            assert_eq!(stats.cleanup_failed, 0);
        }
        println!("C71_NATIVE_W_REJECTIONS {{\"cases\":24,\"gpu_execution\":false,\"credit\":false}}");
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
        fixture_library(window_words, None)
    }
    fn fixture_library(window_words: usize, missing_symbol: Option<&str>) -> Fixture {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory =
            std::env::temp_dir().join(format!("c71-range-ffi-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let library = directory.join("range-host-fixture.so");
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let mut compiler = std::process::Command::new("g++");
        compiler.current_dir(root);
        if let Some(symbol)=missing_symbol { compiler.arg(format!("-D{symbol}={symbol}_unavailable")); }
        let result = compiler.args([
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=all",
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
        pub(in crate::c71_matrix) fn expect_pcs(&self, values: &[u64]) {
            // Test-only observer after the shared finite FFT; production
            // still has no field-value download for resident PCS buffers.
            let call: unsafe extern "C" fn(*const u64, u64) =
                unsafe { self.api.symbol(b"c71_range_test_expect_pcs\0") }.unwrap();
            unsafe { call(values.as_ptr(), values.len() as u64); }
        }
        fn pcs_record(&self, mode: u32) {
            let call: unsafe extern "C" fn(u32) = unsafe { self.api.symbol(b"c71_range_test_pcs_record\0") }.unwrap();
            unsafe { call(mode); }
        }
    }
}

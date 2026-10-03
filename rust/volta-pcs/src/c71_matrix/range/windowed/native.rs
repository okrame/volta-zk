//! Explicit native range backend. The library is trusted executable code;
//! never load a path from the proof/transcript. No environment-selected backend.
use super::*;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::{size_of, size_of_val};
use std::path::PathBuf;
use std::ptr;

#[derive(Clone)]
pub(in crate::c71_matrix) struct Config {
    pub library: PathBuf,
    pub device: i32,
    pub arena_bytes: u64,
    pub reserve_bytes: u64,
    pub window_words: usize,
    pub buckets: u32,
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
    assert!(size_of::<Stats>() == 112 && size_of::<Group>() == 1760 && size_of::<Round>() == 896);

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
macro_rules! api {
    ($($field:ident: $ty:ty => $name:literal),* $(,)?) => {
        struct Api { $($field: $ty,)* _library: Library }
        impl Api {
            fn load(path: &std::path::Path) -> Result<Self, String> {
                let library = Library::open(path)?;
                // SAFETY: fixed C ABI types below mirror c71_range_runtime.h.
                unsafe {
                    let abi: unsafe extern "C" fn() -> u32 = library.symbol(b"c71_range_runtime_abi\0")?;
                    if abi() != 1 { return Err("native range ABI differs".into()); }
                    Ok(Self { $($field: library.symbol(concat!($name, "\0").as_bytes())?,)* _library: library })
                }
            }
        }
    }
}
api! {
    create: unsafe extern "C" fn(i32,u64,u64,*mut Raw)->i32 => "c71_range_create",
    close: unsafe extern "C" fn(Raw,*mut Stats)->i32 => "c71_range_close",
    error: unsafe extern "C" fn(Raw)->*const c_char => "c71_range_error",
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
}
struct Runtime {
    api: Api,
    raw: Raw,
    stopped: bool,
}
impl Runtime {
    fn new(config: &Config) -> Result<Self, String> {
        let api = Api::load(&config.library)?;
        let mut s = Self { api, raw: ptr::null_mut(), stopped: false };
        // SAFETY: owned pointer output; on error Drop also closes partial owners.
        let status = unsafe {
            (s.api.create)(config.device, config.arena_bytes, config.reserve_bytes, &mut s.raw)
        };
        s.check(status)?;
        if s.raw.is_null() {
            return Err("native range returned null owner".into());
        }
        Ok(s)
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
        let mut id = 0;
        let status = unsafe { (self.api.alloc)(self.raw, kind, count as u64, &mut id) };
        self.check(status)?;
        Ok(id)
    }
    fn release(&mut self, id: u64) -> Result<(), String> {
        let status = unsafe { (self.api.release)(self.raw, id) };
        self.check(status)
    }
    fn read<const N: usize>(&mut self, id: u64) -> Result<[Fp3; N], String> {
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
    fn close(&mut self) -> Result<Stats, String> {
        let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
        if raw.is_null() {
            return Ok(Stats::default());
        }
        let mut stats = Stats::default();
        let status = unsafe { (self.api.close)(raw, &mut stats) };
        if status != 0 || stats.cleanup_failed != 0 {
            return Err(format!(
                "native range cleanup failed, reserved bytes: {}",
                stats.arena_bytes
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

pub(super) struct Evaluator<'a, T> {
    source: &'a Source<T>,
    runtime: Runtime,
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
        config: &Config,
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
            runtime: Runtime::new(config)?,
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
            work: Work::default(),
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
        self.work.native = Some(self.runtime.close()?);
        Ok(self.work)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::c71_matrix) struct Fixture {
        pub config: Config,
        directory: PathBuf,
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
    }
}

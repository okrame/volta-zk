//! Sequential diagnostic phases. Linux resets VmHWM at each boundary, so a
//! later small phase does not inherit the high-water mark of an earlier one.
//! LLVM coverage is optional; it counts the unchanged native arithmetic.

use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Instant;

struct Allocator;
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static FREED: AtomicU64 = AtomicU64::new(0);

fn allocated(size: usize) {
    ALLOCATED.fetch_add(size as u64, Relaxed);
    PEAK.fetch_max(LIVE.fetch_add(size as u64, Relaxed) + size as u64, Relaxed);
}

// Counts requested layouts, including every Vec capacity and realloc, across
// both threads. System/allocator metadata, stack and mmap are instead in RSS.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size() as u64, Relaxed);
        FREED.fetch_add(layout.size() as u64, Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = System.realloc(ptr, layout, size);
        if !result.is_null() {
            LIVE.fetch_sub(layout.size() as u64, Relaxed);
            FREED.fetch_add(layout.size() as u64, Relaxed);
            allocated(size);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Phase {
    name: &'static str,
    start: Instant,
    allocated: u64,
    freed: u64,
    live: u64,
}
static CURRENT: Mutex<Option<Phase>> = Mutex::new(None);
static RECORDS: Mutex<Vec<Value>> = Mutex::new(Vec::new());

#[cfg(feature = "c71-work-census")]
unsafe extern "C" {
    fn __llvm_profile_set_filename(name: *const std::ffi::c_char);
    fn __llvm_profile_write_file() -> std::ffi::c_int;
    fn __llvm_profile_reset_counters();
}

fn coverage(index: usize) -> Result<(), String> {
    #[cfg(feature = "c71-work-census")]
    if let Some(directory) = std::env::var_os("C71_COVERAGE_DIR") {
        let path = std::path::PathBuf::from(directory).join(format!("phase-{index:02}.profraw"));
        if path.exists() {
            return Err("coverage snapshot already exists".into());
        }
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| e.to_string())?;
        // Phases change on main only after synchronous Rayon operations join.
        unsafe {
            __llvm_profile_set_filename(name.as_ptr());
            if __llvm_profile_write_file() != 0 {
                return Err("LLVM snapshot failed".into());
            }
            __llvm_profile_reset_counters();
            // The runtime copies the filename. The exit handler writes elsewhere.
            __llvm_profile_set_filename(c"/dev/null".as_ptr());
        }
    }
    let _ = index;
    Ok(())
}

fn close(phase: Phase) -> Result<(), String> {
    let seconds = phase.start.elapsed().as_secs_f64();
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    let allocated = ALLOCATED.load(Relaxed) - phase.allocated;
    let freed = FREED.load(Relaxed) - phase.freed;
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let rss = |key: &str| -> Result<u64, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v * 1024)
            .ok_or_else(|| format!("missing Linux {key}"))
    };
    let mut records = RECORDS.lock().unwrap();
    let index = records.len();
    coverage(index)?;
    records.push(json!({"index": index, "name": phase.name, "seconds": seconds,
        "rss_end_bytes": rss("VmRSS:")?, "rss_peak_bytes": rss("VmHWM:")?,
        "heap_live_start_bytes": phase.live, "heap_live_end_bytes": live,
        "heap_peak_requested_bytes": peak, "heap_allocated_bytes": allocated,
        "heap_freed_bytes": freed}));
    Ok(())
}

pub(super) fn start() -> Result<(), String> {
    if CURRENT.lock().unwrap().is_some() {
        return Err("census already running".into());
    }
    RECORDS.lock().unwrap().clear();
    // Discard process/preflight arithmetic, before the model/capacity lifecycle.
    #[cfg(feature = "c71-work-census")]
    unsafe {
        __llvm_profile_reset_counters();
    }
    begin("initialization")
}

fn begin(name: &'static str) -> Result<(), String> {
    std::fs::write("/proc/self/clear_refs", b"5").map_err(|e| e.to_string())?;
    let live = LIVE.load(Relaxed);
    PEAK.store(live, Relaxed);
    *CURRENT.lock().unwrap() = Some(Phase {
        name,
        start: Instant::now(),
        live,
        allocated: ALLOCATED.load(Relaxed),
        freed: FREED.load(Relaxed),
    });
    Ok(())
}

pub(super) fn mark(name: &'static str) -> Result<(), String> {
    let previous = CURRENT.lock().unwrap().take();
    if let Some(phase) = previous {
        close(phase)?;
        begin(name)?;
    }
    Ok(())
}

pub(super) fn finish() -> Result<Value, String> {
    if let Some(phase) = CURRENT.lock().unwrap().take() {
        close(phase)?;
    }
    Ok(json!({"phases": std::mem::take(&mut *RECORDS.lock().unwrap()),
        "rss_kind": "Linux VmHWM reset each phase; same process contains both roles",
        "heap_kind": "requested allocator layouts including reallocations; not memory-access traffic",
        "coverage_instrumented": cfg!(feature = "c71-work-census"),
        "expanded_array_DRAM_read_bytes": null, "expanded_array_DRAM_write_bytes": null,
        "physical_traffic_admission_bound": "infinity"}))
}

/// A counted fixture, separate from protocol runs and never secret material.
#[cfg(feature = "c71-work-census")]
pub fn self_check() -> Result<Value, String> {
    use super::*;
    use p3_field::extension::PackedCubicTrinomialExtensionField;
    use p3_field::{Algebra, Field};
    use std::hint::black_box as keep;
    type Packed = <Goldilocks as Field>::Packing;
    let a = keep(Fp::new(7));
    let b = keep(volta_field::Fp2::new(a, a));
    let c = keep(Fp3::new(a, a, a));
    let g = keep(Goldilocks::new(7));
    let p = keep(Packed::from(g));
    let e = keep(E::new([g; 3]));
    let pe = keep(PackedCubicTrinomialExtensionField::<Goldilocks, Packed>::new([p; 3]));
    start()?;
    let _ = keep(a * a);
    let _ = keep(b * b);
    let _ = keep(b.mul_base(a));
    let _ = keep(c * c);
    let _ = keep(c.mul_base(a));
    let _ = keep(from_p3(to_p3(c)));
    let _ = keep(g * g);
    let _ = keep(Goldilocks::dot_product::<0>(&[], &[]));
    let _ = keep(Goldilocks::dot_product::<1>(&[g], &[g]));
    let _ = keep(Goldilocks::dot_product::<2>(&[g; 2], &[g; 2]));
    let _ = keep(Goldilocks::dot_product::<3>(&[g; 3], &[g; 3]));
    let _ = keep(p * p);
    let _ = keep(p.square());
    let _ = keep(Packed::dot_product::<3>(&[p; 3], &[p; 3]));
    let _ = keep(Packed::mixed_dot_product::<3>(&[p; 3], &[g; 3]));
    let _ = keep(e * e);
    let _ = keep(e.square());
    let _ = keep(e * g);
    let _ = keep(pe * pe);
    let _ = keep(pe.square());
    let _ = keep(pe * p);
    let _ = keep(g.try_inverse());
    let _ = keep(a.inv());
    // 37 VOLTA products before inverses, 80 P3 including inverse, and
    // 127 further VOLTA products for Fermat: 244 base products, 7 cubic.
    mark("parallel_counter_check")?;
    use rayon::prelude::*;
    (0..2048).into_par_iter().for_each(|_| {
        keep(keep(a) * keep(a));
    });
    Ok(json!({"resources": finish()?}))
}

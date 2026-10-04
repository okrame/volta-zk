//! Sequential diagnostic phases. Linux resets VmHWM at each boundary, so a
//! later small phase does not inherit the high-water mark of an earlier one.
//! LLVM coverage is optional; it counts the unchanged native arithmetic.

use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Allocator;
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static FREED: AtomicU64 = AtomicU64::new(0);

pub(in crate::c71_matrix) const TEMPORARY_LIMIT: u64 = 6_442_450_944;
pub(in crate::c71_matrix) const OPERATIONAL_MARGIN: u64 = 256 << 20;
// Explicit allowance for stack, allocator/driver bookkeeping and device runtime.
// Its physical sufficiency is a required H100 check, never inferred from Vecs.
pub(in crate::c71_matrix) const RUNTIME_ALLOWANCE: u64 = 256 << 20;
pub(in crate::c71_matrix) const PAYLOAD_LIMIT: u64 =
    TEMPORARY_LIMIT - OPERATIONAL_MARGIN - RUNTIME_ALLOWANCE;
static RESERVED: AtomicU64 = AtomicU64::new(0);
static EXTERNAL: AtomicU64 = AtomicU64::new(0);
static EXEMPT_W: AtomicU64 = AtomicU64::new(0);
static LIMIT: AtomicU64 = AtomicU64::new(0);
static BUDGET_ACTIVE: AtomicBool = AtomicBool::new(false);
static SIMULTANEOUS_PEAK: AtomicU64 = AtomicU64::new(0);
static DENIED: AtomicU64 = AtomicU64::new(0);

// One counter serializes host allocations on both roles with native device
// reservations. Realloc charges old+new until success: moving copies count.
fn reserve(size: u64) -> bool {
    let mut current = RESERVED.load(Relaxed);
    loop {
        let Some(next) = current.checked_add(size) else { return false };
        let temporary = next.saturating_sub(EXEMPT_W.load(Relaxed));
        let limit = LIMIT.load(Relaxed);
        if limit != 0 && temporary > limit {
            DENIED.fetch_add(1, Relaxed);
            return false;
        }
        match RESERVED.compare_exchange_weak(current, next, Relaxed, Relaxed) {
            Ok(_) => {
                if limit != 0 {
                    SIMULTANEOUS_PEAK.fetch_max(temporary, Relaxed);
                }
                return true;
            }
            Err(observed) => current = observed,
        }
    }
}

pub(in crate::c71_matrix) extern "C" fn external(delta: i64) -> i32 {
    if delta >= 0 {
        if !reserve(delta as u64) {
            return -1;
        }
        EXTERNAL.fetch_add(delta as u64, Relaxed);
    } else {
        let size = delta.unsigned_abs();
        EXTERNAL.fetch_sub(size, Relaxed);
        RESERVED.fetch_sub(size, Relaxed);
    }
    0
}

// Pin glibc's mmap threshold: otherwise freeing a large FFT raises the
// adaptive threshold and subsequent 16 MiB query levels can remain in arenas.
// Linux/GNU is the canonical runner platform. Small chunks and bookkeeping
// remain explicitly inside RUNTIME_ALLOWANCE, to be checked physically.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_policy() -> bool {
    unsafe extern "C" {
        fn mallopt(parameter: i32, value: i32) -> i32;
    }
    unsafe { mallopt(-3, 128 << 10) != 0 && mallopt(-1, 128 << 10) != 0 && mallopt(-8, 2) != 0 }
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_policy() -> bool {
    false
}

pub(in crate::c71_matrix) struct Budget {
    // Keep precisely the excluded immutable packed allocation alive through
    // teardown. No response buffer, table, root, seed or cache is exempt.
    _weights: Arc<Vec<i16>>,
}
impl Budget {
    pub(in crate::c71_matrix) fn new(weights: &Arc<Vec<i16>>) -> Result<Self, String> {
        if BUDGET_ACTIVE.compare_exchange(false, true, Relaxed, Relaxed).is_err() {
            return Err("temporary budget already active".into());
        }
        if !release_policy() {
            BUDGET_ACTIVE.store(false, Relaxed);
            return Err("canonical allocator release policy unavailable".into());
        }
        let weights = weights.clone();
        let exempt = (weights.capacity() * size_of::<i16>()) as u64;
        let live = RESERVED.load(Relaxed).checked_sub(exempt);
        let Some(live) = live.filter(|&n| n <= PAYLOAD_LIMIT) else {
            BUDGET_ACTIVE.store(false, Relaxed);
            return Err("W census or temporary baseline exceeds budget".into());
        };
        EXEMPT_W.store(exempt, Relaxed);
        SIMULTANEOUS_PEAK.store(live, Relaxed);
        DENIED.store(0, Relaxed);
        LIMIT.store(PAYLOAD_LIMIT, Relaxed);
        Ok(Self { _weights: weights })
    }
}
impl Drop for Budget {
    fn drop(&mut self) {
        LIMIT.store(0, Relaxed);
        EXEMPT_W.store(0, Relaxed);
        BUDGET_ACTIVE.store(false, Relaxed);
    }
}

pub(in crate::c71_matrix) fn simultaneous() -> Value {
    let heap = LIVE.load(Relaxed);
    let external = EXTERNAL.load(Relaxed);
    let exempt = EXEMPT_W.load(Relaxed);
    let peak = SIMULTANEOUS_PEAK.load(Relaxed);
    json!({"host_layout_bytes": heap, "native_reservation_bytes": external,
        "excluded_packed_w_capacity_bytes": exempt,
        "temporary_live_bytes": RESERVED.load(Relaxed).saturating_sub(exempt),
        "temporary_payload_peak_bytes": peak, "payload_limit_bytes": PAYLOAD_LIMIT,
        "runtime_allowance_bytes": RUNTIME_ALLOWANCE,
        "peak_plus_runtime_allowance_bytes": peak + RUNTIME_ALLOWANCE,
        "operational_margin_required_bytes": OPERATIONAL_MARGIN,
        "denied_allocations": DENIED.load(Relaxed), "enforced": LIMIT.load(Relaxed) != 0,
        "host_large_allocation_release": "glibc fixed mmap threshold 128 KiB, max 2 arenas",
        "physical_runtime_allowance_verified": false})
}

fn allocated(size: usize) {
    ALLOCATED.fetch_add(size as u64, Relaxed);
    PEAK.fetch_max(LIVE.fetch_add(size as u64, Relaxed) + size as u64, Relaxed);
}

// Counts requested layouts, including every Vec capacity and realloc, across
// both threads. System/allocator metadata, stack and mmap are instead in RSS.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !reserve(layout.size() as u64) {
            return std::ptr::null_mut();
        }
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            allocated(layout.size());
        } else {
            RESERVED.fetch_sub(layout.size() as u64, Relaxed);
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !reserve(layout.size() as u64) {
            return std::ptr::null_mut();
        }
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            allocated(layout.size());
        } else {
            RESERVED.fetch_sub(layout.size() as u64, Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size() as u64, Relaxed);
        RESERVED.fetch_sub(layout.size() as u64, Relaxed);
        FREED.fetch_add(layout.size() as u64, Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if !reserve(size as u64) {
            return std::ptr::null_mut();
        }
        PEAK.fetch_max(LIVE.load(Relaxed) + size as u64, Relaxed);
        let result = System.realloc(ptr, layout, size);
        if !result.is_null() {
            LIVE.fetch_sub(layout.size() as u64, Relaxed);
            FREED.fetch_add(layout.size() as u64, Relaxed);
            RESERVED.fetch_sub(layout.size() as u64, Relaxed);
            allocated(size);
        } else {
            RESERVED.fetch_sub(size as u64, Relaxed);
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

#[cfg(test)]
mod memory_tests {
    use super::*;

    #[test]
    fn c71_temporary_budget_combines_host_device_and_realloc_before_allocation() {
        let weights = Arc::new(vec![1i16; 1024]);
        let budget = Budget::new(&weights).unwrap();
        assert!(Budget::new(&weights).is_err());
        assert_eq!(EXEMPT_W.load(Relaxed), 2048);
        let baseline = RESERVED.load(Relaxed) - EXEMPT_W.load(Relaxed);
        LIMIT.store(baseline + 4096, Relaxed);
        let mut bytes = Vec::<u8>::new();
        let denied_host = bytes.try_reserve_exact(8192).is_err();
        let native_reserved = external(4096);
        let denied_joint = bytes.try_reserve_exact(1).is_err();
        let denied_native = external(1);
        let native_released = external(-4096);
        bytes.try_reserve_exact(4096).unwrap();
        bytes.extend([11, 12, 13]);
        let denied_realloc = bytes.try_reserve_exact(8192).is_err();
        let retained = bytes.capacity();
        let peak = SIMULTANEOUS_PEAK.load(Relaxed);
        let denied = DENIED.load(Relaxed);
        // Restore before assertions/formatting can allocate their own buffers.
        drop(budget);
        assert!(denied_host && denied_joint && denied_realloc);
        assert_eq!((native_reserved, denied_native, native_released), (0, -1, 0));
        assert_eq!(&bytes, &[11, 12, 13]);
        assert_eq!(retained, 4096);
        assert_eq!(peak, baseline + 4096);
        assert_eq!(denied, 4);
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        unsafe {
            #[repr(C)]
            struct MallInfo {
                fields: [usize; 10],
            }
            unsafe extern "C" {
                fn mallinfo2() -> MallInfo;
            }
            let before = mallinfo2().fields[4]; // hblkhd: mapped allocation bytes
            let scratch = std::hint::black_box(vec![0u8; 16 << 20]);
            let during = mallinfo2().fields[4];
            drop(scratch);
            let after = mallinfo2().fields[4];
            assert!(during >= before + (16 << 20));
            assert_eq!(after, before, "large workspace must return its mmap reservation");
        }
    }
}

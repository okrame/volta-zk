//! Bounded two-role B9 diagnostic, with disposable OS-random correlations.
use serde_json::json;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use volta_field::{Fp, Fp3, P};
use volta_pcg::c71_bootstrap::{self as bootstrap, Context};
use zeroize::Zeroize;

// Same requested-layout convention as the B3 census. No DRAM-traffic claim.
struct Allocator;
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static FREED: AtomicU64 = AtomicU64::new(0);
fn allocated(size: usize) {
    ALLOCATED.fetch_add(size as u64, Relaxed);
    PEAK.fetch_max(LIVE.fetch_add(size as u64, Relaxed) + size as u64, Relaxed);
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            allocated(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            allocated(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as u64, Relaxed);
        FREED.fetch_add(l.size() as u64, Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            LIVE.fetch_sub(l.size() as u64, Relaxed);
            FREED.fetch_add(l.size() as u64, Relaxed);
            allocated(n);
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// The adversary is a legitimate endpoint altering its own framed message.
#[derive(Default)]
struct WireCount {
    sent: AtomicU64,
    received: AtomicU64,
}
struct Channel {
    socket: UnixStream,
    pending: Vec<u8>,
    fault: String,
    count: Arc<WireCount>,
}
impl Read for Channel {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let size = self.socket.read(b)?;
        self.count.received.fetch_add(size as u64, Relaxed);
        Ok(size)
    }
}
impl Write for Channel {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.pending.extend(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let p = &mut self.pending;
        let tag = p[0];
        match (self.fault.as_str(), tag) {
            ("prover-context", 1) | ("verifier-context", 2) => p[49] ^= 1,
            ("receiver-point", 3) | ("sender-point", 4) => p[9 + 67] = 4,
            ("seed-ciphertext", 5) => {
                p[9] ^= 1;
                p[9 + 32] ^= 1;
            }
            ("cope-error", 6) => {
                for i in 0..576 {
                    let offset = 9 + 8 * i;
                    let x = u64::from_le_bytes(p[offset..offset + 8].try_into().unwrap());
                    p[offset..offset + 8]
                        .copy_from_slice(&(Fp::new(x) + Fp::ONE).value().to_le_bytes());
                }
            }
            ("check-response", 8) => {
                let offset = 9 + 72;
                let x = u64::from_le_bytes(p[offset..offset + 8].try_into().unwrap());
                p[offset..offset + 8]
                    .copy_from_slice(&(Fp::new(x) + Fp::ONE).value().to_le_bytes());
            }
            ("challenge-codec", 7) | ("compression-codec", 9) => {
                p[9..17].copy_from_slice(&P.to_le_bytes())
            }
            ("frame-order", 7) => p[0] = 9,
            _ => {}
        }
        let mut remaining = &p[..];
        while !remaining.is_empty() {
            let size = self.socket.write(remaining)?;
            if size == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.count.sent.fetch_add(size as u64, Relaxed);
            remaining = &remaining[size..];
        }
        self.socket.flush()?;
        p.zeroize();
        p.clear();
        Ok(())
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}
fn context(rows: usize) -> Context {
    Context { session: [1; 32], channel: [2; 32], capacity: [3; 32], rows }
}
fn field(a: [u64; 3]) -> Fp3 {
    Fp3::new(Fp::new(a[0]), Fp::new(a[1]), Fp::new(a[2]))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let n: usize = args.get(1).ok_or("expected row count")?.parse()?;
    if ![3, 32].contains(&n) {
        return Err("bounded diagnostic accepts 3 or 32 rows".into());
    }
    let fault = args.get(2).map(String::as_str).unwrap_or("none");
    if ![
        "none",
        "prover-context",
        "verifier-context",
        "receiver-point",
        "sender-point",
        "seed-ciphertext",
        "cope-error",
        "check-response",
        "challenge-codec",
        "compression-codec",
        "frame-order",
    ]
    .contains(&fault)
    {
        return Err("unknown adversarial case".into());
    }
    let live_start = LIVE.load(Relaxed);
    let allocated_start = ALLOCATED.load(Relaxed);
    let freed_start = FREED.load(Relaxed);
    PEAK.store(live_start, Relaxed);
    let (p, v) = UnixStream::pair()?;
    for s in [&p, &v] {
        s.set_read_timeout(Some(Duration::from_secs(50)))?;
        s.set_write_timeout(Some(Duration::from_secs(50)))?;
    }
    let p_count = Arc::new(WireCount::default());
    let v_count = Arc::new(WireCount::default());
    let channel =
        |socket, count| Channel { socket, count, pending: Vec::new(), fault: fault.to_string() };
    let pv = channel(p, p_count.clone());
    let vv = channel(v, v_count.clone());
    // Exactly two process threads: main executes V, the child executes P.
    let prover = std::thread::spawn(move || bootstrap::prover(pv, context(n)));
    let verifier = bootstrap::verifier(vv, context(n));
    let prover = prover.join().map_err(|_| "prover panic")?;
    let accepted = prover.is_ok() && verifier.is_ok();
    let p_error = prover.as_ref().err().map(ToString::to_string);
    let v_error = verifier.as_ref().err().map(ToString::to_string);
    let mut details = json!(null);
    if let (Ok(p), Ok(v)) = (&prover, &verifier) {
        assert_eq!(p.values.len(), n);
        assert_eq!(p.tags.len(), n);
        assert_eq!(v.keys.len(), n);
        for i in 0..n {
            assert_eq!(
                field(p.tags[i]),
                field(v.keys[i]) + field(*v.delta).mul_base(Fp::new(p.values[i]))
            );
        }
        let u = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
        for i in (0..n - n % 3).step_by(3) {
            let x =
                Fp3::new(Fp::new(p.values[i]), Fp::new(p.values[i + 1]), Fp::new(p.values[i + 2]));
            let t = field(p.tags[i]) + u * field(p.tags[i + 1]) + u * u * field(p.tags[i + 2]);
            let k = field(v.keys[i]) + u * field(v.keys[i + 1]) + u * u * field(v.keys[i + 2]);
            assert_eq!(t, k + field(*v.delta) * x);
        }
        assert_eq!(p.audit.sent_frames, v.audit.received_frames);
        assert_eq!(v.audit.sent_frames, p.audit.received_frames);
        let bytes: usize =
            p.audit.sent_frames.iter().chain(&v.audit.sent_frames).map(|(_, n)| n).sum();
        assert_eq!(bytes, 191232 + 576 * (n + 9) * 8 + 72 * n + 601);
        assert_eq!(bytes as u64, p_count.sent.load(Relaxed) + v_count.sent.load(Relaxed));
        assert_eq!(p_count.sent.load(Relaxed), v_count.received.load(Relaxed));
        assert_eq!(v_count.sent.load(Relaxed), p_count.received.load(Relaxed));
        let (a, b) = (&p.audit.work, &v.audit.work);
        assert_eq!(a.fixed_scalar_mul + b.fixed_scalar_mul, 2304);
        assert_eq!(a.variable_scalar_mul + b.variable_scalar_mul, 2304);
        assert_eq!(a.group_hash + b.group_hash, 2304);
        assert_eq!(a.group_candidates, b.group_candidates);
        assert_eq!(a.kdf + b.kdf, 2304);
        assert_eq!(a.point_add + b.point_add, 1728);
        assert_eq!(a.prf_field_outputs + b.prf_field_outputs, (3 * 576 * (n + 9)) as u64);
        assert_eq!(a.cope_gadget_products + b.cope_gadget_products, (2 * 576 * (n + 9)) as u64);
        assert_eq!(a.check_base_products + b.check_base_products, (9 * n) as u64);
        assert_eq!(a.check_fp9_products + b.check_fp9_products, (2 * n + 19) as u64);
        assert_eq!(
            a.compression_fp3_products + b.compression_fp3_products,
            (3 * (2 * n + 1)) as u64
        );
        assert_eq!(a.scalar_candidates + b.scalar_candidates, 8 * 2304);
        assert_eq!(
            a.field_candidates + b.field_candidates,
            8 * (3 * 576 * (n + 9) + 10 * n + 27) as u64
        );
        details = json!({"prover":p.audit,"verifier":v.audit,"protocol_wire_bytes":bytes,
            "all_base_rows_checked":n,"packed_fp3_rows_checked":n/3,"unpacked_rows":n%3});
    }
    drop(prover);
    drop(verifier);
    let live_end = LIVE.load(Relaxed);
    let allocated = ALLOCATED.load(Relaxed) - allocated_start;
    let freed = FREED.load(Relaxed) - freed_start;
    assert_eq!(live_start + allocated - freed, live_end);
    let report = json!({"schema":"c71-b9-native-v1","credit":false,"security_admitted":false,
        "rows":n,"fault":fault,"accepted":accepted,"prover_error":p_error,"verifier_error":v_error,
        "wire_io":{"prover_sent_bytes":p_count.sent.load(Relaxed),"prover_received_bytes":p_count.received.load(Relaxed),
            "verifier_sent_bytes":v_count.sent.load(Relaxed),"verifier_received_bytes":v_count.received.load(Relaxed)},
        "details":details,"heap":{"live_start_bytes":live_start,"live_end_bytes":live_end,
            "allocated_bytes":allocated,"freed_bytes":freed,"peak_requested_bytes":PEAK.load(Relaxed)},
        "physical_DRAM_traffic_measured":false,"inclusive_native_base_arithmetic_measured":false,
        "production_lifecycle_admitted":false});
    println!("{}", serde_json::to_string(&report)?);
    if accepted != (fault == "none") {
        return Err("unexpected adversarial disposition".into());
    }
    Ok(())
}

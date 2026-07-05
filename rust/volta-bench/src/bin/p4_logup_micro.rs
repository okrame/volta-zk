//! P4 step-1 microbench: the new Gruen LogUp (volta-proto) vs the P2.5 spike
//! (volta-bench) on one synthetic instance. Early signal for the
//! pre-registered ≤ 8–10 E-mult/lookup gate (lookup side; table side is
//! reported separately, raw and /12-amortized). Not a milestone report —
//! the number of record lands in p4_report on the real per-layer tables.

use volta_bench::time_paired;
use volta_field::FpStream;
use volta_proto::logup as new_lu;

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let (n_bits, t_bits) = if quick { (16u32, 12u32) } else { (20u32, 16u32) };
    let n = 1usize << n_bits;
    let seed = [7u8; 32];

    // Synthetic instance, same recipe as the spike's p25 report.
    let table: Vec<i16> = (0..1i32 << t_bits).map(|j| (j - (1 << (t_bits - 1))) as i16).collect();
    let f: Vec<i16> = (0..n)
        .map(|i| {
            let x = (i as u64).wrapping_mul(0x9E3779B97F4A7C15).rotate_left(17);
            table[(x % table.len() as u64) as usize]
        })
        .collect();
    let mut mult = vec![0u32; table.len()];
    let off = 1i32 << (t_bits - 1);
    for &v in &f {
        mult[(v as i32 + off) as usize] += 1;
    }

    // --- E-mult counts, per side (new) ---
    let mut chal = FpStream::domain_separated(seed, 0x1004);
    let alpha = chal.next_fp2();
    let mut ctr_f = new_lu::Counters::default();
    let _ = new_lu::prove_frac_tree(&new_lu::LeafP::Ones, &new_lu::lift_q(&f, alpha), &mut chal, &mut ctr_f);
    let mut ctr_t = new_lu::Counters::default();
    let _ = new_lu::prove_frac_tree(
        &new_lu::LeafP::NegMult(&mult),
        &new_lu::lift_q(&table, alpha),
        &mut chal,
        &mut ctr_t,
    );
    let lk = ctr_f.emult_equiv() / n as f64;
    let tb = ctr_t.emult_equiv() / n as f64;
    eprintln!("new  lookup-side : {:>7.2} E-mult/lookup  (fp2 {} base {})", lk, ctr_f.fp2_mults, ctr_f.base_mults);
    eprintln!("new  table-side  : {:>7.2} E-mult/lookup raw, {:>5.2} /12-amortized", tb, tb / 12.0);
    eprintln!("new  total       : {:>7.2} (gate is on lookup-side, target ≤ 8–10)", lk + tb);

    // --- spike count on the same instance ---
    let mut chal_s = FpStream::domain_separated(seed, 0x1005);
    let mut ctr_s = volta_bench::logup::Counters::default();
    let (_a, _p) = volta_bench::logup::logup_prove(&f, &table, &mult, &mut chal_s, &mut ctr_s);
    eprintln!("spike total      : {:>7.2} E-mult/lookup", ctr_s.emult_equiv() / n as f64);

    // --- verify round-trip (new) ---
    let mut cp = FpStream::domain_separated(seed, 0x1006);
    let mut cv = FpStream::domain_separated(seed, 0x1006);
    let mut c1 = new_lu::Counters::default();
    let mut c2 = new_lu::Counters::default();
    let (_a2, proof) = new_lu::logup_prove(&f, &table, &mult, &mut cp, &mut c1);
    assert!(new_lu::logup_verify(&f, &table, &mult, &proof, &mut cv, &mut c2), "verify failed");
    eprintln!("verify           : ok, {:.0} E-mult total, proof {} KB", c2.emult_equiv(), proof.bytes() / 1024);

    // --- wall time, ABBA vs spike ---
    let rounds = if quick { 3 } else { 5 };
    let (t_new, t_spike) = time_paired(
        1,
        rounds,
        || {
            let mut c = FpStream::domain_separated(seed, 0x2000);
            let mut ctr = new_lu::Counters::default();
            let (_x, p) = new_lu::logup_prove(&f, &table, &mult, &mut c, &mut ctr);
            std::hint::black_box(p.bytes());
        },
        || {
            let mut c = FpStream::domain_separated(seed, 0x2001);
            let mut ctr = volta_bench::logup::Counters::default();
            let (_x, p) = volta_bench::logup::logup_prove(&f, &table, &mult, &mut c, &mut ctr);
            std::hint::black_box(p.bytes());
        },
    );
    let ns_new = t_new.as_nanos() as f64 / n as f64;
    let ns_spike = t_spike.as_nanos() as f64 / n as f64;
    eprintln!(
        "wall (ABBA)      : new {:.0} ns/lookup vs spike {:.0} ns/lookup ({:.1}×), {} threads",
        ns_new,
        ns_spike,
        ns_spike / ns_new,
        rayon::current_num_threads()
    );
}

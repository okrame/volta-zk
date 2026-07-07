//! Criterion microbench for the P1 gate: fused MAC epilogue vs native GEMM,
//! plus verifier-side streaming primitives. The JSON of record comes from
//! `p1_report`; this bench provides confidence intervals.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use volta_bench::verifier_fused_scan;
use volta_field::{Fp, Fp2};
use volta_gpt2::{gemm_requant, gemm_requant_auth, EpilogueSpec};

fn bench_gemm(c: &mut Criterion) {
    let shapes = [(100usize, 768usize, 768usize), (100, 768, 2304), (100, 768, 3072)];
    let mut g = c.benchmark_group("p1_gemm");
    g.sample_size(10);
    for (m, k, n) in shapes {
        let a: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
        let b: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
        let ep = EpilogueSpec { shift: 8, seed: [1; 32], tensor_tag: 3 };
        g.bench_with_input(BenchmarkId::new("native", format!("{m}x{k}x{n}")), &(), |bch, _| {
            bch.iter(|| gemm_requant(&a, &b, m, k, n, 8))
        });
        g.bench_with_input(BenchmarkId::new("fused_mac", format!("{m}x{k}x{n}")), &(), |bch, _| {
            bch.iter(|| gemm_requant_auth(&a, &b, m, k, n, ep))
        });
    }
    g.finish();
}

fn bench_verifier(c: &mut Criterion) {
    let n_elems = 1usize << 20;
    let corr: Vec<u64> =
        (0..n_elems).map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();
    let delta = Fp2::new(Fp::new(123456789), Fp::new(987654321));
    let rs: Vec<Fp2> =
        (0..20).map(|j| Fp2::new(Fp::new(j as u64 + 2), Fp::new(3 * j as u64 + 1))).collect();
    let mut g = c.benchmark_group("p1_verifier");
    g.sample_size(10);
    g.bench_function("fused_scan_2^20", |bch| {
        bch.iter(|| verifier_fused_scan([2; 32], 5, delta, &rs, &corr))
    });
    g.finish();
}

criterion_group!(benches, bench_gemm, bench_verifier);
criterion_main!(benches);

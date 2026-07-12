//! P1 verifier-side primitives and the timing/report harness.
//!
//! The verifier never materializes keys or eq(r,·): `EqStream` generates the
//! equality vector with O(log N) state and ~2 amortized Fp2 mults per element;
//! the fused pass expands mock-PCG keys, applies the correction update
//! `k_x = k_r + Δ·δ`, and accumulates `⟨eq(r,·), k_x⟩` in one scan.

pub mod logits_pack;
pub mod logup;

use volta_field::{Fp, Fp2, FpStream};

/// Cloud-instance fingerprint carried by every cloud run of record.
///
/// The harness intentionally reads these values from explicit environment
/// variables instead of guessing provider metadata from the host.  Setting
/// `VOLTA_CLOUD_PROVIDER` enables the record and makes every other field
/// mandatory, so a partially-described cloud JSON cannot be written.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CloudMetadata {
    pub provider: String,
    pub instance_id: String,
    pub region: String,
    pub image: String,
    pub driver_version: String,
    pub cuda_version: String,
    pub gpu_sku: String,
    pub cpu_model: String,
    pub ram_gib: String,
    pub vcpus: String,
}

pub fn cloud_metadata_from_env() -> Option<CloudMetadata> {
    let provider = match std::env::var("VOLTA_CLOUD_PROVIDER") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return None,
    };
    let required = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is required when VOLTA_CLOUD_PROVIDER is set"))
    };
    Some(CloudMetadata {
        provider,
        instance_id: required("VOLTA_CLOUD_INSTANCE_ID"),
        region: required("VOLTA_CLOUD_REGION"),
        image: required("VOLTA_CLOUD_IMAGE"),
        driver_version: required("VOLTA_CLOUD_DRIVER_VERSION"),
        cuda_version: required("VOLTA_CLOUD_CUDA_VERSION"),
        gpu_sku: required("VOLTA_CLOUD_GPU_SKU"),
        cpu_model: required("VOLTA_CLOUD_CPU_MODEL"),
        ram_gib: required("VOLTA_CLOUD_RAM_GIB"),
        vcpus: required("VOLTA_CLOUD_VCPUS"),
    })
}

/// Streaming eq(r, ·) over `{0,1}^n_vars` in index order, O(n_vars) state,
/// amortized ~2 Fp2 mults per element (tensor-product suffix recomputation).
pub struct EqStream {
    rs: Vec<Fp2>,
    one_minus_rs: Vec<Fp2>,
    /// parts[j] = Π_{l ≥ j} factor_l for the current index; parts[n_vars] = 1.
    parts: Vec<Fp2>,
    idx: u64,
    len: u64,
}

impl EqStream {
    pub fn new(rs: &[Fp2]) -> EqStream {
        let n = rs.len();
        assert!(n < 63);
        let one_minus_rs: Vec<Fp2> = rs.iter().map(|&r| Fp2::ONE - r).collect();
        let mut parts = vec![Fp2::ONE; n + 1];
        for j in (0..n).rev() {
            parts[j] = parts[j + 1] * one_minus_rs[j];
        }
        EqStream { rs: rs.to_vec(), one_minus_rs, parts, idx: 0, len: 1u64 << n }
    }

    /// eq(r, idx), then advance. Panics past the end.
    #[inline]
    pub fn next(&mut self) -> Fp2 {
        let val = self.parts[0];
        let prev = self.idx;
        self.idx += 1;
        if self.idx < self.len {
            let t = (prev ^ self.idx).ilog2() as usize; // highest flipped bit → 1
            self.parts[t] = self.parts[t + 1] * self.rs[t];
            for j in (0..t).rev() {
                self.parts[j] = self.parts[j + 1] * self.one_minus_rs[j];
            }
        }
        val
    }
}

/// Correction-based key update: `k_x = k_r + Δ·δ` (δ ∈ F_p ⇒ 2 base mults).
#[inline]
pub fn key_update(k_r: Fp2, delta: Fp2, corr: u64) -> Fp2 {
    k_r + delta.mul_base(Fp::new(corr))
}

/// One fused verifier scan over an authenticated tensor of `corr.len()`
/// elements (padded to the next power of two with zero corrections):
/// expand `k_r` from the mock-PCG stream, update with the correction, and
/// accumulate the MLE-opening inner product `⟨eq(r,·), k_x⟩`.
pub fn verifier_fused_scan(
    seed: [u8; 32],
    domain: u64,
    delta: Fp2,
    rs: &[Fp2],
    corr: &[u64],
) -> Fp2 {
    assert!(corr.len() <= 1usize << rs.len());
    let mut keys = FpStream::domain_separated(seed, domain);
    let mut eq = EqStream::new(rs);
    let mut acc = Fp2::ZERO;
    for &c in corr {
        let k_x = key_update(keys.next_fp2(), delta, c);
        acc += eq.next() * k_x;
    }
    acc
}

/// Median wall time of `iters` runs after `warmup` runs.
pub fn time_median<T>(
    warmup: usize,
    iters: usize,
    mut f: impl FnMut() -> T,
) -> std::time::Duration {
    for _ in 0..warmup {
        std::hint::black_box(f());
    }
    let mut times: Vec<_> = (0..iters)
        .map(|_| {
            let t0 = std::time::Instant::now();
            std::hint::black_box(f());
            t0.elapsed()
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

/// Drift-cancelling paired timing: alternates A/B in ABBA order per round so
/// slow frequency/thermal drift (VM on M2) hits both sides equally. Raw
/// samples remain in execution order so reports can retain dispersion.
pub struct PairedTimingSamples {
    pub a: Vec<std::time::Duration>,
    pub b: Vec<std::time::Duration>,
}

impl PairedTimingSamples {
    pub fn medians(&self) -> (std::time::Duration, std::time::Duration) {
        fn median(xs: &[std::time::Duration]) -> std::time::Duration {
            let mut sorted = xs.to_vec();
            sorted.sort();
            sorted[sorted.len() / 2]
        }
        (median(&self.a), median(&self.b))
    }
}

pub fn time_paired_samples<T, U>(
    warmup: usize,
    rounds: usize,
    mut fa: impl FnMut() -> T,
    mut fb: impl FnMut() -> U,
) -> PairedTimingSamples {
    assert!(rounds > 0, "paired timing needs at least one round");
    for _ in 0..warmup {
        std::hint::black_box(fa());
        std::hint::black_box(fb());
    }
    let mut ta = Vec::with_capacity(rounds * 2);
    let mut tb = Vec::with_capacity(rounds * 2);
    let mut run_a = |ts: &mut Vec<std::time::Duration>| {
        let t0 = std::time::Instant::now();
        std::hint::black_box(fa());
        ts.push(t0.elapsed());
    };
    let mut run_b = |ts: &mut Vec<std::time::Duration>| {
        let t0 = std::time::Instant::now();
        std::hint::black_box(fb());
        ts.push(t0.elapsed());
    };
    for _ in 0..rounds {
        run_a(&mut ta);
        run_b(&mut tb);
        run_b(&mut tb);
        run_a(&mut ta);
    }
    PairedTimingSamples { a: ta, b: tb }
}

/// Compatibility wrapper returning only the ABBA medians.
pub fn time_paired<T, U>(
    warmup: usize,
    rounds: usize,
    fa: impl FnMut() -> T,
    fb: impl FnMut() -> U,
) -> (std::time::Duration, std::time::Duration) {
    time_paired_samples(warmup, rounds, fa, fb).medians()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn paired_timing_medians_do_not_destroy_raw_order() {
        use std::time::Duration;
        let samples = PairedTimingSamples {
            a: vec![Duration::from_millis(9), Duration::from_millis(1), Duration::from_millis(5)],
            b: vec![Duration::from_millis(2), Duration::from_millis(8), Duration::from_millis(4)],
        };
        assert_eq!(samples.medians(), (Duration::from_millis(5), Duration::from_millis(4)));
        assert_eq!(samples.a[0], Duration::from_millis(9));
        assert_eq!(samples.b[0], Duration::from_millis(2));
    }

    #[test]
    fn eq_stream_matches_direct_product_and_sums_to_one() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let rs: Vec<Fp2> = (0..5)
            .map(|_| {
                Fp2::new(
                    Fp::new(rng.gen_range(0..volta_field::P)),
                    Fp::new(rng.gen_range(0..volta_field::P)),
                )
            })
            .collect();
        let mut eq = EqStream::new(&rs);
        let mut total = Fp2::ZERO;
        for i in 0u64..32 {
            let direct = (0..5).fold(Fp2::ONE, |p, j| {
                p * if (i >> j) & 1 == 1 { rs[j] } else { Fp2::ONE - rs[j] }
            });
            let got = eq.next();
            assert_eq!(got, direct, "index {i}");
            total += got;
        }
        assert_eq!(total, Fp2::ONE); // Σ_b eq(r,b) = 1
    }

    #[test]
    fn fused_scan_equals_mle_of_plaintexts() {
        // MAC invariant end-to-end: if corrections encode x (δ = x − r), then
        // ⟨eq, k_x⟩ = ⟨eq, m_x⟩ + Δ·⟨eq, x⟩ with m_x = m_r. Check the k-side
        // scan against a direct computation from the same streams.
        let seed = [7u8; 32];
        let domain = 42;
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let rs: Vec<Fp2> =
            (0..4).map(|_| Fp2::new(Fp::new(rng.gen_range(0..volta_field::P)), Fp::ZERO)).collect();
        let xs: Vec<Fp> = (0..16).map(|_| Fp::new(rng.gen_range(0..1000))).collect();

        // Prover side: k_r plays the tag role here (value-level VOLE mock:
        // the test uses k_r = m_r + Δ·r with r from an aligned mask stream).
        let mut masks = FpStream::domain_separated(seed, domain ^ 1);
        let mut tags = FpStream::domain_separated(seed, domain ^ 2);
        let (mut corr, mut keys) = (Vec::new(), Vec::new());
        for &x in &xs {
            let r = masks.next_fp();
            let m_r = tags.next_fp2();
            corr.push((x - r).value());
            keys.push(m_r + delta.mul_base(r));
        }

        // Verifier scan with keys materialized (bypass ChaCha key stream).
        let mut eq = EqStream::new(&rs);
        let mut acc = Fp2::ZERO;
        for (&k_r, &c) in keys.iter().zip(&corr) {
            acc += eq.next() * key_update(k_r, delta, c);
        }

        // Expected: ⟨eq, m_r⟩ + Δ·⟨eq, x⟩.
        let mut eq2 = EqStream::new(&rs);
        let mut tags2 = FpStream::domain_separated(seed, domain ^ 2);
        let mut expected = Fp2::ZERO;
        for &x in &xs {
            let e = eq2.next();
            expected += e * tags2.next_fp2() + (e * delta).mul_base(x);
        }
        assert_eq!(acc, expected);
    }
}

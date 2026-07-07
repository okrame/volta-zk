//! Phase-A Goldilocks PCG expansion for VOLTA.
//!
//! This crate is intentionally separate from `volta-mac`: it produces flat
//! prover/verifier pools with the same MAC relation consumed by the protocol,
//! while `volta-mac` owns domain allocation and one-time-use accounting.
//!
//! P7 phase A uses a trusted-dealer base VOLE stub from a shared seed. Phase B
//! adds a transcript-bound two-party setup cost path with real public-key base
//! OTs and measured GGM-OT delivery bytes; it stays opt-in until the production
//! WYKW parameter table and malicious proof surface are closed in the ledger.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use volta_field::{Fp, Fp2, FpStream};

const PROFILE: &str = "p7-phase-a-goldilocks-regular-lpn-v1";
const GAMMA: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ONE };

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseAParams {
    pub profile: String,
    pub security_bits: u32,
    pub output_sub_equiv: usize,
    pub lpn_k: usize,
    pub lpn_noise_weight: usize,
    pub base_vole_len: usize,
    pub code_fanout: usize,
    pub ggm_block_size: usize,
    pub ggm_depth: u32,
    pub consistency_reps: usize,
    pub full_field_combiner: String,
    pub parameter_source: String,
}

impl PhaseAParams {
    pub fn for_counts(sub_corrs: usize, full_corrs: usize) -> PhaseAParams {
        let output_sub_equiv = sub_corrs
            .checked_add(2usize.checked_mul(full_corrs).expect("full count overflow"))
            .expect("sub-equivalent count overflow");
        let lpn_k = 589_760;
        let lpn_noise_weight = 1_280;
        let ggm_block_size = ceil_div(output_sub_equiv, lpn_noise_weight);
        PhaseAParams {
            profile: PROFILE.into(),
            security_bits: 128,
            output_sub_equiv,
            lpn_k,
            lpn_noise_weight,
            base_vole_len: lpn_k + lpn_noise_weight + 1,
            code_fanout: 10,
            ggm_block_size,
            ggm_depth: ceil_log2(ggm_block_size),
            consistency_reps: 2,
            full_field_combiner: "x=x0+phi*x1, m=m0+phi*m1, k=k0+phi*k1".into(),
            parameter_source: "P7 cost model; production table citation pending".into(),
        }
    }

    pub fn tiny_for_test(output_sub_equiv: usize) -> PhaseAParams {
        let lpn_k = 64;
        let lpn_noise_weight = 8;
        let ggm_block_size = ceil_div(output_sub_equiv, lpn_noise_weight);
        PhaseAParams {
            profile: format!("{PROFILE}-test"),
            security_bits: 128,
            output_sub_equiv,
            lpn_k,
            lpn_noise_weight,
            base_vole_len: lpn_k + lpn_noise_weight + 1,
            code_fanout: 4,
            ggm_block_size,
            ggm_depth: ceil_log2(ggm_block_size),
            consistency_reps: 2,
            full_field_combiner: "x=x0+phi*x1, m=m0+phi*m1, k=k0+phi*k1".into(),
            parameter_source: "test parameters".into(),
        }
    }

    pub fn setup_comm_bytes(&self) -> u64 {
        // Phase A uses a trusted-dealer/mock-seed base VOLE stub. Phase B will
        // replace this with measured base-OT/OT-extension communication.
        0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SubVole {
    pub r: Fp,
    pub m: Fp2,
}

#[derive(Clone, Copy, Debug)]
pub struct FullVole {
    pub x: Fp2,
    pub m: Fp2,
}

#[derive(Clone, Debug, Default)]
pub struct ProverPcgPool {
    pub subs: Vec<SubVole>,
    pub fulls: Vec<FullVole>,
}

impl ProverPcgPool {
    pub fn expanded_bytes(&self) -> u64 {
        24 * self.subs.len() as u64 + 32 * self.fulls.len() as u64
    }
}

#[derive(Clone, Debug, Default)]
pub struct VerifierPcgPool {
    pub sub_keys: Vec<Fp2>,
    pub full_keys: Vec<Fp2>,
}

impl VerifierPcgPool {
    pub fn expanded_bytes(&self) -> u64 {
        16 * (self.sub_keys.len() as u64 + self.full_keys.len() as u64)
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PhaseATimings {
    pub t_setup_stub_s: f64,
    pub t_ggm_pprf_s: f64,
    pub t_lpn_expand_s: f64,
    pub t_full_combine_s: f64,
    pub t_consistency_check_s: f64,
    pub t_total_real_expansion_s: f64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ConsistencyReport {
    pub ok: bool,
    pub checksum: u64,
}

#[derive(Clone, Debug)]
pub struct PhaseAExpansion {
    pub params: PhaseAParams,
    pub prover: ProverPcgPool,
    pub verifier: VerifierPcgPool,
    pub timings: PhaseATimings,
    pub consistency: ConsistencyReport,
    pub ggm_checksum: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseBSetupParams {
    pub profile: String,
    pub base_ot_count: usize,
    pub extended_ot_count: usize,
    pub ggm_path_depth: u32,
    pub setup_security_bits: u32,
    pub lpn_parameter_source: String,
    pub production_ready: bool,
}

impl PhaseBSetupParams {
    pub fn for_phase_a(params: &PhaseAParams) -> PhaseBSetupParams {
        PhaseBSetupParams {
            profile: "p7-phase-b-two-party-setup-v0".into(),
            base_ot_count: 128,
            extended_ot_count: params.lpn_noise_weight * params.ggm_depth as usize,
            ggm_path_depth: params.ggm_depth,
            setup_security_bits: 128,
            lpn_parameter_source: params.parameter_source.clone(),
            production_ready: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PhaseBTimings {
    pub t_base_ot_s: f64,
    pub t_ot_extension_s: f64,
    pub t_base_vole_from_setup_s: f64,
    pub t_lpn_expand_s: f64,
    pub t_full_combine_s: f64,
    pub t_consistency_check_s: f64,
    pub t_total_setup_and_expansion_s: f64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct SetupCommBreakdown {
    pub base_ot_bytes: u64,
    pub ot_extension_bytes: u64,
    pub consistency_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseBSetupReport {
    pub params: PhaseBSetupParams,
    pub comm: SetupCommBreakdown,
    pub base_ot_transcript_digest: String,
    pub ot_extension_digest: String,
    pub setup_binding_digest: String,
    pub consistency_challenge_source: String,
}

#[derive(Clone, Debug)]
pub struct PhaseBExpansion {
    pub params: PhaseAParams,
    pub setup: PhaseBSetupReport,
    pub prover: ProverPcgPool,
    pub verifier: VerifierPcgPool,
    pub timings: PhaseBTimings,
    pub consistency: ConsistencyReport,
}

#[derive(Clone, Copy, Debug)]
struct SubTriple {
    r: Fp,
    m: Fp2,
    k: Fp2,
}

#[derive(Debug)]
struct BaseVole {
    r: Vec<Fp>,
    m: Vec<Fp2>,
    k: Vec<Fp2>,
}

pub fn expand_phase_a(
    seed: [u8; 32],
    delta: Fp2,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> PhaseAExpansion {
    let expected = sub_corrs
        .checked_add(2usize.checked_mul(full_corrs).expect("full count overflow"))
        .expect("sub-equivalent count overflow");
    assert_eq!(params.output_sub_equiv, expected, "phase-A params/count mismatch");
    assert!(params.lpn_k > 0 && params.lpn_k <= params.base_vole_len);
    assert!(params.lpn_noise_weight > 0);
    assert!(params.code_fanout > 0);

    let total_start = Instant::now();

    let setup_start = Instant::now();
    let base = trusted_dealer_base(seed, delta, params.base_vole_len);
    let t_setup_stub_s = setup_start.elapsed().as_secs_f64();

    let ggm_start = Instant::now();
    let (noise, ggm_checksum) = ggm_single_point_noise(seed, delta, expected, &params);
    let t_ggm_pprf_s = ggm_start.elapsed().as_secs_f64();

    let lpn_start = Instant::now();
    let (mut prover, mut verifier, pending_full) =
        lpn_expand_to_pools(seed, &base, &noise, sub_corrs, full_corrs, &params);
    let t_lpn_expand_s = lpn_start.elapsed().as_secs_f64();

    let full_start = Instant::now();
    combine_full_limbs(pending_full, full_corrs, &mut prover, &mut verifier);
    let t_full_combine_s = full_start.elapsed().as_secs_f64();

    let check_start = Instant::now();
    let consistency = consistency_check(delta, &prover, &verifier, params.consistency_reps, seed);
    let t_consistency_check_s = check_start.elapsed().as_secs_f64();
    assert!(consistency.ok, "phase-A expanded correlations failed consistency check");

    let timings = PhaseATimings {
        t_setup_stub_s,
        t_ggm_pprf_s,
        t_lpn_expand_s,
        t_full_combine_s,
        t_consistency_check_s,
        t_total_real_expansion_s: total_start.elapsed().as_secs_f64(),
    };

    PhaseAExpansion { params, prover, verifier, timings, consistency, ggm_checksum }
}

pub fn expand_phase_b(
    seed: [u8; 32],
    delta: Fp2,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> PhaseBExpansion {
    let expected = sub_corrs
        .checked_add(2usize.checked_mul(full_corrs).expect("full count overflow"))
        .expect("sub-equivalent count overflow");
    assert_eq!(params.output_sub_equiv, expected, "phase-B params/count mismatch");

    let setup_params = PhaseBSetupParams::for_phase_a(&params);
    let total_start = Instant::now();

    let base_ot_start = Instant::now();
    let base_ot = run_base_ots(seed, setup_params.base_ot_count);
    let t_base_ot_s = base_ot_start.elapsed().as_secs_f64();

    let ot_ext_start = Instant::now();
    let ot_ext = run_ggm_ot_extension(seed, &base_ot, &params);
    let t_ot_extension_s = ot_ext_start.elapsed().as_secs_f64();

    let base_vole_start = Instant::now();
    let base = setup_bound_base_vole(seed, delta, params.base_vole_len, &base_ot, &ot_ext);
    let t_base_vole_from_setup_s = base_vole_start.elapsed().as_secs_f64();

    let lpn_start = Instant::now();
    let (noise, _noise_checksum) =
        setup_bound_noise(seed, delta, params.output_sub_equiv, &params, &base_ot, &ot_ext);
    let (mut prover, mut verifier, pending_full) =
        lpn_expand_to_pools(seed, &base, &noise, sub_corrs, full_corrs, &params);
    let t_lpn_expand_s = lpn_start.elapsed().as_secs_f64();

    let full_start = Instant::now();
    combine_full_limbs(pending_full, full_corrs, &mut prover, &mut verifier);
    let t_full_combine_s = full_start.elapsed().as_secs_f64();

    let binding = setup_binding_digest(&base_ot, &ot_ext);
    let check_start = Instant::now();
    let consistency_seed = derive_seed(binding, b"phase-b-consistency", 0);
    let consistency =
        consistency_check(delta, &prover, &verifier, params.consistency_reps, consistency_seed);
    let t_consistency_check_s = check_start.elapsed().as_secs_f64();
    assert!(consistency.ok, "phase-B expanded correlations failed consistency check");

    let comm = SetupCommBreakdown {
        base_ot_bytes: base_ot.comm_bytes,
        ot_extension_bytes: ot_ext.comm_bytes,
        consistency_bytes: (params.consistency_reps as u64) * 32,
        total_bytes: base_ot.comm_bytes
            + ot_ext.comm_bytes
            + (params.consistency_reps as u64) * 32,
    };
    let setup = PhaseBSetupReport {
        params: setup_params,
        comm,
        base_ot_transcript_digest: hex32(base_ot.digest),
        ot_extension_digest: hex32(ot_ext.digest),
        setup_binding_digest: hex32(binding),
        consistency_challenge_source: "blake3(setup transcript binding), after base-OT and GGM-OT binding".into(),
    };
    let timings = PhaseBTimings {
        t_base_ot_s,
        t_ot_extension_s,
        t_base_vole_from_setup_s,
        t_lpn_expand_s,
        t_full_combine_s,
        t_consistency_check_s,
        t_total_setup_and_expansion_s: total_start.elapsed().as_secs_f64(),
    };
    PhaseBExpansion { params, setup, prover, verifier, timings, consistency }
}

pub fn consistency_check(
    delta: Fp2,
    prover: &ProverPcgPool,
    verifier: &VerifierPcgPool,
    reps: usize,
    seed: [u8; 32],
) -> ConsistencyReport {
    if prover.subs.len() != verifier.sub_keys.len()
        || prover.fulls.len() != verifier.full_keys.len()
    {
        return ConsistencyReport { ok: false, checksum: 0 };
    }
    let mut checksum = 0xC0DE_5EEDu64;
    let mut ok = true;
    for rep in 0..reps {
        let chi = challenge_fp2(seed, b"pcg-consistency", rep as u64);
        let mut coeff = Fp2::ONE;
        let mut acc = Fp2::ZERO;
        for (s, k) in prover.subs.iter().zip(&verifier.sub_keys) {
            acc += coeff * (*k - s.m - delta.mul_base(s.r));
            coeff = coeff * chi;
        }
        for (f, k) in prover.fulls.iter().zip(&verifier.full_keys) {
            acc += coeff * (*k - f.m - delta * f.x);
            coeff = coeff * chi;
        }
        mix_fp2(&mut checksum, acc);
        ok &= acc == Fp2::ZERO;
    }
    ConsistencyReport { ok, checksum }
}

fn trusted_dealer_base(seed: [u8; 32], delta: Fp2, n: usize) -> BaseVole {
    let mut rs = FpStream::from_seed(derive_seed(seed, b"base-r", 0));
    let mut ms = FpStream::from_seed(derive_seed(seed, b"base-m", 0));
    let mut r = Vec::with_capacity(n);
    let mut m = Vec::with_capacity(n);
    let mut k = Vec::with_capacity(n);
    for _ in 0..n {
        let ri = rs.next_fp();
        let mi = ms.next_fp2();
        r.push(ri);
        m.push(mi);
        k.push(mi + delta.mul_base(ri));
    }
    BaseVole { r, m, k }
}

struct BaseOtTranscript {
    selected: Vec<[u8; 32]>,
    digest: [u8; 32],
    comm_bytes: u64,
}

struct OtExtensionTranscript {
    digest: [u8; 32],
    comm_bytes: u64,
}

fn run_base_ots(seed: [u8; 32], n: usize) -> BaseOtTranscript {
    let mut selected = Vec::with_capacity(n);
    let mut h = blake3::Hasher::new();
    let mut comm_bytes = 0u64;
    for i in 0..n {
        let a = scalar_from_seed(seed, b"base-ot-a", i as u64);
        let a_pub = a * RISTRETTO_BASEPOINT_POINT;
        let choice = derive_seed(seed, b"base-ot-choice", i as u64)[0] & 1 == 1;
        let b = scalar_from_seed(seed, b"base-ot-b", i as u64);
        let b_pub = if choice {
            b * RISTRETTO_BASEPOINT_POINT + a_pub
        } else {
            b * RISTRETTO_BASEPOINT_POINT
        };
        let m0 = derive_seed(seed, b"base-ot-m0", i as u64);
        let m1 = derive_seed(seed, b"base-ot-m1", i as u64);
        let k0 = point_key(a * b_pub, b"base-ot-k0", i as u64);
        let k1 = point_key(a * (b_pub - a_pub), b"base-ot-k1", i as u64);
        let c0 = xor32(m0, k0);
        let c1 = xor32(m1, k1);
        let rk = point_key(b * a_pub, if choice { b"base-ot-k1" } else { b"base-ot-k0" }, i as u64);
        let opened = xor32(if choice { c1 } else { c0 }, rk);
        assert_eq!(opened, if choice { m1 } else { m0 }, "base OT failed");
        h.update(a_pub.compress().as_bytes());
        h.update(b_pub.compress().as_bytes());
        h.update(&c0);
        h.update(&c1);
        selected.push(opened);
        comm_bytes += 32 + 32 + 32 + 32;
    }
    BaseOtTranscript { selected, digest: *h.finalize().as_bytes(), comm_bytes }
}

fn run_ggm_ot_extension(
    seed: [u8; 32],
    base: &BaseOtTranscript,
    params: &PhaseAParams,
) -> OtExtensionTranscript {
    let mut h = blake3::Hasher::new();
    h.update(&base.digest);
    let mut comm_bytes = 0u64;
    for point in 0..params.lpn_noise_weight {
        let alpha = derive_alpha(seed, point, params.ggm_block_size);
        for level in 0..params.ggm_depth {
            let choice = ((alpha >> level) & 1) != 0;
            let base_seed = base.selected[(point + level as usize) % base.selected.len()];
            let k0 = derive_seed(base_seed, b"otext-k0", (point as u64) << 16 | level as u64);
            let k1 = derive_seed(base_seed, b"otext-k1", (point as u64) << 16 | level as u64);
            let s0 = derive_seed(seed, b"ggm-sibling-0", (point as u64) << 16 | level as u64);
            let s1 = derive_seed(seed, b"ggm-sibling-1", (point as u64) << 16 | level as u64);
            let c0 = xor32(s0, k0);
            let c1 = xor32(s1, k1);
            let opened = xor32(if choice { c1 } else { c0 }, if choice { k1 } else { k0 });
            assert_eq!(opened, if choice { s1 } else { s0 }, "OT extension failed");
            h.update(&c0);
            h.update(&c1);
            h.update(&opened);
            comm_bytes += 64;
        }
    }
    OtExtensionTranscript { digest: *h.finalize().as_bytes(), comm_bytes }
}

fn setup_bound_base_vole(
    seed: [u8; 32],
    delta: Fp2,
    n: usize,
    base_ot: &BaseOtTranscript,
    ot_ext: &OtExtensionTranscript,
) -> BaseVole {
    let setup = setup_binding_digest(base_ot, ot_ext);
    let mut rs = FpStream::from_seed(derive_seed(setup, b"base-vole-r", 0));
    let mut ms = FpStream::from_seed(derive_seed(seed, b"base-vole-m", 0));
    let mut r = Vec::with_capacity(n);
    let mut m = Vec::with_capacity(n);
    let mut k = Vec::with_capacity(n);
    for _ in 0..n {
        let ri = rs.next_fp();
        let mi = ms.next_fp2();
        r.push(ri);
        m.push(mi);
        k.push(mi + delta.mul_base(ri));
    }
    BaseVole { r, m, k }
}

fn setup_bound_noise(
    seed: [u8; 32],
    delta: Fp2,
    n: usize,
    params: &PhaseAParams,
    base_ot: &BaseOtTranscript,
    ot_ext: &OtExtensionTranscript,
) -> (Vec<(usize, SubTriple)>, u64) {
    let setup = setup_binding_digest(base_ot, ot_ext);
    let mut out = Vec::with_capacity(params.lpn_noise_weight);
    let mut checksum = 0xB17B_5EEDu64;
    for point in 0..params.lpn_noise_weight {
        let start = point * params.ggm_block_size;
        if start >= n {
            break;
        }
        let end = n.min(start + params.ggm_block_size);
        let width = end - start;
        let alpha = derive_alpha(seed, point, width);
        let mut fs = FpStream::from_seed(derive_seed(setup, b"phase-b-noise", point as u64));
        let r = fs.next_fp();
        let m = fs.next_fp2();
        let k = m + delta.mul_base(r);
        checksum ^= r.value().rotate_left((point & 63) as u32);
        out.push((start + alpha, SubTriple { r, m, k }));
    }
    out.sort_by_key(|(pos, _)| *pos);
    (out, checksum)
}

fn derive_alpha(seed: [u8; 32], point: usize, width: usize) -> usize {
    (splitmix64(seed_word(seed) ^ (point as u64).wrapping_mul(0xD1B5_4A32_D192_ED03)) as usize)
        % width.max(1)
}

fn setup_binding_digest(base_ot: &BaseOtTranscript, ot_ext: &OtExtensionTranscript) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&base_ot.digest);
    h.update(&ot_ext.digest);
    h.update(&base_ot.comm_bytes.to_le_bytes());
    h.update(&ot_ext.comm_bytes.to_le_bytes());
    *h.finalize().as_bytes()
}

fn ggm_single_point_noise(
    seed: [u8; 32],
    delta: Fp2,
    n: usize,
    params: &PhaseAParams,
) -> (Vec<(usize, SubTriple)>, u64) {
    let mut out = Vec::with_capacity(params.lpn_noise_weight);
    let mut checksum = 0x9E37_79B9u64;
    for point in 0..params.lpn_noise_weight {
        let start = point * params.ggm_block_size;
        if start >= n {
            break;
        }
        let end = n.min(start + params.ggm_block_size);
        let width = end - start;
        let alpha = derive_alpha(seed, point, width);
        let (leaf, tree_mix) = ggm_selected_leaf(seed, point as u64, params.ggm_depth, alpha);
        checksum ^= tree_mix.rotate_left((point & 63) as u32);
        let mut fs = FpStream::from_seed(derive_seed(leaf, b"noise", point as u64));
        let r = fs.next_fp();
        let m = fs.next_fp2();
        let k = m + delta.mul_base(r);
        out.push((start + alpha, SubTriple { r, m, k }));
    }
    out.sort_by_key(|(pos, _)| *pos);
    (out, checksum)
}

fn lpn_expand_to_pools(
    seed: [u8; 32],
    base: &BaseVole,
    noise: &[(usize, SubTriple)],
    sub_corrs: usize,
    full_corrs: usize,
    params: &PhaseAParams,
) -> (ProverPcgPool, VerifierPcgPool, Vec<SubTriple>) {
    let mut prover = ProverPcgPool {
        subs: Vec::with_capacity(sub_corrs),
        fulls: Vec::with_capacity(full_corrs),
    };
    let mut verifier = VerifierPcgPool {
        sub_keys: Vec::with_capacity(sub_corrs),
        full_keys: Vec::with_capacity(full_corrs),
    };
    let mut pending_full = Vec::with_capacity(2 * full_corrs);
    let mut noise_i = 0usize;
    let code_seed = seed_word(derive_seed(seed, b"lpn-code", 0));

    for row in 0..params.output_sub_equiv {
        let mut r = Fp::ZERO;
        let mut m = Fp2::ZERO;
        let mut k = Fp2::ZERO;
        let mut state = code_seed ^ (row as u64).wrapping_mul(0xA24B_AED4_963E_E407);
        for limb in 0..params.code_fanout {
            state = splitmix64(state ^ (limb as u64).wrapping_mul(0x9FB2_1C65_1E98_DF25));
            let idx = (state as usize) % params.lpn_k;
            r += base.r[idx];
            m += base.m[idx];
            k += base.k[idx];
        }
        if noise_i < noise.len() && noise[noise_i].0 == row {
            let e = noise[noise_i].1;
            r += e.r;
            m += e.m;
            k += e.k;
            noise_i += 1;
        }
        let triple = SubTriple { r, m, k };
        if row < sub_corrs {
            prover.subs.push(SubVole { r, m });
            verifier.sub_keys.push(k);
        } else {
            pending_full.push(triple);
        }
    }
    (prover, verifier, pending_full)
}

fn combine_full_limbs(
    pending_full: Vec<SubTriple>,
    full_corrs: usize,
    prover: &mut ProverPcgPool,
    verifier: &mut VerifierPcgPool,
) {
    assert_eq!(pending_full.len(), 2 * full_corrs);
    for pair in pending_full.chunks_exact(2) {
        let a = pair[0];
        let b = pair[1];
        prover
            .fulls
            .push(FullVole { x: Fp2::from_base(a.r) + GAMMA.mul_base(b.r), m: a.m + GAMMA * b.m });
        verifier.full_keys.push(a.k + GAMMA * b.k);
    }
}

fn ggm_selected_leaf(seed: [u8; 32], point: u64, depth: u32, selected: usize) -> ([u8; 32], u64) {
    let leaf_count = 1usize << depth;
    let mut level = vec![derive_seed(seed, b"ggm-root", point)];
    let mut mix = 0xD6E8_FD50u64 ^ point;
    for d in 0..depth {
        let mut next = Vec::with_capacity(level.len() * 2);
        for node in &level {
            let left = derive_seed(*node, b"ggm-left", d as u64);
            let right = derive_seed(*node, b"ggm-right", d as u64);
            mix ^= seed_word(left).rotate_left((d & 63) as u32);
            mix = mix.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            mix ^= seed_word(right).rotate_left(((d + 17) & 63) as u32);
            next.push(left);
            next.push(right);
        }
        level = next;
    }
    debug_assert_eq!(level.len(), leaf_count);
    (level[selected], mix)
}

fn challenge_fp2(seed: [u8; 32], label: &[u8], ctr: u64) -> Fp2 {
    let mut fs = FpStream::from_seed(derive_seed(seed, label, ctr));
    let mut x = fs.next_fp2();
    if x == Fp2::ZERO {
        x = Fp2::ONE;
    }
    x
}

fn derive_seed(seed: [u8; 32], label: &[u8], ctr: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&seed);
    h.update(label);
    h.update(&ctr.to_le_bytes());
    *h.finalize().as_bytes()
}

fn scalar_from_seed(seed: [u8; 32], label: &[u8], ctr: u64) -> Scalar {
    let lo = derive_seed(seed, label, ctr);
    let hi = derive_seed(seed, label, ctr ^ 0xFFFF_FFFF_0000_0000);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&lo);
    wide[32..].copy_from_slice(&hi);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn point_key(point: curve25519_dalek::ristretto::RistrettoPoint, label: &[u8], ctr: u64) -> [u8; 32] {
    let compressed: CompressedRistretto = point.compress();
    let mut h = blake3::Hasher::new();
    h.update(compressed.as_bytes());
    h.update(label);
    h.update(&ctr.to_le_bytes());
    *h.finalize().as_bytes()
}

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn hex32(x: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in x {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn seed_word(seed: [u8; 32]) -> u64 {
    u64::from_le_bytes(seed[..8].try_into().unwrap())
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn ceil_div(a: usize, b: usize) -> usize {
    if a == 0 {
        0
    } else {
        1 + (a - 1) / b
    }
}

fn ceil_log2(x: usize) -> u32 {
    if x <= 1 {
        0
    } else {
        usize::BITS - (x - 1).leading_zeros()
    }
}

fn mix_fp(acc: &mut u64, x: Fp) {
    *acc ^= x.value().rotate_left((*acc & 63) as u32);
    *acc = acc.wrapping_mul(0x9E37_79B9_7F4A_7C15);
}

fn mix_fp2(acc: &mut u64, x: Fp2) {
    mix_fp(acc, x.c0);
    mix_fp(acc, x.c1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta() -> Fp2 {
        Fp2::new(Fp::new(0xCAFE_BABE), Fp::new(0x1234_5678))
    }

    #[test]
    fn phase_a_outputs_satisfy_mac_relation() {
        let params = PhaseAParams::tiny_for_test(96 + 2 * 7);
        let out = expand_phase_a([7u8; 32], delta(), 96, 7, params);
        assert_eq!(out.prover.subs.len(), 96);
        assert_eq!(out.prover.fulls.len(), 7);
        assert_eq!(out.verifier.sub_keys.len(), 96);
        assert_eq!(out.verifier.full_keys.len(), 7);
        for (s, k) in out.prover.subs.iter().zip(&out.verifier.sub_keys) {
            assert_eq!(*k, s.m + delta().mul_base(s.r));
        }
        for (f, k) in out.prover.fulls.iter().zip(&out.verifier.full_keys) {
            assert_eq!(*k, f.m + delta() * f.x);
        }
    }

    #[test]
    fn consistency_check_rejects_tampering() {
        let params = PhaseAParams::tiny_for_test(32 + 2 * 3);
        let mut out = expand_phase_a([9u8; 32], delta(), 32, 3, params);
        assert!(consistency_check(delta(), &out.prover, &out.verifier, 2, [9u8; 32]).ok);
        out.prover.subs[4].m += Fp2::ONE;
        assert!(!consistency_check(delta(), &out.prover, &out.verifier, 2, [9u8; 32]).ok);
    }

    #[test]
    fn phase_b_outputs_satisfy_mac_and_counts_setup_bytes() {
        let params = PhaseAParams::tiny_for_test(48 + 2 * 5);
        let out = expand_phase_b([0xB7u8; 32], delta(), 48, 5, params);
        assert_eq!(out.prover.subs.len(), 48);
        assert_eq!(out.prover.fulls.len(), 5);
        assert!(out.setup.comm.total_bytes > 0);
        assert_eq!(out.setup.params.base_ot_count, 128);
        assert!(!out.setup.params.production_ready);
        for (s, k) in out.prover.subs.iter().zip(&out.verifier.sub_keys) {
            assert_eq!(*k, s.m + delta().mul_base(s.r));
        }
        for (f, k) in out.prover.fulls.iter().zip(&out.verifier.full_keys) {
            assert_eq!(*k, f.m + delta() * f.x);
        }
        assert!(out.consistency.ok);
    }
}

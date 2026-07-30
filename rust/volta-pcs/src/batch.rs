//! Batch reduction of many authenticated W̃ evaluation claims to a single
//! point, so one PCS opening serves a whole response (design note A′,
//! "standard sumcheck batching").
//!
//! Claims arrive as (block, point, authenticated value): each weight tensor
//! occupies a power-of-two aligned block of the flat coefficient vector, so a
//! claim on tensor t at block-point p is a claim on the global MLE at
//! (p ‖ bits(block index)) — the boolean suffix keeps the eq tables
//! block-local, which is what makes the F-side build O(Σ block sizes) instead
//! of O(G·|W|).
//!
//! Protocol: λ drawn after all claims are fixed; one blind product sumcheck
//! (M3 machinery, byte- and correlation-compatible with
//! `volta_proto::blind_prove` — the verifier side IS `blind_verify`) over
//! F(x)·W̃(x) with F = Σ_g λ^{g+1}·eq(r_g, ·) and initial claim
//! Σ λ^{g+1}·v_g (authenticated by linearity). The final authenticated claim
//! F̃(r*)·W̃(r*) divides by the public F̃(r*), leaving the authenticated
//! W̃(r*) that `ligero::open_zk` binds to C_W.

use rayon::prelude::*;
use std::collections::BTreeMap;
use std::time::Instant;
use volta_accel::{Backend, BackendKind, DeviceBuffer, DeviceSlice, Fp2Repr};
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_proto::mle::{eq_points, lagrange3};
use volta_proto::sumcheck_blind::{blind_verify, BlindSumcheckProof};

/// One W̃ evaluation claim on the block at `offset` (aligned: offset is a
/// multiple of 2^point.len()); `point` binds the low variables of the block.
#[derive(Clone, Debug)]
pub struct BlockClaim {
    pub offset: usize,
    pub point: Vec<Fp2>,
}

impl BlockClaim {
    /// The claim's point on the global n_vars MLE: block point ‖ boolean
    /// suffix selecting the block.
    pub fn global_point(&self, n_vars: usize) -> Vec<Fp2> {
        let bv = self.point.len();
        assert!(self.offset % (1 << bv) == 0, "block offset not aligned");
        let mut p = self.point.clone();
        let idx = self.offset >> bv;
        for b in 0..n_vars - bv {
            p.push(if (idx >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO });
        }
        p
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct BatchTimings {
    /// F = Σ λ^g eq_g table build (block-local).
    pub t_f_build_s: f64,
    /// i16 → F_p² embedding of W.
    pub t_w_embed_s: f64,
    /// Blind sumcheck rounds (incl. masks + folds).
    pub t_rounds_s: f64,
    /// Product-round `[g(0), g(2)]` evaluation inside `t_rounds_s`.
    pub t_product_round_s: f64,
    /// F and W folds inside `t_rounds_s`.
    pub t_folds_s: f64,
    /// Masks, transcript, challenge and authenticated-claim orchestration
    /// inside `t_rounds_s`, including the explicitly reported loop residual.
    pub t_masks_transcript_orchestration_s: f64,
    /// Number of product-round message evaluations.
    pub product_round_calls: u64,
    /// Number of F folds.
    pub f_fold_calls: u64,
    /// Number of W folds.
    pub w_fold_calls: u64,
    /// Fp2 symbols read by product-round evaluation (F and W combined).
    pub product_round_symbols_read: u64,
    /// Fp2 symbols read by F folds.
    pub f_fold_symbols_read: u64,
    /// Fp2 symbols read by W folds.
    pub w_fold_symbols_read: u64,
}

impl BatchTimings {
    pub fn total_s(&self) -> f64 {
        self.t_f_build_s + self.t_w_embed_s + self.t_rounds_s
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClaimReduceResidentCounters {
    pub canonical_sources: u64,
    pub canonical_source_symbols: u64,
    pub canonical_source_bytes: u64,
    pub canonical_device_bytes: u64,
    pub source_embedding_calls: u64,
    pub f_generation_calls: u64,
    pub product_round_calls: u64,
    pub f_fold_calls: u64,
    pub w_fold_calls: u64,
    pub protocol_scalar_d2h_bytes: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub d2d_bytes: u64,
    pub kernel_calls: u64,
    pub allocation_requests: u64,
    pub buffer_reuse_hits: u64,
    pub peak_live_host_scratch_bytes: u64,
    pub peak_live_scratch_bytes: u64,
}

#[derive(Debug)]
struct CpuClaimReduceScratch {
    f_primary: Vec<Fp2>,
    f_ping: Vec<Fp2>,
    w_ping: Vec<Fp2>,
    w_pong: Vec<Fp2>,
}

impl CpuClaimReduceScratch {
    fn new(len: usize) -> Self {
        Self {
            f_primary: vec![Fp2::ZERO; len],
            f_ping: vec![Fp2::ZERO; len],
            w_ping: vec![Fp2::ZERO; len],
            w_pong: vec![Fp2::ZERO; len],
        }
    }
}

/// CPU implementation of the resident ClaimReduce operation contract.
///
/// Sources are canonically embedded once, remain immutable, and are folded
/// non-destructively through a geometry-keyed ping-pong pool. This is the
/// local orchestration/differential oracle for the CUDA implementation; it
/// deliberately records zero device traffic.
#[derive(Debug)]
pub struct CpuClaimReduceSettlement {
    canonical_sources: Vec<Vec<Fp2>>,
    scratch_by_len: BTreeMap<usize, CpuClaimReduceScratch>,
    counters: ClaimReduceResidentCounters,
}

#[derive(Debug)]
struct CudaClaimReduceScratch {
    f_primary: DeviceBuffer<Fp2Repr>,
    f_ping: DeviceBuffer<Fp2Repr>,
    w_ping: DeviceBuffer<Fp2Repr>,
    w_pong: DeviceBuffer<Fp2Repr>,
    points_and_scales: DeviceBuffer<Fp2Repr>,
    len: usize,
    max_point_symbols: usize,
}

/// CUDA-resident settlement scope for sequential ClaimReduce instances.
///
/// Every canonical W table is embedded once. One maximum-geometry four-way
/// ping-pong pool is reused by all instances, which remain transcript-
/// sequential. No production fallback exists: every backend error is
/// returned to the caller.
#[derive(Debug)]
pub struct CudaClaimReduceSettlement {
    canonical_sources: Vec<DeviceBuffer<Fp2Repr>>,
    scratch: CudaClaimReduceScratch,
    counters: ClaimReduceResidentCounters,
}

impl CudaClaimReduceSettlement {
    pub fn prepare(
        backend: &mut Backend,
        sources: &[Vec<i16>],
    ) -> Result<Self, volta_accel::AccelError> {
        if backend.kind() != BackendKind::CudaResident
            || sources.is_empty()
            || sources.iter().any(|source| source.len() < 2 || !source.len().is_power_of_two())
        {
            return Err(volta_accel::AccelError::InvalidInput(
                "CUDA ClaimReduce settlement requires resident backend and power-of-two sources",
            ));
        }
        let max_len = sources.iter().map(Vec::len).max().expect("non-empty sources");
        let max_mu = max_len.trailing_zeros() as usize;
        backend.reserve_fp2_product_round_workspace(max_len / 2)?;
        let mut canonical_sources = Vec::with_capacity(sources.len());
        for source in sources {
            let raw = match backend.upload_new_device(source) {
                Ok(value) => value,
                Err(error) => {
                    for buffer in canonical_sources {
                        let _ = backend.free_device(buffer);
                    }
                    return Err(error);
                }
            };
            let embedded = backend.base_to_fp2_broadcast_device(
                DeviceSlice::new(&raw, 0, raw.len()).expect("whole i16 ClaimReduce source"),
                1,
            );
            let raw_free = backend.free_device(raw);
            let embedded = match (embedded, raw_free) {
                (Ok(value), Ok(())) => value,
                (Ok(value), Err(error)) => {
                    let _ = backend.free_device(value);
                    for buffer in canonical_sources {
                        let _ = backend.free_device(buffer);
                    }
                    return Err(error);
                }
                (Err(error), _) => {
                    for buffer in canonical_sources {
                        let _ = backend.free_device(buffer);
                    }
                    return Err(error);
                }
            };
            canonical_sources.push(embedded);
        }
        let mut scratch_buffers = Vec::with_capacity(4);
        for _ in 0..4 {
            match backend.alloc_device::<Fp2Repr>(max_len) {
                Ok(buffer) => scratch_buffers.push(buffer),
                Err(error) => {
                    for buffer in scratch_buffers {
                        let _ = backend.free_device(buffer);
                    }
                    for buffer in canonical_sources {
                        let _ = backend.free_device(buffer);
                    }
                    return Err(error);
                }
            }
        }
        let max_point_symbols = 2 * max_mu + 2;
        let points_and_scales = match backend.alloc_device(max_point_symbols) {
            Ok(buffer) => buffer,
            Err(error) => {
                for buffer in scratch_buffers {
                    let _ = backend.free_device(buffer);
                }
                for buffer in canonical_sources {
                    let _ = backend.free_device(buffer);
                }
                return Err(error);
            }
        };
        let mut scratch_buffers = scratch_buffers.into_iter();
        let f_primary = scratch_buffers.next().expect("four ClaimReduce buffers");
        let f_ping = scratch_buffers.next().expect("four ClaimReduce buffers");
        let w_ping = scratch_buffers.next().expect("four ClaimReduce buffers");
        let w_pong = scratch_buffers.next().expect("four ClaimReduce buffers");
        let canonical_source_symbols =
            sources.iter().map(|source| source.len() as u64).sum::<u64>();
        Ok(Self {
            canonical_sources,
            scratch: CudaClaimReduceScratch {
                f_primary,
                f_ping,
                w_ping,
                w_pong,
                points_and_scales,
                len: max_len,
                max_point_symbols,
            },
            counters: ClaimReduceResidentCounters {
                canonical_sources: sources.len() as u64,
                canonical_source_symbols,
                canonical_source_bytes: canonical_source_symbols * 2,
                canonical_device_bytes: canonical_source_symbols * 16,
                source_embedding_calls: sources.len() as u64,
                h2d_bytes: canonical_source_symbols * 2,
                allocation_requests: (2 * sources.len() + 5) as u64,
                peak_live_host_scratch_bytes: (max_point_symbols * std::mem::size_of::<Fp2Repr>())
                    as u64,
                peak_live_scratch_bytes: (4 * max_len * std::mem::size_of::<Fp2Repr>()
                    + max_point_symbols * std::mem::size_of::<Fp2Repr>())
                    as u64,
                ..Default::default()
            },
        })
    }

    pub fn counters(&self) -> ClaimReduceResidentCounters {
        self.counters
    }

    pub fn release(
        mut self,
        backend: &mut Backend,
    ) -> Result<ClaimReduceResidentCounters, volta_accel::AccelError> {
        let mut first = None;
        for source in self.canonical_sources.drain(..) {
            if let Err(error) = backend.free_device(source) {
                first.get_or_insert(error);
            }
        }
        for buffer in [
            self.scratch.f_primary,
            self.scratch.f_ping,
            self.scratch.w_ping,
            self.scratch.w_pong,
            self.scratch.points_and_scales,
        ] {
            if let Err(error) = backend.free_device(buffer) {
                first.get_or_insert(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(self.counters),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn batch_reduce_prover_cuda_resident(
    settlement: &mut CudaClaimReduceSettlement,
    backend: &mut Backend,
    source_index: usize,
    n_vars: usize,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Result<(BlindSumcheckProof, Vec<Fp2>, ProverAuthed, BatchTimings), volta_accel::AccelError> {
    if backend.kind() != BackendKind::CudaResident || claims.len() != 2 {
        return Err(volta_accel::AccelError::InvalidInput(
            "CUDA ClaimReduce requires resident backend and exactly two claims",
        ));
    }
    let source = settlement
        .canonical_sources
        .get(source_index)
        .ok_or(volta_accel::AccelError::InvalidInput("CUDA ClaimReduce source index"))?;
    let len = 1usize
        .checked_shl(n_vars as u32)
        .ok_or(volta_accel::AccelError::InvalidInput("CUDA ClaimReduce dimension overflow"))?;
    if source.len() != len
        || len > settlement.scratch.len
        || claims.iter().any(|(claim, _)| claim.offset != 0 || claim.point.len() != n_vars)
    {
        return Err(volta_accel::AccelError::InvalidInput("CUDA ClaimReduce geometry mismatch"));
    }
    let lambda = tx.challenge_fp2();
    let lambda_two = lambda * lambda;
    let mut public = Vec::with_capacity(2 * n_vars + 2);
    public.extend(claims[0].0.point.iter().copied().map(Fp2Repr::from));
    public.extend(claims[1].0.point.iter().copied().map(Fp2Repr::from));
    public.push(lambda.into());
    public.push(lambda_two.into());
    if public.len() > settlement.scratch.max_point_symbols {
        return Err(volta_accel::AccelError::InvalidInput(
            "CUDA ClaimReduce point workspace is too small",
        ));
    }
    backend.upload_device(&settlement.scratch.points_and_scales, 0, &public)?;
    settlement.counters.h2d_bytes += (public.len() * std::mem::size_of::<Fp2Repr>()) as u64;
    let mut timings = BatchTimings::default();
    let f_started = Instant::now();
    backend.claim_reduce_f_two_into_device(
        DeviceSlice::new(&settlement.scratch.points_and_scales, 0, public.len())
            .expect("ClaimReduce public row"),
        n_vars,
        &settlement.scratch.f_primary,
        0,
        &settlement.scratch.f_ping,
        0,
        &settlement.scratch.w_ping,
        0,
        &settlement.scratch.w_pong,
        0,
    )?;
    timings.t_f_build_s = f_started.elapsed().as_secs_f64();
    settlement.counters.f_generation_calls += 1;
    settlement.counters.kernel_calls += (2 * n_vars + 3) as u64;
    settlement.counters.buffer_reuse_hits += 4;

    let mut claim = claims[0].1.scale(lambda).add(claims[1].1.scale(lambda_two));
    let rounds_started = Instant::now();
    let mut active_len = len;
    let mut f_primary_active = true;
    let mut w_source_active = true;
    let mut w_ping_active = true;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    for round in 0..n_vars {
        let f_current = if f_primary_active {
            DeviceSlice::new(&settlement.scratch.f_primary, 0, active_len)
        } else {
            DeviceSlice::new(&settlement.scratch.f_ping, 0, active_len)
        }
        .expect("CUDA ClaimReduce F prefix");
        let w_current = if w_source_active {
            DeviceSlice::new(source, 0, active_len)
        } else if w_ping_active {
            DeviceSlice::new(&settlement.scratch.w_ping, 0, active_len)
        } else {
            DeviceSlice::new(&settlement.scratch.w_pong, 0, active_len)
        }
        .expect("CUDA ClaimReduce W prefix");
        let product_started = Instant::now();
        let [g0, g2] = backend.fp2_product_round_device(f_current, w_current)?;
        timings.t_product_round_s += product_started.elapsed().as_secs_f64();
        timings.product_round_calls += 1;
        timings.product_round_symbols_read += 2 * active_len as u64;
        settlement.counters.protocol_scalar_d2h_bytes += 32;
        settlement.counters.d2h_bytes += 32;
        settlement.counters.kernel_calls += 1;

        let orchestration_started = Instant::now();
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
        tx.append("blind_round_corrections", 32);
        let auth_zero = masks[0].authenticate(g0);
        let auth_two = masks[1].authenticate(g2);
        let auth_one = claim.sub(auth_zero);
        let challenge = tx.challenge_fp2();
        let weights = lagrange3(challenge);
        claim = auth_zero
            .scale(weights[0])
            .add(auth_one.scale(weights[1]))
            .add(auth_two.scale(weights[2]));
        timings.t_masks_transcript_orchestration_s += orchestration_started.elapsed().as_secs_f64();

        let next_len = active_len / 2;
        let fold_started = Instant::now();
        let f_output = if f_primary_active {
            &settlement.scratch.f_ping
        } else {
            &settlement.scratch.f_primary
        };
        backend.fp2_fold_rows_into_device(f_current, 1, active_len, challenge, f_output, 0)?;
        let w_output = if w_source_active || !w_ping_active {
            &settlement.scratch.w_ping
        } else {
            &settlement.scratch.w_pong
        };
        backend.fp2_fold_rows_into_device(w_current, 1, active_len, challenge, w_output, 0)?;
        timings.t_folds_s += fold_started.elapsed().as_secs_f64();
        timings.f_fold_calls += 1;
        timings.w_fold_calls += 1;
        timings.f_fold_symbols_read += active_len as u64;
        timings.w_fold_symbols_read += active_len as u64;
        settlement.counters.d2d_bytes += (2 * next_len * std::mem::size_of::<Fp2Repr>()) as u64;
        settlement.counters.kernel_calls += 2;
        f_primary_active = !f_primary_active;
        if w_source_active {
            w_source_active = false;
            w_ping_active = true;
        } else {
            w_ping_active = !w_ping_active;
        }
        active_len = next_len;
        point.push(challenge);
    }
    timings.t_rounds_s = rounds_started.elapsed().as_secs_f64();
    let children =
        timings.t_product_round_s + timings.t_folds_s + timings.t_masks_transcript_orchestration_s;
    if timings.t_rounds_s > children {
        timings.t_masks_transcript_orchestration_s += timings.t_rounds_s - children;
    }
    let f_final = if f_primary_active {
        DeviceSlice::new(&settlement.scratch.f_primary, 0, 1)
    } else {
        DeviceSlice::new(&settlement.scratch.f_ping, 0, 1)
    }
    .expect("CUDA ClaimReduce terminal F");
    let w_final = if w_ping_active {
        DeviceSlice::new(&settlement.scratch.w_ping, 0, 1)
    } else {
        DeviceSlice::new(&settlement.scratch.w_pong, 0, 1)
    }
    .expect("CUDA ClaimReduce terminal W");
    let terminals = backend.download_device_segments(&[f_final, w_final])?;
    settlement.counters.protocol_scalar_d2h_bytes += 32;
    settlement.counters.d2h_bytes += 32;
    let fstar = f_at(
        &claims.iter().map(|(claim, _)| claim.global_point(n_vars)).collect::<Vec<_>>(),
        lambda,
        &point,
    );
    if Fp2::from(terminals[0]) != fstar
        || fstar == Fp2::ZERO
        || claim.x != fstar * Fp2::from(terminals[1])
    {
        return Err(volta_accel::AccelError::InvalidInput(
            "CUDA ClaimReduce terminal identity mismatch",
        ));
    }
    settlement.counters.product_round_calls += timings.product_round_calls;
    settlement.counters.f_fold_calls += timings.f_fold_calls;
    settlement.counters.w_fold_calls += timings.w_fold_calls;
    Ok((BlindSumcheckProof { round_corrs }, point, claim.scale(fstar.inv()), timings))
}

impl CpuClaimReduceSettlement {
    pub fn new(sources: &[Vec<i16>]) -> Result<Self, &'static str> {
        if sources.is_empty()
            || sources.iter().any(|source| source.len() < 2 || !source.len().is_power_of_two())
        {
            return Err("resident ClaimReduce sources must be non-empty power-of-two vectors");
        }
        let canonical_source_symbols = sources
            .iter()
            .try_fold(0u64, |sum, source| sum.checked_add(source.len() as u64))
            .ok_or("resident ClaimReduce source symbol count overflows")?;
        let canonical_sources = sources
            .iter()
            .map(|source| {
                source.par_iter().map(|&value| Fp2::from_base(Fp::from_i64(value as i64))).collect()
            })
            .collect::<Vec<Vec<Fp2>>>();
        Ok(Self {
            canonical_sources,
            scratch_by_len: BTreeMap::new(),
            counters: ClaimReduceResidentCounters {
                canonical_sources: sources.len() as u64,
                canonical_source_symbols,
                canonical_source_bytes: canonical_source_symbols
                    .checked_mul(2)
                    .ok_or("resident ClaimReduce source bytes overflow")?,
                source_embedding_calls: sources.len() as u64,
                ..Default::default()
            },
        })
    }

    pub fn counters(&self) -> ClaimReduceResidentCounters {
        self.counters
    }

    fn source(&self, index: usize) -> Result<&[Fp2], &'static str> {
        self.canonical_sources
            .get(index)
            .map(Vec::as_slice)
            .ok_or("resident ClaimReduce source index is out of range")
    }
}

fn build_scaled_eq_reuse(temp: &mut [Fp2], point: &[Fp2], scale: Fp2) {
    temp.fill(Fp2::ZERO);
    temp[0] = scale;
    let mut size = 1usize;
    for &ri in point.iter().rev() {
        for i in (0..size).rev() {
            let value = temp[i];
            let value_one = value * ri;
            temp[2 * i] = value - value_one;
            temp[2 * i + 1] = value_one;
        }
        size *= 2;
    }
}

fn product_round_par(a: &[Fp2], b: &[Fp2]) -> (Fp2, Fp2) {
    let half = a.len() / 2;
    (0..half)
        .into_par_iter()
        .fold(
            || (Fp2::ZERO, Fp2::ZERO),
            |(sum_zero, sum_two), index| {
                let (a0, a1) = (a[2 * index], a[2 * index + 1]);
                let (b0, b1) = (b[2 * index], b[2 * index + 1]);
                let (da, db) = (a1 - a0, b1 - b0);
                (sum_zero + a0 * b0, sum_two + (a0 + da + da) * (b0 + db + db))
            },
        )
        .reduce(|| (Fp2::ZERO, Fp2::ZERO), |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2))
}

fn fold_into_par(input: &[Fp2], output: &mut [Fp2], challenge: Fp2) {
    output.par_iter_mut().enumerate().for_each(|(index, value)| {
        let low = input[2 * index];
        *value = low + (input[2 * index + 1] - low) * challenge;
    });
}

/// Sequential-transcript resident ClaimReduce over one immutable canonical
/// source. No round-synchronous batching is used.
pub fn batch_reduce_prover_cpu_resident(
    settlement: &mut CpuClaimReduceSettlement,
    source_index: usize,
    n_vars: usize,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Result<(BlindSumcheckProof, Vec<Fp2>, ProverAuthed, BatchTimings), &'static str> {
    let source_len = settlement.source(source_index)?.len();
    if source_len != 1usize.checked_shl(n_vars as u32).unwrap_or(0) || claims.is_empty() {
        return Err("resident ClaimReduce geometry mismatch");
    }
    let source = settlement.canonical_sources[source_index].as_slice();
    let reused = settlement.scratch_by_len.contains_key(&source_len);
    let scratch = settlement
        .scratch_by_len
        .entry(source_len)
        .or_insert_with(|| CpuClaimReduceScratch::new(source_len));
    if reused {
        settlement.counters.buffer_reuse_hits += 1;
    } else {
        settlement.counters.allocation_requests += 4;
        settlement.counters.peak_live_scratch_bytes = settlement
            .counters
            .peak_live_scratch_bytes
            .max(4 * source_len as u64 * std::mem::size_of::<Fp2>() as u64);
        settlement.counters.peak_live_host_scratch_bytes = settlement
            .counters
            .peak_live_host_scratch_bytes
            .max(4 * source_len as u64 * std::mem::size_of::<Fp2>() as u64);
    }
    let mut timings = BatchTimings::default();
    let lambda = tx.challenge_fp2();
    let mut powers = Vec::with_capacity(claims.len());
    let mut power = Fp2::ONE;
    for _ in claims {
        power = power * lambda;
        powers.push(power);
    }
    let f_started = Instant::now();
    scratch.f_primary.fill(Fp2::ZERO);
    for (index, (claim, _)) in claims.iter().enumerate() {
        if claim.offset != 0 || claim.point.len() != n_vars {
            return Err("resident ClaimReduce currently requires full-domain claims");
        }
        build_scaled_eq_reuse(&mut scratch.f_ping, &claim.point, powers[index]);
        scratch
            .f_primary
            .par_iter_mut()
            .zip(&scratch.f_ping)
            .for_each(|(combined, contribution)| *combined += *contribution);
    }
    timings.t_f_build_s = f_started.elapsed().as_secs_f64();
    settlement.counters.f_generation_calls += 1;

    let mut claim = claims
        .iter()
        .enumerate()
        .fold(ProverAuthed::ZERO, |sum, (index, (_, value))| sum.add(value.scale(powers[index])));
    let rounds_started = Instant::now();
    let mut active_len = source_len;
    let mut f_primary_active = true;
    let mut w_source_active = true;
    let mut w_ping_active = true;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    for round in 0..n_vars {
        let f_current = if f_primary_active {
            &scratch.f_primary[..active_len]
        } else {
            &scratch.f_ping[..active_len]
        };
        let w_current = if w_source_active {
            &source[..active_len]
        } else if w_ping_active {
            &scratch.w_ping[..active_len]
        } else {
            &scratch.w_pong[..active_len]
        };
        let product_started = Instant::now();
        let (g0, g2) = product_round_par(f_current, w_current);
        timings.t_product_round_s += product_started.elapsed().as_secs_f64();
        timings.product_round_calls += 1;
        timings.product_round_symbols_read += 2 * active_len as u64;

        let orchestration_started = Instant::now();
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
        tx.append("blind_round_corrections", 32);
        let auth_zero = masks[0].authenticate(g0);
        let auth_two = masks[1].authenticate(g2);
        let auth_one = claim.sub(auth_zero);
        let challenge = tx.challenge_fp2();
        let weights = lagrange3(challenge);
        claim = auth_zero
            .scale(weights[0])
            .add(auth_one.scale(weights[1]))
            .add(auth_two.scale(weights[2]));
        timings.t_masks_transcript_orchestration_s += orchestration_started.elapsed().as_secs_f64();

        let next_len = active_len / 2;
        let folds_started = Instant::now();
        if f_primary_active {
            fold_into_par(
                &scratch.f_primary[..active_len],
                &mut scratch.f_ping[..next_len],
                challenge,
            );
        } else {
            fold_into_par(
                &scratch.f_ping[..active_len],
                &mut scratch.f_primary[..next_len],
                challenge,
            );
        }
        if w_source_active {
            fold_into_par(&source[..active_len], &mut scratch.w_ping[..next_len], challenge);
            w_source_active = false;
            w_ping_active = true;
        } else if w_ping_active {
            fold_into_par(
                &scratch.w_ping[..active_len],
                &mut scratch.w_pong[..next_len],
                challenge,
            );
            w_ping_active = false;
        } else {
            fold_into_par(
                &scratch.w_pong[..active_len],
                &mut scratch.w_ping[..next_len],
                challenge,
            );
            w_ping_active = true;
        }
        timings.t_folds_s += folds_started.elapsed().as_secs_f64();
        timings.f_fold_calls += 1;
        timings.w_fold_calls += 1;
        timings.f_fold_symbols_read += active_len as u64;
        timings.w_fold_symbols_read += active_len as u64;
        f_primary_active = !f_primary_active;
        active_len = next_len;
        point.push(challenge);
    }
    timings.t_rounds_s = rounds_started.elapsed().as_secs_f64();
    let children =
        timings.t_product_round_s + timings.t_folds_s + timings.t_masks_transcript_orchestration_s;
    if timings.t_rounds_s > children {
        timings.t_masks_transcript_orchestration_s += timings.t_rounds_s - children;
    }
    let fstar = f_at(
        &claims.iter().map(|(claim, _)| claim.global_point(n_vars)).collect::<Vec<_>>(),
        lambda,
        &point,
    );
    if fstar == Fp2::ZERO {
        return Err("resident ClaimReduce terminal F evaluation is zero");
    }
    settlement.counters.product_round_calls += timings.product_round_calls;
    settlement.counters.f_fold_calls += timings.f_fold_calls;
    settlement.counters.w_fold_calls += timings.w_fold_calls;
    Ok((BlindSumcheckProof { round_corrs }, point, claim.scale(fstar.inv()), timings))
}

/// Build `dst += scale·eq(point, ·)` over a block (dst.len() = 2^point.len()).
fn add_scaled_eq(dst: &mut [Fp2], point: &[Fp2], scale: Fp2) {
    let mut t = vec![Fp2::ZERO; dst.len()];
    t[0] = scale;
    let mut size = 1usize;
    for &ri in point.iter().rev() {
        for i in (0..size).rev() {
            let v = t[i];
            let v1 = v * ri;
            t[2 * i] = v - v1;
            t[2 * i + 1] = v1;
        }
        size *= 2;
    }
    for (d, s) in dst.iter_mut().zip(&t) {
        *d += *s;
    }
}

/// Parallel twin of `volta_proto::blind_prove`: identical messages, masks and
/// transcript labels; g(0)/g(2) accumulation and folds run on rayon.
fn blind_prove_par(
    mut a: Vec<Fp2>,
    mut b: Vec<Fp2>,
    claim0: ProverAuthed,
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> (BlindSumcheckProof, Vec<Fp2>, ProverAuthed, BatchTimings) {
    assert_eq!(a.len(), b.len());
    let n_vars = a.len().trailing_zeros() as usize;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    let rounds_started = Instant::now();
    let mut timings = BatchTimings::default();
    for round in 0..n_vars {
        let half = a.len() / 2;
        let active_len = a.len() as u64;
        let product_started = Instant::now();
        let (g0, g2) = (0..half)
            .into_par_iter()
            .fold(
                || (Fp2::ZERO, Fp2::ZERO),
                |(s0, s2), i| {
                    let (a0, a1) = (a[2 * i], a[2 * i + 1]);
                    let (b0, b1) = (b[2 * i], b[2 * i + 1]);
                    let (da, db) = (a1 - a0, b1 - b0);
                    (s0 + a0 * b0, s2 + (a0 + da + da) * (b0 + db + db))
                },
            )
            .reduce(|| (Fp2::ZERO, Fp2::ZERO), |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2));
        timings.t_product_round_s += product_started.elapsed().as_secs_f64();
        timings.product_round_calls += 1;
        timings.product_round_symbols_read += 2 * active_len;

        let orchestration_started = Instant::now();
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        let corrs = [g0 - masks[0].x, g2 - masks[1].x];
        tx.append("blind_round_corrections", 32);
        round_corrs.push(corrs);
        let g0_a = masks[0].authenticate(g0);
        let g2_a = masks[1].authenticate(g2);
        let g1_a = claim.sub(g0_a);

        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));
        timings.t_masks_transcript_orchestration_s += orchestration_started.elapsed().as_secs_f64();

        let folds_started = Instant::now();
        a = (0..half).into_par_iter().map(|i| a[2 * i] + (a[2 * i + 1] - a[2 * i]) * r).collect();
        b = (0..half).into_par_iter().map(|i| b[2 * i] + (b[2 * i + 1] - b[2 * i]) * r).collect();
        timings.t_folds_s += folds_started.elapsed().as_secs_f64();
        timings.f_fold_calls += 1;
        timings.w_fold_calls += 1;
        timings.f_fold_symbols_read += active_len;
        timings.w_fold_symbols_read += active_len;
        point.push(r);
    }
    timings.t_rounds_s = rounds_started.elapsed().as_secs_f64();
    let measured_children =
        timings.t_product_round_s + timings.t_folds_s + timings.t_masks_transcript_orchestration_s;
    if timings.t_rounds_s > measured_children {
        timings.t_masks_transcript_orchestration_s += timings.t_rounds_s - measured_children;
    }
    (BlindSumcheckProof { round_corrs }, point, claim, timings)
}

/// Public F̃(r*) = Σ_g λ^{g+1}·eq(r_g, r*), computable by both parties.
fn f_at(claims_pts: &[Vec<Fp2>], lambda: Fp2, rstar: &[Fp2]) -> Fp2 {
    let mut acc = Fp2::ZERO;
    let mut w = Fp2::ONE;
    for p in claims_pts {
        w = w * lambda;
        acc += w * eq_points(p, rstar);
    }
    acc
}

/// Reduce all claims to one authenticated `W̃(r*)`. `w` is the full padded
/// coefficient vector (2^n_vars entries as i16, caller pads).
pub fn batch_reduce_prover(
    w: &[i16],
    n_vars: usize,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> (BlindSumcheckProof, Vec<Fp2>, ProverAuthed, BatchTimings) {
    let size = 1usize << n_vars;
    assert_eq!(w.len(), size);
    assert!(!claims.is_empty());
    let mut tm = BatchTimings::default();

    // λ after all claims are fixed (their corrections are already in tx).
    let lambda = tx.challenge_fp2();

    // F table: block-local eq builds, parallel over disjoint blocks.
    let t0 = Instant::now();
    let mut lam_pows = Vec::with_capacity(claims.len());
    let mut acc = Fp2::ONE;
    for _ in claims {
        acc = acc * lambda;
        lam_pows.push(acc);
    }
    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for (g, (c, _)) in claims.iter().enumerate() {
        let len = 1usize << c.point.len();
        assert!(c.offset % len == 0 && c.offset + len <= size, "bad block");
        groups.entry(c.offset).or_default().push(g);
    }
    let mut f = vec![Fp2::ZERO; size];
    {
        // Disjoint mutable block slices in ascending offset order. Blocks
        // sharing an offset must have equal length (same tensor).
        let mut slices: Vec<(&mut [Fp2], &Vec<usize>)> = Vec::with_capacity(groups.len());
        let mut rest: &mut [Fp2] = &mut f;
        let mut cursor = 0usize;
        for (&off, idxs) in &groups {
            let len = 1usize << claims[idxs[0]].0.point.len();
            for &g in idxs {
                assert_eq!(claims[g].0.point.len(), claims[idxs[0]].0.point.len());
            }
            let (_skip, r) = rest.split_at_mut(off - cursor);
            let (blk, r2) = r.split_at_mut(len);
            slices.push((blk, idxs));
            rest = r2;
            cursor = off + len;
        }
        slices.into_par_iter().for_each(|(blk, idxs)| {
            for &g in idxs {
                add_scaled_eq(blk, &claims[g].0.point, lam_pows[g]);
            }
        });
    }
    tm.t_f_build_s = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let w2: Vec<Fp2> = w.par_iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect();
    tm.t_w_embed_s = t1.elapsed().as_secs_f64();

    let mut claim0 = ProverAuthed::ZERO;
    for (g, (_, v)) in claims.iter().enumerate() {
        claim0 = claim0.add(v.scale(lam_pows[g]));
    }

    let (proof, rstar, claim_n, round_tm) =
        blind_prove_par(f, w2, claim0, stream, mask_dom_base, tx);
    tm.t_rounds_s = round_tm.t_rounds_s;
    tm.t_product_round_s = round_tm.t_product_round_s;
    tm.t_folds_s = round_tm.t_folds_s;
    tm.t_masks_transcript_orchestration_s = round_tm.t_masks_transcript_orchestration_s;
    tm.product_round_calls = round_tm.product_round_calls;
    tm.f_fold_calls = round_tm.f_fold_calls;
    tm.w_fold_calls = round_tm.w_fold_calls;
    tm.product_round_symbols_read = round_tm.product_round_symbols_read;
    tm.f_fold_symbols_read = round_tm.f_fold_symbols_read;
    tm.w_fold_symbols_read = round_tm.w_fold_symbols_read;

    let pts: Vec<Vec<Fp2>> = claims.iter().map(|(c, _)| c.global_point(n_vars)).collect();
    let fstar = f_at(&pts, lambda, &rstar);
    assert!(fstar != Fp2::ZERO, "F̃(r*) = 0 (negligible honest probability)");
    let v_star = claim_n.scale(fstar.inv());
    (proof, rstar, v_star, tm)
}

/// Verifier mirror: returns (r*, key of the authenticated W̃(r*)) to be bound
/// to C_W by `ligero::verify_open`.
pub fn batch_reduce_verifier(
    n_vars: usize,
    claims: &[(BlockClaim, VerifierKey)],
    proof: &BlindSumcheckProof,
    ctx: &mut VerifierCtx,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if claims.is_empty() {
        return None;
    }
    let lambda = tx.challenge_fp2();
    let mut lam_pows = Vec::with_capacity(claims.len());
    let mut acc = Fp2::ONE;
    for _ in claims {
        acc = acc * lambda;
        lam_pows.push(acc);
    }
    let mut k0 = VerifierKey::ZERO;
    for (g, (_, k)) in claims.iter().enumerate() {
        k0 = k0.add(k.scale(lam_pows[g]));
    }
    let (rstar, k_n) = blind_verify(n_vars, k0, proof, ctx, mask_dom_base, tx)?;
    let pts: Vec<Vec<Fp2>> = claims.iter().map(|(c, _)| c.global_point(n_vars)).collect();
    let fstar = f_at(&pts, lambda, &rstar);
    if fstar == Fp2::ZERO {
        return None;
    }
    Some((rstar, k_n.scale(fstar.inv())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_proto::mle::{eq_vec, eval_mle};

    #[test]
    fn add_scaled_eq_matches_eq_vec() {
        let mut s = volta_field::FpStream::from_seed([2u8; 32]);
        let point: Vec<Fp2> = (0..5).map(|_| s.next_fp2()).collect();
        let scale = s.next_fp2();
        let mut dst = vec![Fp2::ZERO; 32];
        add_scaled_eq(&mut dst, &point, scale);
        let eq = eq_vec(&point);
        for i in 0..32 {
            assert_eq!(dst[i], eq[i] * scale, "index {i}");
        }
    }

    #[test]
    fn global_point_selects_block() {
        // W̃_global(p ‖ bits(t)) equals the block MLE at p.
        let mut s = volta_field::FpStream::from_seed([3u8; 32]);
        let w: Vec<Fp2> = (0..64).map(|_| s.next_fp2()).collect();
        let point: Vec<Fp2> = (0..4).map(|_| s.next_fp2()).collect();
        let claim = BlockClaim { offset: 48, point: point.clone() };
        let gp = claim.global_point(6);
        assert_eq!(eval_mle(&w, &gp), eval_mle(&w[48..64], &point));
    }

    #[test]
    fn cpu_resident_claim_reduce_is_byte_identical_and_reuses_immutable_sources() {
        let sources = [6usize, 9, 12]
            .into_iter()
            .map(|mu| {
                (0..1usize << mu)
                    .map(|index| ((index as i32 * 37 + mu as i32 * 11) % 65_521 - 32_760) as i16)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut resident = CpuClaimReduceSettlement::new(&sources).unwrap();
        for repetition in 0..3 {
            for (source_index, source) in sources.iter().enumerate() {
                let mu = source.len().trailing_zeros() as usize;
                let point = |tag: u8| {
                    let mut stream =
                        volta_field::FpStream::from_seed([tag.wrapping_add(repetition); 32]);
                    (0..mu).map(|_| stream.next_fp2()).collect::<Vec<_>>()
                };
                let claims = vec![
                    (
                        BlockClaim { offset: 0, point: point(17 + source_index as u8) },
                        ProverAuthed {
                            x: Fp2::new(Fp::new(123 + repetition as u64), Fp::new(456)),
                            m: Fp2::new(Fp::new(789), Fp::new(1_011)),
                        },
                    ),
                    (
                        BlockClaim { offset: 0, point: point(71 + source_index as u8) },
                        ProverAuthed {
                            x: Fp2::new(Fp::new(2_013), Fp::new(2_417 + repetition as u64)),
                            m: Fp2::new(Fp::new(2_819), Fp::new(3_123)),
                        },
                    ),
                ];
                let domain = 0xC200_0000 + 64 * repetition as u64 + source_index as u64 * 16;
                let mut reference_stream = CorrelationStream::new([0xA1; 32]);
                let mut resident_stream = CorrelationStream::new([0xA1; 32]);
                let mut reference_tx = Transcript::new([0xB2; 32]);
                let mut resident_tx = Transcript::new([0xB2; 32]);
                let (reference_proof, reference_point, reference_value, _) = batch_reduce_prover(
                    source,
                    mu,
                    &claims,
                    &mut reference_stream,
                    domain,
                    &mut reference_tx,
                );
                let (resident_proof, resident_point, resident_value, resident_timings) =
                    batch_reduce_prover_cpu_resident(
                        &mut resident,
                        source_index,
                        mu,
                        &claims,
                        &mut resident_stream,
                        domain,
                        &mut resident_tx,
                    )
                    .unwrap();
                assert_eq!(resident_proof, reference_proof);
                assert_eq!(resident_point, reference_point);
                assert_eq!(resident_value, reference_value);
                assert_eq!(resident_stream.counters, reference_stream.counters);
                assert_eq!(resident_tx.ledger(), reference_tx.ledger());
                assert_eq!(resident_timings.product_round_calls, mu as u64);
                assert_eq!(resident_timings.f_fold_calls, mu as u64);
                assert_eq!(resident_timings.w_fold_calls, mu as u64);
            }
        }
        let counters = resident.counters();
        assert_eq!(counters.source_embedding_calls, 3);
        assert_eq!(counters.f_generation_calls, 9);
        assert_eq!(counters.allocation_requests, 12);
        assert_eq!(counters.buffer_reuse_hits, 6);
        assert_eq!(counters.canonical_device_bytes, 0);
        assert_eq!(counters.h2d_bytes, 0);
        assert_eq!(counters.d2h_bytes, 0);
        assert_eq!(counters.d2d_bytes, 0);
    }

    #[test]
    fn cpu_resident_claim_reduce_preserves_sequential_k1_k16_tape_and_physical_census() {
        fn run(responses: usize) -> ClaimReduceResidentCounters {
            // Production multiplicities (2×mu26, 36×mu22, 13×mu20) scaled
            // down to locally practical dimensions while retaining all 51
            // physical blocks and the exact 51*k sequential caller shape.
            let dimensions = (0..51)
                .map(|index| {
                    if index < 2 {
                        8usize
                    } else if index < 38 {
                        6
                    } else {
                        4
                    }
                })
                .collect::<Vec<_>>();
            let sources = dimensions
                .iter()
                .enumerate()
                .map(|(source_index, &mu)| {
                    (0..1usize << mu)
                        .map(|symbol| {
                            ((symbol as i32 * 101 + source_index as i32 * 271) % 65_521 - 32_760)
                                as i16
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let physical_symbols = sources.iter().map(Vec::len).sum::<usize>() as u64;
            let mut resident = CpuClaimReduceSettlement::new(&sources).unwrap();
            let mut reference_stream = CorrelationStream::new([0x51; 32]);
            let mut resident_stream = CorrelationStream::new([0x51; 32]);
            let mut reference_tx = Transcript::new([0x16; 32]);
            let mut resident_tx = Transcript::new([0x16; 32]);
            for response in 0..responses {
                for (source_index, (&mu, source)) in dimensions.iter().zip(&sources).enumerate() {
                    let point = |claim_ordinal: usize| {
                        let tag = response * 102 + source_index * 2 + claim_ordinal;
                        let mut point_stream =
                            volta_field::FpStream::from_seed([(tag % 251) as u8 + 1; 32]);
                        (0..mu).map(|_| point_stream.next_fp2()).collect::<Vec<_>>()
                    };
                    let claims = [
                        (
                            BlockClaim { offset: 0, point: point(0) },
                            ProverAuthed {
                                x: Fp2::new(
                                    Fp::new((response + source_index + 11) as u64),
                                    Fp::new(17),
                                ),
                                m: Fp2::new(Fp::new(19), Fp::new(23)),
                            },
                        ),
                        (
                            BlockClaim { offset: 0, point: point(1) },
                            ProverAuthed {
                                x: Fp2::new(Fp::new(29), Fp::new((response + 31) as u64)),
                                m: Fp2::new(Fp::new(37), Fp::new((source_index + 41) as u64)),
                            },
                        ),
                    ];
                    let domain = 0xC216_0000 + (response * 51 + source_index) as u64 * 64;
                    let reference = batch_reduce_prover(
                        source,
                        mu,
                        &claims,
                        &mut reference_stream,
                        domain,
                        &mut reference_tx,
                    );
                    let observed = batch_reduce_prover_cpu_resident(
                        &mut resident,
                        source_index,
                        mu,
                        &claims,
                        &mut resident_stream,
                        domain,
                        &mut resident_tx,
                    )
                    .unwrap();
                    assert_eq!(observed.0, reference.0);
                    assert_eq!(observed.1, reference.1);
                    assert_eq!(observed.2, reference.2);
                }
            }
            assert_eq!(resident_stream.counters, reference_stream.counters);
            assert_eq!(resident_tx.ledger(), reference_tx.ledger());
            assert_eq!(resident_tx.challenge_fp2(), reference_tx.challenge_fp2());
            let counters = resident.counters();
            assert_eq!(counters.canonical_sources, 51);
            assert_eq!(counters.canonical_source_symbols, physical_symbols);
            assert_eq!(counters.source_embedding_calls, 51);
            assert_eq!(counters.f_generation_calls, (51 * responses) as u64);
            counters
        }

        let k1 = run(1);
        let k16 = run(16);
        assert_eq!(k1.canonical_sources, k16.canonical_sources);
        assert_eq!(k1.canonical_source_symbols, k16.canonical_source_symbols);
        assert_eq!(k1.source_embedding_calls, k16.source_embedding_calls);
        assert_eq!(k16.f_generation_calls, 16 * k1.f_generation_calls);
        assert_eq!(k16.product_round_calls, 16 * k1.product_round_calls);
        assert_eq!(k16.f_fold_calls, 16 * k1.f_fold_calls);
        assert_eq!(k16.w_fold_calls, 16 * k1.w_fold_calls);
    }
}

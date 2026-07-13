//! P7b response-wide FFN state machine.
//!
//! Prefill and every stacked decode band stop their twelve public layer
//! chains at the same GELU dependency, prove one round-synchronous cohort per
//! band, then resume the unchanged FFN and attention tails in canonical
//! response order. One all-sites TableBank manifest covers the entire
//! response. Proof structs and communication are unchanged; only the public
//! transcript schedule changes. The module is deliberately explicit: no
//! worker threads, shared mutexes, or completion-order challenge assignment.

use crate::block_proof::{
    layer_lookups, prove_attn_block, prove_attn_block_resident, prove_ffn_after_gelu,
    prove_ffn_after_gelu_resident, prove_ffn_before_gelu, prove_ffn_before_gelu_resident,
    verify_attn_block, verify_ffn_after_gelu, verify_ffn_before_gelu, AttnP1, AttnV1, BandShape,
    BlockCtxP, BlockCtxV, CacheSegK, CacheSegP, FfnAfterDownP, FfnAfterDownV, KvPrefixK, KvPrefixP,
    LayerBytes, LayerOut, LayerOutV, LayerP1, LayerProof, LayerV1, ResidentAttnP1,
    ResidentCacheSegP, ResidentFfnAfterDownP, ResidentKvPrefixP, ResidentLayerP1, TableBankP,
    TableBankSiteError, TableBankV,
};
use crate::gemm_proof::ChainDoms;
use crate::logup::{
    blind_instance_prove_batch_cpu, blind_instance_prove_resident_batch,
    blind_instance_verify_batch, CpuLogupBatchJob, LogupBatchError, LogupBatchPlan, LogupBatchSite,
    ResidentLogupBatchJob, VerifyLogupBatchJob,
};
use crate::logup::{Counters, Doms, ProdKeyTriples, ProdTriples, TableKey};
use crate::schedule::{RoundFamily, SiteId};
use crate::thaler::pad_bits;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use volta_accel::{AccelError, Backend, BackendKind};
use volta_field::Fp2;
use volta_gpt2::{Gpt2Model, LayerWitness, ResidentGpt2Model, ResidentLayerView, D, DFF, H, L};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

const GELU_SHIFTS: [Option<u32>; 2] = [Some(0), Some(16)];
const H_PAD: usize = 16;

#[derive(Debug)]
pub(crate) enum FfnScheduleError {
    Public(&'static str),
    Batch(LogupBatchError),
    Table(TableBankSiteError),
    Accel(AccelError),
}

impl fmt::Display for FfnScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(message) => write!(f, "response FFN schedule: {message}"),
            Self::Batch(error) => write!(f, "response FFN schedule: {error}"),
            Self::Table(error) => write!(f, "response FFN table schedule: {error:?}"),
            Self::Accel(error) => write!(f, "response FFN resident schedule: {error}"),
        }
    }
}

impl std::error::Error for FfnScheduleError {}

impl From<LogupBatchError> for FfnScheduleError {
    fn from(error: LogupBatchError) -> Self {
        Self::Batch(error)
    }
}

impl From<TableBankSiteError> for FfnScheduleError {
    fn from(error: TableBankSiteError) -> Self {
        Self::Table(error)
    }
}

impl From<AccelError> for FfnScheduleError {
    fn from(error: AccelError) -> Self {
        Self::Accel(error)
    }
}

pub(crate) struct ScheduledLayerP {
    pub proof: LayerProof,
    pub out: LayerOut,
    pub prod: ProdTriples,
    pub zero: Vec<ProverAuthed>,
}

pub(crate) struct ScheduledLayerV {
    pub out: LayerOutV,
    pub prod: ProdKeyTriples,
    pub zero: Vec<VerifierKey>,
}

fn add_counter(target: &mut Counters, source: &Counters) {
    target.fp2_mults += source.fp2_mults;
    target.base_mults += source.base_mults;
}

fn gelu_site_id(layer_base: u8, layer: usize) -> Result<SiteId, FfnScheduleError> {
    let layer = u8::try_from(layer).map_err(|_| FfnScheduleError::Public("layer overflow"))?;
    let section = layer_base
        .checked_add(layer)
        .ok_or(FfnScheduleError::Public("GELU public section overflow"))?;
    Ok(SiteId::new(section.into(), RoundFamily::LogupAux, 0))
}

fn logup_domain_span(depth: usize) -> Result<u64, FfnScheduleError> {
    let depth =
        u64::try_from(depth).map_err(|_| FfnScheduleError::Public("LogUp depth overflow"))?;
    depth
        .checked_mul(depth.saturating_sub(1))
        .and_then(|rounds| rounds.checked_div(2))
        .and_then(|rounds| rounds.checked_add(2 * depth))
        .and_then(|span| span.checked_add(2))
        .ok_or(FfnScheduleError::Public("LogUp domain span overflow"))
}

pub(crate) struct GeluCohortPlan {
    batch: LogupBatchPlan,
    gelu_span: u64,
    shape: BandShape,
    layer_base: u8,
}

impl GeluCohortPlan {
    fn site(&self, layer: usize) -> Result<SiteId, FfnScheduleError> {
        gelu_site_id(self.layer_base, layer)
    }

    fn sites(&self) -> &[LogupBatchSite] {
        self.batch.sites()
    }
}

pub(crate) fn preflight_gelu_plan(
    t: usize,
    t0: usize,
    layer_base: u8,
    layer_doms: impl IntoIterator<Item = (usize, Doms, u32)>,
) -> Result<GeluCohortPlan, FfnScheduleError> {
    if t < 2 {
        return Err(FfnScheduleError::Public("GELU cohort needs at least two rows"));
    }
    let rb = pad_bits(t);
    let down_depth =
        rb.checked_add(pad_bits(D)).ok_or(FfnScheduleError::Public("FFN-down depth overflow"))?;
    let gelu_depth =
        rb.checked_add(pad_bits(DFF)).ok_or(FfnScheduleError::Public("GELU depth overflow"))?;
    let down_span = logup_domain_span(down_depth)?;
    let gelu_span = logup_domain_span(gelu_depth)?;
    let layers: Vec<_> = layer_doms.into_iter().collect();
    if layers.len() != L {
        return Err(FfnScheduleError::Public("expected exactly 12 model layers"));
    }
    let mut sites = Vec::with_capacity(L);
    for (layer, mut doms, shift_down) in layers {
        doms.take(down_span);
        if shift_down > 16 {
            doms.take(down_span);
        }
        let _ = ChainDoms::alloc(&mut doms, DFF);
        let mask_dom_base = doms.take(gelu_span);
        sites.push(LogupBatchSite {
            id: gelu_site_id(layer_base, layer)?,
            depth: gelu_depth,
            column_count: 2,
            aux_claim_count: 1,
            mask_dom_base,
        });
    }
    Ok(GeluCohortPlan {
        batch: LogupBatchPlan::new(sites)?,
        gelu_span,
        shape: BandShape { t0, q: t },
        layer_base,
    })
}

fn manifest_sites(plans: &[GeluCohortPlan]) -> Result<Vec<SiteId>, FfnScheduleError> {
    if plans.is_empty() {
        return Err(FfnScheduleError::Public("empty GELU response manifest"));
    }
    let mut ids = BTreeSet::new();
    let mut ranges = Vec::with_capacity(plans.len() * L);
    for plan in plans {
        for site in plan.sites() {
            if !ids.insert(site.id) {
                return Err(FfnScheduleError::Public("duplicate GELU response site"));
            }
            let end = site
                .mask_dom_base
                .checked_add(logup_domain_span(site.depth)?)
                .ok_or(FfnScheduleError::Public("GELU manifest domain overflow"))?;
            ranges.push((site.mask_dom_base, end));
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(FfnScheduleError::Public("GELU response domains overlap"));
    }
    Ok(ids.into_iter().collect())
}

pub(crate) fn register_gelu_manifest_p(
    bank: &mut TableBankP,
    plans: &[GeluCohortPlan],
) -> Result<(), FfnScheduleError> {
    let sites = manifest_sites(plans)?;
    bank.register_scheduled_sites(TableKey::Gelu, sites)?;
    Ok(())
}

pub(crate) fn register_gelu_manifest_v(
    bank: &mut TableBankV,
    plans: &[GeluCohortPlan],
) -> Result<(), FfnScheduleError> {
    let sites = manifest_sites(plans)?;
    bank.register_scheduled_sites(TableKey::Gelu, sites)?;
    Ok(())
}

#[cfg(test)]
fn projected_response_gelu_sync_reduction(rows: &[usize]) -> u64 {
    rows.iter()
        .map(|&rows| {
            let depth = pad_bits(rows) + pad_bits(DFF);
            let epochs = depth * (depth - 1) / 2 + depth + 1;
            ((L - 1) * epochs) as u64
        })
        .sum()
}

struct CpuPending {
    doms: Doms,
    dom_xin: u64,
    dom_k: u64,
    dom_v: u64,
    dom_abo: u64,
    dom_fbo: u64,
    xin_corr: Vec<u64>,
    k_corr: Vec<u64>,
    v_corr: Vec<u64>,
    abo_corr: Vec<u64>,
    fbo_corr: Vec<u64>,
    attn: AttnP1,
    ffn: FfnAfterDownP,
    prod: ProdTriples,
    zero: Vec<ProverAuthed>,
    ctr_instances: Counters,
    ctr_other: Counters,
    prefix_fulls: u64,
}

pub(crate) fn preflight_cpu_gelu_sources(
    layers: &[LayerWitness],
    plan: &GeluCohortPlan,
) -> Result<(), FfnScheduleError> {
    let t = plan.shape.q;
    let raw = t.checked_mul(DFF).ok_or(FfnScheduleError::Public("GELU raw geometry overflow"))?;
    if layers.len() != L
        || layers
            .iter()
            .any(|layer| layer.t != t || layer.ffn_up_q.len() != raw || layer.gelu_out.len() != raw)
    {
        return Err(FfnScheduleError::Public("GELU source geometry mismatch"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_layers_scheduled(
    model: &Gpt2Model,
    layers: &[LayerWitness],
    p1s: Vec<LayerP1>,
    prefixes: &[Vec<KvPrefixP<'_>>],
    plan: &GeluCohortPlan,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    mut backend: Option<&mut Backend>,
) -> Result<Vec<ScheduledLayerP>, FfnScheduleError> {
    preflight_cpu_gelu_sources(layers, plan)?;
    let t = plan.shape.q;
    if t < 2 || layers.len() != L || p1s.len() != L || prefixes.len() != L {
        return Err(FfnScheduleError::Public("invalid scheduled layer geometry"));
    }
    if layers.iter().any(|layer| layer.t != t)
        || prefixes.iter().any(|prefix| {
            prefix.iter().map(|segment| segment.rows).sum::<usize>() + t != plan.shape.s()
        })
    {
        return Err(FfnScheduleError::Public("invalid scheduled K/V prefix geometry"));
    }
    bank.preflight_scheduled_roots(TableKey::Gelu, plan.sites().iter().map(|site| site.id))?;
    let luts_for = |layer: usize| {
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[layer];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[layer];
        luts
    };
    // Materialize and shape-check all private CPU columns before the first
    // transcript/correlation mutation of the scheduled phase.
    let entries = 1usize << (pad_bits(t) + pad_bits(DFF));
    let mut gelu_columns = Vec::with_capacity(L);
    for layer in layers {
        let (input, output) =
            crate::block_proof::pair_cols_padded(&layer.ffn_up_q, &layer.gelu_out, t, DFF, 0, 0);
        if input.len() != entries || output.len() != entries {
            return Err(FfnScheduleError::Public("GELU padded geometry mismatch"));
        }
        gelu_columns.push(vec![input, output]);
    }
    let mut pending = Vec::with_capacity(L);
    for (layer, p1) in p1s.into_iter().enumerate() {
        let luts = luts_for(layer);
        let LayerP1 {
            doms,
            dom_xin,
            dom_k,
            dom_v,
            dom_abo,
            dom_fbo,
            xin_corr,
            k_corr,
            v_corr,
            abo_corr,
            fbo_corr,
            ffn,
            attn,
            fulls0: _,
        } = p1;
        let before = stream.counters.full_corrs;
        let mut cx = if let Some(accel) = backend.as_deref_mut() {
            BlockCtxP::with_doms_and_backend(stream, tx, doms, bank, accel)
        } else {
            BlockCtxP::with_doms(stream, tx, doms, bank)
        };
        let ffn = prove_ffn_before_gelu(
            &layers[layer],
            &model.layers[layer].0,
            &luts,
            ffn,
            &mut cx,
            dom_abo,
            dom_fbo,
            Some(&model.layers[layer].1),
        );
        let expected_base = plan.sites()[layer].mask_dom_base;
        if cx.doms.cursor() != expected_base || cx.doms.take(plan.gelu_span) != expected_base {
            return Err(FfnScheduleError::Public("GELU domain simulation diverged"));
        }
        pending.push(CpuPending {
            doms: cx.doms,
            dom_xin,
            dom_k,
            dom_v,
            dom_abo,
            dom_fbo,
            xin_corr,
            k_corr,
            v_corr,
            abo_corr,
            fbo_corr,
            attn,
            ffn,
            prod: cx.prod,
            zero: cx.zero,
            ctr_instances: cx.ctr_instances,
            ctr_other: cx.ctr_other,
            prefix_fulls: stream.counters.full_corrs - before,
        });
    }

    let jobs = pending
        .iter()
        .enumerate()
        .zip(gelu_columns)
        .map(|((layer, state), columns)| CpuLogupBatchJob {
            site: plan.site(layer).expect("validated layer SiteId"),
            columns,
            shifts: GELU_SHIFTS.to_vec(),
            alpha: bank.alpha(TableKey::Gelu),
            aux_claims: vec![state.ffn.gelu_aux_claim()],
        })
        .collect();
    let mut batch_ctr = Counters::default();
    let mut batch_prod = ProdTriples::new();
    let mut batch_zero = Vec::new();
    let fulls_before_batch = stream.counters.full_corrs;
    let outputs = blind_instance_prove_batch_cpu(
        &plan.batch,
        jobs,
        stream,
        tx,
        &mut batch_ctr,
        &mut batch_prod,
        &mut batch_zero,
    )?;
    let batch_fulls = stream.counters.full_corrs - fulls_before_batch;
    if batch_fulls % L as u64 != 0 {
        return Err(FfnScheduleError::Public("GELU correlation attribution is not uniform"));
    }
    let batch_fulls_per_layer = batch_fulls / L as u64;
    let mut outputs: BTreeMap<_, _> =
        outputs.into_iter().map(|output| (output.site, output.output)).collect();
    for site in plan.sites() {
        let output =
            outputs.get(&site.id).ok_or(FfnScheduleError::Public("missing GELU batch output"))?;
        bank.push_scheduled_roots(TableKey::Gelu, site.id, output.roots)?;
    }

    let mut scheduled = Vec::with_capacity(L);
    for (layer, mut state) in pending.into_iter().enumerate() {
        let luts = luts_for(layer);
        let gelu = outputs
            .remove(&plan.site(layer)?)
            .ok_or(FfnScheduleError::Public("missing canonical GELU output"))?;
        if layer == 0 {
            state.prod.extend(std::mem::take(&mut batch_prod));
            state.zero.extend(std::mem::take(&mut batch_zero));
            add_counter(&mut state.ctr_instances, &batch_ctr);
        }
        let tail_before = stream.counters.full_corrs;
        let mut cx = if let Some(accel) = backend.as_deref_mut() {
            BlockCtxP::with_doms_and_backend(stream, tx, state.doms, bank, accel)
        } else {
            BlockCtxP::with_doms(stream, tx, state.doms, bank)
        };
        cx.prod = state.prod;
        cx.zero = state.zero;
        cx.ctr_instances = state.ctr_instances;
        cx.ctr_other = state.ctr_other;
        let (ffn, mut ffn_claims) = prove_ffn_after_gelu(
            &layers[layer],
            &model.layers[layer].0,
            &luts,
            state.ffn,
            gelu,
            &mut cx,
            state.dom_abo,
            Some(&model.layers[layer].1),
        );
        let mut k_segments: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| CacheSegP { dom: segment.dom_k, rows: segment.rows, data: segment.k })
            .collect();
        k_segments.push(CacheSegP { dom: state.dom_k, rows: t, data: &layers[layer].k });
        let mut v_segments: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| CacheSegP { dom: segment.dom_v, rows: segment.rows, data: segment.v })
            .collect();
        v_segments.push(CacheSegP { dom: state.dom_v, rows: t, data: &layers[layer].v });
        let (attn, mut attn_claims) = prove_attn_block(
            &layers[layer],
            &model.layers[layer].0,
            &luts,
            state.attn,
            &mut cx,
            state.dom_xin,
            &k_segments,
            &v_segments,
            state.dom_abo,
            Some(&model.layers[layer].1),
        );
        let cattn = attn_claims.pop().ok_or(FfnScheduleError::Public("attention claim"))?;
        let projection = attn_claims.pop().ok_or(FfnScheduleError::Public("attention claim"))?;
        let up = ffn_claims.pop().ok_or(FfnScheduleError::Public("FFN claim"))?;
        let down = ffn_claims.pop().ok_or(FfnScheduleError::Public("FFN claim"))?;
        if !attn_claims.is_empty() || !ffn_claims.is_empty() {
            return Err(FfnScheduleError::Public("layer claim cardinality mismatch"));
        }
        let shape = plan.shape;
        let t_pad = 1u64 << pad_bits(t);
        let n_above = (H * shape.n_above_head()) as u64;
        let tail_fulls = cx.stream.counters.full_corrs - tail_before;
        let bytes = LayerBytes {
            boundary: 8 * 5 * (t * D) as u64,
            mult: 0,
            ln_vectors: 8 * 8 * t_pad,
            attn_vectors: 8
                * ((3 + luts.params.softmax_row_shift as u64) * H_PAD as u64 * t_pad + n_above),
            rounds_claims: 16 * (state.prefix_fulls + batch_fulls_per_layer + tail_fulls),
        };
        scheduled.push(ScheduledLayerP {
            proof: LayerProof {
                xin_corr: state.xin_corr,
                k_corr: state.k_corr,
                v_corr: state.v_corr,
                abo_corr: state.abo_corr,
                fbo_corr: state.fbo_corr,
                ffn,
                attn,
            },
            out: LayerOut {
                weight_claims: vec![cattn, projection, up, down],
                bytes,
                ctr_instances: cx.ctr_instances,
                ctr_other: cx.ctr_other,
                lookups: layer_lookups(shape),
                dom_xin: state.dom_xin,
                dom_fbo: state.dom_fbo,
                dom_k: state.dom_k,
                dom_v: state.dom_v,
            },
            prod: cx.prod,
            zero: cx.zero,
        });
    }
    Ok(scheduled)
}

struct VerifyPending {
    doms: Doms,
    xin_keys: Vec<Fp2>,
    k_keys: Vec<Fp2>,
    v_keys: Vec<Fp2>,
    abo_keys: Vec<Fp2>,
    fbo_keys: Vec<Fp2>,
    lvk2: crate::block_proof::LnVecsK,
    attn: AttnV1,
    ffn: FfnAfterDownV,
    prod: ProdKeyTriples,
    zero: Vec<VerifierKey>,
}

fn preflight_gelu_proof(
    proof: &crate::logup::BlindInstance,
    depth: usize,
) -> Result<(), FfnScheduleError> {
    let aux =
        proof.lookup.aux.as_ref().ok_or(FfnScheduleError::Public("GELU proof has no aux part"))?;
    if proof.lookup.layers.len() != depth
        || aux.rounds3.len() != depth - 1
        || aux.col_corrs.len() != 2
        || proof.lookup.layers.iter().enumerate().any(|(layer, proof_layer)| {
            proof_layer.round_corrs.len() != if layer + 1 == depth { 0 } else { layer }
        })
    {
        return Err(FfnScheduleError::Public("GELU proof shape mismatch"));
    }
    Ok(())
}

pub(crate) fn preflight_gelu_proofs(
    proofs: &[LayerProof],
    plan: &GeluCohortPlan,
) -> Result<(), FfnScheduleError> {
    if proofs.len() != L {
        return Err(FfnScheduleError::Public("GELU proof cohort size mismatch"));
    }
    let depth = pad_bits(plan.shape.q) + pad_bits(DFF);
    for proof in proofs {
        preflight_gelu_proof(&proof.ffn.inst_gelu, depth)?;
    }
    Ok(())
}

pub(crate) fn verify_layers_scheduled(
    model: &Gpt2Model,
    proofs: &[LayerProof],
    v1s: Vec<LayerV1>,
    prefixes: &[Vec<KvPrefixK<'_>>],
    plan: &GeluCohortPlan,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    bank: &mut TableBankV,
) -> Option<Vec<ScheduledLayerV>> {
    preflight_gelu_proofs(proofs, plan).ok()?;
    let t = plan.shape.q;
    if t < 2 || proofs.len() != L || v1s.len() != L || prefixes.len() != L {
        return None;
    }
    if prefixes.iter().any(|prefix| {
        prefix.iter().map(|segment| segment.rows).sum::<usize>() + t != plan.shape.s()
    }) {
        return None;
    }
    bank.preflight_scheduled_kroots(TableKey::Gelu, plan.sites().iter().map(|site| site.id))
        .ok()?;
    let luts_for = |layer: usize| {
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[layer];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[layer];
        luts
    };
    let depth = pad_bits(t) + pad_bits(DFF);
    let mut pending = Vec::with_capacity(L);
    for (layer, v1) in v1s.into_iter().enumerate() {
        let LayerV1 { doms, xin_keys, k_keys, v_keys, abo_keys, fbo_keys, lvk2, attn } = v1;
        let mut cx = BlockCtxV::with_doms(ctx, tx, doms, bank);
        let ffn = verify_ffn_before_gelu(
            t,
            &luts_for(layer),
            &proofs[layer].ffn,
            &mut cx,
            &abo_keys,
            &fbo_keys,
            Some(&model.layers[layer].1),
        )?;
        let expected_base = plan.sites()[layer].mask_dom_base;
        if cx.doms.cursor() != expected_base || cx.doms.take(plan.gelu_span) != expected_base {
            return None;
        }
        pending.push(VerifyPending {
            doms: cx.doms,
            xin_keys,
            k_keys,
            v_keys,
            abo_keys,
            fbo_keys,
            lvk2,
            attn,
            ffn,
            prod: cx.kprod,
            zero: cx.kzero,
        });
    }

    let auxes: Vec<Vec<_>> = pending.iter().map(|state| vec![state.ffn.gelu_aux()]).collect();
    let jobs = pending
        .iter()
        .enumerate()
        .map(|(layer, _)| {
            Some(VerifyLogupBatchJob {
                site: plan.site(layer).ok()?,
                n_bits: depth,
                shifts: &GELU_SHIFTS,
                alpha: bank.alpha(TableKey::Gelu)?,
                proof: &proofs[layer].ffn.inst_gelu,
                aux_claims: &auxes[layer],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let mut batch_prod = ProdKeyTriples::new();
    let mut batch_zero = Vec::new();
    let outputs =
        blind_instance_verify_batch(&plan.batch, jobs, ctx, tx, &mut batch_prod, &mut batch_zero)
            .ok()?;
    let mut outputs: BTreeMap<_, _> =
        outputs.into_iter().map(|output| (output.site, output.output)).collect();
    for site in plan.sites() {
        let output = outputs.get(&site.id)?;
        bank.push_scheduled_kroots(TableKey::Gelu, site.id, output.kroots).ok()?;
    }

    let mut scheduled = Vec::with_capacity(L);
    for (layer, mut state) in pending.into_iter().enumerate() {
        let gelu = outputs.remove(&plan.site(layer).ok()?)?;
        if layer == 0 {
            state.prod.extend(std::mem::take(&mut batch_prod));
            state.zero.extend(std::mem::take(&mut batch_zero));
        }
        let luts = luts_for(layer);
        let weights = &model.layers[layer].0;
        let mut cx = BlockCtxV::with_doms(ctx, tx, state.doms, bank);
        cx.kprod = state.prod;
        cx.kzero = state.zero;
        let mut ffn_keys = verify_ffn_after_gelu(
            t,
            &weights.ln2_gain,
            &weights.ln2_bias,
            &luts,
            &proofs[layer].ffn,
            &state.lvk2,
            state.ffn,
            gelu,
            &mut cx,
            &state.abo_keys,
            Some(&model.layers[layer].1),
        )?;
        let mut k_segments: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| CacheSegK { rows: segment.rows, keys: segment.k_keys })
            .collect();
        k_segments.push(CacheSegK { rows: t, keys: &state.k_keys });
        let mut v_segments: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| CacheSegK { rows: segment.rows, keys: segment.v_keys })
            .collect();
        v_segments.push(CacheSegK { rows: t, keys: &state.v_keys });
        let mut attn_keys = verify_attn_block(
            plan.shape,
            &weights.ln1_gain,
            &weights.ln1_bias,
            &luts,
            &proofs[layer].attn,
            state.attn,
            &mut cx,
            &state.xin_keys,
            &k_segments,
            &v_segments,
            &state.abo_keys,
            Some(&model.layers[layer].1),
        )?;
        let cattn = attn_keys.pop()?;
        let projection = attn_keys.pop()?;
        let up = ffn_keys.pop()?;
        let down = ffn_keys.pop()?;
        if !attn_keys.is_empty() || !ffn_keys.is_empty() {
            return None;
        }
        scheduled.push(ScheduledLayerV {
            out: LayerOutV {
                weight_keys: vec![cattn, projection, up, down],
                xin_keys: state.xin_keys,
                k_keys: state.k_keys,
                v_keys: state.v_keys,
                fbo_keys: state.fbo_keys,
            },
            prod: cx.kprod,
            zero: cx.kzero,
        });
    }
    Some(scheduled)
}

struct ResidentPending {
    doms: Doms,
    dom_xin: u64,
    dom_k: u64,
    dom_v: u64,
    dom_abo: u64,
    dom_fbo: u64,
    xin_corr: Vec<u64>,
    k_corr: Vec<u64>,
    v_corr: Vec<u64>,
    abo_corr: Vec<u64>,
    fbo_corr: Vec<u64>,
    attn: ResidentAttnP1,
    ffn: ResidentFfnAfterDownP,
    prod: ProdTriples,
    zero: Vec<ProverAuthed>,
    ctr_instances: Counters,
    ctr_other: Counters,
    prefix_fulls: u64,
}

fn cleanup_resident_pending(
    states: Vec<ResidentPending>,
    backend: &mut Backend,
) -> Result<(), AccelError> {
    let mut first = None;
    for state in states {
        if let Err(error) = state.ffn.cleanup(backend) {
            first.get_or_insert(error);
        }
        if let Err(error) = state.attn.free(backend) {
            first.get_or_insert(error);
        }
    }
    first.map_or(Ok(()), Err)
}

fn cleanup_unstarted_resident(
    states: Vec<Option<ResidentLayerP1>>,
    backend: &mut Backend,
) -> Result<(), AccelError> {
    let mut first = None;
    for state in states.into_iter().flatten() {
        if let Err(error) = state.free(backend) {
            first.get_or_insert(error);
        }
    }
    first.map_or(Ok(()), Err)
}

fn remember_cleanup(result: Result<(), AccelError>, first: &mut Option<AccelError>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}

/// Release every resident owner still held by the scheduler. Cleanup is
/// exhaustive; the first release failure is propagated because the CUDA
/// context may no longer be safely reusable even when a protocol error was
/// the original cause.
fn cleanup_resident_owners(
    current_ffn: Option<ResidentFfnAfterDownP>,
    current_attn: Option<ResidentAttnP1>,
    pending: Vec<ResidentPending>,
    unstarted: Vec<Option<ResidentLayerP1>>,
    backend: &mut Backend,
) -> Result<(), AccelError> {
    let mut first = None;
    if let Some(ffn) = current_ffn {
        remember_cleanup(ffn.cleanup(backend), &mut first);
    }
    if let Some(attn) = current_attn {
        remember_cleanup(attn.free(backend), &mut first);
    }
    remember_cleanup(cleanup_resident_pending(pending, backend), &mut first);
    remember_cleanup(cleanup_unstarted_resident(unstarted, backend), &mut first);
    first.map_or(Ok(()), Err)
}

fn resident_failure(
    primary: FfnScheduleError,
    current_ffn: Option<ResidentFfnAfterDownP>,
    current_attn: Option<ResidentAttnP1>,
    pending: Vec<ResidentPending>,
    unstarted: Vec<Option<ResidentLayerP1>>,
    backend: &mut Backend,
) -> FfnScheduleError {
    cleanup_resident_owners(current_ffn, current_attn, pending, unstarted, backend)
        .err()
        .map_or(primary, FfnScheduleError::Accel)
}

pub(crate) fn preflight_resident_gelu_sources<W: ResidentLayerView>(
    layers: &[W],
    p1s: &[ResidentLayerP1],
    plan: &GeluCohortPlan,
    backend: &Backend,
) -> Result<(), FfnScheduleError> {
    let t = plan.shape.q;
    if backend.kind() != BackendKind::CudaResident || layers.len() != L || p1s.len() != L {
        return Err(FfnScheduleError::Public("invalid resident GELU cohort geometry"));
    }
    if layers.iter().any(|layer| {
        layer.rows() != t || layer.pos0() != plan.shape.t0 || layer.seq() != plan.shape.s()
    }) {
        return Err(FfnScheduleError::Public("resident GELU cohort shape mismatch"));
    }
    let entries = 1usize << (pad_bits(t) + pad_bits(DFF));
    for p1 in p1s {
        let view = p1.ffn.gelu.view(0, 2)?;
        if p1.ffn.gelu.columns() != 2
            || p1.ffn.gelu.entries() != entries
            || !view.buffer().is_owned_by(backend)
        {
            return Err(FfnScheduleError::Public("resident GELU ownership mismatch"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_layers_resident_scheduled<W: ResidentLayerView>(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    layers: &[W],
    p1s: Vec<ResidentLayerP1>,
    prefixes: &[Vec<ResidentKvPrefixP>],
    plan: &GeluCohortPlan,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
) -> Result<Vec<ScheduledLayerP>, FfnScheduleError> {
    if let Err(error) = preflight_resident_gelu_sources(layers, &p1s, plan, backend) {
        return Err(resident_failure(
            error,
            None,
            None,
            Vec::new(),
            p1s.into_iter().map(Some).collect(),
            backend,
        ));
    }
    let t = plan.shape.q;
    if prefixes.len() != L
        || prefixes.iter().any(|prefix| {
            prefix.iter().map(|segment| segment.rows).sum::<usize>() + t != plan.shape.s()
        })
    {
        return Err(resident_failure(
            FfnScheduleError::Public("invalid resident K/V prefix geometry"),
            None,
            None,
            Vec::new(),
            p1s.into_iter().map(Some).collect(),
            backend,
        ));
    }
    if let Err(error) =
        bank.preflight_scheduled_roots(TableKey::Gelu, plan.sites().iter().map(|site| site.id))
    {
        return Err(resident_failure(
            error.into(),
            None,
            None,
            Vec::new(),
            p1s.into_iter().map(Some).collect(),
            backend,
        ));
    }
    let luts_for = |layer: usize| {
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[layer];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[layer];
        luts
    };
    let mut unstarted: Vec<_> = p1s.into_iter().map(Some).collect();
    let mut pending = Vec::with_capacity(L);
    for layer in 0..L {
        let p1 = match unstarted[layer].take() {
            Some(state) => state,
            None => {
                return Err(resident_failure(
                    FfnScheduleError::Public("missing resident layer state"),
                    None,
                    None,
                    pending,
                    unstarted,
                    backend,
                ));
            }
        };
        let ResidentLayerP1 {
            doms,
            dom_xin,
            dom_k,
            dom_v,
            dom_abo,
            dom_fbo,
            xin_corr,
            k_corr,
            v_corr,
            abo_corr,
            fbo_corr,
            ffn,
            attn,
            fulls0: _,
        } = p1;
        let before = stream.counters.full_corrs;
        let mut cx = BlockCtxP::with_doms_and_backend(stream, tx, doms, bank, backend);
        let ffn = match prove_ffn_before_gelu_resident(
            &layers[layer],
            resident_model,
            layer,
            &model.layers[layer].0,
            &luts_for(layer),
            ffn,
            &mut cx,
            dom_abo,
            dom_fbo,
            Some(&model.layers[layer].1),
        ) {
            Ok(state) => state,
            Err(error) => {
                return Err(resident_failure(
                    error.into(),
                    None,
                    Some(attn),
                    pending,
                    unstarted,
                    backend,
                ));
            }
        };
        let expected_base = plan.sites()[layer].mask_dom_base;
        if cx.doms.cursor() != expected_base || cx.doms.take(plan.gelu_span) != expected_base {
            return Err(resident_failure(
                FfnScheduleError::Public("resident GELU domains diverged"),
                Some(ffn),
                Some(attn),
                pending,
                unstarted,
                backend,
            ));
        }
        pending.push(ResidentPending {
            doms: cx.doms,
            dom_xin,
            dom_k,
            dom_v,
            dom_abo,
            dom_fbo,
            xin_corr,
            k_corr,
            v_corr,
            abo_corr,
            fbo_corr,
            attn,
            ffn,
            prod: cx.prod,
            zero: cx.zero,
            ctr_instances: cx.ctr_instances,
            ctr_other: cx.ctr_other,
            prefix_fulls: stream.counters.full_corrs - before,
        });
    }

    let jobs_result: Result<Vec<_>, AccelError> = pending
        .iter()
        .enumerate()
        .map(|(layer, state)| {
            Ok(ResidentLogupBatchJob {
                site: plan
                    .site(layer)
                    .map_err(|_| AccelError::InvalidInput("resident GELU SiteId"))?,
                columns: state.ffn.gelu_columns()?,
                column_count: 2,
                entries: state.ffn.gelu_entries(),
                shifts: GELU_SHIFTS.to_vec(),
                alpha: bank.alpha(TableKey::Gelu),
                aux_claims: vec![state.ffn.gelu_aux_claim()],
            })
        })
        .collect();
    let jobs = match jobs_result {
        Ok(jobs) => jobs,
        Err(error) => {
            return Err(resident_failure(error.into(), None, None, pending, Vec::new(), backend));
        }
    };
    let mut batch_ctr = Counters::default();
    let mut batch_prod = ProdTriples::new();
    let mut batch_zero = Vec::new();
    let fulls_before_batch = stream.counters.full_corrs;
    let outputs = match blind_instance_prove_resident_batch(
        &plan.batch,
        jobs,
        stream,
        tx,
        &mut batch_ctr,
        &mut batch_prod,
        &mut batch_zero,
        backend,
    ) {
        Ok(outputs) => outputs,
        Err(error) => {
            return Err(resident_failure(
                FfnScheduleError::Batch(error),
                None,
                None,
                pending,
                Vec::new(),
                backend,
            ));
        }
    };
    let batch_fulls = stream.counters.full_corrs - fulls_before_batch;
    if batch_fulls % L as u64 != 0 {
        return Err(resident_failure(
            FfnScheduleError::Public("resident GELU attribution mismatch"),
            None,
            None,
            pending,
            Vec::new(),
            backend,
        ));
    }
    let batch_fulls_per_layer = batch_fulls / L as u64;
    let mut outputs: BTreeMap<_, _> =
        outputs.into_iter().map(|output| (output.site, output.output)).collect();
    for site in plan.sites() {
        let Some(output) = outputs.get(&site.id) else {
            return Err(resident_failure(
                FfnScheduleError::Public("resident GELU output missing"),
                None,
                None,
                pending,
                Vec::new(),
                backend,
            ));
        };
        if let Err(error) = bank.push_scheduled_roots(TableKey::Gelu, site.id, output.roots) {
            return Err(resident_failure(error.into(), None, None, pending, Vec::new(), backend));
        }
    }

    let mut scheduled = Vec::with_capacity(L);
    let mut pending = pending.into_iter();
    while let Some(mut state) = pending.next() {
        let layer = scheduled.len();
        let site = match plan.site(layer) {
            Ok(site) => site,
            Err(error) => {
                let mut rest = vec![state];
                rest.extend(pending);
                return Err(resident_failure(error, None, None, rest, Vec::new(), backend));
            }
        };
        let gelu = match outputs.remove(&site) {
            Some(output) => output,
            None => {
                let mut rest = vec![state];
                rest.extend(pending);
                return Err(resident_failure(
                    FfnScheduleError::Public("canonical resident GELU missing"),
                    None,
                    None,
                    rest,
                    Vec::new(),
                    backend,
                ));
            }
        };
        if layer == 0 {
            state.prod.extend(std::mem::take(&mut batch_prod));
            state.zero.extend(std::mem::take(&mut batch_zero));
            add_counter(&mut state.ctr_instances, &batch_ctr);
        }
        let tail_before = stream.counters.full_corrs;
        let mut cx = BlockCtxP::with_doms_and_backend(stream, tx, state.doms, bank, backend);
        cx.prod = state.prod;
        cx.zero = state.zero;
        cx.ctr_instances = state.ctr_instances;
        cx.ctr_other = state.ctr_other;
        let (ffn, mut ffn_claims) = match prove_ffn_after_gelu_resident(
            &layers[layer],
            resident_model,
            layer,
            &model.layers[layer].0,
            &luts_for(layer),
            state.ffn,
            gelu,
            &mut cx,
            state.dom_abo,
            Some(&model.layers[layer].1),
        ) {
            Ok(value) => value,
            Err(error) => {
                return Err(resident_failure(
                    error.into(),
                    None,
                    Some(state.attn),
                    pending.collect(),
                    Vec::new(),
                    backend,
                ));
            }
        };
        let mut segments_k: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| ResidentCacheSegP { dom: segment.dom_k, rows: segment.rows })
            .collect();
        segments_k.push(ResidentCacheSegP { dom: state.dom_k, rows: t });
        let mut segments_v: Vec<_> = prefixes[layer]
            .iter()
            .map(|segment| ResidentCacheSegP { dom: segment.dom_v, rows: segment.rows })
            .collect();
        segments_v.push(ResidentCacheSegP { dom: state.dom_v, rows: t });
        let (attn, mut attn_claims) = match prove_attn_block_resident(
            &layers[layer],
            resident_model,
            layer,
            &model.layers[layer].0,
            &luts_for(layer),
            state.attn,
            &mut cx,
            &segments_k,
            &segments_v,
            state.dom_xin,
            state.dom_k,
            state.dom_v,
            state.dom_abo,
            Some(&model.layers[layer].1),
        ) {
            Ok(value) => value,
            Err(error) => {
                return Err(resident_failure(
                    error.into(),
                    None,
                    None,
                    pending.collect(),
                    Vec::new(),
                    backend,
                ));
            }
        };
        if attn_claims.len() != 2 || ffn_claims.len() != 2 {
            return Err(resident_failure(
                FfnScheduleError::Public("resident layer claim cardinality"),
                None,
                None,
                pending.collect(),
                Vec::new(),
                backend,
            ));
        }
        let cattn = attn_claims.pop().expect("cardinality checked");
        let projection = attn_claims.pop().expect("cardinality checked");
        let up = ffn_claims.pop().expect("cardinality checked");
        let down = ffn_claims.pop().expect("cardinality checked");
        let shape = plan.shape;
        let t_pad = 1u64 << pad_bits(t);
        let n_above = (H * shape.n_above_head()) as u64;
        let tail_fulls = cx.stream.counters.full_corrs - tail_before;
        scheduled.push(ScheduledLayerP {
            proof: LayerProof {
                xin_corr: state.xin_corr,
                k_corr: state.k_corr,
                v_corr: state.v_corr,
                abo_corr: state.abo_corr,
                fbo_corr: state.fbo_corr,
                ffn,
                attn,
            },
            out: LayerOut {
                weight_claims: vec![cattn, projection, up, down],
                bytes: LayerBytes {
                    boundary: 8 * 5 * (t * D) as u64,
                    mult: 0,
                    ln_vectors: 8 * 8 * t_pad,
                    attn_vectors: 8
                        * ((3 + model.luts.params.softmax_row_shift as u64) * H_PAD as u64 * t_pad
                            + n_above),
                    rounds_claims: 16 * (state.prefix_fulls + batch_fulls_per_layer + tail_fulls),
                },
                ctr_instances: cx.ctr_instances,
                ctr_other: cx.ctr_other,
                lookups: layer_lookups(shape),
                dom_xin: state.dom_xin,
                dom_fbo: state.dom_fbo,
                dom_k: state.dom_k,
                dom_v: state.dom_v,
            },
            prod: cx.prod,
            zero: cx.zero,
        });
    }
    Ok(scheduled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_public_gelu_schedule_is_rejected_without_protocol_mutation() {
        let stream = CorrelationStream::new([0x31; 32]);
        let tx = Transcript::new([0x42; 32]);
        let bank = TableBankP::new();
        let counters_before = stream.counters;
        let allocation_before = stream.allocation_digest_hex();
        let ledger_before = tx.ledger().clone();
        let bytes_before = tx.total_bytes();
        let keys_before = bank.content_keys();

        // Every public layer advertises the same one-time domain range. The
        // SchedulePlan overlap check must reject this before registration or
        // any transcript/correlation draw can occur.
        let shared = Doms::new(0x1234);
        let result = preflight_gelu_plan(100, 0, 0, (0..L).map(|layer| (layer, shared, 16)));
        assert!(result.is_err());
        assert_eq!(stream.counters, counters_before);
        assert_eq!(stream.allocation_digest_hex(), allocation_before);
        assert_eq!(tx.ledger(), &ledger_before);
        assert_eq!(tx.total_bytes(), bytes_before);
        assert_eq!(bank.content_keys(), keys_before);
    }

    #[test]
    fn official_response_gelu_sync_reduction_is_pre_registered_geometry() {
        // Run of record: one T=100 prefill and one q=50 response band.
        assert_eq!(projected_response_gelu_sync_reduction(&[100, 50]), 3_993);
        // The separate flat-cost curve proves the same 50 tokens as 5×q=10.
        assert_eq!(projected_response_gelu_sync_reduction(&[100, 10, 10, 10, 10, 10]), 9_636);
    }

    #[test]
    fn response_manifest_uses_public_prefill_and_decode_sections() {
        let plan = |rows, t0, layer_base| {
            preflight_gelu_plan(
                rows,
                t0,
                layer_base,
                (0..L).map(|layer| {
                    (
                        layer,
                        Doms::new(crate::block_proof::layer_dom_base(layer_base + layer as u8)),
                        16,
                    )
                }),
            )
            .unwrap()
        };
        let plans = [plan(100, 0, 0), plan(50, 100, 16)];
        let sections: Vec<_> =
            manifest_sites(&plans).unwrap().into_iter().map(SiteId::section).collect();
        assert_eq!(sections, (0u16..12).chain(16..28).collect::<Vec<_>>());
    }
}

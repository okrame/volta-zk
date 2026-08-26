//! P5 full-model prove/verify driver: 12 GPT-2 layers + 11 seam requants +
//! the embedding requant + the final LayerNorm, wired together from EXACTLY
//! the same machinery `block_proof.rs` uses per layer. No new cryptographic
//! design: every piece here is an instance of a mechanism already exercised
//! by `prove_layer`/`verify_layer` — this module only orchestrates the
//! model-level boundary stitching (seams, embedding, final LN) and collects
//! ONE model-wide Π_Prod batch + ONE model-wide Π_ZeroBatch for the caller to
//! close (mirrors `prove_layer`'s per-layer accumulator contract, just
//! scaled up).
//!
//! Layer ids (the `CorrIndex.layer` byte, one-time domain separation): layer
//! `l` uses id `l` (0..11); the seam between layer `l` and `l+1` uses id
//! `200 + l` (200..210, ≤ 11 seams); the embedding uses id 220; the final LN
//! uses id 221. These ranges are disjoint by construction.
//!
//! **Seams**: `forward_model` requants `ffn_block_out(l)` into `x_in(l+1)`
//! with a per-seam shift ≤ 16 (asserted — no chained seams in the P5
//! artifact). Shift 0 is the identity (no lookup): the two boundaries are
//! tied by an equality zero row at a fresh transcript challenge point
//! instead of a range instance.
//!
//! **Embedding**: `embed.acc = wte[tok] + wpe[pos]` requantized into
//! `embed.out`, which is ALSO `layer[0].x_in` (tied by the same equality
//! trick). The requant's ACC claim is deliberately left PENDING in
//! [`ModelOut::embed_acc_claim`] — resolving it against the true
//! `wte[tok]+wpe[pos]` MLE evaluation is the embedding-SELECTION sumcheck's
//! job, out of scope here (the e2e test below stands in for it with the
//! true evaluation directly, exactly like the per-layer tests stand in for
//! the weight-tensor PCS).
//!
//! **Final LN**: runs on the LAST row only (t=1). Its pre-LN input is the
//! last row of `layer[11].ffn_block_out`, which is already authenticated as
//! part of that T×D boundary matrix under a DIFFERENT domain (per-row use);
//! `prove_ln_chain`'s hadamard needs a domain that opens as a 1×D matrix, so
//! the last row is re-authenticated fresh (1×D, +6 KB — negligible) and tied
//! to the T×D boundary by an equality zero row at a fresh challenge point,
//! row-selected by the boolean coordinates of index `t−1`. The chain's
//! upstream `wire` claim (normally the downstream GEMM's X-wire) has no
//! natural producer here (logits are out of scope), so it is manufactured as
//! a fresh opening of the SAME `final_ln.out` boundary auth at a fresh
//! challenge point — a trivially-true "wire" the verifier reconstructs
//! identically, `corr = 0`, no correction needed. The real artifact's
//! `shift_ln_norm = 20 > 16`, so the chained (two-stage) range-site path is
//! exercised here exactly as it is per-layer.

use crate::block_proof::{
    add_range_mult, auth_ln_vecs_p, auth_ln_vecs_resident_p, auth_matrix_rows_p,
    auth_matrix_rows_resident_p, auth_matrix_rows_v, bind_range_site_resident, expand_ln_vecs_k,
    layer_content_keys, layer_dom_base, ln_acc_recompute, open_matrix_k, open_matrix_p,
    open_matrix_resident_p, open_matrix_weighted_rows_k, open_matrix_weighted_rows_p,
    open_matrix_weighted_rows_resident_p, prove_layer_phase1, prove_layer_phase1_band,
    prove_layer_phase1_band_reusing_xin, prove_layer_phase1_band_thinned,
    prove_layer_phase1_resident_thinned, prove_layer_phase1_reusing_xin,
    prove_layer_phase1_thinned, prove_ln_chain, prove_ln_chain_resident, prove_range_site,
    prove_range_site_resident, public_window_fold_resident, range_keys,
    verify_layer_phase1_band_thinned, verify_ln_chain, verify_range_site, BandShape, BlockCtxP,
    BlockCtxV, InstanceLookups, KvPrefixK, KvPrefixP, LayerBytes, LayerP1, LayerProof, LayerV1,
    LnChainProof, ResidentKvPrefixP, ResidentLayerP1, ResidentLnVecsP, TableBankP, TableBankV,
    TableCloseProof,
};
#[cfg(feature = "c6-trace")]
use crate::block_proof::{verify_layer_phase1_band_thinned_c6, C6KvPrefixSource};
#[cfg(feature = "c6-trace")]
use crate::c6_cache_fold::{
    C6CacheFoldAppendSourceLayer, C6CacheFoldAppendSourcePlan, C6CacheFoldKind,
    C6CacheFoldOnlineLayerMetrics, C6CacheFoldTargetInlineProver, C6CacheFoldTargetInlineVerifier,
};
#[cfg(feature = "c6-trace")]
use crate::c6_source::{C6SourceScheduleProverFollower, C6SourceScheduleVerifierFollower};
use crate::ffn_schedule::{
    preflight_cpu_gelu_sources, preflight_gelu_plan, preflight_gelu_plan_thinned,
    preflight_gelu_proofs, preflight_resident_gelu_sources, prove_layers_resident_scheduled,
    prove_layers_scheduled, prove_layers_thinned_scheduled, register_gelu_manifest_p,
    register_gelu_manifest_v, verify_layers_thinned_scheduled,
};
#[cfg(feature = "c6-trace")]
use crate::ffn_schedule::{prove_layers_thinned_scheduled_c6, verify_layers_thinned_scheduled_c6};
use crate::gemm_proof::{WeightClaimP, WireKey, WireOut};
use crate::logup::{eval_mle_counted, Counters, ProdKeyTriples, ProdTriples};
use crate::logup::{Doms, TableKey};
use crate::mle::eq_vec;
use crate::private_argmax::{
    build_private_argmax_resident_witness, build_private_argmax_witness,
    free_private_argmax_prepared, phase_layout_from_lengths, prepare_private_argmax_prover,
    prepare_private_argmax_verifier, prove_private_argmax, verify_private_argmax, ArgmaxPhaseInput,
    PrivateArgmaxPhaseP, PrivateArgmaxPreparedP, PrivateArgmaxProof, ResidentArgmaxPhaseInput,
};
use crate::sumcheck_blind::{blind_prove, blind_prove_resident, blind_verify, BlindSumcheckProof};
use crate::thaler::{fold_w, pad_bits};
use rayon::prelude::*;
use std::collections::BTreeSet;
use volta_accel::{
    AccelError, Backend, BackendKind, DeviceBuffer, DeviceLookupColumns, DeviceSlice, Fp2Repr,
    MatrixFoldAxis,
};
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    BandModelWitness, ConfigBinding, Gpt2Model, Gpt2VerifierModel, LayerI16Field, Luts,
    ModelConfig, ModelWeightField, ModelWitness, P5Params, ResidentBandModelWitness,
    ResidentGpt2Model, ResidentLayerView, ResidentModelWitness, D, H, L, NPOS, VOCAB,
};
use volta_mac::{
    CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn add_bytes(a: &mut LayerBytes, b: &LayerBytes) {
    a.boundary += b.boundary;
    a.mult += b.mult;
    a.ln_vectors += b.ln_vectors;
    a.attn_vectors += b.attn_vectors;
    a.rounds_claims += b.rounds_claims;
}

/// C6 response zero roots are inputs to the fused grand residual, not to the
/// historical clear `ZeroBatch`.  Keeping them behind a role-specific type
/// makes that ownership distinction impossible to erase accidentally at the
/// response seam.
#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
pub struct C6GrandResidualProverRoots(Vec<ProverAuthed>);

#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
impl C6GrandResidualProverRoots {
    fn new(roots: Vec<ProverAuthed>) -> Self {
        Self(roots)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn record_operation_trace_ownership(&self) -> Result<(), volta_mac::C6TraceError> {
        let roots = self.0.iter().copied().map(ProverAuthed::c6_trace_token).collect::<Vec<_>>();
        volta_mac::record_c6_zero_roots(&roots)
    }
}

#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
pub struct C6GrandResidualVerifierRoots(Vec<VerifierKey>);

#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
impl C6GrandResidualVerifierRoots {
    fn new(roots: Vec<VerifierKey>) -> Self {
        Self(roots)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn record_operation_trace_ownership(&self) -> Result<(), volta_mac::C6TraceError> {
        let roots = self.0.iter().copied().map(VerifierKey::c6_trace_token).collect::<Vec<_>>();
        volta_mac::record_c6_zero_roots(&roots)
    }
}

enum ResponseProverCacheMode<'a, 'frame> {
    Legacy(std::marker::PhantomData<(&'a mut (), &'frame mut ())>),
    #[cfg(feature = "c6-trace")]
    #[allow(dead_code)]
    C6 {
        secondary: &'a mut CorrelationStream,
        schedule_follower: &'a mut C6SourceScheduleProverFollower,
        target_builder: &'frame mut C6CacheFoldTargetInlineProver,
        metrics: C6CacheFoldOnlineLayerMetrics,
        append_source_layers: Vec<C6CacheFoldAppendSourceLayer>,
    },
}

enum ResponseVerifierCacheMode<'a, 'frame> {
    Legacy(std::marker::PhantomData<(&'a mut (), &'frame mut ())>),
    #[cfg(feature = "c6-trace")]
    #[allow(dead_code)]
    C6 {
        secondary: &'a mut VerifierCtx,
        schedule_follower: &'a mut C6SourceScheduleVerifierFollower,
        target_cursor: &'a mut C6CacheFoldTargetInlineVerifier<'frame>,
        metrics: C6CacheFoldOnlineLayerMetrics,
        append_source_layers: Vec<C6CacheFoldAppendSourceLayer>,
        paired_targets: Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
    },
}

#[cfg(feature = "c6-trace")]
fn add_c6_response_metrics(
    total: &mut C6CacheFoldOnlineLayerMetrics,
    phase: C6CacheFoldOnlineLayerMetrics,
) {
    total.source_groups += phase.source_groups;
    total.source_cells += phase.source_cells;
    total.coefficient_applications += phase.coefficient_applications;
    total.corrected_targets += phase.corrected_targets;
    total.linear_auxiliary_source_cells += phase.linear_auxiliary_source_cells;
}

fn add_counters(a: &mut Counters, b: &Counters) {
    a.fp2_mults += b.fp2_mults;
    a.base_mults += b.base_mults;
}

/// Boolean MLE coordinates of `idx` over `bits` variables, LSB first (mirrors
/// `head_bit_coords`, generalized to an arbitrary bit width — used to select
/// a single row out of a T×D boundary matrix by its row-var coordinates).
/// S̃(ρ_z) = Σ_i eq_i[i] · Π_b (tok_i bit b ? ρ_z[b] : 1 − ρ_z[b]), bits
/// LSB-first (matching the MLE var order everywhere in this codebase).
fn sel_s_eval(tokens: &[u32], eq_i: &[Fp2], rho_z: &[Fp2]) -> Fp2 {
    let mut s = Fp2::ZERO;
    for (i, &tok) in tokens.iter().enumerate() {
        let mut p = eq_i[i];
        for (b, &r) in rho_z.iter().enumerate() {
            p = p * if (tok >> b) & 1 == 1 { r } else { Fp2::ONE - r };
        }
        s += p;
    }
    s
}

/// G̃(ρ_w) for G(w) = [t0 ≤ w < t0+q]·eq(r_i, w−t0) over the wpe row vars:
/// Σ_{r<q} eq_i[r] · eq(bits(t0+r), ρ_w), bits LSB-first. The P5 prefill case
/// is the window at t0 = 0.
fn masked_eq_eval(eq_i: &[Fp2], t0: usize, q: usize, rho_w: &[Fp2]) -> Fp2 {
    let mut s = Fp2::ZERO;
    for (r, &e) in eq_i.iter().enumerate().take(q) {
        let w = t0 + r;
        let mut p = e;
        for (b, &rr) in rho_w.iter().enumerate() {
            p = p * if (w >> b) & 1 == 1 { rr } else { Fp2::ONE - rr };
        }
        s += p;
    }
    s
}

fn bit_coords(idx: usize, bits: usize) -> Vec<Fp2> {
    (0..bits).map(|b| if (idx >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO }).collect()
}

// ---------------------------------------------------------------------------
// Proof / output types
// ---------------------------------------------------------------------------

/// A seam requant range site (shift ≤ 16, single-stage — P5 seams never
/// chain). `None` at the model level means shift == 0 (identity, no
/// instance — see module docs).
#[derive(Debug, PartialEq, Eq)]
pub struct SeamProof {
    pub inst: crate::logup::BlindInstance,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EmbedProof {
    /// Boundary auth of `embed.out` (T×d, 8 B/value — same convention as the
    /// per-layer boundaries).
    pub out_corr: Vec<u64>,
    pub inst: crate::logup::BlindInstance,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FinalLnProof {
    /// Boundary auth of `final_ln.out` (d values, 1×D).
    pub out_corr: Vec<u64>,
    /// Fresh re-auth of `layer[11].ffn_block_out`'s LAST ROW (1×D) — the LN
    /// chain's `x`/`dom_x` (see module docs).
    pub row_corr: Vec<u64>,
    /// LN vector corrections [mean, var, rsqrt_in, rsqrt_out] at t = 1.
    pub ln_vec_corrs: [Vec<u64>; 4],
    pub ln: LnChainProof,
}

/// Logits claim (P5-D2): the public logits vector is bound at a random ρ_v
/// and reduced by one blind matvec sumcheck over the d vars to one wte PCS
/// claim × one MAC opening of the authenticated final-LN row (Π_Prod row).
#[derive(Debug, PartialEq, Eq)]
pub struct LogitsClaimProof {
    pub sc: BlindSumcheckProof,
    /// Correction authenticating the prover's w̃te(ρ_v, r_l).
    pub wte_corr: Fp2,
}

/// Embedding-selection claim (P5-D2): the pending embed-acc claim equals
/// Σ_z S(z)·w̃te(z, r_d) + w̃pe(r_d ‖ r_i ‖ 0…) with S public (tokens are
/// public); one blind sumcheck over the 16 vocab-bit vars, resolved into one
/// wte claim (zero row, S̃(ρ_z) public) and one wpe claim.
#[derive(Debug, PartialEq, Eq)]
pub struct SelectionProof {
    pub sc: BlindSumcheckProof,
    pub wte_corr: Fp2,
    /// Correction authenticating the claimed masked-wpe contribution
    /// P = Σ_{i<t} eq_i[i]·w̃pe(i, r_d) (real rows only — the committed wpe
    /// block has NONZERO rows t..1023 that the embed acc does not contain,
    /// so a direct w̃pe point claim is wrong at any non-power-of-two t).
    pub p_corr: Fp2,
    /// The masked-wpe sumcheck over the block's 10 row vars:
    /// P = Σ_w G(w)·w̃pe(w, r_d) with G(w) = [w<t]·eq(r_i, w) public.
    pub sc_wpe: BlindSumcheckProof,
    pub wpe_corr: Fp2,
}

/// One decode chunk's PUBLIC data (verifier side): its band logits matrix
/// (q×VOCAB, the response's per-position logits) and the full token sequence.
pub struct ChunkPub<'a> {
    pub q: usize,
    pub logits: &'a [i64],
    pub seq: &'a [u32],
}

/// C3 verifier-side decode chunk: only public response tokens remain; logits
/// are bound privately by [`PrivateArgmaxProof`].
pub struct PrivateChunkPub<'a> {
    pub q: usize,
    pub seq: &'a [u32],
}

/// One decode chunk's witness + the full public token sequence.
pub struct ChunkRef<'a> {
    pub band: &'a BandModelWitness,
    /// Full response tokens (prompt ++ generated), len ≥ t0+q.
    pub seq: &'a [u32],
}

struct C6ContinuationBase<'a> {
    band: &'a BandModelWitness,
    full: &'a ModelWitness,
}

#[derive(Clone, Copy)]
struct C6ContinuationPublic {
    base_t0: usize,
}

/// Device-resident decode chunk plus the public messages that the protocol
/// already requires on the host. The witness itself remains borrowed from
/// opaque CUDA allocations. `logits` is the public-L2 compatibility input;
/// private-L4 callers must pass an empty slice and use the resident logits.
#[doc(hidden)]
pub struct ResidentChunkRef<'a, 'source> {
    pub band: &'a ResidentBandModelWitness<'source>,
    pub logits: &'a [i64],
    pub seq: &'a [u32],
}

/// Per-chunk section ids (CorrIndex.layer bytes): base 16+32c, disjoint from
/// the prefill's (0..11, 200..210, 220, 221, 230, 231) for c < 5.
const MAX_RESPONSE_CHUNKS: usize = 5;

fn chunk_ids(c: usize) -> (u8, u8, u8, u8, u8, u8) {
    assert!(c < MAX_RESPONSE_CHUNKS, "at most 5 decode chunks per response (id space)");
    let b = (16 + 32 * c) as u8;
    (b, b + 12, b + 23, b + 24, b + 25, b + 26)
}

/// One decode chunk's proof: 12 band layers + band seams + band embedding
/// (+ selection at the position window) + band final LN + the band logits
/// claim. Same machinery as the prefill sections, at t = q with the
/// cross-phase K/V cache segments.
#[derive(Debug, PartialEq, Eq)]
pub struct ChunkProof {
    pub layers: Vec<LayerProof>,
    pub seams: Vec<Option<SeamProof>>,
    pub embed: EmbedProof,
    /// Boundary auth of the band final-LN output (q×D).
    pub fin_out_corr: Vec<u64>,
    /// Final-LN vector corrections [mean, var, rsqrt_in, rsqrt_out] (q_pad).
    pub fin_ln_vec_corrs: [Vec<u64>; 4],
    pub fin_ln: LnChainProof,
    pub logits: LogitsClaimProof,
    pub selection: SelectionProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ModelProof {
    pub layers: Vec<LayerProof>,
    /// Index `l` is the seam between layer `l` and `l+1` (11 entries).
    pub seams: Vec<Option<SeamProof>>,
    pub embed: EmbedProof,
    pub final_ln: FinalLnProof,
    pub logits: LogitsClaimProof,
    pub selection: SelectionProof,
    /// Decode chunks (P6), in response order.
    pub chunks: Vec<ChunkProof>,
    /// Per-content table closures (ONE multiset argument per table content
    /// per model — P6 shared-α restructure), canonical `TableKey` order.
    pub tables: Vec<TableCloseProof>,
    /// C3 private-logit greedy decoding. Historical proof modes keep `None`.
    pub private_argmax: Option<PrivateArgmaxProof>,
}

pub struct ModelOut {
    /// Committed-weight claims, LAYER-MAJOR per phase (48 prefill, then 48
    /// per chunk), canonical per-layer order [c_attn, attn_proj, ffn_up,
    /// ffn_down] (as `LayerOut`).
    pub weight_claims: Vec<WeightClaimP>,
    /// Wall time of each decode chunk's phase-1 / phase-2 sections (P6
    /// flat-cost curve; empty without chunks).
    pub chunk_p1_s: Vec<f64>,
    pub chunk_p2_s: Vec<f64>,
    /// The 3 embedding-commitment claims, order [wte(logits), wte(selection),
    /// wpe]: the logits/selection sumchecks CONSUME the embed-acc claim, so
    /// nothing is left pending — these resolve against `layout_gpt2_embed`.
    pub embed_claims: Vec<WeightClaimP>,
    pub bytes: LayerBytes,
    pub ctr_instances: Counters,
    pub ctr_other: Counters,
    pub lookups: Vec<InstanceLookups>,
    pub corr_counters: CorrCounters,
}

pub struct ModelOutV {
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    pub embed_keys: Vec<(Vec<Fp2>, VerifierKey)>,
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// The model's expected table-content set, from PUBLIC parameters (per-layer
/// shift overrides, seam shifts, embed shift). Both parties derive it.
fn model_content_keys_from(p: &P5Params, luts: &Luts) -> BTreeSet<TableKey> {
    let mut keys = BTreeSet::new();
    for l in 0..L {
        let mut luts_l = luts.clone();
        luts_l.params.shift_attn_proj = p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = p.shift_ffn_down[l];
        layer_content_keys(&luts_l, &mut keys);
    }
    for &shift in &p.seam_shifts[..L - 1] {
        if shift > 0 {
            let (k, k1) = range_keys(shift);
            keys.insert(k);
            if let Some(k1) = k1 {
                keys.insert(k1);
            }
        }
    }
    let (ke, ke1) = range_keys(p.shift_embed as u32);
    keys.insert(ke);
    if let Some(k1) = ke1 {
        keys.insert(k1);
    }
    keys
}

pub fn model_content_keys(model: &Gpt2Model) -> BTreeSet<TableKey> {
    model_content_keys_from(&model.p, &model.luts)
}

struct ResidentEmbedP1 {
    doms: Doms,
    dom_out: u64,
    out_corr: Vec<u64>,
    columns: DeviceLookupColumns,
}

impl ResidentEmbedP1 {
    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        backend.free_lookup_columns(self.columns)
    }
}

struct ResidentFinalP1 {
    doms: Doms,
    dom_out: u64,
    out_corr: Vec<u64>,
    dom_row: u64,
    row_corr: Vec<u64>,
    ln_vec_corrs: [Vec<u64>; 4],
    out2: DeviceBuffer<i16>,
    x2: DeviceBuffer<i16>,
    lv: ResidentLnVecsP,
    ln_columns: DeviceLookupColumns,
    rsqrt_columns: DeviceLookupColumns,
}

#[derive(Default)]
struct PendingFinalSources {
    out2: Option<DeviceBuffer<i16>>,
    x2: Option<DeviceBuffer<i16>>,
    acc2: Option<DeviceBuffer<i64>>,
    mean2: Option<DeviceBuffer<i64>>,
    var2: Option<DeviceBuffer<i64>>,
    rin2: Option<DeviceBuffer<i64>>,
    rout2: Option<DeviceBuffer<i16>>,
}

impl PendingFinalSources {
    fn free(mut self, backend: &mut Backend) {
        if let Some(value) = self.rout2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.rin2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.var2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.mean2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.acc2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.x2.take() {
            let _ = backend.free_device(value);
        }
        if let Some(value) = self.out2.take() {
            let _ = backend.free_device(value);
        }
    }
}

impl ResidentFinalP1 {
    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let first = backend.free_lookup_columns(self.rsqrt_columns).err();
        let second = backend.free_lookup_columns(self.ln_columns).err();
        let third = self.lv.free(backend).err();
        let fourth = backend.free_device(self.x2).err();
        let fifth = backend.free_device(self.out2).err();
        first.or(second).or(third).or(fourth).or(fifth).map_or(Ok(()), Err)
    }
}

/// Phase-1 state for a decode band's final LayerNorm. Unlike the square
/// prefill tail, the band proves all q rows directly and therefore needs no
/// duplicated-row compatibility buffers or fresh row authentication.
struct ResidentBandFinalP1 {
    doms: Doms,
    dom_out: u64,
    out_corr: Vec<u64>,
    ln_vec_corrs: [Vec<u64>; 4],
    lv: ResidentLnVecsP,
    ln_columns: DeviceLookupColumns,
    rsqrt_columns: DeviceLookupColumns,
}

impl ResidentBandFinalP1 {
    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let first = backend.free_lookup_columns(self.rsqrt_columns).err();
        let second = backend.free_lookup_columns(self.ln_columns).err();
        let third = self.lv.free(backend).err();
        first.or(second).or(third).map_or(Ok(()), Err)
    }
}

struct ResidentChunkP1 {
    layer_p1s: Vec<ResidentLayerP1>,
    seam_columns: Vec<Option<DeviceLookupColumns>>,
    embed: ResidentEmbedP1,
    final_ln: ResidentBandFinalP1,
}

impl ResidentChunkP1 {
    fn free(self, backend: &mut Backend) {
        for layer in self.layer_p1s {
            let _ = layer.free(backend);
        }
        for columns in self.seam_columns.into_iter().flatten() {
            let _ = backend.free_lookup_columns(columns);
        }
        let _ = self.embed.free(backend);
        let _ = self.final_ln.free(backend);
    }
}

fn free_resident_chunk_phase1s(chunks: Vec<ResidentChunkP1>, backend: &mut Backend) {
    for chunk in chunks {
        chunk.free(backend);
    }
}

fn free_resident_model_phase1(
    layers: Vec<ResidentLayerP1>,
    seams: Vec<Option<DeviceLookupColumns>>,
    embed: Option<ResidentEmbedP1>,
    final_ln: Option<ResidentFinalP1>,
    bank: &mut TableBankP,
    backend: &mut Backend,
) {
    for layer in layers {
        let _ = layer.free(backend);
    }
    for columns in seams.into_iter().flatten() {
        let _ = backend.free_lookup_columns(columns);
    }
    if let Some(embed) = embed {
        let _ = embed.free(backend);
    }
    if let Some(final_ln) = final_ln {
        let _ = final_ln.free(backend);
    }
    bank.free_resident_multiplicities(backend);
}

fn free_resident_argmax_prepared(
    prepared: &mut Option<PrivateArgmaxPreparedP>,
    backend: &mut Backend,
) {
    if let Some(prepared) = prepared.take() {
        let _ = free_private_argmax_prepared(prepared, Some(backend));
    }
}

fn build_resident_final_phase1(
    model: &Gpt2Model,
    wit: &ResidentModelWitness,
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
) -> Result<ResidentFinalP1, AccelError> {
    let t = wit.t;
    let mut sources = PendingFinalSources::default();
    sources.out2 = Some(backend.repeat_vector_device(wit.final_out(), 2)?);
    let last = wit.layers[L - 1].i16(LayerI16Field::FfnBlockOut);
    let last_row = match DeviceSlice::new(last.buffer(), last.offset() + (t - 1) * D, D) {
        Ok(value) => value,
        Err(error) => {
            sources.free(backend);
            return Err(error);
        }
    };
    sources.x2 = match backend.repeat_vector_device(last_row, 2) {
        Ok(value) => Some(value),
        Err(error) => {
            sources.free(backend);
            return Err(error);
        }
    };
    macro_rules! repeat_source {
        ($field:ident, $slice:expr) => {
            match backend.repeat_vector_device($slice, 2) {
                Ok(value) => sources.$field = Some(value),
                Err(error) => {
                    sources.free(backend);
                    return Err(error);
                }
            }
        };
    }
    repeat_source!(acc2, wit.final_acc());
    repeat_source!(mean2, wit.final_mean());
    repeat_source!(var2, wit.final_var());
    repeat_source!(rin2, wit.final_rsqrt_in());
    repeat_source!(rout2, wit.final_rsqrt_out());

    let mut lv: Option<ResidentLnVecsP> = None;
    let mut ln_columns: Option<DeviceLookupColumns> = None;
    let mut rsqrt_columns: Option<DeviceLookupColumns> = None;
    let phase = (|| {
        let mut cx = BlockCtxP::with_backend(stream, tx, 221, bank, backend);
        let dom_out = cx.doms.take(2);
        let out_corr = auth_matrix_rows_resident_p(
            cx.stream,
            cx.tx,
            dom_out,
            DeviceSlice::new(sources.out2.as_ref().unwrap(), 0, 2 * D)?,
            2,
            D,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
        let (ln_vectors, ln_vec_corrs) = auth_ln_vecs_resident_p(
            DeviceSlice::new(sources.mean2.as_ref().unwrap(), 0, 2)?,
            DeviceSlice::new(sources.var2.as_ref().unwrap(), 0, 2)?,
            DeviceSlice::new(sources.rin2.as_ref().unwrap(), 0, 2)?,
            DeviceSlice::new(sources.rout2.as_ref().unwrap(), 0, 2)?,
            1,
            rout_pad,
            cx.stream,
            cx.tx,
            &mut cx.doms,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        lv = Some(ln_vectors);
        let dom_row = cx.doms.take(2);
        let row_corr = auth_matrix_rows_resident_p(
            cx.stream,
            cx.tx,
            dom_row,
            DeviceSlice::new(sources.x2.as_ref().unwrap(), 0, 2 * D)?,
            2,
            D,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        ln_columns = Some(bind_range_site_resident(
            cx.bank,
            DeviceSlice::new(sources.acc2.as_ref().unwrap(), 0, 2 * D)?,
            DeviceSlice::new(sources.out2.as_ref().unwrap(), 0, 2 * D)?,
            error,
            2,
            D,
            model.p.lut.shift_ln_norm,
            cx.backend.as_deref_mut().unwrap(),
        )?);
        rsqrt_columns = Some(crate::block_proof::bind_pair_site_resident(
            cx.bank,
            TableKey::LnRsqrt,
            DeviceSlice::new(sources.rin2.as_ref().unwrap(), 0, 2)?,
            DeviceSlice::new(sources.rout2.as_ref().unwrap(), 0, 2)?,
            2,
            1,
            Fp::ZERO,
            rout_pad,
            false,
            cx.backend.as_deref_mut().unwrap(),
        )?);
        Ok((cx.doms, dom_out, out_corr, dom_row, row_corr, ln_vec_corrs))
    })();
    let (doms, dom_out, out_corr, dom_row, row_corr, ln_vec_corrs) = match phase {
        Ok(value) => value,
        Err(error) => {
            if let Some(value) = rsqrt_columns.take() {
                let _ = backend.free_lookup_columns(value);
            }
            if let Some(value) = ln_columns.take() {
                let _ = backend.free_lookup_columns(value);
            }
            if let Some(value) = lv.take() {
                let _ = value.free(backend);
            }
            sources.free(backend);
            return Err(error);
        }
    };
    // Lookup/LN owners have canonical copies; only out2 and x2 survive.
    let cleanup_acc = backend.free_device(sources.acc2.take().unwrap()).err();
    let cleanup_mean = backend.free_device(sources.mean2.take().unwrap()).err();
    let cleanup_var = backend.free_device(sources.var2.take().unwrap()).err();
    let cleanup_rin = backend.free_device(sources.rin2.take().unwrap()).err();
    let cleanup_rout = backend.free_device(sources.rout2.take().unwrap()).err();
    if let Some(error) =
        cleanup_acc.or(cleanup_mean).or(cleanup_var).or(cleanup_rin).or(cleanup_rout)
    {
        let _ = backend.free_lookup_columns(rsqrt_columns.take().unwrap());
        let _ = backend.free_lookup_columns(ln_columns.take().unwrap());
        let _ = lv.take().unwrap().free(backend);
        sources.free(backend);
        return Err(error);
    }
    Ok(ResidentFinalP1 {
        doms,
        dom_out,
        out_corr,
        dom_row,
        row_corr,
        ln_vec_corrs,
        out2: sources.out2.take().unwrap(),
        x2: sources.x2.take().unwrap(),
        lv: lv.take().unwrap(),
        ln_columns: ln_columns.take().unwrap(),
        rsqrt_columns: rsqrt_columns.take().unwrap(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_resident_band_final_phase1(
    model: &Gpt2Model,
    band: &ResidentBandModelWitness<'_>,
    section: u8,
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
) -> Result<ResidentBandFinalP1, AccelError> {
    let q = band.q;
    let mut lv = None;
    let mut ln_columns = None;
    let mut rsqrt_columns = None;
    let phase = (|| {
        let mut cx = BlockCtxP::with_backend(stream, tx, section, bank, backend);
        let dom_out = cx.doms.take(q as u64);
        let out_corr = auth_matrix_rows_resident_p(
            cx.stream,
            cx.tx,
            dom_out,
            band.final_out(),
            q,
            D,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
        let (vectors, corrs) = auth_ln_vecs_resident_p(
            band.final_mean(),
            band.final_var(),
            band.final_rsqrt_in(),
            band.final_rsqrt_out(),
            pad_bits(q),
            rout_pad,
            cx.stream,
            cx.tx,
            &mut cx.doms,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        lv = Some(vectors);
        ln_columns = Some(bind_range_site_resident(
            cx.bank,
            band.final_acc(),
            band.final_out(),
            error,
            q,
            D,
            model.p.lut.shift_ln_norm,
            cx.backend.as_deref_mut().unwrap(),
        )?);
        rsqrt_columns = Some(crate::block_proof::bind_pair_site_resident(
            cx.bank,
            TableKey::LnRsqrt,
            band.final_rsqrt_in(),
            band.final_rsqrt_out(),
            q,
            1,
            Fp::ZERO,
            rout_pad,
            false,
            cx.backend.as_deref_mut().unwrap(),
        )?);
        Ok((cx.doms, dom_out, out_corr, corrs))
    })();
    match phase {
        Ok((doms, dom_out, out_corr, ln_vec_corrs)) => Ok(ResidentBandFinalP1 {
            doms,
            dom_out,
            out_corr,
            ln_vec_corrs,
            lv: lv.take().expect("built resident band LN vectors"),
            ln_columns: ln_columns.take().expect("built resident band LN range columns"),
            rsqrt_columns: rsqrt_columns.take().expect("built resident band rsqrt columns"),
        }),
        Err(error_value) => {
            if let Some(columns) = rsqrt_columns.take() {
                let _ = backend.free_lookup_columns(columns);
            }
            if let Some(columns) = ln_columns.take() {
                let _ = backend.free_lookup_columns(columns);
            }
            if let Some(vectors) = lv.take() {
                let _ = vectors.free(backend);
            }
            Err(error_value)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_resident_chunk_phase1(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    chunk: &ResidentChunkRef<'_, '_>,
    chunk_index: usize,
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
) -> Result<ResidentChunkP1, AccelError> {
    let band = chunk.band;
    let q = band.q;
    let (layer_base, _seam_base, embed_section, final_section, _logits_section, _selection_section) =
        chunk_ids(chunk_index);
    let mut layer_p1s: Vec<ResidentLayerP1> = Vec::with_capacity(L);
    for layer in 0..L {
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[layer];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[layer];
        let result = {
            let mut cx =
                BlockCtxP::with_backend(stream, tx, layer_base + layer as u8, bank, backend);
            let alias = (matches!(layer, 4 | 8)).then(|| layer_p1s[layer - 1].dom_fbo);
            prove_layer_phase1_resident_thinned(
                layer,
                &band.layers[layer],
                resident_model,
                &luts,
                error,
                &mut cx,
                alias,
            )
        };
        match result {
            Ok(value) => layer_p1s.push(value),
            Err(error_value) => {
                for pending in layer_p1s {
                    let _ = pending.free(backend);
                }
                return Err(error_value);
            }
        }
    }

    let mut seam_columns = Vec::with_capacity(L - 1);
    for layer in 0..L - 1 {
        let shift = model.p.seam_shifts[layer];
        if shift > 16 {
            for pending in layer_p1s {
                let _ = pending.free(backend);
            }
            for columns in seam_columns.into_iter().flatten() {
                let _ = backend.free_lookup_columns(columns);
            }
            return Err(AccelError::InvalidInput("resident seam shift exceeds single-stage range"));
        }
        if shift == 0 {
            seam_columns.push(None);
            continue;
        }
        let columns = bind_range_site_resident(
            bank,
            band.layers[layer].i16(LayerI16Field::FfnBlockOut),
            band.layers[layer + 1].i16(LayerI16Field::XIn),
            error,
            q,
            D,
            shift,
            backend,
        );
        match columns {
            Ok(value) => seam_columns.push(Some(value)),
            Err(error_value) => {
                for pending in layer_p1s {
                    let _ = pending.free(backend);
                }
                for columns in seam_columns.into_iter().flatten() {
                    let _ = backend.free_lookup_columns(columns);
                }
                return Err(error_value);
            }
        }
    }

    let shift_embed = model.p.shift_embed;
    if shift_embed <= 0 || shift_embed > 16 {
        for pending in layer_p1s {
            let _ = pending.free(backend);
        }
        for columns in seam_columns.into_iter().flatten() {
            let _ = backend.free_lookup_columns(columns);
        }
        return Err(AccelError::InvalidInput("resident embedding shift must be in 1..=16"));
    }
    let embed_result = (|| {
        let mut cx = BlockCtxP::with_backend(stream, tx, embed_section, bank, backend);
        let dom_out = cx.doms.take(q as u64);
        let out_corr = auth_matrix_rows_resident_p(
            cx.stream,
            cx.tx,
            dom_out,
            band.embed_out(),
            q,
            D,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        let columns = bind_range_site_resident(
            cx.bank,
            band.embed_acc(),
            band.embed_out(),
            error,
            q,
            D,
            shift_embed as u32,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        Ok(ResidentEmbedP1 { doms: cx.doms, dom_out, out_corr, columns })
    })();
    let embed = match embed_result {
        Ok(value) => value,
        Err(error_value) => {
            for pending in layer_p1s {
                let _ = pending.free(backend);
            }
            for columns in seam_columns.into_iter().flatten() {
                let _ = backend.free_lookup_columns(columns);
            }
            return Err(error_value);
        }
    };
    let final_ln = match build_resident_band_final_phase1(
        model,
        band,
        final_section,
        error,
        stream,
        tx,
        bank,
        backend,
    ) {
        Ok(value) => value,
        Err(error_value) => {
            for pending in layer_p1s {
                let _ = pending.free(backend);
            }
            for columns in seam_columns.into_iter().flatten() {
                let _ = backend.free_lookup_columns(columns);
            }
            let _ = embed.free(backend);
            return Err(error_value);
        }
    };
    Ok(ResidentChunkP1 { layer_p1s, seam_columns, embed, final_ln })
}

#[allow(clippy::too_many_arguments)]
fn prove_resident_band_logits(
    resident_model: &ResidentGpt2Model,
    band: &ResidentBandModelWitness<'_>,
    public_logits: &[i64],
    dom_out: u64,
    section: u8,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
    private_phase: Option<&PrivateArgmaxPhaseP>,
) -> Result<
    (LogitsClaimProof, WeightClaimP, ProdTriples, Vec<ProverAuthed>, Counters, Counters),
    AccelError,
> {
    let q = band.q;
    let qb = pad_bits(q);
    let d_cb = pad_bits(D);
    let mut cx = BlockCtxP::with_backend(stream, tx, section, bank, backend);
    let rho_v: Vec<Fp2> = private_phase.map_or_else(
        || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
        |phase| phase.tau[..16].to_vec(),
    );
    let rho_q: Vec<Fp2> = private_phase
        .map_or_else(|| (0..qb).map(|_| cx.tx.challenge_fp2()).collect(), |_| Vec::new());
    let eq_v = eq_vec(&rho_v);
    let row_weights = private_phase
        .map_or_else(|| eq_vec(&rho_q)[..q].to_vec(), |phase| phase.row_weights.clone());
    cx.ctr_other.fp2_mults += (1 << 16) + (1u64 << qb);
    let logits_claim = private_phase.map_or_else(
        || {
            let mut logits_eval = Fp2::ZERO;
            for row in 0..q {
                let mut row_eval = Fp2::ZERO;
                for (vocab, &value) in
                    public_logits[row * VOCAB..(row + 1) * VOCAB].iter().enumerate()
                {
                    row_eval += eq_v[vocab].mul_base(Fp::from_i64(value));
                }
                logits_eval += row_weights[row] * row_eval;
            }
            cx.ctr_other.base_mults += (q * VOCAB) as u64;
            ProverAuthed::from_public(logits_eval)
        },
        |phase| phase.claim,
    );
    let selected_rows = row_weights.len();
    if selected_rows > q {
        return Err(AccelError::InvalidInput("private argmax row count exceeds resident band"));
    }
    let mut padded_row_weights = vec![Fp2::ZERO; q];
    padded_row_weights[..selected_rows].copy_from_slice(&row_weights);
    let weights = public_window_fold_resident(
        resident_model.model_weight(ModelWeightField::TokenEmbedding),
        VOCAB,
        D,
        0,
        D,
        &eq_v,
        MatrixFoldAxis::Rows,
        cx.backend.as_deref_mut().unwrap(),
    )?;
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    let final_rows = match public_window_fold_resident(
        band.final_out(),
        q,
        D,
        0,
        D,
        &padded_row_weights,
        MatrixFoldAxis::Rows,
        cx.backend.as_deref_mut().unwrap(),
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = cx.backend.as_deref_mut().unwrap().free_device(weights);
            return Err(error);
        }
    };
    cx.ctr_other.base_mults += (selected_rows * D) as u64;
    let domain = cx.doms.take(d_cb as u64);
    let (sumcheck, point, claim, wte_value, _) = blind_prove_resident(
        weights,
        final_rows,
        logits_claim,
        cx.stream,
        domain,
        cx.tx,
        cx.backend.as_deref_mut().unwrap(),
    )?;
    let final_open = if private_phase.is_some() {
        open_matrix_weighted_rows_resident_p(
            cx.stream,
            dom_out,
            band.final_out(),
            q,
            D,
            &point,
            &padded_row_weights,
            cx.backend.as_deref_mut().unwrap(),
        )?
    } else {
        let mut final_point = point.clone();
        final_point.extend(rho_q);
        open_matrix_resident_p(
            cx.stream,
            dom_out,
            band.final_out(),
            q,
            D,
            &final_point,
            cx.backend.as_deref_mut().unwrap(),
        )?
    };
    cx.ctr_other.fp2_mults += ((1usize << d_cb) - 1) as u64;
    let claim_domain = cx.doms.take(1);
    let mask = cx.stream.draw_fulls(claim_domain, 1)[0];
    let correction = wte_value - mask.x;
    cx.stream
        .record_c6_fullfield_plaintexts(claim_domain, &[wte_value])
        .expect("C6 logits WTE correction schedule");
    cx.tx.append_fp2s("logits_wte_correction", &[correction]);
    let wte_auth = mask.authenticate(wte_value);
    cx.prod.push((final_open, wte_auth, claim));
    let mut claim_point = point;
    claim_point.extend(rho_v);
    Ok((
        LogitsClaimProof { sc: sumcheck, wte_corr: correction },
        WeightClaimP { point: claim_point, value: wte_auth, auth_domain: claim_domain },
        cx.prod,
        cx.zero,
        cx.ctr_instances,
        cx.ctr_other,
    ))
}

#[allow(clippy::too_many_arguments)]
fn prove_resident_band_selection(
    resident_model: &ResidentGpt2Model,
    band: &ResidentBandModelWitness<'_>,
    sequence: &[u32],
    embed_acc_point: &[Fp2],
    embed_acc_claim: ProverAuthed,
    section: u8,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
    backend: &mut Backend,
) -> Result<
    (
        SelectionProof,
        WeightClaimP,
        WeightClaimP,
        ProdTriples,
        Vec<ProverAuthed>,
        Counters,
        Counters,
    ),
    AccelError,
> {
    let q = band.q;
    let t0 = band.t0;
    let d_cb = pad_bits(D);
    let mut cx = BlockCtxP::with_backend(stream, tx, section, bank, backend);
    let r_d = &embed_acc_point[..d_cb];
    let r_i = &embed_acc_point[d_cb..];
    let eq_i = eq_vec(r_i);
    cx.ctr_other.fp2_mults += 1u64 << r_i.len();
    let band_tokens = &sequence[t0..t0 + q];
    let mut selection_values = vec![Fp2::ZERO; 1 << 16];
    for (row, &token) in band_tokens.iter().enumerate() {
        selection_values[token as usize] += eq_i[row];
    }
    let selection_raw: Vec<Fp2Repr> = selection_values.iter().copied().map(Into::into).collect();
    let selection_device = cx.backend.as_deref_mut().unwrap().upload_new_device(&selection_raw)?;
    let eq_d = eq_vec(r_d);
    let wte_folded = match public_window_fold_resident(
        resident_model.model_weight(ModelWeightField::TokenEmbedding),
        VOCAB,
        D,
        0,
        D,
        &eq_d,
        MatrixFoldAxis::Columns,
        cx.backend.as_deref_mut().unwrap(),
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = cx.backend.as_deref_mut().unwrap().free_device(selection_device);
            return Err(error);
        }
    };
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    let wpe_folded = match public_window_fold_resident(
        resident_model.model_weight(ModelWeightField::PositionEmbedding),
        NPOS,
        D,
        0,
        D,
        &eq_d,
        MatrixFoldAxis::Columns,
        cx.backend.as_deref_mut().unwrap(),
    ) {
        Ok(value) => value,
        Err(error) => {
            let backend = cx.backend.as_deref_mut().unwrap();
            let _ = backend.free_device(wte_folded);
            let _ = backend.free_device(selection_device);
            return Err(error);
        }
    };
    cx.ctr_other.base_mults += (NPOS * D) as u64;
    let mut position_weights = vec![Fp2::ZERO; NPOS];
    position_weights[t0..t0 + q].copy_from_slice(&eq_i[..q]);
    let position_value = match cx.backend.as_deref_mut().unwrap().weighted_sum_device(
        DeviceSlice::new(&wpe_folded, 0, wpe_folded.len()).expect("whole resident position fold"),
        &position_weights,
    ) {
        Ok(value) => value,
        Err(error) => {
            let backend = cx.backend.as_deref_mut().unwrap();
            let _ = backend.free_device(wpe_folded);
            let _ = backend.free_device(wte_folded);
            let _ = backend.free_device(selection_device);
            return Err(error);
        }
    };
    cx.ctr_other.fp2_mults += q as u64;
    let position_domain = cx.doms.take(1);
    let position_mask = cx.stream.draw_fulls(position_domain, 1)[0];
    let position_correction = position_value - position_mask.x;
    cx.stream
        .record_c6_fullfield_plaintexts(position_domain, &[position_value])
        .expect("C6 selection position correction schedule");
    cx.tx.append_fp2s("selection_p_correction", &[position_correction]);
    let position_auth = position_mask.authenticate(position_value);
    let selection_domain = cx.doms.take(16);
    let selection_result = blind_prove_resident(
        selection_device,
        wte_folded,
        embed_acc_claim.sub(position_auth),
        cx.stream,
        selection_domain,
        cx.tx,
        cx.backend.as_deref_mut().unwrap(),
    );
    let (selection_sc, rho_z, selection_claim, _, wte_value) = match selection_result {
        Ok(value) => value,
        Err(error) => {
            let _ = cx.backend.as_deref_mut().unwrap().free_device(wpe_folded);
            return Err(error);
        }
    };
    let selection_eval = sel_s_eval(band_tokens, &eq_i, &rho_z);
    cx.ctr_other.fp2_mults += 16 * q as u64;
    cx.ctr_other.fp2_mults += ((1usize << 16) - 1) as u64;
    let wte_domain = cx.doms.take(1);
    let wte_mask = cx.stream.draw_fulls(wte_domain, 1)[0];
    let wte_correction = wte_value - wte_mask.x;
    cx.stream
        .record_c6_fullfield_plaintexts(wte_domain, &[wte_value])
        .expect("C6 selection WTE correction schedule");
    cx.tx.append_fp2s("selection_wte_correction", &[wte_correction]);
    let wte_auth = wte_mask.authenticate(wte_value);
    cx.zero.push(wte_auth.scale(selection_eval).sub(selection_claim));
    let mut wte_point = r_d.to_vec();
    wte_point.extend(rho_z);

    let mut g_values = vec![Fp2::ZERO; 1 << 10];
    g_values[t0..t0 + q].copy_from_slice(&eq_i[..q]);
    let g_raw: Vec<Fp2Repr> = g_values.iter().copied().map(Into::into).collect();
    let g_device = match cx.backend.as_deref_mut().unwrap().upload_new_device(&g_raw) {
        Ok(value) => value,
        Err(error) => {
            let _ = cx.backend.as_deref_mut().unwrap().free_device(wpe_folded);
            return Err(error);
        }
    };
    let wpe_domain = cx.doms.take(10);
    let (wpe_sc, rho_w, wpe_claim, _, wpe_value) = blind_prove_resident(
        g_device,
        wpe_folded,
        position_auth,
        cx.stream,
        wpe_domain,
        cx.tx,
        cx.backend.as_deref_mut().unwrap(),
    )?;
    let g_eval = masked_eq_eval(&eq_i, t0, q, &rho_w);
    cx.ctr_other.fp2_mults += 10 * q as u64;
    cx.ctr_other.fp2_mults += ((1usize << 10) - 1) as u64;
    let wpe_claim_domain = cx.doms.take(1);
    let wpe_mask = cx.stream.draw_fulls(wpe_claim_domain, 1)[0];
    let wpe_correction = wpe_value - wpe_mask.x;
    cx.stream
        .record_c6_fullfield_plaintexts(wpe_claim_domain, &[wpe_value])
        .expect("C6 selection WPE correction schedule");
    cx.tx.append_fp2s("selection_wpe_correction", &[wpe_correction]);
    let wpe_auth = wpe_mask.authenticate(wpe_value);
    cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim));
    let mut wpe_point = r_d.to_vec();
    wpe_point.extend(rho_w);
    Ok((
        SelectionProof {
            sc: selection_sc,
            wte_corr: wte_correction,
            p_corr: position_correction,
            sc_wpe: wpe_sc,
            wpe_corr: wpe_correction,
        },
        WeightClaimP { point: wte_point, value: wte_auth, auth_domain: wte_domain },
        WeightClaimP { point: wpe_point, value: wpe_auth, auth_domain: wpe_claim_domain },
        cx.prod,
        cx.zero,
        cx.ctr_instances,
        cx.ctr_other,
    ))
}

/// Prove the whole model (P6 two-phase pipeline). Phase 1 binds every
/// boundary / element auth and ONE global multiplicity vector per table
/// content, model-wide; per-content αs are drawn only then; phase 2 runs all
/// chains/instances with the shared αs and closes ONE table side per
/// content. Π_Prod / Π_ZeroBatch rows accumulate into ONE pair of vectors,
/// returned to the caller for a single closure.
pub fn prove_model(
    model: &Gpt2Model,
    wit: &ModelWitness,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    prove_response(model, wit, &[], stream, tx)
}

pub fn prove_model_with_backend(
    model: &Gpt2Model,
    wit: &ModelWitness,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    prove_response_with_backend(model, wit, &[], stream, tx, backend)
}

/// Internal P7 square/prefill resident prover. The verifier and proof format
/// are exactly [`verify_model`] / [`ModelProof`]. `public_logits` is the
/// model output already allowed to leave the device; every other plaintext
/// witness remains in `wit`'s opaque allocations.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn prove_model_resident(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    wit: &ResidentModelWitness,
    public_logits: &[i64],
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>), AccelError> {
    prove_response_resident(
        model,
        resident_model,
        wit,
        public_logits,
        &[],
        error,
        stream,
        tx,
        backend,
    )
}

/// Resident counterpart of [`prove_response`]. Prefill and every decode band
/// contribute to one phase-1 table bank before any shared alpha is drawn,
/// then close one model-wide product/zero batch and one table side per public
/// content. The square-only entry point above remains a compatibility wrapper.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn prove_response_resident<'chunk, 'source>(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    wit: &ResidentModelWitness,
    public_logits: &[i64],
    chunks: &[ResidentChunkRef<'chunk, 'source>],
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>), AccelError> {
    prove_response_resident_impl(
        model,
        resident_model,
        wit,
        public_logits,
        chunks,
        error,
        stream,
        tx,
        backend,
        false,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn prove_response_resident_private_logits<'chunk, 'source>(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    wit: &ResidentModelWitness,
    chunks: &[ResidentChunkRef<'chunk, 'source>],
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>), AccelError> {
    prove_response_resident_impl(
        model,
        resident_model,
        wit,
        &[],
        chunks,
        error,
        stream,
        tx,
        backend,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_response_resident_impl<'chunk, 'source>(
    model: &Gpt2Model,
    resident_model: &ResidentGpt2Model,
    wit: &ResidentModelWitness,
    public_logits: &[i64],
    chunks: &[ResidentChunkRef<'chunk, 'source>],
    error: DeviceSlice<'_, u32>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
    private_logits: bool,
) -> Result<(ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>), AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident model proving requires the cuda-resident backend",
        ));
    }
    let t = wit.t;
    if t < 2
        || t > NPOS
        || wit.layers.len() != L
        || (!private_logits && public_logits.len() != VOCAB)
        || (private_logits && !public_logits.is_empty())
        || chunks.len() > MAX_RESPONSE_CHUNKS
    {
        return Err(AccelError::InvalidInput("resident model witness geometry mismatch"));
    }
    if private_logits && chunks.is_empty() {
        return Err(AccelError::InvalidInput("C3 private logits require a response chunk"));
    }
    let mut expected_t0 = t;
    for chunk in chunks {
        let Some(logits_len) = chunk.band.q.checked_mul(VOCAB) else {
            return Err(AccelError::InvalidInput("resident response chunk geometry mismatch"));
        };
        let Some(end) = expected_t0.checked_add(chunk.band.q) else {
            return Err(AccelError::InvalidInput("resident response chunk geometry mismatch"));
        };
        if chunk.band.t0 != expected_t0
            || chunk.band.q < 2
            || chunk.band.layers.len() != L
            || (!private_logits && chunk.logits.len() != logits_len)
            || (private_logits && !chunk.logits.is_empty())
            || end > NPOS
            || chunk.seq.len() < end
        {
            return Err(AccelError::InvalidInput("resident response chunk geometry mismatch"));
        }
        expected_t0 = end;
    }
    let private_argmax_witness = if private_logits {
        let mut token_groups = Vec::with_capacity(1 + chunks.len());
        token_groups.push(vec![chunks[0].seq[t]]);
        for (index, chunk) in chunks.iter().enumerate() {
            let selected = if index + 1 == chunks.len() { chunk.band.q - 1 } else { chunk.band.q };
            token_groups.push(
                (0..selected).map(|row| chunk.seq[chunk.band.t0 + row + 1]).collect::<Vec<_>>(),
            );
        }
        let mut inputs = Vec::with_capacity(1 + chunks.len());
        inputs.push(ResidentArgmaxPhaseInput { logits: wit.logits(), tokens: &token_groups[0] });
        for (index, chunk) in chunks.iter().enumerate() {
            let rows = token_groups[index + 1].len();
            let logits = chunk.band.logits();
            inputs.push(ResidentArgmaxPhaseInput {
                logits: DeviceSlice::new(logits.buffer(), logits.offset(), rows * VOCAB)
                    .expect("valid resident private-logit phase"),
                tokens: &token_groups[index + 1],
            });
        }
        Some(build_private_argmax_resident_witness(&inputs, error, backend)?)
    } else {
        None
    };
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;
    let luts_for = |layer: usize| {
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[layer];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[layer];
        luts
    };

    let mut bank = TableBankP::new();
    let mut layer_p1s: Vec<ResidentLayerP1> = Vec::with_capacity(L);
    for layer in 0..L {
        let luts = luts_for(layer);
        let result = {
            let mut cx = BlockCtxP::with_backend(stream, tx, layer as u8, &mut bank, backend);
            let alias = (matches!(layer, 4 | 8)).then(|| layer_p1s[layer - 1].dom_fbo);
            prove_layer_phase1_resident_thinned(
                layer,
                &wit.layers[layer],
                resident_model,
                &luts,
                error,
                &mut cx,
                alias,
            )
        };
        match result {
            Ok(p1) => layer_p1s.push(p1),
            Err(error_value) => {
                free_resident_model_phase1(layer_p1s, Vec::new(), None, None, &mut bank, backend);
                return Err(error_value);
            }
        }
    }

    let mut seam_columns: Vec<Option<DeviceLookupColumns>> = Vec::with_capacity(L - 1);
    for layer in 0..L - 1 {
        let shift = model.p.seam_shifts[layer];
        if shift > 16 {
            free_resident_model_phase1(layer_p1s, seam_columns, None, None, &mut bank, backend);
            return Err(AccelError::InvalidInput("resident seam shift exceeds single-stage range"));
        }
        if shift == 0 {
            seam_columns.push(None);
            continue;
        }
        match bind_range_site_resident(
            &mut bank,
            wit.layers[layer].i16(LayerI16Field::FfnBlockOut),
            wit.layers[layer + 1].i16(LayerI16Field::XIn),
            error,
            t,
            D,
            shift,
            backend,
        ) {
            Ok(columns) => seam_columns.push(Some(columns)),
            Err(error_value) => {
                free_resident_model_phase1(layer_p1s, seam_columns, None, None, &mut bank, backend);
                return Err(error_value);
            }
        }
    }

    let shift_embed = model.p.shift_embed;
    if shift_embed <= 0 || shift_embed > 16 {
        free_resident_model_phase1(layer_p1s, seam_columns, None, None, &mut bank, backend);
        return Err(AccelError::InvalidInput("resident embedding shift must be in 1..=16"));
    }
    let shift_embed = shift_embed as u32;
    let embed_p1_result = (|| {
        let mut cx = BlockCtxP::with_backend(stream, tx, 220, &mut bank, backend);
        let dom_out = cx.doms.take(t as u64);
        let out_corr = auth_matrix_rows_resident_p(
            cx.stream,
            cx.tx,
            dom_out,
            wit.embed_out(),
            t,
            D,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        let columns = bind_range_site_resident(
            cx.bank,
            wit.embed_acc(),
            wit.embed_out(),
            error,
            t,
            D,
            shift_embed,
            cx.backend.as_deref_mut().unwrap(),
        )?;
        Ok(ResidentEmbedP1 { doms: cx.doms, dom_out, out_corr, columns })
    })();
    let embed_p1 = match embed_p1_result {
        Ok(value) => value,
        Err(error_value) => {
            free_resident_model_phase1(layer_p1s, seam_columns, None, None, &mut bank, backend);
            return Err(error_value);
        }
    };

    let final_p1 =
        match build_resident_final_phase1(model, wit, error, stream, tx, &mut bank, backend) {
            Ok(value) => value,
            Err(error_value) => {
                free_resident_model_phase1(
                    layer_p1s,
                    seam_columns,
                    Some(embed_p1),
                    None,
                    &mut bank,
                    backend,
                );
                return Err(error_value);
            }
        };

    let mut chunk_p1s = Vec::with_capacity(chunks.len());
    let mut chunk_p1_s = Vec::with_capacity(chunks.len());
    let mut chunk_p2_s = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let started = std::time::Instant::now();
        match build_resident_chunk_phase1(
            model,
            resident_model,
            chunk,
            chunk_index,
            error,
            stream,
            tx,
            &mut bank,
            backend,
        ) {
            Ok(value) => {
                chunk_p1s.push(value);
                chunk_p1_s.push(started.elapsed().as_secs_f64());
            }
            Err(error_value) => {
                free_resident_chunk_phase1s(chunk_p1s, backend);
                free_resident_model_phase1(
                    layer_p1s,
                    seam_columns,
                    Some(embed_p1),
                    Some(final_p1),
                    &mut bank,
                    backend,
                );
                return Err(error_value);
            }
        }
    }

    match backend.download_device(error.buffer(), error.offset(), 1) {
        Ok(value) if value == [0] => {}
        Ok(_) => {
            free_resident_chunk_phase1s(chunk_p1s, backend);
            free_resident_model_phase1(
                layer_p1s,
                seam_columns,
                Some(embed_p1),
                Some(final_p1),
                &mut bank,
                backend,
            );
            return Err(AccelError::InvalidInput(
                "resident proof wire violated a fixed-point/range invariant",
            ));
        }
        Err(error_value) => {
            free_resident_chunk_phase1s(chunk_p1s, backend);
            free_resident_model_phase1(
                layer_p1s,
                seam_columns,
                Some(embed_p1),
                Some(final_p1),
                &mut bank,
                backend,
            );
            return Err(error_value);
        }
    }

    let mut argmax_prepared: Option<PrivateArgmaxPreparedP> =
        if let Some(witness) = private_argmax_witness {
            match prepare_private_argmax_prover(witness, &mut bank, stream, tx, Some(backend)) {
                Ok(prepared) => Some(prepared),
                Err(error_value) => {
                    free_resident_chunk_phase1s(chunk_p1s, backend);
                    free_resident_model_phase1(
                        layer_p1s,
                        seam_columns,
                        Some(embed_p1),
                        Some(final_p1),
                        &mut bank,
                        backend,
                    );
                    return Err(error_value);
                }
            }
        } else {
            None
        };
    let mut expected_content = model_content_keys(model);
    if private_logits {
        expected_content.insert(TableKey::Range(16));
    }
    if bank.content_keys() != expected_content.into_iter().collect::<Vec<_>>() {
        free_resident_argmax_prepared(&mut argmax_prepared, backend);
        free_resident_chunk_phase1s(chunk_p1s, backend);
        free_resident_model_phase1(
            layer_p1s,
            seam_columns,
            Some(embed_p1),
            Some(final_p1),
            &mut bank,
            backend,
        );
        return Err(AccelError::InvalidInput("resident model table content set mismatch"));
    }
    // Build and validate the entire public response schedule while the table
    // bank is still in phase 1.  Finalization authenticates multiplicities and
    // draws shared alphas, so no malformed schedule may be discovered after it.
    let gelu_manifest_result = (|| {
        let prefill = preflight_gelu_plan_thinned(
            t,
            0,
            0,
            layer_p1s
                .iter()
                .enumerate()
                .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
        )?;
        preflight_resident_gelu_sources(&wit.layers, &layer_p1s, &prefill, backend)?;
        let mut plans = Vec::with_capacity(1 + chunks.len());
        plans.push(prefill);
        for (chunk_index, (chunk, p1)) in chunks.iter().zip(&chunk_p1s).enumerate() {
            let (layer_base, ..) = chunk_ids(chunk_index);
            let plan = preflight_gelu_plan_thinned(
                chunk.band.q,
                chunk.band.t0,
                layer_base,
                p1.layer_p1s
                    .iter()
                    .enumerate()
                    .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
            )?;
            preflight_resident_gelu_sources(&chunk.band.layers, &p1.layer_p1s, &plan, backend)?;
            plans.push(plan);
        }
        Ok::<_, crate::ffn_schedule::FfnScheduleError>(plans)
    })();
    let gelu_manifest = match gelu_manifest_result {
        Ok(plans) => plans,
        Err(error_value) => {
            free_resident_argmax_prepared(&mut argmax_prepared, backend);
            free_resident_chunk_phase1s(chunk_p1s, backend);
            free_resident_model_phase1(
                layer_p1s,
                seam_columns,
                Some(embed_p1),
                Some(final_p1),
                &mut bank,
                backend,
            );
            return Err(match error_value {
                crate::ffn_schedule::FfnScheduleError::Accel(error) => error,
                _ => AccelError::InvalidInput("invalid resident GELU response manifest"),
            });
        }
    };

    let mut table_doms = Doms::new(layer_dom_base(240));
    if let Err(error_value) = bank.finalize_resident(stream, tx, &mut table_doms, backend) {
        free_resident_argmax_prepared(&mut argmax_prepared, backend);
        free_resident_chunk_phase1s(chunk_p1s, backend);
        free_resident_model_phase1(
            layer_p1s,
            seam_columns,
            Some(embed_p1),
            Some(final_p1),
            &mut bank,
            backend,
        );
        return Err(error_value);
    }
    if register_gelu_manifest_p(&mut bank, &gelu_manifest).is_err() {
        free_resident_argmax_prepared(&mut argmax_prepared, backend);
        free_resident_chunk_phase1s(chunk_p1s, backend);
        free_resident_model_phase1(
            layer_p1s,
            seam_columns,
            Some(embed_p1),
            Some(final_p1),
            &mut bank,
            backend,
        );
        return Err(AccelError::InvalidInput("invalid resident GELU response manifest"));
    }

    let mut prod = ProdTriples::new();
    let mut zero = Vec::new();
    let mut weight_claims = Vec::with_capacity(4 * L);
    let mut bytes = LayerBytes::default();
    bytes.mult = bank.mult_bytes();
    let mut ctr_instances = Counters::default();
    let mut ctr_other = Counters::default();
    let mut lookups = Vec::new();
    let mut layer_proofs = Vec::with_capacity(L);
    let mut boundary_doms = Vec::with_capacity(L);
    let mut layer_kv_doms = Vec::with_capacity(L);

    let (private_argmax, private_phases) = if let Some(prepared) = argmax_prepared {
        let argmax = match prove_private_argmax(prepared, &mut bank, stream, tx, Some(backend)) {
            Ok(value) => value,
            Err(error_value) => {
                free_resident_chunk_phase1s(chunk_p1s, backend);
                free_resident_model_phase1(
                    layer_p1s,
                    seam_columns,
                    Some(embed_p1),
                    Some(final_p1),
                    &mut bank,
                    backend,
                );
                return Err(error_value);
            }
        };
        prod.extend(argmax.prod);
        zero.extend(argmax.zero);
        add_counters(&mut ctr_instances, &argmax.ctr_instances);
        add_counters(&mut ctr_other, &argmax.ctr_other);
        (Some(argmax.proof), Some(argmax.phases))
    } else {
        (None, None)
    };

    let prefill_prefixes: Vec<Vec<ResidentKvPrefixP>> = (0..L).map(|_| Vec::new()).collect();
    let scheduled = match prove_layers_resident_scheduled(
        model,
        resident_model,
        &wit.layers,
        layer_p1s,
        &prefill_prefixes,
        &gelu_manifest[0],
        seam_columns,
        200,
        stream,
        tx,
        &mut bank,
        backend,
    ) {
        Ok(value) => value,
        Err(error_value) => {
            free_resident_chunk_phase1s(chunk_p1s, backend);
            free_resident_model_phase1(
                Vec::new(),
                Vec::new(),
                Some(embed_p1),
                Some(final_p1),
                &mut bank,
                backend,
            );
            return Err(match error_value {
                crate::ffn_schedule::FfnScheduleError::Accel(error) => error,
                _ => AccelError::InvalidInput("invalid resident prefill FFN schedule"),
            });
        }
    };
    let seams: Vec<Option<SeamProof>> = scheduled
        .seam_instances
        .into_iter()
        .map(|proof| proof.map(|inst| SeamProof { inst }))
        .collect();
    for layer in scheduled.layers {
        let out = layer.out;
        prod.extend(layer.prod);
        zero.extend(layer.zero);
        add_counters(&mut ctr_instances, &out.ctr_instances);
        add_counters(&mut ctr_other, &out.ctr_other);
        add_bytes(&mut bytes, &out.bytes);
        boundary_doms.push((out.dom_xin, out.dom_fbo));
        layer_kv_doms.push((out.dom_k, out.dom_v));
        lookups.extend(out.lookups);
        weight_claims.extend(out.weight_claims);
        layer_proofs.push(layer.proof);
    }

    let ResidentEmbedP1 { doms: embed_doms, dom_out, out_corr, columns: embed_columns } = embed_p1;
    let embed_result = {
        let mut cx = BlockCtxP::with_doms_and_backend(stream, tx, embed_doms, &mut bank, backend);
        let value = (|| {
            let site = prove_range_site_resident(&embed_columns, shift_embed, Vec::new(), &mut cx)?;
            let out_open = open_matrix_resident_p(
                cx.stream,
                dom_out,
                wit.embed_out(),
                t,
                D,
                &site.main.point,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            cx.zero.push(site.main.col_claims[1].value.sub(out_open));
            let acc_point = site.acc_point().to_vec();
            let acc_claim = site.acc_claim;
            let rho: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
            let embed_open = open_matrix_resident_p(
                cx.stream,
                dom_out,
                wit.embed_out(),
                t,
                D,
                &rho,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            let x0_open = open_matrix_resident_p(
                cx.stream,
                boundary_doms[0].0,
                wit.layers[0].i16(LayerI16Field::XIn),
                t,
                D,
                &rho,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            cx.zero.push(embed_open.sub(x0_open));
            Ok((EmbedProof { out_corr, inst: site.main.proof }, acc_point, acc_claim))
        })();
        let free_result = cx.backend.as_deref_mut().unwrap().free_lookup_columns(embed_columns);
        match (value, free_result) {
            (Ok((proof, point, claim)), Ok(())) => {
                Ok((proof, point, claim, cx.prod, cx.zero, cx.ctr_instances, cx.ctr_other))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    };
    let (embed, embed_acc_point, embed_acc_claim, embed_prod, embed_zero, embed_ctr, embed_other) =
        match embed_result {
            Ok(value) => value,
            Err(error_value) => {
                let _ = final_p1.free(backend);
                free_resident_chunk_phase1s(chunk_p1s, backend);
                bank.free_resident_multiplicities(backend);
                return Err(error_value);
            }
        };
    prod.extend(embed_prod);
    zero.extend(embed_zero);
    add_counters(&mut ctr_instances, &embed_ctr);
    add_counters(&mut ctr_other, &embed_other);

    let ResidentFinalP1 {
        doms: final_doms,
        dom_out: dom_out_final,
        out_corr: out_corr_final,
        dom_row,
        row_corr,
        ln_vec_corrs,
        out2,
        x2,
        lv,
        ln_columns,
        rsqrt_columns,
    } = final_p1;
    let final_result = {
        let mut cx = BlockCtxP::with_doms_and_backend(stream, tx, final_doms, &mut bank, backend);
        (|| {
            let rho_row: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
            let mut point_row = rho_row.clone();
            point_row.extend(bit_coords(0, 1));
            let row_open = open_matrix_resident_p(
                cx.stream,
                dom_row,
                DeviceSlice::new(&x2, 0, 2 * D)?,
                2,
                D,
                &point_row,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            let mut point_last = rho_row;
            point_last.extend(bit_coords(t - 1, rb_t));
            let last_open = open_matrix_resident_p(
                cx.stream,
                boundary_doms[L - 1].1,
                wit.layers[L - 1].i16(LayerI16Field::FfnBlockOut),
                t,
                D,
                &point_last,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            cx.zero.push(row_open.sub(last_open));
            let rho_final: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
            let mut wire_point = rho_final;
            wire_point.extend(bit_coords(0, 1));
            let wire_value = open_matrix_resident_p(
                cx.stream,
                dom_out_final,
                DeviceSlice::new(&out2, 0, 2 * D)?,
                2,
                D,
                &wire_point,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            let wire = WireOut { point: wire_point, value: wire_value, corr: Fp2::ZERO };
            let ln = prove_ln_chain_resident(
                2,
                model.p.lut.shift_ln_norm,
                &ln_columns,
                &rsqrt_columns,
                DeviceSlice::new(&x2, 0, 2 * D)?,
                dom_row,
                resident_model.model_weight(ModelWeightField::FinalLnGain),
                &model.lnf_gain,
                &model.lnf_bias,
                &lv,
                &wire,
                &mut cx,
            )?;
            Ok((ln, cx.prod, cx.zero, cx.ctr_instances, cx.ctr_other))
        })()
    };
    let cleanup_rsqrt = backend.free_lookup_columns(rsqrt_columns).err();
    let cleanup_ln = backend.free_lookup_columns(ln_columns).err();
    let cleanup_vectors = lv.free(backend).err();
    let cleanup_x = backend.free_device(x2).err();
    let final_cleanup_error = cleanup_rsqrt.or(cleanup_ln).or(cleanup_vectors).or(cleanup_x);
    let (final_ln_chain, final_prod, final_zero, final_ctr, final_other) =
        match (final_result, final_cleanup_error) {
            (Ok(value), None) => value,
            (Err(error), _) | (_, Some(error)) => {
                let _ = backend.free_device(out2);
                free_resident_chunk_phase1s(chunk_p1s, backend);
                bank.free_resident_multiplicities(backend);
                return Err(error);
            }
        };
    prod.extend(final_prod);
    zero.extend(final_zero);
    add_counters(&mut ctr_instances, &final_ctr);
    add_counters(&mut ctr_other, &final_other);
    let final_ln =
        FinalLnProof { out_corr: out_corr_final, row_corr, ln_vec_corrs, ln: final_ln_chain };

    // Logits claim: the logits themselves are public output; both private
    // factors and every sumcheck fold remain resident.
    let mut embed_claims = Vec::with_capacity(3);
    let logits_result = {
        let mut cx = BlockCtxP::with_backend(stream, tx, 230, &mut bank, backend);
        (|| {
            let private_phase = private_phases.as_ref().map(|phases| &phases[0]);
            let rho_v: Vec<Fp2> = private_phase.map_or_else(
                || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
                |phase| phase.tau[..16].to_vec(),
            );
            let eq_v = eq_vec(&rho_v);
            cx.ctr_other.fp2_mults += 1 << 16;
            let logits_claim = private_phase.map_or_else(
                || {
                    let mut logits_eval = Fp2::ZERO;
                    for (index, &value) in public_logits.iter().enumerate() {
                        logits_eval += eq_v[index].mul_base(Fp::from_i64(value));
                    }
                    cx.ctr_other.base_mults += VOCAB as u64;
                    ProverAuthed::from_public(logits_eval)
                },
                |phase| phase.claim,
            );
            let a_tab = public_window_fold_resident(
                resident_model.model_weight(ModelWeightField::TokenEmbedding),
                VOCAB,
                D,
                0,
                D,
                &eq_v,
                MatrixFoldAxis::Rows,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            cx.ctr_other.base_mults += (VOCAB * D) as u64;
            let prefill_row_weight = private_phase.map_or(Fp2::ONE, |phase| phase.row_weights[0]);
            let fin_tab = match public_window_fold_resident(
                wit.final_out(),
                1,
                D,
                0,
                D,
                &[prefill_row_weight],
                MatrixFoldAxis::Rows,
                cx.backend.as_deref_mut().unwrap(),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx.backend.as_deref_mut().unwrap().free_device(a_tab);
                    return Err(error);
                }
            };
            let dom_logits = cx.doms.take(d_cb as u64);
            let (sumcheck, point, claim, wte_value, _) = blind_prove_resident(
                a_tab,
                fin_tab,
                logits_claim,
                cx.stream,
                dom_logits,
                cx.tx,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            let final_open = if private_phase.is_some() {
                open_matrix_weighted_rows_resident_p(
                    cx.stream,
                    dom_out_final,
                    DeviceSlice::new(&out2, 0, 2 * D)?,
                    2,
                    D,
                    &point,
                    &[prefill_row_weight, Fp2::ZERO],
                    cx.backend.as_deref_mut().unwrap(),
                )?
            } else {
                let mut final_point = point.clone();
                final_point.extend(bit_coords(0, 1));
                open_matrix_resident_p(
                    cx.stream,
                    dom_out_final,
                    DeviceSlice::new(&out2, 0, 2 * D)?,
                    2,
                    D,
                    &final_point,
                    cx.backend.as_deref_mut().unwrap(),
                )?
            };
            cx.ctr_other.fp2_mults += ((1usize << d_cb) - 1) as u64;
            let domain = cx.doms.take(1);
            let mask = cx.stream.draw_fulls(domain, 1)[0];
            let corr = wte_value - mask.x;
            cx.stream
                .record_c6_fullfield_plaintexts(domain, &[wte_value])
                .expect("C6 resident logits WTE correction schedule");
            cx.tx.append_fp2s("logits_wte_correction", &[corr]);
            let wte_auth = mask.authenticate(wte_value);
            cx.prod.push((final_open, wte_auth, claim));
            let mut claim_point = point;
            claim_point.extend(rho_v);
            Ok((
                LogitsClaimProof { sc: sumcheck, wte_corr: corr },
                WeightClaimP { point: claim_point, value: wte_auth, auth_domain: domain },
                cx.prod,
                cx.zero,
                cx.ctr_instances,
                cx.ctr_other,
            ))
        })()
    };
    let (logits, logits_claim, logits_prod, logits_zero, logits_ctr, logits_other) =
        match logits_result {
            Ok(value) => value,
            Err(error_value) => {
                let _ = backend.free_device(out2);
                free_resident_chunk_phase1s(chunk_p1s, backend);
                bank.free_resident_multiplicities(backend);
                return Err(error_value);
            }
        };
    embed_claims.push(logits_claim);
    prod.extend(logits_prod);
    zero.extend(logits_zero);
    add_counters(&mut ctr_instances, &logits_ctr);
    add_counters(&mut ctr_other, &logits_other);
    if let Err(error_value) = backend.free_device(out2) {
        free_resident_chunk_phase1s(chunk_p1s, backend);
        bank.free_resident_multiplicities(backend);
        return Err(error_value);
    }

    let selection_result = {
        let mut cx = BlockCtxP::with_backend(stream, tx, 231, &mut bank, backend);
        (|| {
            let r_d = &embed_acc_point[..d_cb];
            let r_i = &embed_acc_point[d_cb..];
            let eq_i = eq_vec(r_i);
            cx.ctr_other.fp2_mults += 1u64 << r_i.len();
            let mut selection_values = vec![Fp2::ZERO; 1 << 16];
            for (row, &token) in model.p.tokens[..t].iter().enumerate() {
                selection_values[token as usize] += eq_i[row];
            }
            let selection_raw: Vec<Fp2Repr> =
                selection_values.iter().copied().map(Into::into).collect();
            let selection_device =
                cx.backend.as_deref_mut().unwrap().upload_new_device(&selection_raw)?;
            let eq_d = eq_vec(r_d);
            let wte_folded = match public_window_fold_resident(
                resident_model.model_weight(ModelWeightField::TokenEmbedding),
                VOCAB,
                D,
                0,
                D,
                &eq_d,
                MatrixFoldAxis::Columns,
                cx.backend.as_deref_mut().unwrap(),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx.backend.as_deref_mut().unwrap().free_device(selection_device);
                    return Err(error);
                }
            };
            cx.ctr_other.base_mults += (VOCAB * D) as u64;
            let wpe_folded = match public_window_fold_resident(
                resident_model.model_weight(ModelWeightField::PositionEmbedding),
                NPOS,
                D,
                0,
                D,
                &eq_d,
                MatrixFoldAxis::Columns,
                cx.backend.as_deref_mut().unwrap(),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let backend = cx.backend.as_deref_mut().unwrap();
                    let _ = backend.free_device(wte_folded);
                    let _ = backend.free_device(selection_device);
                    return Err(error);
                }
            };
            cx.ctr_other.base_mults += (NPOS * D) as u64;
            let mut position_weights = vec![Fp2::ZERO; NPOS];
            position_weights[..t].copy_from_slice(&eq_i[..t]);
            let p_value = match cx.backend.as_deref_mut().unwrap().weighted_sum_device(
                DeviceSlice::new(&wpe_folded, 0, wpe_folded.len())
                    .expect("whole resident position fold"),
                &position_weights,
            ) {
                Ok(value) => value,
                Err(error) => {
                    let backend = cx.backend.as_deref_mut().unwrap();
                    let _ = backend.free_device(wpe_folded);
                    let _ = backend.free_device(wte_folded);
                    let _ = backend.free_device(selection_device);
                    return Err(error);
                }
            };
            cx.ctr_other.fp2_mults += t as u64;
            let p_domain = cx.doms.take(1);
            let p_mask = cx.stream.draw_fulls(p_domain, 1)[0];
            let p_corr = p_value - p_mask.x;
            cx.stream
                .record_c6_fullfield_plaintexts(p_domain, &[p_value])
                .expect("C6 resident selection position correction schedule");
            cx.tx.append_fp2s("selection_p_correction", &[p_corr]);
            let p_auth = p_mask.authenticate(p_value);
            let selection_domain = cx.doms.take(16);
            let selection_result = blind_prove_resident(
                selection_device,
                wte_folded,
                embed_acc_claim.sub(p_auth),
                cx.stream,
                selection_domain,
                cx.tx,
                cx.backend.as_deref_mut().unwrap(),
            );
            let (selection_sc, rho_z, selection_claim, _, wte_value) = match selection_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx.backend.as_deref_mut().unwrap().free_device(wpe_folded);
                    return Err(error);
                }
            };
            let selection_eval = sel_s_eval(&model.p.tokens[..t], &eq_i, &rho_z);
            cx.ctr_other.fp2_mults += 16 * t as u64;
            cx.ctr_other.fp2_mults += ((1usize << 16) - 1) as u64;
            let wte_domain = cx.doms.take(1);
            let wte_mask = cx.stream.draw_fulls(wte_domain, 1)[0];
            let wte_corr = wte_value - wte_mask.x;
            cx.stream
                .record_c6_fullfield_plaintexts(wte_domain, &[wte_value])
                .expect("C6 resident selection WTE correction schedule");
            cx.tx.append_fp2s("selection_wte_correction", &[wte_corr]);
            let wte_auth = wte_mask.authenticate(wte_value);
            cx.zero.push(wte_auth.scale(selection_eval).sub(selection_claim));
            let mut wte_point = r_d.to_vec();
            wte_point.extend(rho_z);

            let mut g_values = vec![Fp2::ZERO; 1 << 10];
            g_values[..t].copy_from_slice(&eq_i[..t]);
            let g_raw: Vec<Fp2Repr> = g_values.iter().copied().map(Into::into).collect();
            let g_device = match cx.backend.as_deref_mut().unwrap().upload_new_device(&g_raw) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx.backend.as_deref_mut().unwrap().free_device(wpe_folded);
                    return Err(error);
                }
            };
            let wpe_domain = cx.doms.take(10);
            let (wpe_sc, rho_w, wpe_claim, _, wpe_value) = blind_prove_resident(
                g_device,
                wpe_folded,
                p_auth,
                cx.stream,
                wpe_domain,
                cx.tx,
                cx.backend.as_deref_mut().unwrap(),
            )?;
            let g_eval = masked_eq_eval(&eq_i, 0, t, &rho_w);
            cx.ctr_other.fp2_mults += 10 * t as u64;
            cx.ctr_other.fp2_mults += ((1usize << 10) - 1) as u64;
            let wpe_claim_domain = cx.doms.take(1);
            let wpe_mask = cx.stream.draw_fulls(wpe_claim_domain, 1)[0];
            let wpe_corr = wpe_value - wpe_mask.x;
            cx.stream
                .record_c6_fullfield_plaintexts(wpe_claim_domain, &[wpe_value])
                .expect("C6 resident selection WPE correction schedule");
            cx.tx.append_fp2s("selection_wpe_correction", &[wpe_corr]);
            let wpe_auth = wpe_mask.authenticate(wpe_value);
            cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim));
            let mut wpe_point = r_d.to_vec();
            wpe_point.extend(rho_w);
            Ok((
                SelectionProof { sc: selection_sc, wte_corr, p_corr, sc_wpe: wpe_sc, wpe_corr },
                WeightClaimP { point: wte_point, value: wte_auth, auth_domain: wte_domain },
                WeightClaimP { point: wpe_point, value: wpe_auth, auth_domain: wpe_claim_domain },
                cx.prod,
                cx.zero,
                cx.ctr_instances,
                cx.ctr_other,
            ))
        })()
    };
    let (
        selection,
        selection_wte,
        selection_wpe,
        selection_prod,
        selection_zero,
        sel_ctr,
        sel_other,
    ) = match selection_result {
        Ok(value) => value,
        Err(error_value) => {
            free_resident_chunk_phase1s(chunk_p1s, backend);
            bank.free_resident_multiplicities(backend);
            return Err(error_value);
        }
    };
    embed_claims.push(selection_wte);
    embed_claims.push(selection_wpe);
    prod.extend(selection_prod);
    zero.extend(selection_zero);
    add_counters(&mut ctr_instances, &sel_ctr);
    add_counters(&mut ctr_other, &sel_other);

    let mut chunk_proofs = Vec::with_capacity(chunks.len());
    let mut kv_doms: Vec<Vec<(u64, u64)>> =
        layer_kv_doms.iter().map(|&domains| vec![domains]).collect();
    let mut kv_rows = vec![t];
    let mut pending_chunks: std::collections::VecDeque<_> = chunk_p1s.into();
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let started = std::time::Instant::now();
        let ResidentChunkP1 { layer_p1s, seam_columns, embed, final_ln: band_final_p1 } =
            pending_chunks
                .pop_front()
                .ok_or(AccelError::InvalidInput("missing resident chunk phase-1 state"))?;
        let band = chunk.band;
        let q = band.q;
        let qb = pad_bits(q);
        let n_vars_qd = d_cb + qb;
        let (
            layer_base,
            seam_base,
            _embed_section,
            _final_section,
            logits_section,
            selection_section,
        ) = chunk_ids(chunk_index);
        let mut band_boundary_doms = Vec::with_capacity(L);
        let mut band_layer_proofs = Vec::with_capacity(L);

        let prefixes: Vec<Vec<ResidentKvPrefixP>> = (0..L)
            .map(|layer| {
                kv_doms[layer]
                    .iter()
                    .zip(&kv_rows)
                    .map(|(&(dom_k, dom_v), &rows)| ResidentKvPrefixP { rows, dom_k, dom_v })
                    .collect()
            })
            .collect();
        let scheduled = match prove_layers_resident_scheduled(
            model,
            resident_model,
            &band.layers,
            layer_p1s,
            &prefixes,
            &gelu_manifest[chunk_index + 1],
            seam_columns,
            seam_base,
            stream,
            tx,
            &mut bank,
            backend,
        ) {
            Ok(value) => value,
            Err(error_value) => {
                let _ = embed.free(backend);
                let _ = band_final_p1.free(backend);
                free_resident_chunk_phase1s(pending_chunks.into_iter().collect(), backend);
                bank.free_resident_multiplicities(backend);
                return Err(match error_value {
                    crate::ffn_schedule::FfnScheduleError::Accel(error) => error,
                    _ => AccelError::InvalidInput("invalid resident decode FFN schedule"),
                });
            }
        };
        let band_seams: Vec<Option<SeamProof>> = scheduled
            .seam_instances
            .into_iter()
            .map(|proof| proof.map(|inst| SeamProof { inst }))
            .collect();
        for (layer, scheduled_layer) in scheduled.layers.into_iter().enumerate() {
            let out = scheduled_layer.out;
            prod.extend(scheduled_layer.prod);
            zero.extend(scheduled_layer.zero);
            add_counters(&mut ctr_instances, &out.ctr_instances);
            add_counters(&mut ctr_other, &out.ctr_other);
            add_bytes(&mut bytes, &out.bytes);
            band_boundary_doms.push((out.dom_xin, out.dom_fbo));
            kv_doms[layer].push((out.dom_k, out.dom_v));
            lookups.extend(out.lookups);
            weight_claims.extend(out.weight_claims);
            band_layer_proofs.push(scheduled_layer.proof);
        }
        let _ = layer_base;

        let ResidentEmbedP1 {
            doms: embed_doms,
            dom_out: embed_dom_out,
            out_corr: embed_out_corr,
            columns: embed_columns,
        } = embed;
        let embed_result = {
            let mut cx =
                BlockCtxP::with_doms_and_backend(stream, tx, embed_doms, &mut bank, backend);
            let value = (|| {
                let site =
                    prove_range_site_resident(&embed_columns, shift_embed, Vec::new(), &mut cx)?;
                let out_open = open_matrix_resident_p(
                    cx.stream,
                    embed_dom_out,
                    band.embed_out(),
                    q,
                    D,
                    &site.main.point,
                    cx.backend.as_deref_mut().unwrap(),
                )?;
                cx.zero.push(site.main.col_claims[1].value.sub(out_open));
                let acc_point = site.acc_point().to_vec();
                let acc_claim = site.acc_claim;
                let rho: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
                let embed_open = open_matrix_resident_p(
                    cx.stream,
                    embed_dom_out,
                    band.embed_out(),
                    q,
                    D,
                    &rho,
                    cx.backend.as_deref_mut().unwrap(),
                )?;
                let x_open = open_matrix_resident_p(
                    cx.stream,
                    band_boundary_doms[0].0,
                    band.layers[0].i16(LayerI16Field::XIn),
                    q,
                    D,
                    &rho,
                    cx.backend.as_deref_mut().unwrap(),
                )?;
                cx.zero.push(embed_open.sub(x_open));
                Ok((
                    EmbedProof { out_corr: embed_out_corr, inst: site.main.proof },
                    acc_point,
                    acc_claim,
                ))
            })();
            let cleanup = cx.backend.as_deref_mut().unwrap().free_lookup_columns(embed_columns);
            match (value, cleanup) {
                (Ok((proof, point, claim)), Ok(())) => {
                    Ok((proof, point, claim, cx.prod, cx.zero, cx.ctr_instances, cx.ctr_other))
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        let (
            band_embed,
            embed_acc_point,
            embed_acc_claim,
            embed_prod,
            embed_zero,
            embed_ctr,
            embed_other,
        ) = match embed_result {
            Ok(value) => value,
            Err(error_value) => {
                let _ = band_final_p1.free(backend);
                free_resident_chunk_phase1s(pending_chunks.into_iter().collect(), backend);
                bank.free_resident_multiplicities(backend);
                return Err(error_value);
            }
        };
        prod.extend(embed_prod);
        zero.extend(embed_zero);
        add_counters(&mut ctr_instances, &embed_ctr);
        add_counters(&mut ctr_other, &embed_other);

        let ResidentBandFinalP1 {
            doms: final_doms,
            dom_out: final_dom_out,
            out_corr: final_out_corr,
            ln_vec_corrs: final_ln_vec_corrs,
            lv: final_vectors,
            ln_columns: final_ln_columns,
            rsqrt_columns: final_rsqrt_columns,
        } = band_final_p1;
        let final_result = {
            let mut cx =
                BlockCtxP::with_doms_and_backend(stream, tx, final_doms, &mut bank, backend);
            (|| {
                let rho: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
                let wire_value = open_matrix_resident_p(
                    cx.stream,
                    final_dom_out,
                    band.final_out(),
                    q,
                    D,
                    &rho,
                    cx.backend.as_deref_mut().unwrap(),
                )?;
                let wire = WireOut { point: rho, value: wire_value, corr: Fp2::ZERO };
                let proof = prove_ln_chain_resident(
                    q,
                    model.p.lut.shift_ln_norm,
                    &final_ln_columns,
                    &final_rsqrt_columns,
                    band.layers[L - 1].i16(LayerI16Field::FfnBlockOut),
                    band_boundary_doms[L - 1].1,
                    resident_model.model_weight(ModelWeightField::FinalLnGain),
                    &model.lnf_gain,
                    &model.lnf_bias,
                    &final_vectors,
                    &wire,
                    &mut cx,
                )?;
                Ok((proof, cx.prod, cx.zero, cx.ctr_instances, cx.ctr_other))
            })()
        };
        let final_cleanup = backend
            .free_lookup_columns(final_rsqrt_columns)
            .err()
            .or(backend.free_lookup_columns(final_ln_columns).err())
            .or(final_vectors.free(backend).err());
        let (band_final_ln, final_prod, final_zero, final_ctr, final_other) =
            match (final_result, final_cleanup) {
                (Ok(value), None) => value,
                (Err(error), _) | (_, Some(error)) => {
                    free_resident_chunk_phase1s(pending_chunks.into_iter().collect(), backend);
                    bank.free_resident_multiplicities(backend);
                    return Err(error);
                }
            };
        prod.extend(final_prod);
        zero.extend(final_zero);
        add_counters(&mut ctr_instances, &final_ctr);
        add_counters(&mut ctr_other, &final_other);

        let (band_logits, logits_claim, logits_prod, logits_zero, logits_ctr, logits_other) =
            match prove_resident_band_logits(
                resident_model,
                band,
                chunk.logits,
                final_dom_out,
                logits_section,
                stream,
                tx,
                &mut bank,
                backend,
                private_phases.as_ref().map(|phases| &phases[chunk_index + 1]),
            ) {
                Ok(value) => value,
                Err(error_value) => {
                    free_resident_chunk_phase1s(pending_chunks.into_iter().collect(), backend);
                    bank.free_resident_multiplicities(backend);
                    return Err(error_value);
                }
            };
        embed_claims.push(logits_claim);
        prod.extend(logits_prod);
        zero.extend(logits_zero);
        add_counters(&mut ctr_instances, &logits_ctr);
        add_counters(&mut ctr_other, &logits_other);

        let (
            band_selection,
            selection_wte,
            selection_wpe,
            selection_prod,
            selection_zero,
            selection_ctr,
            selection_other,
        ) = match prove_resident_band_selection(
            resident_model,
            band,
            chunk.seq,
            &embed_acc_point,
            embed_acc_claim,
            selection_section,
            stream,
            tx,
            &mut bank,
            backend,
        ) {
            Ok(value) => value,
            Err(error_value) => {
                free_resident_chunk_phase1s(pending_chunks.into_iter().collect(), backend);
                bank.free_resident_multiplicities(backend);
                return Err(error_value);
            }
        };
        embed_claims.push(selection_wte);
        embed_claims.push(selection_wpe);
        prod.extend(selection_prod);
        zero.extend(selection_zero);
        add_counters(&mut ctr_instances, &selection_ctr);
        add_counters(&mut ctr_other, &selection_other);

        chunk_proofs.push(ChunkProof {
            layers: band_layer_proofs,
            seams: band_seams,
            embed: band_embed,
            fin_out_corr: final_out_corr,
            fin_ln_vec_corrs: final_ln_vec_corrs,
            fin_ln: band_final_ln,
            logits: band_logits,
            selection: band_selection,
        });
        kv_rows.push(q);
        chunk_p2_s.push(started.elapsed().as_secs_f64());
    }
    debug_assert!(pending_chunks.is_empty());

    let tables = bank.close_resident(
        &model.luts,
        stream,
        &mut table_doms,
        tx,
        &mut ctr_instances,
        &mut prod,
        &mut zero,
        backend,
    )?;
    Ok((
        ModelProof {
            layers: layer_proofs,
            seams,
            embed,
            final_ln,
            logits,
            selection,
            chunks: chunk_proofs,
            tables,
            private_argmax,
        },
        ModelOut {
            weight_claims,
            chunk_p1_s,
            chunk_p2_s,
            embed_claims,
            bytes,
            ctr_instances,
            ctr_other,
            lookups,
            corr_counters: stream.counters,
        },
        prod,
        zero,
    ))
}

/// Prove a full RESPONSE: the prefill (`wit`, t rows) plus any number of
/// deferred decode chunks (P6) — one two-phase session, one table bank, one
/// Π_Prod/Π_ZeroBatch closure, weight claims stacked for one PCS opening.
pub fn prove_response(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    let mut cache_mode = ResponseProverCacheMode::Legacy(std::marker::PhantomData);
    prove_response_impl(model, wit, chunks, None, stream, tx, None, false, true, &mut cache_mode)
}

/// C3 response prover. Logits remain prover-private and are replaced on the
/// wire by the range/last-tie greedy-argmax argument.
pub fn prove_response_private_logits(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    let mut cache_mode = ResponseProverCacheMode::Legacy(std::marker::PhantomData);
    prove_response_impl(model, wit, chunks, None, stream, tx, None, true, true, &mut cache_mode)
}

/// C6 response-wide CPU entry point.  It leaves the historical proof object
/// intact for the differential gate, but all attention cache folds use the
/// dual-tape inline target stream and the exact primary-schedule follower.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn prove_response_c6_cache_inline(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    secondary: &mut CorrelationStream,
    schedule_follower: &mut C6SourceScheduleProverFollower,
    target_builder: &mut C6CacheFoldTargetInlineProver,
    tx: &mut Transcript,
) -> (
    ModelProof,
    ModelOut,
    ProdTriples,
    C6GrandResidualProverRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
) {
    assert_eq!(chunks.len(), 1, "C6 v1 requires one stacked decode phase");
    let mut cache_mode = ResponseProverCacheMode::C6 {
        secondary,
        schedule_follower,
        target_builder,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
    };
    let (proof, out, prod, zero) = prove_response_impl(
        model,
        wit,
        chunks,
        None,
        stream,
        tx,
        None,
        false,
        true,
        &mut cache_mode,
    );
    let ResponseProverCacheMode::C6 { metrics, append_source_layers, .. } = cache_mode else {
        unreachable!("C6 response provider mode changed during execution")
    };
    (
        proof,
        out,
        prod,
        C6GrandResidualProverRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers)
            .expect("C6 response append source plan must be canonical"),
    )
}

/// Production C6 response entry point. It combines the exact private-logit
/// T1 statement with the dual-tape cache target stream in the original model
/// execution; callers cannot obtain the same owner by replaying either mode
/// after the fact.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_response_private_logits_c6_cache_inline(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    secondary: &mut CorrelationStream,
    schedule_follower: &mut C6SourceScheduleProverFollower,
    target_builder: &mut C6CacheFoldTargetInlineProver,
    tx: &mut Transcript,
) -> (
    ModelProof,
    ModelOut,
    ProdTriples,
    C6GrandResidualProverRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
) {
    assert_eq!(chunks.len(), 1, "C6 v1 requires one stacked decode phase");
    let mut cache_mode = ResponseProverCacheMode::C6 {
        secondary,
        schedule_follower,
        target_builder,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
    };
    let (proof, out, prod, zero) = prove_response_impl(
        model,
        wit,
        chunks,
        None,
        stream,
        tx,
        None,
        true,
        true,
        &mut cache_mode,
    );
    let ResponseProverCacheMode::C6 { metrics, append_source_layers, .. } = cache_mode else {
        unreachable!("C6 private-logit provider mode changed during execution")
    };
    (
        proof,
        out,
        prod,
        C6GrandResidualProverRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers)
            .expect("C6 private-logit append source plan must be canonical"),
    )
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_response_continuation_private_logits_c6_cache_inline(
    model: &Gpt2Model,
    full: &ModelWitness,
    first: &BandModelWitness,
    second: &BandModelWitness,
    sequence: &[u32],
    stream: &mut CorrelationStream,
    secondary: &mut CorrelationStream,
    schedule_follower: &mut C6SourceScheduleProverFollower,
    target_builder: &mut C6CacheFoldTargetInlineProver,
    tx: &mut Transcript,
) -> (
    ModelProof,
    ModelOut,
    ProdTriples,
    C6GrandResidualProverRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
) {
    assert_eq!(first.q, 26, "C6 continuation first band must contain one overlap row");
    assert_eq!(second.q, 25, "C6 continuation second band must contain 25 new rows");
    assert_eq!(second.t0, first.t0 + first.q, "C6 continuation bands must be contiguous");
    let chunks = [ChunkRef { band: second, seq: sequence }];
    let mut cache_mode = ResponseProverCacheMode::C6 {
        secondary,
        schedule_follower,
        target_builder,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
    };
    let (proof, out, prod, zero) = prove_response_impl(
        model,
        full,
        &chunks,
        Some(C6ContinuationBase { band: first, full }),
        stream,
        tx,
        None,
        true,
        true,
        &mut cache_mode,
    );
    let ResponseProverCacheMode::C6 { metrics, append_source_layers, .. } = cache_mode else {
        unreachable!("C6 continuation provider mode changed during execution")
    };
    let append_source_layers = append_source_layers
        .into_iter()
        .map(|layer| layer.suffix_from(first.t0 + 1))
        .collect::<Result<Vec<_>, _>>()
        .expect("C6 continuation append suffix must be canonical");
    (
        proof,
        out,
        prod,
        C6GrandResidualProverRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers)
            .expect("C6 continuation append source plan must be canonical"),
    )
}

/// Historical C3b control arm retained solely for the preregistered T1/C3b
/// same-process CPU ABBA measurement. It is not a selectable production
/// protocol and deliberately has no resident/backend entry point.
#[doc(hidden)]
pub fn prove_response_private_logits_c3b_baseline(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    let mut cache_mode = ResponseProverCacheMode::Legacy(std::marker::PhantomData);
    prove_response_impl(model, wit, chunks, None, stream, tx, None, true, false, &mut cache_mode)
}

pub fn prove_response_with_backend(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    assert_eq!(
        backend.kind(),
        BackendKind::CudaHybrid,
        "host ModelWitness proving is the hybrid gate; resident proving requires a device witness"
    );
    let mut cache_mode = ResponseProverCacheMode::Legacy(std::marker::PhantomData);
    prove_response_impl(
        model,
        wit,
        chunks,
        None,
        stream,
        tx,
        Some(backend),
        false,
        true,
        &mut cache_mode,
    )
}

pub fn prove_response_private_logits_with_backend(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    assert_eq!(backend.kind(), BackendKind::CudaHybrid);
    let mut cache_mode = ResponseProverCacheMode::Legacy(std::marker::PhantomData);
    prove_response_impl(
        model,
        wit,
        chunks,
        None,
        stream,
        tx,
        Some(backend),
        true,
        true,
        &mut cache_mode,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_response_impl(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    continuation: Option<C6ContinuationBase<'_>>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    mut backend: Option<&mut Backend>,
    private_logits: bool,
    boundary_thinning: bool,
    cache_mode: &mut ResponseProverCacheMode<'_, '_>,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    assert!(
        model.config.binding == ConfigBinding::LegacyImplicit
            && model.config.is_legacy_gpt2_geometry()
            && model.validate_layout().is_ok(),
        "the frozen proof schedule accepts only the validated legacy GPT-2 profile"
    );
    let continuation = continuation.as_ref();
    let t = continuation.map_or(wit.t, |base| base.band.q);
    let base_t0 = continuation.map_or(0, |base| base.band.t0);
    let base_layers =
        continuation.map_or(wit.layers.as_slice(), |base| base.band.layers.as_slice());
    let base_embed_acc =
        continuation.map_or(wit.embed.acc.as_slice(), |base| base.band.embed_acc.as_slice());
    let base_embed_out =
        continuation.map_or(wit.embed.out.as_slice(), |base| base.band.embed_out.as_slice());
    if let Some(base) = continuation {
        assert!(
            base.band.t0 > 0
                && base.band.t0 + base.band.q <= base.full.t
                && chunks.len() == 1
                && chunks[0].band.t0 == base.band.t0 + base.band.q,
            "C6 continuation bands are not contiguous",
        );
    }
    assert!(
        chunks.len() <= MAX_RESPONSE_CHUNKS,
        "at most {MAX_RESPONSE_CHUNKS} decode chunks per response (id space)"
    );
    assert!(!private_logits || !chunks.is_empty(), "C3 private logits require a response chunk");
    assert!(continuation.is_none() || boundary_thinning, "C6 continuation requires T1 thinning");
    let private_argmax_witness = private_logits.then(|| {
        let mut token_groups = Vec::with_capacity(1 + chunks.len());
        if let Some(base) = continuation {
            token_groups
                .push((0..t).map(|row| chunks[0].seq[base.band.t0 + row + 1]).collect::<Vec<_>>());
        } else {
            token_groups.push(vec![chunks[0].seq[t]]);
        }
        for (index, chunk) in chunks.iter().enumerate() {
            let selected = if index + 1 == chunks.len() { chunk.band.q - 1 } else { chunk.band.q };
            token_groups.push(
                (0..selected).map(|row| chunk.seq[chunk.band.t0 + row + 1]).collect::<Vec<_>>(),
            );
        }
        let mut inputs = Vec::with_capacity(1 + chunks.len());
        inputs.push(ArgmaxPhaseInput {
            logits: continuation.map_or(wit.logits.as_slice(), |base| base.band.logits.as_slice()),
            tokens: &token_groups[0],
        });
        for (index, chunk) in chunks.iter().enumerate() {
            let rows = token_groups[index + 1].len();
            inputs.push(ArgmaxPhaseInput {
                logits: &chunk.band.logits[..rows * VOCAB],
                tokens: &token_groups[index + 1],
            });
        }
        build_private_argmax_witness(&inputs)
            .expect("C3 private-logit witness violates the 64-row/range contract")
    });
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut bank = TableBankP::new();
    let mut prod: ProdTriples = Vec::new();
    let mut zero: Vec<ProverAuthed> = Vec::new();
    let mut weight_claims: Vec<WeightClaimP> = Vec::with_capacity(4 * L);
    let mut bytes = LayerBytes::default();
    let mut ctr_instances = Counters::default();
    let mut ctr_other = Counters::default();
    let mut lookups: Vec<InstanceLookups> = Vec::new();
    let mut layer_proofs: Vec<LayerProof> = Vec::with_capacity(L);
    let mut boundary_doms: Vec<(u64, u64)> = Vec::with_capacity(L);
    // Prefill (dom_k, dom_v) per layer — the decode chunks' first cache segment.
    let mut layer_kv_doms: Vec<(u64, u64)> = Vec::with_capacity(L);

    let luts_for = |l: usize| {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        luts_l
    };

    macro_rules! new_block_ctx {
        ($layer:expr) => {{
            if let Some(accel) = backend.as_deref_mut() {
                BlockCtxP::with_backend(stream, tx, $layer, &mut bank, accel)
            } else {
                BlockCtxP::new(stream, tx, $layer, &mut bank)
            }
        }};
    }

    // ======================= PHASE 1 (bind everything) =====================
    let mut layer_p1s: Vec<LayerP1> = Vec::with_capacity(L);
    for l in 0..L {
        let luts_l = luts_for(l);
        let mut cx = new_block_ctx!(l as u8);
        let p1 = if let Some(base) = continuation {
            let entry_alias = (matches!(l, 4 | 8)).then(|| layer_p1s[l - 1].dom_fbo);
            let prefix_k = [&base.full.layers[l].k[..base_t0 * D]];
            prove_layer_phase1_band_thinned(
                l,
                &base_layers[l],
                &model.layers[l].0,
                &luts_l,
                &prefix_k,
                entry_alias,
                &mut cx,
            )
        } else if boundary_thinning {
            let entry_alias = (matches!(l, 4 | 8)).then(|| layer_p1s[l - 1].dom_fbo);
            prove_layer_phase1_thinned(
                l,
                &base_layers[l],
                &model.layers[l].0,
                &luts_l,
                entry_alias,
                &mut cx,
            )
        } else if l > 0 && model.p.seam_shifts[l - 1] == 0 {
            prove_layer_phase1_reusing_xin(
                &base_layers[l],
                &model.layers[l].0,
                &luts_l,
                &layer_p1s[l - 1],
                &mut cx,
            )
        } else {
            prove_layer_phase1(&base_layers[l], &model.layers[l].0, &luts_l, &mut cx)
        };
        layer_p1s.push(p1);
    }
    // Seams: multiplicity contributions only (auth-free phase 1).
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        assert!(
            shift <= 16,
            "P5 seam shifts must be ≤16 (no chained seams supported here) — got {shift} at seam {l}"
        );
        if shift > 0 {
            let acc: Vec<i64> = base_layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
            add_range_mult(&mut bank, &acc, &base_layers[l + 1].x_in, t, D, shift);
        }
    }
    // Embedding: out boundary auth + requant multiplicities.
    let s_emb = model.p.shift_embed;
    assert!(
        s_emb > 0 && s_emb <= 16,
        "P5 embed shift must be single-stage positive ≤16 (got {s_emb}) — left-shift/chained embed not implemented here"
    );
    let s_emb = s_emb as u32;
    let (embed_doms, dom_out, out_corr) = {
        let mut cx = new_block_ctx!(220);
        let dom_out = cx.doms.take(t as u64);
        let out_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_out, base_embed_out, t, D);
        add_range_mult(cx.bank, base_embed_acc, base_embed_out, t, D, s_emb);
        (cx.doms, dom_out, out_corr)
    };
    // Final LN (t=2 duplicated-row batch — see the P5-DEVIATION note below).
    let t_ln = if continuation.is_some() { t } else { 2 };
    let rb_ln = pad_bits(t_ln);
    let s_ln = model.p.lut.shift_ln_norm;
    let (out2, acc_ln2, x2, mean2, var2, rin2, rout2) = if let Some(base) = continuation {
        (
            base.band.fin_out.clone(),
            base.band.fin_acc.clone(),
            base_layers[L - 1].ffn_block_out.clone(),
            base.band.fin_mean.clone(),
            base.band.fin_var.clone(),
            base.band.fin_rsqrt_in.clone(),
            base.band.fin_rsqrt_out.clone(),
        )
    } else {
        let last_row = base_layers[L - 1].ffn_block_out[(t - 1) * D..t * D].to_vec();
        (
            wit.final_ln.out.iter().chain(wit.final_ln.out.iter()).copied().collect(),
            wit.final_ln.acc.iter().chain(wit.final_ln.acc.iter()).copied().collect(),
            last_row.iter().chain(last_row.iter()).copied().collect(),
            vec![wit.final_ln.mean, wit.final_ln.mean],
            vec![wit.final_ln.var, wit.final_ln.var],
            vec![wit.final_ln.rsqrt_in, wit.final_ln.rsqrt_in],
            vec![wit.final_ln.rsqrt_out, wit.final_ln.rsqrt_out],
        )
    };
    let (fl_doms, dom_out_f, out_corr_f, lv_f, ln_vec_corrs_f, dom_row, row_corr) = {
        let mut cx = new_block_ctx!(221);
        let dom_out_f = cx.doms.take(t_ln as u64);
        let out_corr_f = auth_matrix_rows_p(cx.stream, cx.tx, dom_out_f, &out2, t_ln, D);
        let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
        let (lv, ln_vec_corrs) =
            auth_ln_vecs_p(&mut cx, rb_ln, &mean2, &var2, &rin2, &rout2, rout_pad);
        let dom_row = cx.doms.take(t_ln as u64);
        let row_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_row, &x2, t_ln, D);
        add_range_mult(cx.bank, &acc_ln2, &out2, t_ln, D, s_ln);
        let mut mult_rsq = vec![0u32; 1 << 16];
        for &r in &rin2 {
            mult_rsq[r as usize] += 1;
        }
        cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);
        (cx.doms, dom_out_f, out_corr_f, lv, ln_vec_corrs, dom_row, row_corr)
    };
    // ---- decode chunks, phase 1 -------------------------------------------
    // Band layer auths + band mults; band embedding/final-LN auths + mults.
    struct ChunkP1 {
        layer_p1s: Vec<LayerP1>,
        embed_doms: Doms,
        dom_out: u64,
        out_corr: Vec<u64>,
        fin_doms: Doms,
        dom_out_f: u64,
        fin_out_corr: Vec<u64>,
        fin_lv: crate::block_proof::LnVecsP,
        fin_ln_vec_corrs: [Vec<u64>; 4],
        acc_fin: Vec<i64>,
    }
    let s_lnf = model.p.lut.shift_ln_norm;
    let mut chunk_p1s: Vec<ChunkP1> = Vec::with_capacity(chunks.len());
    let mut chunk_p1_s: Vec<f64> = Vec::with_capacity(chunks.len());
    let mut chunk_p2_s: Vec<f64> = Vec::with_capacity(chunks.len());
    {
        let mut t0_expect = base_t0 + t;
        for (c, ch) in chunks.iter().enumerate() {
            let c_t0 = std::time::Instant::now();
            let bw = ch.band;
            assert_eq!(bw.t0, t0_expect, "chunk {c} does not extend the cache");
            assert!(bw.q >= 2, "chunk needs at least 2 rows");
            t0_expect += bw.q;
            let (lb, _sb_id, eb, fb, _gb, _zb) = chunk_ids(c);
            let mut layer_p1s: Vec<LayerP1> = Vec::with_capacity(L);
            for l in 0..L {
                let luts_l = luts_for(l);
                // K prefix DATA for the Q·Kᵀ wires recompute: prefill rows +
                // every earlier chunk's band rows.
                let mut prefix_k: Vec<&[i16]> = Vec::with_capacity(2 + c);
                if let Some(base) = continuation {
                    prefix_k.push(&base.full.layers[l].k[..base_t0 * D]);
                }
                prefix_k.push(&base_layers[l].k);
                for cc in chunks[..c].iter() {
                    prefix_k.push(&cc.band.layers[l].k);
                }
                let mut cx = new_block_ctx!(lb + l as u8);
                let p1 = if boundary_thinning {
                    let entry_alias = (matches!(l, 4 | 8)).then(|| layer_p1s[l - 1].dom_fbo);
                    prove_layer_phase1_band_thinned(
                        l,
                        &bw.layers[l],
                        &model.layers[l].0,
                        &luts_l,
                        &prefix_k,
                        entry_alias,
                        &mut cx,
                    )
                } else if l > 0 && model.p.seam_shifts[l - 1] == 0 {
                    prove_layer_phase1_band_reusing_xin(
                        &bw.layers[l],
                        &model.layers[l].0,
                        &luts_l,
                        &prefix_k,
                        &layer_p1s[l - 1],
                        &mut cx,
                    )
                } else {
                    prove_layer_phase1_band(
                        &bw.layers[l],
                        &model.layers[l].0,
                        &luts_l,
                        &prefix_k,
                        &mut cx,
                    )
                };
                layer_p1s.push(p1);
            }
            // Band seams: multiplicity contributions only.
            for l in 0..L - 1 {
                let shift = model.p.seam_shifts[l];
                if shift > 0 {
                    let acc: Vec<i64> =
                        bw.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
                    add_range_mult(&mut bank, &acc, &bw.layers[l + 1].x_in, bw.q, D, shift);
                }
            }
            // Band embedding: out auth + requant mults.
            let (embed_doms, dom_out, out_corr) = {
                let mut cx = new_block_ctx!(eb);
                let dom_out = cx.doms.take(bw.q as u64);
                let out_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_out, &bw.embed_out, bw.q, D);
                add_range_mult(cx.bank, &bw.embed_acc, &bw.embed_out, bw.q, D, s_emb);
                (cx.doms, dom_out, out_corr)
            };
            // Band final LN: out auth + LN vectors + mults (t = q).
            let (fin_doms, dom_out_f, fin_out_corr, fin_lv, fin_ln_vec_corrs, acc_fin) = {
                let mut cx = new_block_ctx!(fb);
                let dom_out_f = cx.doms.take(bw.q as u64);
                let out_corr_f =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_out_f, &bw.fin_out, bw.q, D);
                let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
                let (lv, corrs) = auth_ln_vecs_p(
                    &mut cx,
                    pad_bits(bw.q),
                    &bw.fin_mean,
                    &bw.fin_var,
                    &bw.fin_rsqrt_in,
                    &bw.fin_rsqrt_out,
                    rout_pad,
                );
                let expected_acc_fin = ln_acc_recompute(
                    &bw.layers[L - 1].ffn_block_out,
                    bw.q,
                    &bw.fin_mean,
                    &bw.fin_rsqrt_out,
                    &model.lnf_gain,
                    &model.lnf_bias,
                    s_lnf,
                );
                assert_eq!(bw.fin_acc, expected_acc_fin, "band final-LN accumulator mismatch");
                add_range_mult(cx.bank, &bw.fin_acc, &bw.fin_out, bw.q, D, s_lnf);
                let mut mult_rsq = vec![0u32; 1 << 16];
                for &r in &bw.fin_rsqrt_in {
                    mult_rsq[r as usize] += 1;
                }
                mult_rsq[0] += ((1usize << pad_bits(bw.q)) - bw.q) as u32;
                cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);
                (cx.doms, dom_out_f, out_corr_f, lv, corrs, bw.fin_acc.clone())
            };
            chunk_p1s.push(ChunkP1 {
                layer_p1s,
                embed_doms,
                dom_out,
                out_corr,
                fin_doms,
                dom_out_f,
                fin_out_corr,
                fin_lv,
                fin_ln_vec_corrs,
                acc_fin,
            });
            chunk_p1_s.push(c_t0.elapsed().as_secs_f64());
        }
    }

    // Validate the complete response-wide GELU site set while the table bank
    // is still in phase 1. Finalization authenticates multiplicities and draws
    // shared alphas, so no malformed schedule may be discovered afterwards.
    let prefill_gelu = if continuation.is_some() {
        preflight_gelu_plan_thinned(
            t,
            base_t0,
            0,
            layer_p1s
                .iter()
                .enumerate()
                .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
        )
    } else if boundary_thinning {
        preflight_gelu_plan_thinned(
            t,
            0,
            0,
            layer_p1s
                .iter()
                .enumerate()
                .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
        )
    } else {
        preflight_gelu_plan(
            t,
            0,
            0,
            layer_p1s
                .iter()
                .enumerate()
                .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
        )
    }
    .unwrap_or_else(|error| panic!("invalid public prefill GELU plan: {error}"));
    preflight_cpu_gelu_sources(base_layers, &prefill_gelu)
        .unwrap_or_else(|error| panic!("invalid prefill GELU sources: {error}"));
    let mut chunk_gelu = Vec::with_capacity(chunks.len());
    for (chunk_index, (chunk, p1)) in chunks.iter().zip(&chunk_p1s).enumerate() {
        let (layer_base, ..) = chunk_ids(chunk_index);
        let plan = if boundary_thinning {
            preflight_gelu_plan_thinned(
                chunk.band.q,
                chunk.band.t0,
                layer_base,
                p1.layer_p1s
                    .iter()
                    .enumerate()
                    .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
            )
        } else {
            preflight_gelu_plan(
                chunk.band.q,
                chunk.band.t0,
                layer_base,
                p1.layer_p1s
                    .iter()
                    .enumerate()
                    .map(|(layer, p1)| (layer, p1.doms, model.p.shift_ffn_down[layer])),
            )
        }
        .unwrap_or_else(|error| panic!("invalid public decode GELU plan: {error}"));
        preflight_cpu_gelu_sources(&chunk.band.layers, &plan)
            .unwrap_or_else(|error| panic!("invalid decode GELU sources: {error}"));
        chunk_gelu.push(plan);
    }
    let mut gelu_manifest = Vec::with_capacity(1 + chunk_gelu.len());
    gelu_manifest.push(prefill_gelu);
    gelu_manifest.extend(chunk_gelu);

    let argmax_prepared: Option<PrivateArgmaxPreparedP> = private_argmax_witness.map(|witness| {
        prepare_private_argmax_prover(witness, &mut bank, stream, tx, None)
            .expect("host C3 argmax registration is infallible")
    });

    // End of phase 1: authenticate every content vector, draw the αs, then
    // register the already validated manifest in the finalized bank.
    let mut expected_content = model_content_keys(model);
    if private_logits {
        expected_content.insert(TableKey::Range(16));
    }
    debug_assert_eq!(
        bank.content_keys(),
        expected_content.into_iter().collect::<Vec<_>>(),
        "prover bank contents diverge from the public content set"
    );
    let mut table_doms = Doms::new(layer_dom_base(240));
    bank.finalize(stream, tx, &mut table_doms);
    bytes.mult += bank.mult_bytes();
    register_gelu_manifest_p(&mut bank, &gelu_manifest)
        .unwrap_or_else(|error| panic!("invalid response GELU manifest: {error}"));

    let (private_argmax, private_phases) = if let Some(prepared) = argmax_prepared {
        let argmax = prove_private_argmax(prepared, &mut bank, stream, tx, backend.as_deref_mut())
            .expect("host private-argmax proving is infallible");
        prod.extend(argmax.prod);
        zero.extend(argmax.zero);
        add_counters(&mut ctr_instances, &argmax.ctr_instances);
        add_counters(&mut ctr_other, &argmax.ctr_other);
        (Some(argmax.proof), Some(argmax.phases))
    } else {
        (None, None)
    };

    // ======================= PHASE 2 (chains + instances) ==================
    // ---- (a) 12 layers -----------------------------------------------------
    // The square/prefill-only model path is the first real P7b scheduler
    // All twelve prefill layers stop after FFN-down, run one GELU cohort,
    // then resume in canonical layer order. The response manifest already
    // includes every later decode cohort under the same TableKey::Gelu.
    let prefill_prefixes: Vec<Vec<KvPrefixP<'_>>> = (0..L)
        .map(|layer| {
            continuation.map_or_else(Vec::new, |base| {
                vec![KvPrefixP {
                    rows: base_t0,
                    dom_k: 0,
                    k: &base.full.layers[layer].k[..base_t0 * D],
                    dom_v: 0,
                    v: &base.full.layers[layer].v[..base_t0 * D],
                }]
            })
        })
        .collect();
    let (scheduled_layers, mut seams): (Vec<_>, Vec<Option<SeamProof>>) = if boundary_thinning {
        let scheduled = match cache_mode {
            ResponseProverCacheMode::Legacy(_) => prove_layers_thinned_scheduled(
                model,
                base_layers,
                layer_p1s,
                &prefill_prefixes,
                &gelu_manifest[0],
                200,
                stream,
                tx,
                &mut bank,
                backend.as_deref_mut(),
            )
            .unwrap_or_else(|error| panic!("invalid public prefill FFN schedule: {error}")),
            #[cfg(feature = "c6-trace")]
            ResponseProverCacheMode::C6 {
                secondary,
                schedule_follower,
                target_builder,
                metrics,
                append_source_layers,
            } => {
                let (scheduled, phase_metrics, phase_sources) = prove_layers_thinned_scheduled_c6(
                    model,
                    base_layers,
                    layer_p1s,
                    &prefill_prefixes,
                    &gelu_manifest[0],
                    200,
                    stream,
                    secondary,
                    schedule_follower,
                    target_builder,
                    tx,
                    &mut bank,
                    backend.as_deref_mut(),
                )
                .unwrap_or_else(|error| panic!("invalid C6 prefill FFN schedule: {error}"));
                add_c6_response_metrics(metrics, phase_metrics);
                *append_source_layers = phase_sources;
                scheduled
            }
        };
        let seams = scheduled
            .seam_instances
            .into_iter()
            .map(|proof| proof.map(|inst| SeamProof { inst }))
            .collect();
        (scheduled.layers, seams)
    } else {
        let scheduled = prove_layers_scheduled(
            model,
            base_layers,
            layer_p1s,
            &prefill_prefixes,
            &gelu_manifest[0],
            stream,
            tx,
            &mut bank,
            backend.as_deref_mut(),
        )
        .unwrap_or_else(|error| panic!("invalid public prefill FFN schedule: {error}"));
        (scheduled, Vec::with_capacity(L - 1))
    };
    for layer in scheduled_layers {
        let out = layer.out;
        prod.extend(layer.prod);
        zero.extend(layer.zero);
        add_counters(&mut ctr_instances, &out.ctr_instances);
        add_counters(&mut ctr_other, &out.ctr_other);
        add_bytes(&mut bytes, &out.bytes);
        boundary_doms.push((out.dom_xin, out.dom_fbo));
        layer_kv_doms.push((out.dom_k, out.dom_v));
        lookups.extend(out.lookups);
        weight_claims.extend(out.weight_claims);
        layer_proofs.push(layer.proof);
    }

    // Historical C3b control arm for the preregistered same-process ABBA
    // timing only. Production T1 resolves these claims inside the reverse
    // four-wave chains above and never reaches this branch.
    if !boundary_thinning {
        for l in 0..L - 1 {
            let shift = model.p.seam_shifts[l];
            let mut cx = new_block_ctx!(200 + l as u8);
            let (dom_xin_next, _) = boundary_doms[l + 1];
            let (_, dom_fbo_l) = boundary_doms[l];
            if shift > 0 {
                let acc: Vec<i64> =
                    base_layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
                let out16 = &base_layers[l + 1].x_in;
                let site = prove_range_site(&acc, out16, t, D, shift, Vec::new(), &mut cx);
                let out_open =
                    open_matrix_p(cx.stream, dom_xin_next, out16, t, D, &site.main.point);
                cx.zero.push(site.main.col_claims[1].value.sub(out_open));
                let acc_open = open_matrix_p(
                    cx.stream,
                    dom_fbo_l,
                    &base_layers[l].ffn_block_out,
                    t,
                    D,
                    site.acc_point(),
                );
                cx.zero.push(site.acc_claim.sub(acc_open));
                seams.push(Some(SeamProof { inst: site.main.proof }));
            } else {
                let rho: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
                let a =
                    open_matrix_p(cx.stream, dom_fbo_l, &base_layers[l].ffn_block_out, t, D, &rho);
                let b =
                    open_matrix_p(cx.stream, dom_xin_next, &base_layers[l + 1].x_in, t, D, &rho);
                cx.zero.push(a.sub(b));
                seams.push(None);
            }
            let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
            prod.extend(lp);
            zero.extend(lz);
            add_counters(&mut ctr_instances, &lci);
            add_counters(&mut ctr_other, &lco);
        }
    }

    // ---- (d) embedding ---------------------------------------------------
    let mut cx = BlockCtxP::with_doms(stream, tx, embed_doms, &mut bank);
    let site = prove_range_site(base_embed_acc, base_embed_out, t, D, s_emb, Vec::new(), &mut cx);
    let out_open = open_matrix_p(cx.stream, dom_out, base_embed_out, t, D, &site.main.point);
    cx.zero.push(site.main.col_claims[1].value.sub(out_open));
    let embed_acc_point = site.acc_point().to_vec();
    let embed_acc_claim = site.acc_claim;
    let (dom_xin0, _) = boundary_doms[0];
    let rho_e: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
    let e_open = open_matrix_p(cx.stream, dom_out, base_embed_out, t, D, &rho_e);
    let x0_open = open_matrix_p(cx.stream, dom_xin0, &base_layers[0].x_in, t, D, &rho_e);
    cx.zero.push(e_open.sub(x0_open));
    let embed = EmbedProof { out_corr, inst: site.main.proof };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (e) final LN (last row only) --------------------------------------
    // **P5-DEVIATION(final-ln-t1)**: run on a length-2 batch where row 1 is
    // an HONEST duplicate of row 0 (the machinery needs n ≥ 2; row 1 is
    // bound to nothing downstream — not a soundness relaxation).
    let mut cx = BlockCtxP::with_doms(stream, tx, fl_doms, &mut bank);
    // Bind row 0 of the duplicated x-auth to layer[11].ffn_block_out's real
    // last row (row 1 is an honest duplicate, unbound).
    let rho_r: Vec<Fp2> = (0..d_cb + if continuation.is_some() { rb_ln } else { 0 })
        .map(|_| cx.tx.challenge_fp2())
        .collect();
    let mut pt_row0 = rho_r.clone();
    if continuation.is_none() {
        pt_row0.extend(bit_coords(0, rb_ln));
    }
    let row_open = open_matrix_p(cx.stream, dom_row, &x2, t_ln, D, &pt_row0);
    let (_, dom_fbo_last) = boundary_doms[L - 1];
    let mut pt_fbo = rho_r;
    if continuation.is_none() {
        pt_fbo.extend(bit_coords(t - 1, rb_t));
    }
    let fbo_open =
        open_matrix_p(cx.stream, dom_fbo_last, &base_layers[L - 1].ffn_block_out, t, D, &pt_fbo);
    cx.zero.push(row_open.sub(fbo_open));

    // Manufactured "wire": a fresh opening of row 0 of the SAME final_ln.out
    // auth (see module docs).
    let rho_f: Vec<Fp2> = (0..d_cb + if continuation.is_some() { rb_ln } else { 0 })
        .map(|_| cx.tx.challenge_fp2())
        .collect();
    let mut pt_wire = rho_f.clone();
    if continuation.is_none() {
        pt_wire.extend(bit_coords(0, rb_ln));
    }
    let wire_val = open_matrix_p(cx.stream, dom_out_f, &out2, t_ln, D, &pt_wire);
    let wire = WireOut { point: pt_wire, value: wire_val, corr: Fp2::ZERO };

    let ln = prove_ln_chain(
        t_ln,
        s_ln,
        &acc_ln2,
        &out2,
        &x2,
        dom_row,
        &mean2,
        &model.lnf_gain,
        &model.lnf_bias,
        &lv_f,
        &wire,
        &mut cx,
    );

    let final_ln =
        FinalLnProof { out_corr: out_corr_f, row_corr, ln_vec_corrs: ln_vec_corrs_f, ln };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (f) logits claim ---------------------------------------------------
    // Legacy mode starts from the public L̃(ρ_v). C3 starts from the
    // authenticated phase-masked claim produced by the private argmax proof.
    // blind matvec sumcheck over the d vars; resolution = one wte PCS claim
    // (authenticated) × the MAC opening of the final-LN row (Π_Prod row).
    let mut embed_claims: Vec<WeightClaimP> = Vec::with_capacity(3);
    let mut cx = new_block_ctx!(230);
    let private_phase = private_phases.as_ref().map(|phases| &phases[0]);
    let rho_v: Vec<Fp2> = private_phase.map_or_else(
        || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
        |phase| phase.tau[..16].to_vec(),
    );
    let eq_v = eq_vec(&rho_v);
    cx.ctr_other.fp2_mults += 1 << 16;
    let logits_claim = private_phase.map_or_else(
        || {
            let mut l_eval = Fp2::ZERO;
            for (v, &lv) in wit.logits.iter().enumerate() {
                l_eval += eq_v[v].mul_base(Fp::from_i64(lv));
            }
            cx.ctr_other.base_mults += VOCAB as u64;
            ProverAuthed::from_public(l_eval)
        },
        |phase| phase.claim,
    );
    // A(l) = w̃te(ρ_v, l): row fold of wte by eq_v — the O(V·d) pass.
    let a_tab: Vec<Fp2> = {
        let wte = &model.wte;
        (0..VOCAB)
            .into_par_iter()
            .fold(
                || vec![Fp2::ZERO; 1 << d_cb],
                |mut acc, v| {
                    let e = eq_v[v];
                    let row = &wte[v * D..(v + 1) * D];
                    for (j, &w) in row.iter().enumerate() {
                        if w != 0 {
                            acc[j] += e.mul_base(Fp::from_i64(w as i64));
                        }
                    }
                    acc
                },
            )
            .reduce(
                || vec![Fp2::ZERO; 1 << d_cb],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b) {
                        *x += y;
                    }
                    a
                },
            )
    };
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    let mut fin_lift = vec![Fp2::ZERO; 1 << d_cb];
    let base_row_weights = private_phase.map(|phase| phase.row_weights.as_slice());
    for row in 0..if continuation.is_some() { t } else { 1 } {
        let row_weight = base_row_weights.map_or(Fp2::ONE, |weights| weights[row]);
        let source =
            if continuation.is_some() { &out2[row * D..(row + 1) * D] } else { &wit.final_ln.out };
        for (j, &x) in source.iter().enumerate() {
            fin_lift[j] += row_weight.mul_base(Fp::from_i64(x as i64));
        }
    }
    let dom_lg = cx.doms.take(d_cb as u64);
    let (lg_sc, r_l, lg_claim_n) =
        blind_prove(a_tab.clone(), fin_lift, logits_claim, cx.stream, dom_lg, cx.tx);
    // f̃in(r_l): row-0 opening of the (duplicated) final-LN-out boundary.
    let fin_open = if continuation.is_some() {
        open_matrix_weighted_rows_p(
            cx.stream,
            dom_out_f,
            &out2,
            t_ln,
            D,
            &r_l,
            base_row_weights.expect("continuation private row weights"),
        )
    } else if private_phase.is_some() {
        open_matrix_weighted_rows_p(
            cx.stream,
            dom_out_f,
            &out2,
            t_ln,
            D,
            &r_l,
            &[base_row_weights.expect("private prefill row weight")[0], Fp2::ZERO],
        )
    } else {
        let mut pt_fin = r_l.clone();
        pt_fin.extend(bit_coords(0, rb_ln));
        open_matrix_p(cx.stream, dom_out_f, &out2, t_ln, D, &pt_fin)
    };
    // Authenticated w̃te(ρ_v, r_l) → PCS claim on the embed commitment.
    let wv = eval_mle_counted(&a_tab, &r_l, &mut cx.ctr_other);
    let dom_wv = cx.doms.take(1);
    let mk = cx.stream.draw_fulls(dom_wv, 1)[0];
    let logits_wte_corr = wv - mk.x;
    cx.stream
        .record_c6_fullfield_plaintexts(dom_wv, &[wv])
        .expect("C6 CPU logits WTE correction schedule");
    cx.tx.append_fp2s("logits_wte_correction", &[logits_wte_corr]);
    let wte_auth = mk.authenticate(wv);
    cx.prod.push((fin_open, wte_auth, lg_claim_n));
    let mut pt_wte = r_l.clone();
    pt_wte.extend(rho_v.iter().copied());
    embed_claims.push(WeightClaimP { point: pt_wte, value: wte_auth, auth_domain: dom_wv });
    let logits_proof = LogitsClaimProof { sc: lg_sc, wte_corr: logits_wte_corr };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (g) embedding selection ---------------------------------------------
    // Consumes the pending embed-acc claim: ẽmbed_acc(r_d, r_i) =
    // Σ_z S(z)·w̃te(z, r_d) + w̃pe(r_d ‖ r_i ‖ 0…), S(z) public from the
    // prompt tokens. Blind sumcheck over the 16 vocab-bit vars, closed by a
    // zero row (S̃(ρ_z) public) against one wte claim, plus one wpe claim.
    let mut cx = new_block_ctx!(231);
    let r_d = &embed_acc_point[..d_cb];
    let r_i = &embed_acc_point[d_cb..];
    let eq_i = eq_vec(r_i);
    cx.ctr_other.fp2_mults += 1u64 << r_i.len();
    let mut s_tab = vec![Fp2::ZERO; 1 << 16];
    let base_tokens: &[u32] = if continuation.is_some() {
        &chunks[0].seq[base_t0..base_t0 + t]
    } else {
        &model.p.tokens[..t]
    };
    for (i, &tok) in base_tokens.iter().enumerate() {
        s_tab[tok as usize] += eq_i[i];
    }
    let eq_d = eq_vec(r_d);
    // W(z) = w̃te(z, r_d): column fold of wte by eq_d (the second O(V·d) pass).
    let mut w_tab = vec![Fp2::ZERO; 1 << 16];
    let folded = fold_w(&model.wte, VOCAB, D, &eq_d);
    w_tab[..folded.len()].copy_from_slice(&folded);
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    // Masked-wpe contribution P = Σ_{i<t} eq_i[i]·w̃pe(i, r_d): the embed
    // acc contains wpe rows 0..t only, while the committed block has nonzero
    // rows up to 1023 — a direct w̃pe point claim over-counts at every
    // non-power-of-two t (pad rows). P is claimed authenticated here and
    // proved by a dedicated masked sumcheck below.
    let wpe_folded = fold_w(&model.wpe, NPOS, D, &eq_d); // w̃pe(·, r_d), 2^10
    cx.ctr_other.base_mults += (NPOS * D) as u64;
    let mut p_val = Fp2::ZERO;
    for i in 0..t {
        p_val += eq_i[i] * wpe_folded[base_t0 + i];
    }
    cx.ctr_other.fp2_mults += t as u64;
    let dom_p = cx.doms.take(1);
    let mk_p = cx.stream.draw_fulls(dom_p, 1)[0];
    let sel_p_corr = p_val - mk_p.x;
    cx.stream
        .record_c6_fullfield_plaintexts(dom_p, &[p_val])
        .expect("C6 CPU selection position correction schedule");
    cx.tx.append_fp2s("selection_p_correction", &[sel_p_corr]);
    let p_auth = mk_p.authenticate(p_val);
    let claim0 = embed_acc_claim.sub(p_auth);
    let dom_sel = cx.doms.take(16);
    let (sel_sc, rho_z, sel_claim_n) =
        blind_prove(s_tab, w_tab.clone(), claim0, cx.stream, dom_sel, cx.tx);
    // S̃(ρ_z): public (tokens + eq weights).
    let s_eval = sel_s_eval(base_tokens, &eq_i, &rho_z);
    cx.ctr_other.fp2_mults += 16 * t as u64;
    // Authenticated w̃te(ρ_z, r_d) → second wte claim.
    let wv2 = eval_mle_counted(&w_tab, &rho_z, &mut cx.ctr_other);
    let dom_wv2 = cx.doms.take(1);
    let mk2 = cx.stream.draw_fulls(dom_wv2, 1)[0];
    let sel_wte_corr = wv2 - mk2.x;
    cx.stream
        .record_c6_fullfield_plaintexts(dom_wv2, &[wv2])
        .expect("C6 CPU selection WTE correction schedule");
    cx.tx.append_fp2s("selection_wte_correction", &[sel_wte_corr]);
    let wte2_auth = mk2.authenticate(wv2);
    cx.zero.push(wte2_auth.scale(s_eval).sub(sel_claim_n));
    let mut pt_wte2 = r_d.to_vec();
    pt_wte2.extend(rho_z.iter().copied());
    embed_claims.push(WeightClaimP { point: pt_wte2, value: wte2_auth, auth_domain: dom_wv2 });
    // Masked-wpe sumcheck: P = Σ_w G(w)·w̃pe(w, r_d) over the 10 row vars,
    // G(w) = [w<t]·eq(r_i, w) public. Resolution: G̃(ρ_w) public × one wpe
    // claim at (r_d ‖ ρ_w).
    let mut g_tab = vec![Fp2::ZERO; 1 << 10];
    g_tab[base_t0..base_t0 + t].copy_from_slice(&eq_i[..t]);
    let dom_wpe_sc = cx.doms.take(10);
    let (wpe_sc, rho_w, wpe_claim_n) =
        blind_prove(g_tab, wpe_folded.clone(), p_auth, cx.stream, dom_wpe_sc, cx.tx);
    let g_eval = masked_eq_eval(&eq_i, base_t0, t, &rho_w);
    cx.ctr_other.fp2_mults += 10 * t as u64;
    let wpe_val = eval_mle_counted(&wpe_folded, &rho_w, &mut cx.ctr_other);
    let dom_wpe = cx.doms.take(1);
    let mk_wpe = cx.stream.draw_fulls(dom_wpe, 1)[0];
    let sel_wpe_corr = wpe_val - mk_wpe.x;
    cx.stream
        .record_c6_fullfield_plaintexts(dom_wpe, &[wpe_val])
        .expect("C6 CPU selection WPE correction schedule");
    cx.tx.append_fp2s("selection_wpe_correction", &[sel_wpe_corr]);
    let wpe_auth = mk_wpe.authenticate(wpe_val);
    cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim_n));
    let mut wpe_pt = r_d.to_vec();
    wpe_pt.extend(rho_w.iter().copied());
    embed_claims.push(WeightClaimP { point: wpe_pt, value: wpe_auth, auth_domain: dom_wpe });
    let selection = SelectionProof {
        sc: sel_sc,
        wte_corr: sel_wte_corr,
        p_corr: sel_p_corr,
        sc_wpe: wpe_sc,
        wpe_corr: sel_wpe_corr,
    };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- decode chunks, phase 2 (P6) ----------------------------------------
    let mut chunk_proofs: Vec<ChunkProof> = Vec::with_capacity(chunks.len());
    // (dom_k, dom_v) of every proven segment per layer, prefill first —
    // extended chunk by chunk (the cache prefixes).
    let mut kv_doms: Vec<Vec<(u64, u64)>> = Vec::with_capacity(L);
    for l in 0..L {
        kv_doms.push(vec![(layer_kv_doms[l].0, layer_kv_doms[l].1)]);
    }
    for (c, (ch, p1c)) in chunks.iter().zip(chunk_p1s.into_iter()).enumerate() {
        let c_t0 = std::time::Instant::now();
        let bw = ch.band;
        let q = bw.q;
        let qb = pad_bits(q);
        let n_vars_qd = d_cb + qb;
        let (lb, sb_id, eb, fb, gb, zb) = chunk_ids(c);
        let mut band_boundary_doms: Vec<(u64, u64)> = Vec::with_capacity(L);
        let mut layer_proofs_c: Vec<LayerProof> = Vec::with_capacity(L);
        // ---- 12 band layers -------------------------------------------------
        let prefixes: Vec<Vec<KvPrefixP<'_>>> = (0..L)
            .map(|l| {
                let mut v = Vec::with_capacity(2 + c);
                if let Some(base) = continuation {
                    v.push(KvPrefixP {
                        rows: base_t0,
                        dom_k: 0,
                        k: &base.full.layers[l].k[..base_t0 * D],
                        dom_v: 0,
                        v: &base.full.layers[l].v[..base_t0 * D],
                    });
                }
                v.push(KvPrefixP {
                    rows: t,
                    dom_k: kv_doms[l][0].0,
                    k: &base_layers[l].k,
                    dom_v: kv_doms[l][0].1,
                    v: &base_layers[l].v,
                });
                for (cc, chc) in chunks[..c].iter().enumerate() {
                    v.push(KvPrefixP {
                        rows: chc.band.q,
                        dom_k: kv_doms[l][cc + 1].0,
                        k: &chc.band.layers[l].k,
                        dom_v: kv_doms[l][cc + 1].1,
                        v: &chc.band.layers[l].v,
                    });
                }
                v
            })
            .collect();
        let (scheduled_layers, mut seams_c): (Vec<_>, Vec<Option<SeamProof>>) = if boundary_thinning
        {
            let scheduled = match cache_mode {
                ResponseProverCacheMode::Legacy(_) => prove_layers_thinned_scheduled(
                    model,
                    &bw.layers,
                    p1c.layer_p1s,
                    &prefixes,
                    &gelu_manifest[c + 1],
                    sb_id,
                    stream,
                    tx,
                    &mut bank,
                    backend.as_deref_mut(),
                )
                .unwrap_or_else(|error| panic!("invalid public decode FFN schedule: {error}")),
                #[cfg(feature = "c6-trace")]
                ResponseProverCacheMode::C6 {
                    secondary,
                    schedule_follower,
                    target_builder,
                    metrics,
                    append_source_layers,
                } => {
                    let (scheduled, phase_metrics, phase_sources) =
                        prove_layers_thinned_scheduled_c6(
                            model,
                            &bw.layers,
                            p1c.layer_p1s,
                            &prefixes,
                            &gelu_manifest[c + 1],
                            sb_id,
                            stream,
                            secondary,
                            schedule_follower,
                            target_builder,
                            tx,
                            &mut bank,
                            backend.as_deref_mut(),
                        )
                        .unwrap_or_else(|error| panic!("invalid C6 decode FFN schedule: {error}"));
                    add_c6_response_metrics(metrics, phase_metrics);
                    *append_source_layers = phase_sources;
                    scheduled
                }
            };
            let seams = scheduled
                .seam_instances
                .into_iter()
                .map(|proof| proof.map(|inst| SeamProof { inst }))
                .collect();
            (scheduled.layers, seams)
        } else {
            let scheduled = prove_layers_scheduled(
                model,
                &bw.layers,
                p1c.layer_p1s,
                &prefixes,
                &gelu_manifest[c + 1],
                stream,
                tx,
                &mut bank,
                backend.as_deref_mut(),
            )
            .unwrap_or_else(|error| panic!("invalid public decode FFN schedule: {error}"));
            (scheduled, Vec::with_capacity(L - 1))
        };
        for (l, layer) in scheduled_layers.into_iter().enumerate() {
            let out = layer.out;
            prod.extend(layer.prod);
            zero.extend(layer.zero);
            add_counters(&mut ctr_instances, &out.ctr_instances);
            add_counters(&mut ctr_other, &out.ctr_other);
            add_bytes(&mut bytes, &out.bytes);
            band_boundary_doms.push((out.dom_xin, out.dom_fbo));
            kv_doms[l].push((out.dom_k, out.dom_v));
            lookups.extend(out.lookups);
            weight_claims.extend(out.weight_claims);
            layer_proofs_c.push(layer.proof);
        }
        if !boundary_thinning {
            for l in 0..L - 1 {
                let shift = model.p.seam_shifts[l];
                let mut cx = new_block_ctx!(sb_id + l as u8);
                let (dom_xin_next, _) = band_boundary_doms[l + 1];
                let (_, dom_fbo_l) = band_boundary_doms[l];
                if shift > 0 {
                    let acc: Vec<i64> =
                        bw.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
                    let out16 = &bw.layers[l + 1].x_in;
                    let site = prove_range_site(&acc, out16, q, D, shift, Vec::new(), &mut cx);
                    let out_open =
                        open_matrix_p(cx.stream, dom_xin_next, out16, q, D, &site.main.point);
                    cx.zero.push(site.main.col_claims[1].value.sub(out_open));
                    let acc_open = open_matrix_p(
                        cx.stream,
                        dom_fbo_l,
                        &bw.layers[l].ffn_block_out,
                        q,
                        D,
                        site.acc_point(),
                    );
                    cx.zero.push(site.acc_claim.sub(acc_open));
                    seams_c.push(Some(SeamProof { inst: site.main.proof }));
                } else {
                    let rho: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
                    let a = open_matrix_p(
                        cx.stream,
                        dom_fbo_l,
                        &bw.layers[l].ffn_block_out,
                        q,
                        D,
                        &rho,
                    );
                    let b =
                        open_matrix_p(cx.stream, dom_xin_next, &bw.layers[l + 1].x_in, q, D, &rho);
                    cx.zero.push(a.sub(b));
                    seams_c.push(None);
                }
                let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
                prod.extend(lp);
                zero.extend(lz);
                add_counters(&mut ctr_instances, &lci);
                add_counters(&mut ctr_other, &lco);
            }
        }
        let _ = (lb, sb_id);
        let _ = eb;
        // ---- band embedding ---------------------------------------------------
        let mut cx = BlockCtxP::with_doms(stream, tx, p1c.embed_doms, &mut bank);
        let site = prove_range_site(&bw.embed_acc, &bw.embed_out, q, D, s_emb, Vec::new(), &mut cx);
        let out_open = open_matrix_p(cx.stream, p1c.dom_out, &bw.embed_out, q, D, &site.main.point);
        cx.zero.push(site.main.col_claims[1].value.sub(out_open));
        let embed_acc_point_c = site.acc_point().to_vec();
        let embed_acc_claim_c = site.acc_claim;
        let (dom_xin0, _) = band_boundary_doms[0];
        let rho_e: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
        let e_open = open_matrix_p(cx.stream, p1c.dom_out, &bw.embed_out, q, D, &rho_e);
        let x0_open = open_matrix_p(cx.stream, dom_xin0, &bw.layers[0].x_in, q, D, &rho_e);
        cx.zero.push(e_open.sub(x0_open));
        let embed_c = EmbedProof { out_corr: p1c.out_corr, inst: site.main.proof };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = fb;
        // ---- band final LN (all q rows; x = the band fbo boundary itself) -----
        let mut cx = BlockCtxP::with_doms(stream, tx, p1c.fin_doms, &mut bank);
        let (_, dom_fbo_last) = band_boundary_doms[L - 1];
        let rho_f: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
        let wire_val = open_matrix_p(cx.stream, p1c.dom_out_f, &bw.fin_out, q, D, &rho_f);
        let wire = WireOut { point: rho_f, value: wire_val, corr: Fp2::ZERO };
        let fin_ln = prove_ln_chain(
            q,
            s_lnf,
            &p1c.acc_fin,
            &bw.fin_out,
            &bw.layers[L - 1].ffn_block_out,
            dom_fbo_last,
            &bw.fin_mean,
            &model.lnf_gain,
            &model.lnf_bias,
            &p1c.fin_lv,
            &wire,
            &mut cx,
        );
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = gb;
        // ---- band logits claim --------------------------------------------------
        let mut cx = new_block_ctx!(gb);
        let private_phase = private_phases.as_ref().map(|phases| &phases[c + 1]);
        let rho_v: Vec<Fp2> = private_phase.map_or_else(
            || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
            |phase| phase.tau[..16].to_vec(),
        );
        let rho_q: Vec<Fp2> = private_phase
            .map_or_else(|| (0..qb).map(|_| cx.tx.challenge_fp2()).collect(), |_| Vec::new());
        let eq_v = eq_vec(&rho_v);
        let row_weights = private_phase
            .map_or_else(|| eq_vec(&rho_q)[..q].to_vec(), |phase| phase.row_weights.clone());
        cx.ctr_other.fp2_mults += (1 << 16) + (1u64 << qb);
        let logits_claim = private_phase.map_or_else(
            || {
                let mut l_eval = Fp2::ZERO;
                for r in 0..q {
                    let mut row_e = Fp2::ZERO;
                    for (v, &lv) in bw.logits[r * VOCAB..(r + 1) * VOCAB].iter().enumerate() {
                        row_e += eq_v[v].mul_base(Fp::from_i64(lv));
                    }
                    l_eval += row_weights[r] * row_e;
                }
                cx.ctr_other.base_mults += (q * VOCAB) as u64;
                ProverAuthed::from_public(l_eval)
            },
            |phase| phase.claim,
        );
        let selected_rows = row_weights.len();
        debug_assert!(selected_rows <= q);
        if private_phase.is_some() {
            debug_assert_eq!(selected_rows, if c + 1 == chunks.len() { q - 1 } else { q });
        }
        let a_tab: Vec<Fp2> = {
            let wte = &model.wte;
            (0..VOCAB)
                .into_par_iter()
                .fold(
                    || vec![Fp2::ZERO; 1 << d_cb],
                    |mut acc, v| {
                        let e = eq_v[v];
                        let row = &wte[v * D..(v + 1) * D];
                        for (j, &w) in row.iter().enumerate() {
                            if w != 0 {
                                acc[j] += e.mul_base(Fp::from_i64(w as i64));
                            }
                        }
                        acc
                    },
                )
                .reduce(
                    || vec![Fp2::ZERO; 1 << d_cb],
                    |mut a, b| {
                        for (x, y) in a.iter_mut().zip(b) {
                            *x += y;
                        }
                        a
                    },
                )
        };
        cx.ctr_other.base_mults += (VOCAB * D) as u64;
        // B(j) = Σ_r eq_q[r]·fin[r,j] — the row fold of the band final-LN out.
        let mut b_tab = vec![Fp2::ZERO; 1 << d_cb];
        for r in 0..selected_rows {
            for j in 0..D {
                b_tab[j] += row_weights[r].mul_base(Fp::from_i64(bw.fin_out[r * D + j] as i64));
            }
        }
        cx.ctr_other.base_mults += (selected_rows * D) as u64;
        let dom_lg = cx.doms.take(d_cb as u64);
        let (lg_sc, r_l, lg_claim_n) =
            blind_prove(a_tab.clone(), b_tab, logits_claim, cx.stream, dom_lg, cx.tx);
        let fin_open = if private_phase.is_some() {
            let mut padded_weights = vec![Fp2::ZERO; q];
            padded_weights[..selected_rows].copy_from_slice(&row_weights);
            open_matrix_weighted_rows_p(
                cx.stream,
                p1c.dom_out_f,
                &bw.fin_out,
                q,
                D,
                &r_l,
                &padded_weights,
            )
        } else {
            let mut pt_fin = r_l.clone();
            pt_fin.extend(rho_q.iter().copied());
            open_matrix_p(cx.stream, p1c.dom_out_f, &bw.fin_out, q, D, &pt_fin)
        };
        let wv = eval_mle_counted(&a_tab, &r_l, &mut cx.ctr_other);
        let dom_wv = cx.doms.take(1);
        let mk = cx.stream.draw_fulls(dom_wv, 1)[0];
        let logits_wte_corr = wv - mk.x;
        cx.stream
            .record_c6_fullfield_plaintexts(dom_wv, &[wv])
            .expect("C6 band logits WTE correction schedule");
        cx.tx.append_fp2s("logits_wte_correction", &[logits_wte_corr]);
        let wte_auth = mk.authenticate(wv);
        cx.prod.push((fin_open, wte_auth, lg_claim_n));
        let mut pt_wte = r_l.clone();
        pt_wte.extend(rho_v.iter().copied());
        embed_claims.push(WeightClaimP { point: pt_wte, value: wte_auth, auth_domain: dom_wv });
        let logits_c = LogitsClaimProof { sc: lg_sc, wte_corr: logits_wte_corr };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = zb;
        // ---- band embedding selection (window at t0) ---------------------------
        let mut cx = new_block_ctx!(zb);
        let r_d = &embed_acc_point_c[..d_cb];
        let r_i = &embed_acc_point_c[d_cb..];
        let eq_i = eq_vec(r_i);
        cx.ctr_other.fp2_mults += 1u64 << r_i.len();
        let band_tokens = &ch.seq[bw.t0..bw.t0 + q];
        let mut s_tab = vec![Fp2::ZERO; 1 << 16];
        for (r, &tok) in band_tokens.iter().enumerate() {
            s_tab[tok as usize] += eq_i[r];
        }
        let eq_d = eq_vec(r_d);
        let mut w_tab = vec![Fp2::ZERO; 1 << 16];
        let folded = fold_w(&model.wte, VOCAB, D, &eq_d);
        w_tab[..folded.len()].copy_from_slice(&folded);
        cx.ctr_other.base_mults += (VOCAB * D) as u64;
        let wpe_folded = fold_w(&model.wpe, NPOS, D, &eq_d);
        cx.ctr_other.base_mults += (NPOS * D) as u64;
        let mut p_val = Fp2::ZERO;
        for r in 0..q {
            p_val += eq_i[r] * wpe_folded[bw.t0 + r];
        }
        cx.ctr_other.fp2_mults += q as u64;
        let dom_p = cx.doms.take(1);
        let mk_p = cx.stream.draw_fulls(dom_p, 1)[0];
        let sel_p_corr = p_val - mk_p.x;
        cx.stream
            .record_c6_fullfield_plaintexts(dom_p, &[p_val])
            .expect("C6 band selection position correction schedule");
        cx.tx.append_fp2s("selection_p_correction", &[sel_p_corr]);
        let p_auth = mk_p.authenticate(p_val);
        let claim0 = embed_acc_claim_c.sub(p_auth);
        let dom_sel = cx.doms.take(16);
        let (sel_sc, rho_z, sel_claim_n) =
            blind_prove(s_tab, w_tab.clone(), claim0, cx.stream, dom_sel, cx.tx);
        let s_eval = sel_s_eval(band_tokens, &eq_i, &rho_z);
        cx.ctr_other.fp2_mults += 16 * q as u64;
        let wv2 = eval_mle_counted(&w_tab, &rho_z, &mut cx.ctr_other);
        let dom_wv2 = cx.doms.take(1);
        let mk2 = cx.stream.draw_fulls(dom_wv2, 1)[0];
        let sel_wte_corr = wv2 - mk2.x;
        cx.stream
            .record_c6_fullfield_plaintexts(dom_wv2, &[wv2])
            .expect("C6 band selection WTE correction schedule");
        cx.tx.append_fp2s("selection_wte_correction", &[sel_wte_corr]);
        let wte2_auth = mk2.authenticate(wv2);
        cx.zero.push(wte2_auth.scale(s_eval).sub(sel_claim_n));
        let mut pt_wte2 = r_d.to_vec();
        pt_wte2.extend(rho_z.iter().copied());
        embed_claims.push(WeightClaimP { point: pt_wte2, value: wte2_auth, auth_domain: dom_wv2 });
        let mut g_tab = vec![Fp2::ZERO; 1 << 10];
        for r in 0..q {
            g_tab[bw.t0 + r] = eq_i[r];
        }
        let dom_wpe_sc = cx.doms.take(10);
        let (wpe_sc, rho_w, wpe_claim_n) =
            blind_prove(g_tab, wpe_folded.clone(), p_auth, cx.stream, dom_wpe_sc, cx.tx);
        let g_eval = masked_eq_eval(&eq_i, bw.t0, q, &rho_w);
        cx.ctr_other.fp2_mults += 10 * q as u64;
        let wpe_val = eval_mle_counted(&wpe_folded, &rho_w, &mut cx.ctr_other);
        let dom_wpe = cx.doms.take(1);
        let mk_wpe = cx.stream.draw_fulls(dom_wpe, 1)[0];
        let sel_wpe_corr = wpe_val - mk_wpe.x;
        cx.stream
            .record_c6_fullfield_plaintexts(dom_wpe, &[wpe_val])
            .expect("C6 band selection WPE correction schedule");
        cx.tx.append_fp2s("selection_wpe_correction", &[sel_wpe_corr]);
        let wpe_auth = mk_wpe.authenticate(wpe_val);
        cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim_n));
        let mut wpe_pt = r_d.to_vec();
        wpe_pt.extend(rho_w.iter().copied());
        embed_claims.push(WeightClaimP { point: wpe_pt, value: wpe_auth, auth_domain: dom_wpe });
        let selection_c = SelectionProof {
            sc: sel_sc,
            wte_corr: sel_wte_corr,
            p_corr: sel_p_corr,
            sc_wpe: wpe_sc,
            wpe_corr: sel_wpe_corr,
        };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);

        chunk_proofs.push(ChunkProof {
            layers: layer_proofs_c,
            seams: seams_c,
            embed: embed_c,
            fin_out_corr: p1c.fin_out_corr,
            fin_ln_vec_corrs: p1c.fin_ln_vec_corrs,
            fin_ln,
            logits: logits_c,
            selection: selection_c,
        });
        chunk_p2_s.push(c_t0.elapsed().as_secs_f64());
    }

    // ---- (h) per-content table sides (ONE multiset argument per content) ----
    let tables = if let Some(accel) = backend.as_deref_mut() {
        bank.close_with_backend(
            &model.luts,
            stream,
            &mut table_doms,
            tx,
            &mut ctr_instances,
            &mut prod,
            &mut zero,
            accel,
        )
    } else {
        bank.close(
            &model.luts,
            stream,
            &mut table_doms,
            tx,
            &mut ctr_instances,
            &mut prod,
            &mut zero,
        )
    };

    let proof = ModelProof {
        layers: layer_proofs,
        seams,
        embed,
        final_ln,
        logits: logits_proof,
        selection,
        chunks: chunk_proofs,
        tables,
        private_argmax,
    };
    let out = ModelOut {
        weight_claims,
        chunk_p1_s,
        chunk_p2_s,
        embed_claims,
        bytes,
        ctr_instances,
        ctr_other,
        lookups,
        corr_counters: stream.counters,
    };
    (proof, out, prod, zero)
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify the whole model (mirror of [`prove_model`], same order throughout).
pub fn verify_model(
    model: &Gpt2Model,
    t: usize,
    logits: &[i64],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    verify_response(model, t, logits, &[], proof, vc, tx)
}

/// Validate every public response dimension and every proof collection that
/// the verifier later indexes.  This runs before the first transcript append,
/// challenge or correlation-key expansion so malformed public input cannot
/// panic after partially consuming a reusable verifier session.
fn preflight_layer_proof_shape(
    shape: BandShape,
    proof: &LayerProof,
    softmax_row_shift: bool,
    layer: usize,
) -> Option<()> {
    if layer >= L {
        return None;
    }
    let rows = shape.q;
    let boundary_len = rows.checked_mul(D)?;
    let row_pad = rows.checked_next_power_of_two()?;
    let group_pos = layer % 4;
    let n_vars = pad_bits(rows) + pad_bits(D);
    let reducer_shape = |proof: &crate::boundary_thinning::EqReductionProof| {
        proof.sumcheck.round_corrs.len() == n_vars
    };
    if (layer == 0) != (proof.xin_corr.len() == boundary_len)
        || (layer != 0 && !proof.xin_corr.is_empty())
        || proof.k_corr.len() != boundary_len
        || proof.v_corr.len() != boundary_len
        || !proof.abo_corr.is_empty()
        || (group_pos == 3) != (proof.fbo_corr.len() == boundary_len)
        || (group_pos != 3 && !proof.fbo_corr.is_empty())
        || (group_pos != 3) != proof.ffn.t1_q_corr.is_some()
        || !proof.ffn.t1_abo_reduce.as_ref().is_some_and(reducer_shape)
        || proof.attn.t1_q_corr.is_none()
        || (group_pos != 0) != proof.attn.t1_x_reduce.is_some()
        || proof.attn.t1_x_reduce.as_ref().is_some_and(|reducer| !reducer_shape(reducer))
        || proof.ffn.ln_vec_corrs.iter().any(|corrections| corrections.len() != row_pad)
        || proof.attn.ln_vec_corrs.iter().any(|corrections| corrections.len() != row_pad)
    {
        return None;
    }

    // Attention row tables use the protocol's fixed 16-head padding, while
    // the sparse above-diagonal stream contains only the twelve real heads.
    let attention_rows = 16usize.checked_mul(row_pad)?;
    let above_len = H.checked_mul(shape.n_above_head())?;
    if [&proof.attn.denoms_corr, &proof.attn.recip_in_corr, &proof.attn.recips_corr]
        .into_iter()
        .any(|corrections| corrections.len() != attention_rows)
        || proof.attn.above_corr.len() != above_len
        || proof.attn.gemm_wv.len() != H
        || proof.attn.gemm_qk.len() != H
        || proof.attn.row_shift_corr.is_some() != softmax_row_shift
        || proof.attn.hadamard2.is_some() != softmax_row_shift
        || proof.attn.ismax_rowsum_corr.is_some() != softmax_row_shift
        || proof
            .attn
            .row_shift_corr
            .as_ref()
            .is_some_and(|corrections| corrections.len() != attention_rows)
    {
        return None;
    }
    Some(())
}

#[cfg(test)]
fn preflight_xin_correction_len(
    boundary_len: usize,
    correction_len: usize,
    reuse_xin: bool,
) -> bool {
    match reuse_xin {
        true => correction_len == 0,
        false => correction_len == boundary_len,
    }
}

/// Public greedy-decoding relation across chunk boundaries.  Row `r` of a
/// chunk samples the token at the next position, so the final row of chunk
/// `c-1` must select the first token carried by chunk `c`.
fn preflight_greedy_tokens(
    t: usize,
    prefill_logits: &[i64],
    chunks: &[ChunkPub<'_>],
) -> Option<()> {
    let mut t0 = t;
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        if chunk.q < 2 || chunk.logits.len() != chunk.q.checked_mul(VOCAB)? {
            return None;
        }

        let predecessor_logits = if chunk_index == 0 {
            prefill_logits
        } else {
            let previous = chunks.get(chunk_index - 1)?;
            if chunk.seq.get(..t0)? != previous.seq.get(..t0)? {
                return None;
            }
            let row_start = previous.q.checked_sub(1)?.checked_mul(VOCAB)?;
            previous.logits.get(row_start..row_start.checked_add(VOCAB)?)?
        };
        let predecessor_argmax = (0..VOCAB).max_by_key(|&v| predecessor_logits[v])?;
        if *chunk.seq.get(t0)? != predecessor_argmax as u32 {
            return None;
        }

        // The last row is deliberately excluded: it is checked as the
        // predecessor of the next chunk, or has no sampled token in the
        // response when this is the final chunk.
        for row_index in 0..chunk.q - 1 {
            let row_start = row_index.checked_mul(VOCAB)?;
            let row = chunk.logits.get(row_start..row_start.checked_add(VOCAB)?)?;
            let argmax = (0..VOCAB).max_by_key(|&v| row[v])?;
            let next = t0.checked_add(row_index)?.checked_add(1)?;
            if *chunk.seq.get(next)? != argmax as u32 {
                return None;
            }
        }
        t0 = t0.checked_add(chunk.q)?;
    }
    Some(())
}

fn private_argmax_public_layout(
    t: usize,
    chunks: &[ChunkPub<'_>],
) -> Option<(Vec<Vec<usize>>, Vec<(usize, usize)>)> {
    let first = chunks.first()?;
    let mut lengths = Vec::with_capacity(1 + chunks.len());
    lengths.push(1usize);
    for (index, chunk) in chunks.iter().enumerate() {
        lengths.push(if index + 1 == chunks.len() { chunk.q.checked_sub(1)? } else { chunk.q });
    }
    let (phases, _) = phase_layout_from_lengths(&lengths)?;
    let mut public_tokens = Vec::with_capacity(lengths.iter().sum());
    public_tokens.push((phases[0][0], *first.seq.get(t)? as usize));
    let mut t0 = t;
    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 && chunk.seq.get(..t0)? != chunks[index - 1].seq.get(..t0)? {
            return None;
        }
        for row in 0..lengths[index + 1] {
            public_tokens.push((phases[index + 1][row], *chunk.seq.get(t0 + row + 1)? as usize));
        }
        t0 = t0.checked_add(chunk.q)?;
    }
    if public_tokens.iter().any(|&(_, token)| token >= VOCAB) {
        return None;
    }
    Some((phases, public_tokens))
}

fn private_argmax_continuation_layout(
    base_t0: usize,
    base_rows: usize,
    chunks: &[ChunkPub<'_>],
) -> Option<(Vec<Vec<usize>>, Vec<(usize, usize)>)> {
    let chunk = chunks.first()?;
    if chunks.len() != 1 || chunk.q != 25 || base_rows != 26 {
        return None;
    }
    let lengths = [base_rows, chunk.q.checked_sub(1)?];
    let (phases, _) = phase_layout_from_lengths(&lengths)?;
    let mut public_tokens = Vec::with_capacity(50);
    for row in 0..base_rows {
        public_tokens.push((phases[0][row], *chunk.seq.get(base_t0 + row + 1)? as usize));
    }
    let chunk_t0 = base_t0.checked_add(base_rows)?;
    for row in 0..lengths[1] {
        public_tokens.push((phases[1][row], *chunk.seq.get(chunk_t0 + row + 1)? as usize));
    }
    if public_tokens.iter().any(|&(_, token)| token >= VOCAB) {
        return None;
    }
    Some((phases, public_tokens))
}

#[derive(Clone, Copy)]
struct Gpt2VerifierView<'a> {
    schedule_model: &'a Gpt2Model,
    config: &'a ModelConfig,
    p: &'a P5Params,
    luts: &'a Luts,
    lnf_gain: &'a [i16],
    lnf_bias: &'a [i16],
    layout_valid: bool,
}

impl<'a> Gpt2VerifierView<'a> {
    fn full(model: &'a Gpt2Model) -> Self {
        Self {
            schedule_model: model,
            config: &model.config,
            p: &model.p,
            luts: &model.luts,
            lnf_gain: &model.lnf_gain,
            lnf_bias: &model.lnf_bias,
            layout_valid: model.validate_layout().is_ok(),
        }
    }

    fn slim(model: &'a Gpt2VerifierModel) -> Self {
        let schedule_model = model.schedule_model();
        Self {
            schedule_model,
            config: &schedule_model.config,
            p: &schedule_model.p,
            luts: &schedule_model.luts,
            lnf_gain: &schedule_model.lnf_gain,
            lnf_bias: &schedule_model.lnf_bias,
            layout_valid: model.validate_layout().is_ok(),
        }
    }
}

fn preflight_verify_response_public(
    model: &Gpt2VerifierView<'_>,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub<'_>],
    continuation: Option<C6ContinuationPublic>,
    proof: &ModelProof,
    private_logits: bool,
) -> Option<()> {
    let global_shifts = [
        model.p.lut.shift_ffn_up,
        model.p.lut.shift_ln_norm,
        model.p.lut.shift_av,
        model.p.lut.shift_softmax_norm,
        model.p.lut.shift_scores,
        model.p.lut.shift_qkv,
    ];
    let base_t0 = continuation.map_or(0, |profile| profile.base_t0);
    let base_end = base_t0.checked_add(t)?;
    if t < 2
        || t > NPOS
        || base_end > NPOS
        || (continuation.is_none() && t > model.p.tokens.len())
        || model.config.binding != ConfigBinding::LegacyImplicit
        || !model.config.is_legacy_gpt2_geometry()
        || !model.layout_valid
        || (!private_logits && logits.len() != VOCAB)
        || (private_logits && (!logits.is_empty() || chunks.is_empty()))
        || chunks.len() > MAX_RESPONSE_CHUNKS
        || proof.layers.len() != L
        || proof.seams.len() != L - 1
        || proof.chunks.len() != chunks.len()
        || proof.private_argmax.is_some() != private_logits
        || !(1..=16).contains(&model.p.shift_embed)
        || global_shifts.into_iter().any(|shift| shift > 32)
        || model.p.shift_attn_proj.iter().copied().any(|shift| shift > 32)
        || model.p.shift_ffn_down.iter().copied().any(|shift| shift > 32)
    {
        return None;
    }

    if proof
        .seams
        .iter()
        .zip(model.p.seam_shifts.iter().copied())
        .any(|(seam, shift)| shift > 16 || seam.is_some() != (shift > 0))
        || proof.embed.out_corr.len() != t.checked_mul(D)?
        || proof.final_ln.out_corr.len()
            != if continuation.is_some() { t.checked_mul(D)? } else { 2usize.checked_mul(D)? }
        || proof.final_ln.row_corr.len()
            != if continuation.is_some() { t.checked_mul(D)? } else { 2usize.checked_mul(D)? }
        || proof.final_ln.ln_vec_corrs.iter().any(|corrections| {
            corrections.len() != if continuation.is_some() { t.next_power_of_two() } else { 2 }
        })
    {
        return None;
    }
    for (layer, layer_proof) in proof.layers.iter().enumerate() {
        preflight_layer_proof_shape(
            continuation.map_or(BandShape::square(t), |_| BandShape { t0: base_t0, q: t }),
            layer_proof,
            model.p.lut.softmax_row_shift,
            layer,
        )?;
    }

    let public_prompt = continuation.is_none().then(|| model.p.tokens.get(..t)).flatten();
    let mut t0 = base_end;
    for (chunk, chunk_proof) in chunks.iter().zip(&proof.chunks) {
        let logits_len = chunk.q.checked_mul(VOCAB)?;
        let end = t0.checked_add(chunk.q)?;
        let chunk_boundary_len = chunk.q.checked_mul(D)?;
        let chunk_pad = chunk.q.checked_next_power_of_two()?;
        if chunk.q < 2
            || (!private_logits && chunk.logits.len() != logits_len)
            || (private_logits && !chunk.logits.is_empty())
            || end > NPOS
            || chunk.seq.len() < end
            || public_prompt.is_some_and(|prompt| chunk.seq.get(..t) != Some(prompt))
            || chunk_proof.layers.len() != L
            || chunk_proof.seams.len() != L - 1
            || chunk_proof
                .seams
                .iter()
                .zip(model.p.seam_shifts.iter().copied())
                .any(|(seam, shift)| seam.is_some() != (shift > 0))
            || chunk_proof.embed.out_corr.len() != chunk_boundary_len
            || chunk_proof.fin_out_corr.len() != chunk_boundary_len
            || chunk_proof.fin_ln_vec_corrs.iter().any(|corrections| corrections.len() != chunk_pad)
        {
            return None;
        }
        for (layer, layer_proof) in chunk_proof.layers.iter().enumerate() {
            preflight_layer_proof_shape(
                BandShape { t0, q: chunk.q },
                layer_proof,
                model.p.lut.softmax_row_shift,
                layer,
            )?;
        }

        t0 = end;
    }
    if !private_logits {
        preflight_greedy_tokens(t, logits, chunks)?;
    } else {
        if continuation.is_some() {
            private_argmax_continuation_layout(base_t0, t, chunks)?;
        } else {
            private_argmax_public_layout(t, chunks)?;
        }
    }

    // `TableBankV::finalize` expands keys incrementally. Validate its entire
    // public shape here so a later table mismatch cannot leave a half-used
    // verifier context.
    let mut expected_tables = model_content_keys_from(model.p, model.luts);
    if private_logits {
        expected_tables.insert(TableKey::Range(16));
    }
    if proof.tables.len() != expected_tables.len()
        || proof.tables.iter().zip(expected_tables).any(|(table, key)| {
            table.key != key || table.mult_corr.len() != crate::block_proof::table_len(key)
        })
    {
        return None;
    }
    Some(())
}

/// Verify a full response (prefill + decode chunks — mirror of
/// [`prove_response`], same order throughout). Also runs the PUBLIC greedy
/// checks: every sampled token must be the argmax of the logits row at the
/// previous position.
pub fn verify_response(
    model: &Gpt2Model,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    let model = Gpt2VerifierView::full(model);
    let mut cache_mode = ResponseVerifierCacheMode::Legacy(std::marker::PhantomData);
    verify_response_impl(&model, t, logits, chunks, None, proof, vc, tx, false, &mut cache_mode)
}

pub fn verify_response_private_logits(
    model: &Gpt2Model,
    t: usize,
    chunks: &[PrivateChunkPub<'_>],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    let model = Gpt2VerifierView::full(model);
    let views: Vec<ChunkPub<'_>> =
        chunks.iter().map(|chunk| ChunkPub { q: chunk.q, logits: &[], seq: chunk.seq }).collect();
    let mut cache_mode = ResponseVerifierCacheMode::Legacy(std::marker::PhantomData);
    verify_response_impl(&model, t, &[], &views, None, proof, vc, tx, true, &mut cache_mode)
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn verify_response_c6_cache_inline(
    model: &Gpt2Model,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    verify_response_c6_cache_inline_view(
        Gpt2VerifierView::full(model),
        t,
        logits,
        chunks,
        proof,
        vc,
        secondary,
        schedule_follower,
        target_cursor,
        tx,
    )
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn verify_response_c6_cache_inline_from_profile(
    model: &Gpt2VerifierModel,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    verify_response_c6_cache_inline_view(
        Gpt2VerifierView::slim(model),
        t,
        logits,
        chunks,
        proof,
        vc,
        secondary,
        schedule_follower,
        target_cursor,
        tx,
    )
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
fn verify_response_c6_cache_inline_view(
    model: Gpt2VerifierView<'_>,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    if chunks.len() != 1 {
        return None;
    }
    let mut cache_mode = ResponseVerifierCacheMode::C6 {
        secondary,
        schedule_follower,
        target_cursor,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
        paired_targets: Vec::with_capacity(4 * crate::c6_cache_fold::C6_CACHE_HEADS * L),
    };
    let (out, prod, zero) = verify_response_impl(
        &model,
        t,
        logits,
        chunks,
        None,
        proof,
        vc,
        tx,
        false,
        &mut cache_mode,
    )?;
    let ResponseVerifierCacheMode::C6 { metrics, append_source_layers, paired_targets, .. } =
        cache_mode
    else {
        unreachable!("C6 response verifier mode changed during execution")
    };
    Some((
        out,
        prod,
        C6GrandResidualVerifierRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers).ok()?,
        paired_targets,
    ))
}

/// Verifier mirror of [`prove_response_private_logits_c6_cache_inline`].
/// The private-logit statement and inline cache schedule are selected before
/// any verifier-key expansion.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn verify_response_private_logits_c6_cache_inline(
    model: &Gpt2Model,
    t: usize,
    chunks: &[PrivateChunkPub<'_>],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    verify_response_private_logits_c6_cache_inline_view(
        Gpt2VerifierView::full(model),
        t,
        chunks,
        proof,
        vc,
        secondary,
        schedule_follower,
        target_cursor,
        tx,
    )
}

/// C6.1 disk-verifier entry point. The client profile contains no committed
/// layer, embedding or output-head matrices.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn verify_response_private_logits_c6_cache_inline_from_profile(
    model: &Gpt2VerifierModel,
    t: usize,
    chunks: &[PrivateChunkPub<'_>],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    verify_response_private_logits_c6_cache_inline_view(
        Gpt2VerifierView::slim(model),
        t,
        chunks,
        proof,
        vc,
        secondary,
        schedule_follower,
        target_cursor,
        tx,
    )
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn verify_response_continuation_private_logits_c6_cache_inline_from_profile(
    model: &Gpt2VerifierModel,
    base_t0: usize,
    sequence: &[u32],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    let model = Gpt2VerifierView::slim(model);
    let views = [ChunkPub { q: 25, logits: &[], seq: sequence }];
    let mut cache_mode = ResponseVerifierCacheMode::C6 {
        secondary,
        schedule_follower,
        target_cursor,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
        paired_targets: Vec::with_capacity(4 * crate::c6_cache_fold::C6_CACHE_HEADS * L),
    };
    let (out, prod, zero) = verify_response_impl(
        &model,
        26,
        &[],
        &views,
        Some(C6ContinuationPublic { base_t0 }),
        proof,
        vc,
        tx,
        true,
        &mut cache_mode,
    )?;
    let ResponseVerifierCacheMode::C6 { metrics, append_source_layers, paired_targets, .. } =
        cache_mode
    else {
        unreachable!("C6 continuation verifier mode changed during execution")
    };
    let append_source_layers = append_source_layers
        .into_iter()
        .map(|layer| layer.suffix_from(base_t0 + 1))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    Some((
        out,
        prod,
        C6GrandResidualVerifierRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers).ok()?,
        paired_targets,
    ))
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
fn verify_response_private_logits_c6_cache_inline_view(
    model: Gpt2VerifierView<'_>,
    t: usize,
    chunks: &[PrivateChunkPub<'_>],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    secondary: &mut VerifierCtx,
    schedule_follower: &mut C6SourceScheduleVerifierFollower,
    target_cursor: &mut C6CacheFoldTargetInlineVerifier<'_>,
    tx: &mut Transcript,
) -> Option<(
    ModelOutV,
    ProdKeyTriples,
    C6GrandResidualVerifierRoots,
    C6CacheFoldOnlineLayerMetrics,
    C6CacheFoldAppendSourcePlan,
    Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
)> {
    if chunks.len() != 1 {
        return None;
    }
    let views: Vec<ChunkPub<'_>> =
        chunks.iter().map(|chunk| ChunkPub { q: chunk.q, logits: &[], seq: chunk.seq }).collect();
    let mut cache_mode = ResponseVerifierCacheMode::C6 {
        secondary,
        schedule_follower,
        target_cursor,
        metrics: C6CacheFoldOnlineLayerMetrics::default(),
        append_source_layers: Vec::with_capacity(L),
        paired_targets: Vec::with_capacity(4 * crate::c6_cache_fold::C6_CACHE_HEADS * L),
    };
    let (out, prod, zero) =
        verify_response_impl(&model, t, &[], &views, None, proof, vc, tx, true, &mut cache_mode)?;
    let ResponseVerifierCacheMode::C6 { metrics, append_source_layers, paired_targets, .. } =
        cache_mode
    else {
        unreachable!("C6 private-logit verifier mode changed during execution")
    };
    Some((
        out,
        prod,
        C6GrandResidualVerifierRoots::new(zero),
        metrics,
        C6CacheFoldAppendSourcePlan::new(append_source_layers).ok()?,
        paired_targets,
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_response_impl(
    model: &Gpt2VerifierView<'_>,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    continuation: Option<C6ContinuationPublic>,
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
    private_logits: bool,
    cache_mode: &mut ResponseVerifierCacheMode<'_, '_>,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    preflight_verify_response_public(
        model,
        t,
        logits,
        chunks,
        continuation,
        proof,
        private_logits,
    )?;
    let base_t0 = continuation.map_or(0, |profile| profile.base_t0);
    let base_shape = continuation.map_or(BandShape::square(t), |_| BandShape { t0: base_t0, q: t });
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut kprod: ProdKeyTriples = Vec::new();
    let mut kzero: Vec<VerifierKey> = Vec::new();
    let mut weight_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(4 * L);
    // (xin_keys, fbo_keys) per layer.
    let mut boundary_keys: Vec<(Vec<VerifierKey>, Vec<VerifierKey>)> = Vec::with_capacity(L);
    // Prefill (k_keys, v_keys) per layer — the chunks' first cache segment.
    let mut boundary_kv_keys: Vec<(Vec<VerifierKey>, Vec<VerifierKey>)> = Vec::with_capacity(L);
    #[cfg(feature = "c6-trace")]
    let mut boundary_kv_sources: Vec<(u64, u64)> = Vec::with_capacity(L);

    let luts_for = |l: usize| {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        luts_l
    };

    // ======================= PHASE 1 mirror (key expansion) =================
    let mut pre_bank = TableBankV::empty();
    let mut layer_v1s: Vec<LayerV1> = Vec::with_capacity(L);
    for l in 0..L {
        let luts_l = luts_for(l);
        let mut cx = BlockCtxV::new(vc, tx, l as u8, &mut pre_bank);
        let entry_alias = (matches!(l, 4 | 8)).then(|| layer_v1s[l - 1].fbo_keys.as_slice());
        let v1 = match cache_mode {
            ResponseVerifierCacheMode::Legacy(_) => verify_layer_phase1_band_thinned(
                l,
                base_shape,
                &luts_l,
                &proof.layers[l],
                entry_alias,
                &mut cx,
            ),
            #[cfg(feature = "c6-trace")]
            ResponseVerifierCacheMode::C6 { .. } => verify_layer_phase1_band_thinned_c6(
                l,
                base_shape,
                &luts_l,
                &proof.layers[l],
                entry_alias,
                &mut cx,
            ),
        };
        let Some(v1) = v1 else {
            return None;
        };
        layer_v1s.push(v1);
    }
    let s_emb = model.p.shift_embed;
    if !(s_emb > 0 && s_emb <= 16) {
        return None;
    }
    let s_emb = s_emb as u32;
    let (embed_doms, out_keys) = {
        let mut cx = BlockCtxV::new(vc, tx, 220, &mut pre_bank);
        let dom_out = cx.doms.take(t as u64);
        if proof.embed.out_corr.len() != t * D {
            return None;
        }
        let out_keys = auth_matrix_rows_v(cx.ctx, cx.tx, dom_out, &proof.embed.out_corr, t, D);
        (cx.doms, out_keys)
    };
    let t_ln = if continuation.is_some() { t } else { 2 };
    let rb_ln = pad_bits(t_ln);
    let (fl_doms, out_keys_f, lvk_f, row_keys) = {
        let mut cx = BlockCtxV::new(vc, tx, 221, &mut pre_bank);
        if proof.final_ln.out_corr.len() != t_ln * D
            || proof.final_ln.row_corr.len() != t_ln * D
            || proof.final_ln.ln_vec_corrs.iter().any(|c| c.len() != 1usize << rb_ln)
        {
            return None;
        }
        let dom_out_f = cx.doms.take(t_ln as u64);
        let out_keys_f =
            auth_matrix_rows_v(cx.ctx, cx.tx, dom_out_f, &proof.final_ln.out_corr, t_ln, D);
        let lvk = expand_ln_vecs_k(&mut cx, &proof.final_ln.ln_vec_corrs);
        let dom_row = cx.doms.take(t_ln as u64);
        let row_keys =
            auth_matrix_rows_v(cx.ctx, cx.tx, dom_row, &proof.final_ln.row_corr, t_ln, D);
        (cx.doms, out_keys_f, lvk, row_keys)
    };
    // ---- decode chunks, phase 1 mirror --------------------------------------
    struct ChunkV1 {
        layer_v1s: Vec<LayerV1>,
        embed_doms: Doms,
        out_keys: Vec<VerifierKey>,
        fin_doms: Doms,
        fin_out_keys: Vec<VerifierKey>,
        fin_lvk: crate::block_proof::LnVecsK,
    }
    let mut chunk_v1s: Vec<ChunkV1> = Vec::with_capacity(chunks.len());
    {
        let mut t0 = base_t0 + t;
        for (c, (ch, cp)) in chunks.iter().zip(&proof.chunks).enumerate() {
            let q = ch.q;
            let sh_c = BandShape { t0, q };
            let q_pad = 1usize << pad_bits(q);
            let (lb, _sb_id, eb, fb, _gb, _zb) = chunk_ids(c);
            let mut layer_v1s: Vec<LayerV1> = Vec::with_capacity(L);
            for l in 0..L {
                let luts_l = luts_for(l);
                let mut cx = BlockCtxV::new(vc, tx, lb + l as u8, &mut pre_bank);
                let entry_alias =
                    (matches!(l, 4 | 8)).then(|| layer_v1s[l - 1].fbo_keys.as_slice());
                let v1 = match cache_mode {
                    ResponseVerifierCacheMode::Legacy(_) => verify_layer_phase1_band_thinned(
                        l,
                        sh_c,
                        &luts_l,
                        &cp.layers[l],
                        entry_alias,
                        &mut cx,
                    )?,
                    #[cfg(feature = "c6-trace")]
                    ResponseVerifierCacheMode::C6 { .. } => verify_layer_phase1_band_thinned_c6(
                        l,
                        sh_c,
                        &luts_l,
                        &cp.layers[l],
                        entry_alias,
                        &mut cx,
                    )?,
                };
                layer_v1s.push(v1);
            }
            let (embed_doms, out_keys) = {
                let mut cx = BlockCtxV::new(vc, tx, eb, &mut pre_bank);
                let dom_out = cx.doms.take(q as u64);
                if cp.embed.out_corr.len() != q * D {
                    return None;
                }
                let out_keys = auth_matrix_rows_v(cx.ctx, cx.tx, dom_out, &cp.embed.out_corr, q, D);
                (cx.doms, out_keys)
            };
            let (fin_doms, fin_out_keys, fin_lvk) = {
                let mut cx = BlockCtxV::new(vc, tx, fb, &mut pre_bank);
                if cp.fin_out_corr.len() != q * D
                    || cp.fin_ln_vec_corrs.iter().any(|cc| cc.len() != q_pad)
                {
                    return None;
                }
                let dom_out_f = cx.doms.take(q as u64);
                let out_keys_f =
                    auth_matrix_rows_v(cx.ctx, cx.tx, dom_out_f, &cp.fin_out_corr, q, D);
                let lvk = expand_ln_vecs_k(&mut cx, &cp.fin_ln_vec_corrs);
                (cx.doms, out_keys_f, lvk)
            };
            chunk_v1s.push(ChunkV1 {
                layer_v1s,
                embed_doms,
                out_keys,
                fin_doms,
                fin_out_keys,
                fin_lvk,
            });
            t0 = t0.checked_add(q)?;
        }
    }

    // Validate every scheduled proof and domain range before table
    // finalization expands multiplicity keys or draws shared alphas.
    let prefill_gelu = preflight_gelu_plan_thinned(
        t,
        base_t0,
        0,
        layer_v1s
            .iter()
            .enumerate()
            .map(|(layer, v1)| (layer, v1.doms, model.p.shift_ffn_down[layer])),
    )
    .ok()?;
    preflight_gelu_proofs(&proof.layers, &prefill_gelu).ok()?;
    let mut gelu_manifest = Vec::with_capacity(1 + chunks.len());
    gelu_manifest.push(prefill_gelu);
    let mut decode_t0 = base_t0 + t;
    for (chunk_index, ((chunk, chunk_proof), v1)) in
        chunks.iter().zip(&proof.chunks).zip(&chunk_v1s).enumerate()
    {
        let (layer_base, ..) = chunk_ids(chunk_index);
        let plan = preflight_gelu_plan_thinned(
            chunk.q,
            decode_t0,
            layer_base,
            v1.layer_v1s
                .iter()
                .enumerate()
                .map(|(layer, v1)| (layer, v1.doms, model.p.shift_ffn_down[layer])),
        )
        .ok()?;
        preflight_gelu_proofs(&chunk_proof.layers, &plan).ok()?;
        gelu_manifest.push(plan);
        decode_t0 = decode_t0.checked_add(chunk.q)?;
    }

    let private_layout = private_logits.then(|| {
        continuation
            .map_or_else(
                || private_argmax_public_layout(t, chunks),
                |profile| private_argmax_continuation_layout(profile.base_t0, t, chunks),
            )
            .expect("private preflight fixed layout")
    });
    let argmax_prepared = if let Some((phases, _)) = &private_layout {
        Some(prepare_private_argmax_verifier(proof.private_argmax.as_ref()?, phases.len(), vc, tx)?)
    } else {
        None
    };

    // End of phase 1: expand the per-content multiplicity keys against the
    // PUBLIC expected content set, draw the shared αs, then register the
    // already validated response manifest.
    let mut expected = model_content_keys_from(model.p, model.luts);
    if private_logits {
        expected.insert(TableKey::Range(16));
    }
    let mut table_doms = Doms::new(layer_dom_base(240));
    let mut bank = TableBankV::finalize(&expected, &proof.tables, vc, tx, &mut table_doms)?;
    register_gelu_manifest_v(&mut bank, &gelu_manifest).ok()?;

    let private_phases = if let (Some(prepared), Some((phase_rows, public_tokens))) =
        (argmax_prepared, private_layout.as_ref())
    {
        let argmax = verify_private_argmax(
            prepared,
            phase_rows,
            public_tokens,
            proof.private_argmax.as_ref()?,
            &mut bank,
            vc,
            tx,
        )?;
        kprod.extend(argmax.prod);
        kzero.extend(argmax.zero);
        Some(argmax.phases)
    } else {
        None
    };

    // ======================= PHASE 2 mirror =================================
    // ---- (a) 12 layers -----------------------------------------------------
    let prefill_prefixes: Vec<Vec<KvPrefixK<'_>>> = (0..L).map(|_| Vec::new()).collect();
    let seam_instances: Vec<_> =
        proof.seams.iter().map(|seam| seam.as_ref().map(|seam| &seam.inst)).collect();
    let scheduled = match cache_mode {
        ResponseVerifierCacheMode::Legacy(_) => verify_layers_thinned_scheduled(
            model.schedule_model,
            &proof.layers,
            &seam_instances,
            layer_v1s,
            &prefill_prefixes,
            &gelu_manifest[0],
            200,
            vc,
            tx,
            &mut bank,
        )?,
        #[cfg(feature = "c6-trace")]
        ResponseVerifierCacheMode::C6 {
            secondary,
            schedule_follower,
            target_cursor,
            metrics,
            append_source_layers,
            paired_targets,
        } => {
            let c6_prefixes: Vec<Vec<C6KvPrefixSource>> = (0..L)
                .map(|_| {
                    continuation.map_or_else(Vec::new, |_| {
                        vec![C6KvPrefixSource { rows: base_t0, dom_k: 0, dom_v: 0 }]
                    })
                })
                .collect();
            let (scheduled, phase_metrics, phase_sources, phase_targets) =
                verify_layers_thinned_scheduled_c6(
                    model.schedule_model,
                    &proof.layers,
                    &seam_instances,
                    layer_v1s,
                    &c6_prefixes,
                    &gelu_manifest[0],
                    200,
                    vc,
                    secondary,
                    schedule_follower,
                    target_cursor,
                    tx,
                    &mut bank,
                )?;
            add_c6_response_metrics(metrics, phase_metrics);
            *append_source_layers = phase_sources;
            paired_targets.extend(phase_targets);
            scheduled
        }
    };
    for layer in scheduled.layers {
        let out = layer.out;
        kprod.extend(layer.prod);
        kzero.extend(layer.zero);
        weight_keys.extend(out.weight_keys);
        boundary_keys.push((out.xin_keys, out.fbo_keys));
        #[cfg(feature = "c6-trace")]
        boundary_kv_sources.push((out.dom_k, out.dom_v));
        boundary_kv_keys.push((out.k_keys, out.v_keys));
    }

    // ---- (d) embedding ---------------------------------------------------
    let mut cx = BlockCtxV::with_doms(vc, tx, embed_doms, &mut bank);
    let site = verify_range_site(n_vars_td, s_emb, &proof.embed.inst, None, &[], &mut cx)?;
    let out_k = open_matrix_k(&out_keys, t, D, &site.main.point);
    cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
    let embed_acc_point = site.acc_point().to_vec();
    let embed_acc_key = site.acc_key;
    let rho_e: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
    let e_k = open_matrix_k(&out_keys, t, D, &rho_e);
    let x0_k = open_matrix_k(&boundary_keys[0].0, t, D, &rho_e);
    cx.kzero.push(e_k.sub(x0_k));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (e) final LN (mirrors the t=2 duplicated-row fix) -----------------
    let mut cx = BlockCtxV::with_doms(vc, tx, fl_doms, &mut bank);
    let rho_r: Vec<Fp2> = (0..d_cb + if continuation.is_some() { rb_ln } else { 0 })
        .map(|_| cx.tx.challenge_fp2())
        .collect();
    let mut pt_row0 = rho_r.clone();
    if continuation.is_none() {
        pt_row0.extend(bit_coords(0, rb_ln));
    }
    let row_k = open_matrix_k(&row_keys, t_ln, D, &pt_row0);
    let mut pt_fbo = rho_r;
    if continuation.is_none() {
        pt_fbo.extend(bit_coords(t - 1, rb_t));
    }
    let fbo_k = open_matrix_k(&boundary_keys[L - 1].1, t, D, &pt_fbo);
    cx.kzero.push(row_k.sub(fbo_k));

    let rho_f: Vec<Fp2> = (0..d_cb + if continuation.is_some() { rb_ln } else { 0 })
        .map(|_| cx.tx.challenge_fp2())
        .collect();
    let mut pt_wire = rho_f;
    if continuation.is_none() {
        pt_wire.extend(bit_coords(0, rb_ln));
    }
    let wire_key = open_matrix_k(&out_keys_f, t_ln, D, &pt_wire);
    let wk = WireKey { point: pt_wire, key: wire_key };

    let s_ln = model.p.lut.shift_ln_norm;
    verify_ln_chain(
        t_ln,
        s_ln,
        model.lnf_gain,
        model.lnf_bias,
        &row_keys,
        &lvk_f,
        &proof.final_ln.ln,
        &wk,
        &mut cx,
    )?;
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (f) logits claim (mirror) -----------------------------------------
    let mut embed_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(3);
    let mut cx = BlockCtxV::new(vc, tx, 230, &mut bank);
    let private_phase = private_phases.as_ref().map(|phases| &phases[0]);
    let rho_v: Vec<Fp2> = private_phase.map_or_else(
        || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
        |phase| phase.tau[..16].to_vec(),
    );
    let eq_v = eq_vec(&rho_v);
    let logits_key = private_phase.map_or_else(
        || {
            let mut l_eval = Fp2::ZERO;
            for (v, &lv) in logits.iter().enumerate() {
                l_eval += eq_v[v].mul_base(Fp::from_i64(lv));
            }
            VerifierKey::from_public(l_eval, cx.ctx.delta)
        },
        |phase| phase.claim,
    );
    let dom_lg = cx.doms.take(d_cb as u64);
    let (r_l, k_claim_n) = blind_verify(d_cb, logits_key, &proof.logits.sc, cx.ctx, dom_lg, cx.tx)?;
    let k_fin = if let Some(phase) = private_phase {
        if continuation.is_some() {
            open_matrix_weighted_rows_k(&out_keys_f, t_ln, D, &r_l, &phase.row_weights)
        } else {
            open_matrix_weighted_rows_k(
                &out_keys_f,
                t_ln,
                D,
                &r_l,
                &[phase.row_weights[0], Fp2::ZERO],
            )
        }
    } else {
        let mut pt_fin = r_l.clone();
        pt_fin.extend(bit_coords(0, rb_ln));
        open_matrix_k(&out_keys_f, t_ln, D, &pt_fin)
    };
    let dom_wv = cx.doms.take(1);
    cx.tx.append_fp2s("logits_wte_correction", &[proof.logits.wte_corr]);
    let k_wte = cx.ctx.correct_full_verifier_key(dom_wv, proof.logits.wte_corr);
    cx.kprod.push((k_fin, k_wte, k_claim_n));
    let mut pt_wte = r_l;
    pt_wte.extend(rho_v.iter().copied());
    embed_keys.push((pt_wte, k_wte));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (g) embedding selection (mirror) ----------------------------------
    let mut cx = BlockCtxV::new(vc, tx, 231, &mut bank);
    let r_d = &embed_acc_point[..d_cb];
    let r_i = &embed_acc_point[d_cb..];
    let eq_i = eq_vec(r_i);
    let dom_p = cx.doms.take(1);
    cx.tx.append_fp2s("selection_p_correction", &[proof.selection.p_corr]);
    let k_p = cx.ctx.correct_full_verifier_key(dom_p, proof.selection.p_corr);
    let k_claim0 = embed_acc_key.sub(k_p);
    let dom_sel = cx.doms.take(16);
    let (rho_z, k_sel_n) = blind_verify(16, k_claim0, &proof.selection.sc, cx.ctx, dom_sel, cx.tx)?;
    let base_tokens = if continuation.is_some() {
        &chunks[0].seq[base_t0..base_t0 + t]
    } else {
        &model.p.tokens[..t]
    };
    let s_eval = sel_s_eval(base_tokens, &eq_i, &rho_z);
    let dom_wv2 = cx.doms.take(1);
    cx.tx.append_fp2s("selection_wte_correction", &[proof.selection.wte_corr]);
    let k_wte2 = cx.ctx.correct_full_verifier_key(dom_wv2, proof.selection.wte_corr);
    cx.kzero.push(k_wte2.scale(s_eval).sub(k_sel_n));
    let mut pt_wte2 = r_d.to_vec();
    pt_wte2.extend(rho_z.iter().copied());
    embed_keys.push((pt_wte2, k_wte2));
    // Masked-wpe sumcheck (mirror): P = Σ_w G(w)·w̃pe(w, r_d).
    let dom_wpe_sc = cx.doms.take(10);
    let (rho_w, k_wpe_n) =
        blind_verify(10, k_p, &proof.selection.sc_wpe, cx.ctx, dom_wpe_sc, cx.tx)?;
    let g_eval = masked_eq_eval(&eq_i, base_t0, t, &rho_w);
    let dom_wpe = cx.doms.take(1);
    cx.tx.append_fp2s("selection_wpe_correction", &[proof.selection.wpe_corr]);
    let k_wpe = cx.ctx.correct_full_verifier_key(dom_wpe, proof.selection.wpe_corr);
    cx.kzero.push(k_wpe.scale(g_eval).sub(k_wpe_n));
    let mut wpe_pt = r_d.to_vec();
    wpe_pt.extend(rho_w.iter().copied());
    embed_keys.push((wpe_pt, k_wpe));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- decode chunks, phase 2 mirror (P6) ----------------------------------
    // Prefill boundary keys are the chunks' first cache segment; each proven
    // chunk extends the per-layer segment lists.
    let mut kv_keys: Vec<Vec<(Vec<VerifierKey>, Vec<VerifierKey>)>> = Vec::with_capacity(L);
    for bk in &boundary_kv_keys {
        kv_keys.push(vec![(bk.0.clone(), bk.1.clone())]);
    }
    #[cfg(feature = "c6-trace")]
    let mut kv_sources: Vec<Vec<(usize, u64, u64)>> = boundary_kv_sources
        .iter()
        .map(|&(dom_k, dom_v)| {
            let mut segments = Vec::with_capacity(2);
            if continuation.is_some() {
                segments.push((base_t0, 0, 0));
            }
            segments.push((t, dom_k, dom_v));
            segments
        })
        .collect();
    {
        let mut t0 = base_t0 + t;
        for (c, (ch, (cp, v1c))) in
            chunks.iter().zip(proof.chunks.iter().zip(chunk_v1s.into_iter())).enumerate()
        {
            let q = ch.q;
            let qb = pad_bits(q);
            let n_vars_qd = d_cb + qb;
            let (_lb, sb_id, _eb, _fb, gb, zb) = chunk_ids(c);
            let mut band_boundary_keys: Vec<(Vec<VerifierKey>, Vec<VerifierKey>)> =
                Vec::with_capacity(L);
            // ---- 12 band layers ------------------------------------------------
            let prefixes: Vec<Vec<KvPrefixK<'_>>> = (0..L)
                .map(|l| {
                    kv_keys[l]
                        .iter()
                        .map(|(kk, vk)| KvPrefixK { rows: kk.len() / D, k_keys: kk, v_keys: vk })
                        .collect()
                })
                .collect();
            let seam_instances: Vec<_> =
                cp.seams.iter().map(|seam| seam.as_ref().map(|seam| &seam.inst)).collect();
            let scheduled = match cache_mode {
                ResponseVerifierCacheMode::Legacy(_) => verify_layers_thinned_scheduled(
                    model.schedule_model,
                    &cp.layers,
                    &seam_instances,
                    v1c.layer_v1s,
                    &prefixes,
                    &gelu_manifest[c + 1],
                    sb_id,
                    vc,
                    tx,
                    &mut bank,
                )?,
                #[cfg(feature = "c6-trace")]
                ResponseVerifierCacheMode::C6 {
                    secondary,
                    schedule_follower,
                    target_cursor,
                    metrics,
                    append_source_layers,
                    paired_targets,
                } => {
                    let c6_prefixes = kv_sources
                        .iter()
                        .map(|segments| {
                            segments
                                .iter()
                                .map(|&(rows, dom_k, dom_v)| C6KvPrefixSource {
                                    rows,
                                    dom_k,
                                    dom_v,
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    let (scheduled, phase_metrics, phase_sources, phase_targets) =
                        verify_layers_thinned_scheduled_c6(
                            model.schedule_model,
                            &cp.layers,
                            &seam_instances,
                            v1c.layer_v1s,
                            &c6_prefixes,
                            &gelu_manifest[c + 1],
                            sb_id,
                            vc,
                            secondary,
                            schedule_follower,
                            target_cursor,
                            tx,
                            &mut bank,
                        )?;
                    add_c6_response_metrics(metrics, phase_metrics);
                    *append_source_layers = phase_sources;
                    paired_targets.extend(phase_targets);
                    scheduled
                }
            };
            for (l, layer) in scheduled.layers.into_iter().enumerate() {
                let out = layer.out;
                kprod.extend(layer.prod);
                kzero.extend(layer.zero);
                weight_keys.extend(out.weight_keys);
                band_boundary_keys.push((out.xin_keys, out.fbo_keys));
                #[cfg(feature = "c6-trace")]
                kv_sources[l].push((q, out.dom_k, out.dom_v));
                kv_keys[l].push((out.k_keys, out.v_keys));
            }
            // ---- band embedding -------------------------------------------------
            let mut cx = BlockCtxV::with_doms(vc, tx, v1c.embed_doms, &mut bank);
            let site = verify_range_site(n_vars_qd, s_emb, &cp.embed.inst, None, &[], &mut cx)?;
            let out_k = open_matrix_k(&v1c.out_keys, q, D, &site.main.point);
            cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
            let embed_acc_point_c = site.acc_point().to_vec();
            let embed_acc_key_c = site.acc_key;
            let rho_e: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
            let e_k = open_matrix_k(&v1c.out_keys, q, D, &rho_e);
            let x0_k = open_matrix_k(&band_boundary_keys[0].0, q, D, &rho_e);
            cx.kzero.push(e_k.sub(x0_k));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band final LN ---------------------------------------------------
            let mut cx = BlockCtxV::with_doms(vc, tx, v1c.fin_doms, &mut bank);
            let rho_f: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
            let wire_key = open_matrix_k(&v1c.fin_out_keys, q, D, &rho_f);
            let wk = WireKey { point: rho_f, key: wire_key };
            let s_lnf = model.p.lut.shift_ln_norm;
            verify_ln_chain(
                q,
                s_lnf,
                model.lnf_gain,
                model.lnf_bias,
                &band_boundary_keys[L - 1].1,
                &v1c.fin_lvk,
                &cp.fin_ln,
                &wk,
                &mut cx,
            )?;
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band logits claim ----------------------------------------------
            let mut cx = BlockCtxV::new(vc, tx, gb, &mut bank);
            let private_phase = private_phases.as_ref().map(|phases| &phases[c + 1]);
            let rho_v: Vec<Fp2> = private_phase.map_or_else(
                || (0..16).map(|_| cx.tx.challenge_fp2()).collect(),
                |phase| phase.tau[..16].to_vec(),
            );
            let rho_q: Vec<Fp2> = private_phase
                .map_or_else(|| (0..qb).map(|_| cx.tx.challenge_fp2()).collect(), |_| Vec::new());
            let eq_v = eq_vec(&rho_v);
            let row_weights = private_phase
                .map_or_else(|| eq_vec(&rho_q)[..q].to_vec(), |phase| phase.row_weights.clone());
            let logits_key = private_phase.map_or_else(
                || {
                    let mut l_eval = Fp2::ZERO;
                    for r in 0..q {
                        let mut row_e = Fp2::ZERO;
                        for (v, &lv) in ch.logits[r * VOCAB..(r + 1) * VOCAB].iter().enumerate() {
                            row_e += eq_v[v].mul_base(Fp::from_i64(lv));
                        }
                        l_eval += row_weights[r] * row_e;
                    }
                    VerifierKey::from_public(l_eval, cx.ctx.delta)
                },
                |phase| phase.claim,
            );
            let dom_lg = cx.doms.take(d_cb as u64);
            let (r_l, k_claim_n) =
                blind_verify(d_cb, logits_key, &cp.logits.sc, cx.ctx, dom_lg, cx.tx)?;
            let k_fin = if private_phase.is_some() {
                let mut padded_weights = vec![Fp2::ZERO; q];
                padded_weights[..row_weights.len()].copy_from_slice(&row_weights);
                open_matrix_weighted_rows_k(&v1c.fin_out_keys, q, D, &r_l, &padded_weights)
            } else {
                let mut pt_fin = r_l.clone();
                pt_fin.extend(rho_q.iter().copied());
                open_matrix_k(&v1c.fin_out_keys, q, D, &pt_fin)
            };
            let dom_wv = cx.doms.take(1);
            cx.tx.append_fp2s("logits_wte_correction", &[cp.logits.wte_corr]);
            let k_wte = cx.ctx.correct_full_verifier_key(dom_wv, cp.logits.wte_corr);
            cx.kprod.push((k_fin, k_wte, k_claim_n));
            let mut pt_wte = r_l;
            pt_wte.extend(rho_v.iter().copied());
            embed_keys.push((pt_wte, k_wte));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band embedding selection ------------------------------------------
            let mut cx = BlockCtxV::new(vc, tx, zb, &mut bank);
            let r_d = &embed_acc_point_c[..d_cb];
            let r_i = &embed_acc_point_c[d_cb..];
            let eq_i = eq_vec(r_i);
            let band_tokens = &ch.seq[t0..t0 + q];
            let dom_p = cx.doms.take(1);
            cx.tx.append_fp2s("selection_p_correction", &[cp.selection.p_corr]);
            let k_p = cx.ctx.correct_full_verifier_key(dom_p, cp.selection.p_corr);
            let k_claim0 = embed_acc_key_c.sub(k_p);
            let dom_sel = cx.doms.take(16);
            let (rho_z, k_sel_n) =
                blind_verify(16, k_claim0, &cp.selection.sc, cx.ctx, dom_sel, cx.tx)?;
            let s_eval = sel_s_eval(band_tokens, &eq_i, &rho_z);
            let dom_wv2 = cx.doms.take(1);
            cx.tx.append_fp2s("selection_wte_correction", &[cp.selection.wte_corr]);
            let k_wte2 = cx.ctx.correct_full_verifier_key(dom_wv2, cp.selection.wte_corr);
            cx.kzero.push(k_wte2.scale(s_eval).sub(k_sel_n));
            let mut pt_wte2 = r_d.to_vec();
            pt_wte2.extend(rho_z.iter().copied());
            embed_keys.push((pt_wte2, k_wte2));
            let dom_wpe_sc = cx.doms.take(10);
            let (rho_w, k_wpe_n) =
                blind_verify(10, k_p, &cp.selection.sc_wpe, cx.ctx, dom_wpe_sc, cx.tx)?;
            let g_eval = masked_eq_eval(&eq_i, t0, q, &rho_w);
            let dom_wpe = cx.doms.take(1);
            cx.tx.append_fp2s("selection_wpe_correction", &[cp.selection.wpe_corr]);
            let k_wpe = cx.ctx.correct_full_verifier_key(dom_wpe, cp.selection.wpe_corr);
            cx.kzero.push(k_wpe.scale(g_eval).sub(k_wpe_n));
            let mut wpe_pt = r_d.to_vec();
            wpe_pt.extend(rho_w.iter().copied());
            embed_keys.push((wpe_pt, k_wpe));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);

            t0 = t0.checked_add(q)?;
        }
    }

    // ---- (h) per-content table sides (mirror) -------------------------------
    bank.close(&model.luts, &proof.tables, vc, &mut table_doms, tx, &mut kprod, &mut kzero)?;

    Some((ModelOutV { weight_keys, embed_keys }, kprod, kzero))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_proof::{cattn_permuted, layer_dom_base};
    use crate::logup::Doms;
    use crate::mle::eval_mle;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::thaler::fold_w;
    use rand::{Rng, SeedableRng};
    #[cfg(feature = "cuda")]
    use volta_gpt2::{
        band_model_witness_resident, forward_model_tokens_resident, upload_resident_model,
    };
    use volta_gpt2::{forward_model, load_model, DFF};
    use volta_mac::zero_batch_exchange;

    fn weights_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    fn weight_true_eval(w: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
        let cb = pad_bits(n);
        let b = fold_w(w, k, n, &eq_vec(&point[..cb]));
        eval_mle(&b, &point[cb..])
    }

    fn assert_response_preflight_rejects_without_mutation(
        model: &Gpt2Model,
        t: usize,
        logits: &[i64],
        chunks: &[ChunkPub<'_>],
        proof: &ModelProof,
        pcg_seed: [u8; 32],
        delta: Fp2,
        tx_seed: [u8; 32],
    ) -> (VerifierCtx, Transcript) {
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut tx = Transcript::new(tx_seed);
        let counters_before = vc.counters;
        let allocation_before = vc.allocation_digest_hex();
        let ledger_before = tx.ledger().clone();
        let transcript_bytes_before = tx.total_bytes();

        assert!(
            verify_response(model, t, logits, chunks, proof, &mut vc, &mut tx).is_none(),
            "malformed response must fail in the entry preflight"
        );
        assert_eq!(vc.counters, counters_before, "preflight rejection consumed correlations");
        assert_eq!(
            vc.allocation_digest_hex(),
            allocation_before,
            "preflight rejection changed the correlation allocation ledger"
        );
        assert_eq!(tx.ledger(), &ledger_before, "preflight rejection changed transcript ledger");
        assert_eq!(
            tx.total_bytes(),
            transcript_bytes_before,
            "preflight rejection charged transcript bytes"
        );
        (vc, tx)
    }

    #[test]
    fn greedy_preflight_binds_the_first_token_of_each_later_chunk() {
        let t = 2usize;
        let mut prefill_logits = vec![0i64; VOCAB];
        prefill_logits[7] = 1;
        let mut first_logits = vec![0i64; 2 * VOCAB];
        first_logits[8] = 1;
        first_logits[VOCAB + 9] = 1;
        let mut second_logits = vec![0i64; 2 * VOCAB];
        second_logits[10] = 1;
        let sequence = vec![101, 102, 7, 8, 9, 10];
        let chunks = [
            ChunkPub { q: 2, logits: &first_logits, seq: &sequence },
            ChunkPub { q: 2, logits: &second_logits, seq: &sequence },
        ];
        assert_eq!(preflight_greedy_tokens(t, &prefill_logits, &chunks), Some(()));

        let mut wrong_boundary = sequence.clone();
        wrong_boundary[4] = 11;
        let malformed = [
            ChunkPub { q: 2, logits: &first_logits, seq: &sequence },
            ChunkPub { q: 2, logits: &second_logits, seq: &wrong_boundary },
        ];
        assert_eq!(preflight_greedy_tokens(t, &prefill_logits, &malformed), None);
    }

    #[test]
    fn identity_alias_preflight_is_canonical_and_fail_closed() {
        let boundary_len = 4 * D;
        assert!(preflight_xin_correction_len(boundary_len, boundary_len, false));
        assert!(!preflight_xin_correction_len(boundary_len, 0, false));
        assert!(preflight_xin_correction_len(boundary_len, 0, true));
        assert!(!preflight_xin_correction_len(boundary_len, boundary_len, true));
        assert!(!preflight_xin_correction_len(boundary_len, boundary_len - 1, true));
        // The proof carries no source identity: once the public seam selects
        // reuse, the verifier derives the only legal source (same session,
        // phase/chunk and rows, immediately preceding layer) itself.
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn c6_continuation_uses_one_overlap_row_and_fifty_new_rows() {
        use crate::c6_cache_fold::{
            begin_c6_cache_fold_trace, C6CacheFoldKind, C6CacheFoldParty,
            C6CacheFoldTargetInlineProver, C6CacheFoldTargetInlineVerifier,
            C6CacheFoldTargetPublicSchedule,
        };
        use crate::c6_residual::C6_RESIDUAL_TRACE_FIXTURE_LOCK;
        use crate::c6_source::{C6SourceScheduleProverFollower, C6SourceScheduleVerifierFollower};
        use volta_gpt2::{band_model_witness, forward_model_tokens, Gpt2VerifierModel, KvCache};
        use volta_mac::{
            begin_c6_prover_trace, compile_c6_operation_trace_for_role, finish_c6_prover_trace,
            C6InstanceExtractionRole, C6TraceSourceManifest, CorrScheduleRole,
        };

        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping C6 continuation gate: artifact not present");
            return;
        }
        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();
        let model = load_model(&dir).unwrap();
        let old_len = 500usize;
        let prompt_len = 100usize;
        let prompt = forward_model(&model, prompt_len);
        let kv = prompt
            .layers
            .iter()
            .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
            .collect::<Vec<_>>();
        let mut cache = KvCache::from_prefill(&kv, prompt_len);
        let (generated, _) = volta_gpt2::generate(
            &model,
            &mut cache,
            &prompt.logits,
            prompt_len,
            old_len + 50 - prompt_len,
        );
        let mut sequence = model.p.tokens[..prompt_len].to_vec();
        sequence.extend_from_slice(&generated);
        let first_full = forward_model_tokens(&model, &sequence[..old_len + 25]);
        let full = forward_model_tokens(&model, &sequence);
        let first = band_model_witness(&model, &first_full, old_len - 1);
        let second = band_model_witness(&model, &full, old_len + 25);
        assert_eq!((first.t0, first.q, second.t0, second.q), (old_len - 1, 26, old_len + 25, 25));
        let extended_gap_count = [&first, &second]
            .into_iter()
            .map(|band| {
                let causal = band.q * band.t0 + band.q * (band.q + 1) / 2;
                band.layers
                    .iter()
                    .map(|layer| {
                        (0..H)
                            .map(|head| {
                                (0..band.q)
                                    .map(|row| {
                                        let width = band.t0 + row + 1;
                                        let start =
                                            head * causal + row * band.t0 + row * (row + 1) / 2;
                                        layer.scores_q[start..start + width]
                                            .iter()
                                            .filter(|&&score| {
                                                volta_gpt2::softmax_score_gap(
                                                    score,
                                                    layer.row_shift[head * band.q + row],
                                                ) > 1 << 15
                                            })
                                            .count()
                                    })
                                    .sum::<usize>()
                            })
                            .sum::<usize>()
                    })
                    .sum::<usize>()
            })
            .sum::<usize>();
        assert!(extended_gap_count > 0, "C62SGE1 lower-tail relation was not exercised");

        let schedule = C6CacheFoldTargetPublicSchedule::new(
            (0..2 * L)
                .flat_map(|_| {
                    std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                        .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
                })
                .collect(),
        )
        .unwrap();
        let statement_digest = [0xD1; 32];
        let transcript_seed = [0xD2; 32];
        let deltas = [
            Fp2::new(Fp::new(0xD301), Fp::new(0xD302)),
            Fp2::new(Fp::new(0xD401), Fp::new(0xD402)),
        ];

        let mut primary = CorrelationStream::new([0xD5; 32]);
        begin_c6_prover_trace().unwrap();
        primary.enable_c6_operation_trace().unwrap();
        primary.enable_c6_source_witness_collection().unwrap();
        let mut secondary = CorrelationStream::new([0xD6; 32]);
        let mut prover_follower = C6SourceScheduleProverFollower::start(&mut secondary).unwrap();
        let mut prover_tx = Transcript::new(transcript_seed);
        let mut builder = C6CacheFoldTargetInlineProver::start_public(
            statement_digest,
            schedule.clone(),
            &mut prover_tx,
        )
        .unwrap();
        let prover_trace = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        let (proof, prover_out, products, zero_roots, prover_metrics, append) =
            prove_response_continuation_private_logits_c6_cache_inline(
                &model,
                &full,
                &first,
                &second,
                &sequence,
                &mut primary,
                &mut secondary,
                &mut prover_follower,
                &mut builder,
                &mut prover_tx,
            );
        let prover_snapshot = prover_trace.finish().unwrap();
        let (frame, _) = builder
            .finish_before_successor_root_with_identity(prover_snapshot.identity, &mut prover_tx)
            .unwrap();
        assert_eq!(prover_out.weight_claims.len(), 96);
        assert_eq!(prover_out.embed_claims.len(), 6);
        assert_eq!(prover_metrics.corrected_targets, 576);
        assert!(append
            .layers()
            .iter()
            .all(|layer| layer.first_row() == old_len && layer.row_count().unwrap() == 50));
        assert_eq!(
            (primary.counters.sub_corrs, primary.counters.full_corrs, primary.counters.domains),
            (1_696_526, 168_918, 72_934),
        );
        let mut product_doms = Doms::new(layer_dom_base(255));
        let product_challenge = prover_tx.challenge_fp2();
        let product_domain = product_doms.take(1);
        let product_mask = primary.draw_product_mask(product_domain, products.len());
        let product_proof =
            prod_batch_prover(&products, product_challenge, product_mask, &mut prover_tx);
        zero_roots.record_operation_trace_ownership().unwrap();
        let operation_trace = finish_c6_prover_trace().unwrap();
        prover_follower.sync_primary(&primary, &mut secondary).unwrap();
        let correlation_schedule = primary.schedule_audit().unwrap();
        let mut next_source = 0u64;
        let mut product_mask_sources = Vec::new();
        for draw in &correlation_schedule.draws {
            if draw.role == CorrScheduleRole::ProductMask {
                product_mask_sources.push(u32::try_from(next_source).unwrap());
            }
            next_source += draw.count;
        }
        let source_manifest = C6TraceSourceManifest::new(
            u32::try_from(next_source).unwrap(),
            correlation_schedule.digest,
            product_mask_sources,
        )
        .unwrap();
        let compiled = compile_c6_operation_trace_for_role(
            &operation_trace,
            &source_manifest,
            C6InstanceExtractionRole::Prover,
        )
        .unwrap();
        let topology = compiled.plan.topology;
        assert_eq!(
            (
                topology.source_count,
                topology.canonical_node_count,
                topology.public_input_count,
                topology.scalar_input_count,
                topology.product_closure_count,
                topology.product_triple_count,
                topology.zero_root_count,
            ),
            (1_865_445, 6_597_601, 1_436, 2_416_845, 673, 21_052, 7_741),
        );
        assert_eq!(
            topology.source_schedule_digest,
            [
                130, 85, 122, 79, 218, 185, 20, 246, 10, 251, 219, 161, 24, 118, 110, 209, 169,
                134, 216, 231, 97, 109, 59, 169, 243, 182, 216, 83, 82, 243, 184, 206,
            ],
        );
        assert_eq!(
            topology.topology_digest,
            [
                14, 91, 135, 30, 168, 34, 119, 229, 183, 235, 119, 196, 184, 17, 203, 108, 35, 185,
                177, 244, 254, 119, 20, 49, 18, 47, 27, 2, 193, 150, 139, 71,
            ],
        );

        let mut primary_v = VerifierCtx::new([0xD5; 32], deltas[0]);
        primary_v.enable_schedule_audit().unwrap();
        let mut secondary_v = VerifierCtx::new([0xD6; 32], deltas[1]);
        let mut verifier_follower =
            C6SourceScheduleVerifierFollower::start(&mut secondary_v).unwrap();
        let mut verifier_tx = Transcript::new(transcript_seed);
        let mut cursor = C6CacheFoldTargetInlineVerifier::start_public(
            &frame,
            schedule,
            deltas,
            &mut verifier_tx,
        )
        .unwrap();
        let verifier_trace = begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).unwrap();
        let verifier_model = Gpt2VerifierModel::from_model(&model).unwrap();
        let preflight_chunks = [ChunkPub { q: 25, logits: &[], seq: &sequence }];
        assert_eq!(
            preflight_verify_response_public(
                &Gpt2VerifierView::slim(&verifier_model),
                26,
                &[],
                &preflight_chunks,
                Some(C6ContinuationPublic { base_t0: old_len - 1 }),
                &proof,
                true,
            ),
            Some(())
        );
        let verified = verify_response_continuation_private_logits_c6_cache_inline_from_profile(
            &verifier_model,
            old_len - 1,
            &sequence,
            &proof,
            &mut primary_v,
            &mut secondary_v,
            &mut verifier_follower,
            &mut cursor,
            &mut verifier_tx,
        );
        let (verifier_out, product_keys, _, verifier_metrics, _, targets) = verified
            .unwrap_or_else(|| {
                panic!(
                    "C6 continuation verifier rejected: {}",
                    prover_tx
                        .debug_first_canonical_divergence(&verifier_tx)
                        .unwrap_or_else(|| "equal transcript prefixes".to_owned())
                )
            });
        let verifier_snapshot = verifier_trace.finish().unwrap();
        cursor
            .finish_before_successor_root_with_identity(
                verifier_snapshot.identity,
                &mut verifier_tx,
            )
            .unwrap();
        assert_eq!(product_challenge, verifier_tx.challenge_fp2());
        let mut verifier_product_doms = Doms::new(layer_dom_base(255));
        let verifier_product_domain = verifier_product_doms.take(1);
        assert_eq!(product_domain, verifier_product_domain);
        let product_mask_key =
            primary_v.expand_product_mask_verifier_key(verifier_product_domain, product_keys.len());
        verifier_tx.append_fp2s("prod_check_m0_m1", &[product_proof.m0, product_proof.m1]);
        assert!(prod_batch_verify(
            &product_keys,
            product_mask_key,
            primary_v.delta,
            product_challenge,
            &product_proof,
        ));
        assert_eq!(verifier_out.weight_keys.len(), 96);
        assert_eq!(verifier_out.embed_keys.len(), 6);
        assert_eq!(verifier_metrics.corrected_targets, 576);
        assert_eq!(targets.len(), 576);
        assert_eq!(verifier_tx.ledger(), prover_tx.ledger());
    }

    /// Production-shaped C6 cache seam: all 12 prefill layers and all 12
    /// stacked-decode layers emit the fixed 576-target C6FT1 stream inline.
    /// The historical zero batch is deliberately not closed here: its
    /// base-only K/V auxiliary rows belong to the pending grand residual.
    #[cfg(feature = "c6-trace")]
    #[test]
    fn c6_response_wide_cache_targets_follow_the_complete_pooled_schedule() {
        use crate::c6_cache_fold::{
            begin_c6_cache_fold_trace, C6CacheFoldKind, C6CacheFoldParty,
            C6CacheFoldTargetInlineProver, C6CacheFoldTargetInlineVerifier,
            C6CacheFoldTargetPublicSchedule, C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES,
        };
        use crate::c6_residual::C6_RESIDUAL_TRACE_FIXTURE_LOCK;
        use crate::c6_source::{
            C6PairedSourceWitness, C6SourceCoordinate, C6SourceScheduleProverFollower,
            C6SourceScheduleVerifierFollower,
        };
        use volta_mac::{
            begin_c6_prover_trace, begin_c6_verifier_trace, compile_c6_operation_trace_for_role,
            derive_c6_runtime_instance_from_trace_diagnostic, finish_c6_prover_trace,
            finish_c6_verifier_trace, C6InstanceExtractionRole, C6TraceSourceManifest,
            CorrScheduleRole,
        };

        let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK.lock().unwrap();
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping C6 response-wide cache gate: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, q) = (4usize, 2usize);
        let prefill = volta_gpt2::forward_model(&model, t);
        let kv = prefill
            .layers
            .iter()
            .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
            .collect::<Vec<_>>();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (generated, _) = volta_gpt2::generate(&model, &mut cache, &prefill.logits, t, q);
        let mut sequence = model.p.tokens[..t].to_vec();
        sequence.extend_from_slice(&generated);
        let full = volta_gpt2::forward_model_tokens(&model, &sequence);
        let band = volta_gpt2::band_model_witness(&model, &full, t);
        let chunks_p = [ChunkRef { band: &band, seq: &sequence }];
        let chunks_v = [PrivateChunkPub { q, seq: &sequence }];

        let primary_seed = [0x61; 32];
        let secondary_seed = [0x62; 32];
        let transcript_seed = [0x63; 32];
        let statement_digest = [0x64; 32];
        let deltas = [
            Fp2::new(Fp::new(0x6101), Fp::new(0x6102)),
            Fp2::new(Fp::new(0x6201), Fp::new(0x6202)),
        ];
        let public_schedule = C6CacheFoldTargetPublicSchedule::new(
            (0..2 * L)
                .flat_map(|_| {
                    std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                        .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
                })
                .collect(),
        )
        .unwrap();

        let mut primary_stream = CorrelationStream::new(primary_seed);
        begin_c6_prover_trace().unwrap();
        primary_stream.enable_c6_operation_trace().unwrap();
        primary_stream.enable_c6_source_witness_collection().unwrap();
        let mut secondary_stream = CorrelationStream::new(secondary_seed);
        let mut prover_follower =
            C6SourceScheduleProverFollower::start(&mut secondary_stream).unwrap();
        let mut prover_tx = Transcript::new(transcript_seed);
        let mut target_builder = C6CacheFoldTargetInlineProver::start_public(
            statement_digest,
            public_schedule.clone(),
            &mut prover_tx,
        )
        .unwrap();
        let prover_trace_guard = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        let (proof, prover_out, products, grand_residual_roots, prover_metrics, append_sources) =
            prove_response_private_logits_c6_cache_inline(
                &model,
                &prefill,
                &chunks_p,
                &mut primary_stream,
                &mut secondary_stream,
                &mut prover_follower,
                &mut target_builder,
                &mut prover_tx,
            );
        assert!(append_sources.layers().iter().all(|layer| layer.row_count().unwrap() == t + q));
        let prover_trace = prover_trace_guard.finish().unwrap();
        let (target_frame, prover_fixed) = target_builder
            .finish_before_successor_root_with_identity(prover_trace.identity, &mut prover_tx)
            .unwrap();

        let mut product_doms_p = Doms::new(layer_dom_base(255));
        let chi = prover_tx.challenge_fp2();
        let product_domain = product_doms_p.take(1);
        let product_mask = primary_stream.draw_product_mask(product_domain, products.len());
        let product_proof = prod_batch_prover(&products, chi, product_mask, &mut prover_tx);
        grand_residual_roots.record_operation_trace_ownership().unwrap();
        let prover_operation_trace = finish_c6_prover_trace().unwrap();

        prover_follower.sync_primary(&primary_stream, &mut secondary_stream).unwrap();
        let primary_schedule = primary_stream.schedule_audit().unwrap();
        let primary_coordinate = C6SourceCoordinate::new(
            primary_stream.finish_c6_subfield_witness_collection().unwrap(),
            primary_stream.finish_c6_fullfield_witness_collection().unwrap(),
            &primary_schedule,
        )
        .unwrap();
        let secondary_coordinate = prover_follower
            .finish_coordinate(&primary_coordinate, &primary_schedule, &mut secondary_stream)
            .unwrap();
        let paired_sources = C6PairedSourceWitness::new(
            [[0x65; 32], [0x66; 32]],
            [primary_coordinate, secondary_coordinate],
            &primary_schedule,
            primary_schedule.digest,
        )
        .unwrap();
        let mut next_source = 0u64;
        let mut product_mask_sources = Vec::new();
        for draw in &primary_schedule.draws {
            if draw.role == CorrScheduleRole::ProductMask {
                product_mask_sources.push(u32::try_from(next_source).unwrap());
            }
            next_source += draw.count;
        }
        let source_manifest = C6TraceSourceManifest::new(
            u32::try_from(next_source).unwrap(),
            primary_schedule.digest,
            product_mask_sources,
        )
        .unwrap();
        assert_eq!(
            paired_sources.subfield_leaf_count() as u64,
            primary_schedule.counters.sub_corrs,
        );
        assert_eq!(
            paired_sources.fullfield_leaf_count() as u64,
            primary_schedule.counters.full_corrs,
        );
        let prover_compiled = compile_c6_operation_trace_for_role(
            &prover_operation_trace,
            &source_manifest,
            C6InstanceExtractionRole::Prover,
        )
        .unwrap();
        let prover_extraction =
            prover_compiled.instance_extraction.decode(prover_compiled.plan.topology).unwrap();
        let prover_runtime = derive_c6_runtime_instance_from_trace_diagnostic(
            &prover_operation_trace,
            &prover_compiled.artifact,
            &prover_extraction,
            prover_compiled.plan.instance,
        )
        .unwrap();
        let prover_installed = prover_compiled.artifact.install(&source_manifest).unwrap();
        let zero_weights = vec![Fp2::ONE; prover_installed.zero_roots().len()];
        let linear = crate::c6_residual::C6CompiledLinearResidual::compile(
            &prover_installed,
            &prover_extraction,
            &prover_runtime,
            &zero_weights,
        )
        .unwrap();
        let leaf_witness =
            linear.build_paired_residual_leaf_witness(&paired_sources, &primary_schedule).unwrap();
        let closure_evaluation = linear
            .evaluate_installed_paired_closure(
                &prover_installed,
                &prover_extraction,
                &prover_runtime,
                &paired_sources,
                &primary_schedule,
            )
            .unwrap();
        let closure_witness = closure_evaluation.closure();
        let auxiliary_witness = closure_witness.transpose_auxiliary_lanes().unwrap();

        let mut primary_verifier = VerifierCtx::new(primary_seed, deltas[0]);
        begin_c6_verifier_trace().unwrap();
        primary_verifier.enable_c6_operation_trace().unwrap();
        primary_verifier.enable_schedule_audit().unwrap();
        let mut secondary_verifier = VerifierCtx::new(secondary_seed, deltas[1]);
        let mut verifier_follower =
            C6SourceScheduleVerifierFollower::start(&mut secondary_verifier).unwrap();
        let mut verifier_tx = Transcript::new(transcript_seed);
        let mut target_cursor = C6CacheFoldTargetInlineVerifier::start_public(
            &target_frame,
            public_schedule,
            deltas,
            &mut verifier_tx,
        )
        .unwrap();
        let verifier_trace_guard = begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).unwrap();
        let (
            verifier_out,
            product_keys,
            verifier_residual_roots,
            verifier_metrics,
            verifier_append_sources,
            verifier_cache_targets,
        ) = verify_response_private_logits_c6_cache_inline(
            &model,
            t,
            &chunks_v,
            &proof,
            &mut primary_verifier,
            &mut secondary_verifier,
            &mut verifier_follower,
            &mut target_cursor,
            &mut verifier_tx,
        )
        .expect("C6 response-wide cache proof verifies");
        assert_eq!(verifier_cache_targets.len(), 4 * crate::c6_cache_fold::C6_CACHE_HEADS * L);
        assert_eq!(append_sources, verifier_append_sources);
        let verifier_trace = verifier_trace_guard.finish().unwrap();
        let verifier_fixed = target_cursor
            .finish_before_successor_root_with_identity(verifier_trace.identity, &mut verifier_tx)
            .unwrap();

        let mut product_doms_v = Doms::new(layer_dom_base(255));
        assert_eq!(chi, verifier_tx.challenge_fp2());
        assert_eq!(product_domain, product_doms_v.take(1));
        let product_mask_key =
            primary_verifier.expand_product_mask_verifier_key(product_domain, product_keys.len());
        assert!(
            prod_batch_verify(&product_keys, product_mask_key, deltas[0], chi, &product_proof,)
        );
        verifier_residual_roots.record_operation_trace_ownership().unwrap();
        let verifier_operation_trace = finish_c6_verifier_trace().unwrap();
        let verifier_compiled = compile_c6_operation_trace_for_role(
            &verifier_operation_trace,
            &source_manifest,
            C6InstanceExtractionRole::Verifier,
        )
        .unwrap();

        assert_eq!(prover_trace.identity, verifier_trace.identity);
        assert_eq!(prover_trace.records, verifier_trace.records);
        assert_eq!(prover_trace.factors, verifier_trace.factors);
        assert_eq!(prover_trace.identity.fold_count, 576);
        assert_eq!(prover_fixed, verifier_fixed);
        assert_eq!(
            target_frame.encode().unwrap().len() as u64,
            C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES
        );
        assert_eq!(prover_out.weight_claims.len(), 8 * L);
        assert_eq!(verifier_out.weight_keys.len(), 8 * L);
        assert_eq!(products.len(), product_keys.len());
        assert_eq!(grand_residual_roots.len(), verifier_residual_roots.len());
        assert_eq!(prover_compiled.plan.identity, verifier_compiled.plan.identity);
        assert_eq!(prover_compiled.plan.topology, verifier_compiled.plan.topology);
        assert_eq!(prover_compiled.plan.instance, verifier_compiled.plan.instance);
        assert_eq!(
            prover_compiled.plan.topology.zero_root_count as usize,
            grand_residual_roots.len(),
        );
        assert_eq!(leaf_witness.source_count(), prover_compiled.plan.topology.source_count);
        assert_eq!(
            closure_witness.census().product_closures,
            prover_compiled.plan.topology.product_closure_count,
        );
        assert_eq!(
            closure_witness.census().product_triples,
            prover_compiled.plan.topology.product_triple_count,
        );
        assert_eq!(
            closure_witness.census().zero_roots,
            prover_compiled.plan.topology.zero_root_count,
        );
        assert_eq!(closure_witness.program_digest(), prover_installed.artifact_digest());
        assert_eq!(
            auxiliary_witness.census().product_rows,
            prover_compiled.plan.topology.product_triple_count,
        );
        assert_eq!(
            auxiliary_witness.census().zero_rows,
            u64::from(prover_compiled.plan.topology.zero_root_count),
        );
        let closure_memory = closure_evaluation.memory_census();
        assert_eq!(
            closure_memory.canonical_nodes,
            u64::from(prover_compiled.plan.topology.canonical_node_count),
        );
        assert!(closure_memory.peak_live_node_values > 0);
        assert!(closure_memory.node_value_capacity >= closure_memory.peak_live_node_values);
        eprintln!(
            "C6 installed closure census: canonical_nodes={} peak_live={} working_heap_bytes={} dense_pair_bytes={} closure_values={}",
            closure_memory.canonical_nodes,
            closure_memory.peak_live_node_values,
            closure_memory.peak_working_heap_bytes,
            closure_memory.dense_paired_node_baseline_bytes,
            closure_witness.census().live_values,
        );

        let expected_source_cells = (2 * L * (2 * t + q) * D) as u64;
        let expected_auxiliary_cells = (2 * L * (t + q) * D) as u64;
        assert_eq!(prover_metrics.source_groups, (2 * 2 * L) as u64);
        assert_eq!(prover_metrics.corrected_targets, 576);
        assert_eq!(prover_metrics.source_cells, expected_source_cells);
        assert_eq!(prover_metrics.coefficient_applications, expected_source_cells);
        assert_eq!(prover_metrics.linear_auxiliary_source_cells, 0);
        assert_eq!(verifier_metrics.source_groups, prover_metrics.source_groups);
        assert_eq!(verifier_metrics.corrected_targets, prover_metrics.corrected_targets);
        assert_eq!(verifier_metrics.source_cells, expected_source_cells);
        assert_eq!(verifier_metrics.coefficient_applications, expected_source_cells);
        assert_eq!(verifier_metrics.linear_auxiliary_source_cells, expected_auxiliary_cells);

        verifier_follower.sync_primary(&primary_verifier, &mut secondary_verifier).unwrap();
        assert_eq!(Some(primary_schedule), primary_verifier.schedule_audit());
        assert_eq!(secondary_stream.schedule_audit(), secondary_verifier.schedule_audit());
        assert_eq!(
            verifier_tx.ledger().get("c6_cache_fold_target_corrections"),
            prover_tx.ledger().get("c6_cache_fold_target_corrections"),
        );
    }

    /// P6 response e2e: prefill (t=12) + ONE decode chunk (q=4) proven in one
    /// two-phase session — band layers over the cross-phase KV cache, band
    /// seams/embed/selection/final-LN/logits, stacked weight claims, one
    /// Π_Prod + one Π_ZeroBatch. Greedy argmax checks run inside
    /// `verify_response`.
    #[test]
    fn response_e2e_on_frozen_artifact() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping response_e2e_on_frozen_artifact: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, n_gen) = (12usize, 4usize);
        let wit0 = volta_gpt2::forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> =
            wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (gen, _rows) = volta_gpt2::generate(&model, &mut cache, &wit0.logits, t, n_gen);
        let mut seq: Vec<u32> = model.p.tokens[..t].to_vec();
        seq.extend_from_slice(&gen);
        let full = volta_gpt2::forward_model_tokens(&model, &seq);
        let band = volta_gpt2::band_model_witness(&model, &full, t);

        let seed = 201u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 9000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let chunks_p = [ChunkRef { band: &band, seq: &seq }];
        #[cfg(feature = "c6-trace")]
        let prover_cache_fold_guard = crate::c6_cache_fold::begin_c6_cache_fold_trace(
            crate::c6_cache_fold::C6CacheFoldParty::Prover,
        )
        .expect("start response prover cache-fold trace");
        let (mut proof, out, prod, mut zero) =
            prove_response(&model, &wit0, &chunks_p, &mut stream, &mut txp);
        #[cfg(feature = "c6-trace")]
        let prover_cache_fold_trace =
            prover_cache_fold_guard.finish().expect("finish response prover cache-fold trace");

        let chunks_v = [ChunkPub { q: n_gen, logits: &band.logits, seq: &seq }];

        // Structural failures are fail-closed at the public entry boundary:
        // no transcript charge/challenge and no correlation key may be used.
        assert_response_preflight_rejects_without_mutation(
            &model,
            t,
            &wit0.logits[..VOCAB - 1],
            &chunks_v,
            &proof,
            pcg_seed,
            delta,
            tx_seed,
        );
        let too_many_chunks: Vec<ChunkPub<'_>> = (0..=MAX_RESPONSE_CHUNKS)
            .map(|_| ChunkPub { q: n_gen, logits: &band.logits, seq: &seq })
            .collect();
        assert_response_preflight_rejects_without_mutation(
            &model,
            t,
            &wit0.logits,
            &too_many_chunks,
            &proof,
            pcg_seed,
            delta,
            tx_seed,
        );
        let removed_layer = proof.chunks[0].layers.pop().expect("test proof has twelve layers");
        let (mut recovery_vc, mut recovery_tx) = assert_response_preflight_rejects_without_mutation(
            &model,
            t,
            &wit0.logits,
            &chunks_v,
            &proof,
            pcg_seed,
            delta,
            tx_seed,
        );
        proof.chunks[0].layers.push(removed_layer);
        assert!(
            verify_response(
                &model,
                t,
                &wit0.logits,
                &chunks_v,
                &proof,
                &mut recovery_vc,
                &mut recovery_tx,
            )
            .is_some(),
            "a rejected malformed call must leave hidden challenge/correlation state reusable"
        );

        #[cfg(feature = "c6-trace")]
        let verifier_cache_fold_guard = crate::c6_cache_fold::begin_c6_cache_fold_trace(
            crate::c6_cache_fold::C6CacheFoldParty::Verifier,
        )
        .expect("start response verifier cache-fold trace");
        let (outv, kprod, mut kzero) =
            verify_response(&model, t, &wit0.logits, &chunks_v, &proof, &mut vc, &mut txv)
                .expect("response proof must verify");
        #[cfg(feature = "c6-trace")]
        let verifier_cache_fold_trace =
            verifier_cache_fold_guard.finish().expect("finish response verifier cache-fold trace");
        #[cfg(feature = "c6-trace")]
        {
            assert_eq!(prover_cache_fold_trace.identity, verifier_cache_fold_trace.identity);
            assert_eq!(prover_cache_fold_trace.records, verifier_cache_fold_trace.records);
            assert_eq!(prover_cache_fold_trace.factors, verifier_cache_fold_trace.factors);
            assert_eq!(prover_cache_fold_trace.identity.fold_count, 2 * L as u32 * 2 * H as u32);
            let expected_applications =
                2 * H as u64 * L as u64 * (t as u64 + (t + n_gen) as u64) * (D / H) as u64;
            assert_eq!(
                prover_cache_fold_trace.identity.coefficient_applications,
                expected_applications
            );
            let mut prefill_records = 0;
            let mut continuation_records = 0;
            for record in &prover_cache_fold_trace.records {
                if record.t0 == 0 {
                    prefill_records += 1;
                    assert_eq!((record.q, record.total_rows), (t as u32, t as u32));
                    assert_eq!(record.segment_rows, vec![t as u32]);
                    assert_eq!(record.schedule_section, record.model_layer);
                } else {
                    continuation_records += 1;
                    assert_eq!(
                        (record.t0, record.q, record.total_rows),
                        (t as u32, n_gen as u32, (t + n_gen) as u32)
                    );
                    assert_eq!(record.segment_rows, vec![t as u32, n_gen as u32]);
                    assert_eq!(record.schedule_section, 16 + record.model_layer);
                }
            }
            assert_eq!(prefill_records, L * 2 * H);
            assert_eq!(continuation_records, L * 2 * H);

            let scalar_roots =
                [Fp2::new(Fp::new(3), Fp::new(5)), Fp2::new(Fp::new(7), Fp::new(11))];
            let mut batch_digests = Vec::new();
            for scalar_root in scalar_roots {
                let prover_batch = crate::c6_cache_fold::compile_c6_cache_fold_scalar_batch(
                    &prover_cache_fold_trace,
                    scalar_root,
                )
                .expect("compile response prover cache-fold scalar batch");
                let verifier_batch = crate::c6_cache_fold::compile_c6_cache_fold_scalar_batch(
                    &verifier_cache_fold_trace,
                    scalar_root,
                )
                .expect("compile response verifier cache-fold scalar batch");
                assert_eq!(prover_batch.identity, verifier_batch.identity);
                assert_eq!(prover_batch.identity.fold_count, 576);
                assert_eq!(prover_batch.identity.factor_values, 44_928);
                assert_eq!(prover_batch.identity.coefficient_applications, expected_applications);
                batch_digests.push(prover_batch.identity.batch_digest);
            }
            assert_ne!(batch_digests[0], batch_digests[1]);
        }

        // Stacked weight claims: 48 prefill + 48 chunk, layer-major.
        assert_eq!(out.weight_claims.len(), 8 * L, "expected 96 stacked weight claims");
        assert_eq!(outv.weight_keys.len(), 8 * L);
        for idx in 0..8 * L {
            let l = (idx / 4) % L;
            let k4 = idx % 4;
            let w = &model.layers[l].0;
            let w_perm = cattn_permuted(&w.c_attn);
            let dims: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &w_perm),
                (D, D, &w.attn_proj),
                (D, DFF, &w.ffn_up),
                (DFF, D, &w.ffn_down),
            ];
            let (kk, n, mat) = dims[k4];
            let wc = &out.weight_claims[idx];
            assert_eq!(outv.weight_keys[idx].0, wc.point, "weight point mismatch at {idx}");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[idx].1.sub(VerifierKey::from_public(tv, delta)));
        }
        // Embedding claims: 3 prefill + 3 chunk, order [wte, wte, wpe] each.
        assert_eq!(out.embed_claims.len(), 6);
        assert_eq!(outv.embed_keys.len(), 6);
        for (i, wc) in out.embed_claims.iter().enumerate() {
            let (kk, n, mat): (usize, usize, &[i16]) =
                if i % 3 == 2 { (NPOS, D, &model.wpe) } else { (VOCAB, D, &model.wte) };
            assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n), "embed claim {i} point len");
            assert_eq!(outv.embed_keys[i].0, wc.point, "embed claim {i} point mismatch");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.embed_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        let mut domsp = Doms::new(layer_dom_base(255));
        let mut domsv = Doms::new(layer_dom_base(255));
        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_product_mask(md, prod.len());
        let k_mask = vc.expand_product_mask_verifier_key(md, kprod.len());
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        assert!(ok_prod && ok_zero, "response e2e must verify");
        eprintln!("response_e2e: t={t} q={n_gen} tokens {gen:?} accepted");
    }

    /// Production-size C3 L4 smoke. The 64x65,536 rectangle is deliberately
    /// not shrunk in tests; run this alongside the C3 gate suite.
    #[test]
    #[ignore = "production-size C3 private-argmax rectangle"]
    fn private_logits_response_e2e_and_wrong_token_rejects() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping private logits response e2e: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, q) = (2usize, 2usize);
        let prefill = forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> =
            prefill.layers.iter().map(|layer| (layer.k.as_slice(), layer.v.as_slice())).collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (generated, _) = volta_gpt2::generate(&model, &mut cache, &prefill.logits, t, q);
        let mut sequence = model.p.tokens[..t].to_vec();
        sequence.extend_from_slice(&generated);
        let full = volta_gpt2::forward_model_tokens(&model, &sequence);
        let band = volta_gpt2::band_model_witness(&model, &full, t);

        let pcg_seed = [0xC3; 32];
        let tx_seed = [0x3C; 32];
        let delta = Fp2::new(Fp::new(0xC301), Fp::new(0x4A11));
        let chunks = [ChunkRef { band: &band, seq: &sequence }];
        let prove_once = || {
            let mut stream = CorrelationStream::new(pcg_seed);
            let mut prover_tx = Transcript::new(tx_seed);
            let (proof, out, prod, zero) = prove_response_private_logits(
                &model,
                &prefill,
                &chunks,
                &mut stream,
                &mut prover_tx,
            );
            (proof, out, prod, zero, stream, prover_tx)
        };
        let (proof, out, prod, zero, mut stream, mut prover_tx) = prove_once();
        let private_core_bytes = prover_tx.total_bytes();
        assert!(proof.private_argmax.is_some());
        assert!(zero.iter().all(|claim| claim.x == Fp2::ZERO));
        assert!(prod.iter().all(|(a, b, c)| a.x * b.x == c.x));

        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let public = [PrivateChunkPub { q, seq: &sequence }];
        let (verified, key_prod, key_zero) = verify_response_private_logits(
            &model,
            t,
            &public,
            &proof,
            &mut verifier,
            &mut verifier_tx,
        )
        .expect("honest private-logit response verifies structurally");
        assert_eq!(out.weight_claims.len(), verified.weight_keys.len());
        assert_eq!(out.embed_claims.len(), verified.embed_keys.len());

        let mut wrong_sequence = sequence.clone();
        wrong_sequence[t] = (wrong_sequence[t] + 1) % VOCAB as u32;
        let (wrong_proof, _, wrong_prod_claims, wrong_zero_claims, mut wrong_stream, mut wrong_txp) =
            prove_once();
        let mut wrong_verifier = VerifierCtx::new(pcg_seed, delta);
        let mut wrong_tx = Transcript::new(tx_seed);
        let wrong_public = [PrivateChunkPub { q, seq: &wrong_sequence }];
        let (_, wrong_key_prod, wrong_key_zero) = verify_response_private_logits(
            &model,
            t,
            &wrong_public,
            &wrong_proof,
            &mut wrong_verifier,
            &mut wrong_tx,
        )
        .expect("wrong public token remains a cryptographic, not structural, rejection");
        assert_ne!(wrong_key_zero, key_zero, "public token must affect the zero constraints");
        let mut wrong_prover_doms = Doms::new(layer_dom_base(255));
        let mut wrong_verifier_doms = Doms::new(layer_dom_base(255));
        let wrong_challenge = wrong_txp.challenge_fp2();
        assert_eq!(wrong_challenge, wrong_tx.challenge_fp2());
        let wrong_product_domain = wrong_prover_doms.take(1);
        assert_eq!(wrong_product_domain, wrong_verifier_doms.take(1));
        let wrong_product_mask =
            wrong_stream.draw_product_mask(wrong_product_domain, wrong_prod_claims.len());
        let wrong_product_key = wrong_verifier
            .expand_product_mask_verifier_key(wrong_product_domain, wrong_key_prod.len());
        let wrong_product_proof = prod_batch_prover(
            &wrong_prod_claims,
            wrong_challenge,
            wrong_product_mask,
            &mut wrong_txp,
        );
        let wrong_product_ok = prod_batch_verify(
            &wrong_key_prod,
            wrong_product_key,
            delta,
            wrong_challenge,
            &wrong_product_proof,
        );
        let wrong_zero_domain = wrong_prover_doms.take(1);
        assert_eq!(wrong_zero_domain, wrong_verifier_doms.take(1));
        let wrong_zero_ok = zero_batch_exchange(
            &wrong_zero_claims,
            &wrong_key_zero,
            &mut wrong_stream,
            &mut wrong_verifier,
            wrong_zero_domain,
            &mut wrong_txp,
        );
        assert!(!(wrong_product_ok && wrong_zero_ok), "wrong token must be rejected at closure");

        let (
            mut forged_proof,
            _,
            forged_prod_claims,
            forged_zero_claims,
            mut forged_stream,
            mut forged_txp,
        ) = prove_once();
        forged_proof
            .private_argmax
            .as_mut()
            .expect("private argmax proof")
            .packed_bridge
            .limb_final_corrs[0] += Fp2::ONE;
        let mut forged_limb_verifier = VerifierCtx::new(pcg_seed, delta);
        let mut forged_limb_tx = Transcript::new(tx_seed);
        let (_, forged_key_prod, forged_key_zero) = verify_response_private_logits(
            &model,
            t,
            &public,
            &forged_proof,
            &mut forged_limb_verifier,
            &mut forged_limb_tx,
        )
        .expect("forged limb remains a cryptographic, not structural, rejection");
        assert_ne!(forged_key_zero, key_zero, "forged limb must alter the zero constraints");
        let mut forged_prover_doms = Doms::new(layer_dom_base(255));
        let mut forged_verifier_doms = Doms::new(layer_dom_base(255));
        let forged_challenge = forged_txp.challenge_fp2();
        assert_eq!(forged_challenge, forged_limb_tx.challenge_fp2());
        let forged_product_domain = forged_prover_doms.take(1);
        assert_eq!(forged_product_domain, forged_verifier_doms.take(1));
        let forged_product_mask =
            forged_stream.draw_product_mask(forged_product_domain, forged_prod_claims.len());
        let forged_product_key = forged_limb_verifier
            .expand_product_mask_verifier_key(forged_product_domain, forged_key_prod.len());
        let forged_product_proof = prod_batch_prover(
            &forged_prod_claims,
            forged_challenge,
            forged_product_mask,
            &mut forged_txp,
        );
        let forged_product_ok = prod_batch_verify(
            &forged_key_prod,
            forged_product_key,
            delta,
            forged_challenge,
            &forged_product_proof,
        );
        let forged_zero_domain = forged_prover_doms.take(1);
        assert_eq!(forged_zero_domain, forged_verifier_doms.take(1));
        let forged_zero_ok = zero_batch_exchange(
            &forged_zero_claims,
            &forged_key_zero,
            &mut forged_stream,
            &mut forged_limb_verifier,
            forged_zero_domain,
            &mut forged_txp,
        );
        assert!(!(forged_product_ok && forged_zero_ok), "forged limb must be rejected at closure");

        let mut legacy_stream = CorrelationStream::new(pcg_seed);
        let mut legacy_tx = Transcript::new(tx_seed);
        let (_, legacy_out, _, _) =
            prove_response(&model, &prefill, &chunks, &mut legacy_stream, &mut legacy_tx);
        let l4_bytes = private_core_bytes - legacy_tx.total_bytes();
        assert_eq!(l4_bytes, 57_840, "C3b test-geometry L4 transcript accounting changed");
        let l4_emults = out.ctr_instances.emult_equiv() - legacy_out.ctr_instances.emult_equiv();
        assert_eq!(l4_emults, 157_705_530.0, "C3b packed Range16 counter reference changed");
        eprintln!(
            "C3 L4 addition: {l4_bytes} transcript bytes, {l4_emults:.1} instance-counter E-mult equivalents"
        );

        let mut prover_doms = Doms::new(layer_dom_base(255));
        let mut verifier_doms = Doms::new(layer_dom_base(255));
        let challenge = prover_tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = prover_doms.take(1);
        assert_eq!(product_domain, verifier_doms.take(1));
        let product_mask = stream.draw_product_mask(product_domain, prod.len());
        let product_key = verifier.expand_product_mask_verifier_key(product_domain, key_prod.len());
        let product_proof = prod_batch_prover(&prod, challenge, product_mask, &mut prover_tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = prover_doms.take(1);
        assert_eq!(zero_domain, verifier_doms.take(1));
        assert!(zero_batch_exchange(
            &zero,
            &key_zero,
            &mut stream,
            &mut verifier,
            zero_domain,
            &mut prover_tx,
        ));
    }

    /// P6 anti-replay smoke: reusing another position's cache-row corrections
    /// (prefill rows replayed as the chunk's K rows, or two chunk K rows
    /// swapped) must be rejected — domains are position-separated.
    #[test]
    fn response_rejects_kv_replay() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping response_rejects_kv_replay: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, n_gen) = (12usize, 4usize);
        let wit0 = volta_gpt2::forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> =
            wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (gen, _rows) = volta_gpt2::generate(&model, &mut cache, &wit0.logits, t, n_gen);
        let mut seq: Vec<u32> = model.p.tokens[..t].to_vec();
        seq.extend_from_slice(&gen);
        let full = volta_gpt2::forward_model_tokens(&model, &seq);
        let band = volta_gpt2::band_model_witness(&model, &full, t);

        for case in 0..2 {
            let seed = 205 + case as u8;
            let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
            let mut stream = CorrelationStream::new([seed; 32]);
            let mut vc = VerifierCtx::new([seed; 32], delta);
            let mut txp = Transcript::new([seed ^ 0x5A; 32]);
            let mut txv = Transcript::new([seed ^ 0x5A; 32]);
            let chunks_p = [ChunkRef { band: &band, seq: &seq }];
            let (mut proof, _out, prod, mut zero) =
                prove_response(&model, &wit0, &chunks_p, &mut stream, &mut txp);
            match case {
                0 => {
                    // Replay: the chunk's K corrections replaced by the
                    // prefill's first q rows (cache-row reuse across phases).
                    let q = n_gen;
                    proof.chunks[0].layers[0]
                        .k_corr
                        .copy_from_slice(&proof.layers[0].k_corr[..q * D]);
                }
                _ => {
                    // Position swap within the chunk's own K rows.
                    let (a, b) = (0usize, 1usize);
                    for j in 0..D {
                        proof.chunks[0].layers[0].k_corr.swap(a * D + j, b * D + j);
                    }
                }
            }
            let chunks_v = [ChunkPub { q: n_gen, logits: &band.logits, seq: &seq }];
            let Some((_outv, kprod, kzero)) =
                verify_response(&model, t, &wit0.logits, &chunks_v, &proof, &mut vc, &mut txv)
            else {
                continue; // structural reject also counts
            };
            // Cheating-prover emulation: clear the prover's zero rows so the
            // MAC keys carry the discrepancy, then close the batches.
            for row in zero.iter_mut() {
                row.x = Fp2::ZERO;
            }
            let mut domsp = Doms::new(layer_dom_base(255));
            let mut domsv = Doms::new(layer_dom_base(255));
            let chi = txp.challenge_fp2();
            assert_eq!(chi, txv.challenge_fp2());
            let md = domsp.take(1);
            assert_eq!(md, domsv.take(1));
            let mask = stream.draw_product_mask(md, prod.len());
            let k_mask = vc.expand_product_mask_verifier_key(md, kprod.len());
            let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
            let _ = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
            let mz = domsp.take(1);
            assert_eq!(mz, domsv.take(1));
            let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
            assert!(!ok_zero, "K/V replay case {case} accepted");
        }
    }

    #[test]
    fn model_e2e_on_frozen_artifact() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping model_e2e_on_frozen_artifact: frozen artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        // Non-power-of-two on purpose: the padded-row/masked-wpe class of
        // bugs (selection identity) is invisible at t == t_pad.
        let t = 20usize;
        let wit = forward_model(&model, t);

        let seed = 200u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 9000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let t0 = std::time::Instant::now();
        let (proof, out, prod, mut zero) = prove_model(&model, &wit, &mut stream, &mut txp);
        let dt = t0.elapsed();

        let (outv, kprod, mut kzero) =
            verify_model(&model, t, &wit.logits, &proof, &mut vc, &mut txv)
                .expect("model proof must verify");

        // Resolve all 48 weight claims (layer-major, canonical per-layer order).
        assert_eq!(out.weight_claims.len(), 4 * L, "expected 48 weight claims");
        assert_eq!(outv.weight_keys.len(), 4 * L);
        for l in 0..L {
            let w = &model.layers[l].0;
            let w_perm = cattn_permuted(&w.c_attn);
            let dims: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &w_perm),
                (D, D, &w.attn_proj),
                (D, DFF, &w.ffn_up),
                (DFF, D, &w.ffn_down),
            ];
            for k in 0..4 {
                let idx = 4 * l + k;
                let (kk, n, mat) = dims[k];
                let wc = &out.weight_claims[idx];
                assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n));
                assert_eq!(
                    outv.weight_keys[idx].0, wc.point,
                    "weight point mismatch across parties, layer {l} slot {k}"
                );
                let tv = weight_true_eval(mat, kk, n, &wc.point);
                zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
                kzero.push(outv.weight_keys[idx].1.sub(VerifierKey::from_public(tv, delta)));
            }
        }

        // Resolve the 3 embedding-commitment claims [wte(logits),
        // wte(selection), wpe] against the true tensor evaluations —
        // test-only stand-in for the real `layout_gpt2_embed` PCS opening.
        assert_eq!(out.embed_claims.len(), 3);
        assert_eq!(outv.embed_keys.len(), 3);
        let embed_dims: [(usize, usize, &[i16]); 3] =
            [(VOCAB, D, &model.wte), (VOCAB, D, &model.wte), (NPOS, D, &model.wpe)];
        for (i, wc) in out.embed_claims.iter().enumerate() {
            let (kk, n, mat) = embed_dims[i];
            assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n), "embed claim {i} point len");
            assert_eq!(outv.embed_keys[i].0, wc.point, "embed claim {i} point mismatch");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.embed_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        // Close ONE Π_Prod batch + ONE Π_ZeroBatch over ALL accumulated rows.
        let mut domsp = Doms::new(layer_dom_base(255));
        let mut domsv = Doms::new(layer_dom_base(255));
        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_product_mask(md, prod.len());
        let k_mask = vc.expand_product_mask_verifier_key(md, kprod.len());
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        assert!(ok_prod && ok_zero, "model e2e must verify");

        eprintln!(
            "model_e2e_on_frozen_artifact: t={t} prove_model wall time = {:.3} s",
            dt.as_secs_f64()
        );
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_full_model_proof_matches_cpu_and_fault_is_rejected() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA full-proof differential: artifact not present");
            return;
        }
        let mut backend = match Backend::cuda_hybrid() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA full-proof differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let t = 3usize; // non-power-of-two padding path
        let wit = forward_model(&model, t);
        let pcg_seed = [231; 32];
        let tx_seed = [0xA7; 32];

        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let (_cpu_proof, cpu_out, cpu_prod, cpu_zero) =
            prove_model(&model, &wit, &mut cpu_stream, &mut cpu_tx);

        backend.begin_measurement().unwrap();
        let mut gpu_stream = CorrelationStream::new(pcg_seed);
        let mut gpu_tx = Transcript::new(tx_seed);
        let (gpu_proof, gpu_out, gpu_prod, gpu_zero) =
            prove_model_with_backend(&model, &wit, &mut gpu_stream, &mut gpu_tx, &mut backend);
        assert_eq!(gpu_out.weight_claims, cpu_out.weight_claims);
        assert_eq!(gpu_out.embed_claims, cpu_out.embed_claims);
        assert_eq!(gpu_out.bytes, cpu_out.bytes);
        assert_eq!(gpu_out.ctr_instances, cpu_out.ctr_instances);
        assert_eq!(gpu_out.ctr_other, cpu_out.ctr_other);
        assert_eq!(gpu_out.lookups, cpu_out.lookups);
        assert_eq!(gpu_out.corr_counters, cpu_out.corr_counters);
        assert_eq!(gpu_prod, cpu_prod);
        assert_eq!(gpu_zero, cpu_zero);
        assert_eq!(gpu_stream.counters, cpu_stream.counters);
        assert_eq!(gpu_tx.ledger(), cpu_tx.ledger());
        assert_eq!(gpu_tx.total_bytes(), cpu_tx.total_bytes());

        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txv = Transcript::new(tx_seed);
        assert!(verify_model(&model, t, &wit.logits, &gpu_proof, &mut vc, &mut txv).is_some());

        // Same persistent context, fresh protocol correlations. The proof
        // outputs stay deterministic, then a device-derived boundary
        // correction is faulted and the final zero batch must reject it.
        let mut fault_stream = CorrelationStream::new(pcg_seed);
        let mut fault_tx = Transcript::new(tx_seed);
        let (mut fault_proof, fault_out, fault_prod, fault_zero) =
            prove_model_with_backend(&model, &wit, &mut fault_stream, &mut fault_tx, &mut backend);
        assert_eq!(fault_out.weight_claims, gpu_out.weight_claims);
        assert_eq!(fault_out.embed_claims, gpu_out.embed_claims);
        assert_eq!(fault_prod, gpu_prod);
        assert_eq!(fault_zero, gpu_zero);
        fault_proof.layers[0].k_corr[0] ^= 1;

        let mut fault_vc = VerifierCtx::new(pcg_seed, delta);
        let mut fault_txv = Transcript::new(tx_seed);
        if let Some((_outv, kprod, kzero)) =
            verify_model(&model, t, &wit.logits, &fault_proof, &mut fault_vc, &mut fault_txv)
        {
            let mut domsp = Doms::new(layer_dom_base(255));
            let mut domsv = Doms::new(layer_dom_base(255));
            let chi = fault_tx.challenge_fp2();
            assert_eq!(chi, fault_txv.challenge_fp2());
            let md = domsp.take(1);
            assert_eq!(md, domsv.take(1));
            let mask = fault_stream.draw_product_mask(md, fault_prod.len());
            let k_mask = fault_vc.expand_product_mask_verifier_key(md, kprod.len());
            let pp = prod_batch_prover(&fault_prod, chi, mask, &mut fault_tx);
            let _ = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
            let mz = domsp.take(1);
            assert_eq!(mz, domsv.take(1));
            assert!(
                !zero_batch_exchange(
                    &fault_zero,
                    &kzero,
                    &mut fault_stream,
                    &mut fault_vc,
                    mz,
                    &mut fault_tx,
                ),
                "faulted CUDA-derived correction was accepted"
            );
        }
        let stats = backend.finish_measurement().unwrap();
        assert!(stats.operation(volta_accel::Operation::Logup).calls > 0);
        assert!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns > 0);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_full_model_matches_cpu_reuses_and_verifies() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident full-model differential: artifact not present");
            return;
        }
        let mut backend = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident full-model differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        // Non-power-of-two rows exercise model seams, embedding padding and
        // the duplicated final-LN bridge in the same full-proof gate.
        let t = 3usize;
        let tokens = model.p.tokens[..t].to_vec();
        let host_witness = forward_model(&model, t);
        let resident_model = upload_resident_model(&model, &mut backend).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut backend).unwrap();
        let resident_logits = backend
            .download_device(
                resident_witness.logits().buffer(),
                resident_witness.logits().offset(),
                VOCAB,
            )
            .unwrap();
        assert_eq!(resident_logits, host_witness.logits);
        let proof_error = backend.upload_new_device(&[0u32]).unwrap();
        let pcg_seed = [241; 32];
        let tx_seed = [0xB7; 32];

        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let (cpu_proof, cpu_out, cpu_prod, cpu_zero) =
            prove_model(&model, &host_witness, &mut cpu_stream, &mut cpu_tx);

        let run_resident = |backend: &mut Backend| {
            let mut stream = CorrelationStream::new(pcg_seed);
            let mut tx = Transcript::new(tx_seed);
            let result = prove_model_resident(
                &model,
                &resident_model,
                &resident_witness,
                &resident_logits,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut stream,
                &mut tx,
                backend,
            )
            .unwrap();
            (result, stream, tx)
        };

        backend.begin_measurement().unwrap();
        let ((proof, out, prod, zero), mut prover_stream, mut prover_tx) =
            run_resident(&mut backend);
        assert_eq!(proof, cpu_proof);
        assert_eq!(out.weight_claims, cpu_out.weight_claims);
        assert_eq!(out.embed_claims, cpu_out.embed_claims);
        assert_eq!(out.bytes, cpu_out.bytes);
        assert_eq!(out.ctr_instances, cpu_out.ctr_instances);
        assert_eq!(out.ctr_other, cpu_out.ctr_other);
        assert_eq!(out.lookups, cpu_out.lookups);
        assert_eq!(out.corr_counters, cpu_out.corr_counters);
        assert_eq!(prod, cpu_prod);
        assert_eq!(zero, cpu_zero);
        assert_eq!(prover_stream.counters, cpu_stream.counters);
        assert_eq!(prover_tx.ledger(), cpu_tx.ledger());
        assert_eq!(prover_tx.total_bytes(), cpu_tx.total_bytes());
        assert_eq!(backend.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let live_after_first = backend.stats().unwrap().live_device_bytes;
        let (
            (mut proof_reused, out_reused, prod_reused, zero_reused),
            mut fault_stream,
            mut fault_tx,
        ) = run_resident(&mut backend);
        assert_eq!(proof_reused, proof);
        assert_eq!(out_reused.weight_claims, out.weight_claims);
        assert_eq!(out_reused.embed_claims, out.embed_claims);
        assert_eq!(out_reused.bytes, out.bytes);
        assert_eq!(out_reused.ctr_instances, out.ctr_instances);
        assert_eq!(out_reused.ctr_other, out.ctr_other);
        assert_eq!(out_reused.lookups, out.lookups);
        assert_eq!(out_reused.corr_counters, out.corr_counters);
        assert_eq!(prod_reused, prod);
        assert_eq!(zero_reused, zero);
        assert_eq!(fault_stream.counters, prover_stream.counters);
        assert_eq!(fault_tx.ledger(), prover_tx.ledger());
        assert_eq!(fault_tx.total_bytes(), prover_tx.total_bytes());
        assert_eq!(
            backend.stats().unwrap().live_device_bytes,
            live_after_first,
            "resident full-model prover leaked across context reuse"
        );

        let delta = Fp2::new(Fp::new(0xE31C_5A17), Fp::new(0x1BAD_CAFE));
        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let (verifier_out, key_prod, mut key_zero) =
            verify_model(&model, t, &resident_logits, &proof, &mut verifier, &mut verifier_tx)
                .expect("resident full-model proof verifies structurally");
        let mut prover_zero = zero.clone();
        for layer in 0..L {
            let weights = &model.layers[layer].0;
            let permuted = cattn_permuted(&weights.c_attn);
            let dimensions: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &permuted),
                (D, D, &weights.attn_proj),
                (D, DFF, &weights.ffn_up),
                (DFF, D, &weights.ffn_down),
            ];
            for (slot, (rows, cols, matrix)) in dimensions.into_iter().enumerate() {
                let index = 4 * layer + slot;
                let value = weight_true_eval(matrix, rows, cols, &out.weight_claims[index].point);
                prover_zero
                    .push(out.weight_claims[index].value.sub(ProverAuthed::from_public(value)));
                key_zero.push(
                    verifier_out.weight_keys[index].1.sub(VerifierKey::from_public(value, delta)),
                );
            }
        }
        let embed_dimensions: [(usize, usize, &[i16]); 3] =
            [(VOCAB, D, &model.wte), (VOCAB, D, &model.wte), (NPOS, D, &model.wpe)];
        for (index, (rows, cols, matrix)) in embed_dimensions.into_iter().enumerate() {
            let value = weight_true_eval(matrix, rows, cols, &out.embed_claims[index].point);
            prover_zero.push(out.embed_claims[index].value.sub(ProverAuthed::from_public(value)));
            key_zero
                .push(verifier_out.embed_keys[index].1.sub(VerifierKey::from_public(value, delta)));
        }
        let mut prover_doms = Doms::new(layer_dom_base(255));
        let mut verifier_doms = Doms::new(layer_dom_base(255));
        let challenge = prover_tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = prover_doms.take(1);
        assert_eq!(product_domain, verifier_doms.take(1));
        let product_mask = prover_stream.draw_product_mask(product_domain, prod.len());
        let product_key = verifier.expand_product_mask_verifier_key(product_domain, key_prod.len());
        let product_proof = prod_batch_prover(&prod, challenge, product_mask, &mut prover_tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = prover_doms.take(1);
        assert_eq!(zero_domain, verifier_doms.take(1));
        assert!(zero_batch_exchange(
            &prover_zero,
            &key_zero,
            &mut prover_stream,
            &mut verifier,
            zero_domain,
            &mut prover_tx,
        ));

        // Fault a correction emitted from a resident boundary. Structural
        // verification may proceed, but the unchanged final zero batch must
        // reject the inconsistent MAC key.
        proof_reused.layers[0].k_corr[0] ^= 1;
        let mut fault_verifier = VerifierCtx::new(pcg_seed, delta);
        let mut fault_verifier_tx = Transcript::new(tx_seed);
        let fault_rejected = if let Some((_out, fault_key_prod, fault_key_zero)) = verify_model(
            &model,
            t,
            &resident_logits,
            &proof_reused,
            &mut fault_verifier,
            &mut fault_verifier_tx,
        ) {
            let mut prover_doms = Doms::new(layer_dom_base(255));
            let mut verifier_doms = Doms::new(layer_dom_base(255));
            let challenge = fault_tx.challenge_fp2();
            assert_eq!(challenge, fault_verifier_tx.challenge_fp2());
            let product_domain = prover_doms.take(1);
            assert_eq!(product_domain, verifier_doms.take(1));
            let product_mask = fault_stream.draw_product_mask(product_domain, prod_reused.len());
            let product_key =
                fault_verifier.expand_product_mask_verifier_key(product_domain, key_prod.len());
            let product_proof =
                prod_batch_prover(&prod_reused, challenge, product_mask, &mut fault_tx);
            let _ =
                prod_batch_verify(&fault_key_prod, product_key, delta, challenge, &product_proof);
            let zero_domain = prover_doms.take(1);
            assert_eq!(zero_domain, verifier_doms.take(1));
            !zero_batch_exchange(
                &zero_reused,
                &fault_key_zero,
                &mut fault_stream,
                &mut fault_verifier,
                zero_domain,
                &mut fault_tx,
            )
        } else {
            true
        };
        assert!(fault_rejected, "faulted CUDA-derived correction was accepted");
        let stats = backend.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        backend.free_device(proof_error).unwrap();
        resident_witness.free(&mut backend).unwrap();
        resident_model.free(&mut backend).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_response_matches_cpu_reuses_verifies_and_rejects_replay() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident response differential: artifact not present");
            return;
        }
        let mut backend = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident response differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let (t, q) = (3usize, 3usize);
        let host_prefill = forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> = host_prefill
            .layers
            .iter()
            .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
            .collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (generated, _) = volta_gpt2::generate(&model, &mut cache, &host_prefill.logits, t, q);
        let mut sequence = model.p.tokens[..t].to_vec();
        sequence.extend_from_slice(&generated);
        let host_source = volta_gpt2::forward_model_tokens(&model, &sequence);
        let host_band = volta_gpt2::band_model_witness(&model, &host_source, t);

        let resident_model = upload_resident_model(&model, &mut backend).unwrap();
        let resident_prefill =
            forward_model_tokens_resident(&resident_model, &sequence[..t], &mut backend).unwrap();
        let resident_source =
            forward_model_tokens_resident(&resident_model, &sequence, &mut backend).unwrap();
        let resident_band =
            band_model_witness_resident(&resident_model, &resident_source, t, q, &mut backend)
                .unwrap();
        let prefill_logits = backend
            .download_device(
                resident_prefill.logits().buffer(),
                resident_prefill.logits().offset(),
                VOCAB,
            )
            .unwrap();
        let band_logits = backend
            .download_device(
                resident_band.logits().buffer(),
                resident_band.logits().offset(),
                q * VOCAB,
            )
            .unwrap();
        assert_eq!(prefill_logits, host_prefill.logits);
        assert_eq!(band_logits, host_band.logits);
        let proof_error = backend.upload_new_device(&[0u32]).unwrap();
        let pcg_seed = [243; 32];
        let tx_seed = [0xBD; 32];

        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let cpu_chunks = [ChunkRef { band: &host_band, seq: &sequence }];
        let (cpu_proof, cpu_out, cpu_prod, cpu_zero) =
            prove_response(&model, &host_prefill, &cpu_chunks, &mut cpu_stream, &mut cpu_tx);

        let run_resident = |backend: &mut Backend| {
            let mut stream = CorrelationStream::new(pcg_seed);
            let mut tx = Transcript::new(tx_seed);
            let chunks =
                [ResidentChunkRef { band: &resident_band, logits: &band_logits, seq: &sequence }];
            let result = prove_response_resident(
                &model,
                &resident_model,
                &resident_prefill,
                &prefill_logits,
                &chunks,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut stream,
                &mut tx,
                backend,
            )
            .unwrap();
            (result, stream, tx)
        };

        backend.begin_measurement().unwrap();
        let ((proof, out, prod, zero), mut prover_stream, mut prover_tx) =
            run_resident(&mut backend);
        assert_eq!(proof, cpu_proof);
        assert_eq!(out.weight_claims, cpu_out.weight_claims);
        assert_eq!(out.embed_claims, cpu_out.embed_claims);
        assert_eq!(out.bytes, cpu_out.bytes);
        assert_eq!(out.ctr_instances, cpu_out.ctr_instances);
        assert_eq!(out.ctr_other, cpu_out.ctr_other);
        assert_eq!(out.lookups, cpu_out.lookups);
        assert_eq!(out.corr_counters, cpu_out.corr_counters);
        assert_eq!(out.chunk_p1_s.len(), 1);
        assert_eq!(out.chunk_p2_s.len(), 1);
        assert_eq!(prod, cpu_prod);
        assert_eq!(zero, cpu_zero);
        assert_eq!(prover_stream.counters, cpu_stream.counters);
        assert_eq!(prover_tx.ledger(), cpu_tx.ledger());
        assert_eq!(prover_tx.total_bytes(), cpu_tx.total_bytes());
        assert_eq!(backend.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let live_after_first = backend.stats().unwrap().live_device_bytes;
        let (
            (mut replay_proof, replay_out, replay_prod, replay_zero),
            mut replay_stream,
            mut replay_tx,
        ) = run_resident(&mut backend);
        assert_eq!(replay_proof, proof);
        assert_eq!(replay_out.weight_claims, out.weight_claims);
        assert_eq!(replay_out.embed_claims, out.embed_claims);
        assert_eq!(replay_out.bytes, out.bytes);
        assert_eq!(replay_out.ctr_instances, out.ctr_instances);
        assert_eq!(replay_out.ctr_other, out.ctr_other);
        assert_eq!(replay_out.lookups, out.lookups);
        assert_eq!(replay_out.corr_counters, out.corr_counters);
        assert_eq!(replay_prod, prod);
        assert_eq!(replay_zero, zero);
        assert_eq!(replay_stream.counters, prover_stream.counters);
        assert_eq!(replay_tx.ledger(), prover_tx.ledger());
        assert_eq!(replay_tx.total_bytes(), prover_tx.total_bytes());
        assert_eq!(
            backend.stats().unwrap().live_device_bytes,
            live_after_first,
            "resident response prover leaked across context reuse"
        );

        let delta = Fp2::new(Fp::new(0xF31C_5A17), Fp::new(0x3BAD_CAFE));
        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let public_chunks = [ChunkPub { q, logits: &band_logits, seq: &sequence }];
        let (verifier_out, key_prod, mut key_zero) = verify_response(
            &model,
            t,
            &prefill_logits,
            &public_chunks,
            &proof,
            &mut verifier,
            &mut verifier_tx,
        )
        .expect("resident response proof verifies structurally and passes public greedy checks");
        let mut prover_zero = zero.clone();
        assert_eq!(out.weight_claims.len(), 8 * L);
        assert_eq!(verifier_out.weight_keys.len(), 8 * L);
        for index in 0..8 * L {
            let layer = (index / 4) % L;
            let slot = index % 4;
            let weights = &model.layers[layer].0;
            let permuted = cattn_permuted(&weights.c_attn);
            let dimensions: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &permuted),
                (D, D, &weights.attn_proj),
                (D, DFF, &weights.ffn_up),
                (DFF, D, &weights.ffn_down),
            ];
            let (rows, cols, matrix) = dimensions[slot];
            assert_eq!(verifier_out.weight_keys[index].0, out.weight_claims[index].point);
            let value = weight_true_eval(matrix, rows, cols, &out.weight_claims[index].point);
            prover_zero.push(out.weight_claims[index].value.sub(ProverAuthed::from_public(value)));
            key_zero.push(
                verifier_out.weight_keys[index].1.sub(VerifierKey::from_public(value, delta)),
            );
        }
        assert_eq!(out.embed_claims.len(), 6);
        assert_eq!(verifier_out.embed_keys.len(), 6);
        for (index, claim) in out.embed_claims.iter().enumerate() {
            let (rows, cols, matrix): (usize, usize, &[i16]) =
                if index % 3 == 2 { (NPOS, D, &model.wpe) } else { (VOCAB, D, &model.wte) };
            assert_eq!(verifier_out.embed_keys[index].0, claim.point);
            let value = weight_true_eval(matrix, rows, cols, &claim.point);
            prover_zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            key_zero
                .push(verifier_out.embed_keys[index].1.sub(VerifierKey::from_public(value, delta)));
        }
        let mut prover_doms = Doms::new(layer_dom_base(255));
        let mut verifier_doms = Doms::new(layer_dom_base(255));
        let challenge = prover_tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = prover_doms.take(1);
        assert_eq!(product_domain, verifier_doms.take(1));
        let product_mask = prover_stream.draw_product_mask(product_domain, prod.len());
        let product_key = verifier.expand_product_mask_verifier_key(product_domain, key_prod.len());
        let product_proof = prod_batch_prover(&prod, challenge, product_mask, &mut prover_tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = prover_doms.take(1);
        assert_eq!(zero_domain, verifier_doms.take(1));
        assert!(zero_batch_exchange(
            &prover_zero,
            &key_zero,
            &mut prover_stream,
            &mut verifier,
            zero_domain,
            &mut prover_tx,
        ));

        replay_proof.chunks[0].layers[0].k_corr[0] ^= 1;
        let mut replay_verifier = VerifierCtx::new(pcg_seed, delta);
        let mut replay_verifier_tx = Transcript::new(tx_seed);
        let replay_rejected = if let Some((_out, replay_key_prod, replay_key_zero)) =
            verify_response(
                &model,
                t,
                &prefill_logits,
                &public_chunks,
                &replay_proof,
                &mut replay_verifier,
                &mut replay_verifier_tx,
            ) {
            let mut prover_doms = Doms::new(layer_dom_base(255));
            let mut verifier_doms = Doms::new(layer_dom_base(255));
            let challenge = replay_tx.challenge_fp2();
            assert_eq!(challenge, replay_verifier_tx.challenge_fp2());
            let product_domain = prover_doms.take(1);
            assert_eq!(product_domain, verifier_doms.take(1));
            let product_mask = replay_stream.draw_product_mask(product_domain, replay_prod.len());
            let product_key =
                replay_verifier.expand_product_mask_verifier_key(product_domain, key_prod.len());
            let product_proof =
                prod_batch_prover(&replay_prod, challenge, product_mask, &mut replay_tx);
            let _ =
                prod_batch_verify(&replay_key_prod, product_key, delta, challenge, &product_proof);
            let zero_domain = prover_doms.take(1);
            assert_eq!(zero_domain, verifier_doms.take(1));
            !zero_batch_exchange(
                &replay_zero,
                &replay_key_zero,
                &mut replay_stream,
                &mut replay_verifier,
                zero_domain,
                &mut replay_tx,
            )
        } else {
            true
        };
        assert!(replay_rejected, "replayed resident chunk K correction was accepted");

        let stats = backend.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        backend.free_device(proof_error).unwrap();
        resident_band.free(&mut backend).unwrap();
        resident_source.free(&mut backend).unwrap();
        resident_prefill.free(&mut backend).unwrap();
        resident_model.free(&mut backend).unwrap();
    }
}

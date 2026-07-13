//! P4 steps 5+6 — fused-block proofs for one transformer layer: the FFN half
//! (residual → requant_ffn_down → GEMM-down → gelu → requant_ffn_up →
//! GEMM-up → LN2 → boundary) and the attention half (residual → out-proj →
//! requant_av → per-head w·V → hadamard/softmax → exp → per-head QKᵀ →
//! requant_qkv → c_attn → LN1 → boundary), plus the whole-layer orchestration
//! `prove_layer`/`verify_layer` (boundary auth hoisted, exactly ONE Π_Prod
//! batch + ONE Π_ZeroBatch closed by the caller over the accumulated rows).
//! No element-wise authentication of internal wires: chains run in reverse
//! dataflow order (LogUp aux folding / chained-GEMM claim0 transport /
//! streamed boundary MAC openings).
//!
//! Layout conventions:
//! * T×d wires: zero-padded `2^pad_bits(d)`-column, `2^pad_bits(T)`-row MLE
//!   domain, column vars LSB, so an instance point `pt` splits as
//!   `(r_j = cols ‖ r_i = rows)` and feeds the chained GEMMs directly.
//! * Rectangular per-head attention wires (scores_q / exp_out / softmax_w):
//!   the causal-packed witness (packed idx = h·caus + i(i+1)/2 + j) is
//!   expanded to `h_pad(16) × T_pad × T_pad` with within-head column vars
//!   LSB, then row vars, then the 4 head bits on TOP:
//!   `y = j + i·T_pad + h·T_pad²`, domain `2^(4 + 2·pad_bits(T))`.
//! * qkv output wire: the c_attn output concat(q, k, v) lives on a PERMUTED
//!   padded T×4096 domain: col' = third·1024 + head·64 + l (natural col
//!   j = third·768 + head·64 + l), so `l` = bits 0..5, head = bits 6..9,
//!   third = bits 10..11 — boolean coordinates select the q/k/v thirds. The
//!   c_attn weight claim consequently lives on the SAME permuted 1024×4096
//!   tensor (`cattn_permuted`) — the P4 PCS layer commit must use it (same
//!   2^22 size as the natural padding, just a column permutation).
//!
//! **Padding** (lookup columns are padded with VALID table elements):
//! * range instances: `rem_pad = 2^(s−1)`, `out_pad = 0` ⇒ transported
//!   `acc_pad = 0` — EXCEPT requant_scores, whose out column is the shared
//!   `scores_q_rect` wire padded with the exp pad INPUT (see below); its
//!   implied non-causal accumulator `2^s·pad_in` is removed by a public
//!   pad-mask correction, and the true above-diagonal QKᵀ accumulators are
//!   element-wise authenticated and added back (they exist mathematically
//!   but are discarded by the causal forward).
//! * exp pair: pad pair `(pad_in, 0)` where `pad_in` is the LEAST exp-LUT
//!   index with output exactly 0 (asserted to exist — exp saturates to 0 for
//!   very negative inputs). Rectangular row sums therefore equal the causal
//!   row sums, so `deñoms(ρ) = 2^rb·ẽxp(½…½, ρ)` holds with NO pad-sum
//!   correction.
//! * softmax_recip pair: pad pair `(0, recip[0])`; the authenticated `recips`
//!   ROW TABLE is padded with `recip[0]` (mirrors ln_rsqrt) — its pad rows
//!   are killed in the hadamard by the zero exp factor.
//! * gelu pair `(0, gelu[0]=0)`, ln_rsqrt pair `(0, ln_rsqrt[0])` as before.
//!
//! **P4-DEVIATION(ln-stats)** (pre-registered, applies to LN1 AND LN2): the
//! LN statistics relations (`d·mean − rowsum` rounding, variance
//! sum-of-squares, `rsqrt_in = var >> ln_var_shift`) are NOT proved in-field;
//! `mean`, `var`, `rsqrt_in` are bound by element-wise authentication and
//! checked prover-side (`assert_ln_stats`). What IS proved: the ln_rsqrt LUT
//! membership, the LN affine `acc = (x−mean)∘(rsqrt·gain) + bias·2^s`
//! (hadamard), and the ln_norm_requant range instance chaining into the
//! upstream GEMM. **P4-DEVIATION(recip-in)** (same pattern, pre-registered
//! here): `recip_in = denoms >> recip_den_shift` (floor shift, exactly the
//! forward's computation) is bound only by element-wise authentication of
//! both vectors plus a prover-side assert; the softmax_recip LUT membership
//! and the `denoms = exp row sums` relation ARE proved in-field.
//!
//! LN gains/biases are PUBLIC in P4 (not among the 4 committed tensors).
//! Exp above the diagonal: `softmax_w_rect = 0` is proved directly by the
//! causal sumcheck; `exp_rect` above the diagonal is then forced to 0 whp by
//! the hadamard (`w = e·recip`, recip ≠ 0 — reciprocal LUT outputs are
//! positive) and independently pinned by the row-sum identity against the
//! authenticated denominators.

use crate::gemm_proof::{
    finalize_gemm_act_chained, finalize_verify_gemm_act_chained, prepare_gemm_act_chained_batch,
    prepare_gemm_act_chained_resident_batch, prove_gemm_committed_chained,
    prove_gemm_committed_chained_resident, verify_gemm_committed_chained, ChainDoms,
    ChainedGemmProof, GemmActRoundOutput, ProveTimings, WeightClaimP, WireKey, WireOut,
};
use crate::hadamard::{
    hadamard_prove, hadamard_prove_resident, hadamard_verify, HadamardDoms, HadamardProof,
};
use crate::logup::{
    blind_instance_prove, blind_instance_prove_resident, blind_instance_prove_with_backend,
    blind_instance_verify, eval_mle_counted, table_side_prove, table_side_prove_resident,
    table_side_prove_with_backend, table_side_verify, BlindInstance, Counters, Doms, InstanceOutP,
    InstanceOutV, LeafAuxClaim, TableKey, TableSideProof,
};
use crate::mle::{eq_vec, eval_mle};
use crate::schedule::{RoundFamily, SchedulePlan, ScheduleSite, SiteId};
use crate::sumcheck_blind::{
    blind_prove, blind_prove_batch, blind_prove_resident, blind_prove_resident_batch, blind_verify,
    blind_verify_batch, BlindSumcheckBatchVerifyJob, BlindSumcheckProof,
    BlindSumcheckResidentBatchJob, BlindSumcheckResidentBatchOutput, ResidentBlindBatchError,
};
use crate::thaler::pad_bits;
use std::collections::{BTreeMap, BTreeSet};
use volta_accel::{
    AccelError, Backend, DeviceAttentionProofWires, DeviceBuffer, DeviceLookupColumns, DeviceSlice,
    ResidentBaseElement, ResidentMatrixElement,
};
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    gemm_i64, GemmBiases, LayerI16Field, LayerI64Field, LayerWeightField, LayerWeights,
    LayerWitness, Luts, ModelWeightField, ResidentGpt2Model, ResidentLayerView, D, DFF, DH, H,
};
use volta_mac::{
    auth_verifier, CorrIndex, CorrelationStream, ProverAuthed, SubMaskRowsReservation, Transcript,
    VerifierCtx, VerifierKey,
};

/// Padded head count (4 head bits).
const H_PAD: usize = 16;
const HEAD_BITS: usize = 4;

#[derive(Clone, Copy)]
#[repr(u32)]
enum AttentionActRole {
    WeightValue = 1,
    QueryKey = 2,
}

/// Stable public identity for the two natural 12-head attention cohorts.
/// `section=layer`; `lane=pos0 | role | head`.  No allocation cursor,
/// completion order, or private geometry participates in the identity.
fn attention_act_site_id(pos0: usize, layer: u16, role: AttentionActRole, head: usize) -> SiteId {
    assert!(pos0 <= 0x00ff_ffff, "attention position does not fit scheduled SiteId");
    assert!(head < 16, "attention head does not fit scheduled SiteId");
    let lane = ((pos0 as u32) << 8) | ((role as u32) << 4) | head as u32;
    SiteId::new(layer, RoundFamily::BlindProduct, lane)
}

fn attention_layer_from_doms(doms: &Doms) -> u16 {
    // CorrIndex packs layer in bits 48..55 of every layer-scoped domain.
    ((doms.cursor() >> 48) & 0xff) as u16
}

fn attention_act_schedule(
    pos0: usize,
    layer: u16,
    role: AttentionActRole,
    rounds: usize,
    doms: &[ChainDoms],
) -> SchedulePlan {
    assert_eq!(doms.len(), H, "one chained domain allocation per public head");
    SchedulePlan::new(
        doms.iter()
            .enumerate()
            .map(|(head, chain)| ScheduleSite {
                id: attention_act_site_id(pos0, layer, role, head),
                rounds,
                mask_dom_base: chain.round_masks,
                mask_dom_span: rounds as u64,
            })
            .collect(),
    )
    .expect("public attention cohort schedule must be valid")
}

fn free_attention_resident_jobs(
    backend: &mut Backend,
    jobs: Vec<BlindSumcheckResidentBatchJob>,
) -> Result<(), AccelError> {
    let mut first = None;
    for job in jobs {
        if let Err(error) = backend.free_device(job.a) {
            first.get_or_insert(error);
        }
        if let Err(error) = backend.free_device(job.b) {
            first.get_or_insert(error);
        }
    }
    first.map_or(Ok(()), Err)
}

fn prove_attention_resident_round_batch(
    plan: &SchedulePlan,
    jobs: Vec<BlindSumcheckResidentBatchJob>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<Vec<BlindSumcheckResidentBatchOutput>, AccelError> {
    // Every job above was allocated through this exact context. Establish
    // that ownership invariant before transferring the vector; the lower
    // level API retains its recoverable WrongBackend contract for callers
    // that accept arbitrary handles.
    assert!(
        jobs.iter().all(|job| job.a.is_owned_by(backend) && job.b.is_owned_by(backend)),
        "attention resident cohort assembled a foreign device buffer"
    );
    match blind_prove_resident_batch(plan, jobs, stream, tx, backend) {
        Ok(outputs) => Ok(outputs),
        Err(ResidentBlindBatchError::Accel(error)) => Err(error),
        Err(ResidentBlindBatchError::Correlation(_)) => Err(AccelError::InvalidInput(
            "resident attention cohort correlation reservation failed",
        )),
        Err(ResidentBlindBatchError::Schedule(_)) => Err(AccelError::InvalidInput(
            "resident attention cohort does not match its sealed schedule",
        )),
        Err(ResidentBlindBatchError::WrongBackend { .. }) => {
            unreachable!("ownership changed after the attention cohort preflight")
        }
    }
}

// ---------------------------------------------------------------------------
// Block contexts (shared by both chains and the layer orchestration)
// ---------------------------------------------------------------------------

/// Layer-scoped base for the block's sequential one-time domains.
pub fn layer_dom_base(layer: u8) -> u64 {
    CorrIndex { session: 1, layer, head: 0, tensor: 0x20, row: 0 }.domain()
}

// ---------------------------------------------------------------------------
// P6 shared-α table bank: one multiset argument per table CONTENT per model
// ---------------------------------------------------------------------------

/// The proof of one table content's closure (per model): its global
/// multiplicity-vector corrections + the shared table side (table fraction
/// tree, fraction-sum chain over all sites, root cross-check).
#[derive(Debug, PartialEq, Eq)]
pub struct TableCloseProof {
    pub key: TableKey,
    pub mult_corr: Vec<u64>,
    pub side: TableSideProof,
}

/// Prover-side model-wide table bank. Phase 1 accumulates one global
/// multiplicity vector per content (`add_mult`); `finalize` authenticates
/// every vector and draws one α per content (strictly after every phase-1
/// binding); phase 2 instances fetch their α and register their lookup-tree
/// root fractions; `close` runs one table side per content.
#[derive(Default)]
pub struct TableBankP {
    mult: BTreeMap<TableKey, Vec<u32>>,
    resident_mult: BTreeMap<TableKey, DeviceBuffer<u32>>,
    alphas: BTreeMap<TableKey, Fp2>,
    roots: BTreeMap<TableKey, Vec<(ProverAuthed, ProverAuthed)>>,
    scheduled_sites: BTreeMap<TableKey, BTreeSet<SiteId>>,
    scheduled_roots: BTreeMap<(TableKey, SiteId), (ProverAuthed, ProverAuthed)>,
    auth: BTreeMap<TableKey, (u64, Vec<Fp>, Vec<u64>)>,
    resident_auth: BTreeMap<TableKey, (u64, Vec<u64>)>,
    finalized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableBankSiteError {
    NotFinalized,
    UnknownContent(TableKey),
    EmptyRegistration(TableKey),
    DuplicateRegistration(TableKey),
    LegacyRootsPresent(TableKey),
    UnregisteredSite { key: TableKey, site: SiteId },
    DuplicateSite { key: TableKey, site: SiteId },
    MissingSite { key: TableKey, site: SiteId },
}

/// The length of a content's table (= multiplicity-vector length).
pub fn table_len(key: TableKey) -> usize {
    match key {
        TableKey::Range(s) => 1usize << s,
        _ => 1usize << 16,
    }
}

/// Table values of a content (pair LUTs are global per model — P5 froze one
/// LUT set; per-layer Luts clones only override shifts).
pub fn table_vals(key: TableKey, luts: &Luts) -> Vec<Fp> {
    match key {
        TableKey::Range(s) => range_table(s),
        TableKey::Exp => pair_table(&luts.exp, true),
        TableKey::Gelu => pair_table(&luts.gelu, true),
        TableKey::LnRsqrt => pair_table(&luts.ln_rsqrt, false),
        TableKey::SoftmaxRecip => pair_table(&luts.softmax_recip, false),
    }
}

/// The content key(s) of a requant range site: single table for s ≤ 16,
/// (stage-2, stage-1) contents for a chained site.
pub fn range_keys(shift: u32) -> (TableKey, Option<TableKey>) {
    if shift <= 16 {
        (TableKey::Range(shift), None)
    } else {
        (TableKey::Range(16), Some(TableKey::Range(shift - 16)))
    }
}

impl TableBankP {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate a site's multiplicities into the content's global vector.
    pub fn add_mult(&mut self, key: TableKey, m: &[u32]) {
        assert!(!self.finalized, "phase 1 is closed — α already drawn");
        assert!(
            self.resident_mult.is_empty(),
            "host and resident multiplicity ownership cannot be mixed"
        );
        assert_eq!(m.len(), table_len(key), "site multiplicity length mismatch for {key:?}");
        let g = self.mult.entry(key).or_insert_with(|| vec![0u32; m.len()]);
        for (a, &b) in g.iter_mut().zip(m) {
            *a += b;
        }
    }

    /// Consume one device-owned site histogram into the model-wide global
    /// multiplicity vector. Equal content keys are accumulated in place and
    /// the temporary input allocation is released exactly once.
    pub fn add_mult_resident(
        &mut self,
        key: TableKey,
        mult: DeviceBuffer<u32>,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        if self.finalized || !self.mult.is_empty() || mult.len() != table_len(key) {
            let _ = backend.free_device(mult);
            return Err(AccelError::InvalidInput("invalid resident table multiplicity"));
        }
        if let Some(global) = self.resident_mult.get(&key) {
            let add_result = backend.u32_add_inplace_device(
                DeviceSlice::new(global, 0, global.len()).expect("whole global multiplicity"),
                DeviceSlice::new(&mult, 0, mult.len()).expect("whole site multiplicity"),
            );
            let free_result = backend.free_device(mult);
            return match (add_result, free_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), _) | (_, Err(error)) => Err(error),
            };
        }
        self.resident_mult.insert(key, mult);
        Ok(())
    }

    /// End of phase 1: authenticate every content's global vector, then draw
    /// one α per content (canonical `TableKey` order on both sides).
    pub fn finalize(
        &mut self,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
        doms: &mut Doms,
    ) {
        assert!(!self.finalized);
        assert!(
            self.resident_mult.is_empty(),
            "host finalize cannot consume resident multiplicities"
        );
        for (key, m) in &self.mult {
            let fp = fp_vec_u32(m);
            let dom = doms.take(1);
            let corr = auth_fp_vec_p(stream, tx, dom, &fp);
            self.auth.insert(*key, (dom, fp, corr));
        }
        for key in self.mult.keys() {
            self.alphas.insert(*key, tx.challenge_fp2());
        }
        self.finalized = true;
    }

    /// Resident phase-1 closure. Mock-PCG masks remain a replaceable host
    /// correlation-provider seam; only masks travel H2D and the existing
    /// correction message travels D2H. Multiplicity values stay resident.
    pub fn finalize_resident(
        &mut self,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
        doms: &mut Doms,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        if self.finalized || !self.mult.is_empty() || self.resident_mult.is_empty() {
            self.free_resident_multiplicities(backend);
            return Err(AccelError::InvalidInput("invalid resident table-bank finalize state"));
        }
        let result = (|| {
            for (key, mult) in &self.resident_mult {
                let dom = doms.take(1);
                let corr = auth_device_vector_p(
                    stream,
                    tx,
                    dom,
                    DeviceSlice::new(mult, 0, mult.len()).expect("whole resident multiplicity"),
                    backend,
                )?;
                self.resident_auth.insert(*key, (dom, corr));
            }
            for key in self.resident_mult.keys() {
                self.alphas.insert(*key, tx.challenge_fp2());
            }
            self.finalized = true;
            Ok(())
        })();
        if result.is_err() {
            self.free_resident_multiplicities(backend);
            self.resident_auth.clear();
            self.alphas.clear();
        }
        result
    }

    pub fn alpha(&self, key: TableKey) -> Fp2 {
        *self.alphas.get(&key).unwrap_or_else(|| panic!("no α for content {key:?}"))
    }

    pub fn push_roots(&mut self, key: TableKey, roots: (ProverAuthed, ProverAuthed)) {
        assert!(
            !self.scheduled_sites.contains_key(&key),
            "table content {key:?} is atomically scheduled; legacy root insertion is forbidden"
        );
        self.roots.entry(key).or_default().push(roots);
    }

    /// Seal the exact public site membership for one table content. Scheduled
    /// roots are keyed by `(TableKey, SiteId)` and later materialized only in
    /// canonical `SiteId` order; completion order never enters the fraction
    /// sum chain.
    pub fn register_scheduled_sites(
        &mut self,
        key: TableKey,
        sites: impl IntoIterator<Item = SiteId>,
    ) -> Result<(), TableBankSiteError> {
        if !self.finalized {
            return Err(TableBankSiteError::NotFinalized);
        }
        if !self.alphas.contains_key(&key) {
            return Err(TableBankSiteError::UnknownContent(key));
        }
        if self.scheduled_sites.contains_key(&key) {
            return Err(TableBankSiteError::DuplicateRegistration(key));
        }
        if self.roots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        let mut registered = BTreeSet::new();
        for site in sites {
            if !registered.insert(site) {
                return Err(TableBankSiteError::DuplicateSite { key, site });
            }
        }
        let sites = registered;
        if sites.is_empty() {
            return Err(TableBankSiteError::EmptyRegistration(key));
        }
        self.scheduled_sites.insert(key, sites);
        Ok(())
    }

    /// Read-only admission check for one scheduled cohort. Once this passes,
    /// its root insertions cannot fail unless code in the same thread mutates
    /// the bank between the preflight and the inserts.
    pub(crate) fn preflight_scheduled_roots(
        &self,
        key: TableKey,
        sites: impl IntoIterator<Item = SiteId>,
    ) -> Result<(), TableBankSiteError> {
        if !self.finalized {
            return Err(TableBankSiteError::NotFinalized);
        }
        if !self.alphas.contains_key(&key) {
            return Err(TableBankSiteError::UnknownContent(key));
        }
        if self.roots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        let mut cohort = BTreeSet::new();
        for site in sites {
            if !cohort.insert(site) || self.scheduled_roots.contains_key(&(key, site)) {
                return Err(TableBankSiteError::DuplicateSite { key, site });
            }
            if !self.scheduled_sites.get(&key).is_some_and(|registered| registered.contains(&site))
            {
                return Err(TableBankSiteError::UnregisteredSite { key, site });
            }
        }
        if cohort.is_empty() {
            return Err(TableBankSiteError::EmptyRegistration(key));
        }
        Ok(())
    }

    pub fn push_scheduled_roots(
        &mut self,
        key: TableKey,
        site: SiteId,
        roots: (ProverAuthed, ProverAuthed),
    ) -> Result<(), TableBankSiteError> {
        if !self.scheduled_sites.get(&key).is_some_and(|sites| sites.contains(&site)) {
            return Err(TableBankSiteError::UnregisteredSite { key, site });
        }
        if self.roots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        if self.scheduled_roots.contains_key(&(key, site)) {
            return Err(TableBankSiteError::DuplicateSite { key, site });
        }
        self.scheduled_roots.insert((key, site), roots);
        Ok(())
    }

    fn validate_scheduled_roots(&self) -> Result<(), TableBankSiteError> {
        for (&key, sites) in &self.scheduled_sites {
            if self.roots.get(&key).is_some_and(|roots| !roots.is_empty()) {
                return Err(TableBankSiteError::LegacyRootsPresent(key));
            }
            for &site in sites {
                if !self.scheduled_roots.contains_key(&(key, site)) {
                    return Err(TableBankSiteError::MissingSite { key, site });
                }
            }
        }
        for &(key, site) in self.scheduled_roots.keys() {
            if !self.scheduled_sites.get(&key).is_some_and(|sites| sites.contains(&site)) {
                return Err(TableBankSiteError::UnregisteredSite { key, site });
            }
        }
        Ok(())
    }

    fn roots_canonical(&self, key: TableKey) -> Option<Vec<(ProverAuthed, ProverAuthed)>> {
        self.scheduled_sites
            .get(&key)
            .map(|sites| sites.iter().map(|&site| self.scheduled_roots[&(key, site)]).collect())
    }

    /// Multiplicity correction bytes (8 B/entry over all contents).
    /// Canonical (sorted) content keys accumulated so far.
    pub fn content_keys(&self) -> Vec<TableKey> {
        assert!(
            self.mult.is_empty() || self.resident_mult.is_empty(),
            "mixed table-bank ownership"
        );
        self.mult.keys().chain(self.resident_mult.keys()).copied().collect()
    }

    pub fn mult_bytes(&self) -> u64 {
        8 * (self.mult.values().map(|m| m.len() as u64).sum::<u64>()
            + self.resident_mult.values().map(|m| m.len() as u64).sum::<u64>())
    }

    /// Close every content: ONE table side against the global multiplicity
    /// vector, the fraction-sum chain over all registered sites, and the m̃
    /// claim resolved against the authenticated vector.
    #[allow(clippy::too_many_arguments)]
    pub fn close(
        self,
        luts: &Luts,
        stream: &mut CorrelationStream,
        doms: &mut Doms,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut crate::logup::ProdTriples,
        zero: &mut Vec<ProverAuthed>,
    ) -> Vec<TableCloseProof> {
        self.close_impl(luts, stream, doms, tx, ctr, prod, zero, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn close_with_backend(
        self,
        luts: &Luts,
        stream: &mut CorrelationStream,
        doms: &mut Doms,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut crate::logup::ProdTriples,
        zero: &mut Vec<ProverAuthed>,
        backend: &mut Backend,
    ) -> Vec<TableCloseProof> {
        self.close_impl(luts, stream, doms, tx, ctr, prod, zero, Some(backend))
    }

    #[allow(clippy::too_many_arguments)]
    fn close_impl(
        self,
        luts: &Luts,
        stream: &mut CorrelationStream,
        doms: &mut Doms,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut crate::logup::ProdTriples,
        zero: &mut Vec<ProverAuthed>,
        mut backend: Option<&mut Backend>,
    ) -> Vec<TableCloseProof> {
        assert!(self.finalized);
        self.validate_scheduled_roots()
            .unwrap_or_else(|error| panic!("invalid scheduled table-bank roots: {error:?}"));
        assert!(
            self.resident_mult.is_empty(),
            "host table-bank close cannot consume resident multiplicities"
        );
        let mut out = Vec::with_capacity(self.mult.len());
        for (key, m) in &self.mult {
            let scheduled = self.roots_canonical(*key);
            let sites = scheduled
                .as_deref()
                .or_else(|| self.roots.get(key).map(Vec::as_slice))
                .unwrap_or_else(|| {
                    panic!("content {key:?} has a multiplicity vector but no sites")
                });
            let tv = table_vals(*key, luts);
            let alpha = self.alphas[key];
            let (side, mult_claim) = if let Some(backend) = backend.as_deref_mut() {
                table_side_prove_with_backend(
                    &tv, m, alpha, sites, stream, doms, tx, ctr, prod, zero, backend,
                )
            } else {
                table_side_prove(&tv, m, alpha, sites, stream, doms, tx, ctr, prod, zero)
            };
            let (dom, fp, corr) = &self.auth[key];
            let opened = open_fp_vec_p(stream, *dom, fp, &mult_claim.point);
            zero.push(mult_claim.value.sub(opened));
            out.push(TableCloseProof { key: *key, mult_corr: corr.clone(), side });
        }
        out
    }

    /// Resident counterpart of [`TableBankP::close`]. It consumes and frees
    /// every global multiplicity allocation, including all remaining buffers
    /// on an error path, so a failed proof cannot poison context reuse.
    #[allow(clippy::too_many_arguments)]
    pub fn close_resident(
        mut self,
        luts: &Luts,
        stream: &mut CorrelationStream,
        doms: &mut Doms,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut crate::logup::ProdTriples,
        zero: &mut Vec<ProverAuthed>,
        backend: &mut Backend,
    ) -> Result<Vec<TableCloseProof>, AccelError> {
        if !self.finalized
            || !self.mult.is_empty()
            || self.resident_mult.is_empty()
            || self.validate_scheduled_roots().is_err()
        {
            self.free_resident_multiplicities(backend);
            return Err(AccelError::InvalidInput("invalid resident table-bank close state"));
        }
        let keys: Vec<TableKey> = self.resident_mult.keys().copied().collect();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let mult = self.resident_mult.remove(&key).expect("resident key disappeared");
            let result = (|| {
                let scheduled = self.roots_canonical(key);
                let sites = scheduled
                    .as_deref()
                    .or_else(|| self.roots.get(&key).map(Vec::as_slice))
                    .ok_or(AccelError::InvalidInput(
                        "resident table content has no lookup sites",
                    ))?;
                let tv = table_vals(key, luts);
                let alpha = self.alphas[&key];
                let (side, mult_claim) = table_side_prove_resident(
                    &tv, &mult, alpha, sites, stream, doms, tx, ctr, prod, zero, backend,
                )?;
                let (dom, corr) = self.resident_auth.get(&key).ok_or(AccelError::InvalidInput(
                    "resident multiplicity was not authenticated",
                ))?;
                let opened = open_fp_vec_resident_p(
                    stream,
                    *dom,
                    DeviceSlice::new(&mult, 0, mult.len()).expect("whole resident multiplicity"),
                    &mult_claim.point,
                    backend,
                )?;
                zero.push(mult_claim.value.sub(opened));
                Ok(TableCloseProof { key, mult_corr: corr.clone(), side })
            })();
            let free_result = backend.free_device(mult);
            let proof = match (result, free_result) {
                (Ok(proof), Ok(())) => proof,
                (Err(error), _) | (_, Err(error)) => {
                    self.free_resident_multiplicities(backend);
                    return Err(error);
                }
            };
            out.push(proof);
        }
        Ok(out)
    }

    pub(crate) fn free_resident_multiplicities(&mut self, backend: &mut Backend) {
        for (_, mult) in std::mem::take(&mut self.resident_mult) {
            let _ = backend.free_device(mult);
        }
    }
}

/// Verifier mirror of [`TableBankP`].
pub struct TableBankV {
    alphas: BTreeMap<TableKey, Fp2>,
    kroots: BTreeMap<TableKey, Vec<(VerifierKey, VerifierKey)>>,
    scheduled_sites: BTreeMap<TableKey, BTreeSet<SiteId>>,
    scheduled_kroots: BTreeMap<(TableKey, SiteId), (VerifierKey, VerifierKey)>,
    keys: BTreeMap<TableKey, Vec<Fp2>>,
}

impl TableBankV {
    /// Placeholder bank for phase-1 contexts (no instance runs in phase 1).
    pub fn empty() -> Self {
        TableBankV {
            alphas: BTreeMap::new(),
            kroots: BTreeMap::new(),
            scheduled_sites: BTreeMap::new(),
            scheduled_kroots: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Mirror of `finalize`: `expected` is the content set derived from the
    /// PUBLIC parameters — the proof must present exactly these contents (in
    /// canonical order), with corr vectors of the right lengths.
    pub fn finalize(
        expected: &std::collections::BTreeSet<TableKey>,
        proofs: &[TableCloseProof],
        ctx: &mut VerifierCtx,
        tx: &mut Transcript,
        doms: &mut Doms,
    ) -> Option<Self> {
        if proofs.len() != expected.len() {
            return None;
        }
        let mut keys = BTreeMap::new();
        for (p, &key) in proofs.iter().zip(expected.iter()) {
            if p.key != key || p.mult_corr.len() != table_len(key) {
                return None;
            }
            let dom = doms.take(1);
            keys.insert(key, keys_fp_vec_v(ctx, dom, &p.mult_corr));
        }
        let mut alphas = BTreeMap::new();
        for &key in expected {
            alphas.insert(key, tx.challenge_fp2());
        }
        Some(TableBankV {
            alphas,
            kroots: BTreeMap::new(),
            scheduled_sites: BTreeMap::new(),
            scheduled_kroots: BTreeMap::new(),
            keys,
        })
    }

    pub fn alpha(&self, key: TableKey) -> Option<Fp2> {
        self.alphas.get(&key).copied()
    }

    pub fn push_kroots(&mut self, key: TableKey, kroots: (VerifierKey, VerifierKey)) {
        assert!(
            !self.scheduled_sites.contains_key(&key),
            "table content {key:?} is atomically scheduled; legacy verifier root insertion is forbidden"
        );
        self.kroots.entry(key).or_default().push(kroots);
    }

    pub fn register_scheduled_sites(
        &mut self,
        key: TableKey,
        sites: impl IntoIterator<Item = SiteId>,
    ) -> Result<(), TableBankSiteError> {
        if !self.alphas.contains_key(&key) {
            return Err(TableBankSiteError::UnknownContent(key));
        }
        if self.scheduled_sites.contains_key(&key) {
            return Err(TableBankSiteError::DuplicateRegistration(key));
        }
        if self.kroots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        let mut registered = BTreeSet::new();
        for site in sites {
            if !registered.insert(site) {
                return Err(TableBankSiteError::DuplicateSite { key, site });
            }
        }
        let sites = registered;
        if sites.is_empty() {
            return Err(TableBankSiteError::EmptyRegistration(key));
        }
        self.scheduled_sites.insert(key, sites);
        Ok(())
    }

    /// Verifier mirror of [`TableBankP::preflight_scheduled_roots`].
    pub(crate) fn preflight_scheduled_kroots(
        &self,
        key: TableKey,
        sites: impl IntoIterator<Item = SiteId>,
    ) -> Result<(), TableBankSiteError> {
        if !self.alphas.contains_key(&key) {
            return Err(TableBankSiteError::UnknownContent(key));
        }
        if self.kroots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        let mut cohort = BTreeSet::new();
        for site in sites {
            if !cohort.insert(site) || self.scheduled_kroots.contains_key(&(key, site)) {
                return Err(TableBankSiteError::DuplicateSite { key, site });
            }
            if !self.scheduled_sites.get(&key).is_some_and(|registered| registered.contains(&site))
            {
                return Err(TableBankSiteError::UnregisteredSite { key, site });
            }
        }
        if cohort.is_empty() {
            return Err(TableBankSiteError::EmptyRegistration(key));
        }
        Ok(())
    }

    pub fn push_scheduled_kroots(
        &mut self,
        key: TableKey,
        site: SiteId,
        roots: (VerifierKey, VerifierKey),
    ) -> Result<(), TableBankSiteError> {
        if !self.scheduled_sites.get(&key).is_some_and(|sites| sites.contains(&site)) {
            return Err(TableBankSiteError::UnregisteredSite { key, site });
        }
        if self.kroots.get(&key).is_some_and(|roots| !roots.is_empty()) {
            return Err(TableBankSiteError::LegacyRootsPresent(key));
        }
        if self.scheduled_kroots.contains_key(&(key, site)) {
            return Err(TableBankSiteError::DuplicateSite { key, site });
        }
        self.scheduled_kroots.insert((key, site), roots);
        Ok(())
    }

    fn validate_scheduled_roots(&self) -> Option<()> {
        for (&key, sites) in &self.scheduled_sites {
            if self.kroots.get(&key).is_some_and(|roots| !roots.is_empty()) {
                return None;
            }
            for &site in sites {
                self.scheduled_kroots.get(&(key, site))?;
            }
        }
        for &(key, site) in self.scheduled_kroots.keys() {
            if !self.scheduled_sites.get(&key).is_some_and(|sites| sites.contains(&site)) {
                return None;
            }
        }
        Some(())
    }

    fn roots_canonical(&self, key: TableKey) -> Option<Vec<(VerifierKey, VerifierKey)>> {
        self.scheduled_sites
            .get(&key)
            .map(|sites| sites.iter().map(|&site| self.scheduled_kroots[&(key, site)]).collect())
    }

    /// Mirror of `close` (same canonical order).
    #[allow(clippy::too_many_arguments)]
    pub fn close(
        self,
        luts: &Luts,
        proofs: &[TableCloseProof],
        ctx: &mut VerifierCtx,
        doms: &mut Doms,
        tx: &mut Transcript,
        kprod: &mut crate::logup::ProdKeyTriples,
        kzero: &mut Vec<VerifierKey>,
    ) -> Option<()> {
        self.validate_scheduled_roots()?;
        for p in proofs {
            let scheduled = self.roots_canonical(p.key);
            let ksites =
                scheduled.as_deref().or_else(|| self.kroots.get(&p.key).map(Vec::as_slice))?;
            let tv = table_vals(p.key, luts);
            let alpha = self.alphas[&p.key];
            let mult_key =
                table_side_verify(&tv, alpha, &p.side, ksites, ctx, doms, tx, kprod, kzero)?;
            let opened = open_fp_vec_k(&self.keys[&p.key], &mult_key.point);
            kzero.push(mult_key.key.sub(opened));
        }
        Some(())
    }
}

#[cfg(test)]
mod table_bank_schedule_tests {
    use super::*;

    fn prover_root(value: u64) -> (ProverAuthed, ProverAuthed) {
        let value = Fp2::from_base(Fp::new(value));
        (
            ProverAuthed { x: value, m: value + Fp2::ONE },
            ProverAuthed { x: value + Fp2::ONE, m: value + value },
        )
    }

    #[test]
    fn table_bank_scheduled_roots_are_atomic_canonical_and_non_overwriting() {
        let key = TableKey::Range(2);
        let a = SiteId::new(2, RoundFamily::LogupAux, 1);
        let b = SiteId::new(2, RoundFamily::LogupAux, 9);
        let mut bank = TableBankP::new();
        bank.finalized = true;
        bank.alphas.insert(key, Fp2::ONE);
        assert_eq!(
            bank.register_scheduled_sites(key, [a, a]),
            Err(TableBankSiteError::DuplicateSite { key, site: a })
        );
        assert!(!bank.scheduled_sites.contains_key(&key));
        bank.register_scheduled_sites(key, [b, a]).unwrap();
        assert_eq!(bank.preflight_scheduled_roots(key, [a, b]), Ok(()));
        assert_eq!(
            bank.preflight_scheduled_roots(key, [a, a]),
            Err(TableBankSiteError::DuplicateSite { key, site: a })
        );
        let first = prover_root(10);
        let second = prover_root(20);
        bank.push_scheduled_roots(key, b, second).unwrap();
        assert_eq!(
            bank.preflight_scheduled_roots(key, [b]),
            Err(TableBankSiteError::DuplicateSite { key, site: b })
        );
        assert_eq!(bank.preflight_scheduled_roots(key, [a]), Ok(()));
        bank.push_scheduled_roots(key, a, first).unwrap();
        assert_eq!(
            bank.push_scheduled_roots(key, a, prover_root(99)),
            Err(TableBankSiteError::DuplicateSite { key, site: a })
        );
        assert_eq!(bank.scheduled_roots[&(key, a)], first);
        assert_eq!(bank.roots_canonical(key).unwrap(), vec![first, second]);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bank.push_roots(key, prover_root(30));
        }))
        .is_err());

        let mut missing = TableBankP::new();
        missing.finalized = true;
        missing.alphas.insert(key, Fp2::ONE);
        missing.register_scheduled_sites(key, [a, b]).unwrap();
        missing.push_scheduled_roots(key, a, first).unwrap();
        assert_eq!(
            missing.validate_scheduled_roots(),
            Err(TableBankSiteError::MissingSite { key, site: b })
        );

        let mut mixed = TableBankP::new();
        mixed.finalized = true;
        mixed.alphas.insert(key, Fp2::ONE);
        mixed.push_roots(key, first);
        assert_eq!(
            mixed.register_scheduled_sites(key, [a]),
            Err(TableBankSiteError::LegacyRootsPresent(key))
        );
    }

    #[test]
    fn verifier_table_bank_rejects_duplicate_and_missing_scheduled_sites() {
        let key = TableKey::Range(2);
        let a = SiteId::new(3, RoundFamily::LogupAux, 0);
        let b = SiteId::new(3, RoundFamily::LogupAux, 1);
        let zero = VerifierKey::from_public(Fp2::ZERO, Fp2::ONE);
        let mut bank = TableBankV::empty();
        bank.alphas.insert(key, Fp2::ONE);
        bank.register_scheduled_sites(key, [a, b]).unwrap();
        assert_eq!(bank.preflight_scheduled_kroots(key, [a, b]), Ok(()));
        bank.push_scheduled_kroots(key, b, (zero, zero)).unwrap();
        assert_eq!(
            bank.preflight_scheduled_kroots(key, [b]),
            Err(TableBankSiteError::DuplicateSite { key, site: b })
        );
        assert!(bank.validate_scheduled_roots().is_none());
        bank.push_scheduled_kroots(key, a, (zero, zero)).unwrap();
        assert!(bank.validate_scheduled_roots().is_some());
        assert_eq!(
            bank.push_scheduled_kroots(key, a, (zero, zero)),
            Err(TableBankSiteError::DuplicateSite { key, site: a })
        );
    }
}

/// Prover-side block context: correlation stream, transcript, sequential
/// domain allocator, the model-wide table bank and the Π_Prod / Π_ZeroBatch
/// accumulators. The final closures (one χ-batched prod check + one zero
/// batch) are run by the caller over the accumulated rows.
pub struct BlockCtxP<'a> {
    pub stream: &'a mut CorrelationStream,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub bank: &'a mut TableBankP,
    pub backend: Option<&'a mut Backend>,
    pub prod: crate::logup::ProdTriples,
    pub zero: Vec<ProverAuthed>,
    /// E-mults spent inside LogUp instances (the p4_report gate number).
    pub ctr_instances: Counters,
    /// E-mults spent on chain-level public evaluations (kept separable).
    pub ctr_other: Counters,
}

impl<'a> BlockCtxP<'a> {
    pub fn new(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        layer: u8,
        bank: &'a mut TableBankP,
    ) -> Self {
        Self::with_doms(stream, tx, Doms::new(layer_dom_base(layer)), bank)
    }

    /// Resume a context whose domain cursor was saved between the phases.
    pub fn with_doms(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        doms: Doms,
        bank: &'a mut TableBankP,
    ) -> Self {
        BlockCtxP {
            stream,
            tx,
            doms,
            bank,
            backend: None,
            prod: Vec::new(),
            zero: Vec::new(),
            ctr_instances: Counters::default(),
            ctr_other: Counters::default(),
        }
    }

    pub fn with_backend(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        layer: u8,
        bank: &'a mut TableBankP,
        backend: &'a mut Backend,
    ) -> Self {
        let mut out = Self::with_doms(stream, tx, Doms::new(layer_dom_base(layer)), bank);
        out.backend = Some(backend);
        out
    }

    pub fn with_doms_and_backend(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        doms: Doms,
        bank: &'a mut TableBankP,
        backend: &'a mut Backend,
    ) -> Self {
        let mut out = Self::with_doms(stream, tx, doms, bank);
        out.backend = Some(backend);
        out
    }

    /// Prove one lookup-side instance with the content's shared α and
    /// register its root fraction with the bank.
    pub(crate) fn inst(
        &mut self,
        key: TableKey,
        cols: &[Vec<Fp>],
        shifts: &[Option<u32>],
        aux: Vec<LeafAuxClaim>,
    ) -> InstanceOutP {
        let alpha = self.bank.alpha(key);
        let out = if let Some(backend) = self.backend.as_deref_mut() {
            blind_instance_prove_with_backend(
                cols,
                shifts,
                alpha,
                aux,
                self.stream,
                &mut self.doms,
                self.tx,
                &mut self.ctr_instances,
                &mut self.prod,
                &mut self.zero,
                backend,
            )
        } else {
            blind_instance_prove(
                cols,
                shifts,
                alpha,
                aux,
                self.stream,
                &mut self.doms,
                self.tx,
                &mut self.ctr_instances,
                &mut self.prod,
                &mut self.zero,
            )
        };
        self.bank.push_roots(key, out.roots);
        out
    }

    /// Lookup-side instance sourced directly from device-owned padded proof
    /// columns. This is intentionally separate from the CPU wrapper so a
    /// resident call cannot silently stage through host vectors.
    pub(crate) fn inst_resident(
        &mut self,
        key: TableKey,
        columns: DeviceSlice<'_, u64>,
        column_count: usize,
        entries: usize,
        shifts: &[Option<u32>],
        aux: Vec<LeafAuxClaim>,
    ) -> Result<InstanceOutP, AccelError> {
        let alpha = self.bank.alpha(key);
        let backend = self
            .backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident lookup requires an explicit backend"))?;
        let out = blind_instance_prove_resident(
            columns,
            column_count,
            entries,
            shifts,
            alpha,
            aux,
            self.stream,
            &mut self.doms,
            self.tx,
            &mut self.ctr_instances,
            &mut self.prod,
            &mut self.zero,
            backend,
        )?;
        self.bank.push_roots(key, out.roots);
        Ok(out)
    }
}

/// Verifier mirror of [`BlockCtxP`].
pub struct BlockCtxV<'a> {
    pub ctx: &'a mut VerifierCtx,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub bank: &'a mut TableBankV,
    pub kprod: crate::logup::ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

impl<'a> BlockCtxV<'a> {
    pub fn new(
        ctx: &'a mut VerifierCtx,
        tx: &'a mut Transcript,
        layer: u8,
        bank: &'a mut TableBankV,
    ) -> Self {
        Self::with_doms(ctx, tx, Doms::new(layer_dom_base(layer)), bank)
    }

    pub fn with_doms(
        ctx: &'a mut VerifierCtx,
        tx: &'a mut Transcript,
        doms: Doms,
        bank: &'a mut TableBankV,
    ) -> Self {
        BlockCtxV { ctx, tx, doms, bank, kprod: Vec::new(), kzero: Vec::new() }
    }

    /// Verify one lookup-side instance with the content's shared α and
    /// register its root-fraction keys with the bank.
    pub(crate) fn inst(
        &mut self,
        key: TableKey,
        n_bits: usize,
        shifts: &[Option<u32>],
        proof: &BlindInstance,
        aux: &[(usize, Vec<Fp2>, VerifierKey)],
    ) -> Option<InstanceOutV> {
        let alpha = self.bank.alpha(key)?;
        let out = blind_instance_verify(
            n_bits,
            shifts,
            alpha,
            proof,
            aux,
            self.ctx,
            &mut self.doms,
            self.tx,
            &mut self.kprod,
            &mut self.kzero,
        )?;
        self.bank.push_kroots(key, out.kroots);
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Element-wise auth + streamed MAC openings (boundaries, small vectors)
// ---------------------------------------------------------------------------

/// Π_Auth for a T×cols boundary tensor: per-row domains `base_dom + row`,
/// mask-only draws, 8 B corrections (the `auth_phase_at` pattern).
pub(crate) fn auth_matrix_rows_p(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
) -> Vec<u64> {
    assert_eq!(x.len(), rows * cols);
    let mut corr = Vec::with_capacity(rows * cols);
    for row in 0..rows {
        let masks = stream.draw_sub_masks(base_dom + row as u64, cols);
        for (j, &r) in masks.iter().enumerate() {
            corr.push((Fp::from_i64(x[row * cols + j] as i64) - r).value());
        }
    }
    tx.append("auth_corrections", 8 * corr.len() as u64);
    corr
}

/// Streamed MAC opening of a row-authenticated matrix at `point`
/// (= cols vars LSB ‖ rows vars): lazy tag expansion + eq fold. Callable
/// multiple times per tensor (tags are re-expanded, the ledger only checks
/// consistency with the mask draw).
pub(crate) fn open_matrix_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    point: &[Fp2],
) -> ProverAuthed {
    let cb = pad_bits(cols);
    assert_eq!(point.len(), cb + pad_bits(rows), "matrix opening point split mismatch");
    let eq_c = eq_vec(&point[..cb]);
    let eq_r = eq_vec(&point[cb..]);
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        let mut v = Fp2::ZERO;
        let mut mt = Fp2::ZERO;
        for (j, t) in tags.into_iter().enumerate() {
            let xv = x[row * cols + j];
            if xv != 0 {
                v += eq_c[j].mul_base(Fp::from_i64(xv as i64));
            }
            mt += eq_c[j] * t;
        }
        val += eq_r[row] * v;
        tag += eq_r[row] * mt;
    }
    ProverAuthed { x: val, m: tag }
}

pub(crate) fn open_matrix_resident_p<T: ResidentMatrixElement>(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: DeviceSlice<'_, T>,
    rows: usize,
    cols: usize,
    point: &[Fp2],
    backend: &mut Backend,
) -> Result<ProverAuthed, AccelError> {
    let cb = pad_bits(cols);
    if point.len() != cb + pad_bits(rows) || x.len() < rows.saturating_mul(cols) {
        return Err(AccelError::InvalidInput("resident matrix opening point mismatch"));
    }
    let eq_c = eq_vec(&point[..cb]);
    let eq_r = eq_vec(&point[cb..]);
    let mut tag = Fp2::ZERO;
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        let row_tag = tags
            .into_iter()
            .zip(&eq_c)
            .fold(Fp2::ZERO, |sum, (value, &weight)| sum + weight * value);
        tag += eq_r[row] * row_tag;
    }
    let value = backend.matrix_mle_eval_device(
        DeviceSlice::new(x.buffer(), x.offset(), rows * cols).expect("validated matrix prefix"),
        rows,
        cols,
        point,
    )?;
    Ok(ProverAuthed { x: value, m: tag })
}

/// Verifier: expand and CACHE the per-element keys of a row-authenticated
/// matrix (each domain is one-time — the cache serves every later opening).
pub(crate) fn auth_matrix_rows_v(
    ctx: &mut VerifierCtx,
    base_dom: u64,
    corr: &[u64],
    rows: usize,
    cols: usize,
) -> Vec<Fp2> {
    assert_eq!(corr.len(), rows * cols);
    let mut keys = Vec::with_capacity(rows * cols);
    for row in 0..rows {
        let kr = auth_verifier(ctx, base_dom + row as u64, &corr[row * cols..(row + 1) * cols]);
        keys.extend(kr.into_iter().map(|k| k.k));
    }
    keys
}

/// Verifier's streamed opening over cached keys.
pub(crate) fn open_matrix_k(keys: &[Fp2], rows: usize, cols: usize, point: &[Fp2]) -> VerifierKey {
    let cb = pad_bits(cols);
    assert_eq!(point.len(), cb + pad_bits(rows), "matrix opening point split mismatch");
    let eq_c = eq_vec(&point[..cb]);
    let eq_r = eq_vec(&point[cb..]);
    let mut k = Fp2::ZERO;
    for row in 0..rows {
        let mut acc = Fp2::ZERO;
        for j in 0..cols {
            acc += eq_c[j] * keys[row * cols + j];
        }
        k += eq_r[row] * acc;
    }
    VerifierKey { k }
}

/// Π_Auth for an `F_p` vector at one domain (LN small vectors, row tables,
/// multiplicity vectors, sparse above-diagonal accumulators).
pub(crate) fn auth_fp_vec_p(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    dom: u64,
    vals: &[Fp],
) -> Vec<u64> {
    let masks = stream.draw_sub_masks(dom, vals.len());
    let corr: Vec<u64> = vals.iter().zip(&masks).map(|(&v, &r)| (v - r).value()).collect();
    tx.append("auth_corrections", 8 * corr.len() as u64);
    corr
}

fn auth_device_vector_p<T: ResidentBaseElement>(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    dom: u64,
    vals: DeviceSlice<'_, T>,
    backend: &mut Backend,
) -> Result<Vec<u64>, AccelError> {
    if vals.is_empty() {
        return Err(AccelError::InvalidInput("cannot authenticate an empty resident vector"));
    }
    let device_masks = reserve_auth_masks_device(stream, dom, 1, vals.len(), backend)?;
    let corrections = match backend.subfield_corrections_device(
        vals,
        DeviceSlice::new(&device_masks, 0, device_masks.len()).expect("whole auth mask vector"),
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(device_masks);
            return Err(error);
        }
    };
    if let Err(error) = backend.free_device(device_masks) {
        let _ = backend.free_device(corrections);
        return Err(error);
    }
    let corr = backend.download_device(&corrections, 0, corrections.len());
    let free_result = backend.free_device(corrections);
    let corr = match (corr, free_result) {
        (Ok(value), Ok(())) => value,
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    tx.append("auth_corrections", 8 * corr.len() as u64);
    Ok(corr)
}

/// Materialize one atomically reserved row-major authentication-mask range on
/// the device. Only the explicitly mock-PCG backend may expand its shared
/// ChaCha8 seed there; pooled/production-oriented VOLE material remains an
/// opaque host allocation and follows the existing upload path.
fn reserve_auth_masks_device(
    stream: &mut CorrelationStream,
    base_dom: u64,
    rows: usize,
    cols: usize,
    backend: &mut Backend,
) -> Result<DeviceBuffer<u64>, AccelError> {
    match stream.reserve_sub_mask_rows(base_dom, rows, cols) {
        SubMaskRowsReservation::ChaCha8 { seed, base_domain, rows, cols } => {
            backend.mock_correlation_sub_masks_device(seed, base_domain, rows, cols)
        }
        SubMaskRowsReservation::Host { masks, rows, cols } => {
            let expected = rows
                .checked_mul(cols)
                .ok_or(AccelError::InvalidInput("authentication mask geometry overflow"))?;
            if masks.len() != expected {
                return Err(AccelError::InvalidInput(
                    "pooled authentication mask reservation length mismatch",
                ));
            }
            let masks_raw: Vec<u64> = masks.into_iter().map(Fp::value).collect();
            backend.upload_new_device(&masks_raw)
        }
    }
}

pub(crate) fn auth_matrix_rows_resident_p<T: ResidentBaseElement>(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    base_dom: u64,
    vals: DeviceSlice<'_, T>,
    rows: usize,
    cols: usize,
    backend: &mut Backend,
) -> Result<Vec<u64>, AccelError> {
    let elements = rows
        .checked_mul(cols)
        .ok_or(AccelError::InvalidInput("resident matrix authentication geometry overflow"))?;
    if rows == 0 || cols == 0 || vals.len() < elements {
        return Err(AccelError::InvalidInput("invalid resident matrix authentication geometry"));
    }
    let device_masks = reserve_auth_masks_device(stream, base_dom, rows, cols, backend)?;
    let values = DeviceSlice::new(vals.buffer(), vals.offset(), elements)
        .expect("validated resident matrix prefix");
    let corrections = match backend.subfield_corrections_device(
        values,
        DeviceSlice::new(&device_masks, 0, device_masks.len()).expect("whole matrix auth masks"),
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(device_masks);
            return Err(error);
        }
    };
    if let Err(error) = backend.free_device(device_masks) {
        let _ = backend.free_device(corrections);
        return Err(error);
    }
    let corr = backend.download_device(&corrections, 0, corrections.len());
    let free_result = backend.free_device(corrections);
    let corr = match (corr, free_result) {
        (Ok(value), Ok(())) => value,
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    tx.append("auth_corrections", 8 * corr.len() as u64);
    Ok(corr)
}

/// Streamed MAC opening of an authenticated vector at `point`
/// (`vals.len() == 2^point.len()`).
pub(crate) fn open_fp_vec_p(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    point: &[Fp2],
) -> ProverAuthed {
    assert_eq!(vals.len(), 1 << point.len());
    let tags = stream.draw_sub_tags(dom, vals.len());
    let eq = eq_vec(point);
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for (i, t) in tags.into_iter().enumerate() {
        if vals[i] != Fp::ZERO {
            val += eq[i].mul_base(vals[i]);
        }
        tag += eq[i] * t;
    }
    ProverAuthed { x: val, m: tag }
}

/// Streamed opening of a resident u32/Fp multiplicity vector. Mock-PCG tags
/// are folded by the protocol host, while the plaintext MLE is evaluated on
/// device and only its scalar claim crosses D2H.
fn open_fp_vec_resident_p<T: ResidentMatrixElement>(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: DeviceSlice<'_, T>,
    point: &[Fp2],
    backend: &mut Backend,
) -> Result<ProverAuthed, AccelError> {
    let expected = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(AccelError::InvalidInput("resident multiplicity point overflow"))?;
    if vals.len() != expected {
        return Err(AccelError::InvalidInput("resident multiplicity point does not match vector"));
    }
    let tags = stream.draw_sub_tags(dom, vals.len());
    let eq = eq_vec(point);
    let tag = tags.into_iter().zip(eq).fold(Fp2::ZERO, |acc, (value, weight)| acc + weight * value);
    let value = backend.mle_eval_device(vals, point)?;
    Ok(ProverAuthed { x: value, m: tag })
}

pub(crate) fn keys_fp_vec_v(ctx: &mut VerifierCtx, dom: u64, corr: &[u64]) -> Vec<Fp2> {
    auth_verifier(ctx, dom, corr).into_iter().map(|k| k.k).collect()
}

pub(crate) fn open_fp_vec_k(keys: &[Fp2], point: &[Fp2]) -> VerifierKey {
    assert_eq!(keys.len(), 1 << point.len());
    let eq = eq_vec(point);
    VerifierKey { k: keys.iter().zip(&eq).fold(Fp2::ZERO, |s, (&k, &e)| s + e * k) }
}

/// Opening of an authenticated vector with EXPLICIT public weights (used for
/// the sparse above-diagonal accumulator list, whose entries sit at scattered
/// rectangular-domain positions): value/tag = Σ_i weights[i]·(vals[i]/tag_i).
pub(crate) fn open_weighted_p(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    weights: &[Fp2],
) -> ProverAuthed {
    assert_eq!(vals.len(), weights.len());
    let tags = stream.draw_sub_tags(dom, vals.len());
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for (i, t) in tags.into_iter().enumerate() {
        if vals[i] != Fp::ZERO {
            val += weights[i].mul_base(vals[i]);
        }
        tag += weights[i] * t;
    }
    ProverAuthed { x: val, m: tag }
}

pub(crate) fn open_weighted_resident_p<T: ResidentMatrixElement>(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: DeviceSlice<'_, T>,
    weights: &[Fp2],
    backend: &mut Backend,
) -> Result<ProverAuthed, AccelError> {
    if vals.len() != weights.len() || vals.is_empty() {
        return Err(AccelError::InvalidInput("resident weighted opening geometry mismatch"));
    }
    let tags = stream.draw_sub_tags(dom, vals.len());
    let tag =
        tags.into_iter().zip(weights).fold(Fp2::ZERO, |sum, (value, &weight)| sum + weight * value);
    let value = backend.weighted_sum_device(vals, weights)?;
    Ok(ProverAuthed { x: value, m: tag })
}

pub(crate) fn open_weighted_k(keys: &[Fp2], weights: &[Fp2]) -> VerifierKey {
    assert_eq!(keys.len(), weights.len());
    VerifierKey { k: keys.iter().zip(weights).fold(Fp2::ZERO, |s, (&k, &w)| s + w * k) }
}

/// Fold a row-authenticated matrix over a COLUMN WINDOW `[c0, c0+w)` with
/// weights `wc` (len w), per row: returns (values, tags), each of length
/// `rows`. Used to pre-fold the per-head V slice for the w·V GEMM B leg
/// (the head-bit prefix is the window selection itself).
pub(crate) fn fold_cols_window_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    assert_eq!(wc.len(), w);
    let mut vals = Vec::with_capacity(rows);
    let mut tags_out = Vec::with_capacity(rows);
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        let mut v = Fp2::ZERO;
        let mut mt = Fp2::ZERO;
        for l in 0..w {
            let xv = x[row * cols + c0 + l];
            if xv != 0 {
                v += wc[l].mul_base(Fp::from_i64(xv as i64));
            }
            mt += wc[l] * tags[c0 + l];
        }
        vals.push(v);
        tags_out.push(mt);
    }
    (vals, tags_out)
}

pub(crate) fn fold_cols_window_k(
    keys: &[Fp2],
    rows: usize,
    cols: usize,
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> Vec<Fp2> {
    (0..rows)
        .map(|row| (0..w).fold(Fp2::ZERO, |s, l| s + wc[l] * keys[row * cols + c0 + l]))
        .collect()
}

/// Fold a row-authenticated matrix over its ROWS with weights `wr`
/// (len ≥ rows), restricted to the column window `[c0, c0+w)`: returns
/// (values, tags) of length `w`. Used to pre-fold the per-head K slice for
/// the QKᵀ GEMM B leg — the sumcheck point lands in K's COLUMN (d_h) vars,
/// while the score-column point `r_j` weights K's ROWS (positions).
pub(crate) fn fold_rows_window_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = vec![Fp2::ZERO; w];
    let mut tags_out = vec![Fp2::ZERO; w];
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        for l in 0..w {
            let xv = x[row * cols + c0 + l];
            if xv != 0 {
                vals[l] += wr[row].mul_base(Fp::from_i64(xv as i64));
            }
            tags_out[l] += wr[row] * tags[c0 + l];
        }
    }
    (vals, tags_out)
}

pub(crate) fn fold_rows_window_k(
    keys: &[Fp2],
    rows: usize,
    cols: usize,
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> Vec<Fp2> {
    let mut out = vec![Fp2::ZERO; w];
    for row in 0..rows {
        for l in 0..w {
            out[l] += wr[row] * keys[row * cols + c0 + l];
        }
    }
    out
}

/// The 4 head bits of head `h` as fixed boolean MLE coordinates.
pub(crate) fn head_bit_coords(h: usize) -> [Fp2; HEAD_BITS] {
    core::array::from_fn(|b| if (h >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO })
}

// ---------------------------------------------------------------------------
// P6 band shapes + cross-phase K/V cache segments
// ---------------------------------------------------------------------------

/// Attention band shape: `q` query rows at positions `t0..t0+q`, attending
/// over the full cache of `s = t0+q` positions. Prefill is the SQUARE band
/// `t0 = 0` (q = s = t) — one code path serves both (ledger P6 plan #2).
#[derive(Clone, Copy, Debug)]
pub struct BandShape {
    pub t0: usize,
    pub q: usize,
}

impl BandShape {
    pub fn square(t: usize) -> BandShape {
        BandShape { t0: 0, q: t }
    }
    pub fn s(&self) -> usize {
        self.t0 + self.q
    }
    pub fn qb(&self) -> usize {
        pad_bits(self.q)
    }
    pub fn sb(&self) -> usize {
        pad_bits(self.s())
    }
    pub fn q_pad(&self) -> usize {
        1 << self.qb()
    }
    pub fn s_pad(&self) -> usize {
        1 << self.sb()
    }
    /// Per-head rectangle size (q_pad × s_pad).
    pub fn sp2(&self) -> usize {
        self.q_pad() * self.s_pad()
    }
    /// Rect domain vars: within-row (sb, LSB) ‖ rows (qb) ‖ heads (4).
    pub fn nr(&self) -> usize {
        self.sb() + self.qb() + HEAD_BITS
    }
    /// Causal window length of band row `i` (positions 0..=t0+i).
    pub fn win(&self, i: usize) -> usize {
        self.t0 + i + 1
    }
    /// Packed offset of band row `i` within one head's causal-packed data.
    pub fn packed_off(&self, i: usize) -> usize {
        i * self.t0 + i * (i + 1) / 2
    }
    /// Packed length per head.
    pub fn caus(&self) -> usize {
        self.packed_off(self.q)
    }
    /// Above-causal real-cell count per head (j in win(i)..s).
    pub fn n_above_head(&self) -> usize {
        (0..self.q).map(|i| self.s() - self.win(i)).sum()
    }
}

/// One authenticated K/V cache segment (rows×D matrix, per-row domains) —
/// the prover side. A layer's cache = the prefill segment(s) followed by the
/// band's own new rows; the square path is the single own segment.
pub struct CacheSegP<'a> {
    pub dom: u64,
    pub rows: usize,
    pub data: &'a [i16],
}

/// Verifier mirror: cached per-element keys of one segment.
pub struct CacheSegK<'a> {
    pub rows: usize,
    pub keys: &'a [Fp2],
}

/// One earlier phase's authenticated K/V (prover side): the prefill (or a
/// previous decode chunk's) boundary tensors + their domains.
pub struct KvPrefixP<'a> {
    pub rows: usize,
    pub dom_k: u64,
    pub k: &'a [i16],
    pub dom_v: u64,
    pub v: &'a [i16],
}

/// Resident prover cache segment. Plaintext values are read from the
/// contiguous cache view supplied by [`ResidentLayerView`]; this record owns
/// only the per-row authentication domain needed to derive the matching MAC
/// tags without materializing prefix data on the host.
#[derive(Clone, Copy)]
pub(crate) struct ResidentCacheSegP {
    pub dom: u64,
    pub rows: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ResidentKvPrefixP {
    pub rows: usize,
    pub dom_k: u64,
    pub dom_v: u64,
}

/// Verifier mirror of [`KvPrefixP`] (cached keys).
pub struct KvPrefixK<'a> {
    pub rows: usize,
    pub k_keys: &'a [Fp2],
    pub v_keys: &'a [Fp2],
}

/// Fold a segmented cache over its ROWS (global row index into `wr`),
/// restricted to the column window `[c0, c0+w)` — segment-general
/// [`fold_rows_window_p`].
pub(crate) fn cache_fold_rows_p(
    stream: &mut CorrelationStream,
    segs: &[CacheSegP],
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = vec![Fp2::ZERO; w];
    let mut tags_out = vec![Fp2::ZERO; w];
    let mut base = 0usize;
    for seg in segs {
        let (sv, st) = fold_rows_window_p(
            stream,
            seg.dom,
            seg.data,
            seg.rows,
            D,
            &wr[base..base + seg.rows],
            c0,
            w,
        );
        for l in 0..w {
            vals[l] += sv[l];
            tags_out[l] += st[l];
        }
        base += seg.rows;
    }
    (vals, tags_out)
}

pub(crate) fn cache_fold_rows_k(segs: &[CacheSegK], wr: &[Fp2], c0: usize, w: usize) -> Vec<Fp2> {
    let mut out = vec![Fp2::ZERO; w];
    let mut base = 0usize;
    for seg in segs {
        let sv = fold_rows_window_k(seg.keys, seg.rows, D, &wr[base..base + seg.rows], c0, w);
        for l in 0..w {
            out[l] += sv[l];
        }
        base += seg.rows;
    }
    out
}

/// Fold a segmented cache over a COLUMN WINDOW per row (segment-general
/// [`fold_cols_window_p`]): returns per-GLOBAL-row (values, tags).
pub(crate) fn cache_fold_cols_p(
    stream: &mut CorrelationStream,
    segs: &[CacheSegP],
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = Vec::new();
    let mut tags = Vec::new();
    for seg in segs {
        let (sv, st) = fold_cols_window_p(stream, seg.dom, seg.data, seg.rows, D, wc, c0, w);
        vals.extend(sv);
        tags.extend(st);
    }
    (vals, tags)
}

pub(crate) fn cache_fold_cols_k(segs: &[CacheSegK], wc: &[Fp2], c0: usize, w: usize) -> Vec<Fp2> {
    let mut out = Vec::new();
    for seg in segs {
        out.extend(fold_cols_window_k(seg.keys, seg.rows, D, wc, c0, w));
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn public_window_fold_resident<T: ResidentMatrixElement>(
    data: DeviceSlice<'_, T>,
    rows: usize,
    stride: usize,
    column_offset: usize,
    width: usize,
    weights: &[Fp2],
    axis: volta_accel::MatrixFoldAxis,
    backend: &mut Backend,
) -> Result<DeviceBuffer<volta_accel::Fp2Repr>, AccelError> {
    let expected = match axis {
        volta_accel::MatrixFoldAxis::Rows => rows,
        volta_accel::MatrixFoldAxis::Columns => width,
    };
    if weights.len() < expected || data.len() < rows.saturating_mul(stride) {
        return Err(AccelError::InvalidInput("resident public matrix-fold geometry mismatch"));
    }
    let raw: Vec<volta_accel::Fp2Repr> =
        weights[..expected].iter().copied().map(Into::into).collect();
    let device_weights = backend.upload_new_device(&raw)?;
    let values = backend.matrix_window_fold_device(
        DeviceSlice::new(data.buffer(), data.offset(), rows * stride).expect("validated matrix"),
        DeviceSlice::new(&device_weights, 0, expected).expect("whole public fold weights"),
        rows,
        stride,
        column_offset,
        width,
        axis,
    );
    let free_result = backend.free_device(device_weights);
    match (values, free_result) {
        (Ok(values), Ok(())) => Ok(values),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn cache_fold_cols_resident_p(
    stream: &mut CorrelationStream,
    segments: &[ResidentCacheSegP],
    data: DeviceSlice<'_, i16>,
    rows: usize,
    weights: &[Fp2],
    column_offset: usize,
    width: usize,
    backend: &mut Backend,
) -> Result<(DeviceBuffer<volta_accel::Fp2Repr>, Vec<Fp2>), AccelError> {
    if segments.iter().map(|segment| segment.rows).sum::<usize>() != rows {
        return Err(AccelError::InvalidInput("resident cache segment rows do not cover cache"));
    }
    let values = public_window_fold_resident(
        data,
        rows,
        D,
        column_offset,
        width,
        weights,
        volta_accel::MatrixFoldAxis::Columns,
        backend,
    )?;
    let mut tags_out = Vec::with_capacity(rows);
    for segment in segments {
        for row in 0..segment.rows {
            let tags = stream.draw_sub_tags(segment.dom + row as u64, D);
            tags_out.push(
                (0..width).fold(Fp2::ZERO, |sum, index| {
                    sum + weights[index] * tags[column_offset + index]
                }),
            );
        }
    }
    Ok((values, tags_out))
}

#[allow(clippy::too_many_arguments)]
fn cache_fold_rows_resident_p(
    stream: &mut CorrelationStream,
    segments: &[ResidentCacheSegP],
    data: DeviceSlice<'_, i16>,
    rows: usize,
    weights: &[Fp2],
    column_offset: usize,
    width: usize,
    backend: &mut Backend,
) -> Result<(DeviceBuffer<volta_accel::Fp2Repr>, Vec<Fp2>), AccelError> {
    if segments.iter().map(|segment| segment.rows).sum::<usize>() != rows || weights.len() < rows {
        return Err(AccelError::InvalidInput("invalid resident cache row-fold geometry"));
    }
    let values = public_window_fold_resident(
        data,
        rows,
        D,
        column_offset,
        width,
        weights,
        volta_accel::MatrixFoldAxis::Rows,
        backend,
    )?;
    let mut tags_out = vec![Fp2::ZERO; width];
    let mut base = 0;
    for segment in segments {
        for row in 0..segment.rows {
            let tags = stream.draw_sub_tags(segment.dom + row as u64, D);
            for index in 0..width {
                tags_out[index] += weights[base + row] * tags[column_offset + index];
            }
        }
        base += segment.rows;
    }
    Ok((values, tags_out))
}

// ---------------------------------------------------------------------------
// Column / table builders
// ---------------------------------------------------------------------------

/// Requant range-instance columns over the padded matrix domain:
/// `rem = acc + 2^(s−1) − (out << s)` (round-half-up semantics of
/// `volta_gpt2::gemm::requant`, asserted in range), out zero-padded, rem
/// padded with the valid element `2^(s−1)` (implied pad accumulator = 0).
pub(crate) fn range_cols_padded(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) -> (Vec<Fp>, Vec<Fp>) {
    assert_eq!(acc.len(), rows * cols);
    assert_eq!(out.len(), rows * cols);
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let half = 1i64 << (shift - 1);
    let mut rem = vec![Fp::new(half as u64); rp * cp];
    let mut o = vec![Fp::ZERO; rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            let a = acc[i * cols + j];
            let y = out[i * cols + j] as i64;
            let r = a + half - (y << shift);
            assert!(
                (0..1i64 << shift).contains(&r),
                "requant remainder out of range (shift {shift}): acc={a}, out={y}"
            );
            rem[i * cp + j] = Fp::new(r as u64);
            o[i * cp + j] = Fp::from_i64(y);
        }
    }
    (rem, o)
}

/// Multiplicities of a range instance over the remainder domain, with the
/// pad element `2^(s−1)` bumped by the pad count.
pub(crate) fn range_mult(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) -> Vec<u32> {
    let half = 1i64 << (shift - 1);
    let mut m = vec![0u32; 1 << shift];
    for (&a, &y) in acc.iter().zip(out) {
        m[(a + half - ((y as i64) << shift)) as usize] += 1;
    }
    let pads = (1usize << pad_bits(rows)) * (1usize << pad_bits(cols)) - rows * cols;
    m[half as usize] += pads as u32;
    m
}

/// One round-half-up shift stage (mirror of the witness generator's).
#[inline]
pub(crate) fn round_stage(acc: i64, s: u32) -> i64 {
    (acc + (1i64 << (s - 1))) >> s
}

/// Chained requant columns (P5 spec §chained requant, shift s > 16):
/// stage 1 rounds the accumulator by s−16 (`y1 = round(acc, s−16)`,
/// `rem1 ∈ [0, 2^(s−16))`), stage 2 rounds `y1` by 16 (`rem2 ∈ [0, 2^16)`,
/// `out` must equal the witness output — double-round semantics). Pads:
/// acc = 0 ⇒ y1 = 0, rem1 = 2^(s−17), rem2 = 2^15, out = 0.
/// Returns ((rem1, y1), (rem2, out)).
#[allow(clippy::type_complexity)]
pub(crate) fn range_cols_padded_chained(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) -> ((Vec<Fp>, Vec<Fp>), (Vec<Fp>, Vec<Fp>)) {
    assert!(shift > 16);
    let s1 = shift - 16;
    let (h1, h2) = (1i64 << (s1 - 1), 1i64 << 15);
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let mut rem1 = vec![Fp::new(h1 as u64); rp * cp];
    let mut y1c = vec![Fp::ZERO; rp * cp];
    let mut rem2 = vec![Fp::new(h2 as u64); rp * cp];
    let mut o = vec![Fp::ZERO; rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            let a = acc[i * cols + j];
            let y = out[i * cols + j] as i64;
            let y1 = round_stage(a, s1);
            let r1 = a + h1 - (y1 << s1);
            debug_assert_eq!(round_stage(y1, 16), y, "witness is not double-rounded");
            let r2 = y1 + h2 - (y << 16);
            assert!((0..1i64 << s1).contains(&r1), "chained stage-1 remainder out of range");
            assert!((0..1i64 << 16).contains(&r2), "chained stage-2 remainder out of range");
            rem1[i * cp + j] = Fp::new(r1 as u64);
            y1c[i * cp + j] = Fp::from_i64(y1);
            rem2[i * cp + j] = Fp::new(r2 as u64);
            o[i * cp + j] = Fp::from_i64(y);
        }
    }
    ((rem1, y1c), (rem2, o))
}

/// Multiplicities of both chained stages, pads bumped at their halves.
pub(crate) fn range_mult_chained(
    acc: &[i64],
    rows: usize,
    cols: usize,
    shift: u32,
) -> (Vec<u32>, Vec<u32>) {
    assert!(shift > 16);
    let s1 = shift - 16;
    let (h1, h2) = (1i64 << (s1 - 1), 1i64 << 15);
    let mut m1 = vec![0u32; 1 << s1];
    let mut m2 = vec![0u32; 1 << 16];
    for &a in acc {
        let y1 = round_stage(a, s1);
        m1[(a + h1 - (y1 << s1)) as usize] += 1;
        let y = round_stage(y1, 16);
        m2[(y1 + h2 - (y << 16)) as usize] += 1;
    }
    let pads = ((1usize << pad_bits(rows)) * (1usize << pad_bits(cols)) - rows * cols) as u32;
    m1[h1 as usize] += pads;
    m2[h2 as usize] += pads;
    (m1, m2)
}

/// Pair-LUT instance columns over the padded matrix domain, pad pair
/// `(pad_in, pad_out)` (must be a valid table pair — asserted by the caller).
pub(crate) fn pair_cols_padded(
    inp: &[i16],
    outp: &[i16],
    rows: usize,
    cols: usize,
    pad_in: i16,
    pad_out: i16,
) -> (Vec<Fp>, Vec<Fp>) {
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let mut ic = vec![Fp::from_i64(pad_in as i64); rp * cp];
    let mut oc = vec![Fp::from_i64(pad_out as i64); rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            ic[i * cp + j] = Fp::from_i64(inp[i * cols + j] as i64);
            oc[i * cp + j] = Fp::from_i64(outp[i * cols + j] as i64);
        }
    }
    (ic, oc)
}

/// Range table `0..2^shift` for a requant instance.
pub(crate) fn range_table(shift: u32) -> Vec<Fp> {
    (0..1u64 << shift).map(Fp::new).collect()
}

/// Packed pair table `t_u = in(u) + 2^16·lut[u]`. `signed_input`: the LUT is
/// indexed by the i16 input's bit pattern (`exp`/`gelu`); otherwise the
/// domain is the non-negative u16 index itself (`ln_rsqrt`/`softmax_recip`).
pub(crate) fn pair_table(lut: &[i16], signed_input: bool) -> Vec<Fp> {
    let two16 = Fp::new(1 << 16);
    lut.iter()
        .enumerate()
        .map(|(u, &o)| {
            let inp = if signed_input { (u as u16 as i16) as i64 } else { u as i64 };
            Fp::from_i64(inp) + Fp::from_i64(o as i64) * two16
        })
        .collect()
}

pub(crate) fn fp_vec_u32(vals: &[u32]) -> Vec<Fp> {
    vals.iter().map(|&m| Fp::new(m as u64)).collect()
}

/// Zero-padded lift of an i64 vector to length `1 << bits`.
pub(crate) fn fp_vec_pad_i64(vals: &[i64], bits: usize) -> Vec<Fp> {
    let mut v = vec![Fp::ZERO; 1 << bits];
    for (i, &x) in vals.iter().enumerate() {
        v[i] = Fp::from_i64(x);
    }
    v
}

/// Zero-padded public MLE lift of an i16 vector.
pub(crate) fn lift_padded_i16(vals: &[i16], bits: usize) -> Vec<Fp2> {
    let mut v = vec![Fp2::ZERO; 1 << bits];
    for (i, &x) in vals.iter().enumerate() {
        v[i] = Fp2::from_base(Fp::from_i64(x as i64));
    }
    v
}

/// Exact-length base-field lifts.
pub(crate) fn fp_col_i16(vals: &[i16]) -> Vec<Fp> {
    vals.iter().map(|&x| Fp::from_i64(x as i64)).collect()
}

pub(crate) fn fp_col_i64(vals: &[i64]) -> Vec<Fp> {
    vals.iter().map(|&x| Fp::from_i64(x)).collect()
}

pub(crate) fn lift_i16_fp2(vals: &[i16]) -> Vec<Fp2> {
    vals.iter().map(|&x| Fp2::from_base(Fp::from_i64(x as i64))).collect()
}

// ---------------------------------------------------------------------------
// Chain-stage helpers
// ---------------------------------------------------------------------------

/// Requant acc-claim transport (tested in logup):
/// `ãcc(pt) = 2^s·oũt(pt) + rẽm(pt) − 2^(s−1)` — col order is [rem, out].
pub(crate) fn transport_p(out: &InstanceOutP, shift: u32) -> ProverAuthed {
    let two_s = Fp2::from_base(Fp::new(1u64 << shift));
    let half = Fp2::from_base(Fp::new(1u64 << (shift - 1)));
    out.col_claims[1]
        .value
        .scale(two_s)
        .add(out.col_claims[0].value)
        .sub(ProverAuthed::from_public(half))
}

pub(crate) fn transport_k(out: &InstanceOutV, shift: u32, delta: Fp2) -> VerifierKey {
    let two_s = Fp2::from_base(Fp::new(1u64 << shift));
    let half = Fp2::from_base(Fp::new(1u64 << (shift - 1)));
    out.col_keys[1]
        .key
        .scale(two_s)
        .add(out.col_keys[0].key)
        .sub(VerifierKey::from_public(half, delta))
}

/// Subtract a per-GEMM bias's public contribution from a transported POST-bias
/// accumulator claim, recovering the pre-bias `acc0 = X·W` claim the chained
/// GEMM expects (P5 §per-GEMM biases; the LN affine's `bias·2^s·rowmask` term
/// is the same pattern, see [`prove_ln_chain`]). `col_bits` is the padded
/// column-var count, `pt` the instance's full point (`cols ‖ rows`).
pub(crate) fn sub_bias_p(
    claim: ProverAuthed,
    bias: &[i16],
    col_bits: usize,
    pt: &[Fp2],
    t: usize,
    shift: u32,
    ctr: &mut Counters,
) -> ProverAuthed {
    let bias_lift = lift_padded_i16(bias, col_bits);
    let bias_eval = eval_mle_counted(&bias_lift, &pt[..col_bits], ctr);
    let rmask = rowmask_eval(&pt[col_bits..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << shift));
    claim.sub(ProverAuthed::from_public(bias_term))
}

/// Verifier mirror of [`sub_bias_p`].
pub(crate) fn sub_bias_k(
    key: VerifierKey,
    bias: &[i16],
    col_bits: usize,
    pt: &[Fp2],
    t: usize,
    shift: u32,
    delta: Fp2,
) -> VerifierKey {
    let bias_lift = lift_padded_i16(bias, col_bits);
    let bias_eval = eval_mle(&bias_lift, &pt[..col_bits]);
    let rmask = rowmask_eval(&pt[col_bits..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << shift));
    key.sub(VerifierKey::from_public(bias_term, delta))
}

/// A proved requant range site: `main` is the instance carrying the OUT
/// column (the single instance for s ≤ 16, stage 2 for s > 16); `stage1` is
/// the extra [rem1, y1] instance of a chained site. `acc_claim` is the
/// transported (post-bias) accumulator claim at `main.point`… stage-1's
/// point for chained sites — callers must use `main.point`/`main.col_claims`
/// for OUT-wire closures and `acc_point()` for the GEMM seam.
pub(crate) struct RangeSiteP {
    pub main: InstanceOutP,
    pub stage1: Option<InstanceOutP>,
    pub acc_claim: ProverAuthed,
}

impl RangeSiteP {
    /// Point the accumulator claim lives at (stage-1's for chained sites).
    pub(crate) fn acc_point(&self) -> &[Fp2] {
        match &self.stage1 {
            Some(s1) => &s1.point,
            None => &self.main.point,
        }
    }
}

/// Prove a requant range site, chained for shift > 16 (P5 spec). `aux`
/// drains external claims into the OUT column (col 1) of the main instance.
/// Multiplicities were accumulated into the bank in phase 1 (`range_keys`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_range_site(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
    aux: Vec<LeafAuxClaim>,
    cx: &mut BlockCtxP,
) -> RangeSiteP {
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        let (rem, oc) = range_cols_padded(acc, out, rows, cols, shift);
        let inst = cx.inst(key_main, &[rem, oc], &[Some(0), None], aux);
        let acc_claim = transport_p(&inst, shift);
        RangeSiteP { main: inst, stage1: None, acc_claim }
    } else {
        let s1 = shift - 16;
        let ((rem1, y1c), (rem2, oc)) = range_cols_padded_chained(acc, out, rows, cols, shift);
        let inst2 = cx.inst(key_main, &[rem2, oc], &[Some(0), None], aux);
        let y1_claim = transport_p(&inst2, 16);
        let inst1 = cx.inst(
            key_s1.unwrap(),
            &[rem1, y1c],
            &[Some(0), None],
            vec![LeafAuxClaim { col: 1, point: inst2.point.clone(), value: y1_claim }],
        );
        let acc_claim = transport_p(&inst1, s1);
        RangeSiteP { main: inst2, stage1: Some(inst1), acc_claim }
    }
}

pub(crate) fn prove_range_site_resident(
    columns: &DeviceLookupColumns,
    shift: u32,
    aux: Vec<LeafAuxClaim>,
    cx: &mut BlockCtxP,
) -> Result<RangeSiteP, AccelError> {
    let (key_main, key_stage1) = range_keys(shift);
    if shift <= 16 {
        if columns.columns() != 2 {
            return Err(AccelError::InvalidInput("single-stage resident range columns mismatch"));
        }
        let instance = cx.inst_resident(
            key_main,
            columns.view(0, 2)?,
            2,
            columns.entries(),
            &[Some(0), None],
            aux,
        )?;
        let acc_claim = transport_p(&instance, shift);
        return Ok(RangeSiteP { main: instance, stage1: None, acc_claim });
    }
    if columns.columns() != 4 {
        return Err(AccelError::InvalidInput("chained resident range columns mismatch"));
    }
    let main = cx.inst_resident(
        key_main,
        columns.view(2, 2)?,
        2,
        columns.entries(),
        &[Some(0), None],
        aux,
    )?;
    let y1_claim = transport_p(&main, 16);
    let stage1 = cx.inst_resident(
        key_stage1.expect("chained range key"),
        columns.view(0, 2)?,
        2,
        columns.entries(),
        &[Some(0), None],
        vec![LeafAuxClaim { col: 1, point: main.point.clone(), value: y1_claim }],
    )?;
    let acc_claim = transport_p(&stage1, shift - 16);
    Ok(RangeSiteP { main, stage1: Some(stage1), acc_claim })
}

pub(crate) struct RangeSiteV {
    pub main: InstanceOutV,
    pub stage1: Option<InstanceOutV>,
    pub acc_key: VerifierKey,
}

impl RangeSiteV {
    pub(crate) fn acc_point(&self) -> &[Fp2] {
        match &self.stage1 {
            Some(s1) => &s1.point,
            None => &self.main.point,
        }
    }
}

/// Verifier mirror of [`prove_range_site`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_range_site(
    n_vars: usize,
    shift: u32,
    proof_main: &BlindInstance,
    proof_s1: Option<&BlindInstance>,
    aux: &[(usize, Vec<Fp2>, VerifierKey)],
    cx: &mut BlockCtxV,
) -> Option<RangeSiteV> {
    let shifts_range = [Some(0u32), None];
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        if proof_s1.is_some() {
            return None;
        }
        let v = cx.inst(key_main, n_vars, &shifts_range, proof_main, aux)?;
        let acc_key = transport_k(&v, shift, cx.ctx.delta);
        Some(RangeSiteV { main: v, stage1: None, acc_key })
    } else {
        let s1 = shift - 16;
        let v2 = cx.inst(key_main, n_vars, &shifts_range, proof_main, aux)?;
        let y1_key = transport_k(&v2, 16, cx.ctx.delta);
        let aux1 = [(1usize, v2.point.clone(), y1_key)];
        let v1 = cx.inst(key_s1.unwrap(), n_vars, &shifts_range, proof_s1?, &aux1)?;
        let acc_key = transport_k(&v1, s1, cx.ctx.delta);
        Some(RangeSiteV { main: v2, stage1: Some(v1), acc_key })
    }
}

/// `Σ_{i<t} eq(r_rows, i)` — the public indicator of real (non-pad) rows,
/// needed by the LN hadamard claim0 (the bias broadcast lives on real rows).
pub(crate) fn rowmask_eval(r_rows: &[Fp2], t: usize) -> Fp2 {
    if t == 1 << r_rows.len() {
        return Fp2::ONE;
    }
    let eq = eq_vec(r_rows);
    eq[..t].iter().fold(Fp2::ZERO, |s, &e| s + e)
}

/// Recompute the LN affine accumulators from the boundary + stats + public
/// gain/bias (bit-identical to the witness trace inputs — pure function, so
/// the band slices need no trace bookkeeping):
/// `acc[i,j] = (x[i,j] − mean[i])·rsqrt_out[i]·gain[j] + (bias[j] << s_ln)`.
pub(crate) fn ln_acc_recompute(
    x: &[i16],
    t: usize,
    mean: &[i64],
    rsqrt_out: &[i16],
    gain: &[i16],
    bias: &[i16],
    s_ln: u32,
) -> Vec<i64> {
    let mut acc = vec![0i64; t * D];
    for i in 0..t {
        for j in 0..D {
            acc[i * D + j] = (x[i * D + j] as i64 - mean[i]) * rsqrt_out[i] as i64 * gain[j] as i64
                + ((bias[j] as i64) << s_ln);
        }
    }
    acc
}

/// Prover-side consistency check of LN statistics vectors against the
/// pre-LN input `x` — the P4-DEVIATION(ln-stats) fallback (see module doc).
pub(crate) fn assert_ln_stats(
    x: &[i16],
    t: usize,
    mean: &[i64],
    var: &[i64],
    rsqrt_in: &[i64],
    rsqrt_out: &[i16],
    luts: &Luts,
) {
    let d = D as i64;
    for i in 0..t {
        let row = &x[i * D..(i + 1) * D];
        let sum: i64 = row.iter().map(|&v| v as i64).sum();
        let m = (sum + d / 2).div_euclid(d);
        assert_eq!(m, mean[i], "P4-DEVIATION(ln-stats): mean inconsistent at row {i}");
        let vs: i64 = row
            .iter()
            .map(|&v| {
                let e = v as i64 - m;
                e * e
            })
            .sum();
        let vr = (vs + d / 2).div_euclid(d);
        assert_eq!(vr, var[i], "P4-DEVIATION(ln-stats): var inconsistent at row {i}");
        let vin = vr >> luts.params.ln_var_shift;
        assert!(vin < 1 << 16, "ln_rsqrt input exceeds u16 domain");
        assert_eq!(vin, rsqrt_in[i], "P4-DEVIATION(ln-stats): rsqrt_in inconsistent");
        assert_eq!(
            luts.ln_rsqrt[vin as usize], rsqrt_out[i],
            "P4-DEVIATION(ln-stats): rsqrt_out inconsistent"
        );
    }
}

// ---------------------------------------------------------------------------
// LN chain (shared by LN2/FFN and LN1/attention)
// ---------------------------------------------------------------------------

/// One LayerNorm's authenticated small vectors (padded to `t_pad`).
pub(crate) struct LnVecsP {
    mean_fp: Vec<Fp>,
    rin_fp: Vec<Fp>,
    rout_fp: Vec<Fp>,
    dom_mean: u64,
    dom_rin: u64,
    dom_rout: u64,
}

/// Authenticate mean/var/rsqrt_in/rsqrt_out (var is authenticated for the
/// record — the ln-stats deviation — but unused by the in-field relations).
/// Returns the vectors + domains and the 4 correction vectors.
pub(crate) fn auth_ln_vecs_p(
    cx: &mut BlockCtxP,
    rb: usize,
    mean: &[i64],
    var: &[i64],
    rsqrt_in: &[i64],
    rsqrt_out: &[i16],
    rout_pad: Fp,
) -> (LnVecsP, [Vec<u64>; 4]) {
    let t = mean.len();
    let t_pad = 1usize << rb;
    let mean_fp = fp_vec_pad_i64(mean, rb);
    let var_fp = fp_vec_pad_i64(var, rb);
    let rin_fp = fp_vec_pad_i64(rsqrt_in, rb);
    // rsqrt_out is padded with the LUT's index-0 output — the pad pair of the
    // ln_rsqrt instance is (0, lut[0]) and the SAME vector closes the
    // hadamard broadcast leg (pad rows killed by the zero centered factor).
    let mut rout_fp = vec![rout_pad; t_pad];
    for i in 0..t {
        rout_fp[i] = Fp::from_i64(rsqrt_out[i] as i64);
    }
    let dom_mean = cx.doms.take(1);
    let mean_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_mean, &mean_fp);
    let dom_var = cx.doms.take(1);
    let var_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_var, &var_fp);
    let dom_rin = cx.doms.take(1);
    let rin_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rin, &rin_fp);
    let dom_rout = cx.doms.take(1);
    let rout_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rout, &rout_fp);
    (
        LnVecsP { mean_fp, rin_fp, rout_fp, dom_mean, dom_rin, dom_rout },
        [mean_corr, var_corr, rin_corr, rout_corr],
    )
}

pub(crate) struct ResidentLnVecsP {
    mean: DeviceBuffer<u64>,
    rin: DeviceBuffer<u64>,
    rout: DeviceBuffer<u64>,
    dom_mean: u64,
    dom_rin: u64,
    dom_rout: u64,
}

impl ResidentLnVecsP {
    pub(crate) fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let first = backend.free_device(self.rout).err();
        let second = backend.free_device(self.rin).err();
        let third = backend.free_device(self.mean).err();
        first.or(second).or(third).map_or(Ok(()), Err)
    }
}

#[allow(clippy::too_many_arguments)]
fn pad_auth_resident_vector<T: ResidentBaseElement>(
    source: DeviceSlice<'_, T>,
    padded_len: usize,
    pad: Fp,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    doms: &mut Doms,
    backend: &mut Backend,
) -> Result<(DeviceBuffer<u64>, u64, Vec<u64>), AccelError> {
    let values = backend.pad_base_vector_device(source, padded_len, pad)?;
    let dom = doms.take(1);
    let corr = auth_device_vector_p(
        stream,
        tx,
        dom,
        DeviceSlice::new(&values, 0, values.len()).expect("whole padded auth vector"),
        backend,
    );
    match corr {
        Ok(corr) => Ok((values, dom, corr)),
        Err(error) => {
            let _ = backend.free_device(values);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn auth_ln_vecs_resident_p(
    mean: DeviceSlice<'_, i64>,
    var: DeviceSlice<'_, i64>,
    rsqrt_in: DeviceSlice<'_, i64>,
    rsqrt_out: DeviceSlice<'_, i16>,
    rb: usize,
    rout_pad: Fp,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    doms: &mut Doms,
    backend: &mut Backend,
) -> Result<(ResidentLnVecsP, [Vec<u64>; 4]), AccelError> {
    let padded_len = 1usize
        .checked_shl(rb as u32)
        .ok_or(AccelError::InvalidInput("resident LN vector dimension overflow"))?;
    if mean.len() != var.len()
        || mean.len() != rsqrt_in.len()
        || mean.len() != rsqrt_out.len()
        || mean.len() > padded_len
    {
        return Err(AccelError::InvalidInput("resident LN vector geometry mismatch"));
    }
    let (mean_values, dom_mean, mean_corr) =
        pad_auth_resident_vector(mean, padded_len, Fp::ZERO, stream, tx, doms, backend)?;
    let (var_values, _dom_var, var_corr) =
        match pad_auth_resident_vector(var, padded_len, Fp::ZERO, stream, tx, doms, backend) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(mean_values);
                return Err(error);
            }
        };
    if let Err(error) = backend.free_device(var_values) {
        let _ = backend.free_device(mean_values);
        return Err(error);
    }
    let (rin_values, dom_rin, rin_corr) =
        match pad_auth_resident_vector(rsqrt_in, padded_len, Fp::ZERO, stream, tx, doms, backend) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(mean_values);
                return Err(error);
            }
        };
    let (rout_values, dom_rout, rout_corr) = match pad_auth_resident_vector(
        rsqrt_out, padded_len, rout_pad, stream, tx, doms, backend,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(rin_values);
            let _ = backend.free_device(mean_values);
            return Err(error);
        }
    };
    Ok((
        ResidentLnVecsP {
            mean: mean_values,
            rin: rin_values,
            rout: rout_values,
            dom_mean,
            dom_rin,
            dom_rout,
        },
        [mean_corr, var_corr, rin_corr, rout_corr],
    ))
}

pub(crate) struct LnVecsK {
    mean_keys: Vec<Fp2>,
    rin_keys: Vec<Fp2>,
    rout_keys: Vec<Fp2>,
}

pub(crate) fn expand_ln_vecs_k(cx: &mut BlockCtxV, corrs: &[Vec<u64>; 4]) -> LnVecsK {
    let dom_mean = cx.doms.take(1);
    let mean_keys = keys_fp_vec_v(cx.ctx, dom_mean, &corrs[0]);
    let dom_var = cx.doms.take(1);
    let _var_keys = keys_fp_vec_v(cx.ctx, dom_var, &corrs[1]);
    let dom_rin = cx.doms.take(1);
    let rin_keys = keys_fp_vec_v(cx.ctx, dom_rin, &corrs[2]);
    let dom_rout = cx.doms.take(1);
    let rout_keys = keys_fp_vec_v(cx.ctx, dom_rout, &corrs[3]);
    LnVecsK { mean_keys, rin_keys, rout_keys }
}

/// The LN chain sub-proof: ln_norm_requant range instance (drains the
/// upstream GEMM's X wire claim) + LN-affine hadamard + ln_rsqrt pair
/// instance closed against the authenticated vectors.
#[derive(Debug, PartialEq, Eq)]
pub struct LnChainProof {
    pub inst_ln: BlindInstance,
    /// Stage-1 instance when shift_ln_norm > 16 (P5 chained requant).
    pub inst_ln_stage1: Option<BlindInstance>,
    pub hadamard: HadamardProof,
    pub inst_rsqrt: BlindInstance,
}

/// LN chain prover: `acc_ln`/`out_ln` are the T×D ln_norm_requant pairs,
/// `x` is the pre-LN boundary tensor (dom `dom_x`), `wire` the upstream
/// GEMM's X wire claim on `out_ln`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ln_chain(
    t: usize,
    s_ln: u32,
    acc_ln: &[i64],
    out_ln: &[i16],
    x: &[i16],
    dom_x: u64,
    mean: &[i64],
    gain: &[i16],
    bias: &[i16],
    lv: &LnVecsP,
    wire: &WireOut,
    cx: &mut BlockCtxP,
) -> LnChainProof {
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D);

    // -- ln_norm_requant range instance (drains the GEMM X wire; chained
    //    two-stage for s_ln > 16 — P5) --------------------------------------
    let site_ln = prove_range_site(
        acc_ln,
        out_ln,
        t,
        D,
        s_ln,
        vec![LeafAuxClaim { col: 1, point: wire.point.clone(), value: wire.value }],
        cx,
    );

    // -- hadamard: acc_ln − bias·2^s·rowmask = (x − mean) ∘ (rsqrt·gain) ----
    // Runs at the ACC claim's point (stage-1's for a chained site).
    let pt_ln = site_ln.acc_point().to_vec();
    let acc_ln_claim = site_ln.acc_claim;
    let bias_lift = lift_padded_i16(bias, d_cb);
    let bias_eval = eval_mle_counted(&bias_lift, &pt_ln[..d_cb], &mut cx.ctr_other);
    let rmask = rowmask_eval(&pt_ln[d_cb..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << s_ln));
    let claim0_h = acc_ln_claim.sub(ProverAuthed::from_public(bias_term));
    let n_ln = 1usize << pt_ln.len();
    let cp_d = 1usize << d_cb;
    let mut e_tab = vec![Fp2::ZERO; n_ln];
    let mut r_tab = vec![Fp2::ZERO; n_ln];
    for i in 0..t_pad {
        for j in 0..cp_d {
            if i < t {
                let a = if j < D { x[i * D + j] as i64 } else { 0 };
                e_tab[i * cp_d + j] = Fp2::from_base(Fp::from_i64(a - mean[i]));
            }
            if j < D {
                r_tab[i * cp_d + j] = Fp2::from_base(lv.rout_fp[i] * Fp::from_i64(gain[j] as i64));
            }
        }
    }
    let hd = HadamardDoms::alloc(&mut cx.doms, pt_ln.len());
    let (had_proof, r_h, e_claim, r_claim) = hadamard_prove(
        &pt_ln,
        e_tab,
        r_tab,
        claim0_h,
        &hd,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    // ẽ(r) = x̃(r) − meañ(r_rows): streamed boundary + vector openings.
    let x_open_r = open_matrix_p(cx.stream, dom_x, x, t, D, &r_h);
    let mean_open = open_fp_vec_p(cx.stream, lv.dom_mean, &lv.mean_fp, &r_h[d_cb..]);
    cx.zero.push(e_claim.sub(x_open_r.sub(mean_open)));
    // R̃(r) = rsqrt̃(r_rows)·g̃ain(r_cols): gain public, rsqrt authenticated.
    let gain_lift = lift_padded_i16(gain, d_cb);
    let gain_eval = eval_mle_counted(&gain_lift, &r_h[..d_cb], &mut cx.ctr_other);
    let rsq_open_h = open_fp_vec_p(cx.stream, lv.dom_rout, &lv.rout_fp, &r_h[d_cb..]);
    cx.zero.push(r_claim.sub(rsq_open_h.scale(gain_eval)));

    // -- ln_rsqrt pair instance, closed against the authed vectors ----------
    let inst_rsqrt = cx.inst(
        TableKey::LnRsqrt,
        &[lv.rin_fp.clone(), lv.rout_fp.clone()],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    let rsq_in_open = open_fp_vec_p(cx.stream, lv.dom_rin, &lv.rin_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[0].value.sub(rsq_in_open));
    let rsq_out_open = open_fp_vec_p(cx.stream, lv.dom_rout, &lv.rout_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[1].value.sub(rsq_out_open));

    LnChainProof {
        inst_ln: site_ln.main.proof,
        inst_ln_stage1: site_ln.stage1.map(|s1| s1.proof),
        hadamard: had_proof,
        inst_rsqrt: inst_rsqrt.proof,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ln_chain_resident(
    t: usize,
    s_ln: u32,
    ln_columns: &DeviceLookupColumns,
    rsqrt_columns: &DeviceLookupColumns,
    x: DeviceSlice<'_, i16>,
    dom_x: u64,
    gain_device: DeviceSlice<'_, i16>,
    gain: &[i16],
    bias: &[i16],
    lv: &ResidentLnVecsP,
    wire: &WireOut,
    cx: &mut BlockCtxP,
) -> Result<LnChainProof, AccelError> {
    let d_cb = pad_bits(D);
    let site_ln = prove_range_site_resident(
        ln_columns,
        s_ln,
        vec![LeafAuxClaim { col: 1, point: wire.point.clone(), value: wire.value }],
        cx,
    )?;
    let point_ln = site_ln.acc_point().to_vec();
    let bias_eval =
        eval_mle_counted(&lift_padded_i16(bias, d_cb), &point_ln[..d_cb], &mut cx.ctr_other);
    let row_mask = rowmask_eval(&point_ln[d_cb..], t);
    let bias_term = bias_eval * row_mask * Fp2::from_base(Fp::new(1u64 << s_ln));
    let claim0 = site_ln.acc_claim.sub(ProverAuthed::from_public(bias_term));
    let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, point_ln.len());
    let backend = cx
        .backend
        .as_deref_mut()
        .ok_or(AccelError::InvalidInput("resident LN chain requires a backend"))?;
    let (centered, scaled) = backend.ln_hadamard_factors_device(
        x,
        DeviceSlice::new(&lv.mean, 0, lv.mean.len()).expect("whole resident LN mean"),
        DeviceSlice::new(&lv.rout, 0, lv.rout.len()).expect("whole resident LN rsqrt"),
        gain_device,
        t,
        D,
    )?;
    let (hadamard, bound_point, centered_claim, scaled_claim) = hadamard_prove_resident(
        &point_ln,
        centered,
        scaled,
        claim0,
        &hadamard_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
        backend,
    )?;
    let x_open = open_matrix_resident_p(cx.stream, dom_x, x, t, D, &bound_point, backend)?;
    let mean_open = open_fp_vec_resident_p(
        cx.stream,
        lv.dom_mean,
        DeviceSlice::new(&lv.mean, 0, lv.mean.len()).expect("whole resident LN mean"),
        &bound_point[d_cb..],
        backend,
    )?;
    cx.zero.push(centered_claim.sub(x_open.sub(mean_open)));
    let gain_eval =
        eval_mle_counted(&lift_padded_i16(gain, d_cb), &bound_point[..d_cb], &mut cx.ctr_other);
    let rsqrt_open = open_fp_vec_resident_p(
        cx.stream,
        lv.dom_rout,
        DeviceSlice::new(&lv.rout, 0, lv.rout.len()).expect("whole resident LN rsqrt"),
        &bound_point[d_cb..],
        backend,
    )?;
    cx.zero.push(scaled_claim.sub(rsqrt_open.scale(gain_eval)));

    let rsqrt_instance = cx.inst_resident(
        TableKey::LnRsqrt,
        rsqrt_columns.view(0, 2)?,
        2,
        rsqrt_columns.entries(),
        &[Some(0), Some(16)],
        Vec::new(),
    )?;
    let rin_open = open_fp_vec_resident_p(
        cx.stream,
        lv.dom_rin,
        DeviceSlice::new(&lv.rin, 0, lv.rin.len()).expect("whole resident LN input"),
        &rsqrt_instance.point,
        cx.backend.as_deref_mut().expect("resident LN backend"),
    )?;
    cx.zero.push(rsqrt_instance.col_claims[0].value.sub(rin_open));
    let rout_open = open_fp_vec_resident_p(
        cx.stream,
        lv.dom_rout,
        DeviceSlice::new(&lv.rout, 0, lv.rout.len()).expect("whole resident LN output"),
        &rsqrt_instance.point,
        cx.backend.as_deref_mut().expect("resident LN backend"),
    )?;
    cx.zero.push(rsqrt_instance.col_claims[1].value.sub(rout_open));

    Ok(LnChainProof {
        inst_ln: site_ln.main.proof,
        inst_ln_stage1: site_ln.stage1.map(|stage1| stage1.proof),
        hadamard,
        inst_rsqrt: rsqrt_instance.proof,
    })
}

/// LN chain verifier (mirror of [`prove_ln_chain`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ln_chain(
    t: usize,
    s_ln: u32,
    gain: &[i16],
    bias: &[i16],
    x_keys: &[Fp2],
    lvk: &LnVecsK,
    proof: &LnChainProof,
    wire: &WireKey,
    cx: &mut BlockCtxV,
) -> Option<()> {
    let rb = pad_bits(t);
    let d_cb = pad_bits(D);
    let n_d = d_cb + rb;
    let shifts_pair = [Some(0u32), Some(16u32)];

    if (s_ln > 16) != proof.inst_ln_stage1.is_some() {
        return None;
    }
    let aux_ln = [(1usize, wire.point.clone(), wire.key)];
    let site_ln =
        verify_range_site(n_d, s_ln, &proof.inst_ln, proof.inst_ln_stage1.as_ref(), &aux_ln, cx)?;

    let pt_ln = site_ln.acc_point().to_vec();
    let k_acc_ln = site_ln.acc_key;
    let bias_lift = lift_padded_i16(bias, d_cb);
    let bias_eval = eval_mle(&bias_lift, &pt_ln[..d_cb]);
    let rmask = rowmask_eval(&pt_ln[d_cb..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << s_ln));
    let k_claim0_h = k_acc_ln.sub(VerifierKey::from_public(bias_term, cx.ctx.delta));
    let hd = HadamardDoms::alloc(&mut cx.doms, pt_ln.len());
    let (r_h, k_e, k_r) = hadamard_verify(
        &pt_ln,
        k_claim0_h,
        &proof.hadamard,
        &hd,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let x_k_r = open_matrix_k(x_keys, t, D, &r_h);
    let mean_k = open_fp_vec_k(&lvk.mean_keys, &r_h[d_cb..]);
    cx.kzero.push(k_e.sub(x_k_r.sub(mean_k)));
    let gain_lift = lift_padded_i16(gain, d_cb);
    let gain_eval = eval_mle(&gain_lift, &r_h[..d_cb]);
    let rsq_k_h = open_fp_vec_k(&lvk.rout_keys, &r_h[d_cb..]);
    cx.kzero.push(k_r.sub(rsq_k_h.scale(gain_eval)));

    let vr = cx.inst(TableKey::LnRsqrt, rb, &shifts_pair, &proof.inst_rsqrt, &[])?;
    let rin_k = open_fp_vec_k(&lvk.rin_keys, &vr.point);
    cx.kzero.push(vr.col_keys[0].key.sub(rin_k));
    let rout_k = open_fp_vec_k(&lvk.rout_keys, &vr.point);
    cx.kzero.push(vr.col_keys[1].key.sub(rout_k));
    Some(())
}

// ---------------------------------------------------------------------------
// FFN block (boundary auth HOISTED to the caller — prove_layer or the tests)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct FfnBlockProof {
    /// LN2 vector corrections: [mean, var, rsqrt_in, rsqrt_out].
    pub ln_vec_corrs: [Vec<u64>; 4],
    // Chain, reverse dataflow order.
    pub inst_down: BlindInstance,
    /// Stage-1 instance when shift_ffn_down > 16 (chained requant).
    pub inst_down_stage1: Option<BlindInstance>,
    pub gemm_down: ChainedGemmProof,
    pub gelu_wire_corr: Fp2,
    pub w_down_corr: Fp2,
    pub inst_gelu: BlindInstance,
    pub inst_up: BlindInstance,
    pub gemm_up: ChainedGemmProof,
    pub ln2_wire_corr: Fp2,
    pub w_up_corr: Fp2,
    pub ln: LnChainProof,
}

/// FFN phase-1 state: LN2 vectors authenticated, all FFN-side multiplicities
/// accumulated into the bank.
pub struct FfnP1 {
    pub(crate) lv: LnVecsP,
    pub(crate) ln_vec_corrs: [Vec<u64>; 4],
}

pub(crate) struct ResidentFfnP1 {
    pub(crate) lv: ResidentLnVecsP,
    pub(crate) ln_vec_corrs: [Vec<u64>; 4],
    pub(crate) down: DeviceLookupColumns,
    pub(crate) gelu: DeviceLookupColumns,
    pub(crate) up: DeviceLookupColumns,
    pub(crate) ln: DeviceLookupColumns,
    pub(crate) rsqrt: DeviceLookupColumns,
}

impl ResidentFfnP1 {
    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        for columns in [self.rsqrt, self.ln, self.up, self.gelu, self.down] {
            if let Err(error) = backend.free_lookup_columns(columns) {
                first.get_or_insert(error);
            }
        }
        if let Err(error) = self.lv.free(backend) {
            first.get_or_insert(error);
        }
        first.map_or(Ok(()), Err)
    }
}

/// FFN phase 1: bind everything the FFN instances will look up (LN vectors +
/// the content-global multiplicity contributions) BEFORE any α is drawn.
pub(crate) fn ffn_phase1(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
) -> FfnP1 {
    let t = wit.t;
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let f_cb = pad_bits(DFF);

    assert_ln_stats(
        &wit.attn_block_out,
        t,
        &wit.ln2_mean,
        &wit.ln2_var,
        &wit.ln2_rsqrt_in,
        &wit.ln2_rsqrt_out,
        luts,
    );
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv, ln_vec_corrs) = auth_ln_vecs_p(
        cx,
        rb,
        &wit.ln2_mean,
        &wit.ln2_var,
        &wit.ln2_rsqrt_in,
        &wit.ln2_rsqrt_out,
        rout_pad,
    );

    let (s_dn, s_up, s_ln) = (p.shift_ffn_down, p.shift_ffn_up, p.shift_ln_norm);
    add_range_mult(cx.bank, &wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn);
    assert_eq!(luts.gelu[0], 0, "gelu pad pair (0,0) requires gelu[0] == 0");
    let ff_pads = (t_pad << f_cb) - t * DFF;
    let mut mult_gelu = vec![0u32; 1 << 16];
    for &y in &wit.ffn_up_q {
        mult_gelu[(y as u16) as usize] += 1;
    }
    mult_gelu[0] += ff_pads as u32; // pad pair (0, gelu[0]=0) at index 0
    cx.bank.add_mult(TableKey::Gelu, &mult_gelu);
    add_range_mult(cx.bank, &wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    // The accumulator is an explicit witness wire; recomputation remains the
    // prover-side consistency assertion required by the logged LN deviation.
    let expected_acc_ln = ln_acc_recompute(
        &wit.attn_block_out,
        t,
        &wit.ln2_mean,
        &wit.ln2_rsqrt_out,
        &weights.ln2_gain,
        &weights.ln2_bias,
        s_ln,
    );
    assert_eq!(wit.ln2_acc, expected_acc_ln, "LN2 accumulator witness mismatch");
    add_range_mult(cx.bank, &wit.ln2_acc, &wit.ln2_out, t, D, s_ln);
    let mut mult_rsq = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq[wit.ln2_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq[0] += (t_pad - t) as u32; // pad pair (0, ln_rsqrt[0]) at index 0
    cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);

    FfnP1 { lv, ln_vec_corrs }
}

pub(crate) fn ffn_phase1_resident<W: ResidentLayerView>(
    wit: &W,
    luts: &Luts,
    error: DeviceSlice<'_, u32>,
    cx: &mut BlockCtxP,
) -> Result<ResidentFfnP1, AccelError> {
    let t = wit.rows();
    let p = luts.params;
    let rb = pad_bits(t);
    let backend = cx
        .backend
        .as_deref_mut()
        .ok_or(AccelError::InvalidInput("resident FFN phase 1 requires a backend"))?;
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv, ln_vec_corrs) = auth_ln_vecs_resident_p(
        wit.i64(LayerI64Field::Ln2Mean),
        wit.i64(LayerI64Field::Ln2Var),
        wit.i64(LayerI64Field::Ln2RsqrtIn),
        wit.i16(LayerI16Field::Ln2RsqrtOut),
        rb,
        rout_pad,
        cx.stream,
        cx.tx,
        &mut cx.doms,
        backend,
    )?;

    let mut sites = Vec::with_capacity(5);
    let result = (|| {
        sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::FfnDownAcc),
            wit.i16(LayerI16Field::FfnDownQ),
            error,
            t,
            D,
            p.shift_ffn_down,
            backend,
        )?);
        assert_eq!(luts.gelu[0], 0, "gelu pad pair requires (0,0)");
        sites.push(bind_pair_site_resident(
            cx.bank,
            TableKey::Gelu,
            wit.i16(LayerI16Field::FfnUpQ),
            wit.i16(LayerI16Field::GeluOut),
            t,
            DFF,
            Fp::ZERO,
            Fp::ZERO,
            true,
            backend,
        )?);
        sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::FfnUpAcc),
            wit.i16(LayerI16Field::FfnUpQ),
            error,
            t,
            DFF,
            p.shift_ffn_up,
            backend,
        )?);
        sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::Ln2Acc),
            wit.i16(LayerI16Field::Ln2Out),
            error,
            t,
            D,
            p.shift_ln_norm,
            backend,
        )?);
        sites.push(bind_pair_site_resident(
            cx.bank,
            TableKey::LnRsqrt,
            wit.i64(LayerI64Field::Ln2RsqrtIn),
            wit.i16(LayerI16Field::Ln2RsqrtOut),
            t,
            1,
            Fp::ZERO,
            rout_pad,
            false,
            backend,
        )?);
        Ok(())
    })();
    if let Err(error) = result {
        for columns in sites {
            let _ = backend.free_lookup_columns(columns);
        }
        let _ = lv.free(backend);
        return Err(error);
    }
    let mut sites = sites.into_iter();
    Ok(ResidentFfnP1 {
        lv,
        ln_vec_corrs,
        down: sites.next().expect("resident FFN down site"),
        gelu: sites.next().expect("resident FFN GELU site"),
        up: sites.next().expect("resident FFN up site"),
        ln: sites.next().expect("resident FFN LN site"),
        rsqrt: sites.next().expect("resident FFN rsqrt site"),
    })
}

/// Accumulate a range site's multiplicities (both chained stages for
/// shift > 16) into the bank under the content key(s).
pub fn add_range_mult(
    bank: &mut TableBankP,
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) {
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        bank.add_mult(key_main, &range_mult(acc, out, rows, cols, shift));
    } else {
        let (m1, m2) = range_mult_chained(acc, rows, cols, shift);
        bank.add_mult(key_main, &m2);
        bank.add_mult(key_s1.unwrap(), &m1);
    }
}

pub(crate) fn bind_range_site_resident<A: volta_accel::ResidentSignedElement>(
    bank: &mut TableBankP,
    accumulators: DeviceSlice<'_, A>,
    outputs: DeviceSlice<'_, i16>,
    error: DeviceSlice<'_, u32>,
    rows: usize,
    cols: usize,
    shift: u32,
    backend: &mut Backend,
) -> Result<DeviceLookupColumns, AccelError> {
    let columns =
        backend.requant_lookup_columns_device(accumulators, outputs, error, rows, cols, shift)?;
    let (key_main, key_stage1) = range_keys(shift);
    let result = (|| {
        if shift <= 16 {
            let mult = backend.histogram_fp_device(columns.column(0)?, 1 << shift)?;
            bank.add_mult_resident(key_main, mult, backend)
        } else {
            let stage1_shift = shift - 16;
            let mult_stage1 = backend.histogram_fp_device(columns.column(0)?, 1 << stage1_shift)?;
            bank.add_mult_resident(key_stage1.expect("chained range key"), mult_stage1, backend)?;
            let mult_main = backend.histogram_fp_device(columns.column(2)?, 1 << 16)?;
            bank.add_mult_resident(key_main, mult_main, backend)
        }
    })();
    if let Err(error) = result {
        let _ = backend.free_lookup_columns(columns);
        return Err(error);
    }
    Ok(columns)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bind_pair_site_resident<A: ResidentBaseElement, B: ResidentBaseElement>(
    bank: &mut TableBankP,
    key: TableKey,
    inputs: DeviceSlice<'_, A>,
    outputs: DeviceSlice<'_, B>,
    rows: usize,
    cols: usize,
    pad_input: Fp,
    pad_output: Fp,
    signed_input: bool,
    backend: &mut Backend,
) -> Result<DeviceLookupColumns, AccelError> {
    let columns = backend
        .pair_lookup_columns_base_device(inputs, outputs, rows, cols, pad_input, pad_output)?;
    let mult = match backend
        .histogram_lut_device(columns.column(0).expect("first pair column"), signed_input)
    {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_lookup_columns(columns);
            return Err(error);
        }
    };
    if let Err(error) = bank.add_mult_resident(key, mult, backend) {
        let _ = backend.free_lookup_columns(columns);
        return Err(error);
    }
    Ok(columns)
}

/// Prove the FFN half (phase 2). The caller has already authenticated the
/// `attn_block_out` / `ffn_block_out` boundaries at `dom_abo` / `dom_fbo`
/// and run [`ffn_phase1`]. Returns the proof and the weight claims
/// `[ffn_down, ffn_up]`.
pub(crate) struct FfnAfterDownP {
    lv: LnVecsP,
    ln_vec_corrs: [Vec<u64>; 4],
    inst_down: BlindInstance,
    inst_down_stage1: Option<BlindInstance>,
    gemm_down: ChainedGemmProof,
    gelu_wire: WireOut,
    w_down_corr: Fp2,
    wclaim_down: WeightClaimP,
}

impl FfnAfterDownP {
    pub(crate) fn gelu_aux_claim(&self) -> LeafAuxClaim {
        LeafAuxClaim { col: 1, point: self.gelu_wire.point.clone(), value: self.gelu_wire.value }
    }
}

/// Run one FFN through the committed down projection and stop at the GELU
/// dependency.  The P7b scheduler keeps one state per layer and resumes it
/// only after the canonical model-wide GELU cohort has completed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ffn_before_gelu(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: FfnP1,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> FfnAfterDownP {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let s_dn = luts.params.shift_ffn_down;
    let d_cb = pad_bits(D);
    let FfnP1 { lv, ln_vec_corrs } = p1;
    let site_dn = prove_range_site(&wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn, Vec::new(), cx);
    let pt_out = site_dn.main.point.clone();
    let f_open = open_matrix_p(cx.stream, dom_fbo, &wit.ffn_block_out, t, D, &pt_out);
    let a_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_out);
    cx.zero.push(site_dn.main.col_claims[1].value.sub(f_open).add(a_open));

    let pt = site_dn.acc_point().to_vec();
    let mut acc_dn_claim = site_dn.acc_claim;
    if let Some(b) = biases {
        acc_dn_claim = sub_bias_p(acc_dn_claim, &b.ffn_down, d_cb, &pt, t, s_dn, &mut cx.ctr_other);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (gemm_down, gelu_wire, w_down_corr, wclaim_down, _, _) = prove_gemm_committed_chained(
        &wit.gelu_out,
        &weights.ffn_down,
        t,
        DFF,
        D,
        r_i_dn,
        r_j_dn,
        acc_dn_claim,
        &cd_down,
        cx.stream,
        cx.tx,
    );
    FfnAfterDownP {
        lv,
        ln_vec_corrs,
        inst_down: site_dn.main.proof,
        inst_down_stage1: site_dn.stage1.map(|stage1| stage1.proof),
        gemm_down,
        gelu_wire,
        w_down_corr,
        wclaim_down,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ffn_after_gelu(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    state: FfnAfterDownP,
    inst_gelu: InstanceOutP,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> (FfnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    let s_up = luts.params.shift_ffn_up;
    let s_ln = luts.params.shift_ln_norm;
    let f_cb = pad_bits(DFF);
    assert!(s_up <= 16, "chained ffn_up requant not wired here");
    let (rem_up, out_up) = range_cols_padded(&wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    let inst_up = cx.inst(
        TableKey::Range(s_up),
        &[rem_up, out_up],
        &[Some(0), None],
        vec![LeafAuxClaim {
            col: 1,
            point: inst_gelu.point.clone(),
            value: inst_gelu.col_claims[0].value,
        }],
    );
    let mut acc_up_claim = transport_p(&inst_up, s_up);
    let pt_u = inst_up.point.clone();
    if let Some(b) = biases {
        acc_up_claim = sub_bias_p(acc_up_claim, &b.ffn_up, f_cb, &pt_u, t, s_up, &mut cx.ctr_other);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_up, wire_ln2, w_up_corr, wclaim_up, _, _) = prove_gemm_committed_chained(
        &wit.ln2_out,
        &weights.ffn_up,
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        acc_up_claim,
        &cd_up,
        cx.stream,
        cx.tx,
    );
    let ln = prove_ln_chain(
        t,
        s_ln,
        &wit.ln2_acc,
        &wit.ln2_out,
        &wit.attn_block_out,
        dom_abo,
        &wit.ln2_mean,
        &weights.ln2_gain,
        &weights.ln2_bias,
        &state.lv,
        &wire_ln2,
        cx,
    );
    (
        FfnBlockProof {
            ln_vec_corrs: state.ln_vec_corrs,
            inst_down: state.inst_down,
            inst_down_stage1: state.inst_down_stage1,
            gemm_down: state.gemm_down,
            gelu_wire_corr: state.gelu_wire.corr,
            w_down_corr: state.w_down_corr,
            inst_gelu: inst_gelu.proof,
            inst_up: inst_up.proof,
            gemm_up,
            ln2_wire_corr: wire_ln2.corr,
            w_up_corr,
            ln,
        },
        vec![state.wclaim_down, wclaim_up],
    )
}

pub(crate) fn prove_ffn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: FfnP1,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> (FfnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    let d_cb = pad_bits(D); // 10
    let f_cb = pad_bits(DFF); // 12
    let FfnP1 { lv, ln_vec_corrs } = p1;

    let s_dn = p.shift_ffn_down;
    let s_up = p.shift_ffn_up;
    let s_ln = p.shift_ln_norm;
    let acc_ln = &wit.ln2_acc;

    // ---- 1+2: ffn_down range site, closed against the residual ------------
    let site_dn = prove_range_site(&wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn, Vec::new(), cx);
    let inst_down = &site_dn.main;
    let pt_out = inst_down.point.clone();
    // Residual zero row: ffn_down_q̃(pt) − f̃bo(pt) + ãbo(pt) = 0, both
    // boundaries opened by streamed MAC opening at the instance's point.
    let f_open = open_matrix_p(cx.stream, dom_fbo, &wit.ffn_block_out, t, D, &pt_out);
    let a_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_out);
    cx.zero.push(inst_down.col_claims[1].value.sub(f_open).add(a_open));

    // ---- 3: acc transport → GEMM-down (committed, chained) ----------------
    let pt = site_dn.acc_point().to_vec();
    let mut acc_dn_claim = site_dn.acc_claim;
    if let Some(b) = biases {
        acc_dn_claim = sub_bias_p(acc_dn_claim, &b.ffn_down, d_cb, &pt, t, s_dn, &mut cx.ctr_other);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (gemm_down, wire_gelu, w_down_corr, wclaim_down, _tm_dn, _cc_dn) =
        prove_gemm_committed_chained(
            &wit.gelu_out,
            &weights.ffn_down,
            t,
            DFF,
            D,
            r_i_dn,
            r_j_dn,
            acc_dn_claim,
            &cd_down,
            cx.stream,
            cx.tx,
        );

    // ---- 4: gelu pair instance (drains the GEMM-down X wire claim) --------
    let (gelu_in, gelu_out_col) = pair_cols_padded(&wit.ffn_up_q, &wit.gelu_out, t, DFF, 0, 0);
    let inst_gelu = cx.inst(
        TableKey::Gelu,
        &[gelu_in, gelu_out_col],
        &[Some(0), Some(16)],
        vec![LeafAuxClaim { col: 1, point: wire_gelu.point.clone(), value: wire_gelu.value }],
    );
    // col_claims[1] (gelu out) is redundant post-fold: the external GEMM
    // claim was consolidated into the instance's own leaf closure. Dropped.

    // ---- 5: ffn_up range instance → GEMM-up -------------------------------
    assert!(s_up <= 16, "chained ffn_up requant not wired here");
    let (rem_up, out_up) = range_cols_padded(&wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    let inst_up = cx.inst(
        TableKey::Range(s_up),
        &[rem_up, out_up],
        &[Some(0), None],
        vec![LeafAuxClaim {
            col: 1,
            point: inst_gelu.point.clone(),
            value: inst_gelu.col_claims[0].value,
        }],
    );
    let mut acc_up_claim = transport_p(&inst_up, s_up);
    let pt_u = inst_up.point.clone();
    if let Some(b) = biases {
        acc_up_claim = sub_bias_p(acc_up_claim, &b.ffn_up, f_cb, &pt_u, t, s_up, &mut cx.ctr_other);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_up, wire_ln2, w_up_corr, wclaim_up, _tm_up, _cc_up) = prove_gemm_committed_chained(
        &wit.ln2_out,
        &weights.ffn_up,
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        acc_up_claim,
        &cd_up,
        cx.stream,
        cx.tx,
    );

    // ---- 6: LN2 chain ------------------------------------------------------
    let ln = prove_ln_chain(
        t,
        s_ln,
        acc_ln,
        &wit.ln2_out,
        &wit.attn_block_out,
        dom_abo,
        &wit.ln2_mean,
        &weights.ln2_gain,
        &weights.ln2_bias,
        &lv,
        &wire_ln2,
        cx,
    );

    let proof = FfnBlockProof {
        ln_vec_corrs,
        inst_down: site_dn.main.proof,
        inst_down_stage1: site_dn.stage1.map(|s1| s1.proof),
        gemm_down,
        gelu_wire_corr: wire_gelu.corr,
        w_down_corr,
        inst_gelu: inst_gelu.proof,
        inst_up: inst_up.proof,
        gemm_up,
        ln2_wire_corr: wire_ln2.corr,
        w_up_corr,
        ln,
    };
    (proof, vec![wclaim_down, wclaim_up])
}

pub(crate) struct ResidentFfnAfterDownP {
    p1: ResidentFfnP1,
    inst_down: BlindInstance,
    inst_down_stage1: Option<BlindInstance>,
    gemm_down: ChainedGemmProof,
    gelu_wire: WireOut,
    w_down_corr: Fp2,
    wclaim_down: WeightClaimP,
}

impl ResidentFfnAfterDownP {
    pub(crate) fn gelu_columns(&self) -> Result<DeviceSlice<'_, u64>, AccelError> {
        self.p1.gelu.view(0, 2)
    }

    pub(crate) fn gelu_entries(&self) -> usize {
        self.p1.gelu.entries()
    }

    pub(crate) fn gelu_aux_claim(&self) -> LeafAuxClaim {
        LeafAuxClaim { col: 1, point: self.gelu_wire.point.clone(), value: self.gelu_wire.value }
    }

    pub(crate) fn cleanup(self, backend: &mut Backend) -> Result<(), AccelError> {
        self.p1.free(backend)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ffn_before_gelu_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    _weights: &LayerWeights,
    luts: &Luts,
    p1: ResidentFfnP1,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> Result<ResidentFfnAfterDownP, AccelError> {
    let result = (|| {
        let t = wit.rows();
        if t < 2 {
            return Err(AccelError::InvalidInput("resident FFN proof needs at least two rows"));
        }
        let params = luts.params;
        let d_cb = pad_bits(D);
        let down_site = prove_range_site_resident(&p1.down, params.shift_ffn_down, Vec::new(), cx)?;
        let output_point = down_site.main.point.clone();
        let backend = cx
            .backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident FFN proof requires a backend"))?;
        let ffn_boundary = open_matrix_resident_p(
            cx.stream,
            dom_fbo,
            wit.i16(LayerI16Field::FfnBlockOut),
            t,
            D,
            &output_point,
            backend,
        )?;
        let attn_boundary = open_matrix_resident_p(
            cx.stream,
            dom_abo,
            wit.i16(LayerI16Field::AttnBlockOut),
            t,
            D,
            &output_point,
            backend,
        )?;
        cx.zero.push(down_site.main.col_claims[1].value.sub(ffn_boundary).add(attn_boundary));
        let down_point = down_site.acc_point().to_vec();
        let mut down_claim = down_site.acc_claim;
        if let Some(biases) = biases {
            down_claim = sub_bias_p(
                down_claim,
                &biases.ffn_down,
                d_cb,
                &down_point,
                t,
                params.shift_ffn_down,
                &mut cx.ctr_other,
            );
        }
        let (r_j_down, r_i_down) = down_point.split_at(d_cb);
        let down_doms = ChainDoms::alloc(&mut cx.doms, DFF);
        let (gemm_down, gelu_wire, w_down_corr, wclaim_down, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::GeluOut),
                resident_model.layer_weight(layer, LayerWeightField::FfnDown)?,
                t,
                DFF,
                D,
                r_i_down,
                r_j_down,
                down_claim,
                &down_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident FFN backend"),
            )?;
        Ok((
            down_site.main.proof,
            down_site.stage1.map(|stage1| stage1.proof),
            gemm_down,
            gelu_wire,
            w_down_corr,
            wclaim_down,
        ))
    })();
    match result {
        Ok((inst_down, inst_down_stage1, gemm_down, gelu_wire, w_down_corr, wclaim_down)) => {
            Ok(ResidentFfnAfterDownP {
                p1,
                inst_down,
                inst_down_stage1,
                gemm_down,
                gelu_wire,
                w_down_corr,
                wclaim_down,
            })
        }
        Err(error) => {
            let cleanup = p1.free(
                cx.backend
                    .as_deref_mut()
                    .ok_or(AccelError::InvalidInput("resident FFN cleanup requires a backend"))?,
            );
            match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ffn_after_gelu_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    weights: &LayerWeights,
    luts: &Luts,
    mut state: ResidentFfnAfterDownP,
    gelu: InstanceOutP,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> Result<(FfnBlockProof, Vec<WeightClaimP>), AccelError> {
    let result = (|| {
        let t = wit.rows();
        let params = luts.params;
        let f_cb = pad_bits(DFF);
        if params.shift_ffn_up > 16 {
            return Err(AccelError::InvalidInput(
                "resident FFN-up chained proof is not represented in FfnBlockProof",
            ));
        }
        let up_site = prove_range_site_resident(
            &state.p1.up,
            params.shift_ffn_up,
            vec![LeafAuxClaim {
                col: 1,
                point: gelu.point.clone(),
                value: gelu.col_claims[0].value,
            }],
            cx,
        )?;
        debug_assert!(up_site.stage1.is_none());
        let up_point = up_site.main.point.clone();
        let mut up_claim = up_site.acc_claim;
        if let Some(biases) = biases {
            up_claim = sub_bias_p(
                up_claim,
                &biases.ffn_up,
                f_cb,
                &up_point,
                t,
                params.shift_ffn_up,
                &mut cx.ctr_other,
            );
        }
        let (r_j_up, r_i_up) = up_point.split_at(f_cb);
        let up_doms = ChainDoms::alloc(&mut cx.doms, D);
        let (gemm_up, wire_ln2, w_up_corr, wclaim_up, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::Ln2Out),
                resident_model.layer_weight(layer, LayerWeightField::FfnUp)?,
                t,
                D,
                DFF,
                r_i_up,
                r_j_up,
                up_claim,
                &up_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident FFN backend"),
            )?;
        let ln = prove_ln_chain_resident(
            t,
            params.shift_ln_norm,
            &state.p1.ln,
            &state.p1.rsqrt,
            wit.i16(LayerI16Field::AttnBlockOut),
            dom_abo,
            resident_model.layer_weight(layer, LayerWeightField::Ln2Gain)?,
            &weights.ln2_gain,
            &weights.ln2_bias,
            &state.p1.lv,
            &wire_ln2,
            cx,
        )?;
        let ln_vec_corrs = std::mem::take(&mut state.p1.ln_vec_corrs);
        Ok((
            FfnBlockProof {
                ln_vec_corrs,
                inst_down: state.inst_down,
                inst_down_stage1: state.inst_down_stage1,
                gemm_down: state.gemm_down,
                gelu_wire_corr: state.gelu_wire.corr,
                w_down_corr: state.w_down_corr,
                inst_gelu: gelu.proof,
                inst_up: up_site.main.proof,
                gemm_up,
                ln2_wire_corr: wire_ln2.corr,
                w_up_corr,
                ln,
            },
            vec![state.wclaim_down, wclaim_up],
        ))
    })();
    let free_result = state.p1.free(
        cx.backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident FFN cleanup requires a backend"))?,
    );
    match (result, free_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
// Retained as the standalone resident-layer compatibility path exercised by
// the CUDA differentials; response proving uses the scheduled split API.
#[allow(dead_code)]
pub(crate) fn prove_ffn_block_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    weights: &LayerWeights,
    luts: &Luts,
    mut p1: ResidentFfnP1,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> Result<(FfnBlockProof, Vec<WeightClaimP>), AccelError> {
    let result = (|| {
        let t = wit.rows();
        if t < 2 {
            return Err(AccelError::InvalidInput("resident FFN proof needs at least two rows"));
        }
        let params = luts.params;
        let d_cb = pad_bits(D);
        let f_cb = pad_bits(DFF);

        let down_site = prove_range_site_resident(&p1.down, params.shift_ffn_down, Vec::new(), cx)?;
        let output_point = down_site.main.point.clone();
        let backend = cx
            .backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident FFN proof requires a backend"))?;
        let ffn_boundary = open_matrix_resident_p(
            cx.stream,
            dom_fbo,
            wit.i16(LayerI16Field::FfnBlockOut),
            t,
            D,
            &output_point,
            backend,
        )?;
        let attn_boundary = open_matrix_resident_p(
            cx.stream,
            dom_abo,
            wit.i16(LayerI16Field::AttnBlockOut),
            t,
            D,
            &output_point,
            backend,
        )?;
        cx.zero.push(down_site.main.col_claims[1].value.sub(ffn_boundary).add(attn_boundary));

        let down_point = down_site.acc_point().to_vec();
        let mut down_claim = down_site.acc_claim;
        if let Some(biases) = biases {
            down_claim = sub_bias_p(
                down_claim,
                &biases.ffn_down,
                d_cb,
                &down_point,
                t,
                params.shift_ffn_down,
                &mut cx.ctr_other,
            );
        }
        let (r_j_down, r_i_down) = down_point.split_at(d_cb);
        let down_doms = ChainDoms::alloc(&mut cx.doms, DFF);
        let (gemm_down, wire_gelu, w_down_corr, wclaim_down, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::GeluOut),
                resident_model.layer_weight(layer, LayerWeightField::FfnDown)?,
                t,
                DFF,
                D,
                r_i_down,
                r_j_down,
                down_claim,
                &down_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident FFN backend"),
            )?;

        let gelu = cx.inst_resident(
            TableKey::Gelu,
            p1.gelu.view(0, 2)?,
            2,
            p1.gelu.entries(),
            &[Some(0), Some(16)],
            vec![LeafAuxClaim { col: 1, point: wire_gelu.point.clone(), value: wire_gelu.value }],
        )?;

        if params.shift_ffn_up > 16 {
            return Err(AccelError::InvalidInput(
                "resident FFN-up chained proof is not represented in FfnBlockProof",
            ));
        }
        let up_site = prove_range_site_resident(
            &p1.up,
            params.shift_ffn_up,
            vec![LeafAuxClaim {
                col: 1,
                point: gelu.point.clone(),
                value: gelu.col_claims[0].value,
            }],
            cx,
        )?;
        debug_assert!(up_site.stage1.is_none());
        let up_point = up_site.main.point.clone();
        let mut up_claim = up_site.acc_claim;
        if let Some(biases) = biases {
            up_claim = sub_bias_p(
                up_claim,
                &biases.ffn_up,
                f_cb,
                &up_point,
                t,
                params.shift_ffn_up,
                &mut cx.ctr_other,
            );
        }
        let (r_j_up, r_i_up) = up_point.split_at(f_cb);
        let up_doms = ChainDoms::alloc(&mut cx.doms, D);
        let (gemm_up, wire_ln2, w_up_corr, wclaim_up, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::Ln2Out),
                resident_model.layer_weight(layer, LayerWeightField::FfnUp)?,
                t,
                D,
                DFF,
                r_i_up,
                r_j_up,
                up_claim,
                &up_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident FFN backend"),
            )?;

        let ln = prove_ln_chain_resident(
            t,
            params.shift_ln_norm,
            &p1.ln,
            &p1.rsqrt,
            wit.i16(LayerI16Field::AttnBlockOut),
            dom_abo,
            resident_model.layer_weight(layer, LayerWeightField::Ln2Gain)?,
            &weights.ln2_gain,
            &weights.ln2_bias,
            &p1.lv,
            &wire_ln2,
            cx,
        )?;
        let ln_vec_corrs = std::mem::take(&mut p1.ln_vec_corrs);
        Ok((
            FfnBlockProof {
                ln_vec_corrs,
                inst_down: down_site.main.proof,
                inst_down_stage1: down_site.stage1.map(|stage1| stage1.proof),
                gemm_down,
                gelu_wire_corr: wire_gelu.corr,
                w_down_corr,
                inst_gelu: gelu.proof,
                inst_up: up_site.main.proof,
                gemm_up,
                ln2_wire_corr: wire_ln2.corr,
                w_up_corr,
                ln,
            },
            vec![wclaim_down, wclaim_up],
        ))
    })();
    let free_result = p1.free(
        cx.backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident FFN cleanup requires a backend"))?,
    );
    match (result, free_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// Verify the FFN half. `abo_keys`/`fbo_keys` are the cached boundary keys
/// (expanded by the caller). On success returns the `[ffn_down, ffn_up]`
/// weight-claim (point, key) pairs; the caller must still close the
/// accumulated `kprod`/`kzero` batches.
pub(crate) struct FfnAfterDownV {
    gelu_wire: WireKey,
    w_pt_down: Vec<Fp2>,
    w_key_down: VerifierKey,
}

impl FfnAfterDownV {
    pub(crate) fn gelu_aux(&self) -> (usize, Vec<Fp2>, VerifierKey) {
        (1, self.gelu_wire.point.clone(), self.gelu_wire.key)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ffn_before_gelu(
    t: usize,
    luts: &Luts,
    proof: &FfnBlockProof,
    cx: &mut BlockCtxV,
    abo_keys: &[Fp2],
    fbo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<FfnAfterDownV> {
    let rb = pad_bits(t);
    let d_cb = pad_bits(D);
    let s_dn = luts.params.shift_ffn_down;
    let n_d = d_cb + rb;
    let site_dn =
        verify_range_site(n_d, s_dn, &proof.inst_down, proof.inst_down_stage1.as_ref(), &[], cx)?;
    let pt_out = site_dn.main.point.clone();
    let f_k = open_matrix_k(fbo_keys, t, D, &pt_out);
    let a_k = open_matrix_k(abo_keys, t, D, &pt_out);
    cx.kzero.push(site_dn.main.col_keys[1].key.sub(f_k).add(a_k));
    let pt = site_dn.acc_point().to_vec();
    let mut k_acc_dn = site_dn.acc_key;
    if let Some(b) = biases {
        k_acc_dn = sub_bias_k(k_acc_dn, &b.ffn_down, d_cb, &pt, t, s_dn, cx.ctx.delta);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (gelu_wire, w_pt_down, w_key_down) = verify_gemm_committed_chained(
        t,
        DFF,
        D,
        r_i_dn,
        r_j_dn,
        k_acc_dn,
        &proof.gemm_down,
        proof.gelu_wire_corr,
        proof.w_down_corr,
        &cd_down,
        cx.ctx,
        cx.tx,
    )?;
    Some(FfnAfterDownV { gelu_wire, w_pt_down, w_key_down })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ffn_after_gelu(
    t: usize,
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &FfnBlockProof,
    lvk: &LnVecsK,
    state: FfnAfterDownV,
    gelu: InstanceOutV,
    cx: &mut BlockCtxV,
    abo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let s_up = luts.params.shift_ffn_up;
    let s_ln = luts.params.shift_ln_norm;
    if s_up > 16 || (s_ln > 16) != proof.ln.inst_ln_stage1.is_some() {
        return None;
    }
    let rb = pad_bits(t);
    let f_cb = pad_bits(DFF);
    let n_ff = f_cb + rb;
    let shifts_range = [Some(0u32), None];
    let aux_up = [(1usize, gelu.point.clone(), gelu.col_keys[0].key)];
    let vu = cx.inst(TableKey::Range(s_up), n_ff, &shifts_range, &proof.inst_up, &aux_up)?;
    let mut k_acc_up = transport_k(&vu, s_up, cx.ctx.delta);
    let pt_u = vu.point.clone();
    if let Some(b) = biases {
        k_acc_up = sub_bias_k(k_acc_up, &b.ffn_up, f_cb, &pt_u, t, s_up, cx.ctx.delta);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_ln2, w_pt_up, k_w_up) = verify_gemm_committed_chained(
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        k_acc_up,
        &proof.gemm_up,
        proof.ln2_wire_corr,
        proof.w_up_corr,
        &cd_up,
        cx.ctx,
        cx.tx,
    )?;
    verify_ln_chain(t, s_ln, ln2_gain, ln2_bias, abo_keys, lvk, &proof.ln, &wk_ln2, cx)?;
    Some(vec![(state.w_pt_down, state.w_key_down), (w_pt_up, k_w_up)])
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ffn_block(
    t: usize,
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &FfnBlockProof,
    lvk: &LnVecsK,
    cx: &mut BlockCtxV,
    abo_keys: &[Fp2],
    fbo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D);
    let f_cb = pad_bits(DFF);
    let s_dn = p.shift_ffn_down;
    let s_up = p.shift_ffn_up;
    let s_ln = p.shift_ln_norm;

    if (s_ln > 16) != proof.ln.inst_ln_stage1.is_some() {
        return None;
    }
    let _ = t_pad;

    // ---- ffn_down site + residual + transport → GEMM-down ------------------
    let n_d = d_cb + rb;
    let n_ff = f_cb + rb;
    let shifts_range = [Some(0u32), None];
    let site_dn =
        verify_range_site(n_d, s_dn, &proof.inst_down, proof.inst_down_stage1.as_ref(), &[], cx)?;
    let vd = &site_dn.main;
    let pt_out = vd.point.clone();
    let f_k = open_matrix_k(fbo_keys, t, D, &pt_out);
    let a_k = open_matrix_k(abo_keys, t, D, &pt_out);
    cx.kzero.push(vd.col_keys[1].key.sub(f_k).add(a_k));

    let pt = site_dn.acc_point().to_vec();
    let mut k_acc_dn = site_dn.acc_key;
    if let Some(b) = biases {
        k_acc_dn = sub_bias_k(k_acc_dn, &b.ffn_down, d_cb, &pt, t, s_dn, cx.ctx.delta);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (wk_gelu, w_pt_dn, k_w_dn) = verify_gemm_committed_chained(
        t,
        DFF,
        D,
        r_i_dn,
        r_j_dn,
        k_acc_dn,
        &proof.gemm_down,
        proof.gelu_wire_corr,
        proof.w_down_corr,
        &cd_down,
        cx.ctx,
        cx.tx,
    )?;

    // ---- gelu instance -----------------------------------------------------
    let shifts_pair = [Some(0u32), Some(16u32)];
    let aux_gelu = [(1usize, wk_gelu.point.clone(), wk_gelu.key)];
    let vg = cx.inst(TableKey::Gelu, n_ff, &shifts_pair, &proof.inst_gelu, &aux_gelu)?;

    // ---- ffn_up instance + transport → GEMM-up -----------------------------
    if s_up > 16 {
        return None;
    }
    let aux_up = [(1usize, vg.point.clone(), vg.col_keys[0].key)];
    let vu = cx.inst(TableKey::Range(s_up), n_ff, &shifts_range, &proof.inst_up, &aux_up)?;
    let mut k_acc_up = transport_k(&vu, s_up, cx.ctx.delta);
    let pt_u = vu.point.clone();
    if let Some(b) = biases {
        k_acc_up = sub_bias_k(k_acc_up, &b.ffn_up, f_cb, &pt_u, t, s_up, cx.ctx.delta);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_ln2, w_pt_up, k_w_up) = verify_gemm_committed_chained(
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        k_acc_up,
        &proof.gemm_up,
        proof.ln2_wire_corr,
        proof.w_up_corr,
        &cd_up,
        cx.ctx,
        cx.tx,
    )?;

    // ---- LN2 chain ----------------------------------------------------------
    verify_ln_chain(t, s_ln, ln2_gain, ln2_bias, abo_keys, lvk, &proof.ln, &wk_ln2, cx)?;

    Some(vec![(w_pt_dn, k_w_dn), (w_pt_up, k_w_up)])
}

// ---------------------------------------------------------------------------
// Attention block — prover-side derived wires
// ---------------------------------------------------------------------------

/// The c_attn weight tensor on the PERMUTED padded 768×4096 column layout
/// (col' = third·1024 + head·64 + l). The P4 layer PCS commits THIS layout.
pub fn cattn_permuted(c_attn: &[i16]) -> Vec<i16> {
    assert_eq!(c_attn.len(), D * 3 * D);
    let mut w = vec![0i16; D * 4096];
    for r in 0..D {
        for j in 0..3 * D {
            let third = j / D;
            let rest = j % D;
            w[r * 4096 + third * 1024 + rest] = c_attn[r * 3 * D + j];
        }
    }
    w
}

/// The c_attn bias vector on the SAME permuted length-4096 column layout as
/// [`cattn_permuted`] (col' = third·1024 + rest, `rest` = head·64 + l), zero
/// at the pad columns (head 12..16 and third 3). Mirrors `cattn_permuted`'s
/// index math exactly, applied to a length-3D vector instead of a D×3D
/// matrix.
pub fn cattn_bias_permuted(c_attn_bias: &[i16]) -> Vec<i16> {
    assert_eq!(c_attn_bias.len(), 3 * D);
    let mut b = vec![0i16; 4096];
    for j in 0..3 * D {
        let third = j / D;
        let rest = j % D;
        b[third * 1024 + rest] = c_attn_bias[j];
    }
    b
}

/// Prover-side derived attention wires: the rectangular expansions of the
/// causal-packed witness fields plus the small authenticated row tables and
/// the recomputed above-diagonal QKᵀ accumulators. Built honestly by
/// [`build_attn_wires`]; the tamper tests mutate a copy (cheating-prover
/// emulation, as in the FFN tests).
/// Band-general view of one layer's attention witness: causal-packed wires
/// with per-row windows `t0+i+1` plus the layer's K cache segments (prefill
/// segment(s) followed by the band's own new rows). The square/prefill case
/// is `BandAttnRefs::square` (t0 = 0, single own segment).
pub struct BandAttnRefs<'a> {
    pub shape: BandShape,
    pub scores_acc: &'a [i64],
    pub scores_q: &'a [i16],
    pub exp_out: &'a [i16],
    pub softmax_w: &'a [i16],
    /// h×q row tables.
    pub row_shift: &'a [i16],
    pub denoms: &'a [i64],
    pub recips: &'a [i16],
    /// q×D.
    pub q_mat: &'a [i16],
    /// K cache segment data (rows×D each), Σ rows = s; the LAST segment is
    /// the band's own K rows.
    pub k_cache: Vec<&'a [i16]>,
}

impl<'a> BandAttnRefs<'a> {
    pub fn square(wit: &'a LayerWitness) -> Self {
        BandAttnRefs {
            shape: BandShape::square(wit.t),
            scores_acc: &wit.scores_acc,
            scores_q: &wit.scores_q,
            exp_out: &wit.exp_out,
            softmax_w: &wit.softmax_w,
            row_shift: &wit.row_shift,
            denoms: &wit.denoms,
            recips: &wit.recips,
            q_mat: &wit.q,
            k_cache: vec![&wit.k],
        }
    }

    /// Band view: `wit` is the band-packed LayerWitness (t = q, windows
    /// t0+i+1); `prefix_k` are the earlier phases' K segments.
    pub fn banded(wit: &'a LayerWitness, shape: BandShape, prefix_k: &[&'a [i16]]) -> Self {
        assert_eq!(wit.t, shape.q);
        let mut k_cache: Vec<&'a [i16]> = prefix_k.to_vec();
        k_cache.push(&wit.k);
        assert_eq!(k_cache.iter().map(|k| k.len()).sum::<usize>(), shape.s() * D);
        BandAttnRefs {
            shape,
            scores_acc: &wit.scores_acc,
            scores_q: &wit.scores_q,
            exp_out: &wit.exp_out,
            softmax_w: &wit.softmax_w,
            row_shift: &wit.row_shift,
            denoms: &wit.denoms,
            recips: &wit.recips,
            q_mat: &wit.q,
            k_cache,
        }
    }
}

pub struct AttnWires {
    pub shape: BandShape,
    /// h_pad×q_pad×s_pad, non-causal = exp pad INPUT (least zero-output idx).
    pub scores_rect: Vec<i16>,
    /// The SHARED scores/exp wire (P5 stable softmax): causal = s − c_row,
    /// non-causal/pads = the exp pad input. With `softmax_row_shift` off
    /// (c ≡ 0) this is byte-identical to `scores_rect`.
    pub sprime_rect: Vec<i16>,
    /// h_pad×q_pad row table of the per-(head,row) shifts c (pads 0).
    pub row_shift_row: Vec<i16>,
    /// Row-max indicator: 1 at the first causal position with s′ = 0 of each
    /// real row, 0 elsewhere (all zeros when the flag is off — unused).
    pub is_max_rect: Vec<i16>,
    /// h_pad×q_pad×s_pad, non-causal = 0 (the exp pad pair's output).
    pub exp_rect: Vec<i16>,
    /// h_pad×q_pad×s_pad, non-causal = 0.
    pub w_rect: Vec<i16>,
    /// The copy the causal sumcheck's B leg folds (== w_rect honestly).
    pub w_rect_causal: Vec<i16>,
    /// Full per-head Q·Kᵀ accumulators over the CACHE (H·q·s, row-major q×s
    /// per head) — recomputed; the forward discards the above-causal half.
    pub acc_full: Vec<i64>,
    /// Above-causal accumulators in fixed order (h, then i, then j≥win(i)).
    pub above_acc: Vec<i64>,
    /// h_pad·q_pad row tables (index = head·q_pad + i), zero pads.
    pub denoms_row: Vec<i64>,
    pub recip_in_row: Vec<i64>,
    /// Pads = softmax_recip[0] (the pad PAIR output — mirrors ln_rsqrt).
    pub recips_row: Vec<i16>,
    /// Least exp-LUT index with output 0 (upholds the zero row sums).
    pub exp_pad_u: usize,
}

impl AttnWires {
    pub fn exp_pad_in(&self) -> i16 {
        (self.exp_pad_u as u16) as i16
    }
}

/// Square/prefill wires (band with t0 = 0).
pub fn build_attn_wires(wit: &LayerWitness, luts: &Luts) -> AttnWires {
    build_attn_wires_band(&BandAttnRefs::square(wit), luts)
}

pub fn build_attn_wires_band(b: &BandAttnRefs, luts: &Luts) -> AttnWires {
    let sh = b.shape;
    let (q, s) = (sh.q, sh.s());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let caus = sh.caus();

    // Exp pad pair: (pad_in, 0) — asserted to exist (exp underflows to 0).
    let exp_pad_u = (0..1usize << 16)
        .find(|&u| luts.exp[u] == 0)
        .expect("exp LUT has no zero output — rectangular padding impossible");
    let pad_in = (exp_pad_u as u16) as i16;

    let mut scores_rect = vec![pad_in; H_PAD * sp2];
    let mut sprime_rect = vec![pad_in; H_PAD * sp2];
    let mut exp_rect = vec![0i16; H_PAD * sp2];
    let mut w_rect = vec![0i16; H_PAD * sp2];
    let row_shift_on = luts.params.softmax_row_shift;
    let mut row_shift_row = vec![0i16; H_PAD * q_pad];
    let mut is_max_rect = vec![0i16; H_PAD * sp2];
    for h in 0..H {
        for i in 0..q {
            let c = if row_shift_on { b.row_shift[h * q + i] } else { 0 };
            row_shift_row[h * q_pad + i] = c;
            let mut max_marked = false;
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                let y = h * sp2 + i * s_pad + j;
                scores_rect[y] = b.scores_q[pidx];
                let sp = b.scores_q[pidx] as i32 - c as i32;
                assert!(sp >= i16::MIN as i32, "row spread exceeds the exp domain");
                sprime_rect[y] = sp as i16;
                if row_shift_on && sp == 0 && !max_marked {
                    is_max_rect[y] = 1;
                    max_marked = true;
                }
                exp_rect[y] = b.exp_out[pidx];
                w_rect[y] = b.softmax_w[pidx];
            }
            assert!(
                !row_shift_on || max_marked,
                "row shift is not the row max (no zero s′ in row)"
            );
        }
    }

    // Recompute the FULL per-head Q·Kᵀ accumulators over the cache.
    let k_all: Vec<i16> = {
        let mut v = Vec::with_capacity(s * D);
        for seg in &b.k_cache {
            v.extend_from_slice(seg);
        }
        v
    };
    assert_eq!(k_all.len(), s * D);
    let mut acc_full = vec![0i64; H * q * s];
    let mut above_acc = Vec::with_capacity(H * sh.n_above_head());
    for h in 0..H {
        let mut qh = vec![0i16; q * DH];
        let mut kht = vec![0i16; DH * s];
        for i in 0..q {
            for l in 0..DH {
                qh[i * DH + l] = b.q_mat[i * D + h * DH + l];
            }
        }
        for j in 0..s {
            for l in 0..DH {
                kht[l * s + j] = k_all[j * D + h * DH + l];
            }
        }
        let s_full = gemm_i64(&qh, &kht, q, DH, s);
        for i in 0..q {
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                assert_eq!(
                    s_full[i * s + j],
                    b.scores_acc[pidx],
                    "witness scores_acc inconsistent with Q·Kᵀ recompute"
                );
            }
        }
        acc_full[h * q * s..(h + 1) * q * s].copy_from_slice(&s_full);
        for i in 0..q {
            for j in sh.win(i)..s {
                above_acc.push(s_full[i * s + j]);
            }
        }
    }

    // Row tables + the P4-DEVIATION(recip-in) prover-side consistency check.
    let recip0 = luts.softmax_recip[0];
    let mut denoms_row = vec![0i64; H_PAD * q_pad];
    let mut recip_in_row = vec![0i64; H_PAD * q_pad];
    let mut recips_row = vec![recip0; H_PAD * q_pad];
    for idx in 0..H_PAD * q_pad {
        let (h, i) = (idx / q_pad, idx % q_pad);
        if h >= H || i >= q {
            denoms_row[idx] = 0;
            recip_in_row[idx] = 0;
            continue;
        }
        let denom = b.denoms[h * q + i];
        let rin = denom >> luts.params.recip_den_shift;
        assert!(rin < 1 << 16, "softmax_recip input exceeds u16 domain");
        assert_eq!(
            luts.softmax_recip[rin as usize],
            b.recips[h * q + i],
            "P4-DEVIATION(recip-in): recips inconsistent with denoms >> shift"
        );
        denoms_row[idx] = denom;
        recip_in_row[idx] = rin;
        recips_row[idx] = b.recips[h * q + i];
    }

    AttnWires {
        shape: sh,
        scores_rect,
        sprime_rect,
        row_shift_row,
        is_max_rect,
        exp_rect,
        w_rect_causal: w_rect.clone(),
        w_rect,
        acc_full,
        above_acc,
        denoms_row,
        recip_in_row,
        recips_row,
        exp_pad_u,
    }
}

// ---------------------------------------------------------------------------
// Attention block — proof object
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct AttnBlockProof {
    /// LN1 vector corrections: [mean, var, rsqrt_in, rsqrt_out].
    pub ln_vec_corrs: [Vec<u64>; 4],
    pub denoms_corr: Vec<u64>,
    pub recip_in_corr: Vec<u64>,
    pub recips_corr: Vec<u64>,
    /// Above-diagonal QKᵀ accumulators (fixed sparse order), 8 B each.
    pub above_corr: Vec<u64>,
    /// P5 stable softmax (present iff softmax_row_shift): the authenticated
    /// row-shift table c, the is_max∘s′ ≡ 0 hadamard, and the is_max rowsum
    /// correction.
    pub row_shift_corr: Option<Vec<u64>>,
    pub hadamard2: Option<HadamardProof>,
    pub ismax_rowsum_corr: Option<Fp2>,
    // Chain, reverse dataflow order.
    pub inst_proj: BlindInstance,
    /// Stage-1 instance when shift_attn_proj > 16 (P5 chained requant,
    /// per-layer residual scales).
    pub inst_proj_stage1: Option<BlindInstance>,
    pub gemm_proj: ChainedGemmProof,
    pub av_wire_corr: Fp2,
    pub w_proj_corr: Fp2,
    pub inst_av: BlindInstance,
    pub av_split_corrs: [Fp2; H],
    pub gemm_wv: Vec<(ChainedGemmProof, Fp2)>,
    pub causal: BlindSumcheckProof,
    pub causal_w_corr: Fp2,
    pub inst_sn: BlindInstance,
    pub hadamard: HadamardProof,
    pub rowsum_corr: Fp2,
    pub inst_exp: BlindInstance,
    pub inst_recip: BlindInstance,
    pub inst_sc: BlindInstance,
    pub sc_split_corrs: [Fp2; H],
    pub gemm_qk: Vec<(ChainedGemmProof, Fp2)>,
    pub inst_qkv: BlindInstance,
    pub gemm_cattn: ChainedGemmProof,
    pub ln1_wire_corr: Fp2,
    pub w_cattn_corr: Fp2,
    pub ln: LnChainProof,
}

/// Close the two authenticated row-table columns after attention step 11.
/// The lookup itself may be the legacy singleton or an output returned by a
/// sealed [`crate::attn_schedule`] cohort; the MAC-opening obligations are
/// identical and remain owned by the block proof.
pub(crate) fn close_softmax_recip_cpu(
    instance: &InstanceOutP,
    dom_rin: u64,
    rin: &[Fp],
    dom_recips: u64,
    recips: &[Fp],
    cx: &mut BlockCtxP,
) {
    let rin_open = open_fp_vec_p(cx.stream, dom_rin, rin, &instance.point);
    cx.zero.push(instance.col_claims[0].value.sub(rin_open));
    let recips_open = open_fp_vec_p(cx.stream, dom_recips, recips, &instance.point);
    cx.zero.push(instance.col_claims[1].value.sub(recips_open));
}

pub(crate) fn close_softmax_recip_resident(
    instance: &InstanceOutP,
    dom_rin: u64,
    rin: DeviceSlice<'_, u64>,
    dom_recips: u64,
    recips: DeviceSlice<'_, u64>,
    cx: &mut BlockCtxP,
) -> Result<(), AccelError> {
    let backend = cx
        .backend
        .as_deref_mut()
        .ok_or(AccelError::InvalidInput("resident reciprocal closure requires a backend"))?;
    let rin_open = open_fp_vec_resident_p(cx.stream, dom_rin, rin, &instance.point, backend)?;
    cx.zero.push(instance.col_claims[0].value.sub(rin_open));
    let recips_open = open_fp_vec_resident_p(
        cx.stream,
        dom_recips,
        recips,
        &instance.point,
        cx.backend.as_deref_mut().expect("resident reciprocal backend"),
    )?;
    cx.zero.push(instance.col_claims[1].value.sub(recips_open));
    Ok(())
}

pub(crate) fn close_softmax_recip_verifier(
    instance: &InstanceOutV,
    rin_keys: &[Fp2],
    recips_keys: &[Fp2],
    cx: &mut BlockCtxV,
) {
    let rin_key = open_fp_vec_k(rin_keys, &instance.point);
    cx.kzero.push(instance.col_keys[0].key.sub(rin_key));
    let recips_key = open_fp_vec_k(recips_keys, &instance.point);
    cx.kzero.push(instance.col_keys[1].key.sub(recips_key));
}

// ---------------------------------------------------------------------------
// Attention block — prover
// ---------------------------------------------------------------------------

/// Build the softmax_norm remainder column over the rect domain:
/// rem = e·rc + 2^(s−1) − w·2^s (pads: e = w = 0 ⇒ rem = 2^(s−1)).
pub(crate) fn build_rem_sn(wires: &AttnWires, s_sn: u32) -> Vec<i64> {
    let sh = wires.shape;
    let half_sn = 1i64 << (s_sn - 1);
    let mut rem_sn = vec![0i64; 1 << sh.nr()];
    for (y, r) in rem_sn.iter_mut().enumerate() {
        let e = wires.exp_rect[y] as i64;
        let rc = wires.recips_row[y >> sh.sb()] as i64;
        let w = wires.w_rect[y] as i64;
        let v = e * rc + half_sn - (w << s_sn);
        assert!((0..1i64 << s_sn).contains(&v), "softmax_norm remainder out of range");
        *r = v;
    }
    rem_sn
}

/// Build the scores remainder column: causal from the witness accumulators,
/// 2^(s−1) pads.
pub(crate) fn build_rem_sc_packed(
    scores_acc: &[i64],
    scores_q: &[i16],
    sh: BandShape,
    s_sc: u32,
) -> Vec<i64> {
    let (s_pad, sp2, caus) = (sh.s_pad(), sh.sp2(), sh.caus());
    let half_sc = 1i64 << (s_sc - 1);
    let mut rem_sc = vec![half_sc; 1 << sh.nr()];
    for h in 0..H {
        for i in 0..sh.q {
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                let r = scores_acc[pidx] + half_sc - ((scores_q[pidx] as i64) << s_sc);
                assert!((0..1i64 << s_sc).contains(&r), "scores remainder out of range");
                rem_sc[h * sp2 + i * s_pad + j] = r;
            }
        }
    }
    rem_sc
}

/// Build the qkv (rem, out) columns on the permuted padded T×4096 domain.
pub(crate) fn build_qkv_cols(wit: &LayerWitness, s_qkv: u32, t_pad: usize) -> (Vec<i64>, Vec<i16>) {
    let t = wit.t;
    let half_qkv = 1i64 << (s_qkv - 1);
    let mut rem_qkv = vec![half_qkv; t_pad * 4096];
    let mut out_qkv = vec![0i16; t_pad * 4096];
    for i in 0..t {
        for j3 in 0..3 * D {
            let third = j3 / D;
            let rest = j3 % D;
            let cprime = third * 1024 + rest;
            let acc = wit.qkv_acc[i * 3 * D + j3];
            let outv = match third {
                0 => wit.q[i * D + rest],
                1 => wit.k[i * D + rest],
                _ => wit.v[i * D + rest],
            };
            let r = acc + half_qkv - ((outv as i64) << s_qkv);
            assert!((0..1i64 << s_qkv).contains(&r), "qkv remainder out of range");
            rem_qkv[i * 4096 + cprime] = r;
            out_qkv[i * 4096 + cprime] = outv;
        }
    }
    (rem_qkv, out_qkv)
}

/// Attention phase-1 state: derived wires + every element-wise auth (LN1
/// vectors, attention row tables, above-diagonal accumulators, row-shift
/// table); all attention-side multiplicities are in the bank.
pub struct AttnP1 {
    pub wires: AttnWires,
    lv1: LnVecsP,
    ln_vec_corrs: [Vec<u64>; 4],
    denoms_fp: Vec<Fp>,
    dom_denoms: u64,
    denoms_corr: Vec<u64>,
    rin_row_fp: Vec<Fp>,
    dom_rin_row: u64,
    recip_in_corr: Vec<u64>,
    recips_fp: Vec<Fp>,
    dom_recips: u64,
    recips_corr: Vec<u64>,
    above_fp: Vec<Fp>,
    dom_above: u64,
    above_corr: Vec<u64>,
    rowshift_fp: Vec<Fp>,
    dom_rowshift: Option<u64>,
    row_shift_corr: Option<Vec<u64>>,
}

pub(crate) struct ResidentAttnP1 {
    wires: DeviceAttentionProofWires,
    lv1: ResidentLnVecsP,
    ln_vec_corrs: [Vec<u64>; 4],
    dom_denoms: u64,
    denoms_corr: Vec<u64>,
    dom_rin_row: u64,
    recip_in_corr: Vec<u64>,
    dom_recips: u64,
    recips_corr: Vec<u64>,
    dom_above: u64,
    above_corr: Vec<u64>,
    dom_rowshift: Option<u64>,
    row_shift_corr: Option<Vec<u64>>,
    proj: DeviceLookupColumns,
    av: DeviceLookupColumns,
    ln: DeviceLookupColumns,
    rsqrt: DeviceLookupColumns,
}

impl ResidentAttnP1 {
    pub(crate) fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = backend.free_lookup_columns(self.rsqrt).err();
        if first.is_none() {
            first = backend.free_lookup_columns(self.ln).err();
        } else {
            let _ = backend.free_lookup_columns(self.ln);
        }
        if first.is_none() {
            first = backend.free_lookup_columns(self.av).err();
        } else {
            let _ = backend.free_lookup_columns(self.av);
        }
        if first.is_none() {
            first = backend.free_lookup_columns(self.proj).err();
        } else {
            let _ = backend.free_lookup_columns(self.proj);
        }
        if first.is_none() {
            first = self.lv1.free(backend).err();
        } else {
            let _ = self.lv1.free(backend);
        }
        if first.is_none() {
            first = backend.free_attention_proof_wires(self.wires).err();
        } else {
            let _ = backend.free_attention_proof_wires(self.wires);
        }
        first.map_or(Ok(()), Err)
    }
}

/// Resident attention phase 1 over either a square witness or a compact band
/// view. The view supplies an explicit full K-cache slice while its own K/V
/// rows remain the boundary-authenticated current segment.
pub(crate) fn attn_phase1_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    luts: &Luts,
    error: DeviceSlice<'_, u32>,
    cx: &mut BlockCtxP,
) -> Result<ResidentAttnP1, AccelError> {
    let t = wit.rows();
    let seq = wit.seq();
    let pos0 = wit.pos0();
    let params = luts.params;
    let rb = pad_bits(t);
    let exp_pad_u = (0..1usize << 16)
        .find(|&index| luts.exp[index] == 0)
        .ok_or(AccelError::InvalidInput("exp LUT has no zero-output padding pair"))?;
    let backend = cx
        .backend
        .as_deref_mut()
        .ok_or(AccelError::InvalidInput("resident attention phase 1 requires a backend"))?;
    let wires = backend.attention_proof_wires_device(
        wit.i16(LayerI16Field::Q),
        wit.k_cache(),
        wit.i16(LayerI16Field::K),
        wit.i16(LayerI16Field::V),
        wit.i64(LayerI64Field::ScoresAcc),
        wit.i16(LayerI16Field::ScoresQ),
        wit.i16(LayerI16Field::RowShift),
        wit.i16(LayerI16Field::ExpOut),
        wit.i64(LayerI64Field::Denoms),
        wit.i16(LayerI16Field::Recips),
        wit.i16(LayerI16Field::SoftmaxW),
        resident_model.model_weight(ModelWeightField::SoftmaxRecipLut),
        wit.i64(LayerI64Field::QkvAcc),
        error,
        t,
        seq,
        pos0,
        H,
        H_PAD,
        DH,
        params.shift_scores,
        params.shift_softmax_norm,
        params.shift_qkv,
        params.recip_den_shift,
        exp_pad_u as u16 as i16,
        luts.softmax_recip[0],
        params.softmax_row_shift,
    )?;

    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv1, ln_vec_corrs) = match auth_ln_vecs_resident_p(
        wit.i64(LayerI64Field::Ln1Mean),
        wit.i64(LayerI64Field::Ln1Var),
        wit.i64(LayerI64Field::Ln1RsqrtIn),
        wit.i16(LayerI16Field::Ln1RsqrtOut),
        rb,
        rout_pad,
        cx.stream,
        cx.tx,
        &mut cx.doms,
        backend,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_attention_proof_wires(wires);
            return Err(error);
        }
    };

    let mut direct_sites = Vec::with_capacity(4);
    let bind_result = (|| {
        let mult_sn =
            backend.histogram_fp_device(wires.rect_column(0)?, 1 << params.shift_softmax_norm)?;
        cx.bank.add_mult_resident(TableKey::Range(params.shift_softmax_norm), mult_sn, backend)?;
        let mult_sc =
            backend.histogram_fp_device(wires.rect_column(2)?, 1 << params.shift_scores)?;
        cx.bank.add_mult_resident(TableKey::Range(params.shift_scores), mult_sc, backend)?;
        let mult_exp = backend.histogram_lut_device(wires.rect_column(3)?, true)?;
        cx.bank.add_mult_resident(TableKey::Exp, mult_exp, backend)?;
        let mult_recip = backend.histogram_lut_device(wires.row_column(1)?, false)?;
        cx.bank.add_mult_resident(TableKey::SoftmaxRecip, mult_recip, backend)?;
        let mult_qkv = backend.histogram_fp_device(wires.qkv_column(0)?, 1 << params.shift_qkv)?;
        cx.bank.add_mult_resident(TableKey::Range(params.shift_qkv), mult_qkv, backend)?;

        direct_sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::Ln1Acc),
            wit.i16(LayerI16Field::Ln1Out),
            error,
            t,
            D,
            params.shift_ln_norm,
            backend,
        )?);
        direct_sites.push(bind_pair_site_resident(
            cx.bank,
            TableKey::LnRsqrt,
            wit.i64(LayerI64Field::Ln1RsqrtIn),
            wit.i16(LayerI16Field::Ln1RsqrtOut),
            t,
            1,
            Fp::ZERO,
            rout_pad,
            false,
            backend,
        )?);
        direct_sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::ProjAcc),
            wit.i16(LayerI16Field::AttnProjQ),
            error,
            t,
            D,
            params.shift_attn_proj,
            backend,
        )?);
        direct_sites.push(bind_range_site_resident(
            cx.bank,
            wit.i64(LayerI64Field::AvAcc),
            wit.i16(LayerI16Field::AvQ),
            error,
            t,
            D,
            params.shift_av,
            backend,
        )?);
        Ok(())
    })();
    if let Err(error) = bind_result {
        for site in direct_sites {
            let _ = backend.free_lookup_columns(site);
        }
        let _ = lv1.free(backend);
        let _ = backend.free_attention_proof_wires(wires);
        return Err(error);
    }

    let auth_result = (|| {
        let dom_denoms = cx.doms.take(1);
        let denoms_corr =
            auth_device_vector_p(cx.stream, cx.tx, dom_denoms, wires.row_column(0)?, backend)?;
        let dom_rin_row = cx.doms.take(1);
        let recip_in_corr =
            auth_device_vector_p(cx.stream, cx.tx, dom_rin_row, wires.row_column(1)?, backend)?;
        let dom_recips = cx.doms.take(1);
        let recips_corr =
            auth_device_vector_p(cx.stream, cx.tx, dom_recips, wires.row_column(2)?, backend)?;
        let dom_above = cx.doms.take(1);
        let above_corr = auth_device_vector_p(cx.stream, cx.tx, dom_above, wires.above(), backend)?;
        let (dom_rowshift, row_shift_corr) = if params.softmax_row_shift {
            let domain = cx.doms.take(1);
            let corrections =
                auth_device_vector_p(cx.stream, cx.tx, domain, wires.row_column(3)?, backend)?;
            (Some(domain), Some(corrections))
        } else {
            (None, None)
        };
        Ok((
            dom_denoms,
            denoms_corr,
            dom_rin_row,
            recip_in_corr,
            dom_recips,
            recips_corr,
            dom_above,
            above_corr,
            dom_rowshift,
            row_shift_corr,
        ))
    })();
    let (
        dom_denoms,
        denoms_corr,
        dom_rin_row,
        recip_in_corr,
        dom_recips,
        recips_corr,
        dom_above,
        above_corr,
        dom_rowshift,
        row_shift_corr,
    ) = match auth_result {
        Ok(values) => values,
        Err(error) => {
            for site in direct_sites {
                let _ = backend.free_lookup_columns(site);
            }
            let _ = lv1.free(backend);
            let _ = backend.free_attention_proof_wires(wires);
            return Err(error);
        }
    };

    let mut direct_sites = direct_sites.into_iter();
    Ok(ResidentAttnP1 {
        wires,
        lv1,
        ln_vec_corrs,
        dom_denoms,
        denoms_corr,
        dom_rin_row,
        recip_in_corr,
        dom_recips,
        recips_corr,
        dom_above,
        above_corr,
        dom_rowshift,
        row_shift_corr,
        ln: direct_sites.next().expect("resident attention LN site"),
        rsqrt: direct_sites.next().expect("resident attention rsqrt site"),
        proj: direct_sites.next().expect("resident attention projection site"),
        av: direct_sites.next().expect("resident attention AV site"),
    })
}

/// Attention phase 1 with caller-supplied wires (the causal-tamper test
/// mutates a copy — cheating-prover emulation).
pub(crate) fn attn_phase1_with_wires(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: AttnWires,
    cx: &mut BlockCtxP,
) -> AttnP1 {
    let t = wit.t;
    let p = luts.params;
    let sh = wires.shape;
    assert_eq!(sh.q, t, "band wires row count must match the witness");
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;

    // ---- multiplicities (before ANY α) --------------------------------------
    let rem_sn = build_rem_sn(&wires, p.shift_softmax_norm);
    let mut mult_sn = vec![0u32; 1 << p.shift_softmax_norm];
    for &r in &rem_sn {
        mult_sn[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_softmax_norm), &mult_sn);
    drop(rem_sn);
    let rem_sc = build_rem_sc_packed(&wit.scores_acc, &wit.scores_q, sh, p.shift_scores);
    let mut mult_sc = vec![0u32; 1 << p.shift_scores];
    for &r in &rem_sc {
        mult_sc[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_scores), &mult_sc);
    drop(rem_sc);
    // exp multiplicities: recount over the rect input column (the SHARED
    // wire s′ — equals scores_rect when the row shift is off).
    let mut mult_exp = vec![0u32; 1 << 16];
    for &s in &wires.sprime_rect {
        mult_exp[(s as u16) as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Exp, &mult_exp);
    // softmax_recip multiplicities over the row-table domain.
    let mut mult_recip = vec![0u32; 1 << 16];
    for &rin in &wires.recip_in_row {
        mult_recip[rin as usize] += 1;
    }
    cx.bank.add_mult(TableKey::SoftmaxRecip, &mult_recip);
    let (rem_qkv, _) = build_qkv_cols(wit, p.shift_qkv, t_pad);
    let mut mult_qkv = vec![0u32; 1 << p.shift_qkv];
    for &r in &rem_qkv {
        mult_qkv[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_qkv), &mult_qkv);
    drop(rem_qkv);
    // LN1 (first half of the shared ln_norm_requant trace) + attn_proj/av.
    assert_ln_stats(
        &wit.x_in,
        t,
        &wit.ln1_mean,
        &wit.ln1_var,
        &wit.ln1_rsqrt_in,
        &wit.ln1_rsqrt_out,
        luts,
    );
    let expected_acc_ln1 = ln_acc_recompute(
        &wit.x_in,
        t,
        &wit.ln1_mean,
        &wit.ln1_rsqrt_out,
        &weights.ln1_gain,
        &weights.ln1_bias,
        p.shift_ln_norm,
    );
    assert_eq!(wit.ln1_acc, expected_acc_ln1, "LN1 accumulator witness mismatch");
    add_range_mult(cx.bank, &wit.ln1_acc, &wit.ln1_out, t, D, p.shift_ln_norm);
    let mut mult_rsq1 = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq1[wit.ln1_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq1[0] += (t_pad - t) as u32;
    cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq1);
    add_range_mult(cx.bank, &wit.proj_acc, &wit.attn_proj_q, t, D, p.shift_attn_proj);
    add_range_mult(cx.bank, &wit.av_acc, &wit.av_q, t, D, p.shift_av);

    // ---- element-wise auth ---------------------------------------------------
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv1, ln_vec_corrs) = auth_ln_vecs_p(
        cx,
        rb,
        &wit.ln1_mean,
        &wit.ln1_var,
        &wit.ln1_rsqrt_in,
        &wit.ln1_rsqrt_out,
        rout_pad,
    );
    let denoms_fp = fp_col_i64(&wires.denoms_row);
    let dom_denoms = cx.doms.take(1);
    let denoms_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_denoms, &denoms_fp);
    let rin_row_fp = fp_col_i64(&wires.recip_in_row);
    let dom_rin_row = cx.doms.take(1);
    let recip_in_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rin_row, &rin_row_fp);
    let recips_fp = fp_col_i16(&wires.recips_row);
    let dom_recips = cx.doms.take(1);
    let recips_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_recips, &recips_fp);
    let above_fp = fp_col_i64(&wires.above_acc);
    let dom_above = cx.doms.take(1);
    let above_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_above, &above_fp);
    // P5 stable softmax: authenticate the row-shift table c (h_pad×t_pad).
    let rowshift_fp = fp_col_i16(&wires.row_shift_row);
    let (dom_rowshift, row_shift_corr) = if p.softmax_row_shift {
        let dom = cx.doms.take(1);
        let corr = auth_fp_vec_p(cx.stream, cx.tx, dom, &rowshift_fp);
        (Some(dom), Some(corr))
    } else {
        (None, None)
    };

    AttnP1 {
        wires,
        lv1,
        ln_vec_corrs,
        denoms_fp,
        dom_denoms,
        denoms_corr,
        rin_row_fp,
        dom_rin_row,
        recip_in_corr,
        recips_fp,
        dom_recips,
        recips_corr,
        above_fp,
        dom_above,
        above_corr,
        rowshift_fp,
        dom_rowshift,
        row_shift_corr,
    }
}

/// Prove the attention half (phase 2). Boundaries (x_in, K, V,
/// attn_block_out) are already authenticated by the caller at the given
/// domains; [`attn_phase1`] ran before any α. Returns the proof and the
/// weight claims `[attn_proj, c_attn]`. The c_attn claim lives on the
/// PERMUTED tensor (see [`cattn_permuted`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_attn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: AttnP1,
    cx: &mut BlockCtxP,
    dom_xin: u64,
    k_segs: &[CacheSegP],
    v_segs: &[CacheSegP],
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> (AttnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    // Band shape: queries = the witness's t rows, cache = the segments. The
    // band's OWN K/V rows are the LAST segment (its dom also serves the qkv
    // third-slice binding).
    let sh = p1.wires.shape;
    assert_eq!(sh.q, t);
    assert_eq!(k_segs.iter().map(|g| g.rows).sum::<usize>(), sh.s());
    assert_eq!(v_segs.iter().map(|g| g.rows).sum::<usize>(), sh.s());
    let own_k = k_segs.last().unwrap();
    let own_v = v_segs.last().unwrap();
    assert_eq!(own_k.rows, t);
    assert_eq!(own_v.rows, t);
    let (dom_k, dom_v) = (own_k.dom, own_v.dom);
    let (qb, sb) = (sh.qb(), sh.sb());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let s_len = sh.s();
    let nr = sh.nr();
    let rb = qb; // row bits of the q×D domains (av/proj/qkv/LN)
    let t_pad = q_pad;
    let d_cb = pad_bits(D); // 10
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;
    let AttnP1 {
        wires,
        lv1,
        ln_vec_corrs,
        denoms_fp,
        dom_denoms,
        denoms_corr,
        rin_row_fp,
        dom_rin_row,
        recip_in_corr,
        recips_fp,
        dom_recips,
        recips_corr,
        above_fp,
        dom_above,
        above_corr,
        rowshift_fp,
        dom_rowshift,
        row_shift_corr,
    } = p1;
    let wires = &wires;

    // Rebuild the cheap derived columns (their multiplicities were bound in
    // phase 1; the columns themselves are pure witness functions).
    let rem_sn = build_rem_sn(wires, s_sn);
    let rem_sc = build_rem_sc_packed(&wit.scores_acc, &wit.scores_q, sh, s_sc);
    let (rem_qkv, out_qkv) = build_qkv_cols(wit, s_qkv, t_pad);
    let acc_ln1 = &wit.ln1_acc;

    // ---- 1: attn_proj range instance, closed against the residual ----------
    // (chained two-stage for s_ap > 16 — P5 per-layer residual scales).
    let site_proj = prove_range_site(&wit.proj_acc, &wit.attn_proj_q, t, D, s_ap, Vec::new(), cx);
    let inst_proj = &site_proj.main;
    let pt_ap = inst_proj.point.clone();
    // Residual: attn_block_out = x_in + attn_proj_q ⇒ zero row at pt_ap.
    let abo_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_ap);
    let xin_open = open_matrix_p(cx.stream, dom_xin, &wit.x_in, t, D, &pt_ap);
    cx.zero.push(inst_proj.col_claims[1].value.sub(abo_open).add(xin_open));

    // ---- 2: transport → out-proj committed chained GEMM (768×768) ----------
    let pt_acc_ap = site_proj.acc_point().to_vec();
    let mut acc_ap_claim = site_proj.acc_claim;
    if let Some(b) = biases {
        acc_ap_claim =
            sub_bias_p(acc_ap_claim, &b.attn_proj, d_cb, &pt_acc_ap, t, s_ap, &mut cx.ctr_other);
    }
    let (r_j_ap, r_i_ap) = pt_acc_ap.split_at(d_cb);
    let cd_proj = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_proj, wire_av, w_proj_corr, wclaim_proj, _tm, _cc) = prove_gemm_committed_chained(
        &wit.av_q,
        &weights.attn_proj,
        t,
        D,
        D,
        r_i_ap,
        r_j_ap,
        acc_ap_claim,
        &cd_proj,
        cx.stream,
        cx.tx,
    );

    // ---- 3: av range instance (drains the out-proj X wire) -----------------
    let (rem_av, out_av) = range_cols_padded(&wit.av_acc, &wit.av_q, t, D, s_av);
    let inst_av = cx.inst(
        TableKey::Range(s_av),
        &[rem_av, out_av],
        &[Some(0), None],
        vec![LeafAuxClaim { col: 1, point: wire_av.point.clone(), value: wire_av.value }],
    );
    let acc_av_claim = transport_p(&inst_av, s_av);
    let pt_av = inst_av.point.clone();

    // ---- 4: av head split ---------------------------------------------------
    // ãcc_av(pt) = Σ_h eq(pt_headbits, h)·ãcc_h(pt_within ‖ pt_rows): the av
    // column index is head·64 + l, so bits 0..5 = within-head (LSB), 6..9 =
    // head; the per-head accumulator MLE lives on (6 within vars ‖ row vars).
    let mut pt_wv: Vec<Fp2> = pt_av[..6].to_vec();
    pt_wv.extend_from_slice(&pt_av[d_cb..]);
    let eqh_av = eq_vec(&pt_av[6..d_cb]);
    cx.ctr_other.fp2_mults += 16 + (64 * t_pad) as u64;
    let mut av_vals = [Fp2::ZERO; H];
    for (h, val) in av_vals.iter_mut().enumerate() {
        let mut slice = vec![Fp2::ZERO; 64 * t_pad];
        for i in 0..t {
            for l in 0..DH {
                slice[i * 64 + l] = Fp2::from_base(Fp::from_i64(wit.av_acc[i * D + h * DH + l]));
            }
        }
        *val = eval_mle_counted(&slice, &pt_wv, &mut cx.ctr_other);
    }
    let dom_split_av = cx.doms.take(1);
    let masks_av = cx.stream.draw_fulls(dom_split_av, H);
    let mut av_split_corrs = [Fp2::ZERO; H];
    let mut av_auth = Vec::with_capacity(H);
    for h in 0..H {
        av_split_corrs[h] = av_vals[h] - masks_av[h].x;
        av_auth.push(ProverAuthed { x: av_vals[h], m: masks_av[h].m });
    }
    cx.tx.append("head_split_corrections", 16 * H as u64);
    let mut row = ProverAuthed::ZERO.sub(acc_av_claim);
    for h in 0..H {
        row = row.add(av_auth[h].scale(eqh_av[h]));
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "av head-split relation violated");
    cx.zero.push(row);

    // ---- 5: per-head w·V act chained GEMMs (m=T, k=T_pad, n=64) ------------
    // Y_h = W_h·V_h; the B leg is the V head slice, pre-folded over its 64
    // within-head columns (fixed head-bit prefix = the column window), the
    // open_b closure finishes the fold over V's ROWS at the sumcheck point.
    let eq_within = eq_vec(&pt_av[..6]);
    let mut gemm_wv = Vec::with_capacity(H);
    let mut aux_sn: Vec<LeafAuxClaim> = Vec::with_capacity(H + 1);
    // Seal membership and every correlation range before preparing/opening
    // the first head. Domain allocation remains in the historical head
    // order, while rounds below advance synchronously across all 12 heads.
    let layer = attention_layer_from_doms(&cx.doms);
    let wv_doms: Vec<ChainDoms> = (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, s_pad)).collect();
    let wv_plan = attention_act_schedule(
        sh.t0,
        layer,
        AttentionActRole::WeightValue,
        pad_bits(s_pad),
        &wv_doms,
    );
    let mut wv_openings = Vec::with_capacity(H);
    let mut wv_timings = Vec::with_capacity(H);
    let mut wv_jobs = Vec::with_capacity(H);
    for h in 0..H {
        let (bvals, btags) = cache_fold_cols_p(cx.stream, v_segs, &eq_within, h * DH, DH);
        let mut b_folded = vec![Fp2::ZERO; s_pad];
        b_folded[..s_len].copy_from_slice(&bvals);
        let x_slice = &wires.w_rect[h * sp2..h * sp2 + t * s_pad];
        let (job, timings) = prepare_gemm_act_chained_batch(
            attention_act_site_id(sh.t0, layer, AttentionActRole::WeightValue, h),
            x_slice,
            b_folded,
            t,
            s_pad,
            DH,
            &pt_av[d_cb..],
            &pt_av[..6],
            av_auth[h],
            &wv_doms[h],
        );
        wv_openings.push((bvals, btags));
        wv_timings.push(timings);
        wv_jobs.push(job);
    }
    let wv_outputs = blind_prove_batch(&wv_plan, wv_jobs, cx.stream, cx.tx)
        .expect("sealed W·V schedule and jobs must agree");
    for (h, ((output, (bvals, btags)), mut timings)) in
        wv_outputs.into_iter().zip(wv_openings).zip(wv_timings).enumerate()
    {
        let rounds: GemmActRoundOutput = output.into();
        assert_eq!(
            rounds.site_id,
            Some(attention_act_site_id(sh.t0, layer, AttentionActRole::WeightValue, h))
        );
        let open_started = std::time::Instant::now();
        let eq_l = eq_vec(&rounds.point);
        let mut value = Fp2::ZERO;
        let mut tag = Fp2::ZERO;
        for row in 0..s_len {
            value += eq_l[row] * bvals[row];
            tag += eq_l[row] * btags[row];
        }
        timings.t_open_tags_s = open_started.elapsed().as_secs_f64();
        let (gp, wire, _r_l, _tm, _cc) = finalize_gemm_act_chained(
            rounds,
            &pt_av[d_cb..],
            ProverAuthed { x: value, m: tag },
            &wv_doms[h],
            cx.stream,
            cx.tx,
            timings,
        )
        .expect("CPU W·V boundary opening matches the scheduled fold");
        // Lift the softmax_w wire claim to the full rect domain: the head
        // bits are appended as fixed boolean coordinates (top vars).
        let mut ptx = wire.point.clone();
        ptx.extend(head_bit_coords(h));
        aux_sn.push(LeafAuxClaim { col: 1, point: ptx, value: wire.value });
        gemm_wv.push((gp, wire.corr));
    }

    // ---- 6: causal mask relation --------------------------------------------
    // Σ_y maskAbove(y)·eq(τ, y)·w_rect(y) = 0 as a blind product sumcheck
    // with the PUBLIC table A = M and claim0 = public 0; the resulting w̃(r)
    // claim is drained by the softmax_norm instance (aux #13).
    let tau: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_tau = eq_vec(&tau);
    cx.ctr_other.fp2_mults += 3 * (1u64 << nr); // eq_tau + fold cost
    let mut m_tab = vec![Fp2::ZERO; 1 << nr];
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                let y = h * sp2 + i * s_pad + j;
                m_tab[y] = eq_tau[y];
            }
        }
    }
    let b_causal = lift_i16_fp2(&wires.w_rect_causal);
    let dom_causal_rounds = cx.doms.take(nr as u64);
    let (causal, r_c, causal_claim_n) = blind_prove(
        m_tab.clone(),
        b_causal,
        ProverAuthed::from_public(Fp2::ZERO),
        cx.stream,
        dom_causal_rounds,
        cx.tx,
    );
    let m_eval = eval_mle_counted(&m_tab, &r_c, &mut cx.ctr_other);
    assert!(m_eval != Fp2::ZERO, "causal mask MLE vanished at r (negligible; redraw)");
    let eq_rc = eq_vec(&r_c);
    cx.ctr_other.fp2_mults += 1 << nr;
    cx.ctr_other.base_mults += wires.w_rect.len() as u64;
    let mut w_eval = Fp2::ZERO;
    for (y, &wv) in wires.w_rect.iter().enumerate() {
        if wv != 0 {
            w_eval += eq_rc[y].mul_base(Fp::from_i64(wv as i64));
        }
    }
    let dom_cw = cx.doms.take(1);
    let fc = cx.stream.draw_fulls(dom_cw, 1)[0];
    let causal_w_corr = w_eval - fc.x;
    cx.tx.append("causal_w_correction", 16);
    let w_auth = ProverAuthed { x: w_eval, m: fc.m };
    // No debug_assert here: this row is exactly where a causal violation
    // must land (cheating-prover emulation in the tests).
    cx.zero.push(w_auth.scale(m_eval).sub(causal_claim_n));
    aux_sn.push(LeafAuxClaim { col: 1, point: r_c.clone(), value: w_auth });

    // ---- 7: softmax_norm range instance (12 wire claims + causal claim) ----
    let rem_sn_col: Vec<Fp> = rem_sn.iter().map(|&r| Fp::new(r as u64)).collect();
    let w_col = fp_col_i16(&wires.w_rect);
    let inst_sn = cx.inst(TableKey::Range(s_sn), &[rem_sn_col, w_col], &[Some(0), None], aux_sn);
    let wacc_claim = transport_p(&inst_sn, s_sn);
    let pt_sn = inst_sn.point.clone();

    // ---- 8: hadamard w_acc = exp_rect ∘ broadcast(recips) -------------------
    // R is constant in the column (LSB) vars, so R̃ at the full sumcheck
    // point IS the recips row-table claim at the (rows ‖ head) part.
    let e_tab = lift_i16_fp2(&wires.exp_rect);
    let r_tab: Vec<Fp2> = (0..1usize << nr).map(|y| Fp2::from_base(recips_fp[y >> sb])).collect();
    let hd = HadamardDoms::alloc(&mut cx.doms, nr);
    let (had_proof, r_h, e_claim, r_claim) = hadamard_prove(
        &pt_sn,
        e_tab,
        r_tab,
        wacc_claim,
        &hd,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let rec_open = open_fp_vec_p(cx.stream, dom_recips, &recips_fp, &r_h[sb..]);
    cx.zero.push(r_claim.sub(rec_open));

    // ---- 9: denominator row sums --------------------------------------------
    // deñoms(ρ) = 2^rb·ẽxp_rect(½..½, ρ): the rect row sums equal the causal
    // ones because every non-causal exp entry is exactly 0 (pad pair).
    let rho: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; sb];
    half_pt.extend_from_slice(&rho);
    let exp_lift = lift_i16_fp2(&wires.exp_rect);
    let rs_val = eval_mle_counted(&exp_lift, &half_pt, &mut cx.ctr_other);
    let dom_rs = cx.doms.take(1);
    let fr = cx.stream.draw_fulls(dom_rs, 1)[0];
    let rowsum_corr = rs_val - fr.x;
    cx.tx.append("rowsum_correction", 16);
    let rs_auth = ProverAuthed { x: rs_val, m: fr.m };
    let den_open = open_fp_vec_p(cx.stream, dom_denoms, &denoms_fp, &rho);
    let two_sb = Fp2::from_base(Fp::new(1u64 << sb));
    cx.zero.push(den_open.sub(rs_auth.scale(two_sb)));

    // ---- 10: exp pair instance ----------------------------------------------
    // Input column = the shared s′ wire. With the row shift on, the row-max
    // soundness rows run first (P5 ledger 2026-07-06 #8): (a) hadamard with
    // public claim 0 at fresh τ₂ proves ĩs_max ∘ s̃′ ≡ 0; (b) an is_max
    // rowsum identity forces Σ_j is_max = 1 on every real row. Their claims
    // drain into the instance's s′ (col 0) and is_max (col 2) columns.
    let sc_col = fp_col_i16(&wires.sprime_rect);
    let exp_col = fp_col_i16(&wires.exp_rect);
    let mut exp_aux = vec![
        LeafAuxClaim { col: 1, point: r_h.clone(), value: e_claim },
        LeafAuxClaim { col: 1, point: half_pt.clone(), value: rs_auth },
    ];
    let mut hadamard2 = None;
    let mut ismax_rowsum_corr = None;
    if p.softmax_row_shift {
        let ismax_tab = lift_i16_fp2(&wires.is_max_rect);
        let sprime_tab = lift_i16_fp2(&wires.sprime_rect);
        let tau2: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
        let hd2 = HadamardDoms::alloc(&mut cx.doms, nr);
        let (had2, r_h2, e2_claim, r2_claim) = hadamard_prove(
            &tau2,
            ismax_tab,
            sprime_tab,
            ProverAuthed::from_public(Fp2::ZERO),
            &hd2,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
        );
        hadamard2 = Some(had2);
        // Rowsum: ĩs_max(½..½, ρ₂)·2^rb = realmask̃(ρ₂) (public RHS).
        let rho2: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
        let mut half_pt2 = vec![half_scalar; sb];
        half_pt2.extend_from_slice(&rho2);
        let ismax_lift = lift_i16_fp2(&wires.is_max_rect);
        let rs2_val = eval_mle_counted(&ismax_lift, &half_pt2, &mut cx.ctr_other);
        let dom_rs2 = cx.doms.take(1);
        let fr2 = cx.stream.draw_fulls(dom_rs2, 1)[0];
        ismax_rowsum_corr = Some(rs2_val - fr2.x);
        cx.tx.append("ismax_rowsum_correction", 16);
        let rs2_auth = ProverAuthed { x: rs2_val, m: fr2.m };
        let eq_rho2 = eq_vec(&rho2);
        cx.ctr_other.fp2_mults += 1u64 << (qb + HEAD_BITS);
        let mut realmask = Fp2::ZERO;
        for h in 0..H {
            for i in 0..t {
                realmask += eq_rho2[h * q_pad + i];
            }
        }
        cx.zero.push(rs2_auth.scale(two_sb).sub(ProverAuthed::from_public(realmask)));
        exp_aux.push(LeafAuxClaim { col: 0, point: r_h2.clone(), value: r2_claim });
        exp_aux.push(LeafAuxClaim { col: 2, point: r_h2, value: e2_claim });
        exp_aux.push(LeafAuxClaim { col: 2, point: half_pt2, value: rs2_auth });
    }
    let ismax_col = fp_col_i16(&wires.is_max_rect);
    let (exp_cols, exp_shifts): (Vec<Vec<Fp>>, Vec<Option<u32>>) = if p.softmax_row_shift {
        (vec![sc_col.clone(), exp_col, ismax_col], vec![Some(0), Some(16), None])
    } else {
        (vec![sc_col.clone(), exp_col], vec![Some(0), Some(16)])
    };
    let inst_exp = cx.inst(TableKey::Exp, &exp_cols, &exp_shifts, exp_aux);

    // ---- 11: softmax_recip pair instance -------------------------------------
    let inst_recip = cx.inst(
        TableKey::SoftmaxRecip,
        &[rin_row_fp.clone(), recips_fp.clone()],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    close_softmax_recip_cpu(&inst_recip, dom_rin_row, &rin_row_fp, dom_recips, &recips_fp, cx);

    // ---- 12: scores range instance + pad-mask correction ---------------------
    let rem_sc_col: Vec<Fp> = rem_sc.iter().map(|&r| Fp::new(r as u64)).collect();
    let inst_sc = cx.inst(
        TableKey::Range(s_sc),
        &[rem_sc_col, sc_col],
        &[Some(0), None],
        vec![LeafAuxClaim {
            col: 1,
            point: inst_exp.point.clone(),
            value: inst_exp.col_claims[0].value,
        }],
    );
    let tr_sc = transport_p(&inst_sc, s_sc);
    let pt_sc = inst_sc.point.clone();
    // The out column is the shared scores_q_rect wire, padded with the exp
    // pad input; its implied non-causal accumulator is the CONSTANT
    // c_pad = pad_in·2^s (rem pads at 2^(s−1)). Public correction:
    //   ãcc_true(pt) = transport(pt) − c_pad·padmask̃(pt) + Ã_above(pt),
    // padmask̃ = 1 − Σ_{causal y} eq(pt, y), Ã_above = the authenticated
    // above-diagonal accumulators (true QKᵀ values on real above-diag cells).
    let eq_sc = eq_vec(&pt_sc);
    cx.ctr_other.fp2_mults += 1 << nr;
    let mut caus_sum = Fp2::ZERO;
    for h in 0..H {
        for i in 0..t {
            for j in 0..sh.win(i) {
                caus_sum += eq_sc[h * sp2 + i * s_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((wires.exp_pad_in() as i64) << s_sc));
    let mut wts = Vec::with_capacity(wires.above_acc.len());
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                wts.push(eq_sc[h * sp2 + i * s_pad + j]);
            }
        }
    }
    let above_open = open_weighted_p(cx.stream, dom_above, &above_fp, &wts);
    let mut acc_sc_true = tr_sc.sub(ProverAuthed::from_public(c_pad * padmask)).add(above_open);
    if p.softmax_row_shift {
        // The out column is s′ = s − c: add back 2^s·⟨gc, c⟩, gc_i = the
        // causal eq mass of row i (authenticated weighted opening of c).
        let mut gcw = vec![Fp2::ZERO; H_PAD * q_pad];
        for h in 0..H {
            for i in 0..t {
                for j in 0..sh.win(i) {
                    gcw[h * q_pad + i] += eq_sc[h * sp2 + i * s_pad + j];
                }
            }
        }
        let gc_open = open_weighted_p(cx.stream, dom_rowshift.unwrap(), &rowshift_fp, &gcw);
        acc_sc_true = acc_sc_true.add(gc_open.scale(Fp2::from_base(Fp::new(1u64 << s_sc))));
    }

    // ---- 13: scores head split ------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[sb + qb..]);
    let mut sc_vals = [Fp2::ZERO; H];
    for (h, val) in sc_vals.iter_mut().enumerate() {
        let mut slice = vec![Fp2::ZERO; sp2];
        for i in 0..t {
            for j in 0..s_len {
                slice[i * s_pad + j] =
                    Fp2::from_base(Fp::from_i64(wires.acc_full[h * t * s_len + i * s_len + j]));
            }
        }
        *val = eval_mle_counted(&slice, &pt_sc[..sb + qb], &mut cx.ctr_other);
    }
    let dom_split_sc = cx.doms.take(1);
    let masks_sc = cx.stream.draw_fulls(dom_split_sc, H);
    let mut sc_split_corrs = [Fp2::ZERO; H];
    let mut sc_auth = Vec::with_capacity(H);
    for h in 0..H {
        sc_split_corrs[h] = sc_vals[h] - masks_sc[h].x;
        sc_auth.push(ProverAuthed { x: sc_vals[h], m: masks_sc[h].m });
    }
    cx.tx.append("head_split_corrections", 16 * H as u64);
    let mut row = ProverAuthed::ZERO.sub(acc_sc_true);
    for h in 0..H {
        row = row.add(sc_auth[h].scale(eqh_sc[h]));
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "scores head-split relation violated");
    cx.zero.push(row);

    // ---- 14: per-head QKᵀ act chained GEMMs (m=T, k=64, n=T) ----------------
    // Y_h = Q_h·K_hᵀ: the contraction runs over the 64 d_h vars, so the
    // sumcheck point r_l lands in K's COLUMN (within-head) vars while the
    // score-column point r_j weights K's ROWS (positions): the B opening is
    // K̃ at (r_l ‖ head bits ‖ r_j) — K rows pre-folded by eq(r_j), the
    // closure finishes over the 64-column window at r_l.
    let eq_rj_sc = eq_vec(&pt_sc[..sb]);
    let mut gemm_qk = Vec::with_capacity(H);
    let mut aux_qkv: Vec<LeafAuxClaim> = Vec::with_capacity(H + 2);
    let qk_doms: Vec<ChainDoms> = (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, DH)).collect();
    let qk_plan =
        attention_act_schedule(sh.t0, layer, AttentionActRole::QueryKey, pad_bits(DH), &qk_doms);
    let mut qk_openings = Vec::with_capacity(H);
    let mut qk_timings = Vec::with_capacity(H);
    let mut qk_jobs = Vec::with_capacity(H);
    for h in 0..H {
        let (kvals, ktags) = cache_fold_rows_p(cx.stream, k_segs, &eq_rj_sc, h * DH, DH);
        let b_folded = kvals.clone();
        let mut qh = vec![0i16; t * DH];
        for i in 0..t {
            for l in 0..DH {
                qh[i * DH + l] = wit.q[i * D + h * DH + l];
            }
        }
        let (job, timings) = prepare_gemm_act_chained_batch(
            attention_act_site_id(sh.t0, layer, AttentionActRole::QueryKey, h),
            &qh,
            b_folded,
            t,
            DH,
            s_len,
            &pt_sc[sb..sb + qb],
            &pt_sc[..sb],
            sc_auth[h],
            &qk_doms[h],
        );
        qk_openings.push((kvals, ktags));
        qk_timings.push(timings);
        qk_jobs.push(job);
    }
    let qk_outputs = blind_prove_batch(&qk_plan, qk_jobs, cx.stream, cx.tx)
        .expect("sealed Q·Kᵀ schedule and jobs must agree");
    for (h, ((output, (kvals, ktags)), mut timings)) in
        qk_outputs.into_iter().zip(qk_openings).zip(qk_timings).enumerate()
    {
        let rounds: GemmActRoundOutput = output.into();
        assert_eq!(
            rounds.site_id,
            Some(attention_act_site_id(sh.t0, layer, AttentionActRole::QueryKey, h))
        );
        let open_started = std::time::Instant::now();
        let eq_l = eq_vec(&rounds.point);
        let mut value = Fp2::ZERO;
        let mut tag = Fp2::ZERO;
        for l in 0..DH {
            value += eq_l[l] * kvals[l];
            tag += eq_l[l] * ktags[l];
        }
        timings.t_open_tags_s = open_started.elapsed().as_secs_f64();
        let (gp, wire, _r_l, _tm, _cc) = finalize_gemm_act_chained(
            rounds,
            &pt_sc[sb..sb + qb],
            ProverAuthed { x: value, m: tag },
            &qk_doms[h],
            cx.stream,
            cx.tx,
            timings,
        )
        .expect("CPU Q·Kᵀ boundary opening matches the scheduled fold");
        // Lift the Q wire claim onto the qkv out column's permuted domain:
        // (r_l ‖ head bits ‖ third=(0,0) ‖ rows).
        let mut ptx = wire.point[..6].to_vec();
        ptx.extend(head_bit_coords(h));
        ptx.push(Fp2::ZERO);
        ptx.push(Fp2::ZERO);
        ptx.extend_from_slice(&wire.point[6..]);
        aux_qkv.push(LeafAuxClaim { col: 1, point: ptx, value: wire.value });
        gemm_qk.push((gp, wire.corr));
    }

    // ---- 15: K/V third-slice aux claims ---------------------------------------
    // The out column's k/v regions are bound to the BOUNDARY tensors by two
    // extra aux claims at fresh points with boolean third selectors; their
    // values ARE the streamed boundary MAC openings (no extra correlations).
    let rho_k: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let k_bound_open = open_matrix_p(cx.stream, dom_k, &wit.k, t, D, &rho_k);
    let mut pt_k = rho_k[..d_cb].to_vec();
    pt_k.push(Fp2::ONE);
    pt_k.push(Fp2::ZERO);
    pt_k.extend_from_slice(&rho_k[d_cb..]);
    aux_qkv.push(LeafAuxClaim { col: 1, point: pt_k, value: k_bound_open });
    let rho_v: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let v_bound_open = open_matrix_p(cx.stream, dom_v, &wit.v, t, D, &rho_v);
    let mut pt_v = rho_v[..d_cb].to_vec();
    pt_v.push(Fp2::ZERO);
    pt_v.push(Fp2::ONE);
    pt_v.extend_from_slice(&rho_v[d_cb..]);
    aux_qkv.push(LeafAuxClaim { col: 1, point: pt_v, value: v_bound_open });

    // ---- 16: qkv range instance → c_attn committed chained GEMM --------------
    let rem_qkv_col: Vec<Fp> = rem_qkv.iter().map(|&r| Fp::new(r as u64)).collect();
    let out_qkv_col = fp_col_i16(&out_qkv);
    let inst_qkv =
        cx.inst(TableKey::Range(s_qkv), &[rem_qkv_col, out_qkv_col], &[Some(0), None], aux_qkv);
    let mut acc_qkv_claim = transport_p(&inst_qkv, s_qkv);
    let pt_qkv = inst_qkv.point.clone();
    if let Some(b) = biases {
        let bias_perm = cattn_bias_permuted(&b.c_attn);
        acc_qkv_claim =
            sub_bias_p(acc_qkv_claim, &bias_perm, 12, &pt_qkv, t, s_qkv, &mut cx.ctr_other);
    }
    let (r_j_qkv, r_i_qkv) = pt_qkv.split_at(12);
    let w_perm = cattn_permuted(&weights.c_attn);
    let cd_cattn = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_cattn, wire_ln1, w_cattn_corr, wclaim_cattn, _tm2, _cc2) =
        prove_gemm_committed_chained(
            &wit.ln1_out,
            &w_perm,
            t,
            D,
            4096,
            r_i_qkv,
            r_j_qkv,
            acc_qkv_claim,
            &cd_cattn,
            cx.stream,
            cx.tx,
        );

    // ---- 17: LN1 chain ----------------------------------------------------------
    let ln = prove_ln_chain(
        t,
        s_ln,
        acc_ln1,
        &wit.ln1_out,
        &wit.x_in,
        dom_xin,
        &wit.ln1_mean,
        &weights.ln1_gain,
        &weights.ln1_bias,
        &lv1,
        &wire_ln1,
        cx,
    );

    let proof = AttnBlockProof {
        ln_vec_corrs,
        denoms_corr,
        recip_in_corr,
        recips_corr,
        above_corr,
        row_shift_corr,
        hadamard2,
        ismax_rowsum_corr,
        inst_proj: site_proj.main.proof,
        inst_proj_stage1: site_proj.stage1.map(|s1| s1.proof),
        gemm_proj,
        av_wire_corr: wire_av.corr,
        w_proj_corr,
        inst_av: inst_av.proof,
        av_split_corrs,
        gemm_wv,
        causal,
        causal_w_corr,
        inst_sn: inst_sn.proof,
        hadamard: had_proof,
        rowsum_corr,
        inst_exp: inst_exp.proof,
        inst_recip: inst_recip.proof,
        inst_sc: inst_sc.proof,
        sc_split_corrs,
        gemm_qk,
        inst_qkv: inst_qkv.proof,
        gemm_cattn,
        ln1_wire_corr: wire_ln1.corr,
        w_cattn_corr,
        ln,
    };
    (proof, vec![wclaim_proj, wclaim_cattn])
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_attn_block_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    weights: &LayerWeights,
    luts: &Luts,
    mut p1: ResidentAttnP1,
    cx: &mut BlockCtxP,
    k_segments: &[ResidentCacheSegP],
    v_segments: &[ResidentCacheSegP],
    dom_xin: u64,
    dom_k: u64,
    dom_v: u64,
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> Result<(AttnBlockProof, Vec<WeightClaimP>), AccelError> {
    let result = (|| {
        let t = wit.rows();
        if t < 2 {
            return Err(AccelError::InvalidInput(
                "resident attention proof needs at least two rows",
            ));
        }
        let params = luts.params;
        let shape = BandShape { t0: wit.pos0(), q: t };
        // `layer` is the model-weight index (always 0..L).  Scheduled SiteIds
        // instead use the public proof section encoded in this block's
        // correlation-domain base; decode bands deliberately live in a
        // different section from prefill.  Derive it exactly as the CPU
        // prover and verifier do so all three parties seal the same cohort.
        let schedule_section = attention_layer_from_doms(&cx.doms);
        let (qb, sb) = (shape.qb(), shape.sb());
        let (q_pad, s_pad, sp2) = (shape.q_pad(), shape.s_pad(), shape.sp2());
        let nr = shape.nr();
        let rect_entries = 1usize << nr;
        let d_cb = pad_bits(D);
        let s_ap = params.shift_attn_proj;
        let s_av = params.shift_av;
        let s_sn = params.shift_softmax_norm;
        let s_sc = params.shift_scores;
        let s_qkv = params.shift_qkv;
        let s_ln = params.shift_ln_norm;

        // 1–2: projection range/residual and committed out projection.
        let proj_site = prove_range_site_resident(&p1.proj, s_ap, Vec::new(), cx)?;
        let projection_point = proj_site.main.point.clone();
        let backend = cx
            .backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident attention proof requires a backend"))?;
        let abo_open = open_matrix_resident_p(
            cx.stream,
            dom_abo,
            wit.i16(LayerI16Field::AttnBlockOut),
            t,
            D,
            &projection_point,
            backend,
        )?;
        let xin_open = open_matrix_resident_p(
            cx.stream,
            dom_xin,
            wit.i16(LayerI16Field::XIn),
            t,
            D,
            &projection_point,
            backend,
        )?;
        cx.zero.push(proj_site.main.col_claims[1].value.sub(abo_open).add(xin_open));
        let projection_acc_point = proj_site.acc_point().to_vec();
        let mut projection_claim = proj_site.acc_claim;
        if let Some(biases) = biases {
            projection_claim = sub_bias_p(
                projection_claim,
                &biases.attn_proj,
                d_cb,
                &projection_acc_point,
                t,
                s_ap,
                &mut cx.ctr_other,
            );
        }
        let (r_j_projection, r_i_projection) = projection_acc_point.split_at(d_cb);
        let projection_doms = ChainDoms::alloc(&mut cx.doms, D);
        let (gemm_proj, wire_av, w_proj_corr, wclaim_proj, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::AvQ),
                resident_model.layer_weight(layer, LayerWeightField::AttnProj)?,
                t,
                D,
                D,
                r_i_projection,
                r_j_projection,
                projection_claim,
                &projection_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            )?;

        // 3–5: AV range, head split, and per-head W·V activation GEMMs.
        if s_av > 16 {
            return Err(AccelError::InvalidInput(
                "resident chained AV range is not represented in AttnBlockProof",
            ));
        }
        let av_site = prove_range_site_resident(
            &p1.av,
            s_av,
            vec![LeafAuxClaim { col: 1, point: wire_av.point.clone(), value: wire_av.value }],
            cx,
        )?;
        debug_assert!(av_site.stage1.is_none());
        let av_claim = av_site.acc_claim;
        let av_point = av_site.main.point.clone();
        let mut wv_point = av_point[..6].to_vec();
        wv_point.extend_from_slice(&av_point[d_cb..]);
        let eq_head_av = eq_vec(&av_point[6..d_cb]);
        cx.ctr_other.fp2_mults += 16 + (DH * q_pad) as u64;
        let mut av_values = [Fp2::ZERO; H];
        for (head, value) in av_values.iter_mut().enumerate() {
            *value = cx
                .backend
                .as_deref_mut()
                .expect("resident attention backend")
                .matrix_window_mle_eval_device(
                    wit.i64(LayerI64Field::AvAcc),
                    t,
                    D,
                    head * DH,
                    DH,
                    &wv_point,
                )?;
            cx.ctr_other.fp2_mults += (DH * q_pad - 1) as u64;
        }
        let split_av_dom = cx.doms.take(1);
        let split_av_masks = cx.stream.draw_fulls(split_av_dom, H);
        let mut av_split_corrs = [Fp2::ZERO; H];
        let mut av_auth = Vec::with_capacity(H);
        for head in 0..H {
            av_split_corrs[head] = av_values[head] - split_av_masks[head].x;
            av_auth.push(ProverAuthed { x: av_values[head], m: split_av_masks[head].m });
        }
        cx.tx.append("head_split_corrections", 16 * H as u64);
        let mut split_row = ProverAuthed::ZERO.sub(av_claim);
        for head in 0..H {
            split_row = split_row.add(av_auth[head].scale(eq_head_av[head]));
        }
        debug_assert_eq!(split_row.x, Fp2::ZERO, "resident AV head split violated");
        cx.zero.push(split_row);

        let eq_within = eq_vec(&av_point[..6]);
        let eq_query_rows = eq_vec(&av_point[d_cb..]);
        let mut gemm_wv = Vec::with_capacity(H);
        let mut aux_sn = Vec::with_capacity(H + 1);
        let wv_doms: Vec<ChainDoms> =
            (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, s_pad)).collect();
        let wv_plan = attention_act_schedule(
            shape.t0,
            schedule_section,
            AttentionActRole::WeightValue,
            pad_bits(s_pad),
            &wv_doms,
        );
        let w_column = p1.wires.rect_column(1)?;
        let mut wv_tags = Vec::with_capacity(H);
        let mut wv_jobs = Vec::with_capacity(H);
        for head in 0..H {
            let head_weights =
                match DeviceSlice::new(w_column.buffer(), w_column.offset() + head * sp2, sp2) {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = free_attention_resident_jobs(
                            cx.backend.as_deref_mut().expect("resident attention backend"),
                            wv_jobs,
                        );
                        return Err(error);
                    }
                };
            let a_folded = match public_window_fold_resident(
                head_weights,
                t,
                s_pad,
                0,
                s_pad,
                &eq_query_rows,
                volta_accel::MatrixFoldAxis::Rows,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        wv_jobs,
                    );
                    return Err(error);
                }
            };
            let b_folded = match cache_fold_cols_resident_p(
                cx.stream,
                v_segments,
                wit.v_cache(),
                shape.s(),
                &eq_within,
                head * DH,
                DH,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx
                        .backend
                        .as_deref_mut()
                        .expect("resident attention backend")
                        .free_device(a_folded);
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        wv_jobs,
                    );
                    return Err(error);
                }
            };
            let (b_folded, b_tags) = b_folded;
            let job = match prepare_gemm_act_chained_resident_batch(
                attention_act_site_id(
                    shape.t0,
                    schedule_section,
                    AttentionActRole::WeightValue,
                    head,
                ),
                a_folded,
                b_folded,
                t,
                s_pad,
                DH,
                &av_point[d_cb..],
                &av_point[..6],
                av_auth[head],
                &wv_doms[head],
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        wv_jobs,
                    );
                    return Err(error);
                }
            };
            wv_tags.push(b_tags);
            wv_jobs.push(job);
        }
        let wv_outputs = prove_attention_resident_round_batch(
            &wv_plan,
            wv_jobs,
            cx.stream,
            cx.tx,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        for (head, (output, b_tags)) in wv_outputs.into_iter().zip(wv_tags).enumerate() {
            let rounds: GemmActRoundOutput = output.into();
            let b_final = rounds.b_final;
            if rounds.site_id
                != Some(attention_act_site_id(
                    shape.t0,
                    schedule_section,
                    AttentionActRole::WeightValue,
                    head,
                ))
            {
                return Err(AccelError::InvalidInput(
                    "resident W·V cohort returned a noncanonical SiteId",
                ));
            }
            let eq = eq_vec(&rounds.point);
            let tag = (0..shape.s()).fold(Fp2::ZERO, |sum, row| sum + eq[row] * b_tags[row]);
            let (proof, wire, _, _, _) = finalize_gemm_act_chained(
                rounds,
                &av_point[d_cb..],
                ProverAuthed { x: b_final, m: tag },
                &wv_doms[head],
                cx.stream,
                cx.tx,
                ProveTimings::default(),
            )?;
            let mut lifted_point = wire.point.clone();
            lifted_point.extend(head_bit_coords(head));
            aux_sn.push(LeafAuxClaim { col: 1, point: lifted_point, value: wire.value });
            gemm_wv.push((proof, wire.corr));
        }

        // 6: causal mask sumcheck. Equality rows and the mask are built D2D;
        // one duplicate is retained solely for the final public MLE scalar.
        let tau: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
        let backend = cx.backend.as_deref_mut().expect("resident attention backend");
        let mask_sumcheck = backend.equality_weights_device(&tau)?;
        if let Err(error) =
            backend.attention_above_mask_device(&mask_sumcheck, t, shape.s(), shape.t0, H, H_PAD)
        {
            let _ = backend.free_device(mask_sumcheck);
            return Err(error);
        }
        let mask_eval = match backend.equality_weights_device(&tau) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(mask_sumcheck);
                return Err(error);
            }
        };
        if let Err(error) =
            backend.attention_above_mask_device(&mask_eval, t, shape.s(), shape.t0, H, H_PAD)
        {
            let _ = backend.free_device(mask_eval);
            let _ = backend.free_device(mask_sumcheck);
            return Err(error);
        }
        let w_lift = match backend.base_to_fp2_broadcast_device(p1.wires.rect_column(1)?, 1) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(mask_eval);
                let _ = backend.free_device(mask_sumcheck);
                return Err(error);
            }
        };
        cx.ctr_other.fp2_mults += 3 * rect_entries as u64;
        let causal_doms = cx.doms.take(nr as u64);
        let causal_result = blind_prove_resident(
            mask_sumcheck,
            w_lift,
            ProverAuthed::from_public(Fp2::ZERO),
            cx.stream,
            causal_doms,
            cx.tx,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        );
        let (causal, causal_point, causal_claim) = match causal_result {
            Ok((proof, point, claim, _, _)) => (proof, point, claim),
            Err(error) => {
                let _ = cx
                    .backend
                    .as_deref_mut()
                    .expect("resident attention backend")
                    .free_device(mask_eval);
                return Err(error);
            }
        };
        let backend = cx.backend.as_deref_mut().expect("resident attention backend");
        let mask_value = backend.mle_eval_device(
            DeviceSlice::new(&mask_eval, 0, mask_eval.len()).expect("whole causal mask"),
            &causal_point,
        );
        let mask_free = backend.free_device(mask_eval);
        let mask_value = match (mask_value, mask_free) {
            (Ok(value), Ok(())) => value,
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        if mask_value == Fp2::ZERO {
            return Err(AccelError::InvalidInput("causal mask MLE vanished at challenge"));
        }
        cx.ctr_other.fp2_mults += (rect_entries - 1) as u64;
        let w_value = backend.mle_eval_device(p1.wires.rect_column(1)?, &causal_point)?;
        cx.ctr_other.fp2_mults += rect_entries as u64;
        cx.ctr_other.base_mults += rect_entries as u64;
        let causal_wire_dom = cx.doms.take(1);
        let causal_mask = cx.stream.draw_fulls(causal_wire_dom, 1)[0];
        let causal_w_corr = w_value - causal_mask.x;
        cx.tx.append("causal_w_correction", 16);
        let causal_w_auth = ProverAuthed { x: w_value, m: causal_mask.m };
        cx.zero.push(causal_w_auth.scale(mask_value).sub(causal_claim));
        aux_sn.push(LeafAuxClaim { col: 1, point: causal_point, value: causal_w_auth });

        // 7–9: softmax normalization, exp×recip Hadamard and row sums.
        let sn_instance = cx.inst_resident(
            TableKey::Range(s_sn),
            p1.wires.softmax_norm_columns(),
            2,
            rect_entries,
            &[Some(0), None],
            aux_sn,
        )?;
        let softmax_acc_claim = transport_p(&sn_instance, s_sn);
        let exp_factor = cx
            .backend
            .as_deref_mut()
            .expect("resident attention backend")
            .base_to_fp2_broadcast_device(p1.wires.rect_column(4)?, 1)?;
        let recip_factor = match cx
            .backend
            .as_deref_mut()
            .expect("resident attention backend")
            .base_to_fp2_broadcast_device(p1.wires.row_column(2)?, s_pad)
        {
            Ok(value) => value,
            Err(error) => {
                let _ = cx
                    .backend
                    .as_deref_mut()
                    .expect("resident attention backend")
                    .free_device(exp_factor);
                return Err(error);
            }
        };
        let hadamard_doms = HadamardDoms::alloc(&mut cx.doms, nr);
        let (hadamard, hadamard_point, exp_claim, recip_claim) = hadamard_prove_resident(
            &sn_instance.point,
            exp_factor,
            recip_factor,
            softmax_acc_claim,
            &hadamard_doms,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        let recip_open = open_fp_vec_resident_p(
            cx.stream,
            p1.dom_recips,
            p1.wires.row_column(2)?,
            &hadamard_point[sb..],
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        cx.zero.push(recip_claim.sub(recip_open));

        let rho: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
        let half = Fp2::from_base(Fp::new(2).inv());
        let mut half_point = vec![half; sb];
        half_point.extend_from_slice(&rho);
        let rowsum_value = cx
            .backend
            .as_deref_mut()
            .expect("resident attention backend")
            .mle_eval_device(p1.wires.rect_column(4)?, &half_point)?;
        cx.ctr_other.fp2_mults += (rect_entries - 1) as u64;
        let rowsum_dom = cx.doms.take(1);
        let rowsum_mask = cx.stream.draw_fulls(rowsum_dom, 1)[0];
        let rowsum_corr = rowsum_value - rowsum_mask.x;
        cx.tx.append("rowsum_correction", 16);
        let rowsum_auth = ProverAuthed { x: rowsum_value, m: rowsum_mask.m };
        let denom_open = open_fp_vec_resident_p(
            cx.stream,
            p1.dom_denoms,
            p1.wires.row_column(0)?,
            &rho,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        let two_sb = Fp2::from_base(Fp::new(1u64 << sb));
        cx.zero.push(denom_open.sub(rowsum_auth.scale(two_sb)));

        // 10: exp lookup plus stable-softmax row-max relations.
        let mut exp_aux = vec![
            LeafAuxClaim { col: 1, point: hadamard_point, value: exp_claim },
            LeafAuxClaim { col: 1, point: half_point.clone(), value: rowsum_auth },
        ];
        let mut hadamard2 = None;
        let mut ismax_rowsum_corr = None;
        if params.softmax_row_shift {
            let ismax = cx
                .backend
                .as_deref_mut()
                .expect("resident attention backend")
                .base_to_fp2_broadcast_device(p1.wires.rect_column(5)?, 1)?;
            let sprime = match cx
                .backend
                .as_deref_mut()
                .expect("resident attention backend")
                .base_to_fp2_broadcast_device(p1.wires.rect_column(3)?, 1)
            {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx
                        .backend
                        .as_deref_mut()
                        .expect("resident attention backend")
                        .free_device(ismax);
                    return Err(error);
                }
            };
            let tau2: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
            let rowmax_doms = HadamardDoms::alloc(&mut cx.doms, nr);
            let (proof, point, ismax_claim, sprime_claim) = hadamard_prove_resident(
                &tau2,
                ismax,
                sprime,
                ProverAuthed::from_public(Fp2::ZERO),
                &rowmax_doms,
                cx.stream,
                cx.tx,
                &mut cx.prod,
                &mut cx.zero,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            )?;
            hadamard2 = Some(proof);
            let rho2: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
            let mut half_point2 = vec![half; sb];
            half_point2.extend_from_slice(&rho2);
            let rowmax_sum = cx
                .backend
                .as_deref_mut()
                .expect("resident attention backend")
                .mle_eval_device(p1.wires.rect_column(5)?, &half_point2)?;
            cx.ctr_other.fp2_mults += (rect_entries - 1) as u64;
            let rowmax_sum_dom = cx.doms.take(1);
            let rowmax_sum_mask = cx.stream.draw_fulls(rowmax_sum_dom, 1)[0];
            ismax_rowsum_corr = Some(rowmax_sum - rowmax_sum_mask.x);
            cx.tx.append("ismax_rowsum_correction", 16);
            let rowmax_sum_auth = ProverAuthed { x: rowmax_sum, m: rowmax_sum_mask.m };
            let eq_rho2 = eq_vec(&rho2);
            cx.ctr_other.fp2_mults += 1u64 << (qb + HEAD_BITS);
            let mut real_mask = Fp2::ZERO;
            for head in 0..H {
                for row in 0..t {
                    real_mask += eq_rho2[head * q_pad + row];
                }
            }
            cx.zero.push(rowmax_sum_auth.scale(two_sb).sub(ProverAuthed::from_public(real_mask)));
            exp_aux.push(LeafAuxClaim { col: 0, point: point.clone(), value: sprime_claim });
            exp_aux.push(LeafAuxClaim { col: 2, point, value: ismax_claim });
            exp_aux.push(LeafAuxClaim { col: 2, point: half_point2, value: rowmax_sum_auth });
        }
        let exp_count = if params.softmax_row_shift { 3 } else { 2 };
        let exp_all = p1.wires.exp_columns();
        let exp_view =
            DeviceSlice::new(exp_all.buffer(), exp_all.offset(), exp_count * rect_entries)?;
        let exp_shifts = [Some(0), Some(16), None];
        let exp_instance = cx.inst_resident(
            TableKey::Exp,
            exp_view,
            exp_count,
            rect_entries,
            &exp_shifts[..exp_count],
            exp_aux,
        )?;

        // 11–12: reciprocal and score lookups, including pad/above/rowshift correction.
        let recip_first = p1.wires.row_column(1)?;
        let recip_view = DeviceSlice::new(
            recip_first.buffer(),
            recip_first.offset(),
            2 * p1.wires.row_entries(),
        )?;
        let recip_instance = cx.inst_resident(
            TableKey::SoftmaxRecip,
            recip_view,
            2,
            p1.wires.row_entries(),
            &[Some(0), Some(16)],
            Vec::new(),
        )?;
        close_softmax_recip_resident(
            &recip_instance,
            p1.dom_rin_row,
            p1.wires.row_column(1)?,
            p1.dom_recips,
            p1.wires.row_column(2)?,
            cx,
        )?;

        let scores_instance = cx.inst_resident(
            TableKey::Range(s_sc),
            p1.wires.scores_columns(),
            2,
            rect_entries,
            &[Some(0), None],
            vec![LeafAuxClaim {
                col: 1,
                point: exp_instance.point.clone(),
                value: exp_instance.col_claims[0].value,
            }],
        )?;
        let transported_scores = transport_p(&scores_instance, s_sc);
        let score_point = scores_instance.point.clone();
        let eq_scores = eq_vec(&score_point);
        cx.ctr_other.fp2_mults += rect_entries as u64;
        let mut causal_mass = Fp2::ZERO;
        for head in 0..H {
            for row in 0..t {
                for col in 0..shape.win(row) {
                    causal_mass += eq_scores[head * sp2 + row * s_pad + col];
                }
            }
        }
        let pad_mask = Fp2::ONE - causal_mass;
        let exp_pad = (0..1usize << 16)
            .find(|&index| luts.exp[index] == 0)
            .ok_or(AccelError::InvalidInput("exp LUT has no padding input"))?
            as u16 as i16;
        let pad_acc = Fp2::from_base(Fp::from_i64((exp_pad as i64) << s_sc));
        let mut above_weights = Vec::with_capacity(H * shape.n_above_head());
        for head in 0..H {
            for row in 0..t {
                for col in shape.win(row)..shape.s() {
                    above_weights.push(eq_scores[head * sp2 + row * s_pad + col]);
                }
            }
        }
        let above_open = open_weighted_resident_p(
            cx.stream,
            p1.dom_above,
            p1.wires.above(),
            &above_weights,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        let mut true_score_claim =
            transported_scores.sub(ProverAuthed::from_public(pad_acc * pad_mask)).add(above_open);
        if params.softmax_row_shift {
            let mut row_weights = vec![Fp2::ZERO; H_PAD * q_pad];
            for head in 0..H {
                for row in 0..t {
                    for col in 0..shape.win(row) {
                        row_weights[head * q_pad + row] +=
                            eq_scores[head * sp2 + row * s_pad + col];
                    }
                }
            }
            let shift_open = open_weighted_resident_p(
                cx.stream,
                p1.dom_rowshift.expect("row-shift domain"),
                p1.wires.row_column(3)?,
                &row_weights,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            )?;
            true_score_claim =
                true_score_claim.add(shift_open.scale(Fp2::from_base(Fp::new(1u64 << s_sc))));
        }

        // 13–15: score head split, QK GEMMs, and K/V boundary selectors.
        let eq_head_scores = eq_vec(&score_point[sb + qb..]);
        let mut score_values = [Fp2::ZERO; H];
        let full_scores = p1.wires.full_scores();
        for (head, value) in score_values.iter_mut().enumerate() {
            let head_scores =
                DeviceSlice::new(full_scores.buffer(), full_scores.offset() + head * sp2, sp2)?;
            *value = cx
                .backend
                .as_deref_mut()
                .expect("resident attention backend")
                .mle_eval_device(head_scores, &score_point[..sb + qb])?;
            cx.ctr_other.fp2_mults += (sp2 - 1) as u64;
        }
        let split_scores_dom = cx.doms.take(1);
        let split_scores_masks = cx.stream.draw_fulls(split_scores_dom, H);
        let mut sc_split_corrs = [Fp2::ZERO; H];
        let mut score_auth = Vec::with_capacity(H);
        for head in 0..H {
            sc_split_corrs[head] = score_values[head] - split_scores_masks[head].x;
            score_auth.push(ProverAuthed { x: score_values[head], m: split_scores_masks[head].m });
        }
        cx.tx.append("head_split_corrections", 16 * H as u64);
        let mut score_split_row = ProverAuthed::ZERO.sub(true_score_claim);
        for head in 0..H {
            score_split_row = score_split_row.add(score_auth[head].scale(eq_head_scores[head]));
        }
        debug_assert_eq!(score_split_row.x, Fp2::ZERO, "resident score head split violated");
        cx.zero.push(score_split_row);

        let eq_score_columns = eq_vec(&score_point[..sb]);
        let eq_score_rows = eq_vec(&score_point[sb..sb + qb]);
        let mut gemm_qk = Vec::with_capacity(H);
        let mut aux_qkv = Vec::with_capacity(H + 2);
        let qk_doms: Vec<ChainDoms> = (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, DH)).collect();
        let qk_plan = attention_act_schedule(
            shape.t0,
            schedule_section,
            AttentionActRole::QueryKey,
            pad_bits(DH),
            &qk_doms,
        );
        let mut qk_tags = Vec::with_capacity(H);
        let mut qk_jobs = Vec::with_capacity(H);
        for head in 0..H {
            let a_folded = match public_window_fold_resident(
                wit.i16(LayerI16Field::Q),
                t,
                D,
                head * DH,
                DH,
                &eq_score_rows,
                volta_accel::MatrixFoldAxis::Rows,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        qk_jobs,
                    );
                    return Err(error);
                }
            };
            let b_folded = match cache_fold_rows_resident_p(
                cx.stream,
                k_segments,
                wit.k_cache(),
                shape.s(),
                &eq_score_columns,
                head * DH,
                DH,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = cx
                        .backend
                        .as_deref_mut()
                        .expect("resident attention backend")
                        .free_device(a_folded);
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        qk_jobs,
                    );
                    return Err(error);
                }
            };
            let (b_folded, b_tags) = b_folded;
            let job = match prepare_gemm_act_chained_resident_batch(
                attention_act_site_id(shape.t0, schedule_section, AttentionActRole::QueryKey, head),
                a_folded,
                b_folded,
                t,
                DH,
                shape.s(),
                &score_point[sb..sb + qb],
                &score_point[..sb],
                score_auth[head],
                &qk_doms[head],
                cx.backend.as_deref_mut().expect("resident attention backend"),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let _ = free_attention_resident_jobs(
                        cx.backend.as_deref_mut().expect("resident attention backend"),
                        qk_jobs,
                    );
                    return Err(error);
                }
            };
            qk_tags.push(b_tags);
            qk_jobs.push(job);
        }
        let qk_outputs = prove_attention_resident_round_batch(
            &qk_plan,
            qk_jobs,
            cx.stream,
            cx.tx,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        for (head, (output, b_tags)) in qk_outputs.into_iter().zip(qk_tags).enumerate() {
            let rounds: GemmActRoundOutput = output.into();
            let b_final = rounds.b_final;
            if rounds.site_id
                != Some(attention_act_site_id(
                    shape.t0,
                    schedule_section,
                    AttentionActRole::QueryKey,
                    head,
                ))
            {
                return Err(AccelError::InvalidInput(
                    "resident Q·Kᵀ cohort returned a noncanonical SiteId",
                ));
            }
            let eq = eq_vec(&rounds.point);
            let tag = (0..DH).fold(Fp2::ZERO, |sum, index| sum + eq[index] * b_tags[index]);
            let (proof, wire, _, _, _) = finalize_gemm_act_chained(
                rounds,
                &score_point[sb..sb + qb],
                ProverAuthed { x: b_final, m: tag },
                &qk_doms[head],
                cx.stream,
                cx.tx,
                ProveTimings::default(),
            )?;
            let mut lifted_point = wire.point[..6].to_vec();
            lifted_point.extend(head_bit_coords(head));
            lifted_point.push(Fp2::ZERO);
            lifted_point.push(Fp2::ZERO);
            lifted_point.extend_from_slice(&wire.point[6..]);
            aux_qkv.push(LeafAuxClaim { col: 1, point: lifted_point, value: wire.value });
            gemm_qk.push((proof, wire.corr));
        }
        let rho_k: Vec<Fp2> = (0..d_cb + qb).map(|_| cx.tx.challenge_fp2()).collect();
        let k_open = open_matrix_resident_p(
            cx.stream,
            dom_k,
            wit.i16(LayerI16Field::K),
            t,
            D,
            &rho_k,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        let mut k_point = rho_k[..d_cb].to_vec();
        k_point.push(Fp2::ONE);
        k_point.push(Fp2::ZERO);
        k_point.extend_from_slice(&rho_k[d_cb..]);
        aux_qkv.push(LeafAuxClaim { col: 1, point: k_point, value: k_open });
        let rho_v: Vec<Fp2> = (0..d_cb + qb).map(|_| cx.tx.challenge_fp2()).collect();
        let v_open = open_matrix_resident_p(
            cx.stream,
            dom_v,
            wit.i16(LayerI16Field::V),
            t,
            D,
            &rho_v,
            cx.backend.as_deref_mut().expect("resident attention backend"),
        )?;
        let mut v_point = rho_v[..d_cb].to_vec();
        v_point.push(Fp2::ZERO);
        v_point.push(Fp2::ONE);
        v_point.extend_from_slice(&rho_v[d_cb..]);
        aux_qkv.push(LeafAuxClaim { col: 1, point: v_point, value: v_open });

        // 16–17: QKV lookup, permuted committed c_attn, and LN1.
        let qkv_instance = cx.inst_resident(
            TableKey::Range(s_qkv),
            p1.wires.qkv_columns(),
            2,
            p1.wires.qkv_entries(),
            &[Some(0), None],
            aux_qkv,
        )?;
        let mut qkv_claim = transport_p(&qkv_instance, s_qkv);
        let qkv_point = qkv_instance.point.clone();
        if let Some(biases) = biases {
            qkv_claim = sub_bias_p(
                qkv_claim,
                &cattn_bias_permuted(&biases.c_attn),
                12,
                &qkv_point,
                t,
                s_qkv,
                &mut cx.ctr_other,
            );
        }
        let (r_j_qkv, r_i_qkv) = qkv_point.split_at(12);
        let cattn_doms = ChainDoms::alloc(&mut cx.doms, D);
        let (gemm_cattn, wire_ln1, w_cattn_corr, wclaim_cattn, _, _) =
            prove_gemm_committed_chained_resident(
                wit.i16(LayerI16Field::Ln1Out),
                resident_model.layer_weight(layer, LayerWeightField::CAttnProof)?,
                t,
                D,
                4096,
                r_i_qkv,
                r_j_qkv,
                qkv_claim,
                &cattn_doms,
                cx.stream,
                cx.tx,
                cx.backend.as_deref_mut().expect("resident attention backend"),
            )?;
        let ln = prove_ln_chain_resident(
            t,
            s_ln,
            &p1.ln,
            &p1.rsqrt,
            wit.i16(LayerI16Field::XIn),
            dom_xin,
            resident_model.layer_weight(layer, LayerWeightField::Ln1Gain)?,
            &weights.ln1_gain,
            &weights.ln1_bias,
            &p1.lv1,
            &wire_ln1,
            cx,
        )?;

        Ok((
            AttnBlockProof {
                ln_vec_corrs: std::mem::take(&mut p1.ln_vec_corrs),
                denoms_corr: std::mem::take(&mut p1.denoms_corr),
                recip_in_corr: std::mem::take(&mut p1.recip_in_corr),
                recips_corr: std::mem::take(&mut p1.recips_corr),
                above_corr: std::mem::take(&mut p1.above_corr),
                row_shift_corr: p1.row_shift_corr.take(),
                hadamard2,
                ismax_rowsum_corr,
                inst_proj: proj_site.main.proof,
                inst_proj_stage1: proj_site.stage1.map(|stage| stage.proof),
                gemm_proj,
                av_wire_corr: wire_av.corr,
                w_proj_corr,
                inst_av: av_site.main.proof,
                av_split_corrs,
                gemm_wv,
                causal,
                causal_w_corr,
                inst_sn: sn_instance.proof,
                hadamard,
                rowsum_corr,
                inst_exp: exp_instance.proof,
                inst_recip: recip_instance.proof,
                inst_sc: scores_instance.proof,
                sc_split_corrs,
                gemm_qk,
                inst_qkv: qkv_instance.proof,
                gemm_cattn,
                ln1_wire_corr: wire_ln1.corr,
                w_cattn_corr,
                ln,
            },
            vec![wclaim_proj, wclaim_cattn],
        ))
    })();
    let free_result = p1.free(
        cx.backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident attention cleanup requires a backend"))?,
    );
    match (result, free_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Attention block — verifier
// ---------------------------------------------------------------------------

/// Attention verifier phase-1 state: cached element-wise keys.
pub struct AttnV1 {
    lvk1: LnVecsK,
    denoms_keys: Vec<Fp2>,
    rin_row_keys: Vec<Fp2>,
    recips_keys: Vec<Fp2>,
    above_keys: Vec<Fp2>,
    rowshift_keys: Option<Vec<Fp2>>,
}

/// Mirror of [`attn_phase1_with_wires`]: length checks + key expansion, in
/// the prover's exact dom/correction order.
pub(crate) fn verify_attn_phase1(
    sh: BandShape,
    luts: &Luts,
    proof: &AttnBlockProof,
    cx: &mut BlockCtxV,
) -> Option<AttnV1> {
    let p = luts.params;
    let t_pad = sh.q_pad();
    let n_above = H * sh.n_above_head();

    // Length checks before consuming any correlations.
    for v in &proof.ln_vec_corrs {
        if v.len() != t_pad {
            return None;
        }
    }
    for v in [&proof.denoms_corr, &proof.recip_in_corr, &proof.recips_corr] {
        if v.len() != H_PAD * t_pad {
            return None;
        }
    }
    if proof.above_corr.len() != n_above || proof.gemm_wv.len() != H || proof.gemm_qk.len() != H {
        return None;
    }
    // P5 stable softmax: presence of the row-shift machinery must match the
    // flag; the row-shift table has the row-table length.
    let row_shift_on = p.softmax_row_shift;
    if row_shift_on != proof.row_shift_corr.is_some()
        || row_shift_on != proof.hadamard2.is_some()
        || row_shift_on != proof.ismax_rowsum_corr.is_some()
    {
        return None;
    }
    if let Some(c) = &proof.row_shift_corr {
        if c.len() != H_PAD * t_pad {
            return None;
        }
    }
    let lvk1 = expand_ln_vecs_k(cx, &proof.ln_vec_corrs);
    let dom_denoms = cx.doms.take(1);
    let denoms_keys = keys_fp_vec_v(cx.ctx, dom_denoms, &proof.denoms_corr);
    let dom_rin_row = cx.doms.take(1);
    let rin_row_keys = keys_fp_vec_v(cx.ctx, dom_rin_row, &proof.recip_in_corr);
    let dom_recips = cx.doms.take(1);
    let recips_keys = keys_fp_vec_v(cx.ctx, dom_recips, &proof.recips_corr);
    let dom_above = cx.doms.take(1);
    let above_keys = keys_fp_vec_v(cx.ctx, dom_above, &proof.above_corr);
    let rowshift_keys = proof.row_shift_corr.as_ref().map(|corr| {
        let dom = cx.doms.take(1);
        keys_fp_vec_v(cx.ctx, dom, corr)
    });
    Some(AttnV1 { lvk1, denoms_keys, rin_row_keys, recips_keys, above_keys, rowshift_keys })
}

/// Verify the attention half against the cached boundary keys (phase 2).
/// Returns the `[attn_proj, c_attn]` weight-claim (point, key) pairs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_attn_block(
    sh: BandShape,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    luts: &Luts,
    proof: &AttnBlockProof,
    v1: AttnV1,
    cx: &mut BlockCtxV,
    xin_keys: &[Fp2],
    k_segs: &[CacheSegK],
    v_segs: &[CacheSegK],
    abo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let p = luts.params;
    let t = sh.q;
    if k_segs.iter().map(|g| g.rows).sum::<usize>() != sh.s()
        || v_segs.iter().map(|g| g.rows).sum::<usize>() != sh.s()
        || k_segs.last()?.rows != t
        || v_segs.last()?.rows != t
    {
        return None;
    }
    let k_keys = k_segs.last()?.keys;
    let v_keys = v_segs.last()?.keys;
    let (qb, sb) = (sh.qb(), sh.sb());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let s_len = sh.s();
    let nr = sh.nr();
    let rb = qb;
    let d_cb = pad_bits(D);
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;
    let n_above = H * sh.n_above_head();
    let row_shift_on = p.softmax_row_shift;
    let AttnV1 { lvk1, denoms_keys, rin_row_keys, recips_keys, above_keys, rowshift_keys } = v1;

    // Presence of the chained stage-1 instances must match the shifts.
    if (s_ap > 16) != proof.inst_proj_stage1.is_some()
        || (s_ln > 16) != proof.ln.inst_ln_stage1.is_some()
    {
        return None;
    }

    // ---- 1+2: attn_proj instance + residual + GEMM -------------------------
    let n_d = d_cb + rb;
    let shifts_range = [Some(0u32), None];
    let shifts_pair = [Some(0u32), Some(16u32)];
    let site_proj =
        verify_range_site(n_d, s_ap, &proof.inst_proj, proof.inst_proj_stage1.as_ref(), &[], cx)?;
    let vp = &site_proj.main;
    let pt_ap = vp.point.clone();
    let abo_k = open_matrix_k(abo_keys, t, D, &pt_ap);
    let xin_k = open_matrix_k(xin_keys, t, D, &pt_ap);
    cx.kzero.push(vp.col_keys[1].key.sub(abo_k).add(xin_k));
    let pt_acc_ap = site_proj.acc_point().to_vec();
    let mut k_acc_ap = site_proj.acc_key;
    if let Some(b) = biases {
        k_acc_ap = sub_bias_k(k_acc_ap, &b.attn_proj, d_cb, &pt_acc_ap, t, s_ap, cx.ctx.delta);
    }
    let (r_j_ap, r_i_ap) = pt_acc_ap.split_at(d_cb);
    let cd_proj = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_av, w_pt_proj, k_w_proj) = verify_gemm_committed_chained(
        t,
        D,
        D,
        r_i_ap,
        r_j_ap,
        k_acc_ap,
        &proof.gemm_proj,
        proof.av_wire_corr,
        proof.w_proj_corr,
        &cd_proj,
        cx.ctx,
        cx.tx,
    )?;

    // ---- 3: av instance ------------------------------------------------------
    let aux_av = [(1usize, wk_av.point.clone(), wk_av.key)];
    let va = cx.inst(TableKey::Range(s_av), n_d, &shifts_range, &proof.inst_av, &aux_av)?;
    let k_acc_av = transport_k(&va, s_av, cx.ctx.delta);
    let pt_av = va.point.clone();

    // ---- 4: av head split ------------------------------------------------------
    let eqh_av = eq_vec(&pt_av[6..d_cb]);
    let dom_split_av = cx.doms.take(1);
    let ks_av = cx.ctx.expand_full_keys(dom_split_av, H);
    let av_keys: Vec<VerifierKey> = (0..H)
        .map(|h| VerifierKey { k: ks_av[h] + cx.ctx.delta * proof.av_split_corrs[h] })
        .collect();
    let mut krow = VerifierKey::ZERO.sub(k_acc_av);
    for h in 0..H {
        krow = krow.add(av_keys[h].scale(eqh_av[h]));
    }
    cx.kzero.push(krow);

    // ---- 5: per-head w·V GEMMs --------------------------------------------------
    let eq_within = eq_vec(&pt_av[..6]);
    let mut aux_sn: Vec<(usize, Vec<Fp2>, VerifierKey)> = Vec::with_capacity(H + 1);
    let layer = attention_layer_from_doms(&cx.doms);
    let wv_doms: Vec<ChainDoms> = (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, s_pad)).collect();
    let wv_plan = attention_act_schedule(
        sh.t0,
        layer,
        AttentionActRole::WeightValue,
        pad_bits(s_pad),
        &wv_doms,
    );
    let mut wv_bkeys = Vec::with_capacity(H);
    let mut wv_jobs = Vec::with_capacity(H);
    for h in 0..H {
        let vkeys_row = cache_fold_cols_k(v_segs, &eq_within, h * DH, DH);
        wv_bkeys.push(vkeys_row);
        wv_jobs.push(BlindSumcheckBatchVerifyJob {
            site_id: attention_act_site_id(sh.t0, layer, AttentionActRole::WeightValue, h),
            n_vars: pad_bits(s_pad),
            claim0: av_keys[h],
            proof: &proof.gemm_wv[h].0.sumcheck,
            mask_dom_base: wv_doms[h].round_masks,
        });
    }
    let wv_outputs = blind_verify_batch(&wv_plan, wv_jobs, cx.ctx, cx.tx)?;
    for (h, (output, vkeys_row)) in wv_outputs.into_iter().zip(wv_bkeys).enumerate() {
        if output.site_id != attention_act_site_id(sh.t0, layer, AttentionActRole::WeightValue, h) {
            return None;
        }
        let eq_l = eq_vec(&output.point);
        let k_b = VerifierKey {
            k: (0..s_len).fold(Fp2::ZERO, |sum, row| sum + eq_l[row] * vkeys_row[row]),
        };
        let (wk, _r_l) = finalize_verify_gemm_act_chained(
            output,
            &pt_av[d_cb..],
            &proof.gemm_wv[h].0,
            proof.gemm_wv[h].1,
            k_b,
            &wv_doms[h],
            cx.ctx,
            cx.tx,
        )?;
        let mut ptx = wk.point.clone();
        ptx.extend(head_bit_coords(h));
        aux_sn.push((1, ptx, wk.key));
    }

    // ---- 6: causal mask relation --------------------------------------------
    let tau: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_tau = eq_vec(&tau);
    let mut m_tab = vec![Fp2::ZERO; 1 << nr];
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                let y = h * sp2 + i * s_pad + j;
                m_tab[y] = eq_tau[y];
            }
        }
    }
    let dom_causal_rounds = cx.doms.take(nr as u64);
    let (r_c, k_causal_n) = blind_verify(
        nr,
        VerifierKey::from_public(Fp2::ZERO, cx.ctx.delta),
        &proof.causal,
        cx.ctx,
        dom_causal_rounds,
        cx.tx,
    )?;
    let m_eval = eval_mle(&m_tab, &r_c);
    if m_eval == Fp2::ZERO {
        return None; // negligible-probability event; redraw/panic acceptable
    }
    let dom_cw = cx.doms.take(1);
    let k_w_causal = VerifierKey {
        k: cx.ctx.expand_full_keys(dom_cw, 1)[0] + cx.ctx.delta * proof.causal_w_corr,
    };
    cx.kzero.push(k_w_causal.scale(m_eval).sub(k_causal_n));
    aux_sn.push((1, r_c.clone(), k_w_causal));

    // ---- 7: softmax_norm instance ----------------------------------------------
    let vsn = cx.inst(TableKey::Range(s_sn), nr, &shifts_range, &proof.inst_sn, &aux_sn)?;
    let k_wacc = transport_k(&vsn, s_sn, cx.ctx.delta);
    let pt_sn = vsn.point.clone();

    // ---- 8: hadamard ---------------------------------------------------------
    let hd = HadamardDoms::alloc(&mut cx.doms, nr);
    let (r_h, k_e, k_r) = hadamard_verify(
        &pt_sn,
        k_wacc,
        &proof.hadamard,
        &hd,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let rec_k = open_fp_vec_k(&recips_keys, &r_h[sb..]);
    cx.kzero.push(k_r.sub(rec_k));

    // ---- 9: denominator row sums ----------------------------------------------
    let rho: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; sb];
    half_pt.extend_from_slice(&rho);
    let dom_rs = cx.doms.take(1);
    let k_rs =
        VerifierKey { k: cx.ctx.expand_full_keys(dom_rs, 1)[0] + cx.ctx.delta * proof.rowsum_corr };
    let den_k = open_fp_vec_k(&denoms_keys, &rho);
    let two_sb = Fp2::from_base(Fp::new(1u64 << sb));
    cx.kzero.push(den_k.sub(k_rs.scale(two_sb)));

    // ---- 10: exp instance --------------------------------------------------------
    let mut aux_exp = vec![(1usize, r_h.clone(), k_e), (1usize, half_pt.clone(), k_rs)];
    if row_shift_on {
        // (a) is_max ∘ s′ ≡ 0 via hadamard with public claim 0 at fresh τ₂.
        let tau2: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
        let hd2 = HadamardDoms::alloc(&mut cx.doms, nr);
        let (r_h2, k_e2, k_r2) = hadamard_verify(
            &tau2,
            VerifierKey::from_public(Fp2::ZERO, cx.ctx.delta),
            proof.hadamard2.as_ref()?,
            &hd2,
            cx.ctx,
            cx.tx,
            &mut cx.kprod,
            &mut cx.kzero,
        )?;
        // (b) is_max rowsum = 1 per real row (public realmask RHS).
        let rho2: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
        let mut half_pt2 = vec![half_scalar; sb];
        half_pt2.extend_from_slice(&rho2);
        let dom_rs2 = cx.doms.take(1);
        let k_rs2 = VerifierKey {
            k: cx.ctx.expand_full_keys(dom_rs2, 1)[0] + cx.ctx.delta * proof.ismax_rowsum_corr?,
        };
        let eq_rho2 = eq_vec(&rho2);
        let mut realmask = Fp2::ZERO;
        for h in 0..H {
            for i in 0..t {
                realmask += eq_rho2[h * q_pad + i];
            }
        }
        cx.kzero.push(k_rs2.scale(two_sb).sub(VerifierKey::from_public(realmask, cx.ctx.delta)));
        aux_exp.push((0usize, r_h2.clone(), k_r2));
        aux_exp.push((2usize, r_h2, k_e2));
        aux_exp.push((2usize, half_pt2, k_rs2));
    }
    let exp_shifts: Vec<Option<u32>> =
        if row_shift_on { vec![Some(0), Some(16), None] } else { vec![Some(0), Some(16)] };
    let vexp = cx.inst(TableKey::Exp, nr, &exp_shifts, &proof.inst_exp, &aux_exp)?;

    // ---- 11: softmax_recip instance -----------------------------------------------
    let vrc =
        cx.inst(TableKey::SoftmaxRecip, rb + HEAD_BITS, &shifts_pair, &proof.inst_recip, &[])?;
    close_softmax_recip_verifier(&vrc, &rin_row_keys, &recips_keys, cx);

    // ---- 12: scores instance + pad-mask correction -----------------------------
    let aux_sc = [(1usize, vexp.point.clone(), vexp.col_keys[0].key)];
    let vsc = cx.inst(TableKey::Range(s_sc), nr, &shifts_range, &proof.inst_sc, &aux_sc)?;
    let k_tr_sc = transport_k(&vsc, s_sc, cx.ctx.delta);
    let pt_sc = vsc.point.clone();
    let exp_pad_u = (0..1usize << 16).find(|&u| luts.exp[u] == 0)?;
    let pad_in = (exp_pad_u as u16) as i16;
    let eq_sc = eq_vec(&pt_sc);
    let mut caus_sum = Fp2::ZERO;
    for h in 0..H {
        for i in 0..t {
            for j in 0..sh.win(i) {
                caus_sum += eq_sc[h * sp2 + i * s_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((pad_in as i64) << s_sc));
    let mut wts = Vec::with_capacity(n_above);
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                wts.push(eq_sc[h * sp2 + i * s_pad + j]);
            }
        }
    }
    let above_k = open_weighted_k(&above_keys, &wts);
    let mut k_acc_sc_true =
        k_tr_sc.sub(VerifierKey::from_public(c_pad * padmask, cx.ctx.delta)).add(above_k);
    if row_shift_on {
        let mut gcw = vec![Fp2::ZERO; H_PAD * q_pad];
        for h in 0..H {
            for i in 0..t {
                for j in 0..sh.win(i) {
                    gcw[h * q_pad + i] += eq_sc[h * sp2 + i * s_pad + j];
                }
            }
        }
        let gc_k = open_weighted_k(rowshift_keys.as_ref()?, &gcw);
        k_acc_sc_true = k_acc_sc_true.add(gc_k.scale(Fp2::from_base(Fp::new(1u64 << s_sc))));
    }

    // ---- 13: scores head split ---------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[sb + qb..]);
    let dom_split_sc = cx.doms.take(1);
    let ks_sc = cx.ctx.expand_full_keys(dom_split_sc, H);
    let sc_keys: Vec<VerifierKey> = (0..H)
        .map(|h| VerifierKey { k: ks_sc[h] + cx.ctx.delta * proof.sc_split_corrs[h] })
        .collect();
    let mut krow = VerifierKey::ZERO.sub(k_acc_sc_true);
    for h in 0..H {
        krow = krow.add(sc_keys[h].scale(eqh_sc[h]));
    }
    cx.kzero.push(krow);

    // ---- 14: per-head QKᵀ GEMMs ---------------------------------------------------
    let eq_rj_sc = eq_vec(&pt_sc[..sb]);
    let mut aux_qkv: Vec<(usize, Vec<Fp2>, VerifierKey)> = Vec::with_capacity(H + 2);
    let qk_doms: Vec<ChainDoms> = (0..H).map(|_| ChainDoms::alloc(&mut cx.doms, DH)).collect();
    let qk_plan =
        attention_act_schedule(sh.t0, layer, AttentionActRole::QueryKey, pad_bits(DH), &qk_doms);
    let mut qk_bkeys = Vec::with_capacity(H);
    let mut qk_jobs = Vec::with_capacity(H);
    for h in 0..H {
        let kkeys_col = cache_fold_rows_k(k_segs, &eq_rj_sc, h * DH, DH);
        qk_bkeys.push(kkeys_col);
        qk_jobs.push(BlindSumcheckBatchVerifyJob {
            site_id: attention_act_site_id(sh.t0, layer, AttentionActRole::QueryKey, h),
            n_vars: pad_bits(DH),
            claim0: sc_keys[h],
            proof: &proof.gemm_qk[h].0.sumcheck,
            mask_dom_base: qk_doms[h].round_masks,
        });
    }
    let qk_outputs = blind_verify_batch(&qk_plan, qk_jobs, cx.ctx, cx.tx)?;
    for (h, (output, kkeys_col)) in qk_outputs.into_iter().zip(qk_bkeys).enumerate() {
        if output.site_id != attention_act_site_id(sh.t0, layer, AttentionActRole::QueryKey, h) {
            return None;
        }
        let eq_l = eq_vec(&output.point);
        let k_b = VerifierKey { k: (0..DH).fold(Fp2::ZERO, |sum, l| sum + eq_l[l] * kkeys_col[l]) };
        let (wk, _r_l) = finalize_verify_gemm_act_chained(
            output,
            &pt_sc[sb..sb + qb],
            &proof.gemm_qk[h].0,
            proof.gemm_qk[h].1,
            k_b,
            &qk_doms[h],
            cx.ctx,
            cx.tx,
        )?;
        let mut ptx = wk.point[..6].to_vec();
        ptx.extend(head_bit_coords(h));
        ptx.push(Fp2::ZERO);
        ptx.push(Fp2::ZERO);
        ptx.extend_from_slice(&wk.point[6..]);
        aux_qkv.push((1, ptx, wk.key));
    }

    // ---- 15: K/V third-slice aux claims -------------------------------------------
    let rho_k: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let k_bound_k = open_matrix_k(k_keys, t, D, &rho_k);
    let mut pt_k = rho_k[..d_cb].to_vec();
    pt_k.push(Fp2::ONE);
    pt_k.push(Fp2::ZERO);
    pt_k.extend_from_slice(&rho_k[d_cb..]);
    aux_qkv.push((1, pt_k, k_bound_k));
    let rho_v: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let v_bound_k = open_matrix_k(v_keys, t, D, &rho_v);
    let mut pt_v = rho_v[..d_cb].to_vec();
    pt_v.push(Fp2::ZERO);
    pt_v.push(Fp2::ONE);
    pt_v.extend_from_slice(&rho_v[d_cb..]);
    aux_qkv.push((1, pt_v, v_bound_k));

    // ---- 16: qkv instance → c_attn GEMM ---------------------------------------------
    let vqkv =
        cx.inst(TableKey::Range(s_qkv), 12 + rb, &shifts_range, &proof.inst_qkv, &aux_qkv)?;
    let mut k_acc_qkv = transport_k(&vqkv, s_qkv, cx.ctx.delta);
    let pt_qkv = vqkv.point.clone();
    if let Some(b) = biases {
        let bias_perm = cattn_bias_permuted(&b.c_attn);
        k_acc_qkv = sub_bias_k(k_acc_qkv, &bias_perm, 12, &pt_qkv, t, s_qkv, cx.ctx.delta);
    }
    let (r_j_qkv, r_i_qkv) = pt_qkv.split_at(12);
    let cd_cattn = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_ln1, w_pt_cattn, k_w_cattn) = verify_gemm_committed_chained(
        t,
        D,
        4096,
        r_i_qkv,
        r_j_qkv,
        k_acc_qkv,
        &proof.gemm_cattn,
        proof.ln1_wire_corr,
        proof.w_cattn_corr,
        &cd_cattn,
        cx.ctx,
        cx.tx,
    )?;

    // ---- 17: LN1 chain -----------------------------------------------------------
    verify_ln_chain(t, s_ln, ln1_gain, ln1_bias, xin_keys, &lvk1, &proof.ln, &wk_ln1, cx)?;

    Some(vec![(w_pt_proj, k_w_proj), (w_pt_cattn, k_w_cattn)])
}

// ---------------------------------------------------------------------------
// Layer orchestration
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct LayerProof {
    // Boundary auth corrections (8 B each), hoisted here — owned once.
    pub xin_corr: Vec<u64>,
    pub k_corr: Vec<u64>,
    pub v_corr: Vec<u64>,
    pub abo_corr: Vec<u64>,
    pub fbo_corr: Vec<u64>,
    pub ffn: FfnBlockProof,
    pub attn: AttnBlockProof,
}

/// Correlation bytes consumed by the layer, by category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayerBytes {
    /// Element-wise boundary auth (x_in, K, V, attn/ffn_block_out), 8 B/val.
    pub boundary: u64,
    /// Element-wise multiplicity-vector auth (14 instances), 8 B/value.
    pub mult: u64,
    /// LN small vectors (mean/var/rsqrt_in/rsqrt_out ×2 LNs), 8 B/value.
    pub ln_vectors: u64,
    /// Attention vectors: denoms/recip_in/recips row tables + above-diag accs.
    pub attn_vectors: u64,
    /// Full-field correlations (round masks, wire/weight/split claims), 16 B.
    pub rounds_claims: u64,
}

/// Measured lookup count of one LogUp instance (= its padded lookup-side
/// leaf count: witness stream length + rectangular/pow2 pads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceLookups {
    pub name: &'static str,
    pub table: &'static str,
    pub lookups: u64,
}

pub struct LayerOut {
    /// Exactly the 4 committed-weight claims, canonical order
    /// [c_attn, attn_proj, ffn_up, ffn_down]. c_attn is on the PERMUTED
    /// 1024×4096 layout (`cattn_permuted`).
    pub weight_claims: Vec<WeightClaimP>,
    pub bytes: LayerBytes,
    /// LogUp-instance E-mults (separable — p4_report's per-lookup number).
    pub ctr_instances: Counters,
    /// Chain-level E-mults outside the instances (public evals etc.).
    pub ctr_other: Counters,
    /// Per-instance measured lookups (p4_report budget gate input).
    pub lookups: Vec<InstanceLookups>,
    /// Boundary domains for `x_in` / `ffn_block_out` (P5 model-level seam
    /// closures need to re-open these streamed MAC-authenticated matrices at
    /// fresh points).
    pub dom_xin: u64,
    pub dom_fbo: u64,
    /// K/V boundary domains (P6 decode chunks reference the prefill's — and
    /// previous chunks' — cache segments through these).
    pub dom_k: u64,
    pub dom_v: u64,
}

pub struct LayerOutV {
    /// (point, key) of the 4 weight claims, canonical order (as LayerOut).
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    /// Cached per-element keys of the `x_in` / `ffn_block_out` boundaries
    /// (P5 model-level seam closures).
    pub xin_keys: Vec<Fp2>,
    /// Cached K/V boundary keys (P6 decode chunks reference the prefill's —
    /// and previous chunks' — cache segments through these).
    pub k_keys: Vec<Fp2>,
    pub v_keys: Vec<Fp2>,
    pub fbo_keys: Vec<Fp2>,
}

/// Per-instance measured lookups for the layer (domain sizes).
pub(crate) fn layer_lookups(sh: BandShape) -> Vec<InstanceLookups> {
    let tp = sh.q_pad() as u64;
    let rect = sh.sp2() as u64 * H_PAD as u64;
    vec![
        InstanceLookups { name: "attn_proj", table: "requant_attn_proj", lookups: tp << 10 },
        InstanceLookups { name: "av", table: "requant_av", lookups: tp << 10 },
        InstanceLookups { name: "softmax_norm", table: "softmax_norm_requant", lookups: rect },
        InstanceLookups { name: "exp", table: "exp", lookups: rect },
        InstanceLookups {
            name: "softmax_recip",
            table: "softmax_recip",
            lookups: tp * H_PAD as u64,
        },
        InstanceLookups { name: "scores", table: "requant_scores", lookups: rect },
        InstanceLookups { name: "qkv", table: "requant_qkv", lookups: tp << 12 },
        InstanceLookups { name: "ln1_norm", table: "ln_norm_requant", lookups: tp << 10 },
        InstanceLookups { name: "ln1_rsqrt", table: "ln_rsqrt", lookups: tp },
        InstanceLookups { name: "ffn_down", table: "requant_ffn_down", lookups: tp << 10 },
        InstanceLookups { name: "gelu", table: "gelu", lookups: tp << 12 },
        InstanceLookups { name: "ffn_up", table: "requant_ffn_up", lookups: tp << 12 },
        InstanceLookups { name: "ln2_norm", table: "ln_norm_requant", lookups: tp << 10 },
        InstanceLookups { name: "ln2_rsqrt", table: "ln_rsqrt", lookups: tp },
    ]
}

/// Layer phase-1 state: boundary auths + both blocks' phase-1 states, plus
/// the saved domain cursor (phase 2 resumes it via `BlockCtxP::with_doms`).
pub struct LayerP1 {
    pub doms: Doms,
    pub(crate) dom_xin: u64,
    pub(crate) dom_k: u64,
    pub(crate) dom_v: u64,
    pub(crate) dom_abo: u64,
    pub(crate) dom_fbo: u64,
    pub(crate) xin_corr: Vec<u64>,
    pub(crate) k_corr: Vec<u64>,
    pub(crate) v_corr: Vec<u64>,
    pub(crate) abo_corr: Vec<u64>,
    pub(crate) fbo_corr: Vec<u64>,
    pub(crate) ffn: FfnP1,
    pub(crate) attn: AttnP1,
    /// Full corrs consumed by phase 1 (byte accounting continuity).
    pub(crate) fulls0: u64,
}

pub(crate) struct ResidentLayerP1 {
    pub doms: Doms,
    pub(crate) dom_xin: u64,
    pub(crate) dom_k: u64,
    pub(crate) dom_v: u64,
    pub(crate) dom_abo: u64,
    pub(crate) dom_fbo: u64,
    pub(crate) xin_corr: Vec<u64>,
    pub(crate) k_corr: Vec<u64>,
    pub(crate) v_corr: Vec<u64>,
    pub(crate) abo_corr: Vec<u64>,
    pub(crate) fbo_corr: Vec<u64>,
    pub(crate) ffn: ResidentFfnP1,
    pub(crate) attn: ResidentAttnP1,
    #[allow(dead_code)]
    pub(crate) fulls0: u64,
}

impl ResidentLayerP1 {
    pub(crate) fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let first = self.attn.free(backend).err();
        let second = self.ffn.free(backend).err();
        first.or(second).map_or(Ok(()), Err)
    }
}

pub(crate) fn prove_layer_phase1_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    luts: &Luts,
    error: DeviceSlice<'_, u32>,
    cx: &mut BlockCtxP,
) -> Result<ResidentLayerP1, AccelError> {
    let t = wit.rows();
    let fulls0 = cx.stream.counters.full_corrs;
    let dom_xin = cx.doms.take(t as u64);
    let xin_corr = auth_matrix_rows_resident_p(
        cx.stream,
        cx.tx,
        dom_xin,
        wit.i16(LayerI16Field::XIn),
        t,
        D,
        cx.backend
            .as_deref_mut()
            .ok_or(AccelError::InvalidInput("resident layer phase 1 requires a backend"))?,
    )?;
    let dom_k = cx.doms.take(t as u64);
    let k_corr = auth_matrix_rows_resident_p(
        cx.stream,
        cx.tx,
        dom_k,
        wit.i16(LayerI16Field::K),
        t,
        D,
        cx.backend.as_deref_mut().expect("resident layer backend"),
    )?;
    let dom_v = cx.doms.take(t as u64);
    let v_corr = auth_matrix_rows_resident_p(
        cx.stream,
        cx.tx,
        dom_v,
        wit.i16(LayerI16Field::V),
        t,
        D,
        cx.backend.as_deref_mut().expect("resident layer backend"),
    )?;
    let dom_abo = cx.doms.take(t as u64);
    let abo_corr = auth_matrix_rows_resident_p(
        cx.stream,
        cx.tx,
        dom_abo,
        wit.i16(LayerI16Field::AttnBlockOut),
        t,
        D,
        cx.backend.as_deref_mut().expect("resident layer backend"),
    )?;
    let dom_fbo = cx.doms.take(t as u64);
    let fbo_corr = auth_matrix_rows_resident_p(
        cx.stream,
        cx.tx,
        dom_fbo,
        wit.i16(LayerI16Field::FfnBlockOut),
        t,
        D,
        cx.backend.as_deref_mut().expect("resident layer backend"),
    )?;

    let ffn = ffn_phase1_resident(wit, luts, error, cx)?;
    let attn = match attn_phase1_resident(wit, resident_model, luts, error, cx) {
        Ok(value) => value,
        Err(error) => {
            let _ = ffn.free(cx.backend.as_deref_mut().expect("resident layer backend"));
            return Err(error);
        }
    };
    Ok(ResidentLayerP1 {
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
        ffn,
        attn,
        fulls0,
    })
}

/// Layer phase 1: authenticate every boundary + element vector and
/// accumulate every multiplicity vector into the bank — all strictly before
/// any α is drawn.
pub fn prove_layer_phase1(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let wires = build_attn_wires(wit, luts);
    prove_layer_phase1_with_wires(wit, weights, luts, wires, cx)
}

/// Band phase 1: the witness is a band-packed LayerWitness (t = q rows at
/// positions t0..t0+q); `prefix` supplies the earlier phases' K data for the
/// Q·Kᵀ recompute in the wires build.
pub fn prove_layer_phase1_band(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    prefix_k: &[&[i16]],
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let t0: usize = prefix_k.iter().map(|k| k.len() / D).sum();
    let sh = BandShape { t0, q: wit.t };
    let refs = BandAttnRefs::banded(wit, sh, prefix_k);
    let wires = build_attn_wires_band(&refs, luts);
    prove_layer_phase1_with_wires(wit, weights, luts, wires, cx)
}

/// [`prove_layer_phase1`] with caller-supplied attention wires (the
/// causal-tamper test mutates a copy — cheating-prover emulation).
pub fn prove_layer_phase1_with_wires(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: AttnWires,
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let t = wit.t;
    let fulls0 = cx.stream.counters.full_corrs;

    // ---- boundary auth, once per layer -------------------------------------
    let dom_xin = cx.doms.take(t as u64);
    let xin_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_xin, &wit.x_in, t, D);
    let dom_k = cx.doms.take(t as u64);
    let k_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_k, &wit.k, t, D);
    let dom_v = cx.doms.take(t as u64);
    let v_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_v, &wit.v, t, D);
    let dom_abo = cx.doms.take(t as u64);
    let abo_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_abo, &wit.attn_block_out, t, D);
    let dom_fbo = cx.doms.take(t as u64);
    let fbo_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_fbo, &wit.ffn_block_out, t, D);

    let ffn = ffn_phase1(wit, weights, luts, cx);
    let attn = attn_phase1_with_wires(wit, weights, luts, wires, cx);

    LayerP1 {
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
        ffn,
        attn,
        fulls0,
    }
}

/// Layer phase 2 (after `TableBankP::finalize`): FFN chain, then attention
/// chain, with the shared per-content αs. The caller closes the accumulated
/// Π_Prod / Π_ZeroBatch and the table bank, and resolves the 4 weight claims
/// against the PCS.
pub fn prove_layer_phase2(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: LayerP1,
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    prove_layer_phase2_band(wit, weights, luts, p1, &[], cx, biases)
}

/// Band phase 2: `prefix` are the earlier phases' authenticated K/V segments
/// (empty for the square/prefill case).
pub fn prove_layer_phase2_band(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: LayerP1,
    prefix: &[KvPrefixP],
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    let t = wit.t;
    let t_pad = 1u64 << pad_bits(t);
    let p = luts.params;
    let sh = p1.attn.wires.shape;
    let LayerP1 {
        doms: _,
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
        ffn: ffn_p1,
        attn: attn_p1,
        fulls0,
    } = p1;

    // ---- reverse dataflow: FFN chain, then attention chain ------------------
    let (ffn, w_ffn) = prove_ffn_block(wit, weights, luts, ffn_p1, cx, dom_abo, dom_fbo, biases);
    let mut k_segs: Vec<CacheSegP> =
        prefix.iter().map(|pf| CacheSegP { dom: pf.dom_k, rows: pf.rows, data: pf.k }).collect();
    k_segs.push(CacheSegP { dom: dom_k, rows: t, data: &wit.k });
    let mut v_segs: Vec<CacheSegP> =
        prefix.iter().map(|pf| CacheSegP { dom: pf.dom_v, rows: pf.rows, data: pf.v }).collect();
    v_segs.push(CacheSegP { dom: dom_v, rows: t, data: &wit.v });
    let (attn, w_attn) = prove_attn_block(
        wit, weights, luts, attn_p1, cx, dom_xin, &k_segs, &v_segs, dom_abo, biases,
    );

    // Canonical weight-claim order: [c_attn, attn_proj, ffn_up, ffn_down].
    let mut w_attn = w_attn;
    let mut w_ffn = w_ffn;
    let wclaim_cattn = w_attn.pop().expect("attn returns 2 claims");
    let wclaim_proj = w_attn.pop().expect("attn returns 2 claims");
    let wclaim_up = w_ffn.pop().expect("ffn returns 2 claims");
    let wclaim_down = w_ffn.pop().expect("ffn returns 2 claims");
    let weight_claims = vec![wclaim_cattn, wclaim_proj, wclaim_up, wclaim_down];
    assert_eq!(weight_claims.len(), 4, "exactly one claim per committed weight tensor");

    // ---- byte accounting (multiplicity bytes live at the MODEL level now —
    // one vector per table content, see `TableBankP::mult_bytes`) -------------
    let n_above = (H * sh.n_above_head()) as u64;
    let bytes = LayerBytes {
        boundary: 8 * 5 * (t * D) as u64,
        mult: 0,
        ln_vectors: 8 * 8 * t_pad,
        attn_vectors: 8 * ((3 + p.softmax_row_shift as u64) * H_PAD as u64 * t_pad + n_above),
        rounds_claims: 16 * (cx.stream.counters.full_corrs - fulls0),
    };

    let proof = LayerProof { xin_corr, k_corr, v_corr, abo_corr, fbo_corr, ffn, attn };
    let out = LayerOut {
        weight_claims,
        bytes,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
        lookups: layer_lookups(sh),
        dom_xin,
        dom_fbo,
        dom_k,
        dom_v,
    };
    (proof, out)
}

/// Resident square/prefill layer phase 2. Both subgraphs consume the same
/// phase-1 table bank and correlation cursor; no alternate proof or verifier
/// representation is introduced.
#[allow(clippy::too_many_arguments)]
// Standalone compatibility wrapper used by resident block differentials.
#[allow(dead_code)]
pub(crate) fn prove_layer_phase2_resident<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    weights: &LayerWeights,
    luts: &Luts,
    p1: ResidentLayerP1,
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> Result<(LayerProof, LayerOut), AccelError> {
    prove_layer_phase2_resident_band(wit, resident_model, layer, weights, luts, p1, &[], cx, biases)
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn prove_layer_phase2_resident_band<W: ResidentLayerView>(
    wit: &W,
    resident_model: &ResidentGpt2Model,
    layer: usize,
    weights: &LayerWeights,
    luts: &Luts,
    p1: ResidentLayerP1,
    prefix: &[ResidentKvPrefixP],
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> Result<(LayerProof, LayerOut), AccelError> {
    let t = wit.rows();
    let t_pad = 1u64 << pad_bits(t);
    let params = luts.params;
    let ResidentLayerP1 {
        doms: _,
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
        ffn: ffn_p1,
        attn: attn_p1,
        fulls0,
    } = p1;
    let ffn_result = prove_ffn_block_resident(
        wit,
        resident_model,
        layer,
        weights,
        luts,
        ffn_p1,
        cx,
        dom_abo,
        dom_fbo,
        biases,
    );
    let (ffn, mut ffn_claims) = match ffn_result {
        Ok(value) => value,
        Err(error) => {
            // FFN owns and releases its own phase-1 state. Attention has not
            // started yet, so release that independent owner explicitly too.
            let cleanup =
                attn_p1.free(cx.backend.as_deref_mut().ok_or(AccelError::InvalidInput(
                    "resident layer cleanup requires a backend",
                ))?);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
    };
    let mut k_segments: Vec<ResidentCacheSegP> = prefix
        .iter()
        .map(|segment| ResidentCacheSegP { dom: segment.dom_k, rows: segment.rows })
        .collect();
    k_segments.push(ResidentCacheSegP { dom: dom_k, rows: t });
    let mut v_segments: Vec<ResidentCacheSegP> = prefix
        .iter()
        .map(|segment| ResidentCacheSegP { dom: segment.dom_v, rows: segment.rows })
        .collect();
    v_segments.push(ResidentCacheSegP { dom: dom_v, rows: t });
    if k_segments.iter().map(|segment| segment.rows).sum::<usize>() != wit.seq()
        || v_segments.iter().map(|segment| segment.rows).sum::<usize>() != wit.seq()
    {
        let _ = attn_p1.free(
            cx.backend
                .as_deref_mut()
                .ok_or(AccelError::InvalidInput("resident layer cleanup requires a backend"))?,
        );
        return Err(AccelError::InvalidInput("resident K/V prefix geometry mismatch"));
    }
    let (attn, mut attn_claims) = prove_attn_block_resident(
        wit,
        resident_model,
        layer,
        weights,
        luts,
        attn_p1,
        cx,
        &k_segments,
        &v_segments,
        dom_xin,
        dom_k,
        dom_v,
        dom_abo,
        biases,
    )?;
    let cattn = attn_claims
        .pop()
        .ok_or(AccelError::InvalidInput("resident attention returned the wrong claim count"))?;
    let projection = attn_claims
        .pop()
        .ok_or(AccelError::InvalidInput("resident attention returned the wrong claim count"))?;
    let up = ffn_claims
        .pop()
        .ok_or(AccelError::InvalidInput("resident FFN returned the wrong claim count"))?;
    let down = ffn_claims
        .pop()
        .ok_or(AccelError::InvalidInput("resident FFN returned the wrong claim count"))?;
    if !attn_claims.is_empty() || !ffn_claims.is_empty() {
        return Err(AccelError::InvalidInput("resident layer claim count mismatch"));
    }
    let shape = BandShape { t0: wit.pos0(), q: t };
    let n_above = (H * shape.n_above_head()) as u64;
    let bytes = LayerBytes {
        boundary: 8 * 5 * (t * D) as u64,
        mult: 0,
        ln_vectors: 8 * 8 * t_pad,
        attn_vectors: 8 * ((3 + params.softmax_row_shift as u64) * H_PAD as u64 * t_pad + n_above),
        rounds_claims: 16 * (cx.stream.counters.full_corrs - fulls0),
    };
    Ok((
        LayerProof { xin_corr, k_corr, v_corr, abo_corr, fbo_corr, ffn, attn },
        LayerOut {
            weight_claims: vec![cattn, projection, up, down],
            bytes,
            ctr_instances: cx.ctr_instances,
            ctr_other: cx.ctr_other,
            lookups: layer_lookups(shape),
            dom_xin,
            dom_fbo,
            dom_k,
            dom_v,
        },
    ))
}

/// The table-content set of one layer (from PUBLIC shift parameters) — the
/// verifier derives the model's expected content set from these.
pub fn layer_content_keys(luts: &Luts, keys: &mut std::collections::BTreeSet<TableKey>) {
    let p = luts.params;
    for s in [
        p.shift_ffn_down,
        p.shift_ffn_up,
        p.shift_ln_norm,
        p.shift_attn_proj,
        p.shift_av,
        p.shift_softmax_norm,
        p.shift_scores,
        p.shift_qkv,
    ] {
        let (k, k1) = range_keys(s);
        keys.insert(k);
        if let Some(k1) = k1 {
            keys.insert(k1);
        }
    }
    keys.insert(TableKey::Gelu);
    keys.insert(TableKey::LnRsqrt);
    keys.insert(TableKey::Exp);
    keys.insert(TableKey::SoftmaxRecip);
}

/// Layer verifier phase-1 state (mirror of [`LayerP1`]).
pub struct LayerV1 {
    pub doms: Doms,
    pub(crate) xin_keys: Vec<Fp2>,
    pub(crate) k_keys: Vec<Fp2>,
    pub(crate) v_keys: Vec<Fp2>,
    pub(crate) abo_keys: Vec<Fp2>,
    pub(crate) fbo_keys: Vec<Fp2>,
    pub(crate) lvk2: LnVecsK,
    pub(crate) attn: AttnV1,
}

/// Layer phase 1 (verifier): expand + cache every element-wise key, in the
/// prover's exact transcript/dom order.
pub fn verify_layer_phase1(
    t: usize,
    luts: &Luts,
    proof: &LayerProof,
    cx: &mut BlockCtxV,
) -> Option<LayerV1> {
    verify_layer_phase1_band(BandShape::square(t), luts, proof, cx)
}

/// Band phase 1 (verifier).
pub fn verify_layer_phase1_band(
    sh: BandShape,
    luts: &Luts,
    proof: &LayerProof,
    cx: &mut BlockCtxV,
) -> Option<LayerV1> {
    let t = sh.q;
    for c in [&proof.xin_corr, &proof.k_corr, &proof.v_corr, &proof.abo_corr, &proof.fbo_corr] {
        if c.len() != t * D {
            return None;
        }
    }
    let t_pad = 1usize << pad_bits(t);
    for v in &proof.ffn.ln_vec_corrs {
        if v.len() != t_pad {
            return None;
        }
    }
    let dom_xin = cx.doms.take(t as u64);
    let xin_keys = auth_matrix_rows_v(cx.ctx, dom_xin, &proof.xin_corr, t, D);
    let dom_k = cx.doms.take(t as u64);
    let k_keys = auth_matrix_rows_v(cx.ctx, dom_k, &proof.k_corr, t, D);
    let dom_v = cx.doms.take(t as u64);
    let v_keys = auth_matrix_rows_v(cx.ctx, dom_v, &proof.v_corr, t, D);
    let dom_abo = cx.doms.take(t as u64);
    let abo_keys = auth_matrix_rows_v(cx.ctx, dom_abo, &proof.abo_corr, t, D);
    let dom_fbo = cx.doms.take(t as u64);
    let fbo_keys = auth_matrix_rows_v(cx.ctx, dom_fbo, &proof.fbo_corr, t, D);

    let lvk2 = expand_ln_vecs_k(cx, &proof.ffn.ln_vec_corrs);
    let attn = verify_attn_phase1(sh, luts, &proof.attn, cx)?;

    Some(LayerV1 { doms: cx.doms, xin_keys, k_keys, v_keys, abo_keys, fbo_keys, lvk2, attn })
}

/// Verify one full layer (phase 2, after `TableBankV::finalize`). On success
/// returns the 4 weight-claim keys (canonical order); the caller must close
/// the accumulated batches, the table bank, and bind the claims to the PCS.
#[allow(clippy::too_many_arguments)]
pub fn verify_layer_phase2(
    t: usize,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &LayerProof,
    v1: LayerV1,
    cx: &mut BlockCtxV,
    biases: Option<&GemmBiases>,
) -> Option<LayerOutV> {
    verify_layer_phase2_band(
        BandShape::square(t),
        ln1_gain,
        ln1_bias,
        ln2_gain,
        ln2_bias,
        luts,
        proof,
        v1,
        &[],
        cx,
        biases,
    )
}

/// Band phase 2 (verifier): `prefix` are the earlier phases' cached K/V key
/// segments (empty for the square/prefill case).
#[allow(clippy::too_many_arguments)]
pub fn verify_layer_phase2_band(
    sh: BandShape,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &LayerProof,
    v1: LayerV1,
    prefix: &[KvPrefixK],
    cx: &mut BlockCtxV,
    biases: Option<&GemmBiases>,
) -> Option<LayerOutV> {
    let t = sh.q;
    let LayerV1 { doms: _, xin_keys, k_keys, v_keys, abo_keys, fbo_keys, lvk2, attn } = v1;

    let mut w_ffn = verify_ffn_block(
        t, ln2_gain, ln2_bias, luts, &proof.ffn, &lvk2, cx, &abo_keys, &fbo_keys, biases,
    )?;
    let w_attn_res = {
        let mut k_segs: Vec<CacheSegK> =
            prefix.iter().map(|pf| CacheSegK { rows: pf.rows, keys: pf.k_keys }).collect();
        k_segs.push(CacheSegK { rows: t, keys: &k_keys });
        let mut v_segs: Vec<CacheSegK> =
            prefix.iter().map(|pf| CacheSegK { rows: pf.rows, keys: pf.v_keys }).collect();
        v_segs.push(CacheSegK { rows: t, keys: &v_keys });
        verify_attn_block(
            sh,
            ln1_gain,
            ln1_bias,
            luts,
            &proof.attn,
            attn,
            cx,
            &xin_keys,
            &k_segs,
            &v_segs,
            &abo_keys,
            biases,
        )
    };
    let mut w_attn = w_attn_res?;

    let wk_cattn = w_attn.pop()?;
    let wk_proj = w_attn.pop()?;
    let wk_up = w_ffn.pop()?;
    let wk_down = w_ffn.pop()?;
    Some(LayerOutV {
        weight_keys: vec![wk_cattn, wk_proj, wk_up, wk_down],
        xin_keys,
        k_keys,
        v_keys,
        fbo_keys,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::thaler::fold_w;
    use rand::{Rng, SeedableRng};
    use std::sync::OnceLock;
    #[cfg(feature = "cuda")]
    use volta_gpt2::{
        band_model_witness, band_model_witness_resident, forward_model_tokens,
        forward_model_tokens_resident, load_model, upload_resident_model,
    };
    use volta_gpt2::{
        build_luts, forward_layer, synthetic_input, synthetic_weights, LutParams, TableId,
    };
    use volta_mac::zero_batch_exchange;

    const T: usize = 4;

    #[cfg(feature = "cuda")]
    fn active_resident_bytes(backend: &Backend) -> u64 {
        let live = backend.stats().unwrap().live_device_bytes;
        let memory = backend.device_memory_breakdown().unwrap();
        let accounted = memory
            .workspace_bytes
            .checked_add(memory.resident_bytes)
            .and_then(|bytes| bytes.checked_add(memory.cached_resident_bytes))
            .expect("resident CUDA memory accounting overflow");
        assert_eq!(live, accounted, "resident CUDA memory categories must sum to live bytes");
        memory.resident_bytes
    }

    /// One real forward pass at T = 4 (≈19 M MACs), shared by all tests.
    fn fixture() -> &'static (Luts, LayerWeights, LayerWitness) {
        static FIX: OnceLock<(Luts, LayerWeights, LayerWitness)> = OnceLock::new();
        FIX.get_or_init(|| {
            let luts = build_luts(LutParams::default());
            let w = synthetic_weights(42);
            let x = synthetic_input(43, T);
            let wit = forward_layer(&x, &w, &luts, T);
            (luts, w, wit)
        })
    }

    #[test]
    fn decode_attention_schedule_uses_public_domain_section() {
        let model_layer = 3u8;
        let decode_section = 16 + model_layer;
        let pos0 = 100usize;

        let mut prover_doms = Doms::new(layer_dom_base(decode_section));
        let prover_section = attention_layer_from_doms(&prover_doms);
        let prover_chains: Vec<_> =
            (0..H).map(|_| ChainDoms::alloc(&mut prover_doms, DH)).collect();
        let prover_plan = attention_act_schedule(
            pos0,
            prover_section,
            AttentionActRole::QueryKey,
            pad_bits(DH),
            &prover_chains,
        );

        let mut verifier_doms = Doms::new(layer_dom_base(decode_section));
        let verifier_section = attention_layer_from_doms(&verifier_doms);
        let verifier_chains: Vec<_> =
            (0..H).map(|_| ChainDoms::alloc(&mut verifier_doms, DH)).collect();
        let verifier_plan = attention_act_schedule(
            pos0,
            verifier_section,
            AttentionActRole::QueryKey,
            pad_bits(DH),
            &verifier_chains,
        );

        assert_eq!(prover_section, u16::from(decode_section));
        assert_ne!(prover_section, u16::from(model_layer));
        assert_eq!(prover_plan.sites(), verifier_plan.sites());
        for (head, site) in prover_plan.sites().iter().enumerate() {
            assert_eq!(site.id.section(), u16::from(decode_section));
            assert_eq!(
                site.id,
                attention_act_site_id(
                    pos0,
                    u16::from(decode_section),
                    AttentionActRole::QueryKey,
                    head,
                )
            );
        }
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_mock_auth_masks_match_cpu_without_h2d() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA mock-auth differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let seed = [0xA7; 32];
        let base_dom = layer_dom_base(17);
        let (rows, cols) = (3usize, 7usize);
        let values: Vec<i16> = (0..rows * cols).map(|i| i as i16 * 13 - 91).collect();

        let mut cpu_stream = CorrelationStream::new(seed);
        let mut cpu_tx = Transcript::new([0xD1; 32]);
        let expected =
            auth_matrix_rows_p(&mut cpu_stream, &mut cpu_tx, base_dom, &values, rows, cols);

        let device_values = gpu.upload_new_device(&values).unwrap();
        let mut gpu_stream = CorrelationStream::new(seed);
        let mut gpu_tx = Transcript::new([0xD1; 32]);
        gpu.begin_measurement().unwrap();
        let got = auth_matrix_rows_resident_p(
            &mut gpu_stream,
            &mut gpu_tx,
            base_dom,
            DeviceSlice::new(&device_values, 0, values.len()).unwrap(),
            rows,
            cols,
            &mut gpu,
        )
        .unwrap();
        let stats = gpu.finish_measurement().unwrap();

        assert_eq!(got, expected);
        assert_eq!(gpu_stream.counters, cpu_stream.counters);
        assert_eq!(gpu_tx.ledger(), cpu_tx.ledger());
        assert_eq!(stats.h2d_bytes, 0, "mock authentication masks must stay device-side");
        assert_eq!(stats.d2h_bytes, (values.len() * std::mem::size_of::<u64>()) as u64);
        assert_eq!(stats.device_generated_bytes, stats.d2h_bytes);
        assert_eq!(stats.operation(volta_accel::Operation::AuthMasks).calls, 1);
        assert_eq!(stats.operation(volta_accel::Operation::PcsRows).calls, 0);
        assert_eq!(stats.sync_host_output, 1);
        assert_eq!(stats.synchronization_reason_total(), stats.synchronizations);
        gpu.free_device(device_values).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_attention_phase1_matches_cpu_bindings() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident attention phase-1 differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident attention phase-1 differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let tokens = model.p.tokens[..3].to_vec();
        let host_witness = forward_model_tokens(&model, &tokens);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];
        let host_layer = &host_witness.layers[0];
        let expected_wires = build_attn_wires(host_layer, &luts);

        let mut cpu_stream = CorrelationStream::new([81; 32]);
        let mut cpu_tx = Transcript::new([82; 32]);
        let mut cpu_bank = TableBankP::new();
        let cpu_p1 = {
            let mut cx = BlockCtxP::new(&mut cpu_stream, &mut cpu_tx, 0, &mut cpu_bank);
            attn_phase1_with_wires(
                host_layer,
                &model.layers[0].0,
                &luts,
                build_attn_wires(host_layer, &luts),
                &mut cx,
            )
        };
        let mut cpu_table_doms = Doms::new(layer_dom_base(239));
        cpu_bank.finalize(&mut cpu_stream, &mut cpu_tx, &mut cpu_table_doms);

        let mut resident_stream = CorrelationStream::new([81; 32]);
        let mut resident_tx = Transcript::new([82; 32]);
        let mut resident_bank = TableBankP::new();
        let resident_p1 = {
            let mut cx = BlockCtxP::with_backend(
                &mut resident_stream,
                &mut resident_tx,
                0,
                &mut resident_bank,
                &mut gpu,
            );
            attn_phase1_resident(
                &resident_witness.layers[0],
                &resident_model,
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap()
        };
        let mut resident_table_doms = Doms::new(layer_dom_base(239));
        resident_bank
            .finalize_resident(
                &mut resident_stream,
                &mut resident_tx,
                &mut resident_table_doms,
                &mut gpu,
            )
            .unwrap();

        assert_eq!(resident_p1.ln_vec_corrs, cpu_p1.ln_vec_corrs);
        assert_eq!(resident_p1.denoms_corr, cpu_p1.denoms_corr);
        assert_eq!(resident_p1.recip_in_corr, cpu_p1.recip_in_corr);
        assert_eq!(resident_p1.recips_corr, cpu_p1.recips_corr);
        assert_eq!(resident_p1.above_corr, cpu_p1.above_corr);
        assert_eq!(resident_p1.row_shift_corr, cpu_p1.row_shift_corr);
        assert_eq!(resident_bank.content_keys(), cpu_bank.content_keys());
        assert_eq!(resident_bank.mult_bytes(), cpu_bank.mult_bytes());
        assert_eq!(resident_bank.alphas, cpu_bank.alphas);
        let cpu_mult_corrs: Vec<_> =
            cpu_bank.auth.iter().map(|(&key, value)| (key, value.2.clone())).collect();
        let resident_mult_corrs: Vec<_> = resident_bank
            .resident_auth
            .iter()
            .map(|(&key, value)| (key, value.1.clone()))
            .collect();
        assert_eq!(resident_mult_corrs, cpu_mult_corrs);
        assert_eq!(resident_stream.counters, cpu_stream.counters);
        assert_eq!(resident_tx.ledger(), cpu_tx.ledger());
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let rect_entries = resident_p1.wires.rect_entries();
        let rect = gpu
            .download_device(
                resident_p1.wires.rect_column(0).unwrap().buffer(),
                0,
                7 * rect_entries,
            )
            .unwrap();
        let mut expected_rect = vec![0u64; 7 * rect_entries];
        let rem_sn = build_rem_sn(&expected_wires, luts.params.shift_softmax_norm);
        let rem_sc = build_rem_sc_packed(
            &host_layer.scores_acc,
            &host_layer.scores_q,
            expected_wires.shape,
            luts.params.shift_scores,
        );
        for index in 0..rect_entries {
            expected_rect[index] = rem_sn[index] as u64;
            expected_rect[rect_entries + index] =
                Fp::from_i64(expected_wires.w_rect[index] as i64).value();
            expected_rect[2 * rect_entries + index] = rem_sc[index] as u64;
            expected_rect[3 * rect_entries + index] =
                Fp::from_i64(expected_wires.sprime_rect[index] as i64).value();
            expected_rect[4 * rect_entries + index] =
                Fp::from_i64(expected_wires.exp_rect[index] as i64).value();
            expected_rect[5 * rect_entries + index] =
                Fp::from_i64(expected_wires.is_max_rect[index] as i64).value();
        }
        let sp2 = expected_wires.shape.sp2();
        let s_pad = expected_wires.shape.s_pad();
        for h in 0..H {
            for i in 0..tokens.len() {
                for j in 0..tokens.len() {
                    let rect_index = h * sp2 + i * s_pad + j;
                    let source = h * tokens.len() * tokens.len() + i * tokens.len() + j;
                    expected_rect[6 * rect_entries + rect_index] =
                        Fp::from_i64(expected_wires.acc_full[source]).value();
                }
            }
        }
        assert_eq!(rect, expected_rect);

        let row_entries = resident_p1.wires.row_entries();
        let row_values = gpu
            .download_device(resident_p1.wires.row_column(0).unwrap().buffer(), 0, 4 * row_entries)
            .unwrap();
        for index in 0..row_entries {
            assert_eq!(Fp::new(row_values[index]), Fp::from_i64(expected_wires.denoms_row[index]));
            assert_eq!(
                Fp::new(row_values[row_entries + index]),
                Fp::from_i64(expected_wires.recip_in_row[index])
            );
            assert_eq!(
                Fp::new(row_values[2 * row_entries + index]),
                Fp::from_i64(expected_wires.recips_row[index] as i64)
            );
            assert_eq!(
                Fp::new(row_values[3 * row_entries + index]),
                Fp::from_i64(expected_wires.row_shift_row[index] as i64)
            );
        }
        let above = resident_p1.wires.above();
        let above_values =
            gpu.download_device(above.buffer(), above.offset(), above.len()).unwrap();
        assert_eq!(
            above_values,
            expected_wires
                .above_acc
                .iter()
                .map(|&value| Fp::from_i64(value).value())
                .collect::<Vec<_>>()
        );
        let (rem_qkv, out_qkv) =
            build_qkv_cols(host_layer, luts.params.shift_qkv, tokens.len().next_power_of_two());
        let qkv_entries = resident_p1.wires.qkv_entries();
        let qkv = gpu
            .download_device(resident_p1.wires.qkv_column(0).unwrap().buffer(), 0, 2 * qkv_entries)
            .unwrap();
        assert_eq!(qkv[..qkv_entries], rem_qkv.iter().map(|&x| x as u64).collect::<Vec<_>>());
        assert_eq!(
            qkv[qkv_entries..],
            out_qkv.iter().map(|&x| Fp::from_i64(x as i64).value()).collect::<Vec<_>>()
        );

        resident_p1.free(&mut gpu).unwrap();
        resident_bank.free_resident_multiplicities(&mut gpu);
        gpu.free_device(proof_error).unwrap();
        resident_witness.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_attention_proof_matches_cpu_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident attention proof differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident attention proof differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let tokens = model.p.tokens[..3].to_vec();
        let host_witness = forward_model_tokens(&model, &tokens);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let t = tokens.len();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];
        let host_layer = &host_witness.layers[0];
        let weights = &model.layers[0].0;
        let biases = &model.layers[0].1;

        let run_cpu = || {
            let mut stream = CorrelationStream::new([121; 32]);
            let mut tx = Transcript::new([122; 32]);
            let mut bank = TableBankP::new();
            let (p1, doms, dom_xin, dom_k, dom_v, dom_abo, xin_corr, k_corr, v_corr, abo_corr) = {
                let mut cx = BlockCtxP::new(&mut stream, &mut tx, 0, &mut bank);
                let dom_xin = cx.doms.take(t as u64);
                let xin_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_xin, &host_layer.x_in, t, D);
                let dom_k = cx.doms.take(t as u64);
                let k_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_k, &host_layer.k, t, D);
                let dom_v = cx.doms.take(t as u64);
                let v_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_v, &host_layer.v, t, D);
                let dom_abo = cx.doms.take(t as u64);
                let abo_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_abo, &host_layer.attn_block_out, t, D);
                let p1 = attn_phase1_with_wires(
                    host_layer,
                    weights,
                    &luts,
                    build_attn_wires(host_layer, &luts),
                    &mut cx,
                );
                (p1, cx.doms, dom_xin, dom_k, dom_v, dom_abo, xin_corr, k_corr, v_corr, abo_corr)
            };
            let mut table_doms = Doms::new(layer_dom_base(238));
            bank.finalize(&mut stream, &mut tx, &mut table_doms);
            let (proof, claims, mut prod, mut zero, mut counters) = {
                let mut cx = BlockCtxP::with_doms(&mut stream, &mut tx, doms, &mut bank);
                let k_segment = [CacheSegP { dom: dom_k, rows: t, data: &host_layer.k }];
                let v_segment = [CacheSegP { dom: dom_v, rows: t, data: &host_layer.v }];
                let (proof, claims) = prove_attn_block(
                    host_layer,
                    weights,
                    &luts,
                    p1,
                    &mut cx,
                    dom_xin,
                    &k_segment,
                    &v_segment,
                    dom_abo,
                    Some(biases),
                );
                (proof, claims, cx.prod, cx.zero, cx.ctr_instances)
            };
            let tables = bank.close(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
            );
            (
                proof,
                claims,
                tables,
                prod,
                zero,
                counters,
                stream.counters,
                tx.ledger().clone(),
                xin_corr,
                k_corr,
                v_corr,
                abo_corr,
            )
        };
        let expected = run_cpu();

        gpu.begin_measurement().unwrap();
        let mut stream = CorrelationStream::new([121; 32]);
        let mut tx = Transcript::new([122; 32]);
        let mut bank = TableBankP::new();
        let (p1, doms, dom_xin, dom_k, dom_v, dom_abo, xin_corr, k_corr, v_corr, abo_corr) = {
            let mut cx = BlockCtxP::with_backend(&mut stream, &mut tx, 0, &mut bank, &mut gpu);
            let dom_xin = cx.doms.take(t as u64);
            let xin_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_xin,
                resident_witness.layers[0].i16(LayerI16Field::XIn),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let dom_k = cx.doms.take(t as u64);
            let k_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_k,
                resident_witness.layers[0].i16(LayerI16Field::K),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let dom_v = cx.doms.take(t as u64);
            let v_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_v,
                resident_witness.layers[0].i16(LayerI16Field::V),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let dom_abo = cx.doms.take(t as u64);
            let abo_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_abo,
                resident_witness.layers[0].i16(LayerI16Field::AttnBlockOut),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let p1 = attn_phase1_resident(
                &resident_witness.layers[0],
                &resident_model,
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap();
            (p1, cx.doms, dom_xin, dom_k, dom_v, dom_abo, xin_corr, k_corr, v_corr, abo_corr)
        };
        let mut table_doms = Doms::new(layer_dom_base(238));
        bank.finalize_resident(&mut stream, &mut tx, &mut table_doms, &mut gpu).unwrap();
        let (proof, claims, mut prod, mut zero, mut counters) = {
            let mut cx =
                BlockCtxP::with_doms_and_backend(&mut stream, &mut tx, doms, &mut bank, &mut gpu);
            let k_segments = [ResidentCacheSegP { dom: dom_k, rows: t }];
            let v_segments = [ResidentCacheSegP { dom: dom_v, rows: t }];
            let (proof, claims) = prove_attn_block_resident(
                &resident_witness.layers[0],
                &resident_model,
                0,
                weights,
                &luts,
                p1,
                &mut cx,
                &k_segments,
                &v_segments,
                dom_xin,
                dom_k,
                dom_v,
                dom_abo,
                Some(biases),
            )
            .unwrap();
            (proof, claims, cx.prod, cx.zero, cx.ctr_instances)
        };
        let tables = bank
            .close_resident(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
                &mut gpu,
            )
            .unwrap();
        let got = (
            proof,
            claims,
            tables,
            prod,
            zero,
            counters,
            stream.counters,
            tx.ledger().clone(),
            xin_corr,
            k_corr,
            v_corr,
            abo_corr,
        );
        assert_eq!(got, expected);
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let delta = Fp2::new(Fp::new(0xAA11_A100), Fp::new(0xA771));
        let mut verifier = VerifierCtx::new([121; 32], delta);
        let mut verifier_tx = Transcript::new([122; 32]);
        let mut pre_bank = TableBankV::empty();
        let (verifier_doms, xin_keys, k_keys, v_keys, abo_keys, attn_v1) = {
            let mut cx = BlockCtxV::new(&mut verifier, &mut verifier_tx, 0, &mut pre_bank);
            let dom_xin_v = cx.doms.take(t as u64);
            let xin_keys = auth_matrix_rows_v(cx.ctx, dom_xin_v, &got.8, t, D);
            let dom_k_v = cx.doms.take(t as u64);
            let k_keys = auth_matrix_rows_v(cx.ctx, dom_k_v, &got.9, t, D);
            let dom_v_v = cx.doms.take(t as u64);
            let v_keys = auth_matrix_rows_v(cx.ctx, dom_v_v, &got.10, t, D);
            let dom_abo_v = cx.doms.take(t as u64);
            let abo_keys = auth_matrix_rows_v(cx.ctx, dom_abo_v, &got.11, t, D);
            let attn_v1 = verify_attn_phase1(BandShape::square(t), &luts, &got.0, &mut cx)
                .expect("resident attention phase 1 verifies");
            (cx.doms, xin_keys, k_keys, v_keys, abo_keys, attn_v1)
        };
        let expected_contents: std::collections::BTreeSet<_> =
            got.2.iter().map(|proof| proof.key).collect();
        let mut verifier_table_doms = Doms::new(layer_dom_base(238));
        let mut verifier_bank = TableBankV::finalize(
            &expected_contents,
            &got.2,
            &mut verifier,
            &mut verifier_tx,
            &mut verifier_table_doms,
        )
        .expect("resident attention table phase 1 verifies");
        let (weight_keys, mut key_prod, mut key_zero) = {
            let mut cx = BlockCtxV::with_doms(
                &mut verifier,
                &mut verifier_tx,
                verifier_doms,
                &mut verifier_bank,
            );
            let k_segments = [CacheSegK { rows: t, keys: &k_keys }];
            let v_segments = [CacheSegK { rows: t, keys: &v_keys }];
            let keys = verify_attn_block(
                BandShape::square(t),
                &weights.ln1_gain,
                &weights.ln1_bias,
                &luts,
                &got.0,
                attn_v1,
                &mut cx,
                &xin_keys,
                &k_segments,
                &v_segments,
                &abo_keys,
                Some(biases),
            )
            .expect("resident attention proof verifies");
            (keys, cx.kprod, cx.kzero)
        };
        verifier_bank
            .close(
                &luts,
                &got.2,
                &mut verifier,
                &mut verifier_table_doms,
                &mut verifier_tx,
                &mut key_prod,
                &mut key_zero,
            )
            .expect("resident attention table closure verifies");
        let cattn = cattn_permuted(&weights.c_attn);
        let mut prover_zero = got.4.clone();
        for ((claim, (point, key)), (matrix, rows, cols)) in got
            .1
            .iter()
            .zip(&weight_keys)
            .zip([(&weights.attn_proj[..], D, D), (&cattn[..], D, 4096)])
        {
            assert_eq!(&claim.point, point);
            let value = weight_true_eval(matrix, rows, cols, point);
            prover_zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            key_zero.push(key.sub(VerifierKey::from_public(value, delta)));
        }
        let mut prover_batch_doms = Doms::new(layer_dom_base(254));
        let mut verifier_batch_doms = Doms::new(layer_dom_base(254));
        let challenge = tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = prover_batch_doms.take(1);
        assert_eq!(product_domain, verifier_batch_doms.take(1));
        let product_mask = stream.draw_fulls(product_domain, 1)[0];
        let product_key = verifier.expand_full_keys(product_domain, 1)[0];
        let product_proof = prod_batch_prover(&got.3, challenge, product_mask, &mut tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = prover_batch_doms.take(1);
        assert_eq!(zero_domain, verifier_batch_doms.take(1));
        assert!(zero_batch_exchange(
            &prover_zero,
            &key_zero,
            &mut stream,
            &mut verifier,
            zero_domain,
            &mut tx,
        ));
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        gpu.free_device(proof_error).unwrap();
        resident_witness.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_full_layer_matches_cpu_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident full-layer differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident full-layer differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let tokens = model.p.tokens[..3].to_vec();
        let host_witness = forward_model_tokens(&model, &tokens);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let t = tokens.len();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];
        let host_layer = &host_witness.layers[0];
        let weights = &model.layers[0].0;
        let biases = &model.layers[0].1;

        let run_cpu = || {
            let mut stream = CorrelationStream::new([131; 32]);
            let mut tx = Transcript::new([132; 32]);
            let mut bank = TableBankP::new();
            let p1 = {
                let mut cx = BlockCtxP::new(&mut stream, &mut tx, 0, &mut bank);
                prove_layer_phase1(host_layer, weights, &luts, &mut cx)
            };
            let mut table_doms = Doms::new(layer_dom_base(237));
            bank.finalize(&mut stream, &mut tx, &mut table_doms);
            let (proof, out, mut prod, mut zero, mut counters, doms, other) = {
                let mut cx = BlockCtxP::with_doms(&mut stream, &mut tx, p1.doms, &mut bank);
                let (proof, out) =
                    prove_layer_phase2(host_layer, weights, &luts, p1, &mut cx, Some(biases));
                (proof, out, cx.prod, cx.zero, cx.ctr_instances, cx.doms, cx.ctr_other)
            };
            let tables = bank.close(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
            );
            (
                proof,
                out.weight_claims,
                out.bytes,
                out.ctr_instances,
                out.ctr_other,
                out.lookups,
                out.dom_xin,
                out.dom_fbo,
                out.dom_k,
                out.dom_v,
                tables,
                prod,
                zero,
                counters,
                other,
                doms,
                stream.counters,
                tx.ledger().clone(),
            )
        };
        let expected = run_cpu();

        gpu.begin_measurement().unwrap();
        let mut stream = CorrelationStream::new([131; 32]);
        let mut tx = Transcript::new([132; 32]);
        let mut bank = TableBankP::new();
        let p1 = {
            let mut cx = BlockCtxP::with_backend(&mut stream, &mut tx, 0, &mut bank, &mut gpu);
            prove_layer_phase1_resident(
                &resident_witness.layers[0],
                &resident_model,
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap()
        };
        let mut table_doms = Doms::new(layer_dom_base(237));
        bank.finalize_resident(&mut stream, &mut tx, &mut table_doms, &mut gpu).unwrap();
        let (proof, out, mut prod, mut zero, mut counters, doms, other) = {
            let mut cx = BlockCtxP::with_doms_and_backend(
                &mut stream,
                &mut tx,
                p1.doms,
                &mut bank,
                &mut gpu,
            );
            let (proof, out) = prove_layer_phase2_resident(
                &resident_witness.layers[0],
                &resident_model,
                0,
                weights,
                &luts,
                p1,
                &mut cx,
                Some(biases),
            )
            .unwrap();
            (proof, out, cx.prod, cx.zero, cx.ctr_instances, cx.doms, cx.ctr_other)
        };
        let tables = bank
            .close_resident(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
                &mut gpu,
            )
            .unwrap();
        let mut got = (
            proof,
            out.weight_claims,
            out.bytes,
            out.ctr_instances,
            out.ctr_other,
            out.lookups,
            out.dom_xin,
            out.dom_fbo,
            out.dom_k,
            out.dom_v,
            tables,
            prod,
            zero,
            counters,
            other,
            doms,
            stream.counters,
            tx.ledger().clone(),
        );
        assert_eq!(got.0, expected.0);
        assert_eq!(got.1, expected.1);
        assert_eq!(got.2, expected.2);
        assert_eq!(got.3, expected.3);
        assert_eq!(got.4, expected.4);
        assert_eq!(got.5, expected.5);
        assert_eq!(got.6, expected.6);
        assert_eq!(got.7, expected.7);
        assert_eq!(got.8, expected.8);
        assert_eq!(got.9, expected.9);
        assert_eq!(got.10, expected.10);
        assert_eq!(got.11, expected.11);
        assert_eq!(got.12, expected.12);
        assert_eq!(got.13, expected.13);
        assert_eq!(got.14, expected.14);
        assert_eq!(got.15, expected.15);
        assert_eq!(got.16, expected.16);
        assert_eq!(got.17, expected.17);
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let delta = Fp2::new(Fp::new(0xBB11_A100), Fp::new(0x1A73));
        let mut verifier = VerifierCtx::new([131; 32], delta);
        let mut verifier_tx = Transcript::new([132; 32]);
        let mut pre_bank = TableBankV::empty();
        let verifier_p1 = {
            let mut cx = BlockCtxV::new(&mut verifier, &mut verifier_tx, 0, &mut pre_bank);
            verify_layer_phase1(t, &luts, &got.0, &mut cx).expect("resident layer phase 1 verifies")
        };
        let mut expected_contents = std::collections::BTreeSet::new();
        layer_content_keys(&luts, &mut expected_contents);
        let mut verifier_table_doms = Doms::new(layer_dom_base(237));
        let mut verifier_bank = TableBankV::finalize(
            &expected_contents,
            &got.10,
            &mut verifier,
            &mut verifier_tx,
            &mut verifier_table_doms,
        )
        .expect("resident layer table phase 1 verifies");
        let (verifier_out, mut key_prod, mut key_zero, mut verifier_doms) = {
            let mut cx = BlockCtxV::with_doms(
                &mut verifier,
                &mut verifier_tx,
                verifier_p1.doms,
                &mut verifier_bank,
            );
            let out = verify_layer_phase2(
                t,
                &weights.ln1_gain,
                &weights.ln1_bias,
                &weights.ln2_gain,
                &weights.ln2_bias,
                &luts,
                &got.0,
                verifier_p1,
                &mut cx,
                Some(biases),
            )
            .expect("resident full layer verifies");
            (out, cx.kprod, cx.kzero, cx.doms)
        };
        verifier_bank
            .close(
                &luts,
                &got.10,
                &mut verifier,
                &mut verifier_table_doms,
                &mut verifier_tx,
                &mut key_prod,
                &mut key_zero,
            )
            .expect("resident layer table closure verifies");
        let cattn = cattn_permuted(&weights.c_attn);
        let dimensions: [(usize, usize, &[i16]); 4] = [
            (D, 4096, &cattn),
            (D, D, &weights.attn_proj),
            (D, DFF, &weights.ffn_up),
            (DFF, D, &weights.ffn_down),
        ];
        let mut prover_zero = got.12.clone();
        for (index, claim) in got.1.iter().enumerate() {
            let (rows, cols, matrix) = dimensions[index];
            assert_eq!(verifier_out.weight_keys[index].0, claim.point);
            let value = weight_true_eval(matrix, rows, cols, &claim.point);
            prover_zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            key_zero.push(
                verifier_out.weight_keys[index].1.sub(VerifierKey::from_public(value, delta)),
            );
        }
        let challenge = tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = got.15.take(1);
        assert_eq!(product_domain, verifier_doms.take(1));
        let product_mask = stream.draw_fulls(product_domain, 1)[0];
        let product_key = verifier.expand_full_keys(product_domain, 1)[0];
        let product_proof = prod_batch_prover(&got.11, challenge, product_mask, &mut tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = got.15.take(1);
        assert_eq!(zero_domain, verifier_doms.take(1));
        assert!(zero_batch_exchange(
            &prover_zero,
            &key_zero,
            &mut stream,
            &mut verifier,
            zero_domain,
            &mut tx,
        ));
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        gpu.free_device(proof_error).unwrap();
        resident_witness.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_band_layer_matches_cpu_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident band-layer differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident band-layer differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let t0 = 2;
        let q = 3;
        let tokens = model.p.tokens[..t0 + q].to_vec();
        let host_source = forward_model_tokens(&model, &tokens);
        let host_band = band_model_witness(&model, &host_source, t0);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_source =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let resident_band =
            band_model_witness_resident(&resident_model, &resident_source, t0, q, &mut gpu)
                .unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];
        let host_layer = &host_band.layers[0];
        let weights = &model.layers[0].0;
        let biases = &model.layers[0].1;
        let prefix_k = &host_source.layers[0].k[..t0 * D];
        let prefix_v = &host_source.layers[0].v[..t0 * D];

        let run_cpu = || {
            let mut stream = CorrelationStream::new([141; 32]);
            let mut tx = Transcript::new([142; 32]);
            let mut bank = TableBankP::new();
            let (p1, prefix_dom_k, prefix_dom_v, prefix_k_corr, prefix_v_corr) = {
                let mut cx = BlockCtxP::new(&mut stream, &mut tx, 0, &mut bank);
                let prefix_dom_k = cx.doms.take(t0 as u64);
                let prefix_k_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, prefix_dom_k, prefix_k, t0, D);
                let prefix_dom_v = cx.doms.take(t0 as u64);
                let prefix_v_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, prefix_dom_v, prefix_v, t0, D);
                let p1 = prove_layer_phase1_band(host_layer, weights, &luts, &[prefix_k], &mut cx);
                (p1, prefix_dom_k, prefix_dom_v, prefix_k_corr, prefix_v_corr)
            };
            let mut table_doms = Doms::new(layer_dom_base(236));
            bank.finalize(&mut stream, &mut tx, &mut table_doms);
            let (proof, out, mut prod, mut zero, mut counters, doms, other) = {
                let mut cx = BlockCtxP::with_doms(&mut stream, &mut tx, p1.doms, &mut bank);
                let prefix = [KvPrefixP {
                    rows: t0,
                    dom_k: prefix_dom_k,
                    k: prefix_k,
                    dom_v: prefix_dom_v,
                    v: prefix_v,
                }];
                let (proof, out) = prove_layer_phase2_band(
                    host_layer,
                    weights,
                    &luts,
                    p1,
                    &prefix,
                    &mut cx,
                    Some(biases),
                );
                (proof, out, cx.prod, cx.zero, cx.ctr_instances, cx.doms, cx.ctr_other)
            };
            let tables = bank.close(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
            );
            (
                proof,
                out.weight_claims,
                out.bytes,
                out.ctr_instances,
                out.ctr_other,
                out.lookups,
                out.dom_xin,
                out.dom_fbo,
                out.dom_k,
                out.dom_v,
                tables,
                prod,
                zero,
                counters,
                other,
                doms,
                stream.counters,
                tx.ledger().clone(),
                prefix_k_corr,
                prefix_v_corr,
                prefix_dom_k,
                prefix_dom_v,
            )
        };
        let expected = run_cpu();

        gpu.begin_measurement().unwrap();
        let mut stream = CorrelationStream::new([141; 32]);
        let mut tx = Transcript::new([142; 32]);
        let mut bank = TableBankP::new();
        let (p1, prefix_dom_k, prefix_dom_v, prefix_k_corr, prefix_v_corr) = {
            let mut cx = BlockCtxP::with_backend(&mut stream, &mut tx, 0, &mut bank, &mut gpu);
            let k_cache = resident_band.layers[0].k_cache();
            let resident_prefix_k =
                DeviceSlice::new(k_cache.buffer(), k_cache.offset(), t0 * D).unwrap();
            let prefix_dom_k = cx.doms.take(t0 as u64);
            let prefix_k_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                prefix_dom_k,
                resident_prefix_k,
                t0,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let v_cache = resident_band.layers[0].v_cache();
            let resident_prefix_v =
                DeviceSlice::new(v_cache.buffer(), v_cache.offset(), t0 * D).unwrap();
            let prefix_dom_v = cx.doms.take(t0 as u64);
            let prefix_v_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                prefix_dom_v,
                resident_prefix_v,
                t0,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let p1 = prove_layer_phase1_resident(
                &resident_band.layers[0],
                &resident_model,
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap();
            (p1, prefix_dom_k, prefix_dom_v, prefix_k_corr, prefix_v_corr)
        };
        let mut table_doms = Doms::new(layer_dom_base(236));
        bank.finalize_resident(&mut stream, &mut tx, &mut table_doms, &mut gpu).unwrap();
        let (proof, out, mut prod, mut zero, mut counters, doms, other) = {
            let mut cx = BlockCtxP::with_doms_and_backend(
                &mut stream,
                &mut tx,
                p1.doms,
                &mut bank,
                &mut gpu,
            );
            let prefix = [ResidentKvPrefixP { rows: t0, dom_k: prefix_dom_k, dom_v: prefix_dom_v }];
            let (proof, out) = prove_layer_phase2_resident_band(
                &resident_band.layers[0],
                &resident_model,
                0,
                weights,
                &luts,
                p1,
                &prefix,
                &mut cx,
                Some(biases),
            )
            .unwrap();
            (proof, out, cx.prod, cx.zero, cx.ctr_instances, cx.doms, cx.ctr_other)
        };
        let tables = bank
            .close_resident(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut counters,
                &mut prod,
                &mut zero,
                &mut gpu,
            )
            .unwrap();
        let got = (
            proof,
            out.weight_claims,
            out.bytes,
            out.ctr_instances,
            out.ctr_other,
            out.lookups,
            out.dom_xin,
            out.dom_fbo,
            out.dom_k,
            out.dom_v,
            tables,
            prod,
            zero,
            counters,
            other,
            doms,
            stream.counters,
            tx.ledger().clone(),
            prefix_k_corr,
            prefix_v_corr,
            prefix_dom_k,
            prefix_dom_v,
        );
        assert_eq!(got.0, expected.0);
        assert_eq!(got.1, expected.1);
        assert_eq!(got.2, expected.2);
        assert_eq!(got.3, expected.3);
        assert_eq!(got.4, expected.4);
        assert_eq!(got.5, expected.5);
        assert_eq!(got.6, expected.6);
        assert_eq!(got.7, expected.7);
        assert_eq!(got.8, expected.8);
        assert_eq!(got.9, expected.9);
        assert_eq!(got.10, expected.10);
        assert_eq!(got.11, expected.11);
        assert_eq!(got.12, expected.12);
        assert_eq!(got.13, expected.13);
        assert_eq!(got.14, expected.14);
        assert_eq!(got.15, expected.15);
        assert_eq!(got.16, expected.16);
        assert_eq!(got.17, expected.17);
        assert_eq!(got.18, expected.18);
        assert_eq!(got.19, expected.19);
        assert_eq!(got.20, expected.20);
        assert_eq!(got.21, expected.21);
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        gpu.free_device(proof_error).unwrap();
        resident_band.free(&mut gpu).unwrap();
        resident_source.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_ffn_phase1_matches_cpu_bindings() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident FFN phase-1 differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident FFN phase-1 differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let tokens = model.p.tokens[..3].to_vec();
        let host_witness = forward_model_tokens(&model, &tokens);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];

        let mut cpu_stream = CorrelationStream::new([91; 32]);
        let mut cpu_tx = Transcript::new([92; 32]);
        let mut cpu_bank = TableBankP::new();
        let cpu_p1 = {
            let mut cx = BlockCtxP::new(&mut cpu_stream, &mut cpu_tx, 0, &mut cpu_bank);
            ffn_phase1(&host_witness.layers[0], &model.layers[0].0, &luts, &mut cx)
        };
        let mut cpu_table_doms = Doms::new(layer_dom_base(240));
        cpu_bank.finalize(&mut cpu_stream, &mut cpu_tx, &mut cpu_table_doms);

        let resident_before_phase1 = active_resident_bytes(&gpu);
        let mut resident_stream = CorrelationStream::new([91; 32]);
        let mut resident_tx = Transcript::new([92; 32]);
        let mut resident_bank = TableBankP::new();
        let resident_p1 = {
            let mut cx = BlockCtxP::with_backend(
                &mut resident_stream,
                &mut resident_tx,
                0,
                &mut resident_bank,
                &mut gpu,
            );
            ffn_phase1_resident(
                &resident_witness.layers[0],
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap()
        };
        let mut resident_table_doms = Doms::new(layer_dom_base(240));
        resident_bank
            .finalize_resident(
                &mut resident_stream,
                &mut resident_tx,
                &mut resident_table_doms,
                &mut gpu,
            )
            .unwrap();

        assert_eq!(resident_p1.ln_vec_corrs, cpu_p1.ln_vec_corrs);
        assert_eq!(resident_bank.content_keys(), cpu_bank.content_keys());
        assert_eq!(resident_bank.mult_bytes(), cpu_bank.mult_bytes());
        assert_eq!(resident_bank.alphas, cpu_bank.alphas);
        let cpu_mult_corrs: Vec<_> =
            cpu_bank.auth.iter().map(|(&key, value)| (key, value.2.clone())).collect();
        let resident_mult_corrs: Vec<_> = resident_bank
            .resident_auth
            .iter()
            .map(|(&key, value)| (key, value.1.clone()))
            .collect();
        assert_eq!(resident_mult_corrs, cpu_mult_corrs);
        assert_eq!(resident_stream.counters, cpu_stream.counters);
        assert_eq!(resident_tx.ledger(), cpu_tx.ledger());
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        assert!(
            active_resident_bytes(&gpu) > resident_before_phase1,
            "resident FFN phase 1 did not retain its owned proof buffers"
        );
        resident_p1.free(&mut gpu).unwrap();
        resident_bank.free_resident_multiplicities(&mut gpu);
        assert_eq!(
            active_resident_bytes(&gpu),
            resident_before_phase1,
            "resident FFN phase 1 retained an active owned proof buffer after cleanup"
        );
        gpu.free_device(proof_error).unwrap();
        resident_witness.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_ffn_proof_matches_cpu_byte_for_byte() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA resident FFN proof differential: artifact absent");
            return;
        }
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident FFN proof differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let tokens = model.p.tokens[..3].to_vec();
        let host_witness = forward_model_tokens(&model, &tokens);
        let resident_model = upload_resident_model(&model, &mut gpu).unwrap();
        let resident_witness =
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        let proof_error = gpu.upload_new_device(&[0u32]).unwrap();
        let t = tokens.len();
        let mut luts = model.luts.clone();
        luts.params.shift_attn_proj = model.p.shift_attn_proj[0];
        luts.params.shift_ffn_down = model.p.shift_ffn_down[0];
        let weights = &model.layers[0].0;
        let biases = &model.layers[0].1;

        let run_cpu = || {
            let mut stream = CorrelationStream::new([111; 32]);
            let mut tx = Transcript::new([112; 32]);
            let mut bank = TableBankP::new();
            let (p1, doms, dom_abo, dom_fbo, abo_corr, fbo_corr) = {
                let mut cx = BlockCtxP::new(&mut stream, &mut tx, 0, &mut bank);
                let dom_abo = cx.doms.take(t as u64);
                let abo_corr = auth_matrix_rows_p(
                    cx.stream,
                    cx.tx,
                    dom_abo,
                    &host_witness.layers[0].attn_block_out,
                    t,
                    D,
                );
                let dom_fbo = cx.doms.take(t as u64);
                let fbo_corr = auth_matrix_rows_p(
                    cx.stream,
                    cx.tx,
                    dom_fbo,
                    &host_witness.layers[0].ffn_block_out,
                    t,
                    D,
                );
                let p1 = ffn_phase1(&host_witness.layers[0], weights, &luts, &mut cx);
                (p1, cx.doms, dom_abo, dom_fbo, abo_corr, fbo_corr)
            };
            let mut table_doms = Doms::new(layer_dom_base(240));
            bank.finalize(&mut stream, &mut tx, &mut table_doms);
            let (proof, claims, mut prod, mut zero, mut ctr) = {
                let mut cx = BlockCtxP::with_doms(&mut stream, &mut tx, doms, &mut bank);
                let (proof, claims) = prove_ffn_block(
                    &host_witness.layers[0],
                    weights,
                    &luts,
                    p1,
                    &mut cx,
                    dom_abo,
                    dom_fbo,
                    Some(biases),
                );
                (proof, claims, cx.prod, cx.zero, cx.ctr_instances)
            };
            let tables = bank.close(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
            );
            (
                proof,
                claims,
                tables,
                prod,
                zero,
                ctr,
                stream.counters,
                tx.ledger().clone(),
                abo_corr,
                fbo_corr,
            )
        };
        let expected = run_cpu();

        gpu.begin_measurement().unwrap();
        let mut stream = CorrelationStream::new([111; 32]);
        let mut tx = Transcript::new([112; 32]);
        let mut bank = TableBankP::new();
        let (p1, doms, dom_abo, dom_fbo, abo_corr, fbo_corr) = {
            let mut cx = BlockCtxP::with_backend(&mut stream, &mut tx, 0, &mut bank, &mut gpu);
            let dom_abo = cx.doms.take(t as u64);
            let abo_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_abo,
                resident_witness.layers[0].i16(LayerI16Field::AttnBlockOut),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let dom_fbo = cx.doms.take(t as u64);
            let fbo_corr = auth_matrix_rows_resident_p(
                cx.stream,
                cx.tx,
                dom_fbo,
                resident_witness.layers[0].i16(LayerI16Field::FfnBlockOut),
                t,
                D,
                cx.backend.as_deref_mut().unwrap(),
            )
            .unwrap();
            let p1 = ffn_phase1_resident(
                &resident_witness.layers[0],
                &luts,
                DeviceSlice::new(&proof_error, 0, 1).unwrap(),
                &mut cx,
            )
            .unwrap();
            (p1, cx.doms, dom_abo, dom_fbo, abo_corr, fbo_corr)
        };
        let mut table_doms = Doms::new(layer_dom_base(240));
        bank.finalize_resident(&mut stream, &mut tx, &mut table_doms, &mut gpu).unwrap();
        let (proof, claims, mut prod, mut zero, mut ctr) = {
            let mut cx =
                BlockCtxP::with_doms_and_backend(&mut stream, &mut tx, doms, &mut bank, &mut gpu);
            let (proof, claims) = prove_ffn_block_resident(
                &resident_witness.layers[0],
                &resident_model,
                0,
                weights,
                &luts,
                p1,
                &mut cx,
                dom_abo,
                dom_fbo,
                Some(biases),
            )
            .unwrap();
            (proof, claims, cx.prod, cx.zero, cx.ctr_instances)
        };
        let tables = bank
            .close_resident(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
                &mut gpu,
            )
            .unwrap();
        let got = (
            proof,
            claims,
            tables,
            prod,
            zero,
            ctr,
            stream.counters,
            tx.ledger().clone(),
            abo_corr,
            fbo_corr,
        );
        assert_eq!(got, expected);
        assert_eq!(gpu.download_device(&proof_error, 0, 1).unwrap(), vec![0]);

        let delta = Fp2::new(Fp::new(0xFF11_A100), Fp::new(0x51DE));
        let mut verifier = VerifierCtx::new([111; 32], delta);
        let mut verifier_tx = Transcript::new([112; 32]);
        let mut pre_bank = TableBankV::empty();
        let (verifier_doms, abo_keys, fbo_keys, ln_keys) = {
            let mut cx = BlockCtxV::new(&mut verifier, &mut verifier_tx, 0, &mut pre_bank);
            let dom_abo_v = cx.doms.take(t as u64);
            let abo_keys = auth_matrix_rows_v(cx.ctx, dom_abo_v, &got.8, t, D);
            let dom_fbo_v = cx.doms.take(t as u64);
            let fbo_keys = auth_matrix_rows_v(cx.ctx, dom_fbo_v, &got.9, t, D);
            let ln_keys = expand_ln_vecs_k(&mut cx, &got.0.ln_vec_corrs);
            (cx.doms, abo_keys, fbo_keys, ln_keys)
        };
        let expected_contents: std::collections::BTreeSet<_> =
            got.2.iter().map(|proof| proof.key).collect();
        let mut verifier_table_doms = Doms::new(layer_dom_base(240));
        let mut verifier_bank = TableBankV::finalize(
            &expected_contents,
            &got.2,
            &mut verifier,
            &mut verifier_tx,
            &mut verifier_table_doms,
        )
        .expect("resident FFN table phase 1 verifies");
        let (weight_keys, mut key_prod, mut key_zero) = {
            let mut cx = BlockCtxV::with_doms(
                &mut verifier,
                &mut verifier_tx,
                verifier_doms,
                &mut verifier_bank,
            );
            let keys = verify_ffn_block(
                t,
                &weights.ln2_gain,
                &weights.ln2_bias,
                &luts,
                &got.0,
                &ln_keys,
                &mut cx,
                &abo_keys,
                &fbo_keys,
                Some(biases),
            )
            .expect("resident FFN proof verifies");
            (keys, cx.kprod, cx.kzero)
        };
        verifier_bank
            .close(
                &luts,
                &got.2,
                &mut verifier,
                &mut verifier_table_doms,
                &mut verifier_tx,
                &mut key_prod,
                &mut key_zero,
            )
            .expect("resident FFN table closure verifies");
        let mut prover_zero = got.4.clone();
        for ((claim, (point, key)), (matrix, rows, cols)) in got
            .1
            .iter()
            .zip(&weight_keys)
            .zip([(&weights.ffn_down[..], DFF, D), (&weights.ffn_up[..], D, DFF)])
        {
            assert_eq!(&claim.point, point);
            let value = weight_true_eval(matrix, rows, cols, point);
            prover_zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            key_zero.push(key.sub(VerifierKey::from_public(value, delta)));
        }
        let mut prover_batch_doms = Doms::new(layer_dom_base(255));
        let mut verifier_batch_doms = Doms::new(layer_dom_base(255));
        let challenge = tx.challenge_fp2();
        assert_eq!(challenge, verifier_tx.challenge_fp2());
        let product_domain = prover_batch_doms.take(1);
        assert_eq!(product_domain, verifier_batch_doms.take(1));
        let product_mask = stream.draw_fulls(product_domain, 1)[0];
        let product_key = verifier.expand_full_keys(product_domain, 1)[0];
        let product_proof = prod_batch_prover(&got.3, challenge, product_mask, &mut tx);
        assert!(prod_batch_verify(&key_prod, product_key, delta, challenge, &product_proof));
        let zero_domain = prover_batch_doms.take(1);
        assert_eq!(zero_domain, verifier_batch_doms.take(1));
        assert!(zero_batch_exchange(
            &prover_zero,
            &key_zero,
            &mut stream,
            &mut verifier,
            zero_domain,
            &mut tx,
        ));
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
        gpu.free_device(proof_error).unwrap();
        resident_witness.free(&mut gpu).unwrap();
        resident_model.free(&mut gpu).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_resident_table_bank_matches_cpu_and_reuses_context() {
        let mut resident = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA resident table-bank differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let luts = build_luts(LutParams::default());
        let key = TableKey::Range(4);
        let entries = 64usize;
        let site0: Vec<Fp> = (0..entries)
            .map(|i| if i < 45 { Fp::new(((i * 11 + 3) % 16) as u64) } else { Fp::ZERO })
            .collect();
        let site1: Vec<Fp> = (0..entries)
            .map(|i| if i < 53 { Fp::new(((i * 7 + 5) % 16) as u64) } else { Fp::ZERO })
            .collect();
        let histogram = |site: &[Fp]| {
            let mut out = vec![0u32; table_len(key)];
            for value in site {
                out[value.value() as usize] += 1;
            }
            out
        };

        let expected = {
            let mut stream = CorrelationStream::new([81; 32]);
            let mut tx = Transcript::new([82; 32]);
            let mut bank = TableBankP::new();
            bank.add_mult(key, &histogram(&site0));
            bank.add_mult(key, &histogram(&site1));
            let mut table_doms = Doms::new(0x8100);
            bank.finalize(&mut stream, &mut tx, &mut table_doms);
            let (site_proofs, mut prod, mut zero, mut ctr) = {
                let mut cx =
                    BlockCtxP::with_doms(&mut stream, &mut tx, Doms::new(0x8200), &mut bank);
                let proof0 = cx.inst(key, &[site0.clone()], &[Some(0)], Vec::new()).proof;
                let proof1 = cx.inst(key, &[site1.clone()], &[Some(0)], Vec::new()).proof;
                ([proof0, proof1], cx.prod, cx.zero, cx.ctr_instances)
            };
            let tables = bank.close(
                &luts,
                &mut stream,
                &mut table_doms,
                &mut tx,
                &mut ctr,
                &mut prod,
                &mut zero,
            );
            (site_proofs, tables, prod, zero, ctr, stream.counters, tx.ledger().clone())
        };

        let raw0: Vec<u64> = site0.iter().map(|value| value.value()).collect();
        let raw1: Vec<u64> = site1.iter().map(|value| value.value()).collect();
        let resident_before_sources = active_resident_bytes(&resident);
        let device0 = resident.upload_new_device(&raw0).unwrap();
        let device1 = resident.upload_new_device(&raw1).unwrap();
        resident.begin_measurement().unwrap();
        let run_resident = |backend: &mut Backend| {
            let mut stream = CorrelationStream::new([81; 32]);
            let mut tx = Transcript::new([82; 32]);
            let mut bank = TableBankP::new();
            let mult0 = backend
                .histogram_fp_device(
                    DeviceSlice::new(&device0, 0, entries).expect("whole lookup site 0"),
                    table_len(key),
                )
                .unwrap();
            bank.add_mult_resident(key, mult0, backend).unwrap();
            let mult1 = backend
                .histogram_fp_device(
                    DeviceSlice::new(&device1, 0, entries).expect("whole lookup site 1"),
                    table_len(key),
                )
                .unwrap();
            bank.add_mult_resident(key, mult1, backend).unwrap();
            let mut table_doms = Doms::new(0x8100);
            bank.finalize_resident(&mut stream, &mut tx, &mut table_doms, backend).unwrap();
            let (site_proofs, mut prod, mut zero, mut ctr) = {
                let mut cx = BlockCtxP::with_doms_and_backend(
                    &mut stream,
                    &mut tx,
                    Doms::new(0x8200),
                    &mut bank,
                    backend,
                );
                let proof0 = cx
                    .inst_resident(
                        key,
                        DeviceSlice::new(&device0, 0, entries).expect("whole lookup site 0"),
                        1,
                        entries,
                        &[Some(0)],
                        Vec::new(),
                    )
                    .unwrap()
                    .proof;
                let proof1 = cx
                    .inst_resident(
                        key,
                        DeviceSlice::new(&device1, 0, entries).expect("whole lookup site 1"),
                        1,
                        entries,
                        &[Some(0)],
                        Vec::new(),
                    )
                    .unwrap()
                    .proof;
                ([proof0, proof1], cx.prod, cx.zero, cx.ctr_instances)
            };
            let tables = bank
                .close_resident(
                    &luts,
                    &mut stream,
                    &mut table_doms,
                    &mut tx,
                    &mut ctr,
                    &mut prod,
                    &mut zero,
                    backend,
                )
                .unwrap();
            (site_proofs, tables, prod, zero, ctr, stream.counters, tx.ledger().clone())
        };

        let got = run_resident(&mut resident);
        assert_eq!(got, expected);
        let live_after_first = resident.stats().unwrap().live_device_bytes;
        let got_reused = run_resident(&mut resident);
        assert_eq!(got_reused, expected);
        assert_eq!(
            resident.stats().unwrap().live_device_bytes,
            live_after_first,
            "resident table bank leaked across context reuse"
        );
        let stats = resident.finish_measurement().unwrap();
        assert!(stats.operation(volta_accel::Operation::Logup).calls > 0);
        assert_eq!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns, 0);
        resident.free_device(device1).unwrap();
        resident.free_device(device0).unwrap();
        assert_eq!(
            active_resident_bytes(&resident),
            resident_before_sources,
            "resident table-bank source buffers remained active after free"
        );
    }

    /// True W̃ evaluation for a k×n weight tensor at a claim point
    /// (cols LSB: r_j ‖ r_l) — the test-only stand-in for the PCS opening.
    fn weight_true_eval(w: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
        let cb = pad_bits(n);
        let b = fold_w(w, k, n, &eq_vec(&point[..cb]));
        eval_mle(&b, &point[cb..])
    }

    /// Two-phase single-layer prover harness (phase 1 → finalize → phase 2 →
    /// per-content table closures). Returns everything the closing batches
    /// need.
    #[allow(clippy::type_complexity)]
    fn prove_layer_test(
        wit: &LayerWitness,
        w: &LayerWeights,
        luts: &Luts,
        wires: Option<AttnWires>,
        stream: &mut CorrelationStream,
        txp: &mut Transcript,
        biases: Option<&GemmBiases>,
    ) -> (
        LayerProof,
        LayerOut,
        Vec<TableCloseProof>,
        crate::logup::ProdTriples,
        Vec<ProverAuthed>,
        Doms,
    ) {
        let mut bank = TableBankP::new();
        let wires = wires.unwrap_or_else(|| build_attn_wires(wit, luts));
        let p1 = {
            let mut cx = BlockCtxP::new(stream, txp, 0, &mut bank);
            prove_layer_phase1_with_wires(wit, w, luts, wires, &mut cx)
        };
        let mut table_doms = Doms::new(layer_dom_base(240));
        bank.finalize(stream, txp, &mut table_doms);
        let mut cx = BlockCtxP::with_doms(stream, txp, p1.doms, &mut bank);
        let (proof, out) = prove_layer_phase2(wit, w, luts, p1, &mut cx, biases);
        let BlockCtxP { doms, mut prod, mut zero, mut ctr_instances, .. } = cx;
        let tables = bank.close(
            luts,
            stream,
            &mut table_doms,
            txp,
            &mut ctr_instances,
            &mut prod,
            &mut zero,
        );
        (proof, out, tables, prod, zero, doms)
    }

    /// Two-phase single-layer verifier harness (mirror of `prove_layer_test`).
    #[allow(clippy::type_complexity)]
    fn verify_layer_test(
        w: &LayerWeights,
        luts: &Luts,
        proof: &LayerProof,
        tables: &[TableCloseProof],
        vc: &mut VerifierCtx,
        txv: &mut Transcript,
        biases: Option<&GemmBiases>,
    ) -> Option<(LayerOutV, crate::logup::ProdKeyTriples, Vec<VerifierKey>, Doms)> {
        let mut pre = TableBankV::empty();
        let v1 = {
            let mut cx = BlockCtxV::new(vc, txv, 0, &mut pre);
            verify_layer_phase1(T, luts, proof, &mut cx)?
        };
        let mut expected = std::collections::BTreeSet::new();
        layer_content_keys(luts, &mut expected);
        let mut table_doms = Doms::new(layer_dom_base(240));
        let mut bankv = TableBankV::finalize(&expected, tables, vc, txv, &mut table_doms)?;
        let mut cx = BlockCtxV::with_doms(vc, txv, v1.doms, &mut bankv);
        let outv = verify_layer_phase2(
            T,
            &w.ln1_gain,
            &w.ln1_bias,
            &w.ln2_gain,
            &w.ln2_bias,
            luts,
            proof,
            v1,
            &mut cx,
            biases,
        )?;
        let BlockCtxV { doms, mut kprod, mut kzero, .. } = cx;
        bankv.close(luts, tables, vc, &mut table_doms, txv, &mut kprod, &mut kzero)?;
        Some((outv, kprod, kzero, doms))
    }

    /// Full layer round trip: prove (optionally on tampered witness/wires),
    /// (optionally tamper the proof), verify, resolve the 4 weight claims
    /// against the true tensors, then close one Π_Prod batch and one
    /// Π_ZeroBatch over ALL accumulated rows. Witness/wires tampers run the
    /// honest prover on bad data: nonzero zero-row values are cleared before
    /// the batch (cheating-prover emulation — the MAC keys keep the truth).
    fn run_layer_case(
        seed: u8,
        tamper_wit: impl FnOnce(&mut LayerWitness, &LayerWeights, &Luts),
        tamper_wires: impl FnOnce(&mut AttnWires),
        tamper_proof: impl FnOnce(&mut LayerProof),
    ) -> bool {
        let (luts, w, wit0) = fixture();
        let mut wit = wit0.clone();
        tamper_wit(&mut wit, w, luts);

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
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

        let mut wires = build_attn_wires(&wit, luts);
        tamper_wires(&mut wires);
        let (mut proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, w, luts, Some(wires), &mut stream, &mut txp, None);
        tamper_proof(&mut proof);

        let Some((outv, kprod, mut kzero, mut domsv)) =
            verify_layer_test(w, luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return false;
        };

        // Weight claims: exactly 4 (c_attn, attn_proj, ffn_up, ffn_down),
        // resolved here against the true W̃ evaluations (PCS = step 7/8).
        assert_eq!(out.weight_claims.len(), 4, "expected exactly 4 weight claims");
        assert_eq!(outv.weight_keys.len(), 4);
        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] =
            [(D, 4096, &w_perm), (D, D, &w.attn_proj), (D, DFF, &w.ffn_up), (DFF, D, &w.ffn_down)];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(wc.point.len(), pad_bits(k) + pad_bits(n));
            assert_eq!(outv.weight_keys[i].0, wc.point, "weight point mismatch across parties");
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        // Cheating-prover emulation for witness/wires tampers (no-op honest).
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
        }

        // Final closures: exactly ONE χ-batched Π_Prod + ONE Π_ZeroBatch.
        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        ok_prod && ok_zero
    }

    #[test]
    fn attn_block_e2e() {
        assert!(run_layer_case(21, |_, _, _| {}, |_| {}, |_| {}), "honest full layer rejected");
    }

    /// Nonzero softmax weight above the diagonal in the prover's causal-B
    /// copy (cheating-prover emulation at the wires level: everything else
    /// stays honest, so the reject is pinned to the causal sumcheck row).
    #[test]
    fn layer_rejects_causal_violation() {
        assert!(
            !run_layer_case(
                22,
                |_, _, _| {},
                |wires| {
                    // head 0, row 0, col 1 — real above-diagonal position.
                    assert_eq!(wires.w_rect_causal[1], 0, "honest above-diag must be 0");
                    wires.w_rect_causal[1] = 7;
                },
                |_| {}
            ),
            "causal violation accepted"
        );
    }

    /// Forged boundary: a K correction tampered on the wire — every K
    /// opening (QKᵀ B legs, the qkv third-slice claim) shifts.
    #[test]
    fn layer_rejects_forged_boundary() {
        assert!(
            !run_layer_case(
                23,
                |_, _, _| {},
                |_| {},
                |p| {
                    p.k_corr[57] = p.k_corr[57].wrapping_add(1);
                }
            ),
            "forged K boundary accepted"
        );
    }

    /// Tampered c_attn weight-claim correction: rejected when the claim is
    /// resolved against the true W̃ evaluation in the closing batch.
    #[test]
    fn layer_rejects_tampered_weight_claim() {
        assert!(
            !run_layer_case(
                24,
                |_, _, _| {},
                |_| {},
                |p| {
                    p.attn.w_cattn_corr += Fp2::ONE;
                }
            ),
            "tampered c_attn weight claim accepted"
        );
    }

    /// Flipped gelu output (out-of-table pair) with the FFN chain downstream
    /// recomputed — the FFN half's tamper coverage now runs layer-level.
    #[test]
    fn layer_rejects_flipped_gelu() {
        assert!(
            !run_layer_case(
                25,
                |wit, w, luts| {
                    wit.gelu_out[123] = wit.gelu_out[123].wrapping_add(7);
                    wit.ffn_down_acc =
                        volta_gpt2::gemm_i64(&wit.gelu_out, &w.ffn_down, wit.t, DFF, D);
                    let s = luts.params.shift_ffn_down;
                    for i in 0..wit.ffn_down_acc.len() {
                        wit.ffn_down_q[i] = volta_gpt2::gemm::requant(wit.ffn_down_acc[i], s);
                    }
                },
                |_| {},
                |_| {}
            ),
            "flipped gelu output accepted"
        );
    }

    /// Forged residual: ffn_block_out entry +1 (boundary auth + residual row).
    #[test]
    fn layer_rejects_forged_residual() {
        assert!(
            !run_layer_case(
                26,
                |wit, _, _| {
                    wit.ffn_block_out[57] = wit.ffn_block_out[57].wrapping_add(1);
                },
                |_| {},
                |_| {}
            ),
            "forged residual accepted"
        );
    }

    /// Tampered FFN wire-claim correction (GEMM-down X-wire WireOut corr).
    #[test]
    fn layer_rejects_tampered_wire_corr() {
        assert!(
            !run_layer_case(
                27,
                |_, _, _| {},
                |_| {},
                |p| {
                    p.ffn.gelu_wire_corr += Fp2::ONE;
                }
            ),
            "tampered wire-claim correction accepted"
        );
    }

    #[test]
    fn layer_counts() {
        let (luts, w, wit) = fixture();
        let mut stream = CorrelationStream::new([77; 32]);
        let mut txp = Transcript::new([78; 32]);
        let (_proof, out, _tables, _prod, _zero, _doms) =
            prove_layer_test(wit, w, luts, None, &mut stream, &mut txp, None);

        // Exactly 4 weight claims with the right point shapes.
        assert_eq!(out.weight_claims.len(), 4);
        assert_eq!(out.weight_claims[0].point.len(), 12 + 10); // c_attn (permuted 1024×4096)
        assert_eq!(out.weight_claims[1].point.len(), 10 + 10); // attn_proj
        assert_eq!(out.weight_claims[2].point.len(), pad_bits(DFF) + pad_bits(D)); // ffn_up
        assert_eq!(out.weight_claims[3].point.len(), pad_bits(D) + pad_bits(DFF)); // ffn_down

        // Corr-byte categories.
        let p = luts.params;
        let t_pad = T.next_power_of_two() as u64;
        assert_eq!(out.bytes.boundary, 8 * 5 * (T * D) as u64);
        assert_eq!(out.bytes.ln_vectors, 8 * 8 * t_pad);
        let n_above = (H * T * (T - 1) / 2) as u64;
        assert_eq!(out.bytes.attn_vectors, 8 * (3 * 16 * t_pad + n_above));
        // Multiplicity bytes live at the MODEL level now (one vector per
        // table CONTENT — the P6 shared-α restructure): per-layer mult = 0.
        let _ = p;
        assert_eq!(out.bytes.mult, 0);
        assert!(out.bytes.rounds_claims > 0, "full-corr bytes must be counted");

        // Measured lookups per instance == witness trace lens + pads.
        let tr = |id: TableId| wit.traces[id as usize].len() as u64;
        let rect = 16 * t_pad * t_pad;
        let expected: [(&str, u64, u64); 14] = [
            ("attn_proj", tr(TableId::RequantAttnProj), t_pad << 10),
            ("av", tr(TableId::RequantAv), t_pad << 10),
            ("softmax_norm", tr(TableId::SoftmaxNormRequant), rect),
            ("exp", tr(TableId::Exp), rect),
            ("softmax_recip", tr(TableId::SoftmaxRecip), 16 * t_pad),
            ("scores", tr(TableId::RequantScores), rect),
            ("qkv", tr(TableId::RequantQkv), t_pad << 12),
            ("ln1_norm", tr(TableId::LnNormRequant) / 2, t_pad << 10),
            ("ln1_rsqrt", tr(TableId::LnRsqrt) / 2, t_pad),
            ("ffn_down", tr(TableId::RequantFfnDown), t_pad << 10),
            ("gelu", tr(TableId::Gelu), t_pad << 12),
            ("ffn_up", tr(TableId::RequantFfnUp), t_pad << 12),
            ("ln2_norm", tr(TableId::LnNormRequant) / 2, t_pad << 10),
            ("ln2_rsqrt", tr(TableId::LnRsqrt) / 2, t_pad),
        ];
        assert_eq!(out.lookups.len(), expected.len());
        for (il, &(name, real, domain)) in out.lookups.iter().zip(&expected) {
            assert_eq!(il.name, name);
            let pads = domain - real;
            assert_eq!(il.lookups, real + pads, "lookup count mismatch for {name}");
        }

        // T=4 telemetry for the report (visible with -- --nocapture).
        println!(
            "layer T={T} bytes: boundary={} mult={} ln_vectors={} attn_vectors={} rounds_claims={}",
            out.bytes.boundary,
            out.bytes.mult,
            out.bytes.ln_vectors,
            out.bytes.attn_vectors,
            out.bytes.rounds_claims
        );
        println!(
            "layer T={T} emult: instances={:.0} other={:.0}; lookups total={}",
            out.ctr_instances.emult_equiv(),
            out.ctr_other.emult_equiv(),
            out.lookups.iter().map(|l| l.lookups).sum::<u64>()
        );

        // Instance E-mults are nonzero and separable from the chain-level ones.
        assert!(out.ctr_instances.emult_equiv() > 0.0);
        assert!(out.ctr_other.emult_equiv() > 0.0);
        assert!(
            out.ctr_instances.fp2_mults > out.ctr_other.fp2_mults,
            "instance counter should dominate the chain-level public evals"
        );
    }

    /// Deterministic small synthetic biases (splitmix-style, magnitude
    /// bounded so no requant saturates alongside `synthetic_weights`/
    /// `synthetic_input`'s sizing at T = 4).
    fn synthetic_biases(seed: u64) -> volta_gpt2::GemmBiases {
        let mut st = seed;
        let mut vec_of = |len: usize| -> Vec<i16> {
            (0..len).map(|_| (splitmix64_test(&mut st) % 64) as i16 - 32).collect()
        };
        volta_gpt2::GemmBiases {
            c_attn: vec_of(3 * D),
            attn_proj: vec_of(D),
            ffn_up: vec_of(DFF),
            ffn_down: vec_of(D),
        }
    }

    /// Test-local copy of the layer.rs splitmix64 (private there).
    fn splitmix64_test(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Full layer round trip with per-GEMM biases threaded through prove and
    /// verify (P5 §per-GEMM biases): synthetic weights/input/biases at T = 4,
    /// `forward_layer_with(Some(&biases))` builds the POST-bias witness, and
    /// the 4 `sub_bias_p`/`sub_bias_k` insertion points must recover the
    /// pre-bias `X·W` claim the chained GEMMs expect. Mirrors `run_layer_case`
    /// for the closing batches (biases aren't part of that harness's shared
    /// fixture, so this test builds its own witness).
    #[test]
    fn layer_with_biases_proves_and_verifies() {
        let luts = build_luts(LutParams::default());
        let w = synthetic_weights(42);
        let biases = synthetic_biases(0xB1A5);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, Some(&biases), &luts, luts.params, T);

        let seed = 90u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
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

        let (proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, Some(&biases));

        let (outv, kprod, mut kzero, mut domsv) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, Some(&biases))
                .expect("honest biased layer must verify");

        assert_eq!(out.weight_claims.len(), 4, "expected exactly 4 weight claims");
        assert_eq!(outv.weight_keys.len(), 4);
        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] =
            [(D, 4096, &w_perm), (D, D, &w.attn_proj), (D, DFF, &w.ffn_up), (DFF, D, &w.ffn_down)];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(wc.point.len(), pad_bits(k) + pad_bits(n));
            assert_eq!(outv.weight_keys[i].0, wc.point, "weight point mismatch across parties");
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        assert!(ok_prod && ok_zero, "honest biased layer's batches must close");
    }

    /// P5 chained requant e2e: shift_attn_proj = shift_ln_norm = 18 forces
    /// the two-stage range instances on both chained sites (per-layer
    /// residual scales / real shift_ln_norm=20). Same closing harness as the
    /// biases test.
    #[test]
    fn layer_with_chained_requant_proves_and_verifies() {
        let params = LutParams { shift_attn_proj: 18, shift_ln_norm: 18, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);
        // The chained trace really is two-stage on both sites.
        assert_eq!(wit.traces[TableId::LnNormRequant as usize].stage1_shift, 2);
        assert_eq!(wit.traces[TableId::RequantAttnProj as usize].stage1_shift, 2);

        let seed = 92u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
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

        let (proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, None);
        assert!(proof.ffn.ln.inst_ln_stage1.is_some(), "ln2 stage-1 instance must be present");
        assert!(proof.attn.inst_proj_stage1.is_some(), "proj stage-1 instance must be present");

        let (outv, kprod, mut kzero, mut domsv) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
                .expect("honest chained layer must verify");

        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] =
            [(D, 4096, &w_perm), (D, D, &w.attn_proj), (D, DFF, &w.ffn_up), (DFF, D, &w.ffn_down)];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(outv.weight_keys[i].0, wc.point);
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        assert!(ok_prod && ok_zero, "honest chained layer's batches must close");
    }

    /// Shared harness for the P5 stable-softmax (row-shift) tests: proves a
    /// row-shifted layer (optionally with tampered wires), verifies, closes.
    fn run_row_shift_case(
        seed: u8,
        tamper_wires: impl FnOnce(&mut AttnWires),
        tamper_proof: impl FnOnce(&mut LayerProof),
    ) -> bool {
        let params = LutParams { softmax_row_shift: true, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);
        assert!(wit.row_shift.iter().any(|&c| c != 0), "row shifts should be nontrivial");

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let mut stream = CorrelationStream::new([seed; 32]);
        let mut vc = VerifierCtx::new([seed; 32], delta);
        let mut txp = Transcript::new([seed ^ 0x5A; 32]);
        let mut txv = Transcript::new([seed ^ 0x5A; 32]);

        let mut wires = build_attn_wires(&wit, &luts);
        assert!(wires.is_max_rect.iter().any(|&m| m == 1));
        tamper_wires(&mut wires);
        let (mut proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, Some(wires), &mut stream, &mut txp, None);
        assert!(proof.attn.row_shift_corr.is_some() && proof.attn.hadamard2.is_some());
        tamper_proof(&mut proof);

        let Some((outv, kprod, mut kzero, mut domsv)) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return false;
        };

        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] =
            [(D, 4096, &w_perm), (D, D, &w.attn_proj), (D, DFF, &w.ffn_up), (DFF, D, &w.ffn_down)];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }
        // Cheating-prover emulation (wires tampers): clear nonzero zero rows.
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
        }

        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        ok_prod && ok_zero
    }

    /// P5 stable softmax e2e: honest row-shifted layer must verify.
    #[test]
    fn layer_with_row_shift_proves_and_verifies() {
        assert!(run_row_shift_case(94, |_| {}, |_| {}), "honest row-shifted layer rejected");
    }

    /// Negative: moving an is_max marker to a position with s′ ≠ 0 (a lying
    /// row-max) must be rejected by the is_max∘s′ hadamard row.
    ///
    /// PRE-EXISTING (also fails at the P5 commit, dev profile): the library's
    /// honest-prover `debug_assert` in `hadamard_prove` fires before the
    /// proof is even produced — dev builds cannot emulate this cheating
    /// prover at the wires level (P4 deviation #10's caveat). A prover-side
    /// panic therefore counts as detection here; release builds exercise the
    /// verifier-side reject.
    #[test]
    fn layer_rejects_lying_row_max() {
        let outcome = std::panic::catch_unwind(|| {
            run_row_shift_case(
                95,
                |wires| {
                    // Find a marked row with >1 causal entries and move the 1 to
                    // a neighbor whose s′ is nonzero.
                    let n = wires.is_max_rect.len();
                    for y in 0..n {
                        if wires.is_max_rect[y] == 1 {
                            for d in [y.wrapping_sub(1), y + 1] {
                                if d < n && wires.sprime_rect[d] != 0 {
                                    wires.is_max_rect[y] = 0;
                                    wires.is_max_rect[d] = 1;
                                    return;
                                }
                            }
                        }
                    }
                    panic!("no movable is_max marker found");
                },
                |_| {},
            )
        });
        assert!(
            !outcome.unwrap_or(false),
            "lying row max accepted (neither prover assert nor verifier reject fired)"
        );
    }

    /// Negative: stripping the row-shift machinery from a row-shifted proof
    /// must be rejected structurally.
    #[test]
    fn layer_rejects_stripped_row_shift() {
        assert!(!run_row_shift_case(
            96,
            |_| {},
            |proof| {
                proof.attn.hadamard2 = None;
            }
        ));
    }

    /// Negative: a chained proof whose stage-1 instance is stripped (or whose
    /// stage-1 mult corr is dropped) must be rejected structurally.
    #[test]
    fn layer_rejects_stripped_chain_stage1() {
        let params = LutParams { shift_attn_proj: 18, shift_ln_norm: 18, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);

        let seed = 93u8;
        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let mut stream = CorrelationStream::new([seed; 32]);
        let mut vc = VerifierCtx::new([seed; 32], delta);
        let mut txp = Transcript::new([seed ^ 0x5A; 32]);
        let mut txv = Transcript::new([seed ^ 0x5A; 32]);

        let (mut proof, _out, tables, _prod, _zero, _doms) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, None);
        proof.attn.inst_proj_stage1 = None;

        let outv = verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None);
        assert!(outv.is_none(), "stripped stage-1 must be rejected");
    }

    /// Negative: proving with biases but verifying with `None` (the verifier
    /// unaware of the biases, or given the wrong ones) must be rejected — the
    /// POST-bias witness accumulators no longer match the pre-bias claim the
    /// chained GEMM would recompute without the `sub_bias_k` correction.
    #[test]
    fn layer_rejects_missing_biases_at_verify() {
        let luts = build_luts(LutParams::default());
        let w = synthetic_weights(42);
        let biases = synthetic_biases(0xB1A5);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, Some(&biases), &luts, luts.params, T);

        let seed = 91u8;
        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let (proof, _out, tables, _prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, Some(&biases));

        // Structural checks pass (the corrections are well-formed), so the
        // mismatch must land in the closing Π_ZeroBatch: the verifier's
        // pre-bias claim reconstruction differs without `sub_bias_k`.
        let Some((_outv, _kprod, mut kzero, mut domsv)) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return; // structural reject is also a pass for this negative test
        };
        // Cheating-prover emulation: clear the prover's nonzero zero rows so
        // the MAC keys carry the discrepancy.
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
        }
        let _ = txp.challenge_fp2();
        let _ = txv.challenge_fp2();
        let _ = domsp.take(1);
        let _ = domsv.take(1);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        let _ = &mut kzero;
        assert!(!ok_zero, "verifying a biased proof with no biases must be rejected");
    }
}

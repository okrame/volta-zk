//! Exact C6 source/correction census for the frozen T1 GPT-2 response.
//!
//! This module deliberately stops at the old MAC source schedule.  It proves
//! that the optional prover/verifier allocation audits are byte-identical,
//! that the model prefix has the frozen T1 counts, and that the only two
//! trailing closure draws are one uncorrected QuickSilver product mask and
//! one corrected ZeroBatch mask.  The later C6 DAG migration must consume
//! this digest; it may not replace it with independently maintained counts.

use std::fmt;
use volta_mac::{
    C6TraceSourceManifest, CorrCounters, CorrScheduleAudit, CorrScheduleDraw, CorrScheduleKind,
    CorrScheduleRole, RESERVED_DOMAIN_BITS,
};

pub type C6CensusDigest = [u8; 32];

pub const C6_T1_MODEL_SUB_CORRELATIONS: u64 = 4_793_590;
pub const C6_T1_MODEL_FULL_CORRELATIONS: u64 = 181_933;
pub const C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES: u64 = 672;
pub const C6_T1_MODEL_LOCAL_PRODUCT_TRIPLES: u64 = 672;
pub const C6_T1_FINAL_PRODUCT_TRIPLES: u64 = 21_667;
pub const C6_T1_TOTAL_PRODUCT_CLOSURES: u64 = 673;
pub const C6_T1_TOTAL_PRODUCT_TRIPLES: u64 = 22_339;
pub const C6_T1_ZERO_CLOSURES: u64 = 8_170;
pub const C6_T1_MODEL_TRANSCRIPT_BYTES: u64 = 41_270_400;
pub const C6_T1_SUB_CORRECTION_BYTES: u64 = 38_348_720;
pub const C6_T1_FULL_CORRECTION_BYTES: u64 = 2_900_176;
pub const C6_T1_MODEL_PRODUCT_MESSAGE_BYTES: u64 = 21_504;
pub const C6_T1_OTHER_MODEL_TRANSCRIPT_BYTES: u64 = 0;
pub const C6_T1_MAC_CLOSURE_BYTES: u64 = 64;
pub const C6_T1_RESERVED_RAW_CORRELATIONS: u64 = 5_235_692;
pub const C6_T1_OLD_PCS_FULL_CORRELATIONS: u64 = 39_116;
pub const C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX: &str =
    "06e789d6e27b9b5092c144463bc6a3e25328fa17f7fca38bd79c02385a134dc8";
pub const C6_T1_COMPLETE_ALLOCATION_SCHEDULE_DIGEST_HEX: &str =
    "b002d4a55d890aa61299c6dbe3e5794cef8d699d96dd64ad3c41d1ad34bb6c35";
pub const C6_T1_SOURCE_SCHEDULE_DIGEST_HEX: &str =
    "526c28885fb6f77e8f569ece89c0c7442be24301a9430f3df4383428528cd9e7";
pub const C6_T1_CORRECTION_SCHEDULE_DIGEST_HEX: &str =
    "a7e22b733c9635de931ef3d9bd001c298facd413b80ff93ea48fa1b610e620da";

pub const C6_RESIDUAL_SLOT_LOG2: u32 = 23;
pub const C6_RESIDUAL_SLOT_ENTRIES: u64 = 1 << C6_RESIDUAL_SLOT_LOG2;
pub const C6_RESIDUAL_SLOT_COUNT: u64 = 8;
pub const C6_RESIDUAL_LEAF_ALIGNED_SLOTS: u64 = 7;
pub const C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES: u64 = 64;

const SOURCE_SCHEDULE_DOMAIN: &str = "volta/proto/c6/t1-source-schedule/v1";
const CORRECTION_SCHEDULE_DOMAIN: &str = "volta/proto/c6/t1-correction-schedule/v1";

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6CensusLeafRole {
    DirectCorrection = 1,
    ProductMask = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CensusError(String);

impl C6CensusError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6CensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6CensusError {}

pub struct C6T1CensusInput<'a> {
    pub prover_schedule: &'a CorrScheduleAudit,
    pub verifier_schedule: &'a CorrScheduleAudit,
    /// Number of draw records already present when `prove_response_*`
    /// returned, before the response-wide Product/ZeroBatch closure.
    pub model_draw_count: usize,
    pub model_counters: CorrCounters,
    pub model_transcript_bytes: u64,
    pub model_sub_correction_bytes: u64,
    pub model_full_correction_bytes: u64,
    pub product_mask_domain: u64,
    pub zero_mask_domain: u64,
    pub product_triples: usize,
    pub zero_closures: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResidualCapacityCensus {
    /// Seven leaf-aligned columns: common typed plaintext plus `(r,m,d)` for
    /// each of the two independent MAC coordinates.
    pub leaf_aligned_slots: u64,
    /// Conservative live entries in the eighth slot: six `(x,m)` operands
    /// per triple and coordinate, two `(x,m)` values per zero closure and a
    /// fixed scalar/footer reserve.
    pub closure_workspace_live_upper_bound: u64,
    pub slot_entries: u64,
    pub total_padded_entries: u64,
    pub total_live_upper_bound: u64,
    pub padded_headroom: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6T1SourceCensus {
    pub model_draw_count: u64,
    pub model_counters: CorrCounters,
    pub total_counters: CorrCounters,
    pub direct_subfield_leaves: u64,
    pub direct_fullfield_leaves: u64,
    pub direct_correction_leaves: u64,
    pub product_mask_leaves: u64,
    pub total_leaves: u64,
    pub local_product_closures: u64,
    pub total_product_closures: u64,
    pub final_product_triples: u64,
    pub total_product_triples: u64,
    pub zero_closures: u64,
    pub model_transcript_bytes: u64,
    pub complete_mac_transcript_bytes: u64,
    pub model_sub_correction_bytes: u64,
    pub model_full_correction_bytes: u64,
    pub model_product_message_bytes: u64,
    pub other_model_transcript_bytes: u64,
    pub model_raw_correlations: u64,
    pub complete_mac_raw_correlations: u64,
    pub reserved_raw_correlations: u64,
    pub old_pcs_raw_reserve: u64,
    pub source_schedule_digest: C6CensusDigest,
    pub correction_schedule_digest: C6CensusDigest,
    pub allocation_schedule_digest: C6CensusDigest,
    pub residual_capacity: C6ResidualCapacityCensus,
}

/// Derive the compact trace-normalizer manifest from the same canonical draw
/// schedule already accepted by the T1 source census.
///
/// Source ordinals flatten draws in protocol order. Only ProductMask
/// ordinals need to be repeated explicitly because every other source has
/// the uniform DirectCorrection role bound by `source_schedule_digest`.
pub fn c6_t1_trace_source_manifest(
    schedule: &CorrScheduleAudit,
    census: &C6T1SourceCensus,
) -> Result<C6TraceSourceManifest, C6CensusError> {
    if !schedule.is_canonical()
        || schedule.digest != census.allocation_schedule_digest
        || schedule.counters != census.total_counters
    {
        return Err(C6CensusError::new(
            "C6 trace manifest input differs from the accepted allocation schedule",
        ));
    }
    let mut next_source = 0u64;
    let mut product_mask_sources = Vec::new();
    for draw in &schedule.draws {
        if draw.role == CorrScheduleRole::ProductMask {
            if draw.kind != CorrScheduleKind::FullField || draw.count != 1 {
                return Err(C6CensusError::new(
                    "C6 trace manifest has a noncanonical ProductMask draw",
                ));
            }
            product_mask_sources.push(
                u32::try_from(next_source)
                    .map_err(|_| C6CensusError::new("C6 ProductMask ordinal exceeds u32"))?,
            );
        }
        next_source = checked_add(next_source, draw.count, "C6 trace source manifest")?;
    }
    if next_source != census.total_leaves
        || product_mask_sources.len() as u64 != census.product_mask_leaves
    {
        return Err(C6CensusError::new(
            "C6 trace manifest census differs from accepted source census",
        ));
    }
    let source_count = u32::try_from(next_source)
        .map_err(|_| C6CensusError::new("C6 trace source count exceeds u32"))?;
    C6TraceSourceManifest::new(source_count, census.source_schedule_digest, product_mask_sources)
        .map_err(|error| C6CensusError::new(error.to_string()))
}

fn checked_u64(value: usize, label: &str) -> Result<u64, C6CensusError> {
    u64::try_from(value).map_err(|_| C6CensusError::new(format!("{label} exceeds u64")))
}

fn checked_add(a: u64, b: u64, label: &str) -> Result<u64, C6CensusError> {
    a.checked_add(b).ok_or_else(|| C6CensusError::new(format!("{label} overflows u64")))
}

fn checked_mul(a: u64, b: u64, label: &str) -> Result<u64, C6CensusError> {
    a.checked_mul(b).ok_or_else(|| C6CensusError::new(format!("{label} overflows u64")))
}

fn prefix_counters(draws: &[CorrScheduleDraw]) -> Result<CorrCounters, C6CensusError> {
    let mut counters = CorrCounters::default();
    for draw in draws {
        match draw.kind {
            CorrScheduleKind::Subfield => {
                counters.sub_corrs =
                    checked_add(counters.sub_corrs, draw.count, "subfield prefix count")?;
            }
            CorrScheduleKind::FullField => {
                counters.full_corrs =
                    checked_add(counters.full_corrs, draw.count, "full-field prefix count")?;
            }
        }
        counters.domains = checked_add(counters.domains, 1, "prefix domain count")?;
    }
    Ok(counters)
}

fn hash_schedule_range(
    hasher: &mut blake3::Hasher,
    first_leaf: u64,
    stage: u8,
    role: C6CensusLeafRole,
    draw: &CorrScheduleDraw,
) {
    hasher.update(&first_leaf.to_le_bytes());
    hasher.update(&[stage, draw.kind as u8, role as u8]);
    hasher.update(&draw.ordinal.to_le_bytes());
    hasher.update(&draw.product_triples.to_le_bytes());
    hasher.update(&draw.domain.to_le_bytes());
    hasher.update(&draw.global_offset.to_le_bytes());
    hasher.update(&draw.count.to_le_bytes());
}

fn schedule_digests(
    model_draws: &[CorrScheduleDraw],
    product_draw: &CorrScheduleDraw,
    zero_draw: &CorrScheduleDraw,
) -> Result<(C6CensusDigest, C6CensusDigest, u64), C6CensusError> {
    let mut source = blake3::Hasher::new_derive_key(SOURCE_SCHEDULE_DOMAIN);
    let mut correction = blake3::Hasher::new_derive_key(CORRECTION_SCHEDULE_DOMAIN);
    let mut first_leaf = 0u64;
    for draw in model_draws {
        let role = match draw.role {
            CorrScheduleRole::DirectCorrection => C6CensusLeafRole::DirectCorrection,
            CorrScheduleRole::ProductMask => C6CensusLeafRole::ProductMask,
        };
        hash_schedule_range(&mut source, first_leaf, 0, role, draw);
        if role == C6CensusLeafRole::DirectCorrection {
            hash_schedule_range(&mut correction, first_leaf, 0, role, draw);
        }
        first_leaf = checked_add(first_leaf, draw.count, "model leaf schedule")?;
    }
    hash_schedule_range(&mut source, first_leaf, 1, C6CensusLeafRole::ProductMask, product_draw);
    first_leaf = checked_add(first_leaf, product_draw.count, "product-mask leaf schedule")?;
    hash_schedule_range(&mut source, first_leaf, 2, C6CensusLeafRole::DirectCorrection, zero_draw);
    hash_schedule_range(
        &mut correction,
        first_leaf,
        2,
        C6CensusLeafRole::DirectCorrection,
        zero_draw,
    );
    first_leaf = checked_add(first_leaf, zero_draw.count, "zero-mask leaf schedule")?;
    Ok((*source.finalize().as_bytes(), *correction.finalize().as_bytes(), first_leaf))
}

pub fn audit_c6_t1_source_census(
    input: C6T1CensusInput<'_>,
) -> Result<C6T1SourceCensus, C6CensusError> {
    if !input.prover_schedule.is_canonical() || !input.verifier_schedule.is_canonical() {
        return Err(C6CensusError::new("noncanonical C6 correlation schedule audit"));
    }
    if input.prover_schedule != input.verifier_schedule {
        return Err(C6CensusError::new("C6 prover/verifier correlation schedules differ"));
    }
    let expected_total_draws = input
        .model_draw_count
        .checked_add(2)
        .ok_or_else(|| C6CensusError::new("C6 model draw count overflows usize"))?;
    if input.prover_schedule.draws.len() != expected_total_draws {
        return Err(C6CensusError::new(
            "C6 closed response must add exactly product-mask and zero-mask draws",
        ));
    }
    if input.model_counters
        != (CorrCounters {
            sub_corrs: C6_T1_MODEL_SUB_CORRELATIONS,
            full_corrs: C6_T1_MODEL_FULL_CORRELATIONS,
            domains: checked_u64(input.model_draw_count, "C6 model draw count")?,
        })
    {
        return Err(C6CensusError::new("C6 model correlation counters differ from frozen T1"));
    }
    let model_draws = &input.prover_schedule.draws[..input.model_draw_count];
    if prefix_counters(model_draws)? != input.model_counters {
        return Err(C6CensusError::new("C6 model counter prefix differs from schedule audit"));
    }

    let product_draw = &input.prover_schedule.draws[input.model_draw_count];
    let zero_draw = &input.prover_schedule.draws[input.model_draw_count + 1];
    let expected_product = CorrScheduleDraw {
        ordinal: input.model_draw_count as u64,
        kind: CorrScheduleKind::FullField,
        role: CorrScheduleRole::ProductMask,
        product_triples: checked_u64(input.product_triples, "C6 final product triples")?,
        domain: input.product_mask_domain,
        global_offset: C6_T1_MODEL_FULL_CORRELATIONS,
        count: 1,
    };
    let expected_zero = CorrScheduleDraw {
        ordinal: input.model_draw_count as u64 + 1,
        kind: CorrScheduleKind::FullField,
        role: CorrScheduleRole::DirectCorrection,
        product_triples: 0,
        domain: input.zero_mask_domain,
        global_offset: C6_T1_MODEL_FULL_CORRELATIONS + 1,
        count: 1,
    };
    if *product_draw != expected_product || *zero_draw != expected_zero {
        return Err(C6CensusError::new(
            "C6 closure tail is not canonical product-mask then zero-mask",
        ));
    }
    if input.product_mask_domain == input.zero_mask_domain
        || input.product_mask_domain & RESERVED_DOMAIN_BITS != 0
        || input.zero_mask_domain & RESERVED_DOMAIN_BITS != 0
    {
        return Err(C6CensusError::new("invalid C6 closure correlation domains"));
    }

    if input.model_transcript_bytes != C6_T1_MODEL_TRANSCRIPT_BYTES
        || input.model_sub_correction_bytes != C6_T1_SUB_CORRECTION_BYTES
        || input.model_full_correction_bytes != C6_T1_FULL_CORRECTION_BYTES
    {
        return Err(C6CensusError::new(
            "C6 model transcript/correction bytes differ from frozen T1",
        ));
    }
    let noncorrection_model_transcript_bytes = input
        .model_transcript_bytes
        .checked_sub(input.model_sub_correction_bytes)
        .and_then(|value| value.checked_sub(input.model_full_correction_bytes))
        .ok_or_else(|| C6CensusError::new("C6 correction bytes exceed model transcript"))?;
    let other_model_transcript_bytes = noncorrection_model_transcript_bytes
        .checked_sub(C6_T1_MODEL_PRODUCT_MESSAGE_BYTES)
        .ok_or_else(|| C6CensusError::new("C6 product messages exceed model transcript"))?;
    if other_model_transcript_bytes != C6_T1_OTHER_MODEL_TRANSCRIPT_BYTES {
        return Err(C6CensusError::new("C6 non-correction model transcript bytes changed"));
    }
    if input.model_sub_correction_bytes
        != checked_mul(C6_T1_MODEL_SUB_CORRELATIONS, 8, "subfield correction bytes")?
        || input.model_full_correction_bytes
            != checked_mul(
                C6_T1_MODEL_FULL_CORRELATIONS - C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES,
                16,
                "full-field correction bytes",
            )?
    {
        return Err(C6CensusError::new(
            "C6 correction byte widths do not match their typed leaves",
        ));
    }

    let final_product_triples = checked_u64(input.product_triples, "C6 product triple count")?;
    let zero_closures = checked_u64(input.zero_closures, "C6 zero closure count")?;
    if final_product_triples != C6_T1_FINAL_PRODUCT_TRIPLES || zero_closures != C6_T1_ZERO_CLOSURES
    {
        return Err(C6CensusError::new("C6 closure census differs from frozen T1"));
    }
    let model_product_draws = model_draws
        .iter()
        .filter(|draw| draw.role == CorrScheduleRole::ProductMask)
        .collect::<Vec<_>>();
    let local_product_closures =
        checked_u64(model_product_draws.len(), "C6 local ProductClosure count")?;
    let local_product_triples = model_product_draws.iter().try_fold(0u64, |total, draw| {
        checked_add(total, draw.product_triples, "C6 local product triples")
    })?;
    if local_product_closures != C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES
        || local_product_triples != C6_T1_MODEL_LOCAL_PRODUCT_TRIPLES
        || model_product_draws.iter().any(|draw| draw.product_triples != 1)
    {
        return Err(C6CensusError::new(
            "C6 typed local ProductClosure schedule differs from frozen T1",
        ));
    }
    let total_product_closures =
        checked_add(local_product_closures, 1, "C6 total ProductClosure count")?;
    let total_product_triples =
        checked_add(local_product_triples, final_product_triples, "C6 total product triple count")?;
    if total_product_closures != C6_T1_TOTAL_PRODUCT_CLOSURES
        || total_product_triples != C6_T1_TOTAL_PRODUCT_TRIPLES
    {
        return Err(C6CensusError::new("C6 total ProductClosure census changed"));
    }

    let direct_subfield_leaves = C6_T1_MODEL_SUB_CORRELATIONS;
    let direct_fullfield_leaves = checked_add(
        C6_T1_MODEL_FULL_CORRELATIONS - local_product_closures,
        1,
        "C6 direct full-field leaves",
    )?;
    let direct_correction_leaves = checked_add(
        direct_subfield_leaves,
        direct_fullfield_leaves,
        "C6 direct correction leaves",
    )?;
    let product_mask_leaves = total_product_closures;
    let total_leaves =
        checked_add(direct_correction_leaves, product_mask_leaves, "C6 total leaves")?;
    if total_leaves > u32::MAX as u64 {
        return Err(C6CensusError::new(
            "C6 source schedule does not fit residual-IR schedule_index",
        ));
    }

    let (source_schedule_digest, correction_schedule_digest, digested_leaves) =
        schedule_digests(model_draws, product_draw, zero_draw)?;
    if digested_leaves != total_leaves {
        return Err(C6CensusError::new("C6 schedule digest leaf count mismatch"));
    }

    let model_raw_correlations = checked_add(
        C6_T1_MODEL_SUB_CORRELATIONS,
        checked_mul(C6_T1_MODEL_FULL_CORRELATIONS, 2, "C6 model full raw count")?,
        "C6 model raw count",
    )?;
    let complete_mac_raw_correlations =
        checked_add(model_raw_correlations, 4, "C6 closure raw count")?;
    let old_pcs_raw_reserve =
        checked_mul(C6_T1_OLD_PCS_FULL_CORRELATIONS, 2, "C6 historical PCS raw reserve")?;
    if checked_add(
        complete_mac_raw_correlations,
        old_pcs_raw_reserve,
        "C6 complete reserved raw count",
    )? != C6_T1_RESERVED_RAW_CORRELATIONS
    {
        return Err(C6CensusError::new("C6 frozen raw reservation no longer reconciles"));
    }

    let closure_workspace_live_upper_bound = checked_add(
        checked_add(
            checked_mul(total_product_triples, 12, "C6 product workspace")?,
            checked_mul(zero_closures, 4, "C6 zero workspace")?,
            "C6 closure workspace",
        )?,
        C6_RESIDUAL_CLOSURE_FOOTER_ENTRIES,
        "C6 closure footer",
    )?;
    if total_leaves > C6_RESIDUAL_SLOT_ENTRIES
        || closure_workspace_live_upper_bound > C6_RESIDUAL_SLOT_ENTRIES
    {
        return Err(C6CensusError::new("C6 paired residual witness exceeds a preregistered slot"));
    }
    let total_padded_entries = checked_mul(
        C6_RESIDUAL_SLOT_COUNT,
        C6_RESIDUAL_SLOT_ENTRIES,
        "C6 residual padded entries",
    )?;
    let total_live_upper_bound = checked_add(
        checked_mul(C6_RESIDUAL_LEAF_ALIGNED_SLOTS, total_leaves, "C6 leaf-aligned live entries")?,
        closure_workspace_live_upper_bound,
        "C6 residual live upper bound",
    )?;
    let padded_headroom = total_padded_entries
        .checked_sub(total_live_upper_bound)
        .ok_or_else(|| C6CensusError::new("C6 residual padded capacity underflow"))?;

    Ok(C6T1SourceCensus {
        model_draw_count: checked_u64(input.model_draw_count, "C6 model draw count")?,
        model_counters: input.model_counters,
        total_counters: input.prover_schedule.counters,
        direct_subfield_leaves,
        direct_fullfield_leaves,
        direct_correction_leaves,
        product_mask_leaves,
        total_leaves,
        local_product_closures,
        total_product_closures,
        final_product_triples,
        total_product_triples,
        zero_closures,
        model_transcript_bytes: input.model_transcript_bytes,
        complete_mac_transcript_bytes: checked_add(
            input.model_transcript_bytes,
            C6_T1_MAC_CLOSURE_BYTES,
            "C6 complete MAC transcript bytes",
        )?,
        model_sub_correction_bytes: input.model_sub_correction_bytes,
        model_full_correction_bytes: input.model_full_correction_bytes,
        model_product_message_bytes: C6_T1_MODEL_PRODUCT_MESSAGE_BYTES,
        other_model_transcript_bytes,
        model_raw_correlations,
        complete_mac_raw_correlations,
        reserved_raw_correlations: C6_T1_RESERVED_RAW_CORRELATIONS,
        old_pcs_raw_reserve,
        source_schedule_digest,
        correction_schedule_digest,
        allocation_schedule_digest: input.prover_schedule.digest,
        residual_capacity: C6ResidualCapacityCensus {
            leaf_aligned_slots: C6_RESIDUAL_LEAF_ALIGNED_SLOTS,
            closure_workspace_live_upper_bound,
            slot_entries: C6_RESIDUAL_SLOT_ENTRIES,
            total_padded_entries,
            total_live_upper_bound,
            padded_headroom,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(draws: Vec<CorrScheduleDraw>) -> CorrScheduleAudit {
        let counters = prefix_counters(&draws).unwrap();
        CorrScheduleAudit { digest: CorrScheduleAudit::canonical_digest(&draws), draws, counters }
    }

    fn fixture() -> (CorrScheduleAudit, usize, CorrCounters, u64, u64) {
        let mut model_draws = vec![
            CorrScheduleDraw {
                ordinal: 0,
                kind: CorrScheduleKind::Subfield,
                role: CorrScheduleRole::DirectCorrection,
                product_triples: 0,
                domain: 10,
                global_offset: 0,
                count: 2_000_000,
            },
            CorrScheduleDraw {
                ordinal: 1,
                kind: CorrScheduleKind::Subfield,
                role: CorrScheduleRole::DirectCorrection,
                product_triples: 0,
                domain: 11,
                global_offset: 2_000_000,
                count: C6_T1_MODEL_SUB_CORRELATIONS - 2_000_000,
            },
            CorrScheduleDraw {
                ordinal: 2,
                kind: CorrScheduleKind::FullField,
                role: CorrScheduleRole::DirectCorrection,
                product_triples: 0,
                domain: 12,
                global_offset: 0,
                count: C6_T1_MODEL_FULL_CORRELATIONS - C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES,
            },
        ];
        for index in 0..C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES {
            model_draws.push(CorrScheduleDraw {
                ordinal: model_draws.len() as u64,
                kind: CorrScheduleKind::FullField,
                role: CorrScheduleRole::ProductMask,
                product_triples: 1,
                domain: 1_000 + index,
                global_offset: C6_T1_MODEL_FULL_CORRELATIONS - C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES
                    + index,
                count: 1,
            });
        }
        let model_draw_count = model_draws.len();
        let model_counters = prefix_counters(&model_draws).unwrap();
        let product_domain = 90;
        let zero_domain = 91;
        let mut draws = model_draws;
        draws.push(CorrScheduleDraw {
            ordinal: model_draw_count as u64,
            kind: CorrScheduleKind::FullField,
            role: CorrScheduleRole::ProductMask,
            product_triples: C6_T1_FINAL_PRODUCT_TRIPLES,
            domain: product_domain,
            global_offset: C6_T1_MODEL_FULL_CORRELATIONS,
            count: 1,
        });
        draws.push(CorrScheduleDraw {
            ordinal: model_draw_count as u64 + 1,
            kind: CorrScheduleKind::FullField,
            role: CorrScheduleRole::DirectCorrection,
            product_triples: 0,
            domain: zero_domain,
            global_offset: C6_T1_MODEL_FULL_CORRELATIONS + 1,
            count: 1,
        });
        (audit(draws), model_draw_count, model_counters, product_domain, zero_domain)
    }

    fn input<'a>(
        prover: &'a CorrScheduleAudit,
        verifier: &'a CorrScheduleAudit,
        model_draw_count: usize,
        model_counters: CorrCounters,
        product_domain: u64,
        zero_domain: u64,
    ) -> C6T1CensusInput<'a> {
        C6T1CensusInput {
            prover_schedule: prover,
            verifier_schedule: verifier,
            model_draw_count,
            model_counters,
            model_transcript_bytes: C6_T1_MODEL_TRANSCRIPT_BYTES,
            model_sub_correction_bytes: C6_T1_SUB_CORRECTION_BYTES,
            model_full_correction_bytes: C6_T1_FULL_CORRECTION_BYTES,
            product_mask_domain: product_domain,
            zero_mask_domain: zero_domain,
            product_triples: C6_T1_FINAL_PRODUCT_TRIPLES as usize,
            zero_closures: C6_T1_ZERO_CLOSURES as usize,
        }
    }

    #[test]
    fn frozen_t1_source_census_and_mu23_capacity_reconcile_exactly() {
        let (prover, draws, counters, product_domain, zero_domain) = fixture();
        let census = audit_c6_t1_source_census(input(
            &prover,
            &prover,
            draws,
            counters,
            product_domain,
            zero_domain,
        ))
        .unwrap();
        assert_eq!(census.direct_subfield_leaves, 4_793_590);
        assert_eq!(census.direct_fullfield_leaves, 181_262);
        assert_eq!(census.direct_correction_leaves, 4_974_852);
        assert_eq!(census.product_mask_leaves, 673);
        assert_eq!(census.total_leaves, 4_975_525);
        assert_eq!(census.local_product_closures, 672);
        assert_eq!(census.total_product_closures, 673);
        assert_eq!(census.total_product_triples, 22_339);
        assert_eq!(census.model_raw_correlations, 5_157_456);
        assert_eq!(census.complete_mac_raw_correlations, 5_157_460);
        assert_eq!(census.old_pcs_raw_reserve, 78_232);
        assert_eq!(census.residual_capacity.closure_workspace_live_upper_bound, 300_812);
        assert_eq!(census.residual_capacity.total_live_upper_bound, 35_129_487);
        assert_eq!(census.residual_capacity.total_padded_entries, 67_108_864);
        assert_eq!(census.residual_capacity.padded_headroom, 31_979_377);

        let manifest = c6_t1_trace_source_manifest(&prover, &census).unwrap();
        assert_eq!(manifest.source_count, 4_975_525);
        assert_eq!(manifest.source_schedule_digest, census.source_schedule_digest);
        assert_eq!(manifest.product_mask_sources.len(), 673);
        assert_eq!(manifest.product_mask_sources[0], 4_974_851);
        assert_eq!(manifest.product_mask_sources[672], 4_975_523);
    }

    #[test]
    fn source_census_rejects_schedule_and_closure_mutations() {
        let (prover, draws, counters, product_domain, zero_domain) = fixture();

        let mut reordered = prover.clone();
        reordered.draws.swap(0, 1);
        assert!(audit_c6_t1_source_census(input(
            &reordered,
            &reordered,
            draws,
            counters,
            product_domain,
            zero_domain,
        ))
        .is_err());

        let mut changed = prover.clone();
        changed.draws[0].count -= 1;
        changed.digest = CorrScheduleAudit::canonical_digest(&changed.draws);
        assert!(audit_c6_t1_source_census(input(
            &changed,
            &changed,
            draws,
            counters,
            product_domain,
            zero_domain,
        ))
        .is_err());

        let mut verifier = prover.clone();
        verifier.draws[0].domain += 1;
        verifier.digest = CorrScheduleAudit::canonical_digest(&verifier.draws);
        assert!(audit_c6_t1_source_census(input(
            &prover,
            &verifier,
            draws,
            counters,
            product_domain,
            zero_domain,
        ))
        .is_err());

        let mut bad_input = input(&prover, &prover, draws, counters, product_domain, zero_domain);
        bad_input.product_triples -= 1;
        assert!(audit_c6_t1_source_census(bad_input).is_err());

        let census = audit_c6_t1_source_census(input(
            &prover,
            &prover,
            draws,
            counters,
            product_domain,
            zero_domain,
        ))
        .unwrap();
        let mut changed_schedule = prover.clone();
        changed_schedule.digest[0] ^= 1;
        assert!(c6_t1_trace_source_manifest(&changed_schedule, &census).is_err());
    }
}

//! Design-only Amendment-5 GPT-2 communication screen.
//!
//! This is not a production prover or verifier.  It materializes the exact
//! candidate packed-opening wire image and independently cross-checks its
//! length against the closed accounting formula.  Every opened `Fp2` symbol
//! and every required Merkle sibling digest is present in the byte vector;
//! only verifier-derived coordinates and hash-node positions are omitted.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use volta_pcs::x4::{merkle_aux_node_count, projected_query_indices};

const QUERY_XOF_CONTEXT: &str = "volta-zk/x4/amendment5-gpt2-preflight/v1";
const QUERY_XOF_SUFFIX: &str = "gpt2-small|102-claims|2026-07-21";
const OPENING_SCHEDULE_CONTEXT: &str = "volta-zk/x4/opening-schedule/v4";
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const FIELD_CARDINALITY_DECIMAL: &str = "340282366762482138490186164457219031041";
const FIELD_CARDINALITY_F64: f64 = 340_282_366_762_482_138_490_186_164_457_219_031_041.0;
const G3_LIMIT_BYTES: u64 = 4_000_000;
const NON_PCS_RESPONSE_BYTES: u64 = 41_270_464;
const ABSOLUTE_RESPONSE_LIMIT_BYTES: u64 = 45_270_464;
const MANDATORY_NON_QUERY_BYTES: u64 = 67_822;
const GPT2_SOURCE_BYTES: u64 = 249_403_904;
const GPT_OSS_SIZING_SOURCE_BYTES: u64 = 41_800_000_000;
const GPT2_PHYSICAL_BLOCKS: u64 = 51;
const GPT2_SUM_MU: u64 = 1_104;
const GPT2_MAX_D: u8 = 27;
const PACKED_MAGIC: [u8; 8] = *b"VOLTAX44";
const PACKED_SCHEMA: u16 = 4;
const PACKED_KIND: u8 = 0x0d;

#[derive(Clone, Debug)]
struct Candidate {
    id: String,
    rate_log2: u8,
    queries: usize,
    is_minimum: bool,
}

#[derive(Clone, Debug)]
struct Group {
    name: String,
    cohort_id: u32,
    domain_log2: u8,
    slot_count: usize,
    touched_slot_count: usize,
}

#[derive(Clone, Debug)]
struct GroupCount {
    group: Group,
    distinct_indices: u64,
    opened_symbols: u64,
    inner_aux_digests: u64,
    outer_aux_digests: u64,
}

#[derive(Clone, Debug)]
struct RoundCount {
    round: u8,
    domain_log2: u8,
    distinct_indices: u64,
    opened_symbols: u64,
    outer_aux_digests: u64,
}

#[derive(Clone, Debug)]
struct PackedCount {
    initial: Vec<GroupCount>,
    rounds: Vec<RoundCount>,
    opened_symbols: u64,
    initial_inner_aux_digests: u64,
    initial_outer_aux_digests: u64,
    fold_outer_aux_digests: u64,
    framing_and_metadata_bytes: u64,
    opened_symbol_bytes: u64,
    merkle_sibling_digest_bytes: u64,
    packed_opening_bytes: u64,
}

#[derive(Serialize)]
struct ChallengeRecord {
    derive_key_context: String,
    xof_input_ascii: String,
    draw_count: usize,
    draw_width_bits: u8,
    replacement: bool,
    ordered_draws_blake3: String,
    ordered_draws: Vec<u64>,
}

#[derive(Serialize)]
struct GeometryRecord {
    profile_mu_max: u8,
    max_extended_variables: u8,
    max_domain_log2: u8,
    gpt_oss_global_blocks: u64,
    gpt_oss_physical_blocks: u64,
    maximum_active_polynomials: u64,
    maximum_aux_variables: u8,
    maximum_weight_oracle_symbols: u64,
    maximum_aux_oracle_symbols: u64,
    gpt2_physical_blocks: u64,
    gpt2_initial_roots: usize,
    gpt2_fold_rounds: u8,
}

#[derive(Serialize)]
struct SoundnessRecord {
    expression: String,
    strict_unique_decoding_base: String,
    proximity_coefficient: u64,
    fold_coefficient: u64,
    claim_coefficient: u64,
    authenticated_link_coefficient: u64,
    zero_batch_coefficient: u64,
    total_field_coefficient: u64,
    field_cardinality: String,
    evaluated_bits: f64,
    required_bits: f64,
    margin_bits: f64,
    previous_query_count_bits: Option<f64>,
    minimum_integer_query_count: bool,
    no_list_decoding_credit: bool,
}

#[derive(Serialize)]
struct InitialGroupRecord {
    name: String,
    cohort_id: u32,
    domain_log2: u8,
    slot_count: usize,
    touched_slot_count: usize,
    distinct_opened_indices: u64,
    opened_symbols: u64,
    inner_aux_digests: u64,
    outer_aux_digests: u64,
}

#[derive(Serialize)]
struct FoldRoundRecord {
    round: u8,
    domain_log2: u8,
    distinct_opened_indices: u64,
    opened_symbols: u64,
    outer_aux_digests: u64,
}

#[derive(Serialize)]
struct ByteRecord {
    packed_frame_magic_ascii: String,
    packed_frame_schema: u16,
    packed_frame_kind: u8,
    framing_and_metadata: u64,
    opened_symbols: u64,
    opened_symbol_bytes: u64,
    initial_inner_aux_digests: u64,
    initial_outer_aux_digests: u64,
    fold_outer_aux_digests: u64,
    total_merkle_sibling_digests: u64,
    merkle_sibling_digest_bytes: u64,
    packed_opening_serialized_bytes: u64,
    closed_formula_bytes: u64,
    formula_matches_materialized_codec: bool,
    mandatory_non_query_bytes: u64,
    complete_pcs_bytes: u64,
    g3_limit_bytes: u64,
    g3_headroom_bytes: i64,
    projected_response_bytes: u64,
    absolute_response_limit_bytes: u64,
    absolute_response_headroom_bytes: i64,
}

#[derive(Serialize)]
struct CorrelationRecord {
    gpt2_exact_claim_reduction_full: u64,
    gpt2_exact_seam_full: u64,
    gpt2_exact_x4_full: u64,
    maximum_claim_reduction_full: u64,
    maximum_seam_full: u64,
    maximum_x4_full: u64,
    pcg_lifecycle_changed: bool,
}

#[derive(Serialize)]
struct StorageRecord {
    first_oracle_source_multiplier: u64,
    gpt2_first_oracle_floor_bytes: u64,
    gpt_oss_first_oracle_floor_bytes: u64,
}

#[derive(Serialize)]
struct CandidateRecord {
    id: String,
    rate: String,
    query_count: usize,
    minimum_row: bool,
    challenge: ChallengeRecord,
    geometry: GeometryRecord,
    soundness: SoundnessRecord,
    initial_groups: Vec<InitialGroupRecord>,
    fold_rounds: Vec<FoldRoundRecord>,
    bytes: ByteRecord,
    correlations: CorrelationRecord,
    storage: StorageRecord,
    g3_pass: bool,
    absolute_response_pass: bool,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    prior_v3_record: String,
    prior_v3_record_sha256: String,
    prior_v3_strict_lower_bound_bytes: u64,
    prior_v3_verdict: String,
    codec_status: String,
    candidates: Vec<CandidateRecord>,
    frozen_candidate_selected_by_this_record: bool,
    notes: Vec<String>,
}

fn command_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(true)
}

fn ceil_log2(value: u64) -> u8 {
    assert!(value > 0);
    if value == 1 {
        0
    } else {
        (u64::BITS - (value - 1).leading_zeros()) as u8
    }
}

fn geometry(rate_log2: u8, queries: usize) -> (u8, u8, u64, u64, u8, u64, u64) {
    assert!((3..=5).contains(&rate_log2));
    let mu = 32 - rate_log2;
    let d = mu + 1;
    let global_blocks = 2u64 << (30 - mu);
    let blocks = 1_656 + global_blocks;
    let polynomials = 2 * blocks;
    let ell = ceil_log2((queries as u64) * u64::from(mu) * u64::from(mu) + 1);
    let n_w = 1u64 << (d + rate_log2);
    let n_g = 1u64 << (ell + rate_log2);
    (mu, d, blocks, polynomials, ell, n_w, n_g)
}

fn soundness(rate_log2: u8, queries: usize) -> (f64, u64, u64, u64, u64, u64) {
    let (mu, d, blocks, polynomials, _ell, n_w, n_g) = geometry(rate_log2, queries);
    let fold = polynomials * ((n_w - 1) + (n_g - 1));
    let claim = blocks * (3 * u64::from(mu) + 4);
    let auth_link = polynomials + 3 * u64::from(d) + 2;
    let zero = blocks + 1;
    let total = fold + claim + auth_link + zero;
    let denominator = (1u64 << (rate_log2 + 1)) as f64;
    let base = ((1u64 << rate_log2) + 1) as f64 / denominator;
    let epsilon =
        polynomials as f64 * base.powi(queries as i32) + total as f64 / FIELD_CARDINALITY_F64;
    (-epsilon.log2(), fold, claim, auth_link, zero, total)
}

fn minimum_queries(rate_log2: u8) -> usize {
    (1..=512)
        .find(|queries| soundness(rate_log2, *queries).0 >= SOUNDNESS_FLOOR_BITS)
        .expect("soundness query count")
}

fn candidates() -> Vec<Candidate> {
    (3..=5)
        .flat_map(|rate_log2| {
            let minimum = minimum_queries(rate_log2);
            [
                Candidate {
                    id: format!("e{}-r{}-s{}", 32 - rate_log2, rate_log2, minimum),
                    rate_log2,
                    queries: minimum,
                    is_minimum: true,
                },
                Candidate {
                    id: format!("e{}-r{}-s{}", 32 - rate_log2, rate_log2, minimum + 1),
                    rate_log2,
                    queries: minimum + 1,
                    is_minimum: false,
                },
            ]
        })
        .collect()
}

fn query_draws(candidate: &Candidate) -> Vec<u64> {
    let max_domain_log2 = GPT2_MAX_D + candidate.rate_log2;
    let input = format!("{}|{}", candidate.id, QUERY_XOF_SUFFIX);
    let mut hasher = blake3::Hasher::new_derive_key(QUERY_XOF_CONTEXT);
    hasher.update(input.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mask = if max_domain_log2 == 32 { u32::MAX } else { (1u32 << max_domain_log2) - 1 };
    (0..candidate.queries)
        .map(|_| {
            let mut word = [0u8; 4];
            reader.fill(&mut word);
            u64::from(u32::from_le_bytes(word) & mask)
        })
        .collect()
}

fn query_digest(draws: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(4 * draws.len());
    for draw in draws {
        bytes.extend_from_slice(&u32::try_from(*draw).unwrap().to_le_bytes());
    }
    blake3::hash(&bytes).to_hex().to_string()
}

fn gpt2_groups(candidate: &Candidate) -> Vec<Group> {
    let r = candidate.rate_log2;
    let mut groups = vec![
        Group {
            name: "Wext-mu26-global-tied-roles".to_owned(),
            cohort_id: 0xA500_0001,
            domain_log2: 27 + r,
            slot_count: 2,
            touched_slot_count: 2,
        },
        Group {
            name: "Wext-mu22-all-layers".to_owned(),
            cohort_id: 0xA500_0002,
            domain_log2: 23 + r,
            slot_count: 64,
            touched_slot_count: 36,
        },
        Group {
            name: "Wext-mu20-layers-and-position".to_owned(),
            cohort_id: 0xA500_0003,
            domain_log2: 21 + r,
            slot_count: 16,
            touched_slot_count: 13,
        },
    ];

    let mut aux_by_ell = BTreeMap::<u8, usize>::new();
    for (mu, count) in [(22u64, 36usize), (20, 13), (26, 2)] {
        let ell = ceil_log2((candidate.queries as u64) * mu * mu + 1);
        *aux_by_ell.entry(ell).or_default() += count;
    }
    for (ordinal, (ell, count)) in aux_by_ell.into_iter().rev().enumerate() {
        groups.push(Group {
            name: format!("aux-ell{ell}-model-global"),
            cohort_id: 0xA500_0100 + ordinal as u32,
            domain_log2: ell + r,
            slot_count: count.next_power_of_two(),
            touched_slot_count: count,
        });
    }
    groups.sort_by(|left, right| {
        right.domain_log2.cmp(&left.domain_log2).then_with(|| left.cohort_id.cmp(&right.cohort_id))
    });
    groups
}

fn packed_count(candidate: &Candidate, draws: &[u64]) -> PackedCount {
    let initial = gpt2_groups(candidate)
        .into_iter()
        .map(|group| {
            let indices = projected_query_indices(draws, group.domain_log2).unwrap();
            let distinct_indices = indices.len() as u64;
            let touched = (0..group.touched_slot_count as u64).collect::<Vec<_>>();
            let inner_depth = group.slot_count.ilog2() as u8;
            let inner_per_coordinate = merkle_aux_node_count(inner_depth, &touched).unwrap();
            GroupCount {
                opened_symbols: distinct_indices * group.touched_slot_count as u64,
                inner_aux_digests: distinct_indices * inner_per_coordinate,
                outer_aux_digests: merkle_aux_node_count(group.domain_log2, &indices).unwrap(),
                distinct_indices,
                group,
            }
        })
        .collect::<Vec<_>>();

    let max_domain_log2 = GPT2_MAX_D + candidate.rate_log2;
    let rounds = (1..=GPT2_MAX_D)
        .map(|round| {
            let domain_log2 = max_domain_log2 - round;
            let indices = projected_query_indices(draws, domain_log2).unwrap();
            let distinct_indices = indices.len() as u64;
            RoundCount {
                round,
                domain_log2,
                distinct_indices,
                opened_symbols: distinct_indices,
                outer_aux_digests: merkle_aux_node_count(domain_log2, &indices).unwrap(),
            }
        })
        .collect::<Vec<_>>();

    let opened_symbols = initial.iter().map(|count| count.opened_symbols).sum::<u64>()
        + rounds.iter().map(|count| count.opened_symbols).sum::<u64>();
    let initial_inner_aux_digests = initial.iter().map(|count| count.inner_aux_digests).sum();
    let initial_outer_aux_digests = initial.iter().map(|count| count.outer_aux_digests).sum();
    let fold_outer_aux_digests = rounds.iter().map(|count| count.outer_aux_digests).sum();
    let opened_symbol_bytes = 16 * opened_symbols;
    let merkle_sibling_digest_bytes =
        32 * (initial_inner_aux_digests + initial_outer_aux_digests + fold_outer_aux_digests);

    // Header + schedule digest + group count + fold-round count; each initial
    // group carries 21 fixed bytes plus its u16 slots, and each fold round 10.
    let framing_and_metadata_bytes = 16
        + 32
        + 2
        + 1
        + initial.iter().map(|count| 21 + 2 * count.group.touched_slot_count as u64).sum::<u64>()
        + 10 * rounds.len() as u64;
    let packed_opening_bytes =
        framing_and_metadata_bytes + opened_symbol_bytes + merkle_sibling_digest_bytes;
    PackedCount {
        initial,
        rounds,
        opened_symbols,
        initial_inner_aux_digests,
        initial_outer_aux_digests,
        fold_outer_aux_digests,
        framing_and_metadata_bytes,
        opened_symbol_bytes,
        merkle_sibling_digest_bytes,
        packed_opening_bytes,
    }
}

fn push_zeros(bytes: &mut Vec<u8>, count: u64) {
    let count = usize::try_from(count).expect("materialized preflight length");
    bytes.resize(bytes.len().checked_add(count).unwrap(), 0);
}

fn materialize_packed_frame(candidate: &Candidate, draws: &[u64], count: &PackedCount) -> Vec<u8> {
    let input = format!("{}|{}", candidate.id, QUERY_XOF_SUFFIX);
    let mut schedule_hasher = blake3::Hasher::new_derive_key(OPENING_SCHEDULE_CONTEXT);
    schedule_hasher.update(input.as_bytes());
    for draw in draws {
        schedule_hasher.update(&u32::try_from(*draw).unwrap().to_le_bytes());
    }
    let schedule_digest = schedule_hasher.finalize();

    let mut body = Vec::new();
    body.extend_from_slice(schedule_digest.as_bytes());
    body.extend_from_slice(&u16::try_from(count.initial.len()).unwrap().to_le_bytes());
    for group in &count.initial {
        body.extend_from_slice(&group.group.cohort_id.to_le_bytes());
        body.push(group.group.domain_log2);
        body.extend_from_slice(&u16::try_from(group.group.slot_count).unwrap().to_le_bytes());
        body.extend_from_slice(
            &u16::try_from(group.group.touched_slot_count).unwrap().to_le_bytes(),
        );
        for slot in 0..group.group.touched_slot_count {
            body.extend_from_slice(&u16::try_from(slot).unwrap().to_le_bytes());
        }
        body.extend_from_slice(&u32::try_from(group.opened_symbols).unwrap().to_le_bytes());
        push_zeros(&mut body, 16 * group.opened_symbols);
        body.extend_from_slice(&u32::try_from(group.inner_aux_digests).unwrap().to_le_bytes());
        push_zeros(&mut body, 32 * group.inner_aux_digests);
        body.extend_from_slice(&u32::try_from(group.outer_aux_digests).unwrap().to_le_bytes());
        push_zeros(&mut body, 32 * group.outer_aux_digests);
    }
    body.push(u8::try_from(count.rounds.len()).unwrap());
    for round in &count.rounds {
        body.push(round.round);
        body.push(round.domain_log2);
        body.extend_from_slice(&u32::try_from(round.opened_symbols).unwrap().to_le_bytes());
        push_zeros(&mut body, 16 * round.opened_symbols);
        body.extend_from_slice(&u32::try_from(round.outer_aux_digests).unwrap().to_le_bytes());
        push_zeros(&mut body, 32 * round.outer_aux_digests);
    }

    let mut encoded = Vec::with_capacity(16 + body.len());
    encoded.extend_from_slice(&PACKED_MAGIC);
    encoded.extend_from_slice(&PACKED_SCHEMA.to_le_bytes());
    encoded.push(PACKED_KIND);
    encoded.push(0);
    encoded.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    encoded.extend_from_slice(&body);
    encoded
}

fn candidate_record(candidate: Candidate) -> CandidateRecord {
    let draws = query_draws(&candidate);
    let packed = packed_count(&candidate, &draws);
    let materialized = materialize_packed_frame(&candidate, &draws, &packed);
    let materialized_len = materialized.len() as u64;
    assert_eq!(materialized_len, packed.packed_opening_bytes);

    let (mu, d, blocks, polynomials, ell, n_w, n_g) =
        geometry(candidate.rate_log2, candidate.queries);
    let (bits, fold, claim, auth_link, zero, total) =
        soundness(candidate.rate_log2, candidate.queries);
    let previous_bits =
        (candidate.queries > 1).then(|| soundness(candidate.rate_log2, candidate.queries - 1).0);
    let minimum = minimum_queries(candidate.rate_log2);
    assert_eq!(candidate.is_minimum, candidate.queries == minimum);
    assert!(bits >= SOUNDNESS_FLOOR_BITS);
    if candidate.is_minimum {
        assert!(previous_bits.unwrap() < SOUNDNESS_FLOOR_BITS);
    }

    let packed_aux = packed.initial_inner_aux_digests
        + packed.initial_outer_aux_digests
        + packed.fold_outer_aux_digests;
    let complete_pcs_bytes = materialized_len + MANDATORY_NON_QUERY_BYTES;
    let projected_response_bytes = NON_PCS_RESPONSE_BYTES + complete_pcs_bytes;
    let source_multiplier = 16u64 << candidate.rate_log2;
    let max_claim_reduction = 2 * blocks * u64::from(mu);
    let max_seam = blocks + 2 * u64::from(d) + 1;
    let gpt2_claim_reduction = 2 * GPT2_SUM_MU;
    let gpt2_seam = GPT2_PHYSICAL_BLOCKS + 2 * u64::from(GPT2_MAX_D) + 1;
    let xof_input = format!("{}|{}", candidate.id, QUERY_XOF_SUFFIX);
    let base_numerator = (1u64 << candidate.rate_log2) + 1;
    let base_denominator = 1u64 << (candidate.rate_log2 + 1);

    CandidateRecord {
        id: candidate.id,
        rate: format!("1/{}", 1u64 << candidate.rate_log2),
        query_count: candidate.queries,
        minimum_row: candidate.is_minimum,
        challenge: ChallengeRecord {
            derive_key_context: QUERY_XOF_CONTEXT.to_owned(),
            xof_input_ascii: xof_input,
            draw_count: draws.len(),
            draw_width_bits: GPT2_MAX_D + candidate.rate_log2,
            replacement: true,
            ordered_draws_blake3: query_digest(&draws),
            ordered_draws: draws,
        },
        geometry: GeometryRecord {
            profile_mu_max: mu,
            max_extended_variables: d,
            max_domain_log2: d + candidate.rate_log2,
            gpt_oss_global_blocks: blocks - 1_656,
            gpt_oss_physical_blocks: blocks,
            maximum_active_polynomials: polynomials,
            maximum_aux_variables: ell,
            maximum_weight_oracle_symbols: n_w,
            maximum_aux_oracle_symbols: n_g,
            gpt2_physical_blocks: GPT2_PHYSICAL_BLOCKS,
            gpt2_initial_roots: packed.initial.len(),
            gpt2_fold_rounds: GPT2_MAX_D,
        },
        soundness: SoundnessRecord {
            expression: format!(
                "{polynomials}*({base_numerator}/{base_denominator})^{} + {total}/{FIELD_CARDINALITY_DECIMAL}",
                candidate.queries
            ),
            strict_unique_decoding_base: format!("{base_numerator}/{base_denominator}"),
            proximity_coefficient: polynomials,
            fold_coefficient: fold,
            claim_coefficient: claim,
            authenticated_link_coefficient: auth_link,
            zero_batch_coefficient: zero,
            total_field_coefficient: total,
            field_cardinality: FIELD_CARDINALITY_DECIMAL.to_owned(),
            evaluated_bits: bits,
            required_bits: SOUNDNESS_FLOOR_BITS,
            margin_bits: bits - SOUNDNESS_FLOOR_BITS,
            previous_query_count_bits: previous_bits,
            minimum_integer_query_count: candidate.is_minimum,
            no_list_decoding_credit: true,
        },
        initial_groups: packed
            .initial
            .iter()
            .map(|count| InitialGroupRecord {
                name: count.group.name.clone(),
                cohort_id: count.group.cohort_id,
                domain_log2: count.group.domain_log2,
                slot_count: count.group.slot_count,
                touched_slot_count: count.group.touched_slot_count,
                distinct_opened_indices: count.distinct_indices,
                opened_symbols: count.opened_symbols,
                inner_aux_digests: count.inner_aux_digests,
                outer_aux_digests: count.outer_aux_digests,
            })
            .collect(),
        fold_rounds: packed
            .rounds
            .iter()
            .map(|count| FoldRoundRecord {
                round: count.round,
                domain_log2: count.domain_log2,
                distinct_opened_indices: count.distinct_indices,
                opened_symbols: count.opened_symbols,
                outer_aux_digests: count.outer_aux_digests,
            })
            .collect(),
        bytes: ByteRecord {
            packed_frame_magic_ascii: String::from_utf8(PACKED_MAGIC.to_vec()).unwrap(),
            packed_frame_schema: PACKED_SCHEMA,
            packed_frame_kind: PACKED_KIND,
            framing_and_metadata: packed.framing_and_metadata_bytes,
            opened_symbols: packed.opened_symbols,
            opened_symbol_bytes: packed.opened_symbol_bytes,
            initial_inner_aux_digests: packed.initial_inner_aux_digests,
            initial_outer_aux_digests: packed.initial_outer_aux_digests,
            fold_outer_aux_digests: packed.fold_outer_aux_digests,
            total_merkle_sibling_digests: packed_aux,
            merkle_sibling_digest_bytes: packed.merkle_sibling_digest_bytes,
            packed_opening_serialized_bytes: materialized_len,
            closed_formula_bytes: packed.packed_opening_bytes,
            formula_matches_materialized_codec: materialized_len == packed.packed_opening_bytes,
            mandatory_non_query_bytes: MANDATORY_NON_QUERY_BYTES,
            complete_pcs_bytes,
            g3_limit_bytes: G3_LIMIT_BYTES,
            g3_headroom_bytes: G3_LIMIT_BYTES as i64 - complete_pcs_bytes as i64,
            projected_response_bytes,
            absolute_response_limit_bytes: ABSOLUTE_RESPONSE_LIMIT_BYTES,
            absolute_response_headroom_bytes:
                ABSOLUTE_RESPONSE_LIMIT_BYTES as i64 - projected_response_bytes as i64,
        },
        correlations: CorrelationRecord {
            gpt2_exact_claim_reduction_full: gpt2_claim_reduction,
            gpt2_exact_seam_full: gpt2_seam,
            gpt2_exact_x4_full: gpt2_claim_reduction + gpt2_seam,
            maximum_claim_reduction_full: max_claim_reduction,
            maximum_seam_full: max_seam,
            maximum_x4_full: max_claim_reduction + max_seam,
            pcg_lifecycle_changed: false,
        },
        storage: StorageRecord {
            first_oracle_source_multiplier: source_multiplier,
            gpt2_first_oracle_floor_bytes: GPT2_SOURCE_BYTES * source_multiplier,
            gpt_oss_first_oracle_floor_bytes: GPT_OSS_SIZING_SOURCE_BYTES * source_multiplier,
        },
        g3_pass: complete_pcs_bytes <= G3_LIMIT_BYTES,
        absolute_response_pass: projected_response_bytes <= ABSOLUTE_RESPONSE_LIMIT_BYTES,
    }
}

fn build_report() -> Report {
    Report {
        schema: 1,
        milestone: "X4-Amendment5-GPT2-candidate-preflight".to_owned(),
        date: command_output(&["date", "+%Y-%m-%d"]),
        git_sha: command_output(&["git", "rev-parse", "HEAD"]),
        git_short_sha: command_output(&["git", "rev-parse", "--short", "HEAD"]),
        git_dirty: git_dirty(),
        prior_v3_record:
            "benchmarks/results/x4-gpt2-g3-preflight-2026-07-21-3aa5952.json".to_owned(),
        prior_v3_record_sha256:
            "a5d2f4ba189c27a7b39e8e0f0c66475057a6f15041483fbe2035bcc69afc4cb9"
                .to_owned(),
        prior_v3_strict_lower_bound_bytes: 4_089_416,
        prior_v3_verdict: "INFEASIBLE; SUPERSEDED CANDIDATE; NOT A NEAR PASS".to_owned(),
        codec_status: "design-only byte-exact v4 reference encoder; not production prover/verifier"
            .to_owned(),
        candidates: candidates().into_iter().map(candidate_record).collect(),
        frozen_candidate_selected_by_this_record: false,
        notes: vec![
            "The materialized reference wire image contains every opened field symbol and every Merkle sibling digest; only verifier-derived coordinates, leaf metadata and sibling positions are absent.".to_owned(),
            "Same-domain slots are model-global and descriptor ordered. Independent Merkle roots share no sibling digest credit. The post-initial protocol is one Section-5.1 different-size activation chain.".to_owned(),
            "The 67,822-byte non-query term retains the v3 envelope, descriptors, manifest, claims, h, M9, authenticated-output link, one fold-commitment chain and response ZeroBatch widths.".to_owned(),
            "All candidates use strict unique decoding. No conjectural list-decoding radius, zero-byte authentication path, compression ratio, PCG/lifecycle change or threshold relaxation is credited.".to_owned(),
            "This record screens candidates only. Amendment 5 must select and freeze one row, pin its design digest, and hard-stop for review before Lean-first.".to_owned(),
        ],
    }
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    let report = build_report();
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    println!("{json}");
    for candidate in &report.candidates {
        eprintln!(
            "{} rate={} s={} bits={:.9} pcs={} headroom={} storage_multiplier={}x",
            candidate.id,
            candidate.rate,
            candidate.query_count,
            candidate.soundness.evaluated_bits,
            candidate.bytes.complete_pcs_bytes,
            candidate.bytes.g3_headroom_bytes,
            candidate.storage.first_oracle_source_multiplier,
        );
    }
    if record {
        if report.git_dirty {
            eprintln!(
                "x4_amendment5_preflight: refusing a run-of-record from a tracked-dirty tree"
            );
            std::process::exit(2);
        }
        let path: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results").join(format!(
                "x4-amendment5-gpt2-preflight-{}-{}.json",
                report.date, report.git_short_sha
            ));
        if path.exists() {
            eprintln!(
                "x4_amendment5_preflight: append-only record already exists: {}",
                path.display()
            );
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only Amendment-5 preflight");
        eprintln!("wrote {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_query_rows_cross_the_registered_floor_exactly_once() {
        assert_eq!(minimum_queries(3), 110);
        assert_eq!(minimum_queries(4), 100);
        assert_eq!(minimum_queries(5), 95);
        for rate_log2 in 3..=5 {
            let minimum = minimum_queries(rate_log2);
            assert!(soundness(rate_log2, minimum - 1).0 < SOUNDNESS_FLOOR_BITS);
            assert!(soundness(rate_log2, minimum).0 >= SOUNDNESS_FLOOR_BITS);
        }
    }

    #[test]
    fn every_preregistered_row_materializes_to_its_closed_byte_count() {
        for candidate in candidates() {
            let draws = query_draws(&candidate);
            let count = packed_count(&candidate, &draws);
            let encoded = materialize_packed_frame(&candidate, &draws, &count);
            assert_eq!(encoded.len() as u64, count.packed_opening_bytes);
            assert!(encoded.len() as u64 + MANDATORY_NON_QUERY_BYTES <= G3_LIMIT_BYTES);
        }
    }

    #[test]
    fn gpt2_correlation_count_stays_exact_and_lifecycle_neutral() {
        let claim = 2 * GPT2_SUM_MU;
        let seam = GPT2_PHYSICAL_BLOCKS + 2 * u64::from(GPT2_MAX_D) + 1;
        assert_eq!(claim, 2_208);
        assert_eq!(seam, 106);
        assert_eq!(claim + seam, 2_314);
    }
}

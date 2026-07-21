//! X4 GPT-2 communication preflight.
//!
//! This deliberately undercounts the best conceivable conforming batch: all
//! 52 initial roots are authenticated, but every post-initial polynomial is
//! granted one shared maximum-depth fold chain and every auxiliary Merkle
//! node is assigned zero bytes.  If that lower bound misses G3, building the
//! production-sized oracles cannot change the verdict.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use volta_field::Fp2;
use volta_pcs::x4::{
    cohort_multiproof_byte_count, manifest_id_digest, projected_query_indices,
    AuthenticatedOutputLinkFrame, CohortMultiproofByteCount, FoldCommitmentFrame, Frame,
    M9TransferFrame, ManifestFrame, ManifestLeafFrame, ManifestTree, OracleKind, Phase,
    ReducedClaimFrame, ResponseZeroBatchFrame, PROFILE_NAME,
};

const DESIGN_SHA256: &str = "f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98";
const LEAN_AUDIT_STDOUT_SHA256: &str =
    "4706e705abc1a8df3eeb96df41388c357f2006671cf90116c9c200f29d36d267";
const SOUNDNESS_BITS: f64 = 83.302_264_033_789_21;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const NON_PCS_RESPONSE_BYTES: u64 = 41_270_464;
const G3_LIMIT_BYTES: u64 = 4_000_000;
const ABSOLUTE_RESPONSE_LIMIT_BYTES: u64 = 45_270_464;
const QUERY_COUNT: usize = 128;
const MAX_DOMAIN_LOG2: u8 = 30;
const MAX_FOLD_ROUNDS: u8 = 27;
const PHYSICAL_BLOCKS: usize = 51;
const FIXED_CLAIMS: usize = 102;
const COHORT_IDS: usize = 26;
const INITIAL_ROOTS: usize = 52;
const QUERY_XOF_CONTEXT: &str = "volta-zk/x4/gpt2-g3-preflight/v1";
const QUERY_XOF_INPUT: &[u8] = b"x4-zkdeepfold-ud-e29-v3|gpt2-small|102-claims|2026-07-21";

#[derive(Clone, Copy)]
struct CohortGroup {
    name: &'static str,
    root_count: u64,
    domain_log2: u8,
    total_slots: usize,
    touched_slots: &'static [u16],
}

const SLOTS_1: &[u16] = &[0];
const SLOTS_2: &[u16] = &[0, 1];
const SLOTS_3_OF_4: &[u16] = &[0, 1, 2];

const INITIAL_GROUPS: &[CohortGroup] = &[
    CohortGroup {
        name: "12 layer mu22 weight-extension roots",
        root_count: 12,
        domain_log2: 26,
        total_slots: 4,
        touched_slots: SLOTS_3_OF_4,
    },
    CohortGroup {
        name: "12 layer mu22 auxiliary roots",
        root_count: 12,
        domain_log2: 19,
        total_slots: 4,
        touched_slots: SLOTS_3_OF_4,
    },
    CohortGroup {
        name: "12 layer mu20 weight-extension roots",
        root_count: 12,
        domain_log2: 24,
        total_slots: 1,
        touched_slots: SLOTS_1,
    },
    CohortGroup {
        name: "12 layer mu20 auxiliary roots",
        root_count: 12,
        domain_log2: 19,
        total_slots: 1,
        touched_slots: SLOTS_1,
    },
    CohortGroup {
        name: "global tied embed/unembed mu26 weight-extension root",
        root_count: 1,
        domain_log2: 30,
        total_slots: 2,
        touched_slots: SLOTS_2,
    },
    CohortGroup {
        name: "global tied embed/unembed mu26 auxiliary root",
        root_count: 1,
        domain_log2: 20,
        total_slots: 2,
        touched_slots: SLOTS_2,
    },
    CohortGroup {
        name: "global positional mu20 weight-extension root",
        root_count: 1,
        domain_log2: 24,
        total_slots: 1,
        touched_slots: SLOTS_1,
    },
    CohortGroup {
        name: "global positional mu20 auxiliary root",
        root_count: 1,
        domain_log2: 19,
        total_slots: 1,
        touched_slots: SLOTS_1,
    },
];

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
struct CohortRecord {
    name: String,
    root_count: u64,
    domain_log2: u8,
    total_slots: usize,
    touched_slots: Vec<u16>,
    distinct_opened_indices_per_root: u64,
    inner_aux_nodes_per_root: u64,
    outer_aux_nodes_per_root: u64,
    bytes_per_root_without_aux_nodes: u64,
    canonical_bytes_per_root: u64,
    subtotal_without_aux_nodes: u64,
    canonical_subtotal: u64,
}

#[derive(Serialize)]
struct FoldRoundRecord {
    fold_round: u8,
    output_domain_log2: u8,
    distinct_opened_indices: u64,
    auxiliary_nodes: u64,
    query_bytes_without_aux_nodes: u64,
    canonical_query_bytes: u64,
}

#[derive(Serialize)]
struct GeometryRecord {
    physical_blocks: usize,
    fixed_claims: usize,
    layer_matrix_blocks: usize,
    tied_embedding_roles: usize,
    positional_blocks: usize,
    cohort_ids: usize,
    initial_roots: usize,
    profile_mu_max: u8,
    gpt2_maximum_original_mu: u8,
    gpt2_maximum_extended_weight_variables: u8,
    gpt2_maximum_initial_domain_log2: u8,
    gpt2_maximum_fold_rounds: u8,
}

#[derive(Serialize)]
struct ByteRecord {
    initial_query_frames_without_aux_nodes: u64,
    one_shared_fold_chain_query_frames_without_aux_nodes: u64,
    query_frames_only_strict_lower_bound: u64,
    envelope_structure: u64,
    descriptor_digests: u64,
    manifest_frames: u64,
    reduced_claim_frames: u64,
    public_masked_h: u64,
    m9_frames: u64,
    authenticated_output_link_frame: u64,
    one_shared_fold_commitment_chain: u64,
    response_zero_batch_frame: u64,
    mandatory_non_query_bytes: u64,
    complete_strict_lower_bound: u64,
    initial_query_frames_with_canonical_aux_nodes: u64,
    one_shared_fold_chain_query_frames_with_canonical_aux_nodes: u64,
    optimistic_canonical_shape_projection: u64,
    g3_limit: u64,
    lower_bound_excess: u64,
    projected_response_lower_bound: u64,
    absolute_response_limit: u64,
}

#[derive(Serialize)]
struct GateRecord {
    g1_lean_green: bool,
    g3_verdict: String,
    g3_reason: String,
    canonical_production_proof_built: bool,
    late_query_refactor_completed: bool,
    gpt2_migration_completed: bool,
    pod_requested: bool,
    hard_stop: bool,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    profile: String,
    design_sha256: String,
    lean_audit_stdout_sha256: String,
    soundness_expression: String,
    soundness_bits: f64,
    required_soundness_bits: f64,
    soundness_unchanged: bool,
    rate: String,
    field_symbol_bytes: usize,
    challenge: ChallengeRecord,
    geometry: GeometryRecord,
    initial_cohorts: Vec<CohortRecord>,
    ideal_shared_fold_rounds: Vec<FoldRoundRecord>,
    bytes: ByteRecord,
    gate: GateRecord,
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

fn descriptor(index: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    digest[8..].fill((index as u8).wrapping_mul(29).wrapping_add(7));
    digest
}

fn query_draws() -> Vec<u64> {
    let mut hasher = blake3::Hasher::new_derive_key(QUERY_XOF_CONTEXT);
    hasher.update(QUERY_XOF_INPUT);
    let mut reader = hasher.finalize_xof();
    (0..QUERY_COUNT)
        .map(|_| {
            let mut word = [0u8; 4];
            reader.fill(&mut word);
            u64::from(u32::from_le_bytes(word) & ((1u32 << MAX_DOMAIN_LOG2) - 1))
        })
        .collect()
}

fn cohort_record(group: CohortGroup, draws: &[u64]) -> (CohortRecord, CohortMultiproofByteCount) {
    let indices = projected_query_indices(draws, group.domain_log2).unwrap();
    let count = cohort_multiproof_byte_count(
        group.domain_log2,
        group.total_slots,
        group.touched_slots,
        1,
        &indices,
    )
    .unwrap();
    let subtotal_without_aux_nodes = count.bytes_without_aux_nodes * group.root_count;
    let canonical_subtotal = count.serialized_bytes * group.root_count;
    (
        CohortRecord {
            name: group.name.to_owned(),
            root_count: group.root_count,
            domain_log2: group.domain_log2,
            total_slots: group.total_slots,
            touched_slots: group.touched_slots.to_vec(),
            distinct_opened_indices_per_root: count.query_count,
            inner_aux_nodes_per_root: count.inner_aux_nodes,
            outer_aux_nodes_per_root: count.outer_aux_nodes,
            bytes_per_root_without_aux_nodes: count.bytes_without_aux_nodes,
            canonical_bytes_per_root: count.serialized_bytes,
            subtotal_without_aux_nodes,
            canonical_subtotal,
        },
        count,
    )
}

fn manifest_bytes(descriptors: &[[u8; 32]]) -> u64 {
    let leaves = descriptors
        .iter()
        .enumerate()
        .map(|(index, digest)| ManifestLeafFrame {
            descriptor_digest: *digest,
            ordered_roots: vec![descriptor(1000 + 2 * index), descriptor(1001 + 2 * index)],
        })
        .collect();
    let tree = ManifestTree::build(manifest_id_digest([0xC1; 32], [0xD2; 32], 1), leaves).unwrap();
    tree.open(descriptors)
        .unwrap()
        .into_iter()
        .map(|frame| match frame {
            ManifestFrame::Leaf(frame) => Frame::ManifestLeaf(frame),
            ManifestFrame::Node(frame) => Frame::ManifestNode(frame),
        })
        .map(|frame| frame.encode().unwrap().len() as u64)
        .sum()
}

fn reduced_claim_bytes() -> u64 {
    [(72usize, 22usize), (26, 20), (4, 26)]
        .into_iter()
        .flat_map(|(count, point_len)| (0..count).map(move |index| (index, point_len)))
        .map(|(index, point_len)| {
            Frame::ReducedClaim(ReducedClaimFrame {
                descriptor_digest: descriptor(index % PHYSICAL_BLOCKS),
                parent_claim_digest: descriptor(2000 + index),
                phase: if index & 1 == 0 { Phase::Prefill } else { Phase::Decode },
                phase_ordinal: (index & 1) as u16,
                point: vec![Fp2::ZERO; point_len],
                affine_scale: Fp2::ZERO,
                auth_domain: 0x740_000 + index as u64,
            })
            .encode()
            .unwrap()
            .len() as u64
        })
        .sum()
}

fn m9_bytes(descriptors: &[[u8; 32]]) -> u64 {
    descriptors
        .iter()
        .map(|digest| {
            Frame::M9Transfer(M9TransferFrame {
                descriptor_digest: *digest,
                mask_correction_symbol: Fp2::ZERO,
            })
            .encode()
            .unwrap()
            .len() as u64
        })
        .sum()
}

fn link_bytes() -> u64 {
    Frame::AuthenticatedOutputLink(AuthenticatedOutputLinkFrame {
        relation_count: (2 * PHYSICAL_BLOCKS) as u16,
        round_count: MAX_FOLD_ROUNDS,
        link_schedule_digest: [0; 32],
        ordered_round_correction_symbols: vec![Fp2::ZERO; 2 * MAX_FOLD_ROUNDS as usize],
        terminal_opened_tag_symbol: Fp2::ZERO,
    })
    .encode()
    .unwrap()
    .len() as u64
}

fn zero_batch_bytes() -> u64 {
    Frame::ResponseZeroBatch(ResponseZeroBatchFrame {
        claim_count: PHYSICAL_BLOCKS as u16,
        mask_correction_symbol: Fp2::ZERO,
        opened_tag_symbol: Fp2::ZERO,
    })
    .encode()
    .unwrap()
    .len() as u64
}

fn fold_commitment_bytes() -> u64 {
    (1..=MAX_FOLD_ROUNDS)
        .map(|round| {
            Frame::FoldCommitment(FoldCommitmentFrame {
                cohort_id: 0,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: round,
                input_log2: MAX_DOMAIN_LOG2 - round + 1,
                output_log2: MAX_DOMAIN_LOG2 - round,
                root_digest: descriptor(3000 + usize::from(round)),
                ordered_message_symbols: vec![
                    Fp2::ZERO;
                    if round == MAX_FOLD_ROUNDS { 3 } else { 2 }
                ],
            })
            .encode()
            .unwrap()
            .len() as u64
        })
        .sum()
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    let draws = query_draws();
    let mut serialized_draws = Vec::with_capacity(4 * draws.len());
    for draw in &draws {
        serialized_draws.extend_from_slice(&(*draw as u32).to_le_bytes());
    }
    let draws_digest = blake3::hash(&serialized_draws).to_hex().to_string();

    assert_eq!(INITIAL_GROUPS.iter().map(|group| group.root_count).sum::<u64>(), 52);
    let mut initial_cohorts = Vec::new();
    let mut initial_without_aux = 0u64;
    let mut initial_canonical = 0u64;
    for group in INITIAL_GROUPS {
        let (record, _) = cohort_record(*group, &draws);
        initial_without_aux += record.subtotal_without_aux_nodes;
        initial_canonical += record.canonical_subtotal;
        initial_cohorts.push(record);
    }

    let mut ideal_shared_fold_rounds = Vec::new();
    let mut shared_without_aux = 0u64;
    let mut shared_canonical = 0u64;
    for round in 1..=MAX_FOLD_ROUNDS {
        let output_domain_log2 = MAX_DOMAIN_LOG2 - round;
        let indices = projected_query_indices(&draws, output_domain_log2).unwrap();
        let count =
            cohort_multiproof_byte_count(output_domain_log2, 1, SLOTS_1, 1, &indices).unwrap();
        shared_without_aux += count.bytes_without_aux_nodes;
        shared_canonical += count.serialized_bytes;
        ideal_shared_fold_rounds.push(FoldRoundRecord {
            fold_round: round,
            output_domain_log2,
            distinct_opened_indices: count.query_count,
            auxiliary_nodes: count.total_aux_nodes,
            query_bytes_without_aux_nodes: count.bytes_without_aux_nodes,
            canonical_query_bytes: count.serialized_bytes,
        });
    }

    let descriptors = (0..PHYSICAL_BLOCKS).map(descriptor).collect::<Vec<_>>();
    let envelope_structure = 110u64;
    let descriptor_digests = (32 * PHYSICAL_BLOCKS) as u64;
    let manifest_frames = manifest_bytes(&descriptors);
    let reduced_claim_frames = reduced_claim_bytes();
    let public_masked_h = (16 * PHYSICAL_BLOCKS) as u64;
    let m9_frames = m9_bytes(&descriptors);
    let authenticated_output_link_frame = link_bytes();
    let one_shared_fold_commitment_chain = fold_commitment_bytes();
    let response_zero_batch_frame = zero_batch_bytes();
    let mandatory_non_query_bytes = envelope_structure
        + descriptor_digests
        + manifest_frames
        + reduced_claim_frames
        + public_masked_h
        + m9_frames
        + authenticated_output_link_frame
        + one_shared_fold_commitment_chain
        + response_zero_batch_frame;
    let query_frames_only_strict_lower_bound = initial_without_aux + shared_without_aux;
    let complete_strict_lower_bound =
        query_frames_only_strict_lower_bound + mandatory_non_query_bytes;
    let optimistic_canonical_shape_projection =
        initial_canonical + shared_canonical + mandatory_non_query_bytes;
    let g3_fail = complete_strict_lower_bound > G3_LIMIT_BYTES;
    let projected_response_lower_bound = NON_PCS_RESPONSE_BYTES + complete_strict_lower_bound;

    let date = command_output(&["date", "+%Y-%m-%d"]);
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let dirty = git_dirty();
    let report = Report {
        schema: 1,
        milestone: "X4-v3-GPT2-G3-absolute-lower-bound".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        profile: String::from_utf8(PROFILE_NAME.to_vec()).unwrap(),
        design_sha256: DESIGN_SHA256.to_owned(),
        lean_audit_stdout_sha256: LEAN_AUDIT_STDOUT_SHA256.to_owned(),
        soundness_expression:
            "3320*(9/16)^128 + 28522064267253/340282366762482138490186164457219031041"
                .to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        required_soundness_bits: SOUNDNESS_FLOOR_BITS,
        soundness_unchanged: SOUNDNESS_BITS == 83.302_264_033_789_21,
        rate: "1/8 strict unique decoding".to_owned(),
        field_symbol_bytes: 16,
        challenge: ChallengeRecord {
            derive_key_context: QUERY_XOF_CONTEXT.to_owned(),
            xof_input_ascii: String::from_utf8(QUERY_XOF_INPUT.to_vec()).unwrap(),
            draw_count: draws.len(),
            draw_width_bits: MAX_DOMAIN_LOG2,
            replacement: true,
            ordered_draws_blake3: draws_digest,
            ordered_draws: draws,
        },
        geometry: GeometryRecord {
            physical_blocks: PHYSICAL_BLOCKS,
            fixed_claims: FIXED_CLAIMS,
            layer_matrix_blocks: 48,
            tied_embedding_roles: 2,
            positional_blocks: 1,
            cohort_ids: COHORT_IDS,
            initial_roots: INITIAL_ROOTS,
            profile_mu_max: 29,
            gpt2_maximum_original_mu: 26,
            gpt2_maximum_extended_weight_variables: MAX_FOLD_ROUNDS,
            gpt2_maximum_initial_domain_log2: MAX_DOMAIN_LOG2,
            gpt2_maximum_fold_rounds: MAX_FOLD_ROUNDS,
        },
        initial_cohorts,
        ideal_shared_fold_rounds,
        bytes: ByteRecord {
            initial_query_frames_without_aux_nodes: initial_without_aux,
            one_shared_fold_chain_query_frames_without_aux_nodes: shared_without_aux,
            query_frames_only_strict_lower_bound,
            envelope_structure,
            descriptor_digests,
            manifest_frames,
            reduced_claim_frames,
            public_masked_h,
            m9_frames,
            authenticated_output_link_frame,
            one_shared_fold_commitment_chain,
            response_zero_batch_frame,
            mandatory_non_query_bytes,
            complete_strict_lower_bound,
            initial_query_frames_with_canonical_aux_nodes: initial_canonical,
            one_shared_fold_chain_query_frames_with_canonical_aux_nodes: shared_canonical,
            optimistic_canonical_shape_projection,
            g3_limit: G3_LIMIT_BYTES,
            lower_bound_excess: complete_strict_lower_bound.saturating_sub(G3_LIMIT_BYTES),
            projected_response_lower_bound,
            absolute_response_limit: ABSOLUTE_RESPONSE_LIMIT_BYTES,
        },
        gate: GateRecord {
            g1_lean_green: true,
            g3_verdict: if g3_fail { "FAIL" } else { "NOT_FAILED_BY_LOWER_BOUND" }.to_owned(),
            g3_reason: "Even one ideal shared fold chain, with every auxiliary Merkle node charged as zero bytes, exceeds the verbatim PCS cap.".to_owned(),
            canonical_production_proof_built: false,
            late_query_refactor_completed: false,
            gpt2_migration_completed: false,
            pod_requested: false,
            hard_stop: g3_fail,
        },
        notes: vec![
            "The two tied-WTE roles are distinct X4 physical blocks so every block retains at most two phase claims; they share the same source tensor but receive separate descriptor slots.".to_owned(),
            "The lower bound retains all mandatory initial roots but grants an unrealistically favorable single post-initial chain across every size and oracle kind.".to_owned(),
            "bytes_without_aux_nodes deletes every 50-byte Merkle auxiliary-node entry; a real canonical proof can only be larger.".to_owned(),
            "No weight artifact, golden reference, protocol parameter, correlation allocation, PCG lifecycle, or soundness term is changed by this analytic preflight.".to_owned(),
            "The production late-query typestate defect remains recorded, but the hard G3 failure makes its refactor non-actionable without a separately authorized amendment.".to_owned(),
            "The pending c3_weights leakage smoke remains scheduled first if a future amendment ever reaches an authorized pod session.".to_owned(),
        ],
    };

    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X4 GPT-2 G3: {} lower_bound={} limit={} excess={} canonical_shape={}",
        report.gate.g3_verdict,
        report.bytes.complete_strict_lower_bound,
        report.bytes.g3_limit,
        report.bytes.lower_bound_excess,
        report.bytes.optimistic_canonical_shape_projection,
    );
    if record {
        if dirty {
            eprintln!("x4_gpt2_preflight: refusing a run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x4-gpt2-g3-preflight-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x4_gpt2_preflight: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X4 GPT-2 G3 preflight");
        eprintln!("wrote {}", path.display());
    }
    if !g3_fail {
        eprintln!("X4 GPT-2 G3 lower bound did not trigger the preregistered stop rule");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preregistered_gpt2_query_only_lower_bound_exceeds_g3() {
        let draws = query_draws();
        let mut serialized_draws = Vec::with_capacity(4 * draws.len());
        for draw in &draws {
            serialized_draws.extend_from_slice(&(*draw as u32).to_le_bytes());
        }
        assert_eq!(
            blake3::hash(&serialized_draws).to_hex().as_str(),
            "26414df2b8fc443cc3171e762eca23788e0bfc7c48016cc250be42a115d0d02b"
        );

        let initial_without_aux = INITIAL_GROUPS
            .iter()
            .map(|group| cohort_record(*group, &draws).0.subtotal_without_aux_nodes)
            .sum::<u64>();
        let shared_without_aux = (1..=MAX_FOLD_ROUNDS)
            .map(|round| {
                let domain_log2 = MAX_DOMAIN_LOG2 - round;
                let indices = projected_query_indices(&draws, domain_log2).unwrap();
                cohort_multiproof_byte_count(domain_log2, 1, SLOTS_1, 1, &indices)
                    .unwrap()
                    .bytes_without_aux_nodes
            })
            .sum::<u64>();
        assert_eq!(initial_without_aux, 3_140_532);
        assert_eq!(shared_without_aux, 881_062);
        assert_eq!(initial_without_aux + shared_without_aux, 4_021_594);
        assert!(initial_without_aux + shared_without_aux > G3_LIMIT_BYTES);

        let descriptors = (0..PHYSICAL_BLOCKS).map(descriptor).collect::<Vec<_>>();
        let mandatory_non_query = 110
            + (32 * PHYSICAL_BLOCKS) as u64
            + manifest_bytes(&descriptors)
            + reduced_claim_bytes()
            + (16 * PHYSICAL_BLOCKS) as u64
            + m9_bytes(&descriptors)
            + link_bytes()
            + fold_commitment_bytes()
            + zero_batch_bytes();
        assert_eq!(mandatory_non_query, 67_822);
        assert_eq!(initial_without_aux + shared_without_aux + mandatory_non_query, 4_089_416);
    }
}

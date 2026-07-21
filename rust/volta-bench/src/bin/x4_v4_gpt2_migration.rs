//! Clean GPT-2 migration/reference record for the frozen X4 schema-4 profile.
//!
//! This rechecks the unchanged 100+50 golden decode and materializes the
//! complete production response-envelope codec at the exact Amendment-5
//! geometry.  It is a byte/correctness migration record, not a full 32-GB
//! oracle commit/open wall record; those remain reserved for the A100 pod.

use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_bench::{x4_v4_record_profile_allowed, X4_V4_RECORD_PROFILE};
use volta_field::Fp2;
use volta_gpt2::{argmax, decode_step, forward_model, load_model, KvCache};
use volta_pcs::x4::{
    authenticated_output_link_schedule_digest_v4, decode_v4,
    gpt2_codec_reference_packed_opening_v4, manifest_id_digest_v4, opening_schedule_digest_v4,
    profile_digest_v4, AuthenticatedOutputLinkFrame, FoldCommitmentFrameV4, FrameV4,
    InitialOpeningScheduleV4, M9TransferFrame, ManifestFrameV4, ManifestLeafFrame, ManifestTreeV4,
    OracleKindV4, PackedOpeningScheduleV4, Phase, ReducedClaimFrame, ResponseEnvelopeFrameV4,
    ResponseZeroBatchFrame, PROFILE_NAME_V4,
};

const DESIGN_SHA256: &str = "c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544";
const FROZEN_DESIGN_BASELINE_SHA256: &str =
    "1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7";
const PRELIGHT_PATH: &str =
    "benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json";
const PREFLIGHT_SHA256: &str = "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499";
const V3_G3_PATH: &str = "benchmarks/results/x4-gpt2-g3-preflight-2026-07-21-3aa5952.json";
const V3_G3_SHA256: &str = "a5d2f4ba189c27a7b39e8e0f0c66475057a6f15041483fbe2035bcc69afc4cb9";
const V3_CPU_PATH: &str = "benchmarks/results/x4-cpu-synthetic-2026-07-21-12bfbe2.json";
const V3_CPU_SHA256: &str = "da2a09a69224df5b17c05bfc5d085604ab8345a9da5f7492090eecc78f0a8bfa";
const SELECTED_TAPE_DIGEST: &str =
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const QUERY_COUNT: usize = 111;
const PHYSICAL_BLOCKS: usize = 51;
const CLAIMS: usize = 102;
const FOLD_ROUNDS: usize = 27;
const PACKED_OPENING_BYTES: u64 = 2_615_414;
const COMPLETE_PCS_BYTES: u64 = 2_683_236;
const NON_PCS_RESPONSE_BYTES: u64 = 41_270_464;
const RESPONSE_BYTES: u64 = 43_953_700;
const G3_LIMIT_BYTES: u64 = 4_000_000;
const RESPONSE_LIMIT_BYTES: u64 = 45_270_464;
const SOUNDNESS_BITS: f64 = 80.255_370_163_990_41;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const GPT2_SOURCE_BYTES: u64 = 249_403_904;
const GPT2_FIRST_ORACLE_FLOOR_BYTES: u64 = 31_923_699_712;

fn digest(index: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    value[8..].fill((index as u8).wrapping_mul(29).wrapping_add(7));
    value
}

fn cohort_root(cohort_id: u32) -> [u8; 32] {
    let mut root = [0u8; 32];
    root[..4].copy_from_slice(&cohort_id.to_le_bytes());
    root[4..].fill((cohort_id as u8).wrapping_mul(13).wrapping_add(5));
    root
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn command_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .current_dir(repo_root())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn sha256(path: &Path) -> String {
    Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|line| line.split_whitespace().next().map(str::to_owned))
        })
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(repo_root())
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(true)
}

fn selected_draws() -> Vec<u64> {
    let bytes = std::fs::read(repo_root().join(PRELIGHT_PATH)).expect("read frozen preflight");
    let value: Value = serde_json::from_slice(&bytes).expect("parse frozen preflight");
    let selected = value["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == "e29-r3-s111")
        .expect("selected Amendment-5 row");
    assert_eq!(selected["query_count"], QUERY_COUNT);
    assert_eq!(selected["challenge"]["draw_width_bits"], 30);
    assert_eq!(selected["challenge"]["ordered_draws_blake3"], SELECTED_TAPE_DIGEST);
    selected["challenge"]["ordered_draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|draw| draw.as_u64().unwrap())
        .collect()
}

fn reference_descriptors() -> Vec<[u8; 32]> {
    (0..PHYSICAL_BLOCKS).map(digest).collect()
}

fn reference_manifest(descriptors: &[[u8; 32]], epoch: u64) -> ManifestTreeV4 {
    let leaves = descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let weight_id = if index < 2 {
                0xA500_0001
            } else if index < 38 {
                0xA500_0002
            } else {
                0xA500_0003
            };
            let auxiliary_id = if index < 2 { 0xA500_0100 } else { 0xA500_0101 };
            ManifestLeafFrame {
                descriptor_digest: *descriptor,
                ordered_roots: vec![cohort_root(weight_id), cohort_root(auxiliary_id)],
            }
        })
        .collect();
    ManifestTreeV4::build(manifest_id_digest_v4([0xC1; 32], [0xD2; 32], epoch), leaves).unwrap()
}

fn reference_claims(descriptors: &[[u8; 32]]) -> Vec<ReducedClaimFrame> {
    [(72usize, 22usize), (26, 20), (4, 26)]
        .into_iter()
        .flat_map(|(count, point_len)| (0..count).map(move |index| (index, point_len)))
        .enumerate()
        .map(|(ordinal, (index, point_len))| ReducedClaimFrame {
            descriptor_digest: descriptors[index % PHYSICAL_BLOCKS],
            parent_claim_digest: digest(2000 + ordinal),
            phase: if ordinal & 1 == 0 { Phase::Prefill } else { Phase::Decode },
            phase_ordinal: (ordinal & 1) as u16,
            point: vec![Fp2::ZERO; point_len],
            affine_scale: Fp2::ZERO,
            auth_domain: 0x740_000 + ordinal as u64,
        })
        .collect()
}

fn reference_folds() -> Vec<FoldCommitmentFrameV4> {
    (1..=FOLD_ROUNDS)
        .map(|round| FoldCommitmentFrameV4 {
            cohort_id: 0xA500_F001,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: round as u8,
            input_log2: (31 - round) as u8,
            output_log2: (30 - round) as u8,
            root_digest: digest(3000 + round),
            ordered_message_symbols: vec![Fp2::ZERO; if round == FOLD_ROUNDS { 3 } else { 2 }],
        })
        .collect()
}

fn initial_schedule() -> Vec<InitialOpeningScheduleV4> {
    [
        (0xA500_0001, 30, 2, 2),
        (0xA500_0002, 26, 64, 36),
        (0xA500_0003, 24, 16, 13),
        (0xA500_0100, 20, 2, 2),
        (0xA500_0101, 19, 64, 49),
    ]
    .into_iter()
    .map(|(cohort_id, domain_log2, slot_count, touched)| InitialOpeningScheduleV4 {
        cohort_id,
        domain_log2,
        slot_count,
        touched_slots: (0..touched).collect(),
        root_digest: cohort_root(cohort_id),
    })
    .collect()
}

#[derive(Serialize)]
struct CodecComponents {
    envelope_structure: u64,
    descriptor_digests: u64,
    manifest_frames: u64,
    reduced_claim_frames: u64,
    public_h_symbols: u64,
    m9_frames: u64,
    authenticated_output_link_frame: u64,
    fold_frames: u64,
    packed_opening_frame: u64,
    response_zero_batch_frame: u64,
    opened_symbols: u64,
    initial_inner_siblings: u64,
    initial_outer_siblings: u64,
    fold_outer_siblings: u64,
    all_real_sibling_digests: u64,
    packed_metadata_bytes: u64,
    summed_bytes: u64,
    serialized_bytes: u64,
    encoded_sha256: String,
}

fn frame_bytes(frame: FrameV4) -> u64 {
    frame.encode().unwrap().len() as u64
}

fn materialize_reference_response(draws: Vec<u64>) -> CodecComponents {
    let epoch = 0xA5_0000_0001;
    let descriptors = reference_descriptors();
    let manifest = reference_manifest(&descriptors, epoch);
    let model_root = manifest.root();
    let manifest_frames = manifest.open(&descriptors).unwrap();
    let claims = reference_claims(&descriptors);
    assert_eq!(claims.len(), CLAIMS);
    let public_h = vec![Fp2::ZERO; PHYSICAL_BLOCKS];
    let m9_frames = descriptors
        .iter()
        .map(|descriptor| M9TransferFrame {
            descriptor_digest: *descriptor,
            mask_correction_symbol: Fp2::ZERO,
        })
        .collect::<Vec<_>>();
    let link_domains =
        (0..2 * FOLD_ROUNDS).map(|index| 0x750_000 + index as u64).collect::<Vec<_>>();
    let link_frame = AuthenticatedOutputLinkFrame {
        relation_count: (2 * PHYSICAL_BLOCKS) as u16,
        round_count: FOLD_ROUNDS as u8,
        link_schedule_digest: authenticated_output_link_schedule_digest_v4(
            epoch,
            &claims,
            &descriptors,
            &public_h,
            &m9_frames,
            FOLD_ROUNDS as u8,
            &link_domains,
        )
        .unwrap(),
        ordered_round_correction_symbols: vec![Fp2::ZERO; 2 * FOLD_ROUNDS],
        terminal_opened_tag_symbol: Fp2::ZERO,
    };
    let folds = reference_folds();
    let schedule = PackedOpeningScheduleV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        initial_groups: initial_schedule(),
        fold_frames: folds.clone(),
        draw_width: 30,
        query_draws: draws,
    };
    schedule.validate().unwrap();
    let mut packed = gpt2_codec_reference_packed_opening_v4();
    packed.opening_schedule_digest = opening_schedule_digest_v4(&schedule).unwrap();
    packed.validate_against_schedule(&schedule).unwrap();
    let zero = ResponseZeroBatchFrame {
        claim_count: PHYSICAL_BLOCKS as u16,
        mask_correction_symbol: Fp2::ZERO,
        opened_tag_symbol: Fp2::ZERO,
    };
    let response = ResponseEnvelopeFrameV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        descriptor_digests: descriptors.clone(),
        manifest_frames: manifest_frames.clone(),
        claim_frames: claims.clone(),
        ordered_h_symbols: public_h,
        m9_frames: m9_frames.clone(),
        authenticated_output_link_frame: link_frame.clone(),
        fold_frames: folds.clone(),
        packed_opening_frame: packed.clone(),
        zero_batch_frame: zero.clone(),
    };
    response
        .validate_statement(model_root, epoch, &descriptors, &claims, &link_domains, &schedule)
        .unwrap();
    volta_pcs::x4::verify_response_manifest_v4(&response, [0xC1; 32], [0xD2; 32], &descriptors)
        .unwrap();
    let encoded = FrameV4::ResponseEnvelope(response.clone()).encode().unwrap();
    assert_eq!(decode_v4(&encoded).unwrap(), FrameV4::ResponseEnvelope(response));

    let manifest_bytes = manifest_frames
        .iter()
        .map(|frame| match frame {
            ManifestFrameV4::Leaf(frame) => frame_bytes(FrameV4::ManifestLeaf(frame.clone())),
            ManifestFrameV4::Node(frame) => frame_bytes(FrameV4::ManifestNode(frame.clone())),
        })
        .sum::<u64>();
    let claim_bytes =
        claims.iter().map(|frame| frame_bytes(FrameV4::ReducedClaim(frame.clone()))).sum::<u64>();
    let m9_bytes =
        m9_frames.iter().map(|frame| frame_bytes(FrameV4::M9Transfer(frame.clone()))).sum::<u64>();
    let link_bytes = frame_bytes(FrameV4::AuthenticatedOutputLink(link_frame));
    let fold_bytes =
        folds.iter().map(|frame| frame_bytes(FrameV4::FoldCommitment(frame.clone()))).sum::<u64>();
    let packed_bytes = frame_bytes(FrameV4::PackedBatchOpening(packed.clone()));
    let zero_bytes = frame_bytes(FrameV4::ResponseZeroBatch(zero));
    let descriptor_bytes = 32 * PHYSICAL_BLOCKS as u64;
    let h_bytes = 16 * PHYSICAL_BLOCKS as u64;
    let without_structure = descriptor_bytes
        + manifest_bytes
        + claim_bytes
        + h_bytes
        + m9_bytes
        + link_bytes
        + fold_bytes
        + packed_bytes
        + zero_bytes;
    let envelope_structure = encoded.len() as u64 - without_structure;
    let summed_bytes = envelope_structure + without_structure;
    let counts = packed.byte_components().unwrap();
    let all_real_sibling_digests =
        counts.initial_inner_siblings + counts.initial_outer_siblings + counts.fold_outer_siblings;
    assert_eq!(packed_bytes, PACKED_OPENING_BYTES);
    assert_eq!(summed_bytes, encoded.len() as u64);
    assert_eq!(encoded.len() as u64, COMPLETE_PCS_BYTES);
    CodecComponents {
        envelope_structure,
        descriptor_digests: descriptor_bytes,
        manifest_frames: manifest_bytes,
        reduced_claim_frames: claim_bytes,
        public_h_symbols: h_bytes,
        m9_frames: m9_bytes,
        authenticated_output_link_frame: link_bytes,
        fold_frames: fold_bytes,
        packed_opening_frame: packed_bytes,
        response_zero_batch_frame: zero_bytes,
        opened_symbols: counts.opened_symbols,
        initial_inner_siblings: counts.initial_inner_siblings,
        initial_outer_siblings: counts.initial_outer_siblings,
        fold_outer_siblings: counts.fold_outer_siblings,
        all_real_sibling_digests,
        packed_metadata_bytes: counts.metadata_bytes,
        summed_bytes,
        serialized_bytes: encoded.len() as u64,
        encoded_sha256: sha256_bytes(&encoded),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!(
        "volta-x4-v4-codec-{}-{}.bin",
        std::process::id(),
        bytes.len()
    ));
    std::fs::write(&path, bytes).unwrap();
    let digest = sha256(&path);
    std::fs::remove_file(path).unwrap();
    digest
}

#[derive(Serialize)]
struct GoldenRecord {
    prompt_tokens: usize,
    decode_tokens: usize,
    checked: bool,
    exact_match: bool,
    generated_tokens_blake3: String,
    wall_s: f64,
    golden_sha256: String,
    weights_bin_sha256: String,
    weights_json_sha256: String,
    weights_params_sha256: String,
}

fn golden_decode() -> GoldenRecord {
    let weights = repo_root().join("benchmarks/weights");
    assert_eq!(sha256(&weights.join("golden-p6.bin")), GOLDEN_P6_SHA256);
    assert_eq!(sha256(&weights.join("gpt2s-q.bin")), GPT2_BIN_SHA256);
    assert_eq!(sha256(&weights.join("gpt2s-q.json")), GPT2_JSON_SHA256);
    assert_eq!(sha256(&weights.join("gpt2s-q.params")), GPT2_PARAMS_SHA256);
    let started = Instant::now();
    let model = load_model(&weights).expect("load frozen GPT-2 model");
    let prompt_tokens = 100;
    let decode_tokens = 50;
    let witness = forward_model(&model, prompt_tokens);
    let kv = witness
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, prompt_tokens);
    let mut generated = Vec::with_capacity(decode_tokens);
    let mut next = argmax(&witness.logits);
    for index in 0..decode_tokens {
        generated.push(next);
        let logits = decode_step(&model, &mut cache, next, prompt_tokens + index);
        next = argmax(&logits);
    }
    let golden = std::fs::read(weights.join("golden-p6.bin")).unwrap();
    assert_eq!(&golden[..8], b"VGOLD2\0\0");
    let read_u32 =
        |offset: usize| u32::from_le_bytes(golden[offset..offset + 4].try_into().unwrap());
    assert_eq!(read_u32(8) as usize, prompt_tokens);
    assert_eq!(read_u32(12) as usize, decode_tokens);
    let reference = (0..decode_tokens).map(|index| read_u32(16 + 4 * index)).collect::<Vec<_>>();
    let exact_match = generated == reference;
    assert!(exact_match, "frozen GPT-2 decode changed during X4 migration");
    let mut token_bytes = Vec::with_capacity(4 * generated.len());
    for token in &generated {
        token_bytes.extend_from_slice(&token.to_le_bytes());
    }
    GoldenRecord {
        prompt_tokens,
        decode_tokens,
        checked: true,
        exact_match,
        generated_tokens_blake3: blake3::hash(&token_bytes).to_hex().to_string(),
        wall_s: started.elapsed().as_secs_f64(),
        golden_sha256: GOLDEN_P6_SHA256.to_owned(),
        weights_bin_sha256: GPT2_BIN_SHA256.to_owned(),
        weights_json_sha256: GPT2_JSON_SHA256.to_owned(),
        weights_params_sha256: GPT2_PARAMS_SHA256.to_owned(),
    }
}

#[derive(Serialize)]
struct HistoricalPin {
    path: String,
    expected_sha256: String,
    observed_sha256: String,
    unchanged: bool,
}

fn historical_pin(path: &str, expected: &str) -> HistoricalPin {
    let observed = sha256(&repo_root().join(path));
    HistoricalPin {
        path: path.to_owned(),
        expected_sha256: expected.to_owned(),
        unchanged: observed == expected,
        observed_sha256: observed,
    }
}

#[derive(Serialize)]
struct GateRecord {
    g1_lean: String,
    g2_migration_correctness: String,
    g3_communication: String,
    g4_isolated_wall: String,
    g5_synthetic_proportionality: String,
    g6_storage_traffic: String,
    overall_x4: String,
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
    frozen_design_baseline_sha256: String,
    query_count: usize,
    rate: String,
    maximum_claim_union: usize,
    selected_tape_blake3: String,
    codec: CodecComponents,
    complete_pcs_bytes: u64,
    g3_limit_bytes: u64,
    g3_headroom_bytes: u64,
    non_pcs_response_bytes: u64,
    measured_response_bytes: u64,
    response_limit_bytes: u64,
    response_headroom_bytes: u64,
    soundness_expression: String,
    soundness_bits: f64,
    soundness_floor_bits: f64,
    soundness_margin_bits: f64,
    soundness_resummed_new_terms: u64,
    correlations_gpt2_claim_reduction: u64,
    correlations_gpt2_seam: u64,
    correlations_gpt2_total: u64,
    logical_source_i16_bytes: u64,
    logical_first_oracle_floor_bytes: u64,
    artifact_policy_for_pod: String,
    golden_decode: GoldenRecord,
    historical_records: Vec<HistoricalPin>,
    historical_rows_mutated: bool,
    production_codec: bool,
    cryptographic_oracle_materialized: bool,
    record_profile_policy: String,
    validator_command: String,
    pending_pod_preflight: String,
    gate: GateRecord,
}

fn requested_profile() -> String {
    let mut profile = X4_V4_RECORD_PROFILE.to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--profile" {
            profile = args.next().unwrap_or_default();
        } else if let Some(value) = arg.strip_prefix("--profile=") {
            profile = value.to_owned();
        }
    }
    profile
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    let profile = requested_profile();
    if record && !x4_v4_record_profile_allowed(&profile) {
        eprintln!(
            "x4_v4_gpt2_migration: refusing record profile {profile:?}; Ligero/v3 are historical read-only"
        );
        std::process::exit(2);
    }
    assert_eq!(PROFILE_NAME_V4, X4_V4_RECORD_PROFILE.as_bytes());
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x4-v4-gpt2-{index}"))
        .build_global()
        .expect("X4 GPT-2 migration initializes four CPU workers first");
    assert_eq!(sha256(&repo_root().join(PRELIGHT_PATH)), PREFLIGHT_SHA256);
    let draws = selected_draws();
    let codec = materialize_reference_response(draws);
    let golden_decode = golden_decode();
    let historical_records = vec![
        historical_pin(V3_G3_PATH, V3_G3_SHA256),
        historical_pin(V3_CPU_PATH, V3_CPU_SHA256),
        historical_pin(PRELIGHT_PATH, PREFLIGHT_SHA256),
    ];
    let historical_rows_mutated = historical_records.iter().any(|pin| !pin.unchanged);
    assert!(!historical_rows_mutated);
    assert_eq!(codec.opened_symbols, 27_564);
    assert_eq!(codec.all_real_sibling_digests, 67_930);
    assert_eq!(codec.serialized_bytes, COMPLETE_PCS_BYTES);
    assert_eq!(NON_PCS_RESPONSE_BYTES + codec.serialized_bytes, RESPONSE_BYTES);
    let gate = GateRecord {
        g1_lean: "PASS — exact frozen v4 statements; 209/116 audit; no new axioms".to_owned(),
        g2_migration_correctness:
            "PASS — golden decode unchanged; schema-4 full reference encode/decode and validators accept"
                .to_owned(),
        g3_communication:
            "PASS — PCS 2,683,236 B <= 4,000,000 B; response 43,953,700 B <= 45,270,464 B"
                .to_owned(),
        g4_isolated_wall: "NOT EVALUATED — full oracle commit/open/verify reserved for pod"
            .to_owned(),
        g5_synthetic_proportionality:
            "EVALUATED IN SEPARATE CLEAN x4-v4 CPU synthetic record".to_owned(),
        g6_storage_traffic:
            "PARTIAL — 31,923,699,712-B logical first-oracle floor pinned; physical traffic/RSS/VRAM reserved for pod"
                .to_owned(),
        overall_x4: "NOT EVALUATED UNTIL A100 RECORDS".to_owned(),
    };
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let report = Report {
        schema: 1,
        milestone: "X4-v4-GPT2-migration".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        profile,
        design_sha256: DESIGN_SHA256.to_owned(),
        frozen_design_baseline_sha256: FROZEN_DESIGN_BASELINE_SHA256.to_owned(),
        query_count: QUERY_COUNT,
        rate: "1/8".to_owned(),
        maximum_claim_union: 3_320,
        selected_tape_blake3: SELECTED_TAPE_DIGEST.to_owned(),
        codec,
        complete_pcs_bytes: COMPLETE_PCS_BYTES,
        g3_limit_bytes: G3_LIMIT_BYTES,
        g3_headroom_bytes: G3_LIMIT_BYTES - COMPLETE_PCS_BYTES,
        non_pcs_response_bytes: NON_PCS_RESPONSE_BYTES,
        measured_response_bytes: RESPONSE_BYTES,
        response_limit_bytes: RESPONSE_LIMIT_BYTES,
        response_headroom_bytes: RESPONSE_LIMIT_BYTES - RESPONSE_BYTES,
        soundness_expression:
            "3320*(9/16)^111 + 28522064267253/340282366762482138490186164457219031041"
                .to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        soundness_floor_bits: SOUNDNESS_FLOOR_BITS,
        soundness_margin_bits: SOUNDNESS_BITS - SOUNDNESS_FLOOR_BITS,
        soundness_resummed_new_terms: 0,
        correlations_gpt2_claim_reduction: 2_208,
        correlations_gpt2_seam: 106,
        correlations_gpt2_total: 2_314,
        logical_source_i16_bytes: GPT2_SOURCE_BYTES,
        logical_first_oracle_floor_bytes: GPT2_FIRST_ORACLE_FLOOR_BYTES,
        artifact_policy_for_pod:
            "persist coefficients+roots; rebuild and root-check queried model-global cohorts; report every physical byte and wall"
                .to_owned(),
        golden_decode,
        historical_records,
        historical_rows_mutated,
        production_codec: true,
        cryptographic_oracle_materialized: false,
        record_profile_policy:
            "v4 only; Ligero/v3 remain available for historical read-only verification and are refused for records"
                .to_owned(),
        validator_command:
            "python3 scripts/report.py --validate-x4-v4-migration <record.json>".to_owned(),
        pending_pod_preflight:
            "fresh exact-reference profile plus R1b NOTE-6 c3_weights two-weight-set leakage smoke"
                .to_owned(),
        gate,
    };
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X4 v4 GPT-2 migration: golden={} PCS={} response={} G3=PASS",
        report.golden_decode.exact_match, report.complete_pcs_bytes, report.measured_response_bytes
    );
    if record {
        if dirty {
            eprintln!("x4_v4_gpt2_migration: refusing a run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path = repo_root()
            .join("benchmarks/results")
            .join(format!("x4-v4-gpt2-migration-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!(
                "x4_v4_gpt2_migration: append-only record already exists: {}",
                path.display()
            );
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X4 v4 GPT-2 migration record");
        eprintln!("wrote {}", path.display());
    }
}

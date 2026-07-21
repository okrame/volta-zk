//! X4 v3 CPU synthetic record: exact 128-query M9 link, G5 touched-block
//! family, same-process ABBA unopened-block comparison, and G6 accounting.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::x4::{
    authenticate_pending_aux_prover, authenticate_pending_aux_verifier, evaluate_multilinear_table,
    manifest_id_digest, multilinear_coefficients, profile_digest,
    prove_authenticated_output_link_production, prove_bound_response_zero_batch,
    verify_authenticated_output_link_production, verify_bound_response_zero_batch,
    verify_response_manifest, AuthenticatedOutputBlockProver, AuthenticatedOutputBlockVerifier,
    AuthenticatedOutputLinkPrefix, CohortIdentity, CohortVerifierConfig, Frame,
    LinkCohortChallenges, LinkCohortKey, LinkPolynomialProver, LinkPolynomialVerifier,
    M9TransferFrame, ManifestFrame, ManifestLeafFrame, ManifestTree, OracleKind, Phase,
    ReducedClaimFrame, ResponseEnvelopeFrame, UdArtifactPolicy, UdChallenges, UdCohortArtifactPlan,
    UdCommittedCohort, UdStreamingCommitMetrics, X4OpeningRegistry, PROFILE_NAME,
};

const DESIGN_SHA256: &str = "f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98";
const LEAN_AUDIT_STDOUT_SHA256: &str =
    "4706e705abc1a8df3eeb96df41388c357f2006671cf90116c9c200f29d36d267";
const SOUNDNESS_BITS: f64 = 83.302_264_033_789_21;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const NON_PCS_RESPONSE_BYTES: u64 = 41_270_464;
const QUERIES: usize = 128;
const SYNTHETIC_VARS: usize = 10;
const SYNTHETIC_COEFFICIENTS: usize = 1 << SYNTHETIC_VARS;
const ORIGINAL_WEIGHT_COEFFICIENTS: usize = SYNTHETIC_COEFFICIENTS / 2;

fn symbol(value: u64) -> Fp2 {
    Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(0x9e37).wrapping_add(17)))
}

fn descriptor(index: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    digest[8..].fill((index as u8).wrapping_mul(17).wrapping_add(3));
    digest
}

struct SyntheticFixture {
    total_blocks: usize,
    descriptors: Vec<[u8; 32]>,
    weight_evaluations: Vec<Vec<Fp2>>,
    auxiliary_evaluations: Vec<Vec<Fp2>>,
    weight: UdCommittedCohort,
    auxiliary: UdCommittedCohort,
    artifact_metrics: UdStreamingCommitMetrics,
    commit_s: f64,
}

impl SyntheticFixture {
    fn build(total_blocks: usize) -> Self {
        assert!(total_blocks.is_power_of_two());
        let descriptors = (0..total_blocks).map(descriptor).collect::<Vec<_>>();
        let weight_evaluations = (0..total_blocks)
            .map(|slot| {
                (0..SYNTHETIC_COEFFICIENTS)
                    .map(|index| symbol(10_000 * slot as u64 + index as u64 + 1))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let auxiliary_evaluations = (0..total_blocks)
            .map(|slot| {
                (0..SYNTHETIC_COEFFICIENTS)
                    .map(|index| symbol(900_000 + 20_000 * slot as u64 + 3 * index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let config = |kind, cohort_id| CohortVerifierConfig {
            identity: CohortIdentity { cohort_id, oracle_kind: kind, fold_round: 0 },
            slot_descriptors: descriptors.iter().copied().map(Some).collect(),
            outer_len: 8 * SYNTHETIC_COEFFICIENTS,
            expected_symbol_count: 1,
        };
        let weight_config = config(OracleKind::WeightExtension, 0x4100 + total_blocks as u32);
        let auxiliary_config = config(OracleKind::Auxiliary, 0x4200 + total_blocks as u32);
        let mut artifact_metrics = UdStreamingCommitMetrics::default();
        artifact_metrics
            .include(
                &UdCohortArtifactPlan::new(
                    &weight_config,
                    UdArtifactPolicy::PersistOracleAndMerkle,
                )
                .unwrap(),
            )
            .unwrap();
        artifact_metrics
            .include(
                &UdCohortArtifactPlan::new(
                    &auxiliary_config,
                    UdArtifactPolicy::PersistOracleAndMerkle,
                )
                .unwrap(),
            )
            .unwrap();
        let started = Instant::now();
        let weight = UdCommittedCohort::commit(
            weight_config,
            weight_evaluations
                .iter()
                .map(|table| Some(multilinear_coefficients(table).unwrap()))
                .collect(),
        )
        .unwrap();
        let auxiliary = UdCommittedCohort::commit(
            auxiliary_config,
            auxiliary_evaluations
                .iter()
                .map(|table| Some(multilinear_coefficients(table).unwrap()))
                .collect(),
        )
        .unwrap();
        let commit_s = started.elapsed().as_secs_f64();
        Self {
            total_blocks,
            descriptors,
            weight_evaluations,
            auxiliary_evaluations,
            weight,
            auxiliary,
            artifact_metrics,
            commit_s,
        }
    }
}

#[derive(Clone, Serialize)]
struct ByteComponents {
    envelope_overhead: u64,
    descriptor_digests: u64,
    manifest_frames: u64,
    reduced_claim_frames: u64,
    public_h_symbols: u64,
    m9_frames: u64,
    authenticated_output_link_frame: u64,
    fold_frames: u64,
    query_frames: u64,
    response_zero_batch_frame: u64,
    closed_formula_total: u64,
    serialized_total: u64,
}

#[derive(Clone, Serialize)]
struct CaseRecord {
    total_blocks: usize,
    touched_blocks: usize,
    fixed_claims: usize,
    original_weight_coefficients_total: u64,
    original_weight_coefficients_touched: u64,
    weight_extension_coefficients_read: u64,
    zk_extension_coefficients_read: u64,
    auxiliary_coefficients_read: u64,
    initial_encoded_symbols_read: u64,
    folded_symbols_written: u64,
    full_correlations_prover: u64,
    full_correlations_verifier: u64,
    expected_full_correlations: u64,
    correlation_domains_prover: u64,
    correlation_domains_verifier: u64,
    allocation_digest_match: bool,
    transcript_bytes_prover: u64,
    transcript_bytes_verifier: u64,
    root_hex: String,
    response_digest: String,
    bytes: ByteComponents,
    open_s: f64,
    verify_s: f64,
    accepted: bool,
}

fn frame_bytes(frame: Frame) -> u64 {
    u64::try_from(frame.encode().unwrap().len()).unwrap()
}

fn challenge_set(fixture: &SyntheticFixture, seed_tag: u64) -> Vec<LinkCohortChallenges> {
    let mut entries = [&fixture.weight, &fixture.auxiliary]
        .into_iter()
        .map(|cohort| LinkCohortChallenges {
            key: LinkCohortKey::from_commitment(cohort.commitment()),
            challenges: UdChallenges {
                combine: Fp2::ZERO,
                folds: (0..SYNTHETIC_VARS)
                    .map(|round| symbol(0x8000 + 31 * seed_tag + round as u64))
                    .collect(),
                query_draws: (0..QUERIES)
                    .map(|query| {
                        ((query as u64 * 61) ^ (seed_tag * 131))
                            & (fixture.weight.commitment().config.outer_len as u64 - 1)
                    })
                    .collect(),
            },
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.key);
    entries
}

fn manifest_for(fixture: &SyntheticFixture, epoch: u64) -> ManifestTree {
    let model_config_digest = [0xC1; 32];
    let weights_digest = [0xD2; 32];
    ManifestTree::build(
        manifest_id_digest(model_config_digest, weights_digest, epoch),
        fixture
            .descriptors
            .iter()
            .map(|descriptor| ManifestLeafFrame {
                descriptor_digest: *descriptor,
                ordered_roots: vec![
                    fixture.weight.commitment().root,
                    fixture.auxiliary.commitment().root,
                ],
            })
            .collect(),
    )
    .unwrap()
}

fn run_case(
    fixture: &SyntheticFixture,
    touched_blocks: usize,
    epoch: u64,
    seed_tag: u64,
) -> CaseRecord {
    assert!(touched_blocks > 0 && touched_blocks <= fixture.total_blocks);
    let touched_descriptors = fixture.descriptors[..touched_blocks].to_vec();
    let point = (0..SYNTHETIC_VARS - 1)
        .map(|index| symbol(0x100 + 13 * index as u64 + seed_tag))
        .chain(std::iter::once(Fp2::ZERO))
        .collect::<Vec<_>>();
    let public_h = (0..touched_blocks)
        .map(|slot| {
            evaluate_multilinear_table(&fixture.weight_evaluations[slot], &point).unwrap()
                + evaluate_multilinear_table(&fixture.auxiliary_evaluations[slot], &point).unwrap()
        })
        .collect::<Vec<_>>();
    let auxiliary_values = (0..touched_blocks)
        .map(|slot| {
            evaluate_multilinear_table(&fixture.auxiliary_evaluations[slot], &point).unwrap()
        })
        .collect::<Vec<_>>();
    let weight_values = (0..touched_blocks)
        .map(|slot| evaluate_multilinear_table(&fixture.weight_evaluations[slot], &point).unwrap())
        .collect::<Vec<_>>();
    let claim_frames = touched_descriptors
        .iter()
        .enumerate()
        .flat_map(|(slot, descriptor)| {
            [Phase::Prefill, Phase::Decode].into_iter().enumerate().map(move |(phase, kind)| {
                ReducedClaimFrame {
                    descriptor_digest: *descriptor,
                    parent_claim_digest: [0x70 + slot as u8; 32],
                    phase: kind,
                    phase_ordinal: phase as u16,
                    point: (0..14).map(|index| symbol(0x900 + index + slot as u64)).collect(),
                    affine_scale: if phase == 0 { Fp2::ONE } else { symbol(3) },
                    auth_domain: 0x500_000 + 2 * slot as u64 + phase as u64,
                }
            })
        })
        .collect::<Vec<_>>();
    let link_domains =
        (0..2 * SYNTHETIC_VARS).map(|index| 0x620_000 + index as u64).collect::<Vec<_>>();
    let pcg_seed = [0x35 ^ seed_tag as u8; 32];
    let tx_seed = [0xA7 ^ seed_tag as u8; 32];
    let delta = symbol(0xD311 + seed_tag);
    let mut prover_stream = CorrelationStream::new(pcg_seed);
    let mut prover_tx = Transcript::new(tx_seed);
    let mut m9_frames = Vec::<M9TransferFrame>::with_capacity(touched_blocks);
    let mut pending_prover = Vec::with_capacity(touched_blocks);
    let open_started = Instant::now();
    for slot in 0..touched_blocks {
        let (pending, frame) = authenticate_pending_aux_prover(
            touched_descriptors[slot],
            auxiliary_values[slot],
            &mut prover_stream,
            0x610_000 + slot as u64,
            &mut prover_tx,
        )
        .unwrap();
        pending_prover.push(pending);
        m9_frames.push(frame);
    }
    let prefix = AuthenticatedOutputLinkPrefix {
        epoch,
        claim_frames: &claim_frames,
        descriptor_digests: &touched_descriptors,
        ordered_h_symbols: &public_h,
        m9_frames: &m9_frames,
        round_correlation_domain_ids: &link_domains,
    };
    let prover_blocks = pending_prover
        .into_iter()
        .enumerate()
        .map(|(slot, pending_aux)| AuthenticatedOutputBlockProver {
            descriptor_digest: touched_descriptors[slot],
            public_h: public_h[slot],
            pending_aux,
            weight_extension: LinkPolynomialProver {
                cohort: &fixture.weight,
                slot: slot as u16,
                evaluations: &fixture.weight_evaluations[slot],
                target_point: &point,
            },
            auxiliary: LinkPolynomialProver {
                cohort: &fixture.auxiliary,
                slot: slot as u16,
                evaluations: &fixture.auxiliary_evaluations[slot],
                target_point: &point,
            },
        })
        .collect();
    let challenges = challenge_set(fixture, seed_tag);
    let manifest = manifest_for(fixture, epoch);
    let model_root = manifest.root();
    let mut prover_registry = X4OpeningRegistry::default();
    let permit = prover_registry.authorize(model_root, epoch).unwrap();
    let (proof, bound_prover, metrics) = prove_authenticated_output_link_production(
        permit,
        model_root,
        prover_blocks,
        prefix,
        &challenges,
        &mut prover_stream,
        &mut prover_tx,
    )
    .unwrap();
    let authenticated_weights = weight_values
        .iter()
        .enumerate()
        .map(|(slot, value)| ProverAuthed { x: *value, m: symbol(0xA000 + slot as u64 + seed_tag) })
        .collect::<Vec<_>>();
    let zero_frame = prove_bound_response_zero_batch(
        &authenticated_weights,
        &bound_prover,
        &public_h,
        &mut prover_stream,
        0x630_000,
        &mut prover_tx,
    )
    .unwrap();
    let fold_frames = proof.fold_frames().cloned().collect::<Vec<_>>();
    let query_frames = proof.query_frames().cloned().collect::<Vec<_>>();
    let manifest_frames = manifest.open(&touched_descriptors).unwrap();
    let envelope = ResponseEnvelopeFrame {
        profile_digest: profile_digest(),
        model_root,
        epoch,
        descriptor_digests: touched_descriptors.clone(),
        manifest_frames: manifest_frames.clone(),
        claim_frames: claim_frames.clone(),
        ordered_h_symbols: public_h.clone(),
        m9_frames: m9_frames.clone(),
        authenticated_output_link_frame: proof.frame.clone(),
        fold_frames: fold_frames.clone(),
        query_frames: query_frames.clone(),
        zero_batch_frame: zero_frame.clone(),
    };
    let encoded = Frame::ResponseEnvelope(envelope.clone()).encode().unwrap();
    let open_s = open_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    let mut verifier_ctx = VerifierCtx::new(pcg_seed, delta);
    let mut verifier_tx = Transcript::new(tx_seed);
    let pending_verifier = m9_frames
        .iter()
        .enumerate()
        .map(|(slot, frame)| {
            authenticate_pending_aux_verifier(
                frame,
                &mut verifier_ctx,
                0x610_000 + slot as u64,
                &mut verifier_tx,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let verifier_blocks = pending_verifier
        .into_iter()
        .enumerate()
        .map(|(slot, pending_aux)| AuthenticatedOutputBlockVerifier {
            descriptor_digest: touched_descriptors[slot],
            public_h: public_h[slot],
            pending_aux,
            weight_extension: LinkPolynomialVerifier {
                commitment: fixture.weight.commitment(),
                slot: slot as u16,
                target_point: &point,
            },
            auxiliary: LinkPolynomialVerifier {
                commitment: fixture.auxiliary.commitment(),
                slot: slot as u16,
                target_point: &point,
            },
        })
        .collect();
    let mut verifier_registry = X4OpeningRegistry::default();
    let permit = verifier_registry.authorize(model_root, epoch).unwrap();
    let bound_verifier = verify_authenticated_output_link_production(
        permit,
        model_root,
        verifier_blocks,
        prefix,
        &challenges,
        &proof,
        &mut verifier_ctx,
        &mut verifier_tx,
    )
    .unwrap();
    let weight_keys = authenticated_weights
        .iter()
        .map(|auth| VerifierKey { k: auth.m + delta * auth.x })
        .collect::<Vec<_>>();
    verify_bound_response_zero_batch(
        &weight_keys,
        &bound_verifier,
        &public_h,
        &zero_frame,
        &mut verifier_ctx,
        0x630_000,
        &mut verifier_tx,
    )
    .unwrap();
    envelope
        .validate_statement(model_root, epoch, &touched_descriptors, &claim_frames, &link_domains)
        .unwrap();
    verify_response_manifest(&envelope, [0xC1; 32], [0xD2; 32], &fixture.descriptors).unwrap();
    let verify_s = verify_started.elapsed().as_secs_f64();

    let manifest_bytes = manifest_frames
        .iter()
        .map(|frame| match frame {
            ManifestFrame::Leaf(frame) => frame_bytes(Frame::ManifestLeaf(frame.clone())),
            ManifestFrame::Node(frame) => frame_bytes(Frame::ManifestNode(frame.clone())),
        })
        .sum::<u64>();
    let claim_bytes = claim_frames
        .iter()
        .map(|frame| frame_bytes(Frame::ReducedClaim(frame.clone())))
        .sum::<u64>();
    let m9_bytes =
        m9_frames.iter().map(|frame| frame_bytes(Frame::M9Transfer(frame.clone()))).sum::<u64>();
    let link_bytes = frame_bytes(Frame::AuthenticatedOutputLink(proof.frame.clone()));
    let fold_bytes = fold_frames
        .iter()
        .map(|frame| frame_bytes(Frame::FoldCommitment(frame.clone())))
        .sum::<u64>();
    let query_bytes = query_frames
        .iter()
        .map(|frame| frame_bytes(Frame::CohortMultiproof(frame.clone())))
        .sum::<u64>();
    let zero_bytes = frame_bytes(Frame::ResponseZeroBatch(zero_frame));
    let descriptor_bytes = 32 * touched_blocks as u64;
    let h_bytes = 16 * touched_blocks as u64;
    let envelope_overhead = 110;
    let closed_formula_total = envelope_overhead
        + descriptor_bytes
        + manifest_bytes
        + claim_bytes
        + h_bytes
        + m9_bytes
        + link_bytes
        + fold_bytes
        + query_bytes
        + zero_bytes;
    assert_eq!(closed_formula_total, encoded.len() as u64);
    let expected_full = touched_blocks as u64 + 2 * SYNTHETIC_VARS as u64 + 1;
    assert_eq!(metrics.seam_full_correlations_with_response_zero, expected_full);
    assert_eq!(prover_stream.counters, verifier_ctx.counters);
    assert_eq!(prover_stream.counters.full_corrs, expected_full);
    assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
    assert_eq!(
        metrics.source_coefficients_read,
        2 * touched_blocks as u64 * SYNTHETIC_COEFFICIENTS as u64
    );
    let response_digest = blake3::hash(&encoded).to_hex().to_string();
    CaseRecord {
        total_blocks: fixture.total_blocks,
        touched_blocks,
        fixed_claims: claim_frames.len(),
        original_weight_coefficients_total: (fixture.total_blocks * ORIGINAL_WEIGHT_COEFFICIENTS)
            as u64,
        original_weight_coefficients_touched: (touched_blocks * ORIGINAL_WEIGHT_COEFFICIENTS)
            as u64,
        weight_extension_coefficients_read: (touched_blocks * SYNTHETIC_COEFFICIENTS) as u64,
        zk_extension_coefficients_read: (touched_blocks * ORIGINAL_WEIGHT_COEFFICIENTS) as u64,
        auxiliary_coefficients_read: (touched_blocks * SYNTHETIC_COEFFICIENTS) as u64,
        initial_encoded_symbols_read: metrics.encoded_symbols_read,
        folded_symbols_written: metrics.folded_symbols_written,
        full_correlations_prover: prover_stream.counters.full_corrs,
        full_correlations_verifier: verifier_ctx.counters.full_corrs,
        expected_full_correlations: expected_full,
        correlation_domains_prover: prover_stream.counters.domains,
        correlation_domains_verifier: verifier_ctx.counters.domains,
        allocation_digest_match: prover_stream.allocation_digest_hex()
            == verifier_ctx.allocation_digest_hex(),
        transcript_bytes_prover: prover_tx.total_bytes(),
        transcript_bytes_verifier: verifier_tx.total_bytes(),
        root_hex: hex(&model_root),
        response_digest,
        bytes: ByteComponents {
            envelope_overhead,
            descriptor_digests: descriptor_bytes,
            manifest_frames: manifest_bytes,
            reduced_claim_frames: claim_bytes,
            public_h_symbols: h_bytes,
            m9_frames: m9_bytes,
            authenticated_output_link_frame: link_bytes,
            fold_frames: fold_bytes,
            query_frames: query_bytes,
            response_zero_batch_frame: zero_bytes,
            closed_formula_total,
            serialized_total: encoded.len() as u64,
        },
        open_s,
        verify_s,
        accepted: true,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * bytes.len());
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
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

fn cpu_model() -> String {
    let proc_model = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            ["model name", "Hardware", "Processor"]
                .iter()
                .find_map(|key| line.split_once(':').filter(|(lhs, _)| lhs.trim() == *key))
                .map(|(_, value)| value.trim())
        })
        .filter(|value| !value.is_empty() && *value != "-")
        .map(str::to_owned);
    proc_model
        .or_else(|| {
            std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name")
                .ok()
                .map(|value| value.trim_matches(['\0', '\n', '\r']).to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| format!("unknown-{}", std::env::consts::ARCH))
}

fn peak_rss_gib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<f64>().ok())
        .map(|kib| kib / 1024.0 / 1024.0)
        .unwrap_or(0.0)
}

#[derive(Serialize)]
struct ArtifactRecord {
    policy: String,
    source_i16_weight_bytes: u64,
    coefficient_bytes: u64,
    logical_first_oracle_bytes: u64,
    merkle_digest_bytes: u64,
    retained_logical_payload_bytes: u64,
    maximum_cohort_working_set_bytes: u64,
    persisted_artifact_bytes: u64,
    recomputed_bytes: u64,
    host_bytes_read: u64,
    host_bytes_written: u64,
    h2d_bytes: u64,
    d2h_bytes: u64,
    peak_device_bytes: u64,
}

#[derive(Serialize)]
struct AbbaRecord {
    order: String,
    warmup_per_side: usize,
    cycles: usize,
    total_blocks_a: usize,
    total_blocks_b: usize,
    touched_blocks: usize,
    a_open_samples_s: Vec<f64>,
    b_open_samples_s: Vec<f64>,
    a_upper_median_s: f64,
    b_upper_median_s: f64,
    b_over_a: f64,
    ceiling: f64,
    pass: bool,
    marginal_serialized_bytes: i64,
}

#[derive(Serialize)]
struct GateRecord {
    overall_x4_verdict: String,
    evaluated_scope: String,
    g1_lean_green: bool,
    g2_synthetic_honest_accepts: bool,
    g3_gpt2_not_evaluated: bool,
    g4_gpt2_not_evaluated: bool,
    g5_touched_family_exact: bool,
    g5_closed_byte_formula_exact: bool,
    g5_no_linear_unopened_payload: bool,
    g5_abba_ratio_ceiling: f64,
    g5_abba_pass: bool,
    g5_verdict: String,
    g6_all_categories_present: bool,
    g6_artifacts_reconcile: bool,
    g6_verdict: String,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    cpu_only: bool,
    rayon_workers: usize,
    detected_logical_cpus: usize,
    cpu_model: String,
    peak_rss_gib: f64,
    profile: String,
    design_sha256: String,
    lean_audit_stdout_sha256: String,
    lean_targets: String,
    soundness_expression: String,
    soundness_bits: f64,
    required_soundness_bits: f64,
    soundness_margin_bits: f64,
    query_count: usize,
    rate: String,
    field_symbol_bytes: usize,
    synthetic_variables: usize,
    commit_seconds_total16: f64,
    commit_seconds_total32: f64,
    touched_family: Vec<CaseRecord>,
    unopened_double_case: CaseRecord,
    abba: AbbaRecord,
    artifacts_total16: ArtifactRecord,
    artifacts_total32: ArtifactRecord,
    permanent_test_command: String,
    permanent_test_status: String,
    pending_pod_preflight: String,
    deviations: Vec<String>,
    gate: GateRecord,
}

fn artifact_record(fixture: &SyntheticFixture) -> ArtifactRecord {
    let metrics = &fixture.artifact_metrics;
    let source_i16_weight_bytes = (fixture.total_blocks * ORIGINAL_WEIGHT_COEFFICIENTS * 2) as u64;
    ArtifactRecord {
        policy: "persist-oracle-and-merkle synthetic path; recompute path root-equivalent in permanent tests"
            .to_owned(),
        source_i16_weight_bytes,
        coefficient_bytes: metrics.coefficient_bytes,
        logical_first_oracle_bytes: metrics.logical_first_oracle_bytes,
        merkle_digest_bytes: metrics.merkle_digest_bytes,
        retained_logical_payload_bytes: metrics.retained_logical_payload_bytes,
        maximum_cohort_working_set_bytes: metrics.maximum_cohort_working_set_bytes,
        persisted_artifact_bytes: 0,
        recomputed_bytes: 0,
        host_bytes_read: 0,
        host_bytes_written: 0,
        h2d_bytes: 0,
        d2h_bytes: 0,
        peak_device_bytes: 0,
    }
}

fn main() {
    let record = std::env::args().any(|arg| arg == "--record");
    let quick = std::env::args().any(|arg| arg == "--quick");
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x4-cpu-{index}"))
        .build_global()
        .expect("X4 report initializes the four-worker CPU pool first");

    eprintln!("X4: building resident synthetic cohorts (16 and 32 blocks) ...");
    let fixture_a = SyntheticFixture::build(16);
    let fixture_b = SyntheticFixture::build(32);
    let mut touched_family = Vec::new();
    for (index, touched) in [1, 2, 4, 8, 16].into_iter().enumerate() {
        let case = run_case(&fixture_a, touched, 100 + index as u64, 10 + index as u64);
        eprintln!(
            "  B={touched}: open={:.4}s verify={:.4}s bytes={}",
            case.open_s, case.verify_s, case.bytes.serialized_total
        );
        touched_family.push(case);
    }
    let unopened_double_case = run_case(&fixture_b, 8, 200, 20);

    eprintln!("X4: same-process ABBA total-block comparison ...");
    let _warm_a = run_case(&fixture_a, 8, 300, 30);
    let _warm_b = run_case(&fixture_b, 8, 301, 31);
    let cycles = if quick { 1 } else { 3 };
    let mut a_samples = Vec::new();
    let mut b_samples = Vec::new();
    let mut counter = 0u64;
    for _ in 0..cycles {
        for side in ['A', 'B', 'B', 'A'] {
            counter += 1;
            let case = if side == 'A' {
                run_case(&fixture_a, 8, 400 + counter, 40 + counter)
            } else {
                run_case(&fixture_b, 8, 400 + counter, 40 + counter)
            };
            if side == 'A' {
                a_samples.push(case.open_s);
            } else {
                b_samples.push(case.open_s);
            }
        }
    }
    let a_median = median(a_samples.clone());
    let b_median = median(b_samples.clone());
    let ratio = b_median / a_median;
    let family_b8 = touched_family.iter().find(|case| case.touched_blocks == 8).unwrap();
    let marginal_serialized_bytes = unopened_double_case.bytes.serialized_total as i64
        - family_b8.bytes.serialized_total as i64;
    let abba = AbbaRecord {
        order: "A/B/B/A".to_owned(),
        warmup_per_side: 1,
        cycles,
        total_blocks_a: 16,
        total_blocks_b: 32,
        touched_blocks: 8,
        a_open_samples_s: a_samples,
        b_open_samples_s: b_samples,
        a_upper_median_s: a_median,
        b_upper_median_s: b_median,
        b_over_a: ratio,
        ceiling: 1.05,
        pass: ratio <= 1.05,
        marginal_serialized_bytes,
    };
    let family_exact = touched_family.iter().all(|case| {
        case.accepted
            && case.fixed_claims == 2 * case.touched_blocks
            && case.original_weight_coefficients_touched
                == (case.touched_blocks * ORIGINAL_WEIGHT_COEFFICIENTS) as u64
            && case.full_correlations_prover == case.expected_full_correlations
            && case.full_correlations_verifier == case.expected_full_correlations
            && case.allocation_digest_match
    });
    let formula_exact = touched_family
        .iter()
        .chain(std::iter::once(&unopened_double_case))
        .all(|case| case.bytes.closed_formula_total == case.bytes.serialized_total);
    let no_linear_unopened_payload = marginal_serialized_bytes >= 0
        && marginal_serialized_bytes
            < i64::try_from(
                (fixture_b.total_blocks - fixture_a.total_blocks) * SYNTHETIC_COEFFICIENTS * 16,
            )
            .unwrap();
    let g5_pass = family_exact && formula_exact && no_linear_unopened_payload && abba.pass;
    let artifacts_a = artifact_record(&fixture_a);
    let artifacts_b = artifact_record(&fixture_b);
    let artifacts_reconcile = artifacts_a.logical_first_oracle_bytes
        == 2 * fixture_a.total_blocks as u64 * SYNTHETIC_COEFFICIENTS as u64 * 8 * 16
        && artifacts_b.logical_first_oracle_bytes
            == 2 * fixture_b.total_blocks as u64 * SYNTHETIC_COEFFICIENTS as u64 * 8 * 16;
    let g6_present = artifacts_a.source_i16_weight_bytes > 0
        && artifacts_a.coefficient_bytes > 0
        && artifacts_a.logical_first_oracle_bytes > 0
        && artifacts_a.merkle_digest_bytes > 0
        && artifacts_a.maximum_cohort_working_set_bytes > 0;
    let gate = GateRecord {
        overall_x4_verdict: "NOT_EVALUATED_UNTIL_GPT2_CPU_A100_RECORDS".to_owned(),
        evaluated_scope: "CPU synthetic G5/G6".to_owned(),
        g1_lean_green: true,
        g2_synthetic_honest_accepts: family_exact,
        g3_gpt2_not_evaluated: true,
        g4_gpt2_not_evaluated: true,
        g5_touched_family_exact: family_exact,
        g5_closed_byte_formula_exact: formula_exact,
        g5_no_linear_unopened_payload: no_linear_unopened_payload,
        g5_abba_ratio_ceiling: 1.05,
        g5_abba_pass: abba.pass,
        g5_verdict: if g5_pass { "PASS" } else { "FAIL" }.to_owned(),
        g6_all_categories_present: g6_present,
        g6_artifacts_reconcile: artifacts_reconcile,
        g6_verdict: if g6_present && artifacts_reconcile { "PASS" } else { "FAIL" }.to_owned(),
    };
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let report = Report {
        schema: 1,
        milestone: "X4-v3-CPU-synthetic".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        cpu_only: true,
        rayon_workers: rayon::current_num_threads(),
        detected_logical_cpus: std::thread::available_parallelism().map(usize::from).unwrap_or(0),
        cpu_model: cpu_model(),
        peak_rss_gib: peak_rss_gib(),
        profile: String::from_utf8(PROFILE_NAME.to_vec()).unwrap(),
        design_sha256: DESIGN_SHA256.to_owned(),
        lean_audit_stdout_sha256: LEAN_AUDIT_STDOUT_SHA256.to_owned(),
        lean_targets: "163 total / 70 X4 (historical 133/40 plus 30 v3)".to_owned(),
        soundness_expression:
            "3320*(9/16)^128 + 28522064267253/340282366762482138490186164457219031041"
                .to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        required_soundness_bits: SOUNDNESS_FLOOR_BITS,
        soundness_margin_bits: SOUNDNESS_BITS - SOUNDNESS_FLOOR_BITS,
        query_count: QUERIES,
        rate: "1/8 strict unique decoding".to_owned(),
        field_symbol_bytes: 16,
        synthetic_variables: SYNTHETIC_VARS,
        commit_seconds_total16: fixture_a.commit_s,
        commit_seconds_total32: fixture_b.commit_s,
        touched_family,
        unopened_double_case,
        abba,
        artifacts_total16: artifacts_a,
        artifacts_total32: artifacts_b,
        permanent_test_command: "cargo test -p volta-pcs x4::".to_owned(),
        permanent_test_status: "recorded separately at the implementation checkpoint".to_owned(),
        pending_pod_preflight:
            "c3_weights_two_weight_set_leakage_smoke remains scheduled before pod X4 records"
                .to_owned(),
        deviations: vec![
            "Synthetic mu is deliberately small and carries no GPT-2 G3/G4 verdict.".to_owned(),
            "Persisted/host/device traffic fields are zero where this in-memory CPU fixture performs no file or device transfer; logical payload and measured peak RSS remain separate.".to_owned(),
            "The recompute policy is exercised by permanent root/proof-equivalence tests; G5 uses retained cohorts so opening work does not rebuild unopened blocks.".to_owned(),
        ],
        gate,
    };
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X4 CPU synthetic: G5={} G6={} ABBA={:.6} peak={:.3} GiB",
        report.gate.g5_verdict, report.gate.g6_verdict, report.abba.b_over_a, report.peak_rss_gib
    );
    if record {
        if dirty {
            eprintln!("x4_report: refusing a run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x4-cpu-synthetic-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x4_report: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X4 CPU record");
        eprintln!("wrote {}", path.display());
    }
    if !g5_pass || !g6_present || !artifacts_reconcile {
        std::process::exit(1);
    }
    let _ = NON_PCS_RESPONSE_BYTES;
}

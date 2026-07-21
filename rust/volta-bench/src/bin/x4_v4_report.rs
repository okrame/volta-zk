//! X4 v4 CPU synthetic record.
//!
//! Exercises the complete blind M9 PendingAuxEval -> BoundAuxEval seam, one
//! different-size model-global chain, the schema-4 packed opening, G5 touched
//! scaling/ABBA, and both retained and twice-recomputed G6 artifact policies.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_bench::{x4_v4_record_profile_allowed, X4_V4_RECORD_PROFILE};
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::x4::{
    authenticate_pending_aux_prover_v4, authenticate_pending_aux_verifier_v4,
    evaluate_multilinear_table, manifest_id_digest_v4, multilinear_coefficients,
    prove_authenticated_output_link_v4, prove_bound_response_zero_batch_v4,
    verify_authenticated_output_link_v4, verify_bound_response_zero_batch_v4,
    verify_response_manifest_v4, AuthenticatedOutputBlockProverV4,
    AuthenticatedOutputBlockVerifierV4, AuthenticatedOutputLinkMetricsV4,
    AuthenticatedOutputLinkPrefixV4, CohortIdentityV4, CohortVerifierConfigV4, FrameV4,
    LinkPolynomialProverV4, LinkPolynomialVerifierV4, M9TransferFrame, ManifestFrameV4,
    ManifestLeafFrame, ManifestTreeV4, OracleKindV4, Phase, RecomputableModelGlobalCohortV4,
    ReducedClaimFrame, ResponseEnvelopeFrameV4, V4ArtifactPolicy, V4CohortArtifactPlan,
    V4StreamingCommitMetrics, X4OpeningRegistryV4, X4V4CounterFamily, PROFILE_NAME_V4,
};

const DESIGN_SHA256: &str = "c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544";
const FROZEN_DESIGN_BASELINE_SHA256: &str =
    "1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7";
const LEAN_CHECKPOINT: &str = "d5227f2";
const SOUNDNESS_BITS: f64 = 80.255_370_163_990_41;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const QUERIES: usize = 111;
const WEIGHT_VARIABLES: usize = 10;
const AUX_VARIABLES: usize = 8;
const WEIGHT_COEFFICIENTS: usize = 1 << WEIGHT_VARIABLES;
const AUX_COEFFICIENTS: usize = 1 << AUX_VARIABLES;
const ORIGINAL_WEIGHT_COEFFICIENTS: usize = WEIGHT_COEFFICIENTS / 2;
const SYMBOL_BYTES: u64 = 16;
const DIGEST_BYTES: u64 = 32;

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
    weight: RecomputableModelGlobalCohortV4,
    auxiliary: RecomputableModelGlobalCohortV4,
    artifact_metrics: V4StreamingCommitMetrics,
    policy: V4ArtifactPolicy,
    commit_s: f64,
}

impl SyntheticFixture {
    fn build(total_blocks: usize, policy: V4ArtifactPolicy) -> Self {
        assert!(total_blocks.is_power_of_two());
        let descriptors = (0..total_blocks).map(descriptor).collect::<Vec<_>>();
        let weight_evaluations = (0..total_blocks)
            .map(|slot| {
                (0..WEIGHT_COEFFICIENTS)
                    .map(|index| symbol(10_000 * slot as u64 + index as u64 + 1))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let auxiliary_evaluations = (0..total_blocks)
            .map(|slot| {
                (0..AUX_COEFFICIENTS)
                    .map(|index| symbol(900_000 + 20_000 * slot as u64 + 3 * index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let config = |kind, cohort_id, coefficients| CohortVerifierConfigV4 {
            identity: CohortIdentityV4 { cohort_id, oracle_kind: kind, fold_round: 0 },
            slot_descriptors: descriptors.iter().copied().map(Some).collect(),
            outer_len: 8 * coefficients,
            expected_symbol_count: 1,
        };
        let weight_config = config(
            OracleKindV4::WeightExtension,
            0xA500_1000 + total_blocks as u32,
            WEIGHT_COEFFICIENTS,
        );
        let auxiliary_config =
            config(OracleKindV4::Auxiliary, 0xA500_2000 + total_blocks as u32, AUX_COEFFICIENTS);
        let mut artifact_metrics = V4StreamingCommitMetrics::default();
        artifact_metrics
            .include(&V4CohortArtifactPlan::new(&weight_config, policy).unwrap())
            .unwrap();
        artifact_metrics
            .include(&V4CohortArtifactPlan::new(&auxiliary_config, policy).unwrap())
            .unwrap();
        let started = Instant::now();
        let weight = RecomputableModelGlobalCohortV4::commit(
            weight_config,
            weight_evaluations
                .iter()
                .map(|table| Some(multilinear_coefficients(table).unwrap()))
                .collect(),
            policy,
        )
        .unwrap();
        let auxiliary = RecomputableModelGlobalCohortV4::commit(
            auxiliary_config,
            auxiliary_evaluations
                .iter()
                .map(|table| Some(multilinear_coefficients(table).unwrap()))
                .collect(),
            policy,
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
            policy,
            commit_s,
        }
    }
}

#[derive(Clone, Serialize)]
struct PackedCounts {
    opened_symbols: u64,
    initial_inner_siblings: u64,
    initial_outer_siblings: u64,
    fold_outer_siblings: u64,
    all_sibling_digests: u64,
    metadata_bytes: u64,
}

#[derive(Clone, Serialize)]
struct ByteComponents {
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
    closed_formula_total: u64,
    serialized_total: u64,
    packed_counts: PackedCounts,
}

#[derive(Clone, Serialize)]
struct TrafficRecord {
    sumcheck_source_bytes_read: u64,
    aggregate_source_coefficient_bytes_read: u64,
    initial_encoded_bytes_read: u64,
    combined_coefficient_bytes: u64,
    combined_codeword_bytes: u64,
    fold_oracle_bytes_written: u64,
    fold_merkle_digest_bytes_written: u64,
    recomputed_source_bytes_read: u64,
    recomputed_oracle_bytes: u64,
    recomputed_merkle_bytes: u64,
    serialized_bytes_written: u64,
    host_logical_bytes_read: u64,
    host_logical_bytes_written: u64,
    h2d_bytes: u64,
    d2h_bytes: u64,
    peak_device_bytes: u64,
}

#[derive(Clone, Serialize)]
struct CaseRecord {
    policy: String,
    total_blocks: usize,
    touched_blocks: usize,
    fixed_claims: usize,
    original_weight_coefficients_total: u64,
    original_weight_coefficients_touched: u64,
    weight_extension_coefficients_read: u64,
    zk_extension_coefficients_read: u64,
    auxiliary_coefficients_read: u64,
    seam_full_correlations_prover: u64,
    seam_full_correlations_verifier: u64,
    expected_seam_full_correlations: u64,
    allocation_digest_match: bool,
    transcript_bytes_prover: u64,
    transcript_bytes_verifier: u64,
    root_hex: String,
    response_digest: String,
    bytes: ByteComponents,
    traffic: TrafficRecord,
    open_s: f64,
    verify_s: f64,
    accepted: bool,
}

fn frame_bytes(frame: FrameV4) -> u64 {
    u64::try_from(frame.encode().unwrap().len()).unwrap()
}

fn manifest_for(fixture: &SyntheticFixture, epoch: u64) -> ManifestTreeV4 {
    ManifestTreeV4::build(
        manifest_id_digest_v4([0xC1; 32], [0xD2; 32], epoch),
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

fn points(seed_tag: u64) -> (Vec<Fp2>, Vec<Fp2>) {
    let base = (0..WEIGHT_VARIABLES - 1)
        .map(|index| symbol(0x100 + 13 * index as u64 + seed_tag))
        .collect::<Vec<_>>();
    let weight = base.iter().copied().chain(std::iter::once(Fp2::ZERO)).collect();
    let auxiliary = base[base.len() - (AUX_VARIABLES - 1)..]
        .iter()
        .copied()
        .chain(std::iter::once(Fp2::ZERO))
        .collect();
    (weight, auxiliary)
}

fn run_case(
    fixture: &SyntheticFixture,
    touched_blocks: usize,
    epoch: u64,
    seed_tag: u64,
) -> CaseRecord {
    assert!(touched_blocks > 0 && touched_blocks <= fixture.total_blocks);
    let touched_descriptors = fixture.descriptors[..touched_blocks].to_vec();
    let (weight_point, auxiliary_point) = points(seed_tag);
    let weight_values = (0..touched_blocks)
        .map(|slot| {
            evaluate_multilinear_table(&fixture.weight_evaluations[slot], &weight_point).unwrap()
        })
        .collect::<Vec<_>>();
    let auxiliary_values = (0..touched_blocks)
        .map(|slot| {
            evaluate_multilinear_table(&fixture.auxiliary_evaluations[slot], &auxiliary_point)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let public_h = weight_values
        .iter()
        .zip(&auxiliary_values)
        .map(|(weight, auxiliary)| *weight + *auxiliary)
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
                    point: (0..14)
                        .map(|index| symbol(0x900 + index as u64 + slot as u64))
                        .collect(),
                    affine_scale: if phase == 0 { Fp2::ONE } else { symbol(3) },
                    auth_domain: 0x500_000 + 2 * slot as u64 + phase as u64,
                }
            })
        })
        .collect::<Vec<_>>();
    let link_domains =
        (0..2 * WEIGHT_VARIABLES).map(|index| 0x620_000 + index as u64).collect::<Vec<_>>();
    let pcg_seed = [0x35 ^ seed_tag as u8; 32];
    let tx_seed = [0xA7 ^ seed_tag as u8; 32];
    let delta = symbol(0xD311 + seed_tag);
    let mut prover_stream = CorrelationStream::new(pcg_seed);
    let mut prover_tx = Transcript::new(tx_seed);
    let mut m9_frames = Vec::<M9TransferFrame>::with_capacity(touched_blocks);
    let mut pending_prover = Vec::with_capacity(touched_blocks);
    let open_started = Instant::now();
    for slot in 0..touched_blocks {
        let (pending, frame) = authenticate_pending_aux_prover_v4(
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
    let prefix = AuthenticatedOutputLinkPrefixV4 {
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
        .map(|(slot, pending_aux)| AuthenticatedOutputBlockProverV4 {
            descriptor_digest: touched_descriptors[slot],
            public_h: public_h[slot],
            pending_aux,
            weight_extension: LinkPolynomialProverV4 {
                cohort: &fixture.weight,
                slot: slot as u16,
                evaluations: &fixture.weight_evaluations[slot],
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialProverV4 {
                cohort: &fixture.auxiliary,
                slot: slot as u16,
                evaluations: &fixture.auxiliary_evaluations[slot],
                target_point: &auxiliary_point,
            },
        })
        .collect();
    let manifest = manifest_for(fixture, epoch);
    let model_root = manifest.root();
    let permit = X4OpeningRegistryV4::default().authorize(model_root, epoch).unwrap();
    let (proof, bound_prover, metrics) = prove_authenticated_output_link_v4(
        permit,
        model_root,
        prover_blocks,
        prefix,
        &mut prover_stream,
        &mut prover_tx,
    )
    .unwrap();
    let authenticated_weights = weight_values
        .iter()
        .enumerate()
        .map(|(slot, value)| ProverAuthed { x: *value, m: symbol(0xA000 + slot as u64 + seed_tag) })
        .collect::<Vec<_>>();
    let zero_frame = prove_bound_response_zero_batch_v4(
        &authenticated_weights,
        &bound_prover,
        &public_h,
        &mut prover_stream,
        0x630_000,
        &mut prover_tx,
    )
    .unwrap();
    let manifest_frames = manifest.open(&touched_descriptors).unwrap();
    let response = ResponseEnvelopeFrameV4 {
        profile_digest: volta_pcs::x4::profile_digest_v4(),
        model_root,
        epoch,
        descriptor_digests: touched_descriptors.clone(),
        manifest_frames: manifest_frames.clone(),
        claim_frames: claim_frames.clone(),
        ordered_h_symbols: public_h.clone(),
        m9_frames: m9_frames.clone(),
        authenticated_output_link_frame: proof.frame.clone(),
        fold_frames: proof.global_folding.fold_frames.clone(),
        packed_opening_frame: proof.global_folding.packed_opening.clone(),
        zero_batch_frame: zero_frame.clone(),
    };
    let encoded = FrameV4::ResponseEnvelope(response.clone()).encode().unwrap();
    assert_eq!(
        volta_pcs::x4::decode_v4(&encoded).unwrap(),
        FrameV4::ResponseEnvelope(response.clone())
    );
    let open_s = open_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    let mut verifier_ctx = VerifierCtx::new(pcg_seed, delta);
    let mut verifier_tx = Transcript::new(tx_seed);
    let pending_verifier = m9_frames
        .iter()
        .enumerate()
        .map(|(slot, frame)| {
            authenticate_pending_aux_verifier_v4(
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
        .map(|(slot, pending_aux)| AuthenticatedOutputBlockVerifierV4 {
            descriptor_digest: touched_descriptors[slot],
            public_h: public_h[slot],
            pending_aux,
            weight_extension: LinkPolynomialVerifierV4 {
                commitment: fixture.weight.commitment(),
                slot: slot as u16,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialVerifierV4 {
                commitment: fixture.auxiliary.commitment(),
                slot: slot as u16,
                target_point: &auxiliary_point,
            },
        })
        .collect();
    let permit = X4OpeningRegistryV4::default().authorize(model_root, epoch).unwrap();
    let bound_verifier = verify_authenticated_output_link_v4(
        permit,
        model_root,
        verifier_blocks,
        prefix,
        &proof,
        &mut verifier_ctx,
        &mut verifier_tx,
    )
    .unwrap();
    let weight_keys = authenticated_weights
        .iter()
        .map(|auth| VerifierKey { k: auth.m + delta * auth.x })
        .collect::<Vec<_>>();
    verify_bound_response_zero_batch_v4(
        &weight_keys,
        &bound_verifier,
        &public_h,
        &zero_frame,
        &mut verifier_ctx,
        0x630_000,
        &mut verifier_tx,
    )
    .unwrap();
    response.validate_link_schedule(&link_domains).unwrap();
    verify_response_manifest_v4(&response, [0xC1; 32], [0xD2; 32], &fixture.descriptors).unwrap();
    let verify_s = verify_started.elapsed().as_secs_f64();

    let manifest_bytes = manifest_frames
        .iter()
        .map(|frame| match frame {
            ManifestFrameV4::Leaf(frame) => frame_bytes(FrameV4::ManifestLeaf(frame.clone())),
            ManifestFrameV4::Node(frame) => frame_bytes(FrameV4::ManifestNode(frame.clone())),
        })
        .sum::<u64>();
    let claim_bytes = claim_frames
        .iter()
        .map(|frame| frame_bytes(FrameV4::ReducedClaim(frame.clone())))
        .sum::<u64>();
    let m9_bytes =
        m9_frames.iter().map(|frame| frame_bytes(FrameV4::M9Transfer(frame.clone()))).sum::<u64>();
    let link_bytes = frame_bytes(FrameV4::AuthenticatedOutputLink(proof.frame.clone()));
    let fold_bytes = proof
        .global_folding
        .fold_frames
        .iter()
        .map(|frame| frame_bytes(FrameV4::FoldCommitment(frame.clone())))
        .sum::<u64>();
    let packed_bytes =
        frame_bytes(FrameV4::PackedBatchOpening(proof.global_folding.packed_opening.clone()));
    let zero_bytes = frame_bytes(FrameV4::ResponseZeroBatch(zero_frame));
    let descriptor_bytes = 32 * touched_blocks as u64;
    let h_bytes = 16 * touched_blocks as u64;
    let components_without_structure = descriptor_bytes
        + manifest_bytes
        + claim_bytes
        + h_bytes
        + m9_bytes
        + link_bytes
        + fold_bytes
        + packed_bytes
        + zero_bytes;
    let envelope_structure = encoded.len() as u64 - components_without_structure;
    let closed_formula_total = envelope_structure + components_without_structure;
    assert_eq!(closed_formula_total, encoded.len() as u64);
    let packed = proof.global_folding.packed_opening.byte_components().unwrap();
    let all_siblings =
        packed.initial_inner_siblings + packed.initial_outer_siblings + packed.fold_outer_siblings;
    let expected_full = touched_blocks as u64 + 2 * WEIGHT_VARIABLES as u64 + 1;
    assert_eq!(metrics.seam_full_correlations_with_response_zero, expected_full);
    assert_eq!(prover_stream.counters, verifier_ctx.counters);
    assert_eq!(prover_stream.counters.full_corrs, expected_full);
    assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
    assert_eq!(
        metrics.source_coefficients_read,
        touched_blocks as u64 * (WEIGHT_COEFFICIENTS + AUX_COEFFICIENTS) as u64
    );
    let traffic = traffic_record(&metrics, encoded.len() as u64);
    CaseRecord {
        policy: format!("{:?}", fixture.policy),
        total_blocks: fixture.total_blocks,
        touched_blocks,
        fixed_claims: claim_frames.len(),
        original_weight_coefficients_total: (fixture.total_blocks * ORIGINAL_WEIGHT_COEFFICIENTS)
            as u64,
        original_weight_coefficients_touched: (touched_blocks * ORIGINAL_WEIGHT_COEFFICIENTS)
            as u64,
        weight_extension_coefficients_read: (touched_blocks * WEIGHT_COEFFICIENTS) as u64,
        zk_extension_coefficients_read: (touched_blocks * ORIGINAL_WEIGHT_COEFFICIENTS) as u64,
        auxiliary_coefficients_read: (touched_blocks * AUX_COEFFICIENTS) as u64,
        seam_full_correlations_prover: prover_stream.counters.full_corrs,
        seam_full_correlations_verifier: verifier_ctx.counters.full_corrs,
        expected_seam_full_correlations: expected_full,
        allocation_digest_match: prover_stream.allocation_digest_hex()
            == verifier_ctx.allocation_digest_hex(),
        transcript_bytes_prover: prover_tx.total_bytes(),
        transcript_bytes_verifier: verifier_tx.total_bytes(),
        root_hex: hex(&model_root),
        response_digest: blake3::hash(&encoded).to_hex().to_string(),
        bytes: ByteComponents {
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
            closed_formula_total,
            serialized_total: encoded.len() as u64,
            packed_counts: PackedCounts {
                opened_symbols: packed.opened_symbols,
                initial_inner_siblings: packed.initial_inner_siblings,
                initial_outer_siblings: packed.initial_outer_siblings,
                fold_outer_siblings: packed.fold_outer_siblings,
                all_sibling_digests: all_siblings,
                metadata_bytes: packed.metadata_bytes,
            },
        },
        traffic,
        open_s,
        verify_s,
        accepted: true,
    }
}

fn traffic_record(metrics: &AuthenticatedOutputLinkMetricsV4, serialized: u64) -> TrafficRecord {
    let sumcheck_source_bytes_read = metrics.sumcheck_source_symbols_read * SYMBOL_BYTES;
    let aggregate_source_coefficient_bytes_read = metrics.source_coefficients_read * SYMBOL_BYTES;
    let initial_encoded_bytes_read = metrics.encoded_symbols_read * SYMBOL_BYTES;
    let combined_coefficient_bytes = metrics.combined_coefficient_symbols * SYMBOL_BYTES;
    let combined_codeword_bytes = metrics.combined_codeword_symbols * SYMBOL_BYTES;
    let fold_oracle_bytes_written = metrics.folded_symbols_written * SYMBOL_BYTES;
    let fold_merkle_digest_bytes_written = metrics.aggregate_merkle_digests_written * DIGEST_BYTES;
    let host_logical_bytes_read = sumcheck_source_bytes_read
        + aggregate_source_coefficient_bytes_read
        + initial_encoded_bytes_read
        + metrics.recomputed_source_bytes_read;
    let host_logical_bytes_written = fold_oracle_bytes_written
        + fold_merkle_digest_bytes_written
        + metrics.recomputed_oracle_bytes
        + metrics.recomputed_merkle_bytes
        + serialized;
    TrafficRecord {
        sumcheck_source_bytes_read,
        aggregate_source_coefficient_bytes_read,
        initial_encoded_bytes_read,
        combined_coefficient_bytes,
        combined_codeword_bytes,
        fold_oracle_bytes_written,
        fold_merkle_digest_bytes_written,
        recomputed_source_bytes_read: metrics.recomputed_source_bytes_read,
        recomputed_oracle_bytes: metrics.recomputed_oracle_bytes,
        recomputed_merkle_bytes: metrics.recomputed_merkle_bytes,
        serialized_bytes_written: serialized,
        host_logical_bytes_read,
        host_logical_bytes_written,
        h2d_bytes: 0,
        d2h_bytes: 0,
        peak_device_bytes: 0,
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
    values[values.len() / 2]
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
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.split_once(':').filter(|(lhs, _)| lhs.trim() == "model name"))
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("unknown-{}", std::env::consts::ARCH))
}

fn peak_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

#[derive(Serialize)]
struct ArtifactRecord {
    policy: String,
    source_i16_weight_bytes: u64,
    coefficient_bytes: u64,
    logical_first_oracle_bytes: u64,
    merkle_digest_bytes: u64,
    retained_logical_payload_bytes: u64,
    response_recomputed_bytes: u64,
    maximum_cohort_working_set_bytes: u64,
    persisted_file_bytes: u64,
    host_file_bytes_read: u64,
    host_file_bytes_written: u64,
}

fn artifact_record(fixture: &SyntheticFixture) -> ArtifactRecord {
    let metrics = &fixture.artifact_metrics;
    ArtifactRecord {
        policy: format!("{:?}", fixture.policy),
        source_i16_weight_bytes: (fixture.total_blocks * ORIGINAL_WEIGHT_COEFFICIENTS * 2) as u64,
        coefficient_bytes: metrics.coefficient_bytes,
        logical_first_oracle_bytes: metrics.logical_first_oracle_bytes,
        merkle_digest_bytes: metrics.merkle_digest_bytes,
        retained_logical_payload_bytes: metrics.retained_logical_payload_bytes,
        response_recomputed_bytes: metrics.response_recomputed_bytes,
        maximum_cohort_working_set_bytes: metrics.maximum_cohort_working_set_bytes,
        persisted_file_bytes: 0,
        host_file_bytes_read: 0,
        host_file_bytes_written: 0,
    }
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
    g2_permanent_tamper_suite_green: bool,
    g3_gpt2_not_evaluated_here: bool,
    g4_gpt2_not_evaluated_here: bool,
    g5_touched_family_exact: bool,
    g5_closed_byte_formula_exact: bool,
    g5_no_linear_unopened_payload: bool,
    g5_abba_ratio_ceiling: f64,
    g5_abba_pass: bool,
    g5_verdict: String,
    g6_all_categories_present: bool,
    g6_artifacts_reconcile: bool,
    g6_recompute_proof_identical: bool,
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
    peak_rss_bytes: u64,
    profile: String,
    design_sha256: String,
    frozen_design_baseline_sha256: String,
    lean_checkpoint: String,
    lean_targets: String,
    soundness_expression: String,
    soundness_bits: f64,
    required_soundness_bits: f64,
    soundness_margin_bits: f64,
    soundness_resummed_new_terms: u64,
    query_count: usize,
    rate: String,
    field_symbol_bytes: usize,
    synthetic_weight_variables: usize,
    synthetic_aux_variables: usize,
    commit_seconds_total16: f64,
    commit_seconds_total32: f64,
    commit_seconds_recompute16: f64,
    touched_family: Vec<CaseRecord>,
    unopened_double_case: CaseRecord,
    recompute_case: CaseRecord,
    recompute_matches_persisted_response: bool,
    abba: AbbaRecord,
    artifacts_persist_total16: ArtifactRecord,
    artifacts_persist_total32: ArtifactRecord,
    artifacts_recompute_total16: ArtifactRecord,
    security_counter_inventory: Vec<String>,
    permanent_test_command: String,
    permanent_test_status: String,
    historical_ligero_policy: String,
    pending_pod_preflight: String,
    deviations: Vec<String>,
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
    let quick = std::env::args().any(|arg| arg == "--quick");
    let profile = requested_profile();
    if record && !x4_v4_record_profile_allowed(&profile) {
        eprintln!(
            "x4_v4_report: refusing record profile {profile:?}; Ligero/v3 are historical read-only"
        );
        std::process::exit(2);
    }
    assert_eq!(PROFILE_NAME_V4, X4_V4_RECORD_PROFILE.as_bytes());
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|index| format!("x4-v4-cpu-{index}"))
        .build_global()
        .expect("X4 v4 report initializes the four-worker CPU pool first");

    eprintln!("X4 v4: building retained synthetic model-global cohorts ...");
    let fixture_a = SyntheticFixture::build(16, V4ArtifactPolicy::PersistOracleAndMerkle);
    let fixture_b = SyntheticFixture::build(32, V4ArtifactPolicy::PersistOracleAndMerkle);
    let fixture_recompute = SyntheticFixture::build(16, V4ArtifactPolicy::RecomputeOracleAndMerkle);
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
    let persisted_reference = run_case(&fixture_a, 8, 900, 90);
    let recompute_case = run_case(&fixture_recompute, 8, 900, 90);
    let recompute_matches = persisted_reference.response_digest == recompute_case.response_digest;

    eprintln!("X4 v4: same-process ABBA unopened-block comparison ...");
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
            && case.seam_full_correlations_prover == case.expected_seam_full_correlations
            && case.seam_full_correlations_verifier == case.expected_seam_full_correlations
            && case.allocation_digest_match
    });
    let formula_exact = touched_family
        .iter()
        .chain([&unopened_double_case, &recompute_case])
        .all(|case| case.bytes.closed_formula_total == case.bytes.serialized_total);
    let unopened_payload_bytes =
        ((fixture_b.total_blocks - fixture_a.total_blocks) * WEIGHT_COEFFICIENTS * 16) as i64;
    let no_linear_unopened_payload =
        marginal_serialized_bytes >= 0 && marginal_serialized_bytes < unopened_payload_bytes;
    let g5_pass = family_exact && formula_exact && no_linear_unopened_payload && abba.pass;
    let artifacts_a = artifact_record(&fixture_a);
    let artifacts_b = artifact_record(&fixture_b);
    let artifacts_recompute = artifact_record(&fixture_recompute);
    let expected_oracle_per_block = ((WEIGHT_COEFFICIENTS + AUX_COEFFICIENTS) * 8 * 16) as u64;
    let artifacts_reconcile = artifacts_a.logical_first_oracle_bytes
        == fixture_a.total_blocks as u64 * expected_oracle_per_block
        && artifacts_b.logical_first_oracle_bytes
            == fixture_b.total_blocks as u64 * expected_oracle_per_block
        && recompute_case.traffic.recomputed_oracle_bytes
            + recompute_case.traffic.recomputed_merkle_bytes
            == artifacts_recompute.response_recomputed_bytes
        && recompute_case.traffic.recomputed_source_bytes_read
            == 2 * artifacts_recompute.coefficient_bytes;
    let g6_present = artifacts_a.source_i16_weight_bytes > 0
        && artifacts_a.coefficient_bytes > 0
        && artifacts_a.logical_first_oracle_bytes > 0
        && artifacts_a.merkle_digest_bytes > 0
        && artifacts_a.maximum_cohort_working_set_bytes > 0
        && recompute_case.traffic.host_logical_bytes_read > 0
        && recompute_case.traffic.host_logical_bytes_written > 0;
    let g6_pass = g6_present && artifacts_reconcile && recompute_matches;
    let gate = GateRecord {
        overall_x4_verdict: "NOT_EVALUATED_UNTIL_GPT2_MIGRATION_AND_A100_RECORDS".to_owned(),
        evaluated_scope: "CPU synthetic schema-4 G1/G2/G5/G6".to_owned(),
        g1_lean_green: true,
        g2_synthetic_honest_accepts: family_exact,
        g2_permanent_tamper_suite_green: true,
        g3_gpt2_not_evaluated_here: true,
        g4_gpt2_not_evaluated_here: true,
        g5_touched_family_exact: family_exact,
        g5_closed_byte_formula_exact: formula_exact,
        g5_no_linear_unopened_payload: no_linear_unopened_payload,
        g5_abba_ratio_ceiling: 1.05,
        g5_abba_pass: abba.pass,
        g5_verdict: if g5_pass { "PASS" } else { "FAIL" }.to_owned(),
        g6_all_categories_present: g6_present,
        g6_artifacts_reconcile: artifacts_reconcile,
        g6_recompute_proof_identical: recompute_matches,
        g6_verdict: if g6_pass { "PASS" } else { "FAIL" }.to_owned(),
    };
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let dirty = git_dirty();
    let report = Report {
        schema: 2,
        milestone: "X4-v4-CPU-synthetic".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: dirty,
        cpu_only: true,
        rayon_workers: rayon::current_num_threads(),
        detected_logical_cpus: std::thread::available_parallelism().map(usize::from).unwrap_or(0),
        cpu_model: cpu_model(),
        peak_rss_bytes: peak_rss_bytes(),
        profile,
        design_sha256: DESIGN_SHA256.to_owned(),
        frozen_design_baseline_sha256: FROZEN_DESIGN_BASELINE_SHA256.to_owned(),
        lean_checkpoint: LEAN_CHECKPOINT.to_owned(),
        lean_targets: "209 total / 116 X4; 46 v4; zero sorry/admit; standard axioms only"
            .to_owned(),
        soundness_expression:
            "3320*(9/16)^111 + 28522064267253/340282366762482138490186164457219031041"
                .to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        required_soundness_bits: SOUNDNESS_FLOOR_BITS,
        soundness_margin_bits: SOUNDNESS_BITS - SOUNDNESS_FLOOR_BITS,
        soundness_resummed_new_terms: 0,
        query_count: QUERIES,
        rate: "1/8 strict unique decoding".to_owned(),
        field_symbol_bytes: 16,
        synthetic_weight_variables: WEIGHT_VARIABLES,
        synthetic_aux_variables: AUX_VARIABLES,
        commit_seconds_total16: fixture_a.commit_s,
        commit_seconds_total32: fixture_b.commit_s,
        commit_seconds_recompute16: fixture_recompute.commit_s,
        touched_family,
        unopened_double_case,
        recompute_case,
        recompute_matches_persisted_response: recompute_matches,
        abba,
        artifacts_persist_total16: artifacts_a,
        artifacts_persist_total32: artifacts_b,
        artifacts_recompute_total16: artifacts_recompute,
        security_counter_inventory: X4V4CounterFamily::ALL
            .iter()
            .map(|family| family.name().to_owned())
            .collect(),
        permanent_test_command: "cargo test -p volta-pcs 'x4::'".to_owned(),
        permanent_test_status: "55 passed before record checkpoint; full workspace rerun required at checkpoint"
            .to_owned(),
        historical_ligero_policy:
            "read-only historical verification; every v4 record-producing mode refuses Ligero/v3"
                .to_owned(),
        pending_pod_preflight:
            "R1b NOTE-6 c3_weights two-weight-set leakage smoke is mandatory before pod records"
                .to_owned(),
        deviations: vec![
            "Synthetic dimensions are deliberately small and carry no GPT-2 G3/G4 verdict."
                .to_owned(),
            "The CPU reference materializes one complete cohort at a time; logical working-set counters and measured VmHWM are both reported. No strip-cap claim is made."
                .to_owned(),
            "File and device traffic are exactly zero for this in-memory CPU run; logical host reads/writes are reported separately and are nonzero."
                .to_owned(),
        ],
        gate,
    };
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    println!("{json}");
    eprintln!(
        "X4 v4 CPU synthetic: G5={} G6={} ABBA={:.6} peak={} B",
        report.gate.g5_verdict, report.gate.g6_verdict, report.abba.b_over_a, report.peak_rss_bytes
    );
    if record {
        if dirty {
            eprintln!("x4_v4_report: refusing a run-of-record from a tracked-dirty tree");
            std::process::exit(2);
        }
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results")
            .join(format!("x4-v4-cpu-synthetic-{date}-{git_short_sha}.json"));
        if path.exists() {
            eprintln!("x4_v4_report: append-only record already exists: {}", path.display());
            std::process::exit(2);
        }
        std::fs::write(&path, json).expect("write append-only X4 v4 CPU record");
        eprintln!("wrote {}", path.display());
    }
    if !g5_pass || !g6_pass {
        std::process::exit(1);
    }
}

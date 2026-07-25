//! Exact local X4d response projection and settlement-codec references.
//!
//! This is a codec/counter generator only. It performs no model proof and no
//! oracle opening, and therefore is never a G1/G2/G5 pod verdict.

use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use volta_bench::x4d_gpt2::{
    x4d_codec_reference_v1, X4dGpt2SettlementCountersV1, X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1,
    X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1,
};
use volta_pcs::x4::{
    x4d_gpt2_settlement_bytes_v1, X4D_GPT2_RESPONSE_BYTES_V1, X4D_PROFILE_NAME_V1,
};

const PREFLIGHT_PATH: &str =
    "benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json";
const DESIGN_PATH: &str = "docs/x4d-deferred-settlement-design.md";

#[derive(Serialize)]
struct ResponseReference {
    accounting_kind: &'static str,
    product_state_at_delivery: &'static str,
    model_transcript_bytes: u64,
    model_mac_closure_bytes: u64,
    pcs_bytes: u64,
    exact_response_bytes: u64,
    materialized_wire_fixture: bool,
}

#[derive(Serialize)]
struct SettlementReference {
    responses: usize,
    claims: usize,
    masked_groups: usize,
    active_chain_polynomials: usize,
    fold_rounds: usize,
    query_draws: usize,
    serialized_bytes: u64,
    expected_bytes: u64,
    sha256: String,
    settlement_bytes_per_response: f64,
    total_amortized_bytes_per_response: f64,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: &'static str,
    profile: String,
    git_sha: String,
    git_dirty: bool,
    design_path: &'static str,
    design_sha256: String,
    source_path: &'static str,
    source_sha256: String,
    preflight_path: &'static str,
    preflight_sha256: String,
    historical_references_modified: bool,
    proof_or_gate_verdict: bool,
    response: ResponseReference,
    settlements: Vec<SettlementReference>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn output(args: &[&str]) -> Result<String, String> {
    let result = Command::new(args[0])
        .args(&args[1..])
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("run {}: {error}", args[0]))?;
    if !result.status.success() {
        return Err(format!("{} exited unsuccessfully", args[0]));
    }
    String::from_utf8(result.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| format!("{} emitted non-UTF8", args[0]))
}

fn sha256(path: &Path) -> Result<String, String> {
    let path = path.to_str().ok_or_else(|| "non-UTF8 SHA-256 path".to_owned())?;
    output(&["sha256sum", path])?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn sha256_bytes(bytes: &[u8], tag: usize) -> Result<String, String> {
    let path =
        std::env::temp_dir().join(format!("volta-x4d-codec-{}-{tag}.bin", std::process::id()));
    std::fs::write(&path, bytes)
        .map_err(|error| format!("write temporary X4d codec bytes: {error}"))?;
    let digest = sha256(&path);
    let _ = std::fs::remove_file(path);
    digest
}

fn selected_draws() -> Result<Vec<u64>, String> {
    let bytes = std::fs::read(repo_root().join(PREFLIGHT_PATH))
        .map_err(|error| format!("read frozen preflight: {error}"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse frozen preflight: {error}"))?;
    value["candidates"]
        .as_array()
        .and_then(|candidates| candidates.iter().find(|candidate| candidate["id"] == "e29-r3-s111"))
        .and_then(|candidate| candidate["challenge"]["ordered_draws"].as_array())
        .ok_or_else(|| "frozen selected draw tape is missing".to_owned())?
        .iter()
        .map(|draw| draw.as_u64().ok_or_else(|| "non-u64 selected draw".to_owned()))
        .collect()
}

fn run() -> Result<Report, String> {
    let draws = selected_draws()?;
    let response = ResponseReference {
        accounting_kind: "exact_x4c_response_traffic_projection_without_pcs",
        product_state_at_delivery: "WEIGHT_PENDING",
        model_transcript_bytes: X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1,
        model_mac_closure_bytes: X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1,
        pcs_bytes: 0,
        exact_response_bytes: X4D_GPT2_RESPONSE_BYTES_V1,
        materialized_wire_fixture: false,
    };
    let mut settlements = Vec::new();
    for responses in [1usize, 8, 16, 32] {
        let counters = X4dGpt2SettlementCountersV1::for_responses(responses)?;
        let reference = x4d_codec_reference_v1(responses, draws.clone())?;
        let serialized_bytes = reference.encoded.len() as u64;
        let expected_bytes = x4d_gpt2_settlement_bytes_v1(responses)
            .map_err(|error| format!("X4d settlement formula: {error:?}"))?;
        if serialized_bytes != expected_bytes {
            return Err(format!("X4d k={responses} reference length changed"));
        }
        settlements.push(SettlementReference {
            responses,
            claims: counters.frozen_claims,
            masked_groups: counters.masked_groups,
            active_chain_polynomials: counters.active_chain_polynomials,
            fold_rounds: counters.fold_rounds,
            query_draws: counters.query_draws,
            serialized_bytes,
            expected_bytes,
            sha256: sha256_bytes(&reference.encoded, responses)?,
            settlement_bytes_per_response: serialized_bytes as f64 / responses as f64,
            total_amortized_bytes_per_response: X4D_GPT2_RESPONSE_BYTES_V1 as f64
                + serialized_bytes as f64 / responses as f64,
        });
    }
    let root = repo_root();
    Ok(Report {
        schema: 1,
        milestone: "X4d-Phase2-local-codec-reference",
        profile: String::from_utf8_lossy(X4D_PROFILE_NAME_V1).into_owned(),
        git_sha: output(&["git", "rev-parse", "HEAD"])?,
        git_dirty: !output(&["git", "status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        design_path: DESIGN_PATH,
        design_sha256: sha256(&root.join(DESIGN_PATH))?,
        source_path: "rust/volta-bench/src/bin/x4d_codec_reference.rs",
        source_sha256: sha256(&root.join("rust/volta-bench/src/bin/x4d_codec_reference.rs"))?,
        preflight_path: PREFLIGHT_PATH,
        preflight_sha256: sha256(&root.join(PREFLIGHT_PATH))?,
        historical_references_modified: false,
        proof_or_gate_verdict: false,
        response,
        settlements,
    })
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let report = run().unwrap_or_else(|error| panic!("X4d codec reference failed: {error}"));
    let encoded = serde_json::to_vec_pretty(&report).expect("serialize X4d codec reference");
    match args.as_slice() {
        [_] => println!("{}", String::from_utf8(encoded).expect("JSON is UTF-8")),
        [_, flag, path] if flag == "--output" => {
            let mut encoded = encoded;
            encoded.push(b'\n');
            std::fs::write(path, encoded).expect("write X4d codec reference");
        }
        _ => panic!("usage: x4d_codec_reference [--output PATH]"),
    }
}

//! Append-only paired verdict for the X4d.2 k=1/k=16 settlement gate.
//!
//! This adapter performs no proving. It consumes two fresh same-host records
//! produced by `x4d_gpt2_pod_record`, checks all binding counters and inherited
//! hot-path gates, and writes the gate decision without allowing the
//! informative X4c wall target to affect `overall_pass`.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMA: u64 = 2;
const INPUT_SCHEMA: u64 = 3;
const INPUT_MILESTONE: &str = "X4d.2-GPT2-resident-settlement-v1";
const MILESTONE: &str = "X4d.2-GPT2-flatness-gate-v1";
const PROFILE: &str = "runpod-a100-x4d-v1";
const PROTOCOL: &str = "x4-zkdeepfold-ud-e29-v4+x4d-deferred-settlement-v1";
const WALL_SEMANTICS: &str = "durable accumulator seal through terminal settlement success, including queued-response priority pause and fresh auxiliary materialization";
const FLATNESS_CEILING: f64 = 1.30;
const INTERFERENCE_CEILING_PERCENT: f64 = 1.00;
const INFORMATIVE_X4C_LOWER_S: f64 = 288.0;
const INFORMATIVE_X4C_UPPER_S: f64 = 307.0;
const UNIQUE_EVALUATION_TABLES: u64 = 102;
const UNIQUE_EVALUATION_TABLE_SYMBOLS: u64 = 601_161_728;
const UNIQUE_CLAIM_REDUCE_SOURCES: u64 = 51;
const UNIQUE_CLAIM_REDUCE_SOURCE_SYMBOLS: u64 = 298_844_160;
const INITIAL_ENCODED_SYMBOLS: u64 = 4_809_293_824;
const COMBINED_CODEWORD_SYMBOLS: u64 = 1_159_200_768;
const RESPONSE_BYTES: u64 = 41_270_464;

struct Args {
    k1: PathBuf,
    k16: PathBuf,
    output: PathBuf,
}

fn usage() -> ! {
    eprintln!("usage: x4d2_flatness_record --k1 PATH --k16 PATH --output FRESH_PATH");
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut k1 = None;
    let mut k16 = None;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--k1" => k1 = Some(PathBuf::from(value())),
            "--k16" => k16 = Some(PathBuf::from(value())),
            "--output" => output = Some(PathBuf::from(value())),
            _ => usage(),
        }
    }
    Args {
        k1: k1.unwrap_or_else(|| usage()),
        k16: k16.unwrap_or_else(|| usage()),
        output: output.unwrap_or_else(|| usage()),
    }
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("run sha256sum: {error}"))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "sha256sum emitted non-UTF8".to_owned())?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn producer_source_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/x4d2_flatness_record.rs")
}

fn clean_git_sha() -> Result<String, String> {
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|error| format!("git status: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("paired verdict requires a clean git tree".to_owned());
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("git rev-parse: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "git SHA is not UTF-8".to_owned())
}

fn write_append_only<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create append-only record {}: {error}", path.display()))?;
    let encoded =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize record: {error}"))?;
    file.write_all(&encoded)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist record {}: {error}", path.display()))
}

fn validate_output_path(path: &Path) -> Result<(), String> {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    if !name.starts_with("x4d2-") || !name.ends_with(".json") {
        return Err("paired verdict requires an x4d2-*.json output name".to_owned());
    }
    Ok(())
}

#[derive(Deserialize)]
struct CloudRow {
    instance_id: String,
}

#[derive(Deserialize)]
struct HardwareRow {
    gpu_uuid: String,
    mem_total_bytes: u64,
    volume_total_bytes: u64,
    response_cpu_ids: Vec<usize>,
    settlement_cpu_ids: Vec<usize>,
    overall_pass: bool,
}

#[derive(Deserialize)]
struct ResponseRow {
    total_g1_s: f64,
    response_bytes: u64,
    accepted: bool,
}

#[derive(Deserialize)]
struct G1Row {
    selected_total_s: f64,
    overall_pass: bool,
}

#[derive(Deserialize)]
struct InterferenceRow {
    percentage_delta: f64,
}

#[derive(Deserialize)]
struct InstrumentationRow {
    claim_reduce_calls: u64,
    claim_reduce_frozen_claims: u64,
    claim_reduce_unique_sources: u64,
    claim_reduce_unique_source_symbols: u64,
    unique_evaluation_tables: u64,
    unique_evaluation_table_symbols: u64,
    materialized_relation_terms: u64,
    fused_relation_terms: u64,
    logical_evaluation_table_symbols_read: u64,
    evaluation_table_passes_per_unique_table: u64,
    encoded_oracle_full_passes: u64,
    response_or_claim_proportional_encoded_oracle_passes: u64,
    initial_encoded_symbols_read: u64,
    combined_codeword_symbols: u64,
    query_gather_calls: u64,
}

#[derive(Deserialize)]
struct SettlementRow {
    responses: usize,
    wall_semantics: String,
    seal_to_terminal_wall_s: f64,
    instrumentation: InstrumentationRow,
    interference: InterferenceRow,
    accepted: bool,
}

#[derive(Deserialize)]
struct InputRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    producer_source_sha256: String,
    profile: String,
    protocol: String,
    design_sha256: String,
    cloud: CloudRow,
    hardware: HardwareRow,
    flatness_pair_role: String,
    responses: Vec<ResponseRow>,
    g1: G1Row,
    settlement: SettlementRow,
}

#[derive(Serialize)]
struct RunSummary {
    input_path: String,
    input_sha256: String,
    responses: usize,
    settlement_wall_s: f64,
    selected_g1_wall_s: f64,
    g1_overall_pass: bool,
    settlement_accepted: bool,
    min_response_wall_s: f64,
    max_response_wall_s: f64,
    response_bytes: u64,
    interference_percentage_delta: f64,
    claim_reduce_calls: u64,
    claim_reduce_frozen_claims: u64,
    claim_reduce_unique_sources: u64,
    claim_reduce_unique_source_symbols: u64,
    unique_evaluation_table_symbols: u64,
    encoded_oracle_full_passes: u64,
    query_gather_calls: u64,
    initial_encoded_symbols_read: u64,
    combined_codeword_symbols: u64,
    materialized_relation_terms: u64,
    fused_relation_terms: u64,
}

#[derive(Serialize)]
struct InformativeTarget {
    lower_s: f64,
    upper_s: f64,
    k16_at_or_below_upper: bool,
    affects_binding_gate: bool,
    policy: String,
}

#[derive(Serialize)]
struct VerdictRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    producer_source_sha256: String,
    profile: String,
    protocol: String,
    design_sha256: String,
    same_host: bool,
    wall_semantics: String,
    k1: RunSummary,
    k16: RunSummary,
    settlement_wall_ratio_k16_over_k1: f64,
    flatness_ceiling: f64,
    wall_flatness_pass: bool,
    initial_encoded_symbols_equal: bool,
    combined_codeword_symbols_equal: bool,
    unique_evaluation_table_symbols_equal: bool,
    unique_claim_reduce_source_symbols_equal: bool,
    encoded_oracle_full_passes_equal: bool,
    query_gather_calls_equal: bool,
    physical_counter_gate_pass: bool,
    g1_rerun_pass: bool,
    response_bytes_unchanged: bool,
    interference_ceiling_percentage_delta: f64,
    interference_rerun_pass: bool,
    inherited_settlement_gates_pass: bool,
    binding_gate_verdict_verbatim: String,
    informative_target: InformativeTarget,
    historical_rows_modified: bool,
    overall_pass: bool,
}

fn positive_finite(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn input_valid(row: &InputRecord, responses: usize, role: &str) -> bool {
    let counters = &row.settlement.instrumentation;
    row.schema == INPUT_SCHEMA
        && row.milestone == INPUT_MILESTONE
        && !row.git_dirty
        && row.profile == PROFILE
        && row.protocol == PROTOCOL
        && row.hardware.overall_pass
        && row.flatness_pair_role == role
        && row.responses.len() == responses + 3
        && row.responses.iter().all(|response| {
            response.accepted
                && response.response_bytes == RESPONSE_BYTES
                && positive_finite(response.total_g1_s)
        })
        && positive_finite(row.g1.selected_total_s)
        && row.settlement.responses == responses
        && row.settlement.wall_semantics == WALL_SEMANTICS
        && positive_finite(row.settlement.seal_to_terminal_wall_s)
        && row.settlement.interference.percentage_delta.is_finite()
        && counters.claim_reduce_calls == 51 * responses as u64
        && counters.claim_reduce_frozen_claims == 102 * responses as u64
        && counters.claim_reduce_unique_sources == UNIQUE_CLAIM_REDUCE_SOURCES
        && counters.claim_reduce_unique_source_symbols == UNIQUE_CLAIM_REDUCE_SOURCE_SYMBOLS
        && counters.unique_evaluation_tables == UNIQUE_EVALUATION_TABLES
        && counters.unique_evaluation_table_symbols == UNIQUE_EVALUATION_TABLE_SYMBOLS
        && counters.materialized_relation_terms == UNIQUE_EVALUATION_TABLES
        && counters.fused_relation_terms
            == UNIQUE_EVALUATION_TABLES * u64::try_from(responses - 1).unwrap()
        && counters.logical_evaluation_table_symbols_read == UNIQUE_EVALUATION_TABLE_SYMBOLS
        && counters.evaluation_table_passes_per_unique_table == 1
        && counters.encoded_oracle_full_passes == 1
        && counters.response_or_claim_proportional_encoded_oracle_passes == 0
        && counters.initial_encoded_symbols_read == INITIAL_ENCODED_SYMBOLS
        && counters.combined_codeword_symbols == COMBINED_CODEWORD_SYMBOLS
        && counters.query_gather_calls == 1
}

fn summary(path: &Path, digest: String, row: &InputRecord) -> RunSummary {
    let min_response_wall_s =
        row.responses.iter().map(|item| item.total_g1_s).fold(f64::INFINITY, f64::min);
    let max_response_wall_s = row.responses.iter().map(|item| item.total_g1_s).fold(0.0, f64::max);
    let counters = &row.settlement.instrumentation;
    RunSummary {
        input_path: path.display().to_string(),
        input_sha256: digest,
        responses: row.settlement.responses,
        settlement_wall_s: row.settlement.seal_to_terminal_wall_s,
        selected_g1_wall_s: row.g1.selected_total_s,
        g1_overall_pass: row.g1.overall_pass,
        settlement_accepted: row.settlement.accepted,
        min_response_wall_s,
        max_response_wall_s,
        response_bytes: RESPONSE_BYTES,
        interference_percentage_delta: row.settlement.interference.percentage_delta,
        claim_reduce_calls: counters.claim_reduce_calls,
        claim_reduce_frozen_claims: counters.claim_reduce_frozen_claims,
        claim_reduce_unique_sources: counters.claim_reduce_unique_sources,
        claim_reduce_unique_source_symbols: counters.claim_reduce_unique_source_symbols,
        unique_evaluation_table_symbols: counters.unique_evaluation_table_symbols,
        encoded_oracle_full_passes: counters.encoded_oracle_full_passes,
        query_gather_calls: counters.query_gather_calls,
        initial_encoded_symbols_read: counters.initial_encoded_symbols_read,
        combined_codeword_symbols: counters.combined_codeword_symbols,
        materialized_relation_terms: counters.materialized_relation_terms,
        fused_relation_terms: counters.fused_relation_terms,
    }
}

fn evaluate(args: &Args) -> Result<VerdictRecord, String> {
    let k1_bytes = fs::read(&args.k1).map_err(|error| format!("read k=1 record: {error}"))?;
    let k16_bytes = fs::read(&args.k16).map_err(|error| format!("read k=16 record: {error}"))?;
    let k1: InputRecord =
        serde_json::from_slice(&k1_bytes).map_err(|error| format!("parse k=1 record: {error}"))?;
    let k16: InputRecord = serde_json::from_slice(&k16_bytes)
        .map_err(|error| format!("parse k=16 record: {error}"))?;
    if !input_valid(&k1, 1, "k1-anchor")
        || !input_valid(&k16, 16, "k16-candidate+unchanged-g1-interference-rerun")
    {
        return Err("an X4d.2 input record failed its structural or inherited gates".to_owned());
    }
    let same_host = k1.git_sha == k16.git_sha
        && k1.producer_source_sha256 == k16.producer_source_sha256
        && k1.design_sha256 == k16.design_sha256
        && k1.cloud.instance_id == k16.cloud.instance_id
        && k1.hardware.gpu_uuid == k16.hardware.gpu_uuid
        && k1.hardware.mem_total_bytes == k16.hardware.mem_total_bytes
        && k1.hardware.volume_total_bytes == k16.hardware.volume_total_bytes
        && k1.hardware.response_cpu_ids == k16.hardware.response_cpu_ids
        && k1.hardware.settlement_cpu_ids == k16.hardware.settlement_cpu_ids;
    if !same_host {
        return Err("k=1 and k=16 records are not from the same pinned host/build".to_owned());
    }
    if clean_git_sha()? != k1.git_sha {
        return Err("paired verdict checkout differs from the input record checkpoint".to_owned());
    }
    let k1_wall = k1.settlement.seal_to_terminal_wall_s;
    let k16_wall = k16.settlement.seal_to_terminal_wall_s;
    let wall_ratio = k16_wall / k1_wall;
    let wall_flatness_pass = wall_ratio <= FLATNESS_CEILING;
    let initial_encoded_symbols_equal = k1.settlement.instrumentation.initial_encoded_symbols_read
        == k16.settlement.instrumentation.initial_encoded_symbols_read;
    let combined_codeword_symbols_equal = k1.settlement.instrumentation.combined_codeword_symbols
        == k16.settlement.instrumentation.combined_codeword_symbols;
    let unique_evaluation_table_symbols_equal =
        k1.settlement.instrumentation.unique_evaluation_table_symbols
            == k16.settlement.instrumentation.unique_evaluation_table_symbols;
    let unique_claim_reduce_source_symbols_equal =
        k1.settlement.instrumentation.claim_reduce_unique_source_symbols
            == k16.settlement.instrumentation.claim_reduce_unique_source_symbols;
    let encoded_oracle_full_passes_equal = k1.settlement.instrumentation.encoded_oracle_full_passes
        == k16.settlement.instrumentation.encoded_oracle_full_passes;
    let query_gather_calls_equal = k1.settlement.instrumentation.query_gather_calls
        == k16.settlement.instrumentation.query_gather_calls;
    let physical_counter_gate_pass = initial_encoded_symbols_equal
        && combined_codeword_symbols_equal
        && unique_evaluation_table_symbols_equal
        && unique_claim_reduce_source_symbols_equal
        && encoded_oracle_full_passes_equal
        && query_gather_calls_equal;
    let g1_rerun_pass = k1.g1.overall_pass && k16.g1.overall_pass;
    let response_bytes_unchanged = k1
        .responses
        .iter()
        .chain(&k16.responses)
        .all(|response| response.response_bytes == RESPONSE_BYTES);
    let interference_rerun_pass =
        k16.settlement.interference.percentage_delta <= INTERFERENCE_CEILING_PERCENT;
    let inherited_settlement_gates_pass = k1.settlement.accepted && k16.settlement.accepted;
    let overall_pass = same_host
        && wall_flatness_pass
        && physical_counter_gate_pass
        && g1_rerun_pass
        && response_bytes_unchanged
        && interference_rerun_pass
        && inherited_settlement_gates_pass;
    let gate_word = if overall_pass { "PASS" } else { "FAIL" };
    Ok(VerdictRecord {
        schema: SCHEMA,
        milestone: MILESTONE.to_owned(),
        git_sha: k1.git_sha.clone(),
        git_dirty: false,
        producer_source_sha256: sha256(&producer_source_path())?,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        design_sha256: k1.design_sha256.clone(),
        same_host,
        wall_semantics: WALL_SEMANTICS.to_owned(),
        k1: summary(&args.k1, sha256(&args.k1)?, &k1),
        k16: summary(&args.k16, sha256(&args.k16)?, &k16),
        settlement_wall_ratio_k16_over_k1: wall_ratio,
        flatness_ceiling: FLATNESS_CEILING,
        wall_flatness_pass,
        initial_encoded_symbols_equal,
        combined_codeword_symbols_equal,
        unique_evaluation_table_symbols_equal,
        unique_claim_reduce_source_symbols_equal,
        encoded_oracle_full_passes_equal,
        query_gather_calls_equal,
        physical_counter_gate_pass,
        g1_rerun_pass,
        response_bytes_unchanged,
        interference_ceiling_percentage_delta: INTERFERENCE_CEILING_PERCENT,
        interference_rerun_pass,
        inherited_settlement_gates_pass,
        binding_gate_verdict_verbatim: format!(
            "{gate_word} — FLATNESS IN k: settlement_wall(k=16) <= 1.30 x \
             settlement_wall(k=1), with equal initial_encoded_symbols_read, \
             combined_codeword_symbols, unique physical evaluation/source \
             symbols, encoded-oracle pass count and query-gather count"
        ),
        informative_target: InformativeTarget {
            lower_s: INFORMATIVE_X4C_LOWER_S,
            upper_s: INFORMATIVE_X4C_UPPER_S,
            k16_at_or_below_upper: k16_wall <= INFORMATIVE_X4C_UPPER_S,
            affects_binding_gate: false,
            policy:
                "Informative only: a 350 s k=16 wall with a green flatness gate is PASS with a note, not FAIL"
                    .to_owned(),
        },
        historical_rows_modified: false,
        overall_pass,
    })
}

fn main() {
    let args = parse_args();
    let result = (|| {
        validate_output_path(&args.output)?;
        if args.output.exists() {
            return Err("paired verdict output must be fresh".to_owned());
        }
        let record = evaluate(&args)?;
        let overall_pass = record.overall_pass;
        write_append_only(&args.output, &record)?;
        if !overall_pass {
            return Err("X4d.2 binding or inherited gate failed; record retained".to_owned());
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("x4d2_flatness_record HARD STOP: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn informative_target_cannot_change_the_binding_flatness_predicate() {
        let k1_wall = 300.0;
        let k16_wall = 350.0;
        assert!(k16_wall / k1_wall <= FLATNESS_CEILING);
        assert!(k16_wall > INFORMATIVE_X4C_UPPER_S);
    }

    #[test]
    fn production_counter_constants_are_the_single_pass_x4c_anchors() {
        assert_eq!(INITIAL_ENCODED_SYMBOLS, 4_809_293_824);
        assert_eq!(COMBINED_CODEWORD_SYMBOLS, 1_159_200_768);
        assert_eq!(UNIQUE_EVALUATION_TABLE_SYMBOLS, 601_161_728);
        assert_eq!(UNIQUE_CLAIM_REDUCE_SOURCE_SYMBOLS, 298_844_160);
    }
}

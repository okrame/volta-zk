//! Fase-D G2/G2b/G3 record harness.
//!
//! This binary is intentionally separate from the proving-path reports: it
//! measures the connection-scoped PCG setup and lifecycle without changing a
//! proof, transcript, response byte, PCS query, or challenge.  Part A builds
//! and tests it but must not execute an official record run.

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use volta_pcg::{
    open_fase_d_connection_with_ggm_prg, ConnectionBinding, ConnectionChannelDirection,
    ConnectionStore, CorrelationDomain, FaseDParams, FaseDStagePlan, GgmPrg,
    ResponseAuthorizationStore,
};

#[derive(Clone, Debug)]
struct Args {
    plan: FaseDStagePlan,
    connection_store: Option<PathBuf>,
    authorization_store: Option<PathBuf>,
    responses: usize,
    abort_on_response: Option<usize>,
    ggm_prg: GgmPrg,
    diagnostic: bool,
}

#[derive(Serialize)]
struct ResponseRow {
    ordinal: usize,
    accepted: bool,
    authorization_burn_digest: String,
    allocation_digest: String,
    channel_ledger_digest: String,
    correlations_consumed: u64,
    base_ot_bytes: u64,
    ot_extension_bytes: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage: fase_d_report --connection-store PATH --authorization-store PATH \
         [--plan terminal-one|chain-six] [--responses N | --abort-on-response N] \
         [--ggm-prg aes128-mmo|blake3] [--diagnostic]"
    );
    std::process::exit(2);
}

fn parse_plan(value: &str) -> FaseDStagePlan {
    match value {
        "terminal-one" => FaseDStagePlan::TerminalOne,
        "chain-six" => FaseDStagePlan::ChainSix,
        _ => usage(),
    }
}

fn parse_args() -> Args {
    let mut out = Args {
        plan: FaseDStagePlan::TerminalOne,
        connection_store: None,
        authorization_store: None,
        responses: 0,
        abort_on_response: None,
        ggm_prg: GgmPrg::Aes128Mmo,
        diagnostic: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--plan" {
            out.plan = parse_plan(&args.next().unwrap_or_else(|| usage()));
        } else if let Some(value) = arg.strip_prefix("--plan=") {
            out.plan = parse_plan(value);
        } else if arg == "--connection-store" {
            out.connection_store = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.strip_prefix("--connection-store=") {
            out.connection_store = Some(PathBuf::from(value));
        } else if arg == "--authorization-store" {
            out.authorization_store = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.strip_prefix("--authorization-store=") {
            out.authorization_store = Some(PathBuf::from(value));
        } else if arg == "--responses" {
            out.responses =
                args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
        } else if let Some(value) = arg.strip_prefix("--responses=") {
            out.responses = value.parse().unwrap_or_else(|_| usage());
        } else if arg == "--abort-on-response" {
            out.abort_on_response =
                Some(args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()));
        } else if let Some(value) = arg.strip_prefix("--abort-on-response=") {
            out.abort_on_response = Some(value.parse().unwrap_or_else(|_| usage()));
        } else if arg == "--ggm-prg" {
            out.ggm_prg =
                args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
        } else if let Some(value) = arg.strip_prefix("--ggm-prg=") {
            out.ggm_prg = value.parse().unwrap_or_else(|_| usage());
        } else if arg == "--diagnostic" {
            out.diagnostic = true;
        } else {
            usage();
        }
    }
    if out.connection_store.is_none() || out.authorization_store.is_none() {
        usage();
    }
    if out.responses != 0 && out.abort_on_response.is_some() {
        eprintln!("fase_d_report: --responses and --abort-on-response are mutually exclusive");
        std::process::exit(2);
    }
    if out.abort_on_response == Some(0) {
        eprintln!("fase_d_report: abort ordinal is one-based");
        std::process::exit(2);
    }
    if out.plan == FaseDStagePlan::ChainSix
        && (out.responses != 0 || out.abort_on_response.is_some())
    {
        eprintln!("fase_d_report: chain-six is digest-and-release and cannot serve responses");
        std::process::exit(2);
    }
    if out.ggm_prg == GgmPrg::Blake3 && !out.diagnostic {
        eprintln!("fase_d_report: BLAKE3 GGM is diagnostic-only");
        std::process::exit(2);
    }
    out
}

fn os_identity(label: &str) -> [u8; 32] {
    let mut value = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut value)
        .unwrap_or_else(|error| panic!("OS entropy unavailable for {label}: {error}"));
    value
}

fn git_head_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|output| !output.status.success() || !output.stdout.is_empty())
        .unwrap_or(true)
}

fn date() -> String {
    std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn detected_logical_cpu_cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

fn detected_physical_cpu_cores(logical_fallback: usize) -> usize {
    let mut cores = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(index) = name.strip_prefix("cpu") else {
                continue;
            };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let topology = entry.path().join("topology");
            let package = std::fs::read_to_string(topology.join("physical_package_id"));
            let core = std::fs::read_to_string(topology.join("core_id"));
            if let (Ok(package), Ok(core)) = (package, core) {
                cores.insert((package.trim().to_owned(), core.trim().to_owned()));
            }
        }
    }
    if cores.is_empty() {
        logical_fallback
    } else {
        cores.len()
    }
}

fn unique_result_path(plan: FaseDStagePlan, date: &str, sha: &str) -> PathBuf {
    let label = match plan {
        FaseDStagePlan::TerminalOne => "fase-d-terminal-one",
        FaseDStagePlan::ChainSix => "fase-d-chain-six",
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results");
    for suffix in 0..1000 {
        let name = if suffix == 0 {
            format!("{label}-{date}-{}.json", &sha[..sha.len().min(7)])
        } else {
            format!("{label}-{date}-{}-{suffix}.json", &sha[..sha.len().min(7)])
        };
        let path = root.join(name);
        if !path.exists() {
            return path;
        }
    }
    panic!("no unused fase-D result path");
}

fn main() {
    let args = parse_args();
    let sha_before = git_head_sha();
    if sha_before.is_empty() || (!args.diagnostic && git_dirty()) {
        eprintln!("fase_d_report: record mode requires an available, clean git revision");
        std::process::exit(2);
    }
    let connection_store = ConnectionStore::new(args.connection_store.as_ref().unwrap())
        .unwrap_or_else(|error| panic!("connection-store preflight failed: {error}"));
    let authorization_store =
        ResponseAuthorizationStore::new(args.authorization_store.as_ref().unwrap())
            .unwrap_or_else(|error| panic!("authorization-store preflight failed: {error}"));
    let binding = ConnectionBinding::new(
        os_identity("connection identity"),
        os_identity("authenticated channel identity"),
        args.plan,
    )
    .unwrap();
    let params = FaseDParams::production(args.plan);
    let mut connection =
        open_fase_d_connection_with_ggm_prg(&connection_store, binding, None, params, args.ggm_prg)
            .unwrap_or_else(|error| panic!("fase-D setup failed: {error}"));

    let setup_base_ot = connection.expansion.comm.base_ot_bytes;
    let setup_ot_extension = connection.expansion.comm.ot_extension_bytes;
    let target_responses = args.abort_on_response.unwrap_or(args.responses);
    let mut response_rows = Vec::with_capacity(target_responses);
    let mut abort_reopen_rejected = None;
    for ordinal in 1..=target_responses {
        let nonce = os_identity("response authorization nonce");
        let response_binding = binding.response_binding(nonce).unwrap();
        let burn = connection
            .connection
            .begin_response(&authorization_store, response_binding)
            .unwrap_or_else(|error| panic!("response {ordinal} authorization failed: {error}"));
        let domain = CorrelationDomain::new(
            binding.connection_id,
            nonce,
            ordinal as u32,
            0,
            ordinal as u64,
            *blake3::hash(format!("fase-d-report/response/{ordinal}").as_bytes()).as_bytes(),
        )
        .unwrap();
        let allocation_digest = {
            let batch = connection
                .allocate_sub_correlations(1, 1, domain)
                .unwrap_or_else(|error| panic!("response {ordinal} allocation failed: {error}"));
            assert_eq!(batch.prover.len(), 1);
            assert_eq!(batch.verifier_keys.len(), 1);
            assert_eq!(
                batch.prover[0].m,
                batch.verifier_keys[0] + batch.verifier_delta.mul_base(batch.prover[0].r)
            );
            batch.allocation.connection_allocation_digest.clone()
        };
        connection
            .connection
            .record_channel_frame(
                ConnectionChannelDirection::ProverToVerifier,
                1,
                &(ordinal as u64).to_le_bytes(),
            )
            .unwrap();

        if args.abort_on_response == Some(ordinal) {
            connection.connection.malicious_check_failed().unwrap();
            let reopen = connection_store.create(binding, None).unwrap_err();
            abort_reopen_rejected = Some(reopen.to_string().contains("terminally burned"));
            response_rows.push(ResponseRow {
                ordinal,
                accepted: false,
                authorization_burn_digest: burn.record_digest,
                allocation_digest,
                channel_ledger_digest: connection.connection.channel_ledger_digest_hex(),
                correlations_consumed: 1,
                base_ot_bytes: if ordinal == 1 { setup_base_ot } else { 0 },
                ot_extension_bytes: if ordinal == 1 { setup_ot_extension } else { 0 },
            });
            break;
        }

        let audit = connection.connection.finish_response_success().unwrap();
        response_rows.push(ResponseRow {
            ordinal,
            accepted: true,
            authorization_burn_digest: burn.record_digest,
            allocation_digest: audit.allocation_digest,
            channel_ledger_digest: audit.channel_ledger_digest,
            correlations_consumed: audit.correlations_consumed,
            base_ot_bytes: if ordinal == 1 { setup_base_ot } else { 0 },
            ot_extension_bytes: if ordinal == 1 { setup_ot_extension } else { 0 },
        });
    }
    if args.abort_on_response.is_none() {
        connection.connection.close().unwrap();
    }

    let sha_after = git_head_sha();
    let dirty_after = git_dirty();
    if sha_after != sha_before || (!args.diagnostic && dirty_after) {
        eprintln!("fase_d_report: git revision changed or became dirty; refusing record");
        std::process::exit(2);
    }
    let logical_cores = detected_logical_cpu_cores();
    let g2_capacity_gate_pass = args.plan == FaseDStagePlan::TerminalOne
        && connection.expansion.capacity.allocatable_stage3 >= 110_000_000;
    let g2_traffic_gate_pass = args.plan == FaseDStagePlan::TerminalOne
        && connection.expansion.comm.total_bytes <= 40_000_000;
    let g2b_three_response_pass = (args.responses >= 3).then(|| {
        response_rows.len() >= 3
            && response_rows.iter().all(|row| row.accepted)
            && response_rows
                .iter()
                .skip(1)
                .all(|row| row.base_ot_bytes == 0 && row.ot_extension_bytes == 0)
    });
    let g2b_abort_response_two_pass = args.abort_on_response.map(|ordinal| {
        ordinal == 2
            && response_rows.len() == 2
            && response_rows[0].accepted
            && !response_rows[1].accepted
            && abort_reopen_rejected == Some(true)
    });
    let g3_generated_approximately_600m = args.plan == FaseDStagePlan::ChainSix
        && connection.expansion.capacity.gross_stage3 >= 600_000_000;
    if !args.diagnostic && args.plan == FaseDStagePlan::TerminalOne {
        assert!(g2_capacity_gate_pass, "G2 usable-capacity gate failed");
        assert!(g2_traffic_gate_pass, "G2 setup-traffic gate failed");
    }
    if !args.diagnostic && args.responses >= 3 {
        assert_eq!(g2b_three_response_pass, Some(true), "G2b multi-response gate failed");
    }
    if !args.diagnostic && args.abort_on_response.is_some() {
        assert_eq!(
            g2b_abort_response_two_pass,
            Some(true),
            "G2b abort/reopen gate requires --abort-on-response 2"
        );
    }
    let report = serde_json::json!({
        "report_schema_version": 1,
        "milestone": "fase-D",
        "date": date(),
        "git_sha": sha_before,
        "git_dirty": dirty_after,
        "plan": args.plan,
        "profile": connection.expansion.params.profile,
        "ggm_prg": connection.expansion.ggm_prg,
        "ggm_aes_feature": connection.expansion.ggm_aes_backend,
        "detected_physical_cpu_cores": detected_physical_cpu_cores(logical_cores),
        "detected_logical_cpu_cores": logical_cores,
        "pcg_setup_rayon_threads": connection.expansion.rayon_threads,
        "pcg_production_ready": false,
        "one_connection_base_phase": connection.expansion.one_base_phase,
        "setup_comm": connection.expansion.comm,
        "channel_audit": connection.expansion.channel,
        "prelude_wall_split": connection.expansion.prelude_timings,
        "stage_wall_splits": connection.expansion.stages,
        "capacity": connection.expansion.capacity,
        "g2_capacity_gate_pass": g2_capacity_gate_pass,
        "g2_traffic_gate_pass": g2_traffic_gate_pass,
        "g2b_three_response_pass": g2b_three_response_pass,
        "g2b_abort_response_two_pass": g2b_abort_response_two_pass,
        "g3_generated_approximately_600m": g3_generated_approximately_600m,
        "connection_allocation_digest": connection.connection.allocation_digest_hex(),
        "connection_channel_ledger_digest": connection.connection.channel_ledger_digest_hex(),
        "stage_counters": connection.connection.stage_counters(),
        "connection_state": connection.connection.state(),
        "completed_responses": connection.connection.completed_responses(),
        "responses": response_rows,
        "responses_after_first_repeat_base_ot_bytes": 0,
        "responses_after_first_repeat_ot_extension_bytes": 0,
        "abort_on_response": args.abort_on_response,
        "abort_reopen_rejected": abort_reopen_rejected,
        "total_setup_wall_s": connection.expansion.t_total_s,
        "prover_buffer_cap_bytes": connection.expansion.params.prover_buffer_cap_bytes,
        "maximum_observed_prover_buffer_high_water_bytes": connection.expansion.stages
            .iter().map(|stage| stage.prover_buffer_high_water_bytes).max().unwrap_or(0),
        "production_setup_audit": connection.production,
    });
    let json = serde_json::to_string_pretty(&report).unwrap();
    if args.diagnostic {
        println!("{json}");
        eprintln!("diagnostic only; no result artifact written");
        return;
    }
    let date = report["date"].as_str().unwrap();
    let sha = report["git_sha"].as_str().unwrap();
    let path = unique_result_path(args.plan, date, sha);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&path).expect("create append-only fase-D result");
    std::io::Write::write_all(&mut file, json.as_bytes()).expect("write fase-D result");
    file.sync_all().expect("fsync fase-D result");
    eprintln!("wrote {}", path.display());
}

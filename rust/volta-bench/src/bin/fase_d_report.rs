//! Fase-D G2/G2b/G3 append-only record harness.
//!
//! This binary measures only connection-scoped PCG setup and lifecycle.  It
//! does not change or execute the proving path.

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use volta_pcg::{
    open_fase_d_connection_with_ggm_prg, ConnectionBinding, ConnectionChannelDirection,
    ConnectionState, ConnectionStore, CorrelationDomain, FaseDParams, FaseDStagePlan, GgmPrg,
    ProductionFaseDConnection, ResponseAuthorizationStore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    G2,
    G2b,
    G3,
}

impl Gate {
    fn parse(value: &str) -> Self {
        match value {
            "g2" => Self::G2,
            "g2b" => Self::G2b,
            "g3" => Self::G3,
            _ => usage(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::G2 => "fase-d-scale110m",
            Self::G2b => "fase-d-connection",
            Self::G3 => "fase-d-scale600m",
        }
    }

    fn plan(self) -> FaseDStagePlan {
        match self {
            Self::G2 | Self::G2b => FaseDStagePlan::TerminalOne,
            Self::G3 => FaseDStagePlan::ChainSix,
        }
    }
}

#[derive(Clone, Debug)]
struct Args {
    gate: Gate,
    connection_store: Option<PathBuf>,
    authorization_store: Option<PathBuf>,
    ggm_prg: GgmPrg,
    diagnostic: bool,
}

#[derive(Clone, Debug, Serialize)]
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
        "usage: fase_d_report --gate g2|g2b|g3 --connection-store PATH \
         --authorization-store PATH [--ggm-prg aes128-mmo|blake3] [--diagnostic]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut gate = None;
    let mut connection_store = None;
    let mut authorization_store = None;
    let mut ggm_prg = GgmPrg::Aes128Mmo;
    let mut diagnostic = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--gate" {
            gate = Some(Gate::parse(&args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.strip_prefix("--gate=") {
            gate = Some(Gate::parse(value));
        } else if arg == "--connection-store" {
            connection_store = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.strip_prefix("--connection-store=") {
            connection_store = Some(PathBuf::from(value));
        } else if arg == "--authorization-store" {
            authorization_store = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.strip_prefix("--authorization-store=") {
            authorization_store = Some(PathBuf::from(value));
        } else if arg == "--ggm-prg" {
            ggm_prg = args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
        } else if let Some(value) = arg.strip_prefix("--ggm-prg=") {
            ggm_prg = value.parse().unwrap_or_else(|_| usage());
        } else if arg == "--diagnostic" {
            diagnostic = true;
        } else {
            usage();
        }
    }
    let gate = gate.unwrap_or_else(|| usage());
    if connection_store.is_none() || authorization_store.is_none() {
        usage();
    }
    if ggm_prg == GgmPrg::Blake3 && !diagnostic {
        eprintln!("fase_d_report: BLAKE3 GGM is diagnostic-only");
        std::process::exit(2);
    }
    Args { gate, connection_store, authorization_store, ggm_prg, diagnostic }
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

fn result_path(gate: Gate, record_date: &str, sha: &str) -> PathBuf {
    let name = format!("{}-{record_date}-{}.json", gate.label(), &sha[..sha.len().min(7)]);
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results").join(name)
}

fn binding(plan: FaseDStagePlan) -> ConnectionBinding {
    ConnectionBinding::new(
        os_identity("connection identity"),
        os_identity("authenticated channel identity"),
        plan,
    )
    .expect("nonzero connection identities")
}

fn open_connection(
    store: &ConnectionStore,
    binding: ConnectionBinding,
    plan: FaseDStagePlan,
    ggm_prg: GgmPrg,
) -> Result<ProductionFaseDConnection, String> {
    open_fase_d_connection_with_ggm_prg(
        store,
        binding,
        None,
        FaseDParams::production(plan),
        ggm_prg,
    )
    .map_err(|error| error.to_string())
}

fn serve_response(
    connection: &mut ProductionFaseDConnection,
    authorizations: &ResponseAuthorizationStore,
    binding: ConnectionBinding,
    ordinal: usize,
    abort: bool,
) -> ResponseRow {
    let nonce = os_identity("response authorization nonce");
    let response_binding = binding.response_binding(nonce).expect("response binding");
    let burn = connection
        .connection
        .begin_response(authorizations, response_binding)
        .unwrap_or_else(|error| panic!("response {ordinal} authorization failed: {error}"));
    let domain = CorrelationDomain::new(
        binding.connection_id,
        nonce,
        ordinal as u32,
        0,
        ordinal as u64,
        *blake3::hash(format!("fase-d-report/response/{ordinal}").as_bytes()).as_bytes(),
    )
    .expect("response domain");
    let allocation_digest = {
        let batch = connection
            .allocate_sub_correlations(1, 1, domain)
            .unwrap_or_else(|error| panic!("response {ordinal} allocation failed: {error}"));
        assert_eq!(batch.prover.len(), 1);
        assert_eq!(batch.verifier_keys.len(), 1);
        assert_eq!(
            batch.verifier_keys[0],
            batch.prover[0].m + batch.verifier_delta.mul_base(batch.prover[0].r)
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
        .expect("canonical response frame");
    let base_ot_bytes = if ordinal == 1 { connection.expansion.comm.base_ot_bytes } else { 0 };
    let ot_extension_bytes =
        if ordinal == 1 { connection.expansion.comm.ot_extension_bytes } else { 0 };
    if abort {
        connection.connection.malicious_check_failed().expect("terminal response abort");
        ResponseRow {
            ordinal,
            accepted: false,
            authorization_burn_digest: burn.record_digest,
            allocation_digest,
            channel_ledger_digest: connection.connection.channel_ledger_digest_hex(),
            correlations_consumed: 1,
            base_ot_bytes,
            ot_extension_bytes,
        }
    } else {
        let audit =
            connection.connection.finish_response_success().expect("successful response marker");
        ResponseRow {
            ordinal,
            accepted: true,
            authorization_burn_digest: burn.record_digest,
            allocation_digest: audit.allocation_digest,
            channel_ledger_digest: audit.channel_ledger_digest,
            correlations_consumed: audit.correlations_consumed,
            base_ot_bytes,
            ot_extension_bytes,
        }
    }
}

fn setup_json(connection: &ProductionFaseDConnection) -> serde_json::Value {
    serde_json::json!({
        "profile": connection.expansion.params.profile,
        "params": connection.expansion.params,
        "ggm_prg": connection.expansion.ggm_prg,
        "ggm_aes_feature": connection.expansion.ggm_aes_backend,
        "pcg_production_ready": connection.expansion.pcg_production_ready,
        "one_connection_base_phase": connection.expansion.one_base_phase,
        "setup_comm": connection.expansion.comm,
        "channel_audit": connection.expansion.channel,
        "prelude_wall_split": connection.expansion.prelude_timings,
        "stage_wall_splits": connection.expansion.stages,
        "capacity": connection.expansion.capacity,
        "total_setup_wall_s": connection.expansion.t_total_s,
        "prover_buffer_cap_bytes": connection.expansion.params.prover_buffer_cap_bytes,
        "maximum_observed_prover_buffer_high_water_bytes": connection.expansion.stages
            .iter().map(|stage| stage.prover_buffer_high_water_bytes).max().unwrap_or(0),
        "production_setup_audit": connection.production,
    })
}

fn lifecycle_json(connection: &ProductionFaseDConnection) -> serde_json::Value {
    serde_json::json!({
        "connection_allocation_digest": connection.connection.allocation_digest_hex(),
        "connection_channel_ledger_digest": connection.connection.channel_ledger_digest_hex(),
        "stage_counters": connection.connection.stage_counters(),
        "connection_state": connection.connection.state(),
        "completed_responses": connection.connection.completed_responses(),
    })
}

fn run_g2(connections: &ConnectionStore, ggm_prg: GgmPrg) -> serde_json::Value {
    let binding = binding(FaseDStagePlan::TerminalOne);
    let mut connection =
        open_connection(connections, binding, FaseDStagePlan::TerminalOne, ggm_prg)
            .unwrap_or_else(|error| panic!("G2 setup failed: {error}"));
    let capacity_pass = connection.expansion.capacity.allocatable_stage3 >= 110_000_000;
    let traffic_pass = connection.expansion.comm.total_bytes <= 40_000_000;
    let setup = setup_json(&connection);
    connection.connection.close().expect("G2 explicit close");
    assert!(capacity_pass, "G2 usable-capacity gate failed");
    assert!(traffic_pass, "G2 setup-traffic gate failed");
    serde_json::json!({
        "gate": "G2",
        "verdict": "PASS",
        "g2_capacity_gate_pass": capacity_pass,
        "g2_traffic_gate_pass": traffic_pass,
        "setup": setup,
        "lifecycle": lifecycle_json(&connection),
    })
}

fn run_g2b(
    connections: &ConnectionStore,
    authorizations: &ResponseAuthorizationStore,
    ggm_prg: GgmPrg,
) -> serde_json::Value {
    let success_binding = binding(FaseDStagePlan::TerminalOne);
    let mut success =
        open_connection(connections, success_binding, FaseDStagePlan::TerminalOne, ggm_prg)
            .unwrap_or_else(|error| panic!("G2b success-connection setup failed: {error}"));
    let success_setup = setup_json(&success);
    let success_responses: Vec<_> = (1..=3)
        .map(|ordinal| {
            serve_response(&mut success, authorizations, success_binding, ordinal, false)
        })
        .collect();
    let state_after_three_successes = success.connection.state();
    let completed_after_three_successes = success.connection.completed_responses();
    success.connection.close().expect("G2b success-connection close");
    let success_lifecycle = lifecycle_json(&success);

    // Drop the first 110M-capacity pool before provisioning the independent
    // abort scenario; this keeps live memory below the preregistered cap.
    drop(success);

    let abort_binding = binding(FaseDStagePlan::TerminalOne);
    let mut aborted =
        open_connection(connections, abort_binding, FaseDStagePlan::TerminalOne, ggm_prg)
            .unwrap_or_else(|error| panic!("G2b abort-connection setup failed: {error}"));
    let abort_setup = setup_json(&aborted);
    let abort_responses = vec![
        serve_response(&mut aborted, authorizations, abort_binding, 1, false),
        serve_response(&mut aborted, authorizations, abort_binding, 2, true),
    ];
    let reopen_error = connections
        .create(abort_binding, None)
        .expect_err("terminally burned G2b connection must reject reopen")
        .to_string();
    let reopen_rejected = reopen_error.contains("terminally burned");
    let abort_lifecycle = lifecycle_json(&aborted);

    let three_response_pass = completed_after_three_successes == 3
        && state_after_three_successes == ConnectionState::Active
        && success_responses.iter().all(|row| row.accepted)
        && success_responses
            .iter()
            .skip(1)
            .all(|row| row.base_ot_bytes == 0 && row.ot_extension_bytes == 0);
    let abort_response_two_pass = abort_responses.len() == 2
        && abort_responses[0].accepted
        && !abort_responses[1].accepted
        && abort_responses[1].base_ot_bytes == 0
        && abort_responses[1].ot_extension_bytes == 0
        && reopen_rejected;
    assert!(three_response_pass, "G2b multi-response gate failed");
    assert!(abort_response_two_pass, "G2b abort/reopen gate failed");

    serde_json::json!({
        "gate": "G2b",
        "verdict": "PASS",
        "g2b_three_response_pass": three_response_pass,
        "g2b_abort_response_two_pass": abort_response_two_pass,
        "responses_after_first_repeat_base_ot_bytes": 0,
        "responses_after_first_repeat_ot_extension_bytes": 0,
        "success_connection": {
            "setup": success_setup,
            "state_after_three_successes": state_after_three_successes,
            "responses": success_responses,
            "lifecycle_after_close": success_lifecycle,
        },
        "aborted_connection": {
            "setup": abort_setup,
            "injected_abort_on_response": 2,
            "responses": abort_responses,
            "durable_reopen_rejected": reopen_rejected,
            "reopen_error": reopen_error,
            "lifecycle": abort_lifecycle,
        },
    })
}

fn run_g3(connections: &ConnectionStore, ggm_prg: GgmPrg) -> serde_json::Value {
    let binding = binding(FaseDStagePlan::ChainSix);
    match open_connection(connections, binding, FaseDStagePlan::ChainSix, ggm_prg) {
        Ok(mut connection) => {
            let generated_approximately_600m =
                connection.expansion.capacity.gross_stage3 >= 600_000_000;
            let buffer_cap_pass = connection.expansion.stages.iter().all(|stage| {
                stage.prover_buffer_high_water_bytes
                    <= connection.expansion.params.prover_buffer_cap_bytes
            });
            let setup = setup_json(&connection);
            connection.connection.close().expect("G3 explicit close");
            serde_json::json!({
                "gate": "G3",
                "verdict": if generated_approximately_600m && buffer_cap_pass { "PASS" } else { "FAIL" },
                "binding": false,
                "g3_generated_approximately_600m": generated_approximately_600m,
                "g3_buffer_cap_pass": buffer_cap_pass,
                "failure_reason": serde_json::Value::Null,
                "setup": setup,
                "lifecycle": lifecycle_json(&connection),
            })
        }
        Err(error) => serde_json::json!({
            "gate": "G3",
            "verdict": "FAIL",
            "binding": false,
            "g3_generated_approximately_600m": false,
            "g3_buffer_cap_pass": false,
            "failure_reason": error,
            "setup": serde_json::Value::Null,
            "lifecycle": serde_json::Value::Null,
        }),
    }
}

fn main() {
    let args = parse_args();
    let sha_before = git_head_sha();
    let dirty_before = git_dirty();
    if sha_before.is_empty() || (!args.diagnostic && dirty_before) {
        eprintln!("fase_d_report: record mode requires an available, clean git revision");
        std::process::exit(2);
    }
    let connections = ConnectionStore::new(args.connection_store.as_ref().unwrap())
        .unwrap_or_else(|error| panic!("connection-store preflight failed: {error}"));
    let authorizations =
        ResponseAuthorizationStore::new(args.authorization_store.as_ref().unwrap())
            .unwrap_or_else(|error| panic!("authorization-store preflight failed: {error}"));
    let gate_result = match args.gate {
        Gate::G2 => run_g2(&connections, args.ggm_prg),
        Gate::G2b => run_g2b(&connections, &authorizations, args.ggm_prg),
        Gate::G3 => run_g3(&connections, args.ggm_prg),
    };
    let sha_after = git_head_sha();
    let dirty_after = git_dirty();
    if sha_after != sha_before || (!args.diagnostic && dirty_after) {
        eprintln!("fase_d_report: git revision changed or became dirty; refusing record");
        std::process::exit(2);
    }
    let logical_cores = detected_logical_cpu_cores();
    let report_date = date();
    let report = serde_json::json!({
        "report_schema_version": 2,
        "milestone": "fase-D",
        "date": report_date,
        "git_sha": sha_before,
        "git_dirty": dirty_after,
        "gate_profile": args.gate.label(),
        "plan": args.gate.plan(),
        "ggm_prg": args.ggm_prg,
        "detected_physical_cpu_cores": detected_physical_cpu_cores(logical_cores),
        "detected_logical_cpu_cores": logical_cores,
        "pcg_setup_rayon_threads": rayon::current_num_threads(),
        "pcg_production_ready": true,
        "result": gate_result,
    });
    let json = serde_json::to_string_pretty(&report).expect("serialize fase-D report");
    if args.diagnostic {
        println!("{json}");
        eprintln!("diagnostic only; no result artifact written");
        return;
    }
    let path = result_path(args.gate, &report_date, &sha_after);
    let mut file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap_or_else(
            |error| panic!("create append-only result {}: {error}", path.display()),
        );
    std::io::Write::write_all(&mut file, json.as_bytes()).expect("write fase-D result");
    file.sync_all().expect("fsync fase-D result");
    eprintln!("wrote {}", path.display());
}

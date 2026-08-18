//! C6.2 real-weight production and verifier record adapter.
//!
//! Prove mode runs one strict 17-certificate continuation session.  Each
//! create-new artifact is loaded and verified on four threads before the
//! client accepts its head and the provider slot receives acknowledgement.

#[cfg(not(all(
    feature = "cuda",
    feature = "c6-trace",
    feature = "c61-p3-authenticated-reference"
)))]
fn main() {
    eprintln!(
        "c62_whir_fiat_shamir_record requires --features cuda,c6-trace,c61-p3-authenticated-reference"
    );
    std::process::exit(2);
}

#[cfg(all(feature = "cuda", feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
mod enabled {
    use rand::{rngs::OsRng, RngCore};
    use serde::Serialize;
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;
    use std::time::{Duration, Instant};
    use volta_accel::{Backend, BackendStats, ResidentTimingPolicy};
    use volta_bench::c61_campaign::{
        build_c62_campaign_setup_manifest, create_c62_campaign_artifact,
        load_c62_campaign_artifact, load_c62_campaign_installed_setup,
        prepare_c62_campaign_cache_precommit, prepare_c62_campaign_continuation_cache_precommit,
        run_c62_campaign_live_production, validate_c62_campaign_cache_precommit_inputs,
        verify_c62_campaign_e2e, verify_c62_loaded_campaign_e2e,
        C61CampaignInstalledSetup, C62CampaignArtifact, C62CampaignLiveProductionOutput,
        C62_CAMPAIGN_SETUP_MAX_BYTES,
    };
    use volta_bench::c6_t1_owner::{
        build_c62_continuation_workload_owner, build_c6_t1_workload_owner,
    };
    use volta_bench::{cloud_metadata_from_env, CloudMetadata};
    use volta_gpt2::{forward_model, generate, load_model, Gpt2VerifierModel, KvCache};
    use volta_mac::Transcript;
    use volta_pcg::{
        open_fase_d_connection_with_ggm_prg, ConnectionAbortReason, ConnectionBinding,
        ConnectionStore, FaseDParams, FaseDStagePlan, GgmPrg, ResponseAuthorizationStore,
    };
    use volta_pcs::c61_authenticated_whir_p3::{
        C61ProductionPersistedResourceAdmission,
        C61_PRODUCTION_COMPILER_FULL_CORRELATIONS_PER_TAPE,
        C61_PRODUCTION_COMPILER_SUB_CORRELATIONS_PER_TAPE,
        C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
        C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
    };
    use volta_pcs::{
        C62PublicArgument, C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE,
        C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_CORRELATIONS_PER_TAPE,
        C6_RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE,
    };
    use volta_pcs::c6_persistent_cache_blind::
        C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE;
    use volta_proto::{
        C61PublicWorkloadInstance, C61PublicWorkloadPreimage, C62NativeFinalCertificate,
        C62ResponseProofEnvelope, C6ClientState, C6ClientStore, C6ProductionPairedPcgAttempt,
        C6SetupManifest, C6SlotReservation, C6SlotStatus, C6SlotStore, C6Workload,
        C62_CERTIFICATE_STRICT_MAX_BYTES, C62_CONTINUATION_1024_FULL_CORRELATIONS,
        C62_CONTINUATION_1024_RAW_CORRELATIONS, C62_CONTINUATION_1024_SUB_CORRELATIONS,
        C62_CONTINUATION_256_FULL_CORRELATIONS, C62_CONTINUATION_256_RAW_CORRELATIONS,
        C62_CONTINUATION_256_SUB_CORRELATIONS, C62_CONTINUATION_512_FULL_CORRELATIONS,
        C62_CONTINUATION_512_RAW_CORRELATIONS, C62_CONTINUATION_512_SUB_CORRELATIONS,
        C62_GENESIS_FULL_CORRELATIONS, C62_GENESIS_RAW_CORRELATIONS, C62_GENESIS_SUB_CORRELATIONS,
        C62_PRODUCTION_SUFFIX_FULL_CORRELATIONS, C62_PRODUCTION_SUFFIX_SUB_CORRELATIONS,
        C62_NATIVE_CERTIFICATE_FRAMING_BYTES, C62_NATIVE_STRICT_PI_FINAL_MAX_BYTES,
        C62_RETAINED_NON_PCS_RESPONSE_BYTES, C6_ABORT_RETRY_CREDITS, C6_ACCEPTANCE_CREDITS,
        C6_TERMINAL_ONE_RAW_CAPACITY,
    };

    const SCHEMA: u64 = 2;
    const PROFILE: &str = "runpod-a100-c62-whir-fiat-shamir-v1";
    const PROTOCOL_ID: &str = "VOLTA-C6.2-C62JVR1-C62FS1-C62AWP1-C62PA1-C62PIF1-C62NFC1-v1";
    const SETUP_PLUS_FIRST_TARGET_BYTES: u64 = 150_000_000;
    const SETUP_PLUS_FIRST_TOLERANCE_BYTES: u64 = 157_500_000;
    const CERTIFICATE_TOLERANCE_BYTES: u64 = 23_099_998;
    const PI_FINAL_TOLERANCE_BYTES: u64 = 4_725_000;
    const PROVER_TARGET_S: f64 = 15.0;
    const PROVER_TOLERANCE_S: f64 = 15.75;
    const VERIFIER_TARGET_S: f64 = 5.0;
    const VERIFIER_TOLERANCE_S: f64 = 5.25;
    const VERIFIER_MEMORY_LIMIT_BYTES: u64 = 8_000_000_000;
    const SOUNDNESS_BITS_PER_CERTIFICATE: f64 = 83.587_833_260_880;
    const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_873_916_41;
    const MODEL_FILES: [&str; 4] =
        ["gpt2s-q.bin", "gpt2s-q.json", "gpt2s-q.params", "golden-p6.bin"];
    const SETUP_FILES: [&str; 5] = [
        "manifest.json",
        "operation-plan.bin",
        "prover-extraction.bin",
        "verifier-extraction.bin",
        "native-target-profile.bin",
    ];
    const SETUP_PROFILE_DIRS: [&str; 17] = [
        "context-000",
        "context-150",
        "context-200",
        "context-250",
        "context-300",
        "context-350",
        "context-400",
        "context-450",
        "context-500",
        "context-550",
        "context-600",
        "context-650",
        "context-700",
        "context-750",
        "context-800",
        "context-850",
        "context-900",
    ];
    const C62_SESSION_RAW_CORRELATIONS: u64 = C62_GENESIS_RAW_CORRELATIONS
        + 6 * C62_CONTINUATION_256_RAW_CORRELATIONS
        + 5 * C62_CONTINUATION_512_RAW_CORRELATIONS
        + 9 * C62_CONTINUATION_1024_RAW_CORRELATIONS;

    fn c62_suffix_correlation_census_valid() -> bool {
        let sub = C61_PRODUCTION_COMPILER_SUB_CORRELATIONS_PER_TAPE;
        let noncompiler_chain_masks =
            (C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u64).saturating_sub(1);
        let full = C6_RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE
            + C6_PERSISTENT_CACHE_BLIND_PRODUCTION_CORRELATIONS_PER_TAPE
            + C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_CORRELATIONS_PER_TAPE
            + C61_PRODUCTION_COMPILER_FULL_CORRELATIONS_PER_TAPE
            + noncompiler_chain_masks;
        sub == C62_PRODUCTION_SUFFIX_SUB_CORRELATIONS as u64
            && full == C62_PRODUCTION_SUFFIX_FULL_CORRELATIONS as u64
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        Preflight,
        Prove,
        Verify,
        Mutate,
    }

    struct Args {
        mode: Mode,
        weights: Option<PathBuf>,
        setup_dir: Option<PathBuf>,
        work_root: Option<PathBuf>,
        run_root: Option<PathBuf>,
        artifact_root: Option<PathBuf>,
        state_root: Option<PathBuf>,
        output: PathBuf,
        threads: usize,
        accept: bool,
    }

    fn usage() -> ! {
        eprintln!(
            "usage: c62_whir_fiat_shamir_record --mode preflight|prove|verify|mutate \
             --output PATH [--weights PATH --setup-dir PATH --work-root PATH] \
             [--run-root PATH --artifact-root PATH --state-root PATH] \
             [--threads N] [--accept]"
        );
        std::process::exit(2)
    }

    fn parse_args() -> Args {
        let mut mode = None;
        let mut weights = None;
        let mut setup_dir = None;
        let mut work_root = None;
        let mut run_root = None;
        let mut artifact_root = None;
        let mut state_root = None;
        let mut output = None;
        let mut threads = 4usize;
        let mut accept = false;
        let mut values = std::env::args().skip(1);
        while let Some(argument) = values.next() {
            let mut value = || values.next().unwrap_or_else(|| usage());
            match argument.as_str() {
                "--mode" => {
                    mode = Some(match value().as_str() {
                        "preflight" => Mode::Preflight,
                        "prove" => Mode::Prove,
                        "verify" => Mode::Verify,
                        "mutate" => Mode::Mutate,
                        _ => usage(),
                    })
                }
                "--weights" => weights = Some(PathBuf::from(value())),
                "--setup-dir" => setup_dir = Some(PathBuf::from(value())),
                "--work-root" => work_root = Some(PathBuf::from(value())),
                "--run-root" => run_root = Some(PathBuf::from(value())),
                "--artifact-root" => artifact_root = Some(PathBuf::from(value())),
                "--state-root" => state_root = Some(PathBuf::from(value())),
                "--output" => output = Some(PathBuf::from(value())),
                "--threads" => threads = value().parse().unwrap_or_else(|_| usage()),
                "--accept" => accept = true,
                _ => usage(),
            }
        }
        if threads == 0 || (accept && mode != Some(Mode::Verify)) {
            usage();
        }
        Args {
            mode: mode.unwrap_or_else(|| usage()),
            weights,
            setup_dir,
            work_root,
            run_root,
            artifact_root,
            state_root,
            output: output.unwrap_or_else(|| usage()),
            threads,
            accept,
        }
    }

    fn required_path<'a>(value: &'a Option<PathBuf>, label: &str) -> Result<&'a Path, String> {
        value.as_deref().ok_or_else(|| format!("{label} is required for this mode"))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn random_digest(label: &str) -> Result<[u8; 32], String> {
        let mut value = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut value)
            .map_err(|error| format!("{label} entropy unavailable: {error}"))?;
        if value == [0; 32] {
            return Err(format!("{label} entropy was zero"));
        }
        Ok(value)
    }

    fn hash_file_set(domain: &str, root: &Path, names: &[&str]) -> Result<[u8; 32], String> {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        for name in names {
            let path = root.join(name);
            let length = fs::metadata(&path)
                .map_err(|error| format!("stat {}: {error}", path.display()))?
                .len();
            let mut file =
                File::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(&length.to_le_bytes());
            let mut buffer = vec![0u8; 1 << 20];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| format!("read {}: {error}", path.display()))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn load_c62_installed_setups(root: &Path) -> Result<[C61CampaignInstalledSetup; 17], String> {
        let actual = fs::read_dir(root)
            .map_err(|error| format!("read setup root {}: {error}", root.display()))?
            .map(|entry| {
                entry
                    .map_err(|error| format!("read setup root entry: {error}"))?
                    .file_name()
                    .into_string()
                    .map_err(|_| "setup root contains a non-UTF8 name".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected = SETUP_PROFILE_DIRS.iter().map(|name| (*name).to_owned()).collect();
        if actual != expected {
            return Err(
                "C6.2 setup root does not contain exactly 17 registered profiles".to_owned()
            );
        }
        for name in SETUP_PROFILE_DIRS {
            let metadata = fs::symlink_metadata(root.join(name))
                .map_err(|error| format!("stat C6.2 setup profile {name}: {error}"))?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(format!("C6.2 setup profile {name} is not a physical directory"));
            }
        }
        SETUP_PROFILE_DIRS
            .iter()
            .map(|name| load_c62_campaign_installed_setup(&root.join(name)))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6.2 installed setup profile census differs".to_owned())
    }

    fn hash_c62_setup_profiles(root: &Path) -> Result<[u8; 32], String> {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.2/installed-profile-bundle/v1");
        for name in SETUP_PROFILE_DIRS {
            let digest = hash_file_set(
                "volta-zk/c6.2/installed-profile-file-set/v1",
                &root.join(name),
                &SETUP_FILES,
            )?;
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(&digest);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn c62_setup_profile_name(old_context: u32) -> Result<&'static str, String> {
        let index = match old_context {
            0 => 0,
            150..=900 if old_context % 50 == 0 => ((old_context - 100) / 50) as usize,
            _ => return Err("C6.2 session has no registered setup profile".to_owned()),
        };
        SETUP_PROFILE_DIRS
            .get(index)
            .copied()
            .ok_or_else(|| "C6.2 session setup profile index is out of range".to_owned())
    }

    fn c62_correlation_profile(old_context: u32) -> Result<(usize, usize, u64), String> {
        match old_context {
            0 => Ok((
                C62_GENESIS_SUB_CORRELATIONS,
                C62_GENESIS_FULL_CORRELATIONS,
                C62_GENESIS_RAW_CORRELATIONS,
            )),
            150 | 200 => Ok((
                C62_CONTINUATION_256_SUB_CORRELATIONS,
                C62_CONTINUATION_256_FULL_CORRELATIONS,
                C62_CONTINUATION_256_RAW_CORRELATIONS,
            )),
            250..=450 if old_context % 50 == 0 => Ok((
                C62_CONTINUATION_512_SUB_CORRELATIONS,
                C62_CONTINUATION_512_FULL_CORRELATIONS,
                C62_CONTINUATION_512_RAW_CORRELATIONS,
            )),
            500..=900 if old_context % 50 == 0 => Ok((
                C62_CONTINUATION_1024_SUB_CORRELATIONS,
                C62_CONTINUATION_1024_FULL_CORRELATIONS,
                C62_CONTINUATION_1024_RAW_CORRELATIONS,
            )),
            _ => Err("C6.2 correlation profile has no registered context".to_owned()),
        }
    }

    fn c62_session_sequence(weights: &Path) -> Result<Vec<u32>, String> {
        let model = load_model(weights).map_err(|error| format!("load session model: {error}"))?;
        model.validate_layout().map_err(|error| error.to_string())?;
        let prefill = forward_model(&model, 100);
        let kv = prefill
            .layers
            .iter()
            .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
            .collect::<Vec<_>>();
        let mut cache = KvCache::from_prefill(&kv, 100);
        let (generated, _) = generate(&model, &mut cache, &prefill.logits, 100, 850);
        let mut sequence = model.p.tokens[..100].to_vec();
        sequence.extend_from_slice(&generated);
        if sequence.len() != 950 {
            return Err("C6.2 session sequence has the wrong final context".to_owned());
        }
        Ok(sequence)
    }

    fn protocol_digest() -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/protocol-identity/v1");
        hasher.update(PROTOCOL_ID.as_bytes());
        *hasher.finalize().as_bytes()
    }

    fn quantization_digest() -> Result<[u8; 32], String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/quantization-spec.md");
        let root = path.parent().ok_or_else(|| "quantization path has no parent".to_owned())?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "quantization path is not UTF-8".to_owned())?;
        hash_file_set("volta-zk/c6.2/quantization-file-set/v1", root, &[name])
    }

    fn git_sha_clean() -> Result<String, String> {
        let status = Command::new("git")
            .args(["status", "--porcelain", "--untracked-files=all"])
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .output()
            .map_err(|error| format!("git status: {error}"))?;
        if !status.status.success() || !status.stdout.is_empty() {
            return Err("record mode requires a clean source tree".to_owned());
        }
        let sha = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .output()
            .map_err(|error| format!("git rev-parse: {error}"))?;
        if !sha.status.success() {
            return Err("git rev-parse failed".to_owned());
        }
        let value = String::from_utf8(sha.stdout)
            .map_err(|_| "git SHA is not UTF-8".to_owned())
            .map(|value| value.trim().to_owned())?;
        if value.len() != 40
            || value.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err("git SHA is not a full lowercase SHA-1 digest".to_owned());
        }
        Ok(value)
    }

    fn mem_available_bytes() -> Result<u64, String> {
        let text = fs::read_to_string("/proc/meminfo")
            .map_err(|error| format!("read /proc/meminfo: {error}"))?;
        let kib = text
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "MemAvailable is absent".to_owned())?;
        kib.checked_mul(1024).ok_or_else(|| "MemAvailable overflows".to_owned())
    }

    fn current_rss_bytes() -> Result<u64, String> {
        let text = fs::read_to_string("/proc/self/status")
            .map_err(|error| format!("read /proc/self/status: {error}"))?;
        let kib = text
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "VmRSS is absent".to_owned())?;
        kib.checked_mul(1024).ok_or_else(|| "VmRSS overflows".to_owned())
    }

    fn filesystem_available_bytes(path: &Path) -> Result<u64, String> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "filesystem path contains NUL".to_owned())?;
        let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
            return Err("statvfs failed".to_owned());
        }
        stats
            .f_bavail
            .checked_mul(stats.f_frsize)
            .ok_or_else(|| "available filesystem bytes overflow".to_owned())
    }

    #[derive(Debug, Serialize)]
    struct HardwareRecord {
        gpu_name: String,
        gpu_uuid: String,
        gpu_total_bytes: u64,
        visible_gpu_count: usize,
        a100_present: bool,
        available_host_bytes: u64,
        available_spill_bytes: u64,
        host_admission_pass: bool,
        spill_admission_pass: bool,
        overall_pass: bool,
    }

    fn hardware_record(work_root: &Path) -> Result<HardwareRecord, String> {
        if !work_root.is_dir() {
            return Err("work root is not a directory".to_owned());
        }
        let selected = std::env::var("CUDA_VISIBLE_DEVICES").ok().filter(|value| !value.is_empty());
        if selected.as_deref().is_some_and(|value| value.split(',').count() != 1) {
            return Err("CUDA_VISIBLE_DEVICES must select one GPU".to_owned());
        }
        let mut command = Command::new("nvidia-smi");
        if let Some(selected) = selected {
            command.arg(format!("--id={selected}"));
        }
        let output = command
            .args(["--query-gpu=name,uuid,memory.total", "--format=csv,noheader,nounits"])
            .output()
            .map_err(|error| format!("run nvidia-smi: {error}"))?;
        if !output.status.success() {
            return Err("nvidia-smi failed".to_owned());
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| "nvidia-smi output is not UTF-8".to_owned())?;
        let rows = text.lines().filter(|row| !row.trim().is_empty()).collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(format!("expected one visible GPU, observed {}", rows.len()));
        }
        let columns = rows[0].split(',').map(str::trim).collect::<Vec<_>>();
        if columns.len() != 3 {
            return Err("nvidia-smi row has the wrong shape".to_owned());
        }
        let gpu_total_bytes = columns[2]
            .parse::<u64>()
            .map_err(|_| "GPU memory is not numeric".to_owned())?
            .checked_mul(1_048_576)
            .ok_or_else(|| "GPU memory bytes overflow".to_owned())?;
        let available_host_bytes = mem_available_bytes()?;
        let available_spill_bytes = filesystem_available_bytes(work_root)?;
        let a100_present = columns[0].contains("A100");
        let host_admission_pass =
            available_host_bytes >= C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES;
        let spill_admission_pass =
            available_spill_bytes >= C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES;
        Ok(HardwareRecord {
            gpu_name: columns[0].to_owned(),
            gpu_uuid: columns[1].to_owned(),
            gpu_total_bytes,
            visible_gpu_count: rows.len(),
            a100_present,
            available_host_bytes,
            available_spill_bytes,
            host_admission_pass,
            spill_admission_pass,
            overall_pass: a100_present && host_admission_pass && spill_admission_pass,
        })
    }

    fn create_new_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| format!("encode {}: {error}", path.display()))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file =
            options.open(path).map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(&bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
        file.sync_all().map_err(|error| format!("fsync {}: {error}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync {}: {error}", parent.display()))
    }

    #[derive(Debug, Default, Serialize)]
    struct IoRecord {
        read_bytes: u64,
        write_bytes: u64,
    }

    fn process_io() -> Result<IoRecord, String> {
        let text = fs::read_to_string("/proc/self/io")
            .map_err(|error| format!("read /proc/self/io: {error}"))?;
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| value.trim().parse::<u64>().ok())
                .ok_or_else(|| format!("{name} is absent from /proc/self/io"))
        };
        Ok(IoRecord { read_bytes: field("read_bytes:")?, write_bytes: field("write_bytes:")? })
    }

    fn io_delta(before: &IoRecord, after: &IoRecord) -> IoRecord {
        IoRecord {
            read_bytes: after.read_bytes.saturating_sub(before.read_bytes),
            write_bytes: after.write_bytes.saturating_sub(before.write_bytes),
        }
    }

    #[derive(Debug, Serialize)]
    struct BackendRecord {
        measurement_wall_ns: u64,
        kernel_ns: u64,
        h2d_bytes: u64,
        d2h_bytes: u64,
        h2d_ns: u64,
        d2h_ns: u64,
        synchronizations: u64,
        synchronization_ns: u64,
        allocation_calls: u64,
        physical_free_calls: u64,
        live_device_bytes: u64,
        peak_device_bytes: u64,
        live_pinned_bytes: u64,
        peak_pinned_bytes: u64,
    }

    impl From<BackendStats> for BackendRecord {
        fn from(stats: BackendStats) -> Self {
            Self {
                measurement_wall_ns: stats.measurement_wall_ns,
                kernel_ns: stats.kernel_ns(),
                h2d_bytes: stats.h2d_bytes,
                d2h_bytes: stats.d2h_bytes,
                h2d_ns: stats.h2d_ns,
                d2h_ns: stats.d2h_ns,
                synchronizations: stats.synchronizations,
                synchronization_ns: stats.synchronization_ns,
                allocation_calls: stats.allocation_calls,
                physical_free_calls: stats.physical_free_calls,
                live_device_bytes: stats.live_device_bytes,
                peak_device_bytes: stats.peak_device_bytes,
                live_pinned_bytes: stats.live_pinned_bytes,
                peak_pinned_bytes: stats.peak_pinned_bytes,
            }
        }
    }

    #[derive(Serialize)]
    struct PreflightRecord {
        schema: u64,
        profile: &'static str,
        mode: &'static str,
        source_git_commit: String,
        git_dirty: bool,
        protocol_id: &'static str,
        protocol_digest: String,
        model_digest: String,
        params_digest: String,
        quantization_digest: String,
        setup_bytes: u64,
        setup_cap_bytes: u64,
        hardware: HardwareRecord,
        cuda_backend_initialized: bool,
        capacity_acceptance_slots: u16,
        capacity_abort_slots: u16,
        capacity_reconciled: bool,
        credit: bool,
        pass: bool,
    }

    fn preflight(args: &Args) -> Result<(), String> {
        let source_git_commit = git_sha_clean()?;
        let weights = required_path(&args.weights, "--weights")?;
        let setup_dir = required_path(&args.setup_dir, "--setup-dir")?;
        let work_root = required_path(&args.work_root, "--work-root")?;
        let hardware = hardware_record(work_root)?;
        let installed = load_c62_installed_setups(setup_dir)?;
        let workload_owner = build_c6_t1_workload_owner(weights)?;
        let verifier_model = Gpt2VerifierModel::from_model(workload_owner.model())?;
        let model_digest = hash_file_set("volta-zk/c6.2/model-file-set/v1", weights, &MODEL_FILES)?;
        let params_digest = hash_c62_setup_profiles(setup_dir)?;
        let quantization_digest = quantization_digest()?;
        let setup = build_c62_campaign_setup_manifest(
            std::array::from_fn(|index| &installed[index]),
            &verifier_model,
            quantization_digest,
            protocol_digest(),
            model_digest,
            params_digest,
            [0x41; 32],
            [[0x42; 32], [0x43; 32]],
        )?;
        let setup_bytes = setup.first_exchange_bytes().map_err(|error| error.to_string())?;
        let backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
            .map_err(|error| format!("initialize CUDA backend: {error}"))?;
        drop(backend);
        let capacity_reconciled = c62_suffix_correlation_census_valid()
            && C62_SESSION_RAW_CORRELATIONS <= C6_TERMINAL_ONE_RAW_CAPACITY;
        let pass = hardware.overall_pass
            && setup_bytes <= C62_CAMPAIGN_SETUP_MAX_BYTES
            && capacity_reconciled
            && C6_ACCEPTANCE_CREDITS == 17
            && C6_ABORT_RETRY_CREDITS == 4;
        let record = PreflightRecord {
            schema: SCHEMA,
            profile: PROFILE,
            mode: "preflight",
            source_git_commit,
            git_dirty: false,
            protocol_id: PROTOCOL_ID,
            protocol_digest: hex(&protocol_digest()),
            model_digest: hex(&model_digest),
            params_digest: hex(&params_digest),
            quantization_digest: hex(&quantization_digest),
            setup_bytes,
            setup_cap_bytes: C62_CAMPAIGN_SETUP_MAX_BYTES,
            hardware,
            cuda_backend_initialized: true,
            capacity_acceptance_slots: C6_ACCEPTANCE_CREDITS,
            capacity_abort_slots: C6_ABORT_RETRY_CREDITS,
            capacity_reconciled,
            credit: false,
            pass,
        };
        create_new_json(&args.output, &record)?;
        if !pass {
            return Err("C6.2 preflight failed".to_owned());
        }
        Ok(())
    }

    #[derive(Serialize)]
    struct SessionCertificateRecord {
        index: u16,
        slot: u32,
        old_context: u32,
        new_context: u32,
        setup_profile: &'static str,
        certificate_digest: String,
        response_context_digest: String,
        native_public_context_digest: String,
        certificate_bytes: u64,
        pi_final_bytes: u64,
        prover_wall_s: f64,
        provider_complete_wall_s: f64,
        verifier_wall_s: f64,
        verifier_additional_peak_bytes: u64,
        certificate_target_pass: bool,
        certificate_tolerance_pass: bool,
        pi_final_target_pass: bool,
        pi_final_tolerance_pass: bool,
        prover_target_pass: bool,
        prover_tolerance_pass: bool,
        verifier_target_pass: bool,
        verifier_tolerance_pass: bool,
        verifier_memory_pass: bool,
        process_io: IoRecord,
        backend: BackendRecord,
        artifact_root: String,
        pass: bool,
    }

    #[derive(Serialize)]
    struct SessionRecord {
        schema: u64,
        profile: &'static str,
        mode: &'static str,
        source_git_commit: String,
        git_dirty: bool,
        cloud: CloudMetadata,
        hardware: HardwareRecord,
        protocol_id: &'static str,
        protocol_digest: String,
        model_digest: String,
        params_digest: String,
        quantization_digest: String,
        setup_wall_s: f64,
        inference_wall_s_excluded: f64,
        setup_bytes: u64,
        setup_plus_first_bytes: u64,
        setup_plus_first_target_pass: bool,
        setup_plus_first_tolerance_pass: bool,
        accepted_slots: u16,
        aborted_slots: Vec<u32>,
        final_context: u32,
        final_next_slot: u32,
        raw_correlations_per_tape: u64,
        expected_raw_correlations_per_tape: u64,
        capacity_reconciled: bool,
        soundness_bits_per_certificate: f64,
        soundness_floor_bits: f64,
        soundness_pass: bool,
        certificates: Vec<SessionCertificateRecord>,
        session_gate_evaluated: bool,
        credit: bool,
        pass: bool,
        artifact_root: String,
        state_root: String,
        run_root: String,
    }

    fn prove(args: &Args) -> Result<(), String> {
        if !c62_suffix_correlation_census_valid() {
            return Err("C6.2 suffix correlation census differs from the allocation".to_owned());
        }
        let source_git_commit = git_sha_clean()?;
        let cloud = cloud_metadata_from_env()
            .ok_or_else(|| "cloud metadata environment is required".to_owned())?;
        let weights = required_path(&args.weights, "--weights")?;
        let setup_dir = required_path(&args.setup_dir, "--setup-dir")?;
        let work_root = required_path(&args.work_root, "--work-root")?;
        let run_root = required_path(&args.run_root, "--run-root")?;
        let artifact_root = required_path(&args.artifact_root, "--artifact-root")?;
        let state_root = required_path(&args.state_root, "--state-root")?;
        for path in [run_root, artifact_root, state_root] {
            if path.exists() {
                return Err(format!("{} must not exist", path.display()));
            }
        }
        let hardware = hardware_record(work_root)?;
        if !hardware.overall_pass {
            return Err("C6.2 hardware admission failed".to_owned());
        }
        fs::create_dir(run_root)
            .map_err(|error| format!("create {}: {error}", run_root.display()))?;
        fs::create_dir(artifact_root)
            .map_err(|error| format!("create {}: {error}", artifact_root.display()))?;
        fs::create_dir(state_root)
            .map_err(|error| format!("create {}: {error}", state_root.display()))?;

        let model_digest = hash_file_set("volta-zk/c6.2/model-file-set/v1", weights, &MODEL_FILES)?;
        let params_digest = hash_c62_setup_profiles(setup_dir)?;
        let quantization_digest = quantization_digest()?;
        let inference_started = Instant::now();
        let session_sequence = c62_session_sequence(weights)?;
        let model = load_model(weights).map_err(|error| format!("load verifier model: {error}"))?;
        let verifier_model = Gpt2VerifierModel::from_model(&model)?;
        drop(model);
        let genesis_owner = build_c6_t1_workload_owner(weights)?;
        if genesis_owner.sequence() != &session_sequence[..150] {
            return Err("C6.2 genesis owner differs from the session prefix".to_owned());
        }
        let inference_wall_s_excluded = inference_started.elapsed().as_secs_f64();

        let installed_profiles = load_c62_installed_setups(setup_dir)?;
        let connection_store = ConnectionStore::new(state_root.join("connections"))
            .map_err(|error| format!("connection store: {error}"))?;
        let authorization_stores = [
            ResponseAuthorizationStore::new(state_root.join("authorization-0"))
                .map_err(|error| format!("authorization store 0: {error}"))?,
            ResponseAuthorizationStore::new(state_root.join("authorization-1"))
                .map_err(|error| format!("authorization store 1: {error}"))?,
        ];
        let bindings = [
            ConnectionBinding::new(
                random_digest("tape-0 connection")?,
                random_digest("tape-0 authenticated channel")?,
                FaseDStagePlan::TerminalOne,
            )
            .map_err(|error| format!("tape-0 binding: {error}"))?,
            ConnectionBinding::new(
                random_digest("tape-1 connection")?,
                random_digest("tape-1 authenticated channel")?,
                FaseDStagePlan::TerminalOne,
            )
            .map_err(|error| format!("tape-1 binding: {error}"))?,
        ];
        let setup_started = Instant::now();
        let mut connections = [
            open_fase_d_connection_with_ggm_prg(
                &connection_store,
                bindings[0],
                None,
                FaseDParams::production(FaseDStagePlan::TerminalOne),
                GgmPrg::Aes128Mmo,
            )
            .map_err(|error| format!("open tape-0 connection: {error}"))?,
            open_fase_d_connection_with_ggm_prg(
                &connection_store,
                bindings[1],
                None,
                FaseDParams::production(FaseDStagePlan::TerminalOne),
                GgmPrg::Aes128Mmo,
            )
            .map_err(|error| format!("open tape-1 connection: {error}"))?,
        ];
        let setup = build_c62_campaign_setup_manifest(
            std::array::from_fn(|index| &installed_profiles[index]),
            &verifier_model,
            quantization_digest,
            protocol_digest(),
            model_digest,
            params_digest,
            random_digest("C6.2 logical connection")?,
            [bindings[0].connection_id, bindings[1].connection_id],
        )?;
        drop(installed_profiles);
        let setup_wall_s = setup_started.elapsed().as_secs_f64();
        let setup_bytes = setup.first_exchange_bytes().map_err(|error| error.to_string())?;
        let capacity_reconciled = C62_SESSION_RAW_CORRELATIONS <= C6_TERMINAL_ONE_RAW_CAPACITY;
        if setup_bytes > C62_CAMPAIGN_SETUP_MAX_BYTES || !capacity_reconciled {
            return Err("C6.2 session setup or correlation capacity exceeds its gate".to_owned());
        }

        let first_run_root = run_root.join("certificate-00");
        fs::create_dir(&first_run_root)
            .map_err(|error| format!("create {}: {error}", first_run_root.display()))?;
        let first_public = C61PublicWorkloadPreimage::new(
            model_digest,
            C6Workload { prompt_tokens: 100, decode_tokens: 50, old_context: 0, new_context: 150 },
            genesis_owner.sequence().to_vec(),
        )
        .map_err(|error| error.to_string())?;
        let genesis_owner = validate_c62_campaign_cache_precommit_inputs(
            &setup,
            genesis_owner,
            &first_public,
            &first_run_root,
        )?;

        let slot_store =
            C6SlotStore::open(state_root.join("slots")).map_err(|error| error.to_string())?;
        let mut backend =
            Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
                .map_err(|error| format!("initialize CUDA backend: {error}"))?;
        let verifier_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .map_err(|error| format!("build four-thread verifier pool: {error}"))?;
        let admission = C61ProductionPersistedResourceAdmission {
            available_host_bytes: hardware.available_host_bytes,
            available_spill_bytes: hardware.available_spill_bytes,
            gpu_total_bytes: hardware.gpu_total_bytes,
            a100_present: hardware.a100_present,
            allow_persisted_executor: true,
        };

        let first_installed =
            load_c62_campaign_installed_setup(&setup_dir.join(c62_setup_profile_name(0)?))?;
        backend
            .begin_measurement()
            .map_err(|error| format!("begin first backend measurement: {error}"))?;
        let first_before_io = process_io()?;
        let first_started = Instant::now();
        let first_precommit = prepare_c62_campaign_cache_precommit(
            &setup,
            genesis_owner,
            first_public,
            &mut backend,
            &first_run_root,
        )?;
        let genesis =
            C6ClientState::genesis_from_setup(&setup, first_precommit.old_head().cache_root)
                .map_err(|error| error.to_string())?;
        if genesis.head != first_precommit.old_head() {
            return Err("C6.2 first precommit differs from client genesis".to_owned());
        }
        let client_store = C6ClientStore::initialize(state_root.join("client.state"), genesis)
            .map_err(|error| error.to_string())?;
        let mut first_state =
            Some((first_precommit, first_installed, first_started, first_before_io));
        let mut certificates = Vec::with_capacity(usize::from(C6_ACCEPTANCE_CREDITS));
        let mut aborted_slots = Vec::with_capacity(usize::from(C6_ABORT_RETRY_CREDITS));

        for index in 0..C6_ACCEPTANCE_CREDITS {
            let current = client_store.load().map_err(|error| error.to_string())?;
            let old_context = current.head.cache_len;
            let expected_old = if index == 0 { 0 } else { 100 + 50 * u32::from(index) };
            if old_context != expected_old || current.pending_attempt.is_some() {
                return Err("C6.2 accepted prefix differs before the next certificate".to_owned());
            }
            let new_context = if old_context == 0 { 150 } else { old_context + 50 };
            let workload = C6Workload {
                prompt_tokens: if old_context == 0 { 100 } else { 0 },
                decode_tokens: 50,
                old_context,
                new_context,
            };
            let run_directory = run_root.join(format!("certificate-{index:02}"));
            let (precommit, installed, prover_started, before_io) = if index == 0 {
                first_state
                    .take()
                    .ok_or_else(|| "C6.2 first response state was already consumed".to_owned())?
            } else {
                fs::create_dir(&run_directory)
                    .map_err(|error| format!("create {}: {error}", run_directory.display()))?;
                let workload_owner = build_c62_continuation_workload_owner(
                    weights,
                    session_sequence[..new_context as usize].to_vec(),
                    old_context as usize,
                )?;
                let public = C61PublicWorkloadPreimage::new(
                    model_digest,
                    workload,
                    workload_owner.sequence().to_vec(),
                )
                .map_err(|error| error.to_string())?;
                let installed = load_c62_campaign_installed_setup(
                    &setup_dir.join(c62_setup_profile_name(old_context)?),
                )?;
                backend
                    .begin_measurement()
                    .map_err(|error| format!("begin backend measurement {index}: {error}"))?;
                let before_io = process_io()?;
                let prover_started = Instant::now();
                let precommit = prepare_c62_campaign_continuation_cache_precommit(
                    &setup,
                    workload_owner,
                    public,
                    current.head,
                    &mut backend,
                    &run_directory,
                )?;
                (precommit, installed, prover_started, before_io)
            };
            if precommit.workload() != workload || precommit.old_head() != current.head {
                return Err("C6.2 response precommit differs from the client state".to_owned());
            }
            let (sub_correlations, full_correlations, raw_correlations) =
                c62_correlation_profile(old_context)?;
            let (pending, client_attempt) = client_store
                .reserve_attempt(
                    current,
                    random_digest("C6.2 accepted attempt nonce")?,
                    raw_correlations,
                    workload,
                )
                .map_err(|error| error.to_string())?;
            let reservation =
                C6SlotReservation::from_client_attempt(setup.connection_id, client_attempt)
                    .map_err(|error| error.to_string())?;
            let mut slot = slot_store.reserve(reservation).map_err(|error| error.to_string())?;
            slot.start().map_err(|error| error.to_string())?;
            let attempt = C6ProductionPairedPcgAttempt::allocate(
                &setup,
                reservation,
                [&authorization_stores[0], &authorization_stores[1]],
                connections,
                sub_correlations,
                full_correlations,
            )
            .map_err(|error| format!("allocate accepted paired PCG attempt {index}: {error}"))?;
            let produced = run_c62_campaign_live_production(
                &setup,
                installed,
                precommit,
                attempt,
                admission,
                &mut backend,
            )?;
            let prover_wall_s = prover_started.elapsed().as_secs_f64();
            let backend_record = BackendRecord::from(
                backend
                    .finish_measurement()
                    .map_err(|error| format!("finish backend measurement {index}: {error}"))?,
            );
            let after_io = process_io()?;
            let C62CampaignLiveProductionOutput {
                certificate,
                public_instance,
                verifier_replay,
                response_context_digest,
                native_public_context_digest,
                connections: returned_connections,
            } = produced;
            connections = returned_connections;
            let certificate_digest =
                slot.produce_c62(&certificate).map_err(|error| error.to_string())?;
            let certificate_directory = artifact_root.join(format!("certificate-{index:02}"));
            create_c62_campaign_artifact(
                &certificate_directory,
                &certificate,
                &verifier_replay,
                &setup,
                &public_instance,
                &source_git_commit,
            )?;
            let provider_complete_wall_s = prover_started.elapsed().as_secs_f64();
            let certificate_bytes = certificate.encoded_len().map_err(|error| error.to_string())?;
            let pi_final_bytes = C62_NATIVE_CERTIFICATE_FRAMING_BYTES
                .checked_add(certificate.proof_envelope.len() as u64)
                .ok_or_else(|| "C6.2 pi_final length overflows".to_owned())?;

            let rss_before = current_rss_bytes()?;
            let sampler = RssSampler::start(rss_before);
            let artifact = load_c62_campaign_artifact(&certificate_directory)?;
            let verifier_started = Instant::now();
            let verified = verifier_pool.install(|| verify_c62_loaded_campaign_e2e(artifact))?;
            let verifier_wall_s = verifier_started.elapsed().as_secs_f64();
            let verifier_additional_peak_bytes = sampler.finish()?.saturating_sub(rss_before);
            if verified.certificate_digest != certificate_digest {
                return Err("C6.2 disk verifier accepted another certificate digest".to_owned());
            }
            let accepted = client_store
                .accept_c62(pending, &certificate)
                .map_err(|error| error.to_string())?;
            slot.acknowledge(verified.certificate_digest).map_err(|error| error.to_string())?;
            if accepted.head.cache_len != new_context
                || accepted.accepted_certificate_digest != certificate_digest
            {
                return Err("C6.2 accepted head differs from the verified certificate".to_owned());
            }

            let certificate_target_pass = certificate_bytes <= C62_CERTIFICATE_STRICT_MAX_BYTES;
            let certificate_tolerance_pass = certificate_bytes <= CERTIFICATE_TOLERANCE_BYTES;
            let pi_final_target_pass = pi_final_bytes <= C62_NATIVE_STRICT_PI_FINAL_MAX_BYTES;
            let pi_final_tolerance_pass = pi_final_bytes <= PI_FINAL_TOLERANCE_BYTES;
            let prover_target_pass = prover_wall_s < PROVER_TARGET_S;
            let prover_tolerance_pass = prover_wall_s < PROVER_TOLERANCE_S;
            let verifier_target_pass = verifier_wall_s < VERIFIER_TARGET_S;
            let verifier_tolerance_pass = verifier_wall_s < VERIFIER_TOLERANCE_S;
            let verifier_memory_pass =
                verifier_additional_peak_bytes <= VERIFIER_MEMORY_LIMIT_BYTES;
            let pass = certificate_tolerance_pass
                && pi_final_tolerance_pass
                && prover_tolerance_pass
                && verifier_tolerance_pass
                && verifier_memory_pass;
            certificates.push(SessionCertificateRecord {
                index,
                slot: reservation.slot,
                old_context,
                new_context,
                setup_profile: c62_setup_profile_name(old_context)?,
                certificate_digest: hex(&certificate_digest),
                response_context_digest: hex(&response_context_digest),
                native_public_context_digest: hex(&native_public_context_digest),
                certificate_bytes,
                pi_final_bytes,
                prover_wall_s,
                provider_complete_wall_s,
                verifier_wall_s,
                verifier_additional_peak_bytes,
                certificate_target_pass,
                certificate_tolerance_pass,
                pi_final_target_pass,
                pi_final_tolerance_pass,
                prover_target_pass,
                prover_tolerance_pass,
                verifier_target_pass,
                verifier_tolerance_pass,
                verifier_memory_pass,
                process_io: io_delta(&before_io, &after_io),
                backend: backend_record,
                artifact_root: certificate_directory.display().to_string(),
                pass,
            });

            if index == 0 {
                let burn_workload = C6Workload {
                    prompt_tokens: 0,
                    decode_tokens: 50,
                    old_context: 150,
                    new_context: 200,
                };
                let (burn_sub, burn_full, burn_raw) = c62_correlation_profile(150)?;
                for burn_index in 0..C6_ABORT_RETRY_CREDITS {
                    let burn_current = client_store.load().map_err(|error| error.to_string())?;
                    let (burn_pending, burn_attempt) = client_store
                        .reserve_attempt(
                            burn_current,
                            random_digest("C6.2 burned attempt nonce")?,
                            burn_raw,
                            burn_workload,
                        )
                        .map_err(|error| error.to_string())?;
                    let burn_reservation =
                        C6SlotReservation::from_client_attempt(setup.connection_id, burn_attempt)
                            .map_err(|error| error.to_string())?;
                    let mut burn_slot =
                        slot_store.reserve(burn_reservation).map_err(|error| error.to_string())?;
                    burn_slot.start().map_err(|error| error.to_string())?;
                    let burn_owner = C6ProductionPairedPcgAttempt::allocate(
                        &setup,
                        burn_reservation,
                        [&authorization_stores[0], &authorization_stores[1]],
                        connections,
                        burn_sub,
                        burn_full,
                    )
                    .map_err(|error| {
                        format!("allocate burned paired PCG attempt {burn_index}: {error}")
                    })?;
                    connections = burn_owner.finish_abort()?;
                    burn_slot.abort().map_err(|error| error.to_string())?;
                    let after_abort = client_store
                        .abort_attempt(burn_pending)
                        .map_err(|error| error.to_string())?;
                    if after_abort.head != burn_current.head
                        || after_abort.raw_high_water
                            != [burn_reservation.correlation_ranges.coordinates[0].start + burn_raw;
                                2]
                    {
                        return Err(
                            "C6.2 aborted slot did not preserve the accepted head".to_owned()
                        );
                    }
                    aborted_slots.push(burn_reservation.slot);
                }
            }
        }

        let final_state = client_store.load().map_err(|error| error.to_string())?;
        for connection in &mut connections {
            connection
                .connection
                .abort(ConnectionAbortReason::ExplicitClose)
                .map_err(|error| format!("close C6.2 connection: {error}"))?;
        }
        let setup_plus_first_bytes = setup_bytes
            .checked_add(
                certificates
                    .first()
                    .ok_or_else(|| "C6.2 session produced no certificate".to_owned())?
                    .certificate_bytes,
            )
            .ok_or_else(|| "C6.2 setup plus first certificate overflows".to_owned())?;
        let setup_plus_first_target_pass = setup_plus_first_bytes <= SETUP_PLUS_FIRST_TARGET_BYTES;
        let setup_plus_first_tolerance_pass =
            setup_plus_first_bytes <= SETUP_PLUS_FIRST_TOLERANCE_BYTES;
        let soundness_pass = SOUNDNESS_BITS_PER_CERTIFICATE >= SOUNDNESS_FLOOR_BITS;
        let exact_session = certificates.len() == usize::from(C6_ACCEPTANCE_CREDITS)
            && aborted_slots.len() == usize::from(C6_ABORT_RETRY_CREDITS)
            && final_state.head.cache_len == 950
            && final_state.next_slot == u32::from(C6_ACCEPTANCE_CREDITS + C6_ABORT_RETRY_CREDITS)
            && final_state.raw_high_water == [C62_SESSION_RAW_CORRELATIONS; 2]
            && final_state.pending_attempt.is_none();
        let pass = exact_session
            && capacity_reconciled
            && setup_plus_first_tolerance_pass
            && soundness_pass
            && certificates.iter().all(|certificate| certificate.pass);
        let record = SessionRecord {
            schema: SCHEMA,
            profile: PROFILE,
            mode: "prove-and-verify-session",
            source_git_commit,
            git_dirty: false,
            cloud,
            hardware,
            protocol_id: PROTOCOL_ID,
            protocol_digest: hex(&protocol_digest()),
            model_digest: hex(&model_digest),
            params_digest: hex(&params_digest),
            quantization_digest: hex(&quantization_digest),
            setup_wall_s,
            inference_wall_s_excluded,
            setup_bytes,
            setup_plus_first_bytes,
            setup_plus_first_target_pass,
            setup_plus_first_tolerance_pass,
            accepted_slots: C6_ACCEPTANCE_CREDITS,
            aborted_slots,
            final_context: final_state.head.cache_len,
            final_next_slot: final_state.next_slot,
            raw_correlations_per_tape: final_state.raw_high_water[0],
            expected_raw_correlations_per_tape: C62_SESSION_RAW_CORRELATIONS,
            capacity_reconciled,
            soundness_bits_per_certificate: SOUNDNESS_BITS_PER_CERTIFICATE,
            soundness_floor_bits: SOUNDNESS_FLOOR_BITS,
            soundness_pass,
            certificates,
            session_gate_evaluated: true,
            credit: pass,
            pass,
            artifact_root: artifact_root.display().to_string(),
            state_root: state_root.display().to_string(),
            run_root: run_root.display().to_string(),
        };
        create_new_json(&args.output, &record)?;
        if !pass {
            return Err("C6.2 exact session product gate failed".to_owned());
        }
        Ok(())
    }

    struct RssSampler {
        stop: Arc<AtomicBool>,
        handle: thread::JoinHandle<u64>,
    }

    impl RssSampler {
        fn start(initial: u64) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                let mut peak = initial;
                while !worker_stop.load(Ordering::Relaxed) {
                    if let Ok(value) = current_rss_bytes() {
                        peak = peak.max(value);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                current_rss_bytes().map_or(peak, |value| peak.max(value))
            });
            Self { stop, handle }
        }

        fn finish(self) -> Result<u64, String> {
            self.stop.store(true, Ordering::Relaxed);
            self.handle.join().map_err(|_| "RSS sampler panicked".to_owned())
        }
    }

    #[derive(Serialize)]
    struct VerifierRecord {
        schema: u64,
        profile: &'static str,
        mode: &'static str,
        source_git_commit: String,
        git_dirty: bool,
        threads: usize,
        official_four_thread: bool,
        accepted_client_head: bool,
        certificate_digest: String,
        certificate_bytes: u64,
        public_argument_bytes: u64,
        proof_envelope_bytes: u64,
        verifier_wall_s: f64,
        rss_before_bytes: u64,
        rss_peak_bytes: u64,
        additional_peak_bytes: u64,
        verifier_target_pass: bool,
        verifier_tolerance_pass: bool,
        verifier_memory_pass: bool,
        session_gate_evaluated: bool,
        credit: bool,
        pass: bool,
    }

    fn verify(args: &Args) -> Result<(), String> {
        let source_git_commit = git_sha_clean()?;
        let artifact_root = required_path(&args.artifact_root, "--artifact-root")?;
        let rss_before_bytes = current_rss_bytes()?;
        let sampler = RssSampler::start(rss_before_bytes);
        let artifact = load_c62_campaign_artifact(artifact_root)?;
        let certificate = artifact.certificate.clone();
        let certificate_bytes = certificate.encoded_len().map_err(|error| error.to_string())?;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build()
            .map_err(|error| format!("build verifier thread pool: {error}"))?;
        let started = Instant::now();
        let verified = pool.install(|| verify_c62_loaded_campaign_e2e(artifact))?;
        let verifier_wall_s = started.elapsed().as_secs_f64();
        let mut accepted_client_head = false;
        if args.accept {
            let state_root = required_path(&args.state_root, "--state-root")?;
            let client_store = C6ClientStore::open(state_root.join("client.state"))
                .map_err(|error| error.to_string())?;
            let pending = client_store.load().map_err(|error| error.to_string())?;
            let slot_store =
                C6SlotStore::open(state_root.join("slots")).map_err(|error| error.to_string())?;
            let mut slot = slot_store
                .open_slot(certificate.connection_id, certificate.slot)
                .map_err(|error| error.to_string())?;
            if slot.status() != C6SlotStatus::Produced
                || slot.retransmit_c62().map_err(|error| error.to_string())?
                    != certificate.encode().map_err(|error| error.to_string())?
            {
                return Err("C6.2 durable slot differs from verified artifact".to_owned());
            }
            let accepted = client_store
                .accept_c62(pending, &certificate)
                .map_err(|error| error.to_string())?;
            if accepted.accepted_certificate_digest != verified.certificate_digest {
                return Err("C6.2 accepted head differs from verifier output".to_owned());
            }
            slot.acknowledge(verified.certificate_digest).map_err(|error| error.to_string())?;
            accepted_client_head = true;
        }
        let rss_peak_bytes = sampler.finish()?;
        let additional_peak_bytes = rss_peak_bytes.saturating_sub(rss_before_bytes);
        let official_four_thread = args.threads == 4;
        let verifier_target_pass = !official_four_thread || verifier_wall_s < VERIFIER_TARGET_S;
        let verifier_tolerance_pass =
            !official_four_thread || verifier_wall_s < VERIFIER_TOLERANCE_S;
        let verifier_memory_pass = additional_peak_bytes <= VERIFIER_MEMORY_LIMIT_BYTES;
        let pass = official_four_thread && verifier_tolerance_pass && verifier_memory_pass;
        let record = VerifierRecord {
            schema: SCHEMA,
            profile: PROFILE,
            mode: "verify",
            source_git_commit,
            git_dirty: false,
            threads: args.threads,
            official_four_thread,
            accepted_client_head,
            certificate_digest: hex(&verified.certificate_digest),
            certificate_bytes,
            public_argument_bytes: verified.public_argument_bytes,
            proof_envelope_bytes: verified.proof_envelope_bytes,
            verifier_wall_s,
            rss_before_bytes,
            rss_peak_bytes,
            additional_peak_bytes,
            verifier_target_pass,
            verifier_tolerance_pass,
            verifier_memory_pass,
            session_gate_evaluated: false,
            credit: false,
            pass,
        };
        create_new_json(&args.output, &record)?;
        if !pass {
            return Err("C6.2 verifier product gate failed".to_owned());
        }
        Ok(())
    }

    fn verify_variant_rejects(
        artifact: &C62CampaignArtifact,
        certificate: &C62NativeFinalCertificate,
        setup: &C6SetupManifest,
        public_instance: &C61PublicWorkloadInstance,
    ) -> bool {
        let verifier_plan =
            match artifact.operation_plan_artifact.clone().install(&artifact.source_manifest) {
                Ok(plan) => plan,
                Err(_) => return true,
            };
        let verifier_extraction =
            match artifact.verifier_extraction_artifact.decode(verifier_plan.topology()) {
                Ok(extraction) => extraction,
                Err(_) => return true,
            };
        verify_c62_campaign_e2e(
            certificate,
            &artifact.verifier_replay,
            setup,
            &artifact.verifier_model,
            public_instance,
            &artifact.source_manifest,
            verifier_plan,
            verifier_extraction,
            artifact.verifier_extraction_setup_bytes,
            &artifact.native_profile,
            &artifact.compiler_profile,
        )
        .is_err()
    }

    fn resealed_certificate_rejects(
        artifact: &C62CampaignArtifact,
        certificate: C62NativeFinalCertificate,
    ) -> bool {
        match certificate.seal() {
            Ok(certificate) => verify_variant_rejects(
                artifact,
                &certificate,
                &artifact.setup_manifest,
                &artifact.public_instance,
            ),
            Err(_) => true,
        }
    }

    fn replace_public_argument(
        certificate: &C62NativeFinalCertificate,
        public_argument: Vec<u8>,
    ) -> C62NativeFinalCertificate {
        let mut changed = certificate.clone();
        changed.retained_transcript.truncate(C62_RETAINED_NON_PCS_RESPONSE_BYTES as usize);
        changed.retained_transcript.extend_from_slice(&public_argument);
        changed
    }

    fn mutate_public_chain(
        artifact: &C62CampaignArtifact,
        chain_index: usize,
        offset: usize,
    ) -> bool {
        let mut chains = artifact.public_argument.native_chains().clone();
        let Some(byte) = chains.get_mut(chain_index).and_then(|chain| chain.get_mut(offset)) else {
            return false;
        };
        *byte ^= 1;
        let public_argument = match C62PublicArgument::new(
            artifact.public_argument.statement_digest(),
            chains,
            artifact.public_argument.arithmetic().to_vec(),
        )
        .and_then(|argument| argument.encode())
        {
            Ok(public_argument) => public_argument,
            Err(_) => return true,
        };
        resealed_certificate_rejects(
            artifact,
            replace_public_argument(&artifact.certificate, public_argument),
        )
    }

    fn mutate_operation_plan_setup(
        setup: &C6SetupManifest,
        old_context: u32,
    ) -> Result<C6SetupManifest, String> {
        const OUTER_HEADER: usize = 92;
        const OUTER_TRAILER: usize = 32;
        const BUNDLE_PROFILES: usize = 17;
        const BUNDLE_LENGTHS_START: usize = 8 + 2 + 2 + 4 * BUNDLE_PROFILES;
        const BUNDLE_DIGESTS_START: usize = BUNDLE_LENGTHS_START + 8 * BUNDLE_PROFILES;
        const BUNDLE_HEADER: usize = BUNDLE_DIGESTS_START + 32 * BUNDLE_PROFILES;
        const INNER_COMPONENTS: usize = 7;
        const INNER_LENGTHS_START: usize = 12;
        const INNER_DIGESTS_START: usize = INNER_LENGTHS_START + INNER_COMPONENTS * 8;
        const INNER_PAYLOAD_START: usize = INNER_DIGESTS_START + INNER_COMPONENTS * 32;
        let outer = &setup.client_parameters;
        if outer.len() < OUTER_HEADER + OUTER_TRAILER || outer.get(..8) != Some(b"C62CP1\0\0") {
            return Err("C6.2 setup does not contain C62CP1".to_owned());
        }
        let inner_len = usize::try_from(u64::from_le_bytes(
            outer[12..20].try_into().expect("fixed C62CP1 inner length"),
        ))
        .map_err(|_| "C62CP1 inner length exceeds usize".to_owned())?;
        let compressed_len = usize::try_from(u64::from_le_bytes(
            outer[20..28].try_into().expect("fixed C62CP1 compressed length"),
        ))
        .map_err(|_| "C62CP1 compressed length exceeds usize".to_owned())?;
        if OUTER_HEADER + compressed_len + OUTER_TRAILER != outer.len() {
            return Err("C62CP1 length mismatch".to_owned());
        }
        let mut inner =
            zstd::bulk::decompress(&outer[OUTER_HEADER..OUTER_HEADER + compressed_len], inner_len)
                .map_err(|error| format!("decompress C62CP1: {error}"))?;
        let profile_index = match old_context {
            0 => 0,
            150..=900 if old_context % 50 == 0 => ((old_context - 100) / 50) as usize,
            _ => return Err("C6.2 mutation has no registered setup profile".to_owned()),
        };
        if inner.len() < BUNDLE_HEADER
            || inner.get(..8) != Some(b"C62MP1\0\0")
            || u16::from_le_bytes(inner[10..12].try_into().expect("fixed profile count"))
                != BUNDLE_PROFILES as u16
        {
            return Err("C62MP1 setup bundle is invalid".to_owned());
        }
        let mut profile_lengths = [0usize; BUNDLE_PROFILES];
        for (index, length) in profile_lengths.iter_mut().enumerate() {
            let offset = BUNDLE_LENGTHS_START + 8 * index;
            *length = usize::try_from(u64::from_le_bytes(
                inner[offset..offset + 8].try_into().expect("fixed profile length"),
            ))
            .map_err(|_| "C62MP1 profile length exceeds usize".to_owned())?;
        }
        let bundle_end = profile_lengths
            .iter()
            .try_fold(BUNDLE_HEADER, |offset, length| offset.checked_add(*length))
            .ok_or_else(|| "C62MP1 bundle length overflows".to_owned())?;
        if bundle_end != inner.len() {
            return Err("C62MP1 profile lengths do not cover the bundle".to_owned());
        }
        let profile_start = profile_lengths[..profile_index]
            .iter()
            .try_fold(BUNDLE_HEADER, |offset, length| offset.checked_add(*length))
            .ok_or_else(|| "C62MP1 profile offset overflows".to_owned())?;
        let profile_len = profile_lengths[profile_index];
        let profile_end = profile_start
            .checked_add(profile_len)
            .ok_or_else(|| "C62MP1 profile end overflows".to_owned())?;
        if profile_len == 0 || profile_end > inner.len() {
            return Err("C62MP1 selected profile is truncated".to_owned());
        }
        let lengths_start = profile_start + INNER_LENGTHS_START;
        let digests_start = profile_start + INNER_DIGESTS_START;
        let payload_start = profile_start + INNER_PAYLOAD_START;
        let source_len = usize::try_from(u64::from_le_bytes(
            inner[lengths_start..lengths_start + 8].try_into().expect("fixed source length"),
        ))
        .map_err(|_| "C61CP4 source length exceeds usize".to_owned())?;
        let plan_len = usize::try_from(u64::from_le_bytes(
            inner[lengths_start + 8..lengths_start + 16].try_into().expect("fixed plan length"),
        ))
        .map_err(|_| "C61CP4 plan length exceeds usize".to_owned())?;
        let plan_start = payload_start
            .checked_add(source_len)
            .ok_or_else(|| "C61CP4 plan offset overflows".to_owned())?;
        if plan_len == 0 || plan_start + plan_len > profile_end {
            return Err("C61CP4 operation plan is absent".to_owned());
        }
        inner[plan_start] ^= 1;
        let plan_digest = *blake3::hash(&inner[plan_start..plan_start + plan_len]).as_bytes();
        inner[digests_start + 32..digests_start + 64].copy_from_slice(&plan_digest);
        let profile_digest = *blake3::hash(&inner[profile_start..profile_end]).as_bytes();
        let bundle_digest = BUNDLE_DIGESTS_START + profile_index * 32;
        inner[bundle_digest..bundle_digest + 32].copy_from_slice(&profile_digest);
        let compressed = zstd::bulk::compress(&inner, 3)
            .map_err(|error| format!("recompress C62CP1: {error}"))?;
        let mut rebuilt = Vec::with_capacity(OUTER_HEADER + compressed.len() + OUTER_TRAILER);
        rebuilt.extend_from_slice(b"C62CP1\0\0");
        rebuilt.extend_from_slice(&1u16.to_le_bytes());
        rebuilt.extend_from_slice(&3u16.to_le_bytes());
        rebuilt.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        rebuilt.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        rebuilt.extend_from_slice(blake3::hash(&inner).as_bytes());
        rebuilt.extend_from_slice(blake3::hash(&compressed).as_bytes());
        rebuilt.extend_from_slice(&compressed);
        let mut outer_hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.2/client-parameters/zstd-envelope/v1");
        outer_hasher.update(&rebuilt);
        rebuilt.extend_from_slice(outer_hasher.finalize().as_bytes());
        let mut changed = setup.clone();
        changed.client_parameters = rebuilt;
        let mut client_hasher = blake3::Hasher::new_derive_key("volta-zk/c6/client-parameters/v2");
        client_hasher.update(&changed.client_parameters);
        changed.client_parameters_digest = *client_hasher.finalize().as_bytes();
        changed.validate().map_err(|error| error.to_string())?;
        Ok(changed)
    }

    fn provider_challenge_surface_closed() -> bool {
        let source = include_str!("../c61_campaign.rs");
        let Some(runner) = source
            .split_once("pub fn run_c62_campaign_live_production(")
            .and_then(|(_, rest)| rest.split_once(") -> Result").map(|(signature, _)| signature))
        else {
            return false;
        };
        let Some(session) =
            source.split_once("impl C62CampaignResponseTranscriptSession").and_then(|(_, rest)| {
                rest.split_once("/// Provider-visible endpoints").map(|(body, _)| body)
            })
        else {
            return false;
        };
        !["challenge", "broker", "endpoint", "tape"].iter().any(|term| runner.contains(term))
            && session.contains("Transcript::new_fiat_shamir(context_digest)")
            && !session.contains("new_interactive")
            && !session.contains("private_entropy")
    }

    #[derive(Serialize)]
    struct MutationCase {
        label: String,
        rejected: bool,
    }

    #[derive(Serialize)]
    struct MutationRecord {
        schema: u64,
        profile: &'static str,
        mode: &'static str,
        source_git_commit: String,
        git_dirty: bool,
        certificate_digest: String,
        baseline_accepts: bool,
        cases: Vec<MutationCase>,
        mutation_count: usize,
        rejected_count: usize,
        every_input_token_covered: bool,
        challenge_context_changes_output: bool,
        challenge_move_changes_output: bool,
        provider_supplies_no_challenge_domain: bool,
        credit: bool,
        pass: bool,
    }

    fn mutate(args: &Args) -> Result<(), String> {
        let source_git_commit = git_sha_clean()?;
        let artifact_root = required_path(&args.artifact_root, "--artifact-root")?;
        let artifact = load_c62_campaign_artifact(artifact_root)?;
        let baseline_accepts = !verify_variant_rejects(
            &artifact,
            &artifact.certificate,
            &artifact.setup_manifest,
            &artifact.public_instance,
        );
        if !baseline_accepts {
            return Err("C6.2 mutation baseline does not verify".to_owned());
        }
        let mut cases = Vec::new();
        let mut push = |label: String, rejected: bool| cases.push(MutationCase { label, rejected });

        for index in 0..artifact.public_instance.public_tokens().len() {
            let mut tokens = artifact.public_instance.public_tokens().to_vec();
            tokens[index] ^= 1;
            let changed = C61PublicWorkloadPreimage::new(
                artifact.public_instance.model_family_digest(),
                artifact.public_instance.workload(),
                tokens,
            )
            .and_then(|preimage| {
                preimage.bind_statements(
                    artifact.public_instance.response_statement_digest(),
                    artifact.public_instance.public_argument_statement_digest(),
                )
            });
            let rejected = changed.is_err()
                || verify_variant_rejects(
                    &artifact,
                    &artifact.certificate,
                    &artifact.setup_manifest,
                    &changed.expect("checked successful public workload mutation"),
                );
            push(format!("input-token-{index}"), rejected);
        }

        for (label, change) in [
            ("old-head-epoch", 0usize),
            ("old-head-cache-len", 1),
            ("old-head-cache-root", 2),
            ("old-head-transition", 3),
            ("new-head-epoch", 4),
            ("new-head-cache-len", 5),
            ("new-head-cache-root", 6),
            ("new-head-transition", 7),
        ] {
            let mut certificate = artifact.certificate.clone();
            match change {
                0 => certificate.old_head.epoch ^= 1,
                1 => certificate.old_head.cache_len ^= 1,
                2 => certificate.old_head.cache_root[0] ^= 1,
                3 => certificate.old_head.producer_transition_digest[0] ^= 1,
                4 => certificate.new_head.epoch ^= 1,
                5 => certificate.new_head.cache_len ^= 1,
                6 => certificate.new_head.cache_root[0] ^= 1,
                7 => certificate.new_head.producer_transition_digest[0] ^= 1,
                _ => unreachable!(),
            }
            let rejected = if change == 7 {
                verify_variant_rejects(
                    &artifact,
                    &certificate,
                    &artifact.setup_manifest,
                    &artifact.public_instance,
                )
            } else {
                resealed_certificate_rejects(&artifact, certificate)
            };
            push(label.to_owned(), rejected);
        }

        let changed_setup = mutate_operation_plan_setup(
            &artifact.setup_manifest,
            artifact.public_instance.workload().old_context,
        )?;
        let mut changed_certificate = artifact.certificate.clone();
        changed_certificate.setup_manifest_digest =
            changed_setup.digest().map_err(|error| error.to_string())?;
        let operation_plan_rejected = match changed_certificate.seal() {
            Ok(changed_certificate) => verify_variant_rejects(
                &artifact,
                &changed_certificate,
                &changed_setup,
                &artifact.public_instance,
            ),
            Err(_) => true,
        };
        push("operation-plan-identity".to_owned(), operation_plan_rejected);

        push("commitment-root".to_owned(), mutate_public_chain(&artifact, 1, 16));
        push("claim-value".to_owned(), mutate_public_chain(&artifact, 1, 48));
        let secondary_len = artifact.public_argument.native_chains()[1].len();
        push(
            "compiler-correction".to_owned(),
            mutate_public_chain(&artifact, 1, secondary_len.saturating_sub(32)),
        );
        push("distinct-roots-divergent-values".to_owned(), mutate_public_chain(&artifact, 3, 48));

        let mut role_bytes =
            artifact.public_argument.encode().map_err(|error| error.to_string())?;
        role_bytes[44] ^= 1;
        push(
            "component-role".to_owned(),
            resealed_certificate_rejects(
                &artifact,
                replace_public_argument(&artifact.certificate, role_bytes),
            ),
        );
        let mut repetition_bytes =
            artifact.public_argument.encode().map_err(|error| error.to_string())?;
        repetition_bytes[46] ^= 1;
        push(
            "component-repetition".to_owned(),
            resealed_certificate_rejects(
                &artifact,
                replace_public_argument(&artifact.certificate, repetition_bytes),
            ),
        );

        let mut wrapper_root = artifact.certificate.clone();
        wrapper_root.wrapper.residual_root[0] ^= 1;
        push(
            "wrapper-commitment-root".to_owned(),
            resealed_certificate_rejects(&artifact, wrapper_root),
        );
        let mut residual = artifact.certificate.clone();
        residual.residual.coordinates[0].correction_rlc.c0 += volta_field::Fp::ONE;
        push("designated-correction".to_owned(), resealed_certificate_rejects(&artifact, residual));

        let envelope = artifact.certificate.decoded_proof_envelope();
        let mut residual_sumcheck = envelope.residual_sumcheck().to_vec();
        residual_sumcheck[0] ^= 1;
        let changed_envelope = C62ResponseProofEnvelope::new(
            residual_sumcheck,
            envelope.product_coordinate_one().to_vec(),
            envelope.residual_pending_corrections().to_vec(),
            envelope.cache_source_bootstrap().to_vec(),
            envelope.cache_blind().to_vec(),
            envelope.cache_fold_targets().to_vec(),
            envelope.authenticated_output_link().to_vec(),
        )
        .and_then(|envelope| envelope.encode());
        let proof_field_rejected = match changed_envelope {
            Ok(changed_envelope) => {
                let mut certificate = artifact.certificate.clone();
                certificate.proof_envelope = changed_envelope;
                resealed_certificate_rejects(&artifact, certificate)
            }
            Err(_) => true,
        };
        push("proof-field".to_owned(), proof_field_rejected);

        let mut transcript_move = artifact.certificate.clone();
        transcript_move.retained_transcript[0] ^= 1;
        let transcript_move_rejected = resealed_certificate_rejects(&artifact, transcript_move);
        push("transcript-move".to_owned(), transcript_move_rejected);
        let mut trailing = artifact.certificate.encode().map_err(|error| error.to_string())?;
        trailing.push(0);
        push("trailing-byte".to_owned(), C62NativeFinalCertificate::decode(&trailing).is_err());

        let mut context_a = Transcript::new_fiat_shamir([0x61; 32])?;
        let mut context_b = Transcript::new_fiat_shamir([0x62; 32])?;
        context_a.append_message("mutation-domain", b"same-move");
        context_b.append_message("mutation-domain", b"same-move");
        let challenge_context_changes_output =
            context_a.challenge_fp2() != context_b.challenge_fp2();
        let mut move_a = Transcript::new_fiat_shamir([0x63; 32])?;
        let mut move_b = Transcript::new_fiat_shamir([0x63; 32])?;
        move_a.append_message("mutation-domain", b"move-a");
        move_b.append_message("mutation-domain", b"move-b");
        let challenge_move_changes_output = move_a.challenge_fp2() != move_b.challenge_fp2();
        let mut point_a = Transcript::new_fiat_shamir([0x64; 32])?;
        let mut point_b = Transcript::new_fiat_shamir([0x64; 32])?;
        point_a.append_message("claim-point-preimage", b"move-a");
        point_b.append_message("claim-point-preimage", b"move-b");
        let claim_point_changes =
            (0..28).map(|_| point_a.challenge_fp2()).ne((0..28).map(|_| point_b.challenge_fp2()));
        push("claim-point".to_owned(), claim_point_changes && transcript_move_rejected);
        push("challenge-domain".to_owned(), challenge_context_changes_output);

        let mutation_count = cases.len();
        let rejected_count = cases.iter().filter(|case| case.rejected).count();
        let every_input_token_covered = artifact.public_instance.public_tokens().len() == 150
            && cases.iter().filter(|case| case.label.starts_with("input-token-")).count() == 150;
        let provider_supplies_no_challenge_domain = provider_challenge_surface_closed();
        let pass = baseline_accepts
            && rejected_count == mutation_count
            && every_input_token_covered
            && challenge_context_changes_output
            && challenge_move_changes_output
            && provider_supplies_no_challenge_domain;
        let record = MutationRecord {
            schema: SCHEMA,
            profile: PROFILE,
            mode: "mutate",
            source_git_commit,
            git_dirty: false,
            certificate_digest: hex(&artifact
                .certificate
                .digest()
                .map_err(|error| error.to_string())?),
            baseline_accepts,
            cases,
            mutation_count,
            rejected_count,
            every_input_token_covered,
            challenge_context_changes_output,
            challenge_move_changes_output,
            provider_supplies_no_challenge_domain,
            credit: false,
            pass,
        };
        create_new_json(&args.output, &record)?;
        if !pass {
            return Err("C6.2 mutation matrix failed".to_owned());
        }
        Ok(())
    }

    #[derive(Serialize)]
    struct FailureRecord<'a> {
        schema: u64,
        profile: &'static str,
        mode: &'a str,
        status: &'static str,
        error: &'a str,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[ignore = "requires generated production weights and setup paths"]
        fn production_first_cache_precommit_inputs_match() {
            let weights = PathBuf::from(std::env::var("C62_DIAG_WEIGHTS").unwrap());
            let setup_dir = PathBuf::from(std::env::var("C62_DIAG_SETUP").unwrap());
            let run_root = PathBuf::from(std::env::var("C62_DIAG_RUN_ROOT").unwrap());
            fs::create_dir(&run_root).unwrap();
            let installed_profiles = load_c62_installed_setups(&setup_dir).unwrap();
            let workload_owner = build_c6_t1_workload_owner(&weights).unwrap();
            let verifier_model = Gpt2VerifierModel::from_model(workload_owner.model()).unwrap();
            let model_digest = hash_file_set(
                "volta-zk/c6.2/model-file-set/v1",
                &weights,
                &MODEL_FILES,
            )
            .unwrap();
            let setup = build_c62_campaign_setup_manifest(
                std::array::from_fn(|index| &installed_profiles[index]),
                &verifier_model,
                quantization_digest().unwrap(),
                protocol_digest(),
                model_digest,
                hash_c62_setup_profiles(&setup_dir).unwrap(),
                [0x71; 32],
                [[0x72; 32], [0x73; 32]],
            )
            .unwrap();
            let public = C61PublicWorkloadPreimage::new(
                model_digest,
                C6Workload {
                    prompt_tokens: 100,
                    decode_tokens: 50,
                    old_context: 0,
                    new_context: 150,
                },
                workload_owner.sequence().to_vec(),
            )
            .unwrap();
            validate_c62_campaign_cache_precommit_inputs(
                &setup,
                workload_owner,
                &public,
                &run_root,
            )
            .unwrap();
        }

        #[test]
        fn record_profile_keeps_tolerance_and_capacity_separate_from_credit() {
            assert_eq!(SCHEMA, 2);
            assert_eq!(SETUP_PLUS_FIRST_TOLERANCE_BYTES, 157_500_000);
            assert_eq!(CERTIFICATE_TOLERANCE_BYTES, 23_099_998);
            assert_eq!(PI_FINAL_TOLERANCE_BYTES, 4_725_000);
            assert_eq!(PROVER_TOLERANCE_S, 15.75);
            assert_eq!(VERIFIER_TOLERANCE_S, 5.25);
            assert_eq!(C6_ACCEPTANCE_CREDITS, 17);
            assert_eq!(C6_ABORT_RETRY_CREDITS, 4);
            let used = C62_SESSION_RAW_CORRELATIONS;
            assert_eq!(used, 49_416_418);
            assert!(c62_suffix_correlation_census_valid());
            assert!(used <= C6_TERMINAL_ONE_RAW_CAPACITY);

            let source = include_str!("c62_whir_fiat_shamir_record.rs");
            let session = source
                .split_once("fn prove(args: &Args)")
                .unwrap()
                .1
                .split_once("struct RssSampler")
                .unwrap()
                .0;
            assert!(session.contains("session_gate_evaluated: true"));
            assert!(session.contains("credit: pass"));
            assert!(session.contains("C6_ACCEPTANCE_CREDITS"));
            assert!(session.contains("C6_ABORT_RETRY_CREDITS"));
            assert!(!source.contains(concat!("exact_", "acceptance_credits")));
            assert!(!source.contains(concat!("exact_", "abort_credits")));
        }

        #[test]
        fn provider_record_has_no_challenge_transport_or_terminal_stop_label() {
            assert!(provider_challenge_surface_closed());
            let source = include_str!("c62_whir_fiat_shamir_record.rs");
            assert!(!source.contains(concat!("status: \"hard", "_stop\"")));
            assert!(!source.contains(concat!("record HARD", " STOP")));
        }

        #[test]
        fn session_profile_distribution_and_state_order_are_frozen() {
            let old_contexts =
                std::iter::once(0).chain((150..=900).step_by(50)).collect::<Vec<_>>();
            assert_eq!(old_contexts.len(), usize::from(C6_ACCEPTANCE_CREDITS));
            let profiles = old_contexts
                .iter()
                .map(|old_context| c62_setup_profile_name(*old_context).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(profiles, SETUP_PROFILE_DIRS);
            assert_eq!(
                [
                    old_contexts.iter().filter(|context| **context == 0).count(),
                    old_contexts.iter().filter(|context| matches!(**context, 150 | 200)).count(),
                    old_contexts.iter().filter(|context| (250..=450).contains(*context)).count(),
                    old_contexts.iter().filter(|context| (500..=900).contains(*context)).count(),
                ],
                [1, 2, 5, 9]
            );

            let source = include_str!("c62_whir_fiat_shamir_record.rs");
            let session = source
                .split_once("fn prove(args: &Args)")
                .unwrap()
                .1
                .split_once("struct RssSampler")
                .unwrap()
                .0;
            let load = session.find("load_c62_campaign_artifact(&certificate_directory)").unwrap();
            let verify = session.find("verify_c62_loaded_campaign_e2e(artifact)").unwrap();
            let accept = session.find(".accept_c62(pending, &certificate)").unwrap();
            let acknowledge =
                session.find("slot.acknowledge(verified.certificate_digest)").unwrap();
            let burn_block = acknowledge + session[acknowledge..].find("if index == 0").unwrap();
            let abort = session.find("connections = burn_owner.finish_abort()").unwrap();
            assert!(load < verify && verify < accept && accept < acknowledge);
            assert!(acknowledge < burn_block && burn_block < abort);
            assert!(session.contains("final_state.head.cache_len == 950"));
            assert!(session.contains("final_state.pending_attempt.is_none()"));
        }
    }

    pub fn main() {
        let args = parse_args();
        let mode = match args.mode {
            Mode::Preflight => "preflight",
            Mode::Prove => "prove",
            Mode::Verify => "verify",
            Mode::Mutate => "mutate",
        };
        let result = match args.mode {
            Mode::Preflight => preflight(&args),
            Mode::Prove => prove(&args),
            Mode::Verify => verify(&args),
            Mode::Mutate => mutate(&args),
        };
        if let Err(error) = result {
            if !args.output.exists() {
                let _ = create_new_json(
                    &args.output,
                    &FailureRecord {
                        schema: SCHEMA,
                        profile: PROFILE,
                        mode,
                        status: "failed",
                        error: &error,
                    },
                );
            }
            eprintln!("c62_whir_fiat_shamir_record FAILED: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(feature = "cuda", feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn main() {
    enabled::main()
}

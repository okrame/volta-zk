//! Measure the strict C6.2 setup bundle from generated local profiles.

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use volta_bench::c61_campaign::{
    build_c62_campaign_setup_manifest, encode_c62_campaign_client_parameters,
    load_c62_campaign_installed_setup, C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES,
    C62_CAMPAIGN_SETUP_MAX_BYTES,
};
use volta_gpt2::{load_model, Gpt2VerifierModel};
use volta_proto::C62_CERTIFICATE_STRICT_MAX_BYTES;

const PROFILE_DIRS: [&str; 17] = [
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
const SETUP_PLUS_FIRST_TOLERANCE_BYTES: u64 = 157_500_000;

#[derive(Serialize)]
struct Measurement {
    schema: u64,
    profile: &'static str,
    client_parameter_bytes: u64,
    client_parameter_cap_bytes: u64,
    setup_bytes: u64,
    setup_cap_bytes: u64,
    certificate_ceiling_bytes: u64,
    setup_plus_certificate_ceiling_bytes: u64,
    setup_plus_first_tolerance_bytes: u64,
    pass: bool,
    credit: bool,
}

fn parse_args() -> Result<(PathBuf, PathBuf), String> {
    let mut weights = None;
    let mut setup_root = None;
    let mut values = std::env::args().skip(1);
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--weights" => {
                weights = Some(PathBuf::from(
                    values.next().ok_or_else(|| "--weights requires a path".to_owned())?,
                ));
            }
            "--setup-root" => {
                setup_root = Some(PathBuf::from(
                    values.next().ok_or_else(|| "--setup-root requires a path".to_owned())?,
                ));
            }
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    Ok((
        weights.ok_or_else(|| "--weights is required".to_owned())?,
        setup_root.ok_or_else(|| "--setup-root is required".to_owned())?,
    ))
}

fn quantization_digest() -> Result<[u8; 32], String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/quantization-spec.md");
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "quantization file name is not UTF-8".to_owned())?;
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/quantization-file-set/v1");
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn run() -> Result<(), String> {
    let (weights, setup_root) = parse_args()?;
    let installed: [_; 17] = PROFILE_DIRS
        .iter()
        .map(|name| load_c62_campaign_installed_setup(&setup_root.join(name)))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "C6.2 setup profile census differs".to_owned())?;
    let model = load_model(&weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout().map_err(|error| error.to_string())?;
    let verifier_model = Gpt2VerifierModel::from_model(&model)?;
    let quantization = quantization_digest()?;
    let installed_refs = std::array::from_fn(|index| &installed[index]);
    let client_parameters =
        encode_c62_campaign_client_parameters(installed_refs, &verifier_model, quantization)?;
    let setup = build_c62_campaign_setup_manifest(
        installed_refs,
        &verifier_model,
        quantization,
        [0x31; 32],
        [0x32; 32],
        [0x33; 32],
        [0x34; 32],
        [[0x35; 32], [0x36; 32]],
    )?;
    let client_parameter_bytes = u64::try_from(client_parameters.len())
        .map_err(|_| "client-parameter length exceeds u64".to_owned())?;
    let setup_bytes = setup.first_exchange_bytes().map_err(|error| error.to_string())?;
    let setup_plus_certificate_ceiling_bytes = setup_bytes
        .checked_add(C62_CERTIFICATE_STRICT_MAX_BYTES)
        .ok_or_else(|| "setup-plus-certificate length overflows".to_owned())?;
    let pass = client_parameter_bytes <= C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES as u64
        && setup_bytes <= C62_CAMPAIGN_SETUP_MAX_BYTES
        && setup_plus_certificate_ceiling_bytes <= SETUP_PLUS_FIRST_TOLERANCE_BYTES;
    let measurement = Measurement {
        schema: 1,
        profile: "c62-local-setup-bundle-measurement-v1",
        client_parameter_bytes,
        client_parameter_cap_bytes: C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES as u64,
        setup_bytes,
        setup_cap_bytes: C62_CAMPAIGN_SETUP_MAX_BYTES,
        certificate_ceiling_bytes: C62_CERTIFICATE_STRICT_MAX_BYTES,
        setup_plus_certificate_ceiling_bytes,
        setup_plus_first_tolerance_bytes: SETUP_PLUS_FIRST_TOLERANCE_BYTES,
        pass,
        credit: false,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&measurement)
            .map_err(|error| format!("encode measurement: {error}"))?
    );
    if !pass {
        return Err("C6.2 local setup bundle exceeds a terminal byte gate".to_owned());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("c62_setup_bundle_measure FAILED: {error}");
        std::process::exit(1);
    }
}

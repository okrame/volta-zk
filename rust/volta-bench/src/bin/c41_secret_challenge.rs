//! Issue and durably burn the sole verifier-private C41SC1 bridge challenge.

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::error::Error;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use volta_field::{Fp, Fp2, P};
use volta_proto::{C41SecretChallengeRequest, C41SecretChallengeResponse, C41VerifierBundle};

type AnyError = Box<dyn Error + Send + Sync>;

struct Args {
    verifier_bundle: PathBuf,
    request: PathBuf,
    expected_request_blake3: String,
    expected_git_sha: String,
    store: PathBuf,
    response_output: PathBuf,
}

#[derive(Serialize)]
struct Record {
    schema: u32,
    profile: &'static str,
    git_sha: String,
    request_blake3: String,
    response_blake3: String,
    response_bytes: usize,
    response_index: u64,
    store_record: String,
    output: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: c41_secret_challenge --verifier-bundle FILE --request FILE \
         --expected-request-blake3 HEX --expected-git-sha SHA --store DIR \
         --response-output FILE"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut verifier_bundle = None;
    let mut request = None;
    let mut expected_request_blake3 = None;
    let mut expected_git_sha = None;
    let mut store = None;
    let mut response_output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--verifier-bundle" => verifier_bundle = Some(PathBuf::from(value())),
            "--request" => request = Some(PathBuf::from(value())),
            "--expected-request-blake3" => expected_request_blake3 = Some(value()),
            "--expected-git-sha" => expected_git_sha = Some(value()),
            "--store" => store = Some(PathBuf::from(value())),
            "--response-output" => response_output = Some(PathBuf::from(value())),
            _ => usage(),
        }
    }
    let expected_request_blake3 = expected_request_blake3.unwrap_or_else(|| usage());
    let expected_git_sha = expected_git_sha.unwrap_or_else(|| usage());
    if !is_lower_hex(&expected_request_blake3, 64) || !is_lower_hex(&expected_git_sha, 40) {
        usage();
    }
    Args {
        verifier_bundle: verifier_bundle.unwrap_or_else(|| usage()),
        request: request.unwrap_or_else(|| usage()),
        expected_request_blake3,
        expected_git_sha,
        store: store.unwrap_or_else(|| usage()),
        response_output: response_output.unwrap_or_else(|| usage()),
    }
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn require_clean_sha(expected: &str) -> Result<(), AnyError> {
    let sha = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["rev-parse", "HEAD"])
        .output()?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()?;
    if !sha.status.success()
        || !status.status.success()
        || !status.stdout.is_empty()
        || String::from_utf8(sha.stdout)?.trim() != expected
    {
        return Err("C41SC1 challenge issuer requires the clean expected revision".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, AnyError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > cap {
        return Err(format!("{} exceeds its byte cap", path.display()).into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(format!("{} exceeds its byte cap", path.display()).into());
    }
    Ok(bytes)
}

fn random_fp() -> Result<Fp, AnyError> {
    loop {
        let mut bytes = [0u8; 8];
        OsRng.try_fill_bytes(&mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        if value < P {
            return Ok(Fp::new(value));
        }
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), AnyError> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn main() -> Result<(), AnyError> {
    let args = parse_args();
    require_clean_sha(&args.expected_git_sha)?;
    if !args.verifier_bundle.is_absolute()
        || !args.request.is_absolute()
        || !args.store.is_absolute()
        || !args.response_output.is_absolute()
    {
        return Err("C41SC1 issuer paths must be absolute".into());
    }
    let bundle = C41VerifierBundle::decode(&read_bounded(&args.verifier_bundle, 128_000_000)?)?;
    bundle.context.validate_production()?;
    let request_bytes = read_bounded(&args.request, 1_000)?;
    let request_blake3 = blake3::hash(&request_bytes).to_hex().to_string();
    if request_blake3 != args.expected_request_blake3 {
        return Err("C41SC1 request differs from the authenticated transfer".into());
    }
    let request = C41SecretChallengeRequest::decode(&request_bytes)?;
    let expected_context = bundle.context.fiat_shamir_context(request.context.statement_digest)?;
    if request.context != expected_context {
        return Err("C41SC1 request does not match the verifier setup".into());
    }
    let response = C41SecretChallengeResponse::new(request, Fp2::new(random_fp()?, random_fp()?))?;
    let response_bytes = response.encode()?;

    DirBuilder::new().mode(0o700).create(&args.store)?;
    let store_record = args
        .store
        .join(format!("{}.response", blake3::Hash::from(response.request_digest).to_hex()));
    // The durable record is first: any later failure burns the request.
    write_secret(&store_record, &response_bytes)?;
    write_secret(&args.response_output, &response_bytes)?;

    let record = Record {
        schema: 1,
        profile: "C41SC1-private-bridge-challenge-v1",
        git_sha: args.expected_git_sha,
        request_blake3,
        response_blake3: blake3::hash(&response_bytes).to_hex().to_string(),
        response_bytes: response_bytes.len(),
        response_index: request.context.response_index,
        store_record: store_record.display().to_string(),
        output: args.response_output.display().to_string(),
    };
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

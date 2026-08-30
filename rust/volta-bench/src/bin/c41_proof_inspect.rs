//! CPU-only bounded structural reader for a complete C4.1 proof.

use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use volta_pcs::{decode_multi_open_canonical, C3_EMBED, C3_WEIGHTS};
use volta_proto::{
    decode_model_proof_c41_canonical, C41ResponseClosureProof, C41ResponseProofEnvelope,
};

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    proof_bytes: u64,
    proof_blake3: String,
    model_bytes: usize,
    weights_pcs_bytes: usize,
    embed_pcs_bytes: usize,
    closure_bytes: usize,
    degree_close: u8,
    canonical: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args_os().nth(1).ok_or("usage: c41_proof_inspect PROOF")?);
    let proof_bytes = File::open(&path)?.metadata()?.len();
    let envelope = C41ResponseProofEnvelope::decode_reader(File::open(&path)?)?;
    let model = decode_model_proof_c41_canonical(envelope.model())?;
    decode_multi_open_canonical(envelope.weights_pcs(), &C3_WEIGHTS, 96)?;
    decode_multi_open_canonical(envelope.embed_pcs(), &C3_EMBED, 6)?;
    C41ResponseClosureProof::decode(envelope.closure())?;

    let mut hasher = blake3::Hasher::new();
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let report = Report {
        schema: "volta-c41-proof-inspect-v1",
        proof_bytes,
        proof_blake3: hasher.finalize().to_hex().to_string(),
        model_bytes: envelope.model().len(),
        weights_pcs_bytes: envelope.weights_pcs().len(),
        embed_pcs_bytes: envelope.embed_pcs().len(),
        closure_bytes: envelope.closure().len(),
        degree_close: model.c41.as_ref().ok_or("model component is not C4.1")?.close.degree,
        canonical: true,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

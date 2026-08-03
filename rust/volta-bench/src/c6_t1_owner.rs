//! Frozen GPT-2 `100+50` workload owner shared by C6 record and production
//! drivers.
//!
//! Construction performs the canonical forward exactly once and checks the
//! generated decode against the registered golden artifact.  The owner is
//! deliberately not `Clone`: downstream C6 stages borrow or consume this
//! same allocation instead of rebuilding the response under another PCG
//! attempt.

use std::fs;
use std::path::Path;
use std::process::Command;

use volta_gpt2::{
    argmax, band_model_witness, decode_step, forward_model, forward_model_tokens, load_model,
    BandModelWitness, Gpt2Model, KvCache, ModelWitness,
};

pub const C6_T1_PROMPT_TOKENS: usize = 100;
pub const C6_T1_DECODE_TOKENS: usize = 50;

const GOLDEN_HEADER_BYTES: usize = 16;
const GOLDEN_BYTES: usize = GOLDEN_HEADER_BYTES + 4 * C6_T1_DECODE_TOKENS + 8 * C6_T1_DECODE_TOKENS;
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";

/// Same-allocation owner for the frozen witness generator output.
pub struct C6T1WorkloadOwner {
    model: Gpt2Model,
    prefill: ModelWitness,
    decode: BandModelWitness,
    sequence: Vec<u32>,
}

impl C6T1WorkloadOwner {
    pub fn model(&self) -> &Gpt2Model {
        &self.model
    }

    pub fn prefill(&self) -> &ModelWitness {
        &self.prefill
    }

    pub fn decode(&self) -> &BandModelWitness {
        &self.decode
    }

    pub fn sequence(&self) -> &[u32] {
        &self.sequence
    }
}

/// Load, validate and execute the exact frozen T1 witness generator once.
pub fn build_c6_t1_workload_owner(weights: &Path) -> Result<C6T1WorkloadOwner, String> {
    verify_inputs(weights)?;
    let model = load_model(weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout()?;
    let prefill = forward_model(&model, C6_T1_PROMPT_TOKENS);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, C6_T1_PROMPT_TOKENS);
    let mut generated = Vec::with_capacity(C6_T1_DECODE_TOKENS);
    let mut next = argmax(&prefill.logits);
    for position in 0..C6_T1_DECODE_TOKENS {
        generated.push(next);
        next = argmax(&decode_step(&model, &mut cache, next, C6_T1_PROMPT_TOKENS + position));
    }
    let golden = parse_golden_tokens(
        &fs::read(weights.join("golden-p6.bin"))
            .map_err(|error| format!("read golden-p6: {error}"))?,
    )?;
    if generated != golden {
        return Err("C6 T1 decode differs from frozen golden-p6".to_owned());
    }
    let mut sequence = model.p.tokens[..C6_T1_PROMPT_TOKENS].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let decode = band_model_witness(&model, &full, C6_T1_PROMPT_TOKENS);
    if prefill.t != C6_T1_PROMPT_TOKENS
        || decode.t0 != C6_T1_PROMPT_TOKENS
        || decode.q != C6_T1_DECODE_TOKENS
    {
        return Err("C6 T1 witness generator changed its frozen geometry".to_owned());
    }
    Ok(C6T1WorkloadOwner { model, prefill, decode, sequence })
}

fn verify_inputs(weights: &Path) -> Result<(), String> {
    for (name, expected) in [
        ("gpt2s-q.bin", GPT2_BIN_SHA256),
        ("gpt2s-q.json", GPT2_JSON_SHA256),
        ("gpt2s-q.params", GPT2_PARAMS_SHA256),
        ("golden-p6.bin", GOLDEN_P6_SHA256),
    ] {
        let observed = c6_t1_sha256_file(&weights.join(name))?;
        if observed != expected {
            return Err(format!("{name} digest changed: expected {expected}, got {observed}"));
        }
    }
    Ok(())
}

/// Canonical file digest helper shared with the append-only census record.
pub fn c6_t1_sha256_file(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("run sha256sum for {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "sha256sum output is not UTF-8".to_owned())?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn parse_golden_tokens(bytes: &[u8]) -> Result<Vec<u32>, String> {
    if bytes.len() != GOLDEN_BYTES || &bytes[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6 has wrong canonical framing".to_owned());
    }
    let prompt = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let decode = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if (prompt, decode) != (C6_T1_PROMPT_TOKENS, C6_T1_DECODE_TOKENS) {
        return Err("golden-p6 has wrong canonical geometry".to_owned());
    }
    Ok((0..C6_T1_DECODE_TOKENS)
        .map(|index| {
            let offset = GOLDEN_HEADER_BYTES + 4 * index;
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        })
        .collect())
}

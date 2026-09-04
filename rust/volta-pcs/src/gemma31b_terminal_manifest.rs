//! Canonical Gemma-31B D126 terminal manifest compiler.
//!
//! This module compiles the checked-in declaration into 480 logical terminal
//! slots. It does not claim that the model/witness compiler emits those slots.
//! `public_source_keys` records inventory dependencies only: those values are
//! not W/norm contents. Their ordered values and base-GKR use still need a
//! pinned runtime binding.

use std::collections::BTreeSet;

pub const GEMMA31B_WEIGHT_TERMINALS: usize = 472;
pub const GEMMA31B_TERMINALS: usize = 480;
pub const GEMMA31B_LOCAL_MATRIX_SCALARS_PER_LAYER: u64 = 478_937_088;
pub const GEMMA31B_GLOBAL_MATRIX_SCALARS_PER_LAYER: u64 = 533_987_328;
pub const GEMMA31B_EMBEDDING_SCALARS: u64 = 1_409_286_144;
pub const GEMMA31B_LOCAL_NORM_SCALARS_PER_LAYER: u64 = 22_016;
pub const GEMMA31B_GLOBAL_NORM_SCALARS_PER_LAYER: u64 = 22_528;
pub const GEMMA31B_FINAL_NORM_SCALARS: u64 = 5_376;
pub const GEMMA31B_MATRIX_SCALARS: u64 = 30_696_013_824;
pub const GEMMA31B_NORM_SCALARS: u64 = 1_331_456;
pub const GEMMA31B_PRIVATE_WEIGHT_SCALARS: u64 = 30_697_345_280;
pub const GEMMA31B_PACKED_I16_BYTES: u64 = 61_394_690_560;
pub const GEMMA31B_PRIVATE_LEARNED_TENSORS: usize = 772;
pub const GEMMA31B_PUBLIC_LAYER_SCALARS: usize = 60;
pub const GEMMA31B_FORBIDDEN_VISION_BRIDGE_TENSORS: usize = 356;
pub const GEMMA31B_PHYSICAL_TENSORS: usize = 1_188;

pub const GEMMA31B_TERMINAL_MANIFEST_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-terminals-v1.csv");

pub const GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-terminals-v1.blake3");

const HEADER: [&str; 24] = [
    "@schema=volta-c7-d126-gemma31b-terminal-manifest-v1",
    "@model=google/gemma-4-31B",
    "@revision=5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
    "@config_sha256=6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
    "@model_index_sha256=d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2",
    "@model_shard_1_lfs_sha256=186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
    "@model_shard_1_bytes=49784788364",
    "@model_shard_2_lfs_sha256=b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
    "@model_shard_2_bytes=12761549884",
    "@model_shards_total_bytes=62546338248",
    "@tensor_payload_bytes=62546177752",
    "@safetensors_framing_bytes=160496",
    "@text_only=true",
    "@context_cap=4096",
    "@private_learned_tensor_count=772",
    "@public_layer_scalar_count=60",
    "@forbidden_vision_bridge_tensor_count=356",
    "@physical_tensor_count=1188",
    "@weight_matrix_scalars=30696013824",
    "@weight_norm_scalars=1331456",
    "@weight_private_scalars=30697345280",
    "@packed_i16_bytes=61394690560",
    "@terminal_count=480",
    "@record_columns=ordinal|plane|owner|use_axis_length|private_source_keys|public_source_keys",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TerminalPlane {
    Weight,
    /// Protocol plane B; no model-level meaning is assigned here.
    PlaneB,
    KvOld,
    KvNew,
}

impl TerminalPlane {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "W" => Ok(Self::Weight),
            "B" => Ok(Self::PlaneB),
            "KV_OLD" => Ok(Self::KvOld),
            "KV_NEW" => Ok(Self::KvNew),
            _ => Err(format!("unknown terminal plane {value:?}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRecord {
    pub ordinal: u16,
    pub plane: TerminalPlane,
    pub owner: String,
    pub use_axis_length: u8,
    /// Private source tensors owned by this W terminal; empty for B/KV.
    pub private_source_keys: Vec<String>,
    /// Public forward dependencies, not contents of the private W terminal.
    pub public_source_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gemma31BTerminalManifest {
    pub records: Vec<TerminalRecord>,
    pub source_digest: [u8; 32],
}

type ExpectedRecord = (TerminalPlane, String, Vec<String>, Vec<String>);

fn matrix_source_key(layer: usize, role: &str) -> String {
    let suffix = match role {
        "q_proj" => "self_attn.q_proj.weight",
        "k_proj" | "k_eq_v_proj" => "self_attn.k_proj.weight",
        "v_proj" => "self_attn.v_proj.weight",
        "o_proj" => "self_attn.o_proj.weight",
        "gate_proj" => "mlp.gate_proj.weight",
        "up_proj" => "mlp.up_proj.weight",
        "down_proj" => "mlp.down_proj.weight",
        _ => unreachable!("matrix roles are fixed"),
    };
    format!("model.language_model.layers.{layer}.{suffix}")
}

fn expected_records() -> Vec<ExpectedRecord> {
    const LOCAL_ROLES: [&str; 7] =
        ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"];
    const GLOBAL_ROLES: [&str; 6] =
        ["q_proj", "k_eq_v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"];
    const NORM_ROLES: [&str; 6] = [
        "input_layernorm.weight",
        "post_attention_layernorm.weight",
        "post_feedforward_layernorm.weight",
        "pre_feedforward_layernorm.weight",
        "self_attn.k_norm.weight",
        "self_attn.q_norm.weight",
    ];

    let mut records = Vec::with_capacity(GEMMA31B_TERMINALS);
    for layer in 0..60 {
        let roles: &[&str] = if layer % 6 == 5 { &GLOBAL_ROLES } else { &LOCAL_ROLES };
        records.extend(roles.iter().map(|role| {
            (
                TerminalPlane::Weight,
                format!("weight/layer/{layer}/{role}"),
                vec![matrix_source_key(layer, role)],
                vec![],
            )
        }));
        let prefix = format!("model.language_model.layers.{layer}");
        records.push((
            TerminalPlane::Weight,
            format!("weight/layer/{layer}/norm_bundle"),
            NORM_ROLES.iter().map(|role| format!("{prefix}.{role}")).collect(),
            vec![format!("{prefix}.layer_scalar")],
        ));
    }
    records.push((
        TerminalPlane::Weight,
        "weight/tied_embedding".to_owned(),
        vec!["model.language_model.embed_tokens.weight".to_owned()],
        vec![],
    ));
    records.push((
        TerminalPlane::Weight,
        "weight/final_norm".to_owned(),
        vec!["model.language_model.norm.weight".to_owned()],
        vec![],
    ));
    records
        .extend((0..4).map(|index| (TerminalPlane::PlaneB, format!("b/{index}"), vec![], vec![])));
    records.extend(
        (0..2).map(|index| (TerminalPlane::KvOld, format!("kv_old/{index}"), vec![], vec![])),
    );
    records.extend(
        (0..2).map(|index| (TerminalPlane::KvNew, format!("kv_new/{index}"), vec![], vec![])),
    );
    records
}

fn parse_source_keys(field: &str) -> Result<Vec<String>, String> {
    if field == "-" {
        return Ok(vec![]);
    }
    let keys: Vec<_> = field.split(';').map(str::to_owned).collect();
    if keys.iter().any(String::is_empty) {
        return Err("source-key list contains an empty key".to_owned());
    }
    Ok(keys)
}

pub fn compile_gemma31b_terminal_manifest(
    source: &str,
) -> Result<Gemma31BTerminalManifest, String> {
    if !source.ends_with('\n') || source.contains('\r') {
        return Err("manifest must use canonical LF lines and end with LF".to_owned());
    }

    let mut lines = source.split_terminator('\n');
    for expected in HEADER {
        if lines.next() != Some(expected) {
            return Err(format!("manifest header differs at {expected:?}"));
        }
    }

    let expected_records = expected_records();
    if expected_records.len() != GEMMA31B_TERMINALS {
        return Err("internal terminal declaration does not contain 480 records".to_owned());
    }
    let mut records = Vec::with_capacity(GEMMA31B_TERMINALS);
    let mut owners = BTreeSet::new();
    for expected_ordinal in 0..GEMMA31B_TERMINALS {
        let line = lines.next().ok_or_else(|| format!("terminal {expected_ordinal} is missing"))?;
        let fields: Vec<_> = line.split(',').collect();
        if fields.len() != 6 {
            return Err(format!("terminal {expected_ordinal} must have six fields"));
        }
        if fields[0] != expected_ordinal.to_string() {
            return Err(format!("terminal order differs at {expected_ordinal}"));
        }
        let ordinal = fields[0]
            .parse::<u16>()
            .map_err(|_| format!("terminal {expected_ordinal} has an invalid ordinal"))?;
        let plane = TerminalPlane::parse(fields[1])?;
        let (expected_plane, expected_owner, expected_private, expected_public) =
            &expected_records[expected_ordinal];
        if plane != *expected_plane || fields[2] != expected_owner {
            return Err(format!("terminal {expected_ordinal} owner or plane differs"));
        }
        if fields[3] != "1" {
            return Err(format!("terminal {expected_ordinal} use axis is not one"));
        }
        if !owners.insert(fields[2].to_owned()) {
            return Err(format!("terminal owner {:?} is duplicated", fields[2]));
        }
        let private_source_keys = parse_source_keys(fields[4])?;
        let public_source_keys = parse_source_keys(fields[5])?;
        if &private_source_keys != expected_private || &public_source_keys != expected_public {
            return Err(format!("terminal {expected_ordinal} source-key mapping differs"));
        }
        records.push(TerminalRecord {
            ordinal,
            plane,
            owner: fields[2].to_owned(),
            use_axis_length: 1,
            private_source_keys,
            public_source_keys,
        });
    }
    if lines.next().is_some() {
        return Err("manifest has trailing terminal records".to_owned());
    }

    let weight_count =
        records.iter().filter(|record| record.plane == TerminalPlane::Weight).count();
    let plane_b_count =
        records.iter().filter(|record| record.plane == TerminalPlane::PlaneB).count();
    let kv_old_count = records.iter().filter(|record| record.plane == TerminalPlane::KvOld).count();
    let kv_new_count = records.iter().filter(|record| record.plane == TerminalPlane::KvNew).count();
    if (weight_count, plane_b_count, kv_old_count, kv_new_count)
        != (GEMMA31B_WEIGHT_TERMINALS, 4, 2, 2)
    {
        return Err("terminal plane census differs from 472/4/2/2".to_owned());
    }

    let mut private_keys = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for record in &records {
        for key in &record.private_source_keys {
            if !private_keys.insert(key) || public_keys.contains(key) {
                return Err(format!("private source key {key:?} is duplicated or public"));
            }
        }
        for key in &record.public_source_keys {
            if !public_keys.insert(key) || private_keys.contains(key) {
                return Err(format!("public source key {key:?} is duplicated or private"));
            }
        }
    }
    if (private_keys.len(), public_keys.len())
        != (GEMMA31B_PRIVATE_LEARNED_TENSORS, GEMMA31B_PUBLIC_LAYER_SCALARS)
    {
        return Err("source-key census differs from 772 private and 60 public".to_owned());
    }

    Ok(Gemma31BTerminalManifest {
        records,
        source_digest: *blake3::hash(source.as_bytes()).as_bytes(),
    })
}

pub fn declared_gemma31b_terminal_manifest() -> Result<Gemma31BTerminalManifest, String> {
    let manifest = compile_gemma31b_terminal_manifest(GEMMA31B_TERMINAL_MANIFEST_SOURCE)?;
    require_gemma31b_manifest_digest(
        GEMMA31B_TERMINAL_MANIFEST_SOURCE,
        GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX,
    )?;
    Ok(manifest)
}

pub fn require_gemma31b_manifest_digest(source: &str, sidecar: &str) -> Result<[u8; 32], String> {
    let bytes = sidecar.as_bytes();
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || bytes[..64].iter().any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("declared Gemma-31B manifest sidecar is not lowercase hex plus LF".to_owned());
    }
    let actual = blake3::hash(source.as_bytes());
    if actual.to_hex().as_str() != &sidecar[..64] {
        return Err(format!(
            "declared Gemma-31B terminal manifest digest differs: {}",
            actual.to_hex()
        ));
    }
    Ok(*actual.as_bytes())
}

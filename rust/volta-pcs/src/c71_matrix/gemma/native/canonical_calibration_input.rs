use super::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    weight_exponents_by_tensor: BTreeMap<String, i32>,
    activation_exponents_by_source: BTreeMap<usize, i32>,
}

fn profiles(path: &Path) -> Result<Vec<Canonical>, String> {
    let mut body = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(1_048_577)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > 1_048_576 {
        return Err("calibration candidate exceeds 1 MiB".into());
    }
    let candidate: Candidate = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let plan = super::super::super::compile()?;
    if candidate.weight_exponents_by_tensor.len() != plan.sources.len() {
        return Err("calibration W exponent count differs".into());
    }
    let weights = plan
        .sources
        .iter()
        .map(|source| {
            candidate
                .weight_exponents_by_tensor
                .get(&source.name)
                .copied()
                .ok_or("calibration W exponent missing".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    (0..3)
        .map(|slot| Canonical::compile(slot, &weights, &candidate.activation_exponents_by_source))
        .collect()
}

struct Tables {
    gelu: Vec<Vec<i16>>,
    exp30: Vec<Vec<i32>>,
    softcap: Vec<i16>,
    rope: [Vec<Vec<[i32; 2]>>; 2],
    digest: String,
}

impl Tables {
    fn read(path: &Path) -> Result<Self, String> {
        let bytes = 60 * 65535 * 6 + 65535 * 2 + 450 * (128 + 64) * 8;
        let file = File::open(path).map_err(|error| error.to_string())?;
        if file.metadata().map_err(|error| error.to_string())?.len() != bytes as u64 {
            return Err("calibration public table byte length differs".into());
        }
        let mut body = Vec::new();
        file.take(bytes as u64 + 1).read_to_end(&mut body).map_err(|error| error.to_string())?;
        if body.len() != bytes {
            return Err("calibration public tables changed length".into());
        }
        let digest = blake3::hash(&body).to_hex().to_string();
        let mut offset = 0;
        let mut take = |count: usize| {
            let start = offset;
            offset += count;
            &body[start..offset]
        };
        let gelu = (0..60)
            .map(|_| {
                take(65535 * 2)
                    .chunks_exact(2)
                    .map(|word| i16::from_le_bytes(word.try_into().unwrap()))
                    .collect()
            })
            .collect();
        let exp30 = (0..60)
            .map(|_| {
                take(65535 * 4)
                    .chunks_exact(4)
                    .map(|word| i32::from_le_bytes(word.try_into().unwrap()))
                    .collect()
            })
            .collect();
        let softcap = take(65535 * 2)
            .chunks_exact(2)
            .map(|word| i16::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let rope = [128, 64].map(|pairs| {
            (0..450)
                .map(|_| {
                    take(pairs * 8)
                        .chunks_exact(8)
                        .map(|pair| {
                            [
                                i32::from_le_bytes(pair[..4].try_into().unwrap()),
                                i32::from_le_bytes(pair[4..].try_into().unwrap()),
                            ]
                        })
                        .collect()
                })
                .collect()
        });
        Ok(Self { gelu, exp30, softcap, rope, digest })
    }
}

pub fn command(arguments: &[String]) -> Result<serde_json::Value, String> {
    let usage = "usage: c71_calibration describe | recipes CANDIDATE | check-input CANDIDATE TABLES | run CANDIDATE TABLES PACKED PAYLOAD_BYTES";
    let Some(mode) = arguments.first().map(String::as_str) else {
        return Err(usage.into());
    };
    if mode == "describe" && arguments.len() == 1 {
        let plan = super::super::super::compile()?;
        let (sources, output, softmax) = plan.softmax_sources_at(0)?;
        let bytes = &sources.attention.rope.gate_up.gelu.rms.bytes;
        return Ok(serde_json::json!({
            "calibrated": false,
            "weight_sources": plan.sources.iter().enumerate().map(|(id, source)| serde_json::json!({
                "id": id, "name": source.name, "rows": source.rows, "columns": source.cols,
                "packed_offset": source.packed_offset
            })).collect::<Vec<_>>(),
            "activation_sources": profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .iter().map(|&id| serde_json::json!({"id": id, "name": bytes.scalar.layout.sources[id].name})).collect::<Vec<_>>(),
            "fixed_pi_exponents": softmax.layers.iter().map(|layer| (layer.pi, -14)).collect::<BTreeMap<_, _>>()
        }));
    }
    if !((mode == "recipes" && arguments.len() == 2)
        || (mode == "check-input" && arguments.len() == 3)
        || (mode == "run" && arguments.len() == 5))
    {
        return Err(usage.into());
    }
    let profiles = profiles(Path::new(&arguments[1]))?;
    let first = &profiles[0];
    if mode == "recipes" {
        return Ok(serde_json::json!({
            "calibrated": false,
            "recipe_digest": blake3::Hash::from_bytes(first.recipes.digest).to_hex().to_string(),
            "gelu": first.recipes.gelu, "exp30": first.recipes.exp30,
            "softcap": first.recipes.softcap, "rms": first.recipes.rms, "rope_positions": 450,
            "table_bytes": 24_414_870
        }));
    }
    let input = Tables::read(Path::new(&arguments[2]))?;
    let gelu: Vec<_> = input
        .gelu
        .iter()
        .enumerate()
        .map(|(profile, rows)| lookup::Table {
            profile: profile as u8,
            lower: -32767,
            outputs: lookup::Outputs::I16(rows),
        })
        .collect();
    let exp30: Vec<_> = input
        .exp30
        .iter()
        .enumerate()
        .map(|(profile, rows)| lookup::Table {
            profile: profile as u8,
            lower: -32767,
            outputs: lookup::Outputs::I32(rows),
        })
        .collect();
    let softcap =
        lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&input.softcap) };
    let rope: [[kernel::rope::Table<'_>; 2]; 3] = std::array::from_fn(|slot| {
        std::array::from_fn(|family| kernel::rope::Table {
            position: 150 * slot,
            rows: &input.rope[family][150 * slot..150 * (slot + 1)],
        })
    });
    let tables = std::array::from_fn(|slot| profile::Tables {
        gelu: &gelu,
        exp30: &exp30,
        softcap: &softcap,
        rope: &rope[slot],
    });
    let public = super::state::Public::from_profiles(profiles, tables)?;
    if mode == "check-input" {
        return Ok(serde_json::json!({
            "calibrated": false, "complete_integer_trial": false,
            "tables_numerically_certified_by_this_binary": false,
            "public_table_blake3": input.digest,
            "required_rows": public.required,
        }));
    }
    let limit: usize = arguments[4].parse().map_err(|_| "invalid calibration payload budget")?;
    let packed = File::open(&arguments[3]).map_err(|error| error.to_string())?;
    let mut reader = calibration::PackedRows::new(&public.profiles[0].plan.sources, packed)?;
    let responses = calibration::fixed_run(&public, &mut reader, limit)?;
    Ok(serde_json::json!({
        "calibrated": false, "credit": false, "gpu_execution": false,
        "complete_integer_trial": true, "tables_numerically_certified_by_this_binary": false,
        "checkpoint_hash_verified_by_this_binary": false, "public_table_blake3": input.digest,
        "responses": responses, "complete_physical_peak": false
    }))
}

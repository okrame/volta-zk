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

fn pilot_graph(profile: &Canonical) -> Result<serde_json::Value, String> {
    let attention = &profile.sources.attention;
    let gate = &attention.rope.gate_up;
    let norms = &gate.gelu.rms.norms;
    let mut steps = Vec::new();
    let mut produced = BTreeSet::new();
    for producer in &profile.steps {
        let (operation, inputs, output, parameters) = match producer {
            Producer::Rne(_) => continue,
            Producer::Embedding => (
                "embedding",
                vec![],
                Some(0),
                serde_json::json!({
                    "weight": profile.plan.cohorts[0].tensor
                }),
            ),
            Producer::Matrix(index) => {
                let pair = profile
                    .recipes
                    .matrix
                    .iter()
                    .find(|pair| pair.raw == *index)
                    .ok_or("pilot matrix output missing")?;
                (
                    "matrix",
                    vec![profile.bytes().scalar.input_sources[index - 1]],
                    Some(pair.output),
                    serde_json::json!({"weight": profile.plan.cohorts[*index].tensor,
                                   "decision_only": *index == profile.output.raw}),
                )
            }
            Producer::Norm(index) => {
                let norm = &norms[*index];
                (
                    "norm",
                    vec![norm.input],
                    Some(norm.output),
                    serde_json::json!({
                        "heads": norm.heads, "columns": norm.columns,
                        "weight": norm.cohort.map(|index| profile.plan.cohorts[index].tensor)
                    }),
                )
            }
            Producer::Affine(index) => {
                let raw = profile.recipes.affine[*index].raw;
                let operation = profile
                    .sources
                    .operations
                    .iter()
                    .find(|operation| operation.raw == raw)
                    .ok_or("pilot affine route missing")?;
                let inputs = if operation.scale.is_some() {
                    vec![operation.inputs[0]]
                } else {
                    operation.inputs.to_vec()
                };
                (
                    "affine",
                    inputs,
                    Some(operation.output),
                    serde_json::json!({"scale": operation.scale}),
                )
            }
            Producer::Gelu(index) => (
                "gelu",
                vec![gate.gelu.gelu[*index].input],
                Some(gate.gelu.gelu[*index].output),
                serde_json::json!({}),
            ),
            Producer::Gate(index) => (
                "gate",
                vec![gate.gelu.gelu[*index].output, gate.products[*index].up],
                Some(gate.products[*index].output),
                serde_json::json!({}),
            ),
            Producer::Rope(index) => {
                let rotation = &attention.rope.rotations[*index];
                (
                    "rope",
                    vec![norms[rotation.norm].output],
                    Some(rotation.output),
                    serde_json::json!({
                        "family": rotation.family, "heads": rotation.heads, "width": rotation.width
                    }),
                )
            }
            Producer::Qk(index) => {
                let layer = &attention.layers[*index];
                (
                    "qk",
                    vec![layer.q, layer.k],
                    Some(layer.score),
                    serde_json::json!({
                        "groups": layer.groups, "repeats": layer.repeats, "lanes": layer.lanes
                    }),
                )
            }
            Producer::Softmax(index) => (
                "softmax",
                vec![profile.softmax.layers[*index].score],
                Some(profile.softmax.layers[*index].pi),
                serde_json::json!({}),
            ),
            Producer::Pv(index) => {
                let layer = &attention.layers[*index];
                (
                    "pv",
                    vec![layer.pi, layer.v],
                    Some(layer.output),
                    serde_json::json!({
                        "groups": layer.groups, "repeats": layer.repeats, "lanes": layer.lanes
                    }),
                )
            }
            Producer::Softcap => (
                "softcap",
                vec![profile.output.input],
                Some(profile.output.output),
                serde_json::json!({"decision_only": true}),
            ),
            Producer::Argmax => (
                "argmax",
                vec![profile.output.output],
                None,
                serde_json::json!({"decision_only": true}),
            ),
        };
        if inputs.iter().any(|input| !produced.contains(input))
            || output.is_some_and(|output| !produced.insert(output))
        {
            return Err("pilot semantic dependency/ownership differs".into());
        }
        steps.push(serde_json::json!({
            "operation": operation, "inputs": inputs, "output": output, "parameters": parameters
        }));
    }
    if produced
        != profile::Recipes::exponent_sources(&profile.sources, &profile.output, &profile.softmax)
    {
        return Err("pilot does not cover every semantic source".into());
    }
    Ok(serde_json::json!({
        "steps": steps,
        "kv_sources": attention.layers.iter().flat_map(|layer| [layer.k, layer.v]).collect::<BTreeSet<_>>(),
        "decision_first": profile.plan.input_route(profile.output.raw)?.row_offset,
        "decision_count": 50,
        "tokens_per_response": 150,
        "responses": 3,
        "floating_initialization_only": true
    }))
}

fn oracle_plan(profile: &Canonical) -> Result<serde_json::Value, String> {
    let attention = &profile.sources.attention;
    let gate = &attention.rope.gate_up;
    let norms = &gate.gelu.rms.norms;
    let steps = profile
        .steps
        .iter()
        .map(|producer| {
            let (kind, parameters) = match producer {
                Producer::Embedding => (
                    "embedding",
                    serde_json::json!({"weight": profile.plan.cohorts[0].tensor}),
                ),
                Producer::Matrix(index) => {
                    let route = profile.plan.input_route(*index)?;
                    (
                        "matrix",
                        serde_json::json!({
                            "weight": profile.plan.cohorts[*index].tensor,
                            "input_row_offset": route.row_offset,
                            "decision_only": *index == profile.output.raw
                        }),
                    )
                }
                Producer::Norm(index) => {
                    let norm = &norms[*index];
                    (
                        "norm",
                        serde_json::json!({
                            "heads": norm.heads, "columns": norm.columns,
                            "weight": norm.cohort.map(|cohort| profile.plan.cohorts[cohort].tensor),
                            "recipe": profile.recipes.rms[*index]
                        }),
                    )
                }
                Producer::Rne(pair) => {
                    ("rne", serde_json::json!({"shift": pair.shift}))
                }
                Producer::Affine(index) => (
                    "affine",
                    serde_json::json!({
                        "coefficients": profile.recipes.affine[*index].inputs.map(|(_, value)| value)
                    }),
                ),
                Producer::Gelu(index) => (
                    "gelu",
                    serde_json::json!({
                        "table": index, "histogram": gate.gelu.gelu[*index].histogram
                    }),
                ),
                Producer::Gate(_) => ("gate", serde_json::json!({})),
                Producer::Rope(index) => {
                    let rotation = &attention.rope.rotations[*index];
                    (
                        "rope",
                        serde_json::json!({
                            "family": rotation.family, "heads": rotation.heads,
                            "width": rotation.width, "position": attention.rope.old
                        }),
                    )
                }
                Producer::Qk(index) => {
                    let layer = &attention.layers[*index];
                    (
                        "qk",
                        serde_json::json!({
                            "groups": layer.groups, "repeats": layer.repeats,
                            "lanes": layer.lanes
                        }),
                    )
                }
                Producer::Softmax(index) => {
                    let layer = &profile.softmax.layers[*index];
                    (
                        "softmax",
                        serde_json::json!({
                            "table": index, "maximum": layer.maximum,
                            "difference": layer.difference, "exponential": layer.exponential,
                            "denominator": layer.denominator, "probability": layer.pi,
                            "histogram": layer.histogram
                        }),
                    )
                }
                Producer::Pv(index) => {
                    let layer = &attention.layers[*index];
                    (
                        "pv",
                        serde_json::json!({
                            "groups": layer.groups, "repeats": layer.repeats,
                            "lanes": layer.lanes
                        }),
                    )
                }
                Producer::Softcap => (
                    "softcap",
                    serde_json::json!({
                        "table": 0, "lower": profile.output.lower,
                        "histogram": profile.output.histogram
                    }),
                ),
                Producer::Argmax => (
                    "argmax",
                    serde_json::json!({"token_offset": profile.output.token_offset}),
                ),
            };
            let (inputs, outputs) = profile.ports(producer);
            Ok(serde_json::json!({
                "kind": kind, "inputs": inputs, "outputs": outputs,
                "parameters": parameters
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(serde_json::json!({
        "schema": "volta-c71-calibration-oracle-plan-v1",
        "old_tokens": attention.rope.old,
        "recipe_digest": blake3::Hash::from_bytes(profile.recipes.digest).to_hex().to_string(),
        "sources": profile.bytes().scalar.layout.sources.iter().enumerate().map(|(id, source)|
            serde_json::json!({
                "id": id, "name": source.name, "rows": source.rows,
                "columns": source.cols, "codec_bytes": profile.bytes().widths[id]
            })).collect::<Vec<_>>(),
        "weights": profile.plan.sources.iter().enumerate().map(|(id, source)|
            serde_json::json!({
                "id": id, "name": source.name, "rows": source.rows,
                "columns": source.cols, "packed_offset": source.packed_offset
            })).collect::<Vec<_>>(),
        "kv_sources": attention.layers.iter()
            .flat_map(|layer| [layer.k, layer.v]).collect::<BTreeSet<_>>(),
        "steps": steps,
        "decision_first": profile.plan.input_route(profile.output.raw)?.row_offset,
        "decision_count": 50,
        "tokens": 150
    }))
}

pub(super) fn profiles(path: &Path) -> Result<Vec<Canonical>, String> {
    let mut body = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(1_048_577)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > 1_048_576 {
        return Err("calibration candidate exceeds 1 MiB".into());
    }
    profiles_from_bytes(&body)
}

pub(super) fn profiles_from_bytes(body: &[u8]) -> Result<Vec<Canonical>, String> {
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

pub(super) struct Tables {
    gelu: Vec<Vec<i16>>,
    exp30: Vec<Vec<i32>>,
    softcap: Vec<i16>,
    rope: [Vec<Vec<[i32; 2]>>; 2],
    digest: String,
}

impl Tables {
    pub(super) const BYTES: usize = 60 * 65535 * 6 + 65535 * 2 + 450 * (128 + 64) * 8;
    pub(super) fn capacity_bytes(&self) -> usize {
        self.gelu.iter().map(|values| values.capacity() * size_of::<i16>()).sum::<usize>()
            + self.exp30.iter().map(|values| values.capacity() * size_of::<i32>()).sum::<usize>()
            + self.softcap.capacity() * size_of::<i16>()
            + self
                .rope
                .iter()
                .flatten()
                .map(|values| values.capacity() * size_of::<[i32; 2]>())
                .sum::<usize>()
            + (self.gelu.capacity()
                + self.exp30.capacity()
                + self.rope.iter().map(Vec::capacity).sum::<usize>())
                * size_of::<Vec<u8>>()
            + self.digest.capacity()
            + size_of::<Self>()
    }
    #[cfg(test)]
    pub(super) fn shape_fixture() -> Self {
        let mut exp = vec![0; 65535];
        exp[0] = 1 << 30;
        Self {
            gelu: vec![vec![0; 65535]; 60],
            exp30: vec![exp; 60],
            softcap: vec![0; 65535],
            rope: [vec![Vec::new(); 450], vec![Vec::new(); 450]],
            digest: String::new(),
        }
    }
    #[cfg(test)]
    pub(super) fn resident_fixture() -> Self {
        let mut tables = Self::shape_fixture();
        tables.rope = [vec![vec![[1 << 30, 0]; 128]; 450], vec![vec![[1 << 30, 0]; 64]; 450]];
        tables
    }
    pub(super) fn with_slot<T>(
        &self,
        slot: usize,
        use_tables: impl FnOnce(&profile::Tables<'_>) -> T,
    ) -> Result<T, String> {
        if slot >= 3 {
            return Err("table slot outside fixed run".into());
        }
        let gelu: Vec<_> = self
            .gelu
            .iter()
            .enumerate()
            .map(|(i, v)| lookup::Table {
                profile: i as u8,
                lower: -32767,
                outputs: lookup::Outputs::I16(v),
            })
            .collect();
        let exp30: Vec<_> = self
            .exp30
            .iter()
            .enumerate()
            .map(|(i, v)| lookup::Table {
                profile: i as u8,
                lower: -32767,
                outputs: lookup::Outputs::I32(v),
            })
            .collect();
        let softcap = lookup::Table {
            profile: 0,
            lower: -32767,
            outputs: lookup::Outputs::I16(&self.softcap),
        };
        let rope = [0, 1].map(|family| kernel::rope::Table {
            position: slot * 150,
            rows: &self.rope[family][slot * 150..(slot + 1) * 150],
        });
        Ok(use_tables(&profile::Tables {
            gelu: &gelu,
            exp30: &exp30,
            softcap: &softcap,
            rope: &rope,
        }))
    }

    pub(super) fn read(path: &Path) -> Result<Self, String> {
        let bytes = Self::BYTES;
        let file = File::open(path).map_err(|error| error.to_string())?;
        if file.metadata().map_err(|error| error.to_string())?.len() != bytes as u64 {
            return Err("calibration public table byte length differs".into());
        }
        let mut body = Vec::new();
        file.take(bytes as u64 + 1).read_to_end(&mut body).map_err(|error| error.to_string())?;
        if body.len() != bytes {
            return Err("calibration public tables changed length".into());
        }
        Self::from_bytes(&body)
    }

    pub(super) fn from_bytes(body: &[u8]) -> Result<Self, String> {
        if body.len() != Self::BYTES {
            return Err("calibration public table byte length differs".into());
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
    let usage = "usage: c71_calibration describe | profile-matrix PACKED | recipes CANDIDATE | oracle-plan CANDIDATE | check-input CANDIDATE TABLES | ledger CANDIDATE TABLES | run CANDIDATE TABLES PACKED PAYLOAD_BYTES | run-trace CANDIDATE TABLES PACKED PAYLOAD_BYTES TRACE";
    let Some(mode) = arguments.first().map(String::as_str) else {
        return Err(usage.into());
    };
    if (mode == "describe" && arguments.len() == 1)
        || (mode == "profile-matrix" && arguments.len() == 2)
    {
        let plan = super::super::super::compile()?;
        let (sources, output, softmax) = plan.softmax_sources_at(0)?;
        let bytes = &sources.attention.rope.gate_up.gelu.rms.bytes;
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|source| (source, 0))
                .collect();
        for layer in &softmax.layers {
            exponents.insert(layer.pi, -14);
        }
        let pilot = Canonical::compile(0, &[0; 772], &exponents)?;
        if mode == "profile-matrix" {
            // Offline screen for phase planning: actual W, synthetic i16 input.
            // No candidate, tables, causal inference or admission is produced.
            let raw = pilot
                .plan
                .cohorts
                .iter()
                .enumerate()
                .filter(|(_, cohort)| cohort.kind == Kind::Matrix)
                .max_by_key(|(_, cohort)| cohort.inner)
                .map(|(id, _)| id)
                .ok_or("matrix profile has no matrix")?;
            let batch = pilot.matrix_batch(raw, 0, 1)?;
            let reader = std::cell::RefCell::new(calibration::PackedRows::new(
                &pilot.plan.sources,
                File::open(&arguments[1]).map_err(|e| e.to_string())?,
            )?);
            let reads = std::cell::Cell::new(0usize);
            let started = std::time::Instant::now();
            let output = pilot.prepare_matrix_batch(
                raw,
                0,
                1,
                8 << 20,
                |id, row, col| {
                    reads.set(reads.get() + 1);
                    reader.borrow_mut().get(id, row, col)
                },
                |_, _, col| Ok(if col % 2 == 0 { 32767 } else { -32767 }),
            )?;
            let elapsed = started.elapsed().as_secs_f64();
            if output.values.len() != 1
                || output.values[0].2.len() != batch.columns
                || reads.get() != batch.columns * batch.inner
            {
                return Err("matrix profile coverage differs".into());
            }
            std::hint::black_box(&output);
            let input: Vec<i16> =
                (0..batch.inner).map(|col| if col % 2 == 0 { 32767 } else { -32767 }).collect();
            let started = std::time::Instant::now();
            let blocked = reader.borrow_mut().matrix_dot(&batch, &input)?;
            let blocked_elapsed = started.elapsed().as_secs_f64();
            if blocked != output.values[0].2 {
                return Err("blocked integer matrix differs from scalar reference".into());
            }
            return Ok(serde_json::json!({"credit": false, "calibrated": false,
                "profile_only": true, "complete_integer_trial": false,
                "packed_hash_checked": false, "synthetic_input": true,
                "rows": batch.columns, "columns": batch.inner,
                "matrix_scalar_products": reads.get(), "wall_seconds": elapsed,
                "blocked_wall_seconds": blocked_elapsed, "exact_reference_equal": true,
                "matrix_evaluations": 2, "total_matrix_scalar_products": 2 * reads.get(),
                "packed_row_loads": reader.borrow().row_loads,
                "packed_row_bytes": reader.borrow().completed_row_bytes}));
        }
        return Ok(serde_json::json!({
            "calibrated": false,
            "weight_sources": plan.sources.iter().enumerate().map(|(id, source)| serde_json::json!({
                "id": id, "name": source.name, "rows": source.rows, "columns": source.cols,
                "packed_offset": source.packed_offset
            })).collect::<Vec<_>>(),
            "activation_sources": profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .iter().map(|&id| serde_json::json!({"id": id, "name": bytes.scalar.layout.sources[id].name,
                    "columns": bytes.scalar.layout.sources[id].cols})).collect::<Vec<_>>(),
            "fixed_pi_exponents": softmax.layers.iter().map(|layer| (layer.pi, -14)).collect::<BTreeMap<_, _>>(),
            "pilot": pilot_graph(&pilot)?
        }));
    }
    if !((matches!(mode, "recipes" | "oracle-plan") && arguments.len() == 2)
        || (matches!(mode, "check-input" | "ledger") && arguments.len() == 3)
        || (mode == "run" && arguments.len() == 5)
        || (mode == "run-trace" && arguments.len() == 6))
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
    if mode == "oracle-plan" {
        return Ok(serde_json::json!({
            "calibrated": false, "credit": false,
            "independent_numeric_execution_complete": false,
            "contexts": profiles.iter().map(oracle_plan).collect::<Result<Vec<_>, _>>()?
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
    if mode == "ledger" {
        let root = C61Commitment::new(vec![[1; 32]]);
        let mut contexts = Vec::new();
        for (slot, profile) in public.profiles.iter().enumerate() {
            let statement = public.statement(
                slot,
                &root,
                &root,
                &[0; 150],
                AttemptContext {
                    session: [2; 32],
                    capacity: [3; 32],
                    slot: slot as u8,
                    predecessor: if slot == 0 { [0; 32] } else { [4; 32] },
                    nonce: [5; 32],
                },
            );
            let rms = &profile.sources.attention.rope.gate_up.gelu.rms;
            contexts.push(serde_json::json!({
                "old_tokens": slot * 150,
                "required_rows_fp3": public.required[slot],
                "rms": rms.work_census(&statement, &profile.recipes.rms)?
            }));
        }
        return Ok(serde_json::json!({
            "calibrated": false, "credit": false, "complete_work": false,
            "complete_physical_peak": false, "full_model_execution": false,
            "tables_numerically_certified_by_this_binary": false,
            "public_table_blake3": input.digest,
            "recipe_digest": blake3::Hash::from_bytes(public.profiles[0].recipes.digest).to_hex().to_string(),
            "three_attempt_reservation_base_rows": 3 * public.required.iter().sum::<usize>(),
            "reservation_scope": "three responses only; excludes W installation and bootstrap",
            "contexts": contexts
        }));
    }
    let limit: usize = arguments[4].parse().map_err(|_| "invalid calibration payload budget")?;
    let packed = File::open(&arguments[3]).map_err(|error| error.to_string())?;
    let mut reader = calibration::PackedRows::new(&public.profiles[0].plan.sources, packed)?;
    let mut trace = if mode == "run-trace" {
        Some(calibration::Trace::create(Path::new(&arguments[5]))?)
    } else {
        None
    };
    let responses = calibration::fixed_run(&public, &mut reader, limit, trace.as_mut())?;
    let trace = trace.map(calibration::Trace::finish).transpose()?;
    Ok(serde_json::json!({
        "calibrated": false, "credit": false, "gpu_execution": false,
        "complete_integer_trial": true, "tables_numerically_certified_by_this_binary": false,
        "checkpoint_hash_verified_by_this_binary": false, "public_table_blake3": input.digest,
        "responses": responses, "trace": trace,
        "independent_comparison_complete": false, "complete_physical_peak": false
    }))
}

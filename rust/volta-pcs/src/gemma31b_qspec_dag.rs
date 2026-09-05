//! Gemma-31B-only compiler for the compact GemmaQuantV1 operator tensor flow.
//!
//! Tensor-output edges are exact for this declared flow. Named public inputs
//! are metadata, not counted edges. This is not a complete semantic DAG,
//! base-GKR circuit, proof-size result, prover-time result, or hardware credit.

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::gemma31b_terminal_manifest::{declared_gemma31b_terminal_manifest, TerminalPlane};

pub const GEMMA31B_QSPEC_DAG_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-qspec-dag-v1.json");
pub const GEMMA31B_QSPEC_DAG_SHA256_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-qspec-dag-v1.sha256");

const MODEL: &str = "google/gemma-4-31B";
const REVISION: &str = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89";
const CONFIG_SHA256: &str = "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e";
const MANIFEST_SHA256: &str = "1af05e2b8d617e261ee20988618a0d05fe1ea5f9f217f04b28c391815e050687";
const MANIFEST_BLAKE3: &str = "3d4817fb8cefe3832ba9cca44a420e39050f69753c10473b52dbd88ed81d14ba";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CompileError {}

type Result<T> = std::result::Result<T, CompileError>;

fn fail(message: impl Into<String>) -> CompileError {
    CompileError(message.into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Classification {
    kind: String,
    exact_declared_operator_invocation_census: bool,
    node_shapes_dtypes_padding_present: bool,
    complete_semantic_dag: bool,
    dependency_edge_definition: String,
    base_gkr_circuit: bool,
    base_gkr_credit: bool,
    prover_certificate_or_hardware_credit: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    model: String,
    revision: String,
    text_only: bool,
    config_sha256: String,
    source_metadata_sha256: String,
    workload_sha256: String,
    terminal_manifest_sha256: String,
    terminal_manifest_blake3: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialSources {
    dependency_closure: String,
    runtime_repository: String,
    runtime_commit: String,
    files: Vec<(String, String)>,
    corroborating_repository: String,
    corroborating_commit: String,
    corroborating_files: Vec<(String, String)>,
    open_runtime_dependency_closure: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelConfig {
    hidden_size: u64,
    intermediate_size: u64,
    vocab_size: u64,
    layers: u64,
    local_layers: u64,
    global_layers: u64,
    global_layer_rule: String,
    query_heads: u64,
    local_kv_heads: u64,
    global_kv_heads: u64,
    local_head_dim: u64,
    global_head_dim: u64,
    attention_k_eq_v: bool,
    attention_scaling: String,
    attention_bias: bool,
    attention_dropout: String,
    sliding_window: u64,
    rms_epsilon: String,
    hidden_activation: String,
    final_logit_softcap: String,
    tie_word_embeddings: bool,
    embedding_scale_bf16_bits: u16,
    embedding_scale_exact: String,
    context_capacity: u64,
    num_kv_shared_layers: u64,
    hidden_size_per_layer_input: u64,
    enable_moe_block: bool,
    use_double_wide_mlp: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    kind: String,
    first_execution: u64,
    count: u64,
    query_tokens: u64,
    cache_before_first: u64,
    cache_after_first: u64,
    emit_decision: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadSchedule {
    executions: u64,
    phases: Vec<Phase>,
    decisions: u64,
    logits_to_keep_per_decision: u64,
    final_cache_tokens: u64,
    terminal_absorb_skips: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Quantization {
    name: String,
    status: String,
    real_encoding: String,
    integer_dtype: String,
    zero_point: i64,
    integer_min: i64,
    integer_max: i64,
    rounding: String,
    rounding_definition: String,
    overflow: String,
    saturation: String,
    accumulator_dtype: String,
    max_dot_k: u64,
    max_abs_dot: u64,
    goldilocks_modulus: u64,
    max_abs_dot_is_below_modulus_half: bool,
    weight_exponent_rule: String,
    exponent_binding: String,
    weight_exponents_by_tensor: (),
    activation_exponents_by_operation: (),
    nonlinear_tables_by_operation: (),
    calibration_manifest_sha256: (),
    golden_manifest_sha256: (),
    packed_weights_sha256: (),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MathematicalSemantics {
    scope: String,
    rmsnorm_with_scale: String,
    rmsnorm_without_scale: String,
    gelu_pytorch_tanh: String,
    softmax: String,
    attention_mask: String,
    local_rope: String,
    global_rope: String,
    rotate_half: String,
    attention: String,
    embedding_scale: String,
    layer_scalar: String,
    final_tanh_softcap: String,
    selection: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct Operation(String, u64, String, String, String);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactProgram {
    prefix: Vec<Operation>,
    layer: Vec<Operation>,
    decision_suffix: Vec<Operation>,
    record_columns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DagCensus {
    pub executions: u64,
    pub operator_tensor_flow_nodes: u64,
    pub tensor_dependency_edges: u64,
    pub layer_private_matrix_invocations: u64,
    pub total_private_matrix_invocations: u64,
    pub weight_terminal_linked_op_invocations: u64,
    pub fixed_activation_scale_owners: u64,
    pub eager_nonpruned_score_cells: u64,
    pub qk_macs: u64,
    pub pv_macs: u64,
    pub dense_learned_matrix_macs: u64,
    pub norm_weighted_element_equations: u64,
    pub final_norm_weighted_element_equations: u64,
    pub weight_terminal_coverage: u64,
    pub full_attention_prefill_shape: [u64; 2],
    pub output_pruned_algorithm_or_theorem: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    classification: Classification,
    identity: Identity,
    official_sources: OfficialSources,
    model_config: ModelConfig,
    workload_schedule: WorkloadSchedule,
    quantization: Quantization,
    mathematical_semantics: MathematicalSemantics,
    compact_program: CompactProgram,
    expected_census: DagCensus,
    blockers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagNode {
    pub id: u64,
    pub execution: u64,
    pub layer: Option<u64>,
    pub operation: String,
    pub dependencies: Vec<u64>,
    pub weight_terminal: Option<String>,
    pub activation_scale_owner: Option<String>,
    pub public_inputs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledGemma31BDag {
    pub census: DagCensus,
    pub nodes: Vec<DagNode>,
    pub manifest_blake3: [u8; 32],
    pub blockers: Vec<String>,
    pub base_gkr_credit: bool,
}

#[derive(Clone, Copy)]
struct Execution {
    query_tokens: u64,
    cache_after: u64,
    emit_decision: bool,
}

fn operation(name: &str, dependencies: u64, rule: &str, weight: &str, scale: &str) -> Operation {
    Operation(name.into(), dependencies, rule.into(), weight.into(), scale.into())
}

fn expected_prefix() -> Vec<Operation> {
    vec![
        operation(
            "token_input",
            0,
            "root-for-prefill;previous-argmax-after-prefill",
            "none",
            "none",
        ),
        operation("embedding_lookup", 1, "token_input", "tied_embedding", "none"),
        operation("embedding_scale", 1, "embedding_lookup", "none", "global"),
    ]
}

fn expected_layer() -> Vec<Operation> {
    const ROWS: [(&str, u64, &str, &str, &str); 26] = [
        ("input_rms", 1, "layer_input", "norm_bundle", "layer"),
        ("q_proj", 1, "input_rms", "matrix", "layer"),
        ("q_norm", 1, "q_proj", "norm_bundle", "layer"),
        ("q_rope", 1, "q_norm", "none", "layer"),
        ("k_proj", 1, "input_rms", "matrix", "layer"),
        ("k_norm", 1, "k_proj", "norm_bundle", "layer"),
        ("k_rope", 1, "k_norm", "none", "layer"),
        (
            "v_source",
            1,
            "local:input_rms;global:k_proj-alias",
            "matrix-local-only",
            "layer-local-only",
        ),
        ("v_norm", 1, "v_source;parameter-free", "none", "layer"),
        (
            "kv_cache_append",
            2,
            "k_rope+v_norm[+same-layer-prior-execution-kv_cache_append]",
            "none",
            "none",
        ),
        ("qk_matmul", 2, "q_rope+kv_cache_append", "none", "layer"),
        ("attention_mask_add", 1, "qk_matmul;reuse-qk-scale", "none", "none"),
        ("softmax", 1, "attention_mask_add", "none", "layer"),
        ("pv_matmul", 2, "softmax+kv_cache_append", "none", "layer"),
        ("o_proj", 1, "pv_matmul", "matrix", "layer"),
        ("post_attention_rms", 1, "o_proj", "norm_bundle", "layer"),
        ("attention_residual_add", 2, "layer_input+post_attention_rms", "none", "layer"),
        ("pre_ffw_rms", 1, "attention_residual_add", "norm_bundle", "layer"),
        ("gate_proj", 1, "pre_ffw_rms", "matrix", "layer"),
        ("gelu_tanh", 1, "gate_proj", "none", "layer"),
        ("up_proj", 1, "pre_ffw_rms", "matrix", "layer"),
        ("gate_up_mul", 2, "gelu_tanh+up_proj", "none", "layer"),
        ("down_proj", 1, "gate_up_mul", "matrix", "layer"),
        ("post_ffw_rms", 1, "down_proj", "norm_bundle", "layer"),
        ("ffw_residual_add", 2, "attention_residual_add+post_ffw_rms", "none", "layer"),
        ("layer_scalar_mul", 1, "ffw_residual_add;public-layer-scalar", "none", "layer"),
    ];
    ROWS.into_iter()
        .map(|(name, dependencies, rule, weight, scale)| {
            operation(name, dependencies, rule, weight, scale)
        })
        .collect()
}

fn expected_suffix() -> Vec<Operation> {
    vec![
        operation("final_rms", 1, "last-layer-scalar", "final_norm", "global"),
        operation("last_row_select", 1, "final_rms;select the last query row", "none", "none"),
        operation("lm_head", 1, "last_row_select", "tied_embedding", "global"),
        operation("final_tanh_softcap", 1, "lm_head", "none", "global"),
        operation("argmax", 1, "final_tanh_softcap", "none", "none"),
    ]
}

fn validate_sources(sources: &OfficialSources) -> Result<()> {
    let runtime_files = [
        (
            "src/transformers/models/gemma4/configuration_gemma4.py",
            "3eb1d90bffeb0caf9bd51ab5007bac8696e54109a8f43ea8919cdd83319a1401",
        ),
        (
            "src/transformers/models/gemma4/modeling_gemma4.py",
            "6a86e03348df5ec104703e7161de9a911137cba500a0be0f133e2850ef0bf935",
        ),
        (
            "src/transformers/activations.py",
            "b39db15a53d1ce29b99ddbc335b56102d26f65db0b288941cf78cbdd0daa7e67",
        ),
        (
            "src/transformers/modeling_rope_utils.py",
            "d8c3c0696a10e8041f31037116e35289d66c1629b8d134d5ca9629c3ac115c3c",
        ),
        (
            "src/transformers/masking_utils.py",
            "7fd2bf34f3abc87953a500c0d53e3e633e5efba10aebcc4dc11422e5769092dd",
        ),
        (
            "src/transformers/cache_utils.py",
            "7935a009f4131f1c21b53fb731f06813bcbaf8a34fe216cb9e83707aaafcf949",
        ),
    ];
    let actual: Vec<_> =
        sources.files.iter().map(|(path, digest)| (path.as_str(), digest.as_str())).collect();
    let corroborating_files = [
        (
            "gemma/gm/nn/gemma4/_gemma4.py",
            "67cf8c06eed95cbea613e1014f8dd23aade95edf5fb415d875118fe5c1605c4f",
        ),
        (
            "gemma/gm/nn/gemma4/_modules.py",
            "aa422c5904a07e11b9076d91b7648fcd175354dea80c6410c92dc3d67574c17f",
        ),
        (
            "gemma/gm/nn/gemma4/_layers.py",
            "55643c31628bd66e94d72bd035910635a4c5bbf2e5a131ce8fb663ddb28b405c",
        ),
        (
            "gemma/gm/nn/gemma4/_transformer.py",
            "301ae29c9acf9d102f85f63322cf35d96216b16a80334885207c13e7832e3dda",
        ),
        (
            "gemma/gm/nn/gemma4/_config.py",
            "6c72fdb786cc676130a753cac5e49c51fbab0bf785213e84facd64026a8cdc25",
        ),
        (
            "gemma/gm/math/_positional_embeddings.py",
            "6f4814d3554dbb4c67bba794e9fb13a2ae39ea7c77dc4a040527d1536fcb0c92",
        ),
    ];
    let actual_corroborating: Vec<_> = sources
        .corroborating_files
        .iter()
        .map(|(path, digest)| (path.as_str(), digest.as_str()))
        .collect();
    if sources.dependency_closure != "partial"
        || sources.runtime_repository != "https://github.com/huggingface/transformers"
        || sources.runtime_commit != "c1c34249fa27deefbd4a377dfbf883a39baf5c6d"
        || actual != runtime_files
        || sources.corroborating_repository != "https://github.com/google-deepmind/gemma"
        || sources.corroborating_commit != "7b785991bd78626c73b317eb43fdbb6c292f7b9c"
        || actual_corroborating != corroborating_files
        || sources.open_runtime_dependency_closure
            != "transitive helpers and kernels imported by the pinned runtime files"
    {
        return Err(fail("official source binding differs"));
    }
    Ok(())
}

fn validate_config(config: &ModelConfig) -> Result<()> {
    if [
        config.hidden_size,
        config.intermediate_size,
        config.vocab_size,
        config.layers,
        config.local_layers,
        config.global_layers,
        config.query_heads,
        config.local_kv_heads,
        config.global_kv_heads,
        config.local_head_dim,
        config.global_head_dim,
        config.sliding_window,
        config.context_capacity,
    ] != [5_376, 21_504, 262_144, 60, 50, 10, 32, 16, 4, 256, 512, 1_024, 4_096]
        || config.global_layer_rule != "layer-index-mod-6-equals-5"
        || !config.attention_k_eq_v
        || config.attention_scaling != "1"
        || config.attention_bias
        || config.attention_dropout != "0"
        || config.rms_epsilon != "1/1000000"
        || config.hidden_activation != "gelu_pytorch_tanh"
        || config.final_logit_softcap != "30"
        || !config.tie_word_embeddings
        || config.embedding_scale_bf16_bits != 17_043
        || config.embedding_scale_exact != "147/2"
        || config.num_kv_shared_layers != 0
        || config.hidden_size_per_layer_input != 0
        || config.enable_moe_block
        || config.use_double_wide_mlp
    {
        return Err(fail("pinned Gemma-31B text configuration differs"));
    }
    Ok(())
}

fn validate_quantization(quant: &Quantization) -> Result<()> {
    let expected_abs = quant
        .max_dot_k
        .checked_mul((quant.integer_max as u64).pow(2))
        .ok_or_else(|| fail("dot-product bound overflow"))?;
    if quant.name != "GemmaQuantV1"
        || quant.status != "BLOCKED"
        || quant.real_encoding != "real=int*2^e"
        || quant.integer_dtype != "i16"
        || quant.zero_point != 0
        || quant.integer_min != -32_767
        || quant.integer_max != 32_767
        || quant.rounding != "round-to-nearest-ties-to-even"
        || quant.rounding_definition
            != "choose n minimizing abs(x-n); at an exact half choose the even n"
        || quant.overflow != "reject"
        || quant.saturation != "none"
        || quant.accumulator_dtype != "i64"
        || quant.max_dot_k != 21_504
        || quant.max_abs_dot != 23_088_334_918_656
        || quant.max_abs_dot != expected_abs
        || quant.goldilocks_modulus != 18_446_744_069_414_584_321
        || !quant.max_abs_dot_is_below_modulus_half
        || quant.max_abs_dot >= quant.goldilocks_modulus / 2
        || quant.weight_exponent_rule
            != "for each nonzero tensor choose the minimum integer e such that every exact finite BF16 value x maps by RNE(x*2^(-e)) into [-32767,32767]; for an all-zero tensor choose e=0"
        || quant.exponent_binding
            != "all weight and activation exponents are frozen before the proof; calibration may propose activation exponents but no exponent may depend on witness values or vary across the 51 executions"
    {
        return Err(fail("GemmaQuantV1 arithmetic declaration differs"));
    }
    let _required_nulls = (
        quant.weight_exponents_by_tensor,
        quant.activation_exponents_by_operation,
        quant.nonlinear_tables_by_operation,
        quant.calibration_manifest_sha256,
        quant.golden_manifest_sha256,
        quant.packed_weights_sha256,
    );
    Ok(())
}

fn validate_semantics(semantics: &MathematicalSemantics) -> Result<()> {
    let expected = [
        (
            semantics.scope.as_str(),
            "exact-real-reference-before-GemmaQuantV1-table-instantiation",
        ),
        (
            semantics.rmsnorm_with_scale.as_str(),
            "y_i=x_i*w_i*(1/1000000+(sum_j x_j^2)/d)^(-1/2)",
        ),
        (
            semantics.rmsnorm_without_scale.as_str(),
            "y_i=x_i*(1/1000000+(sum_j x_j^2)/d)^(-1/2)",
        ),
        (
            semantics.gelu_pytorch_tanh.as_str(),
            "gelu(x)=x/2*(1+tanh(sqrt(2/pi)*(x+44715/1000000*x^3)))",
        ),
        (
            semantics.softmax.as_str(),
            "softmax(s)_j=exp(s_j-max_allowed(s))/sum_allowed_k exp(s_k-max_allowed(s))",
        ),
        (
            semantics.attention_mask.as_str(),
            "eager materializes every declared rectangular score cell, then adds 0 when k<=q and (full_attention or q-k<1024), otherwise -infinity; excluding forbidden softmax terms is mathematical equivalence only and grants no pruning credit",
        ),
        (
            semantics.local_rope.as_str(),
            "inv[j]=10000^(-2*j/256),0<=j<128; rope(x)=x*cos(pos*inv||pos*inv)+rotate_half(x)*sin(pos*inv||pos*inv)",
        ),
        (
            semantics.global_rope.as_str(),
            "inv[j]=1000000^(-2*j/512),0<=j<64; inv[j]=0,64<=j<256; use the same rope equation",
        ),
        (
            semantics.rotate_half.as_str(),
            "rotate_half(x[0:d/2]||x[d/2:d])=(-x[d/2:d])||x[0:d/2]",
        ),
        (
            semantics.attention.as_str(),
            "scores=Q*K^T with scale 1; output=softmax(mask(scores))*V after KV-head repetition",
        ),
        (
            semantics.embedding_scale.as_str(),
            "embedding[token_id] is multiplied by the exact BF16 dyadic 147/2 (bits 0x4293)",
        ),
        (
            semantics.layer_scalar.as_str(),
            "each layer output is multiplied by that layer's exact public BF16 dyadic from manifests/c7-d126-gemma31b-layer-scalars-v1.csv",
        ),
        (
            semantics.final_tanh_softcap.as_str(),
            "softcap(z)=30*tanh(z/30)",
        ),
        (
            semantics.selection.as_str(),
            "greedy argmax; choose the lowest token id on a tie",
        ),
    ];
    if expected.iter().any(|(actual, expected)| actual != expected) {
        return Err(fail("exact mathematical semantics differ"));
    }
    Ok(())
}

fn expand_schedule(schedule: &WorkloadSchedule) -> Result<Vec<Execution>> {
    let expected = [
        ("prefill-decision", 0, 1, 100, 0, 100, true),
        ("decode-decision", 1, 49, 1, 100, 101, true),
        ("terminal-absorb", 50, 1, 1, 149, 150, false),
    ];
    if schedule.executions != 51
        || schedule.decisions != 50
        || schedule.logits_to_keep_per_decision != 1
        || schedule.final_cache_tokens != 150
        || schedule.phases.len() != expected.len()
        || schedule.terminal_absorb_skips
            != ["final_rms", "last_row_select", "lm_head", "final_tanh_softcap", "argmax"]
    {
        return Err(fail("workload schedule header differs"));
    }
    let mut executions = Vec::with_capacity(51);
    for (phase, expected) in schedule.phases.iter().zip(expected) {
        if (
            phase.kind.as_str(),
            phase.first_execution,
            phase.count,
            phase.query_tokens,
            phase.cache_before_first,
            phase.cache_after_first,
            phase.emit_decision,
        ) != expected
        {
            return Err(fail("workload phase differs"));
        }
        for offset in 0..phase.count {
            if phase.cache_after_first + offset
                != phase.cache_before_first + offset + phase.query_tokens
            {
                return Err(fail("cache transition differs"));
            }
            executions.push(Execution {
                query_tokens: phase.query_tokens,
                cache_after: phase.cache_after_first + offset,
                emit_decision: phase.emit_decision,
            });
        }
    }
    if executions.len() != schedule.executions as usize {
        return Err(fail("expanded execution count differs"));
    }
    Ok(executions)
}

fn weight_terminal(layer: Option<u64>, operation: &str, weight: &str) -> Option<String> {
    if weight == "none" {
        return None;
    }
    let Some(layer) = layer else {
        return match operation {
            "embedding_lookup" | "lm_head" => Some("weight/tied_embedding".into()),
            "final_rms" => Some("weight/final_norm".into()),
            _ => None,
        };
    };
    if matches!(
        operation,
        "input_rms" | "q_norm" | "k_norm" | "post_attention_rms" | "pre_ffw_rms" | "post_ffw_rms"
    ) {
        return Some(format!("weight/layer/{layer}/norm_bundle"));
    }
    let role = match operation {
        "q_proj" | "o_proj" | "gate_proj" | "up_proj" | "down_proj" => operation,
        "k_proj" if layer % 6 == 5 => "k_eq_v_proj",
        "k_proj" => "k_proj",
        "v_source" if layer % 6 != 5 => "v_proj",
        _ => return None,
    };
    Some(format!("weight/layer/{layer}/{role}"))
}

fn scale_owner(layer: Option<u64>, operation: &str, scope: &str) -> Result<Option<String>> {
    match (scope, layer) {
        ("none", _) => Ok(None),
        ("global", None) => Ok(Some(format!("model/{operation}"))),
        ("layer", Some(layer)) => Ok(Some(format!("layer/{layer}/{operation}"))),
        ("layer-local-only", Some(layer)) if layer % 6 != 5 => {
            Ok(Some(format!("layer/{layer}/{operation}")))
        }
        ("layer-local-only", Some(_)) => Ok(None),
        _ => Err(fail("invalid activation scale scope")),
    }
}

fn public_inputs(execution: u64, layer: Option<u64>, operation: &str) -> Vec<String> {
    match (operation, layer) {
        ("token_input", None) if execution == 0 => vec![
            "prompt_token_ids/workload_sha256/70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b"
                .into(),
        ],
        ("embedding_scale", None) => vec!["embedding_scale/bf16/0x4293=147/2".into()],
        ("q_rope" | "k_rope", Some(_)) => vec![format!("position_ids/execution/{execution}")],
        ("attention_mask_add", Some(layer)) => {
            let attention = if layer % 6 == 5 { "full_attention" } else { "sliding_attention" };
            vec![format!("attention_mask/{attention}/execution/{execution}")]
        }
        ("layer_scalar_mul", Some(layer)) => {
            vec![format!("model.language_model.layers.{layer}.layer_scalar")]
        }
        _ => vec![],
    }
}

fn push_node(
    nodes: &mut Vec<DagNode>,
    execution: u64,
    layer: Option<u64>,
    operation: &str,
    dependencies: Vec<u64>,
    weight: &str,
    scale: &str,
) -> Result<u64> {
    let id = nodes.len() as u64;
    if dependencies.iter().any(|dependency| *dependency >= id) {
        return Err(fail("tensor-flow dependency is not topological"));
    }
    nodes.push(DagNode {
        id,
        execution,
        layer,
        operation: operation.into(),
        dependencies,
        weight_terminal: weight_terminal(layer, operation, weight),
        activation_scale_owner: scale_owner(layer, operation, scale)?,
        public_inputs: public_inputs(execution, layer, operation),
    });
    Ok(id)
}

fn expand_dag(manifest: &Manifest, executions: &[Execution]) -> Result<Vec<DagNode>> {
    let mut nodes = Vec::with_capacity(79_963);
    let mut prior_cache = vec![None; manifest.model_config.layers as usize];
    let mut previous_argmax = None;
    for (execution_index, execution) in executions.iter().enumerate() {
        let execution_index = execution_index as u64;
        let token_dependencies = match previous_argmax {
            Some(id) => vec![id],
            None if execution_index == 0 => vec![],
            None => return Err(fail("decode token input lacks the previous argmax")),
        };
        let prefix = &manifest.compact_program.prefix;
        let token = push_node(
            &mut nodes,
            execution_index,
            None,
            &prefix[0].0,
            token_dependencies,
            &prefix[0].3,
            &prefix[0].4,
        )?;
        let embedding = push_node(
            &mut nodes,
            execution_index,
            None,
            &prefix[1].0,
            vec![token],
            &prefix[1].3,
            &prefix[1].4,
        )?;
        let mut layer_input = push_node(
            &mut nodes,
            execution_index,
            None,
            &prefix[2].0,
            vec![embedding],
            &prefix[2].3,
            &prefix[2].4,
        )?;

        for layer in 0..manifest.model_config.layers {
            let mut ids = [0u64; 26];
            for (index, operation) in manifest.compact_program.layer.iter().enumerate() {
                let dependencies = match index {
                    0 => vec![layer_input],
                    1 => vec![ids[0]],
                    2 => vec![ids[1]],
                    3 => vec![ids[2]],
                    4 => vec![ids[0]],
                    5 => vec![ids[4]],
                    6 => vec![ids[5]],
                    7 if layer % 6 == 5 => vec![ids[4]],
                    7 => vec![ids[0]],
                    8 => vec![ids[7]],
                    9 => {
                        let mut dependencies = vec![ids[6], ids[8]];
                        if let Some(prior) = prior_cache[layer as usize] {
                            dependencies.push(prior);
                        }
                        dependencies
                    }
                    10 => vec![ids[3], ids[9]],
                    11 => vec![ids[10]],
                    12 => vec![ids[11]],
                    13 => vec![ids[12], ids[9]],
                    14 => vec![ids[13]],
                    15 => vec![ids[14]],
                    16 => vec![layer_input, ids[15]],
                    17 => vec![ids[16]],
                    18 => vec![ids[17]],
                    19 => vec![ids[18]],
                    20 => vec![ids[17]],
                    21 => vec![ids[19], ids[20]],
                    22 => vec![ids[21]],
                    23 => vec![ids[22]],
                    24 => vec![ids[16], ids[23]],
                    25 => vec![ids[24]],
                    _ => return Err(fail("layer program length differs")),
                };
                let prior_edge = usize::from(index == 9 && execution_index > 0);
                if dependencies.len() != operation.1 as usize + prior_edge {
                    return Err(fail("tensor-flow operation dependency arity differs"));
                }
                ids[index] = push_node(
                    &mut nodes,
                    execution_index,
                    Some(layer),
                    &operation.0,
                    dependencies,
                    &operation.3,
                    &operation.4,
                )?;
            }
            prior_cache[layer as usize] = Some(ids[9]);
            layer_input = ids[25];
        }

        if execution.emit_decision {
            let suffix = &manifest.compact_program.decision_suffix;
            let final_rms = push_node(
                &mut nodes,
                execution_index,
                None,
                &suffix[0].0,
                vec![layer_input],
                &suffix[0].3,
                &suffix[0].4,
            )?;
            let last_row = push_node(
                &mut nodes,
                execution_index,
                None,
                &suffix[1].0,
                vec![final_rms],
                &suffix[1].3,
                &suffix[1].4,
            )?;
            let lm_head = push_node(
                &mut nodes,
                execution_index,
                None,
                &suffix[2].0,
                vec![last_row],
                &suffix[2].3,
                &suffix[2].4,
            )?;
            let softcap = push_node(
                &mut nodes,
                execution_index,
                None,
                &suffix[3].0,
                vec![lm_head],
                &suffix[3].3,
                &suffix[3].4,
            )?;
            previous_argmax = Some(push_node(
                &mut nodes,
                execution_index,
                None,
                &suffix[4].0,
                vec![softcap],
                &suffix[4].3,
                &suffix[4].4,
            )?);
        }
    }
    if nodes.len() != 79_963
        || nodes.iter().map(|node| node.dependencies.len()).sum::<usize>() != 101_322
    {
        return Err(fail("expanded tensor-flow node or edge census differs"));
    }
    Ok(nodes)
}

fn compile_census(
    manifest: &Manifest,
    executions: &[Execution],
    nodes: &[DagNode],
) -> Result<DagCensus> {
    let config = &manifest.model_config;
    let decisions = executions.iter().filter(|row| row.emit_decision).count() as u64;
    let layer_matrix_invocations = nodes
        .iter()
        .filter(|node| {
            node.layer.is_some()
                && node.weight_terminal.is_some()
                && matches!(
                    node.operation.as_str(),
                    "q_proj"
                        | "k_proj"
                        | "v_source"
                        | "o_proj"
                        | "gate_proj"
                        | "up_proj"
                        | "down_proj"
                )
        })
        .count() as u64;
    let total_matrix_invocations = layer_matrix_invocations
        + nodes.iter().filter(|node| node.operation == "lm_head").count() as u64;
    let w_linked = nodes.iter().filter(|node| node.weight_terminal.is_some()).count() as u64;
    let scale_owners: BTreeSet<_> =
        nodes.iter().filter_map(|node| node.activation_scale_owner.as_deref()).collect();
    let terminal_coverage: BTreeSet<_> =
        nodes.iter().filter_map(|node| node.weight_terminal.as_deref()).collect();
    let terminal_manifest = declared_gemma31b_terminal_manifest().map_err(|error| fail(error))?;
    let canonical_weight_owners: BTreeSet<_> = terminal_manifest
        .records
        .iter()
        .filter(|record| record.plane == TerminalPlane::Weight)
        .map(|record| record.owner.as_str())
        .collect();
    if terminal_coverage != canonical_weight_owners {
        return Err(fail("compiled W-terminal owners differ from the canonical terminal manifest"));
    }

    let head_dim_total =
        config.local_layers * config.local_head_dim + config.global_layers * config.global_head_dim;
    let mut score_cells = 0u64;
    let mut qk_macs = 0u64;
    for execution in executions {
        let cells_per_layer = config.query_heads * execution.query_tokens * execution.cache_after;
        score_cells += config.layers * cells_per_layer;
        qk_macs += cells_per_layer * head_dim_total;
    }
    let token_rows: u64 = executions.iter().map(|row| row.query_tokens).sum();
    let local_norm_elements = 4 * config.hidden_size
        + config.local_kv_heads * config.local_head_dim
        + config.query_heads * config.local_head_dim;
    let global_norm_elements = 4 * config.hidden_size
        + config.global_kv_heads * config.global_head_dim
        + config.query_heads * config.global_head_dim;
    let norm_equations = token_rows
        * (config.local_layers * local_norm_elements + config.global_layers * global_norm_elements);
    let final_norm_rows: u64 =
        executions.iter().filter(|row| row.emit_decision).map(|row| row.query_tokens).sum();
    let layer_matrix_scalars = 50 * 478_937_088u64 + 10 * 533_987_328u64;
    let dense_macs = token_rows * layer_matrix_scalars + decisions * 1_409_286_144;

    Ok(DagCensus {
        executions: executions.len() as u64,
        operator_tensor_flow_nodes: nodes.len() as u64,
        tensor_dependency_edges: nodes.iter().map(|node| node.dependencies.len() as u64).sum(),
        layer_private_matrix_invocations: layer_matrix_invocations,
        total_private_matrix_invocations: total_matrix_invocations,
        weight_terminal_linked_op_invocations: w_linked,
        fixed_activation_scale_owners: scale_owners.len() as u64,
        eager_nonpruned_score_cells: score_cells,
        qk_macs,
        pv_macs: qk_macs,
        dense_learned_matrix_macs: dense_macs,
        norm_weighted_element_equations: norm_equations,
        final_norm_weighted_element_equations: final_norm_rows * config.hidden_size,
        weight_terminal_coverage: terminal_coverage.len() as u64,
        full_attention_prefill_shape: [100, 100],
        output_pruned_algorithm_or_theorem: false,
    })
}

pub fn compile_gemma31b_qspec_dag(source: &str) -> Result<CompiledGemma31BDag> {
    let manifest: Manifest =
        serde_json::from_str(source).map_err(|error| fail(error.to_string()))?;
    if manifest.schema != "volta-c7-d126-gemma31b-qspec-dag-v1"
        || manifest.classification.kind != "operator-tensor-flow-dag"
        || !manifest.classification.exact_declared_operator_invocation_census
        || manifest.classification.node_shapes_dtypes_padding_present
        || manifest.classification.complete_semantic_dag
        || manifest.classification.dependency_edge_definition
            != "tensor-output dependencies only; named public_inputs are excluded"
        || manifest.classification.base_gkr_circuit
        || manifest.classification.base_gkr_credit
        || manifest.classification.prover_certificate_or_hardware_credit
        || manifest.identity.model != MODEL
        || manifest.identity.revision != REVISION
        || !manifest.identity.text_only
        || manifest.identity.config_sha256 != CONFIG_SHA256
        || manifest.identity.source_metadata_sha256
            != "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
        || manifest.identity.workload_sha256
            != "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b"
        || manifest.identity.terminal_manifest_sha256
            != "a9f4bc9db356c4f40c8f34d1af11367329532ffea53796dfbe2877177c6a9dfa"
        || manifest.identity.terminal_manifest_blake3
            != "c90c41afaaac0c8da4a3c6e4781cd95dab026477999d6e20f565580db82bda25"
    {
        return Err(fail("manifest identity or classification differs"));
    }
    validate_sources(&manifest.official_sources)?;
    validate_config(&manifest.model_config)?;
    validate_quantization(&manifest.quantization)?;
    validate_semantics(&manifest.mathematical_semantics)?;

    let prefix = expected_prefix();
    let layer = expected_layer();
    let suffix = expected_suffix();
    if manifest.compact_program.prefix != prefix
        || manifest.compact_program.layer != layer
        || manifest.compact_program.decision_suffix != suffix
        || manifest.compact_program.record_columns
            != [
                "operation",
                "base_dependencies",
                "dependency_rule",
                "weight_link",
                "activation_scale_scope",
            ]
    {
        return Err(fail("compact operator tensor-flow program differs"));
    }
    let executions = expand_schedule(&manifest.workload_schedule)?;
    let nodes = expand_dag(&manifest, &executions)?;
    let census = compile_census(&manifest, &executions, &nodes)?;
    if census != manifest.expected_census {
        return Err(fail("compiled and declared tensor-flow censuses differ"));
    }
    let expected_blockers = [
        "weight_exponents_by_tensor: require exactly 772 canonical private tensor keys with integer exponents",
        "activation_exponents_by_operation: require exactly 1434 fixed owner keys with integer exponents",
        "nonlinear_tables_by_operation: require canonical RMS/GELU/softmax/RoPE/final-tanh table map and digests",
        "runtime_weights: require both pinned shards and the exact packed i16 digest",
        "decode_ids_and_goldens: require 50 generated token ids and Python-Rust bit equality",
        "integer_lowering: require exact requantization points, operand exponent alignment, finite attention-mask sentinel and an accumulator bound for every operation kind",
        "base_gkr_lowering: require exact rows, wires and a matching Lean relation",
    ];
    if manifest.blockers != expected_blockers {
        return Err(fail("explicit blocker registry differs"));
    }
    Ok(CompiledGemma31BDag {
        census,
        nodes,
        manifest_blake3: *blake3::hash(source.as_bytes()).as_bytes(),
        blockers: manifest.blockers,
        base_gkr_credit: false,
    })
}

pub fn declared_gemma31b_qspec_dag() -> Result<CompiledGemma31BDag> {
    let expected = format!("{MANIFEST_SHA256}  c7-d126-gemma31b-qspec-dag-v1.json\n");
    if GEMMA31B_QSPEC_DAG_SHA256_SIDECAR != expected {
        return Err(fail("declared QSPEC/DAG SHA-256 sidecar differs"));
    }
    if blake3::hash(GEMMA31B_QSPEC_DAG_SOURCE.as_bytes()).to_hex().as_str() != MANIFEST_BLAKE3 {
        return Err(fail("declared QSPEC/DAG source bytes differ"));
    }
    compile_gemma31b_qspec_dag(GEMMA31B_QSPEC_DAG_SOURCE)
}

use volta_pcs::gemma31b_qspec_dag::{
    compile_gemma31b_qspec_dag, declared_gemma31b_qspec_dag, GEMMA31B_QSPEC_DAG_SOURCE,
};

#[test]
fn expands_exact_gemma31b_operator_tensor_flow_without_gkr_credit() {
    let compiled = declared_gemma31b_qspec_dag().unwrap();
    assert_eq!(
        compiled.manifest_blake3,
        *blake3::hash(GEMMA31B_QSPEC_DAG_SOURCE.as_bytes()).as_bytes()
    );
    let census = &compiled.census;
    assert_eq!(census.executions, 51);
    assert_eq!(census.operator_tensor_flow_nodes, 79_963);
    assert_eq!(census.tensor_dependency_edges, 101_322);
    assert_eq!(census.layer_private_matrix_invocations, 20_910);
    assert_eq!(census.total_private_matrix_invocations, 20_960);
    assert_eq!(census.weight_terminal_linked_op_invocations, 39_421);
    assert_eq!(census.fixed_activation_scale_owners, 1_434);
    assert_eq!(census.eager_nonpruned_score_cells, 31_248_000);
    assert_eq!(census.qk_macs, 9_332_736_000);
    assert_eq!(census.pv_macs, 9_332_736_000);
    assert_eq!(census.dense_learned_matrix_macs, 4_463_473_459_200);
    assert_eq!(census.norm_weighted_element_equations, 313_344_000);
    assert_eq!(census.final_norm_weighted_element_equations, 801_024);
    assert_eq!(census.weight_terminal_coverage, 472);
    assert_eq!(census.full_attention_prefill_shape, [100, 100]);
    assert!(!census.output_pruned_algorithm_or_theorem);
    assert!(!compiled.base_gkr_credit);
    assert_eq!(compiled.blockers.len(), 7);
    assert_eq!(compiled.nodes.len(), 79_963);
    assert!(compiled
        .nodes
        .iter()
        .all(|node| node.dependencies.iter().all(|dependency| *dependency < node.id)));

    let mut token_inputs = [None; 51];
    let mut argmax = [None; 50];
    let mut caches = vec![vec![None; 60]; 51];
    let mut local_v = None;
    let mut global_v = None;
    let mut global_k = None;
    let mut last_row = None;
    let mut prefill_final_rms = None;
    let mut prefill_lm_head = None;
    let mut embedding_scale = None;
    let mut local_q_rope = None;
    let mut local_mask = None;
    let mut global_mask = None;
    let mut local_layer_scalar = None;
    for node in &compiled.nodes {
        match (node.operation.as_str(), node.execution, node.layer) {
            ("token_input", execution, None) => token_inputs[execution as usize] = Some(node),
            ("argmax", execution, None) => argmax[execution as usize] = Some(node),
            ("kv_cache_append", execution, Some(layer)) => {
                caches[execution as usize][layer as usize] = Some(node)
            }
            ("v_source", 0, Some(4)) => local_v = Some(node),
            ("v_source", 0, Some(5)) => global_v = Some(node),
            ("k_proj", 0, Some(5)) => global_k = Some(node),
            ("last_row_select", 0, None) => last_row = Some(node),
            ("final_rms", 0, None) => prefill_final_rms = Some(node),
            ("lm_head", 0, None) => prefill_lm_head = Some(node),
            ("embedding_scale", 0, None) => embedding_scale = Some(node),
            ("q_rope", 0, Some(4)) => local_q_rope = Some(node),
            ("attention_mask_add", 0, Some(4)) => local_mask = Some(node),
            ("attention_mask_add", 0, Some(5)) => global_mask = Some(node),
            ("layer_scalar_mul", 0, Some(4)) => local_layer_scalar = Some(node),
            _ => {}
        }
    }
    assert!(token_inputs[0].unwrap().dependencies.is_empty());
    assert_eq!(
        token_inputs[0].unwrap().public_inputs,
        ["prompt_token_ids/workload_sha256/70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b"]
    );
    for execution in 1..51 {
        assert_eq!(
            token_inputs[execution].unwrap().dependencies,
            [argmax[execution - 1].unwrap().id]
        );
    }
    for layer in 0..60 {
        assert_eq!(caches[0][layer].unwrap().dependencies.len(), 2);
        for execution in 1..51 {
            assert_eq!(
                caches[execution][layer].unwrap().dependencies.last(),
                Some(&caches[execution - 1][layer].unwrap().id)
            );
        }
    }
    let local_v = local_v.unwrap();
    assert_eq!(local_v.weight_terminal.as_deref(), Some("weight/layer/4/v_proj"));
    assert_eq!(local_v.activation_scale_owner.as_deref(), Some("layer/4/v_source"));
    let global_v = global_v.unwrap();
    assert_eq!(global_v.dependencies, [global_k.unwrap().id]);
    assert!(global_v.weight_terminal.is_none());
    assert!(global_v.activation_scale_owner.is_none());

    let last_row = last_row.unwrap();
    assert_eq!(last_row.dependencies, [prefill_final_rms.unwrap().id]);
    assert_eq!(prefill_lm_head.unwrap().dependencies, [last_row.id]);
    assert_eq!(embedding_scale.unwrap().public_inputs, ["embedding_scale/bf16/0x4293=147/2"]);
    assert_eq!(local_q_rope.unwrap().public_inputs, ["position_ids/execution/0"]);
    assert_eq!(local_mask.unwrap().public_inputs, ["attention_mask/sliding_attention/execution/0"]);
    assert_eq!(global_mask.unwrap().public_inputs, ["attention_mask/full_attention/execution/0"]);
    assert_eq!(
        local_layer_scalar.unwrap().public_inputs,
        ["model.language_model.layers.4.layer_scalar"]
    );
}

#[test]
fn rejects_quantization_or_pruning_drift() {
    let wrong_rounding = GEMMA31B_QSPEC_DAG_SOURCE.replacen(
        "round-to-nearest-ties-to-even",
        "round-half-away-from-zero",
        1,
    );
    assert!(compile_gemma31b_qspec_dag(&wrong_rounding).is_err());

    let pruned = GEMMA31B_QSPEC_DAG_SOURCE.replacen(
        "eager materializes every declared rectangular score cell",
        "skip masked score cells",
        1,
    );
    assert!(compile_gemma31b_qspec_dag(&pruned).is_err());

    for (from, to) in [
        ("\"text_only\": true", "\"text_only\": false"),
        ("\"attention_bias\": false", "\"attention_bias\": true"),
        (
            "choose n minimizing abs(x-n); at an exact half choose the even n",
            "nearest",
        ),
        ("\"logits_to_keep_per_decision\": 1", "\"logits_to_keep_per_decision\": 0"),
        (
            "\"operation\", \"base_dependencies\"",
            "\"operation\", \"wrong_dependencies\"",
        ),
        (
            "integer_lowering: require exact requantization points, operand exponent alignment, finite attention-mask sentinel and an accumulator bound for every operation kind",
            "integer_lowering: incomplete",
        ),
    ] {
        assert!(compile_gemma31b_qspec_dag(&GEMMA31B_QSPEC_DAG_SOURCE.replacen(from, to, 1)).is_err());
    }
}

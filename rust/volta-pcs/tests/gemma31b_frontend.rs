use std::collections::BTreeSet;

use volta_pcs::c7_gemma_frontend::{
    compile_pinned_gemma31b_frontend, FrontendStatus, WeightRelationKind, LAYER_SCALAR_SOURCE,
    SOURCE_METADATA_SOURCE, WORKLOAD_SOURCE,
};

#[test]
fn pinned_frontend_compiles_exact_metadata_and_stays_blocked() {
    let compiled = compile_pinned_gemma31b_frontend().unwrap();

    assert_eq!(compiled.status, FrontendStatus::Blocked);
    assert!(!compiled.admission_credit);
    assert_eq!(compiled.weight_relations.len(), 472);
    assert_eq!(
        compiled
            .weight_relations
            .iter()
            .filter(|row| row.kind == WeightRelationKind::Matrix)
            .count(),
        410
    );
    assert_eq!(
        compiled
            .weight_relations
            .iter()
            .filter(|row| row.kind == WeightRelationKind::RaggedNormBundle)
            .count(),
        60
    );
    assert_eq!(compiled.weight_relations.iter().flat_map(|row| &row.private_sources).count(), 772);
    assert!(compiled.weight_relations.iter().all(|row| !row.runtime_value_bound));
    assert_eq!(compiled.public_layer_scalars.len(), 60);
    assert_eq!(compiled.public_layer_scalars.first().unwrap().bf16_bits, 15_814);
    assert_eq!(compiled.public_layer_scalars.last().unwrap().bf16_bits, 15_651);
    assert_eq!(
        compiled
            .weight_relations
            .iter()
            .flat_map(|row| &row.private_sources)
            .map(|source| source.nbytes)
            .sum::<u64>(),
        61_394_690_560
    );
    assert!(
        compiled
            .public_layer_scalars
            .iter()
            .map(|row| row.bf16_bits)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
    );

    let global_norm = compiled
        .weight_relations
        .iter()
        .find(|row| row.owner == "weight/layer/5/norm_bundle")
        .unwrap();
    assert!(global_norm
        .private_sources
        .iter()
        .any(|source| source.name.ends_with("self_attn.k_norm.weight") && source.shape == [512]));

    assert_eq!(compiled.bkv_layouts.rows_emitted, 0);
    assert!(!compiled.bkv_layouts.credit);
    assert!(compiled.bkv_layouts.contract.required_fields.contains(&"q_by_round"));
    assert!(compiled.bkv_layouts.contract.required_fields.contains(&"H_by_round"));
    assert_eq!(compiled.base_gkr_cohorts.rows_emitted, 0);
    assert!(!compiled.base_gkr_cohorts.credit);
    assert!(compiled.base_gkr_cohorts.contract.required_fields.contains(&"K"));
    assert!(compiled.base_gkr_cohorts.contract.required_fields.contains(&"sum_d"));
    assert!(compiled.base_gkr_cohorts.contract.required_fields.contains(&"hfin_relation_id"));
    assert_eq!(compiled.blockers.len(), 6);
}

#[test]
fn workload_separates_live_tokens_from_kv_capacity() {
    let compiled = compile_pinned_gemma31b_frontend().unwrap();

    assert_eq!(compiled.workload.prompt_tokens, 100);
    assert_eq!(compiled.workload.response_tokens, 50);
    assert_eq!(compiled.workload.live_tokens, 150);
    assert_eq!(compiled.workload.context_capacity, 4_096);
    assert!(compiled.workload.prompt_token_ids_bound);
    assert!(!compiled.workload.decode_token_ids_bound);
    assert!(!compiled.workload.quantization_bound);
    assert_eq!(compiled.kv_capacity.values_per_token, 450_560);
    assert_eq!(compiled.kv_capacity.live_len, 150);
    assert_eq!(compiled.kv_capacity.capacity, 4_096);
    assert_eq!(compiled.kv_capacity.live_bytes, 135_168_000);
    assert_eq!(compiled.kv_capacity.capacity_bytes, 3_690_987_520);
    assert_eq!(compiled.kv_capacity.persistent_padding_bytes, 0);
}

#[test]
fn checked_in_artifact_drift_is_not_silently_accepted() {
    assert!(!SOURCE_METADATA_SOURCE.contains("\"runtime_tensor_use\": true"));
    assert!(!LAYER_SCALAR_SOURCE.contains(",16256,0x1.0000000000000p+0\n"));
    assert!(WORKLOAD_SOURCE.contains("\"decode_token_ids\": false"));

    let compiled = compile_pinned_gemma31b_frontend().unwrap();
    assert!(compiled.blockers.iter().any(|row| row.code == "gemma_quant_v1"));
    assert!(compiled.blockers.iter().any(|row| row.code == "decode_token_ids"));
    assert!(compiled.blockers.iter().any(|row| row.code == "real_bkv_layouts"));
    assert!(compiled.blockers.iter().any(|row| row.code == "base_gkr_rows"));
}

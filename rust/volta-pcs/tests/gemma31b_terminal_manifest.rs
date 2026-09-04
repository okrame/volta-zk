#[path = "../src/gemma31b_terminal_manifest.rs"]
mod manifest;

use std::collections::BTreeSet;

use manifest::{
    compile_gemma31b_terminal_manifest, declared_gemma31b_terminal_manifest,
    require_gemma31b_manifest_digest, TerminalPlane, GEMMA31B_EMBEDDING_SCALARS,
    GEMMA31B_FINAL_NORM_SCALARS, GEMMA31B_FORBIDDEN_VISION_BRIDGE_TENSORS,
    GEMMA31B_GLOBAL_MATRIX_SCALARS_PER_LAYER, GEMMA31B_GLOBAL_NORM_SCALARS_PER_LAYER,
    GEMMA31B_LOCAL_MATRIX_SCALARS_PER_LAYER, GEMMA31B_LOCAL_NORM_SCALARS_PER_LAYER,
    GEMMA31B_MATRIX_SCALARS, GEMMA31B_NORM_SCALARS, GEMMA31B_PACKED_I16_BYTES,
    GEMMA31B_PHYSICAL_TENSORS, GEMMA31B_PRIVATE_LEARNED_TENSORS, GEMMA31B_PRIVATE_WEIGHT_SCALARS,
    GEMMA31B_PUBLIC_LAYER_SCALARS, GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX,
    GEMMA31B_TERMINAL_MANIFEST_SOURCE,
};

#[test]
fn declared_manifest_is_exact_canonical_and_single_use() {
    let manifest = declared_gemma31b_terminal_manifest().unwrap();
    assert_eq!(manifest.records.len(), 480);
    assert_eq!(manifest.records.first().unwrap().owner, "weight/layer/0/q_proj");
    assert_eq!(manifest.records[39].owner, "weight/layer/4/norm_bundle");
    assert_eq!(manifest.records[40].owner, "weight/layer/5/q_proj");
    assert_eq!(manifest.records[41].owner, "weight/layer/5/k_eq_v_proj");
    assert_eq!(manifest.records[46].owner, "weight/layer/5/norm_bundle");
    assert_eq!(manifest.records[47].owner, "weight/layer/6/q_proj");
    assert_eq!(manifest.records[469].owner, "weight/layer/59/norm_bundle");
    assert_eq!(manifest.records[470].owner, "weight/tied_embedding");
    assert_eq!(manifest.records[471].owner, "weight/final_norm");
    assert_eq!(manifest.records[472].owner, "b/0");
    assert_eq!(manifest.records[476].owner, "kv_old/0");
    assert_eq!(manifest.records[478].owner, "kv_new/0");
    assert_eq!(
        manifest.records[0].private_source_keys,
        ["model.language_model.layers.0.self_attn.q_proj.weight"]
    );
    assert_eq!(manifest.records[7].private_source_keys.len(), 6);
    assert_eq!(
        manifest.records[7].public_source_keys,
        ["model.language_model.layers.0.layer_scalar"]
    );
    assert_eq!(
        manifest.records[41].private_source_keys,
        ["model.language_model.layers.5.self_attn.k_proj.weight"]
    );
    assert!(manifest.records[472..].iter().all(
        |record| record.private_source_keys.is_empty() && record.public_source_keys.is_empty()
    ));
    assert!(manifest.records.iter().all(|record| record.use_axis_length == 1));
    assert!(manifest
        .records
        .iter()
        .enumerate()
        .all(|(ordinal, record)| usize::from(record.ordinal) == ordinal));
    assert_eq!(
        manifest.records.iter().map(|record| &record.owner).collect::<BTreeSet<_>>().len(),
        480
    );
    assert_eq!(
        manifest.records.iter().filter(|record| record.plane == TerminalPlane::Weight).count(),
        472
    );
    assert_eq!(
        manifest.records.iter().filter(|record| record.plane == TerminalPlane::PlaneB).count(),
        4
    );
    assert_eq!(
        manifest.records.iter().filter(|record| record.plane == TerminalPlane::KvOld).count(),
        2
    );
    assert_eq!(
        manifest.records.iter().filter(|record| record.plane == TerminalPlane::KvNew).count(),
        2
    );
    assert_eq!(
        blake3::hash(GEMMA31B_TERMINAL_MANIFEST_SOURCE.as_bytes()).to_hex().as_str(),
        GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX.trim_end()
    );
    assert_eq!(
        manifest
            .records
            .iter()
            .flat_map(|record| &record.private_source_keys)
            .collect::<BTreeSet<_>>()
            .len(),
        772
    );
    assert_eq!(
        manifest
            .records
            .iter()
            .flat_map(|record| &record.public_source_keys)
            .collect::<BTreeSet<_>>()
            .len(),
        60
    );
}

#[test]
fn any_order_owner_axis_or_header_drift_rejects() {
    let source = GEMMA31B_TERMINAL_MANIFEST_SOURCE;
    let first =
        "0,W,weight/layer/0/q_proj,1,model.language_model.layers.0.self_attn.q_proj.weight,-";
    let second =
        "1,W,weight/layer/0/k_proj,1,model.language_model.layers.0.self_attn.k_proj.weight,-";

    let mutations = [
        source.replacen(
            first,
            "0,W,weight/layer/0/q_proj,2,model.language_model.layers.0.self_attn.q_proj.weight,-",
            1,
        ),
        source.replacen(
            first,
            "0,B,weight/layer/0/q_proj,1,model.language_model.layers.0.self_attn.q_proj.weight,-",
            1,
        ),
        source.replacen(
            first,
            "0,W,weight/layer/0/k_proj,1,model.language_model.layers.0.self_attn.q_proj.weight,-",
            1,
        ),
        source.replacen(
            "model.language_model.layers.0.self_attn.q_proj.weight,-",
            "model.language_model.layers.0.self_attn.k_proj.weight,-",
            1,
        ),
        source.replacen(
            "model.language_model.layers.0.layer_scalar",
            "model.language_model.layers.1.layer_scalar",
            1,
        ),
        source.replacen(&format!("{first}\n{second}"), &format!("{second}\n{first}"), 1),
        source.replacen("@context_cap=4096", "@context_cap=4095", 1),
        source.replacen("@public_layer_scalar_count=60", "@public_layer_scalar_count=59", 1),
        source.replacen("@terminal_count=480", "@terminal_count=479", 1),
        source.trim_end_matches('\n').to_owned(),
        format!("{source}480,B,b/4,1,-,-\n"),
    ];

    for mutation in mutations {
        assert!(compile_gemma31b_terminal_manifest(&mutation).is_err());
    }
}

#[test]
fn manifest_sidecar_rejects_digest_or_format_drift() {
    let source = GEMMA31B_TERMINAL_MANIFEST_SOURCE;
    let sidecar = GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX;
    assert!(require_gemma31b_manifest_digest(source, sidecar).is_ok());
    assert!(require_gemma31b_manifest_digest(source, sidecar.trim_end()).is_err());
    assert!(require_gemma31b_manifest_digest(source, &sidecar.to_uppercase()).is_err());
    assert!(require_gemma31b_manifest_digest(&format!("{source}\n"), sidecar).is_err());
}

#[test]
fn pinned_weight_source_census_closes_exactly() {
    assert_eq!(
        50 * GEMMA31B_LOCAL_MATRIX_SCALARS_PER_LAYER
            + 10 * GEMMA31B_GLOBAL_MATRIX_SCALARS_PER_LAYER
            + GEMMA31B_EMBEDDING_SCALARS,
        GEMMA31B_MATRIX_SCALARS
    );
    assert_eq!(
        50 * GEMMA31B_LOCAL_NORM_SCALARS_PER_LAYER
            + 10 * GEMMA31B_GLOBAL_NORM_SCALARS_PER_LAYER
            + GEMMA31B_FINAL_NORM_SCALARS,
        GEMMA31B_NORM_SCALARS
    );
    assert_eq!(GEMMA31B_MATRIX_SCALARS + GEMMA31B_NORM_SCALARS, GEMMA31B_PRIVATE_WEIGHT_SCALARS);
    assert_eq!(GEMMA31B_PRIVATE_WEIGHT_SCALARS * 2, GEMMA31B_PACKED_I16_BYTES);
    assert_eq!(
        GEMMA31B_PRIVATE_LEARNED_TENSORS
            + GEMMA31B_PUBLIC_LAYER_SCALARS
            + GEMMA31B_FORBIDDEN_VISION_BRIDGE_TENSORS,
        GEMMA31B_PHYSICAL_TENSORS
    );
}

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "c7_d126_gemma_metadata.py"
MANIFEST_PATH = ROOT / "manifests" / "c7-d126-gemma31b-source-metadata-v1.json"
SCALAR_PATH = ROOT / "manifests" / "c7-d126-gemma31b-layer-scalars-v1.csv"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_d126_gemma_metadata", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_pinned_metadata_and_public_scalars_validate() -> None:
    module = load_module()
    manifest = load_manifest()
    module.validate_manifest(manifest)

    digest = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    assert digest == "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
    assert MANIFEST_PATH.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{digest}  {MANIFEST_PATH.name}\n"
    )
    assert manifest["summary"] == {
        "complete_weight_shards_downloaded": 0,
        "forbidden_vision_bridge_scalars": 575_743_536,
        "forbidden_vision_bridge_tensors": 356,
        "framing_bytes": 160_496,
        "ordered_public_layer_scalar_bytes_sha256": (
            "4d4ddd2f27faee67f141f83903c02bc93864a92402fd2cb9896da2628e6dbb70"
        ),
        "payload_bytes": 62_546_177_752,
        "physical_tensors": 1_188,
        "private_text_scalars": 30_697_345_280,
        "private_text_tensors": 772,
        "public_layer_scalar_values_are_runtime_usage_claims": False,
        "public_layer_scalars": 60,
        "weight_shard_bytes_requested": 160_616,
        "weight_tensor_value_bytes_requested": 120,
    }
    assert [(row["header_bytes"], row["tensor_count"]) for row in manifest["shards"]] == [
        (136_896, 1_009),
        (23_584, 179),
    ]


def test_layer_scalars_are_ordered_real_bf16_values_not_assumed_one() -> None:
    module = load_module()
    manifest = load_manifest()
    scalars = manifest["public_layer_scalars"]
    assert [row["layer"] for row in scalars] == list(range(60))
    assert scalars[0]["raw_le_hex"] == "c63d"
    assert scalars[0]["value_hexfloat"] == "0x1.8c00000000000p-4"
    assert scalars[-1]["raw_le_hex"] == "233d"
    assert scalars[-1]["value_hexfloat"] == "0x1.4600000000000p-5"
    assert {row["bf16_bits"] for row in scalars} != {0x3F80}

    source_digest = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    scalar_body = SCALAR_PATH.read_bytes()
    module.validate_scalar_csv(scalar_body, manifest, source_digest)
    scalar_digest = hashlib.sha256(scalar_body).hexdigest()
    assert scalar_digest == "52c10c73dad7a8a81f937d4954d3b38b6cf38216393793e23571b3c6017d67af"
    assert SCALAR_PATH.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{scalar_digest}  {SCALAR_PATH.name}\n"
    )


def test_global_key_norm_is_present_but_metadata_claims_no_runtime_use() -> None:
    manifest = load_manifest()
    tensors = {row["name"]: row for row in manifest["tensors"]}
    for layer in range(5, 60, 6):
        prefix = f"model.language_model.layers.{layer}.self_attn"
        assert tensors[f"{prefix}.k_norm.weight"]["shape"] == [512]
        assert tensors[f"{prefix}.k_proj.weight"]["shape"] == [2_048, 5_376]
        assert f"{prefix}.v_proj.weight" not in tensors
    assert manifest["admission_credit"]["runtime_tensor_use"] is False


def test_manifest_and_scalar_csv_tampering_fail_closed() -> None:
    module = load_module()
    manifest = load_manifest()

    wrong_offset = copy.deepcopy(manifest)
    wrong_offset["tensors"][0]["file_offsets"][0] += 1
    with pytest.raises(module.MetadataError):
        module.validate_manifest(wrong_offset)

    wrong_scalar = copy.deepcopy(manifest)
    wrong_scalar["public_layer_scalars"][0]["raw_le_hex"] = "803f"
    with pytest.raises(module.MetadataError):
        module.validate_manifest(wrong_scalar)

    source_digest = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    wrong_csv = SCALAR_PATH.read_bytes().replace(b"0,model.", b"1,model.", 1)
    with pytest.raises(module.MetadataError):
        module.validate_scalar_csv(wrong_csv, manifest, source_digest)

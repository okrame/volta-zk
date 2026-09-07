#!/usr/bin/env python3
"""Validate the frozen, intentionally uninstantiated GemmaQuantV1 contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "manifests" / "c7-d126-gemma31b-quant-requirements-v1.json"

MODEL = "google/gemma-4-31B"
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
REQUIRED_UNINSTANTIATED = (
    "weight_exponents_by_tensor",
    "activation_exponents_by_operation",
    "rounding_rule",
    "saturation_rule",
    "accumulator_bounds_by_operation",
    "lut_table_schema",
    "lut_table_sha256",
    "calibration_schema",
    "calibration_manifest_sha256",
    "golden_schema",
    "golden_manifest_sha256",
    "rust_python_bit_equality_report_sha256",
)
MISSING = ("packed_output.sha256", *REQUIRED_UNINSTANTIATED)


class QuantContractError(ValueError):
    pass


def _expect(actual, expected, label: str) -> None:
    """Compare JSON values without accepting bool as an integer."""
    if type(actual) is not type(expected):
        raise QuantContractError(f"{label}: type differs")
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            raise QuantContractError(f"{label}: fields differ")
        for key in expected:
            _expect(actual[key], expected[key], f"{label}.{key}")
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise QuantContractError(f"{label}: length differs")
        for index, (got, want) in enumerate(zip(actual, expected, strict=True)):
            _expect(got, want, f"{label}[{index}]")
    elif actual != expected:
        raise QuantContractError(f"{label}: value differs")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bound_path(root: Path, name: str) -> Path:
    path = root / name
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise QuantContractError(f"reference escapes repository: {name}") from error
    if not path.is_file():
        raise QuantContractError(f"missing referenced file: {name}")
    return path


def _validate_metadata(contract: dict, root: Path) -> dict:
    spec = contract["checkpoint"]
    path = _bound_path(root, spec["source_metadata_file"])
    if _sha256(path) != spec["source_metadata_sha256"]:
        raise QuantContractError("source metadata SHA-256 differs")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QuantContractError("source metadata is not valid UTF-8 JSON") from error

    _expect(metadata["model"], MODEL, "source metadata model")
    _expect(metadata["revision"], REVISION, "source metadata revision")
    summary = metadata["summary"]
    _expect(summary["private_text_tensors"], 772, "private tensor count")
    _expect(summary["private_text_scalars"], 30_697_345_280, "private scalar count")
    _expect(summary["public_layer_scalars"], 60, "public scalar count")

    private = [row for row in metadata["tensors"] if row["disposition"] == "private_text"]
    if len(private) != 772 or any(row["dtype"] != "BF16" for row in private):
        raise QuantContractError("the 772 private tensors are not all BF16")
    if sum(row["nbytes"] for row in private) != 61_394_690_560:
        raise QuantContractError("private BF16 byte count differs")
    return metadata


def _validate_public_scalars(contract: dict, metadata: dict, root: Path) -> None:
    spec = contract["public_layer_scalars"]
    path = _bound_path(root, spec["file"])
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != spec["sha256"]:
        raise QuantContractError("public scalar CSV SHA-256 differs")

    try:
        lines = body.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise QuantContractError("public scalar CSV is not ASCII") from error
    rows = [line.split(",") for line in lines if line and not line.startswith("@")]
    if len(rows) != 60 or any(len(row) != 5 for row in rows):
        raise QuantContractError("public scalar CSV does not contain 60 five-field rows")

    ordered_raw = bytearray()
    metadata_rows = metadata["public_layer_scalars"]
    for layer, (row, source) in enumerate(zip(rows, metadata_rows, strict=True)):
        expected_name = f"model.language_model.layers.{layer}.layer_scalar"
        if row[0] != str(layer) or row[1] != expected_name:
            raise QuantContractError("public scalar order or name differs")
        try:
            raw = bytes.fromhex(row[2])
        except ValueError as error:
            raise QuantContractError("public scalar raw bytes are invalid hex") from error
        if len(raw) != 2:
            raise QuantContractError("public scalar is not one BF16 value")
        if (
            source["layer"] != layer
            or source["name"] != row[1]
            or source["raw_le_hex"] != row[2]
            or str(source["bf16_bits"]) != row[3]
            or source["value_hexfloat"] != row[4]
        ):
            raise QuantContractError("public scalar CSV and source metadata differ")
        ordered_raw.extend(raw)
    if hashlib.sha256(ordered_raw).hexdigest() != spec["ordered_raw_sha256"]:
        raise QuantContractError("ordered public scalar bytes SHA-256 differs")


def _validate_workload(contract: dict, root: Path) -> None:
    spec = contract["workload"]
    path = _bound_path(root, spec["file"])
    if _sha256(path) != spec["sha256"]:
        raise QuantContractError("workload SHA-256 differs")
    try:
        workload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QuantContractError("workload is not valid UTF-8 JSON") from error
    _expect(workload["model"], MODEL, "workload model")
    _expect(workload["revision"], REVISION, "workload revision")
    _expect(workload["lengths"]["context_capacity_tokens"], 4096, "context capacity")


def validate_contract(contract: dict, root: Path = ROOT) -> dict:
    expected_top = {
        "schema",
        "profile",
        "checkpoint",
        "packed_output",
        "active_field",
        "workload",
        "public_layer_scalars",
        "required_uninstantiated",
        "acquisition_constraints",
        "deterministic_unblock_procedure",
    }
    if type(contract) is not dict or set(contract) != expected_top:
        raise QuantContractError("contract top-level fields differ")

    _expect(contract["schema"], "volta-c7-d126-gemma31b-quant-requirements-v1", "schema")
    _expect(
        contract["profile"],
        {
            "name": "GemmaQuantV1",
            "status": "BLOCKED",
            "instantiated": False,
            "admission_credit": False,
        },
        "profile",
    )
    _expect(
        contract["checkpoint"],
        {
            "model": MODEL,
            "revision": REVISION,
            "source_dtype": "BF16",
            "source_metadata_file": "manifests/c7-d126-gemma31b-source-metadata-v1.json",
            "source_metadata_sha256": "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2",
            "private_tensor_count": 772,
            "private_scalar_count": 30_697_345_280,
        },
        "checkpoint",
    )
    _expect(
        contract["packed_output"],
        {
            "scalar_dtype": "i16",
            "byte_order": "little",
            "zero_point": 0,
            "bytes": 61_394_690_560,
            "sha256": None,
        },
        "packed output",
    )
    _expect(
        contract["active_field"],
        {
            "base": "Goldilocks",
            "base_modulus": 18_446_744_069_414_584_321,
            "extension": "Fp3=Fp[u]/(u^3-2)",
            "extension_degree": 3,
            "encoded_bytes": 24,
        },
        "active field",
    )
    _expect(
        contract["workload"],
        {
            "file": "manifests/c7-d126-gemma31b-workload-v1.json",
            "sha256": "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b",
        },
        "workload",
    )
    _expect(
        contract["public_layer_scalars"],
        {
            "file": "manifests/c7-d126-gemma31b-layer-scalars-v1.csv",
            "sha256": "52c10c73dad7a8a81f937d4954d3b38b6cf38216393793e23571b3c6017d67af",
            "count": 60,
            "ordered_raw_sha256": "4d4ddd2f27faee67f141f83903c02bc93864a92402fd2cb9896da2628e6dbb70",
        },
        "public layer scalars",
    )
    _expect(
        contract["required_uninstantiated"],
        {name: None for name in REQUIRED_UNINSTANTIATED},
        "missing values",
    )
    _expect(
        contract["acquisition_constraints"],
        {
            "pod_authorized": False,
            "full_weight_shard_download_authorized": False,
            "historical_quantization_imports_allowed": False,
            "allowed_current_inputs": (
                "pinned headers, 120 public-scalar bytes, config, index, tokenizer and workload"
            ),
        },
        "acquisition constraints",
    )
    procedure = contract["deterministic_unblock_procedure"]
    if (
        type(procedure) is not list
        or len(procedure) != 7
        or any(type(step) is not str or not step for step in procedure)
        or "never change this requirements artifact to PASS" not in procedure[-1]
    ):
        raise QuantContractError("deterministic unblock procedure differs")

    metadata = _validate_metadata(contract, root)
    _validate_public_scalars(contract, metadata, root)
    _validate_workload(contract, root)
    return {
        "profile": "GemmaQuantV1",
        "status": "BLOCKED",
        "instantiated": False,
        "admission_credit": False,
        "missing": list(MISSING),
        "verified": [
            "pinned BF16 checkpoint metadata",
            "packed i16 layout and byte count requirement",
            "Goldilocks Fp3 active field",
            "frozen workload digest",
            "60 exact ordered public layer scalars",
        ],
    }


def load_and_validate(path: Path = CONTRACT) -> dict:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QuantContractError("quantization contract is unavailable or invalid") from error
    return validate_contract(contract, ROOT)


def main() -> int:
    try:
        report = load_and_validate()
    except QuantContractError as error:
        print(json.dumps({"profile": "GemmaQuantV1", "status": "INVALID", "error": str(error)}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2  # BLOCKED is deliberate: this requirements artifact is not an admission result.


if __name__ == "__main__":
    raise SystemExit(main())

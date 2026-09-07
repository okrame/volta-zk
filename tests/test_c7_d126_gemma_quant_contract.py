from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "c7_d126_gemma_quant_contract.py"
CONTRACT_PATH = ROOT / "manifests" / "c7-d126-gemma31b-quant-requirements-v1.json"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_d126_gemma_quant_contract", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def assert_rejected(module, contract: dict) -> None:
    try:
        module.validate_contract(contract)
    except module.QuantContractError:
        return
    raise AssertionError("invalid GemmaQuantV1 requirements were accepted")


def test_requirements_validate_but_gemma_quant_v1_stays_blocked() -> None:
    module = load_module()
    report = module.validate_contract(load_contract())

    digest = hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest()
    assert digest == "1c887d530b1b33bb8775f58d139378c3f156e5e519c90f150d13a80be296eaf2"
    assert CONTRACT_PATH.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{digest}  {CONTRACT_PATH.name}\n"
    )
    assert report["profile"] == "GemmaQuantV1"
    assert report["status"] == "BLOCKED"
    assert report["instantiated"] is False
    assert report["admission_credit"] is False
    assert report["missing"] == list(module.MISSING)
    assert len(report["missing"]) == 13


def test_a_partial_value_or_pass_claim_is_rejected() -> None:
    module = load_module()
    contract = load_contract()

    partial = copy.deepcopy(contract)
    partial["required_uninstantiated"]["rounding_rule"] = "nearest-even"
    assert_rejected(module, partial)

    promoted = copy.deepcopy(contract)
    promoted["profile"].update(status="PASS", instantiated=True, admission_credit=True)
    assert_rejected(module, promoted)


def test_frozen_digest_or_numeric_type_drift_is_rejected() -> None:
    module = load_module()
    contract = load_contract()

    wrong_digest = copy.deepcopy(contract)
    wrong_digest["workload"]["sha256"] = "00" * 32
    assert_rejected(module, wrong_digest)

    bool_as_count = copy.deepcopy(contract)
    bool_as_count["public_layer_scalars"]["count"] = True
    assert_rejected(module, bool_as_count)

import importlib.util
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def load_artifact_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "p7_artifact_outputs.py"
    spec = importlib.util.spec_from_file_location("p7_artifact_outputs", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_generated_tables_and_figures_preserve_negative_result_and_sources():
    artifact = load_artifact_module()
    outputs = artifact.generated_outputs()
    by_name = {path.name: value for path, value in outputs.items()}

    table = by_name["results.md"]
    assert "rho proof prefill <=10 | FAIL | 3707.595" in table
    assert "rho proof decode <=2 | FAIL | 95.597" in table
    assert "p7-integrated-resident-2026-07-13-1fd5195.json" in table
    assert "Mock-PCG" in table
    for name in ("rho.svg", "response-attribution.svg"):
        root = ET.fromstring(by_name[name])
        assert root.tag.endswith("svg")
    assert "analytic-projection-only" in by_name["shape-memory.csv"]


def test_hardware_manifest_pins_existing_raw_results_by_checksum():
    repo = Path(__file__).resolve().parents[1]
    manifest = json.loads((repo / "artifact/p7/hardware-a100.json").read_text())
    assert manifest["software"]["cuda_backend_abi"] == 17
    assert manifest["gpu"]["compile_arch"] == "sm_80"
    for result in manifest["results"].values():
        payload = (repo / result["path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == result["sha256"]

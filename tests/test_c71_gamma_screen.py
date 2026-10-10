import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("gamma_screen", ROOT / "scripts/c71_gamma_screen.py")
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)


def public_fixture():
    baseline = {"weight_exponents_by_tensor": {"tied": -14, "norm": -4},
                "activation_exponents_by_source": {"0": -14, "1": -7, "2": -5, "3": -14}}
    oracle = {"weights": [{"id": 0, "name": "tied"}, {"id": 1, "name": "norm"}],
              "steps": [{"kind": "norm", "inputs": [1], "outputs": [4, 5, 2],
                         "parameters": {"columns": 2, "weight": 1}},
                        {"kind": "softmax", "outputs": [3, 6, 7, 8, 9, 10],
                         "parameters": {"probability": 3, "histogram": 10}}]}
    return baseline, oracle


def test_candidate_scales_change_at_most_one_bit_and_preserve_fixed_aliases():
    baseline, oracle = public_fixture()
    saved = copy.deepcopy(baseline)
    variants = screen.candidates(baseline, oracle)
    assert baseline == saved
    for name, candidate in variants.items():
        assert candidate["weight_exponents_by_tensor"] == saved["weight_exponents_by_tensor"]
        for source in ("0", "3"):
            assert candidate["activation_exponents_by_source"][source] == saved["activation_exponents_by_source"][source]
        assert all(abs(e - saved["activation_exponents_by_source"][k]) <= 1
                   for k, e in candidate["activation_exponents_by_source"].items())
        _, keys = screen.norms_and_keys(candidate, oracle)
        assert keys[0][2] == -4 and keys[0][-1] is True
    assert variants["rms-even-finer"]["activation_exponents_by_source"]["1"] == -8
    assert variants["rms-even-coarser"]["activation_exponents_by_source"]["1"] == -6


def test_synthetic_RNE_uses_fixed_physical_input_and_checks_real_output_difference():
    base = [(2, -7, -4, -5, True)]
    same = screen.numerical_fixture(base, base)
    finer = screen.numerical_fixture(base, [(2, -8, -4, -6, True)])
    assert same["checked_outputs"] == finer["checked_outputs"] == 3
    assert same["max_abs_dequantized_difference"] == 0
    assert finer["RNE_error_bound_checked"]
    assert not finer["real_weights"] and not finer["token_quality_checked"]


def test_prepare_verifies_all_retained_hashes_and_never_overwrites(tmp_path):
    docs, provenance = screen.inputs(screen.BUNDLE)
    assert len(provenance) == 7 and docs["admission.json"]["gamma_admitted"]
    output = tmp_path / "prepared"
    screen.prepare(screen.BUNDLE, output)
    manifest = json.loads((output / "manifest.json").read_text())
    assert not manifest["credit"] and not manifest["gamma_admitted"]
    assert manifest["baseline_admitted"]
    assert (output / "candidates/admitted.json").read_bytes() == (screen.BUNDLE / "candidate.json").read_bytes()
    for batch in manifest["batches"]:
        recipes = json.loads((output / batch["input"]).read_text())
        assert 1 <= len(recipes) <= 8
    with pytest.raises(FileExistsError):
        screen.prepare(screen.BUNDLE, output)
    altered = tmp_path / "bundle"
    altered.mkdir()
    (altered / "candidate.json").write_text("{}")
    (altered / "transfer-manifest.json").write_text(json.dumps([provenance[0]]))
    with pytest.raises(ValueError, match="identity differs"):
        screen.inputs(altered)

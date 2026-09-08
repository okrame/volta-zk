import importlib.util
import os
from pathlib import Path
import sys


def test_local_guard_accepts_small_child_and_kills_excess_threads():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_c71_matrix.py"
    spec = importlib.util.spec_from_file_location("run_c71_matrix", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    good = runner.bounded([sys.executable, "-c", "print('bounded')"], os.environ)
    assert good["returncode"] == 0 and good["failure"] is None
    assert good["stdout"] == "bounded\n"
    bad = runner.bounded([sys.executable, "-c", "import threading,time; "
                          "[threading.Thread(target=time.sleep,args=(3,)).start() for _ in range(2)]; "
                          "time.sleep(3)"], os.environ)
    assert bad["returncode"] != 0
    assert bad["failure"] == "RSS or thread limit exceeded"


def test_native_census_fixture_and_reconciliation_reject_missing_work():
    import copy
    import json
    import runpy
    import pytest

    root = Path(__file__).resolve().parents[1]
    census = runpy.run_path(str(root / "scripts/c71_work_census.py"))
    record = json.loads((root / "benchmarks/results/c71-b3-census128-diagnostic-20260908-bb64f0e.json").read_text())
    census["validate_self_check"](record["counter_check"])
    census["validate_matrix_census"](record["work_census"], record["execution"])
    bad = copy.deepcopy(record["counter_check"])
    bad["phases"][0]["categories"]["p3_dot"] -= 1
    with pytest.raises(ValueError, match="fixture failed"):
        census["validate_self_check"](bad)
    for index in (2, 7, 11):  # PCG and both PCS roles must contribute actual work.
        bad = copy.deepcopy(record["work_census"])
        bad["phases"][index]["base_products_inclusive"] = 0
        with pytest.raises(ValueError, match="counters missing"):
            census["validate_matrix_census"](bad, record["execution"])
    bad = copy.deepcopy(record["work_census"])
    bad["phases"].pop(12)
    with pytest.raises(ValueError, match="phase coverage"):
        census["validate_matrix_census"](bad, record["execution"])
    bad = copy.deepcopy(record["execution"])
    bad["resources"]["phases"][7]["heap_allocated_bytes"] += 1
    with pytest.raises(ValueError, match="allocator census"):
        census["validate_matrix_census"](record["work_census"], bad)
    # Concrete copies of the same implementation must both be retained.
    parsed = census["parse_lcov"]("SF:field.rs\nFN:66,cgu1\nFN:66,cgu2\nFNDA:2,cgu1\nFNDA:3,cgu2\nend_of_record\n")
    assert sum(r["calls"] for r in parsed) == 5
    with pytest.raises(ValueError, match="duplicate LLVM"):
        census["parse_lcov"]("SF:field.rs\nFN:66,cgu1\nFN:66,cgu1\n")

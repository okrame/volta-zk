"""Bounded owner telemetry and cleanup with a simulated driver; no CUDA credit."""
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/c71_owner_trace_runtime_host.cpp"
HEADER_SOURCE = ROOT / "tests/c71_owner_trace_host.cpp"
FIELDS = {"schema", "credit", "seq", "a_first", "a_group", "monotonic_ns", "op", "edge", "slot",
          "kind", "logical_bytes", "capacity_bytes", "arena_bytes", "weights_bytes",
          "status", "line"}


def compile_fixture(binary, *, header_only=False):
    command = ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=undefined", "-fno-sanitize-recover=all", "-DC71_OWNER_TRACE",
               "-I", str(ROOT / "tests/cuda_stub"), "-I", str(ROOT / "cuda")]
    if header_only:
        command.append(str(HEADER_SOURCE))
    else:
        command += [str(ROOT / "cuda/c71_range_runtime.cpp"), str(SOURCE), "-Wl,--wrap=write"]
    command += ["-o", str(binary)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def run_fixture(binary, scenario, path):
    environment = os.environ.copy()
    environment.pop("C71_OWNER_TRACE_A_FIRST", None)
    environment["C71_OWNER_TRACE_PATH"] = str(path)
    if scenario in {"windowmatched", "windowmissing"}:
        environment["C71_OWNER_TRACE_A_FIRST"] = "1"
    result = subprocess.run([str(binary), scenario], env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    marker, payload = result.stdout.strip().split(" ", 1)
    assert marker == "C71_OWNER_TRACE_RUNTIME"
    report = json.loads(payload)
    assert report["scenario"] == scenario
    assert report["gpu_execution"] is False and report["credit"] is False
    print(result.stdout.strip())
    return report


def read_records(path):
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    records = [json.loads(line) for line in path.read_text().splitlines()]
    for index, record in enumerate(records):
        assert set(record) == FIELDS
        assert record["schema"] == "volta-c71-owner-trace-v1" and record["credit"] is False
        assert record["seq"] == index and -1 <= record["slot"] < 512
        assert -1 <= record["a_first"] <= 511 and -1 <= record["a_group"] <= 511
        assert record["edge"] in {"before", "after"}
        assert record["op"].replace("_", "").isalnum()
        assert record["line"] > 0
        assert record["monotonic_ns"] >= (records[index - 1]["monotonic_ns"] if index else 0)
        for key in ("logical_bytes", "capacity_bytes", "arena_bytes", "weights_bytes"):
            assert record[key] >= 0
    return records


def test_owner_trace_header_is_bounded_private_and_fail_closed(tmp_path):
    binary = tmp_path / "owner-trace-header"
    compile_fixture(binary, header_only=True)
    environment = os.environ.copy()
    environment.pop("C71_OWNER_TRACE_A_FIRST", None)
    result = subprocess.run([str(binary), str(tmp_path)], env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    marker, payload = result.stdout.strip().split(" ", 1)
    assert marker == "C71_OWNER_TRACE_HOST"
    assert json.loads(payload) == {
        "cases": 26, "state_bytes": 32, "record_storage_bytes": 512,
        "maximum_records": 131072, "maximum_file_bytes": 16 << 20,
        "gpu_execution": False, "credit": False,
    }
    records = read_records(tmp_path / "ordinary.jsonl")
    assert len(records) == 5
    assert [(r["edge"], r["arena_bytes"]) for r in records[:4]] == [
        ("before", 0), ("after", 256), ("before", 256), ("after", 0),
    ]
    assert all(r["a_first"] == r["a_group"] == -1 for r in records)
    assert (tmp_path / "symlink.jsonl").read_text() == (tmp_path / "ordinary.jsonl").read_text()
    for name in ("bad-operation", "bad-slot", "bad-edge", "record-ceiling", "byte-ceiling", "write-failure", "closed"):
        assert read_records(tmp_path / f"{name}.jsonl") == []
    selected = read_records(tmp_path / "selected-window.jsonl")
    assert len(selected) == 2
    assert [(r["a_first"], r["a_group"]) for r in selected] == [(34, 34), (34, 35)]
    for name in ("unreached-window", "first-zero", "first-last"):
        assert read_records(tmp_path / f"{name}.jsonl") == []
    assert not (tmp_path / "invalid-selector.jsonl").exists()
    print(result.stdout.strip())


def test_owner_trace_runtime_bookkeeping_survives_logger_faults(tmp_path):
    binary = tmp_path / "owner-trace-runtime"
    compile_fixture(binary)
    scenarios = ("normal", "prealloc", "postalloc", "prefree", "postfree", "postfence",
                 "free_failure", "free_failure_trace", "no_env", "existing", "windowmatched", "windowmissing")
    for scenario in scenarios:
        path = tmp_path / f"runtime-{scenario}.jsonl"
        if scenario == "existing":
            path.write_text("preserved\n")
        report = run_fixture(binary, scenario, path)
        assert report["host_owner_bytes"] == 42128
        debt = 256 if scenario in {"free_failure", "free_failure_trace"} else 0
        assert report["final_arena_bytes"] == report["joint_debt_bytes"] == debt
        assert report["allocations"] == report["releases"] + (1 if debt else 0)
        assert report["cleanup_failed"] == (scenario not in {"normal", "windowmatched"})
        if scenario in {"no_env", "existing"}:
            assert report["native_allocations"] == report["native_frees"] == 0
            if scenario == "existing":
                assert path.read_text() == "preserved\n"
            else:
                assert not path.exists()
            continue
        records = read_records(path)
        if scenario == "windowmissing":
            assert records == []
            assert report["native_allocations"] == report["native_frees"] == 6
            continue
        if scenario == "windowmatched":
            assert records
            assert all(r["a_first"] == r["a_group"] == 1 for r in records)
            assert records[-1]["op"] == "c71_range_close" and records[-1]["arena_bytes"] == 0
            assert report["native_allocations"] == report["native_frees"] == 6
            continue
        assert records[:2][0]["op"] == records[:2][1]["op"] == "c71_range_create"
        assert [r["edge"] for r in records[:2]] == ["before", "after"]
        assert all(r["a_first"] == r["a_group"] == -1 for r in records)
        if scenario == "normal":
            assert records[-1]["op"] == "c71_range_close" and records[-1]["edge"] == "after"
            assert records[-1]["arena_bytes"] == records[-1]["weights_bytes"] == 0
            allocation_events = [r for r in records if r["op"] == "allocate"]
            assert len(allocation_events) == 6
            for before, after in zip(allocation_events[::2], allocation_events[1::2]):
                assert before["edge"] == "before" and after["edge"] == "after"
                assert before["slot"] == after["slot"]
                assert before["capacity_bytes"] == after["capacity_bytes"] == 256
                assert after["arena_bytes"] == before["arena_bytes"] + 256
            release_events = [r for r in records if r["op"] == "c71_range_release"]
            assert len(release_events) == 4
            for before, after in zip(release_events[::2], release_events[1::2]):
                assert after["arena_bytes"] == before["arena_bytes"] - 256
            assert report["native_allocations"] == report["native_frees"] == 4
        elif scenario == "postalloc":
            assert records[-1]["op"] == "allocate" and records[-1]["edge"] == "before"
        elif scenario == "prefree":
            assert records[-1]["op"] == "fence" and records[-1]["edge"] == "after"
        elif scenario == "postfree":
            assert records[-1]["op"] == "c71_range_release" and records[-1]["edge"] == "before"
        elif scenario == "postfence":
            assert records[-1]["op"] == "fence" and records[-1]["edge"] == "before"
        elif scenario == "free_failure":
            failed = [r for r in records if r["op"] == "c71_range_release" and r["edge"] == "after"]
            assert len(failed) == 1 and failed[0]["status"] != 0 and failed[0]["arena_bytes"] == 512
            assert records[-1]["arena_bytes"] == 256

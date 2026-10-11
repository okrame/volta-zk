"""Allocation diagnostic inputs and lifetimes; no GPU execution."""
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("allocation_replay", Path(__file__).resolve().parents[1] / "scripts/c71_cuda_allocation_replay.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_allocation_plan_requires_periodic_bounded_lifetimes():
    m = 1 << 20
    data = dict(schema="volta-c71-allocation-replay-v1", minimum_bytes=m,
                initial=[[0, m]], operations=[["allocate", 1, 2*m], ["release", 1, 2*m]])
    assert MODULE.validate(data) == 3*m
    for ops in ([['allocate', 0, m]], [['release', 0, 2*m]], [['allocate', 1, m]],
                [['allocate', 1, 6 << 30], ['release', 1, 6 << 30]]):
        with pytest.raises(ValueError):
            MODULE.validate(data | dict(operations=ops))


def test_preserved_trace_yields_only_a_complete_periodic_group():
    root = Path(__file__).resolve().parents[1]
    trace = root / "artifact/c7.1-pod/h100-followup-spike-20261010T183000Z/canonical-spike01/owner-trace.jsonl"
    if not trace.exists():
        pytest.skip("private captured allocation trace unavailable")
    data = MODULE.plan(trace, 31)
    assert len(data["initial"]) == 190
    assert len(data["operations"]) == 4728
    assert MODULE.validate(data) < MODULE.PAYLOAD_LIMIT - MODULE.HOST_RESERVE
    for group in (30, 35):
        with pytest.raises(ValueError):
            MODULE.plan(trace, group)

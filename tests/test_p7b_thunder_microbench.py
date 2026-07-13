import importlib.util
from pathlib import Path


def load_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "p7b_thunder_microbench.py"
    )
    spec = importlib.util.spec_from_file_location("p7b_thunder_microbench", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fixture(enqueue_per_launch=8.0, total_per_launch=9.0, graph_total=10_000.0):
    stats = lambda median, count=31: {"median_us": median, "count": count}
    direct = []
    graphs = []
    for kernels in (1, 8, 64, 512, 4096):
        direct.append(
            {
                "kernels": kernels,
                "enqueue_per_launch": stats(
                    enqueue_per_launch if kernels == 4096 else 10.0
                ),
                "total_per_launch": stats(
                    total_per_launch if kernels == 4096 else 11.0
                ),
                "total": stats(40_000.0 if kernels == 4096 else 100.0),
            }
        )
        graphs.append(
            {
                "kernels": kernels,
                "total": stats(graph_total if kernels == 4096 else 90.0),
            }
        )
    return {
        "correctness": True,
        "timing_sane": True,
        "measurement_wall_s": 1800.0,
        "empty_launch_sync": stats(100.0),
        "blocking_d2h_8b": stats(120.0),
        "allocation_8b": {"malloc": stats(80.0), "free": stats(90.0)},
        "direct_bursts": direct,
        "cuda_graphs": graphs,
    }


def test_classify_pipelined_launches_and_material_graph():
    module = load_module()
    decision = module.classify(fixture())

    assert decision["direct_async_launches_pipelined"] is True
    assert decision["cuda_graph_material_lever"] is True
    assert decision["implementation_branch"] == "eliminate-blocking-d2h-first"
    assert decision["graph_speedup_vs_direct_burst"] == 4.0


def test_classify_non_pipelined_launches():
    module = load_module()
    decision = module.classify(
        fixture(enqueue_per_launch=15.0, total_per_launch=20.0, graph_total=50_000.0)
    )

    assert decision["direct_async_launches_pipelined"] is False
    assert decision["cuda_graph_material_lever"] is False
    assert decision["implementation_branch"] == (
        "coarsen-launch-surface-and-eliminate-blocking-d2h"
    )


def test_validate_rejects_wrong_burst_grid():
    module = load_module()
    kernel = fixture()
    kernel["direct_bursts"].pop()

    try:
        module.validate_kernel(kernel, 1800.0)
    except SystemExit as error:
        assert "burst grid" in str(error)
    else:
        raise AssertionError("wrong burst grid was accepted")

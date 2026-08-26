import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "budget_c64_joint_residual_sketch.py"


def load_budget_module():
    spec = importlib.util.spec_from_file_location("budget_c64", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_c64_joint_capacity_screen():
    module = load_budget_module()
    screen = module.build_screen()
    module.self_check(screen)

    assert [row["name"] for row in screen["responses"]] == [
        "genesis_0_150",
        "continuation_150_200",
    ]
    assert screen["open_gates"]

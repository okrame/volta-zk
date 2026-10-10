"""Small schedule/input checks; no PyTorch import or inference credit."""
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("optimized", Path(__file__).resolve().parents[1] / "scripts/c71_optimized_inference.py")
optimized = importlib.util.module_from_spec(spec)
spec.loader.exec_module(optimized)


def test_admitted_histories_and_final_generated_token_are_consumed():
    prompt = list(range(100))
    rows = [{"old_tokens": old, "tokens": prompt + list(range(100, 150))} for old in (0, 150, 300)]
    assert optimized.histories({"responses": rows}, prompt) == rows
    calls = list(optimized.schedule(prompt, rows[0]["tokens"]))
    assert len(calls) == 51 and sum(map(len, calls)) == 150
    assert calls[-1] == [149]
    rows[1]["old_tokens"] = 149
    with pytest.raises(ValueError):
        optimized.histories({"responses": rows}, prompt)


def test_history_rejects_wrong_prompt_and_noninteger_tokens():
    prompt = list(range(100))
    for changed in (True, 262144, -1):
        rows = [{"old_tokens": old, "tokens": prompt + [100] * 50} for old in (0, 150, 300)]
        rows[0]["tokens"][-1] = changed
        with pytest.raises(ValueError):
            optimized.histories({"responses": rows}, prompt)
    rows[0]["tokens"][0] = 1
    with pytest.raises(ValueError):
        optimized.histories({"responses": rows}, prompt)

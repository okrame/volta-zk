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

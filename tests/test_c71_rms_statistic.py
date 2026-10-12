"""Private original-X lifetime and publication; fake driver, no GPU math."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_statistic_owner_order_readonly_source_and_publication(tmp_path):
    binary = tmp_path / 'rms-statistic-owner'
    subprocess.run(['g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    '-I', str(ROOT / 'tests/cuda_stub'), '-I', str(ROOT / 'cuda'),
                    str(ROOT / 'cuda/c71_range_runtime.cpp'),
                    str(ROOT / 'tests/c71_rms_statistic_host.cpp'), '-o', str(binary)],
                   check=True, timeout=30)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.removeprefix('C71_RMS_STATISTIC_OWNER ')) == {
        'success': 1, 'terminal_rejections': 25, 'singleton': True,
        'owned_until_fence': True, 'gpu_execution': False, 'credit': False,
    }

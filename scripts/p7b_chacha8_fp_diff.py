#!/usr/bin/env python3
"""Compile and compare the CUDA ChaCha8/Goldilocks generator with its Rust oracle.

The harness is deliberately standalone: Cargo is forced offline, the CUDA
probe is compiled in a temporary directory, and result files are created with
exclusive-create semantics so an earlier differential can never be replaced.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence


REPO = Path(__file__).resolve().parents[1]
RUST_ROOT = REPO / "rust"
RESULTS = REPO / "benchmarks" / "results"
CUDA_SOURCE = REPO / "cuda" / "p7b_chacha8_fp_diff.cu"
CUDA_HEADER = REPO / "cuda" / "volta_chacha8_fp.cuh"
RUST_ORACLE = REPO / "rust" / "volta-bench" / "src" / "bin" / "p7b_chacha8_fp_vectors.rs"
VECTOR_SCHEMA = "p7b-chacha8-fp-diff-v1"
REPORT_SCHEMA = "p7b-chacha8-fp-differential-report-v1"
GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001
HEX_U64 = re.compile(r"^0x[0-9a-f]{16}$")
DEFAULT_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    mode: str
    seed_hex: str
    base_domain: int
    rows: int
    count: int

    def arguments(self) -> list[str]:
        return [
            "--mode",
            self.mode,
            "--seed-hex",
            self.seed_hex,
            "--base-domain",
            f"0x{self.base_domain:016x}",
            "--rows",
            str(self.rows),
            "--count",
            str(self.count),
        ]

    def as_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "seed_hex": self.seed_hex,
            "base_domain": f"0x{self.base_domain:016x}",
            "rows": self.rows,
            "count": self.count,
        }


# These are the two command lines validated while the standalone CUDA source
# was brought up: the defaults already cross a 64-byte ChaCha block, while the
# second case exercises Fp2 packing with a high seed/domain and a longer row.
CASES = (
    Case(
        name="fp-default-multi-block",
        mode="fp",
        seed_hex=DEFAULT_SEED,
        base_domain=0x0123_4567_89AB_CDEF,
        rows=3,
        count=10,
    ),
    Case(
        name="fp2-high-seed-domain",
        mode="fp2",
        seed_hex="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
        base_domain=0xFEDC_BA98_7654_3210,
        rows=4,
        count=17,
    ),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_fp(value: Any, where: str) -> None:
    if not isinstance(value, str) or not HEX_U64.fullmatch(value):
        raise ValueError(f"{where} is not a normalized 64-bit hex string")
    if int(value, 16) >= GOLDILOCKS_MODULUS:
        raise ValueError(f"{where} is not a canonical Goldilocks value")


def parse_vector_output(raw: bytes, case: Case, implementation: str) -> dict[str, Any]:
    """Parse and validate one oracle output independently of its peer."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{implementation} output is not UTF-8") from error
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"{implementation} output is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{implementation} output root is not an object")

    expected_metadata = {
        "schema": VECTOR_SCHEMA,
        "mode": case.mode,
        "seed_hex": case.seed_hex,
        "base_domain": f"0x{case.base_domain:016x}",
        "rows": case.rows,
        "count": case.count,
    }
    for key, expected in expected_metadata.items():
        if value.get(key) != expected:
            raise ValueError(
                f"{implementation} output has {key}={value.get(key)!r}, expected {expected!r}"
            )

    rows = value.get("values")
    if not isinstance(rows, list) or len(rows) != case.rows:
        raise ValueError(f"{implementation} output has the wrong row count")
    for row_index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != case.count:
            raise ValueError(
                f"{implementation} output row {row_index} has the wrong value count"
            )
        for column_index, item in enumerate(row):
            location = f"{implementation} values[{row_index}][{column_index}]"
            if case.mode == "fp":
                _validate_fp(item, location)
            elif case.mode == "fp2":
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError(f"{location} is not an Fp2 pair")
                _validate_fp(item[0], f"{location}[0]")
                _validate_fp(item[1], f"{location}[1]")
            else:
                raise ValueError(f"unsupported case mode {case.mode!r}")
    return value


def compare_outputs(case: Case, cuda_raw: bytes, rust_raw: bytes) -> dict[str, Any]:
    cuda_json = parse_vector_output(cuda_raw, case, "cuda")
    rust_json = parse_vector_output(rust_raw, case, "rust")
    cuda_canonical = canonical_json_bytes(cuda_json)
    rust_canonical = canonical_json_bytes(rust_json)
    return {
        **case.as_record(),
        "arguments": case.arguments(),
        "cuda": {
            "stdout_bytes": len(cuda_raw),
            "stdout_sha256": sha256_bytes(cuda_raw),
            "canonical_json_sha256": sha256_bytes(cuda_canonical),
        },
        "rust": {
            "stdout_bytes": len(rust_raw),
            "stdout_sha256": sha256_bytes(rust_raw),
            "canonical_json_sha256": sha256_bytes(rust_canonical),
        },
        "structurally_identical": cuda_json == rust_json,
        "byte_identical": cuda_raw == rust_raw,
    }


Run = Callable[..., subprocess.CompletedProcess[bytes]]


def git_metadata(run: Run = subprocess.run) -> dict[str, Any]:
    """Return a state snapshot that can never mistake a failed status for clean."""

    revision = run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if revision.returncode != 0 or not revision.stdout.strip():
        detail = revision.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"could not determine git revision (exit {revision.returncode}): {detail}")

    status = run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    entries = [entry for entry in status.stdout.split(b"\0") if entry]
    return {
        "git_sha": revision.stdout.decode("ascii").strip(),
        # A failed status query is conservatively dirty. Untracked files are
        # explicitly included, unlike the old timing harness helper.
        "git_dirty": status.returncode != 0 or bool(entries),
        "git_status_exit_code": status.returncode,
        "git_status_entries": len(entries),
        "git_status_stdout_sha256": sha256_bytes(status.stdout),
        "git_status_stderr": status.stderr.decode("utf-8", errors="replace").strip(),
    }


def command_result(command: Sequence[str]) -> dict[str, Any]:
    completed = subprocess.run(
        list(command),
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": list(command),
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace").strip(),
        "stderr": completed.stderr.decode("utf-8", errors="replace").strip(),
    }


def require_command_metadata(command: Sequence[str], label: str) -> dict[str, Any]:
    result = command_result(command)
    if result["exit_code"] != 0:
        raise RuntimeError(
            f"{label} metadata command failed with exit {result['exit_code']}: "
            f"{result['stderr']}"
        )
    return result


NVIDIA_SMI_QUERY = [
    "nvidia-smi",
    "--query-gpu=index,name,uuid,driver_version,memory.total",
    "--format=csv,noheader,nounits",
]


def parse_nvidia_smi_rows(stdout: str) -> list[dict[str, Any]]:
    devices = []
    for line_number, row in enumerate(csv.reader(io.StringIO(stdout)), 1):
        if not row or all(not item.strip() for item in row):
            continue
        if len(row) != 5:
            raise ValueError(f"nvidia-smi row {line_number} has {len(row)} fields, expected 5")
        index, name, uuid, driver, memory_mib = (item.strip() for item in row)
        try:
            parsed_index = int(index)
            parsed_memory = int(memory_mib)
        except ValueError as error:
            raise ValueError(f"nvidia-smi row {line_number} has non-numeric metadata") from error
        devices.append(
            {
                "index": parsed_index,
                "name": name,
                "uuid": uuid,
                "driver_version": driver,
                "memory_total_mib": parsed_memory,
            }
        )
    return devices


def gpu_metadata() -> tuple[dict[str, Any], list[str]]:
    executable = shutil.which(NVIDIA_SMI_QUERY[0])
    if executable is None:
        return (
            {
                "available": False,
                "query_exit_code": None,
                "query_stderr": "nvidia-smi not found",
                "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
                "devices": [],
            },
            NVIDIA_SMI_QUERY,
        )
    command = [executable, *NVIDIA_SMI_QUERY[1:]]
    result = command_result(command)
    devices = parse_nvidia_smi_rows(result["stdout"]) if result["exit_code"] == 0 else []
    return (
        {
            "available": result["exit_code"] == 0 and bool(devices),
            "query_exit_code": result["exit_code"],
            "query_stderr": result["stderr"],
            "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
            "devices": devices,
        },
        command,
    )


def run_checked(command: Sequence[str], cwd: Path) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"command failed with exit {completed.returncode}: {' '.join(command)}\n{stderr}"
        )
    return completed.stdout


def default_output_path(date: str, short_sha: str) -> Path:
    stem = f"p7b-chacha8-fp-diff-{date}-{short_sha}"
    candidate = RESULTS / f"{stem}.json"
    if not candidate.exists():
        return candidate
    for suffix in range(1, 1000):
        candidate = RESULTS / f"{stem}-{suffix}.json"
        if not candidate.exists():
            return candidate
    raise RuntimeError("could not allocate an append-only result filename")


def resolve_output(requested: str | None, date: str, short_sha: str) -> Path:
    if requested is None:
        return default_output_path(date, short_sha)
    path = Path(requested).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing result: {path}")
    return path


def write_report_exclusive(path: Path, report: dict[str, Any]) -> None:
    """Atomically claim a new pathname and never truncate an existing result."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as handle:
        handle.write(payload)


def source_hashes() -> list[dict[str, Any]]:
    return [
        {
            "path": str(path.relative_to(REPO)),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in (Path(__file__).resolve(), CUDA_SOURCE, CUDA_HEADER, RUST_ORACLE)
    ]


def cargo_target_dir() -> Path:
    configured = os.environ.get("CARGO_TARGET_DIR")
    if configured is None:
        return RUST_ROOT / "target"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else RUST_ROOT / path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="new result pathname (must not already exist)")
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_80")
    args = parser.parse_args(argv)
    if not args.arch or any(character.isspace() for character in args.arch):
        parser.error("--arch must be a non-empty nvcc architecture token")

    source_control = git_metadata()
    today = dt.date.today().isoformat()
    output = resolve_output(args.output, today, source_control["git_sha"][:12])
    sources = source_hashes()

    nvcc_version = require_command_metadata([args.nvcc, "--version"], "nvcc")
    cargo_version = require_command_metadata(["cargo", "--version"], "cargo")
    rustc_version = require_command_metadata(["rustc", "--version", "--verbose"], "rustc")
    gpu, gpu_command = gpu_metadata()

    commands: dict[str, Any] = {
        "metadata": {
            "nvcc": nvcc_version["command"],
            "cargo": cargo_version["command"],
            "rustc": rustc_version["command"],
            "gpu": gpu_command,
        },
        "case_runs": [],
    }

    with tempfile.TemporaryDirectory(prefix="volta-p7b-chacha8-fp-diff-") as temporary:
        cuda_binary = Path(temporary) / "p7b_chacha8_fp_diff"
        rust_binary = cargo_target_dir() / "release" / "p7b_chacha8_fp_vectors"
        cuda_compile = [
            args.nvcc,
            "-O3",
            "-std=c++17",
            f"-arch={args.arch}",
            str(CUDA_SOURCE),
            "-o",
            str(cuda_binary),
        ]
        rust_compile = [
            "cargo",
            "build",
            "--offline",
            "--release",
            "-p",
            "volta-bench",
            "--bin",
            "p7b_chacha8_fp_vectors",
        ]
        commands["cuda_compile"] = cuda_compile
        commands["cuda_compile_cwd"] = str(REPO)
        commands["rust_compile"] = rust_compile
        commands["rust_compile_cwd"] = str(RUST_ROOT)
        print("compile CUDA:", " ".join(cuda_compile), flush=True)
        run_checked(cuda_compile, REPO)
        print("compile Rust oracle:", " ".join(rust_compile), flush=True)
        run_checked(rust_compile, RUST_ROOT)

        case_records = []
        for case in CASES:
            cuda_command = [str(cuda_binary), *case.arguments()]
            rust_command = [str(rust_binary), *case.arguments()]
            commands["case_runs"].append(
                {
                    "name": case.name,
                    "cuda": cuda_command,
                    "rust": rust_command,
                    "cwd": str(REPO),
                }
            )
            print(f"compare {case.name}", flush=True)
            cuda_raw = run_checked(cuda_command, REPO)
            rust_raw = run_checked(rust_command, REPO)
            case_records.append(compare_outputs(case, cuda_raw, rust_raw))

    structurally_identical = all(case["structurally_identical"] for case in case_records)
    byte_identical = all(case["byte_identical"] for case in case_records)
    if source_hashes() != sources:
        raise RuntimeError("differential sources changed while the harness was running")
    report = {
        "schema": REPORT_SCHEMA,
        "milestone": "P7b-chacha8-fp-differential",
        "date": today,
        "git_sha": source_control["git_sha"],
        "git_dirty": source_control["git_dirty"],
        "source_control": source_control,
        "sources": sources,
        "compiler": {
            "cuda": {
                "executable": args.nvcc,
                "arch": args.arch,
                "version": nvcc_version,
            },
            "rust": {"cargo": cargo_version, "rustc": rustc_version},
        },
        "gpu": gpu,
        "commands": commands,
        "cases": case_records,
        "structurally_identical": structurally_identical,
        "byte_identical": byte_identical,
    }
    write_report_exclusive(output, report)
    try:
        shown_output = output.relative_to(REPO)
    except ValueError:
        shown_output = output
    print(
        json.dumps(
            {
                "output": str(shown_output),
                "structurally_identical": structurally_identical,
                "byte_identical": byte_identical,
            },
            sort_keys=True,
        )
    )
    return 0 if structurally_identical and byte_identical else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)

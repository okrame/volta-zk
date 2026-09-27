#!/usr/bin/env python3
"""Prepare certified public tables and replay a fixed candidate on the C7.1 workload.

This does not initialize activation scales, certify model quality, or authorize
the full CPU replay. Real ingestion and all three successful trials are needed
before a candidate can be frozen as calibrated Gamma.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

import c7_1_gemma_plan as plan
import c7_d126_gemma_weight_ingest as ingest


TABLE_BYTES = 24_414_870


def native_recipes(native: Path, candidate: Path) -> dict:
    ingest._json_no_duplicates(candidate.read_bytes(), "calibration candidate")
    result = subprocess.run([str(native), "recipes", str(candidate)],
                            capture_output=True, text=True, timeout=60, check=True)
    return json.loads(result.stdout)


def table_chunks(recipes: dict):
    if (len(recipes["gelu"]) != 60 or len(recipes["exp30"]) != 60
            or len(recipes["softcap"]) != 2 or recipes["rope_positions"] != 450
            or recipes["table_bytes"] != TABLE_BYTES):
        raise ValueError("canonical public table recipe shape differs")
    cache = {}
    for exponents in recipes["gelu"]:
        key = tuple(exponents)
        if key not in cache:
            cache[key] = plan.gelu_i16_table(*key)
        yield cache[key]
    cache.clear()
    for exponent in recipes["exp30"]:
        if exponent not in cache:
            cache[exponent] = plan.softmax_exp30_table(exponent)
        yield cache[exponent]
    cache.clear()
    yield plan.softcap_i16_table(*recipes["softcap"])
    for family in ("local", "global"):
        for position in range(450):
            yield b"".join(struct.pack("<ii", *pair)
                           for pair in plan.gemma_rope_q30_coefficients(family, position))


@contextmanager
def atomic_output(output: Path):
    if os.path.lexists(output):
        raise FileExistsError(f"refusing to overwrite {output}")
    descriptor, name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".partial", dir=output.parent)
    partial = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as sink:
            yield sink
            sink.flush()
            os.fsync(sink.fileno())
        os.link(partial, output)
        ingest._fsync_directory(output.parent)
    finally:
        partial.unlink(missing_ok=True)


def write_tables(recipes: dict, output: Path) -> dict:
    digest = hashlib.sha256()
    count = 0
    with atomic_output(output) as sink:
        for chunk in table_chunks(recipes):
            sink.write(chunk)
            digest.update(chunk)
            count += len(chunk)
        if count != TABLE_BYTES:
            raise ValueError("canonical public table byte count differs")
    return {"table_sha256": digest.hexdigest(), "table_bytes": count,
            "recipe_digest": recipes["recipe_digest"], "calibrated": False}


def validate_weights(report: dict, candidate: dict, packed: Path) -> None:
    if (report.get("model") != ingest.MODEL or report.get("revision") != ingest.REVISION
            or report.get("metadata_sha256") != ingest.METADATA_SHA256
            or report.get("terminal_manifest_sha256") != ingest.TERMINALS_SHA256
            or report.get("status") != "PACKED_UNADMITTED"
            or report.get("full_source_bodies_verified") is not True
            or report.get("source_sha256") != {name: spec["lfs_sha256"] for name, spec in ingest.SHARDS.items()}
            or report.get("weight_exponents_by_tensor") != candidate.get("weight_exponents_by_tensor")
            or report.get("packed_bytes") != ingest.PACKED_BYTES):
        raise ValueError("candidate does not match the pinned weight ingest report")
    if packed.stat().st_size != ingest.PACKED_BYTES:
        raise ValueError("packed model byte length differs")
    digest, count = ingest.stream_sha256(packed)
    if count != ingest.PACKED_BYTES or digest != report.get("packed_sha256"):
        raise ValueError("packed model hash differs from the ingest report")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("tables", "ledger", "run"))
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ingest-report", type=Path)
    parser.add_argument("--packed", type=Path)
    parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--timeout-seconds", type=int)
    args = parser.parse_args()
    if args.mode == "run" and (args.ingest_report is None or args.packed is None
                               or args.payload_bytes is None or args.payload_bytes <= 0
                               or args.timeout_seconds is None or args.timeout_seconds <= 0):
        parser.error("run requires --ingest-report, --packed, positive --payload-bytes and --timeout-seconds")
    if os.path.lexists(args.output):
        raise FileExistsError(f"refusing to overwrite {args.output}")
    with args.candidate.open("rb") as source:
        candidate_body = source.read(1_048_577)
    if len(candidate_body) > 1_048_576:
        raise ValueError("calibration candidate exceeds 1 MiB")
    with tempfile.TemporaryDirectory(prefix="c71-calibration-") as temporary:
        snapshot = Path(temporary) / "candidate.json"
        snapshot.write_bytes(candidate_body)
        recipes = native_recipes(args.native, snapshot)
        if args.mode == "tables":
            result = write_tables(recipes, args.output)
            print(json.dumps(result, indent=2, sort_keys=True))
            return
        if args.mode == "ledger":
            tables = Path(temporary) / "tables.bin"
            table_report = write_tables(recipes, tables)
            run = subprocess.run([str(args.native), "ledger", str(snapshot), str(tables)],
                                 capture_output=True, text=True, timeout=60, check=True)
            result = json.loads(run.stdout)
            if result["recipe_digest"] != recipes["recipe_digest"]:
                raise ValueError("ledger recipe digest differs from the frozen candidate")
            import c71_gkr_screen as gkr
            for context in result["contexts"]:
                context["rms_structural_support"] = gkr.canonical(context["rms"])
                context["rms_source_prover"] = gkr.source_prover_trace(context["rms"])
            result.update(table_report, candidate_sha256=hashlib.sha256(candidate_body).hexdigest(),
                          native_sha256=ingest.stream_sha256(args.native)[0],
                          tables_generated_by_certified_reference=True)
            with atomic_output(args.output) as sink:
                sink.write((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
            print(json.dumps(result, indent=2, sort_keys=True))
            return
        candidate = ingest._json_no_duplicates(candidate_body, "calibration candidate")
        report = ingest._json_no_duplicates(args.ingest_report.read_bytes(), "weight ingest report")
        validate_weights(report, candidate, args.packed)
        tables = Path(temporary) / "tables.bin"
        table_report = write_tables(recipes, tables)
        command = [str(args.native), "run", str(snapshot), str(tables),
                   str(args.packed), str(args.payload_bytes)]
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout_seconds)
            exit_code = native_exit_code = run.returncode
            result = {"complete_integer_trial": False, "stdout": run.stdout, "stderr": run.stderr}
            if exit_code == 0:
                try:
                    decoded = ingest._json_no_duplicates(run.stdout, "native integer trial")
                    if decoded.get("complete_integer_trial") is not True:
                        raise ValueError("native report does not complete the integer trial")
                except ValueError as error:
                    exit_code = 1
                    result["failure"] = str(error)
                else:
                    result = decoded
            else:
                result["failure"] = "native integer trial failed"
        except subprocess.TimeoutExpired as error:
            exit_code = 124
            native_exit_code = None
            result = {"complete_integer_trial": False, "failure": "integer trial deadline exceeded"}
            for name, value in (("stdout", error.stdout), ("stderr", error.stderr)):
                result[name] = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        result.update(table_report, candidate_sha256=hashlib.sha256(candidate_body).hexdigest(),
                      packed_sha256=report["packed_sha256"],
                      native_sha256=ingest.stream_sha256(args.native)[0],
                      workload_sha256=hashlib.sha256((ingest.ROOT / "manifests/c7-d126-gemma31b-workload-v1.json").read_bytes()).hexdigest(),
                      tables_generated_by_certified_reference=True,
                      packed_hash_checked=True, exit_code=exit_code, native_exit_code=native_exit_code,
                      timeout_seconds=args.timeout_seconds, credit=False)
        with atomic_output(args.output) as sink:
            sink.write((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(result, indent=2, sort_keys=True))
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

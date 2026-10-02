#!/usr/bin/env python3
"""Prepare certified public tables and replay a fixed candidate on the C7.1 workload.

This does not initialize activation scales, certify model quality, or authorize
the full CPU replay. Real ingestion and all three successful trials are needed
before a candidate can be frozen as calibrated Gamma.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

import c7_1_gemma_plan as plan
import c7_d126_gemma_weight_ingest as ingest
import c71_calibration_trace as trace_codec


TABLE_BYTES = 24_414_870


def native_recipes(native: Path, candidate: Path) -> dict:
    ingest._json_no_duplicates(candidate.read_bytes(), "calibration candidate")
    result = subprocess.run([str(native), "recipes", str(candidate)],
                            capture_output=True, timeout=60, check=True)
    return ingest._json_no_duplicates(result.stdout, "native calibration recipes")


def _validate_step_parameters(kind: str, inputs: list[int], outputs: list[int],
                              parameters: dict, old: int) -> None:
    keys = {
        "embedding": {"weight"},
        "matrix": {"weight", "input_row_offset", "decision_only"},
        "norm": {"heads", "columns", "weight", "recipe"},
        "rne": {"shift"},
        "affine": {"coefficients"},
        "gelu": {"table", "histogram"},
        "gate": set(),
        "rope": {"family", "heads", "width", "position"},
        "qk": {"groups", "repeats", "lanes"},
        "softmax": {"table", "maximum", "difference", "exponential", "denominator",
                    "probability", "histogram"},
        "pv": {"groups", "repeats", "lanes"},
        "softcap": {"table", "lower", "histogram"},
        "argmax": {"token_offset"},
    }
    arities = {
        "embedding": ({0}, 1), "matrix": ({1}, 1), "norm": ({1}, (2, 3)),
        "rne": ({1}, 1), "affine": ({1, 2}, 1), "gelu": ({1}, 2),
        "gate": ({2}, 1), "rope": ({1}, 1), "qk": ({2}, 1),
        "softmax": ({1}, 6), "pv": ({2}, 1), "softcap": ({1}, 2),
        "argmax": ({1}, 1),
    }
    output_arities = arities[kind][1]
    if (set(parameters) != keys[kind] or len(inputs) not in arities[kind][0]
            or len(outputs) not in ({output_arities} if isinstance(output_arities, int)
                                    else set(output_arities))):
        raise ValueError("native oracle plan operator shape differs")
    integer = lambda value: type(value) is int
    if kind in {"embedding", "matrix"} and not integer(parameters["weight"]):
        raise ValueError("native oracle plan weight reference differs")
    if kind == "matrix" and (not integer(parameters["input_row_offset"])
                              or parameters["input_row_offset"] < 0
                              or type(parameters["decision_only"]) is not bool):
        raise ValueError("native oracle plan matrix parameters differ")
    if kind == "norm" and (
        any(not integer(parameters[key]) or parameters[key] <= 0 for key in ("heads", "columns"))
        or (parameters["weight"] is not None and not integer(parameters["weight"]))
        or not isinstance(parameters["recipe"], list) or len(parameters["recipe"]) != 3
        or any(not integer(value) for value in parameters["recipe"])
    ):
        raise ValueError("native oracle plan norm parameters differ")
    if kind == "rne" and not integer(parameters["shift"]):
        raise ValueError("native oracle plan RNE parameters differ")
    if kind == "affine" and (not isinstance(parameters["coefficients"], list)
                              or len(parameters["coefficients"]) != 2
                              or any(not integer(value) for value in parameters["coefficients"])):
        raise ValueError("native oracle plan affine parameters differ")
    if kind == "gelu" and (
        not integer(parameters["table"]) or not 0 <= parameters["table"] < 60
        or parameters["histogram"] not in outputs
    ):
        raise ValueError("native oracle plan GELU parameters differ")
    if kind == "rope" and (
        parameters["family"] not in (0, 1) or parameters["position"] != old
        or any(not integer(parameters[key]) or parameters[key] <= 0
               for key in ("heads", "width"))
    ):
        raise ValueError("native oracle plan RoPE parameters differ")
    if kind in {"qk", "pv"} and any(
        not integer(parameters[key]) or parameters[key] <= 0
        for key in ("groups", "repeats", "lanes")
    ):
        raise ValueError("native oracle plan attention parameters differ")
    if kind == "softmax" and (
        not integer(parameters["table"]) or not 0 <= parameters["table"] < 60
        or any(not integer(parameters[key]) for key in
               ("maximum", "difference", "exponential", "denominator", "probability", "histogram"))
        or {parameters[key] for key in ("maximum", "difference", "exponential", "denominator",
                                       "probability", "histogram")} != set(outputs)
    ):
        raise ValueError("native oracle plan softmax parameters differ")
    if kind == "softcap" and (parameters["table"] != 0 or parameters["lower"] != -32767
                               or parameters["histogram"] not in outputs):
        raise ValueError("native oracle plan softcap parameters differ")
    if kind == "argmax" and parameters["token_offset"] != 100:
        raise ValueError("native oracle plan argmax parameters differ")


def _validate_oracle_plan(document: dict, recipes: dict) -> dict:
    if (set(document) != {"calibrated", "contexts", "credit",
                          "independent_numeric_execution_complete"}
            or document["calibrated"] is not False
            or document["credit"] is not False
            or document["independent_numeric_execution_complete"] is not False):
        raise ValueError("native oracle plan status differs")
    contexts = document["contexts"]
    if not isinstance(contexts, list) or len(contexts) != 3:
        raise ValueError("native oracle plan contexts differ")
    expected_kinds = {"embedding", "matrix", "norm", "rne", "affine", "gelu",
                      "gate", "rope", "qk", "softmax", "pv", "softcap", "argmax"}
    common_weights = common_sources = common_steps = None
    for old, context in zip((0, 150, 300), contexts):
        if (set(context) != {"schema", "old_tokens", "recipe_digest", "sources",
                            "weights", "kv_sources", "steps", "decision_first",
                            "decision_count", "tokens"}
                or context["schema"] != "volta-c71-calibration-oracle-plan-v1"
                or context["old_tokens"] != old
                or context["recipe_digest"] != recipes.get("recipe_digest")
                or (context["decision_first"], context["decision_count"], context["tokens"])
                != (99, 50, 150)):
            raise ValueError("native oracle plan context metadata differs")

        weights = context["weights"]
        if (not isinstance(weights, list) or len(weights) != 772
                or [row.get("id") for row in weights] != list(range(772))
                or len({row.get("name") for row in weights}) != 772):
            raise ValueError("native oracle plan weights differ")
        intervals = []
        for row in weights:
            if (set(row) != {"id", "name", "rows", "columns", "packed_offset"}
                    or not isinstance(row["name"], str) or not row["name"]
                    or any(type(row[key]) is not int or row[key] <= 0
                           for key in ("rows", "columns"))
                    or type(row["packed_offset"]) is not int or row["packed_offset"] < 0):
                raise ValueError("native oracle plan weight descriptor differs")
            intervals.append((row["packed_offset"],
                              row["packed_offset"] + row["rows"] * row["columns"]))
        cursor = 0
        for begin, end in sorted(intervals):
            if begin != cursor or end <= begin:
                raise ValueError("native oracle plan packed weight layout differs")
            cursor = end
        if cursor * 2 != ingest.PACKED_BYTES:
            raise ValueError("native oracle plan packed weight length differs")
        if common_weights is None:
            common_weights = weights
        elif weights != common_weights:
            raise ValueError("native oracle plan weights change between contexts")

        sources = context["sources"]
        if (not isinstance(sources, list) or len(sources) != 3471
                or [row.get("id") for row in sources] != list(range(3471))
                or len({row.get("name") for row in sources}) != 3471):
            raise ValueError("native oracle plan sources differ")
        for row in sources:
            if (set(row) != {"id", "name", "rows", "columns", "codec_bytes"}
                    or not isinstance(row["name"], str) or not row["name"]
                    or any(type(row[key]) is not int or row[key] <= 0
                           for key in ("rows", "columns"))
                    or row["codec_bytes"] not in (2, 4, 6)):
                raise ValueError("native oracle plan source descriptor differs")
        source_identity = [(row["id"], row["name"], row["rows"], row["codec_bytes"])
                           for row in sources]
        if common_sources is None:
            common_sources = source_identity
        elif source_identity != common_sources:
            raise ValueError("native oracle plan source identity changes between contexts")

        kv_sources = context["kv_sources"]
        if (not isinstance(kv_sources, list) or len(kv_sources) != 120
                or kv_sources != sorted(set(kv_sources))
                or any(type(source) is not int or not 0 <= source < len(sources)
                       for source in kv_sources)):
            raise ValueError("native oracle plan KV sources differ")
        steps = context["steps"]
        if not isinstance(steps, list) or len(steps) != 2328:
            raise ValueError("native oracle plan step count differs")
        produced = set()
        kinds = set()
        step_identity = []
        for step in steps:
            if set(step) != {"kind", "inputs", "outputs", "parameters"}:
                raise ValueError("native oracle plan step shape differs")
            kind, inputs, outputs, parameters = (step[key] for key in
                                                  ("kind", "inputs", "outputs", "parameters"))
            if (kind not in expected_kinds or not isinstance(inputs, list)
                    or not isinstance(outputs, list) or not outputs
                    or not isinstance(parameters, dict)
                    or any(type(source) is not int or not 0 <= source < len(sources)
                           for source in inputs + outputs)
                    or len(set(inputs)) != len(inputs) or len(set(outputs)) != len(outputs)):
                raise ValueError("native oracle plan step values differ")
            if not set(inputs) <= produced or produced.intersection(outputs):
                raise ValueError("native oracle plan is not a single-producer topological DAG")
            _validate_step_parameters(kind, inputs, outputs, parameters, old)
            for key in ("weight",):
                if key in parameters and parameters[key] is not None \
                        and not 0 <= parameters[key] < len(weights):
                    raise ValueError("native oracle plan weight reference is outside W")
            produced.update(outputs)
            kinds.add(kind)
            normalized = dict(parameters)
            if kind == "rope":
                if parameters.get("position") != old:
                    raise ValueError("native oracle plan RoPE position differs")
                normalized["position"] = 0
            step_identity.append((kind, inputs, outputs, normalized))
        if kinds != expected_kinds or produced != set(range(len(sources))):
            raise ValueError("native oracle plan producer coverage differs")
        if common_steps is None:
            common_steps = step_identity
        elif step_identity != common_steps:
            raise ValueError("native oracle plan DAG changes between contexts")
    return document


def validate_oracle_plan(document: dict, recipes: dict) -> dict:
    try:
        return _validate_oracle_plan(document, recipes)
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("native oracle plan has invalid JSON types") from error


def native_oracle_plan(native: Path, candidate: Path, recipes: dict) -> dict:
    result = subprocess.run([str(native), "oracle-plan", str(candidate)],
                            capture_output=True, timeout=60, check=True)
    document = ingest._json_no_duplicates(result.stdout, "native oracle plan")
    return validate_oracle_plan(document, recipes)


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
    parser.add_argument("mode", choices=("tables", "ledger", "run", "trace"))
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ingest-report", type=Path)
    parser.add_argument("--packed", type=Path)
    parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--trace-output", type=Path)
    args = parser.parse_args()
    if args.mode in ("run", "trace") and (
        args.ingest_report is None
        or args.packed is None
        or args.payload_bytes is None
        or args.payload_bytes <= 0
        or args.timeout_seconds is None
        or args.timeout_seconds <= 0
        or (args.mode == "trace" and args.trace_output is None)
    ):
        parser.error(
            "run/trace require --ingest-report, --packed, positive --payload-bytes and "
            "--timeout-seconds; trace also requires --trace-output"
        )
    if os.path.lexists(args.output):
        raise FileExistsError(f"refusing to overwrite {args.output}")
    if args.trace_output is not None and os.path.lexists(args.trace_output):
        raise FileExistsError(f"refusing to overwrite {args.trace_output}")
    with args.candidate.open("rb") as source:
        candidate_body = source.read(1_048_577)
    if len(candidate_body) > 1_048_576:
        raise ValueError("calibration candidate exceeds 1 MiB")
    with tempfile.TemporaryDirectory(prefix="c71-calibration-") as temporary:
        snapshot = Path(temporary) / "candidate.json"
        snapshot.write_bytes(candidate_body)
        recipes = native_recipes(args.native, snapshot)
        oracle_plan = (native_oracle_plan(args.native, snapshot, recipes)
                       if args.mode == "trace" else None)
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
        trace_context = (tempfile.TemporaryDirectory(prefix=f".{args.trace_output.name}.",
                                                     dir=args.trace_output.parent)
                         if args.mode == "trace" else nullcontext(None))
        with trace_context as trace_directory:
            trace_path = Path(trace_directory) / "trace.bin" if trace_directory else None
            native_mode = "run-trace" if args.mode == "trace" else "run"
            command = [str(args.native), native_mode, str(snapshot), str(tables),
                       str(args.packed), str(args.payload_bytes)]
            if trace_path is not None:
                command.append(str(trace_path))
            try:
                run = subprocess.run(command, capture_output=True, text=True,
                                     timeout=args.timeout_seconds)
                exit_code = native_exit_code = run.returncode
                result = {"complete_integer_trial": False, "stdout": run.stdout,
                          "stderr": run.stderr}
                if exit_code == 0:
                    try:
                        decoded = ingest._json_no_duplicates(run.stdout, "native integer trial")
                        if decoded.get("complete_integer_trial") is not True:
                            raise ValueError("native report does not complete the integer trial")
                        if trace_path is not None:
                            checked = trace_codec.validate(trace_path, oracle_plan=oracle_plan)
                            native_trace = decoded.get("trace")
                            keys = ("format", "bytes", "records", "logical_words", "stored_words",
                                    "final_kv_sources", "blake3_before_footer")
                            if not isinstance(native_trace, dict) or any(
                                native_trace.get(key) != checked.get(key) for key in keys
                            ) or checked.get("recipe_digest") != recipes.get("recipe_digest"):
                                raise ValueError("native and independent trace censuses differ")
                            decoded["trace_validation"] = checked
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
                result = {"complete_integer_trial": False,
                          "failure": "integer trial deadline exceeded"}
                for name, value in (("stdout", error.stdout), ("stderr", error.stderr)):
                    result[name] = (value.decode("utf-8", errors="replace")
                                    if isinstance(value, bytes) else value or "")
            result.update(table_report, candidate_sha256=hashlib.sha256(candidate_body).hexdigest(),
                          packed_sha256=report["packed_sha256"],
                          native_sha256=ingest.stream_sha256(args.native)[0],
                          workload_sha256=hashlib.sha256((ingest.ROOT / "manifests/c7-d126-gemma31b-workload-v1.json").read_bytes()).hexdigest(),
                          tables_generated_by_certified_reference=True,
                          packed_hash_checked=True, exit_code=exit_code,
                          native_exit_code=native_exit_code,
                          timeout_seconds=args.timeout_seconds, credit=False)
            published_trace = False
            try:
                if trace_path is not None and exit_code == 0:
                    os.chmod(trace_path, 0o600)
                    os.link(trace_path, args.trace_output)
                    published_trace = True
                    ingest._fsync_directory(args.trace_output.parent)
                with atomic_output(args.output) as sink:
                    sink.write((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
            except BaseException:
                if published_trace:
                    args.trace_output.unlink()
                    ingest._fsync_directory(args.trace_output.parent)
                raise
    print(json.dumps(result, indent=2, sort_keys=True))
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

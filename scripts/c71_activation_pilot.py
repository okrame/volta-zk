#!/usr/bin/env python3
"""Floating activation initializer over the native C7.1 semantic DAG.

Uses dequantized packed W and the pinned workload, with bounded weight blocks
and causal KV. This pilot proposes Gamma; only a subsequent exact integer run
can validate it. It is neither BF16 model equivalence nor a proof benchmark.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import hashlib
import io
import json
import math
import mmap
import os
from pathlib import Path
import subprocess
import threading
import time

import numpy as np

import c71_calibrate as calibration


def exponent_for_maximum(maximum: float) -> int:
    if not math.isfinite(maximum) or maximum < 0:
        raise ValueError("activation magnitude must be finite and nonnegative")
    if maximum == 0:
        return 0
    numerator, denominator = maximum.as_integer_ratio()
    exponent = numerator.bit_length() - denominator.bit_length() - 15
    while True:
        top, bottom = numerator, denominator
        if exponent < 0:
            top <<= -exponent
        else:
            bottom <<= exponent
        quotient, remainder = divmod(top, bottom)
        rounded = quotient + int(2 * remainder > bottom or
                                 (2 * remainder == bottom and quotient % 2))
        if rounded <= 32767:
            return exponent
        exponent += 1


def work_plan(description, matrix_workers=1):
    graph = description["pilot"]
    tensors = description["weight_sources"]
    reads = products = block_cells = 0
    for step in graph["steps"]:
        parameters = step["parameters"]
        tokens = graph["responses"] * (graph["decision_count"] if parameters.get("decision_only")
                                        else graph["tokens_per_response"])
        weight = parameters.get("weight")
        if weight is None:
            continue
        source = tensors[weight]
        rows = source["rows"] if step["operation"] == "matrix" else 1
        reads += tokens * rows * source["columns"] * 2
        block_cells = max(block_cells, min(rows, 128) * source["columns"])
        if step["operation"] == "matrix":
            products += tokens * rows * source["columns"]
    columns = {source["id"]: source["columns"] for source in description["activation_sources"]}
    kv = sum(columns[source] for source in graph["kv_sources"])
    return dict(calibrated=False, credit=False, floating_initialization_only=True,
                logical_weight_read_bytes=reads, matrix_scalar_products=products,
                weight_block_i16_plus_f64_payload_bytes=10 * block_cells,
                matrix_workers=matrix_workers,
                simultaneous_weight_blocks_payload_bytes=10 * block_cells * matrix_workers,
                final_f64_kv_payload_bytes=8 * kv * graph["responses"] * graph["tokens_per_response"],
                physical_disk_bytes=None, complete_physical_peak=None, runtime_seconds=None)


class PackedWeights:
    def __init__(self, source, descriptors, exponents):
        self.source = source
        self.descriptors = descriptors
        self.exponents = exponents
        self.bytes_read = 0
        self.block_read_validate_seconds = 0.0
        self.block_convert_seconds = 0.0
        self.read_lock = threading.Lock()
        expected = 0
        for descriptor in sorted(descriptors, key=lambda value: value["packed_offset"]):
            if (descriptor["packed_offset"] != expected or descriptor["rows"] <= 0
                    or descriptor["columns"] <= 0):
                raise ValueError("pilot weight layout differs")
            expected += descriptor["rows"] * descriptor["columns"]
        source.seek(0, 2)
        if source.tell() != 2 * expected or not descriptors:
            raise ValueError("pilot packed weight byte length differs")
        if set(exponents) != {descriptor["name"] for descriptor in descriptors}:
            raise ValueError("pilot weight exponent names differ")
        if any(type(value) is not int or not -128 <= value <= 128 for value in exponents.values()):
            raise ValueError("pilot weight exponent outside native envelope")
        self.mapping = None
        try:
            descriptor = source.fileno()
        except (AttributeError, io.UnsupportedOperation):
            pass
        else:
            self.mapping = mmap.mmap(descriptor, 0, access=mmap.ACCESS_READ)

    def block(self, tensor, first, count):
        started = time.monotonic()
        if not 0 <= tensor < len(self.descriptors):
            raise ValueError("pilot weight tensor missing")
        descriptor = self.descriptors[tensor]
        if first < 0 or count <= 0 or first + count > descriptor["rows"]:
            raise ValueError("pilot weight row outside tensor")
        columns = descriptor["columns"]
        offset = 2 * (descriptor["packed_offset"] + first * columns)
        if self.mapping is None:
            with self.read_lock:
                self.source.seek(offset)
                body = calibration.ingest._read_exact(self.source, 2 * count * columns, "pilot W")
            values = np.frombuffer(body, dtype="<i2").reshape(count, columns)
        else:
            values = np.frombuffer(self.mapping, dtype="<i2", count=count * columns,
                                   offset=offset).reshape(count, columns)
        if np.any(values == -32768):
            raise ValueError("pilot weight outside symmetric i16")
        with self.read_lock:
            self.bytes_read += 2 * count * columns
            self.block_read_validate_seconds += time.monotonic() - started
        started = time.monotonic()
        converted = values.astype(np.float64)
        np.ldexp(converted, self.exponents[descriptor["name"]], out=converted)
        with self.read_lock:
            self.block_convert_seconds += time.monotonic() - started
        return converted


class Pilot:
    def __init__(self, description, weights, deadline, matrix_executor=None, progress=None):
        self.description = description
        self.graph = description["pilot"]
        self.weights = weights
        self.deadline = deadline
        self.matrix_executor = matrix_executor
        self.progress = progress
        self.started_at = time.monotonic()
        self.last_progress = -math.inf
        self.location = dict(context=None, token_index=None, step_index=None, operation=None)
        self.operator_timings = {}
        self.completed_tokens = 0
        self.matrix_dot_seconds = 0.0
        self.current = {}
        self.history = {source: [] for source in self.graph["kv_sources"]}
        self.extents = {}
        self.history_bytes = 0
        self.retained_bytes_peak = 0
        self.matrix_scalar_products = 0
        self.coefficients = {}
        self.started = False
        last = {}
        for index, step in enumerate(self.graph["steps"]):
            for source in step["inputs"]:
                last[source] = index
        self.release = [[] for _ in self.graph["steps"]]
        for source, index in last.items():
            self.release[index].append(source)

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("activation pilot deadline exceeded")

    def metrics(self):
        elapsed = time.monotonic() - self.started_at
        return dict(**self.location, elapsed_seconds=elapsed, completed_tokens=self.completed_tokens,
                    tokens_per_second=self.completed_tokens / elapsed if elapsed else 0,
                    matrix_scalar_products=self.matrix_scalar_products,
                    matrix_products_per_second=self.matrix_scalar_products / elapsed if elapsed else 0,
                    weight_read_bytes=self.weights.bytes_read,
                    block_read_validate_worker_seconds=self.weights.block_read_validate_seconds,
                    block_convert_worker_seconds=self.weights.block_convert_seconds,
                    matrix_dot_worker_seconds=self.matrix_dot_seconds,
                    history_payload_bytes=self.history_bytes,
                    retained_payload_peak_bytes=self.retained_bytes_peak,
                    complete_physical_peak=False)

    def emit_progress(self, state, force=False):
        now = time.monotonic()
        if self.progress is not None and (force or now - self.last_progress >= 1):
            self.progress.write(json.dumps(dict(state=state, **self.metrics()), sort_keys=True) + "\n")
            self.progress.flush()
            os.fsync(self.progress.fileno())
            self.last_progress = now

    def evaluate(self, step, token, position):
        operation = step["operation"]
        parameters = step["parameters"]
        inputs = [self.current[source] for source in step["inputs"]]
        if operation == "embedding":
            return self.weights.block(parameters["weight"], token, 1)[0]
        if operation == "matrix":
            tensor = parameters["weight"]
            rows = self.weights.descriptors[tensor]["rows"]
            result = np.empty(rows, dtype=np.float64)
            def multiply(first):
                self.check_deadline()
                count = min(128, rows - first)
                with np.errstate(over="raise", invalid="raise", divide="raise"):
                    block = self.weights.block(tensor, first, count)
                    started = time.monotonic()
                    values = block @ inputs[0]
                    return first, values, time.monotonic() - started
            blocks = range(0, rows, 128)
            products = (map(multiply, blocks) if self.matrix_executor is None
                        else self.matrix_executor.map(multiply, blocks))
            for first, values, seconds in products:
                result[first:first + len(values)] = values
                self.matrix_scalar_products += len(values) * inputs[0].size
                self.matrix_dot_seconds += seconds
                self.emit_progress("matrix_block")
            return result
        if operation == "norm":
            values = inputs[0].reshape(parameters["heads"], parameters["columns"])
            result = values / np.sqrt(np.mean(values * values, axis=1, keepdims=True) + 1e-6)
            if parameters["weight"] is not None:
                result = result * self.weights.block(parameters["weight"], 0, 1)[0]
            return result.ravel()
        if operation == "affine":
            if parameters["scale"] is None:
                return inputs[0] + inputs[1]
            multiplier, exponent = parameters["scale"]
            return inputs[0] * math.ldexp(multiplier, exponent)
        if operation == "gelu":
            values = inputs[0]
            return 0.5 * values * (1 + np.tanh(math.sqrt(2 / math.pi) *
                                              (values + 0.044715 * values**3)))
        if operation == "gate":
            return inputs[0] * inputs[1]
        if operation == "rope":
            family = parameters["family"]
            key = (family, position)
            if key not in self.coefficients:
                self.coefficients[key] = np.ldexp(np.array(
                    calibration.plan.gemma_rope_q30_coefficients(("local", "global")[family], position),
                    dtype=np.float64), -30)
            pairs = self.coefficients[key]
            values = inputs[0].reshape(parameters["heads"], parameters["width"])
            half = parameters["width"] // 2
            active = min(len(pairs), half)
            first, second = values[:, :active], values[:, half:half + active]
            result = values.copy()
            result[:, :active] = pairs[:active, 0] * first - pairs[:active, 1] * second
            result[:, half:half + active] = pairs[:active, 1] * first + pairs[:active, 0] * second
            return result.ravel()
        if operation in ("qk", "pv"):
            groups, repeats, lanes = (parameters[name] for name in ("groups", "repeats", "lanes"))
            history = self.history[step["inputs"][1]]
            if len(history) != position + 1:
                raise ValueError("pilot KV is not the current causal prefix")
            values = np.stack(history).reshape(position + 1, groups, lanes)
            if operation == "qk":
                queries = inputs[0].reshape(groups, repeats, lanes)
                return np.einsum("grd,tgd->grt", queries, values).reshape(groups * repeats, position + 1)
            probabilities = inputs[0].reshape(groups, repeats, position + 1)
            return np.einsum("grt,tgd->grd", probabilities, values).ravel()
        if operation == "softmax":
            values = np.exp(inputs[0] - np.max(inputs[0], axis=1, keepdims=True))
            return values / np.sum(values, axis=1, keepdims=True)
        if operation == "softcap":
            return 30 * np.tanh(inputs[0] / 30)
        if operation == "argmax":
            return int(np.argmax(inputs[0]))
        raise ValueError(f"unknown pilot operation: {operation}")

    def run(self, prompt):
        if self.started:
            raise ValueError("activation pilot already used; discard its partial state")
        self.started = True
        tokens_per_response = self.graph["tokens_per_response"]
        first = self.graph["decision_first"]
        count = self.graph["decision_count"]
        if len(prompt) != first + 1 or first + count + 1 != tokens_per_response:
            raise ValueError("pilot prompt/decision/final-absorption geometry differs")
        responses = []
        for slot in range(self.graph["responses"]):
            tokens = list(prompt) + [0] * count
            for index in range(tokens_per_response):
                position = slot * tokens_per_response + index
                self.coefficients.clear()
                decision = None
                for step_index, step in enumerate(self.graph["steps"]):
                    self.location = dict(context=slot * tokens_per_response, token_index=index,
                                         step_index=step_index, operation=step["operation"])
                    self.emit_progress("before_operator")
                    self.check_deadline()
                    active = first <= index < first + count
                    if not step["parameters"].get("decision_only", False) or active:
                        started = time.monotonic()
                        timing = self.operator_timings.setdefault(str(step_index), dict(
                            operation=step["operation"], calls=0, failures=0, wall_seconds=0.0))
                        try:
                            value = self.evaluate(step, tokens[index], position)
                        except BaseException:
                            timing["failures"] += 1
                            raise
                        else:
                            timing["calls"] += 1
                        finally:
                            timing["wall_seconds"] += time.monotonic() - started
                        output = step["output"]
                        if output is None:
                            if decision is not None:
                                raise ValueError("pilot token has two decisions")
                            decision = value
                        else:
                            if value.size == 0 or not np.isfinite(value).all():
                                raise ValueError(f"nonfinite/empty pilot source {output}")
                            lower, upper = float(value.min()), float(value.max())
                            extent = self.extents.setdefault(output, dict(minimum=lower, maximum=upper, words=0))
                            extent["minimum"] = min(extent["minimum"], lower)
                            extent["maximum"] = max(extent["maximum"], upper)
                            extent["words"] += value.size
                            if output in self.history:
                                if len(self.history[output]) != position:
                                    raise ValueError("pilot KV produced twice or out of order")
                                self.history[output].append(value)
                                self.history_bytes += value.nbytes
                            self.current[output] = value
                            retained = self.history_bytes + sum(row.nbytes for row in self.current.values())
                            self.retained_bytes_peak = max(self.retained_bytes_peak, retained)
                    for source in self.release[step_index]:
                        self.current.pop(source, None)
                if active != (decision is not None) or self.current:
                    raise ValueError("pilot causal decision or last-consumer release differs")
                if decision is not None:
                    tokens[index + 1] = decision
                self.completed_tokens += 1
                self.emit_progress("token_complete", force=True)
            responses.append(tokens)
        expected = {source["id"] for source in self.description["activation_sources"]}
        if set(self.extents) != expected:
            raise ValueError("pilot did not observe every semantic source")
        exponents = {str(source): exponent_for_maximum(max(abs(extent["minimum"]), abs(extent["maximum"]))) +
                     int(extent["minimum"] != 0 or extent["maximum"] != 0)
                     for source, extent in self.extents.items()}
        embedding = self.graph["steps"][0]["parameters"]["weight"]
        exponents["0"] = self.weights.exponents[self.weights.descriptors[embedding]["name"]]
        exponents.update(self.description["fixed_pi_exponents"])
        if any(not -128 <= exponent <= 128 for exponent in exponents.values()):
            raise ValueError("pilot activation scale exceeds the native envelope")
        return dict(weight_exponents_by_tensor=self.weights.exponents, activation_exponents_by_source=exponents), dict(
            calibrated=False, integer_replay_required=True, floating_initialization_only=True,
            responses=responses, extents=self.extents, weight_read_bytes=self.weights.bytes_read,
            matrix_scalar_products=self.matrix_scalar_products, history_payload_bytes=self.history_bytes,
            retained_payload_peak_bytes=self.retained_bytes_peak, complete_physical_peak=False,
            scale_rule="minimum RNE-fit exponent of observed binary64 extrema plus one headroom bit; embedding/Pi fixed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--ingest-report", type=Path)
    parser.add_argument("--packed", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--matrix-workers", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.matrix_workers <= 20:
        parser.error("--matrix-workers must be between 1 and 20")
    description = json.loads(subprocess.run([str(args.native), "describe"], capture_output=True,
                                            text=True, timeout=60, check=True).stdout)
    if args.mode == "plan":
        print(json.dumps(work_plan(description, args.matrix_workers), indent=2, sort_keys=True))
        return
    if (args.timeout_seconds is None or args.timeout_seconds <= 0 or args.ingest_report is None
            or args.packed is None or args.output is None):
        parser.error("run needs --ingest-report, --packed, --output and positive --timeout-seconds")
    args.output.mkdir(mode=0o700)
    result = dict(calibrated=False, floating_initialization_only=True, complete=False, credit=False)
    pilot = None
    progress = open(args.output / "progress.jsonl", "x", opener=lambda path, flags: os.open(path, flags, 0o600))
    try:
        report_body = args.ingest_report.read_bytes()
        report = calibration.ingest._json_no_duplicates(report_body, "weight ingest report")
        workload_body = (calibration.ingest.ROOT / "manifests/c7-d126-gemma31b-workload-v1.json").read_bytes()
        result.update(ingest_report_sha256=hashlib.sha256(report_body).hexdigest(),
                      native_sha256=calibration.ingest.stream_sha256(args.native)[0],
                      numpy_version=np.__version__, planned_work=work_plan(description, args.matrix_workers),
                      workload_sha256=hashlib.sha256(workload_body).hexdigest(),
                      timeout_seconds=args.timeout_seconds)
        weights = report["weight_exponents_by_tensor"]
        calibration.validate_weights(report, {"weight_exponents_by_tensor": weights}, args.packed)
        result.update(packed_sha256=report["packed_sha256"], packed_hash_checked=True)
        workload = json.loads(workload_body)
        with args.packed.open("rb") as source, np.errstate(over="raise", invalid="raise", divide="raise"):
            reader = PackedWeights(source, description["weight_sources"], weights)
            result.update(weight_access="readonly_mmap" if reader.mapping is not None else "stream",
                          immutable_weight_mapping_bytes=len(reader.mapping) if reader.mapping is not None else 0)
            executor = (ThreadPoolExecutor(max_workers=args.matrix_workers)
                        if args.matrix_workers > 1 else nullcontext(None))
            with executor as pool:
                pilot = Pilot(description, reader, time.monotonic() + args.timeout_seconds, pool, progress)
                candidate, observations = pilot.run(workload["prompt"]["token_ids"])
        result.update(observations, complete=True)
        candidate_path = args.output / "candidate.json"
        candidate_body = json.dumps(candidate, indent=2, sort_keys=True) + "\n"
        candidate_path.write_text(candidate_body)
        result["candidate_sha256"] = hashlib.sha256(candidate_body.encode()).hexdigest()
        compiled = subprocess.run([str(args.native), "recipes", str(candidate_path)],
                                  capture_output=True, text=True, timeout=60)
        result.update(candidate_compiles=compiled.returncode == 0, compiler_stderr=compiled.stderr)
        if compiled.returncode:
            raise ValueError("observed candidate does not compile; inspect the preserved observations")
    except Exception as error:
        result.update(error=str(error), success=False)
        raise
    else:
        result["success"] = True
    finally:
        if pilot is not None:
            pilot.emit_progress("complete" if result.get("success") else "failed", force=True)
            result.update(progress=pilot.metrics(), operator_timings=pilot.operator_timings)
        progress.close()
        with open(args.output / "report.json", "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as sink:
            json.dump(result, sink, indent=2, sort_keys=True)
            sink.write("\n")


if __name__ == "__main__":
    main()

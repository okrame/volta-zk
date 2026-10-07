#!/usr/bin/env python3
"""Independent streaming producer for exact C7.1 calibration trace frames."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import time

import numpy as np

import c7_1_gemma_plan as reference
import c7_d126_gemma_weight_ingest as ingest
import c71_calibration_oracle as numeric
import c71_calibration_trace as trace


LOOKUP_ENTRIES = 65_535


def pinned_prompt() -> list[int]:
    workload = ingest._json_no_duplicates(
        (ingest.ROOT / "manifests/c7-d126-gemma31b-workload-v1.json").read_bytes(),
        "calibration workload",
    )
    prompt = workload.get("prompt", {}).get("token_ids")
    if (not isinstance(prompt, list) or len(prompt) != 100
            or any(type(token) is not int or not 0 <= token < 262_144 for token in prompt)
            or hashlib.sha256(struct.pack("<100I", *prompt)).hexdigest()
            != workload["prompt"].get("token_ids_u32le_sha256")):
        raise ValueError("calibration pinned prompt differs")
    return prompt


class Tables:
    def __init__(self, path: Path):
        if path.stat().st_size != 24_414_870:
            raise ValueError("oracle public table byte length differs")
        self.gelu_bytes = 60 * LOOKUP_ENTRIES * 2
        self.exp_bytes = 60 * LOOKUP_ENTRIES * 4
        self.softcap_offset = self.gelu_bytes + self.exp_bytes
        self.body = np.memmap(path, dtype=np.uint8, mode="r")
        self._gelu = {}
        self._exp30 = {}

    def gelu(self, index: int):
        if index not in self._gelu:
            self._gelu[index] = np.ndarray(LOOKUP_ENTRIES, dtype="<i2", buffer=self.body,
                                           offset=index * LOOKUP_ENTRIES * 2)
        return self._gelu[index]

    def exp30(self, index: int):
        if index not in self._exp30:
            self._exp30[index] = np.ndarray(
                LOOKUP_ENTRIES, dtype="<i4", buffer=self.body,
                offset=self.gelu_bytes + index * LOOKUP_ENTRIES * 4)
        return self._exp30[index]

    def softcap(self):
        return np.ndarray(LOOKUP_ENTRIES, dtype="<i2", buffer=self.body,
                          offset=self.softcap_offset)


def _rne(values, shift: int) -> np.ndarray:
    values = np.asarray(values, dtype=np.int64)
    if shift >= 48:
        result = np.zeros(values.shape, dtype=np.int64)
    elif shift <= -15:
        if np.any(values):
            raise ValueError("oracle RNE overflows symmetric i16")
        result = np.zeros(values.shape, dtype=np.int64)
    elif shift <= 0:
        result = values * (1 << -shift)
    else:
        divisor = 1 << shift
        quotient = np.floor_divide(values, divisor)
        remainder = values - quotient * divisor
        result = quotient + ((2 * remainder > divisor)
                             | ((2 * remainder == divisor) & ((quotient & 1) != 0)))
    if np.any(result < -32767) or np.any(result > 32767):
        raise ValueError("oracle RNE output is outside symmetric i16")
    return result


def _encode_signed(values, width: int, *, allow_i16_minimum=False) -> bytes:
    values = np.ascontiguousarray(values, dtype=np.int64).reshape(-1)
    bound = 1 << (8 * width - 1)
    if (not 1 <= width <= 8 or np.any(values < -bound) or np.any(values >= bound)
            or (width == 2 and not allow_i16_minimum and np.any(values == -32768))):
        raise ValueError("oracle frame value exceeds original codec")
    if width in (1, 2, 4, 8):
        return values.astype(f"<i{width}").tobytes()
    little = values.astype("<i8", copy=False).view(np.uint8).reshape(-1, 8)
    return little[:, :width].copy().tobytes()


class Driver:
    def __init__(self, oracle_plan: dict, packed: Path, tables: Path, prompt=None):
        self.plan = oracle_plan
        self.weights = oracle_plan["contexts"][0]["weights"]
        if packed.stat().st_size != ingest.PACKED_BYTES:
            raise ValueError("oracle packed W byte length differs")
        self.packed = np.memmap(packed, dtype="<i2", mode="r")
        self.tables = Tables(tables)
        self.prompt = pinned_prompt() if prompt is None else list(prompt)
        if (len(self.prompt) != 100
                or any(type(token) is not int or not 0 <= token < 262_144
                       for token in self.prompt)):
            raise ValueError("oracle prompt length differs")
        self.kv = {}
        self.frame_count = 0
        self.logical_words = 0
        self.matrix_products = 0
        self.started = time.monotonic()
        self.report = None
        self.plan_sha256 = hashlib.sha256(json.dumps(
            oracle_plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.schedule_audit = ([self._audit_schedule(context) for context in oracle_plan["contexts"]]
                               if all("steps" in context for context in oracle_plan["contexts"])
                               else None)

    def _weight(self, identifier: int) -> np.ndarray:
        source = self.weights[identifier]
        first = source["packed_offset"]
        return self.packed[first:first + source["rows"] * source["columns"]].reshape(
            source["rows"], source["columns"])

    def _matrix(self, identifier: int, values) -> np.ndarray:
        weight = self._weight(identifier)
        output = numeric.matrix_i16(weight, values)
        self.matrix_products += weight.size
        return output

    def _matrix_blas(self, identifier: int, values) -> np.ndarray:
        """Retained exact-binary64 reference for parity and timing screens."""
        weight = self._weight(identifier)
        values = np.asarray(values, dtype=np.int64).reshape(-1)
        if weight.shape[1] != values.size or np.any(values < -32767) or np.any(values > 32767):
            raise ValueError("oracle matrix input shape/range differs")
        if weight.shape[1] * 32767**2 >= 1 << 53:
            raise ValueError("oracle matrix exact-binary64 bound exceeded")
        output = np.empty(weight.shape[0], dtype=np.int64)
        floating_values = values.astype(np.float64)
        for first in range(0, weight.shape[0], 2048):
            block = weight[first:first + 2048]
            if np.any(block == -32768):
                raise ValueError("oracle matrix weight contains i16 minimum")
            computed = block.astype(np.float64) @ floating_values
            if not np.isfinite(computed).all() or not np.equal(computed, np.rint(computed)).all():
                raise ArithmeticError("oracle matrix binary64 result is not an exact integer")
            output[first:first + len(block)] = computed.astype(np.int64)
        self.matrix_products += weight.size
        return output

    @staticmethod
    def _lookup(table, entries, label: str):
        entries = np.asarray(entries, dtype=np.int64)
        if np.any(entries < 0) or np.any(entries >= len(table)):
            raise ValueError(f"oracle {label} lookup input differs")
        return table[entries]

    @staticmethod
    def _rows(step: dict, sources: list[dict], token: int, first: int, count: int):
        kind = step["kind"]
        output = step["outputs"][-1] if kind == "norm" else step["outputs"][0]
        if kind in {"qk", "softmax"} or (kind == "rne" and sources[output]["rows"] == 8192):
            return (head * 256 + token for head in range(32))
        if (kind in {"softcap", "argmax"}
                or (kind == "matrix" and step["parameters"]["decision_only"])
                or (kind == "rne" and sources[output]["rows"] == count)):
            return (token - first,) if first <= token < first + count else ()
        return (token,) if token < sources[output]["rows"] else ()

    @classmethod
    def _audit_schedule(cls, context: dict) -> dict:
        sources = context["sources"]
        weights = context["weights"]
        covered = [bytearray(source["rows"]) for source in sources]

        def require(condition):
            if not condition:
                raise ValueError("oracle plan operator geometry differs")

        for step in context["steps"]:
            kind, inputs, outputs, parameters = (step[key] for key in
                                                  ("kind", "inputs", "outputs", "parameters"))
            if kind == "embedding":
                weight, output = weights[parameters["weight"]], sources[outputs[0]]
                require(weight["rows"] >= 262_144 and weight["columns"] == output["columns"]
                        and output["rows"] == 150)
            elif kind == "matrix":
                weight, source, output = (weights[parameters["weight"]], sources[inputs[0]],
                                          sources[outputs[0]])
                require(weight["rows"] == output["columns"]
                        and weight["columns"] == source["columns"]
                        and parameters["input_row_offset"] + output["rows"] <= source["rows"])
            elif kind == "norm":
                source, output = sources[inputs[0]], sources[outputs[-1]]
                heads, columns = parameters["heads"], parameters["columns"]
                require(source["columns"] == output["columns"] == heads * columns)
                expanded = outputs[:-1]
                require(all(sources[item]["rows"] == output["rows"] * heads for item in expanded)
                        and all(sources[item]["columns"] in (1, columns) for item in expanded))
                if parameters["weight"] is not None:
                    weight = weights[parameters["weight"]]
                    require((weight["rows"], weight["columns"]) == (1, columns))
            elif kind in {"rne", "affine", "gate"}:
                output = sources[outputs[0]]
                require(all((sources[item]["rows"], sources[item]["columns"])
                            == (output["rows"], output["columns"]) for item in inputs))
            elif kind in {"gelu", "softcap"}:
                source, output, histogram = (sources[inputs[0]], sources[outputs[0]],
                                             sources[parameters["histogram"]])
                require((source["rows"], source["columns"])
                        == (output["rows"], output["columns"])
                        and (histogram["rows"], histogram["columns"]) == (1, LOOKUP_ENTRIES))
            elif kind == "rope":
                source, output = sources[inputs[0]], sources[outputs[0]]
                require(source["rows"] == output["rows"]
                        and source["columns"] == output["columns"]
                        == parameters["heads"] * parameters["width"])
            elif kind == "qk":
                q, k, output = sources[inputs[0]], sources[inputs[1]], sources[outputs[0]]
                require(parameters["groups"] * parameters["repeats"] == 32
                        and q["columns"] == 32 * parameters["lanes"]
                        and k["columns"] == parameters["groups"] * parameters["lanes"]
                        and (output["rows"], output["columns"])
                        == (8192, context["old_tokens"] + 150))
            elif kind == "softmax":
                score = sources[inputs[0]]
                wide = [parameters[key] for key in
                        ("difference", "exponential", "probability")]
                scalar = [parameters[key] for key in ("maximum", "denominator")]
                require((score["rows"], score["columns"])
                        == (8192, context["old_tokens"] + 150)
                        and all((sources[item]["rows"], sources[item]["columns"])
                                == (score["rows"], score["columns"]) for item in wide)
                        and all((sources[item]["rows"], sources[item]["columns"])
                                == (score["rows"], 1) for item in scalar)
                        and (sources[parameters["histogram"]]["rows"],
                             sources[parameters["histogram"]]["columns"])
                        == (1, LOOKUP_ENTRIES))
            elif kind == "pv":
                probability, value, output = (sources[inputs[0]], sources[inputs[1]],
                                              sources[outputs[0]])
                require(parameters["groups"] * parameters["repeats"] == 32
                        and (probability["rows"], probability["columns"])
                        == (8192, context["old_tokens"] + 150)
                        and value["columns"] == parameters["groups"] * parameters["lanes"]
                        and (output["rows"], output["columns"])
                        == (150, 32 * parameters["lanes"]))
            elif kind == "argmax":
                source, output = sources[inputs[0]], sources[outputs[0]]
                require((source["rows"], source["columns"])
                        == (output["rows"], output["columns"])
                        and output["rows"] == context["decision_count"])

        def mark(source: int, first: int, rows: int):
            target = covered[source]
            if rows <= 0 or first < 0 or first + rows > len(target) \
                    or any(target[first:first + rows]):
                raise ValueError("oracle plan schedule overlaps or leaves source bounds")
            target[first:first + rows] = b"\1" * rows

        histograms = set()
        for token in range(150):
            for step in context["steps"]:
                kind = step["kind"]
                for row in cls._rows(step, sources, token, context["decision_first"],
                                     context["decision_count"]):
                    outputs, parameters = step["outputs"], step["parameters"]
                    if kind == "norm":
                        heads = parameters["heads"]
                        if parameters["weight"] is None:
                            mark(outputs[0], row * heads, heads)
                            mark(outputs[1], row, 1)
                        else:
                            mark(outputs[0], row * heads, heads)
                            mark(outputs[1], row * heads, heads)
                            mark(outputs[2], row, 1)
                    elif kind in {"gelu", "softcap"}:
                        mark(outputs[0], row, 1)
                        histograms.add(parameters["histogram"])
                    elif kind == "softmax":
                        for key in ("maximum", "difference", "exponential", "denominator",
                                    "probability"):
                            mark(parameters[key], row, 1)
                        histograms.add(parameters["histogram"])
                    else:
                        mark(outputs[0], row, 1)
        for source in cls._padding(context):
            for block in range(32):
                mark(source, block * 256 + 150, 106)
        for source in histograms:
            mark(source, 0, 1)
        if any(any(value == 0 for value in rows) for rows in covered):
            raise ValueError("oracle plan schedule coverage differs")
        if any(sources[source]["codec_bytes"] != 2 for source in context["kv_sources"]):
            raise ValueError("oracle plan KV codec differs")
        return {"sources": len(sources), "coverage_complete": True}

    def _context(self, slot: int, context: dict):
        old = context["old_tokens"]
        sources = context["sources"]
        kv_sources = set(context["kv_sources"])
        consumed = {source for step in context["steps"] for source in step["inputs"]}
        last_use = {}
        for index, step in enumerate(context["steps"]):
            for source in step["inputs"]:
                last_use[source] = index
        release = [[] for _ in context["steps"]]
        for source, index in last_use.items():
            release[index].append(source)
        current = [dict() for _ in sources]
        histograms = {}
        coverage = [0] * len(sources)
        tokens = self.prompt + [0] * 50

        def get(source: int, row: int):
            if source in kv_sources:
                try:
                    return self.kv[source][old + row]
                except (IndexError, KeyError) as error:
                    raise ValueError("oracle current KV read precedes producer") from error
            try:
                return current[source][row]
            except KeyError as error:
                raise ValueError("oracle activation read precedes producer or follows release") from error

        def store(source: int, first_row: int, values: np.ndarray):
            columns = sources[source]["columns"]
            rows = values.reshape(-1, columns)
            if source in kv_sources:
                if source not in self.kv:
                    self.kv[source] = np.empty((450, columns), dtype=np.int16)
                destination = self.kv[source][old + first_row:old + first_row + len(rows)]
                if destination.shape != rows.shape:
                    raise ValueError("oracle KV destination shape differs")
                destination[:] = rows
            elif source in consumed:
                for offset, row_values in enumerate(rows):
                    if first_row + offset in current[source]:
                        raise ValueError("oracle activation row produced twice")
                    current[source][first_row + offset] = row_values.copy()

        for token in range(150):
            next_token = None
            for step_index, step in enumerate(context["steps"]):
                for row in self._rows(step, sources, token, context["decision_first"],
                                      context["decision_count"]):
                    values, histogram, decision = self._evaluate(
                        context, step, row, tokens[token], get)
                    if decision is not None:
                        if next_token is not None:
                            raise ValueError("oracle token has two decisions")
                        next_token = decision
                    for source, first_row, body in values:
                        body = np.asarray(body, dtype=np.int64).reshape(-1)
                        columns = sources[source]["columns"]
                        if not body.size or body.size % columns:
                            raise ValueError("oracle output shape differs")
                        rows = body.size // columns
                        payload = _encode_signed(
                            body, sources[source]["codec_bytes"],
                            allow_i16_minimum=sources[source]["name"] == "U/global/argmax_slack")
                        yield (trace.VALUES, slot, sources[source]["codec_bytes"], source,
                               first_row, rows, columns, 1, payload)
                        self.frame_count += 1
                        self.logical_words += body.size
                        coverage[source] += body.size
                        store(source, first_row, body)
                    if histogram is not None:
                        source, entries = histogram
                        if source not in histograms:
                            histograms[source] = np.zeros(sources[source]["columns"], dtype=np.uint64)
                        entries = np.asarray(entries, dtype=np.int64)
                        if np.any(entries < 0) or np.any(entries >= len(histograms[source])):
                            raise ValueError("oracle histogram entry differs")
                        np.add.at(histograms[source], entries, 1)
                for source in release[step_index]:
                    current[source].clear()
            if (99 <= token < 149) != (next_token is not None):
                raise ValueError("oracle causal decision count differs")
            if next_token is not None:
                tokens[token + 1] = next_token
            if any(current[source] for source in range(len(sources)) if source not in kv_sources):
                raise ValueError("oracle live activation survived its final consumer")

        padding = self._padding(context)
        histogram_padding = 32 * 106 * (old + 150)
        softmax_histograms = {step["parameters"]["histogram"] for step in context["steps"]
                              if step["kind"] == "softmax"}
        for source, descriptor in enumerate(sources):
            if source in padding:
                value = padding[source]
                payload = _encode_signed([value], descriptor["codec_bytes"])
                yield (trace.PADDING, slot, descriptor["codec_bytes"], source, 150, 106,
                       descriptor["columns"], 32, payload)
                self.frame_count += 1
                words = 32 * 106 * descriptor["columns"]
                self.logical_words += words
                coverage[source] += words
            if source in histograms:
                histogram = histograms[source]
                if source in softmax_histograms:
                    histogram[0] += histogram_padding
                if np.any(histogram > (1 << 32) - 1):
                    raise ValueError("oracle histogram overflows u32")
                payload = histogram.astype("<u4").tobytes()
                yield (trace.HISTOGRAM, slot, 4, source, 0, 1, descriptor["columns"], 1, payload)
                self.frame_count += 1
                self.logical_words += descriptor["columns"]
                coverage[source] += descriptor["columns"]
            if coverage[source] != descriptor["rows"] * descriptor["columns"]:
                raise ValueError(f"oracle source {source} coverage differs")
        yield (trace.TOKENS, slot, 4, trace.U32_MAX, 0, 1, 150, 1,
               np.asarray(tokens, dtype="<u4").tobytes())
        self.frame_count += 1
        self.logical_words += 150

    @staticmethod
    def _padding(context: dict) -> dict[int, int]:
        padding = {}
        producers = {output: step for step in context["steps"] for output in step["outputs"]}
        for step in context["steps"]:
            if step["kind"] != "softmax":
                continue
            parameters = step["parameters"]
            padding[parameters["difference"]] = -32767
            padding[parameters["exponential"]] = 1 << 30
            for key in ("maximum", "denominator", "probability"):
                padding[parameters[key]] = 0
            score = step["inputs"][0]
            padding[score] = 0
            score_producer = producers[score]
            if score_producer["kind"] != "rne":
                raise ValueError("oracle softmax score producer differs")
            padding[score_producer["inputs"][0]] = 0
        return padding

    def _evaluate(self, context, step, row, token, get):
        kind, inputs, outputs, parameters = (step[key] for key in
                                              ("kind", "inputs", "outputs", "parameters"))
        histogram = decision = None
        if kind == "embedding":
            weight = self._weight(parameters["weight"])
            if token >= len(weight) or np.any(weight[token] == -32768):
                raise ValueError("oracle embedding address/range differs")
            values = [(outputs[0], row, weight[token].astype(np.int64))]
        elif kind == "matrix":
            values = [(outputs[0], row,
                       self._matrix(parameters["weight"],
                                    get(inputs[0], row + parameters["input_row_offset"])))]
        elif kind == "norm":
            x = np.asarray(get(inputs[0], row), dtype=np.int64)
            heads, columns = parameters["heads"], parameters["columns"]
            weight = (None if parameters["weight"] is None
                      else self._weight(parameters["weight"])[0].astype(np.int64))
            if weight is not None and np.any(weight < -32767):
                raise ValueError("oracle RMS weight contains i16 minimum")
            statistics, products, result = [], [], []
            for head in x.reshape(heads, columns):
                statistic = int(head @ head)
                product = head if weight is None else head * weight
                statistics.append(statistic)
                products.append(product)
                result.append(numeric.rms_batch(product, statistic, columns,
                                                parameters["recipe"]))
            result = np.concatenate(result)
            if weight is None:
                values = [(outputs[0], row * heads, statistics), (outputs[1], row, result)]
            else:
                values = [(outputs[0], row * heads, np.concatenate(products)),
                          (outputs[1], row * heads, statistics), (outputs[2], row, result)]
        elif kind == "rne":
            values = [(outputs[0], row, _rne(get(inputs[0], row), parameters["shift"]))]
        elif kind == "affine":
            coefficients = parameters["coefficients"]
            active = [coefficient for coefficient in coefficients if coefficient]
            if len(active) != len(inputs):
                raise ValueError("oracle affine input map differs")
            result = sum((coefficient * np.asarray(get(source, row), dtype=np.int64)
                          for source, coefficient in zip(inputs, active)),
                         np.zeros_like(get(inputs[0], row), dtype=np.int64))
            values = [(outputs[0], row, result)]
        elif kind == "gelu":
            x = np.asarray(get(inputs[0], row), dtype=np.int64)
            entries = x + 32767
            values = [(outputs[0], row, self._lookup(
                self.tables.gelu(parameters["table"]), entries, "GELU"))]
            histogram = (parameters["histogram"], entries)
        elif kind == "gate":
            values = [(outputs[0], row, np.asarray(get(inputs[0], row), dtype=np.int64)
                       * np.asarray(get(inputs[1], row), dtype=np.int64))]
        elif kind == "rope":
            x = np.asarray(get(inputs[0], row), dtype=np.int64)
            heads, width = parameters["heads"], parameters["width"]
            coefficients = reference.gemma_rope_q30_coefficients(
                "local" if parameters["family"] == 0 else "global",
                parameters["position"] + row)[:width // 2]
            raw = [value for head in x.reshape(heads, width)
                   for value in reference.rope_raw_row(head.tolist(), coefficients)]
            values = [(outputs[0], row, raw)]
        elif kind == "qk":
            head, query = divmod(row, 256)
            lanes, repeats = parameters["lanes"], parameters["repeats"]
            if lanes * 32767**2 >= 1 << 53:
                raise ValueError("oracle QK exact-binary64 bound exceeded")
            q = np.asarray(get(inputs[0], query), dtype=np.int64)[head * lanes:(head + 1) * lanes]
            keys = np.asarray(self.kv[inputs[1]][:context["old_tokens"] + query + 1,
                                                (head // repeats) * lanes:
                                                (head // repeats + 1) * lanes], dtype=np.float64)
            live = keys @ q.astype(np.float64)
            if not np.equal(live, np.rint(live)).all():
                raise ArithmeticError("oracle QK binary64 result is not exact")
            result = np.zeros(context["old_tokens"] + 150, dtype=np.int64)
            result[:len(live)] = live.astype(np.int64)
            values = [(outputs[0], row, result)]
        elif kind == "softmax":
            head, query = divmod(row, 256)
            del head
            x = np.asarray(get(inputs[0], row), dtype=np.int64)
            live = context["old_tokens"] + query + 1
            if np.any(x[live:]):
                raise ValueError("oracle future score is nonzero")
            maximum = int(x[:live].max())
            differences = np.zeros(len(x), dtype=np.int64)
            differences[:live] = maximum - x[:live]
            exponential = self._lookup(self.tables.exp30(parameters["table"]), differences,
                                       "EXP30").astype(np.int64)
            denominator = int(exponential[:live].sum())
            numerator = (1 << 14) * exponential[:live]
            quotient, remainder = np.divmod(numerator, denominator)
            probability = np.zeros(len(x), dtype=np.int64)
            probability[:live] = quotient + ((2 * remainder > denominator)
                                             | ((2 * remainder == denominator)
                                                & ((quotient & 1) != 0)))
            values = [
                (parameters["maximum"], row, [maximum]),
                (parameters["difference"], row, differences - 32767),
                (parameters["exponential"], row, exponential),
                (parameters["denominator"], row, [denominator]),
                (parameters["probability"], row, probability),
            ]
            histogram = (parameters["histogram"], differences)
        elif kind == "pv":
            lanes, repeats = parameters["lanes"], parameters["repeats"]
            live = context["old_tokens"] + row + 1
            if live * 32767**2 >= 1 << 53:
                raise ValueError("oracle PV exact-binary64 bound exceeded")
            result = np.empty(32 * lanes, dtype=np.int64)
            for head in range(32):
                probability = np.asarray(get(inputs[0], head * 256 + row), dtype=np.float64)[:live]
                value = np.asarray(self.kv[inputs[1]][:live,
                                                     (head // repeats) * lanes:
                                                     (head // repeats + 1) * lanes], dtype=np.float64)
                computed = probability @ value
                if not np.equal(computed, np.rint(computed)).all():
                    raise ArithmeticError("oracle PV binary64 result is not exact")
                result[head * lanes:(head + 1) * lanes] = computed.astype(np.int64)
            values = [(outputs[0], row, result)]
        elif kind == "softcap":
            x = np.asarray(get(inputs[0], row), dtype=np.int64)
            entries = x - parameters["lower"]
            values = [(outputs[0], row, self._lookup(self.tables.softcap(), entries, "softcap"))]
            histogram = (parameters["histogram"], entries)
        elif kind == "argmax":
            decision, slack = numeric.argmax(get(inputs[0], row))
            values = [(outputs[0], row, slack)]
        else:
            raise ValueError("oracle operation kind differs")
        return values, histogram, decision

    def frames(self):
        for slot, context in enumerate(self.plan["contexts"]):
            yield from self._context(slot, context)
        context = self.plan["contexts"][2]
        for source in context["kv_sources"]:
            values = self.kv.get(source)
            columns = context["sources"][source]["columns"]
            if values is None or values.shape != (450, columns):
                raise ValueError("oracle final KV shape differs")
            payload = _encode_signed(values, 2)
            yield (trace.FINAL_KV, 2, 2, source, 0, 450, columns, 1, payload)
            self.frame_count += 1
            self.logical_words += values.size
        self.report = {
            "schema": "volta-c71-independent-calibration-oracle-v1",
            "complete": True,
            "contexts": 3,
            "frames": self.frame_count,
            "logical_words": self.logical_words,
            "matrix_products": self.matrix_products,
            "oracle_plan_sha256": self.plan_sha256,
            "schedule_audit": self.schedule_audit,
            "rms_kernel": numeric.rms_kernel_digests(),
            "matrix_kernel": "independent-c11-i16-i64",
            "elapsed_seconds": time.monotonic() - self.started,
        }

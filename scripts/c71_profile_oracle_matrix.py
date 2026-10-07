#!/usr/bin/env python3
"""Offline timing screen of the independent integer matrix kernel.

Actual immutable W must already be verified by ingest. Synthetic alternating
i16 inputs, no tables/causal run/candidate/admission; only use on the authorized
pod. This intentionally initializes just the fields consumed by _matrix.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

import numpy as np

from c71_calibration_oracle_driver import Driver
import c71_calibration_oracle as numeric
from c7_d126_gemma_weight_ingest import PACKED_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=Path)
    parser.add_argument("packed", type=Path)
    parser.add_argument("--compare-reference", action="store_true")
    parser.add_argument("--workers", type=int, choices=range(1, 21), default=1)
    args = parser.parse_args()
    if args.packed.stat().st_size != PACKED_BYTES:
        raise ValueError("matrix screen packed byte length differs")
    description = json.loads(subprocess.run([str(args.native), "describe"], check=True,
                                            capture_output=True, timeout=60).stdout)
    driver = Driver.__new__(Driver)
    driver.weights = description["weight_sources"]
    driver.packed = np.memmap(args.packed, dtype="<i2", mode="r")
    driver.matrix_products = 0
    driver.matrix_workers = args.workers
    matrices = [s["parameters"]["weight"] for s in description["pilot"]["steps"]
                if s["operation"] == "matrix"]
    identifier = max(reversed(matrices), key=lambda i: driver.weights[i]["columns"])
    source = driver.weights[identifier]
    values = np.where(np.arange(source["columns"]) % 2 == 0, 32767, -32767)
    started = time.monotonic()
    numeric.matrix_i16(np.zeros((1, 1), dtype=np.int16), np.zeros(1, dtype=np.int16))
    kernel_init_seconds = time.monotonic() - started
    started = time.monotonic()
    output = driver._matrix(identifier, values)
    elapsed = time.monotonic() - started
    assert output.size == source["rows"] and driver.matrix_products == source["rows"] * source["columns"]
    products = driver.matrix_products
    comparison = None
    if args.compare_reference:
        comparison = bool(np.array_equal(output, driver._matrix_blas(identifier, values)))
        if not comparison:
            raise ValueError("independent integer matrix differs from exact BLAS reference")
    print(json.dumps(dict(credit=False, profile_only=True, complete_integer_trial=False,
                          independent_oracle_complete=False, packed_hash_checked=False,
                          synthetic_input=True, rows=source["rows"], columns=source["columns"],
                          matrix_scalar_products=products, wall_seconds=elapsed,
                          kernel_init_seconds=kernel_init_seconds, matrix_workers=args.workers,
                          exact_reference_equal=comparison)))


if __name__ == "__main__":
    main()

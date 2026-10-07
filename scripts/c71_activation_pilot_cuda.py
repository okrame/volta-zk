"""Explicit offline FP64 cuBLAS matrices; all other pilot operators stay on CPU."""
import ctypes
import time

import numpy as np


class CudaMatrices:
    def __init__(self, library, weights, compare=False):
        self.library = ctypes.CDLL(str(library))
        self.weights = weights
        self.compare = compare
        self.comparison_products = 0
        self.comparison_max_error_ratio = 0.0
        self.comparison_bitwise_equal = True
        self.context = ctypes.c_void_p()
        api = self.library
        signatures = {
            "create": [ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)],
            "upload": [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64],
            "seal": [ctypes.c_void_p],
            "product": [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32,
                        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p],
            "stats": [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
            "close": [ctypes.c_void_p],
        }
        for name, arguments in signatures.items():
            function = getattr(api, "c71_pilot_cuda_" + name)
            function.argtypes, function.restype = arguments, ctypes.c_int
        self.final_metrics = None
        started = time.monotonic()
        words = sum(d["rows"] * d["columns"] for d in weights.descriptors)
        try:
            self.check(api.c71_pilot_cuda_create(words, ctypes.byref(self.context)))
            weights.source.seek(0)
            for first in range(0, words, 1 << 27):
                count = min(1 << 27, words - first)
                if weights.mapping is None:
                    body = weights.source.read(count * 2)
                    if len(body) != count * 2:
                        raise ValueError("CUDA pilot packed input truncated")
                    values = np.frombuffer(body, dtype="<i2")
                else:
                    values = np.frombuffer(weights.mapping, dtype="<i2", count=count, offset=first * 2)
                self.check(api.c71_pilot_cuda_upload(self.context, values.ctypes.data, count))
            self.check(api.c71_pilot_cuda_seal(self.context))
        except BaseException:
            self.close()
            raise
        self.initialization_seconds = time.monotonic() - started

    @staticmethod
    def check(status):
        if status:
            raise RuntimeError("explicit CUDA FP64 pilot failed; no fallback")

    def matrix(self, tensor, values):
        if not self.context.value:
            raise ValueError("CUDA pilot already closed")
        descriptor = self.weights.descriptors[tensor]
        values = np.ascontiguousarray(values, dtype=np.float64)
        rows, columns = descriptor["rows"], descriptor["columns"]
        if values.shape != (columns,):
            raise ValueError("CUDA pilot matrix input shape differs")
        output = np.empty(rows, dtype=np.float64)
        self.check(self.library.c71_pilot_cuda_product(
            self.context, descriptor["packed_offset"], rows, columns,
            self.weights.exponents[descriptor["name"]], values.ctypes.data, output.ctypes.data))
        self.weights.bytes_read += rows * columns * 2
        if self.compare:
            for first in range(0, rows, 128):
                block = self.weights.block(tensor, first, min(128, rows - first))
                expected = block @ values
                actual = output[first:first + len(block)]
                # Two binary64 dot orders: conservative forward-error bound.
                bound = 4 * columns * np.finfo(np.float64).eps * (np.abs(block) @ np.abs(values))
                error = np.abs(actual - expected)
                if np.any(error > bound):
                    raise ArithmeticError("CUDA pilot differs beyond binary64 dot error bound")
                self.comparison_products += 2 * block.size
                self.comparison_bitwise_equal &= actual.tobytes() == expected.tobytes()
                ratio = np.divide(error, bound, out=np.zeros_like(error), where=bound != 0)
                self.comparison_max_error_ratio = max(self.comparison_max_error_ratio, float(ratio.max()))
        return output

    def metrics(self):
        if self.final_metrics is not None:
            return self.final_metrics
        sizes = (ctypes.c_uint64 * 4)()
        seconds = (ctypes.c_double * 4)()
        self.check(self.library.c71_pilot_cuda_stats(self.context, sizes, seconds))
        result = dict(zip(("device_weight_bytes", "device_workspace_bytes", "h2d_bytes", "d2h_bytes"), sizes))
        result.update(zip(("upload_seconds", "conversion_seconds", "gemv_seconds", "download_seconds"), seconds))
        result.update(initialization_seconds=getattr(self, "initialization_seconds", None),
                      cpu_comparison_products=self.comparison_products,
                      comparison_enabled=self.compare,
                      comparison_bitwise_equal=self.comparison_bitwise_equal if self.compare else None,
                      comparison_max_error_ratio=self.comparison_max_error_ratio if self.compare else None,
                      complete_physical_peak=False)
        return result

    def close(self):
        if self.context.value:
            self.final_metrics = self.metrics()
            status = self.library.c71_pilot_cuda_close(self.context)
            self.context = ctypes.c_void_p()
            self.check(status)

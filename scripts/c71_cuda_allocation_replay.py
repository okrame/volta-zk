"""Replay captured large CUDA allocation lifetimes, without weights or kernels.

This isolates an allocator hypothesis; it cannot validate A, a certificate,
or the full physical allowance. Run only on the authorized GPU under the
canonical physical monitor, with no W exemption and a finite deadline.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import time


MINIMUM = 1 << 20
PAYLOAD_LIMIT = 5905580032
HOST_RESERVE = 32 << 20


def plan(path, group):
    if not 0 <= group < 511 or path.stat().st_size > 16 << 20:
        raise ValueError("trace/group outside bounded diagnostic")
    live, initial, operations = {}, None, []
    completed = False
    for sequence, line in enumerate(path.read_text().splitlines()):
        row = json.loads(line)
        if row["schema"] != "volta-c71-owner-trace-v1" or row["seq"] != sequence or row["status"]:
            raise ValueError("invalid or failed source trace")
        if row["a_group"] > group:
            completed = True
            break
        if row["a_group"] == group and initial is None:
            initial = dict(live)
        if row["edge"] != "after" or row["capacity_bytes"] < MINIMUM:
            continue
        slot, size, op = row["slot"], row["capacity_bytes"], row["op"]
        if op not in ("retained_buffer", "allocate", "c71_range_release"):
            continue
        if type(slot) is not int or not 0 <= slot < 512 or type(size) is not int or size % 256:
            raise ValueError("invalid allocation descriptor")
        if op in ("retained_buffer", "allocate"):
            if slot in live:
                raise ValueError("allocation overwrote a live slot")
            live[slot] = size
            action = "allocate"
        else:
            if live.pop(slot, None) != size:
                raise ValueError("release differs from live allocation")
            action = "release"
        if row["a_group"] == group:
            if op == "retained_buffer":
                raise ValueError("choose a group after the initial snapshot")
            operations.append([action, slot, size])
    if not completed or initial is None or not operations or live != initial:
        raise ValueError("incomplete group or nonperiodic allocation lifetime")
    result = dict(schema="volta-c71-allocation-replay-v1", credit=False,
                  source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), source_group=group,
                  minimum_bytes=MINIMUM, initial=sorted(initial.items()), operations=operations,
                  omitted="weights, kernels, host state, and allocation events below 1 MiB")
    validate(result)
    return result


def validate(data):
    if data.get("schema") != "volta-c71-allocation-replay-v1" or data.get("minimum_bytes") != MINIMUM:
        raise ValueError("allocation plan schema differs")
    initial = data["initial"]
    if len(initial) > 512 or len(data["operations"]) > 65536:
        raise ValueError("allocation plan exceeds descriptor bound")
    live = {}
    def shape(slot, size):
        if type(slot) is not int or not 0 <= slot < 512 or type(size) is not int or size < MINIMUM or size % 256:
            raise ValueError("invalid allocation shape")
    for slot, size in initial:
        shape(slot, size)
        if slot in live:
            raise ValueError("duplicate initial slot")
        live[slot] = size
    peak = sum(live.values())
    original = dict(live)
    for action, slot, size in data["operations"]:
        shape(slot, size)
        if action == "allocate" and slot not in live:
            live[slot] = size
        elif action == "release" and live.pop(slot, None) == size:
            pass
        else:
            raise ValueError("invalid allocation lifecycle")
        peak = max(peak, sum(live.values()))
    if live != original or peak + HOST_RESERVE > PAYLOAD_LIMIT:
        raise ValueError("nonperiodic lifetime or payload budget exceeded")
    return peak


def replay(data, repetitions, library):
    peak = validate(data)
    if not 1 <= repetitions <= 512:
        raise ValueError("repetitions outside diagnostic bound")
    cuda = ctypes.CDLL(str(library))
    cuda.cudaMalloc.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t]
    cuda.cudaFree.argtypes = [ctypes.c_void_p]
    cuda.cudaMemGetInfo.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    cuda.cudaDeviceSetLimit.argtypes = [ctypes.c_int, ctypes.c_size_t]
    cuda.cudaDeviceSynchronize.argtypes = []
    def check(status):
        if status:
            raise RuntimeError(f"CUDA status {status}")
    def used():
        free, total = ctypes.c_size_t(), ctypes.c_size_t()
        check(cuda.cudaMemGetInfo(ctypes.byref(free), ctypes.byref(total)))
        return total.value - free.value
    check(cuda.cudaDeviceSetLimit(0, 256))
    baseline = used()
    pointers = {}
    allocations = releases = 0
    started = time.monotonic()
    def allocate(slot, size):
        value = ctypes.c_void_p()
        check(cuda.cudaMalloc(ctypes.byref(value), size))
        pointers[slot] = value
    try:
        for slot, size in data["initial"]:
            allocate(slot, size)
            allocations += 1
        for repetition in range(repetitions):
            before = time.monotonic()
            sampled_peak = used()
            for i, (action, slot, size) in enumerate(data["operations"]):
                if action == "allocate":
                    allocate(slot, size)
                    allocations += 1
                else:
                    value = pointers.pop(slot)  # Do not retry a failed free.
                    check(cuda.cudaFree(value))
                    releases += 1
                if i % 64 == 0:
                    sampled_peak = max(sampled_peak, used())
            check(cuda.cudaDeviceSynchronize())
            print(json.dumps(dict(repetition=repetition, wall_seconds=time.monotonic()-before,
                  cumulative_seconds=time.monotonic()-started, cuda_used_bytes=used(),
                  sampled_cuda_used_peak_bytes=sampled_peak, context_baseline_bytes=baseline,
                  device_payload_peak_bytes=peak, host_payload_reserve_bytes=HOST_RESERVE,
                  allocations=allocations, releases=releases, credit=False)), flush=True)
    finally:
        failed = []
        for slot in list(pointers):
            status = cuda.cudaFree(pointers.pop(slot))
            if status:
                failed.append([slot, status])
        print(json.dumps(dict(cleanup_failures=failed, cuda_used_after_release=used(), credit=False)), flush=True)
        if failed:
            raise RuntimeError("CUDA cleanup failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    make = modes.add_parser("plan")
    make.add_argument("trace", type=Path)
    make.add_argument("group", type=int)
    make.add_argument("output", type=Path)
    run = modes.add_parser("run")
    run.add_argument("plan", type=Path)
    run.add_argument("repetitions", type=int)
    run.add_argument("library", type=Path)
    args = parser.parse_args()
    if args.mode == "plan":
        data = plan(args.trace, args.group)
        with args.output.open("x") as sink:
            json.dump(data, sink, separators=(",", ":"))
    else:
        if args.plan.stat().st_size > 8 << 20:
            raise ValueError("allocation plan file exceeds cap")
        replay(json.loads(args.plan.read_bytes()), args.repetitions, args.library)

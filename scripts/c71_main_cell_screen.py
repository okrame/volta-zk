#!/usr/bin/env python3
"""Check the fixed sm_90 C7.1 fused-main-cell paths; not a generic CFG tool."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import c71_gkr_screen as gkr

ROOT = Path(__file__).resolve().parents[1]
NATIVE_RECORD = ROOT / "benchmarks/results/c71-bounded-rms-gkr-2026-09-19-3e7f24eb332b.json"
EXPECTED_FUNCTION_SHA256 = "1590b46b4c8fe0f382b5ae28380cbf56aaa2840c3780aeed788c50ac9770fefc"


FUNCTION = "c71_gkr_main_cell_fused"
EXP30_O300_FP3_PRODUCTS = 47_241_202_900_983
SCALAR_RESULT_CEILING = 132 * 64 * 2_000_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def extract_function(raw):
    start_match = re.search(
        rf"(?m)^[ \t]*Function : {re.escape(FUNCTION)}[ \t]*\r?$", raw
    )
    require(start_match is not None, f"missing {FUNCTION}")
    next_match = re.search(
        r"(?m)^[ \t]*Function : [^\r\n]+\r?$", raw[start_match.end() :]
    )
    end = len(raw) if next_match is None else start_match.end() + next_match.start()
    block = raw[start_match.start() : end]
    instructions = {}
    for line in block.splitlines():
        match = re.search(r"/\*([0-9a-f]+)\*/\s+(.*?)\s*;\s*/\*", line)
        if match:
            address = int(match.group(1), 16)
            require(address not in instructions, f"duplicate address {address:#x}")
            instructions[address] = match.group(2).strip()
    require(instructions, "function has no parsed instructions")
    return block, instructions


def normalized(operation):
    return " ".join(operation.split())


def expect(instructions, address, operation):
    actual = normalized(instructions.get(address, ""))
    require(actual == normalized(operation), f"{address:#x}: {actual!r} != {operation!r}")


REGISTER = re.compile(r"^(?:U?R\d+)(?:\.reuse)?$")
WIDE = re.compile(r"^IMAD\.WIDE\.U32(?:\.X)?\s+(.+)$")


def register_only_wide(instructions, begin, end):
    found = []
    for address, operation in sorted(instructions.items()):
        if not begin <= address < end:
            continue
        require(
            not (operation.startswith("@") and "IMAD.WIDE.U32" in operation),
            f"predicated IMAD.WIDE in counted range at {address:#x}",
        )
        match = WIDE.fullmatch(operation)
        if match is None:
            continue
        operands = [item.strip() for item in match.group(1).split(",")]
        # IMAD.WIDE may name a carry predicate after the destination.
        if len(operands) == 5 and operands[1].startswith("P"):
            multiplicands = operands[2:4]
        elif len(operands) == 5 and operands[4].startswith("P"):
            multiplicands = operands[1:3]
        else:
            require(len(operands) == 4, f"unexpected IMAD.WIDE operands at {address:#x}")
            multiplicands = operands[1:3]
        if all(REGISTER.fullmatch(item) for item in multiplicands):
            found.append(address)
    return found


def no_branch(instructions, begin, end, label):
    branches = [
        (address, operation)
        for address, operation in sorted(instructions.items())
        if begin <= address < end and re.search(r"\b(?:BR(?:A|X)|CALL|RET|EXIT|JMP|JMX)\b", operation)
    ]
    require(not branches, f"unexpected branch in {label}: {branches}")


def screen(sass_path, source_path=None):
    sass_bytes = Path(sass_path).read_bytes()
    raw = sass_bytes.decode("utf-8")
    block, instructions = extract_function(raw)
    # Fixed-bin certificate: a changed instruction, predicate or control-flow
    # edge needs a fresh review, even if the selected counter is unchanged.
    require(hashlib.sha256(block.encode()).hexdigest() == EXPECTED_FUNCTION_SHA256,
            "compiled function changed; repeat the CFG review")

    # Gate-count bypass, op dispatch, equal-cost AND/XOR fork, joins, loop back-edge.
    expect(instructions, 0x03E0, "ISETP.NE.AND P0, PT, R10, RZ, PT")
    expect(instructions, 0x03F0, "@!P0 BRA 0x13b90")
    expect(instructions, 0x0560, "ISETP.NE.AND P0, PT, R40, 0x2, PT")
    expect(instructions, 0x05F0, "@!P0 BRA 0x102a0")
    expect(instructions, 0x52B0, "ISETP.NE.AND P4, PT, R40, 0x1, PT")
    expect(instructions, 0x6550, "@!P4 BRA 0xab60")
    expect(instructions, 0xAB50, "BRA 0x13310")
    expect(instructions, 0x10290, "BRA 0x13310")
    expect(instructions, 0x13B80, "@!P1 BRA 0x4e0")

    ranges = {
        "noncopy_common": (0x0600, 0x6550),
        "and_suffix": (0x6560, 0xAB50),
        "xor_suffix": (0xAB60, 0x10290),
        "copy": (0x102A0, 0x13310),
        "selector_program_tail": (0x13B90, 0x1CD00),
    }
    for label, (begin, end) in ranges.items():
        no_branch(instructions, begin, end, label)
    counts = {
        label: len(register_only_wide(instructions, begin, end))
        for label, (begin, end) in ranges.items()
    }
    path_counts = {
        "copy": counts["copy"],
        "and": counts["noncopy_common"] + counts["and_suffix"],
        "xor": counts["noncopy_common"] + counts["xor_suffix"],
        "selector_program_tail": counts["selector_program_tail"],
    }
    expected = {"copy": 54, "and": 205, "xor": 205, "selector_program_tail": 180}
    require(path_counts == expected, f"compiled path census changed: {path_counts}")

    fp3_calls = {"copy": 2, "and": 7, "xor": 7, "selector_program_tail": 6}
    observed_floor = min(path_counts[key] // fp3_calls[key] for key in fp3_calls)
    certified_results_per_fp3 = 24
    require(observed_floor >= certified_results_per_fp3, "24 scalar results/Fp3 no longer follows")
    lower = certified_results_per_fp3 * EXP30_O300_FP3_PRODUCTS / SCALAR_RESULT_CEILING
    require(lower > 65, "standalone O=300 lower no longer excludes 65 seconds")

    result = {
        "schema": "volta-c71-main-cell-cfg-v1",
        "credit": False,
        "scope": "named sm_90 fused scalar main-cell binary and exact EXP30 O=300 work",
        "sass_sha256": hashlib.sha256(sass_bytes).hexdigest(),
        "function_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
        "register_only_unpredicated_IMAD_WIDE_U32": {
            "ranges": counts,
            "paths": path_counts,
        },
        "fp3_calls_per_path": fp3_calls,
        "observed_whole_results_per_Fp3_floor": observed_floor,
        "certified_scalar_multiply_results_per_Fp3": certified_results_per_fp3,
        "EXP30_O300_Fp3_products": EXP30_O300_FP3_PRODUCTS,
        "scalar_result_ceiling_per_second": SCALAR_RESULT_CEILING,
        "EXP30_O300_coefficient_only_lower_seconds_conditional": lower,
        "conditions": [
            "132 SM",
            "clock <=2 GHz",
            "<=64 scalar INT multiply results/cycle/SM applies to IMAD.WIDE.U32",
            "canonical cells enumerate each public supported program/cell pair once",
            "same binary/function hash; no tensor/packed/algebraically different backend",
        ],
    }
    cases = []
    for old in (0, 150, 300):
        native = gkr.native_record(NATIVE_RECORD, 'EXP30', old)
        products = gkr.ratio_factored_arithmetic(native, old)['Fp3_mul']
        seconds = certified_results_per_fp3 * products / SCALAR_RESULT_CEILING
        cases.append(dict(old_tokens=old, EXP30_Fp3_products=products,
                          T_proof_only_lower_seconds=seconds,
                          T_response_total_lower_seconds=seconds,
                          T_inference_lower_seconds=0,
                          inference_measured=False, NO_GO=seconds > 65))
    require(cases[-1]['EXP30_Fp3_products'] == EXP30_O300_FP3_PRODUCTS,
            'EXP30 work differs from the fixed public workload')
    result['cases'] = cases
    result['work_source'] = str(NATIVE_RECORD.relative_to(ROOT))
    result['lower_is_subset_not_complete_work_ledger'] = True
    result['spending_gate'] = 'NO-GO for this backend; no H100 run needed'
    if source_path is not None:
        source_bytes = Path(source_path).read_bytes()
        result["source_sha256"] = hashlib.sha256(source_bytes).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sass", nargs="?", default="/tmp/c71-integrated-kernels-sm90.sass")
    parser.add_argument("--source", default="cuda/c71_range_microbench.cu")
    args = parser.parse_args()
    print(json.dumps(screen(args.sass, args.source), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

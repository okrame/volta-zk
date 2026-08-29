#!/usr/bin/env python3
"""Recompute the binding C4.1 folded-query research bounds."""

import math
from itertools import combinations
from pathlib import Path


C4_SETUP = 38_371_465
SETUP_CAP = 3 * C4_SETUP
CELLS = 5 * 3_110_400
OUTPUT_BITS = 17 * CELLS
PRG_USABLE = (1 << 20) - 1_024
EXPANSIONS = (OUTPUT_BITS + PRG_USABLE - 1) // PRG_USABLE
SEED_BITS = EXPANSIONS * 1_024

# Conservative setup profile built only from the already documented C2
# components.  It intentionally spends one whole fase-B shard for the three
# arithmetic-lift checks instead of assuming spare correlations.
EXTRA_FP_SHARD_BYTES = 31_261_434
FERRET_SETUP_BYTES = 1_510_000
FERRET_MAIN_OUTPUTS = 10_000_000
FERRET_BITS_PER_COT = 0.73
FERRET_MAIN_BYTES = math.ceil(FERRET_MAIN_OUTPUTS * FERRET_BITS_PER_COT / 8)
SEED_LIFT_BYTES = SEED_BITS * 16
SEED_ROW_HEADER_BYTES = EXPANSIONS * 9
SETUP_CONTROL_RESERVE_BYTES = 1 << 20
TYPED_SETUP_ENVELOPE = (
    EXTRA_FP_SHARD_BYTES
    + FERRET_SETUP_BYTES
    + FERRET_MAIN_BYTES
    + SEED_LIFT_BYTES
    + SEED_ROW_HEADER_BYTES
    + SETUP_CONTROL_RESERVE_BYTES
)

PACKED_RESPONSE = 84_544_352 - 18_273_600
RESPONSE_CAP = 70_000_000
CLOSE_BYTES = 12 * 16
FRAME_HEADER_BYTES = 9
PACKED_RESPONSE_WITH_CLOSE = PACKED_RESPONSE + FRAME_HEADER_BYTES + CLOSE_BYTES
POLY_SLAB = 3_110_400 * 2 * 12 * 16
ANCHOR_PEAK = 17_158_968_308
DEVICE_CAP = 30_000_000_000
ANCHOR_PROVE_SECONDS = 4.104595717
PROVER_TIME_GATE_RATIO = 1.30
PROVER_TIME_GATE_SECONDS = PROVER_TIME_GATE_RATIO * ANCHOR_PROVE_SECONDS
A100_STREAM_BYTES_PER_SECOND = 418.038245551e9
FOLD_READ_FLOOR_SECONDS = POLY_SLAB / A100_STREAM_BYTES_PER_SECOND
PURE_ADDITIVE_PROVER_RATIO = (
    ANCHOR_PROVE_SECONDS + FOLD_READ_FLOOR_SECONDS
) / ANCHOR_PROVE_SECONDS

BASE_SOUNDNESS_BITS = 78.80929487391641
NEW_ERROR_BUDGET_BITS = -math.log2(2**-78 - 2**-BASE_SOUNDNESS_BITS)
GOLDILOCKS = 2**64 - 2**32 + 1
DEGREE_12_CHECK_BITS = 2 * math.log2(GOLDILOCKS) - math.log2(12)
FIVE_CLOSE_CHECK_BITS = DEGREE_12_CHECK_BITS - math.log2(5)
PRG_CHALLENGE_TARGET_BITS = 128
CONDITIONAL_MULTI_INSTANCE_BITS = PRG_CHALLENGE_TARGET_BITS - math.log2(EXPANSIONS)
COMPOSED_SECURITY_BITS = -math.log2(
    2**-BASE_SOUNDNESS_BITS
    + 2**-FIVE_CLOSE_CHECK_BITS
    + 2**-CONDITIONAL_MULTI_INSTANCE_BITS
)


def logaddexp(a: float, b: float) -> float:
    if a == -math.inf:
        return b
    if b == -math.inf:
        return a
    if a < b:
        a, b = b, a
    return a + math.log1p(math.exp(b - a))


def logdiffexp(a: float, b: float) -> float:
    """Return log(exp(a) - exp(b)); an invalid/nonpositive advantage is -inf."""
    if a <= b:
        return -math.inf
    return a + math.log1p(-math.exp(b - a))


def log_threshold_common_bias(outputs: int, seed: int, arity: int, threshold: int) -> float:
    """Exact finite common-bias formula from D'Antona--Meaux--Unal (2026)."""
    denominator = math.comb(seed, arity)
    result = -math.inf
    for weight in range(seed + 1):
        lower = max(threshold, arity - (seed - weight))
        upper = min(arity, weight)
        numerator = sum(
            math.comb(weight, ones) * math.comb(seed - weight, arity - ones)
            for ones in range(lower, upper + 1)
        )
        if numerator == 0:
            continue
        accept = numerator / denominator
        term = (
            math.lgamma(seed + 1)
            - math.lgamma(weight + 1)
            - math.lgamma(seed - weight + 1)
            - seed * math.log(2)
        )
        if accept < 1:
            term += outputs * math.log(accept)
        result = logaddexp(result, term)
    return result


def best_common_bias_attack(selection: bool) -> tuple[float, int, int]:
    """Minimize the paper's T/adv metric for XOR4-MAJ7(1024, 2^20)."""
    seed, arity, threshold = 1_024, 7, 4
    best = (math.inf, 0, 0)
    for security_gap in range(1, seed + 1):
        equations = seed + security_gap
        if selection:
            # At m=2^20 the paper's greedy selection has depth exactly one:
            # ceil(m*7/1024)=7168, then ceil(7168*6/1023)=43 < 1025.
            used_outputs = equations * seed // arity + 1
            log_real = logaddexp(
                log_threshold_common_bias(equations, seed - 1, arity - 1, threshold),
                log_threshold_common_bias(equations, seed - 1, arity - 1, threshold - 1),
            ) - math.log(2)
            work = equations * seed**2 + used_outputs * arity
        else:
            used_outputs = equations
            log_real = log_threshold_common_bias(equations, seed, arity, threshold)
            work = equations * seed**2
        log_advantage = logdiffexp(log_real, -security_gap * math.log(2))
        if log_advantage == -math.inf:
            continue
        attack_bits = (math.log(work) - log_advantage) / math.log(2)
        if attack_bits < best[0]:
            best = (attack_bits, security_gap, used_outputs)
    return best


def xor4_maj7_truth_table() -> list[bool]:
    return [
        bool(
            ((value & 0xF).bit_count() & 1)
            ^ (((value >> 4) & 0x7F).bit_count() >= 4)
        )
        for value in range(1 << 11)
    ]


def xor4_maj7_resilience(truth: list[bool]) -> int:
    walsh = [1 if not bit else -1 for bit in truth]
    step = 1
    while step < len(walsh):
        for start in range(0, len(walsh), 2 * step):
            for offset in range(step):
                a, b = walsh[start + offset], walsh[start + offset + step]
                walsh[start + offset] = a + b
                walsh[start + offset + step] = a - b
        step *= 2
    return min(mask.bit_count() for mask, coefficient in enumerate(walsh) if coefficient) - 1


def gf2_rank(rows: list[int]) -> int:
    pivots: dict[int, int] = {}
    for row in rows:
        while row:
            pivot = row.bit_length() - 1
            if pivot in pivots:
                row ^= pivots[pivot]
            else:
                pivots[pivot] = row
                break
    return len(pivots)


def xor4_maj7_algebraic_immunity(truth: list[bool]) -> int:
    for degree in range(12):
        monomials = [
            sum(1 << bit for bit in subset)
            for size in range(degree + 1)
            for subset in combinations(range(11), size)
        ]
        for annihilated_value in (False, True):
            rows = [
                sum(
                    1 << column
                    for column, mask in enumerate(monomials)
                    if value & mask == mask
                )
                for value, output in enumerate(truth)
                if output == annihilated_value
            ]
            if gf2_rank(rows) < len(monomials):
                return degree
    raise AssertionError("XOR4-MAJ7 algebraic immunity not found")


COMMON_BIAS_NO_SELECTION = best_common_bias_attack(False)
COMMON_BIAS_ONE_SELECTION = best_common_bias_attack(True)
COMMON_BIAS_MULTI_INSTANCE_BITS = COMMON_BIAS_ONE_SELECTION[0] - math.log2(EXPANSIONS)
XOR4_MAJ7_TRUTH = xor4_maj7_truth_table()
XOR4_MAJ7_RESILIENCE = xor4_maj7_resilience(XOR4_MAJ7_TRUTH)
XOR4_MAJ7_ALGEBRAIC_IMMUNITY = xor4_maj7_algebraic_immunity(XOR4_MAJ7_TRUTH)
GROUP_AND_SOLVE_STRETCH = 2
GROUP_AND_SOLVE_SMALL_MAJ_BOUND = (
    (7 - GROUP_AND_SOLVE_STRETCH + 1) ** GROUP_AND_SOLVE_STRETCH
    + GROUP_AND_SOLVE_STRETCH
)

REPO = Path(__file__).resolve().parents[1]
SOURCE_PINS = {
    "rust/volta-proto/src/block_proof.rs": (
        "value: f_open.sub(site_dn.main.col_claims[1].value)",
        "cache_fold_cols_p(cx.stream, v_segs",
        "cache_fold_rows_p(cx.stream, k_segs",
        "value: k_bound_open",
        "value: v_bound_open",
    ),
    "rust/volta-proto/src/ffn_schedule.rs": (
        "cx.zero.push(claim.value.sub(opened));",
    ),
    "rust/volta-proto/src/gemm_proof.rs": (
        "let x_mask = stream.draw_fulls(doms.x_claim, 1)[0];",
        "prod_batch_prover(&[(x_auth, b_open, rounds.claim)]",
    ),
    "rust/volta-proto/src/logup.rs": (
        "self.claim = self.claim.add(v.scale(mu));",
        ".sub(self.claim);",
    ),
}

for relative, pins in SOURCE_PINS.items():
    source = (REPO / relative).read_text()
    for pin in pins:
        assert pin in source, f"C4.1 source-graph pin changed: {relative}: {pin}"

assert SETUP_CAP == 115_114_395
assert SETUP_CAP - C4_SETUP == 76_742_930
assert EXPANSIONS == 253
assert SEED_BITS == 259_072
assert SEED_BITS <= FERRET_MAIN_OUTPUTS
assert FERRET_MAIN_BYTES == 912_500
assert TYPED_SETUP_ENVELOPE == 38_879_939
assert TYPED_SETUP_ENVELOPE < SETUP_CAP - C4_SETUP
assert PACKED_RESPONSE == 66_270_752 < RESPONSE_CAP
assert PACKED_RESPONSE_WITH_CLOSE == 66_270_953 < RESPONSE_CAP
assert RESPONSE_CAP - PACKED_RESPONSE_WITH_CLOSE == 3_729_047
assert POLY_SLAB == 1_194_393_600
assert ANCHOR_PEAK + POLY_SLAB == 18_353_361_908 < DEVICE_CAP
assert 0.00285 < FOLD_READ_FLOOR_SECONDS < 0.00286
assert PURE_ADDITIVE_PROVER_RATIO > 1
assert PURE_ADDITIVE_PROVER_RATIO < PROVER_TIME_GATE_RATIO
assert math.isclose(PROVER_TIME_GATE_SECONDS, 5.3359744321)
assert NEW_ERROR_BUDGET_BITS > 79.21
assert DEGREE_12_CHECK_BITS > 124.41
assert FIVE_CLOSE_CHECK_BITS > NEW_ERROR_BUDGET_BITS
assert CONDITIONAL_MULTI_INSTANCE_BITS > 96
assert COMPOSED_SECURITY_BITS > 78
assert COMMON_BIAS_NO_SELECTION[1:] == (338, 1_362)
assert 364.88 < COMMON_BIAS_NO_SELECTION[0] < 364.90
assert COMMON_BIAS_ONE_SELECTION[1:] == (258, 187_539)
assert 284.89 < COMMON_BIAS_ONE_SELECTION[0] < 284.90
assert COMMON_BIAS_MULTI_INSTANCE_BITS > 96
assert XOR4_MAJ7_RESILIENCE == 4
assert XOR4_MAJ7_ALGEBRAIC_IMMUNITY == 4
assert 1_024 > GROUP_AND_SOLVE_SMALL_MAJ_BOUND == 38

print(
    {
        "typed_setup_headroom_bytes": SETUP_CAP - C4_SETUP,
        "setup_bits_per_cell": 8 * (SETUP_CAP - C4_SETUP) / CELLS,
        "prg_expansions": EXPANSIONS,
        "authenticated_seed_bits": SEED_BITS,
        "typed_setup_envelope_bytes": TYPED_SETUP_ENVELOPE,
        "total_setup_envelope_bytes": C4_SETUP + TYPED_SETUP_ENVELOPE,
        "setup_margin_after_envelope_bytes": SETUP_CAP - C4_SETUP - TYPED_SETUP_ENVELOPE,
        "packed_response_with_one_close_bytes": PACKED_RESPONSE_WITH_CLOSE,
        "response_margin_after_framed_close_bytes": RESPONSE_CAP - PACKED_RESPONSE_WITH_CLOSE,
        "device_peak_projection_bytes": ANCHOR_PEAK + POLY_SLAB,
        "fold_read_only_floor_seconds": FOLD_READ_FLOOR_SECONDS,
        "pure_additive_prover_ratio": PURE_ADDITIVE_PROVER_RATIO,
        "prover_time_gate_ratio": PROVER_TIME_GATE_RATIO,
        "prover_time_gate_seconds": PROVER_TIME_GATE_SECONDS,
        "analytic_prover_time_gate": "pass",
        "measured_prover_time_gate": "pending paired full-prover measurement",
        "new_error_budget_bits": NEW_ERROR_BUDGET_BITS,
        "degree_12_check_bits": DEGREE_12_CHECK_BITS,
        "five_close_union_bits": FIVE_CLOSE_CHECK_BITS,
        "conditional_128_bit_prg_multi_instance_bits": CONDITIONAL_MULTI_INSTANCE_BITS,
        "conditional_composed_security_bits": COMPOSED_SECURITY_BITS,
        "common_bias_attack_bits_single_instance": COMMON_BIAS_ONE_SELECTION[0],
        "common_bias_attack_bits_253_instances": COMMON_BIAS_MULTI_INSTANCE_BITS,
        "xor4_maj7_resilience": XOR4_MAJ7_RESILIENCE,
        "xor4_maj7_algebraic_immunity": XOR4_MAJ7_ALGEBRAIC_IMMUNITY,
        "group_and_solve_small_majority_bound": GROUP_AND_SOLVE_SMALL_MAJ_BOUND,
        "xor4_maj7_security_credit": "owner-admitted XOR4-MAJ7-128 assumption",
        "source_graph_audit": "pass",
    }
)

#!/usr/bin/env python3
"""Executable pre-backend roofline for the C6 transparent wrapper.

The report has three deliberately separate scopes:

* exact integer capacity and worst-case wire accounting;
* exact rational statistical-error accounting;
* informative time screening from already-recorded A100 kernel anchors.

The time screen is not an end-to-end benchmark or a hardware gate verdict.
It rejects reuse of the historical X4c engine and quantifies the remaining
integration budget for the response-local fused CUDA backend.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from functools import lru_cache
from typing import Any


GOLDILOCKS_P = 2**64 - 2**32 + 1
FP2_CARDINALITY = GOLDILOCKS_P**2

SELECTED_QUERY_COUNT = 86
PCS_REPETITIONS = 2
PCS_RATE_LOG2 = 3
ACTIVE_POLYNOMIALS = 72
MAX_WEIGHT_ORACLE_LOG2 = 28
MAX_AUX_ORACLE_LOG2 = 19
FOLD_TERMINAL_LOG2 = 3

FP2_BYTES = 16
DIGEST_BYTES = 32
PACKED_FRAME_FIXED_METADATA_BYTES = 51
PACKED_GROUP_FIXED_METADATA_BYTES = 21
PACKED_FOLD_ROUND_METADATA_BYTES = 10
FOLD_COMMITMENT_FRAME_BYTES = 90
FINAL_FOLD_EXTRA_SYMBOL_BYTES = FP2_BYTES

# The persistent-cache descendant adds one predecessor-state PCS group. Its
# exact packed opening leaves 620,534 B below the binding 4.5-MB proof cap;
# 600,000 B is frozen before the cache codec/backend and may not be enlarged
# after timing measurements.
NON_PCS_ALLOCATION_BYTES = 600_000
PI_FINAL_CAP_BYTES = 4_500_000
RETAINED_RESPONSE_BYTES = 29_176_632
RESPONSE_CAP_BYTES = 35_000_000
BASE_SHARE_SEED_BYTES = 32
RELATION_SEED_BYTES = 32
RESIDUAL_SEED_BYTES = BASE_SHARE_SEED_BYTES + RELATION_SEED_BYTES
CHALLENGE_ORDER_INCREMENTAL_BYTES = RELATION_SEED_BYTES

PCG_SETUP_BYTES_PER_TAPE = 38_371_465
RESIDUAL_MAC_TAPES = 2
SETUP_CAP_BYTES = 150_000_000

CACHE_ROOT_BOUND_PER_REPETITION = 2**32
CACHE_TRANSITION_ROUNDS = 24
CACHE_TRANSITION_DEGREE = 2
CACHE_TRANSITION_RELATION_BATCH_ROOTS = 3
CACHE_TRANSITION_KV_BATCH_ROOTS = 1
CACHE_TRANSITION_TERMINAL_ROOTS = 1
CACHE_TRANSITION_RELATION_POINT_ROOTS = CACHE_TRANSITION_ROUNDS
CACHE_TRANSITION_ROOTS_PER_REPETITION = (
    CACHE_TRANSITION_DEGREE * CACHE_TRANSITION_ROUNDS
    + CACHE_TRANSITION_RELATION_BATCH_ROOTS
    + CACHE_TRANSITION_KV_BATCH_ROOTS
    + CACHE_TRANSITION_TERMINAL_ROOTS
    + CACHE_TRANSITION_RELATION_POINT_ROOTS
)
CACHE_TRANSITION_EVENT_NUMERATOR = CACHE_TRANSITION_ROOTS_PER_REPETITION**2
# The hidden-u reducers and the pending-output -> packed-PCS authenticated
# link remain one named linear-functional event.  The v3 hiding amendment
# reserves 256 roots per independent repetition for their union.
LINEAR_LINK_ROOT_BOUND_PER_REPETITION = 2**8
HIDDEN_LINEAR_NUMERATOR = LINEAR_LINK_ROOT_BOUND_PER_REPETITION**2
RESIDUAL_PROOF_REPETITIONS = 2
RESIDUAL_MAC_COORDINATES = 2
RESIDUAL_TERMINAL_FORM_KINDS = 2
RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_COUNT = 8
RESIDUAL_LEAF_TABLE_SLOTS = tuple(range(8))
RESIDUAL_AUXILIARY_TABLE_SLOTS = tuple(range(16))
RESIDUAL_TABLE_SLOTS_PER_PROOF_REPETITION = (
    len(RESIDUAL_LEAF_TABLE_SLOTS) + len(RESIDUAL_AUXILIARY_TABLE_SLOTS)
)
RESIDUAL_TABLE_SLOT_REFERENCES = (
    RESIDUAL_PROOF_REPETITIONS * RESIDUAL_TABLE_SLOTS_PER_PROOF_REPETITION
)
RESIDUAL_POST_ROOT_TERMINAL_STREAMS = (
    RESIDUAL_PROOF_REPETITIONS
    * RESIDUAL_MAC_COORDINATES
    * RESIDUAL_TERMINAL_FORM_KINDS
)
RESIDUAL_ALPHA_STREAMS = RESIDUAL_MAC_COORDINATES
RESIDUAL_ATOMIC_WEIGHT_STREAMS = RESIDUAL_PROOF_REPETITIONS
RESIDUAL_COMPLETE_RELATION_STREAMS = (
    RESIDUAL_POST_ROOT_TERMINAL_STREAMS + RESIDUAL_ATOMIC_WEIGHT_STREAMS
)
RESIDUAL_LEAF_TABLE_LOG2 = 23
RESIDUAL_AUXILIARY_TABLE_LOG2 = 16
RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_PER_PROOF_REPETITION = (
    len(RESIDUAL_LEAF_TABLE_SLOTS) * 2**RESIDUAL_LEAF_TABLE_LOG2
    + len(RESIDUAL_AUXILIARY_TABLE_SLOTS) * 2**RESIDUAL_AUXILIARY_TABLE_LOG2
)
RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_SPLIT_V1 = (
    RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_PER_PROOF_REPETITION
)
RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_COMPLETE_V2 = (
    RESIDUAL_PROOF_REPETITIONS
    * RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_PER_PROOF_REPETITION
)
RESIDUAL_OWNER_ADDITIONAL_COEFFICIENT_SYMBOLS = (
    RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_COMPLETE_V2
    - RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_SPLIT_V1
)
RESIDUAL_SUMCHECK_DEGREE_ROUNDS = 2 * 23 + 3 * 15
RESIDUAL_ACTIVATION_ZERO_OPEN_ROOTS = 1
# Rust's ProductClosure uses the scalar-power weights chi^(j+1), so the
# implementation theorem charges T+2 roots for T terminal products.
RESIDUAL_TERMINAL_PRODUCT_ROOTS = (
    RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_COUNT + 2
)
RESIDUAL_TERMINAL_ZERO_ROWS = 2
# The scalar-power ZeroBatch implementation theorem charges T+1 roots.
RESIDUAL_TERMINAL_ZERO_BATCH_ROOTS = RESIDUAL_TERMINAL_ZERO_ROWS + 1
RESIDUAL_BLIND_TRANSCRIPT_ROOTS_PER_COMPLETE_PROOF_REPETITION = (
    RESIDUAL_SUMCHECK_DEGREE_ROUNDS
    + RESIDUAL_ACTIVATION_ZERO_OPEN_ROOTS
    + RESIDUAL_TERMINAL_PRODUCT_ROOTS
    + RESIDUAL_TERMINAL_ZERO_BATCH_ROOTS
)
RESIDUAL_CLEAR_SUMCHECK_PROOF_BYTES = 4_244
RESIDUAL_BLIND_FIRST_ROUND_VALUES_PER_REPETITION = (3 + 2 * 22) + (4 + 3 * 14)
RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE = (
    RESIDUAL_PROOF_REPETITIONS
    * (
        RESIDUAL_BLIND_FIRST_ROUND_VALUES_PER_REPETITION
        + RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_COUNT
        + 1  # one ProductMaskCorr for the eight terminal products
        + 1  # one terminal ZeroBatch mask
    )
)
RESIDUAL_PENDING_SLOT_FULL_CORRELATIONS_PER_TAPE = (
    RESIDUAL_TABLE_SLOT_REFERENCES
)
RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE = (
    RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE
    + RESIDUAL_PENDING_SLOT_FULL_CORRELATIONS_PER_TAPE
)
HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE = 39_116

# C6FT1: one response-fixed correction for every canonical runtime cache
# target on both MAC tapes.  These are linear aggregates of correlations
# already consumed by the model, not fresh authentications.  The fixed tail
# is canonical zero when fewer than the two phase slots are live.
CACHE_FOLD_TARGET_CAPACITY = 576
CACHE_FOLD_TARGET_TAPES = 2
CACHE_FOLD_TARGET_HEADER_BYTES = 48
CACHE_FOLD_TARGET_CORRECTION_BYTES = (
    CACHE_FOLD_TARGET_CAPACITY * CACHE_FOLD_TARGET_TAPES * FP2_BYTES
)
CACHE_FOLD_TARGET_FRAME_BYTES = (
    CACHE_FOLD_TARGET_HEADER_BYTES + CACHE_FOLD_TARGET_CORRECTION_BYTES
)
CACHE_FOLD_TARGET_FRESH_CORRELATIONS_PER_TAPE = 0

# Exact registered wrapper consumers of the historical PCS full-correlation
# reserve.  C6FT1 does not increase this subtotal.
HIDDEN_U_FULL_CORRELATIONS_PER_TAPE = 164
AUTHENTICATED_OUTPUT_LINK_FULL_CORRELATIONS_PER_TAPE = 100
CACHE_BLIND_FULL_CORRELATIONS_PER_TAPE = 104
REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE = (
    RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE
    + HIDDEN_U_FULL_CORRELATIONS_PER_TAPE
    + AUTHENTICATED_OUTPUT_LINK_FULL_CORRELATIONS_PER_TAPE
    + CACHE_BLIND_FULL_CORRELATIONS_PER_TAPE
    + CACHE_FOLD_TARGET_FRESH_CORRELATIONS_PER_TAPE
)

# C6RSC3: dual-tape corrections for 93 round values/repetition, one
# activation-time split ZeroOpen tag/tape, eight terminal product-value
# corrections/tape, one two-symbol ProductClosure/tape and one
# correction+tag ZeroBatch/tape, plus the unchanged 116-byte strict framing.
RESIDUAL_SUMCHECK_PROOF_BYTES = (
    RESIDUAL_PROOF_REPETITIONS
    * RESIDUAL_BLIND_FIRST_ROUND_VALUES_PER_REPETITION
    * RESIDUAL_MAC_TAPES
    * FP2_BYTES
    + RESIDUAL_PROOF_REPETITIONS * RESIDUAL_MAC_TAPES * FP2_BYTES
    + RESIDUAL_PROOF_REPETITIONS
    * RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_COUNT
    * RESIDUAL_MAC_TAPES
    * FP2_BYTES
    + RESIDUAL_PROOF_REPETITIONS * RESIDUAL_MAC_TAPES * 2 * FP2_BYTES
    + RESIDUAL_PROOF_REPETITIONS * RESIDUAL_MAC_TAPES * 2 * FP2_BYTES
    + 116
)
DELTA_ROOT_BOUND_PER_COMPLETE_REPETITION = 2**8
# The clear complete-relation event and the dual-tape blind-transcript
# closure are two named bad branches inside the same Delta-residual event.
DELTA_EVENT_NUMERATOR = 2 * DELTA_ROOT_BOUND_PER_COMPLETE_REPETITION**2

# Frozen T1 atomic-relation census from C6RLM1.  The auxiliary semantic
# domain is the lower half of each 2^16 table; the independently randomized
# upper half is selected away rather than constrained to zero.
T1_SOURCE_COUNT = 4_975_525
T1_PRODUCT_MASK_COUNT = 673
T1_PRODUCT_CLOSURE_COUNT = 673
T1_PRODUCT_TRIPLE_COUNT = 22_339
T1_ZERO_ROOT_COUNT = 8_170
RESIDUAL_LEAF_SEMANTIC_ENTRIES = 2**23
RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES = 2**15
RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_TUPLES = (
    (0, 2),
    (0, 3),
    (1, 2),
    (1, 3),
    (6, 8),
    (6, 9),
    (7, 8),
    (7, 9),
)

RESIDUAL_SOURCE_ATOMIC_OUTPUTS_PER_REPETITION = 3 * T1_SOURCE_COUNT
RESIDUAL_AFFINE_ATOMIC_OUTPUTS_PER_REPETITION = 2 * RESIDUAL_MAC_COORDINATES
RESIDUAL_REVERSE_OUTER_OUTPUTS_PER_REPETITION = (
    2 * RESIDUAL_MAC_COORDINATES
)
RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION = (
    12 * T1_PRODUCT_TRIPLE_COUNT + 4 * T1_ZERO_ROOT_COUNT
)
RESIDUAL_PRODUCT_ATOMIC_OUTPUTS_PER_REPETITION = (
    T1_PRODUCT_CLOSURE_COUNT * RESIDUAL_MAC_COORDINATES * 3
)
RESIDUAL_ZERO_ATOMIC_OUTPUTS_PER_REPETITION = RESIDUAL_MAC_COORDINATES
RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION = (
    7 * (RESIDUAL_LEAF_SEMANTIC_ENTRIES - T1_SOURCE_COUNT)
    + (
        RESIDUAL_LEAF_SEMANTIC_ENTRIES
        - RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION
    )
)
RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION = (
    12 * (RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES - T1_PRODUCT_TRIPLE_COUNT)
    + 4 * (RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES - T1_ZERO_ROOT_COUNT)
)
RESIDUAL_ATOMIC_OUTPUTS_PER_REPETITION = sum(
    (
        RESIDUAL_SOURCE_ATOMIC_OUTPUTS_PER_REPETITION,
        RESIDUAL_AFFINE_ATOMIC_OUTPUTS_PER_REPETITION,
        RESIDUAL_REVERSE_OUTER_OUTPUTS_PER_REPETITION,
        RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION,
        RESIDUAL_PRODUCT_ATOMIC_OUTPUTS_PER_REPETITION,
        RESIDUAL_ZERO_ATOMIC_OUTPUTS_PER_REPETITION,
        RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION,
        RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION,
    )
)
RESIDUAL_ATOMIC_OUTPUTS_TOTAL = (
    RESIDUAL_PROOF_REPETITIONS * RESIDUAL_ATOMIC_OUTPUTS_PER_REPETITION
)

RESIDUAL_TERMINAL_OUTPUTS_PER_SCHEDULE = (
    3 * T1_PRODUCT_TRIPLE_COUNT + T1_ZERO_ROOT_COUNT
)
RESIDUAL_TERMINAL_SCHEDULES_PER_REPETITION = (
    RESIDUAL_MAC_COORDINATES * RESIDUAL_TERMINAL_FORM_KINDS
)
RESIDUAL_TERMINAL_OUTPUTS_PER_REPETITION = (
    RESIDUAL_TERMINAL_SCHEDULES_PER_REPETITION
    * RESIDUAL_TERMINAL_OUTPUTS_PER_SCHEDULE
)
RESIDUAL_TERMINAL_OUTPUTS_TOTAL = (
    RESIDUAL_PROOF_REPETITIONS * RESIDUAL_TERMINAL_OUTPUTS_PER_REPETITION
)

# Exact coefficient-accumulation write census for the frozen atomic grammar.
# The timing screen later charges one read plus one write/multiply-add for
# every such update, in addition to every expander output.
T1_DIRECT_SOURCE_COUNT = T1_SOURCE_COUNT - T1_PRODUCT_MASK_COUNT
RESIDUAL_SOURCE_COEFFICIENT_WRITES_PER_REPETITION = (
    6 * T1_DIRECT_SOURCE_COUNT + 3 * T1_PRODUCT_MASK_COUNT
)
RESIDUAL_AFFINE_COEFFICIENT_WRITES_PER_REPETITION = 6 * T1_SOURCE_COUNT
RESIDUAL_REVERSE_COEFFICIENT_WRITES_PER_REPETITION = (
    4 * T1_SOURCE_COUNT
    + 12 * T1_PRODUCT_TRIPLE_COUNT
    + 4 * T1_ZERO_ROOT_COUNT
)
RESIDUAL_RAW_COPY_COEFFICIENT_WRITES_PER_REPETITION = (
    2 * RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION
)
RESIDUAL_PRODUCT_COEFFICIENT_WRITES_PER_REPETITION = (
    12 * T1_PRODUCT_TRIPLE_COUNT + 4 * T1_PRODUCT_CLOSURE_COUNT
)
RESIDUAL_ZERO_COEFFICIENT_WRITES_PER_REPETITION = 2 * T1_ZERO_ROOT_COUNT
RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION = sum(
    (
        RESIDUAL_SOURCE_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_AFFINE_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_REVERSE_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_RAW_COPY_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_PRODUCT_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_ZERO_COEFFICIENT_WRITES_PER_REPETITION,
        RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION,
        RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION,
    )
)
RESIDUAL_COEFFICIENT_WRITES_TOTAL = (
    RESIDUAL_PROOF_REPETITIONS * RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION
)
RESIDUAL_ATOMIC_REFERENCE_COMPILER_EQUIVALENT_SYMBOLS = (
    RESIDUAL_ATOMIC_OUTPUTS_TOTAL
    + RESIDUAL_TERMINAL_OUTPUTS_TOTAL
    + 2 * RESIDUAL_COEFFICIENT_WRITES_TOTAL
)

# Production-safe two-pass/fused screen.  Per repetition the provider:
# (1) replays once to fix both first messages before any challenge,
# (2) replays after the first leaf challenge to build only the half-size
#     folded leaf coefficient state, and
# (3) replays after auxiliary activation to build only its half-size state.
# The client replays once at the terminal point and retains no coefficient
# vector.  The factor 10 charges at most three first-message accumulations
# (read+write each), one folded-state accumulation and one client-terminal
# accumulation for every coefficient contribution.
RESIDUAL_FUSED_ATOMIC_REPLAYS = 4
RESIDUAL_FUSED_ACCUMULATION_SYMBOLS_PER_WRITE = 10
RESIDUAL_FUSED_COMPILER_EQUIVALENT_SYMBOLS = (
    RESIDUAL_FUSED_ATOMIC_REPLAYS * RESIDUAL_ATOMIC_OUTPUTS_TOTAL
    + RESIDUAL_TERMINAL_OUTPUTS_TOTAL
    + RESIDUAL_FUSED_ACCUMULATION_SYMBOLS_PER_WRITE
    * RESIDUAL_COEFFICIENT_WRITES_TOTAL
)
RESIDUAL_MAX_FOLDED_COEFFICIENT_ELEMENTS = (
    len(RESIDUAL_LEAF_TABLE_SLOTS) * 2 ** (23 - 1)
)
RESIDUAL_MAX_FOLDED_COEFFICIENT_BYTES = (
    RESIDUAL_MAX_FOLDED_COEFFICIENT_ELEMENTS * FP2_BYTES
)

SUMCHECK_BASE_EQUIVALENT_PASSES = 32
COMMIT_RECOMPUTE_PASSES = 2

# Immutable informative measurement anchors.  These are copied verbatim from
# the clean records named in `build_report`; no current machine is sampled.
C4_MODEL_PROVE_RESPONSE_SECONDS = Decimal("4.104595717")
P7_NTT_BYTES = Decimal(268_435_456)
P7_NTT_SECONDS = Decimal("0.006385701")
P7_BLAKE3_BYTES = Decimal(268_435_456)
P7_BLAKE3_SECONDS = Decimal("0.001407478")
P7_STREAM_BYTES_PER_SECOND = Decimal("418.038245551") * Decimal(10**9)
P7_FP2_MULS_PER_SECOND = Decimal("8709130115.65")
X4C_SEAL_SECONDS = Decimal("111.552679710")
X4C_INITIAL_ENCODED_SYMBOLS = 4_809_293_824
X4C_COMBINED_CODEWORD_SYMBOLS = 1_159_200_768


@dataclass(frozen=True)
class WrapperCohort:
    name: str
    oracle_kind: str
    coefficient_log2: int
    slot_count: int
    touched_slots: int
    encoded_domain_log2: int

    def validate(self) -> None:
        if self.oracle_kind not in {"weight", "auxiliary"}:
            raise ValueError(f"unknown oracle kind for {self.name}")
        if self.slot_count <= 0 or self.slot_count & (self.slot_count - 1):
            raise ValueError(f"slot count is not a power of two for {self.name}")
        if self.touched_slots != self.slot_count:
            raise ValueError(f"C6 roofline requires every slot touched for {self.name}")
        expected_expansion = 4 if self.oracle_kind == "weight" else PCS_RATE_LOG2
        if self.encoded_domain_log2 != self.coefficient_log2 + expected_expansion:
            raise ValueError(f"encoded domain mismatch for {self.name}")

    @property
    def coefficient_symbols(self) -> int:
        return self.slot_count * 2**self.coefficient_log2

    @property
    def encoded_symbols(self) -> int:
        return self.slot_count * 2**self.encoded_domain_log2


COHORTS = (
    WrapperCohort("predecessor_cache_state", "weight", 24, 8, 8, 28),
    WrapperCohort("successor_cache_state", "weight", 24, 8, 8, 28),
    WrapperCohort("paired_delta_residual", "weight", 23, 8, 8, 27),
    WrapperCohort("hidden_u_weights", "weight", 21, 8, 8, 25),
    WrapperCohort("hidden_u_embed", "weight", 19, 8, 8, 23),
    WrapperCohort("wrapper_auxiliary", "auxiliary", 16, 32, 32, 19),
)


@dataclass(frozen=True)
class DomainWireMaximum:
    domain_log2: int
    distinct_half_indices: int
    opened_symbols: int
    outer_siblings: int
    payload_bytes: int


@lru_cache(maxsize=None)
def max_merkle_frontier(depth: int, opened_leaves: int) -> int:
    """Exact maximum sibling count for `opened_leaves` in a depth-`depth` tree."""

    if depth < 0 or opened_leaves <= 0 or opened_leaves > 2**depth:
        raise ValueError("invalid Merkle frontier geometry")
    if depth == 0:
        return 0

    half_capacity = 2 ** (depth - 1)
    best = -1
    if opened_leaves <= half_capacity:
        # All leaves can be placed in one child.  The unopened child root is
        # one additional authentication node.
        best = max_merkle_frontier(depth - 1, opened_leaves) + 1
    first_left = max(1, opened_leaves - half_capacity)
    last_left = min(half_capacity, opened_leaves - 1)
    for left in range(first_left, last_left + 1):
        right = opened_leaves - left
        candidate = max_merkle_frontier(depth - 1, left) + max_merkle_frontier(
            depth - 1, right
        )
        best = max(best, candidate)
    if best < 0:
        raise AssertionError("Merkle frontier recurrence has no legal split")
    return best


def paired_domain_wire_maximum(
    domain_log2: int, query_count: int, touched_slots: int
) -> DomainWireMaximum:
    """Maximize symbols plus frontier bytes for projected `+/-` query pairs."""

    if domain_log2 <= 1 or query_count <= 0 or touched_slots <= 0:
        raise ValueError("invalid projected-query geometry")
    half_depth = domain_log2 - 1
    maximum_distinct = min(query_count, 2**half_depth)
    candidates: list[DomainWireMaximum] = []
    for distinct in range(1, maximum_distinct + 1):
        opened = 2 * distinct
        outer = 2 * max_merkle_frontier(half_depth, distinct)
        symbols = opened * touched_slots
        payload = FP2_BYTES * symbols + DIGEST_BYTES * outer
        candidates.append(
            DomainWireMaximum(
                domain_log2=domain_log2,
                distinct_half_indices=distinct,
                opened_symbols=symbols,
                outer_siblings=outer,
                payload_bytes=payload,
            )
        )
    # Stable tie-breaking chooses the smaller distinct set.  The byte maximum
    # is what the cap uses; no soundness credit depends on this choice.
    return max(
        candidates,
        key=lambda item: (item.payload_bytes, -item.distinct_half_indices),
    )


def packed_section_report(query_count: int) -> dict[str, Any]:
    if query_count <= 0:
        raise ValueError("query count must be positive")
    for cohort in COHORTS:
        cohort.validate()

    initial = [
        paired_domain_wire_maximum(
            cohort.encoded_domain_log2, query_count, cohort.touched_slots
        )
        for cohort in COHORTS
    ]
    fold_domains = list(
        range(MAX_WEIGHT_ORACLE_LOG2 - 1, FOLD_TERMINAL_LOG2 - 1, -1)
    )
    folds = [
        paired_domain_wire_maximum(domain_log2, query_count, 1)
        for domain_log2 in fold_domains
    ]
    opened_symbols = sum(item.opened_symbols for item in initial + folds)
    outer_siblings = sum(item.outer_siblings for item in initial + folds)
    inner_siblings = 0
    metadata_bytes = (
        PACKED_FRAME_FIXED_METADATA_BYTES
        + sum(
            PACKED_GROUP_FIXED_METADATA_BYTES + 2 * cohort.touched_slots
            for cohort in COHORTS
        )
        + PACKED_FOLD_ROUND_METADATA_BYTES * len(folds)
    )
    serialized_bytes = (
        FP2_BYTES * opened_symbols
        + DIGEST_BYTES * (inner_siblings + outer_siblings)
        + metadata_bytes
    )
    fold_commitment_bytes = (
        FOLD_COMMITMENT_FRAME_BYTES * len(folds) + FINAL_FOLD_EXTRA_SYMBOL_BYTES
    )
    return {
        "query_count": query_count,
        "initial_domain_maxima": [asdict(item) for item in initial],
        "fold_domain_maxima": [asdict(item) for item in folds],
        "fold_rounds": len(folds),
        "opened_symbols": opened_symbols,
        "inner_siblings": inner_siblings,
        "outer_siblings": outer_siblings,
        "metadata_bytes": metadata_bytes,
        "packed_section_bytes": serialized_bytes,
        "fold_commitment_bytes": fold_commitment_bytes,
        "chain_bytes": serialized_bytes + fold_commitment_bytes,
    }


def rational_decimal(value: Fraction, precision: int = 90) -> Decimal:
    with localcontext() as context:
        context.prec = precision
        return Decimal(value.numerator) / Decimal(value.denominator)


def soundness_bits(error: Fraction, precision: int = 90) -> Decimal:
    if error <= 0:
        raise ValueError("soundness error must be positive")
    with localcontext() as context:
        context.prec = precision
        value = Decimal(error.numerator) / Decimal(error.denominator)
        return -(value.ln() / Decimal(2).ln())


def pcs_error_one_repetition(query_count: int) -> Fraction:
    field_roots = ACTIVE_POLYNOMIALS * (
        (2**MAX_WEIGHT_ORACLE_LOG2 - 1) + (2**MAX_AUX_ORACLE_LOG2 - 1)
    )
    return (
        Fraction(ACTIVE_POLYNOMIALS) * Fraction(9, 16) ** query_count
        + Fraction(field_roots, FP2_CARDINALITY)
    )


def pcs_error_amplified(query_count: int) -> Fraction:
    return pcs_error_one_repetition(query_count) ** PCS_REPETITIONS


def minimum_literal_128_bit_query_count() -> int:
    allocation = Fraction(1, 2**128)
    for query_count in range(1, 513):
        if pcs_error_amplified(query_count) <= allocation:
            return query_count
    raise AssertionError("no query count <=512 reaches 128 bits")


def ligero_q121_error() -> Fraction:
    weights_rate = Fraction(8_192 + 512, 32_768)
    embed_rate = Fraction(32_768 + 512, 131_072)
    weights = (
        (1 - (1 - weights_rate) / 2) ** 121
        + Fraction(24_576 + 96 + 1, FP2_CARDINALITY)
    )
    embed = (
        (1 - (1 - embed_rate) / 2) ** 121
        + Fraction(2_080 + 6 + 1, FP2_CARDINALITY)
    )
    return weights + embed


def build_report() -> dict[str, Any]:
    section = packed_section_report(SELECTED_QUERY_COUNT)
    pcs_bytes = PCS_REPETITIONS * section["chain_bytes"]
    pi_final_maximum = pcs_bytes + NON_PCS_ALLOCATION_BYTES
    response_maximum = RETAINED_RESPONSE_BYTES + pi_final_maximum

    pcs_error = pcs_error_amplified(SELECTED_QUERY_COUNT)
    hidden_error = Fraction(HIDDEN_LINEAR_NUMERATOR, FP2_CARDINALITY**2)
    cache_error = Fraction(
        CACHE_ROOT_BOUND_PER_REPETITION**2, FP2_CARDINALITY**2
    )
    delta_error = Fraction(DELTA_EVENT_NUMERATOR, FP2_CARDINALITY**2)
    wrapper_error = pcs_error + hidden_error + cache_error + delta_error
    complete_error = ligero_q121_error() + wrapper_error

    initial_encoded_symbols = sum(cohort.encoded_symbols for cohort in COHORTS)
    coefficient_symbols = sum(cohort.coefficient_symbols for cohort in COHORTS)
    fold_symbols = PCS_REPETITIONS * (
        2**MAX_WEIGHT_ORACLE_LOG2 - 2**FOLD_TERMINAL_LOG2
    )
    initial_encoded_bytes = initial_encoded_symbols * FP2_BYTES
    coefficient_bytes = coefficient_symbols * FP2_BYTES
    fold_bytes = fold_symbols * FP2_BYTES

    with localcontext() as context:
        context.prec = 60
        ntt_bytes_per_second = P7_NTT_BYTES / P7_NTT_SECONDS
        blake3_bytes_per_second = P7_BLAKE3_BYTES / P7_BLAKE3_SECONDS
        one_commit_recompute_pass = (
            Decimal(initial_encoded_bytes) / ntt_bytes_per_second
            + Decimal(initial_encoded_bytes + fold_bytes) / blake3_bytes_per_second
            + Decimal(fold_bytes) / P7_STREAM_BYTES_PER_SECOND
        )
        sumcheck_work_coefficient_symbols = (
            SUMCHECK_BASE_EQUIVALENT_PASSES * coefficient_symbols
            + RESIDUAL_OWNER_ADDITIONAL_COEFFICIENT_SYMBOLS
            + RESIDUAL_FUSED_COMPILER_EQUIVALENT_SYMBOLS
        )
        sumcheck_work_bytes = sumcheck_work_coefficient_symbols * FP2_BYTES
        sumcheck_equivalent_passes = (
            Decimal(sumcheck_work_coefficient_symbols)
            / Decimal(coefficient_symbols)
        )
        sumcheck_memory_seconds = (
            Decimal(sumcheck_work_bytes) / P7_STREAM_BYTES_PER_SECOND
        )
        sumcheck_arithmetic_seconds = (
            Decimal(sumcheck_work_coefficient_symbols)
            / P7_FP2_MULS_PER_SECOND
        )
        sumcheck_floor_seconds = max(
            sumcheck_memory_seconds, sumcheck_arithmetic_seconds
        )
        wrapper_kernel_floor_seconds = (
            Decimal(COMMIT_RECOMPUTE_PASSES) * one_commit_recompute_pass
            + sumcheck_floor_seconds
        )
        total_kernel_floor_seconds = (
            C4_MODEL_PROVE_RESPONSE_SECONDS + wrapper_kernel_floor_seconds
        )
        integration_budget_to_ceiling = Decimal("20") - total_kernel_floor_seconds
        integration_budget_to_target_low = (
            Decimal("11") - total_kernel_floor_seconds
        )
        integration_budget_to_target_high = (
            Decimal("18") - total_kernel_floor_seconds
        )
        legacy_wrapper_projection = X4C_SEAL_SECONDS * Decimal(
            initial_encoded_symbols + fold_symbols
        ) / Decimal(X4C_INITIAL_ENCODED_SYMBOLS + X4C_COMBINED_CODEWORD_SYMBOLS)
        legacy_total_projection = (
            C4_MODEL_PROVE_RESPONSE_SECONDS + legacy_wrapper_projection
        )

    paired_setup_bytes = RESIDUAL_MAC_TAPES * PCG_SETUP_BYTES_PER_TAPE
    report: dict[str, Any] = {
        "schema": "volta-c6-wrapper-roofline-v2",
        "profile": "c6-transparent-rate8-s86-p72-persistent-cache-v2",
        "capacity": {
            "rate_log2": PCS_RATE_LOG2,
            "selected_query_count": SELECTED_QUERY_COUNT,
            "pcs_repetitions": PCS_REPETITIONS,
            "active_polynomials": ACTIVE_POLYNOMIALS,
            "cohorts": [
                {
                    **asdict(cohort),
                    "coefficient_symbols": cohort.coefficient_symbols,
                    "encoded_symbols": cohort.encoded_symbols,
                }
                for cohort in COHORTS
            ],
            "initial_encoded_symbols": initial_encoded_symbols,
            "initial_encoded_bytes": initial_encoded_bytes,
            "coefficient_symbols": coefficient_symbols,
            "coefficient_bytes": coefficient_bytes,
            "two_chain_fold_symbols": fold_symbols,
            "two_chain_fold_bytes": fold_bytes,
            "largest_cohort_encoded_bytes": max(
                cohort.encoded_symbols * FP2_BYTES for cohort in COHORTS
            ),
        },
        "wire": {
            "one_chain": section,
            "pcs_repetitions": PCS_REPETITIONS,
            "two_chain_pcs_bytes": pcs_bytes,
            "non_pcs_allocation_bytes": NON_PCS_ALLOCATION_BYTES,
            "base_share_seed_bytes": BASE_SHARE_SEED_BYTES,
            "relation_seed_bytes": RELATION_SEED_BYTES,
            "total_residual_seed_bytes": RESIDUAL_SEED_BYTES,
            "challenge_order_incremental_bytes": (
                CHALLENGE_ORDER_INCREMENTAL_BYTES
            ),
            "residual_seeds_within_non_pcs_allocation": (
                RESIDUAL_SEED_BYTES <= NON_PCS_ALLOCATION_BYTES
            ),
            "pi_final_maximum_bytes": pi_final_maximum,
            "pi_final_cap_bytes": PI_FINAL_CAP_BYTES,
            "pi_final_headroom_bytes": PI_FINAL_CAP_BYTES - pi_final_maximum,
            "retained_response_bytes": RETAINED_RESPONSE_BYTES,
            "complete_response_maximum_bytes": response_maximum,
            "response_cap_bytes": RESPONSE_CAP_BYTES,
            "response_headroom_bytes": RESPONSE_CAP_BYTES - response_maximum,
        },
        "setup": {
            "residual_mac_tapes": RESIDUAL_MAC_TAPES,
            "pcg_setup_bytes_per_tape": PCG_SETUP_BYTES_PER_TAPE,
            "paired_pcg_setup_bytes": paired_setup_bytes,
            "setup_cap_bytes": SETUP_CAP_BYTES,
            "client_params_and_framing_budget_bytes": (
                SETUP_CAP_BYTES - paired_setup_bytes
            ),
        },
        "cache_fold_target_bootstrap": {
            "magic": "C6FT1",
            "target_capacity": CACHE_FOLD_TARGET_CAPACITY,
            "mac_tapes": CACHE_FOLD_TARGET_TAPES,
            "header_bytes": CACHE_FOLD_TARGET_HEADER_BYTES,
            "correction_bytes": CACHE_FOLD_TARGET_CORRECTION_BYTES,
            "frame_bytes": CACHE_FOLD_TARGET_FRAME_BYTES,
            "fresh_full_correlations_per_tape": (
                CACHE_FOLD_TARGET_FRESH_CORRELATIONS_PER_TAPE
            ),
            "non_pcs_allocation_remaining_after_frame_bytes": (
                NON_PCS_ALLOCATION_BYTES - CACHE_FOLD_TARGET_FRAME_BYTES
            ),
            "registered_wrapper_full_correlations_per_tape": (
                REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
            ),
            "historical_full_correlation_reserve_per_tape": (
                HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE
            ),
            "registered_full_correlation_headroom_per_tape": (
                HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE
                - REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
            ),
        },
        "residual_relation_ownership": {
            "proof_repetitions": RESIDUAL_PROOF_REPETITIONS,
            "mac_coordinates_per_complete_relation": RESIDUAL_MAC_COORDINATES,
            "terminal_form_kinds_per_coordinate": RESIDUAL_TERMINAL_FORM_KINDS,
            "leaf_table_slots_per_proof_repetition": list(
                RESIDUAL_LEAF_TABLE_SLOTS
            ),
            "auxiliary_table_slots_per_proof_repetition": list(
                RESIDUAL_AUXILIARY_TABLE_SLOTS
            ),
            "table_slots_per_proof_repetition": (
                RESIDUAL_TABLE_SLOTS_PER_PROOF_REPETITION
            ),
            "table_slot_references_across_proof_repetitions": (
                RESIDUAL_TABLE_SLOT_REFERENCES
            ),
            "post_root_terminal_challenge_streams": (
                RESIDUAL_POST_ROOT_TERMINAL_STREAMS
            ),
            "base_share_alpha_streams": RESIDUAL_ALPHA_STREAMS,
            "atomic_weight_streams": RESIDUAL_ATOMIC_WEIGHT_STREAMS,
            "complete_relation_streams": RESIDUAL_COMPLETE_RELATION_STREAMS,
            "owner_coefficient_symbols_per_proof_repetition": (
                RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_PER_PROOF_REPETITION
            ),
            "split_v1_owner_coefficient_symbols": (
                RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_SPLIT_V1
            ),
            "complete_v2_owner_coefficient_symbols": (
                RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_COMPLETE_V2
            ),
            "additional_owner_coefficient_symbols": (
                RESIDUAL_OWNER_ADDITIONAL_COEFFICIENT_SYMBOLS
            ),
            "proof_codec_bytes": RESIDUAL_SUMCHECK_PROOF_BYTES,
            "superseded_clear_proof_codec_bytes": (
                RESIDUAL_CLEAR_SUMCHECK_PROOF_BYTES
            ),
            "wire_delta_from_clear_codec_bytes": (
                RESIDUAL_SUMCHECK_PROOF_BYTES
                - RESIDUAL_CLEAR_SUMCHECK_PROOF_BYTES
            ),
            "blind_round_values_per_repetition": (
                RESIDUAL_BLIND_FIRST_ROUND_VALUES_PER_REPETITION
            ),
            "blind_core_full_correlations_per_tape": (
                RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE
            ),
            "pending_slot_full_correlations_per_tape": (
                RESIDUAL_PENDING_SLOT_FULL_CORRELATIONS_PER_TAPE
            ),
            "blind_full_correlations_per_tape": (
                RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE
            ),
            "historical_pcs_full_correlation_reserve_per_tape": (
                HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE
            ),
            "historical_pcs_full_correlation_headroom_after_residual": (
                HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE
                - RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE
            ),
            "wire_slot_addition_bytes": 0,
        },
        "residual_atomic_relation": {
            "manifest": "C6RLM1",
            "claims_fixed_before_relation_seed": True,
            "source_count": T1_SOURCE_COUNT,
            "direct_source_count": T1_DIRECT_SOURCE_COUNT,
            "product_mask_count": T1_PRODUCT_MASK_COUNT,
            "product_closure_count": T1_PRODUCT_CLOSURE_COUNT,
            "product_triple_count": T1_PRODUCT_TRIPLE_COUNT,
            "zero_root_count": T1_ZERO_ROOT_COUNT,
            "leaf_semantic_entries": RESIDUAL_LEAF_SEMANTIC_ENTRIES,
            "auxiliary_semantic_entries": RESIDUAL_AUXILIARY_SEMANTIC_ENTRIES,
            "auxiliary_quadratic_factor_tuples": [
                list(pair)
                for pair in RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_TUPLES
            ],
            "atomic_outputs_per_repetition": {
                "source_grammar": (
                    RESIDUAL_SOURCE_ATOMIC_OUTPUTS_PER_REPETITION
                ),
                "affine": RESIDUAL_AFFINE_ATOMIC_OUTPUTS_PER_REPETITION,
                "reverse_outer": (
                    RESIDUAL_REVERSE_OUTER_OUTPUTS_PER_REPETITION
                ),
                "raw_copy": RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION,
                "product": RESIDUAL_PRODUCT_ATOMIC_OUTPUTS_PER_REPETITION,
                "zero": RESIDUAL_ZERO_ATOMIC_OUTPUTS_PER_REPETITION,
                "leaf_raw_tails": RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION,
                "auxiliary_tails": (
                    RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION
                ),
                "total": RESIDUAL_ATOMIC_OUTPUTS_PER_REPETITION,
            },
            "atomic_outputs_total": RESIDUAL_ATOMIC_OUTPUTS_TOTAL,
            "terminal_outputs_per_schedule": (
                RESIDUAL_TERMINAL_OUTPUTS_PER_SCHEDULE
            ),
            "terminal_schedules_per_repetition": (
                RESIDUAL_TERMINAL_SCHEDULES_PER_REPETITION
            ),
            "terminal_outputs_per_repetition": (
                RESIDUAL_TERMINAL_OUTPUTS_PER_REPETITION
            ),
            "terminal_outputs_total": RESIDUAL_TERMINAL_OUTPUTS_TOTAL,
            "coefficient_writes_per_repetition": {
                "source_grammar": (
                    RESIDUAL_SOURCE_COEFFICIENT_WRITES_PER_REPETITION
                ),
                "affine": (
                    RESIDUAL_AFFINE_COEFFICIENT_WRITES_PER_REPETITION
                ),
                "reverse": (
                    RESIDUAL_REVERSE_COEFFICIENT_WRITES_PER_REPETITION
                ),
                "raw_copy": (
                    RESIDUAL_RAW_COPY_COEFFICIENT_WRITES_PER_REPETITION
                ),
                "product": (
                    RESIDUAL_PRODUCT_COEFFICIENT_WRITES_PER_REPETITION
                ),
                "zero": RESIDUAL_ZERO_COEFFICIENT_WRITES_PER_REPETITION,
                "leaf_raw_tails": RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION,
                "auxiliary_tails": (
                    RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION
                ),
                "total": RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION,
            },
            "coefficient_writes_total": RESIDUAL_COEFFICIENT_WRITES_TOTAL,
            "reference_compiler_equivalent_symbols": (
                RESIDUAL_ATOMIC_REFERENCE_COMPILER_EQUIVALENT_SYMBOLS
            ),
            "fused_atomic_replays": RESIDUAL_FUSED_ATOMIC_REPLAYS,
            "fused_accumulation_symbols_per_write": (
                RESIDUAL_FUSED_ACCUMULATION_SYMBOLS_PER_WRITE
            ),
            "fused_compiler_equivalent_symbols": (
                RESIDUAL_FUSED_COMPILER_EQUIVALENT_SYMBOLS
            ),
            "maximum_folded_coefficient_elements": (
                RESIDUAL_MAX_FOLDED_COEFFICIENT_ELEMENTS
            ),
            "maximum_folded_coefficient_bytes": (
                RESIDUAL_MAX_FOLDED_COEFFICIENT_BYTES
            ),
        },
        "soundness": {
            "fp2_cardinality": str(FP2_CARDINALITY),
            "minimum_literal_128_bit_query_count": (
                minimum_literal_128_bit_query_count()
            ),
            "selected_query_count": SELECTED_QUERY_COUNT,
            "field_root_coefficient_per_pcs_repetition": (
                ACTIVE_POLYNOMIALS
                * (
                    (2**MAX_WEIGHT_ORACLE_LOG2 - 1)
                    + (2**MAX_AUX_ORACLE_LOG2 - 1)
                )
            ),
            "residual_sumcheck_degree_rounds_per_complete_proof_repetition": (
                RESIDUAL_SUMCHECK_DEGREE_ROUNDS
            ),
            "residual_blind_transcript_roots_per_complete_proof_repetition": (
                RESIDUAL_BLIND_TRANSCRIPT_ROOTS_PER_COMPLETE_PROOF_REPETITION
            ),
            "residual_blind_transcript_root_components": {
                "sumcheck_degree_rounds": RESIDUAL_SUMCHECK_DEGREE_ROUNDS,
                "activation_zero_open": RESIDUAL_ACTIVATION_ZERO_OPEN_ROOTS,
                "terminal_product_scalar_power": RESIDUAL_TERMINAL_PRODUCT_ROOTS,
                "terminal_zero_batch_scalar_power": (
                    RESIDUAL_TERMINAL_ZERO_BATCH_ROOTS
                ),
            },
            "delta_root_bound_per_complete_proof_repetition": (
                DELTA_ROOT_BOUND_PER_COMPLETE_REPETITION
            ),
            "delta_event_numerator": DELTA_EVENT_NUMERATOR,
            "cache_transition_roots_per_repetition": (
                CACHE_TRANSITION_ROOTS_PER_REPETITION
            ),
            "cache_transition_event_numerator": (
                CACHE_TRANSITION_EVENT_NUMERATOR
            ),
            "cache_transition_exact_bits": str(
                soundness_bits(
                    Fraction(CACHE_TRANSITION_EVENT_NUMERATOR, FP2_CARDINALITY**2)
                )
            ),
            "event_bits": {
                "wrapper_pcs": str(soundness_bits(pcs_error)),
                "linear_functional_sumchecks": str(soundness_bits(hidden_error)),
                "cache_argument": str(soundness_bits(cache_error)),
                "delta_residual": str(soundness_bits(delta_error)),
            },
            "event_errors": {
                "wrapper_pcs": str(rational_decimal(pcs_error)),
                "linear_functional_sumchecks": str(rational_decimal(hidden_error)),
                "cache_argument": str(rational_decimal(cache_error)),
                "delta_residual": str(rational_decimal(delta_error)),
            },
            "all_events_meet_literal_128_bits": all(
                error <= Fraction(1, 2**128)
                for error in (pcs_error, hidden_error, cache_error, delta_error)
            ),
            "wrapper_union_bits": str(soundness_bits(wrapper_error)),
            "q121_complete_candidate_bits": str(soundness_bits(complete_error)),
        },
        "time_screen": {
            "verdict_scope": "informative-kernel-roofline-not-end-to-end",
            "admitted_backend": "response-local-fused-p7-cuda",
            "forbidden_backend": "historical-x4c-response-engine",
            "commit_recompute_passes": COMMIT_RECOMPUTE_PASSES,
            "sumcheck_base_equivalent_passes": SUMCHECK_BASE_EQUIVALENT_PASSES,
            "ownership_amendment_additional_coefficient_symbols": (
                RESIDUAL_OWNER_ADDITIONAL_COEFFICIENT_SYMBOLS
            ),
            "atomic_relation_reference_compiler_equivalent_symbols": (
                RESIDUAL_ATOMIC_REFERENCE_COMPILER_EQUIVALENT_SYMBOLS
            ),
            "atomic_relation_fused_compiler_equivalent_symbols": (
                RESIDUAL_FUSED_COMPILER_EQUIVALENT_SYMBOLS
            ),
            "sumcheck_work_coefficient_symbols": (
                sumcheck_work_coefficient_symbols
            ),
            "sumcheck_effective_equivalent_passes": str(
                sumcheck_equivalent_passes
            ),
            "ownership_amendment_timing_credit": (
                "none-before-fused-compiler-benchmark"
            ),
            "atomic_relation_compiler_timing_credit": (
                "none-before-fused-compiler-benchmark"
            ),
            "predecessor_cache_recompute_credit": (
                "none-conservative-full-recompute-charged"
            ),
            "base_model_prove_seconds": str(C4_MODEL_PROVE_RESPONSE_SECONDS),
            "one_commit_recompute_pass_seconds": str(one_commit_recompute_pass),
            "sumcheck_memory_floor_seconds": str(sumcheck_memory_seconds),
            "sumcheck_arithmetic_floor_seconds": str(sumcheck_arithmetic_seconds),
            "wrapper_kernel_floor_seconds": str(wrapper_kernel_floor_seconds),
            "total_kernel_floor_seconds": str(total_kernel_floor_seconds),
            "integration_budget_to_20_seconds": str(integration_budget_to_ceiling),
            "integration_budget_to_11_seconds": str(
                integration_budget_to_target_low
            ),
            "integration_budget_to_12_seconds": str(
                Decimal("12") - total_kernel_floor_seconds
            ),
            "integration_budget_to_15_seconds": str(
                Decimal("15") - total_kernel_floor_seconds
            ),
            "integration_budget_to_18_seconds": str(
                integration_budget_to_target_high
            ),
            "legacy_x4c_wrapper_projection_seconds": str(
                legacy_wrapper_projection
            ),
            "legacy_x4c_total_projection_seconds": str(legacy_total_projection),
            "anchors": {
                "p7_ntt_record": (
                    "p7-gpu-pcs-arithmetic-2026-07-11-366ec4a.json"
                ),
                "p7_blake3_record": (
                    "p7-gpu-blake3-merkle-2026-07-11-3b0a916.json"
                ),
                "p7_stream_record": (
                    "p7-gpu-roofline-2026-07-11-a43d105.json"
                ),
                "c4_anchor_record": (
                    "c4-ligero-t1-anchor-a100-2026-07-27-e99a1e5.json"
                ),
                "x4c_record": (
                    "x4c-gpt2-online-accelerated-2026-07-25-6277c3c.json"
                ),
            },
        },
    }

    assert ACTIVE_POLYNOMIALS == sum(cohort.slot_count for cohort in COHORTS)
    assert RESIDUAL_PROOF_REPETITIONS == PCS_REPETITIONS
    assert RESIDUAL_TABLE_SLOTS_PER_PROOF_REPETITION == 24
    assert RESIDUAL_TABLE_SLOT_REFERENCES == 48
    assert RESIDUAL_POST_ROOT_TERMINAL_STREAMS == 8
    assert RESIDUAL_ALPHA_STREAMS == 2
    assert RESIDUAL_ATOMIC_WEIGHT_STREAMS == 2
    assert RESIDUAL_COMPLETE_RELATION_STREAMS == 10
    assert (
        len(RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_TUPLES)
        == RESIDUAL_AUXILIARY_QUADRATIC_FACTOR_COUNT
    )
    assert RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_PER_PROOF_REPETITION == 68_157_440
    assert RESIDUAL_OWNER_COEFFICIENT_SYMBOLS_COMPLETE_V2 == 136_314_880
    assert RESIDUAL_OWNER_ADDITIONAL_COEFFICIENT_SYMBOLS == 68_157_440
    assert RESIDUAL_SEED_BYTES == 64
    assert CHALLENGE_ORDER_INCREMENTAL_BYTES == 32
    assert RESIDUAL_SOURCE_ATOMIC_OUTPUTS_PER_REPETITION == 14_926_575
    assert RESIDUAL_AFFINE_ATOMIC_OUTPUTS_PER_REPETITION == 4
    assert RESIDUAL_REVERSE_OUTER_OUTPUTS_PER_REPETITION == 4
    assert RESIDUAL_RAW_COPY_OUTPUTS_PER_REPETITION == 300_748
    assert RESIDUAL_PRODUCT_ATOMIC_OUTPUTS_PER_REPETITION == 4_038
    assert RESIDUAL_ZERO_ATOMIC_OUTPUTS_PER_REPETITION == 2
    assert RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION == 31_979_441
    assert RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION == 223_540
    assert RESIDUAL_ATOMIC_OUTPUTS_PER_REPETITION == 47_434_352
    assert RESIDUAL_ATOMIC_OUTPUTS_TOTAL == 94_868_704
    assert RESIDUAL_TERMINAL_OUTPUTS_PER_SCHEDULE == 75_187
    assert RESIDUAL_TERMINAL_OUTPUTS_PER_REPETITION == 300_748
    assert RESIDUAL_TERMINAL_OUTPUTS_TOTAL == 601_496
    assert RESIDUAL_SOURCE_COEFFICIENT_WRITES_PER_REPETITION == 29_851_131
    assert RESIDUAL_AFFINE_COEFFICIENT_WRITES_PER_REPETITION == 29_853_150
    assert RESIDUAL_REVERSE_COEFFICIENT_WRITES_PER_REPETITION == 20_202_848
    assert RESIDUAL_RAW_COPY_COEFFICIENT_WRITES_PER_REPETITION == 601_496
    assert RESIDUAL_PRODUCT_COEFFICIENT_WRITES_PER_REPETITION == 270_760
    assert RESIDUAL_ZERO_COEFFICIENT_WRITES_PER_REPETITION == 16_340
    assert RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION == 112_998_706
    assert RESIDUAL_COEFFICIENT_WRITES_TOTAL == 225_997_412
    assert RESIDUAL_ATOMIC_REFERENCE_COMPILER_EQUIVALENT_SYMBOLS == 547_465_024
    assert RESIDUAL_FUSED_ATOMIC_REPLAYS == 4
    assert RESIDUAL_FUSED_ACCUMULATION_SYMBOLS_PER_WRITE == 10
    assert RESIDUAL_FUSED_COMPILER_EQUIVALENT_SYMBOLS == 2_640_050_432
    assert RESIDUAL_MAX_FOLDED_COEFFICIENT_ELEMENTS == 33_554_432
    assert RESIDUAL_MAX_FOLDED_COEFFICIENT_BYTES == 536_870_912
    assert RESIDUAL_BLIND_FIRST_ROUND_VALUES_PER_REPETITION == 93
    assert RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE == 206
    assert RESIDUAL_PENDING_SLOT_FULL_CORRELATIONS_PER_TAPE == 48
    assert RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE == 254
    assert CACHE_FOLD_TARGET_CORRECTION_BYTES == 18_432
    assert CACHE_FOLD_TARGET_FRAME_BYTES == 18_480
    assert CACHE_FOLD_TARGET_FRESH_CORRELATIONS_PER_TAPE == 0
    assert REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE == 622
    assert (
        HISTORICAL_PCS_FULL_CORRELATION_RESERVE_PER_TAPE
        - REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
        == 38_494
    )
    assert CACHE_FOLD_TARGET_FRAME_BYTES <= NON_PCS_ALLOCATION_BYTES
    assert RESIDUAL_SUMCHECK_PROOF_BYTES == 6_900
    assert RESIDUAL_TERMINAL_PRODUCT_ROOTS == 10
    assert RESIDUAL_TERMINAL_ZERO_BATCH_ROOTS == 3
    assert RESIDUAL_BLIND_TRANSCRIPT_ROOTS_PER_COMPLETE_PROOF_REPETITION == 105
    assert (
        RESIDUAL_BLIND_TRANSCRIPT_ROOTS_PER_COMPLETE_PROOF_REPETITION
        <= DELTA_ROOT_BOUND_PER_COMPLETE_REPETITION
    )
    assert HIDDEN_LINEAR_NUMERATOR == 2**16
    assert DELTA_EVENT_NUMERATOR == 2**17
    assert CACHE_TRANSITION_RELATION_POINT_ROOTS == 24
    assert CACHE_TRANSITION_ROOTS_PER_REPETITION == 77
    assert CACHE_TRANSITION_EVENT_NUMERATOR == 5_929
    assert CACHE_TRANSITION_ROOTS_PER_REPETITION <= CACHE_ROOT_BOUND_PER_REPETITION
    assert minimum_literal_128_bit_query_count() == 85
    assert section["opened_symbols"] == 15_904
    assert section["inner_siblings"] == 0
    assert section["outer_siblings"] == 52_576
    assert section["metadata_bytes"] == 571
    assert section["packed_section_bytes"] == 1_937_467
    assert section["fold_commitment_bytes"] == 2_266
    assert section["chain_bytes"] == 1_939_733
    assert pcs_bytes == 3_879_466
    assert pi_final_maximum == 4_479_466
    assert PI_FINAL_CAP_BYTES - pi_final_maximum == 20_534
    assert response_maximum == 33_656_098
    assert RESPONSE_CAP_BYTES - response_maximum == 1_343_902
    assert paired_setup_bytes == 76_742_930
    assert SETUP_CAP_BYTES - paired_setup_bytes == 73_257_070
    assert initial_encoded_symbols == 5_721_030_656
    assert coefficient_symbols == 358_612_992
    assert fold_symbols == 536_870_896
    assert report["soundness"]["all_events_meet_literal_128_bits"] is True
    assert Decimal(report["soundness"]["q121_complete_candidate_bits"]) > Decimal(
        "78.80929487391641"
    )
    assert total_kernel_floor_seconds < Decimal("20")
    assert legacy_total_projection > Decimal("20")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit the canonical JSON report"
    )
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    wire = report["wire"]
    soundness = report["soundness"]
    timing = report["time_screen"]
    print(f"C6 wrapper profile:          {report['profile']}")
    print(f"selected PCS queries:        {soundness['selected_query_count']}")
    print(
        "two-chain PCS:              "
        f"{wire['two_chain_pcs_bytes']:,} B"
    )
    print(
        "pi_final prereg max:         "
        f"{wire['pi_final_maximum_bytes']:,} B"
    )
    print(
        "complete response max:       "
        f"{wire['complete_response_maximum_bytes']:,} B"
    )
    print(
        "PCS event bits:              "
        f"{Decimal(soundness['event_bits']['wrapper_pcs']):.14f}"
    )
    print(
        "Q121 complete bits:          "
        f"{Decimal(soundness['q121_complete_candidate_bits']):.14f}"
    )
    print(
        "kernel floor incl. model:    "
        f"{Decimal(timing['total_kernel_floor_seconds']):.3f} s (informative)"
    )
    print(
        "integration budget to 20 s:  "
        f"{Decimal(timing['integration_budget_to_20_seconds']):.3f} s"
    )
    print(
        "legacy X4c projection:       "
        f"{Decimal(timing['legacy_x4c_total_projection_seconds']):.3f} s (rejected)"
    )


if __name__ == "__main__":
    main()

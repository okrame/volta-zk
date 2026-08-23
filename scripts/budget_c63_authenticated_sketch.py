#!/usr/bin/env python3
"""C6.3 authenticated-sketch arithmetic screen; grants no protocol credit."""

from __future__ import annotations

import json
import math
from decimal import ROUND_CEILING, Decimal, getcontext
from fractions import Fraction
from typing import Any

import budget_c62_whir_fiat_shamir as c62
import budget_c6_wrapper as c6


getcontext().prec = 80

FP2_BYTES = 16
SUBFIELD_CORRECTION_BYTES = 8

C62_SETUP_BYTES = 101_197_617
C62_PRECOMMIT_NS = 275_113_308_912
C62_FIXED_CACHE_PRELOAD_NS = 36_524_311_692
C62_GW4_NS = 7_359_403_833
C62_NON_WHIR_RESERVE_NS = 3_000_000_000
C62_PRECOMMIT_SPILL_BYTES = 78_383_153_576
C62_PRECOMMIT_READ_BYTES = 103_079_256_064
C62_PRECOMMIT_WRITE_BYTES = 112_742_957_056
C62_PRECOMMIT_H2D_BYTES = 111_669_428_096
C62_PRECOMMIT_D2H_BYTES = 103_079_215_040
C62_GW4_PEAK_VRAM_BYTES = 39_146_362_732
C62_PI_FINAL_MAX_BYTES = 3_485_131
C62_CERTIFICATE_CODEC_CEILING_BYTES = 17_195_995
C62_CACHE_COHORT_LINK_SAVING_BYTES = 759_708
C62_CACHE_ONLY_SMALL_COMPONENTS_BYTES = 22_290
C62_RESPONSE_COMPONENT_HEADER_BYTES = 40
C62_REMOVED_CACHE_COMPONENTS = 3
C62_REMOVED_CACHE_COMPONENT_HEADER_BYTES = (
    C62_RESPONSE_COMPONENT_HEADER_BYTES * C62_REMOVED_CACHE_COMPONENTS
)
C63_RESIDUAL_AUX_PI_BEFORE_CLOSURE_BYTES = (
    C62_PI_FINAL_MAX_BYTES
    - C62_CACHE_COHORT_LINK_SAVING_BYTES
    - C62_CACHE_ONLY_SMALL_COMPONENTS_BYTES
    - C62_REMOVED_CACHE_COMPONENT_HEADER_BYTES
)

SETUP_LIMIT_BYTES = 150_000_000
SETUP_PLUS_FIRST_LIMIT_BYTES = 172_000_000
CERTIFICATE_LIMIT_BYTES = 30_000_000
PI_FINAL_LIMIT_BYTES = 4_500_000
PROVIDER_LIMIT_NS = 20_000_000_000
VERIFIER_LIMIT_NS = 5_000_000_000
VERIFIER_RSS_LIMIT_BYTES = 8_000_000_000
SOUNDNESS_LIMIT_BITS = Decimal("78.80929487391641")
VRAM_GUARD_BYTES = 45_818_576_864

HISTORICAL_FIXED_REMAINDER_BYTES = 6_840_000
HISTORICAL_ASSUMED_MULTIPLIER = 8
BOLT_PAPER_COMPLETE_PROOF_BYTES = 2_090_000
HISTORICAL_NONCOMPARABLE_TOTAL_BYTES = (
    HISTORICAL_FIXED_REMAINDER_BYTES
    + HISTORICAL_ASSUMED_MULTIPLIER * BOLT_PAPER_COMPLETE_PROOF_BYTES
)
C63_T128_COLUMNS = 128
C63_T128_COLUMNS_PER_TAPE = C63_T128_COLUMNS // 2
C63_T128_ROW_BYTES = C63_T128_COLUMNS * SUBFIELD_CORRECTION_BYTES
C63_T128_ROWS_PER_POSITION = 512
C63_T16_COLUMNS = 16
C63_T16_COLUMNS_PER_TAPE = C63_T16_COLUMNS // 2
C63_T16_ROW_BYTES = C63_T16_COLUMNS * SUBFIELD_CORRECTION_BYTES
C63_T16_ROW_DEPTH = 22
# A is conceptually D20 x 16.  The WHIR first-fold layout commits adjacent
# code positions in one D19 x 32 row, without changing its 2^24 symbols.
C63_ENCODED_SKETCH_ROW_DEPTH = 19
C63_ENCODED_SKETCH_ROW_COLUMNS = 32
C63_ENCODED_SKETCH_ROW_BYTES = (
    C63_ENCODED_SKETCH_ROW_COLUMNS * SUBFIELD_CORRECTION_BYTES
)
C63_T16_ROWS_PER_POSITION = 1 << 12
C63_T16_LIVE_ROWS_PER_POSITION = 6 << 9
C63_EXTENSION_ORACLES = 2
C63_BASE_LIMBS_PER_EXTENSION = 2
C63_CONSERVATIVE_BASE_WHIR_BODIES = (
    C63_EXTENSION_ORACLES * C63_BASE_LIMBS_PER_EXTENSION
)
C63_WHIR_PHASE_EVENT_LOWER_BOUND = 60
C61_D23_75BIT_HIDING_WHIR_BYTES = 868_288
C61_D23_HIDING_WHIR_BITS = 75
C63_SELECTED_PER_CORE_SCREEN_BITS = 105
C63_D22_WHIR_RATES = (1, 2, 3, 3, 4, 5, 6, 7)
C63_D19_WHIR_RATES = (1, 2, 3, 4, 5, 6)
C63_D22_WHIR_FOLDING = (1, 2, 2, 2, 2, 2, 2, 2, 2)
C63_D19_WHIR_FOLDING = (1, 2, 2, 2, 2, 2, 2)
C63_D22_WHIR_ROUND_QUERIES = (245, 245, 113, 74, 74, 55, 44, 36)
C63_D19_WHIR_ROUND_QUERIES = (245, 245, 113, 74, 55, 44)
C63_D22_WHIR_FINAL_QUERIES = 31
C63_D19_WHIR_FINAL_QUERIES = 36
C63_D22_WHIR_MASK_QUERIES = 257
C63_D19_WHIR_MASK_QUERIES = 254
C63_D22_WHIR_POW_BITS = 18
C63_D19_WHIR_POW_BITS = 17
C63_D22_WHIR_POW_WITNESSES = 17
C63_D19_WHIR_POW_WITNESSES = 13
C63_D22_WHIR_BODY_BYTES = 1_289_080
C63_D19_WHIR_BODY_BYTES = 970_752
C63_PROJECTED_WHIR_OUTER_BYTES = 20
C63_PROFILED_WHIR_BODIES_BYTES = 2 * (
    C63_D22_WHIR_BODY_BYTES + C63_D19_WHIR_BODY_BYTES
)
C63_UNMODIFIED_DOUBLE_ENCODED_WHIR_BODIES_BYTES = 4_822_680
C63_PROFILED_POW_EXPECTED_TRIALS = 7_995_392
C63_105_POW_EXPECTED_TRIALS = C63_PROFILED_POW_EXPECTED_TRIALS
C63_105_POW_FORMAL_CAP = 1 << 25
C63_SPARSE_H_CLOSURE_BYTES = 1_496
C63_WHIR_TERMINAL_TAG_BYTES = 4 * FP2_BYTES
C63_CORRECTION_ARTIFACT_MAX_BYTES = 2_037_262
C63_PUBLIC_ARGUMENT_FRAMING_BYTES = 384
C63_REDUCED_WRAPPER_PCS_BYTES = 2_668_730
C63_REDUCED_OUTPUT_LINK_BYTES = 2_672_044
C63_RESPONSE_ENVELOPE_BYTES = 2_703_780
C63_SPARSE_H_CLOSURE_CORRELATIONS_PER_TAPE = 44
C63_SPARSE_H_CLOSURE_ERROR_NUMERATOR = 64
C63_SYSTEMATIC_SPOT_FUSION_QUERIES = 4_420
C63_SYSTEMATIC_SPOT_FUSION_ERROR_NUMERATOR = C63_SYSTEMATIC_SPOT_FUSION_QUERIES
C63_MERKLE_MULTIPROOF_COUNT_BYTES = 4
C63_PAIRED_A_QUERIES = 245
C63_INDEPENDENT_LIMB_A_QUERIES = 490
C63_INDEPENDENT_A_PROOFS = 2
C63_SPARSE_SETUP_DESCRIPTOR_BYTES = 80
C63_SPARSE_SETUP_SOCKET_LOG2 = 26
C63_SPARSE_SETUP_SOCKET_COUNT = 1 << C63_SPARSE_SETUP_SOCKET_LOG2
C63_SPARSE_SETUP_PERMUTATION_BYTES = C63_SPARSE_SETUP_SOCKET_COUNT * 4
C63_SPARSE_SETUP_COEFFICIENT_BYTES = C63_SPARSE_SETUP_SOCKET_COUNT * 8
C63_SPARSE_SETUP_RESIDENT_BYTES = (
    C63_SPARSE_SETUP_PERMUTATION_BYTES + C63_SPARSE_SETUP_COEFFICIENT_BYTES
)
C63_FIXED_MODEL_CACHE_BYTES = 12 * (1 << 30)
# Includes one complete D23 Fp2 lane/codeword and its proof workspace.
C63_D23_LANE_GUARD_BYTES = 5_529_141_216
C63_PRE_A_STATE_PROXY_BYTES = 329_307_136
C63_ENCODED_SKETCH_DATA_BYTES = (
    (1 << C63_ENCODED_SKETCH_ROW_DEPTH) * C63_ENCODED_SKETCH_ROW_BYTES
)
C63_ENCODED_SKETCH_MERKLE_BYTES = (
    (1 << (C63_ENCODED_SKETCH_ROW_DEPTH + 1)) - 1
) * 32
C63_ACCEPTED_PROPOSED_ENCODED_SKETCH_BYTES = 2 * (
    C63_ENCODED_SKETCH_DATA_BYTES + C63_ENCODED_SKETCH_MERKLE_BYTES
)
C63_FULL_STATE_PROXY_BYTES = (
    C63_PRE_A_STATE_PROXY_BYTES + C63_ACCEPTED_PROPOSED_ENCODED_SKETCH_BYTES
)
BOLT_PAPER_GAMMA_SENSITIVITY = 0.096
C63_SPOT_SUBTARGET_BITS = C63_SELECTED_PER_CORE_SCREEN_BITS
C63_SPOT_ROWS_AT_PAPER_GAMMA = math.ceil(
    C63_SPOT_SUBTARGET_BITS / -math.log2(1 - BOLT_PAPER_GAMMA_SENSITIVITY / 3)
)
GOLDILOCKS_MODULUS = 18_446_744_069_414_584_321
BOLT_REFERENCE_FIELD_SIZE = 1 << 32
BOLT_LDPC_COLUMN_DEGREE = 16
BOLT_LDPC_CHECK_DEGREE = 128
C63_GOLDILOCKS_GAMMA_SCREEN = Decimal("0.049")
C63_GOLDILOCKS_GAMMA_NUMERATOR = 49
C63_GOLDILOCKS_GAMMA_DENOMINATOR = 1_000
C63_SPOT_SUBTARGETS_BITS = (84, 90, 96, 102, 104, 105)
CACHE_TIME_BUDGET_NS = PROVIDER_LIMIT_NS - C62_GW4_NS - C62_NON_WHIR_RESERVE_NS

SLOTS = 8
LIVE_SLOTS = 2
LAYERS = 12
CAPACITY_TOKENS = 1_024
WIDTH = 768
PADDED_LAYERS = 16
PADDED_WIDTH = 1_024
PADDED_ENTRIES_PER_SLOT = PADDED_LAYERS * CAPACITY_TOKENS * PADDED_WIDTH
CELLS_PER_TOKEN = LIVE_SLOTS * LAYERS * WIDTH


def _bisect_root(function: Any, low: Decimal, high: Decimal) -> Decimal:
    """Small stdlib root finder used only by the non-credit LDPC screen."""
    if function(low) > 0 or function(high) < 0:
        raise ValueError("LDPC root is not bracketed")
    for _ in range(180):
        midpoint = (low + high) / 2
        if function(midpoint) < 0:
            low = midpoint
        else:
            high = midpoint
    return (low + high) / 2


def ldpc_numerical_distance(field_size: int) -> Decimal:
    """Port of Bolt's q_ldpc.py/YHC growth-rate root; not a distance proof."""
    q = Decimal(field_size)
    one = Decimal(1)
    column_degree = Decimal(BOLT_LDPC_COLUMN_DEGREE)
    check_degree = Decimal(BOLT_LDPC_CHECK_DEGREE)

    def entropy(x: Decimal) -> Decimal:
        return x * (one / x).ln() - (one - x) * (one - x).ln() + x * (q - one).ln()

    def omega(x: Decimal) -> Decimal:
        z = one - q * x / (q - one)

        def zeta_difference(z_hat: Decimal) -> Decimal:
            numerator = (
                z_hat
                + z_hat ** (BOLT_LDPC_CHECK_DEGREE - 1)
                + (q - 2) * z_hat**BOLT_LDPC_CHECK_DEGREE
            )
            denominator = one + (q - one) * z_hat**BOLT_LDPC_CHECK_DEGREE
            return numerator / denominator - z

        epsilon = Decimal(1) / Decimal(10) ** 35
        z_hat = _bisect_root(zeta_difference, epsilon, one)
        x_hat = (q - one) * (one - z_hat) / q
        divergence = x * (x / x_hat).ln() + (one - x) * (
            (one - x).ln() - (one - x_hat).ln()
        )
        rho = (one + (q - one) * z_hat**BOLT_LDPC_CHECK_DEGREE).ln()
        return entropy(x) + column_degree / check_degree * (
            check_degree * divergence + rho - q.ln()
        )

    epsilon = Decimal(1) / Decimal(10) ** 20
    return _bisect_root(omega, epsilon, one - one / q - epsilon)


def spot_rows(gamma: Decimal, bits: Decimal) -> int:
    rows = bits * Decimal(2).ln() / -(Decimal(1) - gamma / 3).ln()
    return int(rows.to_integral_value(rounding=ROUND_CEILING))


def binary_entropy(x: Decimal) -> Decimal:
    one = Decimal(1)
    return x * (one / x).ln() + (one - x) * (one / (one - x)).ln()


def finite_ldpc_phi(alpha: Decimal, y: Decimal) -> Decimal:
    """Finite coefficient-bound exponent for one rational saddle witness."""
    q = Decimal(GOLDILOCKS_MODULUS)
    q_minus_one = q - 1
    check_enumerator = (
        (1 + y) ** BOLT_LDPC_CHECK_DEGREE
        + q_minus_one
        * (1 - y / q_minus_one) ** BOLT_LDPC_CHECK_DEGREE
    ) / q
    return (
        (1 - BOLT_LDPC_COLUMN_DEGREE) * binary_entropy(alpha)
        + alpha * q_minus_one.ln()
        + Decimal(BOLT_LDPC_COLUMN_DEGREE)
        / Decimal(BOLT_LDPC_CHECK_DEGREE)
        * check_enumerator.ln()
        - Decimal(BOLT_LDPC_COLUMN_DEGREE) * alpha * y.ln()
    )


def _exp_taylor_lower(x: Fraction, degree: int) -> Fraction:
    total = term = Fraction(1)
    for index in range(1, degree + 1):
        term *= x / index
        total += term
    return total


def _exp_taylor_upper(x: Fraction, degree: int) -> Fraction:
    """Rational exp upper bound from a Taylor sum and geometric tail."""
    total = term = Fraction(1)
    for index in range(1, degree + 1):
        term *= x / index
        total += term
    next_term = term * x / (degree + 1)
    tail_ratio = x / (degree + 2)
    if tail_ratio >= 1:
        raise ValueError("Taylor tail is not geometrically bounded")
    return total + next_term / (1 - tail_ratio)


def finite_ldpc_rational_certificate() -> dict[str, Any]:
    """Exact rational checks behind a conservative 188-bit distance screen."""
    n = 1 << C63_T16_ROW_DEPTH
    maximum_weight = (
        C63_GOLDILOCKS_GAMMA_NUMERATOR * n
        // C63_GOLDILOCKS_GAMMA_DENOMINATOR
    )

    # These imply ln(2) < .694, ln(5/2) < .917 and
    # ln(n/L) > 3.015 without floating-point evaluation.
    assert _exp_taylor_lower(Fraction(347, 500), 4) > 2
    assert _exp_taylor_lower(Fraction(917, 1_000), 5) > Fraction(5, 2)
    assert _exp_taylor_upper(Fraction(603, 200), 7) < Fraction(n, maximum_weight)

    # The l=1 witness y=1/4 gives n*phi <= -234*ln(2)+1/2.
    assert Fraction(5, 4) ** 128 < 1 << 43
    assert GOLDILOCKS_MODULUS > 1 << 63

    # The l=L witness y=2/5 is far smaller than the l=1 endpoint.
    assert Fraction(7, 5) ** 128 / GOLDILOCKS_MODULUS < Fraction(7, 25)
    alpha = Fraction(maximum_weight, n)
    upper_endpoint_n_phi = (
        -15 * maximum_weight * Fraction(3_015, 1_000)
        - 15 * (n - maximum_weight) * (alpha + alpha * alpha / 2)
        + 64 * maximum_weight * Fraction(694, 1_000)
        + 16 * maximum_weight * Fraction(917, 1_000)
        + Fraction(n, 8) * Fraction(7, 25)
    )
    assert upper_endpoint_n_phi < -7_645

    # e^(1/2) < sum_{k>=0}(1/2)^k = 2. Combining the endpoint,
    # binomial-mode and union factors gives 2^(-234+1+27+18).
    assert maximum_weight < 1 << 18
    assert BOLT_LDPC_COLUMN_DEGREE * n + 1 < 1 << 27
    conservative_bits = 234 - 1 - 27 - 18
    assert conservative_bits == 188
    return {
        "method": "exact rational inequalities plus YHC Theorems 3.6 and 5.6",
        "official_arxiv_tex_formula_checked": True,
        "transcendental_interval_dependency_avoided": True,
        "lower_endpoint_n_phi_upper": "-234*ln(2)+1/2",
        "upper_endpoint_n_phi_nat_upper": "<-7645",
        "union_failure_probability_upper": "<2^-188",
        "candidate_distance_bits_lower": conservative_bits,
        "exact_rational_checks_complete": True,
    }


def finite_ldpc_first_moment_screen() -> dict[str, Any]:
    """Avoid YHC's hidden asymptotic constant with its exact first moment."""
    n = 1 << C63_T16_ROW_DEPTH
    maximum_weight = (
        C63_GOLDILOCKS_GAMMA_NUMERATOR * n
        // C63_GOLDILOCKS_GAMMA_DENOMINATOR
    )
    lower_alpha = Decimal(1) / Decimal(n)
    upper_alpha = Decimal(maximum_weight) / Decimal(n)
    lower_y = Decimal(1) / 4
    upper_y = Decimal(2) / 5
    lower_phi = finite_ldpc_phi(lower_alpha, lower_y)
    upper_phi = finite_ldpc_phi(upper_alpha, upper_y)
    log_failure = (
        Decimal(maximum_weight).ln()
        + Decimal(BOLT_LDPC_COLUMN_DEGREE * n + 1).ln()
        + Decimal(n) * max(lower_phi, upper_phi)
    )
    failure_log2_upper = log_failure / Decimal(2).ln()
    return {
        "method": (
            "YHC Theorem 3.6 exact first moment, coefficient upper bound, "
            "binomial-mode bound, Theorem 5.6 endpoint shape, union bound"
        ),
        "n": n,
        "maximum_bad_weight": maximum_weight,
        "lower_endpoint": {
            "alpha": str(lower_alpha),
            "rational_y": "1/4",
            "n_phi_log2_upper": str(Decimal(n) * lower_phi / Decimal(2).ln()),
        },
        "upper_endpoint": {
            "alpha": str(upper_alpha),
            "rational_y": "2/5",
            "n_phi_log2_upper": str(Decimal(n) * upper_phi / Decimal(2).ln()),
        },
        "binomial_mode_overhead": "ln(16*n+1)",
        "failure_log2_upper": str(failure_log2_upper),
        "candidate_distance_bits": str(-failure_log2_upper),
        "hidden_asymptotic_constant_used": False,
        "rational_certificate": finite_ldpc_rational_certificate(),
        "independent_directed_interval_check_complete": False,
        "credit": False,
    }


def maximum_binary_multiproof_siblings(depth: int, queries: int) -> int:
    if not 0 < queries <= 1 << depth:
        raise ValueError("invalid Merkle query geometry")
    return sum(min(queries, 1 << level) for level in range(1, depth)) + 2 - queries


def systematic_opening_screen(depth: int, row_bytes: int, queries: int) -> dict[str, int]:
    siblings = maximum_binary_multiproof_siblings(depth, queries)
    return {
        "tree_depth": depth,
        "queries": queries,
        "row_bytes": row_bytes,
        "row_payload_bytes": queries * row_bytes,
        "maximum_sibling_digests": siblings,
        "maximum_frontier_bytes": siblings * 32,
        "opening_bytes_before_framing": queries * row_bytes + siblings * 32,
    }


def c63_soundness_screen() -> dict[str, Any]:
    """Conservative 105-bit phase union under separated H_pow/H_fs."""
    inherited_error = c62.c61_complete_error()
    whir_core_union_error = Fraction(
        C63_CONSERVATIVE_BASE_WHIR_BODIES,
        1 << C63_SELECTED_PER_CORE_SCREEN_BITS,
    )
    whir_phase_event_lower_bound_error = Fraction(
        C63_WHIR_PHASE_EVENT_LOWER_BOUND,
        1 << C63_SELECTED_PER_CORE_SCREEN_BITS,
    )
    systematic_spot_error = Fraction(1, 1 << C63_SPOT_SUBTARGET_BITS)
    sparse_h_closure_error = Fraction(
        C63_SPARSE_H_CLOSURE_ERROR_NUMERATOR,
        c6.FP2_CARDINALITY,
    )
    systematic_spot_fusion_error = Fraction(
        C63_SYSTEMATIC_SPOT_FUSION_ERROR_NUMERATOR,
        c6.FP2_CARDINALITY,
    )
    terminal_zeroopen_error = Fraction(4, c6.FP2_CARDINALITY)
    interactive_error = (
        inherited_error
        + whir_phase_event_lower_bound_error
        + systematic_spot_error
        + sparse_h_closure_error
        + systematic_spot_fusion_error
        + terminal_zeroopen_error
    )
    phase_event_interactive_error = (
        inherited_error
        + whir_phase_event_lower_bound_error
        + systematic_spot_error
        + sparse_h_closure_error
        + systematic_spot_fusion_error
    )
    joint_eta_error = Fraction(1, c6.FP2_CARDINALITY)
    state_restoration_error = c62.C62_MAX_RANDOM_ORACLE_QUERIES * (
        interactive_error + joint_eta_error
    )
    random_oracle_programming_error = Fraction(
        c62.C62_MAX_RANDOM_ORACLE_QUERIES,
        2**256,
    )
    blake3_collision_error = Fraction(
        c62.C62_MAX_BLAKE3_HASH_INVOCATIONS
        * (c62.C62_MAX_BLAKE3_HASH_INVOCATIONS - 1),
        2 * 2**256,
    )
    rejected_u64_values = 2**64 - c6.GOLDILOCKS_P
    field_sampling_exhaustion_error = (
        2
        * c62.C62_MAX_CHALLENGES
        * Fraction(rejected_u64_values, 2**64)
        ** c62.C62_MAX_REJECTION_DRAWS_PER_LIMB
    )
    finite_setup_distance_error = Fraction(1, 2**188)
    public_xof_computational_assumption_error = Fraction(1, 2**128)
    known_terms_error = (
        state_restoration_error
        + random_oracle_programming_error
        + blake3_collision_error
        + field_sampling_exhaustion_error
        + finite_setup_distance_error
        + public_xof_computational_assumption_error
    )

    def complete_known_error(interactive: Fraction, qro_bound: int) -> Fraction:
        return (
            qro_bound * (interactive + joint_eta_error)
            + Fraction(qro_bound, 2**256)
            + blake3_collision_error
            + field_sampling_exhaustion_error
            + finite_setup_distance_error
            + public_xof_computational_assumption_error
        )

    phase_event_screen_error = complete_known_error(
        phase_event_interactive_error,
        c62.C62_MAX_RANDOM_ORACLE_QUERIES,
    )
    qro_with_expected_pow_trials = (
        c62.C62_MAX_RANDOM_ORACLE_QUERIES + C63_PROFILED_POW_EXPECTED_TRIALS
    )
    def profile_104_error(qro_bound: int) -> Fraction:
        return complete_known_error(interactive_error, qro_bound)

    expected_pow_trial_screen_error = profile_104_error(qro_with_expected_pow_trials)
    maximum_monolithic_qro = 0
    first_failing_qro = qro_with_expected_pow_trials
    while maximum_monolithic_qro + 1 < first_failing_qro:
        candidate = (maximum_monolithic_qro + first_failing_qro) // 2
        if c6.soundness_bits(profile_104_error(candidate)) >= SOUNDNESS_LIMIT_BITS:
            maximum_monolithic_qro = candidate
        else:
            first_failing_qro = candidate
    profile_105_interactive_error = (
        inherited_error
        + Fraction(C63_CONSERVATIVE_BASE_WHIR_BODIES, 1 << 105)
        + Fraction(1, 1 << 105)
        + sparse_h_closure_error
        + systematic_spot_fusion_error
    )

    def profile_105_error(qro_bound: int) -> Fraction:
        return complete_known_error(profile_105_interactive_error, qro_bound)

    profile_105_expected_qro = (
        c62.C62_MAX_RANDOM_ORACLE_QUERIES + C63_105_POW_EXPECTED_TRIALS
    )
    profile_105_expected_error = profile_105_error(profile_105_expected_qro)
    profile_105_capped_qro = (
        c62.C62_MAX_RANDOM_ORACLE_QUERIES + C63_105_POW_FORMAL_CAP
    )
    profile_105_capped_error = profile_105_error(profile_105_capped_qro)

    return {
        "profile_target_bits_per_base_core": C63_SELECTED_PER_CORE_SCREEN_BITS,
        "base_core_count": C63_CONSERVATIVE_BASE_WHIR_BODIES,
        "inherited_c61_interactive": c62.error_report(inherited_error),
        "four_core_union": c62.error_report(whir_core_union_error),
        "whole_core_phase_union_complete": True,
        "whir_phase_event_lower_bound_count": C63_WHIR_PHASE_EVENT_LOWER_BOUND,
        "phase_event_lower_bound_union": c62.error_report(
            whir_phase_event_lower_bound_error
        ),
        "phase_event_lower_bound_complete_under_inherited_qro": c62.error_report(
            phase_event_screen_error
        ),
        "phase_event_lower_bound_clears_gate": (
            c6.soundness_bits(phase_event_screen_error) >= SOUNDNESS_LIMIT_BITS
        ),
        "systematic_spot": c62.error_report(systematic_spot_error),
        "systematic_spot_fusion_4378_over_fp2": c62.error_report(
            systematic_spot_fusion_error
        ),
        "sparse_h_closure_64_over_fp2": c62.error_report(sparse_h_closure_error),
        "four_terminal_zeroopen_over_fp2": c62.error_report(terminal_zeroopen_error),
        "sparse_h_zeroopen_and_mac_additional_error_census_complete": True,
        "interactive_known_terms": c62.error_report(interactive_error),
        "state_restoration": c62.error_report(state_restoration_error),
        "finite_setup_distance": c62.error_report(finite_setup_distance_error),
        "inherited_qro_bound": c62.C62_MAX_RANDOM_ORACLE_QUERIES,
        "known_terms_under_inherited_qro": c62.error_report(known_terms_error),
        "known_terms_under_inherited_qro_clear_gate": (
            c6.soundness_bits(known_terms_error) >= SOUNDNESS_LIMIT_BITS
        ),
        "pow_expected_trials_not_a_security_bound": C63_PROFILED_POW_EXPECTED_TRIALS,
        "qro_plus_expected_pow_trials": qro_with_expected_pow_trials,
        "maximum_monolithic_qro_at_gate": maximum_monolithic_qro,
        "expected_qro_excess_over_gate": (
            qro_with_expected_pow_trials - maximum_monolithic_qro
        ),
        "known_terms_with_expected_pow_trials": c62.error_report(
            expected_pow_trial_screen_error
        ),
        "known_terms_with_expected_pow_trials_clear_gate": (
            c6.soundness_bits(expected_pow_trial_screen_error) >= SOUNDNESS_LIMIT_BITS
        ),
        "pow_qro_resolution": (
            "selected direction: independent H_pow(profile,role,phase,snapshot,witness) "
            "for grinding and H_fs(transcript,accepted_witness) for Fiat-Shamir; "
            "a domain label on one challenger is insufficient"
        ),
        "separated_two_random_oracle_whole_core_terms": c62.error_report(
            known_terms_error
        ),
        "two_random_oracle_work_factor_composition_selected": True,
        "raising_profile_does_not_fix_monolithic_qro": {
            "profile_bits": 105,
            "expected_pow_trials": C63_105_POW_EXPECTED_TRIALS,
            "qro_with_expected_trials": profile_105_expected_qro,
            "expected_trial_screen": c62.error_report(profile_105_expected_error),
            "expected_trial_screen_clear_gate": (
                c6.soundness_bits(profile_105_expected_error) >= SOUNDNESS_LIMIT_BITS
            ),
            "formal_pow_cap": C63_105_POW_FORMAL_CAP,
            "qro_with_formal_cap": profile_105_capped_qro,
            "formal_cap_screen": c62.error_report(profile_105_capped_error),
            "formal_cap_screen_clear_gate": (
                c6.soundness_bits(profile_105_capped_error) >= SOUNDNESS_LIMIT_BITS
            ),
        },
        "public_xof_hybrid_term": "BLAKE3-XOF computational assumption capped at 128 bits",
        "public_xof_assumption_error": c62.error_report(
            public_xof_computational_assumption_error
        ),
        "complete_soundness_gate_evaluated": True,
        "complete_soundness_bits": str(c6.soundness_bits(known_terms_error)),
        "complete_soundness_gate_pass": (
            c6.soundness_bits(known_terms_error) >= SOUNDNESS_LIMIT_BITS
        ),
        "credit": False,
    }


def transition_geometry(old_context: int, new_context: int) -> dict[str, int]:
    if not 0 <= old_context <= new_context <= CAPACITY_TOKENS:
        raise ValueError("invalid GPT-2 cache transition")
    active_address_entries = LIVE_SLOTS * PADDED_ENTRIES_PER_SLOT
    old_live = CELLS_PER_TOKEN * old_context
    new_live = CELLS_PER_TOKEN * new_context
    append = new_live - old_live
    return {
        "old_context_tokens": old_context,
        "new_context_tokens": new_context,
        "append_tokens": new_context - old_context,
        "old_live_fp2_entries": old_live,
        "new_live_fp2_entries": new_live,
        "append_fp2_entries": append,
        "old_live_bytes": old_live * FP2_BYTES,
        "new_live_bytes": new_live * FP2_BYTES,
        "append_bytes": append * FP2_BYTES,
        "new_correction_bytes_per_tape": new_live * SUBFIELD_CORRECTION_BYTES,
        "new_correction_bytes_both_tapes": new_live * SUBFIELD_CORRECTION_BYTES * 2,
        "append_correction_bytes_per_tape": append * SUBFIELD_CORRECTION_BYTES,
        "append_correction_bytes_both_tapes": append * SUBFIELD_CORRECTION_BYTES * 2,
        "active_slot_address_entries": active_address_entries,
        "active_slot_virtual_zero_entries_after": active_address_entries - new_live,
    }


def build_report() -> dict[str, Any]:
    genesis = transition_geometry(0, 150)
    continuation = transition_geometry(150, 200)
    bolt_reference_distance = ldpc_numerical_distance(BOLT_REFERENCE_FIELD_SIZE)
    goldilocks_distance = ldpc_numerical_distance(GOLDILOCKS_MODULUS)
    finite_distance = finite_ldpc_first_moment_screen()
    soundness_screen = c63_soundness_screen()
    genesis_sparse_h_multiply_adds = (
        genesis["new_correction_bytes_both_tapes"]
        // SUBFIELD_CORRECTION_BYTES
        * BOLT_LDPC_COLUMN_DEGREE
    )
    continuation_sparse_h_multiply_adds = (
        continuation["append_correction_bytes_both_tapes"]
        // SUBFIELD_CORRECTION_BYTES
        * BOLT_LDPC_COLUMN_DEGREE
    )
    spot_screens = {
        str(bits): {
            "subtarget_bits": bits,
            "queries_at_numerical_root": spot_rows(goldilocks_distance, Decimal(bits)),
            "queries_at_conservative_gamma": spot_rows(
                C63_GOLDILOCKS_GAMMA_SCREEN, Decimal(bits)
            ),
        }
        for bits in C63_SPOT_SUBTARGETS_BITS
    }
    selected_queries = spot_screens[str(C63_SPOT_SUBTARGET_BITS)][
        "queries_at_conservative_gamma"
    ]
    assert selected_queries == C63_SYSTEMATIC_SPOT_FUSION_QUERIES
    t128_full_opening = systematic_opening_screen(19, 1_024, selected_queries)
    t128_live_max_opening = systematic_opening_screen(19, 768, selected_queries)
    t128_live_average_opening = systematic_opening_screen(19, 576, selected_queries)
    t4_full_opening = systematic_opening_screen(24, 32, selected_queries)
    t16_full_opening = systematic_opening_screen(
        C63_T16_ROW_DEPTH, C63_T16_ROW_BYTES, selected_queries
    )
    t16_encoded_sketch_paired_opening = systematic_opening_screen(
        C63_ENCODED_SKETCH_ROW_DEPTH,
        C63_ENCODED_SKETCH_ROW_BYTES,
        C63_PAIRED_A_QUERIES,
    )
    t16_encoded_sketch_independent_opening = systematic_opening_screen(
        C63_ENCODED_SKETCH_ROW_DEPTH,
        C63_ENCODED_SKETCH_ROW_BYTES,
        C63_INDEPENDENT_LIMB_A_QUERIES,
    )
    t16_encoded_sketch_outer_stress_opening = systematic_opening_screen(
        C63_ENCODED_SKETCH_ROW_DEPTH,
        C63_ENCODED_SKETCH_ROW_BYTES,
        selected_queries,
    )
    t16_old_profile_whir_bodies = (
        C63_CONSERVATIVE_BASE_WHIR_BODIES * C61_D23_75BIT_HIDING_WHIR_BYTES
    )
    t16_profiled_public_bulk_screen = (
        C63_CORRECTION_ARTIFACT_MAX_BYTES
        + t16_encoded_sketch_paired_opening["opening_bytes_before_framing"]
        + C63_MERKLE_MULTIPROOF_COUNT_BYTES
        + C63_PROFILED_WHIR_BODIES_BYTES
        + C63_PUBLIC_ARGUMENT_FRAMING_BYTES
    )
    t16_independent_limb_public_bulk_screen = (
        C63_CORRECTION_ARTIFACT_MAX_BYTES
        + t16_encoded_sketch_independent_opening["opening_bytes_before_framing"]
        + C63_MERKLE_MULTIPROOF_COUNT_BYTES
        + C63_PROFILED_WHIR_BODIES_BYTES
        + C63_PUBLIC_ARGUMENT_FRAMING_BYTES
    )
    t16_independent_separate_public_bulk_screen = (
        C63_CORRECTION_ARTIFACT_MAX_BYTES
        + C63_INDEPENDENT_A_PROOFS
        * (
            t16_encoded_sketch_paired_opening["opening_bytes_before_framing"]
            + C63_MERKLE_MULTIPROOF_COUNT_BYTES
        )
        + C63_PROFILED_WHIR_BODIES_BYTES
        + C63_INDEPENDENT_A_PROOFS * C63_PROJECTED_WHIR_OUTER_BYTES
        + C63_PUBLIC_ARGUMENT_FRAMING_BYTES
    )
    certificate_at_strict_pi_cap_before_new_public_framing = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + PI_FINAL_LIMIT_BYTES
        - 1
        + t16_profiled_public_bulk_screen
    )
    projected_pi_final_with_sparse_h = C63_RESPONSE_ENVELOPE_BYTES + 793
    certificate_with_projected_pi_before_outer_framing = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + projected_pi_final_with_sparse_h
        + t16_profiled_public_bulk_screen
    )
    independent_limb_certificate_at_strict_pi_cap = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + PI_FINAL_LIMIT_BYTES
        - 1
        + t16_independent_limb_public_bulk_screen
    )
    independent_limb_certificate_with_projected_pi = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + projected_pi_final_with_sparse_h
        + t16_independent_limb_public_bulk_screen
    )
    independent_separate_certificate_at_strict_pi_cap = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + PI_FINAL_LIMIT_BYTES
        - 1
        + t16_independent_separate_public_bulk_screen
    )
    independent_separate_certificate_with_projected_pi = (
        C62_CERTIFICATE_CODEC_CEILING_BYTES
        - C62_PI_FINAL_MAX_BYTES
        + projected_pi_final_with_sparse_h
        + t16_independent_separate_public_bulk_screen
    )
    legacy_state_entries = SLOTS * PADDED_ENTRIES_PER_SLOT
    compact_state_entries = LIVE_SLOTS * PADDED_ENTRIES_PER_SLOT
    inactive_virtual_entries = (SLOTS - LIVE_SLOTS) * PADDED_ENTRIES_PER_SLOT
    setup_plus_historical_screen = C62_SETUP_BYTES + HISTORICAL_NONCOMPARABLE_TOTAL_BYTES
    setup_with_sparse_descriptor = C62_SETUP_BYTES + C63_SPARSE_SETUP_DESCRIPTOR_BYTES
    setup_plus_max_certificate = setup_with_sparse_descriptor + CERTIFICATE_LIMIT_BYTES
    setup_plus_projected_first = (
        setup_with_sparse_descriptor + certificate_with_projected_pi_before_outer_framing
    )
    setup_plus_conservative_codec_first = (
        setup_with_sparse_descriptor + independent_separate_certificate_with_projected_pi
    )
    setup_resident_vram = C62_GW4_PEAK_VRAM_BYTES + C63_SPARSE_SETUP_RESIDENT_BYTES
    forced_overlap_vram = (
        setup_resident_vram
        + C63_D23_LANE_GUARD_BYTES
        + C63_FULL_STATE_PROXY_BYTES
    )
    sequential_gw4_phase_vram = setup_resident_vram + C63_FULL_STATE_PROXY_BYTES
    sequential_c63_phase_vram = (
        C63_FIXED_MODEL_CACHE_BYTES
        + C63_SPARSE_SETUP_RESIDENT_BYTES
        + C63_D23_LANE_GUARD_BYTES
        + C63_FULL_STATE_PROXY_BYTES
    )
    speedup = Decimal(C62_PRECOMMIT_NS) / Decimal(CACHE_TIME_BUDGET_NS)

    gates: dict[str, dict[str, Any]] = {
        "setup_bytes": {
            "comparison": "<",
            "limit": SETUP_LIMIT_BYTES,
            "c63_candidate": setup_with_sparse_descriptor,
            "evaluated": True,
            "pass": setup_with_sparse_descriptor < SETUP_LIMIT_BYTES,
        },
        "setup_plus_first_bytes": {
            "comparison": "<",
            "limit": SETUP_PLUS_FIRST_LIMIT_BYTES,
            "c63_candidate": setup_plus_conservative_codec_first,
            "evaluated": True,
            "pass": setup_plus_conservative_codec_first < SETUP_PLUS_FIRST_LIMIT_BYTES,
        },
        "complete_certificate_bytes_experimental": {
            "comparison": "<=",
            "limit": CERTIFICATE_LIMIT_BYTES,
            "c63_candidate": independent_separate_certificate_with_projected_pi,
            "evaluated": True,
            "pass": independent_separate_certificate_with_projected_pi <= CERTIFICATE_LIMIT_BYTES,
        },
        "pi_final_bytes": {
            "comparison": "<",
            "limit": PI_FINAL_LIMIT_BYTES,
            "c63_candidate": projected_pi_final_with_sparse_h,
            "evaluated": True,
            "pass": projected_pi_final_with_sparse_h < PI_FINAL_LIMIT_BYTES,
        },
        "provider_wall_ns": {
            "comparison": "<",
            "limit": PROVIDER_LIMIT_NS,
            "c63_candidate": None,
            "evaluated": False,
        },
        "four_thread_verifier_wall_ns": {
            "comparison": "<",
            "limit": VERIFIER_LIMIT_NS,
            "c63_candidate": None,
            "evaluated": False,
        },
        "verifier_additional_rss_bytes": {
            "comparison": "<=",
            "limit": VERIFIER_RSS_LIMIT_BYTES,
            "c63_candidate": None,
            "evaluated": False,
        },
        "soundness_bits_per_certificate": {
            "comparison": ">=",
            "limit": str(SOUNDNESS_LIMIT_BITS),
            "c63_candidate": soundness_screen["complete_soundness_bits"],
            "evaluated": True,
            "pass": soundness_screen["complete_soundness_gate_pass"],
        },
        "peak_vram_bytes": {
            "comparison": "<=",
            "limit": VRAM_GUARD_BYTES,
            "c63_candidate": None,
            "evaluated": False,
        },
    }

    report: dict[str, Any] = {
        "schema": "volta-c63-authenticated-sketch-analytic-screen-v12",
        "credit": False,
        "transfer_to_c63_gates": False,
        "gates": gates,
        "measured_c62_inputs": {
            "record": "benchmarks/results/c62-cache-precommit-2026-08-22-c2bbd6b.json",
            "setup_bytes": C62_SETUP_BYTES,
            "fixed_cache_preload_ns_excluded_from_response": C62_FIXED_CACHE_PRELOAD_NS,
            "cache_precommit_ns": C62_PRECOMMIT_NS,
            "cache_precommit_spill_bytes": C62_PRECOMMIT_SPILL_BYTES,
            "cache_precommit_read_bytes": C62_PRECOMMIT_READ_BYTES,
            "cache_precommit_write_bytes": C62_PRECOMMIT_WRITE_BYTES,
            "cache_precommit_h2d_bytes": C62_PRECOMMIT_H2D_BYTES,
            "cache_precommit_d2h_bytes": C62_PRECOMMIT_D2H_BYTES,
            "gw4_ns": C62_GW4_NS,
            "non_whir_reserve_ns": C62_NON_WHIR_RESERVE_NS,
            "gw4_peak_vram_bytes": C62_GW4_PEAK_VRAM_BYTES,
        },
        "timing_screen": {
            "provider_limit_ns": PROVIDER_LIMIT_NS,
            "gw4_ns": C62_GW4_NS,
            "non_whir_reserve_ns": C62_NON_WHIR_RESERVE_NS,
            "cache_binding_budget_comparison": "<",
            "cache_binding_budget_ns": CACHE_TIME_BUDGET_NS,
            "cache_binding_budget_seconds": str(
                Decimal(CACHE_TIME_BUDGET_NS) / Decimal(1_000_000_000)
            ),
            "required_precommit_speedup": str(speedup),
            "c63_cache_time_ns": None,
            "evaluated": False,
        },
        "historical_noncomparable_bolt_screen": {
            "basis": (
                "legacy selection arithmetic only; decimal MB means 1,000,000 bytes"
            ),
            "fixed_remainder_bytes": HISTORICAL_FIXED_REMAINDER_BYTES,
            "historical_assumed_multiplier": HISTORICAL_ASSUMED_MULTIPLIER,
            "bolt_paper_complete_proof_bytes": BOLT_PAPER_COMPLETE_PROOF_BYTES,
            "two_point_zero_nine_mb_is_one_c63_body": False,
            "historical_total_bytes": HISTORICAL_NONCOMPARABLE_TOTAL_BYTES,
            "certificate_headroom_bytes": (
                CERTIFICATE_LIMIT_BYTES - HISTORICAL_NONCOMPARABLE_TOTAL_BYTES
            ),
            "c62_setup_plus_historical_total_bytes": setup_plus_historical_screen,
            "historical_certificate_arithmetic_under_limit": (
                HISTORICAL_NONCOMPARABLE_TOTAL_BYTES <= CERTIFICATE_LIMIT_BYTES
            ),
            "historical_setup_plus_first_arithmetic_under_limit": (
                setup_plus_historical_screen < SETUP_PLUS_FIRST_LIMIT_BYTES
            ),
            "not_c63_upper_or_lower_bound": True,
            "credit": False,
            "paper_time_transferred": False,
            "pi_final_inferred": False,
            "soundness_inferred": False,
        },
        "authenticated_sketched_whir_selection": {
            "selected_layout": "append-aligned t16 public-bulk candidate",
            "systematic_object": "one D22 x 16 reshape of canonical D24 x 4 corrections",
            "systematic_column_order": (
                "column=tape+2*kv+4*layer_low+8*channel_high"
            ),
            "columns_per_mac_tape": C63_T16_COLUMNS_PER_TAPE,
            "row_combination_field": "Fp2",
            "row_combination": "one uniform rho over all 16 interleaved columns",
            "mac_tape_closures_separate": True,
            "systematic_commitment": "one typed D12-inside-D10 correction-row root",
            "encoded_sketch_commitment": (
                "pre-rho deterministic A=C^16(H*D') tensor: conceptual D20x16, "
                "WHIR-aligned D19x32 commitment rows"
            ),
            "randomized_hiding_oracles_persisted_across_responses": False,
            "fresh_randomized_base_core_oracles_per_response": 4,
            "systematic_row_bytes_before_metadata": C63_T16_ROW_BYTES,
            "logical_rows_per_appended_position": C63_T16_ROWS_PER_POSITION,
            "stored_rows_per_appended_position": C63_T16_LIVE_ROWS_PER_POSITION,
            "genesis_systematic_correction_payload_bytes": (
                150 * C63_T16_LIVE_ROWS_PER_POSITION * C63_T16_ROW_BYTES
            ),
            "continuation_systematic_correction_payload_bytes": (
                50 * C63_T16_LIVE_ROWS_PER_POSITION * C63_T16_ROW_BYTES
            ),
            "typed_metadata_and_merkle_hash_work_included": False,
            "historical_t128_paper_gamma_spot_sensitivity": {
                "gamma_untransferred": BOLT_PAPER_GAMMA_SENSITIVITY,
                "formula_distance": "gamma/3",
                "subtarget_bits": C63_SPOT_SUBTARGET_BITS,
                "shared_rows": C63_SPOT_ROWS_AT_PAPER_GAMMA,
                "raw_row_bytes": C63_SPOT_ROWS_AT_PAPER_GAMMA
                * C63_T128_ROW_BYTES,
                "evaluated_for_goldilocks": False,
            },
            "goldilocks_ldpc_distance_screen": {
                "method": "stdlib Decimal port of Bolt q_ldpc.py / YHC growth-rate root",
                "field_size": GOLDILOCKS_MODULUS,
                "column_degree": BOLT_LDPC_COLUMN_DEGREE,
                "check_degree": BOLT_LDPC_CHECK_DEGREE,
                "bolt_reference_q_2pow32_root": str(bolt_reference_distance),
                "goldilocks_numerical_root": str(goldilocks_distance),
                "conservative_gamma_used_for_wire": str(C63_GOLDILOCKS_GAMMA_SCREEN),
                "spot_error_formula": "(1-gamma/3)^queries",
                "subtargets": spot_screens,
                "asymptotic_theorem_6_2_instantiated_for_goldilocks": False,
                "asymptotic_setup_failure_bound_instantiated": False,
                "finite_first_moment_candidate": finite_distance,
                "credit": False,
            },
            "systematic_opening_pi_final_obstruction": {
                "selected_noncredit_spot_subtarget_bits": C63_SPOT_SUBTARGET_BITS,
                "selected_conservative_queries": selected_queries,
                "existing_c62_pi_final_bytes": C62_PI_FINAL_MAX_BYTES,
                "existing_c62_pi_final_headroom_bytes": (
                    PI_FINAL_LIMIT_BYTES - 1 - C62_PI_FINAL_MAX_BYTES
                ),
                "t128_full_fixed_row": t128_full_opening,
                "t128_omit_public_padding_worst_live_row": t128_live_max_opening,
                "t128_complete_tile_average_not_a_codec_maximum": t128_live_average_opening,
                "t4_full_fixed_row": t4_full_opening,
                "t16_full_fixed_row": t16_full_opening,
                "t128_opening_alone_exceeds_existing_headroom": (
                    t128_live_max_opening["opening_bytes_before_framing"]
                    > PI_FINAL_LIMIT_BYTES - 1 - C62_PI_FINAL_MAX_BYTES
                ),
                "t4_opening_alone_exceeds_existing_headroom": (
                    t4_full_opening["opening_bytes_before_framing"]
                    > PI_FINAL_LIMIT_BYTES - 1 - C62_PI_FINAL_MAX_BYTES
                ),
                "t16_opening_alone_exceeds_existing_headroom": (
                    t16_full_opening["opening_bytes_before_framing"]
                    > PI_FINAL_LIMIT_BYTES - 1 - C62_PI_FINAL_MAX_BYTES
                ),
                "conclusion": (
                    "no full-row layout may be added to the existing C6.2 pi_final; "
                    "t16 remains viable only with the proposed public/designated split"
                ),
                "credit": False,
            },
            "t16_public_design_screen": {
                "status": "front-runner; replaces the rejected t128 additive layout",
                "reshape": (
                    "D24x4 -> D22x16; row=position|layer_high|channel_low; "
                    "column=tape|kv|layer_low|channel_high"
                ),
                "row_bytes": C63_T16_ROW_BYTES,
                "rows_per_position_tile": C63_T16_ROWS_PER_POSITION,
                "spot_opening": t16_full_opening,
                "spot_opening_encoded_bytes_with_count": (
                    t16_full_opening["opening_bytes_before_framing"]
                    + C63_MERKLE_MULTIPROOF_COUNT_BYTES
                ),
                "encoded_sketch_opening_paired_q_a": t16_encoded_sketch_paired_opening,
                "encoded_sketch_paired_q_a": C63_PAIRED_A_QUERIES,
                "encoded_sketch_paired_bytes_with_count": (
                    t16_encoded_sketch_paired_opening["opening_bytes_before_framing"]
                    + C63_MERKLE_MULTIPROOF_COUNT_BYTES
                ),
                "encoded_sketch_opening_independent_limb_fallback": (
                    t16_encoded_sketch_independent_opening
                ),
                "encoded_sketch_independent_limb_q_a": C63_INDEPENDENT_LIMB_A_QUERIES,
                "encoded_sketch_independent_limb_bytes_with_count": (
                    t16_encoded_sketch_independent_opening[
                        "opening_bytes_before_framing"
                    ]
                    + C63_MERKLE_MULTIPROOF_COUNT_BYTES
                ),
                "encoded_sketch_outer_q_stress_only": (
                    t16_encoded_sketch_outer_stress_opening
                ),
                "paired_q_a_requires_projected_shared_mmcs_adapter": True,
                "legacy_75bit_d23_hiding_whir_body_bytes": (
                    C61_D23_75BIT_HIDING_WHIR_BYTES
                ),
                "legacy_profile_body_count": (
                    C63_CONSERVATIVE_BASE_WHIR_BODIES
                ),
                "legacy_profile_per_body_bits": C61_D23_HIDING_WHIR_BITS,
                "legacy_four_body_union_bits_upper_bound": (
                    C61_D23_HIDING_WHIR_BITS
                    - math.log2(C63_CONSERVATIVE_BASE_WHIR_BODIES)
                ),
                "selected_c63_per_core_screen_bits": C63_SELECTED_PER_CORE_SCREEN_BITS,
                "selected_profile": {
                    "adapter_rule": (
                        "prove decoded m:D22 and u:D19 while supplying their already "
                        "encoded w/y initial oracles; do not encode w/y again"
                    ),
                    "d22_rates": C63_D22_WHIR_RATES,
                    "d22_folding": C63_D22_WHIR_FOLDING,
                    "d22_round_queries": C63_D22_WHIR_ROUND_QUERIES,
                    "d22_final_queries": C63_D22_WHIR_FINAL_QUERIES,
                    "d22_mask_queries": C63_D22_WHIR_MASK_QUERIES,
                    "d22_pow_bits": C63_D22_WHIR_POW_BITS,
                    "d22_pow_witnesses": C63_D22_WHIR_POW_WITNESSES,
                    "d22_body_bytes_each": C63_D22_WHIR_BODY_BYTES,
                    "d19_rates": C63_D19_WHIR_RATES,
                    "d19_folding": C63_D19_WHIR_FOLDING,
                    "d19_round_queries": C63_D19_WHIR_ROUND_QUERIES,
                    "d19_final_queries": C63_D19_WHIR_FINAL_QUERIES,
                    "d19_mask_queries": C63_D19_WHIR_MASK_QUERIES,
                    "d19_pow_bits": C63_D19_WHIR_POW_BITS,
                    "d19_pow_witnesses": C63_D19_WHIR_POW_WITNESSES,
                    "d19_body_bytes_each": C63_D19_WHIR_BODY_BYTES,
                    "two_d22_plus_two_d19_bytes": C63_PROFILED_WHIR_BODIES_BYTES,
                    "projected_outer_bytes_each": C63_PROJECTED_WHIR_OUTER_BYTES,
                    "unmodified_double_encoded_d23_d20_fallback_bytes": (
                        C63_UNMODIFIED_DOUBLE_ENCODED_WHIR_BODIES_BYTES
                    ),
                    "current_c61_codec_forbids_pow": True,
                    "honest_preencoded_cached_base_reference_green": True,
                    "cpu_linked_projected_adapter_reference_green": True,
                    "cpu_fresh_mask_encoding_relation_reference_green": True,
                    "cpu_four_authenticated_terminal_lanes_reference_green": True,
                    "canonical_whir_codec_with_native_pow_green": True,
                    "canonical_correction_rows_codec_green": True,
                    "canonical_public_argument_codec_green": True,
                    "canonical_designated_tail_codec_green": True,
                    "separated_h_pow_h_fs_reference_green": True,
                    "reduced_wrapper_pcs_bytes": C63_REDUCED_WRAPPER_PCS_BYTES,
                    "reduced_output_link_bytes": C63_REDUCED_OUTPUT_LINK_BYTES,
                    "reduced_wrapper_relations": 40,
                    "reduced_wrapper_rounds": 24,
                    "reduced_wrapper_correlations_per_tape": 96,
                    "production_linked_projected_adapter_codec_green": True,
                    "production_fresh_mask_encoding_relation_codec_green": True,
                    "production_four_terminal_lane_codecs_green": True,
                    "joint_ideal_correction_privacy_lean_green": True,
            "production_codec_privacy_audit_green": True,
                    "credit": False,
                },
                "legacy_profile_soundness_is_below_gate": True,
                "legacy_profile_bodies_bytes": t16_old_profile_whir_bodies,
                "sparse_h_closure_framed_bytes": C63_SPARSE_H_CLOSURE_BYTES,
                "four_whir_terminal_tags_bytes": C63_WHIR_TERMINAL_TAG_BYTES,
                "correction_artifact_max_bytes": C63_CORRECTION_ARTIFACT_MAX_BYTES,
                "public_argument_framing_bytes": C63_PUBLIC_ARGUMENT_FRAMING_BYTES,
                "designated_response_envelope_bytes": C63_RESPONSE_ENVELOPE_BYTES,
                "public_bulk_before_sparse_h_tail_and_outer_framing_bytes": (
                    t16_profiled_public_bulk_screen
                ),
                "pi_final_two_cohort_screen": {
                    "removed_cache_cohort_link_bytes": C62_CACHE_COHORT_LINK_SAVING_BYTES,
                    "removed_cache_only_small_components_bytes": (
                        C62_CACHE_ONLY_SMALL_COMPONENTS_BYTES
                    ),
                    "removed_cache_component_headers_bytes": (
                        C62_REMOVED_CACHE_COMPONENT_HEADER_BYTES
                    ),
                    "residual_aux_before_new_closure_bytes": (
                        C63_RESIDUAL_AUX_PI_BEFORE_CLOSURE_BYTES
                    ),
                    "maximum_new_closure_bytes_under_strict_gate": (
                        PI_FINAL_LIMIT_BYTES
                        - 1
                        - C63_RESIDUAL_AUX_PI_BEFORE_CLOSURE_BYTES
                    ),
                },
                "certificate_at_strict_pi_cap_before_new_public_framing_bytes": (
                    certificate_at_strict_pi_cap_before_new_public_framing
                ),
                "certificate_headroom_before_new_public_framing_bytes": (
                    CERTIFICATE_LIMIT_BYTES
                    - certificate_at_strict_pi_cap_before_new_public_framing
                ),
                "projected_pi_final_with_sparse_h_bytes": projected_pi_final_with_sparse_h,
                "certificate_with_projected_pi_before_outer_framing_bytes": (
                    certificate_with_projected_pi_before_outer_framing
                ),
                "certificate_with_projected_pi_headroom_bytes": (
                    CERTIFICATE_LIMIT_BYTES
                    - certificate_with_projected_pi_before_outer_framing
                ),
                "independent_limb_fallback": {
                    "deduplicated_union_requires_outer_a_opening_driver": True,
                    "public_bulk_bytes": t16_independent_limb_public_bulk_screen,
                    "certificate_with_projected_pi_bytes": (
                        independent_limb_certificate_with_projected_pi
                    ),
                    "projected_pi_headroom_bytes": (
                        CERTIFICATE_LIMIT_BYTES
                        - independent_limb_certificate_with_projected_pi
                    ),
                    "certificate_at_strict_pi_cap_bytes": (
                        independent_limb_certificate_at_strict_pi_cap
                    ),
                    "strict_pi_cap_headroom_bytes": (
                        CERTIFICATE_LIMIT_BYTES
                        - independent_limb_certificate_at_strict_pi_cap
                    ),
                },
                "independent_separate_a_proofs_minimal_fallback": {
                    "a_opening_bytes_with_counts": C63_INDEPENDENT_A_PROOFS
                    * (
                        t16_encoded_sketch_paired_opening[
                            "opening_bytes_before_framing"
                        ]
                        + C63_MERKLE_MULTIPROOF_COUNT_BYTES
                    ),
                    "public_bulk_bytes": t16_independent_separate_public_bulk_screen,
                    "certificate_with_projected_pi_bytes": (
                        independent_separate_certificate_with_projected_pi
                    ),
                    "projected_pi_headroom_bytes": (
                        CERTIFICATE_LIMIT_BYTES
                        - independent_separate_certificate_with_projected_pi
                    ),
                    "certificate_at_strict_pi_cap_bytes": (
                        independent_separate_certificate_at_strict_pi_cap
                    ),
                    "strict_pi_cap_headroom_bytes": (
                        CERTIFICATE_LIMIT_BYTES
                        - independent_separate_certificate_at_strict_pi_cap
                    ),
                },
                "partition_rule": (
                    "Delta-independent tagless Bolt/WHIR material is public; only common-X, "
                    "two Delta closures and residual/aux link remain in pi_final"
                ),
                "partition_and_outer_codecs_green": True,
                "credit": False,
            },
            "precode": "setup-seeded sparse Goldilocks H: D22 to D19, columnwise",
            "base_code_and_proximity": "tensorial C^16 inside full Hiding-WHIR",
            "sparse_h_setup_sampler": {
                "sampler": "BLAKE3-XOF plus exact descending Fisher-Yates",
                "ensemble": "YHC socket permutation with independent nonzero labels",
                "public_seed_bytes": 32,
                "expanded_h_digest_bytes": 32,
                "versioned_descriptor_bytes": C63_SPARSE_SETUP_DESCRIPTOR_BYTES,
                "c62_setup_plus_descriptor_floor_bytes": setup_with_sparse_descriptor,
                "floor_plus_30mb_certificate_bytes": setup_plus_max_certificate,
                "floor_plus_projected_first_before_outer_framing_bytes": (
                    setup_plus_projected_first
                ),
                    "complete_c63_setup_candidate_bytes": setup_with_sparse_descriptor,
                "permutation_resident_bytes": C63_SPARSE_SETUP_PERMUTATION_BYTES,
                "coefficient_resident_bytes": C63_SPARSE_SETUP_COEFFICIENT_BYTES,
                "total_resident_bytes": C63_SPARSE_SETUP_RESIDENT_BYTES,
                "c62_peak_plus_sampler_resident_bytes": setup_resident_vram,
                "vram_margin_bytes": VRAM_GUARD_BYTES - setup_resident_vram,
                "shuffle_four_draw_abort_bound": "<2^-126",
                "coefficient_four_draw_abort_bound": "<=2^-102",
                    "public_xof_hybrid_term": "BLAKE3-XOF computational assumption capped at 128 bits",
                "provider_selected_grindable_seed_forbidden": True,
                "parallel_edges_preserved": True,
                "conditional_uniformity_model": "ideal public XOF",
                "credit": False,
            },
            "sparse_h_response_work": {
                "logical_full_matrix_multiply_adds": (
                    C63_T16_COLUMNS
                    * (1 << C63_T16_ROW_DEPTH)
                    * BOLT_LDPC_COLUMN_DEGREE
                ),
                "genesis_live_multiply_adds": genesis_sparse_h_multiply_adds,
                "continuation_delta_multiply_adds": (
                    continuation_sparse_h_multiply_adds
                ),
                "accepted_prefix_recomputed_on_continuation": False,
                "authenticated_sumcheck_closure": {
                    "h_scan_fp2_by_fp_multiply_adds": 67_108_864,
                    "eq_table_fp2_multiplications": 524_287,
                    "sumcheck_fp2_multiplications": 16_777_212,
                    "systematic_spot_rows_fused": (
                        C63_SYSTEMATIC_SPOT_FUSION_QUERIES
                    ),
                    "systematic_spot_indexed_additions": (
                        C63_SYSTEMATIC_SPOT_FUSION_QUERIES
                    ),
                    "separate_spot_batch_body_bytes": 0,
                    "whir_targets_after_fusion": 1,
                    "claim_relation": (
                        "<eq(r),u>+sum beta^(j+1)*x[i_j] = "
                        "<H^T*eq(r)+sum beta^(j+1)*e[i_j],m>"
                    ),
                    "scratch_bytes": 75_497_472,
                    "framed_bytes_when_terminal_residual_joins_zero_batch": (
                        C63_SPARSE_H_CLOSURE_BYTES
                    ),
                    "correlations_per_mac_tape": (
                        C63_SPARSE_H_CLOSURE_CORRELATIONS_PER_TAPE
                    ),
                    "existing_error": "64/|Fp2|",
                    "additional_spot_compression_error": "4420/|Fp2|",
                    "cpu_verifier_scans_h_bytes": C63_SPARSE_SETUP_RESIDENT_BYTES,
                    "production_integration_credit": False,
                },
            },
            "vram_schedule_screen": {
                "basis": "analytic proxy; no tensor/Fp2 executable guard credit",
                "forced_gw4_whir_overlap_bytes": forced_overlap_vram,
                "forced_overlap_exceeds_guard": forced_overlap_vram > VRAM_GUARD_BYTES,
                "sequential_gw4_plus_h_plus_state_bytes": sequential_gw4_phase_vram,
                "sequential_c63_one_workspace_bytes": sequential_c63_phase_vram,
                "lane_guard_includes_one_d23_fp2_codeword": True,
                "pre_a_state_proxy_bytes": C63_PRE_A_STATE_PROXY_BYTES,
                "one_encoded_sketch_data_bytes": C63_ENCODED_SKETCH_DATA_BYTES,
                "one_encoded_sketch_merkle_bytes": C63_ENCODED_SKETCH_MERKLE_BYTES,
                "accepted_plus_proposed_encoded_sketch_bytes": (
                    C63_ACCEPTED_PROPOSED_ENCODED_SKETCH_BYTES
                ),
                "full_old_new_state_proxy_bytes": C63_FULL_STATE_PROXY_BYTES,
                "required_schedule": (
                    "keep H resident; release GW4 transient owners; execute four base "
                    "WHIR cores sequentially with one workspace"
                ),
                "credit": False,
            },
            "transient_code_switch_required": True,
            "conservative_body_census": {
                "extension_oracles": ["w=C(D'*rho)", "y=A*rho=C((H*D')*rho)"],
                "base_limbs_per_extension_oracle": C63_BASE_LIMBS_PER_EXTENSION,
                "sequential_base_whir_cores": C63_CONSERVATIVE_BASE_WHIR_BODIES,
                "persistent_pre_rho_roots": ["D'", "deterministic A"],
                "fresh_randomized_initial_roots_per_response": 4,
                "profiled_bodies_bytes": C63_PROFILED_WHIR_BODIES_BYTES,
            },
            "gw4_changed": False,
            "raw_genesis_corrections_on_wire_bytes": (
                genesis["new_correction_bytes_both_tapes"]
            ),
            "raw_corrections_fit_complete_certificate": (
                genesis["new_correction_bytes_both_tapes"] <= CERTIFICATE_LIMIT_BYTES
            ),
            "credit": False,
        },
        "soundness_screen": soundness_screen,
        "gpt2_cache_geometry": {
            "fp2_bytes": FP2_BYTES,
            "subfield_correction_bytes": SUBFIELD_CORRECTION_BYTES,
            "slots": SLOTS,
            "live_slots": LIVE_SLOTS,
            "layers": LAYERS,
            "capacity_tokens": CAPACITY_TOKENS,
            "width": WIDTH,
            "padded_layers": PADDED_LAYERS,
            "padded_width": PADDED_WIDTH,
            "padded_entries_per_slot": PADDED_ENTRIES_PER_SLOT,
            "legacy_dense_state_fp2_entries": legacy_state_entries,
            "legacy_dense_state_bytes": legacy_state_entries * FP2_BYTES,
            "compact_two_slot_address_fp2_entries": compact_state_entries,
            "compact_two_slot_address_bytes": compact_state_entries * FP2_BYTES,
            "inactive_slot_entries_kept_virtual": inactive_virtual_entries,
            "genesis_wholly_zero_slot_instances_across_old_and_new_roots": 14,
            "zero_predecessor_policy": "setup-owned; never materialized per response",
            "successor_policy": "update two live K/V slots; promote only after acceptance",
            "genesis_0_to_150": genesis,
            "continuation_150_to_200": continuation,
        },
        "unknown_c63_evidence": [
            "provider wall",
            "four-thread verifier wall",
            "verifier additional RSS",
            "peak VRAM",
            "resident GPU integration of sparse H closure and transient code switch",
            "real/AES-PCG full-response execution",
        ],
        "decision": "local codec/privacy/soundness candidate; GPU implementation and real E2E remain required",
    }

    # One executable self-check: any changed input must update the registered arithmetic.
    assert CACHE_TIME_BUDGET_NS == 9_640_596_167
    assert HISTORICAL_NONCOMPARABLE_TOTAL_BYTES == 23_560_000
    assert setup_plus_historical_screen == 124_757_617
    assert CERTIFICATE_LIMIT_BYTES - HISTORICAL_NONCOMPARABLE_TOTAL_BYTES == 6_440_000
    assert C63_T128_ROW_BYTES == 1_024
    assert C63_T128_COLUMNS_PER_TAPE == 64
    assert C63_T16_ROW_BYTES == 128
    assert C63_T16_COLUMNS_PER_TAPE == 8
    assert 150 * C63_T16_LIVE_ROWS_PER_POSITION * C63_T16_ROW_BYTES == 58_982_400
    assert 50 * C63_T16_LIVE_ROWS_PER_POSITION * C63_T16_ROW_BYTES == 19_660_800
    assert C63_SPOT_ROWS_AT_PAPER_GAMMA == 2_238
    assert str(bolt_reference_distance).startswith("0.094114390986")
    assert str(goldilocks_distance).startswith("0.049794378834")
    assert finite_distance["maximum_bad_weight"] == 205_520
    assert Decimal(finite_distance["candidate_distance_bits"]) > Decimal(211)
    assert finite_distance["rational_certificate"]["candidate_distance_bits_lower"] == 188
    assert spot_screens["84"]["queries_at_conservative_gamma"] == 3_536
    assert spot_screens["90"]["queries_at_conservative_gamma"] == 3_789
    assert spot_screens["96"]["queries_at_conservative_gamma"] == 4_041
    assert spot_screens["102"]["queries_at_conservative_gamma"] == 4_294
    assert spot_screens["104"]["queries_at_conservative_gamma"] == 4_378
    assert spot_screens["105"]["queries_at_conservative_gamma"] == 4_420
    assert t128_full_opening["opening_bytes_before_framing"] == 5_495_424
    assert t128_live_max_opening["opening_bytes_before_framing"] == 4_363_904
    assert t128_live_average_opening["opening_bytes_before_framing"] == 3_515_264
    assert t4_full_opening["opening_bytes_before_framing"] == 1_817_984
    assert PI_FINAL_LIMIT_BYTES - 1 - C62_PI_FINAL_MAX_BYTES == 1_014_868
    assert t16_full_opening["opening_bytes_before_framing"] == 1_959_424
    assert t16_encoded_sketch_paired_opening["opening_bytes_before_framing"] == 149_312
    assert t16_encoded_sketch_independent_opening["opening_bytes_before_framing"] == 282_944
    assert t16_encoded_sketch_outer_stress_opening["opening_bytes_before_framing"] == 2_100_864
    assert t16_old_profile_whir_bodies == 3_473_152
    assert C63_PROFILED_WHIR_BODIES_BYTES == 4_519_664
    assert 2 * (
        C63_D22_WHIR_POW_WITNESSES + C63_D19_WHIR_POW_WITNESSES
    ) == C63_WHIR_PHASE_EVENT_LOWER_BOUND
    assert C63_D22_WHIR_ROUND_QUERIES[0] == C63_PAIRED_A_QUERIES
    assert C63_D19_WHIR_ROUND_QUERIES[0] == C63_PAIRED_A_QUERIES
    assert t16_profiled_public_bulk_screen == 6_706_626
    assert t16_independent_limb_public_bulk_screen == 6_840_258
    assert t16_independent_separate_public_bulk_screen == 6_855_982
    assert (
        C62_PI_FINAL_MAX_BYTES
        - C62_CACHE_COHORT_LINK_SAVING_BYTES
        - C62_CACHE_ONLY_SMALL_COMPONENTS_BYTES
        - C62_REMOVED_CACHE_COMPONENT_HEADER_BYTES
        == C63_RESIDUAL_AUX_PI_BEFORE_CLOSURE_BYTES
    )
    assert (
        PI_FINAL_LIMIT_BYTES - 1 - C63_RESIDUAL_AUX_PI_BEFORE_CLOSURE_BYTES
        == 1_796_986
    )
    assert projected_pi_final_with_sparse_h == 2_704_573
    assert certificate_with_projected_pi_before_outer_framing == 23_122_063
    assert (
        CERTIFICATE_LIMIT_BYTES - certificate_with_projected_pi_before_outer_framing
        == 6_877_937
    )
    assert certificate_at_strict_pi_cap_before_new_public_framing == 24_917_489
    assert (
        CERTIFICATE_LIMIT_BYTES
        - certificate_at_strict_pi_cap_before_new_public_framing
        == 5_082_511
    )
    assert independent_limb_certificate_with_projected_pi == 23_255_695
    assert independent_limb_certificate_at_strict_pi_cap == 25_051_121
    assert CERTIFICATE_LIMIT_BYTES - independent_limb_certificate_at_strict_pi_cap == 4_948_879
    assert independent_separate_certificate_with_projected_pi == 23_271_419
    assert independent_separate_certificate_at_strict_pi_cap == 25_066_845
    assert CERTIFICATE_LIMIT_BYTES - independent_separate_certificate_at_strict_pi_cap == 4_933_155
    assert setup_with_sparse_descriptor == 101_197_697
    assert setup_plus_max_certificate == 131_197_697
    assert setup_plus_projected_first == 124_319_760
    assert C63_SPARSE_SETUP_RESIDENT_BYTES == 805_306_368
    assert setup_resident_vram == 39_951_669_100
    assert VRAM_GUARD_BYTES - setup_resident_vram == 5_866_907_764
    assert C63_ENCODED_SKETCH_DATA_BYTES == 134_217_728
    assert C63_ENCODED_SKETCH_MERKLE_BYTES == 33_554_400
    assert C63_ACCEPTED_PROPOSED_ENCODED_SKETCH_BYTES == 335_544_256
    assert C63_FULL_STATE_PROXY_BYTES == 664_851_392
    assert forced_overlap_vram == 46_145_661_708
    assert forced_overlap_vram - VRAM_GUARD_BYTES == 327_084_844
    assert sequential_gw4_phase_vram == 40_616_520_492
    assert sequential_c63_phase_vram == 19_884_200_864
    assert PADDED_ENTRIES_PER_SLOT == 1 << 24
    assert legacy_state_entries == 1 << 27
    assert compact_state_entries == 1 << 25
    assert inactive_virtual_entries == 6 * (1 << 24)
    assert genesis["append_fp2_entries"] == 2_764_800
    assert genesis["append_bytes"] == 44_236_800
    assert genesis["append_correction_bytes_per_tape"] == 22_118_400
    assert genesis["append_correction_bytes_both_tapes"] == 44_236_800
    assert continuation["append_fp2_entries"] == 921_600
    assert continuation["append_bytes"] == 14_745_600
    assert continuation["append_correction_bytes_per_tape"] == 7_372_800
    assert continuation["append_correction_bytes_both_tapes"] == 14_745_600
    assert genesis_sparse_h_multiply_adds == 88_473_600
    assert continuation_sparse_h_multiply_adds == 29_491_200
    assert genesis["new_correction_bytes_both_tapes"] > CERTIFICATE_LIMIT_BYTES
    assert not report["authenticated_sketched_whir_selection"][
        "raw_corrections_fit_complete_certificate"
    ]
    assert speedup > Decimal("28.53")
    assert report["historical_noncomparable_bolt_screen"][
        "historical_certificate_arithmetic_under_limit"
    ]
    assert report["historical_noncomparable_bolt_screen"][
        "historical_setup_plus_first_arithmetic_under_limit"
    ]
    assert report["credit"] is False
    assert soundness_screen["known_terms_under_inherited_qro_clear_gate"]
    assert not soundness_screen["known_terms_with_expected_pow_trials_clear_gate"]
    assert soundness_screen["maximum_monolithic_qro_at_gate"] == 1_154_840
    assert soundness_screen["expected_qro_excess_over_gate"] == 7_889_128
    assert soundness_screen["phase_event_lower_bound_clears_gate"]
    assert not soundness_screen["raising_profile_does_not_fix_monolithic_qro"][
        "expected_trial_screen_clear_gate"
    ]
    assert not soundness_screen["raising_profile_does_not_fix_monolithic_qro"][
        "formal_cap_screen_clear_gate"
    ]
    assert soundness_screen["complete_soundness_gate_evaluated"]
    assert soundness_screen["complete_soundness_gate_pass"]
    assert {
        name for name, gate in gates.items() if gate["evaluated"]
    } == {
        "setup_bytes",
        "setup_plus_first_bytes",
        "complete_certificate_bytes_experimental",
        "pi_final_bytes",
        "soundness_bits_per_certificate",
    }
    assert all(gates[name]["pass"] for name in gates if gates[name]["evaluated"])
    return report


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exact C6.1 decomposition and conservative native-candidate roofline.

This report deliberately has two different verdict scopes:

* exact reconciliation of the existing C6 certificate and residual-compiler
  operation census;
* a preregistered C6.1 native-candidate screen.  Its codec ceilings and
  operation roofline are safe to use for ordered pre-code admission, but are
  not implementation or benchmark credit.

No projected ceiling or analytic roofline is proof-size, setup, prover-time,
verifier-time or hardware credit.  The script must keep saying so until a
later append-only amendment changes the verdict together with evidence.
"""

from __future__ import annotations

import argparse
import json
from decimal import Decimal, localcontext
from fractions import Fraction
from typing import Any

import budget_c6_wrapper as c6


# Immutable C3/C4 transcript anchors.
C4_RESPONSE_BYTES = 84_544_352
C4_DIRECT_AUTH_CORRECTION_BYTES = 38_348_720
C4_PCS_U_VECTOR_BYTES = 17_235_968
C4_PCS_Q120_COLUMNS_BYTES = 26_036_160
C4_PCS_MASK_ROOT_BYTES = 64
C4_PCS_S_CORRECTION_BYTES = 1_632
C4_PCS_MASK_CORRECTION_BYTES = 32
C4_PCS_ZERO_BATCH_TAG_BYTES = 32
C6_Q121_QUERY_INCREMENT_BYTES = 216_968

# Closed C6PIF1/final-certificate anchors.
C6_CERTIFICATE_BYTES = 33_096_991
C6_RETAINED_Q121_BYTES = 29_176_632
C6_STRICT_ENVELOPE_BYTES = 3_919_502
C6_CERTIFICATE_FIXED_FRAMING_BYTES = 857
C6_ENVELOPE_FRAMING_BYTES = 324
C6_WRAPPER_PCS_BYTES = 3_879_466
C6_WRAPPER_LINK_OVERHEAD_BYTES = 3_570

# Owner-frozen strict C6.1 gates.
C61_SETUP_EXCLUSIVE_BYTES = 150_000_000
C61_CERTIFICATE_EXCLUSIVE_BYTES = 22_000_000
C61_SETUP_MAX_BYTES = C61_SETUP_EXCLUSIVE_BYTES - 1
C61_CERTIFICATE_MAX_BYTES = C61_CERTIFICATE_EXCLUSIVE_BYTES - 1
C61_PROVIDER_EXCLUSIVE_SECONDS = Decimal("15")
C61_VERIFIER_EXCLUSIVE_SECONDS = Decimal("5")

# Pre-code allocations.  These are codec design ceilings, not earned sizes.
C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES = 12_000_000
C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES = 8_000_000

# Exact existing setup components.
C6_PAIRED_PCG_BYTES = 2 * 38_371_465
C6_SETUP_MANIFEST_BYTES = 437
C6_CANONICAL_PLAN_BYTES = 63_994_751
C6_VERIFIER_INSTANCE_MAP_BYTES = 5_320_386
C6_EXISTING_SETUP_BYTES = 146_058_504

# Historical measurements.  They are informative anchors with different
# scopes; the report never combines them into a C6.1 verdict.
T1_FOUR_THREAD_VERIFY_RESPONSE_SECONDS = Decimal("0.644346018")
T1_FOUR_THREAD_PCS_VERIFY_SECONDS = Decimal("0.121755365")
T1_FOUR_THREAD_VERIFIER_ACCOUNTED_SECONDS = Decimal("0.765672390")
C6_LOCAL_SCALED_RESPONSE_RESIDUAL_VERIFY_SECONDS = Decimal("1.292475")
C6_LOCAL_PRODUCTION_GEOMETRY_TERMINAL_VERIFY_SECONDS = Decimal("14.002651")
C6_EXISTING_A100_KERNEL_FLOOR_SECONDS = Decimal("11.1793342101309625087567277818689354")

# Exact role-local runtime stream census from the installed extraction map.
C6_VERIFIER_RAW_PUBLIC_VALUES = 1_466
C6_VERIFIER_RAW_SCALAR_VALUES = 10_828_876
C6_VERIFIER_CANONICAL_PUBLIC_VALUES = 1_436
C6_VERIFIER_CANONICAL_SCALAR_VALUES = 10_828_852
C61_RUNTIME_SKETCH_REPETITIONS = 2

# C6RSC4-v4 challenge compression.  Every former pseudo-random scalar stream
# is replaced by a post-commit multilinear equality point.  The public claims
# and roots are fixed before these points are sampled.
C61_ALPHA_STREAMS = c6.RESIDUAL_ALPHA_STREAMS
C61_ALPHA_LOG2 = 23
C61_TERMINAL_STREAMS = c6.RESIDUAL_POST_ROOT_TERMINAL_STREAMS
C61_TERMINAL_LOG2 = 17
C61_ATOMIC_STREAMS = c6.RESIDUAL_ATOMIC_WEIGHT_STREAMS
C61_ATOMIC_LOG2 = 26
C61_EQ_CHALLENGE_FP2_ELEMENTS = (
    C61_ALPHA_STREAMS * C61_ALPHA_LOG2
    + C61_TERMINAL_STREAMS * C61_TERMINAL_LOG2
    + C61_ATOMIC_STREAMS * C61_ATOMIC_LOG2
)
C61_EQ_CHALLENGE_CLIENT_BYTES = C61_EQ_CHALLENGE_FP2_ELEMENTS * c6.FP2_BYTES

# Exact installed sparse-adjoint census.  The operation-plan rows are
# provider-global preprocessing; only the root/version enter client setup.
C61_CANONICAL_NODE_COUNT = 28_845_631
C61_SOURCE_NODE_COUNT = 4_970_850
C61_PUBLIC_NODE_COUNT = 1_436
C61_STRUCTURAL_ZERO_NODE_COUNT = 1
C61_ADD_NODE_COUNT = 12_961_295
C61_SUB_NODE_COUNT = 83_197
C61_SCALE_NODE_COUNT = 10_828_852
C61_SPARSE_OPERAND_COUNT = 36_917_836
C61_NODE_LOG2 = 25
C61_RUNTIME_LOG2 = 24
C61_TERMINAL_OUTPUTS = 64

# Native transparent candidate.  Each model/embedding/compiler component uses
# two independent no-grinding chains with at least 74 analytic bits per chain.
# The 1.5-MB chain ceiling is an explicit strict codec ceiling; the underlying
# maximum non-deduplicated Merkle openings are recomputed below.
C61_NATIVE_CHAIN_BITS = 74
C61_NATIVE_CHAINS_PER_COMPONENT = 2
C61_NATIVE_COMPONENTS = 3
C61_NATIVE_CHAIN_CODEC_MAX_BYTES = 1_500_000
C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES = 500_000
C61_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES = (
    C61_NATIVE_COMPONENTS
    * C61_NATIVE_CHAINS_PER_COMPONENT
    * C61_NATIVE_CHAIN_CODEC_MAX_BYTES
    + C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES
)

# Reference no-grinding HVZK-WHIR parameter rows.  These are copied from the
# official academic prototype parameter solver at commit 92652ca0... and are
# used only to upper-bound opened rows and non-deduplicated Merkle siblings.
# Tuple fields: (codeword rows, row width, in-domain queries, element bytes).
C61_NATIVE_D28_OPEN_ROWS = (
    (402_653_184, 2, 103, 8),
    (100_663_296, 4, 103, 16),
    (50_331_648, 4, 61, 16),
    (25_165_824, 4, 43, 16),
    (12_582_912, 4, 34, 16),
    (6_291_456, 4, 28, 16),
    (3_145_728, 4, 23, 16),
    (1_572_864, 4, 20, 16),
    (786_432, 4, 18, 16),
    (393_216, 4, 16, 16),
    (196_608, 4, 15, 16),
    (98_304, 4, 14, 16),
    (98_304, 4, 13, 16),
    (196_608, 1, 12, 16),
)
C61_NATIVE_D27_OPEN_ROWS = (
    (201_326_592, 2, 103, 8),
    (50_331_648, 4, 103, 16),
    (25_165_824, 4, 61, 16),
    (12_582_912, 4, 43, 16),
    (6_291_456, 4, 34, 16),
    (3_145_728, 4, 28, 16),
    (1_572_864, 4, 23, 16),
    (786_432, 4, 20, 16),
    (393_216, 4, 18, 16),
    (196_608, 4, 16, 16),
    (98_304, 4, 15, 16),
    (65_536, 4, 14, 16),
    (98_304, 4, 13, 16),
    (131_072, 1, 12, 16),
)
C61_NATIVE_MASK_OPENING_UPPER_BYTES = 692_416

# Conservative analytic-time charges.  They are deliberately wider than the
# diagnostic prototype and count every transform class sequentially.
C61_OLD_MODEL_PCS_OPEN_SECONDS = Decimal("0.298579063")
C61_NATIVE_MODEL_TRANSFORM_BYTES = 48_337_256_448
C61_NATIVE_MODEL_LINEAR_SECONDS = Decimal("0.600")
C61_NATIVE_COMPILER_EQUIVALENT_PASSES = 64
C61_NATIVE_COMPILER_PCS_VECTORS = 2
C61_NATIVE_COMPILER_PCS_TRANSFORM_EQUIVALENTS = 5
C61_NATIVE_INTEGRATION_FACTOR = Decimal("1.20")
C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS = Decimal("0.550")
C61_VERIFIER_PUBLIC_ARITHMETIC_SECONDS = Decimal("0.500")
C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES = 4 * 573_299_712
C61_VERIFIER_ADDITIONAL_MEMORY_GATE_BYTES = 8_000_000_000
C61_VERIFIER_CERTIFICATE_BUFFER_BYTES = C61_CERTIFICATE_MAX_BYTES
C61_VERIFIER_NATIVE_CHAIN_SCRATCH_BYTES = 6 * 64_000_000
C61_VERIFIER_PUBLIC_DV_SCRATCH_BYTES = 64_000_000
C61_VERIFIER_ALLOCATOR_RESERVE_BYTES = 42_000_001
C61_VERIFIER_ADDITIONAL_MEMORY_ALLOCATION_BYTES = (
    C61_VERIFIER_CERTIFICATE_BUFFER_BYTES
    + C61_VERIFIER_NATIVE_CHAIN_SCRATCH_BYTES
    + C61_VERIFIER_PUBLIC_DV_SCRATCH_BYTES
    + C61_VERIFIER_ALLOCATOR_RESERVE_BYTES
)


def _non_deduplicated_opening_upper_bytes(
    rows: tuple[tuple[int, int, int, int], ...],
) -> int:
    """Raw rows + one sibling per query and tree level + roots.

    Real Merkle frontiers deduplicate siblings.  This formula intentionally
    does not, so it is an upper bound rather than a measured proof size.
    """

    opened_rows = sum(width * queries * element_bytes for _, width, queries, element_bytes in rows)
    siblings = sum(
        queries * (codeword_rows - 1).bit_length() * 32
        for codeword_rows, _, queries, _ in rows
    )
    roots = len(rows) * 32
    return opened_rows + siblings + roots


def _transparent_transform_seconds(byte_count: int) -> Decimal:
    """Sequential NTT + BLAKE3 + streaming charge at recorded P7 rates."""

    ntt_bytes_per_second = c6.P7_NTT_BYTES / c6.P7_NTT_SECONDS
    blake3_bytes_per_second = c6.P7_BLAKE3_BYTES / c6.P7_BLAKE3_SECONDS
    return (
        Decimal(byte_count) / ntt_bytes_per_second
        + Decimal(byte_count) / blake3_bytes_per_second
        + Decimal(byte_count) / c6.P7_STREAM_BYTES_PER_SECOND
    )


def _error_report(error: Fraction) -> dict[str, str]:
    return {
        "numerator": str(error.numerator),
        "denominator": str(error.denominator),
        "bits": str(c6.soundness_bits(error)),
    }


def build_report() -> dict[str, Any]:
    old_pcs_q120 = (
        C4_PCS_Q120_COLUMNS_BYTES
        + C4_PCS_MASK_ROOT_BYTES
        + C4_PCS_S_CORRECTION_BYTES
        + C4_PCS_MASK_CORRECTION_BYTES
        + C4_PCS_ZERO_BATCH_TAG_BYTES
    )
    old_pcs_q121 = old_pcs_q120 + C6_Q121_QUERY_INCREMENT_BYTES
    old_pcs_public_eligible = (
        C4_PCS_Q120_COLUMNS_BYTES
        + C6_Q121_QUERY_INCREMENT_BYTES
        + C4_PCS_MASK_ROOT_BYTES
    )
    old_pcs_delta_dependent = (
        C4_PCS_S_CORRECTION_BYTES
        + C4_PCS_MASK_CORRECTION_BYTES
        + C4_PCS_ZERO_BATCH_TAG_BYTES
    )
    retained_non_pcs = (
        C4_RESPONSE_BYTES
        - C4_DIRECT_AUTH_CORRECTION_BYTES
        - C4_PCS_U_VECTOR_BYTES
        - old_pcs_q120
    )

    wrapper_delta_payloads = {
        "c6rsc3": c6.RESIDUAL_SUMCHECK_PROOF_BYTES,
        "residual_pending": c6.RESIDUAL_PENDING_CORRECTION_BYTES,
        "c6hub2": c6.HIDDEN_U_PROOF_BYTES,
        "c6ps1": c6.CACHE_SOURCE_BOOTSTRAP_BYTES,
        "c6pc2": c6.CACHE_BLIND_PROOF_BYTES,
        "c6ft1": c6.CACHE_FOLD_TARGET_FRAME_BYTES,
        "c6lnk2_delta_overhead": C6_WRAPPER_LINK_OVERHEAD_BYTES,
    }
    wrapper_delta_bytes = sum(wrapper_delta_payloads.values())
    state_and_framing_bytes = (
        C6_ENVELOPE_FRAMING_BYTES + C6_CERTIFICATE_FIXED_FRAMING_BYTES
    )

    public_eligible_raw_bytes = old_pcs_public_eligible + C6_WRAPPER_PCS_BYTES
    delta_dependent_bytes = (
        retained_non_pcs + old_pcs_delta_dependent + wrapper_delta_bytes
    )
    non_public_remainder_bytes = delta_dependent_bytes + state_and_framing_bytes

    # Active conservative route: replace the complete old weight/embed PCS,
    # including its now-obsolete correction closure, but preserve C6LNK2's
    # wrapper PCS and every existing DV component byte-for-byte.
    active_fixed_remainder_bytes = C6_CERTIFICATE_BYTES - old_pcs_q121
    active_projected_certificate_bytes = (
        active_fixed_remainder_bytes + C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES
    )
    active_public_argument_absolute_max_bytes = (
        C61_CERTIFICATE_MAX_BYTES - active_fixed_remainder_bytes
    )

    # Optional later optimization only; it receives no active-route credit.
    absorb_wrapper_fixed_remainder_bytes = (
        active_fixed_remainder_bytes - C6_WRAPPER_PCS_BYTES
    )
    absorb_wrapper_projected_certificate_bytes = (
        absorb_wrapper_fixed_remainder_bytes
        + C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES
    )

    setup_without_client_compiler_artifacts = (
        C6_PAIRED_PCG_BYTES + C6_SETUP_MANIFEST_BYTES
    )
    projected_setup_bytes = (
        setup_without_client_compiler_artifacts
        + C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES
    )
    projected_first_response_bytes = (
        projected_setup_bytes + active_projected_certificate_bytes
    )

    runtime_stream_values = (
        C6_VERIFIER_RAW_PUBLIC_VALUES + C6_VERIFIER_RAW_SCALAR_VALUES
    )
    runtime_sketch_error = Fraction(
        C61_RUNTIME_LOG2**C61_RUNTIME_SKETCH_REPETITIONS,
        c6.FP2_CARDINALITY**C61_RUNTIME_SKETCH_REPETITIONS,
    )
    runtime_sketch_bits = c6.soundness_bits(runtime_sketch_error)

    # C6RSC4-v4 statistical composition.  The schedule/output/adjoint events
    # are sampled after the relevant roots and claims are fixed.  The three
    # transparent components each use two independent >=74-bit chains.
    equality_schedule_error = Fraction(
        C61_EQ_CHALLENGE_FP2_ELEMENTS, c6.FP2_CARDINALITY
    )
    output_batch_error = Fraction(
        C61_TERMINAL_OUTPUTS - 1, c6.FP2_CARDINALITY
    )
    sparse_adjoint_error = Fraction(C61_NODE_LOG2, c6.FP2_CARDINALITY)
    native_backend_error = Fraction(
        C61_NATIVE_COMPONENTS,
        2 ** (C61_NATIVE_CHAIN_BITS * C61_NATIVE_CHAINS_PER_COMPONENT),
    )
    existing_wrapper_error = (
        c6.pcs_error_amplified(c6.SELECTED_QUERY_COUNT)
        + Fraction(c6.HIDDEN_LINEAR_NUMERATOR, c6.FP2_CARDINALITY**2)
        + Fraction(
            c6.CACHE_ROOT_BOUND_PER_REPETITION**2,
            c6.FP2_CARDINALITY**2,
        )
        + Fraction(c6.DELTA_EVENT_NUMERATOR, c6.FP2_CARDINALITY**2)
    )
    candidate_complete_error = (
        equality_schedule_error
        + runtime_sketch_error
        + output_batch_error
        + sparse_adjoint_error
        + native_backend_error
        + existing_wrapper_error
    )
    candidate_session_error = 17 * candidate_complete_error

    d28_opening_upper_bytes = _non_deduplicated_opening_upper_bytes(
        C61_NATIVE_D28_OPEN_ROWS
    )
    d27_opening_upper_bytes = _non_deduplicated_opening_upper_bytes(
        C61_NATIVE_D27_OPEN_ROWS
    )
    d28_known_chain_bytes = (
        d28_opening_upper_bytes + C61_NATIVE_MASK_OPENING_UPPER_BYTES
    )
    d27_known_chain_bytes = (
        d27_opening_upper_bytes + C61_NATIVE_MASK_OPENING_UPPER_BYTES
    )
    native_projected_certificate_bytes = (
        active_fixed_remainder_bytes + C61_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES
    )
    native_projected_first_response_bytes = (
        projected_setup_bytes + native_projected_certificate_bytes
    )

    provider_state_elements = 4 * C61_CANONICAL_NODE_COUNT + runtime_stream_values
    provider_state_bytes = provider_state_elements * c6.FP2_BYTES

    with localcontext() as context:
        context.prec = 70
        native_model_transform_seconds = _transparent_transform_seconds(
            C61_NATIVE_MODEL_TRANSFORM_BYTES
        )
        native_model_roof_seconds = (
            native_model_transform_seconds + C61_NATIVE_MODEL_LINEAR_SECONDS
        ) * C61_NATIVE_INTEGRATION_FACTOR

        native_compiler_symbols = C61_NATIVE_COMPILER_EQUIVALENT_PASSES * (
            C61_CANONICAL_NODE_COUNT
            + C61_SPARSE_OPERAND_COUNT
            + runtime_stream_values
        )
        native_compiler_memory_seconds = (
            Decimal(native_compiler_symbols * c6.FP2_BYTES)
            / c6.P7_STREAM_BYTES_PER_SECOND
        )
        native_compiler_arithmetic_seconds = (
            Decimal(native_compiler_symbols) / c6.P7_FP2_MULS_PER_SECOND
        )
        native_compiler_core_seconds = max(
            native_compiler_memory_seconds,
            native_compiler_arithmetic_seconds,
        )
        native_compiler_pcs_transform_bytes = (
            C61_NATIVE_COMPILER_PCS_TRANSFORM_EQUIVALENTS
            * C61_NATIVE_COMPILER_PCS_VECTORS
            * 2**C61_NODE_LOG2
            * c6.FP2_BYTES
            * 2  # rate 1/2 encoded domains
        )
        native_compiler_pcs_seconds = _transparent_transform_seconds(
            native_compiler_pcs_transform_bytes
        )
        native_compiler_roof_seconds = (
            native_compiler_core_seconds + native_compiler_pcs_seconds
        ) * C61_NATIVE_INTEGRATION_FACTOR
        native_provider_roof_seconds = (
            C6_EXISTING_A100_KERNEL_FLOOR_SECONDS
            - C61_OLD_MODEL_PCS_OPEN_SECONDS
            + native_model_roof_seconds
            + native_compiler_roof_seconds
        )
        native_verifier_roof_seconds = (
            T1_FOUR_THREAD_VERIFIER_ACCOUNTED_SECONDS
            + Decimal(
                C61_NATIVE_COMPONENTS * C61_NATIVE_CHAINS_PER_COMPONENT
            )
            * C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS
            + C61_VERIFIER_PUBLIC_ARITHMETIC_SECONDS
        )

    compiler_families = {
        "source_grammar": c6.RESIDUAL_SOURCE_COEFFICIENT_WRITES_PER_REPETITION,
        "affine": c6.RESIDUAL_AFFINE_COEFFICIENT_WRITES_PER_REPETITION,
        "reverse": c6.RESIDUAL_REVERSE_COEFFICIENT_WRITES_PER_REPETITION,
        "raw_copy": c6.RESIDUAL_RAW_COPY_COEFFICIENT_WRITES_PER_REPETITION,
        "product": c6.RESIDUAL_PRODUCT_COEFFICIENT_WRITES_PER_REPETITION,
        "zero": c6.RESIDUAL_ZERO_COEFFICIENT_WRITES_PER_REPETITION,
        "leaf_raw_tails": c6.RESIDUAL_LEAF_TAIL_OUTPUTS_PER_REPETITION,
        "auxiliary_tails": c6.RESIDUAL_AUXILIARY_TAIL_OUTPUTS_PER_REPETITION,
    }

    report: dict[str, Any] = {
        "profile": "C6.1-public-compression-precode-v1",
        "verdict": (
            "PRECODE_NATIVE_CANDIDATE_SCREEN_PASS__FORMALIZATION_REQUIRED"
        ),
        "credit": {
            "proof_size": False,
            "setup": False,
            "provider_time": False,
            "verifier_time": False,
            "hardware": False,
        },
        "existing_certificate": {
            "bytes": C6_CERTIFICATE_BYTES,
            "retained_q121_bytes": C6_RETAINED_Q121_BYTES,
            "strict_envelope_bytes": C6_STRICT_ENVELOPE_BYTES,
            "fixed_certificate_framing_bytes": C6_CERTIFICATE_FIXED_FRAMING_BYTES,
            "partition": {
                "public_eligible_raw_bytes": public_eligible_raw_bytes,
                "delta_dependent_bytes": delta_dependent_bytes,
                "state_and_framing_bytes": state_and_framing_bytes,
                "non_public_remainder_bytes": non_public_remainder_bytes,
            },
            "old_weight_embed_pcs": {
                "q120_bytes": old_pcs_q120,
                "q121_bytes": old_pcs_q121,
                "public_columns_and_root_bytes": old_pcs_public_eligible,
                "delta_dependent_closure_bytes": old_pcs_delta_dependent,
                "q121_increment_bytes": C6_Q121_QUERY_INCREMENT_BYTES,
            },
            "retained_non_pcs_delta_transcript_bytes": retained_non_pcs,
            "wrapper": {
                "public_pcs_bytes": C6_WRAPPER_PCS_BYTES,
                "delta_payloads": wrapper_delta_payloads,
                "delta_payload_bytes": wrapper_delta_bytes,
                "envelope_framing_bytes": C6_ENVELOPE_FRAMING_BYTES,
            },
        },
        "active_wire_screen": {
            "route": "replace-old-weight-embed-pcs__retain-c6lnk2-wrapper-pcs",
            "fixed_remainder_bytes": active_fixed_remainder_bytes,
            "public_argument_preregistered_allocation_bytes": (
                C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES
            ),
            "public_argument_absolute_max_bytes": (
                active_public_argument_absolute_max_bytes
            ),
            "projected_certificate_bytes": active_projected_certificate_bytes,
            "strict_certificate_max_bytes": C61_CERTIFICATE_MAX_BYTES,
            "headroom_bytes": (
                C61_CERTIFICATE_MAX_BYTES - active_projected_certificate_bytes
            ),
            "allocation_screen_pass": (
                active_projected_certificate_bytes <= C61_CERTIFICATE_MAX_BYTES
            ),
            "credit": False,
        },
        "optional_absorb_wrapper_pcs_screen": {
            "active_route": False,
            "fixed_remainder_bytes": absorb_wrapper_fixed_remainder_bytes,
            "projected_certificate_bytes_at_same_allocation": (
                absorb_wrapper_projected_certificate_bytes
            ),
            "additional_saving_bytes": C6_WRAPPER_PCS_BYTES,
            "credit": False,
        },
        "selected_native_candidate": {
            "name": "C6PA1-native-HVZK-plus-C6RSC4-v4",
            "status": "PRECODE_SCREEN_ONLY__NO_IMPLEMENTATION_OR_BENCHMARK_CREDIT",
            "statement": (
                "one response conditioned on an already accepted predecessor head"
            ),
            "challenge_schedule": {
                "rule": (
                    "roots and public terminal claims are fixed before every "
                    "multilinear equality point or batching scalar"
                ),
                "alpha": {
                    "streams": C61_ALPHA_STREAMS,
                    "point_dimension": C61_ALPHA_LOG2,
                },
                "terminal": {
                    "streams": C61_TERMINAL_STREAMS,
                    "point_dimension": C61_TERMINAL_LOG2,
                },
                "atomic": {
                    "streams": C61_ATOMIC_STREAMS,
                    "point_dimension": C61_ATOMIC_LOG2,
                },
                "client_challenge_fp2_elements": C61_EQ_CHALLENGE_FP2_ELEMENTS,
                "client_to_provider_bytes_not_in_certificate": (
                    C61_EQ_CHALLENGE_CLIENT_BYTES
                ),
                "former_materialized_prg_oracle": False,
            },
            "sparse_adjoint_compiler": {
                "terminal_claims": C61_TERMINAL_OUTPUTS,
                "one_postclaim_output_rlc": True,
                "canonical_nodes": C61_CANONICAL_NODE_COUNT,
                "node_partition": {
                    "source": C61_SOURCE_NODE_COUNT,
                    "public": C61_PUBLIC_NODE_COUNT,
                    "structural_zero": C61_STRUCTURAL_ZERO_NODE_COUNT,
                    "add": C61_ADD_NODE_COUNT,
                    "sub": C61_SUB_NODE_COUNT,
                    "scale": C61_SCALE_NODE_COUNT,
                },
                "sparse_operand_edges": C61_SPARSE_OPERAND_COUNT,
                "runtime_values": runtime_stream_values,
                "public_pcs_vectors": 2,
                "public_pcs_vector_log2": C61_NODE_LOG2,
                "recurrence": "lambda = root + A^T lambda",
                "provider_global_plan": True,
                "client_receives_plan_or_instance_map": False,
            },
            "native_transparent_backend": {
                "field": "Goldilocks quadratic extension with base-field embedding",
                "mode": "HVZK",
                "decoding_regime": "Johnson",
                "proof_of_work": "forbidden",
                "starting_rate": "1/2",
                "initial_folding_factor": 1,
                "later_folding_factor": 2,
                "chains_per_component": C61_NATIVE_CHAINS_PER_COMPONENT,
                "analytic_bits_per_chain_floor": C61_NATIVE_CHAIN_BITS,
                "components": ["model", "embedding", "compiler"],
                "reference_prototype_commit": (
                    "92652ca01e215548c98e11834e110c43994b94c1"
                ),
                "reference_warning": (
                    "academic prototype; parameters are an analytic/code-size "
                    "screen and not a production dependency or audit"
                ),
                "d28": {
                    "analytic_bits": "74.048384912",
                    "privacy_bits": "124.299560281",
                    "rounds": 13,
                    "non_deduplicated_base_opening_upper_bytes": (
                        d28_opening_upper_bytes
                    ),
                    "known_chain_upper_bytes_including_mask": (
                        d28_known_chain_bytes
                    ),
                    "unallocated_bytes_to_chain_codec_ceiling": (
                        C61_NATIVE_CHAIN_CODEC_MAX_BYTES - d28_known_chain_bytes
                    ),
                },
                "d27": {
                    "analytic_bits": "74.049168779",
                    "privacy_bits": "124.299560281",
                    "rounds": 13,
                    "non_deduplicated_base_opening_upper_bytes": (
                        d27_opening_upper_bytes
                    ),
                    "known_chain_upper_bytes_including_mask": (
                        d27_known_chain_bytes
                    ),
                    "unallocated_bytes_to_chain_codec_ceiling": (
                        C61_NATIVE_CHAIN_CODEC_MAX_BYTES - d27_known_chain_bytes
                    ),
                },
            },
            "wire_screen": {
                "chain_codec_ceiling_bytes": C61_NATIVE_CHAIN_CODEC_MAX_BYTES,
                "chain_count": (
                    C61_NATIVE_COMPONENTS * C61_NATIVE_CHAINS_PER_COMPONENT
                ),
                "arithmetic_mac_link_framing_ceiling_bytes": (
                    C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES
                ),
                "public_argument_codec_ceiling_bytes": (
                    C61_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES
                ),
                "fixed_certificate_remainder_bytes": active_fixed_remainder_bytes,
                "projected_certificate_ceiling_bytes": (
                    native_projected_certificate_bytes
                ),
                "strict_certificate_max_bytes": C61_CERTIFICATE_MAX_BYTES,
                "headroom_bytes": (
                    C61_CERTIFICATE_MAX_BYTES - native_projected_certificate_bytes
                ),
                "projected_setup_bytes": projected_setup_bytes,
                "projected_setup_plus_first_certificate_bytes": (
                    native_projected_first_response_bytes
                ),
                "screen_pass": (
                    native_projected_certificate_bytes <= C61_CERTIFICATE_MAX_BYTES
                    and projected_setup_bytes <= C61_SETUP_MAX_BYTES
                ),
                "credit": False,
            },
            "ephemeral_provider_state_screen": {
                "node_vectors": 4,
                "runtime_vectors": 1,
                "fp2_elements": provider_state_elements,
                "bytes": provider_state_bytes,
                "owner_max_bytes": C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES,
                "headroom_bytes": (
                    C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES - provider_state_bytes
                ),
                "screen_pass": (
                    provider_state_bytes <= C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
                ),
                "persistent": False,
                "credit": False,
            },
            "soundness": {
                "equality_schedule": _error_report(equality_schedule_error),
                "two_runtime_mle_fingerprints": _error_report(
                    runtime_sketch_error
                ),
                "terminal_output_rlc": _error_report(output_batch_error),
                "sparse_adjoint_recurrence": _error_report(
                    sparse_adjoint_error
                ),
                "three_dual_chain_native_components": _error_report(
                    native_backend_error
                ),
                "retained_c6_wrapper": _error_report(existing_wrapper_error),
                "complete_per_certificate": _error_report(
                    candidate_complete_error
                ),
                "informative_seventeen_certificate_union": _error_report(
                    candidate_session_error
                ),
                "per_certificate_target_bits": "78.809",
                "screen_pass": c6.soundness_bits(candidate_complete_error)
                >= Decimal("78.809"),
            },
            "provider_time_roofline": {
                "existing_c6_floor_seconds": str(
                    C6_EXISTING_A100_KERNEL_FLOOR_SECONDS
                ),
                "superseded_old_model_pcs_seconds": str(
                    C61_OLD_MODEL_PCS_OPEN_SECONDS
                ),
                "model_transparent_transform_bytes": (
                    C61_NATIVE_MODEL_TRANSFORM_BYTES
                ),
                "model_transparent_transform_seconds": str(
                    native_model_transform_seconds
                ),
                "model_roof_seconds": str(native_model_roof_seconds),
                "compiler_equivalent_passes": (
                    C61_NATIVE_COMPILER_EQUIVALENT_PASSES
                ),
                "compiler_equivalent_symbols": native_compiler_symbols,
                "compiler_core_seconds": str(native_compiler_core_seconds),
                "compiler_pcs_transform_bytes": (
                    native_compiler_pcs_transform_bytes
                ),
                "compiler_pcs_transform_seconds": str(
                    native_compiler_pcs_seconds
                ),
                "compiler_roof_seconds": str(native_compiler_roof_seconds),
                "projected_total_seconds": str(native_provider_roof_seconds),
                "strict_gate_seconds": str(C61_PROVIDER_EXCLUSIVE_SECONDS),
                "headroom_seconds": str(
                    C61_PROVIDER_EXCLUSIVE_SECONDS - native_provider_roof_seconds
                ),
                "screen_pass": (
                    native_provider_roof_seconds < C61_PROVIDER_EXCLUSIVE_SECONDS
                ),
                "credit": False,
            },
            "verifier_time_roofline": {
                "existing_accounted_seconds": str(
                    T1_FOUR_THREAD_VERIFIER_ACCOUNTED_SECONDS
                ),
                "native_chain_count": (
                    C61_NATIVE_COMPONENTS * C61_NATIVE_CHAINS_PER_COMPONENT
                ),
                "seconds_per_chain_allocation": str(
                    C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS
                ),
                "public_arithmetic_seconds": str(
                    C61_VERIFIER_PUBLIC_ARITHMETIC_SECONDS
                ),
                "projected_total_seconds": str(native_verifier_roof_seconds),
                "strict_gate_seconds": str(C61_VERIFIER_EXCLUSIVE_SECONDS),
                "headroom_seconds": str(
                    C61_VERIFIER_EXCLUSIVE_SECONDS - native_verifier_roof_seconds
                ),
                "screen_pass": (
                    native_verifier_roof_seconds < C61_VERIFIER_EXCLUSIVE_SECONDS
                ),
                "credit": False,
            },
            "verifier_memory_screen": {
                "certificate_buffer_bytes": (
                    C61_VERIFIER_CERTIFICATE_BUFFER_BYTES
                ),
                "six_native_chain_scratch_bytes": (
                    C61_VERIFIER_NATIVE_CHAIN_SCRATCH_BYTES
                ),
                "public_and_dv_scratch_bytes": (
                    C61_VERIFIER_PUBLIC_DV_SCRATCH_BYTES
                ),
                "allocator_reserve_bytes": C61_VERIFIER_ALLOCATOR_RESERVE_BYTES,
                "additional_memory_allocation_bytes": (
                    C61_VERIFIER_ADDITIONAL_MEMORY_ALLOCATION_BYTES
                ),
                "strict_additional_memory_gate_bytes": (
                    C61_VERIFIER_ADDITIONAL_MEMORY_GATE_BYTES
                ),
                "length_prefix_rule": (
                    "strict decoder rejects any component before allocation "
                    "when its registered ceiling is exceeded"
                ),
                "screen_pass": (
                    C61_VERIFIER_ADDITIONAL_MEMORY_ALLOCATION_BYTES
                    <= C61_VERIFIER_ADDITIONAL_MEMORY_GATE_BYTES
                ),
                "credit": False,
            },
            "universal_srs_fallback": {
                "active": False,
                "status": "LOCALLY_OBSTRUCTED_FOR_C6.1",
                "reason": (
                    "a curve PCS does not natively share Goldilocks' scalar "
                    "field; no conservative field-emulation roofline below "
                    "15 seconds is currently available"
                ),
            },
        },
        "setup_screen": {
            "existing_setup_bytes": C6_EXISTING_SETUP_BYTES,
            "existing_components": {
                "paired_pcg": C6_PAIRED_PCG_BYTES,
                "manifest": C6_SETUP_MANIFEST_BYTES,
                "canonical_plan": C6_CANONICAL_PLAN_BYTES,
                "verifier_instance_map": C6_VERIFIER_INSTANCE_MAP_BYTES,
            },
            "compiler_artifacts_removed_from_client_bytes": (
                C6_CANONICAL_PLAN_BYTES + C6_VERIFIER_INSTANCE_MAP_BYTES
            ),
            "base_without_client_compiler_artifacts_bytes": (
                setup_without_client_compiler_artifacts
            ),
            "public_parameter_preregistered_allocation_bytes": (
                C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES
            ),
            "projected_setup_bytes": projected_setup_bytes,
            "strict_setup_max_bytes": C61_SETUP_MAX_BYTES,
            "headroom_bytes": C61_SETUP_MAX_BYTES - projected_setup_bytes,
            "projected_setup_plus_first_certificate_bytes": (
                projected_first_response_bytes
            ),
            "allocation_screen_pass": projected_setup_bytes <= C61_SETUP_MAX_BYTES,
            "contingency": (
                "plan/map removal requires the two-sketch runtime-stream seam; "
                "no setup credit before formal and Rust differentials"
            ),
            "credit": False,
        },
        "verifier_operation_decomposition": {
            "terminal_scalar_outputs_per_repetition": 8 + 16 + 8,
            "proof_repetitions": c6.RESIDUAL_PROOF_REPETITIONS,
            "terminal_scalar_outputs_total": (
                c6.RESIDUAL_PROOF_REPETITIONS * (8 + 16 + 8)
            ),
            "atomic_outputs_per_repetition": c6.RESIDUAL_ATOMIC_OUTPUTS_PER_REPETITION,
            "atomic_outputs_total": c6.RESIDUAL_ATOMIC_OUTPUTS_TOTAL,
            "coefficient_writes_per_repetition": compiler_families,
            "coefficient_writes_total": c6.RESIDUAL_COEFFICIENT_WRITES_TOTAL,
            "runtime_stream": {
                "raw_public_values": C6_VERIFIER_RAW_PUBLIC_VALUES,
                "raw_scalar_values": C6_VERIFIER_RAW_SCALAR_VALUES,
                "raw_values_total": (
                    runtime_stream_values
                ),
                "canonical_public_values": C6_VERIFIER_CANONICAL_PUBLIC_VALUES,
                "canonical_scalar_values": C6_VERIFIER_CANONICAL_SCALAR_VALUES,
                "sketch_repetitions": C61_RUNTIME_SKETCH_REPETITIONS,
                "polynomial_fingerprint_error_numerator": (
                    runtime_sketch_error.numerator
                ),
                "polynomial_fingerprint_error_denominator": (
                    runtime_sketch_error.denominator
                ),
                "polynomial_fingerprint_soundness_bits": str(
                    runtime_sketch_bits
                ),
                "secrecy_rule": (
                    "Public/Scale-scalar values only; Source/key/tag/Delta taint is fatal"
                ),
            },
            "historical_seconds": {
                "t1_four_thread_verify_response": str(
                    T1_FOUR_THREAD_VERIFY_RESPONSE_SECONDS
                ),
                "t1_four_thread_pcs_verify": str(T1_FOUR_THREAD_PCS_VERIFY_SECONDS),
                "t1_four_thread_verifier_accounted": str(
                    T1_FOUR_THREAD_VERIFIER_ACCOUNTED_SECONDS
                ),
                "c6_local_t4q2_response_plus_residual": str(
                    C6_LOCAL_SCALED_RESPONSE_RESIDUAL_VERIFY_SECONDS
                ),
                "c6_local_production_geometry_terminal_replay": str(
                    C6_LOCAL_PRODUCTION_GEOMETRY_TERMINAL_VERIFY_SECONDS
                ),
            },
            "interpretation": (
                "The 14.002651-s term contains the two public semantic compiler "
                "terminal replays; C6RSC4 must attest their 64 Fp2 outputs. "
                "The client retains the DV transcript/MAC checks and streams "
                "two runtime sketches instead of retaining/replaying the plan."
            ),
        },
        "provider_time_screen": {
            "existing_c6_kernel_floor_seconds": str(
                C6_EXISTING_A100_KERNEL_FLOOR_SECONDS
            ),
            "unallocated_seconds_to_strict_15_second_gate": str(
                C61_PROVIDER_EXCLUSIVE_SECONDS - C6_EXISTING_A100_KERNEL_FLOOR_SECONDS
            ),
            "selected_candidate_projected_seconds": str(
                native_provider_roof_seconds
            ),
            "selected_candidate_headroom_seconds": str(
                C61_PROVIDER_EXCLUSIVE_SECONDS - native_provider_roof_seconds
            ),
            "compiler_timing_credit": False,
            "public_argument_timing_credit": False,
            "required_rule": (
                "C6RSC4 consumes the already-emitted provider atomic stream; a "
                "fourth provider semantic replay is forbidden"
            ),
            "verdict": "PRECODE_SCREEN_PASS__NO_BENCHMARK_CREDIT",
        },
        "verifier_time_screen": {
            "strict_gate_seconds": str(C61_VERIFIER_EXCLUSIVE_SECONDS),
            "required_components": [
                "base DV transcript and MAC verification",
                "two streaming runtime sketches",
                "C6PA1/C6RSC4 public verification",
                "unchanged compact Delta/link/cache closure",
            ],
            "selected_candidate_projected_seconds": str(
                native_verifier_roof_seconds
            ),
            "selected_candidate_headroom_seconds": str(
                C61_VERIFIER_EXCLUSIVE_SECONDS - native_verifier_roof_seconds
            ),
            "verdict": "PRECODE_SCREEN_PASS__NO_AVX2_TIMING_CREDIT",
        },
    }

    # Immutable reconciliation assertions.
    assert old_pcs_q120 == 26_037_920
    assert old_pcs_q121 == 26_254_888
    assert old_pcs_public_eligible == 26_253_192
    assert old_pcs_delta_dependent == 1_696
    assert retained_non_pcs == 2_921_744
    assert C6_RETAINED_Q121_BYTES == retained_non_pcs + old_pcs_q121
    assert wrapper_delta_bytes == 39_712
    assert public_eligible_raw_bytes == 30_132_658
    assert delta_dependent_bytes == 2_963_152
    assert state_and_framing_bytes == 1_181
    assert non_public_remainder_bytes == 2_964_333
    assert (
        public_eligible_raw_bytes
        + delta_dependent_bytes
        + state_and_framing_bytes
        == C6_CERTIFICATE_BYTES
    )
    assert active_fixed_remainder_bytes == 6_842_103
    assert active_public_argument_absolute_max_bytes == 15_157_896
    assert active_projected_certificate_bytes == 18_842_103
    assert C61_CERTIFICATE_MAX_BYTES - active_projected_certificate_bytes == 3_157_896
    assert absorb_wrapper_fixed_remainder_bytes == 2_962_637
    assert projected_setup_bytes == 84_743_367
    assert C61_SETUP_MAX_BYTES - projected_setup_bytes == 65_256_632
    assert projected_first_response_bytes == 103_585_470
    assert sum(compiler_families.values()) == c6.RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION
    assert c6.RESIDUAL_COEFFICIENT_WRITES_TOTAL == 225_997_412
    assert c6.RESIDUAL_ATOMIC_OUTPUTS_TOTAL == 94_868_704
    assert runtime_stream_values == 10_830_342
    assert runtime_sketch_bits > Decimal("246")
    assert C61_EQ_CHALLENGE_FP2_ELEMENTS == 234
    assert C61_EQ_CHALLENGE_CLIENT_BYTES == 3_744
    assert (
        C61_SOURCE_NODE_COUNT
        + C61_PUBLIC_NODE_COUNT
        + C61_STRUCTURAL_ZERO_NODE_COUNT
        + C61_ADD_NODE_COUNT
        + C61_SUB_NODE_COUNT
        + C61_SCALE_NODE_COUNT
        == C61_CANONICAL_NODE_COUNT
    )
    assert d28_opening_upper_bytes == 424_688
    assert d27_opening_upper_bytes == 409_008
    assert d28_known_chain_bytes == 1_117_104
    assert d27_known_chain_bytes == 1_101_424
    assert C61_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES == 9_500_000
    assert native_projected_certificate_bytes == 16_342_103
    assert C61_CERTIFICATE_MAX_BYTES - native_projected_certificate_bytes == 5_657_896
    assert native_projected_first_response_bytes == 101_085_470
    assert provider_state_elements == 126_212_866
    assert provider_state_bytes == 2_019_405_856
    assert C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES == 2_293_198_848
    assert C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES - provider_state_bytes == 273_792_992
    assert c6.soundness_bits(equality_schedule_error) > Decimal("120.12")
    assert c6.soundness_bits(candidate_complete_error) > Decimal("119.66")
    assert c6.soundness_bits(candidate_session_error) > Decimal("115.58")
    assert native_compiler_symbols == 4_902_003_776
    assert native_compiler_pcs_transform_bytes == 10_737_418_240
    assert Decimal("14.50") < native_provider_roof_seconds < Decimal("14.51")
    assert native_verifier_roof_seconds == Decimal("4.565672390")
    assert C61_VERIFIER_ADDITIONAL_MEMORY_ALLOCATION_BYTES == 512_000_000
    assert native_projected_certificate_bytes < C61_CERTIFICATE_EXCLUSIVE_BYTES
    assert projected_setup_bytes < C61_SETUP_EXCLUSIVE_BYTES
    assert native_provider_roof_seconds < C61_PROVIDER_EXCLUSIVE_SECONDS
    assert native_verifier_roof_seconds < C61_VERIFIER_EXCLUSIVE_SECONDS
    assert report["credit"] == {
        "proof_size": False,
        "setup": False,
        "provider_time": False,
        "verifier_time": False,
        "hardware": False,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    certificate = report["existing_certificate"]
    active = report["active_wire_screen"]
    setup = report["setup_screen"]
    operations = report["verifier_operation_decomposition"]
    provider = report["provider_time_screen"]
    native = report["selected_native_candidate"]
    print(f"C6.1 pre-code profile:        {report['profile']}")
    print(f"verdict:                     {report['verdict']}")
    print(f"current certificate:         {certificate['bytes']:,} B")
    print(
        "public-eligible raw bytes:   "
        f"{certificate['partition']['public_eligible_raw_bytes']:,} B"
    )
    print(
        "non-public remainder:        "
        f"{certificate['partition']['non_public_remainder_bytes']:,} B"
    )
    print(
        "active fixed remainder:      "
        f"{active['fixed_remainder_bytes']:,} B"
    )
    print(
        "C6PA1 allocation:            "
        f"{active['public_argument_preregistered_allocation_bytes']:,} B"
    )
    print(
        "projected certificate:       "
        f"{active['projected_certificate_bytes']:,} B "
        f"(allocation only; credit={active['credit']})"
    )
    print(
        "projected setup:             "
        f"{setup['projected_setup_bytes']:,} B "
        f"(allocation only; credit={setup['credit']})"
    )
    print(
        "compiler writes total:       "
        f"{operations['coefficient_writes_total']:,}"
    )
    print(
        "runtime values / sketches:   "
        f"{operations['runtime_stream']['raw_values_total']:,} / "
        f"{operations['runtime_stream']['sketch_repetitions']}"
    )
    print(
        "A100 unallocated to 15 s:    "
        f"{Decimal(provider['unallocated_seconds_to_strict_15_second_gate']):.6f} s "
        "(no compiler/public-proof credit)"
    )
    print("-- selected native C6.1 candidate (pre-code only) --")
    print(
        "candidate certificate cap:   "
        f"{native['wire_screen']['projected_certificate_ceiling_bytes']:,} B"
    )
    print(
        "candidate first exchange:    "
        f"{native['wire_screen']['projected_setup_plus_first_certificate_bytes']:,} B"
    )
    print(
        "candidate provider roof:     "
        f"{Decimal(native['provider_time_roofline']['projected_total_seconds']):.6f} s"
    )
    print(
        "candidate verifier roof:     "
        f"{Decimal(native['verifier_time_roofline']['projected_total_seconds']):.6f} s"
    )
    print(
        "candidate soundness:         "
        f"{Decimal(native['soundness']['complete_per_certificate']['bits']):.3f} bits/cert"
    )
    print(
        "ephemeral provider state:    "
        f"{native['ephemeral_provider_state_screen']['bytes']:,} B"
    )
    print("all candidate values above:  screen only; credit=False")


if __name__ == "__main__":
    main()

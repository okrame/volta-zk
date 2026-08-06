#!/usr/bin/env python3
"""Exact C6.1 decomposition and conservative native-candidate roofline.

This report deliberately has two different verdict scopes:

* exact reconciliation of the existing C6 certificate, residual-compiler
  operation census and C6TFR1 coefficient-event domain;
* the preregistered C6.1 native-candidate screen, the feature-gated legacy
  clear-target C6WIR1 PCS/codec reference, and the C6AWP1 claimless
  authenticated-target codec differential.  C6TFR1 now specifies the exact
  terminal-functional relation.  Direct-point integration is complete.  The
  C6TFA1 preregistration factors the exact event fold into two D25 reverse
  lanes plus an eight-family direct reducer.  Its scaled differential is now
  exact, and the direct interval reducer has an executable production-shape
  census.  The terminal projection and exact materialized D25 lane references
  are green.  The scaled public-only verifier now connects the seven blind
  rational trees, joint degree-8 reduction, twelve arithmetic response targets,
  four challenge-dependent terminal-fold response targets, three public plan
  targets and one QuickSilver/ZeroOpen closure to the shared
  Dn/D(n-1) WHIR flow.  The selected monolithic P3 prover-data memory is
  censused exactly at D28/D27 and the persisted/CUDA compiler executor is
  locally implemented.  Production model/embedding chains, a role-separated
  wire verifier and the full-chain benchmark remain absent, so this is not
  final proof or timing credit.

No projected ceiling or analytic roofline is proof-size, setup, prover-time,
verifier-time or hardware credit.  The implemented PCS codec receives only
its explicitly named CPU-reference credit.
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

# C6NBR2 design screen.  The generic correction functional is folded into
# the existing two-repetition C6LNK2 schedule.  It adds one public claim but
# no slot, round, opening, frame or correlation.  GPT-2 is only the first
# profile instance; other profiles substitute their own cohort count.
C61_NBR2_NATIVE_TARGET_COHORTS = 2
C61_NBR2_LINK_SLOT_CLAIMS = 72
C61_NBR2_LINK_RELATIONS = C61_NBR2_LINK_SLOT_CLAIMS + 1
C61_NBR2_LINK_ROUNDS = 25
C61_NBR2_LINK_ROOTS_PER_REPETITION = (
    C61_NBR2_LINK_RELATIONS + 3 * C61_NBR2_LINK_ROUNDS + 2
)
C61_NBR2_COEFFICIENT_LOG2 = 23
C61_NBR2_COEFFICIENT_ELEMENTS = 2**C61_NBR2_COEFFICIENT_LOG2
C61_NBR2_COEFFICIENT_OWNER_BYTES = C61_NBR2_COEFFICIENT_ELEMENTS * c6.FP2_BYTES
C61_NBR2_SOURCE_PREFIX_BYTES = 4_975_525 * c6.FP2_BYTES
# Per repetition: one padded-owner write, less than two full-owner reads and
# less than one full-owner successor write across all folds.
C61_NBR2_TWO_REPETITION_TRAFFIC_BYTES = (
    2 * 4 * C61_NBR2_COEFFICIENT_OWNER_BYTES
)
C61_NBR2_TWO_REPETITION_FP2_MULS = (
    2 * 4 * C61_NBR2_COEFFICIENT_ELEMENTS
)

# Exact existing setup components.
C6_PAIRED_PCG_BYTES = 2 * 38_371_465
C6_SETUP_MANIFEST_BYTES = 437
C6_CANONICAL_PLAN_BYTES = 63_994_751
C6_VERIFIER_INSTANCE_MAP_BYTES = 5_320_386
C6_EXISTING_SETUP_BYTES = 146_058_504
C61_CLIENT_PARAMETER_BYTES_AFTER_RETAINED_MAP = (
    C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES - C6_VERIFIER_INSTANCE_MAP_BYTES
)
C61_TERMINAL_METADATA_HEADER_BYTES = 188
C61_TERMINAL_METADATA_TRAILER_BYTES = 32
C61_TERMINAL_METADATA_PAYLOAD_BYTES = (
    12 * c6.T1_PRODUCT_CLOSURE_COUNT
    + 12 * c6.T1_PRODUCT_TRIPLE_COUNT
    + 4 * c6.T1_ZERO_ROOT_COUNT
)
C61_TERMINAL_METADATA_BYTES = (
    C61_TERMINAL_METADATA_HEADER_BYTES
    + C61_TERMINAL_METADATA_PAYLOAD_BYTES
    + C61_TERMINAL_METADATA_TRAILER_BYTES
)
C61_CLIENT_PARAMETER_BYTES_AFTER_TERMINAL_METADATA = (
    C61_CLIENT_PARAMETER_BYTES_AFTER_RETAINED_MAP - C61_TERMINAL_METADATA_BYTES
)

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

# C6RSC4-v5 challenge compression.  Every former pseudo-random scalar stream
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
C61_OUTPUT_BATCH_CHALLENGE_FP2_ELEMENTS = 1
C61_RUNTIME_POINT_CHALLENGE_FP2_ELEMENTS = (
    C61_RUNTIME_SKETCH_REPETITIONS * 24
)
C61_KNOWN_PRE_NATIVE_CHALLENGE_FP2_ELEMENTS = (
    C61_EQ_CHALLENGE_FP2_ELEMENTS
    + C61_OUTPUT_BATCH_CHALLENGE_FP2_ELEMENTS
    + C61_RUNTIME_POINT_CHALLENGE_FP2_ELEMENTS
)
C61_KNOWN_PRE_NATIVE_CHALLENGE_CLIENT_BYTES = (
    C61_KNOWN_PRE_NATIVE_CHALLENGE_FP2_ELEMENTS * c6.FP2_BYTES
)

# Exact installed sparse-adjoint census.  The operation-plan rows are
# provider-global preprocessing; only the root/version enter client setup.
C61_CANONICAL_NODE_COUNT = 28_845_631
C61_SOURCE_NODE_COUNT = 4_970_850
C61_SCHEDULED_SOURCE_COUNT = 4_975_525
C61_PUBLIC_NODE_COUNT = 1_436
C61_STRUCTURAL_ZERO_NODE_COUNT = 1
C61_ADD_NODE_COUNT = 12_961_295
C61_SUB_NODE_COUNT = 83_197
C61_SCALE_NODE_COUNT = 10_828_852
C61_SPARSE_OPERAND_COUNT = 36_917_836
C61_NODE_LOG2 = 25
C61_RUNTIME_LOG2 = 24
C61_TERMINAL_OUTPUTS = 64
C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2 = 28
C61_TERMINAL_FUNCTIONAL_WRITES = c6.RESIDUAL_COEFFICIENT_WRITES_TOTAL
C61_FOLDED_DIRECT_INTERVAL_REDUCTIONS = 56
C61_FOLDED_DIRECT_INTERVAL_DYADIC_BLOCKS = 510
C61_FOLDED_DIRECT_INTERVAL_TRANSITION_ROWS = 30_072
C61_FOLDED_DIRECT_INTERVAL_MAX_CARRY_STATES = 3
C61_FOLDED_DIRECT_EXPLICIT_TERMS = 1_513_162
C61_FOLDED_DIRECT_TOTAL_ROWS_AND_TERMS = (
    C61_FOLDED_DIRECT_INTERVAL_TRANSITION_ROWS
    + C61_FOLDED_DIRECT_EXPLICIT_TERMS
)

# C6SPR2-v1 retains the three-column provider-global plan oracle and packs
# lanes, boundary/runtime and the node-aligned mu witness into four D25 blocks
# under one semantic response oracle, now physicalized as one D28 base-field
# root.  Fixing that root before the rational
# challenges closes C6SPR1's challenge-adaptive-mu gap.  No edge-domain
# witness or inverse column is committed.
C61_SPARSE_RATIONAL_PLAN_COLUMNS = 3
C61_SPARSE_RATIONAL_PLAN_DOMAIN_LOG2 = 27
C61_SPARSE_RATIONAL_RESPONSE_DOMAIN_EQUIVALENT_D25_VECTORS = 4
C61_SPARSE_RATIONAL_SUBCHECKS = 7
C61_SPARSE_RATIONAL_CLIENT_PARAMETER_FRAME_BYTES = 512
# The arbitrary-Fp2 response is committed as c0||c1 in one physical D28
# base-field polynomial.  This is byte-identical to the former D27 Fp2
# response bundle but no longer relies on an ineligible extension-valued
# initial polynomial.
C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_DOMAIN_LOG2 = 28
C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BASE_ELEMENTS = (
    2**C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_DOMAIN_LOG2
)
C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES = (
    C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BASE_ELEMENTS * 8
)
C61_SPARSE_RATIONAL_RECURRENCE_ACTIVE_ROWS = (
    C61_CANONICAL_NODE_COUNT + C61_SPARSE_OPERAND_COUNT
)

# Native transparent candidate.  Each model/embedding/compiler component uses
# two independent no-grinding chains.  C6AWH1 configures 75 public PCS bits so
# adding one Fp2 MAC event remains strictly below a 74-bit authenticated-chain
# allocation.
# The 1.5-MB chain ceiling is an explicit strict codec ceiling; the underlying
# maximum non-deduplicated Merkle openings are recomputed below.
C61_NATIVE_PUBLIC_PCS_BITS = 75
C61_NATIVE_AUTHENTICATED_CHAIN_BITS = 74
C61_NATIVE_CHAINS_PER_COMPONENT = 2
C61_NATIVE_COMPONENTS = 3
C61_NATIVE_MAX_ORDERED_OPENINGS = 128
C61_NATIVE_MODEL_OPENINGS = 96
C61_NATIVE_EMBEDDING_OPENINGS = 6
C61_NATIVE_CHAIN_CODEC_MAX_BYTES = 1_500_000
# The compiler chains additionally carry the preregistered multi-oracle
# rational-GKR messages.  Model and embedding retain the old ceiling.
C61_NATIVE_COMPILER_CHAIN_CODEC_MAX_BYTES = 2_500_000
C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES = 500_000
C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES = 356
C61_C6RSC4_ARITHMETIC_FRAME_BYTES = 1_212
C61_PREREGISTERED_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES = (
    2 * C61_NATIVE_CHAINS_PER_COMPONENT * C61_NATIVE_CHAIN_CODEC_MAX_BYTES
    + C61_NATIVE_CHAINS_PER_COMPONENT * C61_NATIVE_COMPILER_CHAIN_CODEC_MAX_BYTES
    + C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES
)

# Exact C6AWH1 structural screens at the pinned Plonky3 HVZK-WHIR revision.
# They raise the upstream public security setting to 75 bits and substitute
# one 16-B designated ZeroOpen tag for the 16-B clear evaluation, so the net
# provider wire change is zero.  The bound maximizes every deduplicated
# binary-Merkle frontier; it is not an average collision model.  The modified
# PCS and C6 relation adapter remain pending, so the registered 1,500,000-B
# full-chain cap remains binding.
C61_P3_REFERENCE_COMMIT = "66e290615de1858f2f2f6a804158064c406cda1c"
C61_NATIVE_MASK_LOG_INV_RATE = 1
C61_NATIVE_MASK_QUERIES = 187
C61_NATIVE_D28_ROUNDS = 11
C61_NATIVE_D27_ROUNDS = 10
C61_NATIVE_MAX_OOD_SAMPLES_PER_ROUND = 1
C61_NATIVE_D28_OOD_PRIVACY_BAD_EVENT_NUMERATOR = 11
C61_NATIVE_D27_OOD_PRIVACY_BAD_EVENT_NUMERATOR = 10
C61_NATIVE_D28_PCS_STRICT_MAX_BYTES = 1_172_652
C61_NATIVE_D27_PCS_STRICT_MAX_BYTES = 1_085_464
# The generic P3 prover retains the Boolean message, the rate-1/2 initial
# codeword and every binary-Merkle digest layer.  This is total implementation
# memory, not the narrower coefficient-plus-witness component state below.
C61_MONOLITHIC_BASE_FIELD_BYTES = 8
C61_MONOLITHIC_D28_MESSAGE_BYTES = (1 << 28) * C61_MONOLITHIC_BASE_FIELD_BYTES
C61_MONOLITHIC_D28_ENCODED_BYTES = (1 << 29) * C61_MONOLITHIC_BASE_FIELD_BYTES
C61_MONOLITHIC_D28_MERKLE_BYTES = ((1 << 29) - 1) * 32
C61_MONOLITHIC_D28_RETAINED_LOWER_BOUND_BYTES = (
    C61_MONOLITHIC_D28_MESSAGE_BYTES
    + C61_MONOLITHIC_D28_ENCODED_BYTES
    + C61_MONOLITHIC_D28_MERKLE_BYTES
)
C61_MONOLITHIC_D27_MESSAGE_BYTES = (1 << 27) * C61_MONOLITHIC_BASE_FIELD_BYTES
C61_MONOLITHIC_D27_ENCODED_BYTES = (1 << 28) * C61_MONOLITHIC_BASE_FIELD_BYTES
C61_MONOLITHIC_D27_MERKLE_BYTES = ((1 << 28) - 1) * 32
C61_MONOLITHIC_D27_RETAINED_LOWER_BOUND_BYTES = (
    C61_MONOLITHIC_D27_MESSAGE_BYTES
    + C61_MONOLITHIC_D27_ENCODED_BYTES
    + C61_MONOLITHIC_D27_MERKLE_BYTES
)
C61_MONOLITHIC_CONCURRENT_RETAINED_LOWER_BOUND_BYTES = (
    C61_MONOLITHIC_D28_RETAINED_LOWER_BOUND_BYTES
    + C61_MONOLITHIC_D27_RETAINED_LOWER_BOUND_BYTES
)
# Immutable clear-target Section 0.11 diagnostic; it is not a C6AWH1 size.
C61_NATIVE_CLEAR_TARGET_D14_DIAGNOSTIC_BYTES = 375_584
# Exact strict C6AWP1 D14 claimless codec differential.  Its WHIR payload
# accounting excludes only the final 16-B C6AWH1 tag; the complete strict
# provider-to-client artifact includes it.
C61_NATIVE_CLAIMLESS_D14_DIAGNOSTIC_BYTES = 378_496
C61_NATIVE_CLAIMLESS_D14_WHIR_PAYLOAD_BYTES = 378_480
C61_NATIVE_CLAIMLESS_D14_PROVIDER_SEMANTIC_BYTES = 52_608
C61_NATIVE_CLAIMLESS_D14_PROVIDER_MESSAGES = 26
C61_NATIVE_CLAIMLESS_D14_CLIENT_FP_CHALLENGES = 52
C61_NATIVE_CLAIMLESS_D14_CLIENT_QUERY_CANDIDATES = 2_536
C61_NATIVE_CLAIMLESS_D14_CLIENT_CHALLENGE_BYTES = 10_560
C61_SHARED_MULTI_ORACLE_HEADER_BYTES = 16
C61_SHARED_MULTI_ORACLE_D14_DIAGNOSTIC_BYTES = 677_532
C61_SHARED_MULTI_ORACLE_D14_STRICT_MAX_BYTES = 770_748
C61_SHARED_MULTI_ORACLE_D14_PROVIDER_SEMANTIC_BYTES = 94_752
C61_SHARED_MULTI_ORACLE_D14_PROVIDER_MESSAGES = 36
C61_SHARED_MULTI_ORACLE_D14_CLIENT_FP_CHALLENGES = 75
C61_SHARED_MULTI_ORACLE_D14_CLIENT_QUERY_CANDIDATES = 4_193
C61_SHARED_MULTI_ORACLE_D14_CLIENT_CHALLENGE_BYTES = 17_372
C61_SHARED_MULTI_ORACLE_D14_ARITHMETIC_BYTES = 5_212
C61_SHARED_MULTI_ORACLE_D14_TOTAL_PROVIDER_BYTES = 682_744
C61_SHARED_MULTI_ORACLE_D14_TRANSCRIPT_BYTES = 682_652
C61_SPARSE_RATIONAL_ARITHMETIC_RESPONSE_OPENINGS = 12
C61_EXACT_TERMINAL_FOLD_PHYSICAL_RESPONSE_OPENINGS = 4
C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_OPENINGS = (
    C61_SPARSE_RATIONAL_ARITHMETIC_RESPONSE_OPENINGS
    + C61_EXACT_TERMINAL_FOLD_PHYSICAL_RESPONSE_OPENINGS
)
C61_SPARSE_RATIONAL_PLAN_OPENINGS = 3
C61_SPARSE_RATIONAL_TOTAL_OPENINGS = (
    C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_OPENINGS
    + C61_SPARSE_RATIONAL_PLAN_OPENINGS
)
C61_SPARSE_RATIONAL_RESPONSE_TARGET_SUB_CORRELATIONS = 24
C61_SPARSE_RATIONAL_RESPONSE_TARGET_CORRECTION_BYTES = 192
C61_SPARSE_RATIONAL_PRODUCTION_DEPTHS = (25, 25, 25, 25, 24, 23, 25)
C61_SPARSE_RATIONAL_PRODUCTION_DEPTH_SUM = sum(
    C61_SPARSE_RATIONAL_PRODUCTION_DEPTHS
)
C61_SPARSE_RATIONAL_PRODUCTION_GKR_BYTES = 84_640
C61_SPARSE_RATIONAL_PRODUCTION_JOINT_BYTES = 3_248
C61_SPARSE_RATIONAL_PRODUCTION_ARITHMETIC_BYTES = 88_220
# Strict C6CPX2 outer frame: 148-B typed header plus a 32-B checksum.  The
# four physical plan-fold values are required by the compact verifier; the
# arithmetic and shared-WHIR payloads are counted separately below.
C61_PRODUCTION_COMPILER_CHAIN_OUTER_BYTES = 180
C61_SPARSE_RATIONAL_PRODUCTION_PRODUCT_TRIPLES = 531
C61_SPARSE_RATIONAL_PRODUCTION_ZERO_ROWS = 179
C61_SPARSE_RATIONAL_PRODUCTION_GKR_FULL_CORRELATIONS = 5_290
C61_SPARSE_RATIONAL_PRODUCTION_JOINT_FULL_CORRELATIONS = 200
C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE = 5_493
C61_PRIVATE_ENTROPY_D14_CHALLENGES = 2_588
C61_PRIVATE_ENTROPY_D14_CHECKPOINT_FRONTIER = 1_294
C61_PRIVATE_ENTROPY_D14_CHECKPOINT_BYTES = 73_360
C61_PRIVATE_ENTROPY_D14_DURABLE_JOURNAL_BYTES = 208_204
C61_PRIVATE_ENTROPY_D14_DURABLE_RECORDS = 2_590
C61_NATIVE_CLAIMLESS_D14_BLAKE3 = (
    "9dbaa66336f8833b0a0e3a32f7023f5c25f2166e6e8431244a06b41d707958bb"
)

# C6AWH1 draws one mask for model/embedding/compiler on each MAC tape.  These
# slots come from the already registered attempt reserve and do not enlarge
# the raw-tape or paired-PCG setup allocation.
C6_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE = 622
C6_FULL_CORRELATION_RESERVE_PER_TAPE = 39_116
# Model and embedding retain one WHIR mask each.  The compiler count below
# includes its WHIR mask together with every arithmetic correlation.
C61_NONCOMPILER_AUTHENTICATED_TARGET_MASKS_PER_TAPE = 2
C61_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE = (
    C6_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
    + C61_NONCOMPILER_AUTHENTICATED_TARGET_MASKS_PER_TAPE
    + C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
)
C61_FULL_CORRELATION_HEADROOM_PER_TAPE = (
    C6_FULL_CORRELATION_RESERVE_PER_TAPE
    - C61_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
)
C61_COMPILER_RAW_CORRELATION_EQUIVALENTS_PER_TAPE = (
    2 * C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
    + C61_SPARSE_RATIONAL_RESPONSE_TARGET_SUB_CORRELATIONS
)
C61_RAW_CORRELATION_RESERVE_EQUIVALENTS_PER_TAPE = (
    2 * C6_FULL_CORRELATION_RESERVE_PER_TAPE
)

# Conservative analytic-time charges.  They are deliberately wider than the
# diagnostic prototype and count every transform class sequentially.
C61_OLD_MODEL_PCS_OPEN_SECONDS = Decimal("0.298579063")
C61_NATIVE_MODEL_TRANSFORM_BYTES = 48_337_256_448
C61_NATIVE_MODEL_LINEAR_SECONDS = Decimal("0.600")
C61_NATIVE_COMPILER_EQUIVALENT_PASSES = 64
C61_NATIVE_COMPILER_PCS_VECTORS = (
    C61_SPARSE_RATIONAL_RESPONSE_DOMAIN_EQUIVALENT_D25_VECTORS
)
C61_NATIVE_COMPILER_PCS_TRANSFORM_EQUIVALENTS = 5
C61_NATIVE_INTEGRATION_FACTOR = Decimal("1.20")
C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS = Decimal("0.550")
C61_VERIFIER_PER_COMPILER_CHAIN_SECONDS = Decimal("0.750")
C61_VERIFIER_PUBLIC_ARITHMETIC_SECONDS = Decimal("0.500")
C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES = 4 * 573_299_712
C61_TERMINAL_FUNCTIONAL_TRACE_FP2_BYTES = (
    2**C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2 * c6.FP2_BYTES
)
C61_TERMINAL_FUNCTIONAL_TRACE_BASE_LIMB_BYTES = (
    2**C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2 * 8
)
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

    setup_without_client_plan_and_parameters = (
        C6_PAIRED_PCG_BYTES + C6_SETUP_MANIFEST_BYTES
    )
    projected_setup_bytes = (
        setup_without_client_plan_and_parameters
        + C6_CANONICAL_PLAN_BYTES
        + C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES
    )
    projected_first_response_bytes = (
        projected_setup_bytes + active_projected_certificate_bytes
    )

    raw_verifier_runtime_values = (
        C6_VERIFIER_RAW_PUBLIC_VALUES + C6_VERIFIER_RAW_SCALAR_VALUES
    )
    canonical_runtime_values = (
        C6_VERIFIER_CANONICAL_PUBLIC_VALUES + C6_VERIFIER_CANONICAL_SCALAR_VALUES
    )
    runtime_sketch_error = Fraction(
        C61_RUNTIME_LOG2**C61_RUNTIME_SKETCH_REPETITIONS,
        c6.FP2_CARDINALITY**C61_RUNTIME_SKETCH_REPETITIONS,
    )
    runtime_sketch_bits = c6.soundness_bits(runtime_sketch_error)

    # C6RSC4-v5 statistical composition.  The schedule/output/functional
    # relation events are sampled after the relevant roots and claims are fixed.
    # The three transparent components each use two independent authenticated chains,
    # each strictly below the registered 74-bit error allocation.
    equality_schedule_error = Fraction(
        C61_EQ_CHALLENGE_FP2_ELEMENTS, c6.FP2_CARDINALITY
    )
    output_batch_error = Fraction(
        C61_TERMINAL_OUTPUTS - 1, c6.FP2_CARDINALITY
    )
    lane_batch_error = Fraction(1, c6.FP2_CARDINALITY)
    sparse_recurrence_rational_error = Fraction(
        C61_CANONICAL_NODE_COUNT - 1, c6.FP2_CARDINALITY
    )
    runtime_gather_rational_error = Fraction(
        C61_SCALE_NODE_COUNT - 1, c6.FP2_CARDINALITY
    )
    source_gather_rational_error = Fraction(
        C61_SCHEDULED_SOURCE_COUNT - 1, c6.FP2_CARDINALITY
    )
    terminal_functional_relation_error = (
        lane_batch_error
        + sparse_recurrence_rational_error
        + runtime_gather_rational_error
        + source_gather_rational_error
    )
    # Model/embedding retain the registered at-most-128 ordered batch.  The
    # compiler has exactly nineteen physical claims, folds 179 arithmetic zero
    # rows into the existing terminal tag, and closes all 531 products in one
    # scalar-power QuickSilver batch.  M8 contributes (T+2)/|Fp2|.  Each of
    # the two component chains has independent transcript/MAC randomness.
    ordered_opening_batch_error = Fraction(
        C61_NATIVE_MAX_ORDERED_OPENINGS - 1, c6.FP2_CARDINALITY
    )
    authenticated_target_chain_error = (
        Fraction(1, 2**C61_NATIVE_PUBLIC_PCS_BITS)
        + ordered_opening_batch_error
        + Fraction(1, c6.FP2_CARDINALITY)
    )
    compiler_ordered_opening_batch_error = Fraction(
        C61_SPARSE_RATIONAL_TOTAL_OPENINGS - 1,
        c6.FP2_CARDINALITY,
    )
    compiler_zero_row_rlc_error = Fraction(
        C61_SPARSE_RATIONAL_PRODUCTION_ZERO_ROWS,
        c6.FP2_CARDINALITY,
    )
    compiler_product_batch_error = Fraction(
        C61_SPARSE_RATIONAL_PRODUCTION_PRODUCT_TRIPLES + 2,
        c6.FP2_CARDINALITY,
    )
    compiler_authenticated_chain_error = (
        Fraction(1, 2**C61_NATIVE_PUBLIC_PCS_BITS)
        + compiler_ordered_opening_batch_error
        + compiler_zero_row_rlc_error
        + compiler_product_batch_error
        + Fraction(1, c6.FP2_CARDINALITY)
    )
    native_backend_error = (
        2 * authenticated_target_chain_error**C61_NATIVE_CHAINS_PER_COMPONENT
        + compiler_authenticated_chain_error
        ** C61_NATIVE_CHAINS_PER_COMPONENT
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
        + terminal_functional_relation_error
        + native_backend_error
        + existing_wrapper_error
    )
    # C6NBR1 replaces the secondary native tails by one post-body cohort RLC
    # and one joint ZeroOpen.  This conservative screen does not subtract the
    # old per-chain tails, so it cannot undercharge the amendment.  C6NBR2's
    # 150-root repetition remains inside C6LNK2's frozen 256-root allocation.
    joint_native_bridge_error = Fraction(
        (C61_NBR2_NATIVE_TARGET_COHORTS - 1) + 1,
        c6.FP2_CARDINALITY,
    )
    candidate_complete_error += joint_native_bridge_error
    candidate_session_error = 17 * candidate_complete_error

    # Claim privacy is separate from soundness.  Every code-switch round has
    # one OOD challenge and one fresh pad slot, so the only statistical
    # deviation in the pinned HVZK hybrid is rho=0: one event per round over
    # Fp2.  The all-six and 17-certificate rows conservatively pretend every
    # chain has the larger D28 round count.  BLAKE3-Merkle hiding and the
    # production PCG remain explicit computational terms, not folded into
    # these rational statistical bounds.
    d27_claim_privacy_error = Fraction(
        C61_NATIVE_D27_OOD_PRIVACY_BAD_EVENT_NUMERATOR,
        c6.FP2_CARDINALITY,
    )
    d28_claim_privacy_error = Fraction(
        C61_NATIVE_D28_OOD_PRIVACY_BAD_EVENT_NUMERATOR,
        c6.FP2_CARDINALITY,
    )
    six_chain_claim_privacy_error = (
        C61_NATIVE_COMPONENTS
        * C61_NATIVE_CHAINS_PER_COMPONENT
        * d28_claim_privacy_error
    )
    session_claim_privacy_error = 17 * six_chain_claim_privacy_error

    d28_known_chain_bytes = C61_NATIVE_D28_PCS_STRICT_MAX_BYTES
    d27_known_chain_bytes = C61_NATIVE_D27_PCS_STRICT_MAX_BYTES
    compiler_shared_physical_strict_ceiling_bytes = (
        d28_known_chain_bytes
        + d27_known_chain_bytes
        + C61_SHARED_MULTI_ORACLE_HEADER_BYTES
    )
    compiler_complete_chain_ceiling_bytes = (
        compiler_shared_physical_strict_ceiling_bytes
        + C61_SPARSE_RATIONAL_PRODUCTION_ARITHMETIC_BYTES
        + C61_PRODUCTION_COMPILER_CHAIN_OUTER_BYTES
    )
    compiler_chain_slack_after_complete_relation_bytes = (
        C61_NATIVE_COMPILER_CHAIN_CODEC_MAX_BYTES
        - compiler_complete_chain_ceiling_bytes
    )
    exact_native_public_argument_ceiling_bytes = (
        2 * C61_NATIVE_CHAINS_PER_COMPONENT * C61_NATIVE_CHAIN_CODEC_MAX_BYTES
        + C61_NATIVE_CHAINS_PER_COMPONENT * compiler_complete_chain_ceiling_bytes
        + C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
        + C61_C6RSC4_ARITHMETIC_FRAME_BYTES
    )
    native_projected_certificate_bytes = (
        active_fixed_remainder_bytes + exact_native_public_argument_ceiling_bytes
    )
    native_projected_first_response_bytes = (
        projected_setup_bytes + native_projected_certificate_bytes
    )

    # Production scheduling commits and releases the lane/boundary inputs
    # before the largest rational-GKR workspace.  The conservative peak is
    # two active recurrence buffers plus the canonical runtime vector.
    provider_state_elements = (
        2 * C61_SPARSE_RATIONAL_RECURRENCE_ACTIVE_ROWS
        + canonical_runtime_values
    )
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
            + canonical_runtime_values
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
        nbr2_memory_seconds = (
            Decimal(C61_NBR2_TWO_REPETITION_TRAFFIC_BYTES)
            / c6.P7_STREAM_BYTES_PER_SECOND
        )
        nbr2_arithmetic_seconds = (
            Decimal(C61_NBR2_TWO_REPETITION_FP2_MULS)
            / c6.P7_FP2_MULS_PER_SECOND
        )
        nbr2_provider_roof_seconds = max(
            nbr2_memory_seconds,
            nbr2_arithmetic_seconds,
        ) * C61_NATIVE_INTEGRATION_FACTOR
        native_provider_roof_seconds += nbr2_provider_roof_seconds
        native_verifier_roof_seconds = (
            T1_FOUR_THREAD_VERIFIER_ACCOUNTED_SECONDS
            + Decimal(2 * C61_NATIVE_CHAINS_PER_COMPONENT)
            * C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS
            + Decimal(C61_NATIVE_CHAINS_PER_COMPONENT)
            * C61_VERIFIER_PER_COMPILER_CHAIN_SECONDS
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
        "profile": "C6.1-public-compression-reference-v24-nbr2-design",
        "verdict": (
            "C6AWP1_PRIVATE_ENTROPY_REPLAY_DRIVER_GREEN__"
            "DURABLE_CHECKPOINT_ALLOCATOR_GREEN__ORDERED_96_6_MULTI_OPEN_GREEN__"
            "CANONICAL_RUNTIME_SEAM_GREEN__C6TFR1_EXACT_EVENT_RELATION_"
            "LEAN_RUST_DIFFERENTIAL_TYPED_STATEMENTS_GREEN__"
            "DIRECT_MLE_SCHEDULE_AND_FUSED_PRE_BETA_OUTPUTS_GREEN__"
            "C6TFA1_EXACT_EIGHT_FAMILY_DIFFERENTIAL_GREEN__"
            "DIRECT_INTERVAL_REDUCER_GREEN__"
            "TERMINAL_METADATA_AND_EXACT_D25_LANE_REFERENCES_GREEN__"
            "C6SPR1_RATIONAL_GKR_PREREGISTERED__"
            "SCALED_RATIONAL_GKR_DIFFERENTIAL_GREEN__"
            "CHALLENGE_ADAPTIVE_MU_OBSTRUCTION_CLOSED__"
            "PACKED_MULTI_ORACLE_TYPED_BOUNDARY_GREEN__"
            "SHARED_ROUND_CLAIMLESS_BACKEND_GREEN__"
            "EXACT_SPARSE_RELATION_TO_PHYSICAL_SHARED_WHIR_GREEN__"
            "PRODUCTION_D28_D27_MONOLITHIC_MEMORY_CENSUSED__"
            "PRODUCTION_NATIVE_AND_COMPACT_WIRE_BOUNDARIES_GREEN__"
            "EXACT_T1_OWNER_EXPORT_REQUIRED__"
            "C6NBR2_JOINT_CORRECTION_INNER_PRODUCT_DESIGN_SCREEN_GREEN__"
            "C6NBR2_VERIFIER_MARGINAL_MEASUREMENT_REQUIRED__"
            "NO_FULL_CHAIN_OR_BENCHMARK_CREDIT"
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
            "name": "C6PA1-native-HVZK-plus-C6RSC4-v5",
            "status": (
                "C6AWP1_PRIVATE_ENTROPY_REPLAY_DRIVER_GREEN__"
                "DURABLE_CHECKPOINT_ALLOCATOR_GREEN__ORDERED_96_6_MULTI_OPEN_GREEN__"
                "CANONICAL_RUNTIME_SEAM_GREEN__C6TFR1_EXACT_EVENT_RELATION_"
                "LEAN_RUST_DIFFERENTIAL_TYPED_STATEMENTS_GREEN__"
                "DIRECT_MLE_SCHEDULE_AND_FUSED_PRE_BETA_OUTPUTS_GREEN__"
                "C6TFA1_EXACT_EIGHT_FAMILY_DIFFERENTIAL_GREEN__"
                "DIRECT_INTERVAL_REDUCER_GREEN__"
                "TERMINAL_METADATA_AND_EXACT_D25_LANE_REFERENCES_GREEN__"
                "C6SPR1_RATIONAL_GKR_PREREGISTERED__"
                "SCALED_RATIONAL_GKR_DIFFERENTIAL_GREEN__"
                "CHALLENGE_ADAPTIVE_MU_OBSTRUCTION_CLOSED__"
                "PACKED_MULTI_ORACLE_TYPED_BOUNDARY_GREEN__"
                "SHARED_ROUND_CLAIMLESS_BACKEND_GREEN__"
                "EXACT_SPARSE_RELATION_TO_PHYSICAL_SHARED_WHIR_GREEN__"
                "PRODUCTION_D28_D27_MONOLITHIC_MEMORY_CENSUSED__"
                "PRODUCTION_NATIVE_COMPONENTS_AND_WIRE_VERIFIER_REQUIRED__"
                "NO_FULL_CHAIN_OR_BENCHMARK_CREDIT"
            ),
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
                "equality_schedule_challenge_fp2_elements": (
                    C61_EQ_CHALLENGE_FP2_ELEMENTS
                ),
                "equality_schedule_client_to_provider_bytes": (
                    C61_EQ_CHALLENGE_CLIENT_BYTES
                ),
                "output_batch_challenge_fp2_elements": (
                    C61_OUTPUT_BATCH_CHALLENGE_FP2_ELEMENTS
                ),
                "runtime_point_challenge_fp2_elements": (
                    C61_RUNTIME_POINT_CHALLENGE_FP2_ELEMENTS
                ),
                "known_pre_native_challenge_fp2_elements": (
                    C61_KNOWN_PRE_NATIVE_CHALLENGE_FP2_ELEMENTS
                ),
                "known_pre_native_client_to_provider_bytes_not_in_certificate": (
                    C61_KNOWN_PRE_NATIVE_CHALLENGE_CLIENT_BYTES
                ),
                "native_interactive_challenge_wire": (
                    "C6WIR1 and C6AWP1 diagnostics use 8-B base-field challenges "
                    "and 4-B query candidates after each prover move; distinct-"
                    "query rejection makes the candidate count seed-dependent, "
                    "so runs report it exactly; no upfront chain seed"
                ),
                "former_materialized_prg_oracle": False,
            },
            "terminal_functional_compiler": {
                "terminal_claims": C61_TERMINAL_OUTPUTS,
                "one_postclaim_output_rlc": True,
                "relation": "C6TFR1-v1 coefficient-event functional fold",
                "coefficient_event_writes": C61_TERMINAL_FUNCTIONAL_WRITES,
                "combined_padded_domain_log2": (
                    C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2
                ),
                "terminal_slot_grammar": "2 repetitions * (8 leaf + 16 auxiliary-linear + 8 auxiliary-quadratic)",
                "fixed_node_output_mapping": False,
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
                "runtime_values": canonical_runtime_values,
                "raw_verifier_runtime_values": raw_verifier_runtime_values,
                "public_pcs_vectors": 2,
                "public_pcs_vector_log2": C61_NODE_LOG2,
                "recurrence": (
                    "the installed plan/runtime constrain the atomic event generator; "
                    "the terminal relation folds typed coefficient writes"
                ),
                "provider_global_plan": True,
                "client_receives_plan": False,
                "client_retains_instance_map_bytes": C6_VERIFIER_INSTANCE_MAP_BYTES,
                "additional_semantic_replay_allowed": False,
                "materialized_event_table_allowed": False,
            },
            "native_transparent_backend": {
                "field": "Goldilocks quadratic extension with base-field embedding",
                "mode": "HVZK",
                "decoding_regime": "Johnson",
                "proof_of_work": "forbidden",
                "starting_rate": "1/2",
                "initial_folding_factor": 1,
                "later_folding_factor": 2,
                "mask_log_inv_rate": C61_NATIVE_MASK_LOG_INV_RATE,
                "mask_queries": C61_NATIVE_MASK_QUERIES,
                "chains_per_component": C61_NATIVE_CHAINS_PER_COMPONENT,
                "configured_public_pcs_security_bits": C61_NATIVE_PUBLIC_PCS_BITS,
                "authenticated_chain_error_allocation_bits": (
                    C61_NATIVE_AUTHENTICATED_CHAIN_BITS
                ),
                "components": ["model", "embedding", "compiler"],
                "reference_prototype": "Plonky3 p3-whir 0.6.0",
                "reference_prototype_commit": C61_P3_REFERENCE_COMMIT,
                "claimless_fork_semantic_revision": (
                    "66e290615de1858f2f2f6a804158064c406cda1c+"
                    "c61-claimless-affine-multi-v2"
                ),
                "reference_warning": (
                    "pinned academic implementation behind a reference-only "
                    "feature; not audited and never a production fallback"
                ),
                "clear_target_reference_codec": (
                    "C6WIR1-v1 fixed-shape non-Serde; Section 0.11 only; "
                    "ineligible for native backend integration"
                ),
                "authenticated_target_adapter": {
                    "name": "C6AWH1-v1",
                    "status": (
                        "Claimless affine-target Lean/MAC seams and feature-only "
                        "modified pinned PCS strict D14 codec differential green; "
                        "local claim-privacy equivalent argument green under explicit "
                        "Merkle-hiding/PCG assumptions; backend integration pending"
                    ),
                    "focused_tests_ordinary": 6,
                    "focused_tests_c6_trace": 6,
                    "in_memory_modified_pcs_tests": 5,
                    "clear_claim_observations_removed": True,
                    "clear_claim_observations_scope": (
                        "selected claimless WHIR call graph; legacy sumcheck "
                        "binding API remains but is unreachable from that path"
                    ),
                    "affine_full_verifier_replay_pending": False,
                    "explicit_root_then_point_binding": True,
                    "implicit_point_limb_skip_disabled_on_claimless_path": True,
                    "strict_claimless_codec": "C6AWP1-v1",
                    "strict_claimless_codec_pending": False,
                    "strict_codec_verifier_consumes_serialized_payload": True,
                    "resumable_private_entropy_driver_pending": False,
                    "durable_atomic_checkpoint_pending": False,
                    "scaled_full_relation_integration_pending": False,
                    "production_full_scale_execution_pending": True,
                    "ordered_multi_opening_reduction": {
                        "status": "SCALED_EXACT_COMPILER_FULL_FLOW_GREEN",
                        "maximum_claims_per_chain": C61_NATIVE_MAX_ORDERED_OPENINGS,
                        "model_claims": C61_NATIVE_MODEL_OPENINGS,
                        "embedding_claims": C61_NATIVE_EMBEDDING_OPENINGS,
                        "compiler_claims": C61_SPARSE_RATIONAL_TOTAL_OPENINGS,
                        "provider_artifact_maximum_claim_count_independent": True,
                        "points_and_target_keys_in_enclosing_statement": True,
                        "statement_digest_binding_pending_full_adapter": False,
                        "batching_error": _error_report(ordered_opening_batch_error),
                        "full_chain_credit": False,
                    },
                    "clear_evaluation_bytes_removed_per_chain": 16,
                    "zero_open_tag_bytes_added_per_chain": 16,
                    "provider_to_client_net_bytes_per_chain": 0,
                    "noncompiler_whir_masks_per_tape": (
                        C61_NONCOMPILER_AUTHENTICATED_TARGET_MASKS_PER_TAPE
                    ),
                    "compiler_full_correlations_per_tape": (
                        C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
                    ),
                    "compiler_subfield_correlations_per_tape": (
                        C61_SPARSE_RATIONAL_RESPONSE_TARGET_SUB_CORRELATIONS
                    ),
                    "registered_wrapper_full_correlations_per_tape": (
                        C61_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE
                    ),
                    "reserved_full_correlations_per_tape": (
                        C6_FULL_CORRELATION_RESERVE_PER_TAPE
                    ),
                    "headroom_full_correlations_per_tape": (
                        C61_FULL_CORRELATION_HEADROOM_PER_TAPE
                    ),
                    "compiler_raw_correlation_equivalents_per_tape": (
                        C61_COMPILER_RAW_CORRELATION_EQUIVALENTS_PER_TAPE
                    ),
                    "raw_correlation_reserve_equivalents_per_tape": (
                        C61_RAW_CORRELATION_RESERVE_EQUIVALENTS_PER_TAPE
                    ),
                    "raw_attempt_or_setup_increment_bytes": 0,
                    "claim_privacy_local_equivalent_argument": (
                        "PASS_WITH_EXPLICIT_MERKLE_HIDING_AND_PCG_ASSUMPTIONS"
                    ),
                    "claim_privacy_backend_proof_pending": False,
                    "full_sparse_oracle_simulator_implemented": False,
                    "executable_designated_view_simulator": True,
                    "simulator_reads_real_target_plaintext": False,
                    "simulator_reads_provider_target_tag": False,
                    "simulator_reads_provider_correlation_state": False,
                    "external_cryptographic_review_required_before_production": True,
                },
                "relation_adapter": (
                    "the public-only verifier decodes C6SBA1, verifies the exact "
                    "challenge-dependent sparse relation, binds twelve arithmetic plus "
                    "four terminal-fold physical response openings and three public plan "
                    "openings to shared Dn/D(n-1) WHIR rounds, "
                    "and folds every arithmetic row into one C6AWH1 ZeroOpen"
                ),
                "d28": {
                    "configured_security_target_bits": C61_NATIVE_PUBLIC_PCS_BITS,
                    "rounds": C61_NATIVE_D28_ROUNDS,
                    "pcs_strict_structural_max_bytes": (
                        d28_known_chain_bytes
                    ),
                    "unallocated_bytes_to_chain_codec_ceiling": (
                        C61_NATIVE_CHAIN_CODEC_MAX_BYTES - d28_known_chain_bytes
                    ),
                },
                "d27": {
                    "configured_security_target_bits": C61_NATIVE_PUBLIC_PCS_BITS,
                    "rounds": C61_NATIVE_D27_ROUNDS,
                    "pcs_strict_structural_max_bytes": (
                        d27_known_chain_bytes
                    ),
                    "unallocated_bytes_to_chain_codec_ceiling": (
                        C61_NATIVE_CHAIN_CODEC_MAX_BYTES - d27_known_chain_bytes
                    ),
                },
                "scaled_d14_diagnostic": {
                    "profile": "legacy clear-target C6WIR1 Section 0.11",
                    "strict_payload_bytes": (
                        C61_NATIVE_CLEAR_TARGET_D14_DIAGNOSTIC_BYTES
                    ),
                    "provider_messages": 26,
                    "client_fp_challenges": 52,
                    "client_query_candidates": 2_503,
                    "client_challenge_payload_bytes": 10_428,
                    "credit": False,
                },
                "claimless_scaled_d14_diagnostic": {
                    "profile": "C6AWP1-v1 claimless affine target plus C6AWH1 tag",
                    "strict_provider_to_client_payload_bytes": (
                        C61_NATIVE_CLAIMLESS_D14_DIAGNOSTIC_BYTES
                    ),
                    "whir_payload_bytes_before_final_zero_open_tag": (
                        C61_NATIVE_CLAIMLESS_D14_WHIR_PAYLOAD_BYTES
                    ),
                    "payload_blake3": C61_NATIVE_CLAIMLESS_D14_BLAKE3,
                    "provider_messages": C61_NATIVE_CLAIMLESS_D14_PROVIDER_MESSAGES,
                    "provider_semantic_bytes": (
                        C61_NATIVE_CLAIMLESS_D14_PROVIDER_SEMANTIC_BYTES
                    ),
                    "client_fp_challenges": (
                        C61_NATIVE_CLAIMLESS_D14_CLIENT_FP_CHALLENGES
                    ),
                    "client_query_candidates": (
                        C61_NATIVE_CLAIMLESS_D14_CLIENT_QUERY_CANDIDATES
                    ),
                    "client_challenge_payload_bytes": (
                        C61_NATIVE_CLAIMLESS_D14_CLIENT_CHALLENGE_BYTES
                    ),
                    "strict_round_trip": True,
                    "verifier_consumes_decoded_payload": True,
                    "proof_has_clear_evaluation_field": False,
                    "codec_component_credit": True,
                    "full_chain_proof_size_credit": False,
                },
                "private_entropy_replay_driver": {
                    "profile": "C6ICT1-v1 local in-memory diagnostic",
                    "endpoint_only_private_entropy": True,
                    "provider_reads_verifier_seed": False,
                    "provider_reads_checkpoint": False,
                    "replay_to_frontier": True,
                    "internal_p3_state_checkpoint": False,
                    "strict_checkpoint_codec": True,
                    "checkpoint_codec_mutations_rejected": True,
                    "challenge_count": C61_PRIVATE_ENTROPY_D14_CHALLENGES,
                    "midpoint_checkpoint_frontier": (
                        C61_PRIVATE_ENTROPY_D14_CHECKPOINT_FRONTIER
                    ),
                    "midpoint_checkpoint_bytes_client_local": (
                        C61_PRIVATE_ENTROPY_D14_CHECKPOINT_BYTES
                    ),
                    "provider_to_client_certificate_increment_bytes": 0,
                    "client_to_provider_challenge_bytes": (
                        C61_NATIVE_CLAIMLESS_D14_CLIENT_CHALLENGE_BYTES
                    ),
                    "normal_inline_replay_overhead": False,
                    "retry_replays_provider_prefix": True,
                    "durable_journal_codec": "C6ICJ1-v1 append-only checksum chain",
                    "durable_atomic_checkpoint_pending": False,
                    "challenge_fsync_before_release": True,
                    "client_reserved_attempt_binding": True,
                    "paired_raw_range_burned_before_provider_exposure": True,
                    "provider_move_bound_mask_frontier": 1,
                    "durable_journal_bytes_after_final_seal": (
                        C61_PRIVATE_ENTROPY_D14_DURABLE_JOURNAL_BYTES
                    ),
                    "durable_record_count": C61_PRIVATE_ENTROPY_D14_DURABLE_RECORDS,
                    "wrong_attempt_torn_and_corrupt_rejected": True,
                    "malicious_client_disk_snapshot_rollback_covered": False,
                    "scaled_full_relation_integration_pending": False,
                    "production_full_scale_execution_pending": True,
                    "full_chain_credit": False,
                },
                "claim_privacy": {
                    "scope": (
                        "one claimless C6AWP1 chain in the interactive honest-verifier model, "
                        "conditioned on verifier-owned target/mask keys"
                    ),
                    "max_ood_samples_per_round": (
                        C61_NATIVE_MAX_OOD_SAMPLES_PER_ROUND
                    ),
                    "fresh_pad_slots_per_ood_answer": 1,
                    "d27_statistical_error": _error_report(
                        d27_claim_privacy_error
                    ),
                    "d28_statistical_error": _error_report(
                        d28_claim_privacy_error
                    ),
                    "conservative_six_d28_chain_union": _error_report(
                        six_chain_claim_privacy_error
                    ),
                    "informative_17_certificate_union": _error_report(
                        session_claim_privacy_error
                    ),
                    "exact_final_tag_simulation": True,
                    "computational_terms": [
                        "BLAKE3 Merkle hiding for randomized high-min-entropy codewords",
                        "production AES-PCG pseudorandomness and domain separation",
                    ],
                    "fiat_shamir_covered": False,
                    "external_review_required": True,
                },
            },
            "wire_screen": {
                "model_embedding_chain_codec_ceiling_bytes": (
                    C61_NATIVE_CHAIN_CODEC_MAX_BYTES
                ),
                "model_embedding_chain_count": 2 * C61_NATIVE_CHAINS_PER_COMPONENT,
                "compiler_chain_codec_ceiling_bytes": (
                    C61_NATIVE_COMPILER_CHAIN_CODEC_MAX_BYTES
                ),
                "compiler_response_d28_strict_ceiling_bytes": d28_known_chain_bytes,
                "compiler_plan_d27_strict_ceiling_bytes": d27_known_chain_bytes,
                "shared_multi_oracle_header_bytes": (
                    C61_SHARED_MULTI_ORACLE_HEADER_BYTES
                ),
                "shared_multi_oracle_physical_strict_ceiling_bytes": (
                    compiler_shared_physical_strict_ceiling_bytes
                ),
                "c6sba1_arithmetic_bytes_per_compiler_chain": (
                    C61_SPARSE_RATIONAL_PRODUCTION_ARITHMETIC_BYTES
                ),
                "c6cpx1_outer_bytes_per_compiler_chain": (
                    C61_PRODUCTION_COMPILER_CHAIN_OUTER_BYTES
                ),
                "complete_compiler_chain_ceiling_bytes": (
                    compiler_complete_chain_ceiling_bytes
                ),
                "compiler_chain_slack_after_complete_relation_bytes": (
                    compiler_chain_slack_after_complete_relation_bytes
                ),
                "compiler_chain_count": C61_NATIVE_CHAINS_PER_COMPONENT,
                "arithmetic_mac_link_framing_ceiling_bytes": (
                    C61_NATIVE_ARITHMETIC_AND_LINK_CODEC_MAX_BYTES
                ),
                "c6pa1_outer_framing_bytes": C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES,
                "c6rsc4_arithmetic_frame_bytes": C61_C6RSC4_ARITHMETIC_FRAME_BYTES,
                "arithmetic_mac_link_ceiling_is_nested_not_additive": True,
                "public_argument_codec_ceiling_bytes": (
                    exact_native_public_argument_ceiling_bytes
                ),
                "preregistered_public_argument_allocation_bytes": (
                    C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES
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
                "schedule": (
                    "commit and release one physical base-limb response D28 before "
                    "two active recurrence buffers plus canonical runtime"
                ),
                "physical_response_d28_base_elements": (
                    C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BASE_ELEMENTS
                ),
                "physical_response_d28_bytes": (
                    C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES
                ),
                "packed_response_headroom_bytes": (
                    C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
                    - C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES
                ),
                "active_recurrence_rows_per_buffer": (
                    C61_SPARSE_RATIONAL_RECURRENCE_ACTIVE_ROWS
                ),
                "runtime_vectors": 1,
                "fp2_elements": provider_state_elements,
                "bytes": provider_state_bytes,
                "owner_max_bytes": C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES,
                "headroom_bytes": (
                    C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES - provider_state_bytes
                ),
                "c6nbr2_scheduled_after_compiler_peak": True,
                "c6nbr2_one_repetition_coefficient_owner_bytes": (
                    C61_NBR2_COEFFICIENT_OWNER_BYTES
                ),
                "c6nbr2_unpadded_source_prefix_bytes": (
                    C61_NBR2_SOURCE_PREFIX_BYTES
                ),
                "screen_pass": (
                    provider_state_bytes <= C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
                    and C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES
                    <= C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
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
                "postcommit_lane_batch": _error_report(lane_batch_error),
                "sparse_recurrence_rational_fingerprint": _error_report(
                    sparse_recurrence_rational_error
                ),
                "runtime_gather_rational_fingerprint": _error_report(
                    runtime_gather_rational_error
                ),
                "source_gather_rational_fingerprint": _error_report(
                    source_gather_rational_error
                ),
                "terminal_functional_relation_total": _error_report(
                    terminal_functional_relation_error
                ),
                "one_authenticated_chain_exact_screen": _error_report(
                    authenticated_target_chain_error
                ),
                "ordered_opening_batch_max_127_over_fp2": _error_report(
                    ordered_opening_batch_error
                ),
                "compiler_ordered_19_opening_batch": _error_report(
                    compiler_ordered_opening_batch_error
                ),
                "compiler_folded_179_zero_rows": _error_report(
                    compiler_zero_row_rlc_error
                ),
                "compiler_531_triple_quicksilver_batch": _error_report(
                    compiler_product_batch_error
                ),
                "one_complete_compiler_authenticated_chain": _error_report(
                    compiler_authenticated_chain_error
                ),
                "three_dual_chain_native_components": _error_report(
                    native_backend_error
                ),
                "retained_c6_wrapper": _error_report(existing_wrapper_error),
                "joint_native_bridge_conservative_addition": _error_report(
                    joint_native_bridge_error
                ),
                "c6nbr2_link_relations": C61_NBR2_LINK_RELATIONS,
                "c6nbr2_link_roots_per_repetition": (
                    C61_NBR2_LINK_ROOTS_PER_REPETITION
                ),
                "c6nbr2_covered_by_existing_256_root_allocation": (
                    C61_NBR2_LINK_ROOTS_PER_REPETITION
                    <= c6.LINEAR_LINK_ROOT_BOUND_PER_REPETITION
                ),
                "complete_per_certificate": _error_report(
                    candidate_complete_error
                ),
                "informative_seventeen_certificate_union": _error_report(
                    candidate_session_error
                ),
                "per_certificate_target_bits": "78.80929487391641",
                "screen_pass": c6.soundness_bits(candidate_complete_error)
                >= Decimal("78.80929487391641"),
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
                "c6nbr2_two_repetition_traffic_bytes": (
                    C61_NBR2_TWO_REPETITION_TRAFFIC_BYTES
                ),
                "c6nbr2_two_repetition_fp2_muls": (
                    C61_NBR2_TWO_REPETITION_FP2_MULS
                ),
                "c6nbr2_memory_seconds": str(nbr2_memory_seconds),
                "c6nbr2_arithmetic_seconds": str(nbr2_arithmetic_seconds),
                "c6nbr2_marginal_roof_seconds": str(
                    nbr2_provider_roof_seconds
                ),
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
                "model_embedding_chain_count": 2 * C61_NATIVE_CHAINS_PER_COMPONENT,
                "seconds_per_model_embedding_chain_allocation": str(
                    C61_VERIFIER_PER_NATIVE_CHAIN_SECONDS
                ),
                "compiler_chain_count": C61_NATIVE_CHAINS_PER_COMPONENT,
                "seconds_per_compiler_chain_allocation": str(
                    C61_VERIFIER_PER_COMPILER_CHAIN_SECONDS
                ),
                "public_arithmetic_seconds": str(
                    C61_VERIFIER_PUBLIC_ARITHMETIC_SECONDS
                ),
                "base_projected_total_seconds": str(native_verifier_roof_seconds),
                "projected_total_seconds": str(native_verifier_roof_seconds),
                "strict_gate_seconds": str(C61_VERIFIER_EXCLUSIVE_SECONDS),
                "maximum_c6nbr2_marginal_seconds": str(
                    C61_VERIFIER_EXCLUSIVE_SECONDS - native_verifier_roof_seconds
                ),
                "c6nbr2_local_coefficient_evaluations": 2,
                "c6nbr2_source_prefix_bytes_per_evaluation": (
                    C61_NBR2_SOURCE_PREFIX_BYTES
                ),
                "screen_pass": False,
                "status": "FOUR_THREAD_STREAMING_EVALUATION_MEASUREMENT_REQUIRED",
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
            "local_hard_stop": {
                "status": "C6SPR11_PRODUCTION_NATIVE_COMPONENTS_AND_WIRE_VERIFIER_REQUIRED",
                "persisted_cuda_compiler_executor_green": True,
                "production_model_embedding_chains_green": False,
                "strict_six_chain_c6pa1_assembly_green": False,
                "setup_compliant_role_separated_compiler_verifier_green": False,
                "canonical_runtime_seam_green": True,
                "raw_verifier_runtime_values": raw_verifier_runtime_values,
                "canonical_runtime_values": canonical_runtime_values,
                "deduplicated_raw_values": (
                    raw_verifier_runtime_values - canonical_runtime_values
                ),
                "retained_instance_map_bytes": C6_VERIFIER_INSTANCE_MAP_BYTES,
                "current_scaled_abstraction": (
                    "historical and ineligible: injects beta powers at 64 fixed node indices"
                ),
                "production_terminal_semantics": (
                    "two challenge-dependent 8+16+8 coefficient-functional "
                    "outputs emitted by atomic replay"
                ),
                "selected_exact_relation": (
                    "typed coefficient-event slot injection and postclaim beta fold"
                ),
                "selected_relation_domain_writes": C61_TERMINAL_FUNCTIONAL_WRITES,
                "selected_relation_domain_log2": (
                    C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2
                ),
                "rust_terminal_differential_green": True,
                "direct_mle_schedule_typestate_green": True,
                "scaled_v3_v4_grammar_differential_green": True,
                "actual_fused_c6rsc3_terminal_outputs_green": True,
                "terminal_outputs_fixed_before_beta": True,
                "historical_v3_schedule_preserved": True,
                "typed_native_chain_statements_green": True,
                "native_backend_consumes_typed_relation_statement": False,
                "selected_native_factorization": {
                    "name": "C6TFA1-v1",
                    "reverse_lanes": C61_RUNTIME_SKETCH_REPETITIONS,
                    "plan_dependent_forms_per_lane": 5,
                    "fixed_terminal_node_mapping": False,
                    "direct_families": [
                        "source_grammar",
                        "affine_alpha",
                        "reverse_auxiliary_subtractions",
                        "raw_copy",
                        "product",
                        "zero",
                        "leaf_tail",
                        "auxiliary_tail",
                    ],
                    "scaled_eight_family_differential_green": True,
                    "scaled_coefficient_writes": 2_400,
                    "scaled_family_outputs_per_repetition": [15, 4, 4, 36, 6, 2, 953, 28],
                    "scaled_all_family_folds_nonzero": True,
                    "v3_and_malformed_dimension_reject": True,
                    "constrained_interval_reducer_required": False,
                    "direct_interval_reducer_green": True,
                    "production_interval_reductions": (
                        C61_FOLDED_DIRECT_INTERVAL_REDUCTIONS
                    ),
                    "production_interval_dyadic_blocks": (
                        C61_FOLDED_DIRECT_INTERVAL_DYADIC_BLOCKS
                    ),
                    "production_interval_transition_rows": (
                        C61_FOLDED_DIRECT_INTERVAL_TRANSITION_ROWS
                    ),
                    "production_interval_max_carry_states": (
                        C61_FOLDED_DIRECT_INTERVAL_MAX_CARRY_STATES
                    ),
                    "production_explicit_terms": C61_FOLDED_DIRECT_EXPLICIT_TERMS,
                    "production_direct_reducer_total_rows_and_terms": (
                        C61_FOLDED_DIRECT_TOTAL_ROWS_AND_TERMS
                    ),
                    "production_event_writes_avoided": (
                        C61_TERMINAL_FUNCTIONAL_WRITES
                        - C61_FOLDED_DIRECT_TOTAL_ROWS_AND_TERMS
                    ),
                    "terminal_metadata_codec": "VC6TRM1",
                    "terminal_metadata_bytes": C61_TERMINAL_METADATA_BYTES,
                    "terminal_metadata_authenticated": True,
                    "terminal_metadata_reconstructs_topology_digest": True,
                    "exact_d25_lane_references_green": True,
                    "exact_source_boundary_references_green": True,
                    "native_d25_recurrences_green": False,
                    "credit": False,
                },
                "preregistered_sparse_backend": {
                    "name": "C6SPR2-v1 committed-mu rational-memory GKR",
                    "plan_oracle_columns": ["opcode", "lhs_or_source", "rhs_or_scalar"],
                    "plan_oracle_domain_log2": C61_SPARSE_RATIONAL_PLAN_DOMAIN_LOG2,
                    "plan_oracle_client_parameter_frame_bytes": (
                        C61_SPARSE_RATIONAL_CLIENT_PARAMETER_FRAME_BYTES
                    ),
                    "response_commitments_fixed_before_lane_batch": [
                        "one_physical_D28_base_root_packing_c0_and_c1_limbs_of",
                        "lane_0_D25|lane_1_D25|scale_runtime_D24|source_boundaries_D23|mu_D25",
                    ],
                    "mu_fixed_before_lane_and_rational_challenges": True,
                    "fixed_plan_D27_root_batched_in_same_compiler_chain": True,
                    "multi_oracle_shared_rounds_required": True,
                    "rational_subchecks": C61_SPARSE_RATIONAL_SUBCHECKS,
                    "inverse_columns_committed": 0,
                    "edge_domain_witness_committed": False,
                    "batch_inversion": "product-tree GKR with one checked root inverse",
                    "scaled_differential_green": True,
                    "weighted_fp2_fraction_tree_green": True,
                    "neutral_zero_over_one_padding_green": True,
                    "all_seven_root_mutations_reject": True,
                    "lane_batch_binding_mutation_rejects": True,
                    "all_seven_padding_mutations_reject": True,
                    "exact_response_d28_base_limb_packing_green": True,
                    "exact_plan_d27_packing_green": True,
                    "prechallenge_root_typestate_green": True,
                    "ordered_arithmetic_response_opening_points": (
                        C61_SPARSE_RATIONAL_ARITHMETIC_RESPONSE_OPENINGS
                    ),
                    "ordered_terminal_fold_response_opening_points": (
                        C61_EXACT_TERMINAL_FOLD_PHYSICAL_RESPONSE_OPENINGS
                    ),
                    "ordered_physical_response_opening_points": (
                        C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_OPENINGS
                    ),
                    "ordered_plan_opening_points": C61_SPARSE_RATIONAL_PLAN_OPENINGS,
                    "typed_role_targets_green": True,
                    "root_point_and_layout_mutations_reject": True,
                    "claimless_multi_oracle_opening_green": True,
                    "shared_round_d14_payload_bytes": (
                        C61_SHARED_MULTI_ORACLE_D14_DIAGNOSTIC_BYTES
                    ),
                    "shared_round_d14_strict_max_bytes": (
                        C61_SHARED_MULTI_ORACLE_D14_STRICT_MAX_BYTES
                    ),
                    "shared_round_d14_provider_messages": (
                        C61_SHARED_MULTI_ORACLE_D14_PROVIDER_MESSAGES
                    ),
                    "shared_round_d14_provider_semantic_bytes": (
                        C61_SHARED_MULTI_ORACLE_D14_PROVIDER_SEMANTIC_BYTES
                    ),
                    "shared_round_d14_client_fp_challenges": (
                        C61_SHARED_MULTI_ORACLE_D14_CLIENT_FP_CHALLENGES
                    ),
                    "shared_round_d14_client_query_candidates": (
                        C61_SHARED_MULTI_ORACLE_D14_CLIENT_QUERY_CANDIDATES
                    ),
                    "shared_round_d14_client_challenge_bytes": (
                        C61_SHARED_MULTI_ORACLE_D14_CLIENT_CHALLENGE_BYTES
                    ),
                    "scaled_c6sba1_bytes": C61_SHARED_MULTI_ORACLE_D14_ARITHMETIC_BYTES,
                    "scaled_complete_provider_bytes": (
                        C61_SHARED_MULTI_ORACLE_D14_TOTAL_PROVIDER_BYTES
                    ),
                    "scaled_transcript_bytes": C61_SHARED_MULTI_ORACLE_D14_TRANSCRIPT_BYTES,
                    "production_c6sba1_bytes_per_tape": (
                        C61_SPARSE_RATIONAL_PRODUCTION_ARITHMETIC_BYTES
                    ),
                    "production_fraction_depths": C61_SPARSE_RATIONAL_PRODUCTION_DEPTHS,
                    "production_product_triples_per_tape": (
                        C61_SPARSE_RATIONAL_PRODUCTION_PRODUCT_TRIPLES
                    ),
                    "production_folded_zero_rows_per_tape": (
                        C61_SPARSE_RATIONAL_PRODUCTION_ZERO_ROWS
                    ),
                    "production_response_target_correction_bytes_per_tape": (
                        C61_SPARSE_RATIONAL_RESPONSE_TARGET_CORRECTION_BYTES
                    ),
                    "production_response_target_sub_correlations_per_tape": (
                        C61_SPARSE_RATIONAL_RESPONSE_TARGET_SUB_CORRELATIONS
                    ),
                    "production_full_correlations_per_tape": (
                        C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
                    ),
                    "verifier_private_relation_vectors_accessible": False,
                    "one_existing_zero_open_for_whir_and_arithmetic": True,
                    "scale_runtime_is_zero_based_and_zero_padded": True,
                    "full_chain_credit": False,
                    "credit": False,
                },
                "native_trace_audit": {
                    "implemented_c6rsc3_schedules": (
                        "historical ChaCha8/FpStream v3 plus versioned direct-MLE v4"
                    ),
                    "registered_c61_schedule": "direct multilinear equality points",
                    "direct_point_fp2_elements_already_budgeted": (
                        C61_EQ_CHALLENGE_FP2_ELEMENTS
                    ),
                    "materialized_d28_fp2_trace_bytes": (
                        C61_TERMINAL_FUNCTIONAL_TRACE_FP2_BYTES
                    ),
                    "materialized_d28_fp2_trace_over_state_cap_bytes": (
                        C61_TERMINAL_FUNCTIONAL_TRACE_FP2_BYTES
                        - C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
                    ),
                    "one_base_limb_plus_runtime_bytes": (
                        C61_TERMINAL_FUNCTIONAL_TRACE_BASE_LIMB_BYTES
                        + canonical_runtime_values * c6.FP2_BYTES
                    ),
                    "one_base_limb_plus_runtime_over_state_cap_bytes": (
                        C61_TERMINAL_FUNCTIONAL_TRACE_BASE_LIMB_BYTES
                        + canonical_runtime_values * c6.FP2_BYTES
                        - C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
                    ),
                    "materialized_event_table_allowed": False,
                    "unconstrained_stream_digest_allowed": False,
                    "selected_whir_backend_has_generic_trace_relation": False,
                    "selected_whir_backend_scope": (
                        "claimless authenticated polynomial openings only"
                    ),
                },
                "monolithic_p3_memory_census": {
                    "response_d28_message_bytes": C61_MONOLITHIC_D28_MESSAGE_BYTES,
                    "response_d28_encoded_bytes": C61_MONOLITHIC_D28_ENCODED_BYTES,
                    "response_d28_merkle_bytes": C61_MONOLITHIC_D28_MERKLE_BYTES,
                    "response_d28_retained_lower_bound_bytes": (
                        C61_MONOLITHIC_D28_RETAINED_LOWER_BOUND_BYTES
                    ),
                    "plan_d27_message_bytes": C61_MONOLITHIC_D27_MESSAGE_BYTES,
                    "plan_d27_encoded_bytes": C61_MONOLITHIC_D27_ENCODED_BYTES,
                    "plan_d27_merkle_bytes": C61_MONOLITHIC_D27_MERKLE_BYTES,
                    "plan_d27_retained_lower_bound_bytes": (
                        C61_MONOLITHIC_D27_RETAINED_LOWER_BOUND_BYTES
                    ),
                    "concurrent_retained_lower_bound_bytes": (
                        C61_MONOLITHIC_CONCURRENT_RETAINED_LOWER_BOUND_BYTES
                    ),
                    "includes_later_rounds_gkr_and_allocator_overhead": False,
                    "compared_to_coefficient_witness_cap_as_protocol_gate": False,
                    "production_execution_credit": False,
                },
                "required_before_resume": [
                    "implement a resource-instrumented persisted/recomputable or GPU-resident WHIR prover-data executor byte-identical to the pinned fork",
                    "preserve the two prechallenge roots, shared-round transcript, strict codec and designated ZeroOpen without a silent monolithic or CPU fallback",
                    "execute the exact relation with the production D28 base-limb response and D27 plan geometries",
                    "strict-decode both compiler chains and reconcile coefficient/witness, total RSS, GPU and correlation counters separately",
                    "run a clean local full-chain benchmark before any owner GO or pod contact",
                ],
                "credit": False,
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
            "compiler_plan_retained_for_exact_joint_functional_bytes": (
                C6_CANONICAL_PLAN_BYTES
            ),
            "verifier_instance_map_retained_inside_parameter_allocation_bytes": (
                C6_VERIFIER_INSTANCE_MAP_BYTES
            ),
            "base_without_client_plan_or_new_parameters_bytes": (
                setup_without_client_plan_and_parameters
            ),
            "public_parameter_preregistered_allocation_bytes": (
                C61_CLIENT_PUBLIC_PARAMETER_ALLOCATION_BYTES
            ),
            "parameter_bytes_after_retained_map": (
                C61_CLIENT_PARAMETER_BYTES_AFTER_RETAINED_MAP
            ),
            "terminal_metadata_codec": "VC6TRM1",
            "terminal_metadata_bytes": C61_TERMINAL_METADATA_BYTES,
            "parameter_bytes_after_terminal_metadata": (
                C61_CLIENT_PARAMETER_BYTES_AFTER_TERMINAL_METADATA
            ),
            "sparse_rational_plan_parameter_frame_bytes": (
                C61_SPARSE_RATIONAL_CLIENT_PARAMETER_FRAME_BYTES
            ),
            "parameter_bytes_after_sparse_rational_frame": (
                C61_CLIENT_PARAMETER_BYTES_AFTER_TERMINAL_METADATA
                - C61_SPARSE_RATIONAL_CLIENT_PARAMETER_FRAME_BYTES
            ),
            "projected_setup_bytes": projected_setup_bytes,
            "strict_setup_max_bytes": C61_SETUP_MAX_BYTES,
            "headroom_bytes": C61_SETUP_MAX_BYTES - projected_setup_bytes,
            "projected_setup_plus_native_first_certificate_bytes": (
                native_projected_first_response_bytes
            ),
            "allocation_screen_pass": projected_setup_bytes <= C61_SETUP_MAX_BYTES,
            "contingency": (
                "the exact joint functional retains the canonical plan; no setup "
                "credit before full Rust integration"
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
                "raw_values_total": raw_verifier_runtime_values,
                "canonical_public_values": C6_VERIFIER_CANONICAL_PUBLIC_VALUES,
                "canonical_scalar_values": C6_VERIFIER_CANONICAL_SCALAR_VALUES,
                "canonical_values_total": canonical_runtime_values,
                "retained_extraction_map_bytes": C6_VERIFIER_INSTANCE_MAP_BYTES,
                "canonical_order": "public inputs then scale scalars",
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
    assert projected_setup_bytes == 148_738_118
    assert C61_SETUP_MAX_BYTES - projected_setup_bytes == 1_261_881
    assert projected_first_response_bytes == 167_580_221
    assert sum(compiler_families.values()) == c6.RESIDUAL_COEFFICIENT_WRITES_PER_REPETITION
    assert c6.RESIDUAL_COEFFICIENT_WRITES_TOTAL == 225_997_412
    assert c6.RESIDUAL_ATOMIC_OUTPUTS_TOTAL == 94_868_704
    assert raw_verifier_runtime_values == 10_830_342
    assert canonical_runtime_values == 10_830_288
    assert raw_verifier_runtime_values - canonical_runtime_values == 54
    assert C61_CLIENT_PARAMETER_BYTES_AFTER_RETAINED_MAP == 2_679_614
    assert C61_TERMINAL_METADATA_PAYLOAD_BYTES == 308_824
    assert C61_TERMINAL_METADATA_BYTES == 309_044
    assert C61_CLIENT_PARAMETER_BYTES_AFTER_TERMINAL_METADATA == 2_370_570
    assert runtime_sketch_bits > Decimal("246")
    assert C61_EQ_CHALLENGE_FP2_ELEMENTS == 234
    assert C61_EQ_CHALLENGE_CLIENT_BYTES == 3_744
    assert C61_KNOWN_PRE_NATIVE_CHALLENGE_FP2_ELEMENTS == 283
    assert C61_KNOWN_PRE_NATIVE_CHALLENGE_CLIENT_BYTES == 4_528
    assert (
        C61_SOURCE_NODE_COUNT
        + C61_PUBLIC_NODE_COUNT
        + C61_STRUCTURAL_ZERO_NODE_COUNT
        + C61_ADD_NODE_COUNT
        + C61_SUB_NODE_COUNT
        + C61_SCALE_NODE_COUNT
        == C61_CANONICAL_NODE_COUNT
    )
    assert d28_known_chain_bytes == 1_172_652
    assert d27_known_chain_bytes == 1_085_464
    assert c6.soundness_bits(d27_claim_privacy_error) > Decimal("124.67")
    assert c6.soundness_bits(d28_claim_privacy_error) > Decimal("124.54")
    assert c6.soundness_bits(six_chain_claim_privacy_error) > Decimal("121.95")
    assert c6.soundness_bits(session_claim_privacy_error) > Decimal("117.86")
    assert d28_known_chain_bytes < C61_NATIVE_CHAIN_CODEC_MAX_BYTES
    assert d27_known_chain_bytes < C61_NATIVE_CHAIN_CODEC_MAX_BYTES
    assert authenticated_target_chain_error < Fraction(
        1, 2**C61_NATIVE_AUTHENTICATED_CHAIN_BITS
    )
    assert compiler_authenticated_chain_error < Fraction(
        1, 2**C61_NATIVE_AUTHENTICATED_CHAIN_BITS
    )
    assert C61_NATIVE_MODEL_OPENINGS <= C61_NATIVE_MAX_ORDERED_OPENINGS
    assert C61_NATIVE_EMBEDDING_OPENINGS <= C61_NATIVE_MAX_ORDERED_OPENINGS
    assert ordered_opening_batch_error == Fraction(127, c6.FP2_CARDINALITY)
    assert C61_REGISTERED_WRAPPER_FULL_CORRELATIONS_PER_TAPE == 6_117
    assert C61_FULL_CORRELATION_HEADROOM_PER_TAPE == 32_999
    assert C61_COMPILER_RAW_CORRELATION_EQUIVALENTS_PER_TAPE == 11_010
    assert C61_RAW_CORRELATION_RESERVE_EQUIVALENTS_PER_TAPE == 78_232
    assert C61_NATIVE_CLAIMLESS_D14_DIAGNOSTIC_BYTES == 378_496
    assert C61_MONOLITHIC_D28_MESSAGE_BYTES == 2_147_483_648
    assert C61_MONOLITHIC_D28_ENCODED_BYTES == 4_294_967_296
    assert C61_MONOLITHIC_D28_MERKLE_BYTES == 17_179_869_152
    assert C61_MONOLITHIC_D28_RETAINED_LOWER_BOUND_BYTES == 23_622_320_096
    assert C61_MONOLITHIC_D27_MESSAGE_BYTES == 1_073_741_824
    assert C61_MONOLITHIC_D27_ENCODED_BYTES == 2_147_483_648
    assert C61_MONOLITHIC_D27_MERKLE_BYTES == 8_589_934_560
    assert C61_MONOLITHIC_D27_RETAINED_LOWER_BOUND_BYTES == 11_811_160_032
    assert C61_MONOLITHIC_CONCURRENT_RETAINED_LOWER_BOUND_BYTES == 35_433_480_128
    assert C61_PRIVATE_ENTROPY_D14_CHALLENGES == 2_588
    assert C61_PRIVATE_ENTROPY_D14_CHECKPOINT_FRONTIER * 2 == (
        C61_PRIVATE_ENTROPY_D14_CHALLENGES
    )
    assert C61_PRIVATE_ENTROPY_D14_CHECKPOINT_BYTES == 73_360
    assert C61_PRIVATE_ENTROPY_D14_DURABLE_JOURNAL_BYTES == 208_204
    assert C61_PRIVATE_ENTROPY_D14_DURABLE_RECORDS == (
        C61_PRIVATE_ENTROPY_D14_CHALLENGES + 2
    )
    assert (
        C61_NATIVE_CLAIMLESS_D14_WHIR_PAYLOAD_BYTES
        + c6.FP2_BYTES
        == C61_NATIVE_CLAIMLESS_D14_DIAGNOSTIC_BYTES
    )
    assert C61_PREREGISTERED_NATIVE_PUBLIC_ARGUMENT_CODEC_MAX_BYTES == 11_500_000
    assert compiler_shared_physical_strict_ceiling_bytes == 2_258_132
    assert C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_OPENINGS == 16
    assert C61_SPARSE_RATIONAL_TOTAL_OPENINGS == 19
    assert compiler_complete_chain_ceiling_bytes == 2_346_532
    assert compiler_chain_slack_after_complete_relation_bytes == 153_468
    assert exact_native_public_argument_ceiling_bytes == 10_694_632
    assert exact_native_public_argument_ceiling_bytes < C61_PUBLIC_ARGUMENT_ALLOCATION_BYTES
    assert C61_SHARED_MULTI_ORACLE_D14_DIAGNOSTIC_BYTES == 677_532
    assert C61_SHARED_MULTI_ORACLE_D14_STRICT_MAX_BYTES == 770_748
    assert C61_SHARED_MULTI_ORACLE_D14_ARITHMETIC_BYTES == 5_212
    assert C61_SHARED_MULTI_ORACLE_D14_TOTAL_PROVIDER_BYTES == 682_744
    assert C61_SHARED_MULTI_ORACLE_D14_TRANSCRIPT_BYTES == 682_652
    assert native_projected_certificate_bytes == 17_536_735
    assert C61_CERTIFICATE_MAX_BYTES - native_projected_certificate_bytes == 4_463_264
    assert native_projected_first_response_bytes == 166_274_853
    assert C61_NBR2_LINK_RELATIONS == 73
    assert C61_NBR2_LINK_ROOTS_PER_REPETITION == 150
    assert C61_NBR2_LINK_ROOTS_PER_REPETITION <= c6.LINEAR_LINK_ROOT_BOUND_PER_REPETITION
    assert C61_NBR2_COEFFICIENT_OWNER_BYTES == 134_217_728
    assert C61_NBR2_SOURCE_PREFIX_BYTES == 79_608_400
    assert C61_NBR2_TWO_REPETITION_TRAFFIC_BYTES == 1_073_741_824
    assert C61_NBR2_TWO_REPETITION_FP2_MULS == 67_108_864
    assert provider_state_elements == 142_357_222
    assert provider_state_bytes == 2_277_715_552
    assert C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BASE_ELEMENTS == 268_435_456
    assert C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES == 2_147_483_648
    assert (
        C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
        - C61_SPARSE_RATIONAL_PHYSICAL_RESPONSE_BYTES
        == 145_715_200
    )
    assert C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES == 2_293_198_848
    assert C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES - provider_state_bytes == 15_483_296
    assert c6.soundness_bits(equality_schedule_error) > Decimal("120.12")
    assert terminal_functional_relation_error == Fraction(
        1
        + (C61_CANONICAL_NODE_COUNT - 1)
        + (C61_SCALE_NODE_COUNT - 1)
        + (C61_SCHEDULED_SOURCE_COUNT - 1),
        c6.FP2_CARDINALITY,
    )
    assert C61_SPARSE_RATIONAL_PRODUCTION_DEPTH_SUM == 172
    assert C61_SPARSE_RATIONAL_PRODUCTION_PRODUCT_TRIPLES == (
        3 * C61_SPARSE_RATIONAL_PRODUCTION_DEPTH_SUM
        + 2 * C61_SPARSE_RATIONAL_SUBCHECKS
        + 1
    )
    assert C61_SPARSE_RATIONAL_PRODUCTION_ZERO_ROWS == (
        C61_SPARSE_RATIONAL_PRODUCTION_DEPTH_SUM + 3 + 3 + 1
    )
    assert C61_SPARSE_RATIONAL_PRODUCTION_GKR_FULL_CORRELATIONS == (
        sum(
            depth * depth + 6 * depth + 2
            for depth in C61_SPARSE_RATIONAL_PRODUCTION_DEPTHS
        )
        + 2 * C61_SPARSE_RATIONAL_SUBCHECKS
    )
    assert C61_SPARSE_RATIONAL_PRODUCTION_JOINT_FULL_CORRELATIONS == 25 * 8
    assert C61_SPARSE_RATIONAL_PRODUCTION_FULL_CORRELATIONS_PER_TAPE == (
        C61_SPARSE_RATIONAL_PRODUCTION_GKR_FULL_CORRELATIONS
        + C61_SPARSE_RATIONAL_PRODUCTION_JOINT_FULL_CORRELATIONS
        + 1  # terminal lambda*mu result
        + 1  # global QuickSilver product mask
        + 1  # existing compiler WHIR mask
    )
    assert C61_SPARSE_RATIONAL_PRODUCTION_ARITHMETIC_BYTES == (
        92
        + C61_SPARSE_RATIONAL_RESPONSE_TARGET_CORRECTION_BYTES
        + C61_SPARSE_RATIONAL_PRODUCTION_GKR_BYTES
        + C61_SPARSE_RATIONAL_PRODUCTION_JOINT_BYTES
        + 16
        + 32
    )
    assert C61_TERMINAL_FUNCTIONAL_WRITES == 225_997_412
    assert C61_TERMINAL_FUNCTIONAL_WRITES < 2**C61_TERMINAL_FUNCTIONAL_DOMAIN_LOG2
    assert C61_FOLDED_DIRECT_INTERVAL_REDUCTIONS == 56
    assert C61_FOLDED_DIRECT_INTERVAL_DYADIC_BLOCKS == 510
    assert C61_FOLDED_DIRECT_INTERVAL_TRANSITION_ROWS == 30_072
    assert C61_FOLDED_DIRECT_INTERVAL_MAX_CARRY_STATES == 3
    assert C61_FOLDED_DIRECT_EXPLICIT_TERMS == 1_513_162
    assert C61_FOLDED_DIRECT_TOTAL_ROWS_AND_TERMS == 1_543_234
    assert (
        C61_TERMINAL_FUNCTIONAL_WRITES
        - C61_FOLDED_DIRECT_TOTAL_ROWS_AND_TERMS
        == 224_454_178
    )
    assert c6.soundness_bits(candidate_complete_error) > Decimal("101")
    assert c6.soundness_bits(candidate_session_error) > Decimal("97")
    assert native_compiler_symbols == 4_902_000_320
    assert C61_TERMINAL_FUNCTIONAL_TRACE_FP2_BYTES == 4_294_967_296
    assert (
        C61_TERMINAL_FUNCTIONAL_TRACE_FP2_BYTES
        - C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
        == 2_001_768_448
    )
    assert (
        C61_TERMINAL_FUNCTIONAL_TRACE_BASE_LIMB_BYTES
        + canonical_runtime_values * c6.FP2_BYTES
        == 2_320_768_256
    )
    assert (
        C61_TERMINAL_FUNCTIONAL_TRACE_BASE_LIMB_BYTES
        + canonical_runtime_values * c6.FP2_BYTES
        - C61_EPHEMERAL_PROVIDER_STATE_MAX_BYTES
        == 27_569_408
    )
    assert native_compiler_pcs_transform_bytes == 21_474_836_480
    assert Decimal("14.91") < native_provider_roof_seconds < Decimal("14.92")
    assert native_verifier_roof_seconds == Decimal("4.965672390")
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
    print(f"C6.1 reference profile:       {report['profile']}")
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
        "runtime raw/canonical/sketch: "
        f"{operations['runtime_stream']['raw_values_total']:,} / "
        f"{operations['runtime_stream']['canonical_values_total']:,} / "
        f"{operations['runtime_stream']['sketch_repetitions']}"
    )
    print(
        "A100 unallocated to 15 s:    "
        f"{Decimal(provider['unallocated_seconds_to_strict_15_second_gate']):.6f} s "
        "(no compiler/public-proof credit)"
    )
    print("-- selected native C6.1 candidate (reference PCS/codec only) --")
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

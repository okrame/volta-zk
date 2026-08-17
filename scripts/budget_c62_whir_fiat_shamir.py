#!/usr/bin/env python3
"""Exact C6.2 codec gates and conservative Fiat--Shamir soundness bound."""

from __future__ import annotations

import argparse
import json
from decimal import Decimal
from fractions import Fraction
from typing import Any

import budget_c6_wrapper as c6
import budget_c61_public_compression as c61


SETUP_TARGET_BYTES = 150_000_000
SETUP_TERMINAL_BYTES = 157_500_000
CERTIFICATE_TARGET_BYTES = 21_999_999
CERTIFICATE_TERMINAL_BYTES = 23_099_998
PI_FINAL_TARGET_BYTES = 4_500_000
PI_FINAL_TERMINAL_BYTES = 4_725_000
PROVER_TARGET_SECONDS = Decimal("15")
PROVER_TERMINAL_SECONDS = Decimal("15.75")
VERIFIER_TARGET_SECONDS = Decimal("5")
VERIFIER_TERMINAL_SECONDS = Decimal("5.25")
SOUNDNESS_GATE_BITS = Decimal("78.80929487391641")

C62_CLIENT_PARAMETER_ENVELOPE_BYTES = 124
C62_CLIENT_PARAMETER_BYTES = 65_139_022
C62_COMPRESSED_CLIENT_PARAMETER_PAYLOAD_BYTES = (
    C62_CLIENT_PARAMETER_BYTES - C62_CLIENT_PARAMETER_ENVELOPE_BYTES
)
C62_SETUP_MANIFEST_FRAMING_BYTES = 309
C62_SETUP_BYTES = (
    c61.C6_PAIRED_PCG_BYTES
    + C62_CLIENT_PARAMETER_BYTES
    + C62_SETUP_MANIFEST_FRAMING_BYTES
)

C62_MODEL_CHAIN_MAX_BYTES = 1_172_652
C62_EMBEDDING_CHAIN_MAX_BYTES = 1_085_464
C62_COMPILER_CHAIN_MAX_BYTES = 2_346_532
C62_PUBLIC_ARGUMENT_FRAMING_BYTES = 356
C62_ARITHMETIC_FRAME_BYTES = 1_212
C62_PUBLIC_ARGUMENT_MAX_BYTES = (
    2 * C62_MODEL_CHAIN_MAX_BYTES
    + 2 * C62_EMBEDDING_CHAIN_MAX_BYTES
    + 2 * C62_COMPILER_CHAIN_MAX_BYTES
    + C62_PUBLIC_ARGUMENT_FRAMING_BYTES
    + C62_ARITHMETIC_FRAME_BYTES
)

C62_RETAINED_NON_PCS_RESPONSE_BYTES = 2_921_744
C62_CERTIFICATE_FRAMING_BYTES = 793
C62_ENVELOPE_COMPONENTS = 7
C62_ENVELOPE_FRAMING_BYTES = 324
C62_RESIDUAL_SUMCHECK_MAX_BYTES = 6_900
C62_PRODUCT_COORDINATE_ONE_BYTES = 673 * 32
C62_RESIDUAL_PENDING_BYTES = 1_536
C62_CACHE_SOURCE_BYTES = 304
C62_CACHE_BLIND_MAX_BYTES = 3_506
C62_CACHE_FOLD_TARGET_BYTES = 18_480
C62_AUTHENTICATED_LINK_BYTES = 3_431_752
C62_PROOF_ENVELOPE_MAX_BYTES = (
    C62_ENVELOPE_FRAMING_BYTES
    + C62_RESIDUAL_SUMCHECK_MAX_BYTES
    + C62_PRODUCT_COORDINATE_ONE_BYTES
    + C62_RESIDUAL_PENDING_BYTES
    + C62_CACHE_SOURCE_BYTES
    + C62_CACHE_BLIND_MAX_BYTES
    + C62_CACHE_FOLD_TARGET_BYTES
    + C62_AUTHENTICATED_LINK_BYTES
)
C62_PI_FINAL_MAX_BYTES = C62_CERTIFICATE_FRAMING_BYTES + C62_PROOF_ENVELOPE_MAX_BYTES
C62_CERTIFICATE_CODEC_CEILING_BYTES = (
    C62_CERTIFICATE_FRAMING_BYTES
    + C62_RETAINED_NON_PCS_RESPONSE_BYTES
    + C62_PUBLIC_ARGUMENT_MAX_BYTES
    + C62_PROOF_ENVELOPE_MAX_BYTES
)
C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES = (
    C62_SETUP_BYTES + C62_CERTIFICATE_CODEC_CEILING_BYTES
)

C62_MAX_CHALLENGES = 131_072
C62_MAX_REJECTION_DRAWS_PER_LIMB = 4
C62_MAX_RANDOM_ORACLE_QUERIES = (
    C62_MAX_CHALLENGES * 2 * C62_MAX_REJECTION_DRAWS_PER_LIMB
)
C62_MAX_BLAKE3_HASH_INVOCATIONS = 2**36
C62_ACCEPTED_CERTIFICATES = 17
C62_BURNED_ATTEMPTS = 4
C62_GENESIS_RAW_CORRELATIONS = 5_346_048
C62_CONTINUATION_256_RAW_CORRELATIONS = 2_190_674
C62_CONTINUATION_512_RAW_CORRELATIONS = 2_200_274
C62_CONTINUATION_1024_RAW_CORRELATIONS = 2_210_258
C62_SESSION_RAW_CORRELATIONS_PER_TAPE = (
    C62_GENESIS_RAW_CORRELATIONS
    + 6 * C62_CONTINUATION_256_RAW_CORRELATIONS
    + 5 * C62_CONTINUATION_512_RAW_CORRELATIONS
    + 9 * C62_CONTINUATION_1024_RAW_CORRELATIONS
)
C62_TERMINAL_ONE_RAW_CAPACITY = 110_918_718


def error_report(error: Fraction) -> dict[str, str]:
    return {
        "numerator": str(error.numerator),
        "denominator": str(error.denominator),
        "bits": str(c6.soundness_bits(error)),
    }


def c61_complete_error() -> Fraction:
    report = c61.build_report()
    encoded = report["c6ict5_native_hidden_u_elimination"]["soundness"][
        "complete_per_certificate"
    ]
    return Fraction(int(encoded["numerator"]), int(encoded["denominator"]))


def build_report() -> dict[str, Any]:
    interactive_error = c61_complete_error()
    joint_eta_error = Fraction(1, c6.FP2_CARDINALITY)
    state_restoration_error = C62_MAX_RANDOM_ORACLE_QUERIES * (
        interactive_error + joint_eta_error
    )
    random_oracle_programming_error = Fraction(
        C62_MAX_RANDOM_ORACLE_QUERIES,
        2**256,
    )
    blake3_collision_error = Fraction(
        C62_MAX_BLAKE3_HASH_INVOCATIONS
        * (C62_MAX_BLAKE3_HASH_INVOCATIONS - 1),
        2 * 2**256,
    )
    rejected_u64_values = 2**64 - c6.GOLDILOCKS_P
    field_sampling_exhaustion_error = (
        2
        * C62_MAX_CHALLENGES
        * Fraction(rejected_u64_values, 2**64)
        ** C62_MAX_REJECTION_DRAWS_PER_LIMB
    )
    complete_error = (
        state_restoration_error
        + random_oracle_programming_error
        + blake3_collision_error
        + field_sampling_exhaustion_error
    )
    session_error = C62_ACCEPTED_CERTIFICATES * complete_error

    report: dict[str, Any] = {
        "profile": "C6.2-C62JVR1-C62FS1-exact-local-budget-v1",
        "credit": {
            "proof_size": False,
            "setup": False,
            "provider_time": False,
            "verifier_time": False,
            "hardware": False,
        },
        "gates": {
            "setup_plus_first": {
                "target_bytes": SETUP_TARGET_BYTES,
                "terminal_bytes": SETUP_TERMINAL_BYTES,
                "codec_ceiling_bytes": C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES,
                "target_pass": C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES
                <= SETUP_TARGET_BYTES,
                "terminal_pass": C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES
                <= SETUP_TERMINAL_BYTES,
            },
            "certificate": {
                "target_bytes": CERTIFICATE_TARGET_BYTES,
                "terminal_bytes": CERTIFICATE_TERMINAL_BYTES,
                "codec_ceiling_bytes": C62_CERTIFICATE_CODEC_CEILING_BYTES,
                "target_pass": C62_CERTIFICATE_CODEC_CEILING_BYTES
                <= CERTIFICATE_TARGET_BYTES,
                "terminal_pass": C62_CERTIFICATE_CODEC_CEILING_BYTES
                <= CERTIFICATE_TERMINAL_BYTES,
            },
            "pi_final": {
                "target_bytes": PI_FINAL_TARGET_BYTES,
                "terminal_bytes": PI_FINAL_TERMINAL_BYTES,
                "codec_ceiling_bytes": C62_PI_FINAL_MAX_BYTES,
                "target_pass": C62_PI_FINAL_MAX_BYTES <= PI_FINAL_TARGET_BYTES,
                "terminal_pass": C62_PI_FINAL_MAX_BYTES <= PI_FINAL_TERMINAL_BYTES,
            },
            "prover": {
                "target_seconds": str(PROVER_TARGET_SECONDS),
                "terminal_seconds": str(PROVER_TERMINAL_SECONDS),
                "measured_seconds": None,
                "pod_measurement_required": True,
            },
            "verifier": {
                "target_seconds": str(VERIFIER_TARGET_SECONDS),
                "terminal_seconds": str(VERIFIER_TERMINAL_SECONDS),
                "measured_seconds": None,
                "official_threads": 4,
                "pod_measurement_required": True,
            },
        },
        "setup": {
            "paired_pcg_bytes": c61.C6_PAIRED_PCG_BYTES,
            "compressed_client_parameter_payload_bytes": (
                C62_COMPRESSED_CLIENT_PARAMETER_PAYLOAD_BYTES
            ),
            "client_parameter_envelope_bytes": C62_CLIENT_PARAMETER_ENVELOPE_BYTES,
            "client_parameter_bytes": C62_CLIENT_PARAMETER_BYTES,
            "setup_manifest_framing_bytes": C62_SETUP_MANIFEST_FRAMING_BYTES,
            "total_bytes": C62_SETUP_BYTES,
        },
        "certificate_codec": {
            "retained_non_pcs_response_bytes": C62_RETAINED_NON_PCS_RESPONSE_BYTES,
            "public_argument_max_bytes": C62_PUBLIC_ARGUMENT_MAX_BYTES,
            "proof_envelope_components": C62_ENVELOPE_COMPONENTS,
            "product_coordinate_one_bytes": C62_PRODUCT_COORDINATE_ONE_BYTES,
            "proof_envelope_max_bytes": C62_PROOF_ENVELOPE_MAX_BYTES,
            "certificate_framing_bytes": C62_CERTIFICATE_FRAMING_BYTES,
            "certificate_ceiling_bytes": C62_CERTIFICATE_CODEC_CEILING_BYTES,
            "pi_final_ceiling_bytes": C62_PI_FINAL_MAX_BYTES,
        },
        "fiat_shamir": {
            "challenge_bound": C62_MAX_CHALLENGES,
            "rejection_draws_per_field_limb": C62_MAX_REJECTION_DRAWS_PER_LIMB,
            "random_oracle_query_bound": C62_MAX_RANDOM_ORACLE_QUERIES,
            "blake3_hash_invocation_bound": C62_MAX_BLAKE3_HASH_INVOCATIONS,
            "state_restoration_assumption": (
                "The concrete extractor loses at most one interactive error term "
                "for each bounded random-oracle query."
            ),
            "commitment_binding_assumption": (
                "BLAKE3 is collision resistant for the bounded invocation census."
            ),
        },
        "soundness": {
            "interactive_composition": error_report(interactive_error),
            "c62_joint_eta": error_report(joint_eta_error),
            "state_restoration": error_report(state_restoration_error),
            "random_oracle_programming": error_report(
                random_oracle_programming_error
            ),
            "blake3_collision": error_report(blake3_collision_error),
            "field_sampling_exhaustion": error_report(
                field_sampling_exhaustion_error
            ),
            "complete_per_certificate": error_report(complete_error),
            "seventeen_certificate_union": error_report(session_error),
            "gate_bits": str(SOUNDNESS_GATE_BITS),
            "gate_pass": c6.soundness_bits(complete_error) >= SOUNDNESS_GATE_BITS,
        },
        "session": {
            "accepted_certificates": C62_ACCEPTED_CERTIFICATES,
            "burned_attempts": C62_BURNED_ATTEMPTS,
            "burn_position": "after_certificate_0_at_old_context_150",
            "raw_correlations_per_tape": C62_SESSION_RAW_CORRELATIONS_PER_TAPE,
            "terminal_one_raw_capacity": C62_TERMINAL_ONE_RAW_CAPACITY,
            "capacity_pass": C62_SESSION_RAW_CORRELATIONS_PER_TAPE
            <= C62_TERMINAL_ONE_RAW_CAPACITY,
            "burned_attempts_used_in_hash_trial_bound": False,
        },
    }
    assert C62_PUBLIC_ARGUMENT_MAX_BYTES == 9_210_864
    assert C62_PROOF_ENVELOPE_MAX_BYTES == 3_484_338
    assert C62_PI_FINAL_MAX_BYTES == 3_485_131
    assert C62_CERTIFICATE_CODEC_CEILING_BYTES == 15_617_739
    assert C62_SETUP_BYTES == 141_882_261
    assert C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES == 157_500_000
    assert report["gates"]["setup_plus_first"]["terminal_pass"]
    assert report["gates"]["certificate"]["target_pass"]
    assert report["gates"]["pi_final"]["target_pass"]
    assert report["soundness"]["gate_pass"]
    assert C62_ACCEPTED_CERTIFICATES == 17
    assert C62_BURNED_ATTEMPTS == 4
    assert C62_SESSION_RAW_CORRELATIONS_PER_TAPE == 49_383_784
    assert report["session"]["capacity_pass"]
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    soundness = report["soundness"]["complete_per_certificate"]["bits"]
    print(f"C6.2 setup:                 {C62_SETUP_BYTES:,} B")
    print(f"C6.2 certificate ceiling:  {C62_CERTIFICATE_CODEC_CEILING_BYTES:,} B")
    print(f"C6.2 setup plus first:     {C62_SETUP_PLUS_FIRST_CODEC_CEILING_BYTES:,} B")
    print(f"C6.2 pi_final ceiling:     {C62_PI_FINAL_MAX_BYTES:,} B")
    print(f"C6.2 soundness:            {Decimal(soundness):.12f} bits/certificate")
    print("C6.2 local codec gates:    PASS")
    print("C6.2 pod timing credit:    REQUIRED")


if __name__ == "__main__":
    main()

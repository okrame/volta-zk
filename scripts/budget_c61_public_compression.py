#!/usr/bin/env python3
"""Exact C6.1 byte/operation decomposition and conservative open roofline.

This report deliberately has two different verdict scopes:

* exact reconciliation of the existing C6 certificate and residual-compiler
  operation census;
* a preregistered C6.1 allocation screen whose cryptographic backend and
  timings remain OPEN until an exact proof formula and measured kernels land.

No projected allocation is proof-size, setup, prover-time or verifier-time
credit.  The script must keep saying so until a later append-only amendment
changes the verdict together with evidence.
"""

from __future__ import annotations

import argparse
import json
from decimal import Decimal
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
        (runtime_stream_values - 1) ** C61_RUNTIME_SKETCH_REPETITIONS,
        c6.FP2_CARDINALITY**C61_RUNTIME_SKETCH_REPETITIONS,
    )
    runtime_sketch_bits = c6.soundness_bits(runtime_sketch_error)

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
        "verdict": "EXACT_DECOMPOSITION_PASS__CRYPTOGRAPHIC_ROOFLINE_OPEN",
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
            "compiler_timing_credit": False,
            "public_argument_timing_credit": False,
            "required_rule": (
                "C6RSC4 consumes the already-emitted provider atomic stream; a "
                "fourth provider semantic replay is forbidden"
            ),
            "verdict": "OPEN",
        },
        "verifier_time_screen": {
            "strict_gate_seconds": str(C61_VERIFIER_EXCLUSIVE_SECONDS),
            "required_components": [
                "base DV transcript and MAC verification",
                "two streaming runtime sketches",
                "C6PA1/C6RSC4 public verification",
                "unchanged compact Delta/link/cache closure",
            ],
            "verdict": "OPEN__NO_COMPONENT_BUDGET_OR_TIMING_CREDIT_YET",
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
    assert runtime_sketch_bits > Decimal("209")
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


if __name__ == "__main__":
    main()

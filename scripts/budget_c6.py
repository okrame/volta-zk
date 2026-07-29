#!/usr/bin/env python3
"""Exact analytic budget for the C6 inline Δ-residual certificate.

This script is the executable counterpart of
``docs/c6-delta-residual-inline-design.md``.  Integer byte and correlation
formulas are exact.  Soundness probabilities are represented as rational
numbers; ``Decimal`` is used only for the human-readable base-2 logarithm.

No benchmark observation is consumed here.  In particular, Q=121 is selected
from the preregistered soundness inventory before any C6 implementation or
timing record.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from typing import Any


GOLDILOCKS_P = 2**64 - 2**32 + 1
FP2_CARDINALITY = GOLDILOCKS_P**2

C4_ANCHOR_RESPONSE_BYTES = 84_544_352
C4_ANCHOR_PCS_BYTES = 43_273_888
DIRECT_AUTH_CORRECTION_BYTES = 38_348_720
RESPONSE_CAP_BYTES = 35_000_000
FINAL_PROOF_CAP_BYTES = 4_500_000
SETUP_CAP_BYTES = 150_000_000
FASE_D_SETUP_BYTES = 38_371_465

REGISTERED_SOUNDNESS_FLOOR_BITS = Decimal("78.80929487391641")
LEGACY_Q = 120
C6_Q = 121

BASELINE_RAW_CORRELATIONS = 5_235_692
TERMINAL_ONE_STAGE3_CAPACITY = 110_918_718
ACCEPTANCE_CREDITS = 17
ABORT_RETRY_CREDITS = 4

# These are statistical budgets, not observed failure rates.  Each concrete
# backend must re-resolve its term at or below the allocated bound.
WRAPPER_EVENT_BUDGETS = (
    "linear_functional_sumchecks",
    "wrapper_pcs",
    "cache_argument",
    "delta_residual",
)
WRAPPER_EVENT_ERROR = Fraction(1, 2**128)


@dataclass(frozen=True)
class LigeroTree:
    name: str
    rows: int
    cols: int
    pad: int
    code_len: int
    claims: int

    @property
    def msg_len(self) -> int:
        return self.cols + self.pad

    @property
    def vectors(self) -> int:
        return self.claims + 1

    @property
    def code_bits(self) -> int:
        if self.code_len <= 0 or self.code_len & (self.code_len - 1):
            raise ValueError("Ligero code length must be a positive power of two")
        return self.code_len.bit_length() - 1

    @property
    def effective_rate(self) -> Fraction:
        return Fraction(self.msg_len, self.code_len)

    def query_error(self, q: int) -> Fraction:
        base = 1 - (1 - self.effective_rate) / 2
        return base**q

    @property
    def field_error(self) -> Fraction:
        return Fraction(self.rows + self.claims + 1, FP2_CARDINALITY)

    def soundness_error(self, q: int) -> Fraction:
        return self.query_error(q) + self.field_error

    @property
    def u_vector_bytes(self) -> int:
        return 16 * self.msg_len * self.vectors

    @property
    def one_query_bytes(self) -> int:
        return (
            4
            + 8 * self.rows
            + 16 * self.vectors
            + 2 * 32 * self.code_bits
        )


WEIGHTS = LigeroTree(
    name="weights",
    rows=24_576,
    cols=8_192,
    pad=512,
    code_len=32_768,
    claims=96,
)
EMBED = LigeroTree(
    name="embed",
    rows=2_080,
    cols=32_768,
    pad=512,
    code_len=131_072,
    claims=6,
)
TREES = (WEIGHTS, EMBED)


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


def ligero_error(q: int) -> Fraction:
    if q <= 0:
        raise ValueError("Q must be positive")
    return sum((tree.soundness_error(q) for tree in TREES), start=Fraction())


def complete_statistical_error(q: int) -> Fraction:
    return ligero_error(q) + len(WRAPPER_EVENT_BUDGETS) * WRAPPER_EVENT_ERROR


def minimum_q() -> int:
    for q in range(1, 513):
        if soundness_bits(complete_statistical_error(q)) >= REGISTERED_SOUNDNESS_FLOOR_BITS:
            return q
    raise AssertionError("no Q <=512 meets the C6 soundness floor")


def build_report() -> dict[str, Any]:
    u_vector_bytes = sum(tree.u_vector_bytes for tree in TREES)
    q121_increment = sum(tree.one_query_bytes for tree in TREES) * (C6_Q - LEGACY_Q)
    retained_q120 = (
        C4_ANCHOR_RESPONSE_BYTES
        - DIRECT_AUTH_CORRECTION_BYTES
        - u_vector_bytes
    )
    retained_c6 = retained_q120 + q121_increment
    new_payload_budget = RESPONSE_CAP_BYTES - retained_c6
    projected_at_final_cap = retained_c6 + FINAL_PROOF_CAP_BYTES

    reserved_slots = ACCEPTANCE_CREDITS + ABORT_RETRY_CREDITS
    reserved_raw = reserved_slots * BASELINE_RAW_CORRELATIONS
    remaining_raw = TERMINAL_ONE_STAGE3_CAPACITY - reserved_raw

    q120_ligero = ligero_error(LEGACY_Q)
    q120_complete = complete_statistical_error(LEGACY_Q)
    q121_ligero = ligero_error(C6_Q)
    q121_complete = complete_statistical_error(C6_Q)
    with localcontext() as context:
        context.prec = 90
        session_floor_bits = REGISTERED_SOUNDNESS_FLOOR_BITS - (
            Decimal(ACCEPTANCE_CREDITS).ln() / Decimal(2).ln()
        )

    report: dict[str, Any] = {
        "schema": "volta-c6-budget-v1",
        "profile": "c6-delta-residual-inline-q121-v1",
        "ligero": {
            "legacy_q": LEGACY_Q,
            "selected_q": C6_Q,
            "minimum_q_with_wrapper_inventory": minimum_q(),
            "trees": [
                {
                    **asdict(tree),
                    "msg_len": tree.msg_len,
                    "vectors": tree.vectors,
                    "code_bits": tree.code_bits,
                    "u_vector_bytes": tree.u_vector_bytes,
                    "one_query_bytes": tree.one_query_bytes,
                }
                for tree in TREES
            ],
            "u_vector_bytes": u_vector_bytes,
            "q121_increment_bytes": q121_increment,
        },
        "communication": {
            "c4_anchor_response_bytes": C4_ANCHOR_RESPONSE_BYTES,
            "c4_anchor_pcs_bytes": C4_ANCHOR_PCS_BYTES,
            "removed_direct_auth_correction_bytes": DIRECT_AUTH_CORRECTION_BYTES,
            "removed_u_vector_bytes": u_vector_bytes,
            "retained_q120_bytes": retained_q120,
            "retained_c6_q121_bytes": retained_c6,
            "response_cap_bytes": RESPONSE_CAP_BYTES,
            "new_payload_budget_bytes": new_payload_budget,
            "final_proof_cap_bytes": FINAL_PROOF_CAP_BYTES,
            "projected_response_at_final_proof_cap_bytes": projected_at_final_cap,
            "response_headroom_at_final_proof_cap_bytes": (
                RESPONSE_CAP_BYTES - projected_at_final_cap
            ),
        },
        "setup_and_credit": {
            "setup_cap_bytes": SETUP_CAP_BYTES,
            "fase_d_setup_bytes": FASE_D_SETUP_BYTES,
            "remaining_client_parameter_budget_bytes": SETUP_CAP_BYTES - FASE_D_SETUP_BYTES,
            "terminal_one_stage3_raw_capacity": TERMINAL_ONE_STAGE3_CAPACITY,
            "baseline_raw_correlations": BASELINE_RAW_CORRELATIONS,
            "acceptance_credits": ACCEPTANCE_CREDITS,
            "abort_retry_credits": ABORT_RETRY_CREDITS,
            "reserved_baseline_slots": reserved_slots,
            "reserved_raw_correlations": reserved_raw,
            "remaining_raw_correlations": remaining_raw,
        },
        "soundness": {
            "field_cardinality": str(FP2_CARDINALITY),
            "registered_per_certificate_floor_bits": str(
                REGISTERED_SOUNDNESS_FLOOR_BITS
            ),
            "wrapper_event_names": list(WRAPPER_EVENT_BUDGETS),
            "wrapper_event_budget_bits_each": 128,
            "q120_ligero_error": str(rational_decimal(q120_ligero)),
            "q120_ligero_bits": str(soundness_bits(q120_ligero)),
            "q120_complete_bits": str(soundness_bits(q120_complete)),
            "q121_ligero_error": str(rational_decimal(q121_ligero)),
            "q121_ligero_bits": str(soundness_bits(q121_ligero)),
            "q121_complete_bits": str(soundness_bits(q121_complete)),
            "q120_complete_meets_floor": (
                soundness_bits(q120_complete) >= REGISTERED_SOUNDNESS_FLOOR_BITS
            ),
            "q121_complete_meets_floor": (
                soundness_bits(q121_complete) >= REGISTERED_SOUNDNESS_FLOOR_BITS
            ),
            "session_17_floor_bits": str(session_floor_bits),
        },
    }

    assert u_vector_bytes == 17_235_968
    assert q121_increment == 216_968
    assert retained_q120 == 28_959_664
    assert retained_c6 == 29_176_632
    assert new_payload_budget == 5_823_368
    assert projected_at_final_cap == 33_676_632
    assert reserved_slots == 21
    assert reserved_raw == 109_949_532
    assert remaining_raw == 969_186
    assert minimum_q() == C6_Q
    assert not report["soundness"]["q120_complete_meets_floor"]
    assert report["soundness"]["q121_complete_meets_floor"]
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the canonical JSON report")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    communication = report["communication"]
    credit = report["setup_and_credit"]
    soundness = report["soundness"]
    print(f"C6 profile:                 {report['profile']}")
    print(f"selected Q:                 {report['ligero']['selected_q']}")
    print(f"retained response:          {communication['retained_c6_q121_bytes']:,} B")
    print(f"new-payload budget:         {communication['new_payload_budget_bytes']:,} B")
    print(f"pi_final cap:               {communication['final_proof_cap_bytes']:,} B")
    print(
        "projected response:         "
        f"{communication['projected_response_at_final_proof_cap_bytes']:,} B"
    )
    print(
        "baseline credits:           "
        f"{credit['acceptance_credits']} accepted + "
        f"{credit['abort_retry_credits']} retry"
    )
    print(f"raw credit remaining:       {credit['remaining_raw_correlations']:,}")
    print(f"Q=121 Ligero bits:          {Decimal(soundness['q121_ligero_bits']):.14f}")
    print(f"Q=121 complete-budget bits: {Decimal(soundness['q121_complete_bits']):.14f}")
    print(f"17-cert floor composition:  {Decimal(soundness['session_17_floor_bits']):.14f}")


if __name__ == "__main__":
    main()

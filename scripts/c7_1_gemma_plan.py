#!/usr/bin/env python3
"""C7.1: exact, small algebra checks and planning arithmetic; NOT a prover.

No old protocol implementation is imported. The only historical input is the
digest-pinned model metadata. No weights, network, build or output file needed.
The cleartext diagnostic below MUST NOT be used to prove private weights.
"""

import hashlib
import json
import math
from pathlib import Path


P = (1 << 64) - (1 << 32) + 1
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
METADATA_SHA256 = "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"


def dot(a, b):
    if len(a) != len(b):
        raise ValueError("different vector lengths")
    return sum(x * y for x, y in zip(a, b)) % P


def combine(a, b, r):
    if len(a) != len(b):
        raise ValueError("different vector lengths")
    return [(x + r * y) % P for x, y in zip(a, b)]


def mle(values, point):
    """Little-endian Boolean-index multilinear evaluation, diagnostic only."""
    if len(values) != 1 << len(point):
        raise ValueError("point does not match the Boolean table")
    values = list(values)
    for r in point:
        values = [(a + r * (b - a)) % P
                  for a, b in zip(values[::2], values[1::2])]
    return values[0]


def paired_fold(rows, forms, coins):
    """Keep BOTH vectors. The returned sums are deliberately not masked."""
    if not rows or len(rows) != len(forms) or len(coins) != len(rows) - 1:
        raise ValueError("invalid block count")
    width = len(rows[0])
    if width == 0 or any(len(r) != width for r in [*rows, *forms]):
        raise ValueError("invalid block width")
    f, g = list(rows[0]), list(forms[0])
    sums, cross = [dot(f, g)], []
    claim = sums[0]
    for row, form, r in zip(rows[1:], forms[1:], coins):
        s = dot(row, form)
        t = (dot(f, form) + dot(row, g)) % P
        sums.append(s)
        cross.append(t)
        claim = (claim + r * t + r * r * s) % P
        f, g = combine(f, row, r), combine(g, form, r)
        assert claim == dot(f, g)
    return f, g, sums, cross, claim


def self_check():
    # Unlike the old one-vector rule, this retains row-dependent EQ forms.
    a, b = 3 * pow(4, -1, P) % P, 2 * pow(3, -1, P) % P
    rows = [[6, 0], [-6, 0]]
    forms = [[(1-a)*(1-b) % P, (1-a)*b % P],
             [a*(1-b) % P, a*b % P]]
    f, g, sums, cross, claim = paired_fold(rows, forms, [1])
    assert f == [0, 0] and sum(sums) % P == P - 1
    assert (sums[0] + cross[0] + sums[1]) % P == claim == dot(f, g)
    # Full two-pass evaluation link, with independent dense evaluation.
    for blocks in (1, 2, 4, 8):
        for width in (1, 2, 4, 8):
            rows = [[(i + 3) * (j + 7) - 11 for j in range(width)]
                    for i in range(blocks)]
            forms = [[(i * i + 2) * (j + 1) for j in range(width)]
                     for i in range(blocks)]
            coins = [i * 11 + 5 for i in range(blocks - 1)]
            f, g, sums, _, claim = paired_fold(rows, forms, coins)
            assert sum(sums) % P == sum(dot(r, q) for r, q in zip(rows, forms)) % P
            assert claim == dot(f, g)
            inner = [17 + i for i in range(width.bit_length() - 1)]
            outer = [29 + i for i in range(blocks.bit_length() - 1)]
            x, y = [mle(r, inner) for r in rows], [mle(q, inner) for q in forms]
            weights = [1, *coins]
            assert mle(f, inner) == dot(weights, x)
            assert mle(g, inner) == dot(weights, y)
            assert mle(x, outer) == mle(sum(rows, []), inner + outer)
            assert mle(y, outer) == mle(sum(forms, []), inner + outer)
    # A nonzero degree <= 2 discrepancy has <= 2 roots (exhaustive tiny field).
    for a in range(7):
        for b in range(7):
            for c in range(7):
                if (a, b, c) != (0, 0, 0):
                    assert sum((a + b*r + c*r*r) % 7 == 0 for r in range(7)) <= 2
    for call in (lambda: dot([1], []), lambda: mle([1, 2], []),
                 lambda: paired_fold([[1]], [[1, 2]], [])):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("malformed diagnostic input accepted")


def report():
    path = Path(__file__).resolve().parents[1] / "manifests/c7-d126-gemma31b-source-metadata-v1.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != METADATA_SHA256:
        raise ValueError("model metadata changed")
    metadata = json.loads(raw)
    if metadata["model"] != "google/gemma-4-31B" or metadata["revision"] != REVISION:
        raise ValueError("unexpected model")
    tensors = [t for t in metadata["tensors"] if t["disposition"] == "private_text"]
    live = sum(math.prod(t["shape"]) for t in tensors)
    assert len(tensors) == 772 and live == 30_697_345_280
    n = 1 << (live - 1).bit_length()
    h = n.bit_length() - 1
    candidates = []
    for block_bits in (20, 22, 24, 26):
        block = 1 << block_bits
        m = n // block
        # Explicit clear diagnostic codec: 2m-1 block scalars, 3h sumcheck
        # coefficients, 4 endpoint scalars. FS challenges not transmitted.
        fields = 2*m + 3*h + 3
        candidates.append({
            "block_cells": block,
            "blocks": m,
            "four_fp3_block_buffers_plus_three_row_vectors_bytes": 96*block + 72*m,
            "clear_algebra_payload_fields": fields,
            "clear_algebra_payload_bytes_not_certificate": 24*fields,
            "conditional_interactive_error_numerator": 2*m + 2*h + 1,
            "conditional_error_denominator": P**3,
        })
    return {
        "design": "C7.1",
        "evidence": "small algebra checks and exact planning arithmetic",
        "self_check": "completed",
        "private_weight_cells": live,
        "packed_weight_bytes": 2*live,
        "flat_zero_padded_cells_before_any_masks_or_encoding": n,
        "kv_capacity_i16_bytes": 4096*450_560*2,
        "h100_bytes_after_packed_weights_and_kv_only": 80_000_000_000 - 2*live - 4096*450_560*2,
        "two_additional_packed_source_reads_bytes": 4*live,
        "candidates": candidates,
        "complete_certificate_bytes": None,
        "complete_h100_peak_bytes": None,
        "complete_security_bits": None,
        "warm_prover_seconds": None,
        "four_core_verifier_seconds": None,
    }


if __name__ == "__main__":
    self_check()
    print(json.dumps(report(), indent=2))

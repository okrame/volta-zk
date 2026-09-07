#!/usr/bin/env python3
"""C7.1: exact, small algebra checks and planning arithmetic; NOT a prover.

No old protocol implementation is imported. The only historical input is the
digest-pinned model metadata. No weights, network, build or output file needed.
The cleartext diagnostic below MUST NOT be used to prove private weights.
"""

import hashlib
import json
import math
from collections import Counter
from pathlib import Path


P = (1 << 64) - (1 << 32) + 1
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
METADATA_SHA256 = "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
LIFETIME_ATTEMPTS = 1 << 20
CONTEXT_CAP = 4096


def natural(value, name, minimum=0, maximum=LIFETIME_ATTEMPTS):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def lifecycle_counts(accepted_pairs, failed_attempts=0, capacity_slots=32,
                     root_slots=256):
    """Accounting for ONE model/residency/connection, not a slot allocator.

    Failures mean attempts already reserved; they consume a slot. Capacities
    cover contiguous global slots and do not reset the root-privacy counter.
    Counts for new conversations do not imply permission to truncate a chat.
    """
    natural(accepted_pairs, "accepted_pairs")
    natural(failed_attempts, "failed_attempts")
    natural(capacity_slots, "capacity_slots", 1)
    natural(root_slots, "root_slots", 1)
    attempts = natural(accepted_pairs + failed_attempts, "total_attempts", 1)
    capacities = (attempts + capacity_slots - 1) // capacity_slots
    # The final capacity may be smaller; never reserve beyond the lifetime.
    reserved = min(LIFETIME_ATTEMPTS, capacities * capacity_slots)
    roots_used = (attempts + root_slots - 1) // root_slots
    return {
        "accepted_pairs": accepted_pairs,
        "consumed_attempt_slots": attempts,
        "model_setups": 1,
        "resident_loads": 1,
        "connection_setups": 1,
        "capacity_slots": capacity_slots,
        "capacity_setups": capacities,
        "reserved_slots": reserved,
        "reserved_unused_slots": reserved - attempts,
        "attempts_per_mask_root": root_slots,
        "mask_roots_touched": roots_used,
        "mask_roots_needed_for_reserved_capacity": (reserved + root_slots - 1) // root_slots,
        "mask_root_refreshes_after_first_used": roots_used - 1,
        "full_lifetime_mask_roots": (LIFETIME_ATTEMPTS + root_slots - 1) // root_slots,
    }


def total_cost(counts, unit_costs):
    """Exact frequency accounting for one resource; unknown costs stay unknown.

    Use separately for provider seconds, verifier seconds and offline bytes.
    No CPU/GPU overlap or free prefetch is inferred. Test prices are synthetic.
    Initial and refreshed roots are charged here, not also in model setup.
    """
    frequencies = {
        "model_setup": counts["model_setups"],
        "resident_load": counts["resident_loads"],
        "connection_setup": counts["connection_setups"],
        "capacity_setup": counts["capacity_setups"],
        "mask_root_prepare": counts["mask_roots_needed_for_reserved_capacity"],
        "response_attempt": counts["consumed_attempt_slots"],
    }
    if set(unit_costs) != set(frequencies):
        raise ValueError("all six disjoint cost families must be supplied")
    for value in unit_costs.values():
        if value is not None and (type(value) not in (int, float)
                                  or not math.isfinite(value) or value < 0):
            raise ValueError("cost must be finite, nonnegative, or unknown")
    if any(unit_costs[k] is None for k, n in frequencies.items() if n):
        return None
    return sum(n * (unit_costs[k] or 0) for k, n in frequencies.items())


def conversation_lengths(pairs):
    """Accepted (new prompt tokens, generated tokens); never silently evict."""
    used = 0
    result = []
    for prompt, generated in pairs:
        natural(prompt, "new prompt tokens", 1, CONTEXT_CAP)
        natural(generated, "generated tokens", 1, CONTEXT_CAP)
        after = used + prompt + generated
        if after > CONTEXT_CAP:
            raise ValueError("conversation exceeds 4096; no implicit reset or eviction")
        result.append({"old_kv_tokens": used, "new_prompt_tokens": prompt,
                       "generated_tokens": generated, "new_kv_tokens": after})
        used = after
    return result


def split_i16(value):
    natural(value, "i16", -(1 << 15), (1 << 15) - 1)
    high, low = divmod(value, 256)
    return low, high  # unsigned low byte, signed high byte; never float


def limb_dot(a, b):
    """Four exact integer dot products: algebra reference, NOT a GPU kernel."""
    if len(a) != len(b):
        raise ValueError("different dot-product lengths")
    aa, bb = [split_i16(x) for x in a], [split_i16(x) for x in b]
    ll = sum(x[0]*y[0] for x, y in zip(aa, bb))
    lh = sum(x[0]*y[1] for x, y in zip(aa, bb))
    hl = sum(x[1]*y[0] for x, y in zip(aa, bb))
    hh = sum(x[1]*y[1] for x, y in zip(aa, bb))
    return ll + 256*(lh + hl) + 65536*hh


def fp3_mul_six(a, b):
    """Six base-field products, same u^3=2 relation; algebra diagnostic only."""
    if len(a) != 3 or len(b) != 3:
        raise ValueError("Fp3 needs exactly three limbs")
    for x in (*a, *b):
        natural(x, "canonical Fp limb", 0, P - 1)
    v0, v1, v2 = (a[i]*b[i] % P for i in range(3))
    v01 = ((a[0]+a[1])*(b[0]+b[1]) - v0 - v1) % P
    v02 = ((a[0]+a[2])*(b[0]+b[2]) - v0 - v2) % P
    v12 = ((a[1]+a[2])*(b[1]+b[2]) - v1 - v2) % P
    return ((v0 + v12 + v12) % P, (v01 + v2 + v2) % P, (v02 + v1) % P)


def streaming_work(n, block):
    """Exact abstract multiplication counts for the stated generic schedule.

    f and g are arbitrary Fp3 tables. Excludes assertions, sumcheck, forms,
    masks, PCS, hashing and scalar bookkeeping: not a full prover estimate.
    Count axpy scaling even if its challenge happens to be 0 or 1.
    """
    if (type(n) is not int or type(block) is not int or block < 1 or n < block
            or n & (n - 1) or block & (block - 1)):
        raise ValueError("n and block must be powers of two, with block <= n")
    m = n // block
    return {
        "block_inner_products_fp3_mul": n,
        "cross_inner_products_fp3_mul": 2*(n-block),
        "paired_updates_fp3_mul": 2*(n-block),
        "second_pass_mle_fp3_mul": 2*(n-m),
        "subtotal_fp3_mul_before_sumchecks_forms_masks_pcs": 7*n - 4*block - 2*m,
    }


def hobbit_carrier_screen(n, block, queries):
    """Literal Construction 4 + split masks from §4.3.3; NOT a blind PCS.

    n is the padded source size; block is the PCS block, independently of
    the reduction block. Each proof opens queries DISTINCT columns per half
    of (Enc(W)+rho, rho), disjoint within that proof. Query pairs in two
    attempts are independent and uniform; the SAME rho is reused here.
    No FS grinding, masks from other schemes, or complete-size credit.
    """
    if (type(n) is not int or type(block) is not int or block < 1 or n < block
            or n & (n - 1) or block & (block - 1)):
        raise ValueError("n and block must be powers of two, with block <= n")
    natural(queries, "distinct queries per half", 1, 2*block)
    rows, domain = n // block, 4*block
    h = n.bit_length() - 1
    return {
        "credit": False,
        "carrier_block_cells": block,
        "rows": rows,
        "queries_per_half_not_a_security_derivation": queries,
        "unmasked_column_payload_fp_bytes": 8*queries*rows,
        "split_mask_column_payload_fp_bytes": 16*queries*rows,
        "split_mask_column_payload_fp3_bytes": 48*queries*rows,
        "compact_b_log2_b_work_units_not_complete_work": block*(block.bit_length()-1),
        "queried_column_cells_per_half": queries*rows,
        "linear_screen_conditions_not_physical_fit": (
            h > 0 and block*block >= n and block*h <= n and queries <= block),
        # Fixed coordinate j appears in the first masked half and second
        # mask-only half with probability (queries/domain)^2, exactly.
        "reused_mask_fixed_coordinate_exposure_probability": {
            "numerator": queries**2, "denominator": domain**2},
    }


def private_hobbit_bit_screen(n, live, block, queries):
    """Necessary bounds for one LITERAL private-verifier codec, not all PCS.

    Each 64-bit Fp leaf word gets 64 separate 8-byte subfield corrections;
    two dense Fp3 folding vectors coexist. Grant free omission of the last
    partial live row and all padding to obtain a favorable certificate floor.
    No gates, tags, paths, inner PCS, staging or other components are charged.
    """
    if (type(n) is not int or type(block) is not int or block < 1 or n < block
            or n & (n - 1) or block & (block - 1)):
        raise ValueError("n and block must be powers of two, with block <= n")
    natural(live, "live cells", 1, n)
    natural(queries, "distinct unmasked columns", 1, 4*block)
    floor = 64*8*queries*(live // block)
    buffers = 2*24*block
    return {
        "credit": False,
        "carrier_block_cells": block,
        "queries_not_a_security_derivation": queries,
        "full_live_rows": live // block,
        "dense_leaf_bit_correction_bytes": 64*8*queries*(n // block),
        "full_live_rows_only_bit_correction_bytes": floor,
        "two_dense_fp3_fold_buffers_bytes": buffers,
        "retained_full_column_tree_bytes_if_used": (8*block - 1)*32,
        "passes_only_necessary_certificate_and_arena_bounds": (
            floor <= 35_000_000 and buffers <= 6_442_450_944),
    }


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
    matrix_shapes = Counter(tuple(t["shape"]) for t in tensors if len(t["shape"]) == 2)
    max_dot = max(columns for _, columns in matrix_shapes)
    assert max_dot == 21_504
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
            "generic_unmasked_reduction_work": streaming_work(n, block),
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
        "authorized_max_proof_source_passes": 4,
        "four_packed_proof_source_reads_bytes": 8*live,
        "required_security_bits_strictly_greater_than": 78,
        "model_setup_delta_independence_required": True,
        "model_setup_delta_independence_evidence": "required interface; runtime not implemented",
        "single_user_accounting_examples": [
            lifecycle_counts(pairs, root_slots=root)
            for root in (256, 4096) for pairs in (1, 8, 27, 256, 257)
        ],
        "one_conversation_100_plus_50": {
            "accepted_pairs_before_context_full": CONTEXT_CAP // 150,
            "remaining_tokens": CONTEXT_CAP % 150,
            "first_eight_pairs": conversation_lengths([(100, 50)] * 8),
        },
        "int16_limb_diagnostic": {
            "max_matrix_inner_dimension": max_dot,
            "lo_lo_i32_abs_bound": max_dot * 255**2,
            "lo_hi_i32_abs_bound": max_dot * 255*128,
            "hi_hi_i32_abs_bound": max_dot * 128**2,
            "recombined_i64_abs_bound": max_dot * 32768**2,
            "cuda_kernel_implemented": False,
        },
        "fp3_multiplication_diagnostic": {
            "schoolbook_variable_products": 9,
            "six_product_variable_products": 6,
            "six_product_base_adds_subtracts": 17,
            "cuda_kernel_implemented": False,
            "runtime_backend_changed": False,
        },
        "private_matrix_shape_inventory_not_invocation_counts": [
            {"rows": r, "columns": k, "tensor_count": count}
            for (r, k), count in sorted(matrix_shapes.items())
        ],
        "candidates": candidates,
        "hobbit_direct_carrier_screens": [
            hobbit_carrier_screen(n, 1 << bits, 357) for bits in (23, 24, 25)
        ],
        "hobbit_private_bit_codec_screens": [
            private_hobbit_bit_screen(n, live, 1 << bits, 357)
            for bits in (24, 26, 27, 28)
        ],
        "complete_certificate_bytes": None,
        "complete_h100_peak_bytes": None,
        "complete_security_bits": None,
        "warm_prover_seconds": None,
        "four_core_verifier_seconds": None,
    }


if __name__ == "__main__":
    self_check()
    print(json.dumps(report(), indent=2))
